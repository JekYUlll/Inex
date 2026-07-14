//! Clean-HEAD repository import through one complete encrypted staging root.
//!
//! Git source binding and target object-database construction belong to
//! `inex-git`. This module owns only the CLI transaction: portable logical
//! classification, resource accounting, sequential vault population,
//! independent authenticated re-open, and one whole-root publication.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use inex_core::atomic::{
    AtomicDirectoryPublishError, FilesystemDirectoryIdentity, IMPORT_STAGING_PREFIX,
    ParentSyncStatus, atomic_publish_directory_no_replace_checked, filesystem_directory_identity,
    path_is_supported_local_filesystem,
};
use inex_core::crypto::VaultContentProfile;
use inex_core::format::{MAX_ASSET_PLAINTEXT_LEN, MAX_DOCUMENT_PLAINTEXT_LEN};
use inex_core::path::{AssetPath, LogicalDir, LogicalPath, raw_portable_case_fold_key};
use inex_core::search::MAX_SEARCH_INDEX_BYTES;
use inex_core::sodium::Argon2idParams;
use inex_core::tree::TreeEntryKind;
use inex_core::vault::Vault;
use inex_core::vault_config::{ConfigWarning, KdfPolicy};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_IMPORT_PLAINTEXT_BYTES: u64 = 4_294_967_296;
const TARGET_METADATA_PATHS: [&str; 3] = [".gitattributes", ".gitignore", "vault.json"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryImportIoOperation {
    ResolveDestination,
    InspectStaging,
}

impl fmt::Display for RepositoryImportIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResolveDestination => "validating the absent repository-import destination",
            Self::InspectStaging => "revalidating the encrypted repository-import staging root",
        })
    }
}

#[derive(Debug)]
pub(crate) enum RepositoryImportError {
    Git(inex_git::RepositoryImportError),
    InvalidDestination,
    DestinationExists,
    DestinationParentChanged,
    UnsupportedDestinationFilesystem,
    SourceDestinationOverlap,
    UnsafeSourceNamespace,
    InvalidLogicalPath,
    LogicalPathCollision,
    PhysicalPathCollision,
    MarkdownTooLarge,
    AssetTooLarge,
    MarkdownAggregateTooLarge,
    ImportAggregateTooLarge,
    InvalidMarkdownUtf8,
    SourceChanged,
    StagingCreateFailed,
    StagingIdentityChanged,
    VaultCreateFailed,
    VaultPopulationFailed,
    VaultAuditFailed,
    GitCandidateFailed,
    PublishDestinationExists,
    PublishIndeterminate,
    PublishedCleanupFailed,
    PublishFailed,
    PublishedAuditFailed,
    PublishedDurabilityNotConfirmed,
    Io {
        operation: RepositoryImportIoOperation,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for RepositoryImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Git(error) => write!(formatter, "repository source validation failed: {error}"),
            Self::InvalidDestination => formatter.write_str(
                "repository import requires one absent destination below an existing safe parent",
            ),
            Self::DestinationExists => formatter.write_str(
                "repository import requires a completely absent destination",
            ),
            Self::DestinationParentChanged => formatter.write_str(
                "destination parent changed; the repository import was not published",
            ),
            Self::UnsupportedDestinationFilesystem => formatter.write_str(
                "destination filesystem cannot guarantee local atomic publication",
            ),
            Self::SourceDestinationOverlap => formatter.write_str(
                "source repository and repository-import destination overlap",
            ),
            Self::UnsafeSourceNamespace => formatter
                .write_str("source worktree contains an untracked or empty directory entry"),
            Self::InvalidLogicalPath => formatter.write_str(
                "a tracked source path is outside the portable Inex path profile",
            ),
            Self::LogicalPathCollision => formatter.write_str(
                "tracked source paths collide in the portable logical namespace",
            ),
            Self::PhysicalPathCollision => formatter.write_str(
                "tracked source paths collide after encrypted physical-path mapping",
            ),
            Self::MarkdownTooLarge => formatter.write_str(
                "a tracked Markdown file exceeds the 16 MiB plaintext limit",
            ),
            Self::AssetTooLarge => formatter.write_str(
                "a tracked asset exceeds the 64 MiB plaintext limit",
            ),
            Self::MarkdownAggregateTooLarge => formatter.write_str(
                "tracked Markdown exceeds the 256 MiB aggregate limit",
            ),
            Self::ImportAggregateTooLarge => formatter.write_str(
                "tracked source bodies exceed the 4 GiB repository-import limit",
            ),
            Self::InvalidMarkdownUtf8 => formatter.write_str(
                "a tracked lowercase .md file is not valid UTF-8",
            ),
            Self::SourceChanged => formatter.write_str(
                "source repository changed during import; publication was not started",
            ),
            Self::StagingCreateFailed => formatter.write_str(
                "encrypted repository-import staging creation failed; destination remains absent",
            ),
            Self::StagingIdentityChanged => formatter.write_str(
                "encrypted repository-import staging identity changed; destination was not published",
            ),
            Self::VaultCreateFailed => formatter.write_str(
                "encrypted staging vault creation failed; destination remains absent",
            ),
            Self::VaultPopulationFailed => formatter.write_str(
                "encrypted staging vault population failed; destination remains absent",
            ),
            Self::VaultAuditFailed => formatter.write_str(
                "independent staging vault audit failed; destination remains absent",
            ),
            Self::GitCandidateFailed => formatter.write_str(
                "fresh encrypted Git candidate construction or audit failed; destination remains absent",
            ),
            Self::PublishDestinationExists => formatter.write_str(
                "destination appeared before publication and was not replaced",
            ),
            Self::PublishIndeterminate => formatter.write_str(
                "whole-root publication outcome is indeterminate; no replacement fallback was attempted",
            ),
            Self::PublishedCleanupFailed => formatter.write_str(
                "complete repository was published, but publication-marker cleanup failed",
            ),
            Self::PublishFailed => formatter.write_str(
                "whole-root atomic publication failed; encrypted staging is retained",
            ),
            Self::PublishedAuditFailed => formatter.write_str(
                "repository was published but its final independent audit failed",
            ),
            Self::PublishedDurabilityNotConfirmed => formatter.write_str(
                "complete repository was published, but destination-parent durability was not confirmed",
            ),
            Self::Io { operation, kind } => {
                write!(formatter, "I/O failed while {operation}: {kind:?}")
            }
        }
    }
}

impl std::error::Error for RepositoryImportError {}

impl From<inex_git::RepositoryImportError> for RepositoryImportError {
    fn from(error: inex_git::RepositoryImportError) -> Self {
        Self::Git(error)
    }
}

#[derive(Clone)]
enum PlannedKind {
    Markdown(LogicalPath),
    Asset(AssetPath),
}

impl PlannedKind {
    fn logical_path(&self) -> &str {
        match self {
            Self::Markdown(path) => path.as_str(),
            Self::Asset(path) => path.as_str(),
        }
    }

    fn physical_path(&self) -> PathBuf {
        match self {
            Self::Markdown(path) => path.to_ciphertext_relative_path(),
            Self::Asset(path) => path.to_ciphertext_relative_path(),
        }
    }
}

#[derive(Clone)]
struct PlannedEntry {
    source_index: usize,
    kind: PlannedKind,
}

struct DestinationPlan {
    path: PathBuf,
    parent: PathBuf,
    parent_identity: FilesystemDirectoryIdentity,
}

pub(crate) struct RepositoryImportPlan {
    source: inex_git::SourceSnapshot,
    destination: DestinationPlan,
    directories: Vec<LogicalDir>,
    entries: Vec<PlannedEntry>,
    markdown_files: usize,
    asset_files: usize,
    markdown_bytes: u64,
    asset_bytes: u64,
    largest_asset_bytes: u64,
    normalized_entries: usize,
}

impl fmt::Debug for RepositoryImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryImportPlan")
            .field("source", &"[REDACTED]")
            .field("destination", &"[REDACTED]")
            .field("directories", &self.directories.len())
            .field("entries", &self.entries.len())
            .field("markdown_files", &self.markdown_files)
            .field("asset_files", &self.asset_files)
            .finish_non_exhaustive()
    }
}

impl RepositoryImportPlan {
    pub(crate) fn source_tree_entries(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn source_index_entries(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn source_worktree_files(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn source_directories(&self) -> usize {
        self.source.directory_count()
    }

    pub(crate) const fn markdown_files(&self) -> usize {
        self.markdown_files
    }

    pub(crate) const fn asset_files(&self) -> usize {
        self.asset_files
    }

    pub(crate) const fn markdown_bytes(&self) -> u64 {
        self.markdown_bytes
    }

    pub(crate) const fn asset_bytes(&self) -> u64 {
        self.asset_bytes
    }

    pub(crate) const fn largest_asset_bytes(&self) -> u64 {
        self.largest_asset_bytes
    }

    pub(crate) const fn normalized_entries(&self) -> usize {
        self.normalized_entries
    }

    pub(crate) fn revalidate_source(&self) -> Result<(), RepositoryImportError> {
        self.source
            .revalidate()
            .map_err(|_| RepositoryImportError::SourceChanged)
    }
}

pub(crate) struct RepositoryImportReport {
    pub(crate) committed_markdown: usize,
    pub(crate) committed_assets: usize,
    pub(crate) git_root_commit: String,
    pub(crate) warnings: Vec<ConfigWarning>,
}

/// One freshly unlocked vault whose complete logical inventory and every
/// planned plaintext envelope have been independently audited against source.
///
/// The type is deliberately private and non-cloneable. A future initial
/// candidate-authority call must borrow `vault` from this owner before the
/// legacy-publication conversion consumes it.
struct IndependentlyAuditedVault {
    vault: Vault,
    warnings: Vec<ConfigWarning>,
}

impl fmt::Debug for IndependentlyAuditedVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndependentlyAuditedVault")
            .field("vault", &"[REDACTED]")
            .field("warnings", &self.warnings.len())
            .finish_non_exhaustive()
    }
}

impl IndependentlyAuditedVault {
    /// End the audited-vault lifetime at the explicit legacy-publication seam.
    ///
    /// The future v2 authority path must borrow `self.vault` before this point
    /// and replace, rather than wrap, the legacy v1 publisher.
    fn into_warnings_before_legacy_publication(self) -> Vec<ConfigWarning> {
        let Self { vault, warnings } = self;
        drop(vault);
        warnings
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryImportTerminal {
    NotCreated,
    StagingIncomplete,
    StagingAudited,
    PublicationIndeterminate,
    PublishedNeedsReconcile,
}

impl RepositoryImportTerminal {
    pub(crate) const fn fields(self) -> [&'static str; 4] {
        match self {
            Self::NotCreated => ["not-created", "not-published", "not-created", "none"],
            Self::StagingIncomplete => [
                "retained",
                "not-published",
                "staging-incomplete",
                "prepublication-cleanup",
            ],
            Self::StagingAudited => [
                "retained",
                "not-published",
                "staging-audited",
                "prepublication-cleanup",
            ],
            Self::PublicationIndeterminate => [
                "publication-indeterminate",
                "indeterminate",
                "staging-audited",
                "publication-reconcile",
            ],
            Self::PublishedNeedsReconcile => [
                "published",
                "published",
                "published",
                "publication-reconcile",
            ],
        }
    }
}

pub(crate) struct RepositoryImportExecutionError {
    error: RepositoryImportError,
    terminal: RepositoryImportTerminal,
}

impl RepositoryImportExecutionError {
    pub(crate) fn into_parts(self) -> (RepositoryImportError, RepositoryImportTerminal) {
        (self.error, self.terminal)
    }
}

pub(crate) fn plan(
    source_repository: &Path,
    destination: &Path,
) -> Result<RepositoryImportPlan, RepositoryImportError> {
    let source = inex_git::plan_source_repository(source_repository)?;
    let destination = DestinationPlan::new(&source, destination)?;
    let mut entries = Vec::with_capacity(source.entries().len());
    let mut raw_directories = BTreeSet::new();
    let mut markdown_files = 0_usize;
    let mut asset_files = 0_usize;
    let mut markdown_bytes = 0_u64;
    let mut asset_bytes = 0_u64;
    let mut largest_asset_bytes = 0_u64;
    let normalized_entries = source.normalized_path_entry_count();

    for (source_index, entry) in source.entries().iter().enumerate() {
        let relative = entry.relative_path();
        collect_raw_directories(relative, &mut raw_directories)?;
        let size = entry.size();
        let plaintext = source.read_entry(entry)?;
        if u64::try_from(plaintext.len()).ok() != Some(size)
            || sha256(plaintext.as_slice()) != entry.sha256()
        {
            return Err(RepositoryImportError::SourceChanged);
        }

        let kind = if entry.is_markdown() {
            if size > u64::try_from(MAX_DOCUMENT_PLAINTEXT_LEN).unwrap_or(u64::MAX) {
                return Err(RepositoryImportError::MarkdownTooLarge);
            }
            std::str::from_utf8(plaintext.as_slice())
                .map_err(|_| RepositoryImportError::InvalidMarkdownUtf8)?;
            markdown_bytes = markdown_bytes
                .checked_add(size)
                .ok_or(RepositoryImportError::MarkdownAggregateTooLarge)?;
            if markdown_bytes > u64::try_from(MAX_SEARCH_INDEX_BYTES).unwrap_or(u64::MAX) {
                return Err(RepositoryImportError::MarkdownAggregateTooLarge);
            }
            markdown_files += 1;
            let logical = LogicalPath::parse_canonical(relative)
                .map_err(|_| RepositoryImportError::InvalidLogicalPath)?;
            PlannedKind::Markdown(logical)
        } else {
            if size > u64::try_from(MAX_ASSET_PLAINTEXT_LEN).unwrap_or(u64::MAX) {
                return Err(RepositoryImportError::AssetTooLarge);
            }
            asset_bytes = asset_bytes
                .checked_add(size)
                .ok_or(RepositoryImportError::ImportAggregateTooLarge)?;
            largest_asset_bytes = largest_asset_bytes.max(size);
            asset_files += 1;
            let logical = AssetPath::parse_canonical(relative)
                .map_err(|_| RepositoryImportError::InvalidLogicalPath)?;
            PlannedKind::Asset(logical)
        };
        drop(plaintext);
        entries.push(PlannedEntry { source_index, kind });
    }

    let total = markdown_bytes
        .checked_add(asset_bytes)
        .ok_or(RepositoryImportError::ImportAggregateTooLarge)?;
    if total > MAX_IMPORT_PLAINTEXT_BYTES {
        return Err(RepositoryImportError::ImportAggregateTooLarge);
    }

    let mut directories = Vec::with_capacity(raw_directories.len());
    for raw in raw_directories {
        let logical = LogicalDir::parse_canonical(&raw)
            .map_err(|_| RepositoryImportError::InvalidLogicalPath)?;
        directories.push(logical);
    }
    if directories.len() != source.directory_count() {
        return Err(RepositoryImportError::UnsafeSourceNamespace);
    }
    directories.sort_by(|first, second| {
        first
            .components()
            .count()
            .cmp(&second.components().count())
            .then_with(|| first.cmp(second))
    });
    validate_namespaces(&directories, &entries)?;
    source
        .revalidate()
        .map_err(|_| RepositoryImportError::SourceChanged)?;

    Ok(RepositoryImportPlan {
        source,
        destination,
        directories,
        entries,
        markdown_files,
        asset_files,
        markdown_bytes,
        asset_bytes,
        largest_asset_bytes,
        normalized_entries,
    })
}

pub(crate) fn execute(
    plan: &RepositoryImportPlan,
    password: Zeroizing<Vec<u8>>,
    created_at_ms: i64,
    creation_params: Argon2idParams,
) -> Result<RepositoryImportReport, RepositoryImportExecutionError> {
    let mut terminal = RepositoryImportTerminal::NotCreated;
    let result = (|| -> Result<RepositoryImportReport, RepositoryImportError> {
        plan.revalidate_source()?;
        plan.destination.revalidate(&plan.source)?;
        let staging = StagingRoot::create(&plan.destination)?;
        terminal = RepositoryImportTerminal::StagingIncomplete;
        plan.destination.revalidate(&plan.source)?;
        staging.revalidate(&plan.destination)?;
        build_staging_vault(
            plan,
            staging.path(),
            password.as_slice(),
            created_at_ms,
            creation_params,
        )?;

        let tracked_paths = tracked_target_paths(plan)?;
        let target = inex_git::initialize_and_audit_target(
            staging.path(),
            &tracked_paths,
            created_at_ms.div_euclid(1_000),
        )
        .map_err(|_| RepositoryImportError::GitCandidateFailed)?;
        inex_git::audit_repository_import_target(staging.path(), &target)
            .map_err(|_| RepositoryImportError::GitCandidateFailed)?;
        inex_git::durably_audit_repository_import_target(staging.path(), &target)
            .map_err(|_| RepositoryImportError::GitCandidateFailed)?;

        let audited_vault =
            unlock_and_independently_audit_staging_vault(plan, &staging, password.as_slice())?;
        drop(password);
        terminal = RepositoryImportTerminal::StagingAudited;
        plan.revalidate_source()?;
        plan.destination.revalidate(&plan.source)?;
        staging.revalidate(&plan.destination)?;

        // Future initial candidate authority is acquired here while the same
        // freshly unlocked, fully audited `audited_vault.vault` is still
        // owned. The legacy v1 publisher must never be layered after v2.
        let warnings = audited_vault.into_warnings_before_legacy_publication();

        let publication = match atomic_publish_directory_no_replace_checked(
            staging.path(),
            &plan.destination.path,
            |current| {
                inex_git::audit_repository_import_target_for_publication(current, &target)
                    .map_err(|_| io::Error::other("repository import candidate audit failed"))
            },
        ) {
            Ok(publication) => publication,
            Err(error) => {
                terminal = match error {
                    AtomicDirectoryPublishError::Indeterminate => {
                        RepositoryImportTerminal::PublicationIndeterminate
                    }
                    AtomicDirectoryPublishError::PublishedCleanupFailed => {
                        RepositoryImportTerminal::PublishedNeedsReconcile
                    }
                    _ => RepositoryImportTerminal::StagingAudited,
                };
                return Err(map_publish_error(&error));
            }
        };
        terminal = RepositoryImportTerminal::PublishedNeedsReconcile;

        inex_git::audit_repository_import_target(&plan.destination.path, &target)
            .map_err(|_| RepositoryImportError::PublishedAuditFailed)?;
        if publication.parent_sync != ParentSyncStatus::Synced {
            return Err(RepositoryImportError::PublishedDurabilityNotConfirmed);
        }

        Ok(RepositoryImportReport {
            committed_markdown: plan.markdown_files,
            committed_assets: plan.asset_files,
            git_root_commit: target.root_commit_oid().to_owned(),
            warnings,
        })
    })();
    result.map_err(|error| RepositoryImportExecutionError { error, terminal })
}

fn build_staging_vault(
    plan: &RepositoryImportPlan,
    staging: &Path,
    password: &[u8],
    created_at_ms: i64,
    creation_params: Argon2idParams,
) -> Result<(), RepositoryImportError> {
    build_staging_vault_with_policy(
        plan,
        staging,
        password,
        created_at_ms,
        creation_params,
        KdfPolicy::default(),
    )
}

fn build_staging_vault_with_policy(
    plan: &RepositoryImportPlan,
    staging: &Path,
    password: &[u8],
    created_at_ms: i64,
    creation_params: Argon2idParams,
    policy: KdfPolicy,
) -> Result<(), RepositoryImportError> {
    let profile = if plan.asset_files == 0 {
        VaultContentProfile::DocumentsOnly
    } else {
        VaultContentProfile::OpaqueAssetsV1
    };
    let mut vault = Vault::create_with_profile_and_params(
        staging,
        password,
        created_at_ms,
        profile,
        creation_params,
        policy,
    )
    .map_err(|_| RepositoryImportError::VaultCreateFailed)?;

    for directory in &plan.directories {
        vault
            .create_directory(directory)
            .map_err(|_| RepositoryImportError::VaultPopulationFailed)?;
    }
    for planned in &plan.entries {
        let source_entry = plan
            .source
            .entries()
            .get(planned.source_index)
            .ok_or(RepositoryImportError::SourceChanged)?;
        let plaintext = plan.source.read_entry(source_entry)?;
        match &planned.kind {
            PlannedKind::Markdown(logical) => {
                vault
                    .create_document(logical, plaintext.as_slice(), created_at_ms)
                    .map_err(|_| RepositoryImportError::VaultPopulationFailed)?;
                let committed = vault
                    .read(logical)
                    .map_err(|_| RepositoryImportError::VaultPopulationFailed)?;
                if committed.plaintext.as_slice() != plaintext.as_slice()
                    || sha256(committed.plaintext.as_slice()) != source_entry.sha256()
                {
                    return Err(RepositoryImportError::VaultPopulationFailed);
                }
                drop(committed);
                drop(plaintext);
            }
            PlannedKind::Asset(logical) => {
                vault
                    .create_import_asset(logical, plaintext, created_at_ms)
                    .map_err(|_| RepositoryImportError::VaultPopulationFailed)?;
            }
        }
    }
    plan.revalidate_source()?;
    drop(vault);
    Ok(())
}

fn unlock_and_independently_audit_staging_vault(
    plan: &RepositoryImportPlan,
    staging: &StagingRoot,
    password: &[u8],
) -> Result<IndependentlyAuditedVault, RepositoryImportError> {
    unlock_and_independently_audit_staging_vault_with_policy(
        plan,
        staging,
        password,
        KdfPolicy::default(),
    )
}

fn unlock_and_independently_audit_staging_vault_with_policy(
    plan: &RepositoryImportPlan,
    staging: &StagingRoot,
    password: &[u8],
    policy: KdfPolicy,
) -> Result<IndependentlyAuditedVault, RepositoryImportError> {
    staging.revalidate(&plan.destination)?;
    let mut reopened = Vault::unlock(staging.path(), password, None, policy)
        .map_err(|_| RepositoryImportError::VaultAuditFailed)?;
    let warnings = reopened.warnings().to_vec();
    independently_audit_vault(plan, &mut reopened)?;
    plan.revalidate_source()?;
    staging.revalidate(&plan.destination)?;
    Ok(IndependentlyAuditedVault {
        vault: reopened,
        warnings,
    })
}

fn independently_audit_vault(
    plan: &RepositoryImportPlan,
    vault: &mut Vault,
) -> Result<(), RepositoryImportError> {
    require_exact_logical_inventory(plan, vault)?;
    for planned in &plan.entries {
        let source_entry = plan
            .source
            .entries()
            .get(planned.source_index)
            .ok_or(RepositoryImportError::SourceChanged)?;
        let verified = match &planned.kind {
            PlannedKind::Markdown(path) => vault
                .read(path)
                .map(|document| document.plaintext)
                .map_err(|_| RepositoryImportError::VaultAuditFailed)?,
            PlannedKind::Asset(path) => vault
                .read_asset(path)
                .map(|asset| asset.plaintext)
                .map_err(|_| RepositoryImportError::VaultAuditFailed)?,
        };
        let source_plaintext = plan.source.read_entry(source_entry)?;
        if u64::try_from(verified.len()).ok() != Some(source_entry.size())
            || sha256(verified.as_slice()) != source_entry.sha256()
            || verified.as_slice() != source_plaintext.as_slice()
        {
            return Err(RepositoryImportError::VaultAuditFailed);
        }
        drop(source_plaintext);
        drop(verified);
    }
    Ok(())
}

fn require_exact_logical_inventory(
    plan: &RepositoryImportPlan,
    vault: &mut Vault,
) -> Result<(), RepositoryImportError> {
    let mut expected = Vec::with_capacity(plan.directories.len() + plan.entries.len());
    expected.extend(
        plan.directories
            .iter()
            .map(|directory| (directory.as_str(), TreeEntryKind::Directory)),
    );
    expected.extend(plan.entries.iter().map(|planned| match &planned.kind {
        PlannedKind::Markdown(path) => (path.as_str(), TreeEntryKind::File),
        PlannedKind::Asset(path) => (path.as_str(), TreeEntryKind::Asset),
    }));
    expected.sort_unstable();

    let actual = vault
        .list()
        .map_err(|_| RepositoryImportError::VaultAuditFailed)?;
    if actual.len() != expected.len()
        || actual
            .entries()
            .iter()
            .zip(expected)
            .any(|(actual, (path, kind))| actual.logical_path() != path || actual.kind() != kind)
    {
        return Err(RepositoryImportError::VaultAuditFailed);
    }
    Ok(())
}

fn tracked_target_paths(
    plan: &RepositoryImportPlan,
) -> Result<Vec<PathBuf>, RepositoryImportError> {
    let mut paths = BTreeSet::new();
    for metadata in TARGET_METADATA_PATHS {
        paths.insert(PathBuf::from(metadata));
    }
    for entry in &plan.entries {
        if !paths.insert(entry.kind.physical_path()) {
            return Err(RepositoryImportError::PhysicalPathCollision);
        }
    }
    Ok(paths.into_iter().collect())
}

fn validate_namespaces(
    directories: &[LogicalDir],
    entries: &[PlannedEntry],
) -> Result<(), RepositoryImportError> {
    let mut logical = BTreeMap::new();
    let mut physical = BTreeMap::new();
    for metadata in TARGET_METADATA_PATHS {
        register_namespace(
            &mut physical,
            raw_portable_case_fold_key(metadata).as_str(),
            metadata,
            RepositoryImportError::PhysicalPathCollision,
        )?;
    }
    for directory in directories {
        register_namespace(
            &mut logical,
            directory.case_fold_key().as_str(),
            directory.as_str(),
            RepositoryImportError::LogicalPathCollision,
        )?;
        register_namespace(
            &mut physical,
            raw_portable_case_fold_key(directory.as_str()).as_str(),
            directory.as_str(),
            RepositoryImportError::PhysicalPathCollision,
        )?;
    }
    for entry in entries {
        let logical_path = entry.kind.logical_path();
        register_namespace(
            &mut logical,
            raw_portable_case_fold_key(logical_path).as_str(),
            logical_path,
            RepositoryImportError::LogicalPathCollision,
        )?;
        let physical_path = path_to_slashes(&entry.kind.physical_path())?;
        register_namespace(
            &mut physical,
            raw_portable_case_fold_key(&physical_path).as_str(),
            &physical_path,
            RepositoryImportError::PhysicalPathCollision,
        )?;
    }
    Ok(())
}

fn register_namespace(
    registry: &mut BTreeMap<String, String>,
    fold_key: &str,
    spelling: &str,
    collision: RepositoryImportError,
) -> Result<(), RepositoryImportError> {
    match registry.insert(fold_key.to_owned(), spelling.to_owned()) {
        None => Ok(()),
        Some(_) => Err(collision),
    }
}

fn collect_raw_directories(
    relative: &str,
    directories: &mut BTreeSet<String>,
) -> Result<(), RepositoryImportError> {
    let Some((parent, _)) = relative.rsplit_once('/') else {
        return Ok(());
    };
    let mut current = String::new();
    for component in parent.split('/') {
        if component.is_empty() {
            return Err(RepositoryImportError::InvalidLogicalPath);
        }
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        directories.insert(current.clone());
    }
    Ok(())
}

fn path_to_slashes(path: &Path) -> Result<String, RepositoryImportError> {
    let mut result = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(RepositoryImportError::InvalidLogicalPath);
        };
        let component = component
            .to_str()
            .ok_or(RepositoryImportError::InvalidLogicalPath)?;
        if !result.is_empty() {
            result.push('/');
        }
        result.push_str(component);
    }
    Ok(result)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl DestinationPlan {
    fn new(
        source: &inex_git::SourceSnapshot,
        destination: &Path,
    ) -> Result<Self, RepositoryImportError> {
        if destination.as_os_str().is_empty() {
            return Err(RepositoryImportError::InvalidDestination);
        }
        let absolute = if destination.is_absolute() {
            destination.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?
                .join(destination)
        };
        if !matches!(
            absolute.components().next_back(),
            Some(Component::Normal(_))
        ) {
            return Err(RepositoryImportError::InvalidDestination);
        }
        let name = absolute
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(RepositoryImportError::InvalidDestination)?;
        if name
            .to_ascii_lowercase()
            .starts_with(&IMPORT_STAGING_PREFIX.to_ascii_lowercase())
        {
            return Err(RepositoryImportError::InvalidDestination);
        }
        let raw_parent = absolute
            .parent()
            .ok_or(RepositoryImportError::InvalidDestination)?;
        validate_directory_chain(raw_parent)?;
        let parent = fs::canonicalize(raw_parent)
            .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?;
        validate_directory_chain(&parent)?;
        if !path_is_supported_local_filesystem(&parent)
            .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?
        {
            return Err(RepositoryImportError::UnsupportedDestinationFilesystem);
        }
        let path = parent.join(name);
        reject_existing(&path)?;
        ensure_disjoint(source.root(), &path)?;
        let parent_identity = filesystem_directory_identity(&parent)
            .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?;
        if source.contains_directory_identity(&parent_identity) {
            return Err(RepositoryImportError::SourceDestinationOverlap);
        }
        Ok(Self {
            path,
            parent,
            parent_identity,
        })
    }

    fn revalidate(&self, source: &inex_git::SourceSnapshot) -> Result<(), RepositoryImportError> {
        validate_directory_chain(&self.parent)?;
        let parent = fs::canonicalize(&self.parent)
            .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?;
        let identity = filesystem_directory_identity(&parent)
            .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?;
        if parent != self.parent || identity != self.parent_identity {
            return Err(RepositoryImportError::DestinationParentChanged);
        }
        ensure_disjoint(source.root(), &self.path)?;
        if source.contains_directory_identity(&identity) {
            return Err(RepositoryImportError::SourceDestinationOverlap);
        }
        reject_existing(&self.path)
    }
}

struct StagingRoot {
    path: PathBuf,
    identity: FilesystemDirectoryIdentity,
}

impl StagingRoot {
    fn create(destination: &DestinationPlan) -> Result<Self, RepositoryImportError> {
        for _ in 0..32 {
            let path = destination.parent.join(format!(
                "{IMPORT_STAGING_PREFIX}{}",
                Uuid::new_v4().simple()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    restrict_directory_permissions_best_effort(&path);
                    let identity = filesystem_directory_identity(&path).map_err(|error| {
                        io_error(RepositoryImportIoOperation::InspectStaging, &error)
                    })?;
                    return Ok(Self { path, identity });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(RepositoryImportError::StagingCreateFailed),
            }
        }
        Err(RepositoryImportError::StagingCreateFailed)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn revalidate(&self, destination: &DestinationPlan) -> Result<(), RepositoryImportError> {
        if self.path.parent() != Some(destination.parent.as_path())
            || !self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(IMPORT_STAGING_PREFIX))
        {
            return Err(RepositoryImportError::StagingIdentityChanged);
        }
        let identity = filesystem_directory_identity(&self.path)
            .map_err(|_| RepositoryImportError::StagingIdentityChanged)?;
        if identity != self.identity {
            return Err(RepositoryImportError::StagingIdentityChanged);
        }
        Ok(())
    }
}

fn validate_directory_chain(path: &Path) -> Result<(), RepositoryImportError> {
    let mut ancestors = path
        .ancestors()
        .filter(|entry| !entry.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(RepositoryImportError::InvalidDestination);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(RepositoryImportError::InvalidDestination);
            }
        }
    }
    Ok(())
}

fn reject_existing(path: &Path) -> Result<(), RepositoryImportError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(RepositoryImportError::DestinationExists),
        Err(error) => Err(io_error(
            RepositoryImportIoOperation::ResolveDestination,
            &error,
        )),
    }
}

fn ensure_disjoint(source: &Path, destination: &Path) -> Result<(), RepositoryImportError> {
    if source == destination || source.starts_with(destination) || destination.starts_with(source) {
        Err(RepositoryImportError::SourceDestinationOverlap)
    } else {
        Ok(())
    }
}

fn map_publish_error(error: &AtomicDirectoryPublishError) -> RepositoryImportError {
    match error {
        AtomicDirectoryPublishError::DestinationExists => {
            RepositoryImportError::PublishDestinationExists
        }
        AtomicDirectoryPublishError::Indeterminate => RepositoryImportError::PublishIndeterminate,
        AtomicDirectoryPublishError::PublishedCleanupFailed => {
            RepositoryImportError::PublishedCleanupFailed
        }
        AtomicDirectoryPublishError::InvalidPaths
        | AtomicDirectoryPublishError::NotMoved
        | AtomicDirectoryPublishError::Io { .. } => RepositoryImportError::PublishFailed,
    }
}

fn io_error(operation: RepositoryImportIoOperation, error: &io::Error) -> RepositoryImportError {
    RepositoryImportError::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(unix)]
fn restrict_directory_permissions_best_effort(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_directory_permissions_best_effort(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_limit_is_exactly_four_gibibytes() {
        assert_eq!(MAX_IMPORT_PLAINTEXT_BYTES, 4_294_967_296);
    }

    #[test]
    fn target_metadata_and_source_dot_gitignore_asset_do_not_collide() {
        let asset = AssetPath::parse_canonical(".gitignore")
            .unwrap_or_else(|error| panic!("asset path failed: {error}"));
        assert_eq!(
            asset.to_ciphertext_relative_path(),
            PathBuf::from(".gitignore.asset.enc")
        );
        assert_ne!(
            asset.to_ciphertext_relative_path(),
            PathBuf::from(".gitignore")
        );
    }

    #[test]
    fn raw_directory_collection_includes_each_parent_once() {
        let mut directories = BTreeSet::new();
        collect_raw_directories("a/b/first.md", &mut directories)
            .unwrap_or_else(|error| panic!("collection failed: {error}"));
        collect_raw_directories("a/b/second.png", &mut directories)
            .unwrap_or_else(|error| panic!("collection failed: {error}"));
        assert_eq!(
            directories,
            BTreeSet::from(["a".to_owned(), "a/b".to_owned()])
        );
    }

    #[test]
    fn failure_terminal_fields_match_the_frozen_contract() {
        assert_eq!(
            RepositoryImportTerminal::NotCreated.fields(),
            ["not-created", "not-published", "not-created", "none"]
        );
        assert_eq!(
            RepositoryImportTerminal::StagingIncomplete.fields(),
            [
                "retained",
                "not-published",
                "staging-incomplete",
                "prepublication-cleanup",
            ]
        );
        assert_eq!(
            RepositoryImportTerminal::StagingAudited.fields(),
            [
                "retained",
                "not-published",
                "staging-audited",
                "prepublication-cleanup",
            ]
        );
        assert_eq!(
            RepositoryImportTerminal::PublicationIndeterminate.fields(),
            [
                "publication-indeterminate",
                "indeterminate",
                "staging-audited",
                "publication-reconcile",
            ]
        );
        assert_eq!(
            RepositoryImportTerminal::PublishedNeedsReconcile.fields(),
            [
                "published",
                "published",
                "published",
                "publication-reconcile",
            ]
        );
    }

    #[test]
    fn production_source_freezes_audited_owner_and_legacy_publication_seams() {
        let source = include_str!("repository_import.rs");
        let production = source
            .split_once("\n#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        let execute = production
            .split_once("pub(crate) fn execute(")
            .and_then(|(_, tail)| tail.split_once("\nfn build_staging_vault("))
            .map_or_else(
                || panic!("execute source boundary changed"),
                |(execute, _)| execute,
            );
        let position = |needle: &str| {
            execute
                .find(needle)
                .unwrap_or_else(|| panic!("execute omitted source contract: {needle}"))
        };

        let build = position("build_staging_vault(");
        let git = position("inex_git::initialize_and_audit_target(");
        let git_audit =
            position("inex_git::audit_repository_import_target(staging.path(), &target)");
        let git_durable =
            position("inex_git::durably_audit_repository_import_target(staging.path(), &target)");
        let fresh_audit = position("unlock_and_independently_audit_staging_vault(");
        let password_drop = position("drop(password);");
        let terminal_audited = position("terminal = RepositoryImportTerminal::StagingAudited;");
        let owner_consumed = position("into_warnings_before_legacy_publication()");
        let legacy_publish = position("atomic_publish_directory_no_replace_checked(");
        assert!(
            build < git
                && git < git_audit
                && git_audit < git_durable
                && git_durable < fresh_audit
                && fresh_audit < password_drop
                && password_drop < terminal_audited
                && terminal_audited < owner_consumed
                && owner_consumed < legacy_publish
        );
        assert!(production.contains("password: Zeroizing<Vec<u8>>"));
        assert_eq!(production.matches("Vault::unlock(").count(), 1);
        assert!(production.contains("\nstruct IndependentlyAuditedVault {"));
        assert!(!production.contains("acquire_initial_candidate_authority"));
        assert!(!production.contains("IMPORT_PUBLISH_MARKER_V2"));

        let cli = include_str!("lib.rs");
        assert!(cli.contains("repository_import::execute(plan, password, created_at_ms"));
        assert!(!cli.contains("repository_import::execute(plan, password.as_slice()"));
    }

    #[cfg(target_os = "linux")]
    mod lifecycle {
        use std::ffi::OsStr;
        use std::process::Command;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        use super::*;

        const PASSWORD: &[u8] = b"audited owner test password";
        const CREATED_AT_MS: i64 = 1_783_699_200_000;
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new(label: &str) -> Self {
                let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_nanos());
                let path = std::env::temp_dir().join(format!(
                    "inex-cli-audited-vault-{label}-{}-{nanos}-{counter}",
                    std::process::id()
                ));
                fs::create_dir_all(&path)
                    .unwrap_or_else(|error| panic!("test directory creation failed: {error}"));
                Self(path)
            }

            fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn null_device() -> &'static OsStr {
            OsStr::new("/dev/null")
        }

        fn git(root: &Path, arguments: &[&str]) {
            let output = Command::new("git")
                .current_dir(root)
                .args(arguments)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", null_device())
                .env("GIT_TERMINAL_PROMPT", "0")
                .output()
                .unwrap_or_else(|error| panic!("git spawn failed: {error}"));
            assert!(
                output.status.success(),
                "git {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn weak_policy() -> KdfPolicy {
            KdfPolicy {
                min_creation_ops_limit: 1,
                min_creation_mem_limit_bytes: 8 * 1024,
                max_creation_ops_limit: 4,
                max_creation_mem_limit_bytes: 64 * 1024 * 1024,
                max_unlock_ops_limit: 4,
                max_unlock_mem_limit_bytes: 64 * 1024 * 1024,
            }
        }

        const fn weak_params() -> Argon2idParams {
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            }
        }

        fn fixture(label: &str) -> (TestDirectory, RepositoryImportPlan) {
            let temporary = TestDirectory::new(label);
            let source = temporary.path().join("source");
            let destination = temporary.path().join("vault");
            fs::create_dir(&source)
                .unwrap_or_else(|error| panic!("source creation failed: {error}"));
            git(&source, &["init", "-q", "--initial-branch=main"]);
            fs::write(source.join("journal.md"), b"# Audited owner\n")
                .unwrap_or_else(|error| panic!("Markdown write failed: {error}"));
            fs::write(source.join("image.bin"), b"asset canary")
                .unwrap_or_else(|error| panic!("asset write failed: {error}"));
            git(&source, &["add", "--all"]);
            git(
                &source,
                &[
                    "-c",
                    "user.email=audited-owner@example.invalid",
                    "-c",
                    "user.name=Audited Owner Tests",
                    "-c",
                    "commit.gpgSign=false",
                    "commit",
                    "-q",
                    "-m",
                    "source snapshot",
                ],
            );
            let plan = plan(&source, &destination)
                .unwrap_or_else(|error| panic!("repository plan failed: {error}"));
            (temporary, plan)
        }

        fn build_git_candidate(
            plan: &RepositoryImportPlan,
        ) -> (StagingRoot, inex_git::TargetRepository) {
            let staging = StagingRoot::create(&plan.destination)
                .unwrap_or_else(|error| panic!("staging creation failed: {error}"));
            build_staging_vault_with_policy(
                plan,
                staging.path(),
                PASSWORD,
                CREATED_AT_MS,
                weak_params(),
                weak_policy(),
            )
            .unwrap_or_else(|error| panic!("vault build failed: {error}"));
            assert!(!staging.path().join(".git").exists());
            let tracked = tracked_target_paths(plan)
                .unwrap_or_else(|error| panic!("tracked paths failed: {error}"));
            let target = inex_git::initialize_and_audit_target(
                staging.path(),
                &tracked,
                CREATED_AT_MS.div_euclid(1_000),
            )
            .unwrap_or_else(|error| panic!("Git target creation failed: {error}"));
            assert!(staging.path().join(".git/config").is_file());
            (staging, target)
        }

        #[test]
        fn git_precedes_fresh_audit_and_owner_debug_is_redacted() {
            let (_temporary, plan) = fixture("order");
            let (staging, target) = build_git_candidate(&plan);

            let audited = unlock_and_independently_audit_staging_vault(&plan, &staging, PASSWORD)
                .unwrap_or_else(|error| panic!("fresh audit failed: {error}"));
            assert!(!audited.warnings.is_empty());
            let debug = format!("{audited:?}");
            assert!(debug.contains("vault: \"[REDACTED]\""));
            assert!(debug.contains("warnings: 1"));
            assert!(!debug.contains("audited owner test password"));
            assert!(!debug.contains(&staging.path().to_string_lossy().into_owned()));
            assert!(!debug.contains("WeakKdf"));

            let warnings = audited.into_warnings_before_legacy_publication();
            assert_eq!(warnings.len(), 1);
            inex_git::audit_repository_import_target(staging.path(), &target)
                .unwrap_or_else(|error| panic!("legacy target audit changed: {error}"));
        }

        #[derive(Clone, Copy, Debug)]
        enum ExtraLogicalEntry {
            Directory,
            Markdown,
            Asset,
        }

        #[test]
        fn fresh_audit_rejects_extra_directory_markdown_and_asset_inventory() {
            let (_temporary, plan) = fixture("extra-inventory");
            for extra in [
                ExtraLogicalEntry::Directory,
                ExtraLogicalEntry::Markdown,
                ExtraLogicalEntry::Asset,
            ] {
                let (staging, target) = build_git_candidate(&plan);
                let mut vault = Vault::unlock(staging.path(), PASSWORD, None, KdfPolicy::default())
                    .unwrap_or_else(|error| panic!("tamper vault unlock failed: {error}"));
                match extra {
                    ExtraLogicalEntry::Directory => {
                        vault
                            .create_directory(
                                &LogicalDir::parse_canonical("rogue")
                                    .unwrap_or_else(|error| panic!("rogue dir failed: {error}")),
                            )
                            .unwrap_or_else(|error| panic!("rogue dir create failed: {error}"));
                    }
                    ExtraLogicalEntry::Markdown => {
                        let _ = vault
                            .create_document(
                                &LogicalPath::parse_canonical("rogue.md").unwrap_or_else(|error| {
                                    panic!("rogue Markdown failed: {error}")
                                }),
                                b"rogue plaintext",
                                CREATED_AT_MS,
                            )
                            .unwrap_or_else(|error| {
                                panic!("rogue Markdown create failed: {error}")
                            });
                    }
                    ExtraLogicalEntry::Asset => {
                        let _ = vault
                            .create_import_asset(
                                &AssetPath::parse_canonical("rogue.bin")
                                    .unwrap_or_else(|error| panic!("rogue asset failed: {error}")),
                                Zeroizing::new(b"rogue asset".to_vec()),
                                CREATED_AT_MS,
                            )
                            .unwrap_or_else(|error| panic!("rogue asset create failed: {error}"));
                    }
                }
                drop(vault);

                assert!(
                    matches!(
                        unlock_and_independently_audit_staging_vault(&plan, &staging, PASSWORD),
                        Err(RepositoryImportError::VaultAuditFailed)
                    ),
                    "extra {extra:?} passed exact logical inventory audit"
                );
                drop(target);
                fs::remove_dir_all(staging.path())
                    .unwrap_or_else(|error| panic!("staging cleanup failed: {error}"));
            }
        }
    }
}
