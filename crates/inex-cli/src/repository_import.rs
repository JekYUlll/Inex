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
    FilesystemDirectoryIdentity, IMPORT_STAGING_PREFIX, RepositoryPublicationNamespaceState,
    filesystem_directory_identity, inspect_repository_publication_namespace,
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
    ResolveSource,
    ResolveDestination,
    InspectStaging,
}

impl fmt::Display for RepositoryImportIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResolveSource => "normalizing the repository-import source path",
            Self::ResolveDestination => "normalizing the repository-import destination path",
            Self::InspectStaging => "revalidating the encrypted repository-import staging root",
        })
    }
}

#[derive(Debug)]
pub(crate) enum RepositoryImportError {
    Git(inex_git::RepositoryImportError),
    InvalidSourcePath,
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
    Publication(inex_git::RepositoryCandidatePublicationFailureKind),
    Reconciliation(RepositoryReconcileTerminal),
    Io {
        operation: RepositoryImportIoOperation,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for RepositoryImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Git(error) => write!(formatter, "repository source validation failed: {error}"),
            Self::InvalidSourcePath => formatter.write_str(
                "repository import requires one existing link-free source directory",
            ),
            Self::InvalidDestination => formatter.write_str(
                "repository import requires one direct-child destination below an existing safe parent",
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
            Self::Publication(kind) => kind.fmt(formatter),
            Self::Reconciliation(terminal) => formatter.write_str(terminal.result()),
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

pub(crate) enum RepositoryImportDispatch {
    Creation(Box<RepositoryImportPlan>),
    Existing(RepositoryReconcileRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryReconcileMarkerState {
    ReservedInspectionIndeterminate,
    Absent,
    LegacyUnverifiable,
    ReservedConflict,
    V2Invalid,
    V2Exact,
}

pub(crate) struct RepositoryReconcileRequest {
    destination: DestinationPlan,
    marker_state: RepositoryReconcileMarkerState,
    destination_identity: Option<FilesystemDirectoryIdentity>,
}

impl fmt::Debug for RepositoryReconcileRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryReconcileRequest")
            .field("destination", &"[REDACTED]")
            .field("marker_state", &self.marker_state)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryReconcileTerminal {
    ReservedInspectionIndeterminate,
    Absent,
    LegacyUnverifiable,
    ReservedConflict,
    V2Invalid,
    V2ClaimRejected,
    DurabilityIndeterminate,
    MarkerRetained,
    MarkerReplaced,
    MarkerPostStateIndeterminate,
    PostUnlinkAbsentIndeterminate,
}

impl RepositoryReconcileTerminal {
    #[allow(
        clippy::too_many_lines,
        reason = "the frozen terminal contract is clearer as one exhaustive table"
    )]
    pub(crate) const fn fields(self) -> [&'static str; 7] {
        match self {
            Self::ReservedInspectionIndeterminate => [
                "reserved-inspection-indeterminate",
                "existing-unattributed",
                "reconcile-conflict",
                "existing-unaudited",
                "not-attempted",
                "manual-audit",
                "publication marker namespace inspection failed",
            ],
            Self::Absent => [
                "absent",
                "existing-unattributed",
                "reconcile-not-started",
                "existing-unaudited",
                "not-attempted",
                "manual-audit",
                "existing repository is unattributed",
            ],
            Self::LegacyUnverifiable => [
                "legacy-unverifiable",
                "existing-unattributed",
                "reconcile-conflict",
                "existing-unaudited",
                "retained",
                "manual-audit",
                "legacy publication marker is unverifiable",
            ],
            Self::ReservedConflict => [
                "reserved-conflict",
                "existing-unattributed",
                "reconcile-conflict",
                "existing-unaudited",
                "retained",
                "manual-audit",
                "publication marker namespace conflicts",
            ],
            Self::V2Invalid => [
                "v2-invalid",
                "existing-unattributed",
                "reconcile-conflict",
                "existing-unaudited",
                "retained",
                "manual-audit",
                "publication marker is invalid",
            ],
            Self::V2ClaimRejected => [
                "v2-exact",
                "publication-indeterminate",
                "reconcile-conflict",
                "existing-unaudited",
                "retained",
                "manual-audit",
                "publication claim failed audit",
            ],
            Self::DurabilityIndeterminate => [
                "v2-exact",
                "existing-published",
                "indeterminate",
                "existing-audited",
                "retained",
                "publication-reconcile",
                "publication durability is indeterminate",
            ],
            Self::MarkerRetained => [
                "v2-exact",
                "existing-published",
                "durable-with-marker",
                "existing-audited",
                "retained",
                "publication-reconcile",
                "publication marker remains",
            ],
            Self::MarkerReplaced => [
                "marker-replaced",
                "existing-published",
                "indeterminate",
                "existing-audited",
                "replacement-retained",
                "manual-audit",
                "publication marker was replaced",
            ],
            Self::MarkerPostStateIndeterminate => [
                "marker-poststate-indeterminate",
                "existing-published",
                "indeterminate",
                "existing-audited",
                "indeterminate",
                "manual-audit",
                "publication marker post-state is indeterminate",
            ],
            Self::PostUnlinkAbsentIndeterminate => [
                "post-unlink-absent-indeterminate",
                "existing-published",
                "indeterminate",
                "existing-audited",
                "indeterminate",
                "publication-reconcile",
                "post-unlink publication state is indeterminate",
            ],
        }
    }

    pub(crate) const fn result(self) -> &'static str {
        self.fields()[6]
    }
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
    pub(crate) warnings: Vec<ConfigWarning>,
    publication: inex_git::PublishedRepositoryCandidate,
}

impl RepositoryImportReport {
    pub(crate) const fn committed_markdown(&self) -> u32 {
        self.publication.encrypted_markdown()
    }

    pub(crate) const fn committed_assets(&self) -> u32 {
        self.publication.encrypted_assets()
    }

    pub(crate) fn git_root_commit(&self) -> String {
        self.publication.root_commit_oid()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryReconcileOutcome {
    Preview,
    Reconciled,
}

enum RepositoryReconcileCandidate {
    Preview(inex_git::ExistingRepositoryCandidatePreview),
    Reconciled(Box<inex_git::PublishedRepositoryCandidate>),
}

pub(crate) struct RepositoryReconcileReport {
    candidate: RepositoryReconcileCandidate,
}

impl RepositoryReconcileReport {
    pub(crate) const fn outcome(&self) -> RepositoryReconcileOutcome {
        match &self.candidate {
            RepositoryReconcileCandidate::Preview(_) => RepositoryReconcileOutcome::Preview,
            RepositoryReconcileCandidate::Reconciled(_) => RepositoryReconcileOutcome::Reconciled,
        }
    }

    pub(crate) const fn worktree_files(&self) -> u32 {
        match &self.candidate {
            RepositoryReconcileCandidate::Preview(candidate) => candidate.worktree_files(),
            RepositoryReconcileCandidate::Reconciled(candidate) => candidate.worktree_files(),
        }
    }

    pub(crate) const fn encrypted_markdown(&self) -> u32 {
        match &self.candidate {
            RepositoryReconcileCandidate::Preview(candidate) => candidate.encrypted_markdown(),
            RepositoryReconcileCandidate::Reconciled(candidate) => candidate.encrypted_markdown(),
        }
    }

    pub(crate) const fn encrypted_assets(&self) -> u32 {
        match &self.candidate {
            RepositoryReconcileCandidate::Preview(candidate) => candidate.encrypted_assets(),
            RepositoryReconcileCandidate::Reconciled(candidate) => candidate.encrypted_assets(),
        }
    }

    pub(crate) const fn git_objects(&self) -> u32 {
        match &self.candidate {
            RepositoryReconcileCandidate::Preview(candidate) => candidate.git_objects(),
            RepositoryReconcileCandidate::Reconciled(candidate) => candidate.git_objects(),
        }
    }

    pub(crate) fn root_commit_oid(&self) -> String {
        match &self.candidate {
            RepositoryReconcileCandidate::Preview(candidate) => candidate.root_commit_oid(),
            RepositoryReconcileCandidate::Reconciled(candidate) => candidate.root_commit_oid(),
        }
    }
}

/// One freshly unlocked vault whose complete logical inventory and every
/// planned plaintext envelope have been independently audited against source.
///
/// The type is deliberately private and non-cloneable. The v2 initial
/// publication call borrows `vault` from this owner while constructing its
/// held-lock authority; no legacy publisher is layered afterward.
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
    publication: Option<inex_git::RepositoryCandidatePublicationFailure>,
}

impl RepositoryImportExecutionError {
    pub(crate) const fn terminal(&self) -> RepositoryImportTerminal {
        self.terminal
    }

    pub(crate) fn into_error(self) -> RepositoryImportError {
        let Self {
            error,
            terminal: _,
            publication: _publication,
        } = self;
        error
    }
}

pub(crate) struct RepositoryReconcileExecutionError {
    terminal: RepositoryReconcileTerminal,
    publication: Option<inex_git::RepositoryCandidatePublicationFailure>,
}

impl RepositoryReconcileExecutionError {
    pub(crate) const fn terminal(&self) -> RepositoryReconcileTerminal {
        self.terminal
    }

    pub(crate) fn into_error(self) -> RepositoryImportError {
        let Self {
            terminal,
            publication: _publication,
        } = self;
        RepositoryImportError::Reconciliation(terminal)
    }
}

pub(crate) fn dispatch(
    source_repository: &Path,
    destination: &Path,
) -> Result<RepositoryImportDispatch, RepositoryImportError> {
    let (source_root, source_identity) = resolve_source_root(source_repository)?;
    let (destination, exists) = DestinationPlan::resolve(destination)?;
    ensure_disjoint(&source_root, &destination.path)?;
    if destination.parent_identity == source_identity {
        return Err(RepositoryImportError::SourceDestinationOverlap);
    }

    if exists {
        let destination_identity = destination_identity_if_safe(&destination.path)?;
        if destination_identity.as_ref() == Some(&source_identity) {
            return Err(RepositoryImportError::SourceDestinationOverlap);
        }
        let mut disjointness_identities = vec![destination.parent_identity.clone()];
        if let Some(identity) = &destination_identity {
            disjointness_identities.push(identity.clone());
        }
        if source_tree_contains_directory_identity(
            &source_root,
            &source_identity,
            &disjointness_identities,
        )? {
            return Err(RepositoryImportError::SourceDestinationOverlap);
        }
        let mut marker_state =
            reconcile_marker_state(inspect_repository_publication_namespace(&destination.path));
        let revalidated_identity = destination_identity_if_safe(&destination.path)?;
        if destination_identity != revalidated_identity {
            marker_state = RepositoryReconcileMarkerState::ReservedInspectionIndeterminate;
        }
        return Ok(RepositoryImportDispatch::Existing(
            RepositoryReconcileRequest {
                destination,
                marker_state,
                destination_identity: revalidated_identity,
            },
        ));
    }

    let source = inex_git::plan_source_repository(&source_root)?;
    if source.root() != source_root || !source.contains_directory_identity(&source_identity) {
        return Err(RepositoryImportError::SourceChanged);
    }
    destination.revalidate(&source)?;
    if source.contains_directory_identity(&destination.parent_identity) {
        return Err(RepositoryImportError::SourceDestinationOverlap);
    }
    plan_creation(source, destination)
        .map(Box::new)
        .map(RepositoryImportDispatch::Creation)
}

fn plan_creation(
    source: inex_git::SourceSnapshot,
    destination: DestinationPlan,
) -> Result<RepositoryImportPlan, RepositoryImportError> {
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
    let mut publication_failure = None;
    let result = (|| -> Result<RepositoryImportReport, RepositoryImportError> {
        if !inex_git::initial_repository_publication_supported() {
            return Err(RepositoryImportError::Publication(
                inex_git::RepositoryCandidatePublicationFailureKind::UnsupportedPlatform,
            ));
        }
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

        let IndependentlyAuditedVault { vault, warnings } = audited_vault;
        let destination_child_name = plan
            .destination
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RepositoryImportError::InvalidDestination)?;
        let expected_profile = if plan.asset_files == 0 {
            VaultContentProfile::DocumentsOnly
        } else {
            VaultContentProfile::OpaqueAssetsV1
        };
        let publication = match inex_git::publish_initial_repository_candidate(
            staging.path(),
            &target,
            &vault,
            expected_profile,
            &plan.destination.parent_identity,
            destination_child_name,
        ) {
            Ok(publication) => publication,
            Err(failure) => {
                let kind = failure.kind();
                terminal = publication_terminal(kind);
                publication_failure = Some(failure);
                return Err(RepositoryImportError::Publication(kind));
            }
        };
        drop(vault);

        Ok(RepositoryImportReport {
            warnings,
            publication,
        })
    })();
    result.map_err(|error| RepositoryImportExecutionError {
        error,
        terminal,
        publication: publication_failure,
    })
}

pub(crate) fn execute_reconcile(
    request: &RepositoryReconcileRequest,
    dry_run: bool,
) -> Result<RepositoryReconcileReport, RepositoryReconcileExecutionError> {
    if marker_state_terminal(request.marker_state).is_some() {
        let destination_identity_unchanged =
            destination_identity_if_safe(&request.destination.path).ok()
                == Some(request.destination_identity.clone());
        let current_state = if request.destination.existing_parent_is_unchanged()
            && destination_identity_unchanged
        {
            reconcile_marker_state(inspect_repository_publication_namespace(
                &request.destination.path,
            ))
        } else {
            RepositoryReconcileMarkerState::ReservedInspectionIndeterminate
        };
        let terminal = if current_state == request.marker_state {
            marker_state_terminal(current_state)
                .unwrap_or(RepositoryReconcileTerminal::ReservedInspectionIndeterminate)
        } else {
            RepositoryReconcileTerminal::ReservedInspectionIndeterminate
        };
        return Err(RepositoryReconcileExecutionError {
            terminal,
            publication: None,
        });
    }

    if !request.destination.existing_parent_is_unchanged()
        || destination_identity_if_safe(&request.destination.path).ok()
            != Some(request.destination_identity.clone())
    {
        return Err(RepositoryReconcileExecutionError {
            terminal: RepositoryReconcileTerminal::V2ClaimRejected,
            publication: None,
        });
    }

    let child_name = request
        .destination
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(RepositoryReconcileExecutionError {
            terminal: RepositoryReconcileTerminal::V2ClaimRejected,
            publication: None,
        })?;
    let result = if dry_run {
        inex_git::preview_existing_repository_candidate(
            &request.destination.path,
            &request.destination.parent_identity,
            child_name,
        )
        .map(RepositoryReconcileCandidate::Preview)
    } else {
        inex_git::reconcile_existing_repository_candidate(
            &request.destination.path,
            &request.destination.parent_identity,
            child_name,
        )
        .map(Box::new)
        .map(RepositoryReconcileCandidate::Reconciled)
    };

    match result {
        Ok(candidate) => Ok(RepositoryReconcileReport { candidate }),
        Err(publication) => Err(RepositoryReconcileExecutionError {
            terminal: reconciliation_terminal(publication.kind()),
            publication: Some(publication),
        }),
    }
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
    fn resolve(destination: &Path) -> Result<(Self, bool), RepositoryImportError> {
        let absolute = lexical_absolute_path(destination, ImportPathRole::Destination)?;
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
        if raw_portable_case_fold_key(name)
            .as_str()
            .starts_with(raw_portable_case_fold_key(IMPORT_STAGING_PREFIX).as_str())
        {
            return Err(RepositoryImportError::InvalidDestination);
        }
        let raw_parent = absolute
            .parent()
            .ok_or(RepositoryImportError::InvalidDestination)?;
        let (parent, parent_identity) =
            resolve_verified_directory(raw_parent, ImportPathRole::Destination)?;
        if !path_is_supported_local_filesystem(&parent)
            .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?
        {
            return Err(RepositoryImportError::UnsupportedDestinationFilesystem);
        }
        let path = parent.join(name);
        let exists = destination_exists(&path)?;
        Ok((
            Self {
                path,
                parent,
                parent_identity,
            },
            exists,
        ))
    }

    fn revalidate(&self, source: &inex_git::SourceSnapshot) -> Result<(), RepositoryImportError> {
        let (parent, identity) =
            resolve_verified_directory(&self.parent, ImportPathRole::Destination)?;
        if parent != self.parent || identity != self.parent_identity {
            return Err(RepositoryImportError::DestinationParentChanged);
        }
        ensure_disjoint(source.root(), &self.path)?;
        if source.contains_directory_identity(&identity) {
            return Err(RepositoryImportError::SourceDestinationOverlap);
        }
        reject_existing(&self.path)
    }

    fn existing_parent_is_unchanged(&self) -> bool {
        resolve_verified_directory(&self.parent, ImportPathRole::Destination).is_ok_and(
            |(parent, identity)| parent == self.parent && identity == self.parent_identity,
        )
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

#[derive(Clone, Copy)]
enum ImportPathRole {
    Source,
    Destination,
}

impl ImportPathRole {
    const fn invalid(self) -> RepositoryImportError {
        match self {
            Self::Source => RepositoryImportError::InvalidSourcePath,
            Self::Destination => RepositoryImportError::InvalidDestination,
        }
    }

    const fn operation(self) -> RepositoryImportIoOperation {
        match self {
            Self::Source => RepositoryImportIoOperation::ResolveSource,
            Self::Destination => RepositoryImportIoOperation::ResolveDestination,
        }
    }
}

fn lexical_absolute_path(
    path: &Path,
    role: ImportPathRole,
) -> Result<PathBuf, RepositoryImportError> {
    if path.as_os_str().is_empty() {
        return Err(role.invalid());
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_error(role.operation(), &error))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(role.invalid());
                }
            }
            Component::Normal(name) => normalized.push(name),
        }
    }
    if normalized.is_absolute() {
        Ok(normalized)
    } else {
        Err(role.invalid())
    }
}

fn resolve_source_root(
    source: &Path,
) -> Result<(PathBuf, FilesystemDirectoryIdentity), RepositoryImportError> {
    let absolute = lexical_absolute_path(source, ImportPathRole::Source)?;
    resolve_verified_directory(&absolute, ImportPathRole::Source)
}

fn resolve_verified_directory(
    path: &Path,
    role: ImportPathRole,
) -> Result<(PathBuf, FilesystemDirectoryIdentity), RepositoryImportError> {
    validate_directory_chain(path, role)?;
    let input_identity =
        filesystem_directory_identity(path).map_err(|error| io_error(role.operation(), &error))?;
    let canonical = fs::canonicalize(path).map_err(|error| io_error(role.operation(), &error))?;
    validate_directory_chain(&canonical, role)?;
    let canonical_identity = filesystem_directory_identity(&canonical)
        .map_err(|error| io_error(role.operation(), &error))?;
    validate_directory_chain(path, role)?;
    let revalidated_input_identity =
        filesystem_directory_identity(path).map_err(|error| io_error(role.operation(), &error))?;
    if input_identity != canonical_identity || input_identity != revalidated_input_identity {
        return Err(role.invalid());
    }
    Ok((canonical, canonical_identity))
}

fn validate_directory_chain(
    path: &Path,
    role: ImportPathRole,
) -> Result<(), RepositoryImportError> {
    let mut ancestors = path
        .ancestors()
        .filter(|entry| !entry.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|error| io_error(role.operation(), &error))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(role.invalid());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(role.invalid());
            }
        }
    }
    Ok(())
}

fn destination_exists(path: &Path) -> Result<bool, RepositoryImportError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Ok(_) => Ok(true),
        Err(error) => Err(io_error(
            RepositoryImportIoOperation::ResolveDestination,
            &error,
        )),
    }
}

fn destination_identity_if_safe(
    path: &Path,
) -> Result<Option<FilesystemDirectoryIdentity>, RepositoryImportError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Ok(None);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(None);
        }
    }
    filesystem_directory_identity(path)
        .map(Some)
        .map_err(|error| io_error(RepositoryImportIoOperation::ResolveDestination, &error))
}

#[cfg(target_os = "linux")]
const MAX_SOURCE_DISJOINTNESS_ENTRIES: usize = 1_000_000;
#[cfg(target_os = "linux")]
const MAX_SOURCE_DISJOINTNESS_DEPTH: usize = 256;

fn source_tree_contains_directory_identity(
    source_root: &Path,
    expected_root_identity: &FilesystemDirectoryIdentity,
    identities: &[FilesystemDirectoryIdentity],
) -> Result<bool, RepositoryImportError> {
    #[cfg(target_os = "linux")]
    {
        let root = inex_core::atomic::open_secure_source_root(source_root)
            .map_err(|_| RepositoryImportError::SourceChanged)?;
        if root.identity() != expected_root_identity {
            return Err(RepositoryImportError::SourceChanged);
        }
        let mut entries = 0_usize;
        let contains =
            secure_source_tree_contains_directory_identity(&root, identities, &mut entries, 0)?;
        root.verify_binding()
            .map_err(|_| RepositoryImportError::SourceChanged)?;
        Ok(contains)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let current = filesystem_directory_identity(source_root)
            .map_err(|_| RepositoryImportError::SourceChanged)?;
        if &current != expected_root_identity {
            return Err(RepositoryImportError::SourceChanged);
        }
        let _ = identities;
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
fn secure_source_tree_contains_directory_identity(
    directory: &inex_core::atomic::SecureSourceDirectory,
    identities: &[FilesystemDirectoryIdentity],
    entries: &mut usize,
    depth: usize,
) -> Result<bool, RepositoryImportError> {
    if identities
        .iter()
        .any(|identity| identity == directory.identity())
    {
        return Ok(true);
    }
    directory
        .verify_binding()
        .map_err(|_| RepositoryImportError::SourceChanged)?;
    let children = directory
        .read_dir()
        .map_err(|_| RepositoryImportError::SourceChanged)?;
    for child in children {
        let child = child.map_err(|_| RepositoryImportError::SourceChanged)?;
        *entries = entries
            .checked_add(1)
            .filter(|count| *count <= MAX_SOURCE_DISJOINTNESS_ENTRIES)
            .ok_or(RepositoryImportError::SourceChanged)?;
        if !child
            .file_type()
            .map_err(|_| RepositoryImportError::SourceChanged)?
            .is_dir()
        {
            continue;
        }
        match directory
            .open_child(&child.file_name())
            .map_err(|_| RepositoryImportError::SourceChanged)?
        {
            inex_core::atomic::SecureSourceChild::Directory(child_directory) => {
                if depth >= MAX_SOURCE_DISJOINTNESS_DEPTH {
                    return Err(RepositoryImportError::SourceChanged);
                }
                if secure_source_tree_contains_directory_identity(
                    &child_directory,
                    identities,
                    entries,
                    depth + 1,
                )? {
                    return Ok(true);
                }
            }
            inex_core::atomic::SecureSourceChild::File(_)
            | inex_core::atomic::SecureSourceChild::Other => {
                return Err(RepositoryImportError::SourceChanged);
            }
        }
    }
    directory
        .verify_binding()
        .map_err(|_| RepositoryImportError::SourceChanged)?;
    Ok(false)
}

fn reject_existing(path: &Path) -> Result<(), RepositoryImportError> {
    if destination_exists(path)? {
        Err(RepositoryImportError::DestinationExists)
    } else {
        Ok(())
    }
}

fn ensure_disjoint(source: &Path, destination: &Path) -> Result<(), RepositoryImportError> {
    if source == destination || source.starts_with(destination) || destination.starts_with(source) {
        Err(RepositoryImportError::SourceDestinationOverlap)
    } else {
        Ok(())
    }
}

const fn marker_state_terminal(
    state: RepositoryReconcileMarkerState,
) -> Option<RepositoryReconcileTerminal> {
    match state {
        RepositoryReconcileMarkerState::ReservedInspectionIndeterminate => {
            Some(RepositoryReconcileTerminal::ReservedInspectionIndeterminate)
        }
        RepositoryReconcileMarkerState::Absent => Some(RepositoryReconcileTerminal::Absent),
        RepositoryReconcileMarkerState::LegacyUnverifiable => {
            Some(RepositoryReconcileTerminal::LegacyUnverifiable)
        }
        RepositoryReconcileMarkerState::ReservedConflict => {
            Some(RepositoryReconcileTerminal::ReservedConflict)
        }
        RepositoryReconcileMarkerState::V2Invalid => Some(RepositoryReconcileTerminal::V2Invalid),
        RepositoryReconcileMarkerState::V2Exact => None,
    }
}

fn reconcile_marker_state(
    state: Result<
        RepositoryPublicationNamespaceState,
        inex_core::atomic::RepositoryPublicationNamespaceInspectionError,
    >,
) -> RepositoryReconcileMarkerState {
    match state {
        Err(_) => RepositoryReconcileMarkerState::ReservedInspectionIndeterminate,
        Ok(RepositoryPublicationNamespaceState::Absent) => RepositoryReconcileMarkerState::Absent,
        Ok(RepositoryPublicationNamespaceState::LegacyUnverifiable) => {
            RepositoryReconcileMarkerState::LegacyUnverifiable
        }
        Ok(RepositoryPublicationNamespaceState::ReservedConflict) => {
            RepositoryReconcileMarkerState::ReservedConflict
        }
        Ok(RepositoryPublicationNamespaceState::V2Invalid) => {
            RepositoryReconcileMarkerState::V2Invalid
        }
        Ok(RepositoryPublicationNamespaceState::V2Exact) => RepositoryReconcileMarkerState::V2Exact,
    }
}

const fn reconciliation_terminal(
    kind: inex_git::RepositoryCandidatePublicationFailureKind,
) -> RepositoryReconcileTerminal {
    use inex_git::RepositoryCandidatePublicationFailureKind as Kind;

    match kind {
        Kind::PublicationDurabilityIndeterminate | Kind::PublicationDurabilityRejected => {
            RepositoryReconcileTerminal::DurabilityIndeterminate
        }
        Kind::PublicationMarkerRetained => RepositoryReconcileTerminal::MarkerRetained,
        Kind::PublicationMarkerReplaced => RepositoryReconcileTerminal::MarkerReplaced,
        Kind::PublicationMarkerPostStateIndeterminate => {
            RepositoryReconcileTerminal::MarkerPostStateIndeterminate
        }
        Kind::PostUnlinkIndeterminate | Kind::CleanAuditRejected => {
            RepositoryReconcileTerminal::PostUnlinkAbsentIndeterminate
        }
        Kind::UnsupportedPlatform
        | Kind::InitialAuthorityRejected
        | Kind::InitialClaimRejected
        | Kind::ExistingClaimRejected
        | Kind::InitialPublicationNotMoved
        | Kind::DestinationExists
        | Kind::PublicationIndeterminate
        | Kind::InitialPublicationRejected => RepositoryReconcileTerminal::V2ClaimRejected,
    }
}

const fn publication_terminal(
    kind: inex_git::RepositoryCandidatePublicationFailureKind,
) -> RepositoryImportTerminal {
    use inex_git::RepositoryCandidatePublicationFailureKind as Kind;

    match kind {
        Kind::PublicationIndeterminate => RepositoryImportTerminal::PublicationIndeterminate,
        Kind::PublicationDurabilityIndeterminate
        | Kind::PublicationDurabilityRejected
        | Kind::PublicationMarkerRetained
        | Kind::PublicationMarkerReplaced
        | Kind::PublicationMarkerPostStateIndeterminate
        | Kind::PostUnlinkIndeterminate
        | Kind::CleanAuditRejected => RepositoryImportTerminal::PublishedNeedsReconcile,
        Kind::UnsupportedPlatform
        | Kind::InitialAuthorityRejected
        | Kind::InitialClaimRejected
        | Kind::ExistingClaimRejected
        | Kind::InitialPublicationNotMoved
        | Kind::DestinationExists
        | Kind::InitialPublicationRejected => RepositoryImportTerminal::StagingAudited,
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
    #[allow(
        clippy::too_many_lines,
        reason = "the test mirrors every row of the frozen terminal contract"
    )]
    fn reconcile_terminal_fields_match_the_frozen_contract() {
        let cases = [
            (
                RepositoryReconcileTerminal::ReservedInspectionIndeterminate,
                [
                    "reserved-inspection-indeterminate",
                    "existing-unattributed",
                    "reconcile-conflict",
                    "existing-unaudited",
                    "not-attempted",
                    "manual-audit",
                    "publication marker namespace inspection failed",
                ],
            ),
            (
                RepositoryReconcileTerminal::Absent,
                [
                    "absent",
                    "existing-unattributed",
                    "reconcile-not-started",
                    "existing-unaudited",
                    "not-attempted",
                    "manual-audit",
                    "existing repository is unattributed",
                ],
            ),
            (
                RepositoryReconcileTerminal::LegacyUnverifiable,
                [
                    "legacy-unverifiable",
                    "existing-unattributed",
                    "reconcile-conflict",
                    "existing-unaudited",
                    "retained",
                    "manual-audit",
                    "legacy publication marker is unverifiable",
                ],
            ),
            (
                RepositoryReconcileTerminal::ReservedConflict,
                [
                    "reserved-conflict",
                    "existing-unattributed",
                    "reconcile-conflict",
                    "existing-unaudited",
                    "retained",
                    "manual-audit",
                    "publication marker namespace conflicts",
                ],
            ),
            (
                RepositoryReconcileTerminal::V2Invalid,
                [
                    "v2-invalid",
                    "existing-unattributed",
                    "reconcile-conflict",
                    "existing-unaudited",
                    "retained",
                    "manual-audit",
                    "publication marker is invalid",
                ],
            ),
            (
                RepositoryReconcileTerminal::V2ClaimRejected,
                [
                    "v2-exact",
                    "publication-indeterminate",
                    "reconcile-conflict",
                    "existing-unaudited",
                    "retained",
                    "manual-audit",
                    "publication claim failed audit",
                ],
            ),
            (
                RepositoryReconcileTerminal::DurabilityIndeterminate,
                [
                    "v2-exact",
                    "existing-published",
                    "indeterminate",
                    "existing-audited",
                    "retained",
                    "publication-reconcile",
                    "publication durability is indeterminate",
                ],
            ),
            (
                RepositoryReconcileTerminal::MarkerRetained,
                [
                    "v2-exact",
                    "existing-published",
                    "durable-with-marker",
                    "existing-audited",
                    "retained",
                    "publication-reconcile",
                    "publication marker remains",
                ],
            ),
            (
                RepositoryReconcileTerminal::MarkerReplaced,
                [
                    "marker-replaced",
                    "existing-published",
                    "indeterminate",
                    "existing-audited",
                    "replacement-retained",
                    "manual-audit",
                    "publication marker was replaced",
                ],
            ),
            (
                RepositoryReconcileTerminal::MarkerPostStateIndeterminate,
                [
                    "marker-poststate-indeterminate",
                    "existing-published",
                    "indeterminate",
                    "existing-audited",
                    "indeterminate",
                    "manual-audit",
                    "publication marker post-state is indeterminate",
                ],
            ),
            (
                RepositoryReconcileTerminal::PostUnlinkAbsentIndeterminate,
                [
                    "post-unlink-absent-indeterminate",
                    "existing-published",
                    "indeterminate",
                    "existing-audited",
                    "indeterminate",
                    "publication-reconcile",
                    "post-unlink publication state is indeterminate",
                ],
            ),
        ];
        for (terminal, expected) in cases {
            assert_eq!(terminal.fields(), expected);
            assert_eq!(terminal.result(), expected[6]);
        }
    }

    #[test]
    fn reconcile_classification_and_failure_routing_are_exhaustive() {
        use inex_git::RepositoryCandidatePublicationFailureKind as Failure;

        let namespace_cases = [
            (
                Err(inex_core::atomic::RepositoryPublicationNamespaceInspectionError),
                RepositoryReconcileMarkerState::ReservedInspectionIndeterminate,
            ),
            (
                Ok(RepositoryPublicationNamespaceState::Absent),
                RepositoryReconcileMarkerState::Absent,
            ),
            (
                Ok(RepositoryPublicationNamespaceState::LegacyUnverifiable),
                RepositoryReconcileMarkerState::LegacyUnverifiable,
            ),
            (
                Ok(RepositoryPublicationNamespaceState::ReservedConflict),
                RepositoryReconcileMarkerState::ReservedConflict,
            ),
            (
                Ok(RepositoryPublicationNamespaceState::V2Invalid),
                RepositoryReconcileMarkerState::V2Invalid,
            ),
            (
                Ok(RepositoryPublicationNamespaceState::V2Exact),
                RepositoryReconcileMarkerState::V2Exact,
            ),
        ];
        for (state, expected) in namespace_cases {
            assert_eq!(reconcile_marker_state(state), expected);
            assert_eq!(
                marker_state_terminal(expected).is_none(),
                expected == RepositoryReconcileMarkerState::V2Exact
            );
        }

        let failure_cases = [
            (
                Failure::UnsupportedPlatform,
                RepositoryReconcileTerminal::V2ClaimRejected,
            ),
            (
                Failure::InitialAuthorityRejected,
                RepositoryReconcileTerminal::V2ClaimRejected,
            ),
            (
                Failure::InitialClaimRejected,
                RepositoryReconcileTerminal::V2ClaimRejected,
            ),
            (
                Failure::ExistingClaimRejected,
                RepositoryReconcileTerminal::V2ClaimRejected,
            ),
            (
                Failure::InitialPublicationNotMoved,
                RepositoryReconcileTerminal::V2ClaimRejected,
            ),
            (
                Failure::DestinationExists,
                RepositoryReconcileTerminal::V2ClaimRejected,
            ),
            (
                Failure::PublicationIndeterminate,
                RepositoryReconcileTerminal::V2ClaimRejected,
            ),
            (
                Failure::InitialPublicationRejected,
                RepositoryReconcileTerminal::V2ClaimRejected,
            ),
            (
                Failure::PublicationDurabilityIndeterminate,
                RepositoryReconcileTerminal::DurabilityIndeterminate,
            ),
            (
                Failure::PublicationDurabilityRejected,
                RepositoryReconcileTerminal::DurabilityIndeterminate,
            ),
            (
                Failure::PublicationMarkerRetained,
                RepositoryReconcileTerminal::MarkerRetained,
            ),
            (
                Failure::PublicationMarkerReplaced,
                RepositoryReconcileTerminal::MarkerReplaced,
            ),
            (
                Failure::PublicationMarkerPostStateIndeterminate,
                RepositoryReconcileTerminal::MarkerPostStateIndeterminate,
            ),
            (
                Failure::PostUnlinkIndeterminate,
                RepositoryReconcileTerminal::PostUnlinkAbsentIndeterminate,
            ),
            (
                Failure::CleanAuditRejected,
                RepositoryReconcileTerminal::PostUnlinkAbsentIndeterminate,
            ),
        ];
        for (failure, expected) in failure_cases {
            assert_eq!(reconciliation_terminal(failure), expected);
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source-contract test freezes the complete publication seam"
    )]
    fn production_source_freezes_audited_owner_and_v2_publication_seam() {
        let source = include_str!("repository_import.rs");
        let production = source
            .split_once("\n#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        let execute = production
            .split_once("pub(crate) fn execute(")
            .and_then(|(_, tail)| tail.split_once("\npub(crate) fn execute_reconcile("))
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
        let owner_opened = position("let IndependentlyAuditedVault { vault, warnings }");
        let v2_publish = position("inex_git::publish_initial_repository_candidate(");
        assert!(
            build < git
                && git < git_audit
                && git_audit < git_durable
                && git_durable < fresh_audit
                && fresh_audit < password_drop
                && password_drop < terminal_audited
                && terminal_audited < owner_opened
                && owner_opened < v2_publish
        );
        assert!(production.contains("password: Zeroizing<Vec<u8>>"));
        assert_eq!(production.matches("Vault::unlock(").count(), 1);
        assert!(production.contains("\nstruct IndependentlyAuditedVault {"));
        assert!(!production.contains("acquire_initial_candidate_authority"));
        assert!(!production.contains("IMPORT_PUBLISH_MARKER_V2"));
        assert!(!production.contains("atomic_publish_directory_no_replace_checked"));
        assert!(!production.contains("into_warnings_before_legacy_publication"));

        let dispatch = production
            .split_once("pub(crate) fn dispatch(")
            .and_then(|(_, tail)| tail.split_once("\nfn plan_creation("))
            .map_or_else(
                || panic!("dispatch source boundary changed"),
                |(dispatch, _)| dispatch,
            );
        let path_source = dispatch
            .find("resolve_source_root(source_repository)")
            .expect("source path normalization exists");
        let path_destination = dispatch
            .find("DestinationPlan::resolve(destination)")
            .expect("destination path normalization exists");
        let existing = dispatch.find("if exists").expect("existing branch exists");
        let reserved = dispatch
            .find("inspect_repository_publication_namespace(&destination.path)")
            .expect("reserved namespace routing exists");
        let source_git = dispatch
            .find("inex_git::plan_source_repository(&source_root)")
            .expect("creation source planning exists");
        assert!(
            path_source < path_destination
                && path_destination < existing
                && existing < reserved
                && reserved < source_git
        );
        for forbidden in ["password", "Vault::", "calibrated_creation_params", "Kdf"] {
            assert!(
                !dispatch.contains(forbidden),
                "path-first dispatch gained forbidden work: {forbidden}"
            );
        }

        let reconcile = production
            .split_once("pub(crate) fn execute_reconcile(")
            .and_then(|(_, tail)| tail.split_once("\nfn build_staging_vault("))
            .map_or_else(
                || panic!("execute_reconcile source boundary changed"),
                |(reconcile, _)| reconcile,
            );
        let dry_run_branch = reconcile.find("if dry_run").expect("dry-run branch exists");
        let preview = reconcile
            .find("inex_git::preview_existing_repository_candidate(")
            .expect("dry-run uses the read-only preview");
        let mutation = reconcile
            .find("inex_git::reconcile_existing_repository_candidate(")
            .expect("normal execution uses reconciliation");
        assert!(dry_run_branch < preview && preview < mutation);
        for forbidden in ["plan_source_repository", "password", "Vault::", "Kdf"] {
            assert!(
                !reconcile.contains(forbidden),
                "target-only reconciliation gained forbidden work: {forbidden}"
            );
        }

        let cli = include_str!("lib.rs");
        assert!(cli.contains("repository_import::execute(plan, password, created_at_ms"));
        assert!(!cli.contains("repository_import::execute(plan, password.as_slice()"));
        let command = cli
            .split("fn command_repository_import_create(")
            .nth(1)
            .and_then(|tail| tail.split("fn print_repository_import_success(").next())
            .expect("repository-import command exists");
        let failure_output = command
            .rfind("print_repository_import_terminal(failure.terminal())")
            .expect("failure terminal output exists");
        let failure_flush = command[failure_output..]
            .find("io::stdout().flush()")
            .map(|offset| offset + failure_output)
            .expect("failure output flush exists");
        let failure_drop = command
            .find("failure.into_error()")
            .expect("failure owner is consumed");
        assert!(failure_output < failure_flush && failure_flush < failure_drop);
        let success_output = command
            .find("print_repository_import_success(&report)")
            .expect("success output exists");
        let success_flush = command[success_output..]
            .find("io::stdout()")
            .map(|offset| offset + success_output)
            .expect("success output flush exists");
        assert!(success_output < success_flush);

        let reconcile_command = cli
            .split("fn command_repository_reconcile(")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn format_repository_reconcile_terminal(")
                    .next()
            })
            .expect("repository reconcile command exists");
        let failure_format = reconcile_command
            .find("format_repository_reconcile_terminal(failure.terminal())")
            .expect("reconcile failure formats one block");
        let failure_write = reconcile_command
            .find("write_repository_reconcile_output(&output)")
            .expect("reconcile failure writes one block");
        let failure_drop = reconcile_command
            .find("failure.into_error()")
            .expect("reconcile failure owner is consumed");
        assert!(failure_format < failure_write && failure_write < failure_drop);
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

        #[test]
        fn path_only_disjointness_scan_detects_nested_physical_identity() {
            let temporary = TestDirectory::new("disjointness-identity");
            let source = temporary.path().join("source");
            let nested = source.join("notes").join("images");
            let outside = temporary.path().join("outside");
            fs::create_dir_all(&nested)
                .unwrap_or_else(|error| panic!("nested directory creation failed: {error}"));
            fs::create_dir(&outside)
                .unwrap_or_else(|error| panic!("outside directory creation failed: {error}"));
            let regular = source.join("regular.bin");
            fs::write(&regular, b"non-directory entries are not opened")
                .unwrap_or_else(|error| panic!("regular file creation failed: {error}"));
            fs::hard_link(&regular, source.join("hardlink.bin"))
                .unwrap_or_else(|error| panic!("hardlink creation failed: {error}"));
            std::os::unix::fs::symlink("regular.bin", source.join("symlink.bin"))
                .unwrap_or_else(|error| panic!("symlink creation failed: {error}"));
            let source_identity = filesystem_directory_identity(&source)
                .unwrap_or_else(|error| panic!("source identity failed: {error}"));
            let nested_identity = filesystem_directory_identity(&nested)
                .unwrap_or_else(|error| panic!("nested identity failed: {error}"));
            let outside_identity = filesystem_directory_identity(&outside)
                .unwrap_or_else(|error| panic!("outside identity failed: {error}"));

            assert!(
                source_tree_contains_directory_identity(
                    &source,
                    &source_identity,
                    &[nested_identity],
                )
                .unwrap_or_else(|error| panic!("nested scan failed: {error}"))
            );
            assert!(
                !source_tree_contains_directory_identity(
                    &source,
                    &source_identity,
                    &[outside_identity],
                )
                .unwrap_or_else(|error| panic!("outside scan failed: {error}"))
            );
        }

        #[test]
        fn non_v2_reconcile_detects_same_class_destination_replacement() {
            let temporary = TestDirectory::new("reconcile-replaced-absent");
            let source = temporary.path().join("source");
            let destination = temporary.path().join("existing-vault");
            let retained = temporary.path().join("retained-original");
            fs::create_dir(&source)
                .unwrap_or_else(|error| panic!("source creation failed: {error}"));
            fs::write(source.join("note.md"), b"source canary\n")
                .unwrap_or_else(|error| panic!("source canary failed: {error}"));
            fs::create_dir(&destination)
                .unwrap_or_else(|error| panic!("destination creation failed: {error}"));
            fs::write(destination.join("original.bin"), b"original")
                .unwrap_or_else(|error| panic!("original canary failed: {error}"));

            let request = match dispatch(&source, &destination)
                .unwrap_or_else(|error| panic!("dispatch failed: {error}"))
            {
                RepositoryImportDispatch::Existing(request) => request,
                RepositoryImportDispatch::Creation(_) => {
                    panic!("existing destination routed to creation")
                }
            };
            fs::rename(&destination, &retained)
                .unwrap_or_else(|error| panic!("original retention failed: {error}"));
            fs::create_dir(&destination)
                .unwrap_or_else(|error| panic!("replacement creation failed: {error}"));
            fs::write(destination.join("replacement.bin"), b"replacement")
                .unwrap_or_else(|error| panic!("replacement canary failed: {error}"));

            let terminal = match execute_reconcile(&request, false) {
                Err(failure) => failure.terminal(),
                Ok(_) => panic!("replaced destination unexpectedly reconciled"),
            };
            assert_eq!(
                terminal,
                RepositoryReconcileTerminal::ReservedInspectionIndeterminate
            );
            assert_eq!(
                fs::read(retained.join("original.bin"))
                    .unwrap_or_else(|error| panic!("original canary read failed: {error}")),
                b"original"
            );
            assert_eq!(
                fs::read(destination.join("replacement.bin"))
                    .unwrap_or_else(|error| panic!("replacement canary read failed: {error}")),
                b"replacement"
            );
            assert!(
                !retained
                    .join(inex_core::atomic::VAULT_LOCAL_DIRECTORY)
                    .exists()
            );
            assert!(
                !destination
                    .join(inex_core::atomic::VAULT_LOCAL_DIRECTORY)
                    .exists()
            );
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
            let plan = match dispatch(&source, &destination)
                .unwrap_or_else(|error| panic!("repository dispatch failed: {error}"))
            {
                RepositoryImportDispatch::Creation(plan) => *plan,
                RepositoryImportDispatch::Existing(_) => {
                    panic!("fresh fixture unexpectedly routed to reconcile")
                }
            };
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

            let IndependentlyAuditedVault { vault, warnings } = audited;
            assert_eq!(warnings.len(), 1);
            inex_git::audit_repository_import_target(staging.path(), &target)
                .unwrap_or_else(|error| panic!("target audit changed: {error}"));
            drop(vault);
        }

        #[test]
        fn v2_published_owner_retains_the_mutation_lock_until_acknowledgement() {
            use inex_core::atomic::{
                ExistingVaultMutationLock, ExistingVaultMutationLockError,
                IMPORT_PUBLISH_MARKER_V1, IMPORT_PUBLISH_MARKER_V2, VAULT_LOCAL_DIRECTORY,
                VAULT_MUTATION_LOCK_FILE, filesystem_directory_identity, filesystem_file_identity,
            };

            let (_temporary, plan) = fixture("v2-owner-lock");
            let (staging, target) = build_git_candidate(&plan);
            let audited = unlock_and_independently_audit_staging_vault(&plan, &staging, PASSWORD)
                .unwrap_or_else(|error| panic!("fresh audit failed: {error}"));
            let IndependentlyAuditedVault { vault, warnings } = audited;
            assert_eq!(warnings.len(), 1);
            let destination_name = plan
                .destination
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_else(|| panic!("destination name is not UTF-8"));
            let expected_profile = if plan.asset_files == 0 {
                VaultContentProfile::DocumentsOnly
            } else {
                VaultContentProfile::OpaqueAssetsV1
            };
            let root_identity = filesystem_directory_identity(staging.path())
                .unwrap_or_else(|error| panic!("staging root identity failed: {error}"));
            let local = staging.path().join(VAULT_LOCAL_DIRECTORY);
            let local_identity = filesystem_directory_identity(&local)
                .unwrap_or_else(|error| panic!("staging local identity failed: {error}"));
            let lock_file = fs::File::open(local.join(VAULT_MUTATION_LOCK_FILE))
                .unwrap_or_else(|error| panic!("staging lock open failed: {error}"));
            let lock_identity = filesystem_file_identity(&lock_file)
                .unwrap_or_else(|error| panic!("staging lock identity failed: {error}"));
            drop(lock_file);
            let published = inex_git::publish_initial_repository_candidate(
                staging.path(),
                &target,
                &vault,
                expected_profile,
                &plan.destination.parent_identity,
                destination_name,
            )
            .unwrap_or_else(|error| panic!("v2 publication failed: {error:?}"));
            drop(vault);

            assert_eq!(
                published.encrypted_markdown(),
                u32::try_from(plan.markdown_files)
                    .unwrap_or_else(|_| panic!("Markdown count exceeds u32"))
            );
            assert_eq!(
                published.encrypted_assets(),
                u32::try_from(plan.asset_files)
                    .unwrap_or_else(|_| panic!("asset count exceeds u32"))
            );
            assert_eq!(published.root_commit_oid(), target.root_commit_oid());
            let debug = format!("{published:?}");
            assert!(debug.contains("root_commit_oid: \"[REDACTED]\""));
            assert!(!debug.contains(target.root_commit_oid()));
            assert!(!debug.contains(&plan.destination.path.to_string_lossy().into_owned()));
            for marker in [IMPORT_PUBLISH_MARKER_V1, IMPORT_PUBLISH_MARKER_V2] {
                assert!(
                    !plan
                        .destination
                        .path
                        .join(VAULT_LOCAL_DIRECTORY)
                        .join(marker)
                        .exists()
                );
            }
            assert!(matches!(
                ExistingVaultMutationLock::acquire(
                    &plan.destination.path,
                    &root_identity,
                    &local_identity,
                    &lock_identity,
                ),
                Err(ExistingVaultMutationLockError::Busy)
            ));
            drop(published);
            let guard = ExistingVaultMutationLock::acquire(
                &plan.destination.path,
                &root_identity,
                &local_identity,
                &lock_identity,
            )
            .unwrap_or_else(|error| panic!("lock was not released after owner drop: {error}"));
            drop(guard);
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
