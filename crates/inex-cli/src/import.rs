//! Bounded, copy-only plaintext import through a complete encrypted staging vault.
//!
//! The final vault must be absent. Planning streams the source tree, records
//! exact digests, rejects namespace/mount hazards, and performs no writes.
//! Commit creates a clearly named sibling staging vault, verifies every
//! encrypted document, re-unlocks the complete vault, and only then publishes
//! it with a platform no-replace directory rename. The plaintext source is
//! never opened for writing, renamed, or removed.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use inex_core::atomic::{
    AtomicDirectoryPublishError, FilesystemDirectoryIdentity, IMPORT_PUBLISH_MARKER,
    IMPORT_STAGING_PREFIX, ParentSyncStatus, VAULT_LOCAL_DIRECTORY, VAULT_MUTATION_LOCK_FILE,
    atomic_publish_directory_no_replace_checked, filesystem_directory_identity,
    path_is_supported_local_filesystem,
};
use inex_core::format::{self, MAX_PLAINTEXT_LEN};
use inex_core::path::{LogicalDir, LogicalPath};
use inex_core::search::{MAX_SEARCH_DOCUMENTS, MAX_SEARCH_INDEX_BYTES};
use inex_core::tree::{
    DEFAULT_MAX_TREE_DEPTH, DEFAULT_MAX_TREE_ENTRIES, DEFAULT_MAX_TREE_PATH_BYTES, TreeEntryKind,
};
use inex_core::vault::Vault;
use inex_core::vault_config::ConfigWarning;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use inex_core::atomic::{
    SecureSourceChild, SecureSourceDirectory, SecureSourceFile, open_secure_source_root,
};

#[cfg(not(target_os = "linux"))]
use std::fs::{DirEntry, OpenOptions};

#[cfg(not(target_os = "linux"))]
use inex_core::atomic::open_file_matches_path_and_is_single_link;

const MAX_IMPORT_ENTRIES: usize = DEFAULT_MAX_TREE_ENTRIES;
const MAX_IMPORT_FILES: usize = MAX_SEARCH_DOCUMENTS;
const MAX_IMPORT_DEPTH: usize = DEFAULT_MAX_TREE_DEPTH;
const MAX_IMPORT_PATH_BYTES: usize = DEFAULT_MAX_TREE_PATH_BYTES;
const MAX_IMPORT_PLAINTEXT_BYTES: usize = MAX_SEARCH_INDEX_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImportIoOperation {
    ResolveSource,
    ResolveTarget,
    InspectSource,
    ReadSource,
}

impl fmt::Display for ImportIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResolveSource => "resolving the plaintext source",
            Self::ResolveTarget => "resolving the absent destination",
            Self::InspectSource => "inspecting the plaintext source",
            Self::ReadSource => "reading bounded Markdown source data",
        })
    }
}

#[derive(Debug)]
pub(crate) enum ImportError {
    EmptySourcePath,
    InvalidTargetPath,
    TargetExists,
    TargetParentChanged,
    UnsupportedTargetFilesystem,
    SourceVaultOverlap,
    UnsafeSourceRoot,
    UnsafeSourceEntry,
    SourceMountBoundary,
    NonUtf8SourcePath,
    InvalidLogicalPath,
    SourcePathCollision,
    PhysicalPathCollision,
    EntryLimitExceeded,
    FileLimitExceeded,
    DepthLimitExceeded,
    PathByteLimitExceeded,
    TargetEntryLimitExceeded,
    TargetPathByteLimitExceeded,
    FileTooLarge,
    TotalPlaintextLimitExceeded,
    InvalidMarkdownUtf8,
    SourceChanged,
    StagingCreateFailed,
    StagingIdentityChanged,
    StagingUnexpectedEntry,
    StagingVerificationFailed,
    PublishDestinationExists,
    PublishIndeterminate,
    PublishedCleanupFailed,
    PublishFailed,
    Io {
        operation: ImportIoOperation,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptySourcePath => "plaintext source path is empty",
            Self::InvalidTargetPath => "destination must name one absent child of an existing safe parent directory",
            Self::TargetExists => "copy import requires a completely absent destination vault",
            Self::TargetParentChanged => "destination parent identity changed after planning; final destination was not published",
            Self::UnsupportedTargetFilesystem => "destination filesystem cannot guarantee local atomic publication",
            Self::SourceVaultOverlap => "plaintext source and destination/staging location overlap by path or directory identity",
            Self::UnsafeSourceRoot => "plaintext source root or one of its ancestors is not a safe regular directory",
            Self::UnsafeSourceEntry => "plaintext source contains a link, reparse point, hard-linked file, or special entry",
            Self::SourceMountBoundary => "plaintext source crosses a filesystem mount boundary",
            Self::NonUtf8SourcePath => "an imported source path is not valid UTF-8",
            Self::InvalidLogicalPath => "Markdown source path cannot be normalized to the portable logical-path profile",
            Self::SourcePathCollision => "plaintext source paths collide after Unicode normalization or portable case folding",
            Self::PhysicalPathCollision => "planned ciphertext file and directory names collide on a portable filesystem",
            Self::EntryLimitExceeded => "plaintext source exceeds the import entry limit",
            Self::FileLimitExceeded => "plaintext source exceeds the import Markdown-file limit",
            Self::DepthLimitExceeded => "plaintext source exceeds the import directory-depth limit",
            Self::PathByteLimitExceeded => "plaintext source or observed staging vault exceeds the path-byte budget",
            Self::TargetEntryLimitExceeded => "complete staging vault would exceed the physical entry budget",
            Self::TargetPathByteLimitExceeded => "complete staging vault would exceed the physical path-byte budget",
            Self::FileTooLarge => "a Markdown source file exceeds the per-file plaintext limit",
            Self::TotalPlaintextLimitExceeded => "plaintext source exceeds the cumulative import byte limit",
            Self::InvalidMarkdownUtf8 => "a Markdown source file is not valid UTF-8",
            Self::SourceChanged => "plaintext source changed during import; final destination was not published",
            Self::StagingCreateFailed => "encrypted staging vault creation failed; final destination was not published and any created staging directory is retained",
            Self::StagingIdentityChanged => "encrypted staging root identity changed; final destination was not published",
            Self::StagingUnexpectedEntry => "encrypted staging vault contains a missing, unexpected, link-like, hard-linked, or wrong-kind physical entry",
            Self::StagingVerificationFailed => "complete encrypted staging vault verification failed; final destination was not published and staging is retained",
            Self::PublishDestinationExists => "destination appeared before publication; it was not replaced and encrypted staging is retained",
            Self::PublishIndeterminate => "atomic publication outcome is indeterminate; no replacement fallback was attempted",
            Self::PublishedCleanupFailed => "final vault was published, but cleanup of its private ciphertext-only publication marker failed; do not rerun into the same destination",
            Self::PublishFailed => "atomic publication failed; final destination was not published and encrypted staging is retained",
            Self::Io { .. } => return match self {
                Self::Io { operation, kind } => write!(formatter, "I/O failed while {operation}: {kind:?}"),
                _ => unreachable!(),
            },
        })
    }
}

impl std::error::Error for ImportError {}

#[derive(Clone, Eq, PartialEq)]
struct PlannedDirectory {
    source_relative: PathBuf,
    logical: LogicalDir,
}

#[derive(Clone, Eq, PartialEq)]
struct PlannedFile {
    source_relative: PathBuf,
    logical: LogicalPath,
    plaintext_bytes: usize,
    digest: [u8; 32],
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ImportPlan {
    source_root: PathBuf,
    destination: PathBuf,
    destination_parent: PathBuf,
    destination_parent_identity: Option<FilesystemDirectoryIdentity>,
    directories: Vec<PlannedDirectory>,
    files: Vec<PlannedFile>,
    inspected_entries: usize,
    total_plaintext_bytes: usize,
    skipped_non_markdown: usize,
    normalized_entries: usize,
    source_directory_identities: BTreeSet<FilesystemDirectoryIdentity>,
}

impl fmt::Debug for ImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportPlan")
            .field("source_root", &"[REDACTED]")
            .field("destination", &"[REDACTED]")
            .field("directories", &self.directories.len())
            .field("files", &self.files.len())
            .field("inspected_entries", &self.inspected_entries)
            .field("total_plaintext_bytes", &self.total_plaintext_bytes)
            .field("skipped_non_markdown", &self.skipped_non_markdown)
            .field("normalized_entries", &self.normalized_entries)
            .finish_non_exhaustive()
    }
}

impl ImportPlan {
    pub(crate) fn directory_count(&self) -> usize {
        self.directories.len()
    }
    pub(crate) fn file_count(&self) -> usize {
        self.files.len()
    }
    pub(crate) const fn inspected_entries(&self) -> usize {
        self.inspected_entries
    }
    pub(crate) const fn total_plaintext_bytes(&self) -> usize {
        self.total_plaintext_bytes
    }
    pub(crate) const fn skipped_non_markdown(&self) -> usize {
        self.skipped_non_markdown
    }
    pub(crate) const fn normalized_entries(&self) -> usize {
        self.normalized_entries
    }
    fn revalidate_target(&self) -> Result<(), ImportError> {
        let parent = fs::canonicalize(&self.destination_parent)
            .map_err(|error| io_error(ImportIoOperation::ResolveTarget, &error))?;
        let current_identity = directory_identity(&parent)?;
        if parent != self.destination_parent
            || self.destination_parent_identity.as_ref() != Some(&current_identity)
        {
            return Err(ImportError::TargetParentChanged);
        }
        if self.source_directory_identities.contains(&current_identity) {
            return Err(ImportError::SourceVaultOverlap);
        }
        reject_existing_destination(&self.destination)
    }
}

pub(crate) struct StagingRoot {
    path: PathBuf,
    identity: FilesystemDirectoryIdentity,
}

impl fmt::Debug for StagingRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagingRoot")
            .field("path", &"[REDACTED]")
            .field("identity", &self.identity)
            .finish()
    }
}

impl StagingRoot {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn validate(&self, plan: &ImportPlan) -> Result<(), ImportError> {
        if self.path.parent() != Some(plan.destination_parent.as_path())
            || !self
                .path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with(IMPORT_STAGING_PREFIX))
            || directory_identity(&self.path)? != self.identity
        {
            return Err(ImportError::StagingIdentityChanged);
        }
        Ok(())
    }
}

pub(crate) struct StagingSeal {
    root_identity: FilesystemDirectoryIdentity,
    file_digests: BTreeMap<PathBuf, [u8; 32]>,
}

impl fmt::Debug for StagingSeal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagingSeal")
            .field("root_identity", &self.root_identity)
            .field("sealed_files", &self.file_digests.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImportSummary {
    pub(crate) committed_directories: usize,
    pub(crate) committed_files: usize,
    pub(crate) unconfirmed_file_syncs: usize,
    pub(crate) publish_parent_sync: ParentSyncStatus,
}

pub(crate) fn scan_source(source: &Path, destination: &Path) -> Result<ImportPlan, ImportError> {
    let source_root = resolve_source_root(source)?;
    let (destination, destination_parent) = resolve_absent_target(destination)?;
    ensure_disjoint(&source_root, &destination)?;
    let mut plan = scan_resolved_source(source_root)?;
    let parent_identity = directory_identity(&destination_parent)?;
    if plan.source_directory_identities.contains(&parent_identity) {
        return Err(ImportError::SourceVaultOverlap);
    }
    plan.destination = destination;
    plan.destination_parent = destination_parent;
    plan.destination_parent_identity = Some(parent_identity);
    validate_planned_staging_budget(&plan)?;
    Ok(plan)
}

/// Atomically reserve a fresh, empty staging root without ever accepting a
/// pre-existing directory. The caller may reveal the random name only after
/// this function succeeds.
pub(crate) fn create_staging_root(plan: &ImportPlan) -> Result<StagingRoot, ImportError> {
    plan.revalidate_target()?;
    for _ in 0..32 {
        let path = plan.destination_parent.join(format!(
            "{IMPORT_STAGING_PREFIX}{}",
            Uuid::new_v4().simple()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                restrict_directory_permissions_best_effort(&path);
                let identity = directory_identity(&path)?;
                return Ok(StagingRoot { path, identity });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ImportError::StagingCreateFailed),
        }
    }
    Err(ImportError::StagingCreateFailed)
}

/// Populate and authenticate a caller-created empty staging vault.
pub(crate) fn populate_staging(
    plan: &ImportPlan,
    staging_root: &StagingRoot,
    vault: &mut Vault,
    modified_at_ms: i64,
) -> Result<ImportSummary, ImportError> {
    plan.revalidate_target()?;
    let staging = vault.root();
    staging_root.validate(plan)?;
    if staging != staging_root.path() {
        return Err(ImportError::StagingVerificationFailed);
    }
    ensure_source_unchanged(plan)?;

    let mut summary = ImportSummary {
        committed_directories: 0,
        committed_files: 0,
        unconfirmed_file_syncs: 0,
        publish_parent_sync: ParentSyncStatus::NotSynced,
    };
    for directory in &plan.directories {
        vault
            .create_directory(&directory.logical)
            .map_err(|_| ImportError::StagingVerificationFailed)?;
        summary.committed_directories += 1;
    }
    for planned in &plan.files {
        let plaintext = read_planned_file(plan, planned)?;
        let committed = vault
            .create_document(&planned.logical, plaintext.as_slice(), modified_at_ms)
            .map_err(|_| ImportError::StagingVerificationFailed)?;
        drop(plaintext);
        summary.committed_files += 1;
        if committed.parent_sync == ParentSyncStatus::NotSynced {
            summary.unconfirmed_file_syncs += 1;
        }
        verify_document(vault, planned)?;
    }
    verify_observed_tree(vault, plan)?;
    audit_staging_allowlist(plan, staging_root, false)?;
    ensure_source_unchanged(plan)?;
    Ok(summary)
}

pub(crate) fn verify_reopened_staging(
    plan: &ImportPlan,
    staging_root: &StagingRoot,
    vault: &mut Vault,
) -> Result<(Vec<ConfigWarning>, StagingSeal), ImportError> {
    staging_root.validate(plan)?;
    if vault.root() != staging_root.path() {
        return Err(ImportError::StagingVerificationFailed);
    }
    verify_observed_tree(vault, plan)?;
    for file in &plan.files {
        verify_document(vault, file)?;
    }
    audit_staging_allowlist(plan, staging_root, false)?;
    ensure_source_unchanged(plan)?;
    let seal = seal_staging(plan, staging_root)?;
    Ok((vault.warnings().to_vec(), seal))
}

pub(crate) fn publish_staging(
    plan: &ImportPlan,
    staging: &StagingRoot,
    seal: &StagingSeal,
) -> Result<ParentSyncStatus, ImportError> {
    verify_staging_seal(plan, staging, seal, false)?;
    ensure_source_unchanged(plan)?;
    plan.revalidate_target()?;
    staging.validate(plan)?;
    atomic_publish_directory_no_replace_checked(staging.path(), &plan.destination, |_| {
        verify_staging_seal(plan, staging, seal, true)
            .map_err(|_| io::Error::other("critical staging allowlist audit failed"))
    })
    .map(|outcome| outcome.parent_sync)
    .map_err(|error| match error {
        AtomicDirectoryPublishError::DestinationExists => ImportError::PublishDestinationExists,
        AtomicDirectoryPublishError::Indeterminate => ImportError::PublishIndeterminate,
        AtomicDirectoryPublishError::PublishedCleanupFailed => ImportError::PublishedCleanupFailed,
        AtomicDirectoryPublishError::InvalidPaths
        | AtomicDirectoryPublishError::NotMoved
        | AtomicDirectoryPublishError::Io { .. } => ImportError::PublishFailed,
    })
}

fn read_planned_file(
    plan: &ImportPlan,
    planned: &PlannedFile,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    #[cfg(target_os = "linux")]
    let plaintext =
        read_secure_relative_markdown_file(&plan.source_root, &planned.source_relative)?;
    #[cfg(not(target_os = "linux"))]
    let plaintext = read_markdown_file(&plan.source_root.join(&planned.source_relative))?;
    if plaintext.len() != planned.plaintext_bytes
        || format::etag_digest(plaintext.as_slice()) != planned.digest
    {
        return Err(ImportError::SourceChanged);
    }
    Ok(plaintext)
}

#[cfg(target_os = "linux")]
fn read_secure_relative_markdown_file(
    root: &Path,
    relative: &Path,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let root = open_secure_source_root(root)
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    let mut directories = vec![root];
    let mut components = relative.components().peekable();
    let mut file = None;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(ImportError::InvalidLogicalPath);
        };
        let child = directories
            .last()
            .ok_or(ImportError::SourceChanged)?
            .open_child(name)
            .map_err(|_| ImportError::SourceChanged)?;
        if components.peek().is_some() {
            let SecureSourceChild::Directory(directory) = child else {
                return Err(ImportError::SourceChanged);
            };
            directories.push(directory);
        } else {
            let SecureSourceChild::File(opened) = child else {
                return Err(ImportError::SourceChanged);
            };
            file = Some(opened);
        }
    }
    let plaintext = read_secure_markdown_file(file.ok_or(ImportError::SourceChanged)?)?;
    for directory in directories.iter().rev() {
        directory
            .verify_binding()
            .map_err(|_| ImportError::SourceChanged)?;
    }
    Ok(plaintext)
}

fn verify_document(vault: &mut Vault, planned: &PlannedFile) -> Result<(), ImportError> {
    let opened = vault
        .read(&planned.logical)
        .map_err(|_| ImportError::StagingVerificationFailed)?;
    let valid = opened.plaintext.len() == planned.plaintext_bytes
        && format::etag_digest(opened.plaintext.as_slice()) == planned.digest;
    drop(opened);
    if valid {
        Ok(())
    } else {
        Err(ImportError::StagingVerificationFailed)
    }
}

fn verify_observed_tree(vault: &mut Vault, plan: &ImportPlan) -> Result<(), ImportError> {
    // `Vault::list` performs a fresh bounded physical enumeration. Comparing
    // its exact output to the plan turns the real observed staging namespace,
    // rather than an arithmetic estimate, into the publication gate.
    let tree = vault
        .list()
        .map_err(|_| ImportError::StagingVerificationFailed)?;
    if tree.len() != plan.directories.len().saturating_add(plan.files.len()) {
        return Err(ImportError::StagingVerificationFailed);
    }
    let expected_directories = plan
        .directories
        .iter()
        .map(|entry| entry.logical.as_str())
        .collect::<BTreeSet<_>>();
    let expected_files = plan
        .files
        .iter()
        .map(|entry| entry.logical.as_str())
        .collect::<BTreeSet<_>>();
    for entry in tree.entries() {
        let expected = match entry.kind() {
            TreeEntryKind::Directory => &expected_directories,
            TreeEntryKind::File => &expected_files,
            TreeEntryKind::Asset => return Err(ImportError::StagingVerificationFailed),
        };
        if !expected.contains(entry.logical_path()) {
            return Err(ImportError::StagingVerificationFailed);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedStagingKind {
    Directory,
    File,
}

fn expected_staging_entries(
    plan: &ImportPlan,
    marker_allowed: bool,
) -> Result<BTreeMap<PathBuf, ExpectedStagingKind>, ImportError> {
    let mut expected = BTreeMap::new();
    let required = [
        (PathBuf::from("vault.json"), ExpectedStagingKind::File),
        (
            PathBuf::from(VAULT_LOCAL_DIRECTORY),
            ExpectedStagingKind::Directory,
        ),
        (
            PathBuf::from(VAULT_LOCAL_DIRECTORY).join(VAULT_MUTATION_LOCK_FILE),
            ExpectedStagingKind::File,
        ),
    ];
    for (path, kind) in required {
        if expected.insert(path, kind).is_some() {
            return Err(ImportError::StagingUnexpectedEntry);
        }
    }
    for directory in &plan.directories {
        if expected
            .insert(
                PathBuf::from(directory.logical.as_str()),
                ExpectedStagingKind::Directory,
            )
            .is_some()
        {
            return Err(ImportError::PhysicalPathCollision);
        }
    }
    for file in &plan.files {
        if expected
            .insert(
                file.logical.to_ciphertext_relative_path(),
                ExpectedStagingKind::File,
            )
            .is_some()
        {
            return Err(ImportError::PhysicalPathCollision);
        }
    }
    if marker_allowed
        && expected
            .insert(
                PathBuf::from(VAULT_LOCAL_DIRECTORY).join(IMPORT_PUBLISH_MARKER),
                ExpectedStagingKind::File,
            )
            .is_some()
    {
        return Err(ImportError::StagingUnexpectedEntry);
    }
    Ok(expected)
}

fn validate_planned_staging_budget(plan: &ImportPlan) -> Result<(), ImportError> {
    // Include the temporary publication marker so the dry-run budget covers
    // the largest valid physical staging namespace, not only its steady state.
    let expected = expected_staging_entries(plan, true)?;
    if expected.len() > MAX_IMPORT_ENTRIES {
        return Err(ImportError::TargetEntryLimitExceeded);
    }
    validate_staging_path_byte_budget(expected.keys().map(PathBuf::as_path), MAX_IMPORT_PATH_BYTES)
}

fn validate_staging_path_byte_budget<'a>(
    mut paths: impl Iterator<Item = &'a Path>,
    maximum: usize,
) -> Result<(), ImportError> {
    let path_bytes = paths.try_fold(0_usize, |total, path| {
        total
            .checked_add(encoded_path_len(path))
            .ok_or(ImportError::TargetPathByteLimitExceeded)
    })?;
    if path_bytes > maximum {
        return Err(ImportError::TargetPathByteLimitExceeded);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn audit_staging_allowlist(
    plan: &ImportPlan,
    staging: &StagingRoot,
    marker_allowed: bool,
) -> Result<(), ImportError> {
    staging.validate(plan)?;
    let expected = expected_staging_entries(plan, marker_allowed)?;
    let root =
        open_secure_source_root(staging.path()).map_err(|_| ImportError::StagingIdentityChanged)?;
    if root.identity() != &staging.identity {
        return Err(ImportError::StagingIdentityChanged);
    }
    let mut pending = vec![(root, PathBuf::new())];
    let mut seen = BTreeSet::new();
    let mut inspected_entries = 0_usize;
    let mut inspected_path_bytes = 0_usize;
    while let Some((directory, relative_directory)) = pending.pop() {
        directory
            .verify_binding()
            .map_err(|_| ImportError::StagingIdentityChanged)?;
        let entries = directory
            .read_dir()
            .map_err(|_| ImportError::StagingUnexpectedEntry)?;
        for entry in entries {
            let entry = entry.map_err(|_| ImportError::StagingUnexpectedEntry)?;
            inspected_entries = inspected_entries
                .checked_add(1)
                .ok_or(ImportError::TargetEntryLimitExceeded)?;
            if inspected_entries > MAX_IMPORT_ENTRIES {
                return Err(ImportError::TargetEntryLimitExceeded);
            }
            let name = entry.file_name();
            let relative = relative_directory.join(&name);
            inspected_path_bytes = inspected_path_bytes
                .checked_add(encoded_path_len(&relative))
                .ok_or(ImportError::TargetPathByteLimitExceeded)?;
            if inspected_path_bytes > MAX_IMPORT_PATH_BYTES {
                return Err(ImportError::TargetPathByteLimitExceeded);
            }
            let Some(expected_kind) = expected.get(&relative) else {
                return Err(ImportError::StagingUnexpectedEntry);
            };
            if !seen.insert(relative.clone()) {
                return Err(ImportError::StagingUnexpectedEntry);
            }
            match (expected_kind, directory.open_child(&name)) {
                (ExpectedStagingKind::Directory, Ok(SecureSourceChild::Directory(child))) => {
                    pending.push((child, relative));
                }
                (ExpectedStagingKind::File, Ok(SecureSourceChild::File(file))) => {
                    file.verify_binding()
                        .map_err(|_| ImportError::StagingUnexpectedEntry)?;
                }
                _ => return Err(ImportError::StagingUnexpectedEntry),
            }
        }
        directory
            .verify_binding()
            .map_err(|_| ImportError::StagingIdentityChanged)?;
    }
    if seen.len() != expected.len() || expected.keys().any(|path| !seen.contains(path)) {
        return Err(ImportError::StagingUnexpectedEntry);
    }
    staging.validate(plan)
}

#[cfg(not(target_os = "linux"))]
fn audit_staging_allowlist(
    plan: &ImportPlan,
    staging: &StagingRoot,
    marker_allowed: bool,
) -> Result<(), ImportError> {
    staging.validate(plan)?;
    let expected = expected_staging_entries(plan, marker_allowed)?;
    let root_metadata = fs::symlink_metadata(staging.path())
        .map_err(|error| io_error(ImportIoOperation::ResolveTarget, &error))?;
    let root_device = filesystem_device(&root_metadata);
    let mut mount_boundary = MountBoundary::new()?;
    mount_boundary.set_root(staging.path())?;
    let mut pending = vec![(
        staging.path().to_path_buf(),
        PathBuf::new(),
        staging.identity.clone(),
    )];
    let mut seen = BTreeSet::new();
    let mut inspected_entries = 0_usize;
    let mut inspected_path_bytes = 0_usize;

    while let Some((directory, relative_directory, expected_identity)) = pending.pop() {
        if directory_identity(&directory)? != expected_identity {
            return Err(ImportError::StagingIdentityChanged);
        }
        let entries = fs::read_dir(&directory)
            .map_err(|error| io_error(ImportIoOperation::ResolveTarget, &error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| io_error(ImportIoOperation::ResolveTarget, &error))?;
            inspected_entries = inspected_entries
                .checked_add(1)
                .ok_or(ImportError::TargetEntryLimitExceeded)?;
            if inspected_entries > MAX_IMPORT_ENTRIES {
                return Err(ImportError::TargetEntryLimitExceeded);
            }
            let relative = relative_directory.join(entry.file_name());
            inspected_path_bytes = inspected_path_bytes
                .checked_add(encoded_path_len(&relative))
                .ok_or(ImportError::TargetPathByteLimitExceeded)?;
            if inspected_path_bytes > MAX_IMPORT_PATH_BYTES {
                return Err(ImportError::TargetPathByteLimitExceeded);
            }
            let Some(expected_kind) = expected.get(&relative) else {
                return Err(ImportError::StagingUnexpectedEntry);
            };
            if !seen.insert(relative.clone()) {
                return Err(ImportError::StagingUnexpectedEntry);
            }
            let physical = entry.path();
            let metadata = fs::symlink_metadata(&physical)
                .map_err(|error| io_error(ImportIoOperation::ResolveTarget, &error))?;
            if is_link_or_reparse_point(&metadata)
                || root_device
                    .zip(filesystem_device(&metadata))
                    .is_some_and(|(root, current)| root != current)
                || !mount_boundary.contains(&physical)?
            {
                return Err(ImportError::StagingUnexpectedEntry);
            }
            match expected_kind {
                ExpectedStagingKind::Directory if metadata.file_type().is_dir() => {
                    let identity = directory_identity(&physical)?;
                    pending.push((physical, relative, identity));
                }
                ExpectedStagingKind::File if metadata.file_type().is_file() => {
                    validate_regular_source_entry(&physical)
                        .map_err(|_| ImportError::StagingUnexpectedEntry)?;
                }
                ExpectedStagingKind::Directory | ExpectedStagingKind::File => {
                    return Err(ImportError::StagingUnexpectedEntry);
                }
            }
        }
        if directory_identity(&directory)? != expected_identity {
            return Err(ImportError::StagingIdentityChanged);
        }
    }
    if seen.len() != expected.len() || expected.keys().any(|path| !seen.contains(path)) {
        return Err(ImportError::StagingUnexpectedEntry);
    }
    staging.validate(plan)
}

const MAX_SEALED_STAGING_FILE_BYTES: u64 = 32 * 1024 * 1024;

fn seal_staging(plan: &ImportPlan, staging: &StagingRoot) -> Result<StagingSeal, ImportError> {
    audit_staging_allowlist(plan, staging, false)?;
    let expected = expected_staging_entries(plan, false)?;
    let mut file_digests = BTreeMap::new();
    for (relative, kind) in expected {
        if kind == ExpectedStagingKind::File {
            file_digests.insert(
                relative.clone(),
                digest_staging_file(staging.path(), &relative)?,
            );
        }
    }
    staging.validate(plan)?;
    Ok(StagingSeal {
        root_identity: staging.identity.clone(),
        file_digests,
    })
}

fn verify_staging_seal(
    plan: &ImportPlan,
    staging: &StagingRoot,
    seal: &StagingSeal,
    marker_allowed: bool,
) -> Result<(), ImportError> {
    verify_staging_seal_with_hook(plan, staging, seal, marker_allowed, || Ok(()))
}

fn verify_staging_seal_with_hook<F>(
    plan: &ImportPlan,
    staging: &StagingRoot,
    seal: &StagingSeal,
    marker_allowed: bool,
    after_hashes: F,
) -> Result<(), ImportError>
where
    F: FnOnce() -> Result<(), ImportError>,
{
    if seal.root_identity != staging.identity {
        return Err(ImportError::StagingIdentityChanged);
    }
    let expected_files = expected_staging_entries(plan, false)?
        .into_iter()
        .filter_map(|(path, kind)| (kind == ExpectedStagingKind::File).then_some(path))
        .collect::<BTreeSet<_>>();
    if seal.file_digests.len() != expected_files.len()
        || seal
            .file_digests
            .keys()
            .any(|path| !expected_files.contains(path))
    {
        return Err(ImportError::StagingVerificationFailed);
    }
    for (relative, expected_digest) in &seal.file_digests {
        if digest_staging_file(staging.path(), relative)? != *expected_digest {
            return Err(ImportError::StagingVerificationFailed);
        }
    }
    after_hashes()?;
    // Keep the exact physical namespace walk last: no long-running hash pass
    // may reopen an injection window between this scan and publication.
    audit_staging_allowlist(plan, staging, marker_allowed)
}

#[cfg(target_os = "linux")]
fn digest_staging_file(root: &Path, relative: &Path) -> Result<[u8; 32], ImportError> {
    let root = open_secure_source_root(root).map_err(|_| ImportError::StagingIdentityChanged)?;
    let mut directories = vec![root];
    let mut components = relative.components().peekable();
    let mut file = None;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(ImportError::StagingUnexpectedEntry);
        };
        let child = directories
            .last()
            .ok_or(ImportError::StagingIdentityChanged)?
            .open_child(name)
            .map_err(|_| ImportError::StagingUnexpectedEntry)?;
        if components.peek().is_some() {
            let SecureSourceChild::Directory(directory) = child else {
                return Err(ImportError::StagingUnexpectedEntry);
            };
            directories.push(directory);
        } else {
            let SecureSourceChild::File(opened) = child else {
                return Err(ImportError::StagingUnexpectedEntry);
            };
            file = Some(opened);
        }
    }
    let mut file = file.ok_or(ImportError::StagingUnexpectedEntry)?;
    if file
        .observed_len()
        .map_err(|_| ImportError::StagingUnexpectedEntry)?
        > MAX_SEALED_STAGING_FILE_BYTES
    {
        return Err(ImportError::StagingVerificationFailed);
    }
    file.verify_binding()
        .map_err(|_| ImportError::StagingUnexpectedEntry)?;
    let digest = digest_bounded_reader(&mut file)?;
    file.verify_binding()
        .map_err(|_| ImportError::StagingUnexpectedEntry)?;
    for directory in directories.iter().rev() {
        directory
            .verify_binding()
            .map_err(|_| ImportError::StagingIdentityChanged)?;
    }
    Ok(digest)
}

#[cfg(not(target_os = "linux"))]
fn digest_staging_file(root: &Path, relative: &Path) -> Result<[u8; 32], ImportError> {
    let path = root.join(relative);
    let parent_chain =
        capture_directory_chain(path.parent().ok_or(ImportError::StagingUnexpectedEntry)?)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let mut file = options
        .open(&path)
        .map_err(|_| ImportError::StagingUnexpectedEntry)?;
    let metadata = file
        .metadata()
        .map_err(|_| ImportError::StagingUnexpectedEntry)?;
    if !metadata.file_type().is_file()
        || metadata.len() > MAX_SEALED_STAGING_FILE_BYTES
        || !open_file_matches_path_and_is_single_link(&path, &file)
            .map_err(|_| ImportError::StagingUnexpectedEntry)?
    {
        return Err(ImportError::StagingUnexpectedEntry);
    }
    let digest = digest_bounded_reader(&mut file)?;
    if !open_file_matches_path_and_is_single_link(&path, &file)
        .map_err(|_| ImportError::StagingUnexpectedEntry)?
        || capture_directory_chain(path.parent().ok_or(ImportError::StagingUnexpectedEntry)?)?
            != parent_chain
    {
        return Err(ImportError::StagingUnexpectedEntry);
    }
    Ok(digest)
}

fn digest_bounded_reader(reader: &mut impl Read) -> Result<[u8; 32], ImportError> {
    let mut digest = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    let mut total = 0_u64;
    loop {
        let count = reader
            .read(buffer.as_mut_slice())
            .map_err(|error| io_error(ImportIoOperation::ResolveTarget, &error))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or(ImportError::StagingVerificationFailed)?;
        if total > MAX_SEALED_STAGING_FILE_BYTES {
            return Err(ImportError::StagingVerificationFailed);
        }
        digest.update(&buffer[..count]);
        buffer[..count].fill(0);
    }
    Ok(digest.finalize().into())
}

fn ensure_source_unchanged(plan: &ImportPlan) -> Result<(), ImportError> {
    let root = resolve_source_root(&plan.source_root)?;
    if root != plan.source_root {
        return Err(ImportError::SourceChanged);
    }
    let mut current = scan_resolved_source(root)?;
    current.destination.clone_from(&plan.destination);
    current
        .destination_parent
        .clone_from(&plan.destination_parent);
    current
        .destination_parent_identity
        .clone_from(&plan.destination_parent_identity);
    if current == *plan {
        Ok(())
    } else {
        Err(ImportError::SourceChanged)
    }
}

#[cfg(target_os = "linux")]
fn scan_resolved_source(source_root: PathBuf) -> Result<ImportPlan, ImportError> {
    validate_directory_chain(&source_root)?;
    let secure_root = open_secure_source_root(&source_root)
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    let mut scan = LinuxScanState::new(source_root, secure_root);
    while let Some((directory, relative, depth)) = scan.pending.pop() {
        scan.scan_directory(&directory, &relative, depth)?;
    }
    Ok(scan.finish())
}

#[cfg(target_os = "linux")]
struct LinuxScanState {
    source_root: PathBuf,
    pending: Vec<(SecureSourceDirectory, PathBuf, usize)>,
    directories: Vec<PlannedDirectory>,
    files: Vec<PlannedFile>,
    logical_names: BTreeSet<String>,
    physical_names: BTreeSet<String>,
    source_directory_identities: BTreeSet<FilesystemDirectoryIdentity>,
    inspected_entries: usize,
    inspected_path_bytes: usize,
    total_plaintext_bytes: usize,
    skipped_non_markdown: usize,
    normalized_entries: usize,
}

#[cfg(target_os = "linux")]
impl LinuxScanState {
    fn new(source_root: PathBuf, secure_root: SecureSourceDirectory) -> Self {
        Self {
            source_root,
            pending: vec![(secure_root, PathBuf::new(), 0)],
            directories: Vec::new(),
            files: Vec::new(),
            logical_names: BTreeSet::new(),
            physical_names: BTreeSet::new(),
            source_directory_identities: BTreeSet::new(),
            inspected_entries: 0,
            inspected_path_bytes: 0,
            total_plaintext_bytes: 0,
            skipped_non_markdown: 0,
            normalized_entries: 0,
        }
    }

    fn scan_directory(
        &mut self,
        directory: &SecureSourceDirectory,
        relative_directory: &Path,
        parent_depth: usize,
    ) -> Result<(), ImportError> {
        directory
            .verify_binding()
            .map_err(|_| ImportError::SourceChanged)?;
        self.source_directory_identities
            .insert(directory.identity().clone());
        let entries = directory
            .read_dir()
            .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
            let name = entry.file_name();
            self.inspected_entries = self
                .inspected_entries
                .checked_add(1)
                .ok_or(ImportError::EntryLimitExceeded)?;
            if self.inspected_entries > MAX_IMPORT_ENTRIES {
                return Err(ImportError::EntryLimitExceeded);
            }
            let relative = relative_directory.join(&name);
            let depth = parent_depth
                .checked_add(1)
                .ok_or(ImportError::DepthLimitExceeded)?;
            if depth > MAX_IMPORT_DEPTH {
                return Err(ImportError::DepthLimitExceeded);
            }
            self.inspected_path_bytes = self
                .inspected_path_bytes
                .checked_add(encoded_path_len(&relative))
                .ok_or(ImportError::PathByteLimitExceeded)?;
            if self.inspected_path_bytes > MAX_IMPORT_PATH_BYTES {
                return Err(ImportError::PathByteLimitExceeded);
            }

            let child = directory.open_child(&name).map_err(|error| {
                if error.raw_os_error() == Some(18) {
                    ImportError::SourceMountBoundary
                } else {
                    ImportError::UnsafeSourceEntry
                }
            })?;
            match child {
                SecureSourceChild::Directory(child) => {
                    let text = relative_utf8(&relative)?;
                    let logical =
                        LogicalDir::parse(&text).map_err(|_| ImportError::InvalidLogicalPath)?;
                    self.register_logical(logical.case_fold_key().as_str())?;
                    self.register_physical(logical.as_str())?;
                    if logical.as_str() != text {
                        self.normalized_entries += 1;
                    }
                    self.directories.push(PlannedDirectory {
                        source_relative: relative.clone(),
                        logical,
                    });
                    self.pending.push((child, relative, depth));
                }
                SecureSourceChild::File(file) => {
                    self.inspect_file(file, &name, relative)?;
                }
                SecureSourceChild::Other => return Err(ImportError::UnsafeSourceEntry),
            }
        }
        directory
            .verify_binding()
            .map_err(|_| ImportError::SourceChanged)
    }

    fn inspect_file(
        &mut self,
        file: SecureSourceFile,
        name: &OsStr,
        relative: PathBuf,
    ) -> Result<(), ImportError> {
        file.verify_binding()
            .map_err(|_| ImportError::SourceChanged)?;
        if !os_name_has_markdown_suffix(name) {
            self.skipped_non_markdown += 1;
            return Ok(());
        }
        if self.files.len() >= MAX_IMPORT_FILES {
            return Err(ImportError::FileLimitExceeded);
        }
        let text = relative_utf8(&relative)?;
        let logical = LogicalPath::parse(&text).map_err(|_| ImportError::InvalidLogicalPath)?;
        self.register_logical(logical.case_fold_key().as_str())?;
        let ciphertext = logical.to_ciphertext_relative_path();
        let ciphertext_text = relative_utf8(&ciphertext)?;
        self.register_physical(&ciphertext_text)?;
        if logical.as_str() != text {
            self.normalized_entries += 1;
        }
        let plaintext = read_secure_markdown_file(file)?;
        self.total_plaintext_bytes = self
            .total_plaintext_bytes
            .checked_add(plaintext.len())
            .ok_or(ImportError::TotalPlaintextLimitExceeded)?;
        if self.total_plaintext_bytes > MAX_IMPORT_PLAINTEXT_BYTES {
            return Err(ImportError::TotalPlaintextLimitExceeded);
        }
        self.files.push(PlannedFile {
            source_relative: relative,
            logical,
            plaintext_bytes: plaintext.len(),
            digest: format::etag_digest(plaintext.as_slice()),
        });
        Ok(())
    }

    fn register_logical(&mut self, key: &str) -> Result<(), ImportError> {
        if self.logical_names.insert(key.to_owned()) {
            Ok(())
        } else {
            Err(ImportError::SourcePathCollision)
        }
    }

    fn register_physical(&mut self, path: &str) -> Result<(), ImportError> {
        let key = LogicalDir::parse(path)
            .map_err(|_| ImportError::InvalidLogicalPath)?
            .case_fold_key();
        if self.physical_names.insert(key.as_str().to_owned()) {
            Ok(())
        } else {
            Err(ImportError::PhysicalPathCollision)
        }
    }

    fn finish(mut self) -> ImportPlan {
        self.directories.sort_by(|first, second| {
            first
                .logical
                .components()
                .count()
                .cmp(&second.logical.components().count())
                .then_with(|| first.logical.cmp(&second.logical))
        });
        self.files
            .sort_by(|first, second| first.logical.cmp(&second.logical));
        ImportPlan {
            source_root: self.source_root,
            destination: PathBuf::new(),
            destination_parent: PathBuf::new(),
            destination_parent_identity: None,
            directories: self.directories,
            files: self.files,
            inspected_entries: self.inspected_entries,
            total_plaintext_bytes: self.total_plaintext_bytes,
            skipped_non_markdown: self.skipped_non_markdown,
            normalized_entries: self.normalized_entries,
            source_directory_identities: self.source_directory_identities,
        }
    }
}

#[cfg(target_os = "linux")]
fn read_secure_markdown_file(
    mut file: SecureSourceFile,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let length = file
        .observed_len()
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    if length > u64::try_from(MAX_PLAINTEXT_LEN).unwrap_or(u64::MAX) {
        return Err(ImportError::FileTooLarge);
    }
    let length = usize::try_from(length).map_err(|_| ImportError::FileTooLarge)?;
    file.verify_binding()
        .map_err(|_| ImportError::SourceChanged)?;
    let mut plaintext = Zeroizing::new(vec![0_u8; length]);
    file.read_exact(plaintext.as_mut_slice())
        .map_err(|error| io_error(ImportIoOperation::ReadSource, &error))?;
    let mut extra = Zeroizing::new([0_u8; 1]);
    if file
        .read(extra.as_mut_slice())
        .map_err(|error| io_error(ImportIoOperation::ReadSource, &error))?
        != 0
    {
        return Err(ImportError::SourceChanged);
    }
    file.verify_binding()
        .map_err(|_| ImportError::SourceChanged)?;
    std::str::from_utf8(plaintext.as_slice()).map_err(|_| ImportError::InvalidMarkdownUtf8)?;
    Ok(plaintext)
}

#[cfg(not(target_os = "linux"))]
fn scan_resolved_source(source_root: PathBuf) -> Result<ImportPlan, ImportError> {
    validate_directory_chain(&source_root)?;
    let root_metadata = fs::symlink_metadata(&source_root)
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    let mut mount_boundary = MountBoundary::new()?;
    mount_boundary.set_root(&source_root)?;
    let mut scan = ScanState::new(
        source_root,
        filesystem_device(&root_metadata),
        mount_boundary,
    )?;
    while let Some((directory, relative, depth, identity)) = scan.pending.pop() {
        scan.scan_directory(&directory, &relative, depth, &identity)?;
    }
    Ok(scan.finish())
}

#[cfg(not(target_os = "linux"))]
struct ScanState {
    source_root: PathBuf,
    pending: Vec<(PathBuf, PathBuf, usize, FilesystemDirectoryIdentity)>,
    directories: Vec<PlannedDirectory>,
    files: Vec<PlannedFile>,
    logical_names: BTreeSet<String>,
    physical_names: BTreeSet<String>,
    source_directory_identities: BTreeSet<FilesystemDirectoryIdentity>,
    inspected_entries: usize,
    inspected_path_bytes: usize,
    total_plaintext_bytes: usize,
    skipped_non_markdown: usize,
    normalized_entries: usize,
    root_device: Option<u64>,
    mount_boundary: MountBoundary,
}

#[cfg(not(target_os = "linux"))]
impl ScanState {
    fn new(
        source_root: PathBuf,
        root_device: Option<u64>,
        mount_boundary: MountBoundary,
    ) -> Result<Self, ImportError> {
        let identity = directory_identity(&source_root)?;
        Ok(Self {
            pending: vec![(source_root.clone(), PathBuf::new(), 0, identity)],
            source_root,
            directories: Vec::new(),
            files: Vec::new(),
            logical_names: BTreeSet::new(),
            physical_names: BTreeSet::new(),
            source_directory_identities: BTreeSet::new(),
            inspected_entries: 0,
            inspected_path_bytes: 0,
            total_plaintext_bytes: 0,
            skipped_non_markdown: 0,
            normalized_entries: 0,
            root_device,
            mount_boundary,
        })
    }

    fn scan_directory(
        &mut self,
        directory: &Path,
        relative: &Path,
        depth: usize,
        expected_identity: &FilesystemDirectoryIdentity,
    ) -> Result<(), ImportError> {
        validate_directory_entry(directory)?;
        if &directory_identity(directory)? != expected_identity {
            return Err(ImportError::SourceChanged);
        }
        self.ensure_same_source_mount(directory)?;
        self.source_directory_identities
            .insert(directory_identity(directory)?);
        let entries = fs::read_dir(directory)
            .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
        // Stream each ReadDir result. We deliberately do not collect an
        // attacker-controlled directory before applying global limits.
        for entry in entries {
            let entry =
                entry.map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
            self.inspect_entry(&entry, relative, depth)?;
        }
        validate_directory_entry(directory)?;
        if &directory_identity(directory)? != expected_identity {
            return Err(ImportError::SourceChanged);
        }
        Ok(())
    }

    fn inspect_entry(
        &mut self,
        entry: &DirEntry,
        relative_directory: &Path,
        parent_depth: usize,
    ) -> Result<(), ImportError> {
        self.inspected_entries = self
            .inspected_entries
            .checked_add(1)
            .ok_or(ImportError::EntryLimitExceeded)?;
        if self.inspected_entries > MAX_IMPORT_ENTRIES {
            return Err(ImportError::EntryLimitExceeded);
        }
        let relative = relative_directory.join(entry.file_name());
        let depth = parent_depth
            .checked_add(1)
            .ok_or(ImportError::DepthLimitExceeded)?;
        if depth > MAX_IMPORT_DEPTH {
            return Err(ImportError::DepthLimitExceeded);
        }
        self.inspected_path_bytes = self
            .inspected_path_bytes
            .checked_add(encoded_path_len(&relative))
            .ok_or(ImportError::PathByteLimitExceeded)?;
        if self.inspected_path_bytes > MAX_IMPORT_PATH_BYTES {
            return Err(ImportError::PathByteLimitExceeded);
        }

        let physical = entry.path();
        let metadata = fs::symlink_metadata(&physical)
            .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
        if is_link_or_reparse_point(&metadata) {
            return Err(ImportError::UnsafeSourceEntry);
        }
        self.ensure_same_source_mount(&physical)?;
        if metadata.file_type().is_dir() {
            let text = relative_utf8(&relative)?;
            let logical = LogicalDir::parse(&text).map_err(|_| ImportError::InvalidLogicalPath)?;
            self.register_logical(logical.case_fold_key().as_str())?;
            self.register_physical(logical.as_str())?;
            if logical.as_str() != text {
                self.normalized_entries += 1;
            }
            self.directories.push(PlannedDirectory {
                source_relative: relative.clone(),
                logical,
            });
            let identity = directory_identity(&physical)?;
            self.pending.push((physical, relative, depth, identity));
            return Ok(());
        }
        if !metadata.file_type().is_file() {
            return Err(ImportError::UnsafeSourceEntry);
        }
        validate_regular_source_entry(&physical)?;
        if !os_name_has_markdown_suffix(&entry.file_name()) {
            self.skipped_non_markdown += 1;
            return Ok(());
        }
        if self.files.len() >= MAX_IMPORT_FILES {
            return Err(ImportError::FileLimitExceeded);
        }
        let text = relative_utf8(&relative)?;
        let logical = LogicalPath::parse(&text).map_err(|_| ImportError::InvalidLogicalPath)?;
        self.register_logical(logical.case_fold_key().as_str())?;
        let ciphertext = logical.to_ciphertext_relative_path();
        let ciphertext_text = relative_utf8(&ciphertext)?;
        self.register_physical(&ciphertext_text)?;
        if logical.as_str() != text {
            self.normalized_entries += 1;
        }
        let plaintext = read_markdown_file(&physical)?;
        self.total_plaintext_bytes = self
            .total_plaintext_bytes
            .checked_add(plaintext.len())
            .ok_or(ImportError::TotalPlaintextLimitExceeded)?;
        if self.total_plaintext_bytes > MAX_IMPORT_PLAINTEXT_BYTES {
            return Err(ImportError::TotalPlaintextLimitExceeded);
        }
        self.files.push(PlannedFile {
            source_relative: relative,
            logical,
            plaintext_bytes: plaintext.len(),
            digest: format::etag_digest(plaintext.as_slice()),
        });
        Ok(())
    }

    fn ensure_same_source_mount(&self, path: &Path) -> Result<(), ImportError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
        if self
            .root_device
            .zip(filesystem_device(&metadata))
            .is_some_and(|(a, b)| a != b)
            || !self.mount_boundary.contains(path)?
        {
            return Err(ImportError::SourceMountBoundary);
        }
        Ok(())
    }

    fn register_logical(&mut self, key: &str) -> Result<(), ImportError> {
        if self.logical_names.insert(key.to_owned()) {
            Ok(())
        } else {
            Err(ImportError::SourcePathCollision)
        }
    }

    fn register_physical(&mut self, path: &str) -> Result<(), ImportError> {
        let key = LogicalDir::parse(path)
            .map_err(|_| ImportError::InvalidLogicalPath)?
            .case_fold_key();
        if self.physical_names.insert(key.as_str().to_owned()) {
            Ok(())
        } else {
            Err(ImportError::PhysicalPathCollision)
        }
    }

    fn finish(mut self) -> ImportPlan {
        self.directories.sort_by(|a, b| {
            a.logical
                .components()
                .count()
                .cmp(&b.logical.components().count())
                .then_with(|| a.logical.cmp(&b.logical))
        });
        self.files.sort_by(|a, b| a.logical.cmp(&b.logical));
        ImportPlan {
            source_root: self.source_root,
            destination: PathBuf::new(),
            destination_parent: PathBuf::new(),
            destination_parent_identity: None,
            directories: self.directories,
            files: self.files,
            inspected_entries: self.inspected_entries,
            total_plaintext_bytes: self.total_plaintext_bytes,
            skipped_non_markdown: self.skipped_non_markdown,
            normalized_entries: self.normalized_entries,
            source_directory_identities: self.source_directory_identities,
        }
    }
}

fn resolve_source_root(source: &Path) -> Result<PathBuf, ImportError> {
    if source.as_os_str().is_empty() {
        return Err(ImportError::EmptySourcePath);
    }
    let absolute = absolute_path(source, ImportIoOperation::ResolveSource)?;
    validate_directory_chain(&absolute)?;
    let canonical = fs::canonicalize(&absolute)
        .map_err(|error| io_error(ImportIoOperation::ResolveSource, &error))?;
    validate_directory_chain(&canonical)?;
    Ok(canonical)
}

fn resolve_absent_target(target: &Path) -> Result<(PathBuf, PathBuf), ImportError> {
    if target.as_os_str().is_empty() {
        return Err(ImportError::InvalidTargetPath);
    }
    let absolute = absolute_path(target, ImportIoOperation::ResolveTarget)?;
    let name = absolute.file_name().ok_or(ImportError::InvalidTargetPath)?;
    let name_text = name.to_str().ok_or(ImportError::InvalidTargetPath)?;
    if name_text
        .to_ascii_lowercase()
        .starts_with(&IMPORT_STAGING_PREFIX.to_ascii_lowercase())
    {
        return Err(ImportError::InvalidTargetPath);
    }
    if !matches!(
        absolute.components().next_back(),
        Some(Component::Normal(_))
    ) {
        return Err(ImportError::InvalidTargetPath);
    }
    let parent = absolute.parent().ok_or(ImportError::InvalidTargetPath)?;
    validate_directory_chain(parent)?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| io_error(ImportIoOperation::ResolveTarget, &error))?;
    if !path_is_supported_local_filesystem(&parent)
        .map_err(|error| io_error(ImportIoOperation::ResolveTarget, &error))?
    {
        return Err(ImportError::UnsupportedTargetFilesystem);
    }
    let resolved = parent.join(name);
    reject_existing_destination(&resolved)?;
    Ok((resolved, parent))
}

fn reject_existing_destination(target: &Path) -> Result<(), ImportError> {
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(ImportError::TargetExists),
        Err(error) => Err(io_error(ImportIoOperation::ResolveTarget, &error)),
    }
}

fn absolute_path(path: &Path, operation: ImportIoOperation) -> Result<PathBuf, ImportError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| io_error(operation, &error))
    }
}

fn ensure_disjoint(source: &Path, destination: &Path) -> Result<(), ImportError> {
    if source == destination || source.starts_with(destination) || destination.starts_with(source) {
        Err(ImportError::SourceVaultOverlap)
    } else {
        Ok(())
    }
}

fn validate_directory_chain(path: &Path) -> Result<(), ImportError> {
    let mut ancestors = path
        .ancestors()
        .filter(|entry| !entry.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        validate_directory_entry(ancestor)?;
    }
    Ok(())
}

fn validate_directory_entry(path: &Path) -> Result<(), ImportError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        Err(ImportError::UnsafeSourceRoot)
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn read_markdown_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    if let Some(parent) = path.parent() {
        validate_directory_chain(parent)?;
    }
    #[cfg(not(target_os = "linux"))]
    let parent_chain =
        capture_directory_chain(path.parent().ok_or(ImportError::UnsafeSourceEntry)?)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    validate_file_metadata(&metadata)?;
    let length = usize::try_from(metadata.len()).map_err(|_| ImportError::FileTooLarge)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let mut file = options
        .open(path)
        .map_err(|error| io_error(ImportIoOperation::ReadSource, &error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    validate_file_metadata(&opened)?;
    if opened.len() != metadata.len()
        || !open_file_matches_path_and_is_single_link(path, &file)
            .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?
    {
        return Err(ImportError::SourceChanged);
    }
    // Allocate exactly the observed length once. `read_exact` cannot grow the
    // allocation; the one-byte probe detects a concurrent append.
    let mut plaintext = Zeroizing::new(vec![0_u8; length]);
    file.read_exact(plaintext.as_mut_slice())
        .map_err(|error| io_error(ImportIoOperation::ReadSource, &error))?;
    let mut extra = Zeroizing::new([0_u8; 1]);
    if file
        .read(extra.as_mut_slice())
        .map_err(|error| io_error(ImportIoOperation::ReadSource, &error))?
        != 0
    {
        return Err(ImportError::SourceChanged);
    }
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?
    {
        return Err(ImportError::SourceChanged);
    }
    #[cfg(not(target_os = "linux"))]
    if capture_directory_chain(path.parent().ok_or(ImportError::UnsafeSourceEntry)?)?
        != parent_chain
    {
        return Err(ImportError::SourceChanged);
    }
    std::str::from_utf8(plaintext.as_slice()).map_err(|_| ImportError::InvalidMarkdownUtf8)?;
    Ok(plaintext)
}

#[cfg(not(target_os = "linux"))]
fn validate_regular_source_entry(path: &Path) -> Result<(), ImportError> {
    #[cfg(not(target_os = "linux"))]
    let parent_chain =
        capture_directory_chain(path.parent().ok_or(ImportError::UnsafeSourceEntry)?)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options
        .open(path)
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?;
    if !metadata.file_type().is_file()
        || !open_file_matches_path_and_is_single_link(path, &file)
            .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))?
    {
        return Err(ImportError::UnsafeSourceEntry);
    }
    #[cfg(not(target_os = "linux"))]
    if capture_directory_chain(path.parent().ok_or(ImportError::UnsafeSourceEntry)?)?
        != parent_chain
    {
        return Err(ImportError::SourceChanged);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn capture_directory_chain(
    path: &Path,
) -> Result<Vec<(PathBuf, FilesystemDirectoryIdentity)>, ImportError> {
    let mut ancestors = path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    ancestors
        .into_iter()
        .map(|ancestor| {
            validate_directory_entry(ancestor)?;
            Ok((ancestor.to_path_buf(), directory_identity(ancestor)?))
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn validate_file_metadata(metadata: &Metadata) -> Result<(), ImportError> {
    if is_link_or_reparse_point(metadata) || !metadata.file_type().is_file() {
        return Err(ImportError::UnsafeSourceEntry);
    }
    if metadata.len() > u64::try_from(MAX_PLAINTEXT_LEN).unwrap_or(u64::MAX) {
        return Err(ImportError::FileTooLarge);
    }
    Ok(())
}

fn relative_utf8(path: &Path) -> Result<String, ImportError> {
    let mut text = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(ImportError::InvalidLogicalPath);
        };
        let component = component.to_str().ok_or(ImportError::NonUtf8SourcePath)?;
        if !text.is_empty() {
            text.push('/');
        }
        text.push_str(component);
    }
    Ok(text)
}

fn directory_identity(path: &Path) -> Result<FilesystemDirectoryIdentity, ImportError> {
    filesystem_directory_identity(path)
        .map_err(|error| io_error(ImportIoOperation::InspectSource, &error))
}

#[cfg(not(target_os = "linux"))]
fn filesystem_device(_metadata: &Metadata) -> Option<u64> {
    None
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
struct MountBoundary;

#[cfg(not(target_os = "linux"))]
impl MountBoundary {
    #[allow(clippy::unnecessary_wraps)]
    fn new() -> Result<Self, ImportError> {
        Ok(Self)
    }

    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn set_root(&mut self, _root: &Path) -> Result<(), ImportError> {
        Ok(())
    }

    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn contains(&self, _path: &Path) -> Result<bool, ImportError> {
        Ok(true)
    }
}

fn encoded_path_len(path: &Path) -> usize {
    path.as_os_str().as_encoded_bytes().len()
}

#[cfg(unix)]
fn os_name_has_markdown_suffix(name: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().ends_with(b".md")
}
#[cfg(windows)]
fn os_name_has_markdown_suffix(name: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide()
        .collect::<Vec<_>>()
        .ends_with(&[46, 109, 100])
}
#[cfg(not(any(unix, windows)))]
fn os_name_has_markdown_suffix(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| name.ends_with(".md"))
}

#[cfg(windows)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    options.custom_flags(0x0020_0000);
}
#[cfg(not(any(target_os = "linux", windows)))]
fn configure_no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn restrict_directory_permissions_best_effort(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_directory_permissions_best_effort(_path: &Path) {}

#[cfg(not(windows))]
fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}
#[cfg(windows)]
fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_type().is_symlink() || metadata.file_attributes() & 0x0000_0400 != 0
}

fn io_error(operation: ImportIoOperation, error: &io::Error) -> ImportError {
    ImportError::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use inex_core::path::LogicalPath;
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault_config::KdfPolicy;

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "inex-import-stage-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap_or_else(|error| panic!("test root: {error}"));
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

    fn policy() -> KdfPolicy {
        KdfPolicy {
            min_creation_ops_limit: 1,
            min_creation_mem_limit_bytes: 8 * 1024,
            max_creation_ops_limit: 4,
            max_creation_mem_limit_bytes: 64 * 1024 * 1024,
            max_unlock_ops_limit: 4,
            max_unlock_mem_limit_bytes: 64 * 1024 * 1024,
        }
    }

    fn create_stage(path: &Path) -> Vault {
        Vault::create_with_params(
            path,
            b"new password",
            1_783_699_200_000,
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            },
            policy(),
        )
        .unwrap_or_else(|error| panic!("stage create: {error}"))
    }

    #[test]
    fn complete_stage_is_verified_published_and_source_preserved() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir_all(source.join("Cafe\u{301}")).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let source_file = source.join("Cafe\u{301}/entry.md");
        let expected = b"# Secret\r\nsource remains\n";
        fs::write(&source_file, expected).unwrap_or_else(|e| panic!("write: {e}"));
        fs::write(source.join("skip.bin"), b"skip").unwrap_or_else(|e| panic!("skip: {e}"));
        let destination = root.path().join("vault");
        let plan = scan_source(&source, &destination).unwrap_or_else(|e| panic!("scan: {e}"));
        assert!(!destination.exists());
        let stage = create_staging_root(&plan).unwrap_or_else(|e| panic!("stage root: {e}"));
        let mut vault = create_stage(stage.path());
        let summary = populate_staging(&plan, &stage, &mut vault, 1_783_699_201_000)
            .unwrap_or_else(|e| panic!("populate: {e}"));
        assert_eq!(summary.committed_files, 1);
        drop(vault);
        let mut reopened = Vault::unlock(stage.path(), b"new password", None, policy())
            .unwrap_or_else(|e| panic!("unlock: {e}"));
        let (_, seal) = verify_reopened_staging(&plan, &stage, &mut reopened)
            .unwrap_or_else(|e| panic!("verify: {e}"));
        drop(reopened);
        publish_staging(&plan, &stage, &seal).unwrap_or_else(|e| panic!("publish: {e}"));
        assert!(!stage.path().exists());
        assert!(destination.is_dir());
        assert_eq!(
            fs::read(&source_file).unwrap_or_else(|e| panic!("source: {e}")),
            expected
        );
        let published = Vault::unlock(&destination, b"new password", None, policy())
            .unwrap_or_else(|e| panic!("published: {e}"));
        let logical =
            LogicalPath::parse_canonical("Café/entry.md").unwrap_or_else(|e| panic!("path: {e}"));
        assert_eq!(
            published
                .read(&logical)
                .unwrap_or_else(|e| panic!("read: {e}"))
                .plaintext
                .as_slice(),
            expected
        );
    }

    #[test]
    fn dry_plan_rejects_existing_target_and_creates_nothing() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap_or_else(|e| panic!("mkdir: {e}"));
        fs::write(source.join("a.md"), b"a").unwrap_or_else(|e| panic!("write: {e}"));
        let destination = root.path().join("vault");
        let _plan = scan_source(&source, &destination).unwrap_or_else(|e| panic!("scan: {e}"));
        assert!(!destination.exists());
        fs::create_dir(&destination).unwrap_or_else(|e| panic!("target: {e}"));
        assert!(matches!(
            scan_source(&source, &destination),
            Err(ImportError::TargetExists)
        ));
    }

    #[test]
    fn source_change_keeps_final_absent_and_stage_explicit() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let file = source.join("a.md");
        fs::write(&file, b"before").unwrap_or_else(|e| panic!("write: {e}"));
        let destination = root.path().join("vault");
        let plan = scan_source(&source, &destination).unwrap_or_else(|e| panic!("scan: {e}"));
        let stage = create_staging_root(&plan).unwrap_or_else(|e| panic!("stage root: {e}"));
        let mut vault = create_stage(stage.path());
        fs::write(&file, b"after").unwrap_or_else(|e| panic!("rewrite: {e}"));
        assert!(matches!(
            populate_staging(&plan, &stage, &mut vault, 1),
            Err(ImportError::SourceChanged)
        ));
        assert!(!destination.exists());
        assert!(
            stage
                .path()
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|n| n.starts_with(IMPORT_STAGING_PREFIX))
        );
        assert!(stage.path().is_dir());
    }

    #[test]
    fn intermediate_source_directory_identity_swap_is_rejected() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        let nested = source.join("nested");
        fs::create_dir_all(&nested).unwrap_or_else(|e| panic!("mkdir: {e}"));
        fs::write(nested.join("a.md"), b"same bytes").unwrap_or_else(|e| panic!("write: {e}"));
        let destination = root.path().join("vault");
        let plan = scan_source(&source, &destination).unwrap_or_else(|e| panic!("scan: {e}"));
        let stage = create_staging_root(&plan).unwrap_or_else(|e| panic!("stage: {e}"));
        let mut vault = create_stage(stage.path());

        fs::rename(&nested, root.path().join("retired-nested"))
            .unwrap_or_else(|e| panic!("rename: {e}"));
        fs::create_dir(&nested).unwrap_or_else(|e| panic!("replacement mkdir: {e}"));
        fs::write(nested.join("a.md"), b"same bytes")
            .unwrap_or_else(|e| panic!("replacement write: {e}"));
        assert!(matches!(
            populate_staging(&plan, &stage, &mut vault, 1),
            Err(ImportError::SourceChanged)
        ));
        assert!(!destination.exists());
        assert!(stage.path().is_dir());
    }

    #[test]
    fn replaced_destination_parent_identity_fails_before_population() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap_or_else(|e| panic!("source mkdir: {e}"));
        fs::write(source.join("a.md"), b"source").unwrap_or_else(|e| panic!("source write: {e}"));
        let target_parent = root.path().join("target-parent");
        fs::create_dir(&target_parent).unwrap_or_else(|e| panic!("target mkdir: {e}"));
        let destination = target_parent.join("vault");
        let plan = scan_source(&source, &destination).unwrap_or_else(|e| panic!("scan: {e}"));
        fs::rename(&target_parent, root.path().join("retired-target-parent"))
            .unwrap_or_else(|e| panic!("target parent rename: {e}"));
        fs::create_dir(&target_parent).unwrap_or_else(|e| panic!("replacement mkdir: {e}"));
        assert!(matches!(
            create_staging_root(&plan),
            Err(ImportError::TargetParentChanged)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn physical_ciphertext_directory_collision_is_rejected() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir_all(source.join("A.MD.ENC")).unwrap_or_else(|e| panic!("mkdir: {e}"));
        fs::write(source.join("a.md"), b"file").unwrap_or_else(|e| panic!("write: {e}"));
        assert!(matches!(
            scan_source(&source, &root.path().join("vault")),
            Err(ImportError::PhysicalPathCollision)
        ));
    }

    #[test]
    fn hardlinked_skipped_file_is_still_rejected() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let first = source.join("attachment.bin");
        fs::write(&first, b"not imported").unwrap_or_else(|e| panic!("write: {e}"));
        fs::hard_link(&first, source.join("alias.bin"))
            .unwrap_or_else(|e| panic!("hard link: {e}"));
        assert!(matches!(
            scan_source(&source, &root.path().join("vault")),
            Err(ImportError::UnsafeSourceEntry)
        ));
    }

    #[test]
    fn strict_staging_allowlist_rejects_git_plaintext_and_unrelated_entries() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap_or_else(|e| panic!("mkdir: {e}"));
        fs::write(source.join("a.md"), b"source").unwrap_or_else(|e| panic!("write: {e}"));
        let destination = root.path().join("vault");
        let plan = scan_source(&source, &destination).unwrap_or_else(|e| panic!("scan: {e}"));
        let stage = create_staging_root(&plan).unwrap_or_else(|e| panic!("stage: {e}"));
        let mut vault = create_stage(stage.path());
        populate_staging(&plan, &stage, &mut vault, 1).unwrap_or_else(|e| panic!("populate: {e}"));
        drop(vault);
        let seal = seal_staging(&plan, &stage).unwrap_or_else(|e| panic!("seal: {e}"));

        let git = stage.path().join(".git");
        fs::create_dir(&git).unwrap_or_else(|e| panic!("git injection: {e}"));
        fs::write(git.join("plaintext.md"), b"injected")
            .unwrap_or_else(|e| panic!("git plaintext: {e}"));
        assert!(matches!(
            audit_staging_allowlist(&plan, &stage, false),
            Err(ImportError::StagingUnexpectedEntry)
        ));
        fs::remove_dir_all(&git).unwrap_or_else(|e| panic!("git cleanup: {e}"));

        let plaintext = stage.path().join("leak.md");
        fs::write(&plaintext, b"injected").unwrap_or_else(|e| panic!("plaintext: {e}"));
        assert!(matches!(
            audit_staging_allowlist(&plan, &stage, false),
            Err(ImportError::StagingUnexpectedEntry)
        ));
        fs::remove_file(&plaintext).unwrap_or_else(|e| panic!("plaintext cleanup: {e}"));

        let unrelated = stage.path().join("attachment.bin");
        fs::write(&unrelated, b"injected").unwrap_or_else(|e| panic!("unrelated: {e}"));
        assert!(matches!(
            publish_staging(&plan, &stage, &seal),
            Err(ImportError::StagingUnexpectedEntry)
        ));
        fs::remove_file(&unrelated).unwrap_or_else(|e| panic!("unrelated cleanup: {e}"));

        let ciphertext = stage.path().join("a.md.enc");
        let mut tampered = fs::read(&ciphertext).unwrap_or_else(|e| panic!("ciphertext read: {e}"));
        let last = tampered
            .last_mut()
            .unwrap_or_else(|| panic!("ciphertext was unexpectedly empty"));
        *last ^= 0x01;
        fs::write(&ciphertext, tampered).unwrap_or_else(|e| panic!("ciphertext tamper: {e}"));
        assert!(matches!(
            publish_staging(&plan, &stage, &seal),
            Err(ImportError::StagingVerificationFailed)
        ));
        assert!(!destination.exists());
        assert!(stage.path().is_dir());
    }

    #[test]
    fn final_seal_audit_rejects_entry_injected_after_hashes() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap_or_else(|e| panic!("mkdir: {e}"));
        fs::write(source.join("a.md"), b"source").unwrap_or_else(|e| panic!("write: {e}"));
        let destination = root.path().join("vault");
        let plan = scan_source(&source, &destination).unwrap_or_else(|e| panic!("scan: {e}"));
        let stage = create_staging_root(&plan).unwrap_or_else(|e| panic!("stage: {e}"));
        let mut vault = create_stage(stage.path());
        populate_staging(&plan, &stage, &mut vault, 1).unwrap_or_else(|e| panic!("populate: {e}"));
        drop(vault);
        let seal = seal_staging(&plan, &stage).unwrap_or_else(|e| panic!("seal: {e}"));
        let injected = stage.path().join(".git");

        assert!(matches!(
            verify_staging_seal_with_hook(&plan, &stage, &seal, false, || {
                fs::create_dir(&injected).map_err(|_| ImportError::StagingUnexpectedEntry)?;
                Ok(())
            }),
            Err(ImportError::StagingUnexpectedEntry)
        ));
        assert!(!destination.exists());
        assert!(stage.path().is_dir());
    }

    #[test]
    fn target_name_cannot_impersonate_import_staging() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap_or_else(|e| panic!("mkdir: {e}"));
        assert!(matches!(
            scan_source(
                &source,
                &root
                    .path()
                    .join(format!("{IMPORT_STAGING_PREFIX}user-selected")),
            ),
            Err(ImportError::InvalidTargetPath)
        ));
    }

    #[test]
    fn dry_plan_budget_includes_private_files_ciphertext_and_publish_marker() {
        let root = TestDirectory::new();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap_or_else(|e| panic!("mkdir: {e}"));
        fs::write(source.join("entry.md"), b"source").unwrap_or_else(|e| panic!("write: {e}"));
        let plan = scan_source(&source, &root.path().join("vault"))
            .unwrap_or_else(|e| panic!("scan: {e}"));
        let expected =
            expected_staging_entries(&plan, true).unwrap_or_else(|e| panic!("budget: {e}"));
        for path in [
            PathBuf::from("vault.json"),
            PathBuf::from(VAULT_LOCAL_DIRECTORY),
            PathBuf::from(VAULT_LOCAL_DIRECTORY).join(VAULT_MUTATION_LOCK_FILE),
            PathBuf::from("entry.md.enc"),
            PathBuf::from(VAULT_LOCAL_DIRECTORY).join(IMPORT_PUBLISH_MARKER),
        ] {
            assert!(
                expected.contains_key(&path),
                "missing budget path: {path:?}"
            );
        }
        validate_planned_staging_budget(&plan).unwrap_or_else(|e| panic!("budget failed: {e}"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_chinese_path_budget_uses_core_encoded_bytes_boundary() {
        use std::os::windows::ffi::OsStrExt as _;

        let exact = PathBuf::from("中文");
        let maximum = exact.as_os_str().as_encoded_bytes().len();
        assert_eq!(encoded_path_len(&exact), maximum);
        assert_ne!(
            maximum,
            exact.as_os_str().encode_wide().count().saturating_mul(2)
        );
        validate_staging_path_byte_budget(std::iter::once(exact.as_path()), maximum)
            .unwrap_or_else(|error| panic!("exact boundary failed: {error}"));

        let over = PathBuf::from("中文a");
        assert!(matches!(
            validate_staging_path_byte_budget(std::iter::once(over.as_path()), maximum),
            Err(ImportError::TargetPathByteLimitExceeded)
        ));
    }
}
