//! Atomic ciphertext persistence and the per-vault mutation lock.
//!
//! A save is staged beside its destination, fully written and synchronized,
//! then committed while holding an OS-backed lock in `.vault-local`.  The
//! compare condition is deliberately checked *after* the lock is acquired.
//! No function in this module accepts or creates plaintext.
//!
//! The audited platform module at the end calls `flock(LOCK_EX)` on Linux and
//! `LockFileEx` on Windows, and supplies Windows handle identity/link checks
//! that stable `MetadataExt` does not expose. Closing the lock file releases
//! the lock on both platforms.
//!
//! Linux replacement commits use `rename(2)`, while create-only commits and
//! complete-vault publication use `renameat2(RENAME_NOREPLACE)`; both are
//! followed by a directory sync. Windows commits use
//! `MoveFileExW(MOVEFILE_WRITE_THROUGH)` because Win32 does not document
//! `FlushFileBuffers` as a portable directory-handle barrier. Inex never
//! removes the destination first. The v1 storage contract is consequently
//! limited to local filesystems that implement the platform move atomically.

#![allow(unsafe_code)]

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::path::LogicalPath;

/// Name of the vault-private directory used for process-local state.
pub const VAULT_LOCAL_DIRECTORY: &str = ".vault-local";

/// File locked by every ciphertext or metadata mutation in a vault.
pub const VAULT_MUTATION_LOCK_FILE: &str = "mutation.lock";

/// Prefix identifying abandoned encrypted staging files.
pub const CIPHERTEXT_STAGING_PREFIX: &str = ".inex-ciphertext-stage-";

/// Suffix for encrypted staging files; it intentionally is not Markdown.
pub const CIPHERTEXT_STAGING_SUFFIX: &str = ".tmp";

/// Crash-recovery record for a path-rebinding transaction.
pub const PENDING_REBIND_FILE: &str = "pending-rebind-v1";

/// Prefix used for complete encrypted vaults staged by copy import.
pub const IMPORT_STAGING_PREFIX: &str = ".inex-import-staging-";

/// Private marker temporarily held open across staged-vault publication.
pub const IMPORT_PUBLISH_MARKER: &str = "import-publish-marker-v1";

/// Repository-visible Git attributes installed by explicit user request.
pub const GIT_ATTRIBUTES_FILE: &str = ".gitattributes";

/// Repository-visible ignore rules installed by explicit user request.
pub const GIT_IGNORE_FILE: &str = ".gitignore";

const PENDING_REBIND_STAGING_PREFIX: &str = ".inex-rebind-stage-";
#[cfg(windows)]
const RETIRED_CIPHERTEXT_PREFIX: &str = ".inex-retired-ciphertext-";
const REBIND_JOURNAL_MAGIC: &[u8; 8] = b"INEXRB1\0";
const MAX_JOURNAL_PATH_BYTES: usize = 4 * 1024;

const MAX_STAGING_NAME_ATTEMPTS: usize = 32;
const ETAG_READ_BUFFER_SIZE: usize = 16 * 1024;
const MAX_ATOMIC_TARGET_BYTES: u64 = 32 * 1024 * 1024;

/// Optimistic concurrency condition for one ciphertext commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteCondition {
    /// Replace a regular target only when its complete ciphertext digest
    /// matches this SHA-256 value.
    IfMatch([u8; 32]),
    /// Create a target only when no filesystem entry currently uses its name.
    IfNoneMatch,
}

/// Result of the platform namespace-durability checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentSyncStatus {
    /// Linux synchronized the parent directory, or Windows completed a
    /// write-through namespace move.
    Synced,
    /// The platform or filesystem did not confirm namespace durability.
    NotSynced,
}

/// Successful atomic-write result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicWriteOutcome {
    /// SHA-256 digest of the complete committed ciphertext envelope.
    pub etag: [u8; 32],
    /// Whether the best-effort parent-directory sync succeeded.
    pub parent_sync: ParentSyncStatus,
}

/// Successful atomic publication of a complete staged vault directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicDirectoryPublishOutcome {
    /// Whether the containing directory was synchronized after publication.
    pub parent_sync: ParentSyncStatus,
}

/// Failure to atomically publish a complete staged vault without replacement.
#[derive(Debug, Error)]
pub enum AtomicDirectoryPublishError {
    /// The staging/final paths are not distinct direct children of one parent.
    #[error("staged-vault publication paths are invalid")]
    InvalidPaths,
    /// The final destination already has a filesystem entry.
    #[error("staged-vault destination already exists")]
    DestinationExists,
    /// The no-replace move left the exact complete staging tree in place.
    #[error("staged-vault namespace publication did not move the staging directory")]
    NotMoved,
    /// The platform cannot prove whether the complete staging directory moved.
    #[error("staged-vault namespace publication outcome is indeterminate")]
    Indeterminate,
    /// The complete staging tree was published, but its private marker remains.
    #[error("staged vault was published but private marker cleanup failed")]
    PublishedCleanupFailed,
    /// A scrubbed filesystem operation failed before publication.
    #[error("staged-vault publication I/O failed")]
    Io {
        /// Original error without caller data in this error's display text.
        #[source]
        source: io::Error,
    },
}

impl AtomicDirectoryPublishError {
    fn io(source: io::Error) -> Self {
        Self::Io { source }
    }
}

/// Successful conditional deletion result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicDeleteOutcome {
    /// Whether the containing directory was synchronized after deletion.
    pub parent_sync: ParentSyncStatus,
}

/// Successful authenticated path-rebinding result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicRebindOutcome {
    /// Digest of the complete destination envelope.
    pub etag: [u8; 32],
    /// Whether source retirement passed the platform durability checkpoint.
    pub source_parent_sync: ParentSyncStatus,
    /// Whether destination commit passed the platform durability checkpoint.
    pub destination_parent_sync: ParentSyncStatus,
}

/// Durability checkpoints reported after an atomic regular-file namespace move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicFileMoveOutcome {
    /// Whether the source parent recorded removal of the old source name.
    pub source_parent_sync: ParentSyncStatus,
    /// Whether the destination parent recorded publication of the new name.
    pub destination_parent_sync: ParentSyncStatus,
}

/// Result of checking a crash-recovery journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebindRecoveryOutcome {
    /// Whether a journal was reconciled and callers should invalidate cached
    /// tree/search state.
    pub changed_repository: bool,
}

/// Non-secret description of the target observed during a failed condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentTarget {
    /// No entry existed at the destination name.
    Absent,
    /// A regular file existed, with this complete-ciphertext SHA-256 digest.
    File([u8; 32]),
    /// An entry existed but was not a regular, non-symlink file.
    Other,
}

/// I/O stage associated with a scrubbed atomic-write failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AtomicWriteStage {
    /// Creating the same-directory staging file.
    CreateStaging,
    /// Writing the ciphertext staging file.
    WriteStaging,
    /// Flushing the staging file's userspace writer state.
    FlushStaging,
    /// Synchronizing staging content and metadata.
    SyncStaging,
    /// Reopening and hashing the synchronized staging file.
    VerifyStaging,
    /// Preparing `.vault-local` and its mutation-lock file.
    PrepareLock,
    /// Acquiring the operating-system mutation lock.
    AcquireLock,
    /// Reading the current target for the in-lock condition check.
    ReadCurrent,
    /// Preparing or reading the encrypted-only rebind recovery journal.
    RebindJournal,
    /// Renaming the complete staging file over the destination.
    Replace,
    /// Verifying the committed destination before source deletion.
    VerifyDestination,
    /// Removing an authenticated source after a rebind commit.
    RemoveSource,
    /// Removing an authenticated target after an in-lock condition check.
    RemoveTarget,
}

impl fmt::Display for AtomicWriteStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CreateStaging => "staging creation",
            Self::WriteStaging => "staging write",
            Self::FlushStaging => "staging flush",
            Self::SyncStaging => "staging sync",
            Self::VerifyStaging => "staging verification",
            Self::PrepareLock => "vault lock preparation",
            Self::AcquireLock => "vault lock acquisition",
            Self::ReadCurrent => "in-lock target read",
            Self::RebindJournal => "rebind recovery journal",
            Self::Replace => "atomic replacement",
            Self::VerifyDestination => "destination verification",
            Self::RemoveSource => "source removal",
            Self::RemoveTarget => "target removal",
        })
    }
}

/// Error returned by an atomic ciphertext write or vault-lock acquisition.
///
/// Display text deliberately omits paths, ciphertext bytes, and caller data.
#[derive(Debug, Error)]
pub enum AtomicWriteError {
    /// The destination has no usable file name or parent directory.
    #[error("atomic ciphertext destination is not a valid file path")]
    InvalidTarget,
    /// `.vault-local` or its lock path was a symlink or unexpected file type.
    #[error("vault mutation lock path is not a regular local path")]
    UnsafeLockPath,
    /// The caller's compare condition did not match the in-lock target state.
    #[error("ciphertext write condition did not match current target")]
    Conflict {
        /// State observed while holding the vault mutation lock.
        current: CurrentTarget,
    },
    /// A synchronized staging file did not hash to the supplied bytes.
    #[error("synchronized ciphertext staging verification failed")]
    StagingVerificationFailed,
    /// Caller supplied bytes that cannot later participate in bounded CAS.
    #[error("ciphertext target exceeds the atomic mutation size limit")]
    TargetTooLarge,
    /// The OS reported a namespace-move error and post-check state matched
    /// neither the complete requested target nor the exact pre-commit state.
    #[error("ciphertext namespace commit outcome is indeterminate")]
    NamespaceCommitIndeterminate {
        /// Digest of the complete ciphertext that was intended to commit.
        expected_etag: [u8; 32],
    },
    /// A rebind committed its destination but retained the source for safety.
    #[error("ciphertext rebind requires crash recovery before another mutation")]
    RebindPending {
        /// Digest of the complete destination envelope, when committed.
        destination_etag: [u8; 32],
    },
    /// A pending rebind journal could not be reconciled without risking data.
    #[error("pending ciphertext rebind has conflicting filesystem state")]
    RebindRecoveryConflict,
    /// A filesystem or OS-lock operation failed.
    #[error("atomic ciphertext operation failed during {stage}")]
    Io {
        /// Non-secret operation stage.
        stage: AtomicWriteStage,
        /// Original I/O failure. Standard library calls used here do not add
        /// file contents to their errors.
        #[source]
        source: io::Error,
    },
}

impl AtomicWriteError {
    fn io(stage: AtomicWriteStage, source: io::Error) -> Self {
        Self::Io { stage, source }
    }
}

/// Held exclusive OS lock for one vault's mutation domain.
///
/// Dropping this value closes the underlying file, which releases the lock.
pub struct VaultMutationLock {
    _file: File,
}

impl fmt::Debug for VaultMutationLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultMutationLock { .. }")
    }
}

/// Vault-scoped mutation guard for composing structural validation and commit
/// under one cross-process lock.
///
/// Repository code should prefer this guard over acquiring
/// [`VaultMutationLock`] directly. It permits a tree/collision check followed
/// by a write, delete, or rebind without releasing the cooperative mutation
/// domain in between.
pub struct VaultMutationGuard {
    root: PathBuf,
    recovery_changed_repository: bool,
    _lock: VaultMutationLock,
}

impl fmt::Debug for VaultMutationGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultMutationGuard { .. }")
    }
}

impl VaultMutationGuard {
    /// Acquires the vault mutation lock and resolves any safe pending rebind.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed lock or recovery error. A conflicting recovery state
    /// is left untouched for explicit user inspection.
    pub fn acquire(vault_root: &Path) -> Result<Self, AtomicWriteError> {
        let lock = VaultMutationLock::acquire(vault_root)?;
        let recovery_changed_repository = recover_pending_rebind_locked(vault_root)?;
        Ok(Self {
            root: vault_root.to_path_buf(),
            recovery_changed_repository,
            _lock: lock,
        })
    }

    /// Whether acquiring this guard reconciled a pending rebind journal.
    #[must_use]
    pub const fn recovery_changed_repository(&self) -> bool {
        self.recovery_changed_repository
    }

    /// Inspects one target while the mutation lock remains held.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed I/O error when the target cannot be safely read.
    pub fn inspect(&self, target: &Path) -> Result<CurrentTarget, AtomicWriteError> {
        ensure_write_target_in_root(&self.root, target)?;
        inspect_current_target(target)
    }

    /// Stages, verifies and conditionally commits ciphertext while this guard
    /// keeps structural checks serialized.
    ///
    /// # Errors
    ///
    /// Returns a condition conflict, staging verification failure, or scrubbed
    /// I/O error. Pre-commit errors preserve the previous target.
    pub fn write(
        &self,
        target: &Path,
        ciphertext: &[u8],
        condition: WriteCondition,
    ) -> Result<AtomicWriteOutcome, AtomicWriteError> {
        ensure_write_target_in_root(&self.root, target)?;
        let parent = target_parent(target).ok_or(AtomicWriteError::InvalidTarget)?;
        let (mut staging, etag) = stage_and_verify(parent, ciphertext, &NoFaults)?;
        let current = inspect_current_target(target)?;
        enforce_condition(condition, current)?;
        if let Err(source) = namespace_move(
            staging.path(),
            target,
            matches!(condition, WriteCondition::IfMatch(_)),
        ) {
            return reconcile_failed_namespace_commit(target, current, etag, source)
                .map(|parent_sync| AtomicWriteOutcome { etag, parent_sync });
        }
        staging.disarm();
        Ok(AtomicWriteOutcome {
            etag,
            parent_sync: sync_namespace_parent_status(parent),
        })
    }

    /// Conditionally deletes one target while this guard remains held.
    ///
    /// # Errors
    ///
    /// Returns a condition conflict or scrubbed filesystem error. Only
    /// [`WriteCondition::IfMatch`] is accepted.
    pub fn delete(
        &self,
        target: &Path,
        condition: WriteCondition,
    ) -> Result<AtomicDeleteOutcome, AtomicWriteError> {
        ensure_ciphertext_target_in_root(&self.root, target)?;
        if !matches!(condition, WriteCondition::IfMatch(_)) {
            return Err(AtomicWriteError::InvalidTarget);
        }
        let parent = target_parent(target).ok_or(AtomicWriteError::InvalidTarget)?;
        enforce_condition(condition, inspect_current_target(target)?)?;
        retire_ciphertext_entry(&self.root, target)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RemoveTarget, source))?;
        Ok(AtomicDeleteOutcome {
            parent_sync: sync_namespace_parent_status(parent),
        })
    }

    /// Commits a re-encrypted destination and removes its authenticated source
    /// with crash recovery.
    ///
    /// # Errors
    ///
    /// Returns a conflict, pending recovery state, or scrubbed I/O error. The
    /// source is retained unless the destination was committed and verified.
    pub fn rebind(
        &self,
        source: &Path,
        destination: &Path,
        replacement_envelope: &[u8],
        source_condition: WriteCondition,
        destination_condition: WriteCondition,
    ) -> Result<AtomicRebindOutcome, AtomicWriteError> {
        rebind_locked(
            &self.root,
            source,
            destination,
            replacement_envelope,
            source_condition,
            destination_condition,
        )
    }
}

impl VaultMutationLock {
    /// Acquires the exclusive cross-process mutation lock for `vault_root`.
    ///
    /// The lock lives at `.vault-local/mutation.lock`. The directory and file
    /// are created if necessary, with restrictive permissions where the host
    /// exposes a suitable standard-library API.
    ///
    /// # Errors
    ///
    /// Returns an error if the local lock path cannot be prepared, is a
    /// symlink/unexpected type, or the OS lock operation fails.
    pub fn acquire(vault_root: &Path) -> Result<Self, AtomicWriteError> {
        Self::acquire_with_faults(vault_root, &NoFaults)
    }

    fn acquire_with_faults<F: FaultInjector>(
        vault_root: &Path,
        faults: &F,
    ) -> Result<Self, AtomicWriteError> {
        faults
            .check(FaultPoint::PrepareLock)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;

        let lock_directory = vault_root.join(VAULT_LOCAL_DIRECTORY);
        prepare_lock_directory(vault_root, &lock_directory)?;
        let lock_path = lock_directory.join(VAULT_MUTATION_LOCK_FILE);
        reject_unsafe_existing_lock_file(vault_root, &lock_path)?;

        let file = open_lock_file(&lock_path)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;
        reject_unsafe_existing_lock_file(vault_root, &lock_path)?;
        restrict_file_permissions_best_effort(&file);

        faults
            .check(FaultPoint::AcquireLock)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::AcquireLock, source))?;
        platform::lock_exclusive(&file)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::AcquireLock, source))?;

        Ok(Self { _file: file })
    }
}

/// Writes and atomically commits an already-encrypted byte envelope.
///
/// `target` is never opened for writing. A random `create_new` staging file is
/// created in the same directory, written, flushed, and synchronized first.
/// The function then acquires the vault mutation lock, rechecks `condition`,
/// and renames the complete staging file over `target`. Parent-directory sync
/// is best effort and reported in the successful outcome.
///
/// The caller remains responsible for validating the EDRY envelope and for
/// ensuring `target` is the filesystem path of a validated logical vault path.
///
/// # Errors
///
/// Returns [`AtomicWriteError::Conflict`] when the target state does not match
/// `condition`. Other errors identify only a non-secret operation stage. Any
/// pre-replace error leaves the previous target untouched and makes a
/// best-effort attempt to remove the encrypted staging file.
pub fn atomic_write_ciphertext(
    vault_root: &Path,
    target: &Path,
    ciphertext: &[u8],
    condition: WriteCondition,
) -> Result<AtomicWriteOutcome, AtomicWriteError> {
    atomic_write_ciphertext_with_faults(vault_root, target, ciphertext, condition, &NoFaults)
}

/// Publish a complete encrypted staging vault as a previously absent vault.
///
/// Both paths must be distinct direct children of the same resolved local
/// filesystem directory, and the staging name must start with
/// [`IMPORT_STAGING_PREFIX`]. The platform namespace operation is strictly
/// no-replace (`renameat2(RENAME_NOREPLACE)` on Linux and `MoveFileExW`
/// without `MOVEFILE_REPLACE_EXISTING` on Windows). A synchronized random
/// marker inside `.vault-local` permits safe reconciliation when an operating
/// system reports an error after actually moving the directory.
///
/// # Errors
///
/// Returns [`AtomicDirectoryPublishError::DestinationExists`] without
/// replacing an existing entry. An indeterminate result is reported when
/// post-state does not prove either the old or complete new namespace state.
/// Inex never falls back to a replacing rename.
pub fn atomic_publish_directory_no_replace(
    staging: &Path,
    destination: &Path,
) -> Result<AtomicDirectoryPublishOutcome, AtomicDirectoryPublishError> {
    atomic_publish_directory_no_replace_checked(staging, destination, |_| Ok(()))
}

/// Publish a staged vault after running one final caller-supplied physical
/// audit with the synchronized publication marker present.
///
/// The audit runs after identities for the parent, staging root, private
/// directory, and marker have been captured, and immediately before the
/// no-replace namespace operation. It must inspect only ciphertext metadata
/// and names and must not mutate the staging tree.
///
/// # Errors
///
/// Returns the same fail-closed errors as
/// [`atomic_publish_directory_no_replace`], or a scrubbed I/O error when the
/// critical audit rejects the tree.
pub fn atomic_publish_directory_no_replace_checked<F>(
    staging: &Path,
    destination: &Path,
    critical_audit: F,
) -> Result<AtomicDirectoryPublishOutcome, AtomicDirectoryPublishError>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    atomic_publish_directory_no_replace_with_fault(
        staging,
        destination,
        critical_audit,
        false,
        false,
        false,
    )
}

#[allow(clippy::too_many_lines)]
fn atomic_publish_directory_no_replace_with_fault<F>(
    staging: &Path,
    destination: &Path,
    critical_audit: F,
    inject_error_after_move: bool,
    skip_move: bool,
    inject_marker_cleanup_failure: bool,
) -> Result<AtomicDirectoryPublishOutcome, AtomicDirectoryPublishError>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let staging_parent = staging
        .parent()
        .ok_or(AtomicDirectoryPublishError::InvalidPaths)?;
    let destination_parent = destination
        .parent()
        .ok_or(AtomicDirectoryPublishError::InvalidPaths)?;
    let staging_name = staging
        .file_name()
        .ok_or(AtomicDirectoryPublishError::InvalidPaths)?;
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    let destination_name = destination
        .file_name()
        .ok_or(AtomicDirectoryPublishError::InvalidPaths)?;
    if !staging_name
        .to_str()
        .is_some_and(|name| name.starts_with(IMPORT_STAGING_PREFIX))
        || staging == destination
    {
        return Err(AtomicDirectoryPublishError::InvalidPaths);
    }

    let resolved_parent =
        fs::canonicalize(staging_parent).map_err(AtomicDirectoryPublishError::io)?;
    let resolved_destination_parent =
        fs::canonicalize(destination_parent).map_err(AtomicDirectoryPublishError::io)?;
    if resolved_parent != resolved_destination_parent {
        return Err(AtomicDirectoryPublishError::InvalidPaths);
    }
    if !path_is_supported_local_filesystem(&resolved_parent)
        .map_err(AtomicDirectoryPublishError::io)?
        || !paths_share_mount(&resolved_parent, staging).map_err(AtomicDirectoryPublishError::io)?
    {
        return Err(AtomicDirectoryPublishError::InvalidPaths);
    }
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => return Err(AtomicDirectoryPublishError::DestinationExists),
        Err(error) => return Err(AtomicDirectoryPublishError::io(error)),
    }

    let parent_identity =
        filesystem_directory_identity(&resolved_parent).map_err(AtomicDirectoryPublishError::io)?;
    let staging_identity =
        filesystem_directory_identity(staging).map_err(AtomicDirectoryPublishError::io)?;
    let local = staging.join(VAULT_LOCAL_DIRECTORY);
    let local_identity =
        filesystem_directory_identity(&local).map_err(AtomicDirectoryPublishError::io)?;

    #[cfg(target_os = "linux")]
    let parent_handle = platform::open_source_directory_path(&resolved_parent)
        .map_err(AtomicDirectoryPublishError::io)?;
    #[cfg(target_os = "linux")]
    let staging_handle =
        platform::open_source_directory_path(staging).map_err(AtomicDirectoryPublishError::io)?;
    #[cfg(target_os = "linux")]
    let local_handle =
        platform::open_source_directory_path(&local).map_err(AtomicDirectoryPublishError::io)?;
    #[cfg(target_os = "linux")]
    if linux_directory_identity_from_file(&parent_handle)
        .ok()
        .as_ref()
        != Some(&parent_identity)
        || linux_directory_identity_from_file(&staging_handle)
            .ok()
            .as_ref()
            != Some(&staging_identity)
        || linux_directory_identity_from_file(&local_handle)
            .ok()
            .as_ref()
            != Some(&local_identity)
    {
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }
    #[cfg(target_os = "linux")]
    let publish_handles_match = || {
        linux_directory_identity_from_file(&parent_handle)
            .is_ok_and(|identity| identity == parent_identity)
            && linux_directory_identity_from_file(&staging_handle)
                .is_ok_and(|identity| identity == staging_identity)
            && linux_directory_identity_from_file(&local_handle)
                .is_ok_and(|identity| identity == local_identity)
    };
    #[cfg(not(target_os = "linux"))]
    let publish_handles_match = || true;

    let marker = local.join(IMPORT_PUBLISH_MARKER);
    let marker_bytes = *Uuid::new_v4().as_bytes();
    let mut marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .map_err(AtomicDirectoryPublishError::io)?;
    marker_file
        .write_all(&marker_bytes)
        .and_then(|()| marker_file.sync_all())
        .map_err(AtomicDirectoryPublishError::io)?;
    platform::sync_directory(&local).map_err(AtomicDirectoryPublishError::io)?;
    platform::sync_directory(staging).map_err(AtomicDirectoryPublishError::io)?;

    // Freeze all cooperative Inex mutations from the critical physical audit
    // through namespace publication and post-state reconciliation.
    let _vault_lock = VaultMutationLock::acquire(staging).map_err(|error| match error {
        AtomicWriteError::Io { source, .. } => AtomicDirectoryPublishError::io(source),
        _ => AtomicDirectoryPublishError::Indeterminate,
    })?;
    critical_audit(staging).map_err(AtomicDirectoryPublishError::io)?;
    if filesystem_directory_identity(&resolved_parent)
        .ok()
        .as_ref()
        != Some(&parent_identity)
        || filesystem_directory_identity(staging).ok().as_ref() != Some(&staging_identity)
        || filesystem_directory_identity(&local).ok().as_ref() != Some(&local_identity)
        || !marker_matches_open_file(&marker, &marker_file, marker_bytes.len())
        || !publish_handles_match()
    {
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }
    match inspect_directory_state(destination).map_err(AtomicDirectoryPublishError::io)? {
        DirectoryState::Absent => {}
        DirectoryState::Directory(_) | DirectoryState::Other => {
            return Err(AtomicDirectoryPublishError::DestinationExists);
        }
    }

    #[cfg(target_os = "linux")]
    let mut move_result = if skip_move {
        Err(io::Error::other("injected skipped namespace move"))
    } else {
        platform::namespace_move_no_replace_in_directory(
            &parent_handle,
            staging_name,
            destination_name,
        )
    };
    #[cfg(not(target_os = "linux"))]
    let mut move_result = if skip_move {
        Err(io::Error::other("injected skipped namespace move"))
    } else {
        namespace_move(staging, destination, false)
    };
    if inject_error_after_move && move_result.is_ok() {
        move_result = Err(io::Error::other(
            "injected return error after complete move",
        ));
    }

    let parent_unchanged = filesystem_directory_identity(&resolved_parent)
        .is_ok_and(|identity| identity == parent_identity);
    let stage_state = inspect_directory_state(staging);
    let destination_state = inspect_directory_state(destination);

    let exact_published = parent_unchanged
        && publish_handles_match()
        && matches!(stage_state, Ok(DirectoryState::Absent))
        && matches!(
            destination_state,
            Ok(DirectoryState::Directory(ref identity)) if *identity == staging_identity
        )
        && filesystem_directory_identity(&destination.join(VAULT_LOCAL_DIRECTORY))
            .is_ok_and(|identity| identity == local_identity)
        && marker_matches_open_file(
            &destination
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER),
            &marker_file,
            marker_bytes.len(),
        );
    if !exact_published {
        let exact_not_moved = parent_unchanged
            && matches!(
                stage_state,
                Ok(DirectoryState::Directory(ref identity)) if *identity == staging_identity
            )
            && matches!(destination_state, Ok(DirectoryState::Absent))
            && filesystem_directory_identity(&local)
                .is_ok_and(|identity| identity == local_identity)
            && marker_matches_open_file(&marker, &marker_file, marker_bytes.len());
        if exact_not_moved {
            return Err(AtomicDirectoryPublishError::NotMoved);
        }
        let stage_is_exact = matches!(
            stage_state,
            Ok(DirectoryState::Directory(ref identity)) if *identity == staging_identity
        );
        let final_is_unrelated = !matches!(destination_state, Ok(DirectoryState::Absent))
            && !matches!(
                destination_state,
                Ok(DirectoryState::Directory(ref identity)) if *identity == staging_identity
            );
        if parent_unchanged && stage_is_exact && final_is_unrelated {
            return Err(AtomicDirectoryPublishError::DestinationExists);
        }
        let _ = move_result;
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }

    let published_marker = destination
        .join(VAULT_LOCAL_DIRECTORY)
        .join(IMPORT_PUBLISH_MARKER);
    let marker_cleanup = if inject_marker_cleanup_failure {
        Err(io::Error::other(
            "injected publication-marker cleanup failure",
        ))
    } else {
        fs::remove_file(&published_marker)
    };
    if marker_cleanup.is_err() {
        let exact_published_with_marker = filesystem_directory_identity(&resolved_parent)
            .is_ok_and(|identity| identity == parent_identity)
            && filesystem_directory_identity(destination)
                .is_ok_and(|identity| identity == staging_identity)
            && filesystem_directory_identity(&destination.join(VAULT_LOCAL_DIRECTORY))
                .is_ok_and(|identity| identity == local_identity)
            && marker_matches_open_file(&published_marker, &marker_file, marker_bytes.len())
            && publish_handles_match();
        return Err(if exact_published_with_marker {
            AtomicDirectoryPublishError::PublishedCleanupFailed
        } else {
            AtomicDirectoryPublishError::Indeterminate
        });
    }
    drop(marker_file);
    if !matches!(fs::symlink_metadata(&published_marker), Err(error) if error.kind() == io::ErrorKind::NotFound)
    {
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }
    let internal_synced = platform::sync_directory(&destination.join(VAULT_LOCAL_DIRECTORY))
        .is_ok()
        && platform::sync_directory(destination).is_ok();
    let parent_synced = sync_namespace_parent(&resolved_parent).is_ok();
    if !filesystem_directory_identity(&resolved_parent)
        .is_ok_and(|identity| identity == parent_identity)
        || !filesystem_directory_identity(destination)
            .is_ok_and(|identity| identity == staging_identity)
        || !filesystem_directory_identity(&destination.join(VAULT_LOCAL_DIRECTORY))
            .is_ok_and(|identity| identity == local_identity)
        || !publish_handles_match()
    {
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }
    Ok(AtomicDirectoryPublishOutcome {
        parent_sync: if internal_synced && parent_synced {
            ParentSyncStatus::Synced
        } else {
            ParentSyncStatus::NotSynced
        },
    })
}

#[derive(Debug)]
enum DirectoryState {
    Absent,
    Directory(FilesystemDirectoryIdentity),
    Other,
}

fn inspect_directory_state(path: &Path) -> io::Result<DirectoryState> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DirectoryState::Absent);
        }
        Err(error) => return Err(error),
    };
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        return Ok(DirectoryState::Other);
    }
    filesystem_directory_identity(path).map(DirectoryState::Directory)
}

fn marker_matches_open_file(path: &Path, marker_file: &File, expected_len: usize) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() != u64::try_from(expected_len).unwrap_or(u64::MAX)
    {
        return false;
    }
    platform::open_file_matches_path_and_is_single_link_same_tree(path, marker_file)
        .unwrap_or(false)
}

fn atomic_write_ciphertext_with_faults<F: FaultInjector>(
    vault_root: &Path,
    target: &Path,
    ciphertext: &[u8],
    condition: WriteCondition,
    faults: &F,
) -> Result<AtomicWriteOutcome, AtomicWriteError> {
    ensure_write_target_in_root(vault_root, target)?;
    let parent = target_parent(target).ok_or(AtomicWriteError::InvalidTarget)?;
    let (mut staging, new_etag) = stage_and_verify(parent, ciphertext, faults)?;

    faults
        .check(FaultPoint::BeforeLock)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::AcquireLock, source))?;
    let _lock = VaultMutationLock::acquire_with_faults(vault_root, faults)?;
    let _ = recover_pending_rebind_locked(vault_root)?;

    faults
        .check(FaultPoint::ReadCurrent)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?;
    let current = inspect_current_target(target)?;
    enforce_condition(condition, current)?;

    faults
        .check(FaultPoint::Replace)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::Replace, source))?;
    if let Err(source) = namespace_move(
        staging.path(),
        target,
        matches!(condition, WriteCondition::IfMatch(_)),
    ) {
        return reconcile_failed_namespace_commit(target, current, new_etag, source).map(
            |parent_sync| AtomicWriteOutcome {
                etag: new_etag,
                parent_sync,
            },
        );
    }
    staging.disarm();

    let parent_sync =
        if faults.check(FaultPoint::SyncParent).is_ok() && sync_namespace_parent(parent).is_ok() {
            ParentSyncStatus::Synced
        } else {
            ParentSyncStatus::NotSynced
        };

    Ok(AtomicWriteOutcome {
        etag: new_etag,
        parent_sync,
    })
}

/// Conditionally deletes one regular ciphertext file while holding the vault
/// mutation lock.
///
/// A pending path-rebind transaction is recovered first. The target digest is
/// then re-read under the same lock and must match `condition`; callers cannot
/// request an unconditional delete.
///
/// # Errors
///
/// Returns [`AtomicWriteError::Conflict`] if the target is absent, unsafe, or
/// has changed. Other errors are scrubbed I/O or recovery failures.
pub fn atomic_delete_ciphertext(
    vault_root: &Path,
    target: &Path,
    condition: WriteCondition,
) -> Result<AtomicDeleteOutcome, AtomicWriteError> {
    VaultMutationGuard::acquire(vault_root)?.delete(target, condition)
}

/// Re-encrypts a file under a new authenticated logical path, then removes the
/// old path without risking loss of the source.
///
/// The destination envelope is staged and verified before the vault lock is
/// acquired. Under one lock, both source and destination conditions are
/// checked, a synchronized recovery journal is installed, and the destination
/// is committed and verified before source deletion. A crash or I/O failure
/// after destination commit leaves a journal that the next mutation (or
/// [`recover_pending_rebind`]) deterministically finishes.
///
/// # Errors
///
/// Returns a conflict when either condition fails, a pending/recovery error if
/// both paths must be retained, or a scrubbed I/O error before destination
/// commit. The function never removes the source unless the exact destination
/// bytes have been committed and re-read successfully.
pub fn atomic_rebind_ciphertext(
    vault_root: &Path,
    source: &Path,
    destination: &Path,
    replacement_envelope: &[u8],
    source_condition: WriteCondition,
    destination_condition: WriteCondition,
) -> Result<AtomicRebindOutcome, AtomicWriteError> {
    let guard = VaultMutationGuard::acquire(vault_root)?;
    guard.rebind(
        source,
        destination,
        replacement_envelope,
        source_condition,
        destination_condition,
    )
}

fn rebind_locked(
    vault_root: &Path,
    source: &Path,
    destination: &Path,
    replacement_envelope: &[u8],
    source_condition: WriteCondition,
    destination_condition: WriteCondition,
) -> Result<AtomicRebindOutcome, AtomicWriteError> {
    if source == destination
        || !matches!(source_condition, WriteCondition::IfMatch(_))
        || !matches!(destination_condition, WriteCondition::IfNoneMatch)
    {
        return Err(AtomicWriteError::InvalidTarget);
    }
    ensure_ciphertext_target_in_root(vault_root, source)?;
    ensure_ciphertext_target_in_root(vault_root, destination)?;
    let source_parent = target_parent(source).ok_or(AtomicWriteError::InvalidTarget)?;
    let destination_parent = target_parent(destination).ok_or(AtomicWriteError::InvalidTarget)?;
    let (mut staging, destination_etag) =
        stage_and_verify(destination_parent, replacement_envelope, &NoFaults)?;

    enforce_condition(source_condition, inspect_current_target(source)?)?;
    enforce_condition(destination_condition, inspect_current_target(destination)?)?;

    let source_etag = match source_condition {
        WriteCondition::IfMatch(etag) => etag,
        WriteCondition::IfNoneMatch => return Err(AtomicWriteError::InvalidTarget),
    };
    let journal = RebindJournal::new(
        vault_root,
        source,
        destination,
        source_etag,
        destination_etag,
    )?;
    install_rebind_journal(vault_root, &journal)?;

    if let Err(source) = namespace_move(staging.path(), destination, false) {
        return match inspect_current_target(destination) {
            Ok(CurrentTarget::File(actual)) if actual == destination_etag => {
                Err(AtomicWriteError::RebindPending { destination_etag })
            }
            Ok(CurrentTarget::Absent) => {
                remove_rebind_journal_best_effort(vault_root);
                Err(AtomicWriteError::io(AtomicWriteStage::Replace, source))
            }
            Ok(CurrentTarget::File(_) | CurrentTarget::Other) | Err(_) => {
                Err(AtomicWriteError::RebindRecoveryConflict)
            }
        };
    }
    staging.disarm();

    if inspect_current_target(destination)? != CurrentTarget::File(destination_etag) {
        return Err(AtomicWriteError::RebindPending { destination_etag });
    }
    let Ok(destination_parent_sync) = sync_rebind_parent(destination_parent) else {
        return Err(AtomicWriteError::RebindPending { destination_etag });
    };
    if retire_ciphertext_entry(vault_root, source).is_err() {
        return Err(AtomicWriteError::RebindPending { destination_etag });
    }
    let Ok(source_parent_sync) = sync_rebind_parent(source_parent) else {
        return Err(AtomicWriteError::RebindPending { destination_etag });
    };
    finish_rebind_journal(vault_root)?;
    Ok(AtomicRebindOutcome {
        etag: destination_etag,
        source_parent_sync,
        destination_parent_sync,
    })
}

/// Recovers a crash-interrupted rebind transaction, if present.
///
/// # Errors
///
/// Returns a scrubbed error when the journal is malformed or inaccessible, or
/// [`AtomicWriteError::RebindRecoveryConflict`] if current files no longer
/// match a state that can be completed without data loss.
pub fn recover_pending_rebind(
    vault_root: &Path,
) -> Result<RebindRecoveryOutcome, AtomicWriteError> {
    let _lock = VaultMutationLock::acquire(vault_root)?;
    recover_pending_rebind_locked(vault_root)
        .map(|changed_repository| RebindRecoveryOutcome { changed_repository })
}

/// Checks that an already-open regular file still names the same current path
/// entry and has exactly one hard link.
///
/// This is a narrow cross-platform no-follow primitive for bounded readers.
/// On Windows it uses `GetFileInformationByHandle` because the equivalent
/// stable `MetadataExt` identity/link methods are not available at the crate's
/// MSRV.
///
/// # Errors
///
/// Returns an I/O error if the path cannot be reopened without following its
/// final reparse point or either handle cannot be queried. `Ok(false)` means
/// identity, file type, reparse, or single-link validation failed.
pub fn open_file_matches_path_and_is_single_link(path: &Path, file: &File) -> io::Result<bool> {
    platform::open_file_matches_path_and_is_single_link(path, file)
}

/// Atomically moves one verified regular file to a previously absent name.
///
/// `source_file` must remain open for the call and must identify the exact
/// single-link regular file currently named by `source`. Both paths must be
/// absolute, have canonical non-link parents on one supported local mount,
/// and name direct children of those parents. The source file's content must
/// already have been synchronized when content durability is required.
///
/// The destination is never replaced. Linux uses
/// `renameat2(RENAME_NOREPLACE)` and Windows uses
/// `MoveFileExW(MOVEFILE_WRITE_THROUGH)` without the replace flag. A
/// successful cross-parent move checkpoints both parent directories and
/// reports each result independently.
///
/// The namespace operation is path based after the final handle/path identity
/// check. Callers must therefore exclude a non-cooperating process running as
/// the same OS user from directly rebinding either path during this call.
///
/// # Errors
///
/// Returns an I/O error when either path is unsafe, non-local, crosses a mount,
/// the source no longer matches `source_file`, the destination exists, or the
/// platform move fails. A move error is returned without deleting, retrying,
/// or otherwise reconciling either path; callers that need crash recovery must
/// inspect their own durable transaction record.
pub fn atomic_move_verified_file_no_replace(
    source: &Path,
    source_file: &File,
    destination: &Path,
) -> io::Result<AtomicFileMoveOutcome> {
    let paths = VerifiedFileMovePaths::resolve(source, destination)?;
    paths.verify_source(source_file)?;
    match fs::symlink_metadata(&paths.destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "atomic file-move destination already exists",
            ));
        }
        Err(error) => return Err(error),
    }
    paths.verify_parent_bindings()?;
    paths.verify_source(source_file)?;
    platform::namespace_move(&paths.source, &paths.destination, false)?;
    Ok(paths.sync_parents())
}

/// Atomically replaces one verified regular destination with a verified file.
///
/// `source_file` and `destination_file` are consumed by the call and must
/// identify the exact single-link regular files currently named by their
/// respective paths. Both paths must be absolute, have canonical non-link
/// parents on one supported local mount, and name direct children of those
/// parents. The source file's content must already have been synchronized when
/// content durability is required.
///
/// Linux uses one replacing `rename`, while Windows uses
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. The old
/// destination is never deleted first. A successful cross-parent replacement
/// checkpoints both parent directories and reports each result independently.
///
/// Both handles are released after the final handle/path identity check and
/// before the path-based namespace replacement so that Windows permits the
/// move. Callers must therefore exclude a non-cooperating process running as
/// the same OS user from directly rebinding either path during this call. This
/// helper is not a kernel-level handle-bound compare-and-exchange primitive.
///
/// # Errors
///
/// Returns an I/O error when either path is unsafe, non-local, crosses a mount,
/// either open file no longer matches its path, both paths identify one file,
/// or the platform move fails. A move error is returned without cleanup,
/// retry, or fallback; callers that need crash recovery must inspect their own
/// durable transaction record.
pub fn atomic_replace_verified_file(
    source: &Path,
    source_file: File,
    destination: &Path,
    destination_file: File,
) -> io::Result<AtomicFileMoveOutcome> {
    let paths = VerifiedFileMovePaths::resolve(source, destination)?;
    paths.verify_source(&source_file)?;
    paths.verify_destination(&destination_file)?;
    if open_file_matches_path_and_is_single_link(&paths.destination, &source_file)? {
        return Err(invalid_atomic_file_move(
            "atomic file-move paths identify one file",
        ));
    }
    paths.verify_parent_bindings()?;
    paths.verify_source(&source_file)?;
    paths.verify_destination(&destination_file)?;
    drop(destination_file);
    drop(source_file);
    platform::namespace_move(&paths.source, &paths.destination, true)?;
    Ok(paths.sync_parents())
}

#[derive(Debug)]
struct VerifiedFileMovePaths {
    source: PathBuf,
    destination: PathBuf,
    source_parent: PathBuf,
    destination_parent: PathBuf,
    source_parent_identity: FilesystemDirectoryIdentity,
    destination_parent_identity: FilesystemDirectoryIdentity,
}

impl VerifiedFileMovePaths {
    fn resolve(source: &Path, destination: &Path) -> io::Result<Self> {
        if !source.is_absolute()
            || !destination.is_absolute()
            || source == destination
            || !path_is_lexically_normal(source)
            || !path_is_lexically_normal(destination)
        {
            return Err(invalid_atomic_file_move(
                "atomic file-move paths must be distinct absolute paths",
            ));
        }
        let source_name = source
            .file_name()
            .ok_or_else(|| invalid_atomic_file_move("atomic file-move source has no file name"))?;
        let destination_name = destination.file_name().ok_or_else(|| {
            invalid_atomic_file_move("atomic file-move destination has no file name")
        })?;
        let source_parent = source
            .parent()
            .ok_or_else(|| invalid_atomic_file_move("atomic file-move source has no parent"))?;
        let destination_parent = destination.parent().ok_or_else(|| {
            invalid_atomic_file_move("atomic file-move destination has no parent")
        })?;
        if !path_ancestors_are_non_link_directories(source_parent)?
            || !path_ancestors_are_non_link_directories(destination_parent)?
        {
            return Err(invalid_atomic_file_move(
                "atomic file-move parent chain is not canonical and link-free",
            ));
        }
        let source_parent_input_identity = filesystem_directory_identity(source_parent)?;
        let destination_parent_input_identity = filesystem_directory_identity(destination_parent)?;
        let resolved_source_parent = fs::canonicalize(source_parent)?;
        let resolved_destination_parent = fs::canonicalize(destination_parent)?;
        let resolved_source = resolved_source_parent.join(source_name);
        let resolved_destination = resolved_destination_parent.join(destination_name);

        let source_parent_identity = filesystem_directory_identity(&resolved_source_parent)?;
        let destination_parent_identity =
            filesystem_directory_identity(&resolved_destination_parent)?;
        if source_parent_input_identity != source_parent_identity
            || destination_parent_input_identity != destination_parent_identity
            || source_parent_identity.volume != destination_parent_identity.volume
            || !paths_share_mount(&resolved_source_parent, &resolved_destination_parent)?
        {
            return Err(invalid_atomic_file_move(
                "atomic file-move paths cross a mount",
            ));
        }
        if !path_is_supported_local_filesystem(&resolved_source_parent)?
            || !path_is_supported_local_filesystem(&resolved_destination_parent)?
            || !path_is_supported_local_filesystem(&resolved_source)?
            || !paths_share_mount(&resolved_source_parent, &resolved_source)?
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "atomic file-move paths are not on one supported local mount",
            ));
        }

        Ok(Self {
            source: resolved_source,
            destination: resolved_destination,
            source_parent: resolved_source_parent,
            destination_parent: resolved_destination_parent,
            source_parent_identity,
            destination_parent_identity,
        })
    }

    fn verify_source(&self, source_file: &File) -> io::Result<()> {
        verify_open_single_link_regular_file(&self.source, source_file)?;
        if !paths_share_mount(&self.source_parent, &self.source)? {
            return Err(invalid_atomic_file_move(
                "atomic file-move source crosses a mount",
            ));
        }
        Ok(())
    }

    fn verify_destination(&self, destination_file: &File) -> io::Result<()> {
        verify_open_single_link_regular_file(&self.destination, destination_file)?;
        if !path_is_supported_local_filesystem(&self.destination)?
            || !paths_share_mount(&self.destination_parent, &self.destination)?
        {
            return Err(invalid_atomic_file_move(
                "atomic file-move destination crosses a mount",
            ));
        }
        Ok(())
    }

    fn verify_parent_bindings(&self) -> io::Result<()> {
        if filesystem_directory_identity(&self.source_parent)? != self.source_parent_identity
            || filesystem_directory_identity(&self.destination_parent)?
                != self.destination_parent_identity
        {
            return Err(invalid_atomic_file_move(
                "atomic file-move parent identity changed",
            ));
        }
        Ok(())
    }

    fn sync_parents(&self) -> AtomicFileMoveOutcome {
        let destination_parent_sync = sync_namespace_parent_status(&self.destination_parent);
        let source_parent_sync = if self.source_parent == self.destination_parent {
            destination_parent_sync
        } else {
            sync_namespace_parent_status(&self.source_parent)
        };
        AtomicFileMoveOutcome {
            source_parent_sync,
            destination_parent_sync,
        }
    }
}

fn path_is_lexically_normal(path: &Path) -> bool {
    path.components().all(|component| {
        matches!(
            component,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::Normal(_)
        )
    })
}

fn path_ancestors_are_non_link_directories(path: &Path) -> io::Result<bool> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)?;
        if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_open_single_link_regular_file(path: &Path, file: &File) -> io::Result<()> {
    if open_file_matches_path_and_is_single_link(path, file)? {
        Ok(())
    } else {
        Err(invalid_atomic_file_move(
            "atomic file-move path is not the verified single-link regular file",
        ))
    }
}

fn invalid_atomic_file_move(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Stable identity of one directory on its backing filesystem/volume.
///
/// This opaque value is suitable for equality checks that detect bind-mount,
/// junction, and alternate-spelling aliases without exposing platform handle
/// structures to callers.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FilesystemDirectoryIdentity {
    volume: u64,
    identifier: [u8; 16],
}

/// Obtain the filesystem identity of a non-link directory.
///
/// # Errors
///
/// Returns an I/O error when `path` is not a normal directory, is link-like,
/// or the platform cannot obtain a stable volume/file identifier.
pub fn filesystem_directory_identity(path: &Path) -> io::Result<FilesystemDirectoryIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory identity requires a non-link directory",
        ));
    }
    platform::filesystem_directory_identity(path, &metadata)
}

/// A Linux directory handle used for source import traversal without resolving
/// intermediate components through mutable path strings.
#[cfg(target_os = "linux")]
pub struct SecureSourceDirectory {
    file: File,
    path: PathBuf,
    identity: FilesystemDirectoryIdentity,
    parent: Option<(File, std::ffi::OsString)>,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for SecureSourceDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecureSourceDirectory { path: [REDACTED], .. }")
    }
}

/// One child opened relative to a held [`SecureSourceDirectory`] descriptor.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum SecureSourceChild {
    /// A non-link directory on the same mount.
    Directory(SecureSourceDirectory),
    /// A single-link regular file on the same mount.
    File(SecureSourceFile),
    /// A socket, FIFO, device, or another unsupported filesystem object.
    Other,
}

/// A Linux regular-file handle opened relative to a held source directory.
#[cfg(target_os = "linux")]
pub struct SecureSourceFile {
    file: File,
    parent: File,
    name: std::ffi::OsString,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for SecureSourceFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecureSourceFile { .. }")
    }
}

/// Open a canonical Linux source root as a held, non-link directory handle.
///
/// # Errors
///
/// Returns an I/O error when the root cannot be opened without following its
/// final component or its path no longer names the captured directory.
#[cfg(target_os = "linux")]
pub fn open_secure_source_root(path: &Path) -> io::Result<SecureSourceDirectory> {
    let file = platform::open_source_directory_path(path)?;
    let identity = linux_directory_identity_from_file(&file)?;
    if filesystem_directory_identity(path)? != identity {
        return Err(io::Error::other(
            "source root identity changed while opening",
        ));
    }
    Ok(SecureSourceDirectory {
        file,
        path: path.to_path_buf(),
        identity,
        parent: None,
    })
}

#[cfg(target_os = "linux")]
impl SecureSourceDirectory {
    /// Enumerate names through the held directory descriptor.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when descriptor-backed enumeration is unavailable.
    pub fn read_dir(&self) -> io::Result<fs::ReadDir> {
        platform::read_source_directory_handle(&self.file)
    }

    /// Open one direct child with `openat2`, `RESOLVE_BENEATH`,
    /// `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_XDEV`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for a missing/raced name, a link/magic-link,
    /// mount crossing, or a descriptor query failure.
    pub fn open_child(&self, name: &std::ffi::OsStr) -> io::Result<SecureSourceChild> {
        let file = platform::open_source_child(&self.file, name)?;
        let metadata = file.metadata()?;
        if metadata.file_type().is_dir() {
            let identity = linux_directory_identity_from_file(&file)?;
            return Ok(SecureSourceChild::Directory(SecureSourceDirectory {
                file,
                path: self.path.join(name),
                identity,
                parent: Some((self.file.try_clone()?, name.to_os_string())),
            }));
        }
        if metadata.file_type().is_file() {
            use std::os::unix::fs::MetadataExt as _;

            if metadata.nlink() != 1 {
                return Err(io::Error::other("source regular file is hard linked"));
            }
            return Ok(SecureSourceChild::File(SecureSourceFile {
                file,
                parent: self.file.try_clone()?,
                name: name.to_os_string(),
            }));
        }
        Ok(SecureSourceChild::Other)
    }

    /// Verify that the original namespace name still resolves to this handle.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the name is missing, link-like, cross-mount,
    /// or no longer has the captured identity.
    pub fn verify_binding(&self) -> io::Result<()> {
        let current = if let Some((parent, name)) = &self.parent {
            platform::open_source_child(parent, name)?
        } else {
            platform::open_source_directory_path(&self.path)?
        };
        if !current.metadata()?.file_type().is_dir()
            || linux_directory_identity_from_file(&current)? != self.identity
        {
            return Err(io::Error::other("source directory binding changed"));
        }
        Ok(())
    }

    /// Return the captured opaque directory identity.
    #[must_use]
    pub fn identity(&self) -> &FilesystemDirectoryIdentity {
        &self.identity
    }
}

#[cfg(target_os = "linux")]
impl SecureSourceFile {
    /// Return the length observed on the held file handle.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if metadata cannot be queried.
    pub fn observed_len(&self) -> io::Result<u64> {
        self.file.metadata().map(|metadata| metadata.len())
    }

    /// Verify that the parent-relative name still resolves to this exact,
    /// single-link regular-file handle.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for a raced name or identity/link mismatch.
    pub fn verify_binding(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        let current = platform::open_source_child(&self.parent, &self.name)?;
        let held = self.file.metadata()?;
        let observed = current.metadata()?;
        if !observed.file_type().is_file()
            || held.nlink() != 1
            || observed.nlink() != 1
            || held.dev() != observed.dev()
            || held.ino() != observed.ino()
        {
            return Err(io::Error::other("source file binding changed"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Read for SecureSourceFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

#[cfg(target_os = "linux")]
fn linux_directory_identity_from_file(file: &File) -> io::Result<FilesystemDirectoryIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source handle is not a directory",
        ));
    }
    let mut identifier = [0_u8; 16];
    identifier[..8].copy_from_slice(&metadata.ino().to_le_bytes());
    identifier[15] = 1;
    Ok(FilesystemDirectoryIdentity {
        volume: metadata.dev(),
        identifier,
    })
}

/// Reports whether a vault path resides on a supported local filesystem.
///
/// Linux rejects known network and FUSE mount types using the most-specific
/// `/proc/self/mountinfo` entry. Windows accepts fixed/removable/RAM volumes
/// and rejects remote, unknown, optical, and missing roots.
///
/// # Errors
///
/// Returns an I/O error when the platform cannot determine the backing volume
/// safely. Callers should fail closed rather than assuming local semantics.
pub fn path_is_supported_local_filesystem(path: &Path) -> io::Result<bool> {
    platform::path_is_supported_local_filesystem(path)
}

pub(crate) fn paths_share_mount(first: &Path, second: &Path) -> io::Result<bool> {
    platform::paths_share_mount(first, second)
}

fn reconcile_failed_namespace_commit(
    target: &Path,
    before: CurrentTarget,
    expected_etag: [u8; 32],
    source: io::Error,
) -> Result<ParentSyncStatus, AtomicWriteError> {
    match inspect_current_target(target) {
        Ok(CurrentTarget::File(actual)) if actual == expected_etag => {
            Ok(ParentSyncStatus::NotSynced)
        }
        Ok(after) if after == before => {
            Err(AtomicWriteError::io(AtomicWriteStage::Replace, source))
        }
        Ok(_) | Err(_) => Err(AtomicWriteError::NamespaceCommitIndeterminate { expected_etag }),
    }
}

fn stage_and_verify<F: FaultInjector>(
    parent: &Path,
    ciphertext: &[u8],
    faults: &F,
) -> Result<(StagingFile, [u8; 32]), AtomicWriteError> {
    if u64::try_from(ciphertext.len()).unwrap_or(u64::MAX) > MAX_ATOMIC_TARGET_BYTES {
        return Err(AtomicWriteError::TargetTooLarge);
    }
    let expected_etag = digest_bytes(ciphertext);
    faults
        .check(FaultPoint::CreateStaging)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::CreateStaging, source))?;
    let mut staging = StagingFile::create(parent)?;
    faults
        .check(FaultPoint::WriteStaging)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::WriteStaging, source))?;
    staging
        .file_mut()
        .write_all(ciphertext)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::WriteStaging, source))?;
    faults
        .check(FaultPoint::FlushStaging)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::FlushStaging, source))?;
    staging
        .file_mut()
        .flush()
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::FlushStaging, source))?;
    faults
        .check(FaultPoint::SyncStaging)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::SyncStaging, source))?;
    staging
        .file()
        .sync_all()
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::SyncStaging, source))?;
    staging.close();

    faults
        .check(FaultPoint::VerifyStaging)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::VerifyStaging, source))?;
    let actual_etag = digest_path(staging.path(), AtomicWriteStage::VerifyStaging)?;
    if actual_etag != expected_etag {
        return Err(AtomicWriteError::StagingVerificationFailed);
    }
    Ok((staging, expected_etag))
}

fn sync_namespace_parent_status(parent: &Path) -> ParentSyncStatus {
    if sync_namespace_parent(parent).is_ok() {
        ParentSyncStatus::Synced
    } else {
        ParentSyncStatus::NotSynced
    }
}

fn sync_rebind_parent(parent: &Path) -> Result<ParentSyncStatus, ()> {
    match sync_namespace_parent(parent) {
        Ok(()) => Ok(ParentSyncStatus::Synced),
        Err(_) => Err(()),
    }
}

#[derive(Debug)]
struct RebindJournal {
    source_relative: String,
    destination_relative: String,
    source_etag: [u8; 32],
    destination_etag: [u8; 32],
}

impl RebindJournal {
    fn new(
        vault_root: &Path,
        source: &Path,
        destination: &Path,
        source_etag: [u8; 32],
        destination_etag: [u8; 32],
    ) -> Result<Self, AtomicWriteError> {
        Ok(Self {
            source_relative: journal_relative_path(vault_root, source)?,
            destination_relative: journal_relative_path(vault_root, destination)?,
            source_etag,
            destination_etag,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, AtomicWriteError> {
        let source = self.source_relative.as_bytes();
        let destination = self.destination_relative.as_bytes();
        let source_length =
            u16::try_from(source.len()).map_err(|_| AtomicWriteError::InvalidTarget)?;
        let destination_length =
            u16::try_from(destination.len()).map_err(|_| AtomicWriteError::InvalidTarget)?;
        let mut bytes = Vec::with_capacity(76 + source.len() + destination.len());
        bytes.extend_from_slice(REBIND_JOURNAL_MAGIC);
        bytes.extend_from_slice(&source_length.to_be_bytes());
        bytes.extend_from_slice(&destination_length.to_be_bytes());
        bytes.extend_from_slice(&self.source_etag);
        bytes.extend_from_slice(&self.destination_etag);
        bytes.extend_from_slice(source);
        bytes.extend_from_slice(destination);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, AtomicWriteError> {
        const FIXED: usize = 8 + 2 + 2 + 32 + 32;
        if bytes.len() < FIXED || &bytes[..8] != REBIND_JOURNAL_MAGIC {
            return Err(AtomicWriteError::RebindRecoveryConflict);
        }
        let source_length = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
        let destination_length = usize::from(u16::from_be_bytes([bytes[10], bytes[11]]));
        if source_length == 0
            || destination_length == 0
            || source_length > MAX_JOURNAL_PATH_BYTES
            || destination_length > MAX_JOURNAL_PATH_BYTES
            || bytes.len() != FIXED + source_length + destination_length
        {
            return Err(AtomicWriteError::RebindRecoveryConflict);
        }
        let source_etag = bytes[12..44]
            .try_into()
            .map_err(|_| AtomicWriteError::RebindRecoveryConflict)?;
        let destination_etag = bytes[44..76]
            .try_into()
            .map_err(|_| AtomicWriteError::RebindRecoveryConflict)?;
        let source_relative = std::str::from_utf8(&bytes[FIXED..FIXED + source_length])
            .map_err(|_| AtomicWriteError::RebindRecoveryConflict)?
            .to_owned();
        let destination_relative = std::str::from_utf8(&bytes[FIXED + source_length..])
            .map_err(|_| AtomicWriteError::RebindRecoveryConflict)?
            .to_owned();
        validate_journal_relative_path(&source_relative)?;
        validate_journal_relative_path(&destination_relative)?;
        if source_relative == destination_relative {
            return Err(AtomicWriteError::RebindRecoveryConflict);
        }
        Ok(Self {
            source_relative,
            destination_relative,
            source_etag,
            destination_etag,
        })
    }
}

fn journal_relative_path(vault_root: &Path, target: &Path) -> Result<String, AtomicWriteError> {
    let relative = target
        .strip_prefix(vault_root)
        .map_err(|_| AtomicWriteError::InvalidTarget)?;
    let value = relative
        .to_str()
        .ok_or(AtomicWriteError::InvalidTarget)?
        .replace('\\', "/");
    validate_journal_relative_path(&value).map_err(|_| AtomicWriteError::InvalidTarget)?;
    Ok(value)
}

fn validate_journal_relative_path(value: &str) -> Result<(), AtomicWriteError> {
    if value.is_empty()
        || value.len() > MAX_JOURNAL_PATH_BYTES
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(AtomicWriteError::RebindRecoveryConflict);
    }
    LogicalPath::from_ciphertext_relative_path(Path::new(value))
        .map_err(|_| AtomicWriteError::RebindRecoveryConflict)?;
    Ok(())
}

fn pending_rebind_path(vault_root: &Path) -> PathBuf {
    vault_root
        .join(VAULT_LOCAL_DIRECTORY)
        .join(PENDING_REBIND_FILE)
}

fn install_rebind_journal(
    vault_root: &Path,
    journal: &RebindJournal,
) -> Result<(), AtomicWriteError> {
    let local = vault_root.join(VAULT_LOCAL_DIRECTORY);
    if case_alias_exists(&pending_rebind_path(vault_root))
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?
    {
        return Err(AtomicWriteError::RebindRecoveryConflict);
    }
    let bytes = journal.encode()?;
    let staging_path = local.join(format!(
        "{PENDING_REBIND_STAGING_PREFIX}{}",
        Uuid::new_v4().simple()
    ));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    configure_restrictive_creation(&mut options);
    let mut staging = options
        .open(&staging_path)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
    let result = (|| {
        restrict_file_permissions_best_effort(&staging);
        staging
            .write_all(&bytes)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
        staging
            .flush()
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
        staging
            .sync_all()
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
        drop(staging);
        namespace_move(&staging_path, &pending_rebind_path(vault_root), false)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
        sync_namespace_parent(&local)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging_path);
    }
    result
}

fn recover_pending_rebind_locked(vault_root: &Path) -> Result<bool, AtomicWriteError> {
    let journal_path = pending_rebind_path(vault_root);
    if case_alias_exists(&journal_path)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?
    {
        return Err(AtomicWriteError::RebindRecoveryConflict);
    }
    let metadata = match fs::symlink_metadata(&journal_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(AtomicWriteError::io(
                AtomicWriteStage::RebindJournal,
                source,
            ));
        }
    };
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_file() {
        return Err(AtomicWriteError::RebindRecoveryConflict);
    }
    if usize::try_from(metadata.len())
        .map_or(true, |length| length > 76 + MAX_JOURNAL_PATH_BYTES * 2)
    {
        return Err(AtomicWriteError::RebindRecoveryConflict);
    }
    let bytes = read_rebind_journal_bounded(&journal_path, 76 + MAX_JOURNAL_PATH_BYTES * 2)?;
    let journal = RebindJournal::decode(&bytes)?;
    let source = vault_root.join(&journal.source_relative);
    let destination = vault_root.join(&journal.destination_relative);
    ensure_ciphertext_target_in_root(vault_root, &source)
        .map_err(|_| AtomicWriteError::RebindRecoveryConflict)?;
    ensure_ciphertext_target_in_root(vault_root, &destination)
        .map_err(|_| AtomicWriteError::RebindRecoveryConflict)?;
    let source_state = inspect_current_target(&source)?;
    let destination_state = inspect_current_target(&destination)?;
    match (source_state, destination_state) {
        (CurrentTarget::File(source_etag), CurrentTarget::Absent)
            if source_etag == journal.source_etag =>
        {
            finish_rebind_journal(vault_root)?;
        }
        (CurrentTarget::File(source_etag), CurrentTarget::File(destination_etag))
            if source_etag == journal.source_etag
                && destination_etag == journal.destination_etag =>
        {
            let destination_parent =
                target_parent(&destination).ok_or(AtomicWriteError::RebindRecoveryConflict)?;
            if sync_rebind_parent(destination_parent).is_err() {
                return Err(AtomicWriteError::RebindPending {
                    destination_etag: journal.destination_etag,
                });
            }
            retire_ciphertext_entry(vault_root, &source).map_err(|_| {
                AtomicWriteError::RebindPending {
                    destination_etag: journal.destination_etag,
                }
            })?;
            let source_parent =
                target_parent(&source).ok_or(AtomicWriteError::RebindRecoveryConflict)?;
            if sync_rebind_parent(source_parent).is_err() {
                return Err(AtomicWriteError::RebindPending {
                    destination_etag: journal.destination_etag,
                });
            }
            finish_rebind_journal(vault_root)?;
        }
        (CurrentTarget::Absent, CurrentTarget::File(destination_etag))
            if destination_etag == journal.destination_etag =>
        {
            for parent in [target_parent(&destination), target_parent(&source)] {
                let parent = parent.ok_or(AtomicWriteError::RebindRecoveryConflict)?;
                if sync_rebind_parent(parent).is_err() {
                    return Err(AtomicWriteError::RebindPending {
                        destination_etag: journal.destination_etag,
                    });
                }
            }
            finish_rebind_journal(vault_root)?;
        }
        _ => return Err(AtomicWriteError::RebindRecoveryConflict),
    }
    Ok(true)
}

fn read_rebind_journal_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, AtomicWriteError> {
    let file = File::open(path)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
    if !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
        || !open_file_matches_path_and_is_single_link(path, &file)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?
    {
        return Err(AtomicWriteError::RebindRecoveryConflict);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
    if bytes.len() > maximum {
        return Err(AtomicWriteError::RebindRecoveryConflict);
    }
    Ok(bytes)
}

fn finish_rebind_journal(vault_root: &Path) -> Result<(), AtomicWriteError> {
    let path = pending_rebind_path(vault_root);
    match retire_ciphertext_entry(vault_root, &path) {
        Ok(()) => {
            sync_namespace_parent(&vault_root.join(VAULT_LOCAL_DIRECTORY))
                .map_err(|source| AtomicWriteError::io(AtomicWriteStage::RebindJournal, source))?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AtomicWriteError::io(
            AtomicWriteStage::RebindJournal,
            source,
        )),
    }
}

fn remove_rebind_journal_best_effort(vault_root: &Path) {
    let _ = retire_ciphertext_entry(vault_root, &pending_rebind_path(vault_root));
}

fn target_parent(target: &Path) -> Option<&Path> {
    target.file_name()?;
    match target.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Some(Path::new(".")),
        Some(parent) => Some(parent),
        None => Some(Path::new(".")),
    }
}

fn ensure_write_target_in_root(vault_root: &Path, target: &Path) -> Result<(), AtomicWriteError> {
    let relative = validated_relative_target(vault_root, target)?;
    if relative == Path::new("vault.json")
        || relative == Path::new(GIT_ATTRIBUTES_FILE)
        || relative == Path::new(GIT_IGNORE_FILE)
    {
        if case_alias_exists(target)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?
        {
            Err(AtomicWriteError::InvalidTarget)
        } else {
            Ok(())
        }
    } else {
        LogicalPath::from_ciphertext_relative_path(relative)
            .map(|_| ())
            .map_err(|_| AtomicWriteError::InvalidTarget)
    }
}

fn ensure_ciphertext_target_in_root(
    vault_root: &Path,
    target: &Path,
) -> Result<(), AtomicWriteError> {
    let relative = validated_relative_target(vault_root, target)?;
    LogicalPath::from_ciphertext_relative_path(relative)
        .map(|_| ())
        .map_err(|_| AtomicWriteError::InvalidTarget)
}

fn validated_relative_target<'a>(
    vault_root: &'a Path,
    target: &'a Path,
) -> Result<&'a Path, AtomicWriteError> {
    let relative = target
        .strip_prefix(vault_root)
        .map_err(|_| AtomicWriteError::InvalidTarget)?;
    if relative.as_os_str().is_empty() {
        return Err(AtomicWriteError::InvalidTarget);
    }

    let root_metadata = fs::symlink_metadata(vault_root)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?;
    if is_link_or_reparse_point(&root_metadata) || !root_metadata.file_type().is_dir() {
        return Err(AtomicWriteError::InvalidTarget);
    }

    let mut current = vault_root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(component) = component else {
            return Err(AtomicWriteError::InvalidTarget);
        };
        if component.to_str().is_some_and(|name| {
            name.eq_ignore_ascii_case(VAULT_LOCAL_DIRECTORY) || name.eq_ignore_ascii_case(".git")
        }) {
            return Err(AtomicWriteError::InvalidTarget);
        }
        if components.peek().is_none() {
            break;
        }
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?;
        if is_link_or_reparse_point(&metadata)
            || !metadata.file_type().is_dir()
            || !platform::metadata_is_same_filesystem(&root_metadata, &metadata)
        {
            return Err(AtomicWriteError::InvalidTarget);
        }
    }
    let parent = target.parent().ok_or(AtomicWriteError::InvalidTarget)?;
    if !platform::paths_share_mount(vault_root, parent)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?
    {
        return Err(AtomicWriteError::InvalidTarget);
    }
    match fs::symlink_metadata(target) {
        Ok(metadata)
            if !platform::metadata_is_same_filesystem(&root_metadata, &metadata)
                || !platform::paths_share_mount(vault_root, target).map_err(|source| {
                    AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source)
                })? =>
        {
            return Err(AtomicWriteError::InvalidTarget);
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source));
        }
    }
    Ok(relative)
}

fn enforce_condition(
    condition: WriteCondition,
    current: CurrentTarget,
) -> Result<(), AtomicWriteError> {
    let matches = match (condition, current) {
        (WriteCondition::IfMatch(expected), CurrentTarget::File(actual)) => expected == actual,
        (WriteCondition::IfNoneMatch, CurrentTarget::Absent) => true,
        (WriteCondition::IfMatch(_), CurrentTarget::Absent | CurrentTarget::Other)
        | (WriteCondition::IfNoneMatch, CurrentTarget::File(_) | CurrentTarget::Other) => false,
    };
    if matches {
        Ok(())
    } else {
        Err(AtomicWriteError::Conflict { current })
    }
}

fn inspect_current_target(target: &Path) -> Result<CurrentTarget, AtomicWriteError> {
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(CurrentTarget::Absent),
        Err(source) => {
            return Err(AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source));
        }
    };
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_ATOMIC_TARGET_BYTES
    {
        return Ok(CurrentTarget::Other);
    }

    let mut file = match File::open(target) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(CurrentTarget::Absent),
        Err(source) => {
            return Err(AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source));
        }
    };

    let handle_metadata = file
        .metadata()
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?;
    if !handle_metadata.file_type().is_file()
        || handle_metadata.len() > MAX_ATOMIC_TARGET_BYTES
        || !open_file_matches_path_and_is_single_link(target, &file)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?
    {
        return Ok(CurrentTarget::Other);
    }

    let Some(digest) = digest_reader_bounded(&mut file, MAX_ATOMIC_TARGET_BYTES)? else {
        return Ok(CurrentTarget::Other);
    };
    Ok(CurrentTarget::File(digest))
}

fn digest_reader_bounded<R: Read>(
    reader: &mut R,
    maximum: u64,
) -> Result<Option<[u8; 32]>, AtomicWriteError> {
    let mut limited = reader.take(maximum.saturating_add(1));
    let digest = digest_reader(&mut limited)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?;
    if limited.limit() == 0 {
        Ok(None)
    } else {
        Ok(Some(digest))
    }
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn digest_path(path: &Path, stage: AtomicWriteStage) -> Result<[u8; 32], AtomicWriteError> {
    let mut file = File::open(path).map_err(|source| AtomicWriteError::io(stage, source))?;
    digest_reader(&mut file).map_err(|source| AtomicWriteError::io(stage, source))
}

fn digest_reader<R: Read>(reader: &mut R) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; ETAG_READ_BUFFER_SIZE];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(read) => hasher.update(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn prepare_lock_directory(vault_root: &Path, path: &Path) -> Result<(), AtomicWriteError> {
    if case_alias_exists(path)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?
    {
        return Err(AtomicWriteError::UnsafeLockPath);
    }
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(AtomicWriteError::io(AtomicWriteStage::PrepareLock, source));
        }
    }

    let metadata = fs::symlink_metadata(path)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;
    let root_metadata = fs::symlink_metadata(vault_root)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
        || !platform::metadata_is_same_filesystem(&root_metadata, &metadata)
        || !platform::paths_share_mount(vault_root, path)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?
    {
        return Err(AtomicWriteError::UnsafeLockPath);
    }
    restrict_directory_permissions_best_effort(path);
    Ok(())
}

fn reject_unsafe_existing_lock_file(
    vault_root: &Path,
    path: &Path,
) -> Result<(), AtomicWriteError> {
    if case_alias_exists(path)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?
    {
        return Err(AtomicWriteError::UnsafeLockPath);
    }
    let root_metadata = fs::symlink_metadata(vault_root)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if is_link_or_reparse_point(&metadata)
                || !metadata.file_type().is_file()
                || !platform::metadata_is_same_filesystem(&root_metadata, &metadata)
                || !platform::paths_share_mount(vault_root, path).map_err(|source| {
                    AtomicWriteError::io(AtomicWriteStage::PrepareLock, source)
                })? =>
        {
            Err(AtomicWriteError::UnsafeLockPath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AtomicWriteError::io(AtomicWriteStage::PrepareLock, source)),
    }
}

fn case_alias_exists(path: &Path) -> io::Result<bool> {
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    let Some(expected) = path.file_name() else {
        return Ok(false);
    };
    let Some(expected_text) = expected.to_str() else {
        return Ok(true);
    };
    for entry in fs::read_dir(parent)? {
        let actual = entry?.file_name();
        if actual != expected
            && actual
                .to_str()
                .is_some_and(|text| text.eq_ignore_ascii_case(expected_text))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    configure_restrictive_creation(&mut options);
    options.open(path)
}

fn namespace_move(source: &Path, destination: &Path, replace: bool) -> io::Result<()> {
    platform::namespace_move(source, destination, replace)
}

fn sync_namespace_parent(parent: &Path) -> io::Result<()> {
    platform::sync_namespace_parent(parent)
}

#[cfg(windows)]
fn retire_ciphertext_entry(vault_root: &Path, target: &Path) -> io::Result<()> {
    let local = vault_root.join(VAULT_LOCAL_DIRECTORY);
    for _ in 0..MAX_STAGING_NAME_ATTEMPTS {
        let retired = local.join(format!(
            "{RETIRED_CIPHERTEXT_PREFIX}{}",
            Uuid::new_v4().simple()
        ));
        match namespace_move(target, &retired, false) {
            Ok(()) => {
                let _ = fs::remove_file(retired);
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "retired ciphertext name attempts exhausted",
    ))
}

#[cfg(not(windows))]
fn retire_ciphertext_entry(_vault_root: &Path, target: &Path) -> io::Result<()> {
    fs::remove_file(target)
}

/// Synchronize a directory after committing non-secret repository metadata.
///
/// Linux uses a directory `fsync`; Windows reports the result of the audited
/// write-through namespace path. Callers must already have validated the
/// directory and must never use this helper as a substitute for an atomic
/// move.
///
/// # Errors
///
/// Returns the platform I/O error when the directory durability checkpoint
/// cannot be completed.
pub fn sync_directory(parent: &Path) -> io::Result<()> {
    platform::sync_directory(parent)
}

struct StagingFile {
    path: PathBuf,
    file: Option<File>,
    armed: bool,
}

impl StagingFile {
    fn create(parent: &Path) -> Result<Self, AtomicWriteError> {
        for _ in 0..MAX_STAGING_NAME_ATTEMPTS {
            let path = random_staging_path(parent);
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            configure_restrictive_creation(&mut options);
            match options.open(&path) {
                Ok(file) => {
                    restrict_file_permissions_best_effort(&file);
                    return Ok(Self {
                        path,
                        file: Some(file),
                        armed: true,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(AtomicWriteError::io(
                        AtomicWriteStage::CreateStaging,
                        source,
                    ));
                }
            }
        }

        Err(AtomicWriteError::io(
            AtomicWriteStage::CreateStaging,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique encrypted staging name",
            ),
        ))
    }

    fn file(&self) -> &File {
        self.file
            .as_ref()
            .unwrap_or_else(|| unreachable!("open staging file invariant"))
    }

    fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .unwrap_or_else(|| unreachable!("open staging file invariant"))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn close(&mut self) {
        drop(self.file.take());
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn random_staging_path(parent: &Path) -> PathBuf {
    let random = Uuid::new_v4().simple();
    parent.join(format!(
        "{CIPHERTEXT_STAGING_PREFIX}{random}{CIPHERTEXT_STAGING_SUFFIX}"
    ))
}

#[cfg(not(windows))]
fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0
}

#[cfg(unix)]
fn configure_restrictive_creation(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn configure_restrictive_creation(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn restrict_file_permissions_best_effort(file: &File) {
    use std::os::unix::fs::PermissionsExt;

    let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file_permissions_best_effort(_file: &File) {
    // Windows has no std API for constructing a current-user-only DACL.
    // The staging file inherits the containing vault directory's ACL.
}

#[cfg(unix)]
fn restrict_directory_permissions_best_effort(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_directory_permissions_best_effort(_path: &Path) {
    // The directory inherits the vault root's ACL on Windows.
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    CreateStaging,
    WriteStaging,
    FlushStaging,
    SyncStaging,
    VerifyStaging,
    BeforeLock,
    PrepareLock,
    AcquireLock,
    ReadCurrent,
    Replace,
    SyncParent,
}

trait FaultInjector: Sync {
    fn check(&self, point: FaultPoint) -> io::Result<()>;
}

#[derive(Debug)]
struct NoFaults;

impl FaultInjector for NoFaults {
    fn check(&self, _point: FaultPoint) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CString;
    use std::fs::{self, File, Metadata};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    const LOCK_EX: i32 = 2;
    const AT_FDCWD: i32 = -100;
    const RENAME_NOREPLACE: u32 = 1;
    const O_DIRECTORY: i32 = 0o200_000;
    const O_NOFOLLOW: i32 = 0o400_000;
    const O_CLOEXEC: i32 = 0o2_000_000;
    const O_NONBLOCK: i32 = 0o4_000;
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const SYS_OPENAT2: isize = 437;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[link(name = "c")]
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
        fn renameat2(
            old_directory_fd: i32,
            old_path: *const std::ffi::c_char,
            new_directory_fd: i32,
            new_path: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
        fn syscall(number: isize, ...) -> isize;
    }

    pub(super) fn lock_exclusive(file: &File) -> io::Result<()> {
        loop {
            // SAFETY: `file` owns a valid descriptor for the duration of this
            // call, and `LOCK_EX` is the Linux flock exclusive-lock flag.
            if unsafe { flock(file.as_raw_fd(), LOCK_EX) } == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    pub(super) fn open_source_directory_path(path: &Path) -> io::Result<File> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secure directory root must be absolute",
            ));
        }
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "secure directory root contains NUL",
            )
        })?;
        let how = OpenHow {
            flags: u64::try_from(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC).unwrap_or(0),
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        // SAFETY: `path` and `how` remain live for the syscall, the size is
        // the kernel open_how v0 layout, and a successful descriptor is
        // transferred exactly once into `File`.
        let descriptor = unsafe {
            syscall(
                SYS_OPENAT2,
                AT_FDCWD,
                path.as_ptr(),
                &raw const how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = i32::try_from(descriptor)
            .map_err(|_| io::Error::other("openat2 returned an invalid descriptor"))?;
        // SAFETY: the successful syscall returned one owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    pub(super) fn open_source_child(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "source child name contains NUL",
            )
        })?;
        if name.as_bytes().contains(&b'/') || matches!(name.as_bytes(), b"." | b"..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source child must be one normal component",
            ));
        }
        let how = OpenHow {
            flags: u64::try_from(O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK).unwrap_or(0),
            mode: 0,
            resolve: RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS
                | RESOLVE_BENEATH,
        };
        // SAFETY: `name` and `how` are live for the syscall, the size matches
        // the kernel open_how v0 layout, and a nonnegative descriptor is
        // transferred exactly once into `File`.
        let descriptor = unsafe {
            syscall(
                SYS_OPENAT2,
                parent.as_raw_fd(),
                name.as_ptr(),
                &raw const how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = i32::try_from(descriptor)
            .map_err(|_| io::Error::other("openat2 descriptor overflow"))?;
        // SAFETY: the successful syscall returned one newly owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    pub(super) fn read_source_directory_handle(directory: &File) -> io::Result<fs::ReadDir> {
        fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
    }

    pub(super) fn metadata_is_same_filesystem(first: &Metadata, second: &Metadata) -> bool {
        first.dev() == second.dev()
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn filesystem_directory_identity(
        _path: &Path,
        metadata: &Metadata,
    ) -> io::Result<super::FilesystemDirectoryIdentity> {
        let mut identifier = [0_u8; 16];
        identifier[..8].copy_from_slice(&metadata.ino().to_le_bytes());
        identifier[15] = 1;
        Ok(super::FilesystemDirectoryIdentity {
            volume: metadata.dev(),
            identifier,
        })
    }

    pub(super) fn paths_share_mount(first: &Path, second: &Path) -> io::Result<bool> {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
        let first = std::fs::canonicalize(first)?;
        let second = std::fs::canonicalize(second)?;
        Ok(matches!(
            (
                mount_id_for_path(&mountinfo, &first)?,
                mount_id_for_path(&mountinfo, &second)?,
            ),
            (Some(first), Some(second)) if first == second
        ))
    }

    pub(super) fn open_file_matches_path_and_is_single_link(
        path: &Path,
        file: &File,
    ) -> io::Result<bool> {
        let handle = file.metadata()?;
        let current = std::fs::symlink_metadata(path)?;
        Ok(!current.file_type().is_symlink()
            && current.file_type().is_file()
            && handle.file_type().is_file()
            && current.nlink() == 1
            && handle.nlink() == 1
            && current.dev() == handle.dev()
            && current.ino() == handle.ino())
    }

    pub(super) fn open_file_matches_path_and_is_single_link_same_tree(
        path: &Path,
        file: &File,
    ) -> io::Result<bool> {
        open_file_matches_path_and_is_single_link(path, file)
    }

    pub(super) fn path_is_supported_local_filesystem(path: &Path) -> io::Result<bool> {
        let canonical = std::fs::canonicalize(path)?;
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
        let Some((_, filesystem_type)) = mount_for_path(&mountinfo, &canonical)? else {
            return Ok(false);
        };
        Ok(!is_unsupported_filesystem_type(filesystem_type))
    }

    fn mount_id_for_path(mountinfo: &str, path: &Path) -> io::Result<Option<u64>> {
        mount_for_path(mountinfo, path).map(|selected| selected.map(|(mount_id, _)| mount_id))
    }

    fn mount_for_path<'a>(mountinfo: &'a str, path: &Path) -> io::Result<Option<(u64, &'a str)>> {
        let mut selected: Option<(usize, u64, &str)> = None;
        for line in mountinfo.lines() {
            let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
                continue;
            };
            let mut fields = mount_fields.split_whitespace();
            let Some(mount_id) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            let Some(encoded_mount) = mount_fields.split_whitespace().nth(4) else {
                continue;
            };
            let Some(filesystem_type) = filesystem_fields.split_whitespace().next() else {
                continue;
            };
            let mount = decode_mountinfo_path(encoded_mount)?;
            if path.starts_with(&mount) {
                let specificity = mount.as_os_str().as_encoded_bytes().len();
                if selected.is_none_or(|(current, _, _)| specificity >= current) {
                    selected = Some((specificity, mount_id, filesystem_type));
                }
            }
        }
        Ok(selected.map(|(_, mount_id, filesystem_type)| (mount_id, filesystem_type)))
    }

    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }

    pub(super) fn namespace_move(
        source: &Path,
        destination: &Path,
        replace: bool,
    ) -> io::Result<()> {
        if replace {
            return std::fs::rename(source, destination);
        }
        let source = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
        let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
        })?;
        // SAFETY: both C strings are live and NUL terminated. AT_FDCWD makes
        // absolute paths resolve independently of any borrowed directory fd.
        if unsafe {
            renameat2(
                AT_FDCWD,
                source.as_ptr(),
                AT_FDCWD,
                destination.as_ptr(),
                RENAME_NOREPLACE,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn namespace_move_no_replace_in_directory(
        parent: &File,
        source_name: &std::ffi::OsStr,
        destination_name: &std::ffi::OsStr,
    ) -> io::Result<()> {
        let source = CString::new(source_name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source name contains NUL"))?;
        let destination = CString::new(destination_name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination name contains NUL")
        })?;
        if source.as_bytes().contains(&b'/') || destination.as_bytes().contains(&b'/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "namespace publication requires direct child names",
            ));
        }
        // SAFETY: both names are live/NUL terminated direct-child names and
        // `parent` keeps the same directory descriptor live for both sides.
        if unsafe {
            renameat2(
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
                RENAME_NOREPLACE,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn sync_namespace_parent(path: &Path) -> io::Result<()> {
        sync_directory(path)
    }

    fn decode_mountinfo_path(value: &str) -> io::Result<PathBuf> {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'\\' && index + 3 < bytes.len() {
                let digits = &bytes[index + 1..index + 4];
                if digits.iter().all(|digit| matches!(digit, b'0'..=b'7')) {
                    decoded.push(
                        (digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + (digits[2] - b'0'),
                    );
                    index += 4;
                    continue;
                }
            }
            decoded.push(bytes[index]);
            index += 1;
        }
        if decoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mountinfo path contains NUL",
            ));
        }
        Ok(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
    }

    fn is_unsupported_filesystem_type(filesystem_type: &str) -> bool {
        filesystem_type.starts_with("fuse")
            || matches!(
                filesystem_type,
                "9p" | "afs"
                    | "ceph"
                    | "cifs"
                    | "coda"
                    | "davfs"
                    | "gfs"
                    | "gfs2"
                    | "glusterfs"
                    | "lustre"
                    | "ncp"
                    | "nfs"
                    | "nfs4"
                    | "ocfs2"
                    | "smb3"
            )
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::fs::{File, Metadata, OpenOptions};
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;

    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ID_INFO_CLASS: i32 = 18;
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_RAMDISK: u32 = 6;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const VERBATIM_PATH_PREFIX: [u16; 4] = [92, 92, 63, 92];
    const DEVICE_PATH_PREFIX: [u16; 4] = [92, 92, 46, 92];
    const VERBATIM_UNC_PATH_PREFIX: [u16; 8] = [92, 92, 63, 92, 85, 78, 67, 92];

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut c_void,
    }

    impl Overlapped {
        const fn zeroed() -> Self {
            Self {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event: std::ptr::null_mut(),
            }
        }
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LockFileEx(
            file: *mut c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
        fn GetFileInformationByHandleEx(
            file: *mut c_void,
            information_class: i32,
            information: *mut c_void,
            buffer_size: u32,
        ) -> i32;
        fn GetVolumePathNameW(
            file_name: *const u16,
            volume_path_name: *mut u16,
            buffer_length: u32,
        ) -> i32;
        fn GetDriveTypeW(root_path_name: *const u16) -> u32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;
        fn FlushFileBuffers(file: *mut c_void) -> i32;
        fn CloseHandle(object: *mut c_void) -> i32;
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct FileId128 {
        identifier: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: FileId128,
    }

    pub(super) fn lock_exclusive(file: &File) -> io::Result<()> {
        let mut overlapped = Overlapped::zeroed();
        // SAFETY: the raw handle remains owned by `file`; `overlapped` is a
        // correctly laid out, live OVERLAPPED value for this synchronous call.
        let result = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                u32::MAX,
                u32::MAX,
                &raw mut overlapped,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn metadata_is_same_filesystem(_first: &Metadata, _second: &Metadata) -> bool {
        // Directory mount points and junctions carry the reparse attribute and
        // are rejected before traversal. Regular files cannot span volumes.
        true
    }

    pub(super) fn filesystem_directory_identity(
        path: &Path,
        _metadata: &Metadata,
    ) -> io::Result<super::FilesystemDirectoryIdentity> {
        let encoded = extended_path(path)?;
        // SAFETY: the path is live/NUL terminated and the returned handle is
        // checked before ownership is transferred exactly once to `File`.
        let handle = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == std::ptr::without_provenance_mut::<c_void>(usize::MAX) {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is live and uniquely owned after successful
        // CreateFileW; `File` closes it once on drop.
        let file = unsafe { File::from_raw_handle(handle) };
        let legacy = handle_information(&file)?;
        if legacy.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory identity rejected a reparse point",
            ));
        }
        let modern = file_id_information(&file)?;
        if modern.file_id.identifier.iter().any(|byte| *byte != 0) {
            return Ok(super::FilesystemDirectoryIdentity {
                volume: modern.volume_serial_number,
                identifier: modern.file_id.identifier,
            });
        }
        let file_index = u64::from(legacy.file_index_high) << 32 | u64::from(legacy.file_index_low);
        if file_index == 0 {
            return Err(io::Error::other("directory identity is unavailable"));
        }
        let mut identifier = [0_u8; 16];
        identifier[..8].copy_from_slice(&file_index.to_le_bytes());
        identifier[15] = 1;
        Ok(super::FilesystemDirectoryIdentity {
            volume: u64::from(legacy.volume_serial_number),
            identifier,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn paths_share_mount(_first: &Path, _second: &Path) -> io::Result<bool> {
        // Traversed mount points are reparse points and fail before this check.
        Ok(true)
    }

    pub(super) fn open_file_matches_path_and_is_single_link(
        path: &Path,
        file: &File,
    ) -> io::Result<bool> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let current = options.open(path)?;
        let handle_info = handle_information(file)?;
        let current_info = handle_information(&current)?;
        let handle_id = file_id_information(file)?;
        let current_id = file_id_information(&current)?;
        Ok(
            handle_info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && current_info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && handle_info.number_of_links == 1
                && current_info.number_of_links == 1
                && same_file_identity(&handle_info, &current_info, &handle_id, &current_id),
        )
    }

    pub(super) fn open_file_matches_path_and_is_single_link_same_tree(
        path: &Path,
        file: &File,
    ) -> io::Result<bool> {
        // This narrow comparison is used only after the publisher has proven
        // the parent, staging-root, and private-directory FileIds. Within that
        // captured tree the file identifier is sufficient; ignoring the
        // volume field also accommodates Wine changing its synthetic volume
        // serial when the same directory is renamed.
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let current = options.open(path)?;
        let held_legacy = handle_information(file)?;
        let current_legacy = handle_information(&current)?;
        let held_modern = file_id_information(file)?;
        let current_modern = file_id_information(&current)?;
        if held_legacy.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || current_legacy.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || held_legacy.number_of_links != 1
            || current_legacy.number_of_links != 1
        {
            return Ok(false);
        }
        let held_has_modern = held_modern.file_id.identifier.iter().any(|byte| *byte != 0);
        let current_has_modern = current_modern
            .file_id
            .identifier
            .iter()
            .any(|byte| *byte != 0);
        if held_has_modern && current_has_modern {
            return Ok(held_modern.file_id == current_modern.file_id);
        }
        if held_has_modern || current_has_modern {
            return Ok(false);
        }
        let held_index =
            u64::from(held_legacy.file_index_high) << 32 | u64::from(held_legacy.file_index_low);
        let current_index = u64::from(current_legacy.file_index_high) << 32
            | u64::from(current_legacy.file_index_low);
        Ok(held_index != 0 && held_index == current_index)
    }

    fn same_file_identity(
        first_legacy: &ByHandleFileInformation,
        second_legacy: &ByHandleFileInformation,
        first_modern: &FileIdInfo,
        second_modern: &FileIdInfo,
    ) -> bool {
        let first_has_128_bit_id = first_modern
            .file_id
            .identifier
            .iter()
            .any(|byte| *byte != 0);
        let second_has_128_bit_id = second_modern
            .file_id
            .identifier
            .iter()
            .any(|byte| *byte != 0);
        match (first_has_128_bit_id, second_has_128_bit_id) {
            (true, true) => first_modern == second_modern,
            (false, false) => {
                let first_index = u64::from(first_legacy.file_index_high) << 32
                    | u64::from(first_legacy.file_index_low);
                let second_index = u64::from(second_legacy.file_index_high) << 32
                    | u64::from(second_legacy.file_index_low);
                first_index != 0
                    && first_legacy.volume_serial_number == second_legacy.volume_serial_number
                    && first_index == second_index
            }
            (true, false) | (false, true) => false,
        }
    }

    pub(super) fn path_is_supported_local_filesystem(path: &Path) -> io::Result<bool> {
        let canonical = std::fs::canonicalize(path)?;
        let encoded = extended_path(&canonical)?;
        let mut volume = vec![0_u16; 32_768];
        let buffer_length = u32::try_from(volume.len())
            .map_err(|_| io::Error::other("volume path buffer overflow"))?;
        // SAFETY: both UTF-16 buffers are live, NUL-terminated/size bounded,
        // and Windows writes at most `buffer_length` code units.
        if unsafe { GetVolumePathNameW(encoded.as_ptr(), volume.as_mut_ptr(), buffer_length) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful GetVolumePathNameW produced a NUL-terminated root
        // path in the live `volume` buffer.
        let drive_type = unsafe { GetDriveTypeW(volume.as_ptr()) };
        Ok(matches!(
            drive_type,
            DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_RAMDISK
        ))
    }

    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        let encoded = extended_path(path)?;
        // SAFETY: the UTF-16 path is NUL terminated; all optional pointers are
        // null; the returned handle is checked before use.
        let handle = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle == std::ptr::without_provenance_mut::<c_void>(usize::MAX) {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a live directory handle returned by CreateFileW.
        let flushed = unsafe { FlushFileBuffers(handle) };
        let flush_error = if flushed == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        // SAFETY: this closes exactly the owned handle once.
        let closed = unsafe { CloseHandle(handle) };
        if let Some(error) = flush_error {
            return Err(error);
        }
        if closed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn namespace_move(
        source: &Path,
        destination: &Path,
        replace: bool,
    ) -> io::Result<()> {
        let source = extended_path(source)?;
        let destination = extended_path(destination)?;
        let flags = MOVEFILE_WRITE_THROUGH
            | if replace {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            };
        // SAFETY: both paths are live, NUL-terminated UTF-16 strings. No copy
        // flag is supplied, so Windows cannot silently cross volumes.
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn sync_namespace_parent(_path: &Path) -> io::Result<()> {
        // Every namespace mutation in this module reached this checkpoint via
        // MoveFileExW(MOVEFILE_WRITE_THROUGH). Directory-handle flushing is a
        // separate optional capability, not the Windows commit barrier.
        Ok(())
    }

    fn extended_path(path: &Path) -> io::Result<Vec<u16>> {
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows path contains NUL",
            ));
        }
        for code_unit in &mut encoded {
            if *code_unit == u16::from(b'/') {
                *code_unit = u16::from(b'\\');
            }
        }

        let mut result = if encoded.starts_with(&VERBATIM_PATH_PREFIX) {
            encoded
        } else if encoded.starts_with(&DEVICE_PATH_PREFIX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows device paths are not vault paths",
            ));
        } else if encoded.starts_with(&[u16::from(b'\\'), u16::from(b'\\')]) {
            let mut result = VERBATIM_UNC_PATH_PREFIX.to_vec();
            result.extend_from_slice(&encoded[2..]);
            result
        } else if encoded.len() >= 3
            && matches!(encoded[0], 0x41..=0x5a | 0x61..=0x7a)
            && encoded[1] == u16::from(b':')
            && encoded[2] == u16::from(b'\\')
        {
            let mut result = VERBATIM_PATH_PREFIX.to_vec();
            result.extend_from_slice(&encoded);
            result
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows vault paths must be absolute",
            ));
        };
        result.push(0);
        Ok(result)
    }

    fn handle_information(file: &File) -> io::Result<ByHandleFileInformation> {
        let mut information = MaybeUninit::<ByHandleFileInformation>::uninit();
        // SAFETY: `file` owns a valid handle and Windows initializes the full
        // BY_HANDLE_FILE_INFORMATION value on a nonzero result.
        let result =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: the successful API contract initialized every field.
            Ok(unsafe { information.assume_init() })
        }
    }

    fn file_id_information(file: &File) -> io::Result<FileIdInfo> {
        let mut information = MaybeUninit::<FileIdInfo>::uninit();
        let buffer_size = u32::try_from(std::mem::size_of::<FileIdInfo>())
            .map_err(|_| io::Error::other("FILE_ID_INFO size overflow"))?;
        // SAFETY: `file` owns a valid handle and the output buffer has the
        // exact FILE_ID_INFO layout and size requested by FileIdInfo class.
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FILE_ID_INFO_CLASS,
                information.as_mut_ptr().cast(),
                buffer_size,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: the successful API contract initialized every field.
            Ok(unsafe { information.assume_init() })
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::Path;

        use super::{
            ByHandleFileInformation, FileId128, FileIdInfo, FileTime, extended_path,
            same_file_identity,
        };

        #[test]
        fn extended_path_encodes_drive_unc_and_rejects_ambiguous_namespaces() {
            let drive = match extended_path(Path::new("C:/vault/note.md.enc")) {
                Ok(path) => path,
                Err(error) => panic!("drive path encoding failed: {error}"),
            };
            assert!(drive.starts_with(&[92, 92, 63, 92, 67, 58, 92]));
            assert_eq!(drive.last(), Some(&0));

            let unc = match extended_path(Path::new(r"\\server\share\vault")) {
                Ok(path) => path,
                Err(error) => panic!("UNC path encoding failed: {error}"),
            };
            assert!(unc.starts_with(&[92, 92, 63, 92, 85, 78, 67, 92]));

            assert!(extended_path(Path::new("relative\\vault")).is_err());
            assert!(extended_path(Path::new(r"\\.\PhysicalDrive0")).is_err());
            assert!(extended_path(Path::new("C:\\bad\0name")).is_err());
        }

        #[test]
        fn modern_file_identity_is_preferred_when_nonzero() {
            let legacy_a = legacy(7, 10);
            let legacy_b = legacy(8, 11);
            let modern_a = modern(91, [0xa5; 16]);
            let modern_b = modern(91, [0xa5; 16]);
            assert!(same_file_identity(
                &legacy_a, &legacy_b, &modern_a, &modern_b
            ));
            assert!(!same_file_identity(
                &legacy_a,
                &legacy_b,
                &modern_a,
                &modern(91, [0x5a; 16]),
            ));
        }

        #[test]
        fn zero_modern_file_identity_falls_back_and_never_accepts_zero_legacy_id() {
            let no_modern = modern(0, [0; 16]);
            assert!(same_file_identity(
                &legacy(7, 10),
                &legacy(7, 10),
                &no_modern,
                &no_modern,
            ));
            assert!(!same_file_identity(
                &legacy(7, 10),
                &legacy(7, 11),
                &no_modern,
                &no_modern,
            ));
            assert!(!same_file_identity(
                &legacy(7, 0),
                &legacy(7, 0),
                &no_modern,
                &no_modern,
            ));
        }

        fn modern(volume_serial_number: u64, identifier: [u8; 16]) -> FileIdInfo {
            FileIdInfo {
                volume_serial_number,
                file_id: FileId128 { identifier },
            }
        }

        fn legacy(volume_serial_number: u32, file_index: u64) -> ByHandleFileInformation {
            let zero_time = FileTime { low: 0, high: 0 };
            ByHandleFileInformation {
                file_attributes: 0,
                creation_time: zero_time,
                last_access_time: zero_time,
                last_write_time: zero_time,
                volume_serial_number,
                file_size_high: 0,
                file_size_low: 0,
                number_of_links: 1,
                file_index_high: u32::try_from(file_index >> 32).unwrap_or(0),
                file_index_low: u32::try_from(file_index & u64::from(u32::MAX)).unwrap_or(0),
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use std::fs::{File, Metadata};
    use std::io;
    use std::path::Path;

    pub(super) fn lock_exclusive(_file: &File) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vault mutation locking is supported only on Linux and Windows",
        ))
    }

    pub(super) fn metadata_is_same_filesystem(_first: &Metadata, _second: &Metadata) -> bool {
        false
    }

    pub(super) fn filesystem_directory_identity(
        _path: &Path,
        _metadata: &Metadata,
    ) -> io::Result<super::FilesystemDirectoryIdentity> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "directory identity is supported only on Linux and Windows",
        ))
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn paths_share_mount(_first: &Path, _second: &Path) -> io::Result<bool> {
        Ok(false)
    }

    pub(super) fn open_file_matches_path_and_is_single_link(
        _path: &Path,
        _file: &File,
    ) -> io::Result<bool> {
        Ok(false)
    }

    pub(super) fn open_file_matches_path_and_is_single_link_same_tree(
        _path: &Path,
        _file: &File,
    ) -> io::Result<bool> {
        Ok(false)
    }

    pub(super) fn path_is_supported_local_filesystem(_path: &Path) -> io::Result<bool> {
        Ok(false)
    }

    pub(super) fn sync_directory(_path: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "directory synchronization is supported only on Linux and Windows",
        ))
    }

    pub(super) fn namespace_move(
        _source: &Path,
        _destination: &Path,
        _replace: bool,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "namespace moves are supported only on Linux and Windows",
        ))
    }

    pub(super) fn sync_namespace_parent(_path: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "namespace durability is supported only on Linux and Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::{
        AtomicDirectoryPublishError, AtomicWriteError, AtomicWriteStage, CIPHERTEXT_STAGING_PREFIX,
        CIPHERTEXT_STAGING_SUFFIX, CurrentTarget, FaultInjector, FaultPoint, IMPORT_STAGING_PREFIX,
        MAX_ATOMIC_TARGET_BYTES, ParentSyncStatus, RebindJournal, VAULT_LOCAL_DIRECTORY,
        VAULT_MUTATION_LOCK_FILE, VaultMutationGuard, VaultMutationLock, WriteCondition,
        atomic_delete_ciphertext, atomic_move_verified_file_no_replace,
        atomic_publish_directory_no_replace, atomic_publish_directory_no_replace_with_fault,
        atomic_rebind_ciphertext, atomic_replace_verified_file, atomic_write_ciphertext,
        atomic_write_ciphertext_with_faults, digest_bytes, install_rebind_journal,
        pending_rebind_path, reconcile_failed_namespace_commit, recover_pending_rebind,
    };

    #[cfg(windows)]
    use super::open_file_matches_path_and_is_single_link;

    const OLD_CIPHERTEXT: &[u8] = b"EDRY-old-authenticated-ciphertext";
    const NEW_CIPHERTEXT: &[u8] = b"EDRY-new-authenticated-ciphertext";

    #[cfg(target_os = "linux")]
    #[test]
    fn secure_source_handle_detects_intermediate_directory_identity_swap() -> io::Result<()> {
        let fixture = TestVault::new()?;
        fs::write(fixture.notes().join("original.md"), b"source")?;
        let root = super::open_secure_source_root(fixture.root())?;
        let super::SecureSourceChild::Directory(notes) =
            root.open_child(std::ffi::OsStr::new("notes"))?
        else {
            return Err(io::Error::other("notes was not a secure directory"));
        };
        let retired = fixture.root().join("retired-notes");
        fs::rename(fixture.notes(), &retired)?;
        fs::create_dir(fixture.notes())?;
        fs::write(fixture.notes().join("original.md"), b"source")?;

        assert!(notes.verify_binding().is_err());
        let held_names = notes
            .read_dir()?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        assert!(held_names.contains(&std::ffi::OsString::from("original.md")));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secure_source_root_rejects_symlinked_ancestor() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = TestVault::new()?;
        let real = fixture.root().join("real");
        let source = real.join("source");
        fs::create_dir_all(&source)?;
        let alias = fixture.root().join("alias");
        symlink(&real, &alias)?;

        assert!(super::open_secure_source_root(&alias.join("source")).is_err());
        assert!(super::open_secure_source_root(&source).is_ok());
        Ok(())
    }

    #[test]
    fn complete_directory_publish_is_no_replace_and_removes_marker() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let staging = fixture.root().join(format!("{IMPORT_STAGING_PREFIX}test"));
        let local = staging.join(VAULT_LOCAL_DIRECTORY);
        fs::create_dir_all(&local)?;
        fs::write(
            staging.join("vault.json"),
            b"encrypted-metadata-placeholder",
        )?;
        let destination = fixture.root().join("published");

        atomic_publish_directory_no_replace(&staging, &destination).map_err(io::Error::other)?;
        assert!(!staging.exists());
        assert!(destination.join("vault.json").is_file());
        assert!(
            !destination
                .join(VAULT_LOCAL_DIRECTORY)
                .join(super::IMPORT_PUBLISH_MARKER)
                .exists()
        );

        let second = fixture
            .root()
            .join(format!("{IMPORT_STAGING_PREFIX}second"));
        fs::create_dir_all(second.join(VAULT_LOCAL_DIRECTORY))?;
        assert!(matches!(
            atomic_publish_directory_no_replace(&second, &destination),
            Err(AtomicDirectoryPublishError::DestinationExists)
        ));
        assert!(second.is_dir());
        assert_eq!(
            fs::read(destination.join("vault.json"))?,
            b"encrypted-metadata-placeholder"
        );
        Ok(())
    }

    #[test]
    fn directory_publish_reconciles_error_after_complete_move() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let staging = fixture
            .root()
            .join(format!("{IMPORT_STAGING_PREFIX}post-error"));
        fs::create_dir_all(staging.join(VAULT_LOCAL_DIRECTORY))?;
        fs::write(staging.join("vault.json"), b"complete")?;
        let destination = fixture.root().join("published-after-error");

        atomic_publish_directory_no_replace_with_fault(
            &staging,
            &destination,
            |_| Ok(()),
            true,
            false,
            false,
        )
        .map_err(io::Error::other)?;
        assert!(!staging.exists());
        assert_eq!(fs::read(destination.join("vault.json"))?, b"complete");
        assert!(
            !destination
                .join(VAULT_LOCAL_DIRECTORY)
                .join(super::IMPORT_PUBLISH_MARKER)
                .exists()
        );
        Ok(())
    }

    #[test]
    fn directory_publish_classifies_exact_unmoved_state() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let staging = fixture
            .root()
            .join(format!("{IMPORT_STAGING_PREFIX}not-moved"));
        fs::create_dir_all(staging.join(VAULT_LOCAL_DIRECTORY))?;
        let destination = fixture.root().join("still-absent");
        assert!(matches!(
            atomic_publish_directory_no_replace_with_fault(
                &staging,
                &destination,
                |_| Ok(()),
                false,
                true,
                false,
            ),
            Err(AtomicDirectoryPublishError::NotMoved)
        ));
        assert!(staging.is_dir());
        assert!(!destination.exists());
        Ok(())
    }

    #[test]
    fn directory_publish_reports_marker_cleanup_failure_after_exact_move() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let staging = fixture
            .root()
            .join(format!("{IMPORT_STAGING_PREFIX}cleanup-failure"));
        fs::create_dir_all(staging.join(VAULT_LOCAL_DIRECTORY))?;
        fs::write(staging.join("vault.json"), b"complete")?;
        let destination = fixture.root().join("published-cleanup-failure");

        assert!(matches!(
            atomic_publish_directory_no_replace_with_fault(
                &staging,
                &destination,
                |_| Ok(()),
                false,
                false,
                true,
            ),
            Err(AtomicDirectoryPublishError::PublishedCleanupFailed)
        ));
        assert!(!staging.exists());
        assert_eq!(fs::read(destination.join("vault.json"))?, b"complete");
        assert!(
            destination
                .join(VAULT_LOCAL_DIRECTORY)
                .join(super::IMPORT_PUBLISH_MARKER)
                .is_file()
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn directory_publish_rejects_parent_identity_swap_at_critical_audit() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let parent = fixture.root().join("publish-parent");
        let staging = parent.join(format!("{IMPORT_STAGING_PREFIX}parent-swap"));
        fs::create_dir_all(staging.join(VAULT_LOCAL_DIRECTORY))?;
        let destination = parent.join("published-parent-swap");
        let retired = fixture.root().join("retired-publish-parent");

        assert!(matches!(
            super::atomic_publish_directory_no_replace_checked(&staging, &destination, |_| {
                fs::rename(&parent, &retired)?;
                fs::create_dir(&parent)?;
                Ok(())
            }),
            Err(AtomicDirectoryPublishError::Indeterminate)
        ));
        assert!(!destination.exists());
        assert!(
            retired
                .join(staging.file_name().unwrap_or_default())
                .is_dir()
        );
        Ok(())
    }

    #[test]
    fn directory_publish_rejects_staging_identity_swap_at_critical_audit() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let staging = fixture
            .root()
            .join(format!("{IMPORT_STAGING_PREFIX}identity-swap"));
        fs::create_dir_all(staging.join(VAULT_LOCAL_DIRECTORY))?;
        let destination = fixture.root().join("identity-swap-final");
        let retired = fixture.root().join("retired-stage");
        assert!(matches!(
            super::atomic_publish_directory_no_replace_checked(&staging, &destination, |current| {
                fs::rename(current, &retired)?;
                fs::create_dir_all(current.join(VAULT_LOCAL_DIRECTORY))?;
                Ok(())
            },),
            Err(AtomicDirectoryPublishError::Indeterminate | AtomicDirectoryPublishError::Io { .. })
        ));
        assert!(!destination.exists());
        assert!(retired.is_dir() || staging.is_dir());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_identity_distinguishes_two_live_files() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let first_path = fixture.note("identity-a.md.enc");
        let second_path = fixture.note("identity-b.md.enc");
        fs::write(&first_path, OLD_CIPHERTEXT)?;
        fs::write(&second_path, OLD_CIPHERTEXT)?;
        let first = fs::File::open(&first_path)?;
        assert!(open_file_matches_path_and_is_single_link(
            &first_path,
            &first,
        )?);
        assert!(!open_file_matches_path_and_is_single_link(
            &second_path,
            &first,
        )?);
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_move_no_replace_publishes_absent_destination() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("index.lock");
        let destination = fixture.root().join("index");
        fs::write(&source, b"candidate-index")?;
        let source_file = fs::File::open(&source)?;

        let outcome = atomic_move_verified_file_no_replace(&source, &source_file, &destination)?;

        assert!(!source.exists());
        assert_eq!(fs::read(&destination)?, b"candidate-index");
        assert_eq!(outcome.source_parent_sync, ParentSyncStatus::Synced);
        assert_eq!(outcome.destination_parent_sync, ParentSyncStatus::Synced);
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_move_no_replace_preserves_existing_destination() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("index.lock");
        let destination = fixture.root().join("index");
        fs::write(&source, b"candidate-index")?;
        fs::write(&destination, b"current-index")?;
        let source_file = fs::File::open(&source)?;

        let error = atomic_move_verified_file_no_replace(&source, &source_file, &destination)
            .expect_err("an existing destination must not be replaced");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&source)?, b"candidate-index");
        assert_eq!(fs::read(&destination)?, b"current-index");
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_replace_commits_complete_source() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("index.lock");
        let destination = fixture.root().join("index");
        fs::write(&source, b"candidate-index")?;
        fs::write(&destination, b"current-index")?;
        let source_file = fs::File::open(&source)?;
        let destination_file = fs::File::open(&destination)?;

        let outcome =
            atomic_replace_verified_file(&source, source_file, &destination, destination_file)?;

        assert!(!source.exists());
        assert_eq!(fs::read(&destination)?, b"candidate-index");
        assert_eq!(outcome.source_parent_sync, ParentSyncStatus::Synced);
        assert_eq!(outcome.destination_parent_sync, ParentSyncStatus::Synced);
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_move_check_failure_never_cleans_up_or_retries() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("index.lock");
        let destination = fixture.root().join("index");
        let retired_destination = fixture.root().join("retired-index");
        fs::write(&source, b"candidate-index")?;
        fs::write(&destination, b"expected-current-index")?;
        let source_file = fs::File::open(&source)?;
        let stale_destination_file = fs::File::open(&destination)?;
        fs::rename(&destination, &retired_destination)?;
        fs::write(&destination, b"concurrent-index")?;

        let error = atomic_replace_verified_file(
            &source,
            source_file,
            &destination,
            stale_destination_file,
        )
        .expect_err("a stale destination handle must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&source)?, b"candidate-index");
        assert_eq!(fs::read(&destination)?, b"concurrent-index");
        assert_eq!(fs::read(&retired_destination)?, b"expected-current-index");
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_move_checkpoints_both_cross_parent_directories() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source_parent = fixture.root().join("source-parent");
        let destination_parent = fixture.root().join("destination-parent");
        fs::create_dir(&source_parent)?;
        fs::create_dir(&destination_parent)?;
        let source = source_parent.join("index.lock");
        let destination = destination_parent.join("index");
        fs::write(&source, b"candidate-index")?;
        let source_file = fs::File::open(&source)?;

        let outcome = atomic_move_verified_file_no_replace(&source, &source_file, &destination)?;

        assert!(!source.exists());
        assert_eq!(fs::read(&destination)?, b"candidate-index");
        assert_eq!(outcome.source_parent_sync, ParentSyncStatus::Synced);
        assert_eq!(outcome.destination_parent_sync, ParentSyncStatus::Synced);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_file_moves_reject_symlinks_and_hardlinks() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = TestVault::new()?;

        let real_source = fixture.root().join("real-source");
        let symlink_source = fixture.root().join("symlink-source");
        let symlink_destination = fixture.root().join("symlink-destination");
        fs::write(&real_source, b"source")?;
        symlink(&real_source, &symlink_source)?;
        let symlink_source_file = fs::File::open(&symlink_source)?;
        assert_eq!(
            atomic_move_verified_file_no_replace(
                &symlink_source,
                &symlink_source_file,
                &symlink_destination,
            )
            .expect_err("a symlink source must be rejected")
            .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(symlink_source.is_symlink());
        assert!(!symlink_destination.exists());

        let hardlink_source = fixture.root().join("hardlink-source");
        let hardlink_alias = fixture.root().join("hardlink-alias");
        let hardlink_destination = fixture.root().join("hardlink-destination");
        fs::write(&hardlink_source, b"source")?;
        fs::hard_link(&hardlink_source, &hardlink_alias)?;
        let hardlink_source_file = fs::File::open(&hardlink_source)?;
        assert_eq!(
            atomic_move_verified_file_no_replace(
                &hardlink_source,
                &hardlink_source_file,
                &hardlink_destination,
            )
            .expect_err("a multiply-linked source must be rejected")
            .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(fs::read(&hardlink_source)?, b"source");
        assert_eq!(fs::read(&hardlink_alias)?, b"source");
        assert!(!hardlink_destination.exists());

        let replace_source = fixture.root().join("replace-source");
        let real_destination = fixture.root().join("real-destination");
        let symlinked_destination = fixture.root().join("symlinked-destination");
        fs::write(&replace_source, b"candidate")?;
        fs::write(&real_destination, b"current")?;
        symlink(&real_destination, &symlinked_destination)?;
        let replace_source_file = fs::File::open(&replace_source)?;
        let symlinked_destination_file = fs::File::open(&symlinked_destination)?;
        assert_eq!(
            atomic_replace_verified_file(
                &replace_source,
                replace_source_file,
                &symlinked_destination,
                symlinked_destination_file,
            )
            .expect_err("a symlink destination must be rejected")
            .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(fs::read(&replace_source)?, b"candidate");
        assert_eq!(fs::read(&real_destination)?, b"current");
        assert!(symlinked_destination.is_symlink());

        let hardlink_replace_source = fixture.root().join("hardlink-replace-source");
        let hardlink_replace_destination = fixture.root().join("hardlink-replace-destination");
        let hardlink_replace_alias = fixture.root().join("hardlink-replace-alias");
        fs::write(&hardlink_replace_source, b"candidate")?;
        fs::write(&hardlink_replace_destination, b"current")?;
        fs::hard_link(&hardlink_replace_destination, &hardlink_replace_alias)?;
        let hardlink_replace_source_file = fs::File::open(&hardlink_replace_source)?;
        let hardlink_replace_destination_file = fs::File::open(&hardlink_replace_destination)?;
        assert_eq!(
            atomic_replace_verified_file(
                &hardlink_replace_source,
                hardlink_replace_source_file,
                &hardlink_replace_destination,
                hardlink_replace_destination_file,
            )
            .expect_err("a multiply-linked destination must be rejected")
            .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(fs::read(&hardlink_replace_source)?, b"candidate");
        assert_eq!(fs::read(&hardlink_replace_destination)?, b"current");
        assert_eq!(fs::read(&hardlink_replace_alias)?, b"current");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_file_moves_reject_symlinked_parent_ancestors() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = TestVault::new()?;
        let real_ancestor = fixture.root().join("real-ancestor");
        let real_parent = real_ancestor.join("ordinary-parent");
        let symlink_ancestor = fixture.root().join("symlink-ancestor");
        fs::create_dir_all(&real_parent)?;
        symlink(&real_ancestor, &symlink_ancestor)?;
        let real_source = real_parent.join("source");
        let aliased_source = symlink_ancestor.join("ordinary-parent").join("source");
        let destination = fixture.root().join("destination");
        fs::write(&real_source, b"source")?;
        let aliased_source_file = fs::File::open(&aliased_source)?;

        let error = atomic_move_verified_file_no_replace(
            &aliased_source,
            &aliased_source_file,
            &destination,
        )
        .expect_err("a symlinked parent ancestor must be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&real_source)?, b"source");
        assert!(!destination.exists());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_namespace_mutations_support_paths_beyond_max_path() -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;

        let mut root =
            std::env::temp_dir().join(format!("inex-long-namespace-test-{}", uuid::Uuid::new_v4()));
        for index in 0..8 {
            root.push(format!("segment-{index}-{}", "x".repeat(32)));
        }
        let notes = root.join("notes");
        fs::create_dir_all(&notes)?;
        let fixture = TestVault { root, notes };
        let source = fixture.note("source.md.enc");
        let destination = fixture.note("destination.md.enc");
        assert!(source.as_os_str().encode_wide().count() > 260);

        atomic_write_ciphertext(
            fixture.root(),
            &source,
            OLD_CIPHERTEXT,
            WriteCondition::IfNoneMatch,
        )
        .map_err(io::Error::other)?;
        atomic_rebind_ciphertext(
            fixture.root(),
            &source,
            &destination,
            NEW_CIPHERTEXT,
            WriteCondition::IfMatch(digest_bytes(OLD_CIPHERTEXT)),
            WriteCondition::IfNoneMatch,
        )
        .map_err(io::Error::other)?;
        assert!(!source.exists());
        assert_eq!(fs::read(&destination)?, NEW_CIPHERTEXT);
        atomic_delete_ciphertext(
            fixture.root(),
            &destination,
            WriteCondition::IfMatch(digest_bytes(NEW_CIPHERTEXT)),
        )
        .map_err(io::Error::other)?;
        assert!(!destination.exists());
        Ok(())
    }

    #[test]
    fn create_only_commit_is_complete_and_leaves_no_staging_file() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("create.md.enc");

        let outcome = atomic_write_ciphertext(
            fixture.root(),
            &target,
            NEW_CIPHERTEXT,
            WriteCondition::IfNoneMatch,
        )
        .map_err(io::Error::other)?;

        assert_eq!(fs::read(&target)?, NEW_CIPHERTEXT);
        assert_eq!(outcome.etag, digest_bytes(NEW_CIPHERTEXT));
        assert_no_staging_files(fixture.notes())?;
        assert!(
            fixture
                .root()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(VAULT_MUTATION_LOCK_FILE)
                .is_file()
        );
        Ok(())
    }

    #[test]
    fn failed_namespace_move_is_reconciled_from_complete_post_state() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("reconcile.md.enc");
        fs::write(&target, NEW_CIPHERTEXT)?;
        assert_eq!(
            reconcile_failed_namespace_commit(
                &target,
                CurrentTarget::Absent,
                digest_bytes(NEW_CIPHERTEXT),
                io::Error::other("injected namespace failure"),
            )
            .map_err(io::Error::other)?,
            ParentSyncStatus::NotSynced
        );

        fs::remove_file(&target)?;
        assert!(matches!(
            reconcile_failed_namespace_commit(
                &target,
                CurrentTarget::Absent,
                digest_bytes(NEW_CIPHERTEXT),
                io::Error::other("injected namespace failure"),
            ),
            Err(AtomicWriteError::Io { .. })
        ));

        fs::write(&target, OLD_CIPHERTEXT)?;
        assert!(matches!(
            reconcile_failed_namespace_commit(
                &target,
                CurrentTarget::Absent,
                digest_bytes(NEW_CIPHERTEXT),
                io::Error::other("injected namespace failure"),
            ),
            Err(AtomicWriteError::NamespaceCommitIndeterminate { .. })
        ));
        Ok(())
    }

    #[test]
    fn oversized_input_is_rejected_before_staging() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("oversized.md.enc");
        let oversized = vec![0_u8; usize::try_from(MAX_ATOMIC_TARGET_BYTES).unwrap_or(0) + 1];
        assert!(matches!(
            atomic_write_ciphertext(
                fixture.root(),
                &target,
                &oversized,
                WriteCondition::IfNoneMatch
            ),
            Err(AtomicWriteError::TargetTooLarge)
        ));
        assert!(!target.exists());
        assert_no_staging_files(fixture.notes())?;
        Ok(())
    }

    #[test]
    fn matching_etag_replaces_complete_ciphertext() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("replace.md.enc");
        fs::write(&target, OLD_CIPHERTEXT)?;

        let outcome = atomic_write_ciphertext(
            fixture.root(),
            &target,
            NEW_CIPHERTEXT,
            WriteCondition::IfMatch(digest_bytes(OLD_CIPHERTEXT)),
        )
        .map_err(io::Error::other)?;

        assert_eq!(fs::read(&target)?, NEW_CIPHERTEXT);
        assert_eq!(outcome.etag, digest_bytes(NEW_CIPHERTEXT));
        assert_no_staging_files(fixture.notes())?;
        Ok(())
    }

    #[test]
    fn stale_etag_preserves_old_target_and_reports_current_digest() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("stale.md.enc");
        fs::write(&target, OLD_CIPHERTEXT)?;

        let error = atomic_write_ciphertext(
            fixture.root(),
            &target,
            NEW_CIPHERTEXT,
            WriteCondition::IfMatch([0xa5; 32]),
        )
        .expect_err("stale etag must conflict");

        assert!(matches!(
            error,
            AtomicWriteError::Conflict {
                current: CurrentTarget::File(current)
            } if current == digest_bytes(OLD_CIPHERTEXT)
        ));
        assert_eq!(fs::read(&target)?, OLD_CIPHERTEXT);
        assert_no_staging_files(fixture.notes())?;
        Ok(())
    }

    #[test]
    fn create_only_conflict_preserves_existing_target() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("exists.md.enc");
        fs::write(&target, OLD_CIPHERTEXT)?;

        let error = atomic_write_ciphertext(
            fixture.root(),
            &target,
            NEW_CIPHERTEXT,
            WriteCondition::IfNoneMatch,
        )
        .expect_err("existing target must conflict");

        assert!(matches!(error, AtomicWriteError::Conflict { .. }));
        assert_eq!(fs::read(&target)?, OLD_CIPHERTEXT);
        assert_no_staging_files(fixture.notes())?;
        Ok(())
    }

    #[test]
    fn every_injected_precommit_failure_preserves_old_target_and_cleans_staging() -> io::Result<()>
    {
        let points = [
            FaultPoint::CreateStaging,
            FaultPoint::WriteStaging,
            FaultPoint::FlushStaging,
            FaultPoint::SyncStaging,
            FaultPoint::VerifyStaging,
            FaultPoint::BeforeLock,
            FaultPoint::PrepareLock,
            FaultPoint::AcquireLock,
            FaultPoint::ReadCurrent,
            FaultPoint::Replace,
        ];

        for point in points {
            let fixture = TestVault::new()?;
            let target = fixture.note("fault.md.enc");
            fs::write(&target, OLD_CIPHERTEXT)?;
            let fault = FailAt(point);

            let error = atomic_write_ciphertext_with_faults(
                fixture.root(),
                &target,
                NEW_CIPHERTEXT,
                WriteCondition::IfMatch(digest_bytes(OLD_CIPHERTEXT)),
                &fault,
            )
            .expect_err("fault injection must fail before commit");

            assert!(matches!(error, AtomicWriteError::Io { .. }));
            assert_eq!(fs::read(&target)?, OLD_CIPHERTEXT, "fault: {point:?}");
            assert_no_staging_files(fixture.notes())?;
        }
        Ok(())
    }

    #[test]
    fn parent_sync_failure_is_nonfatal_and_commit_stays_visible() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("parent-sync.md.enc");
        let fault = FailAt(FaultPoint::SyncParent);

        let outcome = atomic_write_ciphertext_with_faults(
            fixture.root(),
            &target,
            NEW_CIPHERTEXT,
            WriteCondition::IfNoneMatch,
            &fault,
        )
        .map_err(io::Error::other)?;

        assert_eq!(outcome.parent_sync, ParentSyncStatus::NotSynced);
        assert_eq!(fs::read(&target)?, NEW_CIPHERTEXT);
        assert_no_staging_files(fixture.notes())?;
        Ok(())
    }

    #[test]
    fn os_lock_serializes_competing_etag_commits() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("race.md.enc");
        fs::write(&target, OLD_CIPHERTEXT)?;
        let condition = WriteCondition::IfMatch(digest_bytes(OLD_CIPHERTEXT));
        let rendezvous = Arc::new(Rendezvous {
            barrier: Barrier::new(2),
        });

        let first_root = fixture.root().to_path_buf();
        let first_target = target.clone();
        let first_faults = Arc::clone(&rendezvous);
        let first = thread::spawn(move || {
            atomic_write_ciphertext_with_faults(
                &first_root,
                &first_target,
                b"EDRY-first-competing-ciphertext",
                condition,
                first_faults.as_ref(),
            )
        });

        let second_root = fixture.root().to_path_buf();
        let second_target = target.clone();
        let second_faults = Arc::clone(&rendezvous);
        let second = thread::spawn(move || {
            atomic_write_ciphertext_with_faults(
                &second_root,
                &second_target,
                b"EDRY-second-competing-ciphertext",
                condition,
                second_faults.as_ref(),
            )
        });

        let results = [
            first
                .join()
                .map_err(|_| io::Error::other("thread panicked"))?,
            second
                .join()
                .map_err(|_| io::Error::other("thread panicked"))?,
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(AtomicWriteError::Conflict { .. })))
                .count(),
            1
        );
        let committed = fs::read(&target)?;
        assert!(
            committed == b"EDRY-first-competing-ciphertext"
                || committed == b"EDRY-second-competing-ciphertext"
        );
        assert_no_staging_files(fixture.notes())?;
        Ok(())
    }

    #[test]
    fn conditional_delete_preserves_stale_target_then_removes_exact_match() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("delete.md.enc");
        fs::write(&target, OLD_CIPHERTEXT)?;
        assert!(matches!(
            atomic_delete_ciphertext(fixture.root(), &target, WriteCondition::IfMatch([0xa5; 32])),
            Err(AtomicWriteError::Conflict { .. })
        ));
        assert_eq!(fs::read(&target)?, OLD_CIPHERTEXT);

        atomic_delete_ciphertext(
            fixture.root(),
            &target,
            WriteCondition::IfMatch(digest_bytes(OLD_CIPHERTEXT)),
        )
        .map_err(io::Error::other)?;
        assert!(!target.exists());
        Ok(())
    }

    #[test]
    fn rebind_commits_verified_destination_then_removes_source_and_journal() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.note("source.md.enc");
        let destination = fixture.note("destination.md.enc");
        fs::write(&source, OLD_CIPHERTEXT)?;

        let outcome = atomic_rebind_ciphertext(
            fixture.root(),
            &source,
            &destination,
            NEW_CIPHERTEXT,
            WriteCondition::IfMatch(digest_bytes(OLD_CIPHERTEXT)),
            WriteCondition::IfNoneMatch,
        )
        .map_err(io::Error::other)?;
        assert_eq!(outcome.etag, digest_bytes(NEW_CIPHERTEXT));
        assert!(!source.exists());
        assert_eq!(fs::read(&destination)?, NEW_CIPHERTEXT);
        assert!(!pending_rebind_path(fixture.root()).exists());
        Ok(())
    }

    #[test]
    fn recovery_finishes_only_the_exact_journaled_rebind_state() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.note("recover-source.md.enc");
        let destination = fixture.note("recover-destination.md.enc");
        fs::write(&source, OLD_CIPHERTEXT)?;
        fs::write(&destination, NEW_CIPHERTEXT)?;
        drop(VaultMutationLock::acquire(fixture.root()).map_err(io::Error::other)?);
        let journal = RebindJournal::new(
            fixture.root(),
            &source,
            &destination,
            digest_bytes(OLD_CIPHERTEXT),
            digest_bytes(NEW_CIPHERTEXT),
        )
        .map_err(io::Error::other)?;
        install_rebind_journal(fixture.root(), &journal).map_err(io::Error::other)?;

        let recovered = recover_pending_rebind(fixture.root()).map_err(io::Error::other)?;
        assert!(recovered.changed_repository);
        assert!(!source.exists());
        assert_eq!(fs::read(&destination)?, NEW_CIPHERTEXT);
        assert!(!pending_rebind_path(fixture.root()).exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn recovery_rejects_replaced_symlink_ancestor_without_touching_target() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = TestVault::new()?;
        let source = fixture.note("escaped-source.md.enc");
        let destination = fixture.note("escaped-destination.md.enc");
        fs::write(&source, OLD_CIPHERTEXT)?;
        drop(VaultMutationLock::acquire(fixture.root()).map_err(io::Error::other)?);
        let journal = RebindJournal::new(
            fixture.root(),
            &source,
            &destination,
            digest_bytes(OLD_CIPHERTEXT),
            digest_bytes(NEW_CIPHERTEXT),
        )
        .map_err(io::Error::other)?;
        install_rebind_journal(fixture.root(), &journal).map_err(io::Error::other)?;

        fs::remove_file(&source)?;
        fs::remove_dir(fixture.notes())?;
        let outside = fixture.root().join("outside");
        fs::create_dir(&outside)?;
        let outside_source = outside.join("escaped-source.md.enc");
        fs::write(&outside_source, OLD_CIPHERTEXT)?;
        symlink(&outside, fixture.notes())?;

        assert!(matches!(
            recover_pending_rebind(fixture.root()),
            Err(AtomicWriteError::RebindRecoveryConflict)
        ));
        assert_eq!(fs::read(outside_source)?, OLD_CIPHERTEXT);
        Ok(())
    }

    #[test]
    fn mutation_guard_cannot_target_private_or_noncanonical_storage() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let guard = VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?;
        let lock = fixture
            .root()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(VAULT_MUTATION_LOCK_FILE);
        assert!(matches!(
            guard.delete(&lock, WriteCondition::IfMatch(digest_bytes(b""))),
            Err(AtomicWriteError::InvalidTarget)
        ));
        assert!(matches!(
            guard.write(
                &fixture.root().join(".git/escape.md.enc"),
                NEW_CIPHERTEXT,
                WriteCondition::IfNoneMatch
            ),
            Err(AtomicWriteError::InvalidTarget)
        ));
        assert!(lock.exists());
        Ok(())
    }

    #[test]
    fn wrong_case_private_directory_alias_fails_closed() -> io::Result<()> {
        let fixture = TestVault::new()?;
        fs::create_dir(fixture.root().join(".VAULT-LOCAL"))?;
        let target = fixture.note("case-alias.md.enc");
        assert!(matches!(
            atomic_write_ciphertext(
                fixture.root(),
                &target,
                NEW_CIPHERTEXT,
                WriteCondition::IfNoneMatch
            ),
            Err(AtomicWriteError::UnsafeLockPath)
        ));
        assert!(!target.exists());
        Ok(())
    }

    #[test]
    fn metadata_write_rejects_wrong_case_vault_json_alias() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let alias = fixture.root().join("VAULT.JSON");
        fs::write(&alias, OLD_CIPHERTEXT)?;
        let guard = VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?;
        assert!(matches!(
            guard.write(
                &fixture.root().join("vault.json"),
                NEW_CIPHERTEXT,
                WriteCondition::IfNoneMatch,
            ),
            Err(AtomicWriteError::InvalidTarget)
        ));
        assert_eq!(fs::read(alias)?, OLD_CIPHERTEXT);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_cannot_redirect_guard_staging_or_commit() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = TestVault::new()?;
        let outside = fixture.root().join("outside");
        fs::create_dir(&outside)?;
        symlink(&outside, fixture.root().join("escape"))?;
        let guard = VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?;
        assert!(matches!(
            guard.write(
                &fixture.root().join("escape/note.md.enc"),
                NEW_CIPHERTEXT,
                WriteCondition::IfNoneMatch
            ),
            Err(AtomicWriteError::InvalidTarget)
        ));
        assert!(!outside.join("note.md.enc").exists());
        Ok(())
    }

    #[test]
    fn error_display_and_debug_never_include_ciphertext() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("redacted.md.enc");
        let secret = b"EDRY-super-secret-ciphertext-marker";
        let error = atomic_write_ciphertext_with_faults(
            fixture.root(),
            &target,
            secret,
            WriteCondition::IfNoneMatch,
            &FailAt(FaultPoint::WriteStaging),
        )
        .expect_err("fault must be returned");

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("super-secret"));
        assert!(!debug.contains("super-secret"));
        assert_no_staging_files(fixture.notes())?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn committed_file_and_lock_state_use_restrictive_modes() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let fixture = TestVault::new()?;
        let target = fixture.note("permissions.md.enc");
        atomic_write_ciphertext(
            fixture.root(),
            &target,
            NEW_CIPHERTEXT,
            WriteCondition::IfNoneMatch,
        )
        .map_err(io::Error::other)?;

        let local = fixture.root().join(VAULT_LOCAL_DIRECTORY);
        let lock = local.join(VAULT_MUTATION_LOCK_FILE);
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&local)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&lock)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_lock_path_is_rejected_without_touching_target() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = TestVault::new()?;
        let target = fixture.note("unsafe-lock.md.enc");
        fs::write(&target, OLD_CIPHERTEXT)?;
        let outside = fixture.root().join("outside-lock-target");
        fs::write(&outside, b"do-not-change")?;
        let local = fixture.root().join(VAULT_LOCAL_DIRECTORY);
        fs::create_dir(&local)?;
        symlink(&outside, local.join(VAULT_MUTATION_LOCK_FILE))?;

        let error = atomic_write_ciphertext(
            fixture.root(),
            &target,
            NEW_CIPHERTEXT,
            WriteCondition::IfMatch(digest_bytes(OLD_CIPHERTEXT)),
        )
        .expect_err("symlinked lock path must be rejected");

        assert!(matches!(error, AtomicWriteError::UnsafeLockPath));
        assert_eq!(fs::read(&outside)?, b"do-not-change");
        assert_eq!(fs::read(&target)?, OLD_CIPHERTEXT);
        assert_no_staging_files(fixture.notes())?;
        Ok(())
    }

    #[derive(Debug)]
    struct FailAt(FaultPoint);

    impl FaultInjector for FailAt {
        fn check(&self, point: FaultPoint) -> io::Result<()> {
            if point == self.0 {
                Err(io::Error::other("injected atomic write failure"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug)]
    struct Rendezvous {
        barrier: Barrier,
    }

    impl FaultInjector for Rendezvous {
        fn check(&self, point: FaultPoint) -> io::Result<()> {
            if point == FaultPoint::BeforeLock {
                self.barrier.wait();
            }
            Ok(())
        }
    }

    struct TestVault {
        root: PathBuf,
        notes: PathBuf,
    }

    impl TestVault {
        fn new() -> io::Result<Self> {
            let root =
                std::env::temp_dir().join(format!("inex-atomic-test-{}", uuid::Uuid::new_v4()));
            let notes = root.join("notes");
            fs::create_dir_all(&notes)?;
            Ok(Self { root, notes })
        }

        fn root(&self) -> &Path {
            &self.root
        }

        fn notes(&self) -> &Path {
            &self.notes
        }

        fn note(&self, name: &str) -> PathBuf {
            self.notes.join(name)
        }
    }

    impl Drop for TestVault {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn assert_no_staging_files(directory: &Path) -> io::Result<()> {
        let names = fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<HashSet<_>>>()?;
        assert!(names.iter().all(|name| {
            let name = name.to_string_lossy();
            !(name.starts_with(CIPHERTEXT_STAGING_PREFIX)
                && name.ends_with(CIPHERTEXT_STAGING_SUFFIX))
        }));
        Ok(())
    }

    #[test]
    fn io_error_stage_is_scrubbed_but_machine_readable() {
        let error = AtomicWriteError::io(
            AtomicWriteStage::SyncStaging,
            io::Error::other("disk unavailable"),
        );
        assert!(matches!(
            error,
            AtomicWriteError::Io {
                stage: AtomicWriteStage::SyncStaging,
                ..
            }
        ));
    }
}
