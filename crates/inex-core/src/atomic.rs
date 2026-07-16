//! Atomic ciphertext persistence and the per-vault mutation lock.
//!
//! A save first acquires an OS-backed lock in `.vault-local`, then is staged
//! inside that private directory, fully written, synchronized, and committed
//! to its destination while the lock remains held. The compare condition is
//! deliberately checked under the same lock. No function in this module
//! accepts or creates plaintext.
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
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::path::{AssetPath, LogicalPath, raw_portable_case_fold_key};
use crate::publication::{PublicationMarkerError, PublicationMarkerV2};
#[cfg(target_os = "linux")]
use crate::publication::{PublicationMarkerV2Input, PublicationMarkerV2PreflightInput};

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

/// Reserved basename prefix for repository-import publication claims.
pub const IMPORT_PUBLISH_MARKER_PREFIX: &str = "import-publish-marker-";

/// Legacy private publication marker retained for preview compatibility.
pub const IMPORT_PUBLISH_MARKER_V1: &str = "import-publish-marker-v1";

/// Canonical cross-process repository-import publication marker.
pub const IMPORT_PUBLISH_MARKER_V2: &str = "import-publish-marker-v2";

/// Legacy marker name used by the current preview directory publisher.
pub const IMPORT_PUBLISH_MARKER: &str = IMPORT_PUBLISH_MARKER_V1;

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
const MAX_STAGING_RECOVERY_ENTRIES: usize = 100_000;
const MAX_STAGING_RECOVERY_PATH_BYTES: usize = 32 * 1024 * 1024;
// Opaque-assets v1 is a bounded whole-file format. Callers retain their
// narrower per-kind limits, while the shared atomic writer must admit the
// exact largest authenticated asset envelope.
const MAX_ATOMIC_TARGET_BYTES: u64 = 67_112_988;

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
    /// Linux synchronized the parent directory; Windows either completed a
    /// write-through namespace move or flushed the parent directory after a
    /// verified deletion.
    Synced,
    /// The platform or filesystem did not confirm namespace durability.
    NotSynced,
}

/// Successful atomic-write result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicWriteOutcome {
    /// SHA-256 digest of the complete committed ciphertext envelope.
    pub etag: [u8; 32],
    /// Whether both the private staging directory and target parent syncs
    /// succeeded after the cross-directory namespace commit.
    pub parent_sync: ParentSyncStatus,
}

/// Successful atomic publication of a complete staged vault directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicDirectoryPublishOutcome {
    /// Whether the containing directory was synchronized after publication.
    pub parent_sync: ParentSyncStatus,
}

/// Failure to atomically move a verified directory without replacement.
#[derive(Debug, Error)]
pub enum AtomicDirectoryPublishError {
    /// The source/destination paths are not safe distinct sibling entries.
    #[error("verified directory-move paths are invalid")]
    InvalidPaths,
    /// The destination already has a filesystem entry.
    #[error("verified directory-move destination already exists")]
    DestinationExists,
    /// The no-replace operation left the exact source directory in place.
    #[error("verified directory namespace operation did not move the source")]
    NotMoved,
    /// Physical identities cannot prove one complete namespace outcome.
    #[error("verified directory namespace-move outcome is indeterminate")]
    Indeterminate,
    /// An import tree moved, but its caller-managed private marker remains.
    #[error("verified directory moved but caller-managed marker cleanup failed")]
    PublishedCleanupFailed,
    /// A scrubbed filesystem operation failed before the outcome was known.
    #[error("verified directory move I/O failed")]
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

/// Failure to remove one exact, identity-verified filesystem entry.
///
/// The variants deliberately describe only the physical outcome. Callers
/// retain their own recovery receipt and decide whether a later invocation
/// may resume from the pre-remove or post-remove state.
#[derive(Debug, Error)]
pub enum AtomicVerifiedRemoveError {
    /// The path, parent, source type, or expected identity is outside the
    /// supported local direct-child profile.
    #[error("verified removal path is invalid")]
    InvalidPath,
    /// An errored removal provably left the exact verified source in place.
    #[error("verified removal did not remove the source")]
    NotRemoved,
    /// The source path no longer proves either the exact old or absent state.
    #[error("verified removal outcome is indeterminate")]
    Indeterminate,
    /// A scrubbed filesystem operation failed before a physical outcome was
    /// available.
    #[error("verified removal I/O failed")]
    Io {
        /// Original error without caller path data in the display text.
        #[source]
        source: io::Error,
    },
}

impl AtomicVerifiedRemoveError {
    fn io(source: io::Error) -> Self {
        Self::Io { source }
    }

    fn initial(source: io::Error) -> Self {
        if matches!(
            source.kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::NotFound | io::ErrorKind::Unsupported
        ) {
            Self::InvalidPath
        } else {
            Self::io(source)
        }
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
    /// Creating the vault-private staging file.
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
    /// Auditing and removing safe crash-abandoned ciphertext staging files.
    RecoverStaging,
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
            Self::RecoverStaging => "ciphertext staging recovery",
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
    /// A staging-looking path could not be proven safe to remove.
    #[error("ciphertext staging recovery found an unsafe filesystem entry")]
    UnsafeStagingPath,
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
    /// A canonical repository publication claim must be reconciled before any
    /// ordinary vault mutation or recovery is allowed.
    #[error("repository publication reconciliation is required before vault mutation")]
    RepositoryPublicationReconcileRequired,
    /// A legacy, malformed, aliased, conflicting, or indeterminate repository
    /// publication namespace requires manual audit before vault mutation.
    #[error("repository publication marker state requires manual audit")]
    RepositoryPublicationManualAuditRequired,
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
    file: File,
}

impl fmt::Debug for VaultMutationLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultMutationLock { .. }")
    }
}

/// Failure from the existing-only, nonblocking publication mutation lock.
///
/// The variants and their debug/display output deliberately contain no paths
/// or filesystem identity bytes.
#[derive(Debug, Error)]
pub enum ExistingVaultMutationLockError {
    /// The candidate root path is not an absolute, link-free directory chain.
    #[error("existing vault root is unsafe")]
    UnsafeRoot,
    /// The current root does not reproduce the caller's audited identity.
    #[error("existing vault root identity changed")]
    RootIdentityMismatch,
    /// The exact `.vault-local` path is not a link-free directory.
    #[error("existing vault private directory is unsafe")]
    UnsafeLocalDirectory,
    /// The private directory does not reproduce the audited identity.
    #[error("existing vault private directory identity changed")]
    LocalIdentityMismatch,
    /// The opened lock or its filesystem/stream proof is structurally unsafe.
    #[error("existing vault mutation lock is unsafe")]
    UnsafeLock,
    /// The held lock does not reproduce the caller's audited identity.
    #[error("existing vault mutation lock identity changed")]
    LockIdentityMismatch,
    /// Another process or handle already holds the cooperative mutation lock.
    #[error("existing vault mutation lock is busy")]
    Busy,
    /// The target platform cannot provide the required existing-only lock.
    #[error("existing-only vault mutation locking is unsupported")]
    Unsupported,
    /// A read-only filesystem or identity query failed.
    #[error("existing-only vault mutation lock validation failed")]
    Io(#[source] io::Error),
}

impl ExistingVaultMutationLockError {
    fn io(source: io::Error) -> Self {
        if source.kind() == io::ErrorKind::Unsupported {
            Self::Unsupported
        } else {
            Self::Io(source)
        }
    }
}

/// Failure to open one existing destination's canonical publication claim.
///
/// This error is deliberately scrubbed: no variant contains a path, marker
/// body, publication identifier, candidate seal, or filesystem identity.
#[derive(Error)]
pub enum ExistingPublicationMarkerV2OpenError {
    /// The destination root is not one exact, link-free local directory.
    #[error("existing publication root is unsafe")]
    UnsafeRoot,
    /// The exact existing `.vault-local` directory is structurally unsafe.
    #[error("existing publication private directory is unsafe")]
    UnsafePrivateDirectory,
    /// The exact existing zero-byte, single-link lock is structurally unsafe.
    #[error("existing publication mutation lock is unsafe")]
    UnsafeLock,
    /// Another process or handle already holds the cooperative mutation lock.
    #[error("existing publication mutation lock is busy")]
    Busy,
    /// The reserved publication-marker namespace is not the sole canonical v2
    /// claim required by this opener.
    #[error("existing publication marker namespace conflicts")]
    NamespaceConflict,
    /// A held root, private directory, lock, marker, or recorded role drifted.
    #[error("existing publication authority changed")]
    AuthorityChanged,
    /// The target platform cannot provide the complete held Linux primitive.
    #[error("existing publication marker opening is unsupported")]
    Unsupported,
    /// A scrubbed read-only filesystem or identity query failed. Only the
    /// stable standard-library error class is retained.
    #[error("existing publication marker opening failed")]
    Io(io::ErrorKind),
}

impl fmt::Debug for ExistingPublicationMarkerV2OpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeRoot => "ExistingPublicationMarkerV2OpenError::UnsafeRoot",
            Self::UnsafePrivateDirectory => {
                "ExistingPublicationMarkerV2OpenError::UnsafePrivateDirectory"
            }
            Self::UnsafeLock => "ExistingPublicationMarkerV2OpenError::UnsafeLock",
            Self::Busy => "ExistingPublicationMarkerV2OpenError::Busy",
            Self::NamespaceConflict => "ExistingPublicationMarkerV2OpenError::NamespaceConflict",
            Self::AuthorityChanged => "ExistingPublicationMarkerV2OpenError::AuthorityChanged",
            Self::Unsupported => "ExistingPublicationMarkerV2OpenError::Unsupported",
            Self::Io(_) => "ExistingPublicationMarkerV2OpenError::Io(..)",
        })
    }
}

#[cfg(target_os = "linux")]
impl ExistingPublicationMarkerV2OpenError {
    fn io(source: io::Error) -> Self {
        let kind = source.kind();
        // Consume and discard the potentially path-bearing source before the
        // public error value is constructed.
        drop(source);
        if kind == io::ErrorKind::Unsupported {
            Self::Unsupported
        } else {
            Self::Io(kind)
        }
    }

    fn from_lock(error: ExistingVaultMutationLockError) -> Self {
        match error {
            ExistingVaultMutationLockError::UnsafeRoot => Self::UnsafeRoot,
            ExistingVaultMutationLockError::UnsafeLocalDirectory => Self::UnsafePrivateDirectory,
            ExistingVaultMutationLockError::UnsafeLock => Self::UnsafeLock,
            ExistingVaultMutationLockError::Busy => Self::Busy,
            ExistingVaultMutationLockError::Unsupported => Self::Unsupported,
            ExistingVaultMutationLockError::RootIdentityMismatch
            | ExistingVaultMutationLockError::LocalIdentityMismatch
            | ExistingVaultMutationLockError::LockIdentityMismatch => Self::AuthorityChanged,
            ExistingVaultMutationLockError::Io(source) => Self::io(source),
        }
    }

    fn from_marker(error: HeldPublicationMarkerV2Error) -> Self {
        match error {
            HeldPublicationMarkerV2Error::InvalidInput
            | HeldPublicationMarkerV2Error::AuthorityChanged => Self::AuthorityChanged,
            HeldPublicationMarkerV2Error::NamespaceConflict => Self::NamespaceConflict,
            HeldPublicationMarkerV2Error::Io(source) => Self::io(source),
        }
    }
}

/// Read-only classification of the reserved repository-publication namespace.
///
/// This classification is only a routing decision. `V2Exact` proves one
/// canonical marker pathname and byte stream; repository reconciliation must
/// still bind its identities, domain, child names, private state, and candidate
/// seal while holding the existing mutation lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryPublicationNamespaceState {
    /// The marker parent is absent or its complete inventory has no reserved
    /// basename.
    Absent,
    /// The sole reserved entry is the exact safe 16-byte legacy marker.
    LegacyUnverifiable,
    /// Multiple, aliased, unknown, or unsafe legacy reserved entries exist.
    ReservedConflict,
    /// The sole exact v2 pathname has unsafe properties or noncanonical bytes.
    V2Invalid,
    /// The sole exact v2 pathname and marker byte stream are canonical.
    V2Exact,
}

/// Failure to complete a read-only reserved-publication namespace inventory.
///
/// The error intentionally carries no path, marker bytes, identity, or OS
/// message. Callers must fail closed and direct the user to manual audit.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("repository publication marker namespace inspection is indeterminate")]
pub struct RepositoryPublicationNamespaceInspectionError;

/// Held existing-only publication lock for one already-audited vault root.
///
/// Acquisition opens only the exact pre-existing zero-byte
/// `.vault-local/mutation.lock`, never creates or chmods a path, never runs
/// ciphertext staging cleanup, and never replays rebind recovery. The
/// platform lock attempt is nonblocking. Dropping this value closes the held
/// file and releases the lock.
pub struct ExistingVaultMutationLock {
    root_identity: FilesystemDirectoryIdentity,
    local_identity: FilesystemDirectoryIdentity,
    lock_identity: FilesystemFileIdentity,
    file: File,
}

impl fmt::Debug for ExistingVaultMutationLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExistingVaultMutationLock { .. }")
    }
}

/// Caller-controlled fields for one Linux held publication-marker creation.
///
/// The staging-root, marker-parent, and marker-file identities are derived
/// from handles already held by the primitive. The common-parent identity is
/// retained because it belongs to the caller's sibling-publication contract.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub struct HeldPublicationMarkerV2CreateInput<'a> {
    /// One canonical identity scheme shared by every marker role.
    pub scheme: PublicationIdentityScheme,
    /// Nonzero CSPRNG publication identifier.
    pub publication_id: [u8; 16],
    /// Previously audited common-parent directory identity.
    pub common_parent_identity: &'a FilesystemDirectoryIdentity,
    /// Exact current staging-root direct-child name.
    pub staging_child_name: &'a str,
    /// Exact future destination direct-child name.
    pub destination_child_name: &'a str,
    /// Exact repository-specific marker domain.
    pub domain: &'a str,
    /// Nonempty opaque candidate seal.
    pub candidate_seal: &'a [u8],
}

#[cfg(target_os = "linux")]
impl fmt::Debug for HeldPublicationMarkerV2CreateInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeldPublicationMarkerV2CreateInput")
            .field("scheme", &self.scheme)
            .field("publication_id", &"[REDACTED]")
            .field("common_parent_identity", &"[REDACTED]")
            .field("staging_child_name", &"[REDACTED]")
            .field("destination_child_name", &"[REDACTED]")
            .field("domain", &"[REDACTED]")
            .field("candidate_seal", &"[REDACTED]")
            .finish()
    }
}

/// Failure to create, open, or revalidate one held publication marker.
///
/// No variant carries a path, marker body, publication identifier, candidate
/// seal, or filesystem identity. Once create-new has succeeded, failures do
/// not remove the reserved entry: an incomplete claim remains visible and
/// must be reconciled or audited by a later process.
#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
pub enum HeldPublicationMarkerV2Error {
    /// Caller fields or the staging-root child name are invalid.
    #[error("held publication marker input is invalid")]
    InvalidInput,
    /// A destination child or held reserved-prefix inventory conflicts with
    /// the requested state.
    #[error("held publication marker namespace conflicts with the requested state")]
    NamespaceConflict,
    /// A held root, directory, lock, file, or canonical body changed.
    #[error("held publication marker authority changed")]
    AuthorityChanged,
    /// A scrubbed filesystem operation failed.
    #[error("held publication marker filesystem operation failed")]
    Io(#[source] io::Error),
}

/// Shared immutable claim, held-directory, and mutation-lock authority.
#[cfg(target_os = "linux")]
struct PublicationMarkerV2Authority {
    marker: PublicationMarkerV2,
    marker_file_identity: FilesystemFileIdentity,
    common_parent: SecureSourceDirectory,
    root: SecureSourceDirectory,
    marker_parent: SecureSourceDirectory,
    mutation_lock: ExistingVaultMutationLock,
}

/// Linear Linux authority for one canonical publication-marker v2 claim.
///
/// The value owns the exact marker/root/private-directory handles and the
/// same existing-only mutation lock that preceded marker creation or opening.
/// It is intentionally neither `Clone` nor `Copy`, exposes no raw handle, and
/// drops the mutation lock last.
///
/// ```compile_fail
/// use inex_core::atomic::HeldPublicationMarkerV2;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<HeldPublicationMarkerV2>();
/// ```
pub struct HeldPublicationMarkerV2 {
    #[cfg(target_os = "linux")]
    marker_file: SecureSourceFile,
    #[cfg(target_os = "linux")]
    authority: PublicationMarkerV2Authority,
    #[cfg(not(target_os = "linux"))]
    unsupported: std::convert::Infallible,
}

#[cfg(target_os = "linux")]
struct FormerPublicationMarkerFile {
    file: File,
}

#[cfg(target_os = "linux")]
impl FormerPublicationMarkerFile {
    fn is_unlinked(&self) -> bool {
        linux_regular_file_handle_is_unlinked(&self.file)
    }
}

#[cfg(target_os = "linux")]
fn linux_regular_file_handle_is_unlinked(file: &File) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    file.metadata()
        .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.nlink() == 0)
}

#[cfg(target_os = "linux")]
impl fmt::Debug for HeldPublicationMarkerV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldPublicationMarkerV2 { .. }")
    }
}

#[cfg(not(target_os = "linux"))]
impl fmt::Debug for HeldPublicationMarkerV2 {
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.unsupported {}
    }
}

/// Live Linux authority after the exact held v2 marker was removed but its
/// parent-directory synchronization was not confirmed.
///
/// This value is intentionally neither `Clone` nor `Copy`. Its only mutating
/// operation retries the held marker-parent synchronization and associated
/// read-only revalidation; it cannot unlink or recreate a marker.
#[cfg(target_os = "linux")]
#[must_use]
pub struct UnsyncedPostUnlinkPublicationMarkerV2 {
    former_marker_file: FormerPublicationMarkerFile,
    authority: PublicationMarkerV2Authority,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for UnsyncedPostUnlinkPublicationMarkerV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnsyncedPostUnlinkPublicationMarkerV2 { .. }")
    }
}

/// Live Linux authority after exact marker removal and marker-parent sync.
///
/// The in-memory immutable claim, former marker identity, held root/private
/// directories, and original mutation lock remain owned until the caller's
/// clean audit and terminal result complete. The marker cannot be recreated.
#[cfg(target_os = "linux")]
#[must_use]
pub struct SyncedPostUnlinkPublicationMarkerV2 {
    former_marker_file: FormerPublicationMarkerFile,
    authority: PublicationMarkerV2Authority,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for SyncedPostUnlinkPublicationMarkerV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SyncedPostUnlinkPublicationMarkerV2 { .. }")
    }
}

/// Opaque terminal owner for a replacement or indeterminate unlink state.
///
/// It exposes no retry, cleanup, handle, or lock API. Retaining this value lets
/// the caller keep the same mutation lock through emission of a scrubbed
/// terminal result; dropping it releases that lock last.
#[cfg(target_os = "linux")]
#[must_use]
pub struct TerminalPublicationMarkerV2Authority {
    _former_marker_file: FormerPublicationMarkerFile,
    _authority: PublicationMarkerV2Authority,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for TerminalPublicationMarkerV2Authority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalPublicationMarkerV2Authority { .. }")
    }
}

/// Physical result of consuming one exact held publication marker.
///
/// Every variant retains the same mutation-lock lifetime. Its discriminant,
/// debug output, and errors expose no raw I/O error, path, marker byte,
/// identity, publication id, or candidate seal. Authority payloads expose
/// marker and identity data only through their explicit read-only getters.
#[cfg(target_os = "linux")]
#[must_use]
pub enum HeldPublicationMarkerV2UnlinkOutcome {
    /// The exact canonical marker remains and may be retried only by the
    /// caller's still-valid durable-with-marker typestate.
    NotRemoved(HeldPublicationMarkerV2),
    /// The exact marker is absent and its held parent was synchronized.
    RemovedAndParentSynced(SyncedPostUnlinkPublicationMarkerV2),
    /// The exact marker is absent, but parent synchronization was not proved.
    RemovedButParentSyncIndeterminate(UnsyncedPostUnlinkPublicationMarkerV2),
    /// A foreign entry occupies the exact marker pathname and was retained.
    ReplacementRetained(TerminalPublicationMarkerV2Authority),
    /// No exact old-present, absent, or replacement result could be proved.
    PostStateIndeterminate(TerminalPublicationMarkerV2Authority),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for HeldPublicationMarkerV2UnlinkOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotRemoved(_) => "HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(..)",
            Self::RemovedAndParentSynced(_) => {
                "HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced(..)"
            }
            Self::RemovedButParentSyncIndeterminate(_) => {
                "HeldPublicationMarkerV2UnlinkOutcome::RemovedButParentSyncIndeterminate(..)"
            }
            Self::ReplacementRetained(_) => {
                "HeldPublicationMarkerV2UnlinkOutcome::ReplacementRetained(..)"
            }
            Self::PostStateIndeterminate(_) => {
                "HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(..)"
            }
        })
    }
}

/// Result of retrying only post-unlink marker-parent synchronization.
#[cfg(target_os = "linux")]
#[must_use]
pub enum PostUnlinkMarkerParentSyncOutcome {
    /// The exact absent state and held parent synchronization are proved.
    Synced(SyncedPostUnlinkPublicationMarkerV2),
    /// Exact absence remains proved, but synchronization is still unconfirmed.
    StillIndeterminate(UnsyncedPostUnlinkPublicationMarkerV2),
    /// A replacement appeared and was retained without another unlink.
    ReplacementRetained(TerminalPublicationMarkerV2Authority),
    /// Post-unlink authority or namespace state became indeterminate.
    PostStateIndeterminate(TerminalPublicationMarkerV2Authority),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PostUnlinkMarkerParentSyncOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Synced(_) => "PostUnlinkMarkerParentSyncOutcome::Synced(..)",
            Self::StillIndeterminate(_) => {
                "PostUnlinkMarkerParentSyncOutcome::StillIndeterminate(..)"
            }
            Self::ReplacementRetained(_) => {
                "PostUnlinkMarkerParentSyncOutcome::ReplacementRetained(..)"
            }
            Self::PostStateIndeterminate(_) => {
                "PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(..)"
            }
        })
    }
}

/// Scrubbed read-only failure from a synchronized post-unlink owner.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PostUnlinkPublicationMarkerV2Error {
    /// A held directory, mutation lock, current root, or recorded role drifted.
    #[error("post-unlink publication authority changed")]
    AuthorityChanged,
    /// The reserved publication-marker namespace is not exact absent state.
    #[error("post-unlink publication marker namespace conflicts")]
    NamespaceConflict,
    /// A scrubbed filesystem observation was inconclusive.
    #[error("post-unlink publication state is indeterminate")]
    Indeterminate,
}

enum ReservedMarkerInspection {
    SafeBytes(Vec<u8>),
    Unsafe,
}

/// Inspect the repository-import publication-marker namespace without
/// creating, recovering, synchronizing, or removing any filesystem entry.
///
/// The inventory is bounded and revalidates the vault root, `.vault-local`,
/// and any held marker after inspection. A missing `.vault-local` is the clean
/// state used while creating a new vault. Any incomplete inventory or identity
/// drift is returned as an indeterminate inspection rather than being treated
/// as an absent marker.
///
/// # Errors
///
/// Returns a scrubbed indeterminate error when directory safety, local
/// filesystem support, complete enumeration, held-file binding, or final
/// identity revalidation cannot be proved.
pub fn inspect_repository_publication_namespace(
    vault_root: &Path,
) -> Result<RepositoryPublicationNamespaceState, RepositoryPublicationNamespaceInspectionError> {
    inspect_repository_publication_namespace_impl(vault_root)
        .map_err(|_| RepositoryPublicationNamespaceInspectionError)
}

fn inspect_repository_publication_namespace_impl(
    vault_root: &Path,
) -> io::Result<RepositoryPublicationNamespaceState> {
    if !vault_root.is_absolute()
        || !path_is_lexically_normal(vault_root)
        || !path_ancestors_are_non_link_directories(vault_root)?
        || !path_is_supported_local_filesystem(vault_root)?
    {
        return Err(io::Error::other(
            "repository publication root cannot be proved safe",
        ));
    }
    let root_identity = filesystem_directory_identity(vault_root)?;
    verify_directory_has_no_alternate_data_streams(vault_root, &root_identity)?;

    let local = vault_root.join(VAULT_LOCAL_DIRECTORY);
    let local_metadata = match fs::symlink_metadata(&local) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            revalidate_publication_namespace_root(vault_root, &root_identity)?;
            if matches!(
                fs::symlink_metadata(&local),
                Err(error) if error.kind() == io::ErrorKind::NotFound
            ) {
                return Ok(RepositoryPublicationNamespaceState::Absent);
            }
            return Err(io::Error::other(
                "repository publication marker parent changed during inspection",
            ));
        }
        Ok(metadata) => metadata,
        Err(error) => return Err(error),
    };
    if is_link_or_reparse_point(&local_metadata) || !local_metadata.file_type().is_dir() {
        return Err(io::Error::other(
            "repository publication marker parent is unsafe",
        ));
    }
    if !path_ancestors_are_non_link_directories(&local)?
        || !path_is_supported_local_filesystem(&local)?
        || !paths_share_mount(vault_root, &local)?
    {
        return Err(io::Error::other(
            "repository publication marker parent cannot be proved local",
        ));
    }
    let local_identity = filesystem_directory_identity(&local)?;
    verify_directory_has_no_alternate_data_streams(&local, &local_identity)?;

    let reserved_prefix = raw_portable_case_fold_key(IMPORT_PUBLISH_MARKER_PREFIX);
    let mut reserved = Vec::new();
    let mut entry_count = 0_usize;
    let mut name_bytes = 0_usize;
    for entry in fs::read_dir(&local)? {
        let entry = entry?;
        entry_count = entry_count
            .checked_add(1)
            .filter(|count| *count <= MAX_STAGING_RECOVERY_ENTRIES)
            .ok_or_else(|| io::Error::other("private namespace entry limit exceeded"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("private namespace name is not portable UTF-8"))?;
        name_bytes = name_bytes
            .checked_add(name.len())
            .filter(|total| *total <= MAX_STAGING_RECOVERY_PATH_BYTES)
            .ok_or_else(|| io::Error::other("private namespace path limit exceeded"))?;
        if raw_portable_case_fold_key(&name)
            .as_str()
            .starts_with(reserved_prefix.as_str())
        {
            reserved.push(name);
        }
    }
    revalidate_publication_namespace_directories(
        vault_root,
        &root_identity,
        &local,
        &local_identity,
    )?;

    let state = classify_reserved_publication_entries(&local, &reserved)?;
    revalidate_publication_namespace_directories(
        vault_root,
        &root_identity,
        &local,
        &local_identity,
    )?;
    Ok(state)
}

fn classify_reserved_publication_entries(
    local: &Path,
    reserved: &[String],
) -> io::Result<RepositoryPublicationNamespaceState> {
    Ok(match reserved {
        [] => RepositoryPublicationNamespaceState::Absent,
        [name] if name == IMPORT_PUBLISH_MARKER_V1 => {
            match inspect_reserved_marker(&local.join(name), Some(16))? {
                ReservedMarkerInspection::SafeBytes(_) => {
                    RepositoryPublicationNamespaceState::LegacyUnverifiable
                }
                ReservedMarkerInspection::Unsafe => {
                    RepositoryPublicationNamespaceState::ReservedConflict
                }
            }
        }
        [name] if name == IMPORT_PUBLISH_MARKER_V2 => {
            match inspect_reserved_marker(&local.join(name), None)? {
                ReservedMarkerInspection::SafeBytes(bytes) => {
                    match PublicationMarkerV2::parse(&bytes) {
                        Ok(_) => RepositoryPublicationNamespaceState::V2Exact,
                        Err(
                            PublicationMarkerError::InvalidFormat
                            | PublicationMarkerError::ResourceLimit,
                        ) => RepositoryPublicationNamespaceState::V2Invalid,
                        Err(PublicationMarkerError::Io { .. }) => {
                            return Err(io::Error::other(
                                "canonical publication marker read failed",
                            ));
                        }
                    }
                }
                ReservedMarkerInspection::Unsafe => RepositoryPublicationNamespaceState::V2Invalid,
            }
        }
        [_] | [_, ..] => RepositoryPublicationNamespaceState::ReservedConflict,
    })
}

fn inspect_reserved_marker(
    path: &Path,
    exact_size: Option<u64>,
) -> io::Result<ReservedMarkerInspection> {
    let path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::other(
                "reserved publication marker disappeared during inspection",
            ));
        }
        Err(error) => return Err(error),
    };
    if is_link_or_reparse_point(&path_metadata) || !path_metadata.file_type().is_file() {
        return Ok(ReservedMarkerInspection::Unsafe);
    }
    if exact_size.is_some_and(|size| path_metadata.len() != size)
        || path_metadata.len()
            > u64::try_from(crate::publication::PUBLICATION_MARKER_READ_LIMIT_BYTES)
                .unwrap_or(u64::MAX)
    {
        return Ok(ReservedMarkerInspection::Unsafe);
    }

    let mut file = platform::open_existing_mutation_lock(path)?;
    if !platform::open_file_is_single_link(&file)? {
        return Ok(ReservedMarkerInspection::Unsafe);
    }
    if !open_file_matches_path_and_is_single_link(path, &file)? {
        return Err(io::Error::other(
            "reserved publication marker path changed during inspection",
        ));
    }
    if let Err(error) = verify_regular_file_has_no_alternate_data_streams(path, &file) {
        return if error.kind() == io::ErrorKind::InvalidData {
            Ok(ReservedMarkerInspection::Unsafe)
        } else {
            Err(error)
        };
    }
    let held_identity = filesystem_file_identity(&file)?;
    let held_size = file.metadata()?.len();
    if held_size != path_metadata.len() {
        return Err(io::Error::other(
            "reserved publication marker changed during inspection",
        ));
    }
    let allocation = usize::try_from(held_size)
        .map_err(|_| io::Error::other("reserved publication marker is too large"))?;
    let mut bytes = vec![0_u8; allocation];
    file.read_exact(&mut bytes)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(io::Error::other(
            "reserved publication marker grew during inspection",
        ));
    }
    if filesystem_file_identity(&file)? != held_identity
        || !open_file_matches_path_and_is_single_link(path, &file)?
    {
        return Err(io::Error::other(
            "reserved publication marker binding changed during inspection",
        ));
    }
    verify_regular_file_has_no_alternate_data_streams(path, &file)?;
    Ok(ReservedMarkerInspection::SafeBytes(bytes))
}

fn revalidate_publication_namespace_root(
    vault_root: &Path,
    expected_root: &FilesystemDirectoryIdentity,
) -> io::Result<()> {
    if filesystem_directory_identity(vault_root)? != *expected_root
        || !path_is_supported_local_filesystem(vault_root)?
    {
        return Err(io::Error::other(
            "repository publication root identity changed",
        ));
    }
    verify_directory_has_no_alternate_data_streams(vault_root, expected_root)
}

fn revalidate_publication_namespace_directories(
    vault_root: &Path,
    expected_root: &FilesystemDirectoryIdentity,
    local: &Path,
    expected_local: &FilesystemDirectoryIdentity,
) -> io::Result<()> {
    revalidate_publication_namespace_root(vault_root, expected_root)?;
    if filesystem_directory_identity(local)? != *expected_local
        || !path_is_supported_local_filesystem(local)?
        || !paths_share_mount(vault_root, local)?
    {
        return Err(io::Error::other(
            "repository publication marker parent identity changed",
        ));
    }
    verify_directory_has_no_alternate_data_streams(local, expected_local)
}

fn require_no_repository_publication_claim(vault_root: &Path) -> Result<(), AtomicWriteError> {
    match inspect_repository_publication_namespace(vault_root) {
        Ok(RepositoryPublicationNamespaceState::Absent) => Ok(()),
        Ok(RepositoryPublicationNamespaceState::V2Exact) => {
            Err(AtomicWriteError::RepositoryPublicationReconcileRequired)
        }
        Ok(
            RepositoryPublicationNamespaceState::LegacyUnverifiable
            | RepositoryPublicationNamespaceState::ReservedConflict
            | RepositoryPublicationNamespaceState::V2Invalid,
        )
        | Err(_) => Err(AtomicWriteError::RepositoryPublicationManualAuditRequired),
    }
}

/// Open one already-published canonical v2 claim and retain its exact
/// existing mutation lock.
///
/// Linux opens the root, `.vault-local`, `mutation.lock`, and marker through
/// one descriptor-bound chain. The lock file must already exist as an exact
/// zero-byte, single-link regular file; acquisition is nonblocking. This
/// function never creates or chmods a path, never runs ciphertext cleanup,
/// never replays recovery, and never removes or rewrites a marker. The
/// returned authority is valid only when `current_root` occupies the marker's
/// recorded destination and the recorded staging sibling is absent.
///
/// Other targets fail closed with
/// [`ExistingPublicationMarkerV2OpenError::Unsupported`].
///
/// # Errors
///
/// Returns a scrubbed structural, busy, namespace, authority, unsupported,
/// or I/O error. Every failure drops any transient handles without modifying
/// the existing namespace.
pub fn open_existing_publication_marker_v2(
    current_root: &Path,
) -> Result<HeldPublicationMarkerV2, ExistingPublicationMarkerV2OpenError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = current_root;
        Err(ExistingPublicationMarkerV2OpenError::Unsupported)
    }

    #[cfg(target_os = "linux")]
    {
        open_existing_publication_marker_v2_linux(current_root)
    }
}

#[cfg(target_os = "linux")]
fn open_existing_publication_marker_v2_linux(
    current_root: &Path,
) -> Result<HeldPublicationMarkerV2, ExistingPublicationMarkerV2OpenError> {
    if !current_root.is_absolute() || !path_is_lexically_normal(current_root) {
        return Err(ExistingPublicationMarkerV2OpenError::UnsafeRoot);
    }

    let held_root =
        open_secure_source_root(current_root).map_err(ExistingPublicationMarkerV2OpenError::io)?;
    held_root
        .verify_no_alternate_data_streams()
        .map_err(ExistingPublicationMarkerV2OpenError::io)?;

    let marker_parent = match held_root
        .open_child(std::ffi::OsStr::new(VAULT_LOCAL_DIRECTORY))
        .map_err(ExistingPublicationMarkerV2OpenError::io)?
    {
        SecureSourceChild::Directory(directory) => directory,
        SecureSourceChild::File(_) | SecureSourceChild::Other => {
            return Err(ExistingPublicationMarkerV2OpenError::UnsafePrivateDirectory);
        }
    };
    marker_parent
        .verify_no_alternate_data_streams()
        .map_err(ExistingPublicationMarkerV2OpenError::io)?;

    let mutation_lock =
        acquire_held_existing_publication_lock(current_root, &held_root, &marker_parent)?;
    drop(marker_parent);
    let held = mutation_lock
        .open_held_publication_marker_v2(current_root, held_root)
        .map_err(ExistingPublicationMarkerV2OpenError::from_marker)?;
    held.require_published_at(current_root)
        .map_err(ExistingPublicationMarkerV2OpenError::from_marker)?;
    Ok(held)
}

#[cfg(target_os = "linux")]
fn acquire_held_existing_publication_lock(
    current_root: &Path,
    held_root: &SecureSourceDirectory,
    marker_parent: &SecureSourceDirectory,
) -> Result<ExistingVaultMutationLock, ExistingPublicationMarkerV2OpenError> {
    let root_identity = held_root.identity().clone();
    let local_identity = marker_parent.identity().clone();

    let held_lock = match marker_parent
        .open_child(std::ffi::OsStr::new(VAULT_MUTATION_LOCK_FILE))
        .map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                ExistingPublicationMarkerV2OpenError::io(source)
            } else {
                ExistingPublicationMarkerV2OpenError::UnsafeLock
            }
        })? {
        SecureSourceChild::File(file) => file,
        SecureSourceChild::Directory(_) | SecureSourceChild::Other => {
            return Err(ExistingPublicationMarkerV2OpenError::UnsafeLock);
        }
    };
    if held_lock
        .observed_len()
        .map_err(ExistingPublicationMarkerV2OpenError::io)?
        != 0
    {
        return Err(ExistingPublicationMarkerV2OpenError::UnsafeLock);
    }
    held_lock
        .verify_no_alternate_data_streams()
        .map_err(|_| ExistingPublicationMarkerV2OpenError::UnsafeLock)?;
    let lock_identity = held_lock
        .identity()
        .map_err(|_| ExistingPublicationMarkerV2OpenError::UnsafeLock)?;
    if lock_identity.projections.comparison_volume()
        != local_identity.projections.comparison_volume()
    {
        return Err(ExistingPublicationMarkerV2OpenError::UnsafeLock);
    }

    validate_existing_vault_lock_state(
        current_root,
        &root_identity,
        &local_identity,
        &lock_identity,
        &held_lock.file,
    )
    .map_err(ExistingPublicationMarkerV2OpenError::from_lock)?;
    held_root
        .verify_no_alternate_data_streams()
        .map_err(ExistingPublicationMarkerV2OpenError::io)?;
    marker_parent
        .verify_no_alternate_data_streams()
        .map_err(ExistingPublicationMarkerV2OpenError::io)?;
    held_lock
        .verify_no_alternate_data_streams()
        .map_err(|_| ExistingPublicationMarkerV2OpenError::UnsafeLock)?;

    if !platform::try_lock_exclusive(&held_lock.file)
        .map_err(ExistingPublicationMarkerV2OpenError::io)?
    {
        return Err(ExistingPublicationMarkerV2OpenError::Busy);
    }

    held_root
        .verify_no_alternate_data_streams()
        .map_err(ExistingPublicationMarkerV2OpenError::io)?;
    marker_parent
        .verify_no_alternate_data_streams()
        .map_err(ExistingPublicationMarkerV2OpenError::io)?;
    held_lock
        .verify_no_alternate_data_streams()
        .map_err(|_| ExistingPublicationMarkerV2OpenError::UnsafeLock)?;
    validate_existing_vault_lock_state(
        current_root,
        &root_identity,
        &local_identity,
        &lock_identity,
        &held_lock.file,
    )
    .map_err(ExistingPublicationMarkerV2OpenError::from_lock)?;

    let SecureSourceFile { file, .. } = held_lock;
    let mutation_lock = ExistingVaultMutationLock {
        root_identity,
        local_identity,
        lock_identity,
        file,
    };
    Ok(mutation_lock)
}

impl ExistingVaultMutationLock {
    /// Opens and nonblockingly locks one exact, already-audited mutation lock.
    ///
    /// The expected identities must come from a prior marker-free/seal audit.
    /// This function performs no persistent mutation and does not invoke any
    /// vault recovery path.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed structural/identity error,
    /// [`ExistingVaultMutationLockError::Busy`] when the cooperative lock is
    /// already held, or [`ExistingVaultMutationLockError::Unsupported`] when
    /// the host cannot provide the required primitive.
    pub fn acquire(
        vault_root: &Path,
        expected_root_identity: &FilesystemDirectoryIdentity,
        expected_local_identity: &FilesystemDirectoryIdentity,
        expected_lock_identity: &FilesystemFileIdentity,
    ) -> Result<Self, ExistingVaultMutationLockError> {
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = (
                vault_root,
                expected_root_identity,
                expected_local_identity,
                expected_lock_identity,
            );
            return Err(ExistingVaultMutationLockError::Unsupported);
        }
        validate_existing_vault_directories(
            vault_root,
            expected_root_identity,
            expected_local_identity,
        )?;
        let lock_path = vault_root
            .join(VAULT_LOCAL_DIRECTORY)
            .join(VAULT_MUTATION_LOCK_FILE);
        let file = platform::open_existing_mutation_lock(&lock_path)
            .map_err(ExistingVaultMutationLockError::io)?;
        validate_existing_vault_lock_state(
            vault_root,
            expected_root_identity,
            expected_local_identity,
            expected_lock_identity,
            &file,
        )?;
        if !platform::try_lock_exclusive(&file).map_err(ExistingVaultMutationLockError::io)? {
            return Err(ExistingVaultMutationLockError::Busy);
        }
        validate_existing_vault_lock_state(
            vault_root,
            expected_root_identity,
            expected_local_identity,
            expected_lock_identity,
            &file,
        )?;
        Ok(Self {
            root_identity: expected_root_identity.clone(),
            local_identity: expected_local_identity.clone(),
            lock_identity: expected_lock_identity.clone(),
            file,
        })
    }

    /// Revalidates the exact held root/private-directory/lock identities at a
    /// candidate path, including after a whole-root rename.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed error if the candidate path, any identity, the empty
    /// lock body, single-link binding, or alternate-stream proof has drifted.
    pub fn revalidate(&self, candidate_root: &Path) -> Result<(), ExistingVaultMutationLockError> {
        validate_existing_vault_lock_state(
            candidate_root,
            &self.root_identity,
            &self.local_identity,
            &self.lock_identity,
            &self.file,
        )
    }

    /// Returns the audited physical vault-root identity.
    #[must_use]
    pub const fn root_identity(&self) -> &FilesystemDirectoryIdentity {
        &self.root_identity
    }

    /// Returns the audited physical `.vault-local` identity.
    #[must_use]
    pub const fn local_identity(&self) -> &FilesystemDirectoryIdentity {
        &self.local_identity
    }

    /// Returns the audited physical zero-byte lock-file identity.
    #[must_use]
    pub const fn lock_identity(&self) -> &FilesystemFileIdentity {
        &self.lock_identity
    }

    /// Consume this lock and one already-held staging root to create the exact
    /// canonical publication-marker v2 claim.
    ///
    /// Linux performs one descriptor-relative `openat2` create-new beneath
    /// the held `.vault-local`, writes and synchronizes the canonical body,
    /// performs bounded exact re-reads, synchronizes the held private/root
    /// directory handles, and returns an owner that keeps this same lock.
    /// No path-based create or directory sync participates in the authority.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed input, namespace, authority, or I/O error. If the
    /// create-new operation itself succeeded, no later error deletes or
    /// replaces the reserved marker.
    #[cfg(target_os = "linux")]
    pub fn create_held_publication_marker_v2(
        self,
        staging_root: &Path,
        held_root: SecureSourceDirectory,
        input: HeldPublicationMarkerV2CreateInput<'_>,
    ) -> Result<HeldPublicationMarkerV2, HeldPublicationMarkerV2Error> {
        HeldPublicationMarkerV2::create(staging_root, held_root, self, input)
    }

    /// Consume this lock and one already-held root to open the sole exact
    /// canonical publication-marker v2 claim without modifying it.
    ///
    /// The complete reserved-prefix inventory must contain only the exact v2
    /// basename. The returned owner binds the canonical body to the held
    /// common/root/private/file identities and retains this same lock.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed namespace, authority, or I/O error for a missing,
    /// aliased, malformed, rebound, hard-linked, or otherwise unsafe claim.
    #[cfg(target_os = "linux")]
    pub fn open_held_publication_marker_v2(
        self,
        current_root: &Path,
        held_root: SecureSourceDirectory,
    ) -> Result<HeldPublicationMarkerV2, HeldPublicationMarkerV2Error> {
        HeldPublicationMarkerV2::open_existing(current_root, held_root, self)
    }
}

fn validate_existing_vault_directories(
    vault_root: &Path,
    expected_root_identity: &FilesystemDirectoryIdentity,
    expected_local_identity: &FilesystemDirectoryIdentity,
) -> Result<(), ExistingVaultMutationLockError> {
    if !vault_root.is_absolute() || !path_is_lexically_normal(vault_root) {
        return Err(ExistingVaultMutationLockError::UnsafeRoot);
    }
    if !path_ancestors_are_non_link_directories(vault_root)
        .map_err(ExistingVaultMutationLockError::io)?
    {
        return Err(ExistingVaultMutationLockError::UnsafeRoot);
    }
    if !path_is_supported_local_filesystem(vault_root)
        .map_err(ExistingVaultMutationLockError::io)?
    {
        return Err(ExistingVaultMutationLockError::UnsafeRoot);
    }
    let root_identity =
        filesystem_directory_identity(vault_root).map_err(ExistingVaultMutationLockError::io)?;
    if root_identity != *expected_root_identity {
        return Err(ExistingVaultMutationLockError::RootIdentityMismatch);
    }

    let local = vault_root.join(VAULT_LOCAL_DIRECTORY);
    if !path_ancestors_are_non_link_directories(&local)
        .map_err(ExistingVaultMutationLockError::io)?
    {
        return Err(ExistingVaultMutationLockError::UnsafeLocalDirectory);
    }
    if !path_is_supported_local_filesystem(&local).map_err(ExistingVaultMutationLockError::io)?
        || !paths_share_mount(vault_root, &local).map_err(ExistingVaultMutationLockError::io)?
    {
        return Err(ExistingVaultMutationLockError::UnsafeLocalDirectory);
    }
    let local_identity =
        filesystem_directory_identity(&local).map_err(ExistingVaultMutationLockError::io)?;
    if local_identity != *expected_local_identity {
        return Err(ExistingVaultMutationLockError::LocalIdentityMismatch);
    }
    Ok(())
}

fn validate_existing_vault_lock_location(
    vault_root: &Path,
    lock_path: &Path,
) -> Result<(), ExistingVaultMutationLockError> {
    if !path_is_supported_local_filesystem(lock_path).map_err(ExistingVaultMutationLockError::io)?
        || !paths_share_mount(vault_root, lock_path).map_err(ExistingVaultMutationLockError::io)?
    {
        return Err(ExistingVaultMutationLockError::UnsafeLock);
    }
    Ok(())
}

fn validate_existing_vault_lock_binding(
    lock_path: &Path,
    expected_lock_identity: &FilesystemFileIdentity,
    file: &File,
) -> Result<(), ExistingVaultMutationLockError> {
    let path_metadata =
        fs::symlink_metadata(lock_path).map_err(ExistingVaultMutationLockError::io)?;
    let held_metadata = file
        .metadata()
        .map_err(ExistingVaultMutationLockError::io)?;
    if is_link_or_reparse_point(&path_metadata)
        || !path_metadata.file_type().is_file()
        || path_metadata.len() != 0
        || !held_metadata.file_type().is_file()
        || held_metadata.len() != 0
    {
        return Err(ExistingVaultMutationLockError::UnsafeLock);
    }
    let held_identity = filesystem_file_identity(file).map_err(|source| {
        if source.kind() == io::ErrorKind::InvalidInput {
            ExistingVaultMutationLockError::UnsafeLock
        } else {
            ExistingVaultMutationLockError::io(source)
        }
    })?;
    if held_identity != *expected_lock_identity {
        return Err(ExistingVaultMutationLockError::LockIdentityMismatch);
    }
    if !open_file_matches_path_and_is_single_link(lock_path, file)
        .map_err(ExistingVaultMutationLockError::io)?
    {
        return Err(ExistingVaultMutationLockError::LockIdentityMismatch);
    }
    Ok(())
}

fn validate_existing_vault_lock_state(
    vault_root: &Path,
    expected_root_identity: &FilesystemDirectoryIdentity,
    expected_local_identity: &FilesystemDirectoryIdentity,
    expected_lock_identity: &FilesystemFileIdentity,
    file: &File,
) -> Result<(), ExistingVaultMutationLockError> {
    validate_existing_vault_directories(
        vault_root,
        expected_root_identity,
        expected_local_identity,
    )?;
    let lock_path = vault_root
        .join(VAULT_LOCAL_DIRECTORY)
        .join(VAULT_MUTATION_LOCK_FILE);
    validate_existing_vault_lock_location(vault_root, &lock_path)?;
    validate_existing_vault_lock_binding(&lock_path, expected_lock_identity, file)?;
    verify_regular_file_has_no_alternate_data_streams(&lock_path, file).map_err(|source| {
        if matches!(
            source.kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData
        ) {
            ExistingVaultMutationLockError::UnsafeLock
        } else {
            ExistingVaultMutationLockError::io(source)
        }
    })?;
    validate_existing_vault_lock_binding(&lock_path, expected_lock_identity, file)?;
    validate_existing_vault_lock_location(vault_root, &lock_path)?;
    validate_existing_vault_directories(vault_root, expected_root_identity, expected_local_identity)
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
    root_identity: FilesystemDirectoryIdentity,
    local_identity: FilesystemDirectoryIdentity,
    recovery_changed_repository: bool,
    lock: VaultMutationLock,
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
        Self::acquire_with_faults(vault_root, &NoFaults)
    }

    fn acquire_with_faults<F: FaultInjector>(
        vault_root: &Path,
        faults: &F,
    ) -> Result<Self, AtomicWriteError> {
        require_no_repository_publication_claim(vault_root)?;
        let root_identity = filesystem_directory_identity(vault_root)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;
        let lock = VaultMutationLock::acquire_with_faults(vault_root, faults)?;
        let locked_root_identity = filesystem_directory_identity(vault_root)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;
        if locked_root_identity != root_identity {
            return Err(AtomicWriteError::io(
                AtomicWriteStage::PrepareLock,
                io::Error::other("vault root identity changed while acquiring its mutation lock"),
            ));
        }
        let local = vault_root.join(VAULT_LOCAL_DIRECTORY);
        let local_identity = filesystem_directory_identity(&local)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;
        let lock_path = local.join(VAULT_MUTATION_LOCK_FILE);
        if !open_file_matches_path_and_is_single_link(&lock_path, &lock.file)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?
        {
            return Err(AtomicWriteError::UnsafeLockPath);
        }
        require_no_repository_publication_claim(vault_root)?;
        recover_ciphertext_staging_locked(vault_root)?;
        let recovery_changed_repository = recover_pending_rebind_locked(vault_root)?;
        Ok(Self {
            root: vault_root.to_path_buf(),
            root_identity,
            local_identity,
            recovery_changed_repository,
            lock,
        })
    }

    /// Whether this live guard still protects the exact physical vault root.
    ///
    /// The check fails closed when either the path used to acquire the guard
    /// or `candidate_root` is missing, unreadable, or rebound to another
    /// directory identity.
    #[must_use]
    pub fn is_for_root(&self, candidate_root: &Path) -> bool {
        let local = self.root.join(VAULT_LOCAL_DIRECTORY);
        let candidate_local = candidate_root.join(VAULT_LOCAL_DIRECTORY);
        let lock_path = local.join(VAULT_MUTATION_LOCK_FILE);
        let candidate_lock_path = candidate_local.join(VAULT_MUTATION_LOCK_FILE);
        filesystem_directory_identity(&self.root).is_ok_and(|current| current == self.root_identity)
            && filesystem_directory_identity(candidate_root)
                .is_ok_and(|candidate| candidate == self.root_identity)
            && filesystem_directory_identity(&local)
                .is_ok_and(|current| current == self.local_identity)
            && filesystem_directory_identity(&candidate_local)
                .is_ok_and(|candidate| candidate == self.local_identity)
            && open_file_matches_path_and_is_single_link(&lock_path, &self.lock.file)
                .unwrap_or(false)
            && open_file_matches_path_and_is_single_link(&candidate_lock_path, &self.lock.file)
                .unwrap_or(false)
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
        let staging_parent = self.root.join(VAULT_LOCAL_DIRECTORY);
        let (mut staging, etag) = stage_and_verify(&staging_parent, ciphertext, &NoFaults)?;
        let current = inspect_current_target(target)?;
        enforce_condition(condition, current)?;
        if let Err(source) = namespace_move(
            staging.path(),
            target,
            matches!(condition, WriteCondition::IfMatch(_)),
        ) {
            return reconcile_failed_namespace_commit(target, current, etag, source).map(
                |target_parent_sync| AtomicWriteOutcome {
                    etag,
                    parent_sync: combine_parent_sync(
                        target_parent_sync,
                        sync_namespace_parent_status(&staging_parent),
                    ),
                },
            );
        }
        staging.disarm();
        Ok(AtomicWriteOutcome {
            etag,
            parent_sync: sync_staging_and_target_parents_status(&staging_parent, parent),
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

        let (file, lock_created) = open_lock_file(&lock_path)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::PrepareLock, source))?;
        reject_unsafe_existing_lock_file(vault_root, &lock_path)?;
        if lock_created {
            restrict_file_permissions_best_effort(&file);
        }

        faults
            .check(FaultPoint::AcquireLock)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::AcquireLock, source))?;
        platform::lock_exclusive(&file)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::AcquireLock, source))?;

        Ok(Self { file })
    }
}

/// Writes and atomically commits an already-encrypted byte envelope.
///
/// `target` is never opened for writing. The function first acquires the vault
/// mutation lock and recovers safe crash-abandoned staging files. It then
/// creates a random `create_new` staging file inside `.vault-local`, writes,
/// flushes, synchronizes and verifies it, rechecks `condition`, and renames the
/// complete staging file over `target`. Source and target parent-directory
/// syncs are best effort and reported together in the successful outcome.
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

/// Move one verified directory to a previously absent sibling name.
///
/// Both paths must be distinct absolute direct children of one canonical,
/// link-free parent on a supported local filesystem. The source identity is
/// captured before `critical_audit` and verified again immediately before the
/// strictly no-replace namespace operation. Linux binds both names to a held
/// parent descriptor for `renameat2(RENAME_NOREPLACE)`; Windows uses
/// `MoveFileExW(MOVEFILE_WRITE_THROUGH)` without the replace flag.
///
/// This primitive deliberately knows nothing about import staging names,
/// vault-private directories, or publication markers. Callers that require a
/// stronger tree-content invariant must enforce it in `critical_audit` and
/// hold their own mutation guard or equivalent exclusive protocol for the
/// duration of the call. `critical_audit` runs exactly once after the physical
/// source identity is captured and receives the exact `source` path supplied
/// by the caller, including its platform-specific path spelling; internal
/// canonical or Windows verbatim paths are never substituted into the callback.
/// Callers must also exclude a non-cooperating process running as the same OS
/// user from rebinding either child name between the final identity check and
/// the namespace operation; post-state reconciliation detects but cannot
/// prevent that path-based race. This API is not an operating-system-level
/// compare-and-exchange over directory identity.
///
/// # Errors
///
/// Returns [`AtomicDirectoryPublishError::DestinationExists`] when an
/// unrelated destination is present, [`AtomicDirectoryPublishError::NotMoved`]
/// when an errored namespace operation provably left the exact source in
/// place, and [`AtomicDirectoryPublishError::Indeterminate`] when physical
/// identities do not prove one complete outcome. An audit failure is returned
/// as a scrubbed [`AtomicDirectoryPublishError::Io`].
pub fn atomic_move_verified_directory_no_replace_checked<F>(
    source: &Path,
    destination: &Path,
    critical_audit: F,
) -> Result<AtomicDirectoryPublishOutcome, AtomicDirectoryPublishError>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    atomic_move_verified_directory_no_replace_checked_with_faults(
        source,
        destination,
        |current| critical_audit(current).map_err(AtomicDirectoryPublishError::io),
        DirectoryMoveFault::None,
    )
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DirectoryMoveFault {
    #[default]
    None,
    BeforeMove,
    AfterMove,
    DirectorySync,
    ParentSync,
}

fn atomic_move_verified_directory_no_replace_checked_with_faults<F>(
    source: &Path,
    destination: &Path,
    critical_audit: F,
    fault: DirectoryMoveFault,
) -> Result<AtomicDirectoryPublishOutcome, AtomicDirectoryPublishError>
where
    F: FnOnce(&Path) -> Result<(), AtomicDirectoryPublishError>,
{
    let paths = VerifiedDirectoryMovePaths::resolve(source, destination)?;
    critical_audit(source)?;
    if !paths.parent_and_source_match() {
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }
    match inspect_directory_state(&paths.destination) {
        Ok(DirectoryState::Absent) => {}
        Ok(DirectoryState::Directory(_) | DirectoryState::Other) => {
            return Err(AtomicDirectoryPublishError::DestinationExists);
        }
        Err(_) => return Err(AtomicDirectoryPublishError::Indeterminate),
    }

    #[cfg(target_os = "linux")]
    let mut move_result = if fault == DirectoryMoveFault::BeforeMove {
        Err(io::Error::other("injected error before directory move"))
    } else {
        platform::namespace_move_no_replace_in_directory(
            &paths.parent_handle,
            &paths.source_name,
            &paths.destination_name,
        )
    };
    #[cfg(not(target_os = "linux"))]
    let mut move_result = if fault == DirectoryMoveFault::BeforeMove {
        Err(io::Error::other("injected error before directory move"))
    } else {
        namespace_move(&paths.source, &paths.destination, false)
    };
    if fault == DirectoryMoveFault::AfterMove && move_result.is_ok() {
        move_result = Err(io::Error::other("injected error after directory move"));
    }

    let source_state = inspect_directory_state(&paths.source);
    let destination_state = inspect_directory_state(&paths.destination);
    let parent_unchanged = paths.parent_matches();
    let held_source_unchanged = paths.held_source_matches();
    let exact_moved = parent_unchanged
        && held_source_unchanged
        && matches!(source_state, Ok(DirectoryState::Absent))
        && matches!(
            destination_state,
            Ok(DirectoryState::Directory(ref identity)) if *identity == paths.source_identity
        );
    if !exact_moved {
        let exact_not_moved = parent_unchanged
            && held_source_unchanged
            && matches!(
                source_state,
                Ok(DirectoryState::Directory(ref identity)) if *identity == paths.source_identity
            )
            && matches!(destination_state, Ok(DirectoryState::Absent));
        if exact_not_moved && move_result.is_err() {
            return Err(AtomicDirectoryPublishError::NotMoved);
        }
        let source_is_exact = matches!(
            source_state,
            Ok(DirectoryState::Directory(ref identity)) if *identity == paths.source_identity
        );
        let destination_is_foreign = !matches!(destination_state, Ok(DirectoryState::Absent))
            && !matches!(
                destination_state,
                Ok(DirectoryState::Directory(ref identity)) if *identity == paths.source_identity
            );
        if parent_unchanged && held_source_unchanged && source_is_exact && destination_is_foreign {
            return Err(AtomicDirectoryPublishError::DestinationExists);
        }
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }

    let directory_synced = fault != DirectoryMoveFault::DirectorySync
        && platform::sync_directory(&paths.destination).is_ok();
    let parent_synced =
        fault != DirectoryMoveFault::ParentSync && sync_namespace_parent(&paths.parent).is_ok();
    if !paths.exact_moved_state() {
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }
    Ok(AtomicDirectoryPublishOutcome {
        parent_sync: if directory_synced && parent_synced {
            ParentSyncStatus::Synced
        } else {
            ParentSyncStatus::NotSynced
        },
    })
}

#[derive(Debug)]
struct VerifiedDirectoryMovePaths {
    source: PathBuf,
    destination: PathBuf,
    parent: PathBuf,
    #[cfg(target_os = "linux")]
    source_name: std::ffi::OsString,
    #[cfg(target_os = "linux")]
    destination_name: std::ffi::OsString,
    parent_identity: FilesystemDirectoryIdentity,
    source_identity: FilesystemDirectoryIdentity,
    #[cfg(target_os = "linux")]
    parent_handle: File,
    #[cfg(target_os = "linux")]
    source_handle: File,
}

impl VerifiedDirectoryMovePaths {
    fn resolve(source: &Path, destination: &Path) -> Result<Self, AtomicDirectoryPublishError> {
        if !source.is_absolute()
            || !destination.is_absolute()
            || source == destination
            || !path_is_lexically_normal(source)
            || !path_is_lexically_normal(destination)
        {
            return Err(AtomicDirectoryPublishError::InvalidPaths);
        }
        let source_parent = source
            .parent()
            .ok_or(AtomicDirectoryPublishError::InvalidPaths)?;
        let destination_parent = destination
            .parent()
            .ok_or(AtomicDirectoryPublishError::InvalidPaths)?;
        let source_name = source
            .file_name()
            .ok_or(AtomicDirectoryPublishError::InvalidPaths)?
            .to_os_string();
        let destination_name = destination
            .file_name()
            .ok_or(AtomicDirectoryPublishError::InvalidPaths)?
            .to_os_string();
        if !path_ancestors_are_non_link_directories(source_parent)
            .map_err(AtomicDirectoryPublishError::io)?
            || !path_ancestors_are_non_link_directories(destination_parent)
                .map_err(AtomicDirectoryPublishError::io)?
        {
            return Err(AtomicDirectoryPublishError::InvalidPaths);
        }
        let source_parent_input_identity = filesystem_directory_identity(source_parent)
            .map_err(AtomicDirectoryPublishError::io)?;
        let destination_parent_input_identity = filesystem_directory_identity(destination_parent)
            .map_err(AtomicDirectoryPublishError::io)?;
        let parent = fs::canonicalize(source_parent).map_err(AtomicDirectoryPublishError::io)?;
        let destination_parent =
            fs::canonicalize(destination_parent).map_err(AtomicDirectoryPublishError::io)?;
        if parent != destination_parent {
            return Err(AtomicDirectoryPublishError::InvalidPaths);
        }
        let parent_identity =
            filesystem_directory_identity(&parent).map_err(AtomicDirectoryPublishError::io)?;
        if source_parent_input_identity != parent_identity
            || destination_parent_input_identity != parent_identity
        {
            return Err(AtomicDirectoryPublishError::InvalidPaths);
        }
        let source = parent.join(&source_name);
        let destination = parent.join(&destination_name);
        if source == destination
            || !path_is_supported_local_filesystem(&parent)
                .map_err(AtomicDirectoryPublishError::io)?
            || !path_is_supported_local_filesystem(&source)
                .map_err(AtomicDirectoryPublishError::io)?
            || !paths_share_mount(&parent, &source).map_err(AtomicDirectoryPublishError::io)?
        {
            return Err(AtomicDirectoryPublishError::InvalidPaths);
        }
        let source_identity =
            match inspect_directory_state(&source).map_err(AtomicDirectoryPublishError::io)? {
                DirectoryState::Directory(identity) => identity,
                DirectoryState::Absent => {
                    return Err(AtomicDirectoryPublishError::io(io::Error::new(
                        io::ErrorKind::NotFound,
                        "verified directory-move source is absent",
                    )));
                }
                DirectoryState::Other => return Err(AtomicDirectoryPublishError::InvalidPaths),
            };
        match inspect_directory_state(&destination).map_err(AtomicDirectoryPublishError::io)? {
            DirectoryState::Absent => {}
            DirectoryState::Directory(_) | DirectoryState::Other => {
                return Err(AtomicDirectoryPublishError::DestinationExists);
            }
        }

        #[cfg(target_os = "linux")]
        let parent_handle = platform::open_source_directory_path(&parent)
            .map_err(AtomicDirectoryPublishError::io)?;
        #[cfg(target_os = "linux")]
        let source_handle = platform::open_source_directory_path(&source)
            .map_err(AtomicDirectoryPublishError::io)?;
        let paths = Self {
            source,
            destination,
            parent,
            #[cfg(target_os = "linux")]
            source_name,
            #[cfg(target_os = "linux")]
            destination_name,
            parent_identity,
            source_identity,
            #[cfg(target_os = "linux")]
            parent_handle,
            #[cfg(target_os = "linux")]
            source_handle,
        };
        if !paths.parent_and_source_match() {
            return Err(AtomicDirectoryPublishError::Indeterminate);
        }
        Ok(paths)
    }

    fn parent_matches(&self) -> bool {
        let path_matches = filesystem_directory_identity(&self.parent)
            .is_ok_and(|identity| identity == self.parent_identity);
        #[cfg(target_os = "linux")]
        let handle_matches = linux_directory_identity_from_file(&self.parent_handle)
            .is_ok_and(|identity| identity == self.parent_identity);
        #[cfg(not(target_os = "linux"))]
        let handle_matches = true;
        path_matches && handle_matches
    }

    fn held_source_matches(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            linux_directory_identity_from_file(&self.source_handle)
                .is_ok_and(|identity| identity == self.source_identity)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.parent_identity.comparison_volume() == self.source_identity.comparison_volume()
        }
    }

    fn parent_and_source_match(&self) -> bool {
        self.parent_matches()
            && self.held_source_matches()
            && filesystem_directory_identity(&self.source)
                .is_ok_and(|identity| identity == self.source_identity)
    }

    fn exact_moved_state(&self) -> bool {
        self.parent_matches()
            && self.held_source_matches()
            && matches!(
                inspect_directory_state(&self.source),
                Ok(DirectoryState::Absent)
            )
            && matches!(
                inspect_directory_state(&self.destination),
                Ok(DirectoryState::Directory(ref identity)) if *identity == self.source_identity
            )
    }
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
    let resolved_staging = resolved_parent.join(staging_name);
    let resolved_destination = resolved_parent.join(destination_name);
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
    let mut marker_options = OpenOptions::new();
    marker_options.write(true).create_new(true);
    permit_namespace_rename(&mut marker_options);
    let mut marker_file = marker_options
        .open(&marker)
        .map_err(AtomicDirectoryPublishError::io)?;
    marker_file
        .write_all(&marker_bytes)
        .and_then(|()| marker_file.sync_all())
        .map_err(AtomicDirectoryPublishError::io)?;
    sync_staging_directory_before_publish(&local)?;
    sync_staging_directory_before_publish(staging)?;

    // Freeze all cooperative Inex mutations from the critical physical audit
    // through namespace publication and post-state reconciliation.
    let _vault_lock = VaultMutationLock::acquire(staging).map_err(|error| match error {
        AtomicWriteError::Io { source, .. } => AtomicDirectoryPublishError::io(source),
        _ => AtomicDirectoryPublishError::Indeterminate,
    })?;
    let import_audit = |current: &Path| {
        critical_audit(staging).map_err(AtomicDirectoryPublishError::io)?;
        if filesystem_directory_identity(&resolved_parent)
            .ok()
            .as_ref()
            != Some(&parent_identity)
            || current != resolved_staging
            || filesystem_directory_identity(current).ok().as_ref() != Some(&staging_identity)
            || filesystem_directory_identity(&local).ok().as_ref() != Some(&local_identity)
            || !marker_matches_open_file(&marker, &marker_file, marker_bytes.len())
            || !publish_handles_match()
        {
            return Err(AtomicDirectoryPublishError::Indeterminate);
        }
        Ok(())
    };
    let move_fault = if skip_move {
        DirectoryMoveFault::BeforeMove
    } else if inject_error_after_move {
        DirectoryMoveFault::AfterMove
    } else {
        DirectoryMoveFault::None
    };
    let directory_move_result = atomic_move_verified_directory_no_replace_checked_with_faults(
        &resolved_staging,
        &resolved_destination,
        import_audit,
        move_fault,
    );
    let exact_import_source = || {
        filesystem_directory_identity(&resolved_parent)
            .is_ok_and(|identity| identity == parent_identity)
            && filesystem_directory_identity(staging)
                .is_ok_and(|identity| identity == staging_identity)
            && filesystem_directory_identity(&local)
                .is_ok_and(|identity| identity == local_identity)
            && marker_matches_open_file(&marker, &marker_file, marker_bytes.len())
            && publish_handles_match()
    };
    match directory_move_result {
        Ok(_) => {}
        Err(error @ AtomicDirectoryPublishError::NotMoved) => {
            if exact_import_source()
                && matches!(
                    inspect_directory_state(destination),
                    Ok(DirectoryState::Absent)
                )
            {
                return Err(error);
            }
            return Err(AtomicDirectoryPublishError::Indeterminate);
        }
        Err(error @ AtomicDirectoryPublishError::DestinationExists) => {
            let destination_state = inspect_directory_state(destination);
            let destination_is_foreign = !matches!(destination_state, Ok(DirectoryState::Absent))
                && !matches!(
                    destination_state,
                    Ok(DirectoryState::Directory(ref identity)) if *identity == staging_identity
                );
            if exact_import_source() && destination_is_foreign {
                return Err(error);
            }
            return Err(AtomicDirectoryPublishError::Indeterminate);
        }
        Err(error) => return Err(error),
    }

    let published_marker = destination
        .join(VAULT_LOCAL_DIRECTORY)
        .join(IMPORT_PUBLISH_MARKER);
    let exact_published_with_marker = || {
        filesystem_directory_identity(&resolved_parent)
            .is_ok_and(|identity| identity == parent_identity)
            && filesystem_directory_identity(destination)
                .is_ok_and(|identity| identity == staging_identity)
            && filesystem_directory_identity(&destination.join(VAULT_LOCAL_DIRECTORY))
                .is_ok_and(|identity| identity == local_identity)
            && marker_matches_open_file(&published_marker, &marker_file, marker_bytes.len())
            && publish_handles_match()
    };
    if !exact_published_with_marker() {
        return Err(AtomicDirectoryPublishError::Indeterminate);
    }
    let marker_cleanup = if inject_marker_cleanup_failure {
        Err(io::Error::other(
            "injected publication-marker cleanup failure",
        ))
    } else {
        fs::remove_file(&published_marker)
    };
    if marker_cleanup.is_err() {
        return Err(if exact_published_with_marker() {
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

fn sync_staging_directory_before_publish(path: &Path) -> Result<(), AtomicDirectoryPublishError> {
    #[cfg(windows)]
    {
        // FlushFileBuffers on a directory is not a Windows namespace-commit
        // guarantee and is unsupported on some valid local filesystems. The
        // marker itself was already synchronized; MoveFileExW with
        // MOVEFILE_WRITE_THROUGH is the required publication barrier.
        let _ = platform::sync_directory(path);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        platform::sync_directory(path).map_err(AtomicDirectoryPublishError::io)
    }
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

    faults
        .check(FaultPoint::BeforeLock)
        .map_err(|source| AtomicWriteError::io(AtomicWriteStage::AcquireLock, source))?;
    let _guard = VaultMutationGuard::acquire_with_faults(vault_root, faults)?;
    let staging_parent = vault_root.join(VAULT_LOCAL_DIRECTORY);
    let (mut staging, new_etag) = stage_and_verify(&staging_parent, ciphertext, faults)?;

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
            |target_parent_sync| AtomicWriteOutcome {
                etag: new_etag,
                parent_sync: combine_parent_sync(
                    target_parent_sync,
                    sync_namespace_parent_status(&staging_parent),
                ),
            },
        );
    }
    staging.disarm();

    let parent_sync = if faults.check(FaultPoint::SyncParent).is_ok()
        && sync_namespace_parent(&staging_parent).is_ok()
        && sync_namespace_parent(parent).is_ok()
    {
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
/// Under one lock, crash-abandoned staging is recovered, the destination
/// envelope is staged and verified, both source and destination conditions are
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
    let staging_parent = vault_root.join(VAULT_LOCAL_DIRECTORY);
    let (mut staging, destination_etag) =
        stage_and_verify(&staging_parent, replacement_envelope, &NoFaults)?;

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
    let Ok(destination_parent_sync) =
        sync_rebind_commit_parents(&staging_parent, destination_parent)
    else {
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
    let guard = VaultMutationGuard::acquire(vault_root)?;
    Ok(RebindRecoveryOutcome {
        changed_repository: guard.recovery_changed_repository(),
    })
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

/// Stable scheme used to project an opaque filesystem identity onto a wire.
///
/// The discriminants are part of the publication-marker wire format and must
/// not be renumbered.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum PublicationIdentityScheme {
    /// Linux `st_dev` plus the normalized `st_ino` identifier.
    LinuxDevInodeV1 = 1,
    /// Windows 64-bit volume serial plus a nonzero `FILE_ID_128`.
    WindowsModernFileId128V1 = 2,
    /// Windows legacy volume serial plus normalized 64-bit file index.
    WindowsLegacyFileIndexV1 = 3,
}

impl PublicationIdentityScheme {
    /// Returns the exact unsigned value encoded in publication marker wires.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }
}

/// Immutable canonical 24-byte projection of one filesystem identity.
///
/// The first eight bytes are the volume in big-endian order and the remaining
/// sixteen bytes are the scheme-specific normalized identifier. The fields
/// are private so callers cannot relabel bytes with a different scheme.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicationIdentityWire {
    scheme: PublicationIdentityScheme,
    bytes: [u8; 24],
}

impl PublicationIdentityWire {
    fn new(scheme: PublicationIdentityScheme, volume: u64, identifier: [u8; 16]) -> Self {
        let mut bytes = [0_u8; 24];
        bytes[..8].copy_from_slice(&volume.to_be_bytes());
        bytes[8..].copy_from_slice(&identifier);
        Self { scheme, bytes }
    }

    /// Returns the explicit provenance of these wire bytes.
    #[must_use]
    pub const fn scheme(&self) -> PublicationIdentityScheme {
        self.scheme
    }

    /// Returns the exact canonical 24-byte wire projection.
    #[must_use]
    pub const fn wire_bytes(&self) -> &[u8; 24] {
        &self.bytes
    }

    fn volume(&self) -> u64 {
        u64::from_be_bytes([
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5],
            self.bytes[6],
            self.bytes[7],
        ])
    }
}

impl fmt::Debug for PublicationIdentityWire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "PublicationIdentityWire {{ scheme: {:?}, bytes: [REDACTED] }}",
            self.scheme
        )
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct FilesystemIdentityProjections {
    primary: PublicationIdentityWire,
}

impl FilesystemIdentityProjections {
    fn single(primary: PublicationIdentityWire) -> Self {
        Self { primary }
    }

    fn get(&self, scheme: PublicationIdentityScheme) -> Option<PublicationIdentityWire> {
        (self.primary.scheme() == scheme).then_some(self.primary)
    }

    fn comparison_volume(&self) -> u64 {
        self.primary.volume()
    }
}

fn normalized_index_identifier(index: u64, discriminator: u8) -> [u8; 16] {
    let mut identifier = [0_u8; 16];
    identifier[..8].copy_from_slice(&index.to_le_bytes());
    identifier[15] = discriminator;
    identifier
}

#[cfg(any(target_os = "linux", test))]
fn linux_identity_projections(
    volume: u64,
    inode: u64,
    discriminator: u8,
) -> FilesystemIdentityProjections {
    FilesystemIdentityProjections::single(PublicationIdentityWire::new(
        PublicationIdentityScheme::LinuxDevInodeV1,
        volume,
        normalized_index_identifier(inode, discriminator),
    ))
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsModernIdentityQueryOutcome {
    // This means the modern API succeeded with an all-zero identifier. API
    // errors are never represented by this variant.
    LegacyOnly,
    Available { volume: u64, identifier: [u8; 16] },
}

#[cfg(any(windows, test))]
fn classify_windows_modern_identity_query(
    query: io::Result<(u64, [u8; 16])>,
) -> io::Result<WindowsModernIdentityQueryOutcome> {
    // No Windows error code is treated as an implicit legacy-only result:
    // without a documented, narrow unsupported outcome, every error remains
    // observable and fails the identity proof closed.
    let (volume, identifier) = query?;
    if identifier.iter().all(|byte| *byte == 0) {
        Ok(WindowsModernIdentityQueryOutcome::LegacyOnly)
    } else {
        Ok(WindowsModernIdentityQueryOutcome::Available { volume, identifier })
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsModernIdentityComparison {
    UseLegacy,
    Resolved(bool),
}

#[cfg(any(windows, test))]
fn compare_windows_modern_identities(
    first: WindowsModernIdentityQueryOutcome,
    second: WindowsModernIdentityQueryOutcome,
    include_volume: bool,
) -> WindowsModernIdentityComparison {
    match (first, second) {
        (
            WindowsModernIdentityQueryOutcome::LegacyOnly,
            WindowsModernIdentityQueryOutcome::LegacyOnly,
        ) => WindowsModernIdentityComparison::UseLegacy,
        (
            WindowsModernIdentityQueryOutcome::Available {
                volume: first_volume,
                identifier: first_identifier,
            },
            WindowsModernIdentityQueryOutcome::Available {
                volume: second_volume,
                identifier: second_identifier,
            },
        ) => WindowsModernIdentityComparison::Resolved(
            first_identifier == second_identifier
                && (!include_volume || first_volume == second_volume),
        ),
        (
            WindowsModernIdentityQueryOutcome::LegacyOnly,
            WindowsModernIdentityQueryOutcome::Available { .. },
        )
        | (
            WindowsModernIdentityQueryOutcome::Available { .. },
            WindowsModernIdentityQueryOutcome::LegacyOnly,
        ) => WindowsModernIdentityComparison::Resolved(false),
    }
}

#[cfg(any(windows, test))]
fn windows_identity_projections(
    legacy_volume: u32,
    legacy_index: u64,
    modern: WindowsModernIdentityQueryOutcome,
    discriminator: u8,
) -> io::Result<FilesystemIdentityProjections> {
    let primary = match modern {
        WindowsModernIdentityQueryOutcome::Available { volume, identifier } => {
            PublicationIdentityWire::new(
                PublicationIdentityScheme::WindowsModernFileId128V1,
                volume,
                identifier,
            )
        }
        WindowsModernIdentityQueryOutcome::LegacyOnly => {
            if legacy_index == 0 {
                return Err(io::Error::other(
                    "legacy Windows filesystem identity is unavailable",
                ));
            }
            PublicationIdentityWire::new(
                PublicationIdentityScheme::WindowsLegacyFileIndexV1,
                u64::from(legacy_volume),
                normalized_index_identifier(legacy_index, discriminator),
            )
        }
    };
    Ok(FilesystemIdentityProjections::single(primary))
}

/// Stable identity of one single-link regular file.
///
/// The fields are deliberately opaque. The value can be retained after a
/// Windows namespace operation forces every open file handle to be closed,
/// then compared with a freshly opened path using
/// [`path_matches_file_identity_and_is_single_link`].
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct FilesystemFileIdentity {
    projections: FilesystemIdentityProjections,
}

impl FilesystemFileIdentity {
    /// Returns this identity's single canonical projection when its captured
    /// primary scheme is exactly `scheme`.
    #[must_use]
    pub fn publication_identity(
        &self,
        scheme: PublicationIdentityScheme,
    ) -> Option<PublicationIdentityWire> {
        self.projections.get(scheme)
    }
}

impl fmt::Debug for FilesystemFileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemFileIdentity")
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

/// Captures the physical identity of one held single-link regular file.
///
/// # Errors
///
/// Returns an I/O error when the handle is not a regular file, has multiple
/// hard links, is a Windows reparse point, or lacks a stable platform file ID.
pub fn filesystem_file_identity(file: &File) -> io::Result<FilesystemFileIdentity> {
    platform::filesystem_file_identity(file)
}

/// Reopens `path` and compares it with one captured physical file identity.
///
/// This function never follows a final symlink/reparse point as an accepted
/// match and requires the current file to have exactly one hard link. Missing
/// paths return their normal `NotFound` I/O error so callers can classify
/// `Absent` separately from `Foreign`.
///
/// # Errors
///
/// Returns an I/O error when the path cannot be inspected or reopened.
pub fn path_matches_file_identity_and_is_single_link(
    path: &Path,
    expected: &FilesystemFileIdentity,
) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_file() {
        return Ok(false);
    }
    let file = File::open(path)?;
    if !open_file_matches_path_and_is_single_link(path, &file)? {
        return Ok(false);
    }
    filesystem_file_identity(&file).map(|identity| identity == *expected)
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

/// Removes the exact single-link regular file identified by `held_file`.
///
/// `path` must be an absolute, lexically normal direct child of a canonical,
/// link-free directory on a supported local filesystem. The parent binding
/// and held file identity are checked when the operation is prepared and
/// again immediately before removal. An errored platform removal is reconciled
/// as either exact removed, exact not removed, or indeterminate; a foreign
/// rebound path is never removed.
///
/// The final namespace operation remains path based. As with the verified
/// move primitives, callers must exclude a non-cooperating process running as
/// the same OS user from rebinding the child name after the final identity
/// check. Post-state reconciliation detects but cannot prevent that race.
/// `held_file` is consumed so Windows can close the handle before the path is
/// deleted; its opaque [`FilesystemFileIdentity`] remains available for the
/// post-state comparison.
///
/// # Errors
///
/// Returns [`AtomicVerifiedRemoveError::InvalidPath`] for an unsafe path or
/// source, [`AtomicVerifiedRemoveError::NotRemoved`] when the exact old file
/// remains after an error, and [`AtomicVerifiedRemoveError::Indeterminate`]
/// when neither the exact old nor absent state can be proved.
pub fn atomic_remove_verified_file(
    path: &Path,
    held_file: File,
) -> Result<AtomicDeleteOutcome, AtomicVerifiedRemoveError> {
    atomic_remove_verified_file_impl(
        path,
        held_file,
        |_| Ok(()),
        |_| Ok(()),
        VerifiedRemoveFault::None,
        true,
    )
}

/// Removes the exact empty directory identified by `expected_identity`.
///
/// The directory must be an absolute, lexically normal direct child of one
/// canonical, link-free parent on a supported local filesystem. Its parent,
/// physical identity, and empty inventory are checked twice before the path-
/// based removal. An errored removal is reconciled without ever deleting a
/// foreign rebound directory.
///
/// The same-user path-race boundary is identical to
/// [`atomic_move_verified_directory_no_replace_checked`]: this is a
/// cooperative-filesystem primitive, not a kernel-level directory CAS.
///
/// # Errors
///
/// Returns [`AtomicVerifiedRemoveError`] when the path is unsafe or nonempty,
/// when the exact old directory remains after an error, or when the physical
/// result is ambiguous.
pub fn atomic_remove_verified_empty_directory(
    path: &Path,
    expected_identity: &FilesystemDirectoryIdentity,
) -> Result<AtomicDeleteOutcome, AtomicVerifiedRemoveError> {
    atomic_remove_verified_empty_directory_impl(
        path,
        expected_identity,
        |_| Ok(()),
        |_| Ok(()),
        VerifiedRemoveFault::None,
    )
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum VerifiedRemoveFault {
    #[default]
    None,
    ErrorBeforeRemove,
    RemoveThenError,
    ParentSync,
}

#[cfg(test)]
fn atomic_remove_verified_file_with_faults<F, G>(
    path: &Path,
    held_file: File,
    before_remove: F,
    after_remove: G,
    fault: VerifiedRemoveFault,
) -> Result<AtomicDeleteOutcome, AtomicVerifiedRemoveError>
where
    F: FnOnce(&Path) -> io::Result<()>,
    G: FnOnce(&Path) -> io::Result<()>,
{
    atomic_remove_verified_file_impl(path, held_file, before_remove, after_remove, fault, true)
}

fn atomic_remove_verified_file_impl<F, G>(
    path: &Path,
    held_file: File,
    before_remove: F,
    after_remove: G,
    fault: VerifiedRemoveFault,
    sync_parent_by_path: bool,
) -> Result<AtomicDeleteOutcome, AtomicVerifiedRemoveError>
where
    F: FnOnce(&Path) -> io::Result<()>,
    G: FnOnce(&Path) -> io::Result<()>,
{
    let verified = VerifiedRemovePath::resolve(path)?;
    verified.verify_file(&held_file)?;
    let expected_identity =
        filesystem_file_identity(&held_file).map_err(AtomicVerifiedRemoveError::initial)?;
    before_remove(&verified.path).map_err(AtomicVerifiedRemoveError::io)?;
    if !verified.parent_matches() || !verified.file_matches(&held_file) {
        return Err(AtomicVerifiedRemoveError::Indeterminate);
    }
    drop(held_file);

    let mut remove_result = if fault == VerifiedRemoveFault::ErrorBeforeRemove {
        Err(io::Error::other(
            "injected error before verified file removal",
        ))
    } else {
        fs::remove_file(&verified.path)
    };
    if fault == VerifiedRemoveFault::RemoveThenError && remove_result.is_ok() {
        remove_result = Err(io::Error::other(
            "injected error after verified file removal",
        ));
    }
    after_remove(&verified.path).map_err(AtomicVerifiedRemoveError::io)?;

    match verified.file_state(&expected_identity) {
        VerifiedRemoveState::Absent if verified.parent_matches() => Ok(AtomicDeleteOutcome {
            parent_sync: verified.parent_sync(fault, sync_parent_by_path),
        }),
        VerifiedRemoveState::Exact if verified.parent_matches() && remove_result.is_err() => {
            Err(AtomicVerifiedRemoveError::NotRemoved)
        }
        VerifiedRemoveState::Absent | VerifiedRemoveState::Exact | VerifiedRemoveState::Foreign => {
            Err(AtomicVerifiedRemoveError::Indeterminate)
        }
    }
}

#[cfg(test)]
fn atomic_remove_verified_empty_directory_with_faults<F, G>(
    path: &Path,
    expected_identity: &FilesystemDirectoryIdentity,
    before_remove: F,
    after_remove: G,
    fault: VerifiedRemoveFault,
) -> Result<AtomicDeleteOutcome, AtomicVerifiedRemoveError>
where
    F: FnOnce(&Path) -> io::Result<()>,
    G: FnOnce(&Path) -> io::Result<()>,
{
    atomic_remove_verified_empty_directory_impl(
        path,
        expected_identity,
        before_remove,
        after_remove,
        fault,
    )
}

fn atomic_remove_verified_empty_directory_impl<F, G>(
    path: &Path,
    expected_identity: &FilesystemDirectoryIdentity,
    before_remove: F,
    after_remove: G,
    fault: VerifiedRemoveFault,
) -> Result<AtomicDeleteOutcome, AtomicVerifiedRemoveError>
where
    F: FnOnce(&Path) -> io::Result<()>,
    G: FnOnce(&Path) -> io::Result<()>,
{
    let verified = VerifiedRemovePath::resolve(path)?;
    verified.verify_empty_directory(expected_identity)?;
    before_remove(&verified.path).map_err(AtomicVerifiedRemoveError::io)?;
    if !verified.parent_matches()
        || !verified.directory_matches(expected_identity)
        || !verified.directory_is_empty()
    {
        return Err(AtomicVerifiedRemoveError::Indeterminate);
    }

    let mut remove_result = if fault == VerifiedRemoveFault::ErrorBeforeRemove {
        Err(io::Error::other(
            "injected error before verified directory removal",
        ))
    } else {
        fs::remove_dir(&verified.path)
    };
    if fault == VerifiedRemoveFault::RemoveThenError && remove_result.is_ok() {
        remove_result = Err(io::Error::other(
            "injected error after verified directory removal",
        ));
    }
    after_remove(&verified.path).map_err(AtomicVerifiedRemoveError::io)?;

    match verified.directory_state(expected_identity) {
        VerifiedRemoveState::Absent if verified.parent_matches() => Ok(AtomicDeleteOutcome {
            parent_sync: verified.parent_sync(fault, true),
        }),
        VerifiedRemoveState::Exact if verified.parent_matches() && remove_result.is_err() => {
            Err(AtomicVerifiedRemoveError::NotRemoved)
        }
        VerifiedRemoveState::Absent | VerifiedRemoveState::Exact | VerifiedRemoveState::Foreign => {
            Err(AtomicVerifiedRemoveError::Indeterminate)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifiedRemoveState {
    Absent,
    Exact,
    Foreign,
}

#[derive(Debug)]
struct VerifiedRemovePath {
    path: PathBuf,
    parent: PathBuf,
    parent_identity: FilesystemDirectoryIdentity,
}

impl VerifiedRemovePath {
    fn resolve(path: &Path) -> Result<Self, AtomicVerifiedRemoveError> {
        if !path.is_absolute() || !path_is_lexically_normal(path) || path.file_name().is_none() {
            return Err(AtomicVerifiedRemoveError::InvalidPath);
        }
        let parent = path
            .parent()
            .ok_or(AtomicVerifiedRemoveError::InvalidPath)?;
        if !path_ancestors_are_non_link_directories(parent)
            .map_err(AtomicVerifiedRemoveError::initial)?
        {
            return Err(AtomicVerifiedRemoveError::InvalidPath);
        }
        let input_parent_identity =
            filesystem_directory_identity(parent).map_err(AtomicVerifiedRemoveError::initial)?;
        let parent = fs::canonicalize(parent).map_err(AtomicVerifiedRemoveError::initial)?;
        let parent_identity =
            filesystem_directory_identity(&parent).map_err(AtomicVerifiedRemoveError::initial)?;
        let path = parent.join(
            path.file_name()
                .ok_or(AtomicVerifiedRemoveError::InvalidPath)?,
        );
        if input_parent_identity != parent_identity
            || !path_is_supported_local_filesystem(&parent)
                .map_err(AtomicVerifiedRemoveError::initial)?
            || !path_is_supported_local_filesystem(&path)
                .map_err(AtomicVerifiedRemoveError::initial)?
            || !paths_share_mount(&parent, &path).map_err(AtomicVerifiedRemoveError::initial)?
        {
            return Err(AtomicVerifiedRemoveError::InvalidPath);
        }
        let verified = Self {
            path,
            parent,
            parent_identity,
        };
        if !verified.parent_matches() {
            return Err(AtomicVerifiedRemoveError::InvalidPath);
        }
        Ok(verified)
    }

    fn parent_matches(&self) -> bool {
        filesystem_directory_identity(&self.parent)
            .is_ok_and(|identity| identity == self.parent_identity)
    }

    fn verify_file(&self, held_file: &File) -> Result<(), AtomicVerifiedRemoveError> {
        if self.file_matches(held_file) {
            Ok(())
        } else {
            Err(AtomicVerifiedRemoveError::InvalidPath)
        }
    }

    fn file_matches(&self, held_file: &File) -> bool {
        open_file_matches_path_and_is_single_link(&self.path, held_file).unwrap_or(false)
            && paths_share_mount(&self.parent, &self.path).unwrap_or(false)
    }

    fn file_state(&self, expected_identity: &FilesystemFileIdentity) -> VerifiedRemoveState {
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => VerifiedRemoveState::Absent,
            Ok(_)
                if path_matches_file_identity_and_is_single_link(&self.path, expected_identity)
                    .unwrap_or(false) =>
            {
                VerifiedRemoveState::Exact
            }
            Ok(_) | Err(_) => VerifiedRemoveState::Foreign,
        }
    }

    fn verify_empty_directory(
        &self,
        expected_identity: &FilesystemDirectoryIdentity,
    ) -> Result<(), AtomicVerifiedRemoveError> {
        if self.directory_matches(expected_identity) && self.directory_is_empty() {
            Ok(())
        } else {
            Err(AtomicVerifiedRemoveError::InvalidPath)
        }
    }

    fn directory_matches(&self, expected_identity: &FilesystemDirectoryIdentity) -> bool {
        filesystem_directory_identity(&self.path)
            .is_ok_and(|identity| identity == *expected_identity)
            && paths_share_mount(&self.parent, &self.path).unwrap_or(false)
    }

    fn directory_is_empty(&self) -> bool {
        fs::read_dir(&self.path).is_ok_and(|mut entries| entries.next().is_none())
    }

    fn directory_state(
        &self,
        expected_identity: &FilesystemDirectoryIdentity,
    ) -> VerifiedRemoveState {
        match inspect_directory_state(&self.path) {
            Ok(DirectoryState::Absent) => VerifiedRemoveState::Absent,
            Ok(DirectoryState::Directory(identity)) if identity == *expected_identity => {
                VerifiedRemoveState::Exact
            }
            Ok(DirectoryState::Directory(_) | DirectoryState::Other) | Err(_) => {
                VerifiedRemoveState::Foreign
            }
        }
    }

    fn parent_sync(
        &self,
        fault: VerifiedRemoveFault,
        sync_parent_by_path: bool,
    ) -> ParentSyncStatus {
        if !sync_parent_by_path || fault == VerifiedRemoveFault::ParentSync {
            ParentSyncStatus::NotSynced
        } else if platform::sync_directory(&self.parent).is_ok() {
            ParentSyncStatus::Synced
        } else {
            ParentSyncStatus::NotSynced
        }
    }
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
            || source_parent_identity.comparison_volume()
                != destination_parent_identity.comparison_volume()
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
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct FilesystemDirectoryIdentity {
    projections: FilesystemIdentityProjections,
}

impl FilesystemDirectoryIdentity {
    /// Returns this identity's single canonical projection when its captured
    /// primary scheme is exactly `scheme`.
    #[must_use]
    pub fn publication_identity(
        &self,
        scheme: PublicationIdentityScheme,
    ) -> Option<PublicationIdentityWire> {
        self.projections.get(scheme)
    }

    fn comparison_volume(&self) -> u64 {
        self.projections.comparison_volume()
    }
}

impl fmt::Debug for FilesystemDirectoryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemDirectoryIdentity")
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod publication_identity_tests {
    use std::cmp::Ordering;
    use std::io;

    use super::{
        FilesystemDirectoryIdentity, FilesystemFileIdentity, PublicationIdentityScheme,
        WindowsModernIdentityComparison, WindowsModernIdentityQueryOutcome,
        classify_windows_modern_identity_query, compare_windows_modern_identities,
        linux_identity_projections, windows_identity_projections,
    };

    const VOLUME: u64 = 0x0102_0304_0506_0708;
    const INDEX: u64 = 0x1112_1314_1516_1718;

    #[test]
    fn publication_scheme_wire_values_are_frozen() {
        assert_eq!(PublicationIdentityScheme::LinuxDevInodeV1.wire_value(), 1);
        assert_eq!(
            PublicationIdentityScheme::WindowsModernFileId128V1.wire_value(),
            2
        );
        assert_eq!(
            PublicationIdentityScheme::WindowsLegacyFileIndexV1.wire_value(),
            3
        );
    }

    #[test]
    fn linux_directory_and_file_projections_match_the_exact_wire() {
        let directory = FilesystemDirectoryIdentity {
            projections: linux_identity_projections(VOLUME, INDEX, 1),
        };
        let file = FilesystemFileIdentity {
            projections: linux_identity_projections(VOLUME, INDEX, 2),
        };
        let expected_directory = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
            0x12, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let mut expected_file = expected_directory;
        expected_file[23] = 2;

        let Some(directory_wire) =
            directory.publication_identity(PublicationIdentityScheme::LinuxDevInodeV1)
        else {
            panic!("Linux directory projection is missing");
        };
        let Some(file_wire) = file.publication_identity(PublicationIdentityScheme::LinuxDevInodeV1)
        else {
            panic!("Linux file projection is missing");
        };
        assert_eq!(directory_wire.wire_bytes(), &expected_directory);
        assert_eq!(file_wire.wire_bytes(), &expected_file);
        assert_eq!(
            directory.publication_identity(PublicationIdentityScheme::WindowsLegacyFileIndexV1),
            None
        );
    }

    #[test]
    fn windows_legacy_projection_matches_the_exact_wire() {
        let file = FilesystemFileIdentity {
            projections: windows_identity_projections(
                0x0102_0304,
                INDEX,
                WindowsModernIdentityQueryOutcome::LegacyOnly,
                2,
            )
            .expect("nonzero legacy identity must project"),
        };
        let expected = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
            0x12, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let Some(wire) =
            file.publication_identity(PublicationIdentityScheme::WindowsLegacyFileIndexV1)
        else {
            panic!("Windows legacy projection is missing");
        };
        assert_eq!(wire.wire_bytes(), &expected);
        assert_eq!(
            file.publication_identity(PublicationIdentityScheme::WindowsModernFileId128V1),
            None
        );
    }

    #[test]
    fn windows_modern_capture_is_exact_and_cannot_be_relabelled_legacy() {
        let modern_identifier = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ];
        let directory = FilesystemDirectoryIdentity {
            projections: windows_identity_projections(
                0x0102_0304,
                INDEX,
                WindowsModernIdentityQueryOutcome::Available {
                    volume: VOLUME,
                    identifier: modern_identifier,
                },
                1,
            )
            .expect("nonzero modern identity must project"),
        };
        let expected_modern = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
            0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        ];
        let Some(modern) =
            directory.publication_identity(PublicationIdentityScheme::WindowsModernFileId128V1)
        else {
            panic!("Windows modern projection is missing");
        };
        assert_eq!(modern.wire_bytes(), &expected_modern);
        assert_eq!(
            directory.publication_identity(PublicationIdentityScheme::WindowsLegacyFileIndexV1),
            None
        );
    }

    #[test]
    fn zero_modern_identity_is_legacy_only_and_availability_drift_is_unequal() {
        let legacy_only = FilesystemFileIdentity {
            projections: windows_identity_projections(
                7,
                10,
                WindowsModernIdentityQueryOutcome::LegacyOnly,
                2,
            )
            .expect("nonzero legacy identity must project"),
        };
        let zero_modern = FilesystemFileIdentity {
            projections: windows_identity_projections(
                7,
                10,
                classify_windows_modern_identity_query(Ok((91, [0; 16])))
                    .expect("an all-zero successful modern query must classify"),
                2,
            )
            .expect("nonzero legacy identity must project"),
        };
        let modern_available = FilesystemFileIdentity {
            projections: windows_identity_projections(
                7,
                10,
                WindowsModernIdentityQueryOutcome::Available {
                    volume: 91,
                    identifier: [0xa5; 16],
                },
                2,
            )
            .expect("nonzero modern identity must project"),
        };

        assert_eq!(legacy_only, zero_modern);
        assert_ne!(legacy_only, modern_available);
        assert_eq!(
            zero_modern.publication_identity(PublicationIdentityScheme::WindowsModernFileId128V1),
            None
        );
    }

    #[test]
    fn modern_query_propagates_errors_and_legacy_path_requires_two_zero_outcomes() {
        let arbitrary_error = classify_windows_modern_identity_query(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic query failure",
        )))
        .expect_err("an arbitrary modern-query error must not become legacy-only");
        assert_eq!(arbitrary_error.kind(), io::ErrorKind::PermissionDenied);

        let legacy_only = WindowsModernIdentityQueryOutcome::LegacyOnly;
        let modern = WindowsModernIdentityQueryOutcome::Available {
            volume: 7,
            identifier: [0x5a; 16],
        };
        assert_eq!(
            compare_windows_modern_identities(legacy_only, legacy_only, true),
            WindowsModernIdentityComparison::UseLegacy
        );
        assert_eq!(
            compare_windows_modern_identities(legacy_only, modern, true),
            WindowsModernIdentityComparison::Resolved(false)
        );
        let same_identifier_other_volume = WindowsModernIdentityQueryOutcome::Available {
            volume: 8,
            identifier: [0x5a; 16],
        };
        assert_eq!(
            compare_windows_modern_identities(modern, same_identifier_other_volume, true),
            WindowsModernIdentityComparison::Resolved(false)
        );
        assert_eq!(
            compare_windows_modern_identities(modern, same_identifier_other_volume, false),
            WindowsModernIdentityComparison::Resolved(true)
        );
    }

    #[test]
    fn modern_projection_ignores_zero_legacy_index_and_has_one_scheme() {
        let modern = WindowsModernIdentityQueryOutcome::Available {
            volume: 91,
            identifier: [0xa5; 16],
        };
        let first = FilesystemFileIdentity {
            projections: windows_identity_projections(7, 0, modern, 2)
                .expect("modern identity must not require a legacy index"),
        };
        let second = FilesystemFileIdentity {
            projections: windows_identity_projections(8, 11, modern, 2)
                .expect("modern identity must ignore legacy identity fields"),
        };

        assert_eq!(first, second);
        assert_eq!(first.cmp(&second), Ordering::Equal);
        assert_eq!(
            first.publication_identity(PublicationIdentityScheme::WindowsLegacyFileIndexV1),
            None
        );
        assert_eq!(
            second.publication_identity(PublicationIdentityScheme::WindowsLegacyFileIndexV1),
            None
        );
    }

    #[test]
    fn legacy_only_projection_rejects_zero_legacy_index() {
        assert!(
            windows_identity_projections(7, 0, WindowsModernIdentityQueryOutcome::LegacyOnly, 2,)
                .is_err()
        );
    }

    #[test]
    fn filesystem_and_wire_debug_output_redacts_identity_bytes() {
        let identity = FilesystemFileIdentity {
            projections: linux_identity_projections(VOLUME, INDEX, 2),
        };
        let Some(wire) = identity.publication_identity(PublicationIdentityScheme::LinuxDevInodeV1)
        else {
            panic!("Linux file projection is missing");
        };

        assert_eq!(
            format!("{wire:?}"),
            "PublicationIdentityWire { scheme: LinuxDevInodeV1, bytes: [REDACTED] }"
        );
        assert_eq!(
            format!("{identity:?}"),
            "FilesystemFileIdentity { identity: \"[REDACTED]\" }"
        );
        assert!(!format!("{wire:?}").contains("0102030405060708"));
    }
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

/// Proves that one held regular file has no Windows alternate data streams.
///
/// The path must name the exact single-link, non-reparse regular file held by
/// `file` before and after the stream query. Linux has no NTFS-style named data
/// streams, so it performs only those common path/identity checks. Windows
/// queries `FileStreamInfo` on the held handle and accepts only the sole
/// unnamed/default stream. Other platforms fail closed as unsupported.
///
/// # Errors
///
/// Returns an I/O error if the path or handle is unsafe, their identity drifts,
/// the platform cannot enumerate streams reliably, the returned stream chain
/// is malformed, or any named/duplicate stream is present.
pub fn verify_regular_file_has_no_alternate_data_streams(
    path: &Path,
    file: &File,
) -> io::Result<()> {
    if !open_file_matches_path_and_is_single_link(path, file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "alternate-stream proof requires the held single-link regular file",
        ));
    }
    platform::verify_regular_file_has_no_alternate_data_streams(file)?;
    if !open_file_matches_path_and_is_single_link(path, file)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "alternate-stream proof lost the held file binding",
        ));
    }
    Ok(())
}

/// Proves that one identity-bound directory has no Windows data streams.
///
/// Windows opens the final directory without following a reparse point,
/// compares that handle with `expected_identity`, and queries `FileStreamInfo`
/// on the same handle. The path identity is checked again after the query.
/// Linux performs the common identity checks and otherwise succeeds because
/// it has no NTFS-style named streams. Other platforms fail closed.
///
/// # Errors
///
/// Returns an I/O error if the path is unsafe or drifts, a handle cannot be
/// identity-bound, stream enumeration is unavailable or malformed, or any
/// directory data stream is present.
pub fn verify_directory_has_no_alternate_data_streams(
    path: &Path,
    expected_identity: &FilesystemDirectoryIdentity,
) -> io::Result<()> {
    if filesystem_directory_identity(path)? != *expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "alternate-stream proof requires the expected directory identity",
        ));
    }
    platform::verify_directory_has_no_alternate_data_streams(path, expected_identity)?;
    if filesystem_directory_identity(path)? != *expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "alternate-stream proof lost the directory binding",
        ));
    }
    Ok(())
}

#[cfg(any(test, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsStreamObjectKind {
    RegularFile,
    Directory,
}

#[cfg(any(test, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsStreamQueryFailure {
    NoStreams,
    InventoryTooLarge,
    Other,
}

#[cfg(any(test, windows))]
fn classify_windows_stream_query_failure(raw_os_error: Option<i32>) -> WindowsStreamQueryFailure {
    match raw_os_error {
        Some(38) => WindowsStreamQueryFailure::NoStreams,
        Some(122 | 234) => WindowsStreamQueryFailure::InventoryTooLarge,
        Some(_) | None => WindowsStreamQueryFailure::Other,
    }
}

#[cfg(any(test, windows))]
fn windows_stream_info_has_no_alternate_data_streams(
    buffer: &[u8],
    object_kind: WindowsStreamObjectKind,
) -> io::Result<bool> {
    const HEADER_BYTES: usize = 24;
    const UNNAMED_DATA_STREAM_UTF16_LE: &[u8] = b":\0:\0$\0D\0A\0T\0A\0";

    let mut offset = 0_usize;
    let mut entry_count = 0_usize;
    loop {
        let header_end = offset
            .checked_add(HEADER_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stream offset overflow"))?;
        if header_end > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream header exceeds the query buffer",
            ));
        }
        let next_offset = u32::from_le_bytes(
            buffer[offset..offset + 4]
                .try_into()
                .map_err(|_| io::Error::other("stream offset slice is invalid"))?,
        );
        let name_length = usize::try_from(u32::from_le_bytes(
            buffer[offset + 4..offset + 8]
                .try_into()
                .map_err(|_| io::Error::other("stream length slice is invalid"))?,
        ))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stream name is too long"))?;
        if name_length % 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream name is not complete UTF-16",
            ));
        }
        let name_end = header_end.checked_add(name_length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "stream name length overflow")
        })?;
        let entry_end = if next_offset == 0 {
            buffer.len()
        } else {
            let next_offset = usize::try_from(next_offset).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "stream next offset overflow")
            })?;
            if next_offset % 8 != 0 || next_offset < HEADER_BYTES.saturating_add(name_length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream next offset is not aligned or forward",
                ));
            }
            offset.checked_add(next_offset).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "stream chain offset overflow")
            })?
        };
        if name_end > entry_end || entry_end > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream entry exceeds the query buffer",
            ));
        }

        entry_count = entry_count.saturating_add(1);
        let name = &buffer[header_end..name_end];
        let unnamed = name.is_empty() || name == UNNAMED_DATA_STREAM_UTF16_LE;
        if object_kind == WindowsStreamObjectKind::Directory || !unnamed || entry_count != 1 {
            return Ok(false);
        }
        if next_offset == 0 {
            return Ok(true);
        }
        offset = entry_end;
    }
}

#[cfg(test)]
mod windows_stream_info_tests {
    use std::io;

    use super::{
        WindowsStreamObjectKind, WindowsStreamQueryFailure, classify_windows_stream_query_failure,
        windows_stream_info_has_no_alternate_data_streams,
    };

    #[test]
    fn query_failures_accept_only_eof_and_bound_inventory_growth() {
        assert_eq!(
            classify_windows_stream_query_failure(Some(38)),
            WindowsStreamQueryFailure::NoStreams,
        );
        for raw_error in [122, 234] {
            assert_eq!(
                classify_windows_stream_query_failure(Some(raw_error)),
                WindowsStreamQueryFailure::InventoryTooLarge,
            );
        }
        for raw_error in [None, Some(1), Some(5), Some(87)] {
            assert_eq!(
                classify_windows_stream_query_failure(raw_error),
                WindowsStreamQueryFailure::Other,
            );
        }
    }

    #[test]
    fn regular_file_accepts_only_one_default_stream() -> io::Result<()> {
        assert!(parse(&chain(&[""]))?);
        assert!(parse(&chain(&["::$DATA"]))?);
        assert!(!parse(&chain(&[":named:$DATA"]))?);
        assert!(!parse(&chain(&[":$DATA:$DATA"]))?);
        assert!(!parse(&chain(&["::$DATA", ":named:$DATA"]))?);
        assert!(!parse(&chain(&["::$DATA", "::$DATA"]))?);
        Ok(())
    }

    #[test]
    fn directory_rejects_every_returned_data_stream_entry() -> io::Result<()> {
        for name in ["", "::$DATA", ":named:$DATA"] {
            assert!(!windows_stream_info_has_no_alternate_data_streams(
                &chain(&[name]),
                WindowsStreamObjectKind::Directory,
            )?);
        }
        Ok(())
    }

    #[test]
    fn malformed_stream_chains_fail_closed() {
        assert_invalid_data(&[0_u8; 23]);

        let mut odd_name = vec![0_u8; 25];
        odd_name[4..8].copy_from_slice(&1_u32.to_le_bytes());
        assert_invalid_data(&odd_name);

        let mut unaligned_next = vec![0_u8; 32];
        unaligned_next[..4].copy_from_slice(&25_u32.to_le_bytes());
        assert_invalid_data(&unaligned_next);

        let mut short_next = vec![0_u8; 32];
        short_next[..4].copy_from_slice(&16_u32.to_le_bytes());
        assert_invalid_data(&short_next);

        let mut next_beyond_buffer = vec![0_u8; 31];
        next_beyond_buffer[..4].copy_from_slice(&32_u32.to_le_bytes());
        assert_invalid_data(&next_beyond_buffer);

        let mut name_beyond_entry = vec![0_u8; 32];
        name_beyond_entry[..4].copy_from_slice(&32_u32.to_le_bytes());
        name_beyond_entry[4..8].copy_from_slice(&10_u32.to_le_bytes());
        assert_invalid_data(&name_beyond_entry);
    }

    fn parse(buffer: &[u8]) -> io::Result<bool> {
        windows_stream_info_has_no_alternate_data_streams(
            buffer,
            WindowsStreamObjectKind::RegularFile,
        )
    }

    fn assert_invalid_data(buffer: &[u8]) {
        let error = parse(buffer).expect_err("a malformed stream chain must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    fn chain(names: &[&str]) -> Vec<u8> {
        assert!(!names.is_empty());
        let mut buffer = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let encoded_name = name
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            let minimum_bytes = 24 + encoded_name.len();
            let entry_bytes = if index + 1 == names.len() {
                minimum_bytes
            } else {
                minimum_bytes.next_multiple_of(8)
            };
            let next_offset = if index + 1 == names.len() {
                0
            } else {
                u32::try_from(entry_bytes).unwrap_or(u32::MAX)
            };
            let name_length = u32::try_from(encoded_name.len()).unwrap_or(u32::MAX);
            let start = buffer.len();
            buffer.resize(start + entry_bytes, 0);
            buffer[start..start + 4].copy_from_slice(&next_offset.to_le_bytes());
            buffer[start + 4..start + 8].copy_from_slice(&name_length.to_le_bytes());
            buffer[start + 24..start + minimum_bytes].copy_from_slice(&encoded_name);
        }
        buffer
    }
}

/// A Linux directory handle used for source import traversal without resolving
/// intermediate components through mutable path strings.
#[cfg(target_os = "linux")]
pub struct SecureSourceDirectory {
    file: File,
    identity: FilesystemDirectoryIdentity,
    binding: SecureSourceDirectoryBinding,
}

#[cfg(target_os = "linux")]
enum SecureSourceDirectoryBinding {
    Root(PathBuf),
    Child {
        parent: File,
        name: std::ffi::OsString,
    },
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
        identity,
        binding: SecureSourceDirectoryBinding::Root(path.to_path_buf()),
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
                identity,
                binding: SecureSourceDirectoryBinding::Child {
                    parent: self.file.try_clone()?,
                    name: name.to_os_string(),
                },
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
        let current = match &self.binding {
            SecureSourceDirectoryBinding::Root(path) => platform::open_source_directory_path(path)?,
            SecureSourceDirectoryBinding::Child { parent, name } => {
                platform::open_source_child(parent, name)?
            }
        };
        if !current.metadata()?.file_type().is_dir()
            || linux_directory_identity_from_file(&current)? != self.identity
        {
            return Err(io::Error::other("source directory binding changed"));
        }
        Ok(())
    }

    /// Verify directory stream state through this held descriptor.
    ///
    /// The original root/parent-relative binding is checked before and after
    /// the handle-only platform query. No descendant path is reconstructed.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the binding drifts, the handle is no longer a
    /// directory, or platform stream verification fails.
    pub fn verify_no_alternate_data_streams(&self) -> io::Result<()> {
        self.verify_binding()?;
        platform::verify_directory_handle_has_no_alternate_data_streams(&self.file)?;
        self.verify_binding()
    }

    /// Return the captured opaque directory identity.
    #[must_use]
    pub fn identity(&self) -> &FilesystemDirectoryIdentity {
        &self.identity
    }
}

#[cfg(target_os = "linux")]
impl SecureSourceFile {
    /// Return the stable opaque identity of this held single-link file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the descriptor no longer names a regular
    /// single-link file or its identity cannot be queried.
    pub fn identity(&self) -> io::Result<FilesystemFileIdentity> {
        filesystem_file_identity(&self.file)
    }

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

    /// Verify alternate-stream state on this held single-link file.
    ///
    /// Both namespace checks use the parent descriptor and exact child name;
    /// the stream query uses only the already-open file handle. A replacement
    /// symlink, FIFO, or device is therefore rejected without a pathname open.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the binding drifts or handle-only stream
    /// verification fails.
    pub fn verify_no_alternate_data_streams(&self) -> io::Result<()> {
        self.verify_binding()?;
        platform::verify_regular_file_has_no_alternate_data_streams(&self.file)?;
        self.verify_binding()
    }
}

#[cfg(target_os = "linux")]
impl Read for SecureSourceFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeldReservedPublicationInventory {
    Absent,
    ExactV2,
    Conflict,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishedDurabilitySyncPoint {
    Root,
    CommonParent,
}

#[cfg(target_os = "linux")]
impl HeldPublicationMarkerV2 {
    fn create(
        staging_root_path: &Path,
        held_root: SecureSourceDirectory,
        mutation_lock: ExistingVaultMutationLock,
        input: HeldPublicationMarkerV2CreateInput<'_>,
    ) -> Result<Self, HeldPublicationMarkerV2Error> {
        let (common_parent, root, marker_parent, current_child_name) =
            prepare_held_publication_directories(staging_root_path, held_root, &mutation_lock)?;
        if current_child_name != input.staging_child_name
            || common_parent.identity() != input.common_parent_identity
        {
            return Err(HeldPublicationMarkerV2Error::InvalidInput);
        }
        PublicationMarkerV2::validate_creation_fields(PublicationMarkerV2PreflightInput {
            scheme: input.scheme,
            publication_id: input.publication_id,
            common_parent_identity: input.common_parent_identity,
            staging_root_identity: root.identity(),
            marker_parent_identity: marker_parent.identity(),
            domain: input.domain,
            staging_child_name: input.staging_child_name,
            destination_child_name: input.destination_child_name,
            candidate_seal: input.candidate_seal,
        })
        .map_err(|_| HeldPublicationMarkerV2Error::InvalidInput)?;
        require_pre_marker_creation_state(
            staging_root_path,
            &common_parent,
            &root,
            &marker_parent,
            &mutation_lock,
            input.destination_child_name,
        )?;

        let mut marker_file = create_secure_publication_marker(&marker_parent)
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        let marker_file_identity = marker_file
            .identity()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        if marker_file_identity.projections.comparison_volume()
            != marker_parent.identity().comparison_volume()
        {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
        let marker = PublicationMarkerV2::new(PublicationMarkerV2Input {
            scheme: input.scheme,
            publication_id: input.publication_id,
            common_parent_identity: input.common_parent_identity,
            staging_root_identity: root.identity(),
            marker_parent_identity: marker_parent.identity(),
            marker_file_identity: &marker_file_identity,
            domain: input.domain,
            staging_child_name: input.staging_child_name,
            destination_child_name: input.destination_child_name,
            candidate_seal: input.candidate_seal,
        })
        .map_err(|_| HeldPublicationMarkerV2Error::AuthorityChanged)?;
        let canonical = marker.to_bytes();

        marker_file
            .file
            .write_all(&canonical)
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        marker_file
            .file
            .flush()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        marker_file
            .file
            .sync_all()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        let observed =
            read_canonical_held_publication_marker(&mut marker_file, &marker_file_identity)?;
        if observed != marker
            || marker_file
                .observed_len()
                .map_err(HeldPublicationMarkerV2Error::Io)?
                != u64::try_from(canonical.len()).unwrap_or(u64::MAX)
        {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }

        marker_parent
            .verify_binding()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        platform::sync_directory_handle(&marker_parent.file)
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        marker_parent
            .verify_binding()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        root.verify_binding()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        platform::sync_directory_handle(&root.file).map_err(HeldPublicationMarkerV2Error::Io)?;
        root.verify_binding()
            .map_err(HeldPublicationMarkerV2Error::Io)?;

        let held = Self {
            marker_file,
            authority: PublicationMarkerV2Authority {
                marker,
                marker_file_identity,
                common_parent,
                root,
                marker_parent,
                mutation_lock,
            },
        };
        held.revalidate_at(staging_root_path)?;
        Ok(held)
    }

    fn open_existing(
        current_root_path: &Path,
        held_root: SecureSourceDirectory,
        mutation_lock: ExistingVaultMutationLock,
    ) -> Result<Self, HeldPublicationMarkerV2Error> {
        let (common_parent, root, marker_parent, _) =
            prepare_held_publication_directories(current_root_path, held_root, &mutation_lock)?;
        require_held_reserved_inventory(&marker_parent, HeldReservedPublicationInventory::ExactV2)?;
        revalidate_pre_marker_authority(
            current_root_path,
            &common_parent,
            &root,
            &marker_parent,
            &mutation_lock,
        )?;

        let mut marker_file = match marker_parent
            .open_child(std::ffi::OsStr::new(IMPORT_PUBLISH_MARKER_V2))
            .map_err(HeldPublicationMarkerV2Error::Io)?
        {
            SecureSourceChild::File(file) => file,
            SecureSourceChild::Directory(_) | SecureSourceChild::Other => {
                return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
            }
        };
        let marker_file_identity = marker_file
            .identity()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        if marker_file_identity.projections.comparison_volume()
            != marker_parent.identity().comparison_volume()
        {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
        let marker =
            read_canonical_held_publication_marker(&mut marker_file, &marker_file_identity)?;
        let held = Self {
            marker_file,
            authority: PublicationMarkerV2Authority {
                marker,
                marker_file_identity,
                common_parent,
                root,
                marker_parent,
                mutation_lock,
            },
        };
        held.revalidate_at(current_root_path)?;
        Ok(held)
    }

    /// Revalidate the same held lock, directories, marker identity, canonical
    /// body, and complete reserved-prefix inventory at `current_root`.
    ///
    /// `current_root` may use either the marker's staging child name or its
    /// destination child name, allowing the owner to remain valid across one
    /// caller-managed whole-root move. This method performs no write, sync,
    /// cleanup, move, or recovery action.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed error if any held or current binding, marker role,
    /// body byte, hard-link count, stream state, or reserved alias differs.
    pub fn revalidate_at(&self, current_root: &Path) -> Result<(), HeldPublicationMarkerV2Error> {
        self.authority
            .mutation_lock
            .revalidate(current_root)
            .map_err(|_| HeldPublicationMarkerV2Error::AuthorityChanged)?;
        if self.authority.root.identity() != self.authority.mutation_lock.root_identity()
            || self.authority.marker_parent.identity()
                != self.authority.mutation_lock.local_identity()
            || self
                .marker_file
                .identity()
                .map_err(HeldPublicationMarkerV2Error::Io)?
                != self.authority.marker_file_identity
        {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
        revalidate_current_publication_root(
            current_root,
            &self.authority.common_parent,
            &self.authority.root,
            &self.authority.marker,
        )?;
        platform::verify_directory_handle_has_no_alternate_data_streams(&self.authority.root.file)
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        self.authority
            .marker_parent
            .verify_no_alternate_data_streams()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        self.marker_file
            .verify_no_alternate_data_streams()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        require_held_reserved_inventory(
            &self.authority.marker_parent,
            HeldReservedPublicationInventory::ExactV2,
        )?;

        let mut observed_file = match self
            .authority
            .marker_parent
            .open_child(std::ffi::OsStr::new(IMPORT_PUBLISH_MARKER_V2))
            .map_err(HeldPublicationMarkerV2Error::Io)?
        {
            SecureSourceChild::File(file) => file,
            SecureSourceChild::Directory(_) | SecureSourceChild::Other => {
                return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
            }
        };
        if observed_file
            .identity()
            .map_err(HeldPublicationMarkerV2Error::Io)?
            != self.authority.marker_file_identity
        {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
        let observed = read_canonical_held_publication_marker(
            &mut observed_file,
            &self.authority.marker_file_identity,
        )?;
        if observed != self.authority.marker
            || !self
                .authority
                .marker
                .common_parent_matches(self.authority.common_parent.identity())
            || !self
                .authority
                .marker
                .staging_root_matches(self.authority.root.identity())
            || !self
                .authority
                .marker
                .marker_parent_matches(self.authority.marker_parent.identity())
            || !self
                .authority
                .marker
                .marker_file_matches(&self.authority.marker_file_identity)
        {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }

        require_held_reserved_inventory(
            &self.authority.marker_parent,
            HeldReservedPublicationInventory::ExactV2,
        )?;
        revalidate_current_publication_root(
            current_root,
            &self.authority.common_parent,
            &self.authority.root,
            &self.authority.marker,
        )?;
        self.authority
            .marker_parent
            .verify_binding()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        self.marker_file
            .verify_binding()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        self.authority
            .mutation_lock
            .revalidate(current_root)
            .map_err(|_| HeldPublicationMarkerV2Error::AuthorityChanged)
    }

    /// Require this staging claim's recorded destination sibling to be absent
    /// at one bounded observation.
    ///
    /// The destination lookup is performed relative to the already-held
    /// common-parent descriptor. The complete marker, root, private directory,
    /// and lock authority is revalidated before and after the lookup. This
    /// operation is valid only while `current_root` names the marker's staging
    /// child; after publication the destination necessarily names the held
    /// root and this check is no longer meaningful. Absence does not reserve
    /// the sibling name: callers must recheck it and use a no-replace move at
    /// publication.
    ///
    /// # Errors
    ///
    /// Returns `NamespaceConflict` when an ordinary single-link file or
    /// directory occupies the exact destination name. Link-like, hard-linked,
    /// cross-mount, raced, or otherwise indeterminate entries return a
    /// scrubbed authority or I/O error and are never treated as absent.
    pub fn require_destination_absent_at(
        &self,
        current_root: &Path,
    ) -> Result<(), HeldPublicationMarkerV2Error> {
        let current_name = current_root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(HeldPublicationMarkerV2Error::AuthorityChanged)?;
        if current_name != self.authority.marker.staging_child_name() {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
        self.revalidate_at(current_root)?;
        require_held_publication_child_absent(
            &self.authority.common_parent,
            self.authority.marker.destination_child_name(),
        )?;
        self.revalidate_at(current_root)
    }

    /// Require the held root to occupy its recorded destination while the
    /// recorded staging sibling is absent at one bounded observation.
    ///
    /// The complete held marker/lock authority and descriptor-relative
    /// staging absence are repeatedly interleaved. This is the read-only role
    /// gate used by an initial publisher after its no-replace move and by a
    /// fresh existing-only reconciliation guard. It performs no sync, move,
    /// unlink, creation, cleanup, or recovery action.
    ///
    /// Absence does not reserve the staging name. A later transition must
    /// revalidate this authority immediately around every namespace mutation.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed namespace, authority, or I/O error unless the exact
    /// destination role, canonical marker, held identities, mutation lock,
    /// reserved inventory, and staging absence remain reproducible.
    pub fn require_published_at(
        &self,
        current_root: &Path,
    ) -> Result<(), HeldPublicationMarkerV2Error> {
        let current_name = current_root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(HeldPublicationMarkerV2Error::AuthorityChanged)?;
        if current_name != self.authority.marker.destination_child_name() {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
        self.revalidate_at(current_root)?;
        require_held_publication_child_absent(
            &self.authority.common_parent,
            self.authority.marker.staging_child_name(),
        )?;
        self.revalidate_at(current_root)?;
        require_held_publication_child_absent(
            &self.authority.common_parent,
            self.authority.marker.staging_child_name(),
        )?;
        self.revalidate_at(current_root)
    }

    /// Synchronize the published root before its common-parent namespace.
    ///
    /// Both durability barriers operate on the directories already held by
    /// this linear publication authority. The destination-role gate brackets
    /// the root barrier, then the held common parent is verified immediately
    /// before and after its barrier, followed by one final destination-role
    /// gate. No pathname is reopened for synchronization, and this operation
    /// performs no move, unlink, creation, cleanup, or recovery action.
    ///
    /// # Errors
    ///
    /// Returns a namespace, authority, or I/O error unless the exact published
    /// role is reproduced at every bounded check around the ordered barriers.
    /// These checks do not exclude a non-cooperating same-UID process from a
    /// swap-and-restore race. Because this method borrows `self`, every failure
    /// retains the same marker and mutation-lock authority for explicit
    /// inspection or retry.
    pub fn synchronize_published_root_and_common_parent_at(
        &self,
        destination: &Path,
    ) -> Result<(), HeldPublicationMarkerV2Error> {
        self.synchronize_published_root_and_common_parent_at_with_hook(destination, |_| Ok(()))
    }

    fn synchronize_published_root_and_common_parent_at_with_hook<BeforeSync>(
        &self,
        destination: &Path,
        mut before_sync: BeforeSync,
    ) -> Result<(), HeldPublicationMarkerV2Error>
    where
        BeforeSync: FnMut(PublishedDurabilitySyncPoint) -> io::Result<()>,
    {
        self.require_published_at(destination)?;
        before_sync(PublishedDurabilitySyncPoint::Root)
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        platform::sync_directory_handle(&self.authority.root.file)
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        self.require_published_at(destination)?;

        self.authority
            .common_parent
            .verify_binding()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        before_sync(PublishedDurabilitySyncPoint::CommonParent)
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        platform::sync_directory_handle(&self.authority.common_parent.file)
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        self.authority
            .common_parent
            .verify_binding()
            .map_err(HeldPublicationMarkerV2Error::Io)?;

        self.require_published_at(destination)
    }

    /// Borrow the validated canonical marker value without exposing its file.
    #[must_use]
    pub const fn marker(&self) -> &PublicationMarkerV2 {
        &self.authority.marker
    }

    /// Borrow the exact held marker-file identity for marker-aware audits.
    #[must_use]
    pub const fn marker_file_identity(&self) -> &FilesystemFileIdentity {
        &self.authority.marker_file_identity
    }

    /// Borrow the exact root identity retained by the held mutation lock.
    #[must_use]
    pub const fn root_identity(&self) -> &FilesystemDirectoryIdentity {
        self.authority.mutation_lock.root_identity()
    }

    /// Borrow the exact `.vault-local` identity retained by the held lock.
    #[must_use]
    pub const fn marker_parent_identity(&self) -> &FilesystemDirectoryIdentity {
        self.authority.mutation_lock.local_identity()
    }

    /// Borrow the exact held root descriptor authority for marker-aware
    /// physical collectors.
    ///
    /// [`SecureSourceDirectory`] preserves descriptor-relative opening and
    /// binding checks without exposing its raw file descriptor.
    #[must_use]
    pub const fn held_root(&self) -> &SecureSourceDirectory {
        &self.authority.root
    }

    /// Duplicate the same held root descriptor into a read-only traversal
    /// view whose namespace binding is `current_root`.
    ///
    /// This is the narrow bridge required after an authorized whole-root
    /// rename: the returned [`SecureSourceDirectory`] still opens descendants
    /// from a duplicate of this authority's held root descriptor, while its
    /// binding checks use the already-revalidated current pathname. No raw
    /// descriptor or caller-provided identity is accepted or exposed.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed error unless the complete held authority validates
    /// both before and after duplicating and checking the current-bound view.
    pub fn held_root_view_at(
        &self,
        current_root: &Path,
    ) -> Result<SecureSourceDirectory, HeldPublicationMarkerV2Error> {
        self.revalidate_at(current_root)?;
        let view = SecureSourceDirectory {
            file: self
                .authority
                .root
                .file
                .try_clone()
                .map_err(HeldPublicationMarkerV2Error::Io)?,
            identity: self.authority.root.identity.clone(),
            binding: SecureSourceDirectoryBinding::Root(current_root.to_path_buf()),
        };
        view.verify_no_alternate_data_streams()
            .map_err(HeldPublicationMarkerV2Error::Io)?;
        if view.identity() != self.authority.root.identity() {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
        self.revalidate_at(current_root)?;
        Ok(view)
    }

    /// Match one freshly collected physical baseline against every held
    /// root/private-directory/lock role without exposing the held lock file.
    ///
    /// This predicate is intended for marker-aware collectors which receive
    /// this complete authority value. It does not replace [`Self::revalidate_at`]:
    /// callers must still revalidate the pathname and held handles before and
    /// after their complete inventory.
    #[must_use]
    pub fn matches_physical_baseline(
        &self,
        root_identity: &FilesystemDirectoryIdentity,
        local_identity: &FilesystemDirectoryIdentity,
        lock_identity: &FilesystemFileIdentity,
    ) -> bool {
        self.authority.root.identity() == root_identity
            && self.authority.marker_parent.identity() == local_identity
            && self.authority.mutation_lock.root_identity() == root_identity
            && self.authority.mutation_lock.local_identity() == local_identity
            && self.authority.mutation_lock.lock_identity() == lock_identity
    }

    /// Consume this exact held marker and classify one destination-only unlink.
    ///
    /// The current root must be the marker's recorded destination child and
    /// the recorded staging child must be absent. The exact canonical marker
    /// is revalidated immediately before the pathname unlink. The original
    /// marker handle remains held while a duplicate is consumed by the
    /// verified-remove primitive, so an errored call can distinguish exact
    /// old-present, exact absent, replacement, and indeterminate post-states.
    ///
    /// Every returned variant retains the same mutation-lock lifetime. Once
    /// exact absence is proved, no returned type can regain write, deletion,
    /// or reconstruction authority over the old claim; only marker-parent
    /// synchronization and read-only classification or audit remain available.
    ///
    /// The final namespace operation is pathname based, not a kernel-level
    /// identity compare-and-exchange. The complete checks before and after it
    /// preserve replacements observed under the cooperative Inex lock
    /// protocol, but a noncooperating process with the same OS identity can
    /// still race the last check-to-unlink window.
    pub fn unlink_exact_published_marker_at(
        self,
        current_root: &Path,
    ) -> HeldPublicationMarkerV2UnlinkOutcome {
        self.unlink_exact_published_marker_at_impl(
            current_root,
            |_| Ok(()),
            |_| Ok(()),
            VerifiedRemoveFault::None,
        )
    }

    #[cfg(test)]
    fn unlink_exact_published_marker_at_with_faults<BeforeRemove, AfterRemove>(
        self,
        current_root: &Path,
        before_remove: BeforeRemove,
        after_remove: AfterRemove,
        fault: VerifiedRemoveFault,
    ) -> HeldPublicationMarkerV2UnlinkOutcome
    where
        BeforeRemove: FnOnce(&Path) -> io::Result<()>,
        AfterRemove: FnOnce(&Path) -> io::Result<()>,
    {
        self.unlink_exact_published_marker_at_impl(current_root, before_remove, after_remove, fault)
    }

    fn unlink_exact_published_marker_at_impl<BeforeRemove, AfterRemove>(
        self,
        current_root: &Path,
        before_remove: BeforeRemove,
        after_remove: AfterRemove,
        fault: VerifiedRemoveFault,
    ) -> HeldPublicationMarkerV2UnlinkOutcome
    where
        BeforeRemove: FnOnce(&Path) -> io::Result<()>,
        AfterRemove: FnOnce(&Path) -> io::Result<()>,
    {
        if self
            .revalidate_exact_published_marker_at(current_root)
            .is_err()
        {
            return self
                .into_terminal_unlink_outcome(HeldPublicationMarkerPostState::Indeterminate);
        }

        let Ok(marker_file) = self.marker_file.file.try_clone() else {
            return if self
                .revalidate_exact_published_marker_at(current_root)
                .is_ok()
            {
                HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(self)
            } else {
                self.into_terminal_unlink_outcome(HeldPublicationMarkerPostState::Indeterminate)
            };
        };
        let marker_path = current_root
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let effect_attempted = std::cell::Cell::new(false);
        let remove_result = atomic_remove_verified_file_impl(
            &marker_path,
            marker_file,
            |path| {
                self.revalidate_exact_published_marker_at(current_root)
                    .map_err(|_| io::Error::other("held publication marker changed"))?;
                before_remove(path)?;
                self.revalidate_exact_published_marker_at(current_root)
                    .map_err(|_| io::Error::other("held publication marker changed"))
            },
            |path| {
                if fault != VerifiedRemoveFault::ErrorBeforeRemove {
                    effect_attempted.set(true);
                }
                after_remove(path)
            },
            fault,
            PUBLICATION_MARKER_SYNC_PARENT_BY_PATH,
        );

        if matches!(remove_result, Err(AtomicVerifiedRemoveError::NotRemoved))
            && self
                .revalidate_exact_published_marker_at(current_root)
                .is_ok()
        {
            return HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(self);
        }

        let state = self.classify_marker_post_state(current_root);
        match state {
            HeldPublicationMarkerPostState::ExactHeld => {
                HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(self)
            }
            HeldPublicationMarkerPostState::Absent
                if effect_attempted.get() && self.marker_file_is_unlinked() =>
            {
                self.finish_removed_marker(current_root, fault == VerifiedRemoveFault::ParentSync)
            }
            HeldPublicationMarkerPostState::Replacement => {
                self.into_terminal_unlink_outcome(HeldPublicationMarkerPostState::Replacement)
            }
            HeldPublicationMarkerPostState::Absent
            | HeldPublicationMarkerPostState::Indeterminate => {
                self.into_terminal_unlink_outcome(HeldPublicationMarkerPostState::Indeterminate)
            }
        }
    }

    fn revalidate_exact_published_marker_at(
        &self,
        current_root: &Path,
    ) -> Result<(), HeldPublicationMarkerV2Error> {
        self.revalidate_at(current_root)?;
        self.authority
            .revalidate_published_base_at(current_root)
            .map_err(map_post_unlink_error_to_held)?;
        self.revalidate_at(current_root)
    }

    fn classify_marker_post_state(&self, current_root: &Path) -> HeldPublicationMarkerPostState {
        if self
            .revalidate_exact_published_marker_at(current_root)
            .is_ok()
        {
            return HeldPublicationMarkerPostState::ExactHeld;
        }
        if self
            .authority
            .revalidate_published_base_at(current_root)
            .is_err()
        {
            return HeldPublicationMarkerPostState::Indeterminate;
        }

        match classify_exact_marker_namespace(&self.authority) {
            ExactMarkerNamespaceState::Absent => HeldPublicationMarkerPostState::Absent,
            ExactMarkerNamespaceState::PresentFile(identity)
                if identity != self.authority.marker_file_identity =>
            {
                HeldPublicationMarkerPostState::Replacement
            }
            ExactMarkerNamespaceState::PresentOther => HeldPublicationMarkerPostState::Replacement,
            ExactMarkerNamespaceState::PresentFile(_)
            | ExactMarkerNamespaceState::Indeterminate => {
                HeldPublicationMarkerPostState::Indeterminate
            }
        }
    }

    fn marker_file_is_unlinked(&self) -> bool {
        linux_regular_file_handle_is_unlinked(&self.marker_file.file)
    }

    fn finish_removed_marker(
        self,
        current_root: &Path,
        inject_sync_failure: bool,
    ) -> HeldPublicationMarkerV2UnlinkOutcome {
        let (former_marker_file, authority) = self.into_post_unlink_parts();
        let post = UnsyncedPostUnlinkPublicationMarkerV2 {
            former_marker_file,
            authority,
        };
        match post.retry_marker_parent_sync_at_impl(current_root, inject_sync_failure) {
            PostUnlinkMarkerParentSyncOutcome::Synced(owner) => {
                HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced(owner)
            }
            PostUnlinkMarkerParentSyncOutcome::StillIndeterminate(owner) => {
                HeldPublicationMarkerV2UnlinkOutcome::RemovedButParentSyncIndeterminate(owner)
            }
            PostUnlinkMarkerParentSyncOutcome::ReplacementRetained(owner) => {
                HeldPublicationMarkerV2UnlinkOutcome::ReplacementRetained(owner)
            }
            PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(owner) => {
                HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(owner)
            }
        }
    }

    fn into_post_unlink_parts(self) -> (FormerPublicationMarkerFile, PublicationMarkerV2Authority) {
        let Self {
            marker_file,
            authority,
        } = self;
        let SecureSourceFile { file, parent, name } = marker_file;
        drop(parent);
        drop(name);
        (FormerPublicationMarkerFile { file }, authority)
    }

    fn into_terminal_unlink_outcome(
        self,
        state: HeldPublicationMarkerPostState,
    ) -> HeldPublicationMarkerV2UnlinkOutcome {
        let (former_marker_file, authority) = self.into_post_unlink_parts();
        let owner = TerminalPublicationMarkerV2Authority {
            _former_marker_file: former_marker_file,
            _authority: authority,
        };
        match state {
            HeldPublicationMarkerPostState::Replacement => {
                HeldPublicationMarkerV2UnlinkOutcome::ReplacementRetained(owner)
            }
            HeldPublicationMarkerPostState::ExactHeld
            | HeldPublicationMarkerPostState::Absent
            | HeldPublicationMarkerPostState::Indeterminate => {
                HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(owner)
            }
        }
    }
}

#[cfg(target_os = "linux")]
const PUBLICATION_MARKER_SYNC_PARENT_BY_PATH: bool = false;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeldPublicationMarkerPostState {
    ExactHeld,
    Absent,
    Replacement,
    Indeterminate,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum ExactMarkerNamespaceState {
    Absent,
    PresentFile(FilesystemFileIdentity),
    PresentOther,
    Indeterminate,
}

#[cfg(target_os = "linux")]
fn classify_exact_marker_namespace(
    authority: &PublicationMarkerV2Authority,
) -> ExactMarkerNamespaceState {
    let Ok(first_inventory) = held_reserved_publication_inventory(&authority.marker_parent) else {
        return ExactMarkerNamespaceState::Indeterminate;
    };
    let first = match authority
        .marker_parent
        .open_child(std::ffi::OsStr::new(IMPORT_PUBLISH_MARKER_V2))
    {
        Err(error) if error.kind() == io::ErrorKind::NotFound => ExactMarkerNamespaceState::Absent,
        Ok(SecureSourceChild::File(file)) => match file.identity() {
            Ok(identity) => ExactMarkerNamespaceState::PresentFile(identity),
            Err(_) => ExactMarkerNamespaceState::Indeterminate,
        },
        Ok(SecureSourceChild::Directory(_) | SecureSourceChild::Other) => {
            ExactMarkerNamespaceState::PresentOther
        }
        Err(_) if first_inventory == HeldReservedPublicationInventory::ExactV2 => {
            ExactMarkerNamespaceState::Indeterminate
        }
        Err(_) => ExactMarkerNamespaceState::Indeterminate,
    };

    let Ok(second_inventory) = held_reserved_publication_inventory(&authority.marker_parent) else {
        return ExactMarkerNamespaceState::Indeterminate;
    };
    match first {
        ExactMarkerNamespaceState::Absent
            if first_inventory == HeldReservedPublicationInventory::Absent
                && second_inventory == HeldReservedPublicationInventory::Absent =>
        {
            match authority
                .marker_parent
                .open_child(std::ffi::OsStr::new(IMPORT_PUBLISH_MARKER_V2))
            {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    ExactMarkerNamespaceState::Absent
                }
                Ok(SecureSourceChild::File(file)) => match file.identity() {
                    Ok(identity) => ExactMarkerNamespaceState::PresentFile(identity),
                    Err(_) => ExactMarkerNamespaceState::Indeterminate,
                },
                Ok(SecureSourceChild::Directory(_) | SecureSourceChild::Other) => {
                    ExactMarkerNamespaceState::PresentOther
                }
                Err(_) => ExactMarkerNamespaceState::Indeterminate,
            }
        }
        ExactMarkerNamespaceState::PresentFile(identity)
            if first_inventory == HeldReservedPublicationInventory::ExactV2
                && second_inventory == HeldReservedPublicationInventory::ExactV2 =>
        {
            ExactMarkerNamespaceState::PresentFile(identity)
        }
        ExactMarkerNamespaceState::PresentOther
            if matches!(
                (first_inventory, second_inventory),
                (
                    HeldReservedPublicationInventory::ExactV2,
                    HeldReservedPublicationInventory::ExactV2
                )
            ) =>
        {
            ExactMarkerNamespaceState::PresentOther
        }
        ExactMarkerNamespaceState::Absent
        | ExactMarkerNamespaceState::PresentFile(_)
        | ExactMarkerNamespaceState::PresentOther
        | ExactMarkerNamespaceState::Indeterminate => ExactMarkerNamespaceState::Indeterminate,
    }
}

#[cfg(target_os = "linux")]
impl PublicationMarkerV2Authority {
    fn revalidate_published_base_at(
        &self,
        current_root: &Path,
    ) -> Result<(), PostUnlinkPublicationMarkerV2Error> {
        let current_name = current_root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(PostUnlinkPublicationMarkerV2Error::AuthorityChanged)?;
        if current_name != self.marker.destination_child_name() {
            return Err(PostUnlinkPublicationMarkerV2Error::AuthorityChanged);
        }
        self.mutation_lock
            .revalidate(current_root)
            .map_err(|_| PostUnlinkPublicationMarkerV2Error::AuthorityChanged)?;
        if self.root.identity() != self.mutation_lock.root_identity()
            || self.marker_parent.identity() != self.mutation_lock.local_identity()
            || !self
                .marker
                .common_parent_matches(self.common_parent.identity())
            || !self.marker.staging_root_matches(self.root.identity())
            || !self
                .marker
                .marker_parent_matches(self.marker_parent.identity())
            || !self.marker.marker_file_matches(&self.marker_file_identity)
        {
            return Err(PostUnlinkPublicationMarkerV2Error::AuthorityChanged);
        }
        revalidate_current_publication_root(
            current_root,
            &self.common_parent,
            &self.root,
            &self.marker,
        )
        .map_err(|error| map_held_error_to_post_unlink(&error))?;
        platform::verify_directory_handle_has_no_alternate_data_streams(&self.root.file)
            .map_err(|_| PostUnlinkPublicationMarkerV2Error::Indeterminate)?;
        self.marker_parent
            .verify_no_alternate_data_streams()
            .map_err(|_| PostUnlinkPublicationMarkerV2Error::Indeterminate)?;
        require_held_publication_staging_absent(self)?;
        self.marker_parent
            .verify_binding()
            .map_err(|_| PostUnlinkPublicationMarkerV2Error::Indeterminate)?;
        revalidate_current_publication_root(
            current_root,
            &self.common_parent,
            &self.root,
            &self.marker,
        )
        .map_err(|error| map_held_error_to_post_unlink(&error))?;
        require_held_publication_staging_absent(self)?;
        self.mutation_lock
            .revalidate(current_root)
            .map_err(|_| PostUnlinkPublicationMarkerV2Error::AuthorityChanged)
    }

    fn revalidate_post_unlink_absent_at(
        &self,
        current_root: &Path,
    ) -> Result<(), PostUnlinkPublicationMarkerV2Error> {
        self.revalidate_published_base_at(current_root)?;
        match classify_exact_marker_namespace(self) {
            ExactMarkerNamespaceState::Absent => {}
            ExactMarkerNamespaceState::PresentFile(_) | ExactMarkerNamespaceState::PresentOther => {
                return Err(PostUnlinkPublicationMarkerV2Error::NamespaceConflict);
            }
            ExactMarkerNamespaceState::Indeterminate => {
                return Err(PostUnlinkPublicationMarkerV2Error::Indeterminate);
            }
        }
        self.revalidate_published_base_at(current_root)
    }

    fn classify_post_unlink_absence(&self, current_root: &Path) -> PostUnlinkAbsenceState {
        if self.revalidate_published_base_at(current_root).is_err() {
            return PostUnlinkAbsenceState::Indeterminate;
        }
        match classify_exact_marker_namespace(self) {
            ExactMarkerNamespaceState::Absent
                if self.revalidate_published_base_at(current_root).is_ok() =>
            {
                PostUnlinkAbsenceState::Absent
            }
            ExactMarkerNamespaceState::PresentFile(_) | ExactMarkerNamespaceState::PresentOther => {
                PostUnlinkAbsenceState::Replacement
            }
            ExactMarkerNamespaceState::Absent | ExactMarkerNamespaceState::Indeterminate => {
                PostUnlinkAbsenceState::Indeterminate
            }
        }
    }

    fn matches_physical_baseline(
        &self,
        root_identity: &FilesystemDirectoryIdentity,
        local_identity: &FilesystemDirectoryIdentity,
        lock_identity: &FilesystemFileIdentity,
    ) -> bool {
        self.root.identity() == root_identity
            && self.marker_parent.identity() == local_identity
            && self.mutation_lock.root_identity() == root_identity
            && self.mutation_lock.local_identity() == local_identity
            && self.mutation_lock.lock_identity() == lock_identity
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostUnlinkAbsenceState {
    Absent,
    Replacement,
    Indeterminate,
}

#[cfg(target_os = "linux")]
fn require_held_publication_staging_absent(
    authority: &PublicationMarkerV2Authority,
) -> Result<(), PostUnlinkPublicationMarkerV2Error> {
    match authority
        .common_parent
        .open_child(std::ffi::OsStr::new(authority.marker.staging_child_name()))
    {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(PostUnlinkPublicationMarkerV2Error::AuthorityChanged),
        Err(_) => Err(PostUnlinkPublicationMarkerV2Error::Indeterminate),
    }
}

#[cfg(target_os = "linux")]
fn map_held_error_to_post_unlink(
    error: &HeldPublicationMarkerV2Error,
) -> PostUnlinkPublicationMarkerV2Error {
    match error {
        HeldPublicationMarkerV2Error::NamespaceConflict => {
            PostUnlinkPublicationMarkerV2Error::NamespaceConflict
        }
        HeldPublicationMarkerV2Error::InvalidInput
        | HeldPublicationMarkerV2Error::AuthorityChanged => {
            PostUnlinkPublicationMarkerV2Error::AuthorityChanged
        }
        HeldPublicationMarkerV2Error::Io(_) => PostUnlinkPublicationMarkerV2Error::Indeterminate,
    }
}

#[cfg(target_os = "linux")]
fn map_post_unlink_error_to_held(
    error: PostUnlinkPublicationMarkerV2Error,
) -> HeldPublicationMarkerV2Error {
    match error {
        PostUnlinkPublicationMarkerV2Error::NamespaceConflict => {
            HeldPublicationMarkerV2Error::NamespaceConflict
        }
        PostUnlinkPublicationMarkerV2Error::AuthorityChanged
        | PostUnlinkPublicationMarkerV2Error::Indeterminate => {
            HeldPublicationMarkerV2Error::AuthorityChanged
        }
    }
}

#[cfg(target_os = "linux")]
impl UnsyncedPostUnlinkPublicationMarkerV2 {
    /// Retry only exact-absence revalidation and held marker-parent sync.
    pub fn retry_marker_parent_sync_at(
        self,
        current_root: &Path,
    ) -> PostUnlinkMarkerParentSyncOutcome {
        self.retry_marker_parent_sync_at_impl(current_root, false)
    }

    fn retry_marker_parent_sync_at_impl(
        self,
        current_root: &Path,
        inject_sync_failure: bool,
    ) -> PostUnlinkMarkerParentSyncOutcome {
        if !self.former_marker_file.is_unlinked() {
            return PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(self.into_terminal());
        }
        match self.authority.classify_post_unlink_absence(current_root) {
            PostUnlinkAbsenceState::Absent => {}
            PostUnlinkAbsenceState::Replacement => {
                return PostUnlinkMarkerParentSyncOutcome::ReplacementRetained(
                    self.into_terminal(),
                );
            }
            PostUnlinkAbsenceState::Indeterminate => {
                return PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(
                    self.into_terminal(),
                );
            }
        }

        if self.authority.marker_parent.verify_binding().is_err() {
            return PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(self.into_terminal());
        }
        let sync_succeeded = !inject_sync_failure
            && platform::sync_directory_handle(&self.authority.marker_parent.file).is_ok();
        if self.authority.marker_parent.verify_binding().is_err()
            || !self.former_marker_file.is_unlinked()
        {
            return PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(self.into_terminal());
        }
        match self.authority.classify_post_unlink_absence(current_root) {
            PostUnlinkAbsenceState::Absent if sync_succeeded => {
                let Self {
                    former_marker_file,
                    authority,
                } = self;
                PostUnlinkMarkerParentSyncOutcome::Synced(SyncedPostUnlinkPublicationMarkerV2 {
                    former_marker_file,
                    authority,
                })
            }
            PostUnlinkAbsenceState::Absent => {
                PostUnlinkMarkerParentSyncOutcome::StillIndeterminate(self)
            }
            PostUnlinkAbsenceState::Replacement => {
                PostUnlinkMarkerParentSyncOutcome::ReplacementRetained(self.into_terminal())
            }
            PostUnlinkAbsenceState::Indeterminate => {
                PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(self.into_terminal())
            }
        }
    }

    fn into_terminal(self) -> TerminalPublicationMarkerV2Authority {
        let Self {
            former_marker_file,
            authority,
        } = self;
        TerminalPublicationMarkerV2Authority {
            _former_marker_file: former_marker_file,
            _authority: authority,
        }
    }
}

#[cfg(target_os = "linux")]
impl SyncedPostUnlinkPublicationMarkerV2 {
    /// Revalidate the exact published root, absent marker namespace, held
    /// directories, former marker identity, and original mutation lock.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed error if the retained authority, absent marker
    /// namespace, former marker inode, or published-root binding has drifted.
    pub fn revalidate_absent_at(
        &self,
        current_root: &Path,
    ) -> Result<(), PostUnlinkPublicationMarkerV2Error> {
        if !self.former_marker_file.is_unlinked() {
            return Err(PostUnlinkPublicationMarkerV2Error::AuthorityChanged);
        }
        self.authority
            .revalidate_post_unlink_absent_at(current_root)?;
        if !self.former_marker_file.is_unlinked() {
            return Err(PostUnlinkPublicationMarkerV2Error::AuthorityChanged);
        }
        Ok(())
    }

    /// Borrow the immutable publication claim retained in memory after unlink.
    #[must_use]
    pub const fn marker(&self) -> &PublicationMarkerV2 {
        &self.authority.marker
    }

    /// Borrow the former exact marker-file identity for the live clean audit.
    #[must_use]
    pub const fn marker_file_identity(&self) -> &FilesystemFileIdentity {
        &self.authority.marker_file_identity
    }

    /// Borrow the exact root identity retained by the held mutation lock.
    #[must_use]
    pub const fn root_identity(&self) -> &FilesystemDirectoryIdentity {
        self.authority.mutation_lock.root_identity()
    }

    /// Borrow the exact `.vault-local` identity retained by the held lock.
    #[must_use]
    pub const fn marker_parent_identity(&self) -> &FilesystemDirectoryIdentity {
        self.authority.mutation_lock.local_identity()
    }

    /// Duplicate the held root into a current-path-bound read-only clean-audit
    /// view. Exact marker absence is revalidated before and after duplication.
    /// The returned owned traversal view is not mutation-lock authority and is
    /// not lifetime-branded by Rust; callers must keep this owner alive across
    /// traversal and revalidate it after the complete audit. Higher-level
    /// collectors should enforce that borrow and final-revalidation contract.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed error if exact absence or retained authority cannot
    /// be proved before and after constructing the read-only view.
    pub fn held_root_view_at(
        &self,
        current_root: &Path,
    ) -> Result<SecureSourceDirectory, PostUnlinkPublicationMarkerV2Error> {
        self.revalidate_absent_at(current_root)?;
        let view = SecureSourceDirectory {
            file: self
                .authority
                .root
                .file
                .try_clone()
                .map_err(|_| PostUnlinkPublicationMarkerV2Error::Indeterminate)?,
            identity: self.authority.root.identity.clone(),
            binding: SecureSourceDirectoryBinding::Root(current_root.to_path_buf()),
        };
        view.verify_no_alternate_data_streams()
            .map_err(|_| PostUnlinkPublicationMarkerV2Error::Indeterminate)?;
        if view.identity() != self.authority.root.identity() {
            return Err(PostUnlinkPublicationMarkerV2Error::AuthorityChanged);
        }
        self.revalidate_absent_at(current_root)?;
        Ok(view)
    }

    /// Match a marker-free clean physical baseline to the retained authority.
    #[must_use]
    pub fn matches_physical_baseline(
        &self,
        root_identity: &FilesystemDirectoryIdentity,
        local_identity: &FilesystemDirectoryIdentity,
        lock_identity: &FilesystemFileIdentity,
    ) -> bool {
        self.authority
            .matches_physical_baseline(root_identity, local_identity, lock_identity)
    }
}

#[cfg(target_os = "linux")]
fn prepare_held_publication_directories(
    current_root: &Path,
    held_root: SecureSourceDirectory,
    mutation_lock: &ExistingVaultMutationLock,
) -> Result<
    (
        SecureSourceDirectory,
        SecureSourceDirectory,
        SecureSourceDirectory,
        String,
    ),
    HeldPublicationMarkerV2Error,
> {
    if !current_root.is_absolute() || !path_is_lexically_normal(current_root) {
        return Err(HeldPublicationMarkerV2Error::InvalidInput);
    }
    let common_parent_path = current_root
        .parent()
        .ok_or(HeldPublicationMarkerV2Error::InvalidInput)?;
    let current_child_name = current_root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(HeldPublicationMarkerV2Error::InvalidInput)?
        .to_owned();
    mutation_lock
        .revalidate(current_root)
        .map_err(|_| HeldPublicationMarkerV2Error::AuthorityChanged)?;
    held_root
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    if held_root.identity() != mutation_lock.root_identity()
        || !path_is_supported_local_filesystem(common_parent_path)
            .map_err(HeldPublicationMarkerV2Error::Io)?
        || !paths_share_mount(common_parent_path, current_root)
            .map_err(HeldPublicationMarkerV2Error::Io)?
    {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }

    let common_parent =
        open_secure_source_root(common_parent_path).map_err(HeldPublicationMarkerV2Error::Io)?;
    common_parent
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    let observed_root = match common_parent
        .open_child(std::ffi::OsStr::new(&current_child_name))
        .map_err(HeldPublicationMarkerV2Error::Io)?
    {
        SecureSourceChild::Directory(directory) => directory,
        SecureSourceChild::File(_) | SecureSourceChild::Other => {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
    };
    if observed_root.identity() != held_root.identity() {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    observed_root
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;

    let marker_parent = match held_root
        .open_child(std::ffi::OsStr::new(VAULT_LOCAL_DIRECTORY))
        .map_err(HeldPublicationMarkerV2Error::Io)?
    {
        SecureSourceChild::Directory(directory) => directory,
        SecureSourceChild::File(_) | SecureSourceChild::Other => {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
    };
    if marker_parent.identity() != mutation_lock.local_identity() {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    marker_parent
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    mutation_lock
        .revalidate(current_root)
        .map_err(|_| HeldPublicationMarkerV2Error::AuthorityChanged)?;
    Ok((common_parent, held_root, marker_parent, current_child_name))
}

#[cfg(target_os = "linux")]
fn revalidate_pre_marker_authority(
    current_root: &Path,
    common_parent: &SecureSourceDirectory,
    root: &SecureSourceDirectory,
    marker_parent: &SecureSourceDirectory,
    mutation_lock: &ExistingVaultMutationLock,
) -> Result<(), HeldPublicationMarkerV2Error> {
    mutation_lock
        .revalidate(current_root)
        .map_err(|_| HeldPublicationMarkerV2Error::AuthorityChanged)?;
    common_parent
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    root.verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    marker_parent
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    if root.identity() != mutation_lock.root_identity()
        || marker_parent.identity() != mutation_lock.local_identity()
    {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_pre_marker_creation_state(
    staging_root_path: &Path,
    common_parent: &SecureSourceDirectory,
    root: &SecureSourceDirectory,
    marker_parent: &SecureSourceDirectory,
    mutation_lock: &ExistingVaultMutationLock,
    destination_child_name: &str,
) -> Result<(), HeldPublicationMarkerV2Error> {
    require_held_reserved_inventory(marker_parent, HeldReservedPublicationInventory::Absent)?;
    revalidate_pre_marker_authority(
        staging_root_path,
        common_parent,
        root,
        marker_parent,
        mutation_lock,
    )?;
    require_held_publication_child_absent(common_parent, destination_child_name)?;
    revalidate_pre_marker_authority(
        staging_root_path,
        common_parent,
        root,
        marker_parent,
        mutation_lock,
    )
}

#[cfg(target_os = "linux")]
fn require_held_publication_child_absent(
    common_parent: &SecureSourceDirectory,
    destination_child_name: &str,
) -> Result<(), HeldPublicationMarkerV2Error> {
    common_parent
        .verify_binding()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    let lookup = common_parent.open_child(std::ffi::OsStr::new(destination_child_name));
    common_parent
        .verify_binding()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    match lookup {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(HeldPublicationMarkerV2Error::NamespaceConflict),
        Err(error) => Err(HeldPublicationMarkerV2Error::Io(error)),
    }
}

#[cfg(target_os = "linux")]
fn revalidate_current_publication_root(
    current_root: &Path,
    common_parent: &SecureSourceDirectory,
    held_root: &SecureSourceDirectory,
    marker: &PublicationMarkerV2,
) -> Result<(), HeldPublicationMarkerV2Error> {
    if !current_root.is_absolute() || !path_is_lexically_normal(current_root) {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    let current_parent = current_root
        .parent()
        .ok_or(HeldPublicationMarkerV2Error::AuthorityChanged)?;
    let current_name = current_root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(HeldPublicationMarkerV2Error::AuthorityChanged)?;
    if current_name != marker.staging_child_name()
        && current_name != marker.destination_child_name()
    {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    common_parent
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    if filesystem_directory_identity(current_parent).map_err(HeldPublicationMarkerV2Error::Io)?
        != *common_parent.identity()
        || !marker.common_parent_matches(common_parent.identity())
    {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    let observed_root = match common_parent
        .open_child(std::ffi::OsStr::new(current_name))
        .map_err(HeldPublicationMarkerV2Error::Io)?
    {
        SecureSourceChild::Directory(directory) => directory,
        SecureSourceChild::File(_) | SecureSourceChild::Other => {
            return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
        }
    };
    observed_root
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    if observed_root.identity() != held_root.identity()
        || !marker.staging_root_matches(held_root.identity())
    {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn held_reserved_publication_inventory(
    marker_parent: &SecureSourceDirectory,
) -> io::Result<HeldReservedPublicationInventory> {
    marker_parent.verify_binding()?;
    let reserved_prefix = raw_portable_case_fold_key(IMPORT_PUBLISH_MARKER_PREFIX);
    let mut reserved_count = 0_usize;
    let mut exact_v2 = false;
    let mut entry_count = 0_usize;
    let mut name_bytes = 0_usize;
    for entry in marker_parent.read_dir()? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("private namespace name is not portable UTF-8"))?;
        entry_count = entry_count
            .checked_add(1)
            .filter(|count| *count <= MAX_STAGING_RECOVERY_ENTRIES)
            .ok_or_else(|| io::Error::other("private namespace entry limit exceeded"))?;
        name_bytes = name_bytes
            .checked_add(name.len())
            .filter(|total| *total <= MAX_STAGING_RECOVERY_PATH_BYTES)
            .ok_or_else(|| io::Error::other("private namespace path limit exceeded"))?;
        if raw_portable_case_fold_key(&name)
            .as_str()
            .starts_with(reserved_prefix.as_str())
        {
            reserved_count = reserved_count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("reserved namespace count overflow"))?;
            exact_v2 |= name == IMPORT_PUBLISH_MARKER_V2;
        }
    }
    marker_parent.verify_binding()?;
    Ok(match (reserved_count, exact_v2) {
        (0, false) => HeldReservedPublicationInventory::Absent,
        (1, true) => HeldReservedPublicationInventory::ExactV2,
        _ => HeldReservedPublicationInventory::Conflict,
    })
}

#[cfg(target_os = "linux")]
fn require_held_reserved_inventory(
    marker_parent: &SecureSourceDirectory,
    expected: HeldReservedPublicationInventory,
) -> Result<(), HeldPublicationMarkerV2Error> {
    if held_reserved_publication_inventory(marker_parent)
        .map_err(HeldPublicationMarkerV2Error::Io)?
        == expected
    {
        Ok(())
    } else {
        Err(HeldPublicationMarkerV2Error::NamespaceConflict)
    }
}

#[cfg(target_os = "linux")]
fn create_secure_publication_marker(
    marker_parent: &SecureSourceDirectory,
) -> io::Result<SecureSourceFile> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    marker_parent.verify_binding()?;
    let file = platform::create_publication_marker_child(
        &marker_parent.file,
        std::ffi::OsStr::new(IMPORT_PUBLISH_MARKER_V2),
    )?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() != 0
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(io::Error::other(
            "created publication marker is not an exact private regular file",
        ));
    }
    let marker_file = SecureSourceFile {
        file,
        parent: marker_parent.file.try_clone()?,
        name: std::ffi::OsString::from(IMPORT_PUBLISH_MARKER_V2),
    };
    marker_file.verify_no_alternate_data_streams()?;
    marker_parent.verify_binding()?;
    Ok(marker_file)
}

#[cfg(target_os = "linux")]
fn read_canonical_held_publication_marker(
    marker_file: &mut SecureSourceFile,
    expected_identity: &FilesystemFileIdentity,
) -> Result<PublicationMarkerV2, HeldPublicationMarkerV2Error> {
    verify_secure_publication_marker_metadata(marker_file)
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    marker_file
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    let initial_length = marker_file
        .observed_len()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    if marker_file
        .identity()
        .map_err(HeldPublicationMarkerV2Error::Io)?
        != *expected_identity
        || initial_length
            > u64::try_from(crate::publication::PUBLICATION_MARKER_READ_LIMIT_BYTES)
                .unwrap_or(u64::MAX)
    {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    marker_file
        .file
        .seek(SeekFrom::Start(0))
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    let marker = PublicationMarkerV2::read_bounded(marker_file)
        .map_err(|_| HeldPublicationMarkerV2Error::AuthorityChanged)?;
    marker_file
        .verify_no_alternate_data_streams()
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    verify_secure_publication_marker_metadata(marker_file)
        .map_err(HeldPublicationMarkerV2Error::Io)?;
    if marker_file
        .identity()
        .map_err(HeldPublicationMarkerV2Error::Io)?
        != *expected_identity
        || marker_file
            .observed_len()
            .map_err(HeldPublicationMarkerV2Error::Io)?
            != initial_length
        || initial_length != u64::try_from(marker.to_bytes().len()).unwrap_or(u64::MAX)
    {
        return Err(HeldPublicationMarkerV2Error::AuthorityChanged);
    }
    Ok(marker)
}

#[cfg(target_os = "linux")]
fn verify_secure_publication_marker_metadata(marker_file: &SecureSourceFile) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = marker_file.file.metadata()?;
    if metadata.file_type().is_file() && metadata.nlink() == 1 && metadata.mode() & 0o777 == 0o600 {
        Ok(())
    } else {
        Err(io::Error::other(
            "held publication marker metadata is not canonical",
        ))
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
    Ok(FilesystemDirectoryIdentity {
        projections: linux_identity_projections(metadata.dev(), metadata.ino(), 1),
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

fn combine_parent_sync(first: ParentSyncStatus, second: ParentSyncStatus) -> ParentSyncStatus {
    if first == ParentSyncStatus::Synced && second == ParentSyncStatus::Synced {
        ParentSyncStatus::Synced
    } else {
        ParentSyncStatus::NotSynced
    }
}

fn sync_staging_and_target_parents_status(
    staging_parent: &Path,
    target_parent: &Path,
) -> ParentSyncStatus {
    combine_parent_sync(
        sync_namespace_parent_status(staging_parent),
        sync_namespace_parent_status(target_parent),
    )
}

fn sync_rebind_parent(parent: &Path) -> Result<ParentSyncStatus, ()> {
    match sync_namespace_parent(parent) {
        Ok(()) => Ok(ParentSyncStatus::Synced),
        Err(_) => Err(()),
    }
}

fn sync_rebind_commit_parents(
    staging_parent: &Path,
    destination_parent: &Path,
) -> Result<ParentSyncStatus, ()> {
    sync_rebind_parent(staging_parent)?;
    sync_rebind_parent(destination_parent)
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

#[derive(Debug)]
struct StagingRecoveryCandidate {
    path: PathBuf,
    identity: FilesystemFileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StagingNameClass {
    None,
    Exact,
    WrongCase,
}

#[derive(Debug, Default)]
struct StagingRecoveryScan {
    inspected_entries: usize,
    inspected_path_bytes: usize,
    candidates: Vec<StagingRecoveryCandidate>,
}

fn recover_ciphertext_staging_locked(vault_root: &Path) -> Result<(), AtomicWriteError> {
    let root_identity = filesystem_directory_identity(vault_root).map_err(staging_recovery_io)?;
    let root = fs::canonicalize(vault_root).map_err(staging_recovery_io)?;
    if filesystem_directory_identity(&root).map_err(staging_recovery_io)? != root_identity {
        return Err(AtomicWriteError::UnsafeStagingPath);
    }
    let local = root.join(VAULT_LOCAL_DIRECTORY);
    let local_identity = filesystem_directory_identity(&local).map_err(staging_recovery_io)?;
    if !paths_share_mount(&root, &local).map_err(staging_recovery_io)? {
        return Err(AtomicWriteError::UnsafeStagingPath);
    }

    let mut scan = StagingRecoveryScan::default();
    collect_staging_recovery_candidates(&root, &local, &mut scan)?;
    verify_staging_recovery_directories(&root, &local, &root_identity, &local_identity)?;

    for candidate in &scan.candidates {
        remove_staging_recovery_candidate(&root, candidate)?;
    }
    verify_staging_recovery_directories(&root, &local, &root_identity, &local_identity)
}

fn collect_staging_recovery_candidates(
    root: &Path,
    local: &Path,
    scan: &mut StagingRecoveryScan,
) -> Result<(), AtomicWriteError> {
    let entries = fs::read_dir(local).map_err(staging_recovery_io)?;
    for entry in entries {
        let entry = entry.map_err(staging_recovery_io)?;
        let name = entry.file_name();
        scan.inspected_entries = scan.inspected_entries.saturating_add(1);
        scan.inspected_path_bytes = scan
            .inspected_path_bytes
            .saturating_add(name.as_encoded_bytes().len());
        if scan.inspected_entries > MAX_STAGING_RECOVERY_ENTRIES
            || scan.inspected_path_bytes > MAX_STAGING_RECOVERY_PATH_BYTES
        {
            return Err(AtomicWriteError::UnsafeStagingPath);
        }

        let path = local.join(&name);
        let _metadata = fs::symlink_metadata(&path).map_err(staging_recovery_io)?;
        match classify_staging_name(&name) {
            StagingNameClass::WrongCase => return Err(AtomicWriteError::UnsafeStagingPath),
            StagingNameClass::Exact => {
                scan.candidates
                    .push(audit_staging_recovery_candidate(root, &path)?);
            }
            StagingNameClass::None => {}
        }
    }
    Ok(())
}

fn verify_staging_recovery_directories(
    root: &Path,
    local: &Path,
    root_identity: &FilesystemDirectoryIdentity,
    local_identity: &FilesystemDirectoryIdentity,
) -> Result<(), AtomicWriteError> {
    if filesystem_directory_identity(root).map_err(staging_recovery_io)? != *root_identity
        || filesystem_directory_identity(local).map_err(staging_recovery_io)? != *local_identity
        || !paths_share_mount(root, local).map_err(staging_recovery_io)?
    {
        return Err(AtomicWriteError::UnsafeStagingPath);
    }
    Ok(())
}

fn audit_staging_recovery_candidate(
    root: &Path,
    path: &Path,
) -> Result<StagingRecoveryCandidate, AtomicWriteError> {
    let metadata = fs::symlink_metadata(path).map_err(staging_recovery_io)?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_ATOMIC_TARGET_BYTES
        || !paths_share_mount(root, path).map_err(staging_recovery_io)?
    {
        return Err(AtomicWriteError::UnsafeStagingPath);
    }
    let file = File::open(path).map_err(staging_recovery_io)?;
    let held_metadata = file.metadata().map_err(staging_recovery_io)?;
    if !held_metadata.file_type().is_file()
        || held_metadata.len() > MAX_ATOMIC_TARGET_BYTES
        || !open_file_matches_path_and_is_single_link(path, &file).map_err(staging_recovery_io)?
    {
        return Err(AtomicWriteError::UnsafeStagingPath);
    }
    verify_regular_file_has_no_alternate_data_streams(path, &file)
        .map_err(|_| AtomicWriteError::UnsafeStagingPath)?;
    let identity =
        filesystem_file_identity(&file).map_err(|_| AtomicWriteError::UnsafeStagingPath)?;
    if !open_file_matches_path_and_is_single_link(path, &file).map_err(staging_recovery_io)? {
        return Err(AtomicWriteError::UnsafeStagingPath);
    }
    Ok(StagingRecoveryCandidate {
        path: path.to_path_buf(),
        identity,
    })
}

fn remove_staging_recovery_candidate(
    root: &Path,
    candidate: &StagingRecoveryCandidate,
) -> Result<(), AtomicWriteError> {
    let metadata =
        fs::symlink_metadata(&candidate.path).map_err(|_| AtomicWriteError::UnsafeStagingPath)?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_ATOMIC_TARGET_BYTES
        || !paths_share_mount(root, &candidate.path).map_err(staging_recovery_io)?
    {
        return Err(AtomicWriteError::UnsafeStagingPath);
    }
    let file = File::open(&candidate.path).map_err(|_| AtomicWriteError::UnsafeStagingPath)?;
    if filesystem_file_identity(&file).map_err(|_| AtomicWriteError::UnsafeStagingPath)?
        != candidate.identity
        || !open_file_matches_path_and_is_single_link(&candidate.path, &file)
            .map_err(staging_recovery_io)?
    {
        return Err(AtomicWriteError::UnsafeStagingPath);
    }
    verify_regular_file_has_no_alternate_data_streams(&candidate.path, &file)
        .map_err(|_| AtomicWriteError::UnsafeStagingPath)?;
    atomic_remove_verified_file(&candidate.path, file)
        .map_err(|_| AtomicWriteError::UnsafeStagingPath)?;
    Ok(())
}

fn classify_staging_name(name: &std::ffi::OsStr) -> StagingNameClass {
    let Some(name) = name.to_str() else {
        return StagingNameClass::None;
    };
    let expected_length = CIPHERTEXT_STAGING_PREFIX.len() + 32 + CIPHERTEXT_STAGING_SUFFIX.len();
    let bytes = name.as_bytes();
    if bytes.len() != expected_length {
        return StagingNameClass::None;
    }
    let prefix_end = CIPHERTEXT_STAGING_PREFIX.len();
    let suffix_start = prefix_end + 32;
    let prefix = &bytes[..prefix_end];
    let random = &bytes[prefix_end..suffix_start];
    let suffix = &bytes[suffix_start..];
    if !prefix.eq_ignore_ascii_case(CIPHERTEXT_STAGING_PREFIX.as_bytes())
        || !suffix.eq_ignore_ascii_case(CIPHERTEXT_STAGING_SUFFIX.as_bytes())
        || !random.iter().all(u8::is_ascii_hexdigit)
    {
        return StagingNameClass::None;
    }
    if prefix == CIPHERTEXT_STAGING_PREFIX.as_bytes()
        && suffix == CIPHERTEXT_STAGING_SUFFIX.as_bytes()
        && random
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        StagingNameClass::Exact
    } else {
        StagingNameClass::WrongCase
    }
}

fn staging_recovery_io(source: io::Error) -> AtomicWriteError {
    AtomicWriteError::io(AtomicWriteStage::RecoverStaging, source)
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
            let staging_parent = vault_root.join(VAULT_LOCAL_DIRECTORY);
            if sync_rebind_commit_parents(&staging_parent, destination_parent).is_err() {
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
            let staging_parent = vault_root.join(VAULT_LOCAL_DIRECTORY);
            for parent in [
                Some(staging_parent.as_path()),
                target_parent(&destination),
                target_parent(&source),
            ] {
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
        || relative == Path::new(".inex/keyslots/umbra-default.inex-keyslot")
        || relative == Path::new(".inex/config.umbra.inex")
    {
        if case_alias_exists(target)
            .map_err(|source| AtomicWriteError::io(AtomicWriteStage::ReadCurrent, source))?
        {
            Err(AtomicWriteError::InvalidTarget)
        } else {
            Ok(())
        }
    } else {
        if LogicalPath::from_ciphertext_relative_path(relative).is_ok()
            || AssetPath::from_ciphertext_relative_path(relative).is_ok()
        {
            Ok(())
        } else {
            Err(AtomicWriteError::InvalidTarget)
        }
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
    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(source) => {
            return Err(AtomicWriteError::io(AtomicWriteStage::PrepareLock, source));
        }
    };

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
    if created {
        restrict_directory_permissions_best_effort(path);
    }
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

fn open_lock_file(path: &Path) -> io::Result<(File, bool)> {
    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    configure_restrictive_creation(&mut create);
    permit_namespace_rename(&mut create);
    match create.open(path) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            existing.read(true).write(true);
            permit_namespace_rename(&mut existing);
            existing.open(path).map(|file| (file, false))
        }
        Err(error) => Err(error),
    }
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

/// Keep internal marker and lock handles compatible with a Windows directory
/// namespace move. Their data remains protected by the exclusive file lock;
/// allowing deletion only permits the staged vault root to be renamed as one
/// atomic namespace operation.
#[cfg(windows)]
fn permit_namespace_rename(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
}

#[cfg(not(windows))]
fn permit_namespace_rename(_options: &mut OpenOptions) {}

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
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    const AT_FDCWD: i32 = -100;
    const RENAME_NOREPLACE: u32 = 1;
    const O_DIRECTORY: i32 = 0o200_000;
    const O_RDWR: i32 = 0o2;
    const O_CREAT: i32 = 0o100;
    const O_EXCL: i32 = 0o200;
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

    pub(super) fn open_existing_mutation_lock(path: &Path) -> io::Result<File> {
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        options.open(path)
    }

    pub(super) fn try_lock_exclusive(file: &File) -> io::Result<bool> {
        loop {
            // SAFETY: `file` owns a valid descriptor for this call; LOCK_EX
            // requests the exclusive lock and LOCK_NB forbids waiting.
            if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0 {
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(false),
                _ => return Err(error),
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

    pub(super) fn create_publication_marker_child(
        parent: &File,
        name: &std::ffi::OsStr,
    ) -> io::Result<File> {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication marker child name contains NUL",
            )
        })?;
        if name.as_bytes().contains(&b'/') || matches!(name.as_bytes(), b"." | b"..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication marker must be one direct child",
            ));
        }
        let how = OpenHow {
            flags: u64::try_from(O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC).unwrap_or(0),
            mode: 0o600,
            resolve: RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS
                | RESOLVE_BENEATH,
        };
        // SAFETY: `name` and `how` remain live for the syscall, `parent` is
        // one held directory descriptor, and a successful create-new
        // descriptor is transferred exactly once into `File`.
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
        Ok(super::FilesystemDirectoryIdentity {
            projections: super::linux_identity_projections(metadata.dev(), metadata.ino(), 1),
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn filesystem_file_identity(
        file: &File,
    ) -> io::Result<super::FilesystemFileIdentity> {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file identity requires a single-link regular file",
            ));
        }
        Ok(super::FilesystemFileIdentity {
            projections: super::linux_identity_projections(metadata.dev(), metadata.ino(), 2),
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn verify_regular_file_has_no_alternate_data_streams(
        _file: &File,
    ) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn verify_directory_handle_has_no_alternate_data_streams(
        file: &File,
    ) -> io::Result<()> {
        if file.metadata()?.file_type().is_dir() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "alternate-stream proof requires a held directory",
            ))
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn verify_directory_has_no_alternate_data_streams(
        _path: &Path,
        _expected_identity: &super::FilesystemDirectoryIdentity,
    ) -> io::Result<()> {
        Ok(())
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

    pub(super) fn open_file_is_single_link(file: &File) -> io::Result<bool> {
        let metadata = file.metadata()?;
        Ok(metadata.file_type().is_file() && metadata.nlink() == 1)
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

    pub(super) fn sync_directory_handle(directory: &File) -> io::Result<()> {
        if !directory.metadata()?.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory synchronization requires a held directory",
            ));
        }
        directory.sync_all()
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
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_STREAM_INFO_CLASS: i32 = 7;
    const FILE_ID_INFO_CLASS: i32 = 18;
    const STREAM_INFO_BUFFER_BYTES: usize = 64 * 1024;
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

    pub(super) fn open_existing_mutation_lock(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options.open(path)
    }

    pub(super) fn try_lock_exclusive(file: &File) -> io::Result<bool> {
        let mut overlapped = Overlapped::zeroed();
        // SAFETY: the handle remains owned by `file`; the live OVERLAPPED has
        // the documented layout, and FAIL_IMMEDIATELY forbids lock waiting.
        let result = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &raw mut overlapped,
            )
        };
        if result != 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
            Ok(false)
        } else {
            Err(error)
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
        let file = open_directory_no_follow(path)?;
        directory_identity_from_file(&file)
    }

    fn open_directory_no_follow(path: &Path) -> io::Result<File> {
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
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn directory_identity_from_file(file: &File) -> io::Result<super::FilesystemDirectoryIdentity> {
        let metadata = file.metadata()?;
        let legacy = handle_information(file)?;
        if !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory identity requires a directory handle",
            ));
        }
        if legacy.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory identity rejected a reparse point",
            ));
        }
        let modern = modern_identity_query(file)?;
        let file_index = u64::from(legacy.file_index_high) << 32 | u64::from(legacy.file_index_low);
        Ok(super::FilesystemDirectoryIdentity {
            projections: super::windows_identity_projections(
                legacy.volume_serial_number,
                file_index,
                modern,
                1,
            )?,
        })
    }

    pub(super) fn filesystem_file_identity(
        file: &File,
    ) -> io::Result<super::FilesystemFileIdentity> {
        let metadata = file.metadata()?;
        let legacy = handle_information(file)?;
        if !metadata.file_type().is_file()
            || legacy.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || legacy.number_of_links != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file identity requires a non-reparse single-link regular file",
            ));
        }
        let modern = modern_identity_query(file)?;
        let file_index = u64::from(legacy.file_index_high) << 32 | u64::from(legacy.file_index_low);
        Ok(super::FilesystemFileIdentity {
            projections: super::windows_identity_projections(
                legacy.volume_serial_number,
                file_index,
                modern,
                2,
            )?,
        })
    }

    pub(super) fn verify_regular_file_has_no_alternate_data_streams(file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        let information = handle_information(file)?;
        if !metadata.file_type().is_file()
            || information.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || information.number_of_links != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "alternate-stream proof requires a non-reparse single-link regular file",
            ));
        }
        verify_handle_has_no_alternate_data_streams(
            file,
            super::WindowsStreamObjectKind::RegularFile,
        )
    }

    pub(super) fn verify_directory_has_no_alternate_data_streams(
        path: &Path,
        expected_identity: &super::FilesystemDirectoryIdentity,
    ) -> io::Result<()> {
        let file = open_directory_no_follow(path)?;
        if directory_identity_from_file(&file)? != *expected_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "alternate-stream proof opened a different directory",
            ));
        }
        verify_handle_has_no_alternate_data_streams(
            &file,
            super::WindowsStreamObjectKind::Directory,
        )
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
        let handle_id = modern_identity_query(file)?;
        let current_id = modern_identity_query(&current)?;
        Ok(
            handle_info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && current_info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && handle_info.number_of_links == 1
                && current_info.number_of_links == 1
                && same_file_identity(&handle_info, &current_info, &handle_id, &current_id),
        )
    }

    pub(super) fn open_file_is_single_link(file: &File) -> io::Result<bool> {
        let information = handle_information(file)?;
        Ok(
            information.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && information.number_of_links == 1,
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
        let held_modern = modern_identity_query(file)?;
        let current_modern = modern_identity_query(&current)?;
        if held_legacy.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || current_legacy.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || held_legacy.number_of_links != 1
            || current_legacy.number_of_links != 1
        {
            return Ok(false);
        }
        match super::compare_windows_modern_identities(held_modern, current_modern, false) {
            super::WindowsModernIdentityComparison::Resolved(matches) => Ok(matches),
            super::WindowsModernIdentityComparison::UseLegacy => {
                let held_index = u64::from(held_legacy.file_index_high) << 32
                    | u64::from(held_legacy.file_index_low);
                let current_index = u64::from(current_legacy.file_index_high) << 32
                    | u64::from(current_legacy.file_index_low);
                Ok(held_index != 0 && held_index == current_index)
            }
        }
    }

    fn same_file_identity(
        first_legacy: &ByHandleFileInformation,
        second_legacy: &ByHandleFileInformation,
        first_modern: &super::WindowsModernIdentityQueryOutcome,
        second_modern: &super::WindowsModernIdentityQueryOutcome,
    ) -> bool {
        match super::compare_windows_modern_identities(*first_modern, *second_modern, true) {
            super::WindowsModernIdentityComparison::Resolved(matches) => matches,
            super::WindowsModernIdentityComparison::UseLegacy => {
                let first_index = u64::from(first_legacy.file_index_high) << 32
                    | u64::from(first_legacy.file_index_low);
                let second_index = u64::from(second_legacy.file_index_high) << 32
                    | u64::from(second_legacy.file_index_low);
                first_index != 0
                    && first_legacy.volume_serial_number == second_legacy.volume_serial_number
                    && first_index == second_index
            }
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

    fn modern_identity_query(file: &File) -> io::Result<super::WindowsModernIdentityQueryOutcome> {
        super::classify_windows_modern_identity_query(
            file_id_information(file)
                .map(|identity| (identity.volume_serial_number, identity.file_id.identifier)),
        )
    }

    fn verify_handle_has_no_alternate_data_streams(
        file: &File,
        object_kind: super::WindowsStreamObjectKind,
    ) -> io::Result<()> {
        let mut aligned_buffer = vec![0_u64; STREAM_INFO_BUFFER_BYTES / std::mem::size_of::<u64>()];
        let buffer_size = u32::try_from(STREAM_INFO_BUFFER_BYTES)
            .map_err(|_| io::Error::other("FILE_STREAM_INFO buffer size overflow"))?;
        // SAFETY: `file` owns a valid handle and `aligned_buffer` provides a
        // live, writable, 8-byte-aligned region of exactly `buffer_size`
        // bytes for the synchronous FileStreamInfo query.
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FILE_STREAM_INFO_CLASS,
                aligned_buffer.as_mut_ptr().cast(),
                buffer_size,
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            return match super::classify_windows_stream_query_failure(error.raw_os_error()) {
                super::WindowsStreamQueryFailure::NoStreams => Ok(()),
                super::WindowsStreamQueryFailure::InventoryTooLarge => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "alternate-stream inventory exceeds the bounded query buffer",
                )),
                super::WindowsStreamQueryFailure::Other => Err(error),
            };
        }
        // SAFETY: the vector remains live and contains exactly
        // STREAM_INFO_BUFFER_BYTES initialized bytes. The parser performs no
        // typed dereferences and validates every offset before slicing.
        let buffer = unsafe {
            std::slice::from_raw_parts(
                aligned_buffer.as_ptr().cast::<u8>(),
                STREAM_INFO_BUFFER_BYTES,
            )
        };
        if super::windows_stream_info_has_no_alternate_data_streams(buffer, object_kind)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "named or duplicate data stream is present",
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::Path;

        use super::{ByHandleFileInformation, FileTime, extended_path, same_file_identity};
        use crate::atomic::{
            WindowsModernIdentityQueryOutcome, classify_windows_modern_identity_query,
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

        fn modern(
            volume_serial_number: u64,
            identifier: [u8; 16],
        ) -> WindowsModernIdentityQueryOutcome {
            classify_windows_modern_identity_query(Ok((volume_serial_number, identifier)))
                .expect("synthetic successful query must classify")
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

    pub(super) fn open_existing_mutation_lock(_path: &Path) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "existing-only mutation locking is unsupported",
        ))
    }

    pub(super) fn try_lock_exclusive(_file: &File) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "existing-only mutation locking is unsupported",
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

    pub(super) fn filesystem_file_identity(
        _file: &File,
    ) -> io::Result<super::FilesystemFileIdentity> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file identity is supported only on Linux and Windows",
        ))
    }

    pub(super) fn verify_regular_file_has_no_alternate_data_streams(
        _file: &File,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "alternate-stream verification is supported only on Linux and Windows",
        ))
    }

    pub(super) fn verify_directory_has_no_alternate_data_streams(
        _path: &Path,
        _expected_identity: &super::FilesystemDirectoryIdentity,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "alternate-stream verification is supported only on Linux and Windows",
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

    pub(super) fn open_file_is_single_link(_file: &File) -> io::Result<bool> {
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
    #[cfg(target_os = "linux")]
    use std::ffi::{CString, c_char, c_int};
    use std::fs;
    use std::io;
    #[cfg(target_os = "linux")]
    use std::io::Write as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[cfg(any(target_os = "linux", windows))]
    use std::process::{Command, Stdio};
    #[cfg(any(target_os = "linux", windows))]
    use std::time::{Duration, Instant};

    use super::{
        AtomicDirectoryPublishError, AtomicWriteError, AtomicWriteStage, CIPHERTEXT_STAGING_PREFIX,
        CIPHERTEXT_STAGING_SUFFIX, CurrentTarget, ExistingVaultMutationLock,
        ExistingVaultMutationLockError, FaultInjector, FaultPoint, IMPORT_PUBLISH_MARKER_V1,
        IMPORT_PUBLISH_MARKER_V2, IMPORT_STAGING_PREFIX, MAX_ATOMIC_TARGET_BYTES,
        PENDING_REBIND_FILE, ParentSyncStatus, RebindJournal, RepositoryPublicationNamespaceState,
        VAULT_LOCAL_DIRECTORY, VAULT_MUTATION_LOCK_FILE, VaultMutationGuard, VaultMutationLock,
        WriteCondition, atomic_delete_ciphertext, atomic_move_verified_file_no_replace,
        atomic_publish_directory_no_replace, atomic_publish_directory_no_replace_with_fault,
        atomic_rebind_ciphertext, atomic_replace_verified_file, atomic_write_ciphertext,
        atomic_write_ciphertext_with_faults, digest_bytes,
        inspect_repository_publication_namespace, install_rebind_journal, pending_rebind_path,
        reconcile_failed_namespace_commit, recover_pending_rebind,
        verify_directory_has_no_alternate_data_streams,
        verify_regular_file_has_no_alternate_data_streams,
    };

    #[cfg(windows)]
    use super::open_file_matches_path_and_is_single_link;

    const OLD_CIPHERTEXT: &[u8] = b"EDRY-old-authenticated-ciphertext";
    const NEW_CIPHERTEXT: &[u8] = b"EDRY-new-authenticated-ciphertext";

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        fn mkfifo(path: *const c_char, mode: u32) -> c_int;
    }

    #[cfg(target_os = "linux")]
    fn create_fifo(path: &Path) -> io::Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "FIFO path contains NUL"))?;
        // SAFETY: `path` is a live NUL-terminated byte string and mode 0600
        // contains only portable permission bits.
        if unsafe { mkfifo(path.as_ptr(), 0o600) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    struct ExistingLockIdentities {
        root: super::FilesystemDirectoryIdentity,
        local: super::FilesystemDirectoryIdentity,
        lock: super::FilesystemFileIdentity,
    }

    #[cfg(any(target_os = "linux", windows))]
    fn initialize_existing_lock(root: &Path) -> io::Result<ExistingLockIdentities> {
        let local = root.join(VAULT_LOCAL_DIRECTORY);
        fs::create_dir(&local)?;
        let lock_path = local.join(VAULT_MUTATION_LOCK_FILE);
        fs::write(&lock_path, [])?;
        let lock_file = fs::File::open(&lock_path)?;
        Ok(ExistingLockIdentities {
            root: super::filesystem_directory_identity(root)?,
            local: super::filesystem_directory_identity(&local)?,
            lock: super::filesystem_file_identity(&lock_file)?,
        })
    }

    #[cfg(any(target_os = "linux", windows))]
    fn write_canonical_publication_marker_v2(root: &Path) -> io::Result<PathBuf> {
        let local = root.join(VAULT_LOCAL_DIRECTORY);
        if !local.exists() {
            fs::create_dir(&local)?;
        }
        let marker_path = local.join(IMPORT_PUBLISH_MARKER_V2);
        fs::write(&marker_path, [])?;
        let marker_file = fs::File::open(&marker_path)?;
        let common_parent = super::filesystem_directory_identity(
            root.parent()
                .ok_or_else(|| io::Error::other("test vault has no parent"))?,
        )?;
        let staging_root = super::filesystem_directory_identity(root)?;
        let marker_parent = super::filesystem_directory_identity(&local)?;
        let marker_file_identity = super::filesystem_file_identity(&marker_file)?;
        let scheme = [
            super::PublicationIdentityScheme::LinuxDevInodeV1,
            super::PublicationIdentityScheme::WindowsModernFileId128V1,
            super::PublicationIdentityScheme::WindowsLegacyFileIndexV1,
        ]
        .into_iter()
        .find(|scheme| {
            common_parent.publication_identity(*scheme).is_some()
                && staging_root.publication_identity(*scheme).is_some()
                && marker_parent.publication_identity(*scheme).is_some()
                && marker_file_identity.publication_identity(*scheme).is_some()
        })
        .ok_or_else(|| io::Error::other("test marker identities have no uniform scheme"))?;
        let marker = crate::publication::PublicationMarkerV2::new(
            crate::publication::PublicationMarkerV2Input {
                scheme,
                publication_id: [7_u8; 16],
                common_parent_identity: &common_parent,
                staging_root_identity: &staging_root,
                marker_parent_identity: &marker_parent,
                marker_file_identity: &marker_file_identity,
                domain: "inex.repository-import.v1",
                staging_child_name: ".inex-import-staging-00000000000000000000000000000000",
                destination_child_name: "destination",
                candidate_seal: &[0x5a; 32],
            },
        )
        .map_err(io::Error::other)?;
        drop(marker_file);
        fs::write(&marker_path, marker.to_bytes())?;
        Ok(marker_path)
    }

    #[cfg(target_os = "linux")]
    fn held_marker_test_input<'a>(
        root: &'a Path,
        common_parent_identity: &'a super::FilesystemDirectoryIdentity,
        destination_child_name: &'a str,
    ) -> io::Result<super::HeldPublicationMarkerV2CreateInput<'a>> {
        let staging_child_name = root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| io::Error::other("test staging root has no portable child name"))?;
        Ok(super::HeldPublicationMarkerV2CreateInput {
            scheme: super::PublicationIdentityScheme::LinuxDevInodeV1,
            publication_id: [0x37; 16],
            common_parent_identity,
            staging_child_name,
            destination_child_name,
            domain: "inex.repository-import.v1",
            candidate_seal: &[0xa5; 32],
        })
    }

    #[cfg(target_os = "linux")]
    fn held_root_and_existing_lock(
        root: &Path,
    ) -> io::Result<(super::SecureSourceDirectory, ExistingVaultMutationLock)> {
        let identities = initialize_existing_lock(root)?;
        let held_root = super::open_secure_source_root(root)?;
        let mutation_lock = ExistingVaultMutationLock::acquire(
            root,
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        Ok((held_root, mutation_lock))
    }

    #[cfg(target_os = "linux")]
    fn try_create_test_held_marker(
        root: &Path,
        destination_child_name: &str,
    ) -> io::Result<Result<super::HeldPublicationMarkerV2, super::HeldPublicationMarkerV2Error>>
    {
        let common_parent = super::filesystem_directory_identity(
            root.parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let (held_root, lock) = held_root_and_existing_lock(root)?;
        let input = held_marker_test_input(root, &common_parent, destination_child_name)?;
        Ok(lock.create_held_publication_marker_v2(root, held_root, input))
    }

    #[cfg(target_os = "linux")]
    struct PublishedRootGuard {
        original: PathBuf,
        destination: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl PublishedRootGuard {
        fn destination(&self) -> &Path {
            &self.destination
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for PublishedRootGuard {
        fn drop(&mut self) {
            if self.destination.exists() && !self.original.exists() {
                let _ = fs::rename(&self.destination, &self.original);
            }
            if self.destination.exists() {
                let _ = fs::remove_dir_all(&self.destination);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn published_held_marker(
        fixture: &TestVault,
    ) -> io::Result<(
        super::HeldPublicationMarkerV2,
        PublishedRootGuard,
        ExistingLockIdentities,
    )> {
        let identities = initialize_existing_lock(fixture.root())?;
        let held_root = super::open_secure_source_root(fixture.root())?;
        let lock = ExistingVaultMutationLock::acquire(
            fixture.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        let common_parent_path = fixture
            .root()
            .parent()
            .ok_or_else(|| io::Error::other("test root has no parent"))?;
        let common_parent = super::filesystem_directory_identity(common_parent_path)?;
        let destination_name = format!(
            "inex-held-marker-published-{}",
            uuid::Uuid::new_v4().simple()
        );
        let destination = common_parent_path.join(&destination_name);
        let input = held_marker_test_input(fixture.root(), &common_parent, &destination_name)?;
        let held = lock
            .create_held_publication_marker_v2(fixture.root(), held_root, input)
            .map_err(io::Error::other)?;
        fs::rename(fixture.root(), &destination)?;
        let guard = PublishedRootGuard {
            original: fixture.root().to_path_buf(),
            destination,
        };
        held.revalidate_at(guard.destination())
            .map_err(io::Error::other)?;
        Ok((held, guard, identities))
    }

    #[cfg(target_os = "linux")]
    fn assert_publication_lock_busy(root: &Path, identities: &ExistingLockIdentities) {
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                root,
                &identities.root,
                &identities.local,
                &identities.lock,
            ),
            Err(ExistingVaultMutationLockError::Busy)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_exact_unlink_returns_synced_post_owner() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&fixture)?;
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);

        let outcome = held.unlink_exact_published_marker_at(published.destination());
        let owner = match outcome {
            super::HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced(owner) => owner,
            other => panic!("expected synchronized exact unlink, got {other:?}"),
        };
        assert!(!marker_path.exists());
        owner
            .revalidate_absent_at(published.destination())
            .map_err(io::Error::other)?;
        let root_view = owner
            .held_root_view_at(published.destination())
            .map_err(io::Error::other)?;
        assert_eq!(root_view.identity(), &identities.root);
        assert!(owner.matches_physical_baseline(
            &identities.root,
            &identities.local,
            &identities.lock,
        ));
        assert_publication_lock_busy(published.destination(), &identities);
        drop(root_view);
        drop(owner);
        let reacquired = ExistingVaultMutationLock::acquire(
            published.destination(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        drop(reacquired);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_unlink_rejects_staging_without_removal() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let identities = initialize_existing_lock(fixture.root())?;
        let held_root = super::open_secure_source_root(fixture.root())?;
        let lock = ExistingVaultMutationLock::acquire(
            fixture.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        let common_parent = super::filesystem_directory_identity(
            fixture
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let input = held_marker_test_input(fixture.root(), &common_parent, "published-target")?;
        let held = lock
            .create_held_publication_marker_v2(fixture.root(), held_root, input)
            .map_err(io::Error::other)?;
        let marker_path = fixture.local().join(IMPORT_PUBLISH_MARKER_V2);

        let owner = match held.unlink_exact_published_marker_at(fixture.root()) {
            super::HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(owner) => owner,
            other => panic!("staging unlink must fail closed, got {other:?}"),
        };
        assert!(marker_path.exists());
        assert_publication_lock_busy(fixture.root(), &identities);
        drop(owner);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_unlink_reconciles_not_removed_and_remove_then_error()
    -> io::Result<()> {
        let not_removed = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&not_removed)?;
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let held = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::ErrorBeforeRemove,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(held) => held,
            other => panic!("expected exact not-removed owner, got {other:?}"),
        };
        assert!(marker_path.exists());
        held.revalidate_at(published.destination())
            .map_err(io::Error::other)?;
        assert_publication_lock_busy(published.destination(), &identities);
        let owner = match held.unlink_exact_published_marker_at(published.destination()) {
            super::HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced(owner) => owner,
            other => panic!("retry should remove exact marker, got {other:?}"),
        };
        drop(owner);

        let remove_then_error = TestVault::new()?;
        let (held, published, _) = published_held_marker(&remove_then_error)?;
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::RemoveThenError,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced(owner) => owner,
            other => panic!("effect reconciliation should prove removal, got {other:?}"),
        };
        assert!(!marker_path.exists());
        owner
            .revalidate_absent_at(published.destination())
            .map_err(io::Error::other)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_unlink_parent_sync_fault_is_retryable() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&fixture)?;
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::ParentSync,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::RemovedButParentSyncIndeterminate(
                owner,
            ) => owner,
            other => panic!("parent-sync fault must retain retry owner, got {other:?}"),
        };
        assert_publication_lock_busy(published.destination(), &identities);
        let owner = match owner.retry_marker_parent_sync_at_impl(published.destination(), true) {
            super::PostUnlinkMarkerParentSyncOutcome::StillIndeterminate(owner) => owner,
            other => panic!("repeated parent-sync fault must retain retry owner, got {other:?}"),
        };
        assert_publication_lock_busy(published.destination(), &identities);
        let owner = match owner.retry_marker_parent_sync_at(published.destination()) {
            super::PostUnlinkMarkerParentSyncOutcome::Synced(owner) => owner,
            other => panic!("held parent sync retry should succeed, got {other:?}"),
        };
        owner
            .revalidate_absent_at(published.destination())
            .map_err(io::Error::other)?;
        drop(owner);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_unlink_retains_after_remove_replacement() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&fixture)?;
        let replacement = b"replacement created after exact unlink";
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| Ok(()),
            |marker| fs::write(marker, replacement),
            super::VerifiedRemoveFault::None,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::ReplacementRetained(owner) => owner,
            other => panic!("after-unlink replacement must be retained, got {other:?}"),
        };
        assert_eq!(fs::read(&marker_path)?, replacement);
        assert_publication_lock_busy(published.destination(), &identities);
        drop(owner);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_unlink_parent_sync_retry_rejects_replacement_and_alias() -> io::Result<()> {
        let replaced = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&replaced)?;
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::ParentSync,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::RemovedButParentSyncIndeterminate(
                owner,
            ) => owner,
            other => panic!("parent-sync fault must retain retry owner, got {other:?}"),
        };
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let replacement = b"replacement before parent-sync retry";
        fs::write(&marker_path, replacement)?;
        let terminal = match owner.retry_marker_parent_sync_at(published.destination()) {
            super::PostUnlinkMarkerParentSyncOutcome::ReplacementRetained(owner) => owner,
            other => panic!("retry must retain replacement, got {other:?}"),
        };
        assert_eq!(fs::read(&marker_path)?, replacement);
        assert_publication_lock_busy(published.destination(), &identities);
        drop(terminal);

        let aliased = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&aliased)?;
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::ParentSync,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::RemovedButParentSyncIndeterminate(
                owner,
            ) => owner,
            other => panic!("parent-sync fault must retain retry owner, got {other:?}"),
        };
        let alias = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join("import-publish-marker-foreign");
        fs::write(&alias, b"reserved alias before parent-sync retry")?;
        let terminal = match owner.retry_marker_parent_sync_at(published.destination()) {
            super::PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(owner) => owner,
            other => panic!("reserved alias must make retry terminal, got {other:?}"),
        };
        assert_eq!(
            fs::read(&alias)?,
            b"reserved alias before parent-sync retry"
        );
        assert_publication_lock_busy(published.destination(), &identities);
        drop(terminal);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_unlink_parent_sync_retry_rejects_reappeared_staging() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&fixture)?;
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::ParentSync,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::RemovedButParentSyncIndeterminate(
                owner,
            ) => owner,
            other => panic!("parent-sync fault must retain retry owner, got {other:?}"),
        };
        let staging = published.original.clone();
        fs::create_dir(&staging)?;
        let terminal = match owner.retry_marker_parent_sync_at(published.destination()) {
            super::PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(owner) => owner,
            other => panic!("reappeared staging must make retry terminal, got {other:?}"),
        };
        assert!(staging.is_dir());
        assert_publication_lock_busy(published.destination(), &identities);
        drop(terminal);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_unlink_rejects_reappeared_staging_before_removal() -> io::Result<()>
    {
        let fixture = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&fixture)?;
        let staging = published.original.clone();
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let terminal = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| fs::create_dir(&staging),
            |_| Ok(()),
            super::VerifiedRemoveFault::None,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(owner) => owner,
            other => panic!("pre-unlink staging sibling must be terminal, got {other:?}"),
        };
        assert!(marker_path.is_file());
        assert!(staging.is_dir());
        assert_publication_lock_busy(published.destination(), &identities);
        drop(terminal);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_unlink_rejects_reappeared_staging_after_removal() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&fixture)?;
        let staging = published.original.clone();
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let terminal = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| Ok(()),
            |_| fs::create_dir(&staging),
            super::VerifiedRemoveFault::None,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(owner) => owner,
            other => panic!("reappeared staging sibling must be terminal, got {other:?}"),
        };
        assert!(!marker_path.exists());
        assert!(staging.is_dir());
        assert_publication_lock_busy(published.destination(), &identities);
        drop(terminal);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_unlink_preserves_replacement_and_link_indeterminate()
    -> io::Result<()> {
        let replaced = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&replaced)?;
        let retired = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join("retired-held-marker");
        let replacement = b"foreign replacement canary";
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |marker| {
                fs::rename(marker, &retired)?;
                fs::write(marker, replacement)
            },
            |_| Ok(()),
            super::VerifiedRemoveFault::None,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::ReplacementRetained(owner) => owner,
            other => panic!("replacement must be retained, got {other:?}"),
        };
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        assert_eq!(fs::read(&marker_path)?, replacement);
        assert!(retired.exists());
        assert_publication_lock_busy(published.destination(), &identities);
        drop(owner);

        let linked = TestVault::new()?;
        let (held, published, _) = published_held_marker(&linked)?;
        let hardlink = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join("held-marker-hardlink");
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |marker| fs::hard_link(marker, &hardlink),
            |_| Ok(()),
            super::VerifiedRemoveFault::None,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(owner) => owner,
            other => panic!("unsafe linked marker must be retained, got {other:?}"),
        };
        assert!(marker_path.exists());
        assert!(hardlink.exists());
        drop(owner);

        let indeterminate = TestVault::new()?;
        let (held, published, _) = published_held_marker(&indeterminate)?;
        let alias = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join("import-publish-marker-foreign");
        let owner = match held.unlink_exact_published_marker_at_with_faults(
            published.destination(),
            |_| fs::write(&alias, b"reserved alias canary"),
            |_| Ok(()),
            super::VerifiedRemoveFault::None,
        ) {
            super::HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(owner) => owner,
            other => panic!("conflicting post-state must be indeterminate, got {other:?}"),
        };
        assert_eq!(fs::read(alias)?, b"reserved alias canary");
        drop(owner);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_unlink_owners_are_redacted_and_api_is_linear() -> io::Result<()> {
        const {
            assert!(!super::PUBLICATION_MARKER_SYNC_PARENT_BY_PATH);
        }

        let fixture = TestVault::new()?;
        let (held, published, _) = published_held_marker(&fixture)?;
        let outcome = held.unlink_exact_published_marker_at(published.destination());
        let debug = format!("{outcome:?}");
        assert_eq!(
            debug,
            "HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced(..)"
        );
        assert!(!debug.contains(published.destination().to_string_lossy().as_ref()));
        let owner = match outcome {
            super::HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced(owner) => owner,
            other => panic!("expected synchronized owner, got {other:?}"),
        };
        assert_eq!(
            format!("{owner:?}"),
            "SyncedPostUnlinkPublicationMarkerV2 { .. }"
        );
        drop(owner);

        let source = include_str!("atomic.rs");
        let unsynced = source
            .split("pub struct UnsyncedPostUnlinkPublicationMarkerV2")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub struct SyncedPostUnlinkPublicationMarkerV2")
                    .next()
            })
            .expect("unsynced owner source exists");
        assert!(!unsynced.contains("derive(Clone"));
        assert!(!unsynced.contains("impl Drop for Unsynced"));
        let unsynced_impl = source
            .split("impl UnsyncedPostUnlinkPublicationMarkerV2")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl SyncedPostUnlinkPublicationMarkerV2")
                    .next()
            })
            .expect("unsynced impl source exists");
        assert!(unsynced_impl.contains("retry_marker_parent_sync_at"));
        assert!(!unsynced_impl.contains("unlink_exact_published_marker_at"));
        assert!(!unsynced_impl.contains("held_root_view_at"));
        let held_drop_impl = ["impl Drop for ", "HeldPublicationMarkerV2"].concat();
        let manually_dropped_held = ["ManuallyDrop<", "HeldPublicationMarkerV2"].concat();
        assert!(!source.contains(&held_drop_impl));
        assert!(!source.contains(&manually_dropped_held));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_create_open_and_lock_lifetime_are_exact() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = TestVault::new()?;
        let common_parent = super::filesystem_directory_identity(
            fixture
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let (held_root, mutation_lock) = held_root_and_existing_lock(fixture.root())?;
        let destination = format!("published-{}", uuid::Uuid::new_v4().simple());
        let input = held_marker_test_input(fixture.root(), &common_parent, &destination)?;
        let marker_path = fixture.local().join(IMPORT_PUBLISH_MARKER_V2);
        let held = mutation_lock
            .create_held_publication_marker_v2(fixture.root(), held_root, input)
            .map_err(io::Error::other)?;

        held.revalidate_at(fixture.root())
            .map_err(io::Error::other)?;
        assert_eq!(held.marker().to_bytes(), fs::read(&marker_path)?);
        assert!(
            held.marker()
                .marker_file_matches(held.marker_file_identity())
        );
        assert_eq!(
            held.root_identity(),
            &super::filesystem_directory_identity(fixture.root())?
        );
        assert_eq!(
            held.marker_parent_identity(),
            &super::filesystem_directory_identity(&fixture.local())?
        );
        assert_eq!(
            fs::metadata(&marker_path)?.permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(format!("{held:?}"), "HeldPublicationMarkerV2 { .. }");
        assert!(!format!("{input:?}").contains("repository-import"));

        let current_identities = ExistingLockIdentities {
            root: super::filesystem_directory_identity(fixture.root())?,
            local: super::filesystem_directory_identity(&fixture.local())?,
            lock: {
                let file = fs::File::open(fixture.local().join(VAULT_MUTATION_LOCK_FILE))?;
                super::filesystem_file_identity(&file)?
            },
        };
        assert!(held.matches_physical_baseline(
            &current_identities.root,
            &current_identities.local,
            &current_identities.lock,
        ));
        assert!(!held.matches_physical_baseline(
            &current_identities.root,
            &current_identities.local,
            held.marker_file_identity(),
        ));
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                fixture.root(),
                &current_identities.root,
                &current_identities.local,
                &current_identities.lock,
            ),
            Err(ExistingVaultMutationLockError::Busy)
        ));
        let expected_wire = held.marker().to_bytes();
        drop(held);

        let held_root = super::open_secure_source_root(fixture.root())?;
        let lock = ExistingVaultMutationLock::acquire(
            fixture.root(),
            &current_identities.root,
            &current_identities.local,
            &current_identities.lock,
        )
        .map_err(io::Error::other)?;
        let reopened = lock
            .open_held_publication_marker_v2(fixture.root(), held_root)
            .map_err(io::Error::other)?;
        reopened
            .revalidate_at(fixture.root())
            .map_err(io::Error::other)?;
        assert_eq!(reopened.marker().to_bytes(), expected_wire);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_publication_marker_opener_is_fused_and_retains_the_exact_lock() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let (initial, published, identities) = published_held_marker(&fixture)?;
        let expected_marker = initial.marker().to_bytes();
        drop(initial);

        let reopened = super::open_existing_publication_marker_v2(published.destination())
            .map_err(io::Error::other)?;
        reopened
            .require_published_at(published.destination())
            .map_err(io::Error::other)?;
        assert_eq!(reopened.marker().to_bytes(), expected_marker);
        assert!(reopened.matches_physical_baseline(
            &identities.root,
            &identities.local,
            &identities.lock,
        ));
        assert_publication_lock_busy(published.destination(), &identities);

        drop(reopened);
        let reacquired = ExistingVaultMutationLock::acquire(
            published.destination(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        drop(reacquired);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_publication_marker_opener_requires_destination_role_and_absent_staging()
    -> io::Result<()> {
        let staging = TestVault::new()?;
        let destination_name = format!("published-{}", uuid::Uuid::new_v4().simple());
        let held = try_create_test_held_marker(staging.root(), &destination_name)?
            .map_err(io::Error::other)?;
        let marker_path = staging.local().join(IMPORT_PUBLISH_MARKER_V2);
        let marker_before = fs::read(&marker_path)?;
        drop(held);
        assert!(matches!(
            super::open_existing_publication_marker_v2(staging.root()),
            Err(super::ExistingPublicationMarkerV2OpenError::AuthorityChanged)
        ));
        assert_eq!(fs::read(&marker_path)?, marker_before);

        let reappeared = TestVault::new()?;
        let (held, published, _) = published_held_marker(&reappeared)?;
        drop(held);
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let marker_before = fs::read(&marker_path)?;
        fs::create_dir(reappeared.root())?;
        assert!(matches!(
            super::open_existing_publication_marker_v2(published.destination()),
            Err(super::ExistingPublicationMarkerV2OpenError::NamespaceConflict)
        ));
        assert_eq!(fs::read(&marker_path)?, marker_before);
        assert!(reappeared.root().is_dir());
        fs::remove_dir(reappeared.root())?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_publication_marker_opener_missing_entries_have_zero_side_effects() -> io::Result<()>
    {
        use std::os::unix::fs::PermissionsExt as _;

        let missing_root =
            std::env::temp_dir().join(format!("inex-missing-publication-{}", uuid::Uuid::new_v4()));
        assert!(!missing_root.exists());
        assert!(super::open_existing_publication_marker_v2(&missing_root).is_err());
        assert!(!missing_root.exists());

        let missing_local = TestVault::new()?;
        let root_entries_before = fs::read_dir(missing_local.root())?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<HashSet<_>>>()?;
        assert!(super::open_existing_publication_marker_v2(missing_local.root()).is_err());
        let root_entries_after = fs::read_dir(missing_local.root())?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<HashSet<_>>>()?;
        assert_eq!(root_entries_after, root_entries_before);
        assert!(!missing_local.local().exists());

        let missing_lock = TestVault::new()?;
        fs::create_dir(missing_lock.local())?;
        let marker_canary = missing_lock.local().join(IMPORT_PUBLISH_MARKER_V2);
        fs::write(&marker_canary, b"marker-canary-must-remain")?;
        assert!(super::open_existing_publication_marker_v2(missing_lock.root()).is_err());
        assert_eq!(fs::read(&marker_canary)?, b"marker-canary-must-remain");
        assert!(!missing_lock.local().join(VAULT_MUTATION_LOCK_FILE).exists());

        let missing_marker = TestVault::new()?;
        let identities = initialize_existing_lock(missing_marker.root())?;
        let lock_path = missing_marker.local().join(VAULT_MUTATION_LOCK_FILE);
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o646))?;
        let recovery_canary = missing_marker.local().join(PENDING_REBIND_FILE);
        let staging_canary = missing_marker
            .local()
            .join(".inex-ciphertext-stage-opener-canary.tmp");
        fs::write(&recovery_canary, b"recovery-canary")?;
        fs::write(&staging_canary, b"staging-canary")?;
        assert!(super::open_existing_publication_marker_v2(missing_marker.root()).is_err());
        assert!(
            !missing_marker
                .local()
                .join(IMPORT_PUBLISH_MARKER_V2)
                .exists()
        );
        assert_eq!(fs::metadata(&lock_path)?.len(), 0);
        assert_eq!(
            fs::metadata(&lock_path)?.permissions().mode() & 0o777,
            0o646
        );
        assert_eq!(fs::read(&recovery_canary)?, b"recovery-canary");
        assert_eq!(fs::read(&staging_canary)?, b"staging-canary");
        let reacquired = ExistingVaultMutationLock::acquire(
            missing_marker.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        drop(reacquired);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_publication_marker_opener_rejects_busy_and_unsafe_locks_without_mutation()
    -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let busy = TestVault::new()?;
        let (initial, published, _) = published_held_marker(&busy)?;
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let marker_before = fs::read(&marker_path)?;
        assert!(matches!(
            super::open_existing_publication_marker_v2(published.destination()),
            Err(super::ExistingPublicationMarkerV2OpenError::Busy)
        ));
        assert_eq!(fs::read(&marker_path)?, marker_before);
        drop(initial);
        drop(
            super::open_existing_publication_marker_v2(published.destination())
                .map_err(io::Error::other)?,
        );

        let symlinked = TestVault::new()?;
        fs::create_dir(symlinked.local())?;
        let symlink_target = symlinked.local().join("lock-target-canary");
        fs::write(&symlink_target, b"symlink-target-canary")?;
        let symlink_lock = symlinked.local().join(VAULT_MUTATION_LOCK_FILE);
        symlink(&symlink_target, &symlink_lock)?;
        assert!(matches!(
            super::open_existing_publication_marker_v2(symlinked.root()),
            Err(super::ExistingPublicationMarkerV2OpenError::UnsafeLock)
        ));
        assert_eq!(fs::read(&symlink_target)?, b"symlink-target-canary");
        assert_eq!(fs::read_link(&symlink_lock)?, symlink_target);

        let hardlinked = TestVault::new()?;
        fs::create_dir(hardlinked.local())?;
        let hardlink_source = hardlinked.local().join("lock-hardlink-canary");
        let hardlink_lock = hardlinked.local().join(VAULT_MUTATION_LOCK_FILE);
        fs::write(&hardlink_source, [])?;
        fs::hard_link(&hardlink_source, &hardlink_lock)?;
        assert!(matches!(
            super::open_existing_publication_marker_v2(hardlinked.root()),
            Err(super::ExistingPublicationMarkerV2OpenError::UnsafeLock)
        ));
        assert_eq!(fs::metadata(&hardlink_source)?.len(), 0);
        assert_eq!(fs::metadata(&hardlink_lock)?.len(), 0);

        let nonzero = TestVault::new()?;
        fs::create_dir(nonzero.local())?;
        let nonzero_lock = nonzero.local().join(VAULT_MUTATION_LOCK_FILE);
        fs::write(&nonzero_lock, b"nonzero-lock-canary")?;
        assert!(matches!(
            super::open_existing_publication_marker_v2(nonzero.root()),
            Err(super::ExistingPublicationMarkerV2OpenError::UnsafeLock)
        ));
        assert_eq!(fs::read(&nonzero_lock)?, b"nonzero-lock-canary");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_publication_marker_opener_rejects_marker_drift_aliases_and_extras() -> io::Result<()>
    {
        let drifted = TestVault::new()?;
        let (held, published, _) = published_held_marker(&drifted)?;
        drop(held);
        let marker_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        fs::write(&marker_path, b"drifted-marker-canary")?;
        assert!(super::open_existing_publication_marker_v2(published.destination()).is_err());
        assert_eq!(fs::read(&marker_path)?, b"drifted-marker-canary");

        let aliased = TestVault::new()?;
        let (held, published, _) = published_held_marker(&aliased)?;
        drop(held);
        let exact_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let exact_before = fs::read(&exact_path)?;
        let alias_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join("IMPORT-PUBLISH-MARKER-V2");
        fs::write(&alias_path, b"alias-canary")?;
        assert!(matches!(
            super::open_existing_publication_marker_v2(published.destination()),
            Err(super::ExistingPublicationMarkerV2OpenError::NamespaceConflict)
        ));
        assert_eq!(fs::read(&exact_path)?, exact_before);
        assert_eq!(fs::read(&alias_path)?, b"alias-canary");

        let extra = TestVault::new()?;
        let (held, published, _) = published_held_marker(&extra)?;
        drop(held);
        let exact_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let exact_before = fs::read(&exact_path)?;
        let extra_path = published
            .destination()
            .join(VAULT_LOCAL_DIRECTORY)
            .join("import-publish-marker-foreign");
        fs::write(&extra_path, b"extra-canary")?;
        assert!(matches!(
            super::open_existing_publication_marker_v2(published.destination()),
            Err(super::ExistingPublicationMarkerV2OpenError::NamespaceConflict)
        ));
        assert_eq!(fs::read(&exact_path)?, exact_before);
        assert_eq!(fs::read(&extra_path)?, b"extra-canary");

        let redacted = super::ExistingPublicationMarkerV2OpenError::Io(io::ErrorKind::Other);
        assert_eq!(
            format!("{redacted:?}"),
            "ExistingPublicationMarkerV2OpenError::Io(..)"
        );
        assert!(std::error::Error::source(&redacted).is_none());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn existing_publication_marker_opener_is_uniform_and_fails_closed_off_linux() {
        let opener: fn(
            &Path,
        ) -> Result<
            super::HeldPublicationMarkerV2,
            super::ExistingPublicationMarkerV2OpenError,
        > = super::open_existing_publication_marker_v2;
        assert!(matches!(
            opener(Path::new("unsupported-existing-publication")),
            Err(super::ExistingPublicationMarkerV2OpenError::Unsupported)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_rejects_occupied_destination_before_create() -> io::Result<()> {
        let occupied = TestVault::new()?;
        let common_parent_path = occupied
            .root()
            .parent()
            .ok_or_else(|| io::Error::other("test root has no parent"))?;
        let common_parent = super::filesystem_directory_identity(common_parent_path)?;
        let destination_name = format!(
            "inex-held-marker-occupied-{}",
            uuid::Uuid::new_v4().simple()
        );
        let destination = common_parent_path.join(&destination_name);
        fs::write(&destination, b"foreign-destination-canary")?;
        assert!(matches!(
            try_create_test_held_marker(occupied.root(), &destination_name)?,
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert_eq!(
            common_parent,
            super::filesystem_directory_identity(common_parent_path)?
        );
        assert_eq!(fs::read(&destination)?, b"foreign-destination-canary");
        assert!(!occupied.local().join(IMPORT_PUBLISH_MARKER_V2).exists());
        fs::remove_file(&destination)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_rejects_unsafe_destination_entries_before_create() -> io::Result<()>
    {
        use std::os::unix::fs::symlink;

        let occupied_directory = TestVault::new()?;
        let parent = occupied_directory
            .root()
            .parent()
            .ok_or_else(|| io::Error::other("test root has no parent"))?;
        let directory_name = format!("inex-dest-dir-{}", uuid::Uuid::new_v4().simple());
        let directory = parent.join(&directory_name);
        fs::create_dir(&directory)?;
        assert!(matches!(
            try_create_test_held_marker(occupied_directory.root(), &directory_name)?,
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert!(directory.is_dir());
        assert!(
            !occupied_directory
                .local()
                .join(IMPORT_PUBLISH_MARKER_V2)
                .exists()
        );
        fs::remove_dir(&directory)?;

        let occupied_symlink = TestVault::new()?;
        let parent = occupied_symlink
            .root()
            .parent()
            .ok_or_else(|| io::Error::other("test root has no parent"))?;
        let symlink_name = format!("inex-dest-link-{}", uuid::Uuid::new_v4().simple());
        let symlink_path = parent.join(&symlink_name);
        symlink(occupied_symlink.root(), &symlink_path)?;
        assert!(matches!(
            try_create_test_held_marker(occupied_symlink.root(), &symlink_name)?,
            Err(super::HeldPublicationMarkerV2Error::Io(_))
        ));
        assert_eq!(fs::read_link(&symlink_path)?, occupied_symlink.root());
        assert!(
            !occupied_symlink
                .local()
                .join(IMPORT_PUBLISH_MARKER_V2)
                .exists()
        );
        fs::remove_file(&symlink_path)?;

        let occupied_hardlink = TestVault::new()?;
        let parent = occupied_hardlink
            .root()
            .parent()
            .ok_or_else(|| io::Error::other("test root has no parent"))?;
        let hardlink_nonce = uuid::Uuid::new_v4().simple();
        let hardlink_name = format!("inex-dest-hardlink-{hardlink_nonce}");
        let hardlink_source = parent.join(format!("inex-dest-hardlink-source-{hardlink_nonce}"));
        let hardlink_path = parent.join(&hardlink_name);
        fs::write(&hardlink_source, b"hardlink-destination-canary")?;
        fs::hard_link(&hardlink_source, &hardlink_path)?;
        assert!(matches!(
            try_create_test_held_marker(occupied_hardlink.root(), &hardlink_name)?,
            Err(super::HeldPublicationMarkerV2Error::Io(_))
        ));
        assert_eq!(fs::read(&hardlink_path)?, b"hardlink-destination-canary");
        assert!(
            !occupied_hardlink
                .local()
                .join(IMPORT_PUBLISH_MARKER_V2)
                .exists()
        );
        fs::remove_file(&hardlink_path)?;
        fs::remove_file(&hardlink_source)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_destination_check_retains_owner_and_lock() -> io::Result<()> {
        let appeared = TestVault::new()?;
        let common_parent_path = appeared
            .root()
            .parent()
            .ok_or_else(|| io::Error::other("test root has no parent"))?;
        let destination_name = format!(
            "inex-held-marker-appeared-{}",
            uuid::Uuid::new_v4().simple()
        );
        let destination = common_parent_path.join(&destination_name);
        let held = try_create_test_held_marker(appeared.root(), &destination_name)?
            .map_err(io::Error::other)?;
        held.require_destination_absent_at(appeared.root())
            .map_err(io::Error::other)?;
        fs::create_dir(&destination)?;
        assert!(matches!(
            held.require_destination_absent_at(appeared.root()),
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert!(appeared.local().join(IMPORT_PUBLISH_MARKER_V2).is_file());
        let identities = ExistingLockIdentities {
            root: super::filesystem_directory_identity(appeared.root())?,
            local: super::filesystem_directory_identity(&appeared.local())?,
            lock: super::filesystem_file_identity(&fs::File::open(
                appeared.local().join(VAULT_MUTATION_LOCK_FILE),
            )?)?,
        };
        assert_publication_lock_busy(appeared.root(), &identities);
        fs::remove_dir(&destination)?;
        held.require_destination_absent_at(appeared.root())
            .map_err(io::Error::other)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_rejects_invalid_input_and_reserved_alias_before_create()
    -> io::Result<()> {
        let invalid = TestVault::new()?;
        let common_parent = super::filesystem_directory_identity(
            invalid
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let (held_root, lock) = held_root_and_existing_lock(invalid.root())?;
        let mut input = held_marker_test_input(invalid.root(), &common_parent, "destination")?;
        input.publication_id = [0; 16];
        assert!(matches!(
            lock.create_held_publication_marker_v2(invalid.root(), held_root, input),
            Err(super::HeldPublicationMarkerV2Error::InvalidInput)
        ));
        assert!(!invalid.local().join(IMPORT_PUBLISH_MARKER_V2).exists());

        let aliased = TestVault::new()?;
        let identities = initialize_existing_lock(aliased.root())?;
        let alias = aliased.local().join("IMPORT-PUBLISH-MARKER-V2");
        fs::write(&alias, b"foreign-reserved-canary")?;
        let held_root = super::open_secure_source_root(aliased.root())?;
        let lock = ExistingVaultMutationLock::acquire(
            aliased.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        let common_parent = super::filesystem_directory_identity(
            aliased
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let input = held_marker_test_input(aliased.root(), &common_parent, "destination")?;
        assert!(matches!(
            lock.create_held_publication_marker_v2(aliased.root(), held_root, input),
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert_eq!(fs::read(alias)?, b"foreign-reserved-canary");
        assert!(!aliased.local().join(IMPORT_PUBLISH_MARKER_V2).exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_create_preserves_preexisting_exact_v1_and_extra_claims()
    -> io::Result<()> {
        let exact = TestVault::new()?;
        let identities = initialize_existing_lock(exact.root())?;
        let exact_path = write_canonical_publication_marker_v2(exact.root())?;
        let exact_before = fs::read(&exact_path)?;
        let held_root = super::open_secure_source_root(exact.root())?;
        let lock = ExistingVaultMutationLock::acquire(
            exact.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        let common_parent = super::filesystem_directory_identity(
            exact
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let input = held_marker_test_input(exact.root(), &common_parent, "destination")?;
        assert!(matches!(
            lock.create_held_publication_marker_v2(exact.root(), held_root, input),
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert_eq!(fs::read(&exact_path)?, exact_before);

        let legacy = TestVault::new()?;
        let identities = initialize_existing_lock(legacy.root())?;
        let legacy_path = legacy.local().join(IMPORT_PUBLISH_MARKER_V1);
        fs::write(&legacy_path, [0x42; 16])?;
        let held_root = super::open_secure_source_root(legacy.root())?;
        let lock = ExistingVaultMutationLock::acquire(
            legacy.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        let common_parent = super::filesystem_directory_identity(
            legacy
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let input = held_marker_test_input(legacy.root(), &common_parent, "destination")?;
        assert!(matches!(
            lock.create_held_publication_marker_v2(legacy.root(), held_root, input),
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert_eq!(fs::read(&legacy_path)?, [0x42; 16]);
        assert!(!legacy.local().join(IMPORT_PUBLISH_MARKER_V2).exists());

        let multiple = TestVault::new()?;
        let identities = initialize_existing_lock(multiple.root())?;
        let exact_path = write_canonical_publication_marker_v2(multiple.root())?;
        let exact_before = fs::read(&exact_path)?;
        let extra_path = multiple.local().join("import-publish-marker-foreign");
        fs::write(&extra_path, b"foreign-reserved-canary")?;
        let held_root = super::open_secure_source_root(multiple.root())?;
        let lock = ExistingVaultMutationLock::acquire(
            multiple.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        let common_parent = super::filesystem_directory_identity(
            multiple
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let input = held_marker_test_input(multiple.root(), &common_parent, "destination")?;
        assert!(matches!(
            lock.create_held_publication_marker_v2(multiple.root(), held_root, input),
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert_eq!(fs::read(exact_path)?, exact_before);
        assert_eq!(fs::read(extra_path)?, b"foreign-reserved-canary");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_revalidation_rejects_body_and_link_drift() -> io::Result<()> {
        let tampered = TestVault::new()?;
        let common_parent = super::filesystem_directory_identity(
            tampered
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let (held_root, lock) = held_root_and_existing_lock(tampered.root())?;
        let input = held_marker_test_input(tampered.root(), &common_parent, "destination")?;
        let held = lock
            .create_held_publication_marker_v2(tampered.root(), held_root, input)
            .map_err(io::Error::other)?;
        fs::write(
            tampered.local().join(IMPORT_PUBLISH_MARKER_V2),
            b"not-canonical",
        )?;
        assert!(held.revalidate_at(tampered.root()).is_err());
        drop(held);

        let linked = TestVault::new()?;
        let common_parent = super::filesystem_directory_identity(
            linked
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let (held_root, lock) = held_root_and_existing_lock(linked.root())?;
        let input = held_marker_test_input(linked.root(), &common_parent, "destination")?;
        let held = lock
            .create_held_publication_marker_v2(linked.root(), held_root, input)
            .map_err(io::Error::other)?;
        let marker_path = linked.local().join(IMPORT_PUBLISH_MARKER_V2);
        fs::hard_link(&marker_path, linked.local().join("marker-hardlink"))?;
        assert!(held.revalidate_at(linked.root()).is_err());
        assert!(marker_path.exists());

        let grown = TestVault::new()?;
        let common_parent = super::filesystem_directory_identity(
            grown
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let (held_root, lock) = held_root_and_existing_lock(grown.root())?;
        let input = held_marker_test_input(grown.root(), &common_parent, "destination")?;
        let held = lock
            .create_held_publication_marker_v2(grown.root(), held_root, input)
            .map_err(io::Error::other)?;
        let marker_path = grown.local().join(IMPORT_PUBLISH_MARKER_V2);
        let mut append = fs::OpenOptions::new().append(true).open(&marker_path)?;
        append.write_all(b"trailing")?;
        append.sync_all()?;
        drop(append);
        assert!(held.revalidate_at(grown.root()).is_err());
        drop(held);

        let replaced = TestVault::new()?;
        let common_parent = super::filesystem_directory_identity(
            replaced
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let (held_root, lock) = held_root_and_existing_lock(replaced.root())?;
        let input = held_marker_test_input(replaced.root(), &common_parent, "destination")?;
        let held = lock
            .create_held_publication_marker_v2(replaced.root(), held_root, input)
            .map_err(io::Error::other)?;
        let marker_path = replaced.local().join(IMPORT_PUBLISH_MARKER_V2);
        let retired_path = replaced.local().join("retired-marker-canary");
        let canonical = held.marker().to_bytes();
        fs::rename(&marker_path, &retired_path)?;
        fs::write(&marker_path, &canonical)?;
        assert!(held.revalidate_at(replaced.root()).is_err());
        assert_eq!(fs::read(&marker_path)?, canonical);
        assert!(retired_path.exists());
        drop(held);

        let extra = TestVault::new()?;
        let common_parent = super::filesystem_directory_identity(
            extra
                .root()
                .parent()
                .ok_or_else(|| io::Error::other("test root has no parent"))?,
        )?;
        let (held_root, lock) = held_root_and_existing_lock(extra.root())?;
        let input = held_marker_test_input(extra.root(), &common_parent, "destination")?;
        let held = lock
            .create_held_publication_marker_v2(extra.root(), held_root, input)
            .map_err(io::Error::other)?;
        let extra_path = extra.local().join("import-publish-marker-foreign");
        fs::write(&extra_path, b"foreign-reserved-canary")?;
        assert!(matches!(
            held.revalidate_at(extra.root()),
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert_eq!(fs::read(extra_path)?, b"foreign-reserved-canary");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_marker_revalidates_after_external_whole_root_rename() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let common_parent_path = fixture
            .root()
            .parent()
            .ok_or_else(|| io::Error::other("test root has no parent"))?;
        let common_parent = super::filesystem_directory_identity(common_parent_path)?;
        let destination_name = format!("inex-held-marker-dest-{}", uuid::Uuid::new_v4().simple());
        let destination = common_parent_path.join(&destination_name);
        let (held_root, lock) = held_root_and_existing_lock(fixture.root())?;
        let input = held_marker_test_input(fixture.root(), &common_parent, &destination_name)?;
        let held = lock
            .create_held_publication_marker_v2(fixture.root(), held_root, input)
            .map_err(io::Error::other)?;
        assert!(matches!(
            held.require_published_at(fixture.root()),
            Err(super::HeldPublicationMarkerV2Error::AuthorityChanged)
        ));

        fs::rename(fixture.root(), &destination)?;
        assert!(held.revalidate_at(fixture.root()).is_err());
        held.revalidate_at(&destination).map_err(io::Error::other)?;
        held.require_published_at(&destination)
            .map_err(io::Error::other)?;
        assert!(matches!(
            held.require_destination_absent_at(&destination),
            Err(super::HeldPublicationMarkerV2Error::AuthorityChanged)
        ));
        fs::create_dir(fixture.root())?;
        assert!(matches!(
            held.require_published_at(&destination),
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert!(fixture.root().is_dir());
        fs::remove_dir(fixture.root())?;
        held.require_published_at(&destination)
            .map_err(io::Error::other)?;
        let current_root = held
            .held_root_view_at(&destination)
            .map_err(io::Error::other)?;
        assert_eq!(current_root.identity(), held.root_identity());
        current_root.verify_no_alternate_data_streams()?;
        drop(current_root);
        fs::rename(&destination, fixture.root())?;
        held.revalidate_at(fixture.root())
            .map_err(io::Error::other)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_durability_is_handle_only_root_then_parent_and_role_gated() -> io::Result<()>
    {
        let staging = TestVault::new()?;
        let destination_name = format!("published-{}", uuid::Uuid::new_v4().simple());
        let staging_held = try_create_test_held_marker(staging.root(), &destination_name)?
            .map_err(io::Error::other)?;
        let mut staging_sync_called = false;
        assert!(matches!(
            staging_held.synchronize_published_root_and_common_parent_at_with_hook(
                staging.root(),
                |_| {
                    staging_sync_called = true;
                    Ok(())
                },
            ),
            Err(super::HeldPublicationMarkerV2Error::AuthorityChanged)
        ));
        assert!(!staging_sync_called);
        drop(staging_held);

        let fixture = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&fixture)?;
        let mut sync_order = Vec::new();
        held.synchronize_published_root_and_common_parent_at_with_hook(
            published.destination(),
            |point| {
                sync_order.push(point);
                Ok(())
            },
        )
        .map_err(io::Error::other)?;
        assert_eq!(
            sync_order,
            [
                super::PublishedDurabilitySyncPoint::Root,
                super::PublishedDurabilitySyncPoint::CommonParent,
            ]
        );
        held.require_published_at(published.destination())
            .map_err(io::Error::other)?;
        assert_publication_lock_busy(published.destination(), &identities);

        let source = include_str!("atomic.rs");
        let public_sync_method =
            ["pub fn synchronize_published_root_", "and_common_parent_at"].concat();
        let durability_impl = source
            .split(&public_sync_method)
            .nth(1)
            .and_then(|tail| {
                tail.split("/// Borrow the validated canonical marker value")
                    .next()
            })
            .expect("published durability implementation source exists");
        assert!(!durability_impl.contains("sync_directory("));
        assert_eq!(
            durability_impl
                .matches("platform::sync_directory_handle")
                .count(),
            2
        );
        let root_sync = durability_impl
            .find("&self.authority.root.file")
            .expect("held-root sync exists");
        let parent_sync = durability_impl
            .find("&self.authority.common_parent.file")
            .expect("held-common-parent sync exists");
        assert!(root_sync < parent_sync);
        assert_eq!(source.matches(&public_sync_method).count(), 1);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_durability_faults_retain_owner_and_order() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let (held, published, identities) = published_held_marker(&fixture)?;
        let expected_marker = held.marker().to_bytes();

        let mut root_fault_order = Vec::new();
        let root_fault = held
            .synchronize_published_root_and_common_parent_at_with_hook(
                published.destination(),
                |point| {
                    root_fault_order.push(point);
                    Err(io::Error::other("synthetic held-root sync fault"))
                },
            )
            .expect_err("held-root fault must stop before the common-parent barrier");
        assert!(matches!(
            root_fault,
            super::HeldPublicationMarkerV2Error::Io(_)
        ));
        assert_eq!(
            root_fault_order,
            [super::PublishedDurabilitySyncPoint::Root]
        );
        assert_eq!(held.marker().to_bytes(), expected_marker);
        held.require_published_at(published.destination())
            .map_err(io::Error::other)?;
        assert_publication_lock_busy(published.destination(), &identities);

        let mut parent_fault_order = Vec::new();
        let parent_fault = held
            .synchronize_published_root_and_common_parent_at_with_hook(
                published.destination(),
                |point| {
                    parent_fault_order.push(point);
                    if point == super::PublishedDurabilitySyncPoint::CommonParent {
                        Err(io::Error::other("synthetic held-parent sync fault"))
                    } else {
                        Ok(())
                    }
                },
            )
            .expect_err("held-parent fault must retain the same publication owner");
        assert!(matches!(
            parent_fault,
            super::HeldPublicationMarkerV2Error::Io(_)
        ));
        assert_eq!(
            parent_fault_order,
            [
                super::PublishedDurabilitySyncPoint::Root,
                super::PublishedDurabilitySyncPoint::CommonParent,
            ]
        );
        assert_eq!(held.marker().to_bytes(), expected_marker);
        held.require_published_at(published.destination())
            .map_err(io::Error::other)?;
        assert_publication_lock_busy(published.destination(), &identities);

        held.synchronize_published_root_and_common_parent_at(published.destination())
            .map_err(io::Error::other)?;
        assert_eq!(held.marker().to_bytes(), expected_marker);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_publication_durability_rejects_staging_reappearance_after_role_gate() -> io::Result<()>
    {
        let fixture = TestVault::new()?;
        let staging_path = fixture.root().to_path_buf();
        let (held, published, identities) = published_held_marker(&fixture)?;
        let expected_marker = held.marker().to_bytes();
        let mut sync_order = Vec::new();

        let outcome = held.synchronize_published_root_and_common_parent_at_with_hook(
            published.destination(),
            |point| {
                sync_order.push(point);
                if point == super::PublishedDurabilitySyncPoint::Root {
                    fs::create_dir(&staging_path)?;
                }
                Ok(())
            },
        );
        assert!(matches!(
            outcome,
            Err(super::HeldPublicationMarkerV2Error::NamespaceConflict)
        ));
        assert_eq!(sync_order, [super::PublishedDurabilitySyncPoint::Root]);
        assert!(staging_path.is_dir());
        assert_eq!(held.marker().to_bytes(), expected_marker);
        assert_publication_lock_busy(published.destination(), &identities);

        fs::remove_dir(&staging_path)?;
        held.synchronize_published_root_and_common_parent_at(published.destination())
            .map_err(io::Error::other)?;
        held.require_published_at(published.destination())
            .map_err(io::Error::other)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn publication_namespace_classifier_freezes_all_routing_classes() -> io::Result<()> {
        let absent = TestVault::new()?;
        assert_eq!(
            inspect_repository_publication_namespace(absent.root()).map_err(io::Error::other)?,
            RepositoryPublicationNamespaceState::Absent
        );
        assert!(!absent.local().exists());

        let legacy = TestVault::new()?;
        fs::create_dir(legacy.local())?;
        fs::write(legacy.local().join(IMPORT_PUBLISH_MARKER_V1), [3_u8; 16])?;
        assert_eq!(
            inspect_repository_publication_namespace(legacy.root()).map_err(io::Error::other)?,
            RepositoryPublicationNamespaceState::LegacyUnverifiable
        );

        let legacy_unsafe = TestVault::new()?;
        fs::create_dir(legacy_unsafe.local())?;
        fs::write(
            legacy_unsafe.local().join(IMPORT_PUBLISH_MARKER_V1),
            [3_u8; 15],
        )?;
        assert_eq!(
            inspect_repository_publication_namespace(legacy_unsafe.root())
                .map_err(io::Error::other)?,
            RepositoryPublicationNamespaceState::ReservedConflict
        );

        let malformed = TestVault::new()?;
        fs::create_dir(malformed.local())?;
        fs::write(malformed.local().join(IMPORT_PUBLISH_MARKER_V2), b"bad")?;
        assert_eq!(
            inspect_repository_publication_namespace(malformed.root()).map_err(io::Error::other)?,
            RepositoryPublicationNamespaceState::V2Invalid
        );

        let exact = TestVault::new()?;
        write_canonical_publication_marker_v2(exact.root())?;
        assert_eq!(
            inspect_repository_publication_namespace(exact.root()).map_err(io::Error::other)?,
            RepositoryPublicationNamespaceState::V2Exact
        );

        let alias = TestVault::new()?;
        fs::create_dir(alias.local())?;
        fs::write(
            alias.local().join("IMPORT-PUBLISH-MARKER-V2"),
            b"reserved alias",
        )?;
        assert_eq!(
            inspect_repository_publication_namespace(alias.root()).map_err(io::Error::other)?,
            RepositoryPublicationNamespaceState::ReservedConflict
        );

        let multiple = TestVault::new()?;
        fs::create_dir(multiple.local())?;
        fs::write(multiple.local().join(IMPORT_PUBLISH_MARKER_V1), [1_u8; 16])?;
        fs::write(multiple.local().join(IMPORT_PUBLISH_MARKER_V2), b"bad")?;
        assert_eq!(
            inspect_repository_publication_namespace(multiple.root()).map_err(io::Error::other)?,
            RepositoryPublicationNamespaceState::ReservedConflict
        );
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn publication_barrier_prevents_lock_creation_for_existing_claims() -> io::Result<()> {
        let exact = TestVault::new()?;
        write_canonical_publication_marker_v2(exact.root())?;
        let lock_path = exact.local().join(VAULT_MUTATION_LOCK_FILE);
        assert!(matches!(
            VaultMutationGuard::acquire(exact.root()),
            Err(AtomicWriteError::RepositoryPublicationReconcileRequired)
        ));
        assert!(!lock_path.exists());

        let legacy = TestVault::new()?;
        fs::create_dir(legacy.local())?;
        fs::write(legacy.local().join(IMPORT_PUBLISH_MARKER_V1), [9_u8; 16])?;
        let lock_path = legacy.local().join(VAULT_MUTATION_LOCK_FILE);
        assert!(matches!(
            VaultMutationGuard::acquire(legacy.root()),
            Err(AtomicWriteError::RepositoryPublicationManualAuditRequired)
        ));
        assert!(!lock_path.exists());
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    struct MarkerBetweenBarrierChecks {
        marker: PathBuf,
    }

    #[cfg(any(target_os = "linux", windows))]
    impl FaultInjector for MarkerBetweenBarrierChecks {
        fn check(&self, point: FaultPoint) -> io::Result<()> {
            if point == FaultPoint::PrepareLock {
                fs::write(&self.marker, [5_u8; 16])?;
            }
            Ok(())
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn publication_barrier_rechecks_under_lock_before_recovery() -> io::Result<()> {
        let fixture = TestVault::new()?;
        initialize_existing_lock(fixture.root())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(fixture.local(), fs::Permissions::from_mode(0o751))?;
            fs::set_permissions(
                fixture.local().join(VAULT_MUTATION_LOCK_FILE),
                fs::Permissions::from_mode(0o640),
            )?;
        }
        let staging = exact_staging_path(&fixture.local(), 'c');
        fs::write(&staging, b"encrypted recovery canary")?;
        let fault = MarkerBetweenBarrierChecks {
            marker: fixture.local().join(IMPORT_PUBLISH_MARKER_V1),
        };
        assert!(matches!(
            VaultMutationGuard::acquire_with_faults(fixture.root(), &fault),
            Err(AtomicWriteError::RepositoryPublicationManualAuditRequired)
        ));
        assert_eq!(fs::read(&staging)?, b"encrypted recovery canary");
        assert_eq!(fs::read(fault.marker)?, [5_u8; 16]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(fixture.local())?.permissions().mode() & 0o777,
                0o751
            );
            assert_eq!(
                fs::metadata(fixture.local().join(VAULT_MUTATION_LOCK_FILE))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o640
            );
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn existing_only_lock_preserves_mode_and_private_recovery_state() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let identities = initialize_existing_lock(fixture.root())?;
        let local = fixture.local();
        let pending = local.join(PENDING_REBIND_FILE);
        let ciphertext_staging = exact_staging_path(&local, 'a');
        let rebind_staging = local.join(format!(".inex-rebind-stage-{}", "b".repeat(32)));
        fs::write(&pending, b"pending-rebind-canary")?;
        fs::write(&ciphertext_staging, b"ciphertext-staging-canary")?;
        fs::write(&rebind_staging, b"rebind-staging-canary")?;

        #[cfg(unix)]
        let mode_before = {
            use std::os::unix::fs::PermissionsExt as _;
            fs::metadata(local.join(VAULT_MUTATION_LOCK_FILE))?
                .permissions()
                .mode()
        };

        let held = ExistingVaultMutationLock::acquire(
            fixture.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        held.revalidate(fixture.root()).map_err(io::Error::other)?;
        assert_eq!(held.root_identity(), &identities.root);
        assert_eq!(held.local_identity(), &identities.local);
        assert_eq!(held.lock_identity(), &identities.lock);
        assert_eq!(format!("{held:?}"), "ExistingVaultMutationLock { .. }");

        assert_eq!(fs::read(&pending)?, b"pending-rebind-canary");
        assert_eq!(fs::read(&ciphertext_staging)?, b"ciphertext-staging-canary");
        assert_eq!(fs::read(&rebind_staging)?, b"rebind-staging-canary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(local.join(VAULT_MUTATION_LOCK_FILE))?
                    .permissions()
                    .mode(),
                mode_before
            );
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn existing_only_lock_never_creates_missing_root_local_or_lock() -> io::Result<()> {
        let donor = TestVault::new()?;
        let donor_identities = initialize_existing_lock(donor.root())?;

        let missing_root = std::env::temp_dir().join(format!(
            "inex-existing-lock-missing-root-{}",
            uuid::Uuid::new_v4()
        ));
        let missing_error = ExistingVaultMutationLock::acquire(
            &missing_root,
            &donor_identities.root,
            &donor_identities.local,
            &donor_identities.lock,
        )
        .expect_err("a missing root must fail without creation");
        assert!(matches!(
            missing_error,
            ExistingVaultMutationLockError::Io(ref source)
                if source.kind() == io::ErrorKind::NotFound
        ));
        assert!(!missing_root.exists());
        assert!(!format!("{missing_error:?}").contains("missing-root"));

        let missing_local = TestVault::new()?;
        let missing_local_root = super::filesystem_directory_identity(missing_local.root())?;
        let missing_local_error = ExistingVaultMutationLock::acquire(
            missing_local.root(),
            &missing_local_root,
            &donor_identities.local,
            &donor_identities.lock,
        )
        .expect_err("a missing private directory must fail without creation");
        assert!(matches!(
            missing_local_error,
            ExistingVaultMutationLockError::Io(ref source)
                if source.kind() == io::ErrorKind::NotFound
        ));
        assert!(!missing_local.local().exists());

        let missing_lock = TestVault::new()?;
        fs::create_dir(missing_lock.local())?;
        let missing_lock_root = super::filesystem_directory_identity(missing_lock.root())?;
        let missing_lock_local = super::filesystem_directory_identity(&missing_lock.local())?;
        let missing_lock_path = missing_lock.local().join(VAULT_MUTATION_LOCK_FILE);
        let missing_lock_error = ExistingVaultMutationLock::acquire(
            missing_lock.root(),
            &missing_lock_root,
            &missing_lock_local,
            &donor_identities.lock,
        )
        .expect_err("a missing lock must fail without creation");
        assert!(matches!(
            missing_lock_error,
            ExistingVaultMutationLockError::Io(ref source)
                if source.kind() == io::ErrorKind::NotFound
        ));
        assert!(!missing_lock_path.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_only_lock_rejects_unsupported_mount_without_creation() -> io::Result<()> {
        let unsupported_root = Path::new("/sys/fs/fuse/connections");
        if !unsupported_root.is_dir()
            || super::path_is_supported_local_filesystem(unsupported_root)?
        {
            return Ok(());
        }
        let local = unsupported_root.join(VAULT_LOCAL_DIRECTORY);
        if local.exists() {
            return Ok(());
        }

        let donor = TestVault::new()?;
        let identities = initialize_existing_lock(donor.root())?;
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                unsupported_root,
                &identities.root,
                &identities.local,
                &identities.lock,
            ),
            Err(ExistingVaultMutationLockError::UnsafeRoot)
        ));
        assert!(!local.exists());

        let other_mount = Path::new("/dev/shm");
        if other_mount.is_dir() {
            use std::os::unix::fs::MetadataExt as _;
            if fs::metadata(donor.root())?.dev() != fs::metadata(other_mount)?.dev() {
                assert!(!super::paths_share_mount(donor.root(), other_mount)?);
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn existing_only_lock_rejects_wrong_expected_and_rebound_identities() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let identities = initialize_existing_lock(fixture.root())?;
        let donor = TestVault::new()?;
        let donor_identities = initialize_existing_lock(donor.root())?;

        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                fixture.root(),
                &donor_identities.root,
                &identities.local,
                &identities.lock,
            ),
            Err(ExistingVaultMutationLockError::RootIdentityMismatch)
        ));
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                fixture.root(),
                &identities.root,
                &donor_identities.local,
                &identities.lock,
            ),
            Err(ExistingVaultMutationLockError::LocalIdentityMismatch)
        ));
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                fixture.root(),
                &identities.root,
                &identities.local,
                &donor_identities.lock,
            ),
            Err(ExistingVaultMutationLockError::LockIdentityMismatch)
        ));

        let lock_path = fixture.local().join(VAULT_MUTATION_LOCK_FILE);
        let retired = fixture.local().join("retired-existing-lock");
        fs::rename(&lock_path, &retired)?;
        fs::write(&lock_path, [])?;
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                fixture.root(),
                &identities.root,
                &identities.local,
                &identities.lock,
            ),
            Err(ExistingVaultMutationLockError::LockIdentityMismatch)
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_only_lock_rejects_symlink_hardlink_and_nonzero_lock() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let nonzero = TestVault::new()?;
        let nonzero_identities = initialize_existing_lock(nonzero.root())?;
        fs::write(nonzero.local().join(VAULT_MUTATION_LOCK_FILE), b"not-empty")?;
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                nonzero.root(),
                &nonzero_identities.root,
                &nonzero_identities.local,
                &nonzero_identities.lock,
            ),
            Err(ExistingVaultMutationLockError::UnsafeLock)
        ));

        let hardlink = TestVault::new()?;
        let hardlink_identities = initialize_existing_lock(hardlink.root())?;
        let hardlink_lock = hardlink.local().join(VAULT_MUTATION_LOCK_FILE);
        fs::hard_link(&hardlink_lock, hardlink.local().join("lock-alias"))?;
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                hardlink.root(),
                &hardlink_identities.root,
                &hardlink_identities.local,
                &hardlink_identities.lock,
            ),
            Err(ExistingVaultMutationLockError::UnsafeLock)
        ));

        let symlinked = TestVault::new()?;
        let symlink_identities = initialize_existing_lock(symlinked.root())?;
        let symlink_lock = symlinked.local().join(VAULT_MUTATION_LOCK_FILE);
        let actual = symlinked.local().join("actual-lock");
        fs::rename(&symlink_lock, &actual)?;
        symlink(&actual, &symlink_lock)?;
        assert!(
            ExistingVaultMutationLock::acquire(
                symlinked.root(),
                &symlink_identities.root,
                &symlink_identities.local,
                &symlink_identities.lock,
            )
            .is_err()
        );
        assert!(
            fs::symlink_metadata(&symlink_lock)?
                .file_type()
                .is_symlink()
        );
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn existing_only_lock_reports_busy_without_waiting() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let identities = initialize_existing_lock(fixture.root())?;
        let held = ExistingVaultMutationLock::acquire(
            fixture.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;

        let started = Instant::now();
        assert!(matches!(
            ExistingVaultMutationLock::acquire(
                fixture.root(),
                &identities.root,
                &identities.local,
                &identities.lock,
            ),
            Err(ExistingVaultMutationLockError::Busy)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(held);

        drop(
            ExistingVaultMutationLock::acquire(
                fixture.root(),
                &identities.root,
                &identities.local,
                &identities.lock,
            )
            .map_err(io::Error::other)?,
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_only_lock_revalidates_after_whole_root_rename() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let identities = initialize_existing_lock(fixture.root())?;
        let held = ExistingVaultMutationLock::acquire(
            fixture.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        let original = fixture.root().to_path_buf();
        let renamed = original.with_file_name(format!(
            "inex-existing-lock-renamed-{}",
            uuid::Uuid::new_v4()
        ));

        fs::rename(&original, &renamed)?;
        assert!(held.revalidate(&original).is_err());
        held.revalidate(&renamed).map_err(io::Error::other)?;
        fs::rename(&renamed, &original)?;
        held.revalidate(&original).map_err(io::Error::other)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_only_held_lock_revalidate_rejects_path_rebind() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let identities = initialize_existing_lock(fixture.root())?;
        let held = ExistingVaultMutationLock::acquire(
            fixture.root(),
            &identities.root,
            &identities.local,
            &identities.lock,
        )
        .map_err(io::Error::other)?;
        let lock_path = fixture.local().join(VAULT_MUTATION_LOCK_FILE);
        let retired = fixture.local().join("held-retired-lock");
        fs::rename(&lock_path, &retired)?;
        fs::write(&lock_path, [])?;

        assert!(matches!(
            held.revalidate(fixture.root()),
            Err(ExistingVaultMutationLockError::LockIdentityMismatch)
        ));
        assert!(lock_path.is_file());
        assert!(retired.is_file());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn alternate_data_stream_proofs_preserve_linux_identity_checks() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let file_path = fixture.root().join("inventory-file");
        fs::write(&file_path, b"inventory")?;
        let file = fs::File::open(&file_path)?;
        verify_regular_file_has_no_alternate_data_streams(&file_path, &file)?;

        let directory = fixture.root().join("inventory-directory");
        fs::create_dir(&directory)?;
        let identity = super::filesystem_directory_identity(&directory)?;
        verify_directory_has_no_alternate_data_streams(&directory, &identity)?;

        let replacement = fixture.root().join("inventory-replacement");
        fs::write(&replacement, b"replacement")?;
        fs::rename(&replacement, &file_path)?;
        assert_eq!(
            verify_regular_file_has_no_alternate_data_streams(&file_path, &file)
                .expect_err("a rebound path must fail the stream proof")
                .kind(),
            io::ErrorKind::InvalidInput,
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn alternate_data_stream_proofs_reject_windows_file_and_directory_streams() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let file_path = fixture.root().join("inventory-file");
        fs::write(&file_path, b"inventory")?;
        let file = fs::File::open(&file_path)?;
        verify_regular_file_has_no_alternate_data_streams(&file_path, &file)?;

        let file_stream = windows_stream_path(&file_path, "inex-test");
        fs::write(&file_stream, b"hidden")?;
        assert_eq!(
            verify_regular_file_has_no_alternate_data_streams(&file_path, &file)
                .expect_err("a file ADS must fail the stream proof")
                .kind(),
            io::ErrorKind::InvalidData,
        );
        fs::remove_file(&file_stream)?;
        verify_regular_file_has_no_alternate_data_streams(&file_path, &file)?;

        let directory = fixture.root().join("inventory-directory");
        fs::create_dir(&directory)?;
        let identity = super::filesystem_directory_identity(&directory)?;
        verify_directory_has_no_alternate_data_streams(&directory, &identity)?;

        let directory_stream = windows_stream_path(&directory, "inex-test");
        fs::write(&directory_stream, b"hidden")?;
        assert_eq!(
            verify_directory_has_no_alternate_data_streams(&directory, &identity)
                .expect_err("a directory ADS must fail the stream proof")
                .kind(),
            io::ErrorKind::InvalidData,
        );
        fs::remove_file(&directory_stream)?;
        verify_directory_has_no_alternate_data_streams(&directory, &identity)?;
        Ok(())
    }

    #[cfg(windows)]
    fn windows_stream_path(path: &Path, name: &str) -> PathBuf {
        let mut stream_path = path.as_os_str().to_os_string();
        stream_path.push(format!(":{name}"));
        PathBuf::from(stream_path)
    }

    #[cfg(any(target_os = "linux", windows))]
    fn assert_verified_remove_sync_status(status: ParentSyncStatus) {
        #[cfg(target_os = "linux")]
        assert_eq!(status, ParentSyncStatus::Synced);
        #[cfg(windows)]
        assert!(matches!(
            status,
            ParentSyncStatus::Synced | ParentSyncStatus::NotSynced
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secure_source_handle_detects_intermediate_directory_identity_swap() -> io::Result<()> {
        let fixture = TestVault::new()?;
        fs::write(fixture.notes().join("original.md"), b"source")?;
        let root = super::open_secure_source_root(fixture.root())?;
        assert!(matches!(
            &root.binding,
            super::SecureSourceDirectoryBinding::Root(path) if path == fixture.root()
        ));
        let super::SecureSourceChild::Directory(notes) =
            root.open_child(std::ffi::OsStr::new("notes"))?
        else {
            return Err(io::Error::other("notes was not a secure directory"));
        };
        assert!(matches!(
            &notes.binding,
            super::SecureSourceDirectoryBinding::Child { name, .. } if name == "notes"
        ));
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
    fn held_source_file_stream_proof_rejects_symlink_and_fifo_replacements_without_blocking()
    -> io::Result<()> {
        use std::os::unix::fs::symlink;
        use std::sync::mpsc;

        fn require_fast_rejection(file: super::SecureSourceFile) -> io::Result<()> {
            let (sender, receiver) = mpsc::sync_channel(1);
            let worker = thread::spawn(move || {
                let _ = sender.send(file.verify_no_alternate_data_streams());
            });
            let result = receiver
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| io::Error::other("held stream proof blocked on replacement"))?;
            worker
                .join()
                .map_err(|_| io::Error::other("held stream proof worker panicked"))?;
            if result.is_err() {
                Ok(())
            } else {
                Err(io::Error::other("replacement unexpectedly passed"))
            }
        }

        let fixture = TestVault::new()?;
        let path = fixture.root().join("race.bin");
        let outside = fixture.root().join("outside.bin");
        fs::write(&outside, b"outside")?;
        fs::write(&path, b"baseline")?;
        let root = super::open_secure_source_root(fixture.root())?;
        let super::SecureSourceChild::File(held_for_symlink) =
            root.open_child(std::ffi::OsStr::new("race.bin"))?
        else {
            return Err(io::Error::other("baseline was not a secure file"));
        };
        fs::remove_file(&path)?;
        symlink(&outside, &path)?;
        require_fast_rejection(held_for_symlink)?;

        fs::remove_file(&path)?;
        fs::write(&path, b"baseline")?;
        let super::SecureSourceChild::File(held_for_fifo) =
            root.open_child(std::ffi::OsStr::new("race.bin"))?
        else {
            return Err(io::Error::other("restored baseline was not a secure file"));
        };
        fs::remove_file(&path)?;
        create_fifo(&path)?;
        require_fast_rejection(held_for_fifo)
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

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_directory_move_audit_receives_exact_caller_source_path() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("candidate-bundle");
        let destination = fixture.root().join("stable-bundle");
        fs::create_dir(&source)?;
        fs::write(source.join("manifest"), b"complete")?;

        let outcome = super::atomic_move_verified_directory_no_replace_checked(
            &source,
            &destination,
            |current| {
                assert_eq!(current, source);
                assert!(!current.join(VAULT_LOCAL_DIRECTORY).exists());
                Ok(())
            },
        )
        .map_err(io::Error::other)?;

        assert!(!source.exists());
        assert_eq!(fs::read(destination.join("manifest"))?, b"complete");
        assert!(matches!(
            outcome.parent_sync,
            ParentSyncStatus::Synced | ParentSyncStatus::NotSynced
        ));
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_directory_move_rejects_existing_destination() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("candidate");
        let destination = fixture.root().join("stable");
        fs::create_dir(&source)?;
        fs::create_dir(&destination)?;
        fs::write(source.join("identity"), b"source")?;
        fs::write(destination.join("identity"), b"foreign")?;

        assert!(matches!(
            super::atomic_move_verified_directory_no_replace_checked(
                &source,
                &destination,
                |_| Ok(())
            ),
            Err(AtomicDirectoryPublishError::DestinationExists)
        ));
        assert_eq!(fs::read(source.join("identity"))?, b"source");
        assert_eq!(fs::read(destination.join("identity"))?, b"foreign");
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_directory_move_classifies_foreign_destination_after_audit() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("candidate");
        let destination = fixture.root().join("stable");
        fs::create_dir(&source)?;

        assert!(matches!(
            super::atomic_move_verified_directory_no_replace_checked(&source, &destination, |_| {
                fs::create_dir(&destination)?;
                Ok(())
            }),
            Err(AtomicDirectoryPublishError::DestinationExists)
        ));
        assert!(source.is_dir());
        assert!(destination.is_dir());
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_directory_move_rejects_source_identity_swap_after_audit() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("candidate");
        let destination = fixture.root().join("stable");
        let retired = fixture.root().join("retired-candidate");
        fs::create_dir(&source)?;

        assert!(matches!(
            super::atomic_move_verified_directory_no_replace_checked(
                &source,
                &destination,
                |current| {
                    fs::rename(current, &retired).and_then(|()| fs::create_dir(current))?;
                    Ok(())
                }
            ),
            Err(AtomicDirectoryPublishError::Indeterminate)
        ));
        assert!(source.is_dir());
        assert!(retired.is_dir());
        assert!(!destination.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_directory_move_rejects_parent_identity_swap_after_audit() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let parent = fixture.root().join("bundle-parent");
        let source = parent.join("candidate");
        let destination = parent.join("stable");
        let retired = fixture.root().join("retired-bundle-parent");
        fs::create_dir_all(&source)?;

        assert!(matches!(
            super::atomic_move_verified_directory_no_replace_checked(&source, &destination, |_| {
                fs::rename(&parent, &retired).and_then(|()| fs::create_dir(&parent))?;
                Ok(())
            }),
            Err(AtomicDirectoryPublishError::Indeterminate)
        ));
        assert!(retired.join("candidate").is_dir());
        assert!(!destination.exists());
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_directory_move_classifies_error_before_move_as_not_moved() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("candidate");
        let destination = fixture.root().join("stable");
        fs::create_dir(&source)?;

        assert!(matches!(
            super::atomic_move_verified_directory_no_replace_checked_with_faults(
                &source,
                &destination,
                |_| Ok(()),
                super::DirectoryMoveFault::BeforeMove
            ),
            Err(AtomicDirectoryPublishError::NotMoved)
        ));
        assert!(source.is_dir());
        assert!(!destination.exists());
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_directory_move_reconciles_error_after_move() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let source = fixture.root().join("candidate");
        let destination = fixture.root().join("stable");
        fs::create_dir(&source)?;
        fs::write(source.join("manifest"), b"complete")?;

        super::atomic_move_verified_directory_no_replace_checked_with_faults(
            &source,
            &destination,
            |_| Ok(()),
            super::DirectoryMoveFault::AfterMove,
        )
        .map_err(io::Error::other)?;
        assert!(!source.exists());
        assert_eq!(fs::read(destination.join("manifest"))?, b"complete");
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_directory_move_reports_unconfirmed_directory_or_parent_sync() -> io::Result<()> {
        let fixture = TestVault::new()?;
        for (suffix, fault) in [
            ("directory", super::DirectoryMoveFault::DirectorySync),
            ("parent", super::DirectoryMoveFault::ParentSync),
        ] {
            let source = fixture.root().join(format!("candidate-{suffix}"));
            let destination = fixture.root().join(format!("stable-{suffix}"));
            fs::create_dir(&source)?;
            let outcome = super::atomic_move_verified_directory_no_replace_checked_with_faults(
                &source,
                &destination,
                |_| Ok(()),
                fault,
            )
            .map_err(io::Error::other)?;
            assert_eq!(outcome.parent_sync, ParentSyncStatus::NotSynced);
            assert!(!source.exists());
            assert!(destination.is_dir());
        }
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
    fn opaque_file_identity_distinguishes_bytes_and_survives_rename() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let first = fixture.root().join("identity-first");
        let second = fixture.root().join("identity-second");
        let renamed = fixture.root().join("identity-renamed");
        fs::write(&first, b"byte-identical")?;
        fs::write(&second, b"byte-identical")?;
        let first_file = fs::File::open(&first)?;
        let second_file = fs::File::open(&second)?;
        let first_identity = super::filesystem_file_identity(&first_file)?;
        let second_identity = super::filesystem_file_identity(&second_file)?;
        assert_ne!(first_identity, second_identity);
        assert!(super::path_matches_file_identity_and_is_single_link(
            &first,
            &first_identity,
        )?);
        assert!(!super::path_matches_file_identity_and_is_single_link(
            &second,
            &first_identity,
        )?);

        drop(first_file);
        fs::rename(&first, &renamed)?;
        assert!(super::path_matches_file_identity_and_is_single_link(
            &renamed,
            &first_identity,
        )?);
        assert!(matches!(
            super::path_matches_file_identity_and_is_single_link(&first, &first_identity),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        ));

        let alias = fixture.root().join("identity-hardlink");
        fs::hard_link(&renamed, &alias)?;
        assert!(!super::path_matches_file_identity_and_is_single_link(
            &renamed,
            &first_identity,
        )?);
        assert!(super::filesystem_file_identity(&fs::File::open(&renamed)?).is_err());
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

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_remove_deletes_only_the_held_single_link_file() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let path = fixture.root().join("cleanup-receipt");
        fs::write(&path, b"canonical receipt")?;
        let held = fs::File::open(&path)?;

        let outcome = super::atomic_remove_verified_file(&path, held).map_err(io::Error::other)?;

        assert!(!path.exists());
        assert_verified_remove_sync_status(outcome.parent_sync);
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_remove_reconciles_removed_not_removed_and_unsynced() -> io::Result<()> {
        let fixture = TestVault::new()?;

        let not_removed = fixture.root().join("not-removed");
        fs::write(&not_removed, b"receipt")?;
        let not_removed_file = fs::File::open(&not_removed)?;
        assert!(matches!(
            super::atomic_remove_verified_file_with_faults(
                &not_removed,
                not_removed_file,
                |_| Ok(()),
                |_| Ok(()),
                super::VerifiedRemoveFault::ErrorBeforeRemove,
            ),
            Err(super::AtomicVerifiedRemoveError::NotRemoved)
        ));
        assert_eq!(fs::read(&not_removed)?, b"receipt");

        let removed = fixture.root().join("removed-then-error");
        fs::write(&removed, b"receipt")?;
        let removed_file = fs::File::open(&removed)?;
        let outcome = super::atomic_remove_verified_file_with_faults(
            &removed,
            removed_file,
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::RemoveThenError,
        )
        .map_err(io::Error::other)?;
        assert!(!removed.exists());
        assert_verified_remove_sync_status(outcome.parent_sync);

        let unsynced = fixture.root().join("removed-unsynced");
        fs::write(&unsynced, b"receipt")?;
        let unsynced_file = fs::File::open(&unsynced)?;
        let outcome = super::atomic_remove_verified_file_with_faults(
            &unsynced,
            unsynced_file,
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::ParentSync,
        )
        .map_err(io::Error::other)?;
        assert!(!unsynced.exists());
        assert_eq!(outcome.parent_sync, ParentSyncStatus::NotSynced);
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_remove_preserves_foreign_rebinds() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let path = fixture.root().join("receipt");
        let retained = fixture.root().join("retained-receipt");
        fs::write(&path, b"owned receipt")?;
        let held = fs::File::open(&path)?;

        assert!(matches!(
            super::atomic_remove_verified_file_with_faults(
                &path,
                held,
                |current| {
                    fs::rename(current, &retained)?;
                    fs::write(current, b"foreign receipt")
                },
                |_| Ok(()),
                super::VerifiedRemoveFault::None,
            ),
            Err(super::AtomicVerifiedRemoveError::Indeterminate)
        ));
        assert_eq!(fs::read(&path)?, b"foreign receipt");
        assert_eq!(fs::read(&retained)?, b"owned receipt");

        let after_path = fixture.root().join("receipt-after-remove");
        fs::write(&after_path, b"owned receipt")?;
        let after_held = fs::File::open(&after_path)?;
        assert!(matches!(
            super::atomic_remove_verified_file_with_faults(
                &after_path,
                after_held,
                |_| Ok(()),
                |current| fs::write(current, b"foreign after remove"),
                super::VerifiedRemoveFault::None,
            ),
            Err(super::AtomicVerifiedRemoveError::Indeterminate)
        ));
        assert_eq!(fs::read(&after_path)?, b"foreign after remove");
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_file_remove_detects_parent_identity_rebind() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let parent = fixture.root().join("cleanup-parent");
        let retired_parent = fixture.root().join("retired-cleanup-parent");
        fs::create_dir(&parent)?;
        let path = parent.join("receipt");
        fs::write(&path, b"owned receipt")?;
        let held = fs::File::open(&path)?;

        assert!(matches!(
            super::atomic_remove_verified_file_with_faults(
                &path,
                held,
                |_| {
                    fs::rename(&parent, &retired_parent)?;
                    fs::create_dir(&parent)?;
                    fs::write(parent.join("receipt"), b"foreign receipt")
                },
                |_| Ok(()),
                super::VerifiedRemoveFault::None,
            ),
            Err(super::AtomicVerifiedRemoveError::Indeterminate)
        ));
        assert_eq!(fs::read(parent.join("receipt"))?, b"foreign receipt");
        assert_eq!(fs::read(retired_parent.join("receipt"))?, b"owned receipt");

        let after_parent = fixture.root().join("cleanup-parent-after");
        let after_retired = fixture.root().join("retired-cleanup-parent-after");
        fs::create_dir(&after_parent)?;
        let after_path = after_parent.join("receipt");
        fs::write(&after_path, b"owned receipt")?;
        let after_held = fs::File::open(&after_path)?;
        assert!(matches!(
            super::atomic_remove_verified_file_with_faults(
                &after_path,
                after_held,
                |_| Ok(()),
                |_| {
                    fs::rename(&after_parent, &after_retired)?;
                    fs::create_dir(&after_parent)?;
                    fs::write(after_parent.join("receipt"), b"foreign after remove")
                },
                super::VerifiedRemoveFault::None,
            ),
            Err(super::AtomicVerifiedRemoveError::Indeterminate)
        ));
        assert_eq!(
            fs::read(after_parent.join("receipt"))?,
            b"foreign after remove"
        );
        assert!(after_retired.is_dir());
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_empty_directory_remove_reconciles_all_durable_outcomes() -> io::Result<()> {
        let fixture = TestVault::new()?;

        let removed = fixture.root().join("cleanup-empty");
        fs::create_dir(&removed)?;
        let removed_identity = super::filesystem_directory_identity(&removed)?;
        let outcome = super::atomic_remove_verified_empty_directory(&removed, &removed_identity)
            .map_err(io::Error::other)?;
        assert!(!removed.exists());
        assert_verified_remove_sync_status(outcome.parent_sync);

        let not_removed = fixture.root().join("cleanup-not-removed");
        fs::create_dir(&not_removed)?;
        let not_removed_identity = super::filesystem_directory_identity(&not_removed)?;
        assert!(matches!(
            super::atomic_remove_verified_empty_directory_with_faults(
                &not_removed,
                &not_removed_identity,
                |_| Ok(()),
                |_| Ok(()),
                super::VerifiedRemoveFault::ErrorBeforeRemove,
            ),
            Err(super::AtomicVerifiedRemoveError::NotRemoved)
        ));
        assert!(not_removed.is_dir());

        let after_error = fixture.root().join("cleanup-removed-then-error");
        fs::create_dir(&after_error)?;
        let after_error_identity = super::filesystem_directory_identity(&after_error)?;
        let outcome = super::atomic_remove_verified_empty_directory_with_faults(
            &after_error,
            &after_error_identity,
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::RemoveThenError,
        )
        .map_err(io::Error::other)?;
        assert!(!after_error.exists());
        assert_verified_remove_sync_status(outcome.parent_sync);

        let unsynced = fixture.root().join("cleanup-removed-unsynced");
        fs::create_dir(&unsynced)?;
        let unsynced_identity = super::filesystem_directory_identity(&unsynced)?;
        let outcome = super::atomic_remove_verified_empty_directory_with_faults(
            &unsynced,
            &unsynced_identity,
            |_| Ok(()),
            |_| Ok(()),
            super::VerifiedRemoveFault::ParentSync,
        )
        .map_err(io::Error::other)?;
        assert!(!unsynced.exists());
        assert_eq!(outcome.parent_sync, ParentSyncStatus::NotSynced);
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_empty_directory_remove_rejects_nonempty_and_foreign_rebinds() -> io::Result<()> {
        let fixture = TestVault::new()?;

        let nonempty = fixture.root().join("cleanup-nonempty");
        fs::create_dir(&nonempty)?;
        fs::write(nonempty.join("manifest"), b"owned manifest")?;
        let nonempty_identity = super::filesystem_directory_identity(&nonempty)?;
        assert!(matches!(
            super::atomic_remove_verified_empty_directory(&nonempty, &nonempty_identity),
            Err(super::AtomicVerifiedRemoveError::InvalidPath)
        ));
        assert_eq!(fs::read(nonempty.join("manifest"))?, b"owned manifest");

        let rebound = fixture.root().join("cleanup-rebound");
        let retained = fixture.root().join("retained-cleanup");
        fs::create_dir(&rebound)?;
        let rebound_identity = super::filesystem_directory_identity(&rebound)?;
        assert!(matches!(
            super::atomic_remove_verified_empty_directory_with_faults(
                &rebound,
                &rebound_identity,
                |current| {
                    fs::rename(current, &retained)?;
                    fs::create_dir(current)?;
                    fs::write(current.join("foreign"), b"foreign directory")
                },
                |_| Ok(()),
                super::VerifiedRemoveFault::None,
            ),
            Err(super::AtomicVerifiedRemoveError::Indeterminate)
        ));
        assert_eq!(fs::read(rebound.join("foreign"))?, b"foreign directory");
        assert!(retained.is_dir());

        let after_rebound = fixture.root().join("cleanup-after-remove");
        fs::create_dir(&after_rebound)?;
        let after_identity = super::filesystem_directory_identity(&after_rebound)?;
        assert!(matches!(
            super::atomic_remove_verified_empty_directory_with_faults(
                &after_rebound,
                &after_identity,
                |_| Ok(()),
                |current| {
                    fs::create_dir(current)?;
                    fs::write(current.join("foreign"), b"foreign after remove")
                },
                super::VerifiedRemoveFault::None,
            ),
            Err(super::AtomicVerifiedRemoveError::Indeterminate)
        ));
        assert_eq!(
            fs::read(after_rebound.join("foreign"))?,
            b"foreign after remove"
        );

        let parent = fixture.root().join("directory-parent-after-remove");
        let retired_parent = fixture.root().join("retired-directory-parent-after-remove");
        fs::create_dir(&parent)?;
        let directory = parent.join("cleanup");
        fs::create_dir(&directory)?;
        let directory_identity = super::filesystem_directory_identity(&directory)?;
        assert!(matches!(
            super::atomic_remove_verified_empty_directory_with_faults(
                &directory,
                &directory_identity,
                |_| Ok(()),
                |_| {
                    fs::rename(&parent, &retired_parent)?;
                    fs::create_dir(&parent)?;
                    fs::create_dir(parent.join("cleanup"))?;
                    fs::write(parent.join("cleanup/foreign"), b"foreign parent")
                },
                super::VerifiedRemoveFault::None,
            ),
            Err(super::AtomicVerifiedRemoveError::Indeterminate)
        ));
        assert_eq!(fs::read(parent.join("cleanup/foreign"))?, b"foreign parent");
        assert!(retired_parent.is_dir());
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn verified_remove_rejects_hardlinked_file() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let file = fixture.root().join("receipt");
        let alias = fixture.root().join("receipt-alias");
        fs::write(&file, b"receipt")?;
        fs::hard_link(&file, &alias)?;
        let held = fs::File::open(&file)?;
        assert!(matches!(
            super::atomic_remove_verified_file(&file, held),
            Err(super::AtomicVerifiedRemoveError::InvalidPath)
        ));
        assert_eq!(fs::read(&file)?, b"receipt");
        assert_eq!(fs::read(&alias)?, b"receipt");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_remove_rejects_file_and_directory_symlinks() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = TestVault::new()?;
        let symlink_target = fixture.root().join("receipt-symlink-target");
        let symlink_file = fixture.root().join("receipt-symlink");
        fs::write(&symlink_target, b"receipt")?;
        symlink(&symlink_target, &symlink_file)?;
        let symlink_held = fs::File::open(&symlink_file)?;
        assert!(matches!(
            super::atomic_remove_verified_file(&symlink_file, symlink_held),
            Err(super::AtomicVerifiedRemoveError::InvalidPath)
        ));
        assert!(symlink_file.is_symlink());
        assert_eq!(fs::read(&symlink_target)?, b"receipt");

        let real_directory = fixture.root().join("real-cleanup");
        let linked_directory = fixture.root().join("linked-cleanup");
        fs::create_dir(&real_directory)?;
        symlink(&real_directory, &linked_directory)?;
        let identity = super::filesystem_directory_identity(&real_directory)?;
        assert!(matches!(
            super::atomic_remove_verified_empty_directory(&linked_directory, &identity),
            Err(super::AtomicVerifiedRemoveError::InvalidPath)
        ));
        assert!(linked_directory.is_symlink());
        assert!(real_directory.is_dir());
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
        assert_no_staging_files(&fixture.local())?;
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
    fn guard_acquire_removes_safe_partial_staging_from_private_namespace() -> io::Result<()> {
        let fixture = TestVault::new()?;
        drop(VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?);
        let staging = exact_staging_path(&fixture.local(), '0');
        fs::write(&staging, b"EDRY-partial")?;

        drop(VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?);

        assert!(!staging.exists());
        assert_no_staging_files(&fixture.local())?;
        Ok(())
    }

    #[test]
    fn content_tree_exact_staging_names_are_never_recovered() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let unrelated_file = exact_staging_path(fixture.notes(), '5');
        let logical_directory = exact_staging_path(fixture.notes(), '6');
        fs::write(&unrelated_file, b"legacy unrelated data")?;
        fs::create_dir(&logical_directory)?;

        drop(VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?);

        assert_eq!(fs::read(unrelated_file)?, b"legacy unrelated data");
        assert!(logical_directory.is_dir());
        Ok(())
    }

    #[test]
    fn staging_recovery_preserves_wrong_case_aliases_and_fails_closed() -> io::Result<()> {
        let fixture = TestVault::new()?;
        fs::create_dir(fixture.local())?;
        let prefix_alias = fixture.local().join(format!(
            ".INEX-CIPHERTEXT-STAGE-{}{}",
            "0".repeat(32),
            CIPHERTEXT_STAGING_SUFFIX
        ));
        let hex_alias = exact_staging_path(&fixture.local(), 'A');
        fs::write(&prefix_alias, b"partial")?;
        fs::write(&hex_alias, b"partial")?;

        assert!(matches!(
            VaultMutationGuard::acquire(fixture.root()),
            Err(AtomicWriteError::UnsafeStagingPath)
        ));
        assert_eq!(fs::read(prefix_alias)?, b"partial");
        assert_eq!(fs::read(hex_alias)?, b"partial");
        Ok(())
    }

    #[test]
    fn staging_recovery_preserves_exact_name_directories_and_fails_closed() -> io::Result<()> {
        let fixture = TestVault::new()?;
        fs::create_dir(fixture.local())?;
        let staging_directory = exact_staging_path(&fixture.local(), '7');
        fs::create_dir(&staging_directory)?;

        assert!(matches!(
            VaultMutationGuard::acquire(fixture.root()),
            Err(AtomicWriteError::UnsafeStagingPath)
        ));
        assert!(staging_directory.is_dir());
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn staging_recovery_preserves_oversized_candidates_and_fails_closed() -> io::Result<()> {
        let fixture = TestVault::new()?;
        fs::create_dir(fixture.local())?;
        let staging = exact_staging_path(&fixture.local(), '1');
        let file = fs::File::create(&staging)?;
        file.set_len(MAX_ATOMIC_TARGET_BYTES.saturating_add(1))?;
        drop(file);

        assert!(matches!(
            VaultMutationGuard::acquire(fixture.root()),
            Err(AtomicWriteError::UnsafeStagingPath)
        ));
        assert_eq!(fs::metadata(staging)?.len(), MAX_ATOMIC_TARGET_BYTES + 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn staging_recovery_preserves_hardlinks_and_symlinks_and_fails_closed() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let hardlink_fixture = TestVault::new()?;
        fs::create_dir(hardlink_fixture.local())?;
        let hardlink_staging = exact_staging_path(&hardlink_fixture.local(), '2');
        let hardlink_alias = hardlink_fixture.local().join("hardlink-alias");
        fs::write(&hardlink_staging, b"partial")?;
        fs::hard_link(&hardlink_staging, &hardlink_alias)?;
        assert!(matches!(
            VaultMutationGuard::acquire(hardlink_fixture.root()),
            Err(AtomicWriteError::UnsafeStagingPath)
        ));
        assert_eq!(fs::read(&hardlink_staging)?, b"partial");
        assert_eq!(fs::read(&hardlink_alias)?, b"partial");

        let symlink_fixture = TestVault::new()?;
        let outside = symlink_fixture.notes().join("outside");
        fs::create_dir(symlink_fixture.local())?;
        let symlink_staging = exact_staging_path(&symlink_fixture.local(), '3');
        fs::write(&outside, b"do-not-remove")?;
        symlink(&outside, &symlink_staging)?;
        assert!(matches!(
            VaultMutationGuard::acquire(symlink_fixture.root()),
            Err(AtomicWriteError::UnsafeStagingPath)
        ));
        assert!(symlink_staging.is_symlink());
        assert_eq!(fs::read(outside)?, b"do-not-remove");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn staging_recovery_preserves_candidates_with_ads_and_fails_closed() -> io::Result<()> {
        let fixture = TestVault::new()?;
        fs::create_dir(fixture.local())?;
        let staging = exact_staging_path(&fixture.local(), '4');
        fs::write(&staging, b"partial")?;
        fs::write(windows_stream_path(&staging, "hidden"), b"hidden")?;

        assert!(matches!(
            VaultMutationGuard::acquire(fixture.root()),
            Err(AtomicWriteError::UnsafeStagingPath)
        ));
        assert_eq!(fs::read(staging)?, b"partial");
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
        assert_no_staging_files(&fixture.local())?;
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
        assert_no_staging_files(&fixture.local())?;
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
        assert_no_staging_files(&fixture.local())?;
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
        assert_no_staging_files(&fixture.local())?;
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
            assert_no_staging_files(&fixture.local())?;
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn native_abrupt_write_child() -> io::Result<()> {
        let Some(root) = std::env::var_os("INEX_ATOMIC_ABRUPT_CHILD_ROOT") else {
            return Ok(());
        };
        let Some(ready) = std::env::var_os("INEX_ATOMIC_ABRUPT_CHILD_READY") else {
            return Err(io::Error::other("abrupt child ready path is missing"));
        };
        let point = match std::env::var("INEX_ATOMIC_ABRUPT_CHILD_POINT").as_deref() {
            Ok("verify-staging") => FaultPoint::VerifyStaging,
            Ok("before-lock") => FaultPoint::BeforeLock,
            Ok("replace") => FaultPoint::Replace,
            Ok("sync-parent") => FaultPoint::SyncParent,
            _ => return Err(io::Error::other("abrupt child fault point is invalid")),
        };
        let root = PathBuf::from(root);
        let target = root.join("notes").join("abrupt.md.enc");
        let blocker = BlockAt {
            point,
            ready: PathBuf::from(ready),
        };
        let _ = atomic_write_ciphertext_with_faults(
            &root,
            &target,
            NEW_CIPHERTEXT,
            WriteCondition::IfMatch(digest_bytes(OLD_CIPHERTEXT)),
            &blocker,
        );
        Err(io::Error::other(
            "abrupt child returned instead of blocking at its checkpoint",
        ))
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn native_force_kill_preserves_a_complete_atomic_write_state() -> io::Result<()> {
        let points = [
            ("verify-staging", OLD_CIPHERTEXT, true),
            ("before-lock", OLD_CIPHERTEXT, false),
            ("replace", OLD_CIPHERTEXT, true),
            ("sync-parent", NEW_CIPHERTEXT, false),
        ];

        for (point, expected_target, expected_abandoned_staging) in points {
            let fixture = TestVault::new()?;
            let target = fixture.note("abrupt.md.enc");
            fs::write(&target, OLD_CIPHERTEXT)?;
            let ready = fixture.root().join("abrupt-child-ready");
            let mut child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "atomic::tests::native_abrupt_write_child",
                    "--nocapture",
                ])
                .env("INEX_ATOMIC_ABRUPT_CHILD_ROOT", fixture.root())
                .env("INEX_ATOMIC_ABRUPT_CHILD_READY", &ready)
                .env("INEX_ATOMIC_ABRUPT_CHILD_POINT", point)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;

            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if matches!(fs::read(&ready), Ok(bytes) if bytes == b"ready") {
                    break;
                }
                if let Some(status) = child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "abrupt child exited before checkpoint {point}: {status}"
                    )));
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::other(format!(
                        "abrupt child did not reach checkpoint {point}"
                    )));
                }
                thread::sleep(Duration::from_millis(10));
            }

            child.kill()?;
            let status = child.wait()?;
            assert!(
                !status.success(),
                "force-killed child reported success: {point}"
            );
            assert_eq!(fs::read(&target)?, expected_target, "checkpoint: {point}");

            let abandoned = ciphertext_staging_paths(&fixture.local())?;
            assert_eq!(
                abandoned.len(),
                usize::from(expected_abandoned_staging),
                "checkpoint: {point}"
            );
            for staging in &abandoned {
                assert_eq!(fs::read(staging)?, NEW_CIPHERTEXT, "checkpoint: {point}");
            }

            drop(VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?);
            assert_no_staging_files(&fixture.local())?;

            fs::remove_file(&ready)?;
            let condition = WriteCondition::IfMatch(digest_bytes(expected_target));
            let replacement = if expected_target == OLD_CIPHERTEXT {
                NEW_CIPHERTEXT
            } else {
                OLD_CIPHERTEXT
            };
            atomic_write_ciphertext(fixture.root(), &target, replacement, condition)
                .map_err(io::Error::other)?;
            assert_eq!(fs::read(&target)?, replacement, "checkpoint: {point}");
            assert_no_staging_files(&fixture.local())?;
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
        assert_no_staging_files(&fixture.local())?;
        Ok(())
    }

    #[test]
    fn os_lock_serializes_competing_etag_commits() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let target = fixture.note("race.md.enc");
        fs::write(&target, OLD_CIPHERTEXT)?;
        // Freeze the existing lock namespace before the two writers rendezvous.
        // Otherwise one thread may conservatively reject `.vault-local`
        // appearing during its pre-lock publication scan, which tests that
        // scan's fail-closed behavior rather than OS-lock serialization.
        drop(VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?);
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
        assert_no_staging_files(&fixture.local())?;
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
    fn mutation_guard_binds_the_exact_physical_vault_root() -> io::Result<()> {
        let fixture = TestVault::new()?;
        let other = TestVault::new()?;
        let guard = VaultMutationGuard::acquire(fixture.root()).map_err(io::Error::other)?;
        assert!(guard.is_for_root(fixture.root()));
        assert!(!guard.is_for_root(other.root()));

        let retired = fixture.root().with_extension("retired-root");
        fs::rename(fixture.root(), &retired)?;
        fs::create_dir(fixture.root())?;
        assert!(!guard.is_for_root(fixture.root()));
        fs::remove_dir(fixture.root())?;
        fs::rename(&retired, fixture.root())?;
        assert!(guard.is_for_root(fixture.root()));

        let local = fixture.root().join(VAULT_LOCAL_DIRECTORY);
        let retired_local = fixture.root().join("retired-vault-local");
        fs::rename(&local, &retired_local)?;
        fs::create_dir(&local)?;
        assert!(!guard.is_for_root(fixture.root()));
        fs::remove_dir(&local)?;
        fs::rename(&retired_local, &local)?;
        assert!(guard.is_for_root(fixture.root()));

        let lock = local.join(VAULT_MUTATION_LOCK_FILE);
        let retired_lock = local.join("retired-mutation-lock");
        fs::rename(&lock, &retired_lock)?;
        fs::write(&lock, b"foreign lock inode")?;
        assert!(!guard.is_for_root(fixture.root()));
        fs::remove_file(&lock)?;
        fs::rename(&retired_lock, &lock)?;
        assert!(guard.is_for_root(fixture.root()));
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
        assert_no_staging_files(&fixture.local())?;
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
        assert_no_staging_files(&fixture.local())?;
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

    #[cfg(any(target_os = "linux", windows))]
    #[derive(Debug)]
    struct BlockAt {
        point: FaultPoint,
        ready: PathBuf,
    }

    #[cfg(any(target_os = "linux", windows))]
    impl FaultInjector for BlockAt {
        fn check(&self, point: FaultPoint) -> io::Result<()> {
            if point != self.point {
                return Ok(());
            }
            let staged = self.ready.with_extension("staged");
            fs::write(&staged, b"ready")?;
            fs::File::open(&staged)?.sync_all()?;
            fs::rename(&staged, &self.ready)?;
            loop {
                thread::park();
            }
        }
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

        fn local(&self) -> PathBuf {
            self.root.join(VAULT_LOCAL_DIRECTORY)
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

    fn exact_staging_path(directory: &Path, hex: char) -> PathBuf {
        directory.join(format!(
            "{CIPHERTEXT_STAGING_PREFIX}{}{CIPHERTEXT_STAGING_SUFFIX}",
            hex.to_string().repeat(32)
        ))
    }

    fn assert_no_staging_files(directory: &Path) -> io::Result<()> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let names = entries
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<HashSet<_>>>()?;
        assert!(names.iter().all(|name| {
            let name = name.to_string_lossy();
            !(name.starts_with(CIPHERTEXT_STAGING_PREFIX)
                && name.ends_with(CIPHERTEXT_STAGING_SUFFIX))
        }));
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows))]
    fn ciphertext_staging_paths(directory: &Path) -> io::Result<Vec<PathBuf>> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        entries
            .filter_map(|entry| match entry {
                Ok(entry) => {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with(CIPHERTEXT_STAGING_PREFIX)
                        && name.ends_with(CIPHERTEXT_STAGING_SUFFIX)
                    {
                        Some(Ok(entry.path()))
                    } else {
                        None
                    }
                }
                Err(error) => Some(Err(error)),
            })
            .collect()
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
