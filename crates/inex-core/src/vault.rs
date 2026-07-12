//! Repository-level encrypted-vault lifecycle.
//!
//! This module is the only core layer that combines authenticated vault
//! metadata, logical paths, EDRY envelopes, ciphertext-only persistence, tree
//! discovery, and the in-memory search index. It never creates a plaintext
//! filesystem object. All returned plaintext allocations are zeroizing.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::atomic::{
    AtomicRebindOutcome, AtomicWriteError, AtomicWriteOutcome, CurrentTarget, ParentSyncStatus,
    VaultMutationGuard, WriteCondition, open_file_matches_path_and_is_single_link,
    paths_share_mount, recover_pending_rebind, sync_directory,
};
use crate::crypto::{
    self, CryptoError, DecryptedDocument, EncryptedDocument, EnvelopeKind, ExpectedEnvelopeKind,
    FileIdentity, VaultMasterKey,
};
use crate::format::{self, ContentFlags, EdryHeader};
use crate::path::{LogicalDir, LogicalPath, PathError, portable_case_fold};
use crate::search::{
    Document as SearchDocument, MemorySearchIndex, SearchError, SearchHit, SearchQuery,
};
use crate::sodium::Argon2idParams;
use crate::tree::{self, TreeEntryKind, TreeError, VaultTree};
use crate::vault_config::{
    ConfigError, ConfigWarning, KdfPolicy, MAX_VAULT_JSON_BYTES, VaultConfig,
};

/// Fixed metadata filename at the root of every vault.
pub const VAULT_CONFIG_FILE: &str = "vault.json";

/// Largest complete EDRY envelope accepted from disk.
pub const MAX_EDRY_ENVELOPE_BYTES: usize =
    format::EDRY_PREFIX_LEN + format::MAX_HEADER_LEN + format::MAX_CIPHERTEXT_LEN;

/// A repository I/O operation exposed without filesystem paths or OS text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VaultIoOperation {
    /// Inspecting a vault root or one of its directory entries.
    Inspect,
    /// Creating the vault root or a logical directory.
    CreateDirectory,
    /// Resolving a stable absolute vault-root path.
    CanonicalizeRoot,
    /// Opening a regular ciphertext or metadata file.
    Open,
    /// Reading a bounded ciphertext or metadata file.
    Read,
    /// Removing a regular ciphertext file or empty directory.
    Remove,
    /// Synchronizing a directory after a structural mutation.
    SyncDirectory,
}

impl fmt::Display for VaultIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Inspect => "filesystem inspection",
            Self::CreateDirectory => "directory creation",
            Self::CanonicalizeRoot => "vault-root resolution",
            Self::Open => "bounded file open",
            Self::Read => "bounded file read",
            Self::Remove => "filesystem removal",
            Self::SyncDirectory => "directory synchronization",
        })
    }
}

/// Repository-level vault failure with secret-free display text.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Cryptographic authentication or format validation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Vault metadata was invalid before a password KDF was attempted.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A logical path was outside the portable v1 profile.
    #[error(transparent)]
    Path(#[from] PathError),
    /// Repository discovery failed closed.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// The bounded in-memory search index rejected an operation.
    #[error(transparent)]
    Search(#[from] SearchError),
    /// A filesystem operation failed; paths and OS messages are omitted.
    #[error("vault I/O failed during {operation}: {kind:?}")]
    Io {
        /// Non-secret operation classification.
        operation: VaultIoOperation,
        /// Stable standard-library error classification.
        kind: io::ErrorKind,
    },
    /// The vault root or a traversed entry was a link/reparse point or had an
    /// unexpected filesystem type.
    #[error("vault storage contains an unsafe filesystem entry")]
    UnsafeFilesystemEntry,
    /// Vault storage is not on a supported local filesystem.
    #[error("vault storage must reside on a supported local filesystem")]
    UnsupportedFilesystem,
    /// The requested vault has already been initialized.
    #[error("vault metadata already exists")]
    AlreadyInitialized,
    /// The requested vault has no `vault.json` metadata.
    #[error("vault metadata does not exist")]
    NotInitialized,
    /// A new logical entry already exists.
    #[error("logical vault entry already exists")]
    AlreadyExists,
    /// A new logical entry aliases another entry under portable case folding.
    #[error("logical vault entry collides under Unicode case folding")]
    CaseFoldCollision,
    /// A required logical parent directory is absent.
    #[error("logical parent directory does not exist")]
    ParentDirectoryMissing,
    /// The requested logical document does not exist as a regular ciphertext
    /// file.
    #[error("encrypted document does not exist")]
    DocumentNotFound,
    /// The expected ciphertext etag was malformed.
    #[error("ciphertext etag must use canonical `sha256:` lowercase hex")]
    InvalidEtag,
    /// The optimistic write/delete condition did not match current storage.
    #[error("vault mutation conflicts with the current ciphertext etag")]
    Conflict {
        /// Current regular-file digest when one could be obtained safely.
        current_etag: Option<String>,
    },
    /// Search was requested before a successful in-memory rebuild.
    #[error("the in-memory search index has not been built")]
    SearchIndexNotReady,
    /// An internal UTF-8 conversion invariant failed without exposing bytes.
    #[error("authenticated Markdown could not be indexed as UTF-8")]
    SearchUtf8Invariant,
    /// An untrusted metadata or envelope file exceeded its byte bound before
    /// a full allocation was permitted.
    #[error("vault file exceeds its configured byte limit")]
    FileTooLarge,
    /// Caller-supplied draft bytes exceeded the EDRY envelope byte bound.
    #[error("encrypted draft envelope exceeds the EDRY v1 byte limit")]
    EnvelopeTooLarge,
    /// A staged ciphertext did not survive a synchronized re-read unchanged.
    #[error("atomic ciphertext staging verification failed")]
    AtomicVerificationFailed,
    /// A namespace move reported failure and the post-check could not prove
    /// either the exact old or requested complete ciphertext state.
    #[error("vault namespace commit outcome requires explicit verification")]
    NamespaceCommitIndeterminate {
        /// Canonical digest of the complete ciphertext intended to commit.
        expected_etag: String,
    },
    /// A destination committed but source cleanup must be recovered before
    /// another mutation.
    #[error("authenticated rename requires repository recovery")]
    RenameRecoveryPending {
        /// Canonical digest of the already committed destination.
        destination_etag: String,
    },
    /// A pending rename journal and repository state could not be reconciled
    /// without risking loss.
    #[error("authenticated rename recovery found conflicting repository state")]
    RenameRecoveryConflict,
    /// A password-slot commit succeeded but re-opening it with the new
    /// password failed. The on-disk metadata is retained for recovery.
    #[error("password-slot metadata committed but post-commit verification failed")]
    PasswordCommitVerificationFailed,
}

/// Non-plaintext metadata returned after a committed document mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentMetadata {
    /// Authenticated EDRY header.
    pub header: EdryHeader,
    /// Canonical SHA-256 etag of the complete encrypted envelope.
    pub etag: String,
    /// Result of the platform namespace-durability checkpoint.
    pub parent_sync: ParentSyncStatus,
}

/// Result of adding a new independently wrapped password slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordSlotCommit {
    /// Stable identifier of the new password slot.
    pub new_slot_id: Uuid,
    /// Result of the root namespace-durability checkpoint.
    pub parent_sync: ParentSyncStatus,
}

/// Successful crash-recoverable authenticated path rename.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenameOutcome {
    /// Authenticated metadata of the destination envelope.
    pub document: DocumentMetadata,
    /// Whether source retirement passed the platform durability checkpoint.
    pub source_parent_sync: ParentSyncStatus,
}

/// An unlocked repository session.
///
/// Dropping this value releases the guarded master key and zeroizes the
/// memory-only search index. Password bytes are never retained.
pub struct Vault {
    root: PathBuf,
    config: VaultConfig,
    config_etag: [u8; 32],
    master_key: VaultMasterKey,
    unlocked_slot_id: Uuid,
    warnings: Vec<ConfigWarning>,
    search_index: MemorySearchIndex,
    search_index_ready: bool,
    search_fingerprint: Option<[u8; 32]>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Vault")
            .field("root", &"<redacted>")
            .field("vault_id", &self.config.vault_id)
            .field("key_epoch", &self.config.key_epoch)
            .field("config_etag", &encode_etag(self.config_etag))
            .field("unlocked_slot_id", &self.unlocked_slot_id)
            .field("master_key", &self.master_key)
            .field("warning_count", &self.warnings.len())
            .field("search_index", &self.search_index)
            .field("search_index_ready", &self.search_index_ready)
            .field("search_fingerprint", &self.search_fingerprint.is_some())
            .finish()
    }
}

impl Vault {
    /// Create a vault with the production KDF policy, atomically persist its
    /// metadata, and re-open it before returning.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] if the root is unsafe, metadata already exists,
    /// creation/KDF fails, the metadata commit conflicts, or post-commit
    /// authentication fails.
    pub fn create(
        root: impl AsRef<Path>,
        password: &[u8],
        created_at_ms: i64,
    ) -> Result<Self, VaultError> {
        Self::create_with_policy(root, password, created_at_ms, KdfPolicy::default())
    }

    /// Create a vault using process-cached v1 calibration bounded by `policy`.
    ///
    /// Calibration and pure request validation complete before an absent vault
    /// root may be created.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for an invalid calibration policy, KDF failure,
    /// unsafe root, existing metadata, commit failure, or post-commit
    /// authentication failure.
    pub fn create_with_policy(
        root: impl AsRef<Path>,
        password: &[u8],
        created_at_ms: i64,
        policy: KdfPolicy,
    ) -> Result<Self, VaultError> {
        let params = crypto::calibrated_creation_params(policy)?;
        Self::create_with_params(root, password, created_at_ms, params, policy)
    }

    /// Create a vault with explicit KDF parameters and policy.
    ///
    /// This is intended for calibrated creation and low-cost deterministic
    /// tests. Normal callers should use [`Self::create`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for an unsafe root, an existing vault, invalid
    /// KDF policy, a failed atomic commit, or post-commit authentication
    /// failure.
    pub fn create_with_params(
        root: impl AsRef<Path>,
        password: &[u8],
        created_at_ms: i64,
        params: Argon2idParams,
        policy: KdfPolicy,
    ) -> Result<Self, VaultError> {
        crypto::validate_vault_creation_request(password, created_at_ms, params, policy)?;
        let root = prepare_vault_root(root.as_ref())?;
        ensure_uninitialized_root(&root)?;
        let created = crypto::create_vault_with_params(password, created_at_ms, params, policy)?;
        Self::commit_created(&root, created, password, policy)
    }

    fn commit_created(
        root: &Path,
        created: crypto::CreatedVault,
        password: &[u8],
        policy: KdfPolicy,
    ) -> Result<Self, VaultError> {
        let metadata = created.config.to_json_bytes(policy)?;
        let target = root.join(VAULT_CONFIG_FILE);
        let guard = VaultMutationGuard::acquire(root).map_err(map_atomic_error)?;
        ensure_uninitialized_root(root)?;
        let outcome = guard
            .write(&target, &metadata, WriteCondition::IfNoneMatch)
            .map_err(map_atomic_error)?;
        drop(guard);
        drop(created);

        let mut reopened = Self::unlock(root, password, None, policy)
            .map_err(|_| VaultError::PasswordCommitVerificationFailed)?;
        reopened.config_etag = outcome.etag;
        Ok(reopened)
    }

    /// Open, resource-validate, unlock, and authenticate an existing vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] if the root/config entry is unsafe, the bounded
    /// metadata read fails, parsing fails, the selected slot is ambiguous, or
    /// password/metadata authentication fails.
    pub fn unlock(
        root: impl AsRef<Path>,
        password: &[u8],
        slot_id: Option<Uuid>,
        policy: KdfPolicy,
    ) -> Result<Self, VaultError> {
        let root = resolve_existing_vault_root(root.as_ref())?;
        let config_path = root.join(VAULT_CONFIG_FILE);
        if !unique_exact_ascii_child(&root, VAULT_CONFIG_FILE)? {
            return if entry_state(&config_path)? == EntryState::Absent {
                Err(VaultError::NotInitialized)
            } else {
                Err(VaultError::UnsafeFilesystemEntry)
            };
        }
        ensure_same_mount(&root, &config_path)?;
        let metadata = match read_regular_bounded(&config_path, MAX_VAULT_JSON_BYTES) {
            Err(VaultError::DocumentNotFound) => return Err(VaultError::NotInitialized),
            other => other?,
        };
        let config_etag = digest(&metadata);
        let (config, _) = VaultConfig::parse_untrusted(&metadata, policy)?;
        let unlocked = crypto::unlock_vault(&config, password, slot_id, policy)?;
        recover_pending_rebind(&root).map_err(map_atomic_error)?;

        Ok(Self {
            root,
            config,
            config_etag,
            master_key: unlocked.master_key,
            unlocked_slot_id: unlocked.slot_id,
            warnings: unlocked.warnings,
            search_index: MemorySearchIndex::new(),
            search_index_ready: false,
            search_fingerprint: None,
        })
    }

    /// Return the resolved vault root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrow authenticated vault metadata.
    #[must_use]
    pub const fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Return the password slot used to unlock this session.
    #[must_use]
    pub const fn unlocked_slot_id(&self) -> Uuid {
        self.unlocked_slot_id
    }

    /// Borrow non-fatal metadata policy warnings from unlock.
    #[must_use]
    pub fn warnings(&self) -> &[ConfigWarning] {
        &self.warnings
    }

    /// Return the canonical etag of the authenticated `vault.json` bytes.
    #[must_use]
    pub fn config_etag(&self) -> String {
        encode_etag(self.config_etag)
    }

    /// Discover a deterministic logical tree without opening document bytes.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the root contains an unsafe, plaintext,
    /// noncanonical, colliding, or resource-exhausting entry.
    pub fn list(&mut self) -> Result<VaultTree, VaultError> {
        let _guard = self.acquire_mutation_guard()?;
        Ok(tree::scan_vault_tree(&self.root)?)
    }

    /// Read and authenticate one committed encrypted Markdown document.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the path chain/target is unsafe, the
    /// envelope exceeds its bound, framing/AAD authentication fails, or the
    /// document belongs to a different vault/path/epoch.
    pub fn read(&self, logical_path: &LogicalPath) -> Result<DecryptedDocument, VaultError> {
        self.read_kind(logical_path, ExpectedEnvelopeKind::Committed)
    }

    /// Authenticate one committed EDRY envelope supplied from an external
    /// ciphertext-only source such as a Git object.
    ///
    /// This is the only supported bridge from Git plumbing into the unlocked
    /// vault key domain. The bytes are bounded before parsing and must bind to
    /// this vault, epoch, and exact logical path. No filesystem object is
    /// created and the returned plaintext allocation zeroizes on drop.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the envelope exceeds the v1 bound or fails
    /// framing, context, authentication, kind, or UTF-8 validation.
    pub fn authenticate_committed_envelope(
        &self,
        logical_path: &LogicalPath,
        envelope: &[u8],
    ) -> Result<DecryptedDocument, VaultError> {
        if envelope.len() > MAX_EDRY_ENVELOPE_BYTES {
            return Err(VaultError::EnvelopeTooLarge);
        }
        Ok(crypto::decrypt_document(
            &self.master_key,
            self.config.vault_id,
            self.config.key_epoch,
            logical_path,
            ExpectedEnvelopeKind::Committed,
            envelope,
        )?)
    }

    /// Encrypt an in-memory three-way merge result as a committed EDRY file.
    ///
    /// `identity_header` must have come from an authenticated committed stage
    /// for the same vault and logical path. Its stable file id and creation
    /// time are retained. The unresolved flag is set or cleared according to
    /// `unresolved`; the draft flag can never enter committed storage.
    ///
    /// This method only prepares ciphertext. Callers must still use the vault
    /// mutation lock and an optimistic condition when writing it to disk.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for a mismatched identity header, invalid merge
    /// bytes/timestamp, or any cryptographic failure.
    pub fn encrypt_merge_result(
        &self,
        logical_path: &LogicalPath,
        identity_header: &EdryHeader,
        plaintext: &[u8],
        modified_at_ms: i64,
        unresolved: bool,
    ) -> Result<EncryptedDocument, VaultError> {
        if identity_header.vault_id != self.config.vault_id
            || identity_header.key_epoch != self.config.key_epoch
            || identity_header.logical_path != logical_path.as_str()
            || identity_header.is_draft()
        {
            return Err(CryptoError::DocumentContextMismatch.into());
        }

        let retained_bits = identity_header.content_flags.bits()
            & !ContentFlags::UNRESOLVED_MERGE.bits()
            & !ContentFlags::DRAFT.bits();
        let mut flags = ContentFlags::from_bits(retained_bits).map_err(CryptoError::from)?;
        if unresolved {
            flags |= ContentFlags::UNRESOLVED_MERGE;
        }
        Ok(crypto::encrypt_document(
            &self.master_key,
            self.config.vault_id,
            self.config.key_epoch,
            logical_path,
            Some(FileIdentity::from_header(identity_header)),
            plaintext,
            modified_at_ms,
            flags,
            EnvelopeKind::Committed,
        )?)
    }

    fn read_kind(
        &self,
        logical_path: &LogicalPath,
        expected_kind: ExpectedEnvelopeKind,
    ) -> Result<DecryptedDocument, VaultError> {
        let target = self.document_target(logical_path)?;
        let envelope = read_regular_bounded(&target, MAX_EDRY_ENVELOPE_BYTES)?;
        Ok(crypto::decrypt_document(
            &self.master_key,
            self.config.vault_id,
            self.config.key_epoch,
            logical_path,
            expected_kind,
            &envelope,
        )?)
    }

    /// Create and atomically commit one new encrypted Markdown document.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] if the logical destination/parent is unsafe or
    /// colliding, plaintext is invalid, encryption fails, or the destination
    /// already exists by commit time.
    pub fn create_document(
        &mut self,
        logical_path: &LogicalPath,
        plaintext: &[u8],
        modified_at_ms: i64,
    ) -> Result<DocumentMetadata, VaultError> {
        let encrypted = crypto::encrypt_document(
            &self.master_key,
            self.config.vault_id,
            self.config.key_epoch,
            logical_path,
            None,
            plaintext,
            modified_at_ms,
            ContentFlags::NONE,
            EnvelopeKind::Committed,
        )?;
        let guard = self.acquire_mutation_guard()?;
        self.ensure_destination_available_locked(logical_path)?;
        let target = self.document_target_allow_absent(logical_path)?;
        let outcome = guard
            .write(&target, &encrypted.bytes, WriteCondition::IfNoneMatch)
            .map_err(map_atomic_error)?;
        drop(guard);
        self.invalidate_search_index();
        Ok(document_metadata(encrypted, outcome))
    }

    /// Save exact Markdown bytes using optimistic ciphertext concurrency.
    ///
    /// A fresh nonce is generated and stable file id/creation time are
    /// retained. `expected_etag` is rechecked by the atomic layer immediately
    /// before replacement. When the current authenticated header is marked as
    /// an unresolved merge, a save clears that flag only after all canonical
    /// diff3 marker lines have been removed; ordinary files never gain the
    /// flag merely because their Markdown resembles a marker.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for an invalid etag, missing/unsafe document,
    /// stale etag, authentication/encryption failure, or atomic write failure.
    pub fn save_document(
        &mut self,
        logical_path: &LogicalPath,
        plaintext: &[u8],
        expected_etag: &str,
        modified_at_ms: i64,
    ) -> Result<DocumentMetadata, VaultError> {
        let expected = decode_etag(expected_etag)?;
        let current = self.read(logical_path)?;
        if decode_etag(&current.etag)? != expected {
            return Err(VaultError::Conflict {
                current_etag: Some(current.etag),
            });
        }
        let identity = FileIdentity::from_header(&current.header);
        let mut content_flags = current.header.content_flags;
        if content_flags.contains(ContentFlags::UNRESOLVED_MERGE)
            && !contains_diff3_markers(plaintext)
        {
            content_flags = ContentFlags::from_bits(
                content_flags.bits() & !ContentFlags::UNRESOLVED_MERGE.bits(),
            )
            .map_err(CryptoError::from)?;
        }
        drop(current);

        let encrypted = crypto::encrypt_document(
            &self.master_key,
            self.config.vault_id,
            self.config.key_epoch,
            logical_path,
            Some(identity),
            plaintext,
            modified_at_ms,
            content_flags,
            EnvelopeKind::Committed,
        )?;
        let guard = self.acquire_mutation_guard()?;
        let target = self.document_target(logical_path)?;
        ensure_regular_file_bounded(&target, MAX_EDRY_ENVELOPE_BYTES)?;
        let outcome = guard
            .write(&target, &encrypted.bytes, WriteCondition::IfMatch(expected))
            .map_err(map_atomic_error)?;
        drop(guard);
        self.invalidate_search_index();
        Ok(document_metadata(encrypted, outcome))
    }

    /// Create one empty logical directory without following links.
    ///
    /// Only a single directory component is created; its parent must already
    /// exist. This operation writes no plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for root, missing/unsafe parent, an existing or
    /// case-fold-colliding entry, or an I/O failure.
    pub fn create_directory(&mut self, logical_dir: &LogicalDir) -> Result<(), VaultError> {
        if logical_dir.is_root() {
            return Err(VaultError::AlreadyExists);
        }
        let _guard = self.acquire_mutation_guard()?;
        let tree = tree::scan_vault_tree(&self.root)?;
        let parent = logical_dir
            .parent()
            .ok_or(VaultError::ParentDirectoryMissing)?;
        ensure_directory_spelling(&tree, &parent)?;
        ensure_logical_name_available(&tree, logical_dir.as_str())?;
        let physical_parent = self.directory_target(&parent, true)?;
        let target = physical_parent.join(
            logical_dir
                .name()
                .ok_or(VaultError::ParentDirectoryMissing)?,
        );
        reject_existing_entry(&target)?;
        fs::create_dir(&target).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                VaultError::AlreadyExists
            } else {
                io_error(VaultIoOperation::CreateDirectory, &error)
            }
        })?;
        restrict_directory_permissions_best_effort(&target);
        let _ = sync_directory(&physical_parent);
        self.invalidate_search_index();
        Ok(())
    }

    /// Encrypt a zero-disk-plaintext editor draft.
    ///
    /// When `base_etag` is present, the current committed document must match
    /// it and supplies the stable file identity. A missing base etag is only
    /// accepted for a path that does not currently exist.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for an invalid/stale base etag, unsafe path,
    /// existing new-draft path, invalid Markdown, or encryption failure.
    pub fn encrypt_draft(
        &self,
        logical_path: &LogicalPath,
        plaintext: &[u8],
        base_etag: Option<&str>,
        modified_at_ms: i64,
    ) -> Result<EncryptedDocument, VaultError> {
        let (identity, flags, base_digest) = if let Some(base_etag) = base_etag {
            let expected = decode_etag(base_etag)?;
            let current = self.read(logical_path)?;
            if decode_etag(&current.etag)? != expected {
                return Err(VaultError::Conflict {
                    current_etag: Some(current.etag),
                });
            }
            (
                Some(FileIdentity::from_header(&current.header)),
                current.header.content_flags,
                Some(expected),
            )
        } else {
            match self.document_entry_state(logical_path)? {
                EntryState::Absent => (None, ContentFlags::NONE, None),
                EntryState::Regular => return Err(VaultError::AlreadyExists),
                EntryState::Unsafe => return Err(VaultError::UnsafeFilesystemEntry),
            }
        };

        Ok(crypto::encrypt_document(
            &self.master_key,
            self.config.vault_id,
            self.config.key_epoch,
            logical_path,
            identity,
            plaintext,
            modified_at_ms,
            flags,
            EnvelopeKind::Draft {
                base_etag: base_digest,
            },
        )?)
    }

    /// Authenticate and decrypt an encrypted editor draft held by the caller.
    ///
    /// Draft bytes may live in editor-managed backup storage, but plaintext is
    /// returned only in a zeroizing allocation.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for malformed/tampered bytes or a vault,
    /// path/epoch, or committed-versus-draft context mismatch.
    pub fn decrypt_draft(
        &self,
        logical_path: &LogicalPath,
        encrypted_draft: &[u8],
    ) -> Result<DecryptedDocument, VaultError> {
        if encrypted_draft.len() > MAX_EDRY_ENVELOPE_BYTES {
            return Err(VaultError::EnvelopeTooLarge);
        }
        Ok(crypto::decrypt_document(
            &self.master_key,
            self.config.vault_id,
            self.config.key_epoch,
            logical_path,
            ExpectedEnvelopeKind::Draft,
            encrypted_draft,
        )?)
    }

    /// Rebuild the bounded plaintext search index entirely in memory.
    ///
    /// The previous index is cleared before rebuilding so peak plaintext stays
    /// within the configured session cap. No plaintext or index bytes are
    /// written to disk.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when tree discovery, bounded reads, decryption,
    /// UTF-8 conversion, or configured index limits fail.
    pub fn rebuild_search_index(&mut self) -> Result<usize, VaultError> {
        let guard = self.acquire_mutation_guard()?;
        let tree = tree::scan_vault_tree(&self.root)?;
        let fingerprint = self.repository_fingerprint(&guard, &tree)?;
        self.invalidate_search_index();
        let mut replacement = MemorySearchIndex::new();
        for entry in tree.entries() {
            if entry.kind() != TreeEntryKind::File {
                continue;
            }
            let logical_path = LogicalPath::parse_canonical(entry.logical_path())?;
            let mut document = self.read(&logical_path)?;
            let bytes = std::mem::take(&mut *document.plaintext);
            let plaintext = match String::from_utf8(bytes) {
                Ok(plaintext) => Zeroizing::new(plaintext),
                Err(error) => {
                    let mut bytes = error.into_bytes();
                    bytes.zeroize();
                    return Err(VaultError::SearchUtf8Invariant);
                }
            };
            replacement.upsert(SearchDocument::new(logical_path, plaintext)?)?;
        }
        let current_tree = tree::scan_vault_tree(&self.root)?;
        let current_fingerprint = self.repository_fingerprint(&guard, &current_tree)?;
        if fingerprint != current_fingerprint {
            return Err(VaultError::Conflict { current_etag: None });
        }
        let count = replacement.document_count();
        self.search_index = replacement;
        self.search_index_ready = true;
        self.search_fingerprint = Some(fingerprint);
        Ok(count)
    }

    /// Query the current zeroizing in-memory search index.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::SearchIndexNotReady`] before a successful rebuild,
    /// or a bounded query validation error.
    pub fn search(&mut self, query: &SearchQuery) -> Result<Zeroizing<Vec<SearchHit>>, VaultError> {
        let guard = self.acquire_mutation_guard()?;
        if !self.search_index_ready {
            return Err(VaultError::SearchIndexNotReady);
        }
        let tree = tree::scan_vault_tree(&self.root)?;
        let current_fingerprint = self.repository_fingerprint(&guard, &tree)?;
        if self.search_fingerprint != Some(current_fingerprint) {
            drop(guard);
            self.invalidate_search_index();
            return Err(VaultError::SearchIndexNotReady);
        }
        Ok(self.search_index.search(query)?)
    }

    /// Clear and zeroize every indexed plaintext document.
    pub fn clear_search_index(&mut self) {
        self.invalidate_search_index();
    }

    /// Add, pre-verify, atomically commit, and post-verify a password slot.
    ///
    /// Existing slots are never removed by this operation. Password changes
    /// therefore use this method first and call [`Self::remove_password_slot`]
    /// only after the new credential has returned successfully. Each supplied
    /// work factor is raised to at least the authenticated slot's value before
    /// wrapping, so this operation cannot silently weaken that credential.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for invalid policy/password data, metadata
    /// authentication failure, a concurrent config change, commit failure, or
    /// failure to re-open the exact committed bytes with the new password.
    pub fn add_password_slot(
        &mut self,
        new_password: &[u8],
        created_at_ms: i64,
        params: Argon2idParams,
        policy: KdfPolicy,
    ) -> Result<PasswordSlotCommit, VaultError> {
        let current_slot = self.config.key_slot(self.unlocked_slot_id)?;
        let params = Argon2idParams {
            ops_limit: params.ops_limit.max(current_slot.kdf.ops_limit),
            mem_limit_bytes: params.mem_limit_bytes.max(current_slot.kdf.mem_limit_bytes),
        };
        let (updated, new_slot_id) = crypto::add_password_slot(
            &self.config,
            &self.master_key,
            new_password,
            created_at_ms,
            params,
            policy,
        )?;
        let metadata = updated.to_json_bytes(policy)?;
        let (preverified, _) = VaultConfig::parse_untrusted(&metadata, policy)?;
        crypto::unlock_vault(&preverified, new_password, Some(new_slot_id), policy)?;

        let target = self.root.join(VAULT_CONFIG_FILE);
        let guard = self.acquire_mutation_guard()?;
        ensure_regular_file_bounded(&target, MAX_VAULT_JSON_BYTES)?;
        let outcome = guard
            .write(
                &target,
                &metadata,
                WriteCondition::IfMatch(self.config_etag),
            )
            .map_err(map_atomic_error)?;
        drop(guard);

        self.adopt_committed_config(new_password, new_slot_id, policy, outcome.etag)
            .map_err(|_| VaultError::PasswordCommitVerificationFailed)?;
        Ok(PasswordSlotCommit {
            new_slot_id,
            parent_sync: outcome.parent_sync,
        })
    }

    /// Return calibrated no-downgrade parameters for a password rewrap.
    ///
    /// The authenticated slot used to open this session is the lower bound for
    /// each work-factor component. Stronger legacy values are retained while
    /// they remain inside the configured reader ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when calibration fails, the authenticated slot
    /// is missing, or its parameters cannot be safely retained under `policy`.
    pub fn calibrated_password_rewrap_params(
        &self,
        policy: KdfPolicy,
    ) -> Result<Argon2idParams, VaultError> {
        let current_slot = self.config.key_slot(self.unlocked_slot_id)?;
        Ok(crypto::calibrated_password_rewrap_params(
            Argon2idParams {
                ops_limit: current_slot.kdf.ops_limit,
                mem_limit_bytes: current_slot.kdf.mem_limit_bytes,
            },
            policy,
        )?)
    }

    /// Remove one old password slot after another slot has been verified.
    ///
    /// The last slot cannot be removed. This is intentionally a separate
    /// atomic commit from [`Self::add_password_slot`], so any failure leaves
    /// the newly added and old credentials both available rather than risking
    /// lockout.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] if the slot is absent/last, metadata
    /// authentication fails, another writer changed `vault.json`, or the
    /// committed config cannot be authenticated with `retained_password` and
    /// `retained_slot_id`.
    pub fn remove_password_slot(
        &mut self,
        slot_to_remove: Uuid,
        retained_password: &[u8],
        retained_slot_id: Uuid,
        policy: KdfPolicy,
    ) -> Result<ParentSyncStatus, VaultError> {
        if slot_to_remove == retained_slot_id {
            return Err(CryptoError::CannotRemoveLastSlot.into());
        }
        let updated =
            crypto::remove_password_slot(&self.config, &self.master_key, slot_to_remove, policy)?;
        let metadata = updated.to_json_bytes(policy)?;
        let (preverified, _) = VaultConfig::parse_untrusted(&metadata, policy)?;
        crypto::unlock_vault(
            &preverified,
            retained_password,
            Some(retained_slot_id),
            policy,
        )?;

        let target = self.root.join(VAULT_CONFIG_FILE);
        let guard = self.acquire_mutation_guard()?;
        ensure_regular_file_bounded(&target, MAX_VAULT_JSON_BYTES)?;
        let outcome = guard
            .write(
                &target,
                &metadata,
                WriteCondition::IfMatch(self.config_etag),
            )
            .map_err(map_atomic_error)?;
        drop(guard);
        self.adopt_committed_config(retained_password, retained_slot_id, policy, outcome.etag)
            .map_err(|_| VaultError::PasswordCommitVerificationFailed)?;
        Ok(outcome.parent_sync)
    }

    /// Begin a fail-safe password change by committing a verified new slot.
    ///
    /// This method deliberately retains every old slot. After it succeeds,
    /// call [`Self::remove_password_slot`] as a separate explicit transaction.
    /// Keeping the stages separate ensures a removal failure cannot hide the
    /// fact that the new credential was already committed.
    ///
    /// # Errors
    ///
    /// Returns any error from new-slot creation, pre-verification, atomic
    /// commit, or post-commit verification. No old slot is modified.
    pub fn change_password(
        &mut self,
        new_password: &[u8],
        created_at_ms: i64,
        params: Argon2idParams,
        policy: KdfPolicy,
    ) -> Result<PasswordSlotCommit, VaultError> {
        self.add_password_slot(new_password, created_at_ms, params, policy)
    }

    /// Rename one document while rebinding its authenticated logical path.
    ///
    /// The replacement envelope is fully encrypted and staged before commit.
    /// A synchronized crash-recovery journal ensures the source is never
    /// removed before the exact destination has committed durably.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for a malformed/stale source etag, missing or
    /// unauthenticated source, unsafe/colliding destination, encryption
    /// failure, or a crash-recovery/atomic transaction error.
    pub fn rename_document(
        &mut self,
        source: &LogicalPath,
        destination: &LogicalPath,
        source_etag: &str,
        modified_at_ms: i64,
    ) -> Result<RenameOutcome, VaultError> {
        let expected = decode_etag(source_etag)?;
        let current = self.read(source)?;
        if decode_etag(&current.etag)? != expected {
            return Err(VaultError::Conflict {
                current_etag: Some(current.etag),
            });
        }
        let identity = FileIdentity::from_header(&current.header);
        let flags = current.header.content_flags;
        let encrypted = crypto::encrypt_document(
            &self.master_key,
            self.config.vault_id,
            self.config.key_epoch,
            destination,
            Some(identity),
            current.plaintext.as_slice(),
            modified_at_ms,
            flags,
            EnvelopeKind::Committed,
        )?;
        drop(current);

        let guard = self.acquire_mutation_guard()?;
        let tree = tree::scan_vault_tree(&self.root)?;
        ensure_directory_spelling(&tree, &destination.parent())?;
        ensure_logical_name_available(&tree, destination.as_str())?;
        let source_target = self.document_target(source)?;
        ensure_regular_file_bounded(&source_target, MAX_EDRY_ENVELOPE_BYTES)?;
        let destination_target = self.document_target_allow_absent(destination)?;
        if entry_state(&destination_target)? != EntryState::Absent {
            return Err(VaultError::AlreadyExists);
        }
        let atomic = guard
            .rebind(
                &source_target,
                &destination_target,
                &encrypted.bytes,
                WriteCondition::IfMatch(expected),
                WriteCondition::IfNoneMatch,
            )
            .map_err(map_atomic_error)?;
        drop(guard);
        self.invalidate_search_index();
        Ok(rename_outcome(encrypted, atomic))
    }

    /// Conditionally delete one committed ciphertext document.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for a malformed/stale etag, unsafe/missing or
    /// oversized target, or an in-lock removal failure.
    pub fn delete_document(
        &mut self,
        logical_path: &LogicalPath,
        expected_etag: &str,
    ) -> Result<ParentSyncStatus, VaultError> {
        let expected = decode_etag(expected_etag)?;
        let guard = self.acquire_mutation_guard()?;
        let target = self.document_target(logical_path)?;
        ensure_regular_file_bounded(&target, MAX_EDRY_ENVELOPE_BYTES)?;
        let outcome = guard
            .delete(&target, WriteCondition::IfMatch(expected))
            .map_err(map_atomic_error)?;
        drop(guard);
        self.invalidate_search_index();
        Ok(outcome.parent_sync)
    }

    fn adopt_committed_config(
        &mut self,
        password: &[u8],
        slot_id: Uuid,
        policy: KdfPolicy,
        expected_etag: [u8; 32],
    ) -> Result<(), VaultError> {
        let config_path = self.root.join(VAULT_CONFIG_FILE);
        ensure_same_mount(&self.root, &config_path)?;
        let metadata = read_regular_bounded(&config_path, MAX_VAULT_JSON_BYTES)?;
        if digest(&metadata) != expected_etag {
            return Err(VaultError::Conflict {
                current_etag: Some(encode_etag(digest(&metadata))),
            });
        }
        let (config, _) = VaultConfig::parse_untrusted(&metadata, policy)?;
        let unlocked = crypto::unlock_vault(&config, password, Some(slot_id), policy)?;
        self.config = config;
        self.config_etag = expected_etag;
        self.master_key = unlocked.master_key;
        self.unlocked_slot_id = unlocked.slot_id;
        self.warnings = unlocked.warnings;
        Ok(())
    }

    fn document_target(&self, logical_path: &LogicalPath) -> Result<PathBuf, VaultError> {
        let target = self.document_target_allow_absent(logical_path)?;
        match entry_state(&target)? {
            EntryState::Regular => {
                ensure_exact_entry_name(
                    target.parent().ok_or(VaultError::UnsafeFilesystemEntry)?,
                    target
                        .file_name()
                        .ok_or(VaultError::UnsafeFilesystemEntry)?,
                )?;
                ensure_same_mount(&self.root, &target)?;
                Ok(target)
            }
            EntryState::Absent => Err(VaultError::DocumentNotFound),
            EntryState::Unsafe => Err(VaultError::UnsafeFilesystemEntry),
        }
    }

    fn document_target_allow_absent(
        &self,
        logical_path: &LogicalPath,
    ) -> Result<PathBuf, VaultError> {
        let parent = self.directory_target(&logical_path.parent(), true)?;
        Ok(parent.join(
            logical_path
                .to_ciphertext_relative_path()
                .file_name()
                .ok_or(VaultError::UnsafeFilesystemEntry)?,
        ))
    }

    fn directory_target(
        &self,
        logical_dir: &LogicalDir,
        require_exists: bool,
    ) -> Result<PathBuf, VaultError> {
        let mut current = self.root.clone();
        for component in logical_dir.components() {
            let exact = exact_child_exists(&current, std::ffi::OsStr::new(component))?;
            current.push(component);
            if !exact {
                if entry_state(&current)? != EntryState::Absent {
                    return Err(VaultError::CaseFoldCollision);
                }
                if require_exists {
                    return Err(VaultError::ParentDirectoryMissing);
                }
                return Ok(current);
            }
            match entry_state(&current)? {
                EntryState::Regular | EntryState::Unsafe => {
                    let metadata = fs::symlink_metadata(&current)
                        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
                    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
                        return Err(VaultError::UnsafeFilesystemEntry);
                    }
                    ensure_same_mount(&self.root, &current)?;
                }
                EntryState::Absent if require_exists => {
                    return Err(VaultError::ParentDirectoryMissing);
                }
                EntryState::Absent => return Ok(current),
            }
        }
        Ok(current)
    }

    fn ensure_destination_available_locked(
        &self,
        logical_path: &LogicalPath,
    ) -> Result<(), VaultError> {
        let tree = tree::scan_vault_tree(&self.root)?;
        ensure_directory_spelling(&tree, &logical_path.parent())?;
        ensure_logical_name_available(&tree, logical_path.as_str())?;
        match self.document_entry_state(logical_path)? {
            EntryState::Absent => Ok(()),
            EntryState::Regular => Err(VaultError::AlreadyExists),
            EntryState::Unsafe => Err(VaultError::UnsafeFilesystemEntry),
        }
    }

    fn document_entry_state(&self, logical_path: &LogicalPath) -> Result<EntryState, VaultError> {
        let target = self.document_target_allow_absent(logical_path)?;
        let parent = target.parent().ok_or(VaultError::UnsafeFilesystemEntry)?;
        let name = target
            .file_name()
            .ok_or(VaultError::UnsafeFilesystemEntry)?;
        if exact_child_exists(parent, name)? {
            entry_state(&target)
        } else {
            Ok(EntryState::Absent)
        }
    }

    fn acquire_mutation_guard(&mut self) -> Result<VaultMutationGuard, VaultError> {
        let guard = VaultMutationGuard::acquire(&self.root).map_err(map_atomic_error)?;
        if guard.recovery_changed_repository() {
            self.invalidate_search_index();
        }
        Ok(guard)
    }

    fn invalidate_search_index(&mut self) {
        self.search_index.clear();
        self.search_index_ready = false;
        self.search_fingerprint = None;
    }

    fn repository_fingerprint(
        &self,
        guard: &VaultMutationGuard,
        tree: &VaultTree,
    ) -> Result<[u8; 32], VaultError> {
        let mut hasher = Sha256::new();
        hasher.update(b"INEX-SEARCH-FINGERPRINT-V1\0");
        for entry in tree.entries() {
            hasher.update([match entry.kind() {
                TreeEntryKind::Directory => 0,
                TreeEntryKind::File => 1,
            }]);
            let path = entry.logical_path().as_bytes();
            hasher.update(u32::try_from(path.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(path);
            if entry.kind() == TreeEntryKind::File {
                let logical_path = LogicalPath::parse_canonical(entry.logical_path())?;
                let target = self.document_target(&logical_path)?;
                match guard.inspect(&target).map_err(map_atomic_error)? {
                    CurrentTarget::File(etag) => hasher.update(etag),
                    CurrentTarget::Absent => return Err(VaultError::DocumentNotFound),
                    CurrentTarget::Other => return Err(VaultError::UnsafeFilesystemEntry),
                }
            }
        }
        Ok(hasher.finalize().into())
    }
}

fn document_metadata(
    encrypted: EncryptedDocument,
    outcome: AtomicWriteOutcome,
) -> DocumentMetadata {
    DocumentMetadata {
        header: encrypted.header,
        etag: encrypted.etag,
        parent_sync: outcome.parent_sync,
    }
}

fn contains_diff3_markers(plaintext: &[u8]) -> bool {
    plaintext.split(|byte| *byte == b'\n').any(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        line.starts_with(b"<<<<<<< ")
            || line.starts_with(b"||||||| ")
            || line == b"======="
            || line.starts_with(b">>>>>>> ")
    })
}

fn rename_outcome(encrypted: EncryptedDocument, outcome: AtomicRebindOutcome) -> RenameOutcome {
    RenameOutcome {
        document: DocumentMetadata {
            header: encrypted.header,
            etag: encrypted.etag,
            parent_sync: outcome.destination_parent_sync,
        },
        source_parent_sync: outcome.source_parent_sync,
    }
}

fn prepare_vault_root(root: &Path) -> Result<PathBuf, VaultError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => validate_directory_metadata(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(root)
                .map_err(|error| io_error(VaultIoOperation::CreateDirectory, &error))?;
            restrict_directory_permissions_best_effort(root);
        }
        Err(error) => return Err(io_error(VaultIoOperation::Inspect, &error)),
    }
    resolve_existing_vault_root(root)
}

fn resolve_existing_vault_root(root: &Path) -> Result<PathBuf, VaultError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    validate_directory_metadata(&metadata)?;
    let resolved = fs::canonicalize(root)
        .map_err(|error| io_error(VaultIoOperation::CanonicalizeRoot, &error))?;
    let resolved_metadata = fs::symlink_metadata(&resolved)
        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    validate_directory_metadata(&resolved_metadata)?;
    let local = crate::atomic::path_is_supported_local_filesystem(&resolved)
        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    if !local {
        return Err(VaultError::UnsupportedFilesystem);
    }
    Ok(resolved)
}

fn validate_directory_metadata(metadata: &Metadata) -> Result<(), VaultError> {
    if is_link_or_reparse_point(metadata) || !metadata.file_type().is_dir() {
        Err(VaultError::UnsafeFilesystemEntry)
    } else {
        Ok(())
    }
}

fn ensure_uninitialized_root(root: &Path) -> Result<(), VaultError> {
    for entry in fs::read_dir(root).map_err(|error| io_error(VaultIoOperation::Inspect, &error))? {
        let entry = entry.map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(VaultError::UnsafeFilesystemEntry);
        };
        if name.eq_ignore_ascii_case(VAULT_CONFIG_FILE) {
            return Err(VaultError::AlreadyInitialized);
        }
        if name.eq_ignore_ascii_case(crate::atomic::VAULT_LOCAL_DIRECTORY)
            && name != crate::atomic::VAULT_LOCAL_DIRECTORY
        {
            return Err(VaultError::UnsafeFilesystemEntry);
        }
    }
    tree::scan_vault_tree(root)?;
    Ok(())
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, VaultError> {
    let file = open_regular_file_bounded(path, maximum)?;
    let handle_metadata = file
        .metadata()
        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;

    let mut bytes = Vec::with_capacity(
        usize::try_from(handle_metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    (&file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(VaultIoOperation::Read, &error))?;
    if bytes.len() > maximum {
        return Err(VaultError::FileTooLarge);
    }
    let still_current = open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    if !still_current {
        return Err(VaultError::UnsafeFilesystemEntry);
    }
    Ok(bytes)
}

fn ensure_regular_file_bounded(path: &Path, maximum: usize) -> Result<(), VaultError> {
    drop(open_regular_file_bounded(path, maximum)?);
    Ok(())
}

fn open_regular_file_bounded(path: &Path, maximum: usize) -> Result<File, VaultError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(VaultError::DocumentNotFound);
        }
        Err(error) => return Err(io_error(VaultIoOperation::Inspect, &error)),
    };
    validate_regular_file_metadata(&metadata, maximum)?;

    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow_read(&mut options);
    let file = options
        .open(path)
        .map_err(|error| io_error(VaultIoOperation::Open, &error))?;
    let handle_metadata = file
        .metadata()
        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    validate_regular_file_metadata(&handle_metadata, maximum)?;
    let safe = open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    if !safe {
        return Err(VaultError::UnsafeFilesystemEntry);
    }
    Ok(file)
}

fn validate_regular_file_metadata(metadata: &Metadata, maximum: usize) -> Result<(), VaultError> {
    if is_link_or_reparse_point(metadata) || !metadata.file_type().is_file() {
        return Err(VaultError::UnsafeFilesystemEntry);
    }
    if metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(VaultError::FileTooLarge);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_no_follow_read(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    // Linux `O_NOFOLLOW`; opening the final component fails if it became a
    // symlink after the link-aware metadata check.
    const O_NOFOLLOW: i32 = 0o400_000;
    options.custom_flags(O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_no_follow_read(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    // Open the reparse point itself so handle metadata can reject junctions,
    // mount points, and symbolic links instead of following them.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(target_os = "linux", windows)))]
fn configure_no_follow_read(_options: &mut OpenOptions) {}

fn ensure_logical_name_available(tree: &VaultTree, candidate: &str) -> Result<(), VaultError> {
    let candidate_file = LogicalPath::parse_canonical(candidate).ok();
    let candidate_dir = LogicalDir::parse_canonical(candidate).ok();
    let candidate_fold = candidate_file
        .as_ref()
        .map(|path| path.case_fold_key().as_str().to_owned())
        .or_else(|| {
            candidate_dir
                .as_ref()
                .map(|path| path.case_fold_key().as_str().to_owned())
        })
        .ok_or(VaultError::UnsafeFilesystemEntry)?;

    for entry in tree.entries() {
        if entry.logical_path() == candidate {
            return Err(VaultError::AlreadyExists);
        }
        let existing_fold = match entry.kind() {
            TreeEntryKind::File => LogicalPath::parse_canonical(entry.logical_path())?
                .case_fold_key()
                .as_str()
                .to_owned(),
            TreeEntryKind::Directory => LogicalDir::parse_canonical(entry.logical_path())?
                .case_fold_key()
                .as_str()
                .to_owned(),
        };
        if existing_fold == candidate_fold {
            return Err(VaultError::CaseFoldCollision);
        }
    }
    Ok(())
}

fn ensure_directory_spelling(tree: &VaultTree, requested: &LogicalDir) -> Result<(), VaultError> {
    if requested.is_root() {
        return Ok(());
    }

    let mut prefix = LogicalDir::root();
    for component in requested.components() {
        prefix = prefix.join_dir(component)?;
        let requested_fold = prefix.case_fold_key();
        let mut exact = false;
        for entry in tree.entries() {
            if entry.kind() != TreeEntryKind::Directory {
                continue;
            }
            let existing = LogicalDir::parse_canonical(entry.logical_path())?;
            if existing == prefix {
                exact = true;
                break;
            }
            if existing.case_fold_key() == requested_fold {
                return Err(VaultError::CaseFoldCollision);
            }
        }
        if !exact {
            return Err(VaultError::ParentDirectoryMissing);
        }
    }
    Ok(())
}

fn exact_child_exists(parent: &Path, expected_name: &std::ffi::OsStr) -> Result<bool, VaultError> {
    let expected = expected_name
        .to_str()
        .ok_or(VaultError::UnsafeFilesystemEntry)?;
    let expected_fold = portable_case_fold(expected);
    let mut matching = 0_usize;
    let mut exact = 0_usize;
    let entries =
        fs::read_dir(parent).map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
        let name = entry.file_name();
        let text = name.to_str().ok_or(VaultError::UnsafeFilesystemEntry)?;
        if portable_case_fold(text) == expected_fold {
            matching = matching.saturating_add(1);
            if text == expected {
                exact = exact.saturating_add(1);
            }
        }
    }
    match (matching, exact) {
        (0, 0) => Ok(false),
        (1, 1) => Ok(true),
        _ => Err(VaultError::CaseFoldCollision),
    }
}

fn unique_exact_ascii_child(parent: &Path, expected: &str) -> Result<bool, VaultError> {
    let mut matching = 0_usize;
    let mut exact = 0_usize;
    for entry in
        fs::read_dir(parent).map_err(|error| io_error(VaultIoOperation::Inspect, &error))?
    {
        let entry = entry.map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
        let name = entry.file_name();
        let text = name.to_str().ok_or(VaultError::UnsafeFilesystemEntry)?;
        if text.eq_ignore_ascii_case(expected) {
            matching += 1;
            if text == expected {
                exact += 1;
            }
        }
    }
    match (matching, exact) {
        (0, 0) => Ok(false),
        (1, 1) => Ok(true),
        _ => Err(VaultError::UnsafeFilesystemEntry),
    }
}

fn ensure_exact_entry_name(
    parent: &Path,
    expected_name: &std::ffi::OsStr,
) -> Result<(), VaultError> {
    if exact_child_exists(parent, expected_name)? {
        Ok(())
    } else {
        Err(VaultError::CaseFoldCollision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryState {
    Absent,
    Regular,
    Unsafe,
}

fn entry_state(path: &Path) -> Result<EntryState, VaultError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_or_reparse_point(&metadata) => Ok(EntryState::Unsafe),
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_dir() => {
            Ok(EntryState::Regular)
        }
        Ok(_) => Ok(EntryState::Unsafe),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(EntryState::Absent),
        Err(error) => Err(io_error(VaultIoOperation::Inspect, &error)),
    }
}

fn reject_existing_entry(path: &Path) -> Result<(), VaultError> {
    match entry_state(path)? {
        EntryState::Absent => Ok(()),
        EntryState::Regular => Err(VaultError::AlreadyExists),
        EntryState::Unsafe => Err(VaultError::UnsafeFilesystemEntry),
    }
}

fn decode_etag(value: &str) -> Result<[u8; 32], VaultError> {
    let hexadecimal = value
        .strip_prefix(format::ETAG_PREFIX)
        .ok_or(VaultError::InvalidEtag)?;
    if hexadecimal.len() != 64
        || !hexadecimal
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultError::InvalidEtag);
    }
    let mut result = [0_u8; 32];
    for (index, pair) in hexadecimal.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(result)
}

fn hex_nibble(byte: u8) -> Result<u8, VaultError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(VaultError::InvalidEtag),
    }
}

fn encode_etag(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(format::ETAG_PREFIX.len() + 64);
    encoded.push_str(format::ETAG_PREFIX);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn map_atomic_error(error: AtomicWriteError) -> VaultError {
    match error {
        AtomicWriteError::Conflict { current } => VaultError::Conflict {
            current_etag: match current {
                CurrentTarget::File(digest) => Some(encode_etag(digest)),
                CurrentTarget::Absent | CurrentTarget::Other => None,
            },
        },
        AtomicWriteError::InvalidTarget | AtomicWriteError::UnsafeLockPath => {
            VaultError::UnsafeFilesystemEntry
        }
        AtomicWriteError::StagingVerificationFailed => VaultError::AtomicVerificationFailed,
        AtomicWriteError::TargetTooLarge => VaultError::FileTooLarge,
        AtomicWriteError::NamespaceCommitIndeterminate { expected_etag } => {
            VaultError::NamespaceCommitIndeterminate {
                expected_etag: encode_etag(expected_etag),
            }
        }
        AtomicWriteError::RebindPending { destination_etag } => VaultError::RenameRecoveryPending {
            destination_etag: encode_etag(destination_etag),
        },
        AtomicWriteError::RebindRecoveryConflict => VaultError::RenameRecoveryConflict,
        AtomicWriteError::Io { stage: _, source } => VaultError::Io {
            operation: VaultIoOperation::Read,
            kind: source.kind(),
        },
    }
}

fn io_error(operation: VaultIoOperation, error: &io::Error) -> VaultError {
    VaultError::Io {
        operation,
        kind: error.kind(),
    }
}

fn ensure_same_mount(root: &Path, path: &Path) -> Result<(), VaultError> {
    let same = paths_share_mount(root, path)
        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    if same {
        Ok(())
    } else {
        Err(VaultError::UnsupportedFilesystem)
    }
}

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

    const REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::search::CaseSensitivity;

    use super::*;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "inex-vault-test-{}-{nanos}-{counter}",
                std::process::id()
            ));
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

    fn test_policy() -> KdfPolicy {
        KdfPolicy {
            min_creation_ops_limit: 1,
            min_creation_mem_limit_bytes: 8 * 1024,
            max_creation_ops_limit: 4,
            max_creation_mem_limit_bytes: 64 * 1024 * 1024,
            max_unlock_ops_limit: 4,
            max_unlock_mem_limit_bytes: 64 * 1024 * 1024,
        }
    }

    fn test_params() -> Argon2idParams {
        Argon2idParams {
            ops_limit: 1,
            mem_limit_bytes: 8 * 1024,
        }
    }

    fn logical(value: &str) -> LogicalPath {
        LogicalPath::parse_canonical(value)
            .unwrap_or_else(|error| panic!("invalid test logical path: {error}"))
    }

    fn create_test_vault(directory: &TestDirectory) -> Vault {
        Vault::create_with_params(
            directory.path(),
            b"old password",
            1_783_699_200_000,
            test_params(),
            test_policy(),
        )
        .unwrap_or_else(|error| panic!("test vault creation failed: {error}"))
    }

    #[test]
    fn create_unlock_read_save_and_fresh_nonce_round_trip() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("2026-07-11.md");
        let created = vault
            .create_document(&path, "# 初稿\r\n".as_bytes(), 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        let first_bytes = fs::read(directory.path().join("2026-07-11.md.enc"))
            .unwrap_or_else(|error| panic!("ciphertext read failed: {error}"));

        let saved = vault
            .save_document(
                &path,
                "# 初稿\r\n".as_bytes(),
                &created.etag,
                1_783_699_202_000,
            )
            .unwrap_or_else(|error| panic!("save failed: {error}"));
        let second_bytes = fs::read(directory.path().join("2026-07-11.md.enc"))
            .unwrap_or_else(|error| panic!("ciphertext read failed: {error}"));
        assert_ne!(first_bytes, second_bytes);
        assert_ne!(created.etag, saved.etag);
        assert_eq!(created.header.file_id, saved.header.file_id);

        drop(vault);
        let reopened = Vault::unlock(directory.path(), b"old password", None, test_policy())
            .unwrap_or_else(|error| panic!("unlock failed: {error}"));
        let plaintext = reopened
            .read(&path)
            .unwrap_or_else(|error| panic!("read failed: {error}"));
        assert_eq!(plaintext.plaintext.as_slice(), "# 初稿\r\n".as_bytes());
    }

    #[test]
    fn stale_save_is_rejected_and_debug_redacts_root_and_plaintext() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("secret.md");
        let created = vault
            .create_document(&path, b"canary plaintext", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        let saved = vault
            .save_document(&path, b"replacement", &created.etag, 1_783_699_202_000)
            .unwrap_or_else(|error| panic!("save failed: {error}"));
        let stale = vault.save_document(&path, b"do not commit", &created.etag, 1_783_699_203_000);
        assert!(matches!(stale, Err(VaultError::Conflict { .. })));
        let debug = format!("{vault:?}");
        assert!(!debug.contains(directory.path().to_string_lossy().as_ref()));
        assert!(!debug.contains("canary plaintext"));
        assert_eq!(
            vault
                .read(&path)
                .unwrap_or_else(|error| panic!("read failed: {error}"))
                .etag,
            saved.etag
        );
    }

    #[test]
    fn directories_tree_search_and_mutation_invalidation_work() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let year = LogicalDir::parse_canonical("2026")
            .unwrap_or_else(|error| panic!("directory failed: {error}"));
        vault
            .create_directory(&year)
            .unwrap_or_else(|error| panic!("mkdir failed: {error}"));
        let path = logical("2026/entry.md");
        vault
            .create_document(&path, "alpha 世界\n".as_bytes(), 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        let tree = vault
            .list()
            .unwrap_or_else(|error| panic!("list failed: {error}"));
        assert_eq!(tree.len(), 2);
        assert_eq!(
            vault
                .rebuild_search_index()
                .unwrap_or_else(|error| panic!("rebuild failed: {error}")),
            1
        );
        let query = SearchQuery::with_defaults(
            Zeroizing::new("世界".to_owned()),
            CaseSensitivity::Sensitive,
        )
        .unwrap_or_else(|error| panic!("query failed: {error}"));
        assert_eq!(
            vault
                .search(&query)
                .unwrap_or_else(|error| panic!("search failed: {error}"))
                .len(),
            1
        );
        let current = vault
            .read(&path)
            .unwrap_or_else(|error| panic!("read failed: {error}"));
        vault
            .save_document(&path, b"beta", &current.etag, 1_783_699_202_000)
            .unwrap_or_else(|error| panic!("save failed: {error}"));
        assert!(matches!(
            vault.search(&query),
            Err(VaultError::SearchIndexNotReady)
        ));
    }

    #[test]
    fn search_detects_ciphertext_changes_from_another_vault_session() {
        let directory = TestDirectory::new();
        let mut first = create_test_vault(&directory);
        let path = logical("shared.md");
        let created = first
            .create_document(&path, b"old needle", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        first
            .rebuild_search_index()
            .unwrap_or_else(|error| panic!("rebuild failed: {error}"));
        let query = SearchQuery::with_defaults(
            Zeroizing::new("needle".to_owned()),
            CaseSensitivity::Sensitive,
        )
        .unwrap_or_else(|error| panic!("query failed: {error}"));
        assert_eq!(
            first
                .search(&query)
                .unwrap_or_else(|error| panic!("initial search failed: {error}"))
                .len(),
            1
        );

        let mut second = Vault::unlock(directory.path(), b"old password", None, test_policy())
            .unwrap_or_else(|error| panic!("second unlock failed: {error}"));
        second
            .save_document(&path, b"replacement", &created.etag, 1_783_699_202_000)
            .unwrap_or_else(|error| panic!("second save failed: {error}"));

        assert!(matches!(
            first.search(&query),
            Err(VaultError::SearchIndexNotReady)
        ));
    }

    #[test]
    fn search_detects_same_size_tampering_with_restored_timestamps() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("metadata-collision.md");
        vault
            .create_document(&path, b"old needle", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        vault
            .rebuild_search_index()
            .unwrap_or_else(|error| panic!("rebuild failed: {error}"));
        let query = SearchQuery::with_defaults(
            Zeroizing::new("needle".to_owned()),
            CaseSensitivity::Sensitive,
        )
        .unwrap_or_else(|error| panic!("query failed: {error}"));

        let target = directory.path().join("metadata-collision.md.enc");
        let metadata = fs::metadata(&target)
            .unwrap_or_else(|error| panic!("ciphertext metadata failed: {error}"));
        let accessed = metadata
            .accessed()
            .unwrap_or_else(|error| panic!("access time failed: {error}"));
        let modified = metadata
            .modified()
            .unwrap_or_else(|error| panic!("modification time failed: {error}"));
        let mut bytes =
            fs::read(&target).unwrap_or_else(|error| panic!("ciphertext read failed: {error}"));
        let last = bytes
            .last_mut()
            .unwrap_or_else(|| panic!("ciphertext unexpectedly empty"));
        *last ^= 1;
        fs::write(&target, bytes)
            .unwrap_or_else(|error| panic!("same-size ciphertext rewrite failed: {error}"));
        let file = OpenOptions::new()
            .write(true)
            .open(&target)
            .unwrap_or_else(|error| panic!("timestamp restore open failed: {error}"));
        file.set_times(
            std::fs::FileTimes::new()
                .set_accessed(accessed)
                .set_modified(modified),
        )
        .unwrap_or_else(|error| panic!("timestamp restore failed: {error}"));

        assert!(matches!(
            vault.search(&query),
            Err(VaultError::SearchIndexNotReady)
        ));
    }

    #[test]
    fn encrypted_draft_binds_path_kind_and_base_etag() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("draft.md");
        let committed = vault
            .create_document(&path, b"base", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        let draft = vault
            .encrypt_draft(
                &path,
                b"unsaved secret",
                Some(&committed.etag),
                1_783_699_202_000,
            )
            .unwrap_or_else(|error| panic!("draft encrypt failed: {error}"));
        assert!(!String::from_utf8_lossy(&draft.bytes).contains("unsaved secret"));
        let decrypted = vault
            .decrypt_draft(&path, &draft.bytes)
            .unwrap_or_else(|error| panic!("draft decrypt failed: {error}"));
        assert_eq!(decrypted.plaintext.as_slice(), b"unsaved secret");
        assert_eq!(
            decrypted.header.base_etag,
            Some(
                decode_etag(&committed.etag).unwrap_or_else(|error| panic!("etag failed: {error}"))
            )
        );
        assert!(vault.read(&path).is_ok());
        assert!(
            vault
                .decrypt_draft(&logical("other.md"), &draft.bytes)
                .is_err()
        );
    }

    #[test]
    fn new_draft_rejects_ascii_and_unicode_casefold_aliases() {
        let directory = TestDirectory::new();
        let vault = create_test_vault(&directory);
        for (physical_alias, requested) in [
            ("Entry.md.enc", "entry.md"),
            ("STRASSE.md.enc", "straße.md"),
        ] {
            let alias = directory.path().join(physical_alias);
            fs::write(&alias, b"opaque collision")
                .unwrap_or_else(|error| panic!("draft alias create failed: {error}"));
            assert!(matches!(
                vault.encrypt_draft(
                    &logical(requested),
                    b"must not encrypt against an aliased path",
                    None,
                    1_783_699_201_000,
                ),
                Err(VaultError::CaseFoldCollision)
            ));
            fs::remove_file(alias)
                .unwrap_or_else(|error| panic!("draft alias cleanup failed: {error}"));
        }
    }

    #[test]
    fn password_change_keeps_edry_bytes_and_new_slot_survives_old_removal() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("password.md");
        vault
            .create_document(&path, b"unchanged", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        let before = fs::read(directory.path().join("password.md.enc"))
            .unwrap_or_else(|error| panic!("read failed: {error}"));
        let old_slot = vault.unlocked_slot_id();
        let committed = vault
            .add_password_slot(
                b"new password",
                1_783_699_202_000,
                test_params(),
                test_policy(),
            )
            .unwrap_or_else(|error| panic!("add slot failed: {error}"));
        vault
            .remove_password_slot(
                old_slot,
                b"new password",
                committed.new_slot_id,
                test_policy(),
            )
            .unwrap_or_else(|error| panic!("remove slot failed: {error}"));
        let after = fs::read(directory.path().join("password.md.enc"))
            .unwrap_or_else(|error| panic!("read failed: {error}"));
        assert_eq!(before, after);
        drop(vault);
        assert!(
            Vault::unlock(
                directory.path(),
                b"new password",
                Some(committed.new_slot_id),
                test_policy()
            )
            .is_ok()
        );
        assert!(Vault::unlock(directory.path(), b"old password", None, test_policy()).is_err());
    }

    #[test]
    fn password_slot_addition_never_weakens_authenticated_work_factors() {
        let directory = TestDirectory::new();
        let mut vault = Vault::create_with_params(
            directory.path(),
            b"old password",
            1_783_699_200_000,
            Argon2idParams {
                ops_limit: 2,
                mem_limit_bytes: 16 * 1024,
            },
            test_policy(),
        )
        .unwrap_or_else(|error| panic!("strong test vault creation failed: {error}"));
        let committed = vault
            .add_password_slot(
                b"new password",
                1_783_699_202_000,
                test_params(),
                test_policy(),
            )
            .unwrap_or_else(|error| panic!("slot add failed: {error}"));
        let slot = vault
            .config()
            .key_slot(committed.new_slot_id)
            .unwrap_or_else(|error| panic!("new slot missing: {error}"));
        assert_eq!(slot.kdf.ops_limit, 2);
        assert_eq!(slot.kdf.mem_limit_bytes, 16 * 1024);
    }

    #[test]
    fn calibrated_password_change_preserves_slot_above_creation_cap() {
        let directory = TestDirectory::new();
        let strong_memory = crate::vault_config::DEFAULT_MAX_CREATION_MEM_LIMIT_BYTES + 8 * 1024;
        let strong_creation_policy = KdfPolicy {
            max_creation_mem_limit_bytes: strong_memory,
            ..KdfPolicy::default()
        };
        let mut vault = Vault::create_with_params(
            directory.path(),
            b"old password",
            1_783_699_200_000,
            Argon2idParams {
                ops_limit: crate::vault_config::MIN_CREATION_OPS_LIMIT,
                mem_limit_bytes: strong_memory,
            },
            strong_creation_policy,
        )
        .unwrap_or_else(|error| panic!("strong vault creation failed: {error}"));

        let rewrap_params = vault
            .calibrated_password_rewrap_params(KdfPolicy::default())
            .unwrap_or_else(|error| panic!("rewrap calibration failed: {error}"));
        assert_eq!(rewrap_params.mem_limit_bytes, strong_memory);
        let committed = vault
            .change_password(
                b"new password",
                1_783_699_202_000,
                rewrap_params,
                KdfPolicy::default(),
            )
            .unwrap_or_else(|error| panic!("strong password change failed: {error}"));
        let slot = vault
            .config()
            .key_slot(committed.new_slot_id)
            .unwrap_or_else(|error| panic!("new strong slot missing: {error}"));
        assert_eq!(slot.kdf.ops_limit, rewrap_params.ops_limit);
        assert_eq!(slot.kdf.mem_limit_bytes, strong_memory);
        drop(vault);

        assert!(
            Vault::unlock(
                directory.path(),
                b"new password",
                Some(committed.new_slot_id),
                KdfPolicy::default(),
            )
            .is_ok()
        );
    }

    #[test]
    fn symlink_document_and_plaintext_markdown_fail_closed() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        fs::write(directory.path().join("leak.md"), b"plaintext")
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        assert!(matches!(
            vault.list(),
            Err(VaultError::Tree(TreeError::PlaintextMarkdown { .. }))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let target = directory.path().join("outside");
            fs::write(&target, b"not edry").unwrap_or_else(|error| panic!("write failed: {error}"));
            symlink(&target, directory.path().join("linked.md.enc"))
                .unwrap_or_else(|error| panic!("symlink failed: {error}"));
            assert!(matches!(
                vault.read(&logical("linked.md")),
                Err(VaultError::UnsafeFilesystemEntry)
            ));
        }
    }

    #[test]
    fn rename_rebinds_aad_and_delete_is_conditioned() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let source = logical("source.md");
        let destination = logical("destination.md");
        let created = vault
            .create_document(&source, b"rename secret", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        vault
            .rebuild_search_index()
            .unwrap_or_else(|error| panic!("search rebuild failed: {error}"));

        let renamed = vault
            .rename_document(&source, &destination, &created.etag, 1_783_699_202_000)
            .unwrap_or_else(|error| panic!("rename failed: {error}"));
        assert_eq!(created.header.file_id, renamed.document.header.file_id);
        assert_eq!(renamed.document.header.logical_path, destination.as_str());
        assert!(matches!(
            vault.read(&source),
            Err(VaultError::DocumentNotFound)
        ));
        assert_eq!(
            vault
                .read(&destination)
                .unwrap_or_else(|error| panic!("destination read failed: {error}"))
                .plaintext
                .as_slice(),
            b"rename secret"
        );
        let query = SearchQuery::with_defaults(
            Zeroizing::new("rename".to_owned()),
            CaseSensitivity::Sensitive,
        )
        .unwrap_or_else(|error| panic!("query failed: {error}"));
        assert!(matches!(
            vault.search(&query),
            Err(VaultError::SearchIndexNotReady)
        ));

        let wrong_etag = encode_etag([0_u8; 32]);
        assert!(matches!(
            vault.delete_document(&destination, &wrong_etag),
            Err(VaultError::Conflict { .. })
        ));
        vault
            .delete_document(&destination, &renamed.document.etag)
            .unwrap_or_else(|error| panic!("delete failed: {error}"));
        assert!(matches!(
            vault.read(&destination),
            Err(VaultError::DocumentNotFound)
        ));
    }

    #[test]
    fn ancestor_spelling_aliases_fail_before_ciphertext_commit() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let canonical = LogicalDir::parse_canonical("Foo")
            .unwrap_or_else(|error| panic!("directory failed: {error}"));
        vault
            .create_directory(&canonical)
            .unwrap_or_else(|error| panic!("mkdir failed: {error}"));

        let result = vault.create_document(
            &logical("foo/new.md"),
            b"must not commit",
            1_783_699_201_000,
        );
        assert!(matches!(result, Err(VaultError::CaseFoldCollision)));
        assert!(!directory.path().join("Foo/new.md.enc").exists());

        let child = LogicalDir::parse_canonical("foo/child")
            .unwrap_or_else(|error| panic!("directory failed: {error}"));
        assert!(matches!(
            vault.create_directory(&child),
            Err(VaultError::CaseFoldCollision)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn direct_document_operations_reject_coexisting_casefold_aliases() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let notes = LogicalDir::parse_canonical("notes")
            .unwrap_or_else(|error| panic!("directory failed: {error}"));
        vault
            .create_directory(&notes)
            .unwrap_or_else(|error| panic!("mkdir failed: {error}"));
        let path = logical("notes/entry.md");
        let created = vault
            .create_document(&path, b"alias-sensitive", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));

        fs::create_dir(directory.path().join("NOTES"))
            .unwrap_or_else(|error| panic!("alias directory create failed: {error}"));
        assert!(matches!(
            vault.read(&path),
            Err(VaultError::CaseFoldCollision)
        ));
        fs::remove_dir(directory.path().join("NOTES"))
            .unwrap_or_else(|error| panic!("alias directory cleanup failed: {error}"));

        fs::copy(
            directory.path().join("notes/entry.md.enc"),
            directory.path().join("notes/Entry.md.enc"),
        )
        .unwrap_or_else(|error| panic!("alias ciphertext copy failed: {error}"));
        assert!(matches!(
            vault.read(&path),
            Err(VaultError::CaseFoldCollision)
        ));
        assert!(matches!(
            vault.save_document(&path, b"must not commit", &created.etag, 1_783_699_202_000,),
            Err(VaultError::CaseFoldCollision)
        ));
        assert!(matches!(
            vault.delete_document(&path, &created.etag),
            Err(VaultError::CaseFoldCollision)
        ));
    }

    #[test]
    fn oversized_and_hardlinked_envelopes_fail_before_decryption() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let huge_path = directory.path().join("huge.md.enc");
        let huge = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&huge_path)
            .unwrap_or_else(|error| panic!("huge file create failed: {error}"));
        huge.set_len(
            u64::try_from(MAX_EDRY_ENVELOPE_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .unwrap_or_else(|error| panic!("huge file resize failed: {error}"));
        assert!(matches!(
            vault.read(&logical("huge.md")),
            Err(VaultError::FileTooLarge)
        ));
        fs::remove_file(huge_path).unwrap_or_else(|error| panic!("huge cleanup failed: {error}"));

        let path = logical("linked-source.md");
        vault
            .create_document(&path, b"content", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        let physical = directory.path().join("linked-source.md.enc");
        let alias = directory.path().join("ciphertext-alias.bin");
        fs::hard_link(&physical, &alias)
            .unwrap_or_else(|error| panic!("hard link failed: {error}"));
        assert!(matches!(
            vault.read(&path),
            Err(VaultError::UnsafeFilesystemEntry)
        ));
        fs::remove_file(alias).unwrap_or_else(|error| panic!("hard-link cleanup failed: {error}"));
        assert!(vault.read(&path).is_ok());
    }

    #[test]
    fn hardlinked_vault_metadata_is_rejected_before_kdf() {
        let directory = TestDirectory::new();
        let vault = create_test_vault(&directory);
        drop(vault);
        let alias = directory.path().join("metadata-alias.bin");
        fs::hard_link(directory.path().join(VAULT_CONFIG_FILE), &alias)
            .unwrap_or_else(|error| panic!("metadata hard link failed: {error}"));
        assert!(matches!(
            Vault::unlock(directory.path(), b"old password", None, test_policy()),
            Err(VaultError::UnsafeFilesystemEntry)
        ));
        fs::remove_file(alias).unwrap_or_else(|error| panic!("metadata cleanup failed: {error}"));
        assert!(Vault::unlock(directory.path(), b"old password", None, test_policy()).is_ok());
    }

    #[test]
    fn oversized_vault_metadata_is_rejected_before_password_work() {
        let directory = TestDirectory::new();
        let vault = create_test_vault(&directory);
        drop(vault);
        let metadata = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(directory.path().join(VAULT_CONFIG_FILE))
            .unwrap_or_else(|error| panic!("metadata open failed: {error}"));
        metadata
            .set_len(
                u64::try_from(MAX_VAULT_JSON_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .unwrap_or_else(|error| panic!("metadata resize failed: {error}"));
        assert!(matches!(
            Vault::unlock(directory.path(), b"old password", None, test_policy()),
            Err(VaultError::FileTooLarge)
        ));
    }

    #[test]
    fn wrong_case_vault_metadata_name_is_never_opened() {
        let directory = TestDirectory::new();
        let vault = create_test_vault(&directory);
        drop(vault);
        let canonical = directory.path().join(VAULT_CONFIG_FILE);
        let bytes = fs::read(&canonical)
            .unwrap_or_else(|error| panic!("metadata read before recasing failed: {error}"));
        fs::remove_file(&canonical)
            .unwrap_or_else(|error| panic!("metadata removal before recasing failed: {error}"));
        fs::write(directory.path().join("VAULT.JSON"), bytes)
            .unwrap_or_else(|error| panic!("wrong-case metadata creation failed: {error}"));
        assert!(Vault::unlock(directory.path(), b"old password", None, test_policy()).is_err());
        assert!(matches!(
            Vault::create_with_params(
                directory.path(),
                b"different",
                1_783_699_200_000,
                test_params(),
                test_policy(),
            ),
            Err(VaultError::AlreadyInitialized)
        ));
    }

    #[test]
    fn invalid_creation_policy_has_no_absent_root_side_effect() {
        let directory = TestDirectory::new();
        assert!(!directory.path().exists());

        let mut explicit_policy = test_policy();
        explicit_policy.max_creation_ops_limit = 2;
        let explicit = Vault::create_with_params(
            directory.path(),
            b"new password",
            1_783_699_200_000,
            Argon2idParams {
                ops_limit: 3,
                mem_limit_bytes: 8 * 1024,
            },
            explicit_policy,
        );
        assert!(matches!(
            explicit,
            Err(VaultError::Crypto(CryptoError::Config(
                ConfigError::KdfAboveCreationPolicy
            )))
        ));
        assert!(!directory.path().exists());

        let calibrated_policy = KdfPolicy {
            max_creation_mem_limit_bytes: 32 * 1024 * 1024,
            ..KdfPolicy::default()
        };
        let calibrated = Vault::create_with_policy(
            directory.path(),
            b"new password",
            1_783_699_200_000,
            calibrated_policy,
        );
        assert!(matches!(
            calibrated,
            Err(VaultError::Crypto(CryptoError::Config(
                ConfigError::KdfAboveCreationPolicy
            )))
        ));
        assert!(!directory.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_and_wrong_case_vault_metadata_cannot_coexist() {
        let directory = TestDirectory::new();
        let vault = create_test_vault(&directory);
        drop(vault);
        fs::copy(
            directory.path().join(VAULT_CONFIG_FILE),
            directory.path().join("VAULT.JSON"),
        )
        .unwrap_or_else(|error| panic!("metadata alias copy failed: {error}"));
        assert!(matches!(
            Vault::unlock(directory.path(), b"old password", None, test_policy()),
            Err(VaultError::UnsafeFilesystemEntry)
        ));
    }

    #[test]
    fn etag_codec_is_canonical() {
        let bytes = [0xab; 32];
        let encoded = encode_etag(bytes);
        assert!(matches!(decode_etag(&encoded), Ok(decoded) if decoded == bytes));
        assert!(decode_etag("sha256:AB").is_err());
        assert!(decode_etag("abc").is_err());
    }

    #[test]
    fn diff3_marker_detection_is_line_scoped_and_crlf_aware() {
        assert!(contains_diff3_markers(b"<<<<<<< ours\nbody\n"));
        assert!(contains_diff3_markers(b"body\r\n=======\r\n"));
        assert!(contains_diff3_markers(b">>>>>>> theirs"));
        assert!(!contains_diff3_markers(b"quoted <<<<<<< ours\n"));
        assert!(!contains_diff3_markers(b"resolved body\n"));
    }
}
