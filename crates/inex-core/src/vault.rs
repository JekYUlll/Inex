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
    paths_share_mount, sync_directory,
};
use crate::crypto::{
    self, CryptoError, DecryptedAsset, DecryptedDocument, EncryptedAsset, EncryptedDocument,
    EnvelopeKind, ExpectedEnvelopeKind, FileIdentity, VaultContentProfile, VaultMasterKey,
};
use crate::format::{self, ContentFlags, EdryHeader};
use crate::path::{AssetPath, LogicalDir, LogicalPath, PathError, portable_case_fold};
use crate::search::{
    Document as SearchDocument, MemorySearchIndex, SearchError, SearchHit, SearchQuery,
};
use crate::sodium::Argon2idParams;
use crate::tree::{self, TreeEntryKind, TreeError, VaultTree, VaultTreeProfile};
use crate::umbra_config::{
    EncryptedUmbraConfigV1, UMBRA_CONFIG_PATH, UmbraConfigError, UmbraConfigV1,
};
use crate::umbra_document::{
    OuterSlotStrategy, PrivateAnnotationSpec, PrivateSlotPayloadV1, UmbraDocumentError,
    UmbraDocumentV1,
};
use crate::umbra_keyslot::{
    UMBRA_DEFAULT_KEYSLOT_PATH, UmbraKey, UmbraKeyslotError, UmbraKeyslotV1,
};
use crate::umbra_render::{
    OwnedRenderMap, RenderedUmbraProjection, SelectionClass, TextRange, UmbraRenderError,
    map_plain_ranges_to_outer, normalize_and_classify_selections, render_umbra_projection,
    validate_outer_marker_slots,
};
use crate::vault_config::{
    ConfigError, ConfigWarning, KdfPolicy, MAX_VAULT_JSON_BYTES, VaultConfig,
};

/// Fixed metadata filename at the root of every vault.
pub const VAULT_CONFIG_FILE: &str = "vault.json";

/// Largest complete EDRY envelope accepted from disk.
pub const MAX_EDRY_ENVELOPE_BYTES: usize =
    format::EDRY_PREFIX_LEN + format::MAX_HEADER_LEN + format::MAX_CIPHERTEXT_LEN;

/// Largest complete opaque-asset EDRY envelope accepted from disk.
pub const MAX_ASSET_EDRY_ENVELOPE_BYTES: usize = format::MAX_ASSET_ENVELOPE_BYTES;

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
    /// The requested logical asset does not exist as a regular ciphertext
    /// file.
    #[error("encrypted asset does not exist")]
    AssetNotFound,
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
    /// A canonical repository-import publication claim must be reconciled
    /// before this vault can be opened or mutated normally.
    #[error("repository publication reconciliation is required")]
    RepositoryPublicationReconcileRequired,
    /// Reserved repository-publication state is unsafe or unverifiable and
    /// must be preserved for manual audit.
    #[error("repository publication marker state requires manual audit")]
    RepositoryPublicationManualAuditRequired,
    /// A password-slot commit succeeded but re-opening it with the new
    /// password failed. The on-disk metadata is retained for recovery.
    #[error("password-slot metadata committed but post-commit verification failed")]
    PasswordCommitVerificationFailed,
    /// Umbra keyslot creation, authentication, or persistence failed.
    #[error(transparent)]
    UmbraKeyslot(#[from] UmbraKeyslotError),
    /// Umbra encrypted catalog/profile processing failed.
    #[error(transparent)]
    UmbraConfig(#[from] UmbraConfigError),
    /// Umbra Outer container processing failed.
    #[error(transparent)]
    UmbraDocument(#[from] UmbraDocumentError),
    /// Umbra projection rendering or selection-map processing failed.
    #[error(transparent)]
    UmbraRender(#[from] UmbraRenderError),
    /// An operation requires a currently unlocked Umbra session.
    #[error("Umbra is locked")]
    UmbraLocked,
    /// The sole Umbra password slot is not initialized for this vault.
    #[error("Umbra is not initialized")]
    UmbraNotInitialized,
    /// Umbra initialization was requested even though the slot already exists.
    #[error("Umbra is already initialized")]
    UmbraAlreadyInitialized,
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

/// Non-plaintext metadata returned after a create-only asset import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetMetadata {
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

/// Result of one atomic private-annotation wrap operation.
///
/// The projection is freshly rendered from the ciphertext that was just
/// committed. Callers must replace their old buffer and `RenderMap` together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedPrivateAnnotation {
    /// Metadata for the committed feature-2 document envelope.
    pub document: DocumentMetadata,
    /// Fresh unlocked projection and range map for the committed state.
    pub projection: RenderedUmbraProjection,
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
    umbra: Option<UmbraSession>,
}

/// Memory-only Umbra state. Dropping it clears the protected data key.
struct UmbraSession {
    slot: UmbraKeyslotV1,
    key: UmbraKey,
    slot_etag: [u8; 32],
    config_etag: Option<[u8; 32]>,
}

/// Non-secret Umbra session state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UmbraStatus {
    /// Whether a valid sole v1 password slot exists on disk.
    pub initialized: bool,
    /// Whether the current process session holds `K_umbra`.
    pub unlocked: bool,
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
            .field("umbra_unlocked", &self.umbra.is_some())
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
        Self::create_with_profile(
            root,
            password,
            created_at_ms,
            VaultContentProfile::DocumentsOnly,
        )
    }

    /// Create a vault with one explicit authenticated content profile.
    ///
    /// This is only a creation-time decision for a new vault. It does not
    /// upgrade an existing feature-free vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] under the same conditions as [`Self::create`].
    pub fn create_with_profile(
        root: impl AsRef<Path>,
        password: &[u8],
        created_at_ms: i64,
        profile: VaultContentProfile,
    ) -> Result<Self, VaultError> {
        Self::create_with_profile_and_policy(
            root,
            password,
            created_at_ms,
            profile,
            KdfPolicy::default(),
        )
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
        Self::create_with_profile_and_policy(
            root,
            password,
            created_at_ms,
            VaultContentProfile::DocumentsOnly,
            policy,
        )
    }

    /// Create a vault with an explicit content profile and calibrated policy.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for invalid calibration, unsafe storage,
    /// existing metadata, cryptographic failure, or failed verification.
    pub fn create_with_profile_and_policy(
        root: impl AsRef<Path>,
        password: &[u8],
        created_at_ms: i64,
        profile: VaultContentProfile,
        policy: KdfPolicy,
    ) -> Result<Self, VaultError> {
        let params = crypto::calibrated_creation_params(policy)?;
        Self::create_with_profile_and_params(root, password, created_at_ms, profile, params, policy)
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
        Self::create_with_profile_and_params(
            root,
            password,
            created_at_ms,
            VaultContentProfile::DocumentsOnly,
            params,
            policy,
        )
    }

    /// Create a vault with an explicit content profile and KDF parameters.
    ///
    /// This deterministic entry point is intended for new-vault import and
    /// tests. It never mutates an existing vault's required features.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for invalid input/policy, unsafe storage,
    /// existing metadata, cryptographic failure, or failed verification.
    pub fn create_with_profile_and_params(
        root: impl AsRef<Path>,
        password: &[u8],
        created_at_ms: i64,
        profile: VaultContentProfile,
        params: Argon2idParams,
        policy: KdfPolicy,
    ) -> Result<Self, VaultError> {
        crypto::validate_vault_creation_request(password, created_at_ms, params, policy)?;
        let root = prepare_vault_root(root.as_ref())?;
        ensure_uninitialized_root(&root, content_profile_to_tree_profile(profile))?;
        let created = crypto::create_vault_with_profile_and_params(
            password,
            created_at_ms,
            profile,
            params,
            policy,
        )?;
        Self::commit_created(&root, created, password, policy)
    }

    fn commit_created(
        root: &Path,
        created: crypto::CreatedVault,
        password: &[u8],
        policy: KdfPolicy,
    ) -> Result<Self, VaultError> {
        let tree_profile = tree_profile_for_config(&created.config);
        let metadata = created.config.to_json_bytes(policy)?;
        let target = root.join(VAULT_CONFIG_FILE);
        let guard = VaultMutationGuard::acquire(root).map_err(map_atomic_error)?;
        ensure_uninitialized_root(root, tree_profile)?;
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
        let _guard = VaultMutationGuard::acquire(&root).map_err(map_atomic_error)?;
        tree::scan_vault_tree_with_profile(&root, tree_profile_for_config(&config))?;

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
            umbra: None,
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

    /// Return only the current Umbra initialization and memory-lock state.
    ///
    /// This validates only public password-slot metadata when no live session
    /// exists; it never derives a KEK or decrypts `K_umbra`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe, malformed, or resource-exhausting
    /// public keyslot path.
    pub fn umbra_status(&self) -> Result<UmbraStatus, VaultError> {
        if self.umbra.is_some() {
            return Ok(UmbraStatus {
                initialized: true,
                unlocked: true,
            });
        }
        match load_umbra_keyslot(&self.root) {
            Ok(_) => Ok(UmbraStatus {
                initialized: true,
                unlocked: false,
            }),
            Err(VaultError::UmbraNotInitialized) => Ok(UmbraStatus {
                initialized: false,
                unlocked: false,
            }),
            Err(error) => Err(error),
        }
    }

    /// Initialize the sole v1 Umbra slot and retain its fresh key in memory.
    ///
    /// The caller must have already displayed and confirmed the unrecoverable
    /// password warning. This method never treats the Outer password as an
    /// Umbra credential.
    ///
    /// # Errors
    ///
    /// Returns an error if a slot already exists, internal storage is unsafe,
    /// the password is invalid, or atomic persistence fails.
    pub fn initialize_umbra(&mut self, password: &[u8]) -> Result<UmbraStatus, VaultError> {
        let keyslot_target = self.root.join(UMBRA_DEFAULT_KEYSLOT_PATH);
        let guard = self.acquire_mutation_guard()?;
        ensure_umbra_keyslot_parent(&self.root)?;
        match entry_state(&keyslot_target)? {
            EntryState::Absent => {}
            EntryState::Regular => return Err(VaultError::UmbraAlreadyInitialized),
            EntryState::Unsafe => return Err(VaultError::UnsafeFilesystemEntry),
        }
        let (slot, key) = UmbraKeyslotV1::initialize(self.config.vault_id, password)?;
        let bytes = slot.to_json()?;
        let outcome = guard
            .write(&keyslot_target, &bytes, WriteCondition::IfNoneMatch)
            .map_err(map_atomic_error)?;
        drop(guard);
        self.umbra = Some(UmbraSession {
            slot,
            key,
            slot_etag: outcome.etag,
            config_etag: None,
        });
        self.umbra_status()
    }

    /// Unlock `K_umbra` independently of the Outer vault password.
    ///
    /// # Errors
    ///
    /// Returns an error if Umbra is not initialized, public slot storage is
    /// unsafe, or the supplied password cannot authenticate the slot.
    pub fn unlock_umbra(&mut self, password: &[u8]) -> Result<UmbraStatus, VaultError> {
        let (slot, slot_etag) = load_umbra_keyslot(&self.root)?;
        let key = slot.unlock(self.config.vault_id, password)?;
        self.umbra = Some(UmbraSession {
            slot,
            key,
            slot_etag,
            config_etag: None,
        });
        self.umbra_status()
    }

    /// Clear `K_umbra` and all future private caches from this vault session.
    ///
    /// Private projections/indexes are added with the document-container
    /// milestone; this state transition already clears their key authority.
    pub fn lock_umbra(&mut self) {
        self.umbra = None;
    }

    /// Rewrap the live `K_umbra` with a new password without re-encrypting
    /// private slots or configuration.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without a live Umbra session, or an
    /// error if the replacement slot cannot be authenticated and committed.
    pub fn change_umbra_password(&mut self, new_password: &[u8]) -> Result<(), VaultError> {
        let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
        let replacement =
            session
                .slot
                .rewrap_unlocked(self.config.vault_id, new_password, &session.key)?;
        let bytes = replacement.to_json()?;
        let target = self.root.join(UMBRA_DEFAULT_KEYSLOT_PATH);
        let expected = session.slot_etag;
        let guard = self.acquire_mutation_guard()?;
        let outcome = guard
            .write(&target, &bytes, WriteCondition::IfMatch(expected))
            .map_err(map_atomic_error)?;
        drop(guard);
        let session = self.umbra.as_mut().ok_or(VaultError::UmbraLocked)?;
        session.slot = replacement;
        session.slot_etag = outcome.etag;
        Ok(())
    }

    /// Enable authenticated feature 2 after Umbra has been initialized and
    /// unlocked in this session.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without a live Umbra session, or an
    /// error if the metadata update conflicts or fails authentication.
    pub fn enable_umbra_private_annotations(
        &mut self,
        policy: KdfPolicy,
    ) -> Result<ParentSyncStatus, VaultError> {
        if self.umbra.is_none() {
            return Err(VaultError::UmbraLocked);
        }
        let updated =
            crypto::enable_umbra_private_annotations(&self.config, &self.master_key, policy)?;
        let metadata = updated.to_json_bytes(policy)?;
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
        let (reopened, _) = VaultConfig::parse_untrusted(&metadata, policy)?;
        // The constructor above has already authenticated the update. This
        // explicit byte/etag check prevents adopting a different commit.
        if digest(&metadata) != outcome.etag {
            return Err(VaultError::AtomicVerificationFailed);
        }
        self.config = reopened;
        self.config_etag = outcome.etag;
        Ok(outcome.parent_sync)
    }

    /// Load the encrypted shared tag catalog and annotation profiles.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] when no live `K_umbra` exists, or
    /// fails closed for unsafe paths, malformed ciphertext, and AEAD failure.
    pub fn load_umbra_config(&mut self) -> Result<UmbraConfigV1, VaultError> {
        if self.umbra.is_none() {
            return Err(VaultError::UmbraLocked);
        }
        let Some((bytes, etag)) = load_umbra_config_bytes(&self.root)? else {
            let session = self.umbra.as_mut().ok_or(VaultError::UmbraLocked)?;
            session.config_etag = None;
            return Ok(UmbraConfigV1::empty());
        };
        let session = self.umbra.as_mut().ok_or(VaultError::UmbraLocked)?;
        let envelope = EncryptedUmbraConfigV1::from_json(&bytes)?;
        let config = envelope.decrypt(self.config.vault_id, session.slot.key_id(), &session.key)?;
        session.config_etag = Some(etag);
        Ok(config)
    }

    /// Encrypt and atomically save the shared tag catalog and profiles.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] when no live `K_umbra` exists, or
    /// an error if CAS persistence or post-commit authentication fails.
    pub fn save_umbra_config(&mut self, config: &UmbraConfigV1) -> Result<(), VaultError> {
        let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
        let envelope = EncryptedUmbraConfigV1::encrypt(
            self.config.vault_id,
            session.slot.key_id(),
            &session.key,
            config,
        )?;
        let bytes = envelope.to_json()?;
        let target = self.root.join(UMBRA_CONFIG_PATH);
        let condition = match session.config_etag {
            Some(etag) => WriteCondition::IfMatch(etag),
            None => WriteCondition::IfNoneMatch,
        };
        let guard = self.acquire_mutation_guard()?;
        let outcome = guard
            .write(&target, &bytes, condition)
            .map_err(map_atomic_error)?;
        let (committed, committed_etag) =
            load_umbra_config_bytes(&self.root)?.ok_or(VaultError::AtomicVerificationFailed)?;
        if committed_etag != outcome.etag || committed != bytes {
            return Err(VaultError::AtomicVerificationFailed);
        }
        let session = self.umbra.as_mut().ok_or(VaultError::UmbraLocked)?;
        let committed_envelope = EncryptedUmbraConfigV1::from_json(&committed)?;
        let verified = committed_envelope.decrypt(
            self.config.vault_id,
            session.slot.key_id(),
            &session.key,
        )?;
        if &verified != config {
            return Err(VaultError::AtomicVerificationFailed);
        }
        session.config_etag = Some(outcome.etag);
        Ok(())
    }

    /// Discover a deterministic logical tree without opening document bytes.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the root contains an unsafe, plaintext,
    /// noncanonical, colliding, or resource-exhausting entry.
    pub fn list(&mut self) -> Result<VaultTree, VaultError> {
        let _guard = self.acquire_mutation_guard()?;
        self.scan_tree()
    }

    /// Read and authenticate one committed encrypted Markdown document.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the path chain/target is unsafe, the
    /// envelope exceeds its bound, framing/AAD authentication fails, or the
    /// document belongs to a different vault/path/epoch.
    pub fn read(&self, logical_path: &LogicalPath) -> Result<DecryptedDocument, VaultError> {
        let document = self.read_kind(logical_path, ExpectedEnvelopeKind::Committed)?;
        if !document.header.required_features.is_empty() {
            return Err(CryptoError::DocumentContextMismatch.into());
        }
        Ok(document)
    }

    /// Read one feature-2 Outer projection without decrypting private slots.
    ///
    /// This method is intentionally separate from [`Self::read`]: callers
    /// using the normal Markdown API must never receive an Umbra container in
    /// an editor buffer by accident. It does not require `K_umbra`, because
    /// the returned projection contains only public Outer Markdown and slot
    /// ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error unless the committed EDRY header requires exactly
    /// feature 2 and its decrypted body is a canonical Outer container.
    pub fn read_umbra_outer_document(
        &self,
        logical_path: &LogicalPath,
    ) -> Result<(DecryptedDocument, UmbraDocumentV1), VaultError> {
        let document = self.read_kind(logical_path, ExpectedEnvelopeKind::Committed)?;
        if document.header.required_features.as_slice()
            != [crate::features::UMBRA_PRIVATE_ANNOTATIONS_V1]
        {
            return Err(CryptoError::DocumentContextMismatch.into());
        }
        let outer = UmbraDocumentV1::from_json(document.plaintext.as_slice())?;
        Ok((document, outer))
    }

    /// Create and atomically commit one feature-2 Umbra Outer document.
    ///
    /// A live Umbra session is required even if the initial container has no
    /// slots, so the feature cannot be enabled or populated from Outer mode.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without `K_umbra`, or an error for
    /// a missing feature-2 metadata negotiation, invalid container, unsafe
    /// destination, or failed ciphertext commit.
    pub fn create_umbra_outer_document(
        &mut self,
        logical_path: &LogicalPath,
        document: &UmbraDocumentV1,
        modified_at_ms: i64,
    ) -> Result<DocumentMetadata, VaultError> {
        if self.umbra.is_none() {
            return Err(VaultError::UmbraLocked);
        }
        validate_outer_marker_slots(document)?;
        let plaintext = Zeroizing::new(document.to_json()?);
        let encrypted = crypto::encrypt_umbra_outer_document(
            &self.master_key,
            &self.config,
            logical_path,
            None,
            plaintext.as_slice(),
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

    /// Atomically upgrade one ordinary committed Markdown document into a
    /// feature-2 Umbra Outer container with the same public Markdown.
    ///
    /// The operation preserves the authenticated file identity and content
    /// flags, but changes the EDRY required-feature set only after a live
    /// Umbra session, feature-2 metadata negotiation, and the caller's
    /// current ciphertext etag have all been verified. It never decrypts or
    /// materializes any private slot because the initial container is empty.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without `K_umbra`, a conflict for a
    /// stale etag, or a context error when the document is already feature-2
    /// (or otherwise not an ordinary Markdown envelope).
    pub fn convert_document_to_umbra_outer(
        &mut self,
        logical_path: &LogicalPath,
        expected_etag: &str,
        modified_at_ms: i64,
    ) -> Result<DocumentMetadata, VaultError> {
        if self.umbra.is_none() {
            return Err(VaultError::UmbraLocked);
        }
        let mut current = self.read_kind(logical_path, ExpectedEnvelopeKind::Committed)?;
        if !current.header.required_features.is_empty() {
            return Err(CryptoError::DocumentContextMismatch.into());
        }
        require_matching_etag(&current, expected_etag)?;
        let identity = FileIdentity::from_header(&current.header);
        let flags = current.header.content_flags;
        let bytes = std::mem::take(&mut *current.plaintext);
        let markdown = match String::from_utf8(bytes) {
            Ok(markdown) => markdown,
            Err(error) => {
                let mut invalid = error.into_bytes();
                invalid.zeroize();
                return Err(CryptoError::InvalidMarkdownUtf8.into());
            }
        };
        let outer = UmbraDocumentV1::new(markdown);
        let plaintext = Zeroizing::new(outer.to_json()?);
        let encrypted = crypto::encrypt_umbra_outer_document(
            &self.master_key,
            &self.config,
            logical_path,
            Some(identity),
            plaintext.as_slice(),
            modified_at_ms,
            flags,
            EnvelopeKind::Committed,
        )?;
        let expected = decode_etag(expected_etag)?;
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

    /// Save an Umbra Outer projection while retaining its authenticated EDRY
    /// identity and requiring a live `K_umbra` session.
    ///
    /// Private slot ciphertext remains opaque to this method; dedicated
    /// private-slot mutation APIs will require and use the live key.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without a live session, or an
    /// error for an etag conflict, feature mismatch, invalid Outer container,
    /// unsafe target, or failed atomic ciphertext replacement.
    pub fn save_umbra_outer_document(
        &mut self,
        logical_path: &LogicalPath,
        document: &UmbraDocumentV1,
        expected_etag: &str,
        modified_at_ms: i64,
    ) -> Result<DocumentMetadata, VaultError> {
        if self.umbra.is_none() {
            return Err(VaultError::UmbraLocked);
        }
        let expected = decode_etag(expected_etag)?;
        let current = self.read_kind(logical_path, ExpectedEnvelopeKind::Committed)?;
        if current.header.required_features.as_slice()
            != [crate::features::UMBRA_PRIVATE_ANNOTATIONS_V1]
        {
            return Err(CryptoError::DocumentContextMismatch.into());
        }
        if decode_etag(&current.etag)? != expected {
            return Err(VaultError::Conflict {
                current_etag: Some(current.etag),
            });
        }
        let identity = FileIdentity::from_header(&current.header);
        let flags = current.header.content_flags;
        drop(current);

        validate_outer_marker_slots(document)?;
        let plaintext = Zeroizing::new(document.to_json()?);
        let encrypted = crypto::encrypt_umbra_outer_document(
            &self.master_key,
            &self.config,
            logical_path,
            Some(identity),
            plaintext.as_slice(),
            modified_at_ms,
            flags,
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

    /// Decrypt one private slot from a feature-2 document in the current
    /// Umbra session.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without `K_umbra`, or an error for
    /// a non-Umbra document, missing slot, or any authenticated slot failure.
    pub fn read_umbra_private_slot(
        &self,
        logical_path: &LogicalPath,
        slot_id: &str,
    ) -> Result<PrivateSlotPayloadV1, VaultError> {
        let (_, document) = self.read_umbra_outer_document(logical_path)?;
        let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
        Ok(document.decrypt_private_slot(
            self.config.vault_id,
            logical_path.as_str(),
            session.slot.key_id(),
            &session.key,
            slot_id,
        )?)
    }

    /// Render the fully unlocked canonical Umbra Markdown projection and its
    /// bounded private-block map.
    ///
    /// Outer clients must use [`Self::read_umbra_outer_document`] instead;
    /// this method requires a live `K_umbra` session and therefore never
    /// exposes private Markdown, kinds, or tags while Umbra is locked.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without `K_umbra`, or an error for
    /// a missing/tampered slot, an invalid marker-to-slot mapping, or invalid
    /// private payload.
    pub fn render_umbra_projection(
        &self,
        logical_path: &LogicalPath,
    ) -> Result<RenderedUmbraProjection, VaultError> {
        let (_, document) = self.read_umbra_outer_document(logical_path)?;
        let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
        let mut payloads = std::collections::BTreeMap::new();
        for slot_id in document.slots.keys() {
            let payload = document.decrypt_private_slot(
                self.config.vault_id,
                logical_path.as_str(),
                session.slot.key_id(),
                &session.key,
                slot_id,
            )?;
            payloads.insert(slot_id.clone(), payload);
        }
        Ok(render_umbra_projection(&document, &payloads)?)
    }

    /// Atomically wrap one or more plain Umbra projection selections in fresh
    /// encrypted private slots.
    ///
    /// The supplied projection and map must exactly match the currently
    /// authenticated document and `expected_etag`. This prevents a client
    /// from applying byte ranges calculated for stale content. All ranges use
    /// the same validated private annotation spec; overlapping ranges are
    /// merged and replacements run from the end of the Outer document.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without a live `K_umbra`,
    /// [`VaultError::Conflict`] for a stale ciphertext etag, and a
    /// secret-free render error when a selection is private, mixed, stale, or
    /// otherwise cannot be mapped to one Outer replacement. No mutation is
    /// written until every selection and private payload has been validated.
    #[allow(clippy::too_many_arguments)] // all editor-supplied consistency inputs are explicit at this boundary
    pub fn apply_private_annotation(
        &mut self,
        logical_path: &LogicalPath,
        expected_etag: &str,
        supplied_projection: &str,
        supplied_render_map: &OwnedRenderMap,
        selections: &[TextRange],
        spec: &PrivateAnnotationSpec,
        merge_adjacent: bool,
        modified_at_ms: i64,
    ) -> Result<AppliedPrivateAnnotation, VaultError> {
        spec.validate()?;
        let (read, mut document) = self.read_umbra_outer_document(logical_path)?;
        require_matching_etag(&read, expected_etag)?;

        let current_projection = {
            let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
            let mut payloads = std::collections::BTreeMap::new();
            for slot_id in document.slots.keys() {
                let payload = document.decrypt_private_slot(
                    self.config.vault_id,
                    logical_path.as_str(),
                    session.slot.key_id(),
                    &session.key,
                    slot_id,
                )?;
                payloads.insert(slot_id.clone(), payload);
            }
            render_umbra_projection(&document, &payloads)?
        };
        if supplied_projection != current_projection.markdown
            || supplied_render_map != &current_projection.render_map
        {
            return Err(UmbraRenderError::StaleRenderMap.into());
        }

        let SelectionClass::Plain(plain_ranges) = normalize_and_classify_selections(
            &current_projection.markdown,
            &current_projection.render_map,
            selections,
            merge_adjacent,
        )?
        else {
            return Err(UmbraRenderError::AnnotationSelectionNotPlain.into());
        };
        let outer_ranges =
            map_plain_ranges_to_outer(&current_projection.render_map, &plain_ranges)?;

        {
            let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
            for (projection_range, outer_range) in
                plain_ranges.iter().zip(outer_ranges.iter()).rev()
            {
                let slot_id = fresh_private_slot_id(&document);
                let payload = PrivateSlotPayloadV1 {
                    format: "inex-private-slot".to_owned(),
                    version: 1,
                    kind: spec.kind,
                    tag_ids: spec.tag_ids.clone(),
                    markdown: current_projection.markdown
                        [projection_range.start..projection_range.end]
                        .to_owned(),
                    created_at_ms: modified_at_ms,
                    updated_at_ms: modified_at_ms,
                };
                document.insert_private_slot(
                    self.config.vault_id,
                    logical_path.as_str(),
                    session.slot.key_id(),
                    &session.key,
                    slot_id.clone(),
                    spec.outer.clone(),
                    &payload,
                )?;
                let marker = format!("{{{{inex-private-slot:{slot_id}}}}}");
                document
                    .outer_markdown
                    .replace_range(outer_range.start..outer_range.end, &marker);
            }
        }
        validate_outer_marker_slots(&document)?;
        let metadata =
            self.save_umbra_outer_document(logical_path, &document, expected_etag, modified_at_ms)?;
        let projection = self.render_umbra_projection(logical_path)?;
        Ok(AppliedPrivateAnnotation {
            document: metadata,
            projection,
        })
    }

    /// Insert one fresh encrypted private slot and atomically persist the
    /// changed feature-2 Outer projection. `outer_markdown` must contain the
    /// new canonical marker and retain exactly one marker for every existing
    /// slot.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without `K_umbra`, or an error for
    /// a stale etag, invalid slot/payload, or failed atomic persistence.
    #[allow(clippy::too_many_arguments)] // annotation inputs are intentionally explicit at the security boundary
    pub fn insert_umbra_private_slot(
        &mut self,
        logical_path: &LogicalPath,
        expected_etag: &str,
        outer_markdown: String,
        slot_id: String,
        outer: OuterSlotStrategy,
        payload: &PrivateSlotPayloadV1,
        modified_at_ms: i64,
    ) -> Result<DocumentMetadata, VaultError> {
        let (read, mut document) = self.read_umbra_outer_document(logical_path)?;
        require_matching_etag(&read, expected_etag)?;
        let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
        document.insert_private_slot(
            self.config.vault_id,
            logical_path.as_str(),
            session.slot.key_id(),
            &session.key,
            slot_id,
            outer,
            payload,
        )?;
        document.outer_markdown = outer_markdown;
        validate_outer_marker_slots(&document)?;
        self.save_umbra_outer_document(logical_path, &document, expected_etag, modified_at_ms)
    }

    /// Replace one private slot's encrypted payload/metadata while retaining
    /// its stable slot ID, then atomically persist the containing document.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without `K_umbra`, or an error for
    /// a stale etag, missing slot, invalid payload, or failed persistence.
    #[allow(clippy::too_many_arguments)] // annotation inputs are intentionally explicit at the security boundary
    pub fn replace_umbra_private_slot(
        &mut self,
        logical_path: &LogicalPath,
        expected_etag: &str,
        slot_id: &str,
        outer: OuterSlotStrategy,
        payload: &PrivateSlotPayloadV1,
        modified_at_ms: i64,
    ) -> Result<DocumentMetadata, VaultError> {
        let (read, mut document) = self.read_umbra_outer_document(logical_path)?;
        require_matching_etag(&read, expected_etag)?;
        let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
        document.replace_private_slot(
            self.config.vault_id,
            logical_path.as_str(),
            session.slot.key_id(),
            &session.key,
            slot_id,
            outer,
            payload,
        )?;
        self.save_umbra_outer_document(logical_path, &document, expected_etag, modified_at_ms)
    }

    /// Decrypt and remove one complete private slot as one Vault mutation.
    ///
    /// The caller may use the returned private payload to restore plaintext
    /// into an Umbra projection only after the outer-container commit has
    /// succeeded. `outer_markdown` must remove the matching marker while
    /// retaining all other marker identities. This method never moves that
    /// payload into an Outer index.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::UmbraLocked`] without `K_umbra`, or an error for
    /// a stale etag, missing/tampered slot, or failed persistence.
    pub fn remove_umbra_private_slot(
        &mut self,
        logical_path: &LogicalPath,
        expected_etag: &str,
        outer_markdown: String,
        slot_id: &str,
        modified_at_ms: i64,
    ) -> Result<(DocumentMetadata, PrivateSlotPayloadV1), VaultError> {
        let (read, mut document) = self.read_umbra_outer_document(logical_path)?;
        require_matching_etag(&read, expected_etag)?;
        let payload = {
            let session = self.umbra.as_ref().ok_or(VaultError::UmbraLocked)?;
            document.decrypt_private_slot(
                self.config.vault_id,
                logical_path.as_str(),
                session.slot.key_id(),
                &session.key,
                slot_id,
            )?
        };
        document.remove_private_slot(slot_id)?;
        document.outer_markdown = outer_markdown;
        validate_outer_marker_slots(&document)?;
        let metadata =
            self.save_umbra_outer_document(logical_path, &document, expected_etag, modified_at_ms)?;
        Ok((metadata, payload))
    }

    /// Read and fully authenticate one committed opaque asset.
    ///
    /// The in-memory Markdown search index is cleared before allocating the
    /// bounded whole-file asset plaintext. No plaintext byte is returned until
    /// complete AEAD authentication succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when feature 1 is unavailable, the target is
    /// missing or unsafe, the envelope exceeds the asset bound, or framing,
    /// context, or authentication fails.
    pub fn read_asset(&mut self, logical_path: &AssetPath) -> Result<DecryptedAsset, VaultError> {
        self.invalidate_search_index();
        if !self.config.supports_opaque_assets() {
            return Err(CryptoError::OpaqueAssetsNotEnabled.into());
        }
        let target = self.asset_target(logical_path)?;
        let envelope = read_regular_bounded(&target, MAX_ASSET_EDRY_ENVELOPE_BYTES)
            .map_err(map_asset_not_found)?;
        Ok(crypto::decrypt_asset(
            &self.master_key,
            &self.config,
            logical_path,
            &envelope,
        )?)
    }

    /// Create-only import of one bounded opaque asset into a feature-1 vault.
    ///
    /// This API exists for new-vault import population. It never replaces an
    /// asset and is intentionally not exposed as a general asset-write RPC.
    /// It takes ownership of a zeroizing plaintext allocation and wipes it
    /// immediately after encryption, before the synchronized ciphertext is
    /// reopened and authenticated. Verification compares the planned length
    /// and digest, so the importer never retains two complete plaintext
    /// allocations concurrently.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] for a feature mismatch, unsafe/colliding path,
    /// oversized body, cryptographic failure, create-only conflict, or failed
    /// post-commit verification.
    pub fn create_import_asset(
        &mut self,
        logical_path: &AssetPath,
        mut plaintext: Zeroizing<Vec<u8>>,
        modified_at_ms: i64,
    ) -> Result<AssetMetadata, VaultError> {
        self.invalidate_search_index();
        let planned_plaintext_len = plaintext.len();
        let planned_plaintext_digest = Zeroizing::new(digest(plaintext.as_slice()));
        let encrypted = crypto::encrypt_asset(
            &self.master_key,
            &self.config,
            logical_path,
            None,
            plaintext.as_slice(),
            modified_at_ms,
        )?;
        plaintext.zeroize();
        drop(plaintext);
        let guard = self.acquire_mutation_guard()?;
        let tree = self.scan_tree()?;
        ensure_directory_spelling(&tree, &logical_path.parent())?;
        ensure_logical_name_available(&tree, logical_path.as_str())?;
        let target = self.asset_target_allow_absent(logical_path)?;
        match self.asset_entry_state(logical_path)? {
            EntryState::Absent => {}
            EntryState::Regular => return Err(VaultError::AlreadyExists),
            EntryState::Unsafe => return Err(VaultError::UnsafeFilesystemEntry),
        }
        let outcome = guard
            .write(&target, &encrypted.bytes, WriteCondition::IfNoneMatch)
            .map_err(map_atomic_error)?;

        let committed = read_regular_bounded(&target, MAX_ASSET_EDRY_ENVELOPE_BYTES)
            .map_err(map_asset_not_found)?;
        if digest(&committed) != outcome.etag || committed != encrypted.bytes {
            return Err(VaultError::AtomicVerificationFailed);
        }
        let verified =
            crypto::decrypt_asset(&self.master_key, &self.config, logical_path, &committed)?;
        if verified.header != encrypted.header
            || verified.etag != encrypted.etag
            || verified.plaintext.len() != planned_plaintext_len
            || digest(verified.plaintext.as_slice()) != *planned_plaintext_digest
        {
            return Err(VaultError::AtomicVerificationFailed);
        }
        drop(verified);
        drop(guard);
        Ok(asset_metadata(encrypted, outcome))
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
        let tree = self.scan_tree()?;
        let parent = logical_dir
            .parent()
            .ok_or(VaultError::ParentDirectoryMissing)?;
        ensure_directory_spelling(&tree, &parent)?;
        ensure_logical_name_available(&tree, logical_dir.as_str())?;
        let physical_parent = self.directory_target(&parent, true)?;
        let name = logical_dir
            .name()
            .ok_or(VaultError::ParentDirectoryMissing)?;
        if exact_child_exists(&physical_parent, std::ffi::OsStr::new(name))? {
            return Err(VaultError::AlreadyExists);
        }
        let target = physical_parent.join(name);
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
        let tree = self.scan_tree()?;
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
        let current_tree = self.scan_tree()?;
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
        let tree = self.scan_tree()?;
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
        let tree = self.scan_tree()?;
        ensure_directory_spelling(&tree, &destination.parent())?;
        ensure_logical_name_available(&tree, destination.as_str())?;
        let source_target = self.document_target(source)?;
        ensure_regular_file_bounded(&source_target, MAX_EDRY_ENVELOPE_BYTES)?;
        match self.document_entry_state(destination)? {
            EntryState::Absent => {}
            EntryState::Regular => return Err(VaultError::AlreadyExists),
            EntryState::Unsafe => return Err(VaultError::UnsafeFilesystemEntry),
        }
        let destination_target = self.document_target_allow_absent(destination)?;
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

    fn asset_target(&self, logical_path: &AssetPath) -> Result<PathBuf, VaultError> {
        let target = self.asset_target_allow_absent(logical_path)?;
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
            EntryState::Absent => Err(VaultError::AssetNotFound),
            EntryState::Unsafe => Err(VaultError::UnsafeFilesystemEntry),
        }
    }

    fn asset_target_allow_absent(&self, logical_path: &AssetPath) -> Result<PathBuf, VaultError> {
        let parent = self.directory_target(&logical_path.parent(), true)?;
        Ok(parent.join(
            logical_path
                .to_ciphertext_relative_path()
                .file_name()
                .ok_or(VaultError::UnsafeFilesystemEntry)?,
        ))
    }

    fn asset_entry_state(&self, logical_path: &AssetPath) -> Result<EntryState, VaultError> {
        let target = self.asset_target_allow_absent(logical_path)?;
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

    fn scan_tree(&self) -> Result<VaultTree, VaultError> {
        Ok(tree::scan_vault_tree_with_profile(
            &self.root,
            tree_profile_for_config(&self.config),
        )?)
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
        let tree = self.scan_tree()?;
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
                TreeEntryKind::Asset => 2,
            }]);
            let path = entry.logical_path().as_bytes();
            hasher.update(u32::try_from(path.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(path);
            let target = match entry.kind() {
                TreeEntryKind::Directory => None,
                TreeEntryKind::File => {
                    let logical_path = LogicalPath::parse_canonical(entry.logical_path())?;
                    Some((self.document_target(&logical_path)?, false))
                }
                TreeEntryKind::Asset => {
                    let logical_path = AssetPath::parse_canonical(entry.logical_path())?;
                    Some((self.asset_target(&logical_path)?, true))
                }
            };
            if let Some((target, asset)) = target {
                match guard.inspect(&target).map_err(map_atomic_error)? {
                    CurrentTarget::File(etag) => hasher.update(etag),
                    CurrentTarget::Absent if asset => return Err(VaultError::AssetNotFound),
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

fn asset_metadata(encrypted: EncryptedAsset, outcome: AtomicWriteOutcome) -> AssetMetadata {
    AssetMetadata {
        header: encrypted.header,
        etag: encrypted.etag,
        parent_sync: outcome.parent_sync,
    }
}

fn tree_profile_for_config(config: &VaultConfig) -> VaultTreeProfile {
    if config.supports_opaque_assets() {
        VaultTreeProfile::OpaqueAssetsV1
    } else {
        VaultTreeProfile::DocumentsOnly
    }
}

const fn content_profile_to_tree_profile(profile: VaultContentProfile) -> VaultTreeProfile {
    match profile {
        VaultContentProfile::DocumentsOnly => VaultTreeProfile::DocumentsOnly,
        VaultContentProfile::OpaqueAssetsV1 => VaultTreeProfile::OpaqueAssetsV1,
    }
}

fn map_asset_not_found(error: VaultError) -> VaultError {
    match error {
        VaultError::DocumentNotFound => VaultError::AssetNotFound,
        other => other,
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

fn ensure_uninitialized_root(root: &Path, profile: VaultTreeProfile) -> Result<(), VaultError> {
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
    tree::scan_vault_tree_with_profile(root, profile)?;
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
    let candidate_asset = AssetPath::parse_canonical(candidate).ok();
    let candidate_dir = LogicalDir::parse_canonical(candidate).ok();
    let candidate_fold = candidate_file
        .as_ref()
        .map(|path| path.case_fold_key().as_str().to_owned())
        .or_else(|| {
            candidate_asset
                .as_ref()
                .map(|path| path.case_fold_key().as_str().to_owned())
        })
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
            TreeEntryKind::Asset => AssetPath::parse_canonical(entry.logical_path())?
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

fn ensure_umbra_keyslot_parent(root: &Path) -> Result<(), VaultError> {
    let internal = root.join(".inex");
    ensure_private_directory(root, &internal)?;
    let keyslots = internal.join("keyslots");
    ensure_private_directory(root, &keyslots)
}

fn ensure_private_directory(root: &Path, directory: &Path) -> Result<(), VaultError> {
    let parent = directory
        .parent()
        .ok_or(VaultError::UnsafeFilesystemEntry)?;
    let name = directory
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(VaultError::UnsafeFilesystemEntry)?;
    reject_ascii_case_alias(parent, name)?;
    match fs::create_dir(directory) {
        Ok(()) => restrict_directory_permissions_best_effort(directory),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(VaultIoOperation::CreateDirectory, &error)),
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        return Err(VaultError::UnsafeFilesystemEntry);
    }
    ensure_same_mount(root, directory)
}

fn load_umbra_keyslot(root: &Path) -> Result<(UmbraKeyslotV1, [u8; 32]), VaultError> {
    let internal = root.join(".inex");
    let keyslots = internal.join("keyslots");
    for directory in [&internal, &keyslots] {
        let parent = directory
            .parent()
            .ok_or(VaultError::UnsafeFilesystemEntry)?;
        let name = directory
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(VaultError::UnsafeFilesystemEntry)?;
        reject_ascii_case_alias(parent, name)?;
        let metadata = fs::symlink_metadata(directory).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => VaultError::UmbraNotInitialized,
            _ => io_error(VaultIoOperation::Inspect, &error),
        })?;
        if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
            return Err(VaultError::UnsafeFilesystemEntry);
        }
        ensure_same_mount(root, directory)?;
    }
    let path = root.join(UMBRA_DEFAULT_KEYSLOT_PATH);
    reject_ascii_case_alias(&keyslots, "umbra-default.inex-keyslot")?;
    if !exact_child_exists(
        &keyslots,
        std::ffi::OsStr::new("umbra-default.inex-keyslot"),
    )? {
        return match entry_state(&path)? {
            EntryState::Absent => Err(VaultError::UmbraNotInitialized),
            EntryState::Regular | EntryState::Unsafe => Err(VaultError::UnsafeFilesystemEntry),
        };
    }
    ensure_same_mount(root, &path)?;
    let bytes = read_regular_bounded(&path, 16 * 1024)?;
    let etag = digest(&bytes);
    let slot = UmbraKeyslotV1::from_json(&bytes)?;
    Ok((slot, etag))
}

type UmbraConfigBytes = (Vec<u8>, [u8; 32]);

fn load_umbra_config_bytes(root: &Path) -> Result<Option<UmbraConfigBytes>, VaultError> {
    let internal = root.join(".inex");
    reject_ascii_case_alias(root, ".inex")?;
    let metadata = match fs::symlink_metadata(&internal) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(VaultIoOperation::Inspect, &error)),
    };
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        return Err(VaultError::UnsafeFilesystemEntry);
    }
    ensure_same_mount(root, &internal)?;
    reject_ascii_case_alias(&internal, "config.umbra.inex")?;
    let path = root.join(UMBRA_CONFIG_PATH);
    if !exact_child_exists(&internal, std::ffi::OsStr::new("config.umbra.inex"))? {
        return match entry_state(&path)? {
            EntryState::Absent => Ok(None),
            EntryState::Regular | EntryState::Unsafe => Err(VaultError::UnsafeFilesystemEntry),
        };
    }
    ensure_same_mount(root, &path)?;
    let bytes = read_regular_bounded(&path, 1024 * 1024)?;
    let etag = digest(&bytes);
    Ok(Some((bytes, etag)))
}

fn reject_ascii_case_alias(parent: &Path, expected: &str) -> Result<(), VaultError> {
    for entry in
        fs::read_dir(parent).map_err(|error| io_error(VaultIoOperation::Inspect, &error))?
    {
        let entry = entry.map_err(|error| io_error(VaultIoOperation::Inspect, &error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(VaultError::UnsafeFilesystemEntry);
        };
        if name != expected && name.eq_ignore_ascii_case(expected) {
            return Err(VaultError::CaseFoldCollision);
        }
    }
    Ok(())
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

fn require_matching_etag(
    document: &DecryptedDocument,
    expected_etag: &str,
) -> Result<(), VaultError> {
    let expected = decode_etag(expected_etag)?;
    if decode_etag(&document.etag)? != expected {
        return Err(VaultError::Conflict {
            current_etag: Some(document.etag.clone()),
        });
    }
    Ok(())
}

fn fresh_private_slot_id(document: &UmbraDocumentV1) -> String {
    loop {
        let candidate = format!("p_{}", Uuid::new_v4().simple());
        if !document.slots.contains_key(&candidate) {
            return candidate;
        }
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
        AtomicWriteError::InvalidTarget
        | AtomicWriteError::UnsafeLockPath
        | AtomicWriteError::UnsafeStagingPath => VaultError::UnsafeFilesystemEntry,
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
        AtomicWriteError::RepositoryPublicationReconcileRequired => {
            VaultError::RepositoryPublicationReconcileRequired
        }
        AtomicWriteError::RepositoryPublicationManualAuditRequired => {
            VaultError::RepositoryPublicationManualAuditRequired
        }
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

    fn asset(value: &str) -> AssetPath {
        AssetPath::parse_canonical(value)
            .unwrap_or_else(|error| panic!("invalid test asset path: {error}"))
    }

    fn asset_plaintext(value: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(value.to_vec())
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

    fn create_test_asset_vault(directory: &TestDirectory) -> Vault {
        Vault::create_with_profile_and_params(
            directory.path(),
            b"old password",
            1_783_699_200_000,
            VaultContentProfile::OpaqueAssetsV1,
            test_params(),
            test_policy(),
        )
        .unwrap_or_else(|error| panic!("test asset vault creation failed: {error}"))
    }

    #[test]
    fn umbra_slot_is_independent_and_password_reset_requires_live_session() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        assert_eq!(
            vault.umbra_status().expect("inspect uninitialized state"),
            UmbraStatus {
                initialized: false,
                unlocked: false,
            }
        );

        let initialized = vault
            .initialize_umbra(b"first Umbra password")
            .expect("initialize Umbra");
        assert_eq!(
            initialized,
            UmbraStatus {
                initialized: true,
                unlocked: true,
            }
        );
        assert!(directory.path().join(UMBRA_DEFAULT_KEYSLOT_PATH).is_file());
        assert!(matches!(
            vault.initialize_umbra(b"another Umbra password"),
            Err(VaultError::UmbraAlreadyInitialized)
        ));

        vault.lock_umbra();
        assert!(matches!(
            vault.change_umbra_password(b"new Umbra password"),
            Err(VaultError::UmbraLocked)
        ));
        assert!(matches!(
            vault.unlock_umbra(b"wrong Umbra password"),
            Err(VaultError::UmbraKeyslot(
                UmbraKeyslotError::AuthenticationFailed
            ))
        ));
        vault
            .unlock_umbra(b"first Umbra password")
            .expect("unlock Umbra independently");
        vault
            .change_umbra_password(b"new Umbra password")
            .expect("reset from live session");
        vault.lock_umbra();
        assert!(matches!(
            vault.unlock_umbra(b"first Umbra password"),
            Err(VaultError::UmbraKeyslot(
                UmbraKeyslotError::AuthenticationFailed
            ))
        ));
        vault
            .unlock_umbra(b"new Umbra password")
            .expect("unlock with reset password");
    }

    #[test]
    fn umbra_config_requires_live_session_and_is_ciphertext_only_on_disk() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        assert!(matches!(
            vault.load_umbra_config(),
            Err(VaultError::UmbraLocked)
        ));
        vault
            .initialize_umbra(b"Umbra config password")
            .expect("initialize Umbra");
        let mut config = UmbraConfigV1::empty();
        config
            .tag_catalog
            .push(crate::umbra_config::PrivateTagDefinition {
                id: "secret-tag".to_owned(),
                label: "INEX_SECRET_TAG_CANARY".to_owned(),
                description: String::new(),
                aliases: Vec::new(),
                sort_order: 1,
                default_selected: false,
                archived: false,
            });
        vault.save_umbra_config(&config).expect("save config");
        let disk = fs::read(directory.path().join(UMBRA_CONFIG_PATH)).expect("read ciphertext");
        assert!(!String::from_utf8_lossy(&disk).contains("INEX_SECRET_TAG_CANARY"));
        assert_eq!(vault.load_umbra_config().expect("load config"), config);
        vault.lock_umbra();
        assert!(matches!(
            vault.load_umbra_config(),
            Err(VaultError::UmbraLocked)
        ));
    }

    #[test]
    fn feature_two_requires_live_umbra_session_and_is_committed_to_metadata() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        assert!(matches!(
            vault.enable_umbra_private_annotations(test_policy()),
            Err(VaultError::UmbraLocked)
        ));
        vault
            .initialize_umbra(b"feature two password")
            .expect("initialize");
        vault
            .enable_umbra_private_annotations(test_policy())
            .expect("enable feature two");
        assert_eq!(vault.config().required_features, vec![2]);
    }

    #[test]
    fn feature_two_outer_projection_has_a_dedicated_safe_read_write_path() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("2026-07-umbra.md");
        let outer = UmbraDocumentV1::new("# public outer projection\n".to_owned());

        assert!(matches!(
            vault.create_umbra_outer_document(&path, &outer, 1_783_699_201_000),
            Err(VaultError::UmbraLocked)
        ));
        vault
            .initialize_umbra(b"outer projection password")
            .expect("initialize Umbra");
        vault
            .enable_umbra_private_annotations(test_policy())
            .expect("enable feature two");
        let created = vault
            .create_umbra_outer_document(&path, &outer, 1_783_699_201_000)
            .expect("create feature two container");
        assert_eq!(
            created.header.required_features,
            vec![crate::features::UMBRA_PRIVATE_ANNOTATIONS_V1]
        );
        assert!(matches!(
            vault.read(&path),
            Err(VaultError::Crypto(CryptoError::DocumentContextMismatch))
        ));

        vault.lock_umbra();
        let (read, projection) = vault
            .read_umbra_outer_document(&path)
            .expect("Outer projection never needs K_umbra");
        assert_eq!(projection, outer);
        assert!(matches!(
            vault.save_umbra_outer_document(&path, &projection, &read.etag, 1_783_699_202_000),
            Err(VaultError::UmbraLocked)
        ));

        vault
            .unlock_umbra(b"outer projection password")
            .expect("unlock Umbra");
        let updated = UmbraDocumentV1::new("# updated public projection\n".to_owned());
        let saved = vault
            .save_umbra_outer_document(&path, &updated, &read.etag, 1_783_699_202_000)
            .expect("save outer container");
        assert_eq!(saved.header.file_id, created.header.file_id);
        assert_ne!(saved.etag, created.etag);
        let (_, reopened) = vault
            .read_umbra_outer_document(&path)
            .expect("reopen feature two container");
        assert_eq!(reopened, updated);
    }

    #[test]
    fn ordinary_document_upgrade_to_umbra_is_live_session_etag_bound_and_preserves_identity() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("2026-07-upgrade.md");
        let created = vault
            .create_document(&path, b"# existing public Markdown\n", 1_783_699_201_000)
            .expect("create ordinary document");
        assert!(matches!(
            vault.convert_document_to_umbra_outer(&path, &created.etag, 1_783_699_202_000),
            Err(VaultError::UmbraLocked)
        ));
        vault
            .initialize_umbra(b"upgrade Umbra password")
            .expect("initialize Umbra");
        vault
            .enable_umbra_private_annotations(test_policy())
            .expect("enable feature two");
        let stale = format!("sha256:{}", "0".repeat(64));
        assert!(matches!(
            vault.convert_document_to_umbra_outer(&path, &stale, 1_783_699_202_000),
            Err(VaultError::Conflict { .. })
        ));
        assert_eq!(
            vault
                .read(&path)
                .expect("stale conversion keeps normal document")
                .plaintext
                .as_slice(),
            b"# existing public Markdown\n"
        );

        let upgraded = vault
            .convert_document_to_umbra_outer(&path, &created.etag, 1_783_699_202_000)
            .expect("upgrade ordinary document");
        assert_eq!(upgraded.header.file_id, created.header.file_id);
        assert_eq!(upgraded.header.created_at_ms, created.header.created_at_ms);
        assert_eq!(
            upgraded.header.required_features,
            vec![crate::features::UMBRA_PRIVATE_ANNOTATIONS_V1]
        );
        assert!(matches!(
            vault.read(&path),
            Err(VaultError::Crypto(CryptoError::DocumentContextMismatch))
        ));
        let (_, outer) = vault
            .read_umbra_outer_document(&path)
            .expect("read upgraded outer projection");
        assert_eq!(outer.outer_markdown, "# existing public Markdown\n");
        assert!(matches!(
            vault.convert_document_to_umbra_outer(&path, &upgraded.etag, 1_783_699_203_000),
            Err(VaultError::Crypto(CryptoError::DocumentContextMismatch))
        ));
    }

    #[test]
    fn private_slot_mutations_require_umbra_and_keep_canaries_out_of_outer_state() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("2026-07-private.md");
        vault
            .initialize_umbra(b"private slot password")
            .expect("initialize Umbra");
        vault
            .enable_umbra_private_annotations(test_policy())
            .expect("enable feature two");
        let created = vault
            .create_umbra_outer_document(
                &path,
                &UmbraDocumentV1::new("# outer text\n".to_owned()),
                1_783_699_201_000,
            )
            .expect("create outer document");
        let payload = PrivateSlotPayloadV1 {
            format: "inex-private-slot".to_owned(),
            version: 1,
            kind: crate::umbra_config::PrivateAnnotationKind::Comment,
            tag_ids: vec!["relationship".to_owned(), "secret-tag".to_owned()],
            markdown: "INEX_SECRET_SLOT_CANARY".to_owned(),
            created_at_ms: 1_783_699_201_000,
            updated_at_ms: 1_783_699_201_000,
        };
        let inserted = vault
            .insert_umbra_private_slot(
                &path,
                &created.etag,
                "# outer text\n{{inex-private-slot:p_01}}\n".to_owned(),
                "p_01".to_owned(),
                OuterSlotStrategy {
                    mode: crate::umbra_config::OuterMode::Drop,
                    cover_text: None,
                },
                &payload,
                1_783_699_202_000,
            )
            .expect("insert slot");
        let disk = fs::read(directory.path().join("2026-07-private.md.enc"))
            .expect("read encrypted document");
        assert!(!String::from_utf8_lossy(&disk).contains("INEX_SECRET_SLOT_CANARY"));
        let (_, outer) = vault
            .read_umbra_outer_document(&path)
            .expect("read Outer projection");
        assert!(!outer.outer_markdown.contains("INEX_SECRET_SLOT_CANARY"));
        assert_eq!(
            vault
                .read_umbra_private_slot(&path, "p_01")
                .expect("read private slot"),
            payload
        );
        let rendered = vault
            .render_umbra_projection(&path)
            .expect("render unlocked Umbra projection");
        assert!(rendered.markdown.contains("INEX_SECRET_SLOT_CANARY"));
        assert_eq!(rendered.render_map.private_slots.len(), 1);

        let replacement = PrivateSlotPayloadV1 {
            updated_at_ms: 1_783_699_203_000,
            markdown: "INEX_REPLACED_SLOT_CANARY".to_owned(),
            ..payload.clone()
        };
        let replaced = vault
            .replace_umbra_private_slot(
                &path,
                &inserted.etag,
                "p_01",
                OuterSlotStrategy {
                    mode: crate::umbra_config::OuterMode::Placeholder,
                    cover_text: None,
                },
                &replacement,
                1_783_699_203_000,
            )
            .expect("replace slot");
        assert_eq!(
            vault
                .read_umbra_private_slot(&path, "p_01")
                .expect("read replaced slot"),
            replacement
        );
        vault.lock_umbra();
        assert!(matches!(
            vault.render_umbra_projection(&path),
            Err(VaultError::UmbraLocked)
        ));
        assert!(matches!(
            vault.read_umbra_private_slot(&path, "p_01"),
            Err(VaultError::UmbraLocked)
        ));
        assert!(matches!(
            vault.remove_umbra_private_slot(
                &path,
                &replaced.etag,
                "# outer text\n".to_owned(),
                "p_01",
                1_783_699_204_000
            ),
            Err(VaultError::UmbraLocked)
        ));
        vault
            .unlock_umbra(b"private slot password")
            .expect("unlock Umbra");
        let (removed, restored) = vault
            .remove_umbra_private_slot(
                &path,
                &replaced.etag,
                "# outer text\n".to_owned(),
                "p_01",
                1_783_699_204_000,
            )
            .expect("remove slot");
        assert_eq!(restored, replacement);
        assert_ne!(removed.etag, replaced.etag);
        assert!(matches!(
            vault.read_umbra_private_slot(&path, "p_01"),
            Err(VaultError::UmbraDocument(UmbraDocumentError::SlotNotFound))
        ));
    }

    #[test]
    fn private_annotation_wraps_multiple_plain_ranges_atomically() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let path = logical("2026-07-annotations.md");
        vault
            .initialize_umbra(b"annotation password")
            .expect("initialize Umbra");
        vault
            .enable_umbra_private_annotations(test_policy())
            .expect("enable feature two");
        let created = vault
            .create_umbra_outer_document(
                &path,
                &UmbraDocumentV1::new(
                    "INEX_SECRET_SLOT_A\\nordinary text\\nINEX_SECRET_SLOT_B\\n".to_owned(),
                ),
                1_783_699_201_000,
            )
            .expect("create outer document");
        let before = vault
            .render_umbra_projection(&path)
            .expect("render plain projection");
        let first_start = before
            .markdown
            .find("INEX_SECRET_SLOT_A")
            .expect("first selection");
        let second_start = before
            .markdown
            .find("INEX_SECRET_SLOT_B")
            .expect("second selection");
        let selections = [
            TextRange::new(first_start, first_start + "INEX_SECRET_SLOT_A".len())
                .expect("first range"),
            TextRange::new(second_start, second_start + "INEX_SECRET_SLOT_B".len())
                .expect("second range"),
        ];
        let spec = PrivateAnnotationSpec {
            kind: crate::umbra_config::PrivateAnnotationKind::Comment,
            tag_ids: vec!["comment-content".to_owned(), "secret-tag".to_owned()],
            outer: OuterSlotStrategy {
                mode: crate::umbra_config::OuterMode::Drop,
                cover_text: None,
            },
        };

        let applied = vault
            .apply_private_annotation(
                &path,
                &created.etag,
                &before.markdown,
                &before.render_map,
                &selections,
                &spec,
                false,
                1_783_699_202_000,
            )
            .expect("atomically annotate both ranges");
        assert_eq!(applied.projection.render_map.private_slots.len(), 2);
        assert!(applied.projection.markdown.contains("INEX_SECRET_SLOT_A"));
        assert!(applied.projection.markdown.contains("INEX_SECRET_SLOT_B"));

        let (_, outer) = vault
            .read_umbra_outer_document(&path)
            .expect("read Outer projection");
        assert_eq!(outer.slots.len(), 2);
        assert!(outer.outer_markdown.contains("ordinary text"));
        assert!(!outer.outer_markdown.contains("INEX_SECRET_SLOT_A"));
        assert!(!outer.outer_markdown.contains("INEX_SECRET_SLOT_B"));
        for slot_id in outer.slots.keys() {
            let payload = vault
                .read_umbra_private_slot(&path, slot_id)
                .expect("decrypt wrapped payload");
            assert_eq!(payload.kind, spec.kind);
            assert_eq!(payload.tag_ids, spec.tag_ids);
        }
        let disk = fs::read(directory.path().join("2026-07-annotations.md.enc"))
            .expect("read encrypted document");
        let disk = String::from_utf8_lossy(&disk);
        assert!(!disk.contains("INEX_SECRET_SLOT_A"));
        assert!(!disk.contains("INEX_SECRET_SLOT_B"));
        assert!(!disk.contains("secret-tag"));

        assert!(matches!(
            vault.apply_private_annotation(
                &path,
                &created.etag,
                &applied.projection.markdown,
                &applied.projection.render_map,
                &[TextRange::new(0, 1).expect("stale range")],
                &spec,
                false,
                1_783_699_203_000,
            ),
            Err(VaultError::Conflict { .. })
        ));
        let private_range = applied.projection.render_map.private_slots[0].projection_range;
        assert!(matches!(
            vault.apply_private_annotation(
                &path,
                &applied.document.etag,
                &applied.projection.markdown,
                &applied.projection.render_map,
                &[private_range],
                &spec,
                false,
                1_783_699_203_000,
            ),
            Err(VaultError::UmbraRender(
                UmbraRenderError::AnnotationSelectionNotPlain
            ))
        ));
        let (_, after_rejections) = vault
            .read_umbra_outer_document(&path)
            .expect("read unchanged document");
        assert_eq!(after_rejections, outer);
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
    fn unlock_recovers_safe_partial_ciphertext_staging_before_tree_scan() {
        let directory = TestDirectory::new();
        drop(create_test_vault(&directory));
        let staging = directory
            .path()
            .join(crate::atomic::VAULT_LOCAL_DIRECTORY)
            .join(format!(
                "{}{}{}",
                crate::atomic::CIPHERTEXT_STAGING_PREFIX,
                "0".repeat(32),
                crate::atomic::CIPHERTEXT_STAGING_SUFFIX
            ));
        fs::write(&staging, b"EDRY-partial")
            .unwrap_or_else(|error| panic!("partial staging write failed: {error}"));

        let reopened = Vault::unlock(directory.path(), b"old password", None, test_policy())
            .unwrap_or_else(|error| panic!("unlock recovery failed: {error}"));

        assert_eq!(reopened.root(), directory.path());
        assert!(!staging.exists());
    }

    #[test]
    fn asset_profile_create_import_list_read_and_reopen_round_trip() {
        let directory = TestDirectory::new();
        let mut vault = create_test_asset_vault(&directory);
        assert_eq!(vault.config().required_features.as_slice(), [1]);

        let path = asset("images/station.png");
        let images = LogicalDir::parse_canonical("images")
            .unwrap_or_else(|error| panic!("directory failed: {error}"));
        vault
            .create_directory(&images)
            .unwrap_or_else(|error| panic!("mkdir failed: {error}"));
        let bytes = [0_u8, 0xff, 0x89, b'P', b'N', b'G'];
        let created = vault
            .create_import_asset(&path, asset_plaintext(&bytes), 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("asset import failed: {error}"));
        assert_eq!(created.header.logical_path, path.as_str());
        assert_eq!(created.header.required_features.as_slice(), [1]);

        let tree = vault
            .list()
            .unwrap_or_else(|error| panic!("list failed: {error}"));
        assert!(tree.entries().iter().any(|entry| {
            entry.kind() == TreeEntryKind::Asset && entry.logical_path() == path.as_str()
        }));
        let opened = vault
            .read_asset(&path)
            .unwrap_or_else(|error| panic!("asset read failed: {error}"));
        assert_eq!(opened.plaintext.as_slice(), bytes);
        assert_eq!(opened.etag, created.etag);
        drop(opened);
        assert!(matches!(
            vault.create_import_asset(&path, asset_plaintext(&bytes), 1_783_699_202_000),
            Err(VaultError::AlreadyExists)
        ));

        drop(vault);
        let mut reopened = Vault::unlock(directory.path(), b"old password", None, test_policy())
            .unwrap_or_else(|error| panic!("unlock failed: {error}"));
        assert_eq!(
            reopened
                .read_asset(&path)
                .unwrap_or_else(|error| panic!("reopened asset read failed: {error}"))
                .plaintext
                .as_slice(),
            bytes
        );
    }

    #[test]
    fn feature_free_vault_rejects_asset_import_before_writing() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        assert!(vault.config().required_features.is_empty());
        let path = asset("image.bin");
        assert!(matches!(
            vault.create_import_asset(&path, asset_plaintext(b"opaque"), 1_783_699_201_000),
            Err(VaultError::Crypto(CryptoError::OpaqueAssetsNotEnabled))
        ));
        assert!(!directory.path().join("image.bin.asset.enc").exists());
    }

    #[test]
    fn asset_profile_creation_rejects_plaintext_before_metadata_commit() {
        let directory = TestDirectory::new();
        fs::create_dir_all(directory.path())
            .unwrap_or_else(|error| panic!("fixture root create failed: {error}"));
        fs::write(directory.path().join("image.png"), b"plaintext")
            .unwrap_or_else(|error| panic!("plaintext fixture write failed: {error}"));
        assert!(matches!(
            Vault::create_with_profile_and_params(
                directory.path(),
                b"old password",
                1_783_699_200_000,
                VaultContentProfile::OpaqueAssetsV1,
                test_params(),
                test_policy(),
            ),
            Err(VaultError::Tree(TreeError::UnexpectedRegularFile { .. }))
        ));
        assert!(!directory.path().join(VAULT_CONFIG_FILE).exists());
    }

    #[test]
    fn asset_ciphertext_changes_invalidate_search_without_indexing_asset() {
        let directory = TestDirectory::new();
        let mut vault = create_test_asset_vault(&directory);
        vault
            .create_document(&logical("note.md"), b"searchable", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("document create failed: {error}"));
        vault
            .create_import_asset(
                &asset("image.bin"),
                asset_plaintext(b"not searchable"),
                1_783_699_201_000,
            )
            .unwrap_or_else(|error| panic!("asset import failed: {error}"));
        assert_eq!(
            vault
                .rebuild_search_index()
                .unwrap_or_else(|error| panic!("search rebuild failed: {error}")),
            1
        );

        let target = directory.path().join("image.bin.asset.enc");
        let mut ciphertext = fs::read(&target)
            .unwrap_or_else(|error| panic!("asset ciphertext read failed: {error}"));
        let last = ciphertext
            .last_mut()
            .unwrap_or_else(|| panic!("asset ciphertext unexpectedly empty"));
        *last ^= 1;
        fs::write(&target, ciphertext)
            .unwrap_or_else(|error| panic!("asset ciphertext mutation failed: {error}"));

        let query = SearchQuery::with_defaults(
            Zeroizing::new("searchable".to_owned()),
            CaseSensitivity::Sensitive,
        )
        .unwrap_or_else(|error| panic!("query failed: {error}"));
        assert!(matches!(
            vault.search(&query),
            Err(VaultError::SearchIndexNotReady)
        ));
    }

    #[test]
    fn asset_and_document_names_share_the_portable_collision_domain() {
        let directory = TestDirectory::new();
        let mut vault = create_test_asset_vault(&directory);
        vault
            .create_import_asset(
                &asset("FOO.MD"),
                asset_plaintext(b"opaque"),
                1_783_699_201_000,
            )
            .unwrap_or_else(|error| panic!("asset import failed: {error}"));
        assert!(matches!(
            vault.create_document(&logical("foo.md"), b"markdown", 1_783_699_202_000),
            Err(VaultError::CaseFoldCollision)
        ));
    }

    #[test]
    fn asset_import_rejects_a_directory_alias_of_its_physical_mapping() {
        let directory = TestDirectory::new();
        let mut vault = create_test_asset_vault(&directory);
        fs::create_dir(directory.path().join("FOO.ASSET.ENC"))
            .unwrap_or_else(|error| panic!("physical alias directory failed: {error}"));
        assert!(matches!(
            vault
                .create_import_asset(&asset("foo"), asset_plaintext(b"opaque"), 1_783_699_201_000,),
            Err(VaultError::CaseFoldCollision)
        ));
        assert!(!directory.path().join("foo.asset.enc").exists());
    }

    #[test]
    fn directory_creation_rejects_document_and_asset_physical_aliases() {
        let asset_directory = TestDirectory::new();
        let mut asset_vault = create_test_asset_vault(&asset_directory);
        asset_vault
            .create_import_asset(&asset("foo"), asset_plaintext(b"opaque"), 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("asset import failed: {error}"));
        let asset_alias = LogicalDir::parse_canonical("FOO.ASSET.ENC")
            .unwrap_or_else(|error| panic!("asset alias directory failed: {error}"));
        assert!(matches!(
            asset_vault.create_directory(&asset_alias),
            Err(VaultError::CaseFoldCollision)
        ));

        let document_directory = TestDirectory::new();
        let mut document_vault = create_test_vault(&document_directory);
        document_vault
            .create_document(&logical("foo.md"), b"markdown", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("document create failed: {error}"));
        let document_alias = LogicalDir::parse_canonical("FOO.MD.ENC")
            .unwrap_or_else(|error| panic!("document alias directory failed: {error}"));
        assert!(matches!(
            document_vault.create_directory(&document_alias),
            Err(VaultError::CaseFoldCollision)
        ));
    }

    #[test]
    fn oversized_asset_envelope_is_rejected_before_read_allocation() {
        let directory = TestDirectory::new();
        let mut vault = create_test_asset_vault(&directory);
        let target = directory.path().join("large.bin.asset.enc");
        let file = File::create(&target)
            .unwrap_or_else(|error| panic!("oversized fixture create failed: {error}"));
        file.set_len(
            u64::try_from(MAX_ASSET_EDRY_ENVELOPE_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .unwrap_or_else(|error| panic!("oversized fixture resize failed: {error}"));
        drop(file);
        assert!(matches!(
            vault.read_asset(&asset("large.bin")),
            Err(VaultError::FileTooLarge)
        ));
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
    fn rename_rejects_a_directory_alias_of_the_destination_ciphertext() {
        let directory = TestDirectory::new();
        let mut vault = create_test_vault(&directory);
        let source = logical("source.md");
        let created = vault
            .create_document(&source, b"rename secret", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("source create failed: {error}"));
        fs::create_dir(directory.path().join("TARGET.MD.ENC"))
            .unwrap_or_else(|error| panic!("destination alias failed: {error}"));
        assert!(matches!(
            vault.rename_document(
                &source,
                &logical("target.md"),
                &created.etag,
                1_783_699_202_000,
            ),
            Err(VaultError::CaseFoldCollision)
        ));
        assert!(vault.read(&source).is_ok());
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
