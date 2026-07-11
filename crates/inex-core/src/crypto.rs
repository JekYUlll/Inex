//! High-level vault-key, password-slot, and EDRY cryptographic lifecycle.
//!
//! This module composes the narrow libsodium boundary with authenticated vault
//! metadata and deterministic EDRY framing. It never writes files; storage
//! transactions are handled by the vault layer after complete ciphertext has
//! been produced in memory.

use std::fmt;

use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::format::{
    self, CipherSuite, ContentFlags, EdryHeader, FileKeyDerivation, FormatError, PlaintextKind,
};
use crate::path::LogicalPath;
use crate::sodium::{
    self, Argon2idLimits, Argon2idParams, LockedBytes, SecureMemoryHealth, SodiumError,
};
use crate::vault_config::{
    ConfigError, ConfigWarning, EncodedBytes, KdfAlgorithm, KdfConfig, KdfPolicy, KeySlot,
    KeySlotKind, MAX_KEY_SLOTS, VaultConfig, VaultFeatures, VaultFormat, WrapAlgorithm, WrapConfig,
    validate_password,
};

const FILE_KEY_DOMAIN: &[u8] = b"INEX-FILE-V1\0";

/// A random vault master key held in libsodium guarded memory.
pub struct VaultMasterKey {
    bytes: LockedBytes<{ sodium::KEY_BYTES }>,
}

impl VaultMasterKey {
    /// Generate a new random master key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if libsodium initialization, secure allocation,
    /// or random generation fails.
    pub fn random() -> Result<Self, CryptoError> {
        Ok(Self {
            bytes: LockedBytes::random()?,
        })
    }

    /// Report best-effort secure-memory hardening for this key.
    #[must_use]
    pub const fn memory_health(&self) -> SecureMemoryHealth {
        self.bytes.health()
    }

    fn from_plaintext(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            bytes: LockedBytes::from_slice(bytes)?,
        })
    }
}

impl fmt::Debug for VaultMasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultMasterKey")
            .field("contents", &"<redacted>")
            .field("health", &self.memory_health())
            .finish()
    }
}

/// Result of creating a new in-memory vault identity and first password slot.
#[derive(Debug)]
pub struct CreatedVault {
    pub config: VaultConfig,
    pub master_key: VaultMasterKey,
    pub slot_id: Uuid,
}

/// Result of authenticating one password slot and the complete vault metadata.
#[derive(Debug)]
pub struct UnlockedVault {
    pub master_key: VaultMasterKey,
    pub slot_id: Uuid,
    pub warnings: Vec<ConfigWarning>,
}

/// Stable file identity retained across saves and logical renames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub file_id: Uuid,
    pub created_at_ms: i64,
}

impl FileIdentity {
    /// Construct the stable identity represented by an authenticated header.
    #[must_use]
    pub const fn from_header(header: &EdryHeader) -> Self {
        Self {
            file_id: header.file_id,
            created_at_ms: header.created_at_ms,
        }
    }
}

/// Whether an encrypted output is a committed vault file or editor backup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeKind {
    Committed,
    Draft { base_etag: Option<[u8; 32]> },
}

/// Expected envelope kind during authenticated decryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedEnvelopeKind {
    Committed,
    Draft,
    Either,
}

/// Complete encrypted output ready for an atomic ciphertext-only write.
pub struct EncryptedDocument {
    pub header: EdryHeader,
    pub bytes: Vec<u8>,
    pub etag: String,
}

impl fmt::Debug for EncryptedDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedDocument")
            .field("header", &self.header)
            .field("ciphertext_bytes", &self.bytes.len())
            .field("etag", &self.etag)
            .finish()
    }
}

/// Authenticated plaintext returned in a zeroizing owned allocation.
pub struct DecryptedDocument {
    pub header: EdryHeader,
    pub plaintext: Zeroizing<Vec<u8>>,
    pub etag: String,
}

impl fmt::Debug for DecryptedDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedDocument")
            .field("header", &self.header)
            .field("plaintext", &"<redacted>")
            .field("plaintext_bytes", &self.plaintext.len())
            .field("etag", &self.etag)
            .finish()
    }
}

/// Errors from authenticated vault and document cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Sodium(#[from] SodiumError),
    #[error("vault password authentication failed")]
    VaultAuthenticationFailed,
    #[error("vault metadata authentication failed")]
    MetadataAuthenticationFailed,
    #[error("a password slot must be selected when multiple slots exist")]
    SlotSelectionRequired,
    #[error("the last password slot cannot be removed")]
    CannotRemoveLastSlot,
    #[error("wrapped master-key output had an invalid length")]
    InvalidWrappedKeyLength,
    #[error("EDRY document does not match the expected vault, epoch, path, or kind")]
    DocumentContextMismatch,
    #[error("EDRY document authentication failed")]
    DocumentAuthenticationFailed,
    #[error("decrypted Markdown is not valid UTF-8")]
    InvalidMarkdownUtf8,
    #[error("document plaintext exceeds the EDRY v1 size limit")]
    PlaintextTooLarge,
}

/// Create a new vault using the production v1 KDF policy and defaults.
///
/// # Errors
///
/// Returns [`CryptoError`] for an invalid password/timestamp or any
/// cryptographic initialization, KDF, allocation, wrapping, or metadata
/// authentication failure.
pub fn create_vault(password: &[u8], created_at_ms: i64) -> Result<CreatedVault, CryptoError> {
    create_vault_with_params(
        password,
        created_at_ms,
        sodium::DEFAULT_ARGON2ID_PARAMS,
        KdfPolicy::default(),
    )
}

/// Create a new vault with explicit parameters and policy.
///
/// This is used by policy calibration and deterministic low-cost tests. Normal
/// callers should use [`create_vault`].
///
/// # Errors
///
/// Returns [`CryptoError`] when the password, timestamp, parameters, policy,
/// secure allocation, KDF, wrapping, or metadata MAC operation fails.
pub fn create_vault_with_params(
    password: &[u8],
    created_at_ms: i64,
    params: Argon2idParams,
    policy: KdfPolicy,
) -> Result<CreatedVault, CryptoError> {
    validate_password(password)?;
    if created_at_ms < 0 {
        return Err(ConfigError::InvalidTimestamp.into());
    }
    validate_new_slot_params(params, policy)?;

    let master_key = VaultMasterKey::random()?;
    let vault_id = random_uuid_v4()?;
    let slot_id = random_uuid_v4()?;
    let salt = sodium::random_array::<{ sodium::ARGON2ID_SALT_BYTES }>()?;
    let nonce = sodium::random_array::<{ sodium::XCHACHA20_NONCE_BYTES }>()?;
    let slot = KeySlot {
        id: slot_id,
        kind: KeySlotKind::Password,
        kdf: KdfConfig {
            algorithm: KdfAlgorithm::Argon2id13,
            salt: EncodedBytes::new(salt),
            ops_limit: params.ops_limit,
            mem_limit_bytes: params.mem_limit_bytes,
        },
        wrap: WrapConfig {
            algorithm: WrapAlgorithm::XChaCha20Poly1305Ietf,
            nonce: EncodedBytes::new(nonce),
            ciphertext: EncodedBytes::new([0_u8; 48]),
        },
        created_at: created_at_ms,
    };
    let mut config = VaultConfig {
        format: VaultFormat::V1,
        vault_id,
        key_epoch: 0,
        created_at: created_at_ms,
        required_features: Vec::new(),
        key_slots: vec![slot],
        features: VaultFeatures::default(),
        metadata_mac: EncodedBytes::new([0_u8; 32]),
    };

    let wrapped = wrap_master_key(&config, slot_id, password, &master_key, policy)?;
    config.key_slots[0].wrap.ciphertext = EncodedBytes::new(wrapped);
    refresh_metadata_mac(&mut config, &master_key)?;
    config.validate_for_creation(policy)?;

    Ok(CreatedVault {
        config,
        master_key,
        slot_id,
    })
}

/// Unlock and authenticate a vault password slot and the complete metadata.
///
/// When more than one slot exists, `slot_id` is required to cap attacker-
/// controlled KDF amplification.
///
/// # Errors
///
/// Returns [`CryptoError`] for invalid/resource-exhausting metadata, missing
/// slot selection, a wrong password, unwrap failure, or metadata MAC failure.
pub fn unlock_vault(
    config: &VaultConfig,
    password: &[u8],
    slot_id: Option<Uuid>,
    policy: KdfPolicy,
) -> Result<UnlockedVault, CryptoError> {
    validate_password(password)?;
    let warnings = config.validate_untrusted(policy)?;
    let selected_id = match (slot_id, config.key_slots.as_slice()) {
        (Some(id), _) if config.key_slots.iter().any(|slot| slot.id == id) => id,
        (Some(_), _) => return Err(CryptoError::VaultAuthenticationFailed),
        (None, [only]) => only.id,
        (None, _) => return Err(CryptoError::SlotSelectionRequired),
    };

    let master_key = unwrap_master_key(config, selected_id, password, policy)?;
    verify_metadata_mac(config, &master_key)?;
    Ok(UnlockedVault {
        master_key,
        slot_id: selected_id,
        warnings,
    })
}

/// Return a copy of metadata with one new independently wrapped password slot.
///
/// The current metadata MAC is verified before modification. The original
/// config is unchanged; storage code must atomically commit and re-open the
/// returned config before removing an old slot.
///
/// # Errors
///
/// Returns [`CryptoError`] when current metadata is unauthenticated, capacity
/// is exhausted, the new password/KDF is invalid, or wrapping/MAC generation
/// fails.
pub fn add_password_slot(
    config: &VaultConfig,
    master_key: &VaultMasterKey,
    password: &[u8],
    created_at_ms: i64,
    params: Argon2idParams,
    policy: KdfPolicy,
) -> Result<(VaultConfig, Uuid), CryptoError> {
    validate_password(password)?;
    config.validate_untrusted(policy)?;
    verify_metadata_mac(config, master_key)?;
    validate_new_slot_params(params, policy)?;
    if created_at_ms < 0 {
        return Err(ConfigError::InvalidKeySlotTimestamp.into());
    }
    if config.key_slots.len() >= MAX_KEY_SLOTS {
        return Err(ConfigError::TooManyKeySlots.into());
    }

    let mut updated = config.clone();
    let slot_id = random_uuid_v4()?;
    let salt = sodium::random_array::<{ sodium::ARGON2ID_SALT_BYTES }>()?;
    let nonce = sodium::random_array::<{ sodium::XCHACHA20_NONCE_BYTES }>()?;
    updated.key_slots.push(KeySlot {
        id: slot_id,
        kind: KeySlotKind::Password,
        kdf: KdfConfig {
            algorithm: KdfAlgorithm::Argon2id13,
            salt: EncodedBytes::new(salt),
            ops_limit: params.ops_limit,
            mem_limit_bytes: params.mem_limit_bytes,
        },
        wrap: WrapConfig {
            algorithm: WrapAlgorithm::XChaCha20Poly1305Ietf,
            nonce: EncodedBytes::new(nonce),
            ciphertext: EncodedBytes::new([0_u8; 48]),
        },
        created_at: created_at_ms,
    });
    let wrapped = wrap_master_key(&updated, slot_id, password, master_key, policy)?;
    let new_slot = updated
        .key_slots
        .iter_mut()
        .find(|slot| slot.id == slot_id)
        .ok_or(ConfigError::KeySlotNotFound)?;
    new_slot.wrap.ciphertext = EncodedBytes::new(wrapped);
    refresh_metadata_mac(&mut updated, master_key)?;
    updated.validate_untrusted(policy)?;
    Ok((updated, slot_id))
}

/// Remove one authenticated password slot without modifying the master key.
///
/// # Errors
///
/// Returns [`CryptoError`] when current metadata is unauthenticated, the slot
/// is absent, it is the last slot, or metadata MAC regeneration fails.
pub fn remove_password_slot(
    config: &VaultConfig,
    master_key: &VaultMasterKey,
    slot_id: Uuid,
    policy: KdfPolicy,
) -> Result<VaultConfig, CryptoError> {
    config.validate_untrusted(policy)?;
    verify_metadata_mac(config, master_key)?;
    if config.key_slots.len() == 1 {
        return Err(CryptoError::CannotRemoveLastSlot);
    }
    if !config.key_slots.iter().any(|slot| slot.id == slot_id) {
        return Err(ConfigError::KeySlotNotFound.into());
    }

    let mut updated = config.clone();
    updated.key_slots.retain(|slot| slot.id != slot_id);
    refresh_metadata_mac(&mut updated, master_key)?;
    updated.validate_untrusted(policy)?;
    Ok(updated)
}

/// Encrypt exact UTF-8 Markdown into a committed EDRY file or encrypted draft.
///
/// `identity` is `None` for a new document and preserves file id/creation time
/// for saves and renames. A fresh random nonce is generated on every call.
///
/// # Errors
///
/// Returns [`CryptoError`] for invalid UTF-8/size/time/path/header values or
/// any random, derivation, secure-memory, AEAD, or framing failure.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_document(
    master_key: &VaultMasterKey,
    vault_id: Uuid,
    key_epoch: u32,
    logical_path: &LogicalPath,
    identity: Option<FileIdentity>,
    plaintext: &[u8],
    modified_at_ms: i64,
    mut content_flags: ContentFlags,
    kind: EnvelopeKind,
) -> Result<EncryptedDocument, CryptoError> {
    if plaintext.len() > format::MAX_PLAINTEXT_LEN {
        return Err(CryptoError::PlaintextTooLarge);
    }
    std::str::from_utf8(plaintext).map_err(|_| CryptoError::InvalidMarkdownUtf8)?;
    let identity = match identity {
        Some(identity) => identity,
        None => FileIdentity {
            file_id: random_uuid_v4()?,
            created_at_ms: modified_at_ms,
        },
    };
    let base_etag = match kind {
        EnvelopeKind::Committed => {
            if content_flags.contains(ContentFlags::DRAFT) {
                return Err(CryptoError::DocumentContextMismatch);
            }
            None
        }
        EnvelopeKind::Draft { base_etag } => {
            content_flags |= ContentFlags::DRAFT;
            base_etag
        }
    };
    let header = EdryHeader {
        vault_id,
        file_id: identity.file_id,
        logical_path: logical_path.as_str().to_owned(),
        key_epoch,
        key_derivation: FileKeyDerivation::Blake2b256V1,
        cipher: CipherSuite::XChaCha20Poly1305Ietf,
        nonce: sodium::random_array()?,
        plaintext_kind: PlaintextKind::Utf8Markdown,
        created_at_ms: identity.created_at_ms,
        modified_at_ms,
        content_flags,
        required_features: Vec::new(),
        base_etag,
    };
    encrypt_with_header(master_key, header, plaintext)
}

/// Authenticate and decrypt an EDRY document in an expected logical context.
///
/// # Errors
///
/// Returns [`CryptoError`] for malformed/noncanonical framing, context or kind
/// mismatch, authentication failure, invalid UTF-8, or key-derivation failure.
pub fn decrypt_document(
    master_key: &VaultMasterKey,
    expected_vault_id: Uuid,
    expected_key_epoch: u32,
    expected_path: &LogicalPath,
    expected_kind: ExpectedEnvelopeKind,
    envelope: &[u8],
) -> Result<DecryptedDocument, CryptoError> {
    let parts = format::split_envelope(envelope)?;
    if parts.header.vault_id != expected_vault_id
        || parts.header.key_epoch != expected_key_epoch
        || parts.header.logical_path != expected_path.as_str()
        || !kind_matches(expected_kind, parts.header.is_draft())
    {
        return Err(CryptoError::DocumentContextMismatch);
    }

    let file_key = derive_file_key(
        master_key,
        parts.header.vault_id,
        parts.header.key_epoch,
        parts.header.file_id,
    )?;
    let aad = parts.associated_data()?;
    let plaintext = file_key
        .with_read(|key| {
            sodium::xchacha20poly1305_decrypt(parts.ciphertext, &aad, &parts.header.nonce, key)
        })?
        .map_err(|error| match error {
            SodiumError::AuthenticationFailed => CryptoError::DocumentAuthenticationFailed,
            other => CryptoError::Sodium(other),
        })?;
    std::str::from_utf8(plaintext.as_slice()).map_err(|_| CryptoError::InvalidMarkdownUtf8)?;

    Ok(DecryptedDocument {
        header: parts.header,
        plaintext,
        etag: format::etag(envelope),
    })
}

fn encrypt_with_header(
    master_key: &VaultMasterKey,
    header: EdryHeader,
    plaintext: &[u8],
) -> Result<EncryptedDocument, CryptoError> {
    let file_key = derive_file_key(
        master_key,
        header.vault_id,
        header.key_epoch,
        header.file_id,
    )?;
    let aad = format::associated_data_for_header(&header)?;
    let ciphertext = file_key.with_read(|key| {
        sodium::xchacha20poly1305_encrypt(plaintext, &aad, &header.nonce, key)
    })??;
    let bytes = format::build_envelope(&header, &ciphertext)?;
    let etag = format::etag(&bytes);
    Ok(EncryptedDocument {
        header,
        bytes,
        etag,
    })
}

fn derive_file_key(
    master_key: &VaultMasterKey,
    vault_id: Uuid,
    key_epoch: u32,
    file_id: Uuid,
) -> Result<LockedBytes<{ sodium::KEY_BYTES }>, CryptoError> {
    let mut context = Vec::with_capacity(FILE_KEY_DOMAIN.len() + 16 + 4 + 16);
    context.extend_from_slice(FILE_KEY_DOMAIN);
    context.extend_from_slice(vault_id.as_bytes());
    context.extend_from_slice(&key_epoch.to_be_bytes());
    context.extend_from_slice(file_id.as_bytes());
    let mut derived = master_key
        .bytes
        .with_read(|key| sodium::blake2b_256_keyed(key, &context))??;
    let locked = LockedBytes::from_slice(&derived);
    derived.zeroize();
    Ok(locked?)
}

fn wrap_master_key(
    config: &VaultConfig,
    slot_id: Uuid,
    password: &[u8],
    master_key: &VaultMasterKey,
    policy: KdfPolicy,
) -> Result<[u8; 48], CryptoError> {
    let slot = config.key_slot(slot_id)?;
    let params = slot_params(slot);
    let kek = sodium::derive_kek_argon2id13(
        password,
        slot.kdf.salt.as_array(),
        params,
        reader_limits(policy),
    )?;
    let aad = config.wrap_aad(slot_id)?;
    let ciphertext = kek.with_read(|kek_bytes| {
        master_key.bytes.with_read(|master_bytes| {
            sodium::xchacha20poly1305_encrypt(
                master_bytes,
                &aad,
                slot.wrap.nonce.as_array(),
                kek_bytes,
            )
        })
    })???;
    let mut ciphertext = Zeroizing::new(ciphertext);
    let array = ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidWrappedKeyLength)?;
    ciphertext.zeroize();
    Ok(array)
}

fn unwrap_master_key(
    config: &VaultConfig,
    slot_id: Uuid,
    password: &[u8],
    policy: KdfPolicy,
) -> Result<VaultMasterKey, CryptoError> {
    let slot = config.key_slot(slot_id)?;
    let kek = sodium::derive_kek_argon2id13(
        password,
        slot.kdf.salt.as_array(),
        slot_params(slot),
        reader_limits(policy),
    )?;
    let aad = config.wrap_aad(slot_id)?;
    let plaintext = kek
        .with_read(|kek_bytes| {
            sodium::xchacha20poly1305_decrypt(
                slot.wrap.ciphertext.as_array(),
                &aad,
                slot.wrap.nonce.as_array(),
                kek_bytes,
            )
        })?
        .map_err(|error| match error {
            SodiumError::AuthenticationFailed => CryptoError::VaultAuthenticationFailed,
            other => CryptoError::Sodium(other),
        })?;
    if plaintext.len() != sodium::KEY_BYTES {
        return Err(CryptoError::VaultAuthenticationFailed);
    }
    VaultMasterKey::from_plaintext(plaintext.as_slice())
}

fn refresh_metadata_mac(
    config: &mut VaultConfig,
    master_key: &VaultMasterKey,
) -> Result<(), CryptoError> {
    config.metadata_mac = EncodedBytes::new(compute_metadata_mac(config, master_key)?);
    Ok(())
}

fn verify_metadata_mac(
    config: &VaultConfig,
    master_key: &VaultMasterKey,
) -> Result<(), CryptoError> {
    let mut actual = compute_metadata_mac(config, master_key)?;
    let matches = sodium::constant_time_eq(&actual, config.metadata_mac.as_array())?;
    actual.zeroize();
    if matches {
        Ok(())
    } else {
        Err(CryptoError::MetadataAuthenticationFailed)
    }
}

fn compute_metadata_mac(
    config: &VaultConfig,
    master_key: &VaultMasterKey,
) -> Result<[u8; 32], CryptoError> {
    let key_context = config.metadata_key_context();
    let mut metadata_key = master_key
        .bytes
        .with_read(|key| sodium::blake2b_256_keyed(key, &key_context))??;
    let payload = config.metadata_payload()?;
    let result = sodium::blake2b_256_keyed(&metadata_key, &payload);
    metadata_key.zeroize();
    Ok(result?)
}

fn validate_new_slot_params(params: Argon2idParams, policy: KdfPolicy) -> Result<(), CryptoError> {
    if params.ops_limit < policy.min_creation_ops_limit
        || params.mem_limit_bytes < policy.min_creation_mem_limit_bytes
    {
        return Err(ConfigError::KdfBelowCreationPolicy.into());
    }
    params.validate(reader_limits(policy))?;
    Ok(())
}

const fn reader_limits(policy: KdfPolicy) -> Argon2idLimits {
    Argon2idLimits {
        min_ops_limit: 1,
        max_ops_limit: policy.max_unlock_ops_limit,
        min_mem_limit_bytes: crate::vault_config::MIN_UNLOCK_MEM_LIMIT_BYTES,
        max_mem_limit_bytes: policy.max_unlock_mem_limit_bytes,
    }
}

const fn slot_params(slot: &KeySlot) -> Argon2idParams {
    Argon2idParams {
        ops_limit: slot.kdf.ops_limit,
        mem_limit_bytes: slot.kdf.mem_limit_bytes,
    }
}

fn random_uuid_v4() -> Result<Uuid, CryptoError> {
    let mut bytes = sodium::random_array::<16>()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

const fn kind_matches(expected: ExpectedEnvelopeKind, is_draft: bool) -> bool {
    match expected {
        ExpectedEnvelopeKind::Committed => !is_draft,
        ExpectedEnvelopeKind::Draft => is_draft,
        ExpectedEnvelopeKind::Either => true,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureArgon2id {
        algorithm: String,
        ops_limit: u64,
        mem_limit_bytes: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureVector {
        schema_version: u32,
        classification: String,
        description: String,
        password_utf8: String,
        password_base64_url: String,
        master_key_base64_url: String,
        vault_id: Uuid,
        slot_id: Uuid,
        salt_base64_url: String,
        argon2id: FixtureArgon2id,
        wrap_nonce_base64_url: String,
        key_epoch: u32,
        file_id: Uuid,
        document_nonce_base64_url: String,
        logical_path: String,
        vault_created_at_ms: i64,
        file_created_at_ms: i64,
        file_modified_at_ms: i64,
        plaintext_base64_url: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FixtureExpected {
        schema_version: u32,
        wrapped_master_key_base64_url: String,
        metadata_mac_base64_url: String,
        header_cbor_base64_url: String,
        ciphertext_body_base64_url: String,
        etag: String,
    }

    fn test_policy() -> KdfPolicy {
        KdfPolicy {
            min_creation_ops_limit: 1,
            min_creation_mem_limit_bytes: 8 * 1024,
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

    fn created() -> CreatedVault {
        match create_vault_with_params(
            b"correct horse",
            1_783_699_200_000,
            test_params(),
            test_policy(),
        ) {
            Ok(created) => created,
            Err(error) => panic!("test vault creation failed: {error}"),
        }
    }

    fn path() -> LogicalPath {
        match LogicalPath::parse_canonical("2026/07/日记.md") {
            Ok(path) => path,
            Err(error) => panic!("test path failed: {error}"),
        }
    }

    fn decode_fixture_bytes(value: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(value)
            .expect("fixture base64url is canonical and valid")
    }

    fn decode_fixture_array<const N: usize>(value: &str) -> [u8; N] {
        decode_fixture_bytes(value)
            .try_into()
            .unwrap_or_else(|bytes: Vec<u8>| panic!("fixture needs {N} bytes, got {}", bytes.len()))
    }

    fn fixed_vector(vector: &FixtureVector) -> (VaultMasterKey, VaultConfig, EncryptedDocument) {
        let policy = test_policy();
        assert_eq!(vector.argon2id.algorithm, "argon2id13");
        let password = decode_fixture_bytes(&vector.password_base64_url);
        assert_eq!(password, vector.password_utf8.as_bytes());
        let master_key = VaultMasterKey::from_plaintext(&decode_fixture_array::<32>(
            &vector.master_key_base64_url,
        ))
        .expect("fixed master key allocation succeeds");
        let mut config = VaultConfig {
            format: VaultFormat::V1,
            vault_id: vector.vault_id,
            key_epoch: vector.key_epoch,
            created_at: vector.vault_created_at_ms,
            required_features: Vec::new(),
            key_slots: vec![KeySlot {
                id: vector.slot_id,
                kind: KeySlotKind::Password,
                kdf: KdfConfig {
                    algorithm: KdfAlgorithm::Argon2id13,
                    salt: EncodedBytes::new(decode_fixture_array(&vector.salt_base64_url)),
                    ops_limit: vector.argon2id.ops_limit,
                    mem_limit_bytes: vector.argon2id.mem_limit_bytes,
                },
                wrap: WrapConfig {
                    algorithm: WrapAlgorithm::XChaCha20Poly1305Ietf,
                    nonce: EncodedBytes::new(decode_fixture_array(&vector.wrap_nonce_base64_url)),
                    ciphertext: EncodedBytes::new([0; 48]),
                },
                created_at: vector.vault_created_at_ms,
            }],
            features: VaultFeatures::default(),
            metadata_mac: EncodedBytes::new([0; 32]),
        };
        let wrapped = wrap_master_key(&config, vector.slot_id, &password, &master_key, policy)
            .expect("fixed master key wrapping succeeds");
        config.key_slots[0].wrap.ciphertext = EncodedBytes::new(wrapped);
        refresh_metadata_mac(&mut config, &master_key).expect("fixed metadata MAC succeeds");
        config
            .validate_untrusted(policy)
            .expect("fixed vault metadata is valid");

        let header = EdryHeader {
            vault_id: vector.vault_id,
            file_id: vector.file_id,
            logical_path: vector.logical_path.clone(),
            key_epoch: vector.key_epoch,
            key_derivation: FileKeyDerivation::Blake2b256V1,
            cipher: CipherSuite::XChaCha20Poly1305Ietf,
            nonce: decode_fixture_array(&vector.document_nonce_base64_url),
            plaintext_kind: PlaintextKind::Utf8Markdown,
            created_at_ms: vector.file_created_at_ms,
            modified_at_ms: vector.file_modified_at_ms,
            content_flags: ContentFlags::NONE,
            required_features: Vec::new(),
            base_etag: None,
        };
        let document = encrypt_with_header(
            &master_key,
            header,
            &decode_fixture_bytes(&vector.plaintext_base64_url),
        )
        .expect("fixed EDRY encryption succeeds");
        (master_key, config, document)
    }

    #[test]
    fn committed_v1_fixture_is_exact_and_future_readable() {
        let vector: FixtureVector =
            serde_json::from_str(include_str!("../../../fixtures/v1-fixed/vector.json"))
                .expect("fixture vector JSON parses");
        let expected: FixtureExpected =
            serde_json::from_str(include_str!("../../../fixtures/v1-fixed/expected.json"))
                .expect("fixture expected JSON parses");
        assert_eq!(vector.schema_version, 1);
        assert_eq!(expected.schema_version, 1);
        assert_eq!(vector.classification, "public-non-secret-test-vector");
        assert!(vector.description.contains("Never use"));

        let (master_key, config, generated) = fixed_vector(&vector);
        let fixture_vault = include_bytes!("../../../fixtures/v1-fixed/vault.json");
        let serialized = config
            .to_json_bytes(test_policy())
            .expect("fixed vault JSON serializes");
        assert_eq!(serialized, fixture_vault);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(config.key_slots[0].wrap.ciphertext.as_array()),
            expected.wrapped_master_key_base64_url
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(config.metadata_mac.as_array()),
            expected.metadata_mac_base64_url
        );

        let fixture_envelope = decode_fixture_bytes(
            include_str!("../../../fixtures/v1-fixed/document.md.enc.b64").trim(),
        );
        assert_eq!(generated.bytes, fixture_envelope);
        assert_eq!(generated.etag, expected.etag);
        assert_eq!(format::etag(&fixture_envelope), expected.etag);
        let parts = format::split_envelope(&fixture_envelope).expect("fixture EDRY parses");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(parts.header_bytes),
            expected.header_cbor_base64_url
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(parts.ciphertext),
            expected.ciphertext_body_base64_url
        );
        assert_eq!(parts.header, generated.header);

        let (parsed, warnings) =
            VaultConfig::parse_untrusted(fixture_vault, test_policy()).expect("vault JSON parses");
        assert!(warnings.is_empty());
        assert_eq!(parsed, config);
        let password = decode_fixture_bytes(&vector.password_base64_url);
        let unlocked = unlock_vault(&parsed, &password, None, test_policy())
            .expect("fixture password unlocks committed vault metadata");
        let logical_path =
            LogicalPath::parse_canonical(&vector.logical_path).expect("fixture path is canonical");
        let decrypted = decrypt_document(
            &unlocked.master_key,
            parsed.vault_id,
            parsed.key_epoch,
            &logical_path,
            ExpectedEnvelopeKind::Committed,
            &fixture_envelope,
        )
        .expect("committed fixture decrypts through normal v1 reader");
        assert_eq!(
            decrypted.plaintext.as_slice(),
            decode_fixture_bytes(&vector.plaintext_base64_url)
        );
        assert_eq!(decrypted.header, generated.header);
        assert_eq!(decrypted.etag, expected.etag);

        let direct = decrypt_document(
            &master_key,
            vector.vault_id,
            vector.key_epoch,
            &logical_path,
            ExpectedEnvelopeKind::Committed,
            &fixture_envelope,
        )
        .expect("fixed master key independently decrypts fixture");
        assert_eq!(direct.plaintext, decrypted.plaintext);
    }

    #[test]
    fn create_unlock_and_wrong_password_are_safe() {
        let created = created();
        let unlocked = unlock_vault(&created.config, b"correct horse", None, test_policy());
        assert!(unlocked.is_ok());
        let wrong = unlock_vault(&created.config, b"wrong horse", None, test_policy());
        assert!(matches!(wrong, Err(CryptoError::VaultAuthenticationFailed)));

        let known_key = VaultMasterKey::from_plaintext(&[0x5a; sodium::KEY_BYTES])
            .expect("secure test-key allocation succeeds");
        let health = known_key.memory_health();
        assert!(
            health.page_protection,
            "libsodium page guards must be active"
        );
        let readable = known_key
            .bytes
            .with_read(|bytes| sodium::constant_time_eq(bytes, &[0x5a; sodium::KEY_BYTES]))
            .expect("protected key can transition to read-only")
            .expect("constant-time comparison succeeds");
        assert!(readable);

        let debug = format!("{known_key:?}");
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains(&format!("{health:?}")));
        assert!(!debug.contains("5a5a5a5a"));
    }

    #[test]
    fn metadata_tampering_is_detected_after_unwrap() {
        let created = created();
        let mut tampered = created.config.clone();
        tampered.metadata_mac = EncodedBytes::new([0x5a; 32]);
        let result = unlock_vault(&tampered, b"correct horse", None, test_policy());
        assert!(matches!(
            result,
            Err(CryptoError::MetadataAuthenticationFailed)
        ));
    }

    #[test]
    fn password_slot_change_does_not_rewrite_edry() {
        let created = created();
        let encrypted = encrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &path(),
            None,
            "# secret\r\n中文\n".as_bytes(),
            1_783_699_200_100,
            ContentFlags::NONE,
            EnvelopeKind::Committed,
        );
        let encrypted = match encrypted {
            Ok(value) => value,
            Err(error) => panic!("encryption failed: {error}"),
        };
        let before = encrypted.bytes.clone();

        let (with_new, new_id) = match add_password_slot(
            &created.config,
            &created.master_key,
            b"new password",
            1_783_699_200_200,
            test_params(),
            test_policy(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("slot add failed: {error}"),
        };
        let unlocked_new = unlock_vault(&with_new, b"new password", Some(new_id), test_policy())
            .expect("new slot unlocks the same master key");
        let via_new_slot = decrypt_document(
            &unlocked_new.master_key,
            with_new.vault_id,
            with_new.key_epoch,
            &path(),
            ExpectedEnvelopeKind::Committed,
            &encrypted.bytes,
        )
        .expect("new password slot decrypts pre-existing EDRY bytes");
        assert_eq!(
            via_new_slot.plaintext.as_slice(),
            "# secret\r\n中文\n".as_bytes()
        );
        assert!(matches!(
            unlock_vault(&with_new, b"new password", None, test_policy()),
            Err(CryptoError::SlotSelectionRequired)
        ));

        let removed = match remove_password_slot(
            &with_new,
            &created.master_key,
            created.slot_id,
            test_policy(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("slot remove failed: {error}"),
        };
        assert!(unlock_vault(&removed, b"new password", None, test_policy()).is_ok());
        assert_eq!(encrypted.bytes, before);
    }

    #[test]
    fn committed_document_round_trips_exact_bytes_and_context() {
        let created = created();
        let plaintext = "# 标题\r\nemoji: 🧊\n".as_bytes();
        let encrypted = match encrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &path(),
            None,
            plaintext,
            1_783_699_200_100,
            ContentFlags::NONE,
            EnvelopeKind::Committed,
        ) {
            Ok(value) => value,
            Err(error) => panic!("encryption failed: {error}"),
        };
        let decrypted = match decrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &path(),
            ExpectedEnvelopeKind::Committed,
            &encrypted.bytes,
        ) {
            Ok(value) => value,
            Err(error) => panic!("decryption failed: {error}"),
        };
        assert_eq!(decrypted.plaintext.as_slice(), plaintext);
        assert_eq!(decrypted.etag, encrypted.etag);

        let other_path = LogicalPath::parse_canonical("2026/07/other.md");
        assert!(other_path.is_ok());
        assert!(matches!(
            decrypt_document(
                &created.master_key,
                created.config.vault_id,
                created.config.key_epoch,
                &other_path.unwrap(),
                ExpectedEnvelopeKind::Committed,
                &encrypted.bytes,
            ),
            Err(CryptoError::DocumentContextMismatch)
        ));
    }

    #[test]
    fn utf8_and_newline_corpus_round_trips_without_normalization() {
        let created = created();
        let long = "🧊南极e\u{301}\r\n".repeat(4_097);
        let corpus: Vec<&[u8]> = vec![
            b"",
            b"plain ASCII",
            b"# LF\nsecond\n",
            b"# CRLF\r\nsecond\r\n",
            b"mixed\r\nline\nlast\r",
            "中文、emoji 🧊、مرحبا".as_bytes(),
            "NFC: é; NFD: e\u{301}".as_bytes(),
            "\u{feff}BOM is content\n".as_bytes(),
            "embedded NUL: \0 still UTF-8".as_bytes(),
            long.as_bytes(),
        ];

        for (index, plaintext) in corpus.into_iter().enumerate() {
            let modified_at_ms =
                1_783_699_200_100 + i64::try_from(index).expect("small corpus index fits in i64");
            let encrypted = encrypt_document(
                &created.master_key,
                created.config.vault_id,
                created.config.key_epoch,
                &path(),
                None,
                plaintext,
                modified_at_ms,
                ContentFlags::NONE,
                EnvelopeKind::Committed,
            )
            .expect("valid UTF-8 corpus entry encrypts");
            let decrypted = decrypt_document(
                &created.master_key,
                created.config.vault_id,
                created.config.key_epoch,
                &path(),
                ExpectedEnvelopeKind::Committed,
                &encrypted.bytes,
            )
            .expect("valid UTF-8 corpus entry decrypts");
            assert_eq!(decrypted.plaintext.as_slice(), plaintext, "case {index}");
        }

        assert!(matches!(
            encrypt_document(
                &created.master_key,
                created.config.vault_id,
                created.config.key_epoch,
                &path(),
                None,
                &[0xf0, 0x28, 0x8c, 0x28],
                1_783_699_200_200,
                ContentFlags::NONE,
                EnvelopeKind::Committed,
            ),
            Err(CryptoError::InvalidMarkdownUtf8)
        ));
    }

    #[test]
    fn repeated_identical_saves_preserve_identity_and_never_reuse_a_nonce() {
        let created = created();
        let original_path = path();
        let original = encrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &original_path,
            None,
            b"same content\r\n",
            1_783_699_200_100,
            ContentFlags::NONE,
            EnvelopeKind::Committed,
        )
        .expect("original encrypts");
        let identity = FileIdentity::from_header(&original.header);
        let mut nonces = HashSet::from([original.header.nonce]);
        let mut previous_etag = original.etag.clone();

        for offset in 1_i64..=32 {
            let saved = encrypt_document(
                &created.master_key,
                created.config.vault_id,
                created.config.key_epoch,
                &original_path,
                Some(identity),
                b"same content\r\n",
                1_783_699_200_100 + offset,
                ContentFlags::NONE,
                EnvelopeKind::Committed,
            )
            .expect("repeat save encrypts");
            assert_eq!(FileIdentity::from_header(&saved.header), identity);
            assert!(
                nonces.insert(saved.header.nonce),
                "save {offset} reused a nonce"
            );
            assert_ne!(saved.etag, previous_etag);
            previous_etag = saved.etag;
        }
    }

    #[test]
    fn rename_then_save_preserves_identity_and_rebinds_context() {
        let created = created();
        let original_path = path();
        let renamed_path =
            LogicalPath::parse_canonical("2026/07/重命名.md").expect("rename path is valid");
        let original = encrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &original_path,
            None,
            b"same content\r\n",
            1_783_699_200_100,
            ContentFlags::NONE,
            EnvelopeKind::Committed,
        )
        .expect("original encrypts");
        let identity = FileIdentity::from_header(&original.header);

        let renamed = encrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &renamed_path,
            Some(identity),
            b"same content\r\n",
            1_783_699_200_200,
            ContentFlags::NONE,
            EnvelopeKind::Committed,
        )
        .expect("renamed document re-encrypts");
        assert_eq!(FileIdentity::from_header(&renamed.header), identity);
        assert_eq!(renamed.header.logical_path, renamed_path.as_str());
        assert_ne!(renamed.bytes, original.bytes);
        assert!(matches!(
            decrypt_document(
                &created.master_key,
                created.config.vault_id,
                created.config.key_epoch,
                &original_path,
                ExpectedEnvelopeKind::Committed,
                &renamed.bytes,
            ),
            Err(CryptoError::DocumentContextMismatch)
        ));
        let decrypted = decrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &renamed_path,
            ExpectedEnvelopeKind::Committed,
            &renamed.bytes,
        )
        .expect("renamed context decrypts");
        assert_eq!(decrypted.plaintext.as_slice(), b"same content\r\n");

        let resaved = encrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &renamed_path,
            Some(FileIdentity::from_header(&renamed.header)),
            b"changed after rename\n",
            1_783_699_200_300,
            ContentFlags::NONE,
            EnvelopeKind::Committed,
        )
        .expect("post-rename save encrypts");
        assert_eq!(FileIdentity::from_header(&resaved.header), identity);
        assert_ne!(resaved.header.nonce, renamed.header.nonce);
        assert_ne!(resaved.etag, renamed.etag);
        let reloaded = decrypt_document(
            &created.master_key,
            created.config.vault_id,
            created.config.key_epoch,
            &renamed_path,
            ExpectedEnvelopeKind::Committed,
            &resaved.bytes,
        )
        .expect("post-rename save reloads");
        assert_eq!(reloaded.plaintext.as_slice(), b"changed after rename\n");
    }

    #[test]
    fn tampering_returns_no_plaintext() {
        let created = created();
        let mut encrypted = match encrypt_document(
            &created.master_key,
            created.config.vault_id,
            0,
            &path(),
            None,
            b"secret canary",
            1_783_699_200_100,
            ContentFlags::NONE,
            EnvelopeKind::Committed,
        ) {
            Ok(value) => value,
            Err(error) => panic!("encryption failed: {error}"),
        };
        let last = encrypted.bytes.len() - 1;
        encrypted.bytes[last] ^= 1;
        assert!(matches!(
            decrypt_document(
                &created.master_key,
                created.config.vault_id,
                0,
                &path(),
                ExpectedEnvelopeKind::Committed,
                &encrypted.bytes,
            ),
            Err(CryptoError::DocumentAuthenticationFailed)
        ));
    }

    #[test]
    fn encrypted_draft_binds_base_etag_and_kind() {
        let created = created();
        let base = [0xa5; 32];
        let encrypted = match encrypt_document(
            &created.master_key,
            created.config.vault_id,
            0,
            &path(),
            None,
            b"unsaved",
            1_783_699_200_100,
            ContentFlags::NONE,
            EnvelopeKind::Draft {
                base_etag: Some(base),
            },
        ) {
            Ok(value) => value,
            Err(error) => panic!("draft encryption failed: {error}"),
        };
        assert!(encrypted.header.is_draft());
        assert_eq!(encrypted.header.base_etag, Some(base));
        assert!(matches!(
            decrypt_document(
                &created.master_key,
                created.config.vault_id,
                0,
                &path(),
                ExpectedEnvelopeKind::Committed,
                &encrypted.bytes,
            ),
            Err(CryptoError::DocumentContextMismatch)
        ));
        assert!(
            decrypt_document(
                &created.master_key,
                created.config.vault_id,
                0,
                &path(),
                ExpectedEnvelopeKind::Draft,
                &encrypted.bytes,
            )
            .is_ok()
        );
    }
}
