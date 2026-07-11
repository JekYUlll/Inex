//! Authenticated `vault.json` data model and deterministic metadata encoding.
//!
//! The JSON file is untrusted until a password slot unwraps the master key and
//! the metadata MAC verifies. This module performs all resource-bound checks
//! needed before the password KDF is called and provides deterministic CBOR
//! bytes for slot AAD and the metadata MAC.

use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use minicbor::Encoder;
use minicbor::encode;
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

/// Maximum accepted `vault.json` size before JSON parsing.
pub const MAX_VAULT_JSON_BYTES: usize = 1024 * 1024;
/// New vaults must use at least 64 MiB for Argon2id.
pub const MIN_CREATION_MEM_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
/// New vaults must use at least three Argon2id operations.
pub const MIN_CREATION_OPS_LIMIT: u64 = 3;
/// Default defensive ceiling applied before invoking an untrusted KDF request.
pub const DEFAULT_MAX_UNLOCK_MEM_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
/// Default defensive Argon2id operations ceiling.
pub const DEFAULT_MAX_UNLOCK_OPS_LIMIT: u64 = 20;
/// v1 supports a deliberately small number of independently wrapped slots.
pub const MAX_KEY_SLOTS: usize = 16;
/// Exact lower bound accepted from legacy metadata before libsodium validation.
pub const MIN_UNLOCK_MEM_LIMIT_BYTES: u64 = 8 * 1024;
/// Passwords are exact UTF-8 bytes and are never trimmed or normalized.
pub const MAX_PASSWORD_BYTES: usize = 1024;

const WRAP_AAD_DOMAIN: &[u8] = b"INEX-WRAP-V1\0";
const METADATA_KEY_DOMAIN: &[u8] = b"INEX-METADATA-KEY-V1\0";

/// A fixed-size value serialized as canonical unpadded base64url.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedBytes<const N: usize>([u8; N]);

impl<const N: usize> EncodedBytes<N> {
    /// Construct a fixed-size encoded value from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow the decoded bytes.
    #[must_use]
    pub const fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    /// Consume the wrapper.
    #[must_use]
    pub const fn into_inner(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> fmt::Debug for EncodedBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedBytes")
            .field("length", &N)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> Serialize for EncodedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

struct EncodedBytesVisitor<const N: usize>;

impl<const N: usize> Visitor<'_> for EncodedBytesVisitor<N> {
    type Value = EncodedBytes<N>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "canonical unpadded base64url that decodes to exactly {N} bytes"
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        let decoded = URL_SAFE_NO_PAD.decode(value).map_err(E::custom)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(E::custom("non-canonical base64url"));
        }
        let actual = decoded.len();
        let bytes = decoded
            .try_into()
            .map_err(|_| E::custom(format_args!("expected {N} bytes, got {actual}")))?;
        Ok(EncodedBytes(bytes))
    }
}

impl<'de, const N: usize> Deserialize<'de> for EncodedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(EncodedBytesVisitor)
    }
}

/// Version tuple for the vault metadata schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFormat {
    pub major: u8,
    pub minor: u8,
}

impl VaultFormat {
    pub const V1: Self = Self { major: 1, minor: 0 };
}

/// Algorithms are explicit so a future library default cannot change v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    #[serde(rename = "argon2id13")]
    Argon2id13,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KdfConfig {
    pub algorithm: KdfAlgorithm,
    pub salt: EncodedBytes<16>,
    pub ops_limit: u64,
    pub mem_limit_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrapAlgorithm {
    #[serde(rename = "xchacha20-poly1305-ietf")]
    XChaCha20Poly1305Ietf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrapConfig {
    pub algorithm: WrapAlgorithm,
    pub nonce: EncodedBytes<24>,
    pub ciphertext: EncodedBytes<48>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeySlotKind {
    #[serde(rename = "password")]
    Password,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeySlot {
    #[serde(with = "canonical_uuid")]
    pub id: Uuid,
    pub kind: KeySlotKind,
    pub kdf: KdfConfig,
    pub wrap: WrapConfig,
    pub created_at: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultFeatures {
    pub filename_encryption: bool,
    pub streaming_blobs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultConfig {
    pub format: VaultFormat,
    #[serde(with = "canonical_uuid")]
    pub vault_id: Uuid,
    pub key_epoch: u32,
    pub created_at: i64,
    pub required_features: Vec<u32>,
    pub key_slots: Vec<KeySlot>,
    pub features: VaultFeatures,
    pub metadata_mac: EncodedBytes<32>,
}

/// Resource ceilings and creation floors for Argon2id metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfPolicy {
    pub min_creation_ops_limit: u64,
    pub min_creation_mem_limit_bytes: u64,
    pub max_unlock_ops_limit: u64,
    pub max_unlock_mem_limit_bytes: u64,
}

impl Default for KdfPolicy {
    fn default() -> Self {
        Self {
            min_creation_ops_limit: MIN_CREATION_OPS_LIMIT,
            min_creation_mem_limit_bytes: MIN_CREATION_MEM_LIMIT_BYTES,
            max_unlock_ops_limit: DEFAULT_MAX_UNLOCK_OPS_LIMIT,
            max_unlock_mem_limit_bytes: DEFAULT_MAX_UNLOCK_MEM_LIMIT_BYTES,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigWarning {
    WeakKdf { slot_id: Uuid },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("vault metadata exceeds the size limit")]
    MetadataTooLarge,
    #[error("invalid vault metadata JSON")]
    InvalidJson(#[source] serde_json::Error),
    #[error("unsupported vault metadata version")]
    UnsupportedVersion,
    #[error("vault identifier is invalid")]
    InvalidVaultId,
    #[error("vault creation timestamp is invalid")]
    InvalidTimestamp,
    #[error("required features are not strictly sorted")]
    NonCanonicalRequiredFeatures,
    #[error("required vault feature is unsupported")]
    UnsupportedRequiredFeature,
    #[error("optional feature is enabled but unsupported in v1")]
    UnsupportedFeature,
    #[error("vault must contain at least one password slot")]
    NoKeySlots,
    #[error("vault contains too many key slots")]
    TooManyKeySlots,
    #[error("key slot identifier is invalid or duplicated")]
    InvalidKeySlotId,
    #[error("key slot timestamp is invalid")]
    InvalidKeySlotTimestamp,
    #[error("Argon2id parameters are outside safe reader bounds")]
    KdfOutsideReaderBounds,
    #[error("Argon2id creation parameters are below policy")]
    KdfBelowCreationPolicy,
    #[error("password length is outside the supported range")]
    InvalidPasswordLength,
    #[error("password is not valid UTF-8")]
    InvalidPasswordUtf8,
    #[error("deterministic metadata encoding failed")]
    CborEncoding,
    #[error("requested key slot does not exist")]
    KeySlotNotFound,
}

impl VaultConfig {
    /// Parse and resource-bound untrusted JSON before any password KDF call.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the input exceeds the size bound, is not
    /// valid schema JSON, or fails pre-authentication validation.
    pub fn parse_untrusted(
        bytes: &[u8],
        policy: KdfPolicy,
    ) -> Result<(Self, Vec<ConfigWarning>), ConfigError> {
        if bytes.len() > MAX_VAULT_JSON_BYTES {
            return Err(ConfigError::MetadataTooLarge);
        }
        let config: Self = serde_json::from_slice(bytes).map_err(ConfigError::InvalidJson)?;
        let warnings = config.validate_untrusted(policy)?;
        Ok((config, warnings))
    }

    /// Validate all semantics that are safe to inspect before authentication.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for unsupported versions/features, invalid or
    /// duplicate slots, invalid timestamps, or KDF parameters outside the
    /// configured reader resource bounds.
    pub fn validate_untrusted(&self, policy: KdfPolicy) -> Result<Vec<ConfigWarning>, ConfigError> {
        if self.format != VaultFormat::V1 {
            return Err(ConfigError::UnsupportedVersion);
        }
        if self.vault_id.is_nil() {
            return Err(ConfigError::InvalidVaultId);
        }
        if self.created_at < 0 {
            return Err(ConfigError::InvalidTimestamp);
        }
        if !strictly_sorted_unique(&self.required_features) {
            return Err(ConfigError::NonCanonicalRequiredFeatures);
        }
        if !self.required_features.is_empty() {
            return Err(ConfigError::UnsupportedRequiredFeature);
        }
        if self.features.filename_encryption || self.features.streaming_blobs {
            return Err(ConfigError::UnsupportedFeature);
        }
        if self.key_slots.is_empty() {
            return Err(ConfigError::NoKeySlots);
        }
        if self.key_slots.len() > MAX_KEY_SLOTS {
            return Err(ConfigError::TooManyKeySlots);
        }

        let mut ids = HashSet::with_capacity(self.key_slots.len());
        let mut warnings = Vec::new();
        for slot in &self.key_slots {
            if slot.id.is_nil() || !ids.insert(slot.id) {
                return Err(ConfigError::InvalidKeySlotId);
            }
            if slot.created_at < 0 {
                return Err(ConfigError::InvalidKeySlotTimestamp);
            }
            if slot.kdf.ops_limit == 0
                || slot.kdf.ops_limit > policy.max_unlock_ops_limit
                || slot.kdf.mem_limit_bytes < MIN_UNLOCK_MEM_LIMIT_BYTES
                || slot.kdf.mem_limit_bytes > policy.max_unlock_mem_limit_bytes
                || usize::try_from(slot.kdf.mem_limit_bytes).is_err()
            {
                return Err(ConfigError::KdfOutsideReaderBounds);
            }
            if slot.kdf.ops_limit < policy.min_creation_ops_limit
                || slot.kdf.mem_limit_bytes < policy.min_creation_mem_limit_bytes
            {
                warnings.push(ConfigWarning::WeakKdf { slot_id: slot.id });
            }
        }
        Ok(warnings)
    }

    /// Require every slot to satisfy the creation policy.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for an untrusted-metadata validation failure or
    /// when one or more slots fall below the new-vault KDF floor.
    pub fn validate_for_creation(&self, policy: KdfPolicy) -> Result<(), ConfigError> {
        let warnings = self.validate_untrusted(policy)?;
        if warnings.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::KdfBelowCreationPolicy)
        }
    }

    /// Serialize stable, human-readable JSON. Security does not depend on JSON
    /// member order; the MAC uses [`Self::metadata_payload`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the configuration is invalid under
    /// `policy` or JSON serialization fails.
    pub fn to_json_bytes(&self, policy: KdfPolicy) -> Result<Vec<u8>, ConfigError> {
        self.validate_untrusted(policy)?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(ConfigError::InvalidJson)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Get a slot by its stable UUID.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::KeySlotNotFound`] when `id` is absent.
    pub fn key_slot(&self, id: Uuid) -> Result<&KeySlot, ConfigError> {
        self.key_slots
            .iter()
            .find(|slot| slot.id == id)
            .ok_or(ConfigError::KeySlotNotFound)
    }

    /// Deterministic slot AAD independent of JSON object ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the slot is absent or deterministic CBOR
    /// encoding cannot be completed.
    pub fn wrap_aad(&self, slot_id: Uuid) -> Result<Vec<u8>, ConfigError> {
        let slot = self.key_slot(slot_id)?;
        let mut encoder = Encoder::new(Vec::new());
        enc(encoder.array(12))?;
        enc(encoder.bytes(WRAP_AAD_DOMAIN))?;
        enc(encoder.u8(self.format.major))?;
        enc(encoder.u8(self.format.minor))?;
        enc(encoder.bytes(self.vault_id.as_bytes()))?;
        enc(encoder.u32(self.key_epoch))?;
        enc(encoder.bytes(slot.id.as_bytes()))?;
        enc(encoder.u8(key_slot_kind_id(slot.kind)))?;
        enc(encoder.u8(kdf_algorithm_id(slot.kdf.algorithm)))?;
        enc(encoder.bytes(slot.kdf.salt.as_array()))?;
        enc(encoder.u64(slot.kdf.ops_limit))?;
        enc(encoder.u64(slot.kdf.mem_limit_bytes))?;
        enc(encoder.u8(wrap_algorithm_id(slot.wrap.algorithm)))?;
        Ok(encoder.into_writer())
    }

    /// Bytes fed to the master-keyed derivation for the metadata MAC key.
    #[must_use]
    pub fn metadata_key_context(&self) -> Vec<u8> {
        let mut context = Vec::with_capacity(METADATA_KEY_DOMAIN.len() + 16 + 4);
        context.extend_from_slice(METADATA_KEY_DOMAIN);
        context.extend_from_slice(self.vault_id.as_bytes());
        context.extend_from_slice(&self.key_epoch.to_be_bytes());
        context
    }

    /// Deterministic authenticated representation of every semantic field
    /// except `metadataMac`. Slots are ordered by raw UUID bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::CborEncoding`] when a collection length cannot
    /// be represented or the in-memory encoder reports failure.
    pub fn metadata_payload(&self) -> Result<Vec<u8>, ConfigError> {
        let mut slots: Vec<&KeySlot> = self.key_slots.iter().collect();
        slots.sort_unstable_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));

        let mut encoder = Encoder::new(Vec::new());
        enc(encoder.map(7))?;

        enc(encoder.u8(0))?;
        enc(encoder.array(2))?;
        enc(encoder.u8(self.format.major))?;
        enc(encoder.u8(self.format.minor))?;

        enc(encoder.u8(1))?;
        enc(encoder.bytes(self.vault_id.as_bytes()))?;

        enc(encoder.u8(2))?;
        enc(encoder.u32(self.key_epoch))?;

        enc(encoder.u8(3))?;
        enc(encoder.i64(self.created_at))?;

        enc(encoder.u8(4))?;
        enc(encoder.array(
            u64::try_from(self.required_features.len()).map_err(|_| ConfigError::CborEncoding)?,
        ))?;
        for feature in &self.required_features {
            enc(encoder.u32(*feature))?;
        }

        enc(encoder.u8(5))?;
        enc(encoder.map(2))?;
        enc(encoder.u8(0))?;
        enc(encoder.bool(self.features.filename_encryption))?;
        enc(encoder.u8(1))?;
        enc(encoder.bool(self.features.streaming_blobs))?;

        enc(encoder.u8(6))?;
        enc(encoder.array(u64::try_from(slots.len()).map_err(|_| ConfigError::CborEncoding)?))?;
        for slot in slots {
            encode_slot(&mut encoder, slot)?;
        }

        Ok(encoder.into_writer())
    }
}

/// Validate password bytes without trimming or normalization.
///
/// # Errors
///
/// Returns [`ConfigError::InvalidPasswordLength`] for an empty password or one
/// longer than [`MAX_PASSWORD_BYTES`], and
/// [`ConfigError::InvalidPasswordUtf8`] for invalid UTF-8. Valid bytes are not
/// trimmed or normalized.
pub fn validate_password(password: &[u8]) -> Result<(), ConfigError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(ConfigError::InvalidPasswordLength);
    }
    std::str::from_utf8(password).map_err(|_| ConfigError::InvalidPasswordUtf8)?;
    Ok(())
}

fn encode_slot(encoder: &mut Encoder<Vec<u8>>, slot: &KeySlot) -> Result<(), ConfigError> {
    enc(encoder.map(5))?;
    enc(encoder.u8(0))?;
    enc(encoder.bytes(slot.id.as_bytes()))?;
    enc(encoder.u8(1))?;
    enc(encoder.u8(key_slot_kind_id(slot.kind)))?;

    enc(encoder.u8(2))?;
    enc(encoder.map(4))?;
    enc(encoder.u8(0))?;
    enc(encoder.u8(kdf_algorithm_id(slot.kdf.algorithm)))?;
    enc(encoder.u8(1))?;
    enc(encoder.bytes(slot.kdf.salt.as_array()))?;
    enc(encoder.u8(2))?;
    enc(encoder.u64(slot.kdf.ops_limit))?;
    enc(encoder.u8(3))?;
    enc(encoder.u64(slot.kdf.mem_limit_bytes))?;

    enc(encoder.u8(3))?;
    enc(encoder.map(3))?;
    enc(encoder.u8(0))?;
    enc(encoder.u8(wrap_algorithm_id(slot.wrap.algorithm)))?;
    enc(encoder.u8(1))?;
    enc(encoder.bytes(slot.wrap.nonce.as_array()))?;
    enc(encoder.u8(2))?;
    enc(encoder.bytes(slot.wrap.ciphertext.as_array()))?;

    enc(encoder.u8(4))?;
    enc(encoder.i64(slot.created_at))?;
    Ok(())
}

const fn key_slot_kind_id(kind: KeySlotKind) -> u8 {
    match kind {
        KeySlotKind::Password => 1,
    }
}

const fn kdf_algorithm_id(algorithm: KdfAlgorithm) -> u8 {
    match algorithm {
        KdfAlgorithm::Argon2id13 => 1,
    }
}

const fn wrap_algorithm_id(algorithm: WrapAlgorithm) -> u8 {
    match algorithm {
        WrapAlgorithm::XChaCha20Poly1305Ietf => 1,
    }
}

fn strictly_sorted_unique(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn enc<T>(result: Result<T, encode::Error<Infallible>>) -> Result<T, ConfigError> {
    result.map_err(|_| ConfigError::CborEncoding)
}

mod canonical_uuid {
    use std::fmt;

    use serde::de::Visitor;
    use serde::{Deserializer, Serializer};
    use uuid::Uuid;

    pub(super) fn serialize<S>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.hyphenated().to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CanonicalUuidVisitor)
    }

    struct CanonicalUuidVisitor;

    impl Visitor<'_> for CanonicalUuidVisitor {
        type Value = Uuid;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a lowercase hyphenated UUID")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let parsed = Uuid::parse_str(value).map_err(E::custom)?;
            if parsed.hyphenated().to_string() != value {
                return Err(E::custom("UUID is not canonical lowercase hyphenated text"));
            }
            Ok(parsed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(id: u128, ops_limit: u64, mem_limit_bytes: u64) -> KeySlot {
        KeySlot {
            id: Uuid::from_u128(id),
            kind: KeySlotKind::Password,
            kdf: KdfConfig {
                algorithm: KdfAlgorithm::Argon2id13,
                salt: EncodedBytes::new([0x11; 16]),
                ops_limit,
                mem_limit_bytes,
            },
            wrap: WrapConfig {
                algorithm: WrapAlgorithm::XChaCha20Poly1305Ietf,
                nonce: EncodedBytes::new([0x22; 24]),
                ciphertext: EncodedBytes::new([0x33; 48]),
            },
            created_at: 1_783_699_200_000,
        }
    }

    fn config() -> VaultConfig {
        VaultConfig {
            format: VaultFormat::V1,
            vault_id: Uuid::from_u128(0x7b9a_a4d2_7f30_4d42_b57b_7fd4_c155_abcd),
            key_epoch: 0,
            created_at: 1_783_699_200_000,
            required_features: Vec::new(),
            key_slots: vec![slot(
                0x4495_7ed4_7051_45bd_8e4e_39b1_7d09_a3a1,
                MIN_CREATION_OPS_LIMIT,
                MIN_CREATION_MEM_LIMIT_BYTES,
            )],
            features: VaultFeatures::default(),
            metadata_mac: EncodedBytes::new([0x44; 32]),
        }
    }

    #[test]
    fn json_round_trip_is_canonical_base64url() {
        let original = config();
        let json = original.to_json_bytes(KdfPolicy::default()).unwrap();
        let text = std::str::from_utf8(&json).unwrap();
        assert!(!text.contains('='));
        assert!(text.ends_with('\n'));

        let (parsed, warnings) = VaultConfig::parse_untrusted(&json, KdfPolicy::default()).unwrap();
        assert_eq!(parsed, original);
        assert!(warnings.is_empty());
    }

    #[test]
    fn padded_or_wrong_length_base64_is_rejected() {
        let mut value = serde_json::to_value(config()).unwrap();
        value["metadataMac"] = serde_json::Value::String("AA==".to_owned());
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            VaultConfig::parse_untrusted(&bytes, KdfPolicy::default()),
            Err(ConfigError::InvalidJson(_))
        ));
    }

    #[test]
    fn noncanonical_uuid_spellings_are_rejected() {
        let canonical_vault = config().vault_id.hyphenated().to_string();
        let canonical_slot = config().key_slots[0].id.hyphenated().to_string();
        for noncanonical in [
            canonical_vault.to_uppercase(),
            canonical_vault.replace('-', ""),
            format!("{{{canonical_vault}}}"),
            format!("urn:uuid:{canonical_vault}"),
        ] {
            let mut value = serde_json::to_value(config()).unwrap();
            value["vaultId"] = serde_json::Value::String(noncanonical);
            assert!(matches!(
                VaultConfig::parse_untrusted(
                    &serde_json::to_vec(&value).unwrap(),
                    KdfPolicy::default()
                ),
                Err(ConfigError::InvalidJson(_))
            ));
        }
        for noncanonical in [
            canonical_slot.to_uppercase(),
            canonical_slot.replace('-', ""),
            format!("{{{canonical_slot}}}"),
            format!("urn:uuid:{canonical_slot}"),
        ] {
            let mut value = serde_json::to_value(config()).unwrap();
            value["keySlots"][0]["id"] = serde_json::Value::String(noncanonical);
            assert!(matches!(
                VaultConfig::parse_untrusted(
                    &serde_json::to_vec(&value).unwrap(),
                    KdfPolicy::default()
                ),
                Err(ConfigError::InvalidJson(_))
            ));
        }
    }

    #[test]
    fn weak_legacy_kdf_warns_but_creation_rejects() {
        let mut value = config();
        value.key_slots[0].kdf.ops_limit = 2;
        let warnings = value.validate_untrusted(KdfPolicy::default()).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            value.validate_for_creation(KdfPolicy::default()),
            Err(ConfigError::KdfBelowCreationPolicy)
        ));
    }

    #[test]
    fn resource_exhaustion_metadata_is_rejected_before_kdf() {
        let mut value = config();
        value.key_slots[0].kdf.mem_limit_bytes = DEFAULT_MAX_UNLOCK_MEM_LIMIT_BYTES + 1;
        assert!(matches!(
            value.validate_untrusted(KdfPolicy::default()),
            Err(ConfigError::KdfOutsideReaderBounds)
        ));
    }

    #[test]
    fn duplicate_slot_ids_are_rejected() {
        let mut value = config();
        value.key_slots.push(value.key_slots[0].clone());
        assert!(matches!(
            value.validate_untrusted(KdfPolicy::default()),
            Err(ConfigError::InvalidKeySlotId)
        ));
    }

    #[test]
    fn metadata_payload_sorts_slots_by_uuid() {
        let mut left = config();
        left.key_slots.push(slot(
            0x1495_7ed4_7051_45bd_8e4e_39b1_7d09_a3a1,
            MIN_CREATION_OPS_LIMIT,
            MIN_CREATION_MEM_LIMIT_BYTES,
        ));
        let mut right = left.clone();
        right.key_slots.reverse();
        assert_eq!(
            left.metadata_payload().unwrap(),
            right.metadata_payload().unwrap()
        );
    }

    #[test]
    fn wrap_aad_binds_kdf_parameters() {
        let left = config();
        let slot_id = left.key_slots[0].id;
        let mut right = left.clone();
        right.key_slots[0].kdf.ops_limit += 1;
        assert_ne!(
            left.wrap_aad(slot_id).unwrap(),
            right.wrap_aad(slot_id).unwrap()
        );
    }

    #[test]
    fn password_validation_preserves_exact_nonempty_bytes() {
        assert!(validate_password(b"  passphrase  ").is_ok());
        assert!(validate_password("密碼".as_bytes()).is_ok());
        assert!(matches!(
            validate_password(b""),
            Err(ConfigError::InvalidPasswordLength)
        ));
        assert!(matches!(
            validate_password(&vec![b'x'; MAX_PASSWORD_BYTES + 1]),
            Err(ConfigError::InvalidPasswordLength)
        ));
        assert!(matches!(
            validate_password(&[0xff, 0xfe]),
            Err(ConfigError::InvalidPasswordUtf8)
        ));
    }
}
