//! Independent Umbra password-slot lifecycle.
//!
//! The Outer vault password never derives or substitutes for this key.  The
//! module intentionally owns only the wrapped random data key and its public
//! slot metadata; document/config encryption is layered on top of the unlocked
//! [`UmbraKey`].

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::atomic::{
    AtomicWriteError, AtomicWriteOutcome, WriteCondition, atomic_write_ciphertext,
};
use crate::sodium::{
    self, Argon2idLimits, Argon2idParams, LockedBytes, SecureMemoryHealth, SodiumError,
};
use crate::vault_config::{ConfigError, EncodedBytes, validate_password};

/// Sole v1 Umbra password-slot identifier.
pub const UMBRA_DEFAULT_SLOT_ID: &str = "umbra-default";
/// Canonical relative location of the sole v1 Umbra password slot.
pub const UMBRA_DEFAULT_KEYSLOT_PATH: &str = ".inex/keyslots/umbra-default.inex-keyslot";
/// Umbra password-slot format marker.
pub const UMBRA_KEYSLOT_FORMAT: &str = "inex-keyslot";
/// Umbra password-slot schema version.
pub const UMBRA_KEYSLOT_VERSION: u32 = 1;
/// Fixed v1 Argon2id work factors for an Umbra password slot.
pub const UMBRA_KDF_PARAMS: Argon2idParams = Argon2idParams {
    ops_limit: 3,
    mem_limit_bytes: 268_435_456,
};

const UMBRA_WRAP_AAD_DOMAIN: &[u8] = b"INEX-UMBRA-KEYSLOT-V1\0";
const UMBRA_WRAP_CIPHERTEXT_BYTES: usize = sodium::KEY_BYTES + 16;

/// Random Umbra data key, retained only in protected process memory.
pub struct UmbraKey {
    bytes: LockedBytes<{ sodium::KEY_BYTES }>,
}

impl UmbraKey {
    /// Generate a fresh random data key for a new Umbra identity.
    ///
    /// # Errors
    ///
    /// Returns an error if protected allocation or the system CSPRNG fails.
    pub fn random() -> Result<Self, UmbraKeyslotError> {
        Ok(Self {
            bytes: LockedBytes::random()?,
        })
    }

    fn from_plaintext(bytes: &[u8]) -> Result<Self, UmbraKeyslotError> {
        Ok(Self {
            bytes: LockedBytes::from_slice(bytes)?,
        })
    }

    /// Report best-effort operating-system protections for this live key.
    #[must_use]
    pub const fn memory_health(&self) -> SecureMemoryHealth {
        self.bytes.health()
    }

    /// Derive one domain-separated subkey without exposing `K_umbra`.
    pub(crate) fn derive_subkey(
        &self,
        context: &[u8],
    ) -> Result<LockedBytes<{ sodium::KEY_BYTES }>, UmbraKeyslotError> {
        let mut derived = self
            .bytes
            .with_read(|key| sodium::blake2b_256_keyed(key, context))??;
        let protected = LockedBytes::from_slice(&derived)?;
        derived.zeroize();
        Ok(protected)
    }
}

impl fmt::Debug for UmbraKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UmbraKey")
            .field("contents", &"<redacted>")
            .field("health", &self.memory_health())
            .finish()
    }
}

/// Public, password-wrapped representation of the one v1 Umbra data key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UmbraKeyslotV1 {
    format: String,
    version: u32,
    slot_id: String,
    #[serde(with = "canonical_uuid")]
    key_id: Uuid,
    purpose: String,
    kdf: UmbraKdfV1,
    wrap: UmbraWrapV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UmbraKdfV1 {
    name: String,
    salt: EncodedBytes<{ sodium::ARGON2ID_SALT_BYTES }>,
    opslimit: u64,
    memlimit: u64,
    parallelism: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UmbraWrapV1 {
    algorithm: String,
    nonce: EncodedBytes<{ sodium::XCHACHA20_NONCE_BYTES }>,
    ciphertext: EncodedBytes<UMBRA_WRAP_CIPHERTEXT_BYTES>,
}

impl UmbraKeyslotV1 {
    /// Create a new sole v1 slot and its random, protected `K_umbra`.
    ///
    /// The supplied vault ID is authenticated as wrap associated data and is
    /// never written into this public slot file.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid password, KDF failure, or secure-memory
    /// allocation failure.
    pub fn initialize(
        vault_id: Uuid,
        password: &[u8],
    ) -> Result<(Self, UmbraKey), UmbraKeyslotError> {
        validate_password(password)?;
        let key = UmbraKey::random()?;
        let key_id = random_uuid_v4()?;
        let slot = Self::wrap_key(vault_id, password, key_id, &key)?;
        Ok((slot, key))
    }

    /// Decode and validate the canonical public slot representation.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed format error for malformed or unsupported metadata.
    pub fn from_json(bytes: &[u8]) -> Result<Self, UmbraKeyslotError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| UmbraKeyslotError::InvalidSlot)?;
        value.validate()?;
        Ok(value)
    }

    /// Encode the canonical slot JSON. The output contains no plaintext key or
    /// password-derived key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory public slot is invalid.
    pub fn to_json(&self) -> Result<Vec<u8>, UmbraKeyslotError> {
        self.validate()?;
        serde_json::to_vec_pretty(self).map_err(|_| UmbraKeyslotError::InvalidSlot)
    }

    /// Atomically persist this public slot at its sole canonical v1 path.
    ///
    /// The caller must create the validated `.inex/keyslots` directory during
    /// vault initialization; this method never falls back to a non-atomic
    /// write. A replacement password slot uses `IfMatch` with the previous
    /// public-file digest.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed atomic-write error when the target changes or the
    /// vault mutation lock cannot commit the complete replacement.
    pub fn write_atomically(
        &self,
        vault_root: &Path,
        condition: WriteCondition,
    ) -> Result<AtomicWriteOutcome, UmbraKeyslotError> {
        let bytes = self.to_json()?;
        let target = vault_root.join(UMBRA_DEFAULT_KEYSLOT_PATH);
        Ok(atomic_write_ciphertext(
            vault_root, &target, &bytes, condition,
        )?)
    }

    /// Unwrap the data key for an Umbra unlock attempt.
    ///
    /// Authentication failures deliberately do not distinguish a wrong
    /// password from altered public slot metadata.
    ///
    /// # Errors
    ///
    /// Returns [`UmbraKeyslotError::AuthenticationFailed`] if the key cannot
    /// be authenticated with this password and vault identity.
    pub fn unlock(&self, vault_id: Uuid, password: &[u8]) -> Result<UmbraKey, UmbraKeyslotError> {
        self.validate()?;
        validate_password(password)?;
        let kek = sodium::derive_kek_argon2id13(
            password,
            self.kdf.salt.as_array(),
            UMBRA_KDF_PARAMS,
            umbra_kdf_limits(),
        )?;
        let aad = self.wrap_aad(vault_id);
        let plaintext = kek
            .with_read(|kek_bytes| {
                sodium::xchacha20poly1305_decrypt(
                    self.wrap.ciphertext.as_array(),
                    &aad,
                    self.wrap.nonce.as_array(),
                    kek_bytes,
                )
            })?
            .map_err(|_| UmbraKeyslotError::AuthenticationFailed)?;
        if plaintext.len() != sodium::KEY_BYTES {
            return Err(UmbraKeyslotError::AuthenticationFailed);
        }
        UmbraKey::from_plaintext(plaintext.as_slice())
    }

    /// Rewrap an already-unlocked key with a new Umbra password.
    ///
    /// This operation deliberately does not require the old password: a live
    /// session has already authenticated possession of `K_umbra`.
    ///
    /// # Errors
    ///
    /// Returns an error if the new password is invalid or encryption fails.
    pub fn rewrap_unlocked(
        &self,
        vault_id: Uuid,
        new_password: &[u8],
        key: &UmbraKey,
    ) -> Result<Self, UmbraKeyslotError> {
        self.validate()?;
        validate_password(new_password)?;
        Self::wrap_key(vault_id, new_password, self.key_id, key)
    }

    /// Return the public data-key identifier retained for future rotation.
    #[must_use]
    pub const fn key_id(&self) -> Uuid {
        self.key_id
    }

    fn wrap_key(
        vault_id: Uuid,
        password: &[u8],
        key_id: Uuid,
        key: &UmbraKey,
    ) -> Result<Self, UmbraKeyslotError> {
        let salt = sodium::random_array::<{ sodium::ARGON2ID_SALT_BYTES }>()?;
        let nonce = sodium::random_array::<{ sodium::XCHACHA20_NONCE_BYTES }>()?;
        let kdf = UmbraKdfV1 {
            name: "argon2id".to_owned(),
            salt: EncodedBytes::new(salt),
            opslimit: UMBRA_KDF_PARAMS.ops_limit,
            memlimit: UMBRA_KDF_PARAMS.mem_limit_bytes,
            parallelism: 1,
        };
        let mut slot = Self {
            format: UMBRA_KEYSLOT_FORMAT.to_owned(),
            version: UMBRA_KEYSLOT_VERSION,
            slot_id: UMBRA_DEFAULT_SLOT_ID.to_owned(),
            key_id,
            purpose: "umbra".to_owned(),
            kdf,
            wrap: UmbraWrapV1 {
                algorithm: "xchacha20-poly1305".to_owned(),
                nonce: EncodedBytes::new(nonce),
                ciphertext: EncodedBytes::new([0_u8; UMBRA_WRAP_CIPHERTEXT_BYTES]),
            },
        };
        let kek = sodium::derive_kek_argon2id13(
            password,
            slot.kdf.salt.as_array(),
            UMBRA_KDF_PARAMS,
            umbra_kdf_limits(),
        )?;
        let aad = slot.wrap_aad(vault_id);
        let ciphertext = kek.with_read(|kek_bytes| {
            key.bytes.with_read(|key_bytes| {
                sodium::xchacha20poly1305_encrypt(
                    key_bytes,
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
            .map_err(|_| UmbraKeyslotError::InvalidSlot)?;
        ciphertext.zeroize();
        slot.wrap.ciphertext = EncodedBytes::new(array);
        Ok(slot)
    }

    fn validate(&self) -> Result<(), UmbraKeyslotError> {
        if self.format != UMBRA_KEYSLOT_FORMAT
            || self.version != UMBRA_KEYSLOT_VERSION
            || self.slot_id != UMBRA_DEFAULT_SLOT_ID
            || self.purpose != "umbra"
            || self.kdf.name != "argon2id"
            || self.kdf.opslimit != UMBRA_KDF_PARAMS.ops_limit
            || self.kdf.memlimit != UMBRA_KDF_PARAMS.mem_limit_bytes
            || self.kdf.parallelism != 1
            || self.wrap.algorithm != "xchacha20-poly1305"
        {
            return Err(UmbraKeyslotError::InvalidSlot);
        }
        UMBRA_KDF_PARAMS.validate(umbra_kdf_limits())?;
        Ok(())
    }

    fn wrap_aad(&self, vault_id: Uuid) -> Vec<u8> {
        let mut aad = Vec::with_capacity(UMBRA_WRAP_AAD_DOMAIN.len() + 16 + 16 + 64);
        aad.extend_from_slice(UMBRA_WRAP_AAD_DOMAIN);
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(UMBRA_DEFAULT_KEYSLOT_PATH.as_bytes());
        aad.push(0);
        aad.extend_from_slice(self.slot_id.as_bytes());
        aad.push(0);
        aad.extend_from_slice(self.key_id.as_bytes());
        aad.extend_from_slice(&self.version.to_be_bytes());
        aad
    }
}

fn umbra_kdf_limits() -> Argon2idLimits {
    Argon2idLimits {
        min_ops_limit: UMBRA_KDF_PARAMS.ops_limit,
        max_ops_limit: UMBRA_KDF_PARAMS.ops_limit,
        min_mem_limit_bytes: UMBRA_KDF_PARAMS.mem_limit_bytes,
        max_mem_limit_bytes: UMBRA_KDF_PARAMS.mem_limit_bytes,
    }
}

fn random_uuid_v4() -> Result<Uuid, SodiumError> {
    let mut bytes = sodium::random_array::<16>()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

/// Scrubbed Umbra keyslot errors. None include a password, plaintext key, or
/// filesystem path.
#[derive(Debug, Error)]
pub enum UmbraKeyslotError {
    /// The password violates the common vault password contract.
    #[error("invalid Umbra password")]
    InvalidPassword(#[from] ConfigError),
    /// Public slot JSON or fixed v1 metadata is invalid.
    #[error("invalid Umbra password slot")]
    InvalidSlot,
    /// Password, vault identity, or public slot authentication failed.
    #[error("Umbra password slot authentication failed")]
    AuthenticationFailed,
    /// Cryptographic primitive or secure-memory operation failed.
    #[error("Umbra cryptographic operation failed")]
    Sodium(#[from] SodiumError),
    /// Atomic slot persistence failed.
    #[error("Umbra password slot persistence failed")]
    AtomicWrite(#[from] AtomicWriteError),
}

mod canonical_uuid {
    use serde::{Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    pub fn serialize<S>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.hyphenated().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let parsed = Uuid::parse_str(&value).map_err(serde::de::Error::custom)?;
        if parsed.hyphenated().to_string() != value {
            return Err(serde::de::Error::custom("non-canonical UUID"));
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_v1_parameters_and_json_round_trip() {
        assert_eq!(UMBRA_KDF_PARAMS.ops_limit, 3);
        assert_eq!(UMBRA_KDF_PARAMS.mem_limit_bytes, 268_435_456);

        // This test exercises serialization without paying a production 256 MiB
        // Argon2id invocation. Crypto behavior is covered by the integration
        // tests using an injected test-only KDF in the next core milestone.
        let json = br#"{
          "format": "inex-keyslot", "version": 1,
          "slotId": "umbra-default",
          "keyId": "00000000-0000-4000-8000-000000000000",
          "purpose": "umbra",
          "kdf": {"name": "argon2id", "salt": "AAAAAAAAAAAAAAAAAAAAAA", "opslimit": 3, "memlimit": 268435456, "parallelism": 1},
          "wrap": {"algorithm": "xchacha20-poly1305", "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "ciphertext": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        }"#;
        let slot = UmbraKeyslotV1::from_json(json).expect("valid public slot");
        let encoded = slot.to_json().expect("encode public slot");
        assert!(
            std::str::from_utf8(&encoded)
                .expect("utf8")
                .contains("\"memlimit\": 268435456")
        );
    }

    #[test]
    fn rejects_noncanonical_or_non_v1_slot_metadata() {
        let json = br#"{
          "format": "inex-keyslot", "version": 1,
          "slotId": "another-slot",
          "keyId": "00000000-0000-4000-8000-000000000000",
          "purpose": "umbra",
          "kdf": {"name": "argon2id", "salt": "AAAAAAAAAAAAAAAAAAAAAA", "opslimit": 3, "memlimit": 268435456, "parallelism": 1},
          "wrap": {"algorithm": "xchacha20-poly1305", "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "ciphertext": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        }"#;
        assert!(matches!(
            UmbraKeyslotV1::from_json(json),
            Err(UmbraKeyslotError::InvalidSlot)
        ));
    }

    #[test]
    fn real_kdf_unlock_and_live_session_password_reset_preserve_the_key() {
        let vault_id = Uuid::from_bytes([7_u8; 16]);
        let (slot, key) = UmbraKeyslotV1::initialize(vault_id, b"old Umbra password")
            .expect("initialize the independent Umbra key");
        let unlocked = slot
            .unlock(vault_id, b"old Umbra password")
            .expect("unlock with the configured password");
        let replacement = slot
            .rewrap_unlocked(vault_id, b"new Umbra password", &unlocked)
            .expect("reset password from an unlocked session");
        assert_eq!(replacement.key_id(), slot.key_id());
        assert!(matches!(
            replacement.unlock(vault_id, b"old Umbra password"),
            Err(UmbraKeyslotError::AuthenticationFailed)
        ));
        let after_reset = replacement
            .unlock(vault_id, b"new Umbra password")
            .expect("unlock with the replacement password");

        let nonce = [11_u8; sodium::XCHACHA20_NONCE_BYTES];
        let aad = b"test only: compare protected key identity";
        let before = key
            .bytes
            .with_read(|bytes| sodium::xchacha20poly1305_encrypt(b"canary", aad, &nonce, bytes))
            .expect("read protected original key")
            .expect("encrypt with original key");
        let after = after_reset
            .bytes
            .with_read(|bytes| sodium::xchacha20poly1305_encrypt(b"canary", aad, &nonce, bytes))
            .expect("read protected reset key")
            .expect("encrypt with reset key");
        assert_eq!(before, after, "password reset must preserve K_umbra");
        assert!(matches!(
            replacement.unlock(Uuid::from_bytes([8_u8; 16]), b"new Umbra password"),
            Err(UmbraKeyslotError::AuthenticationFailed)
        ));
    }
}
