//! Encrypted Umbra tag catalog and annotation-profile configuration.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::sodium::{self, SodiumError};
use crate::umbra_keyslot::{UmbraKey, UmbraKeyslotError};
use crate::vault_config::EncodedBytes;

/// Canonical encrypted configuration path inside a vault.
pub const UMBRA_CONFIG_PATH: &str = ".inex/config.umbra.inex";
const ENVELOPE_FORMAT: &str = "inex-umbra-config-envelope";
const CONFIG_FORMAT: &str = "inex-umbra-config";
const CONFIG_KEY_DOMAIN: &[u8] = b"INEX-UMBRA-CONFIG-KEY-V1\0";
const CONFIG_AAD_DOMAIN: &[u8] = b"INEX-UMBRA-CONFIG-AAD-V1\0";

/// Private annotation metadata form supported in Umbra v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivateAnnotationKind {
    Block,
    Comment,
}

/// Deliberately public Outer rendering behavior stored with a private slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OuterMode {
    Drop,
    Cover,
    Placeholder,
}

/// User-defined private tag definition. Every field is inside the ciphertext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateTagDefinition {
    pub id: String,
    pub label: String,
    pub description: String,
    pub aliases: Vec<String>,
    pub sort_order: i32,
    pub default_selected: bool,
    pub archived: bool,
}

/// Reusable private annotation choice. Every field is inside the ciphertext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnotationProfile {
    pub id: String,
    pub label: String,
    pub kind: PrivateAnnotationKind,
    pub tag_ids: Vec<String>,
    pub outer: OuterMode,
    pub prompt_for_cover: bool,
}

/// Private defaults retained only in encrypted Umbra configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateAnnotationDefaults {
    pub kind: PrivateAnnotationKind,
    pub tag_ids: Vec<String>,
    pub outer: OuterMode,
    pub default_profile_id: String,
}

/// Decrypted shared tag catalog and profile configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UmbraConfigV1 {
    pub format: String,
    pub version: u32,
    pub tag_catalog: Vec<PrivateTagDefinition>,
    pub annotation_profiles: Vec<AnnotationProfile>,
    pub defaults: PrivateAnnotationDefaults,
}

impl UmbraConfigV1 {
    /// Construct the minimum empty encrypted config.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            format: CONFIG_FORMAT.to_owned(),
            version: 1,
            tag_catalog: Vec::new(),
            annotation_profiles: Vec::new(),
            defaults: PrivateAnnotationDefaults {
                kind: PrivateAnnotationKind::Comment,
                tag_ids: Vec::new(),
                outer: OuterMode::Drop,
                default_profile_id: String::new(),
            },
        }
    }

    fn validate(&self) -> Result<(), UmbraConfigError> {
        if self.format != CONFIG_FORMAT || self.version != 1 {
            return Err(UmbraConfigError::InvalidConfig);
        }
        for tag in &self.tag_catalog {
            if !valid_id(&tag.id) || tag.label.is_empty() {
                return Err(UmbraConfigError::InvalidConfig);
            }
        }
        for profile in &self.annotation_profiles {
            if !valid_id(&profile.id)
                || profile.label.is_empty()
                || !valid_tag_list(&profile.tag_ids)
            {
                return Err(UmbraConfigError::InvalidConfig);
            }
        }
        if !valid_tag_list(&self.defaults.tag_ids) {
            return Err(UmbraConfigError::InvalidConfig);
        }
        Ok(())
    }
}

/// Canonical public envelope around encrypted config bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedUmbraConfigV1 {
    format: String,
    version: u32,
    #[serde(with = "canonical_uuid")]
    key_id: Uuid,
    nonce: EncodedBytes<{ sodium::XCHACHA20_NONCE_BYTES }>,
    ciphertext: String,
}

impl EncryptedUmbraConfigV1 {
    /// Encrypt a config with a domain-separated `K_umbra` subkey.
    ///
    /// # Errors
    ///
    /// Returns an error if the private schema is invalid or encryption fails.
    pub fn encrypt(
        vault_id: Uuid,
        key_id: Uuid,
        key: &UmbraKey,
        config: &UmbraConfigV1,
    ) -> Result<Self, UmbraConfigError> {
        config.validate()?;
        let mut plaintext = Zeroizing::new(
            serde_json::to_vec(config).map_err(|_| UmbraConfigError::InvalidConfig)?,
        );
        let nonce = sodium::random_array::<{ sodium::XCHACHA20_NONCE_BYTES }>()?;
        let derived = key.derive_subkey(&key_context(vault_id, key_id))?;
        let aad = aad(vault_id, key_id);
        let ciphertext = derived.with_read(|bytes| {
            sodium::xchacha20poly1305_encrypt(&plaintext, &aad, &nonce, bytes)
        })??;
        plaintext.zeroize();
        Ok(Self {
            format: ENVELOPE_FORMAT.to_owned(),
            version: 1,
            key_id,
            nonce: EncodedBytes::new(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    /// Decrypt and validate private config. No partial config is returned on
    /// envelope, key-ID, AEAD, or schema failure.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for a wrong key, vault, key ID, or
    /// ciphertext, and never returns partially decoded private metadata.
    pub fn decrypt(
        &self,
        vault_id: Uuid,
        key_id: Uuid,
        key: &UmbraKey,
    ) -> Result<UmbraConfigV1, UmbraConfigError> {
        if self.format != ENVELOPE_FORMAT || self.version != 1 || self.key_id != key_id {
            return Err(UmbraConfigError::AuthenticationFailed);
        }
        let ciphertext = decode_canonical(&self.ciphertext)?;
        let derived = key.derive_subkey(&key_context(vault_id, key_id))?;
        let aad = aad(vault_id, key_id);
        let plaintext = derived
            .with_read(|bytes| {
                sodium::xchacha20poly1305_decrypt(&ciphertext, &aad, self.nonce.as_array(), bytes)
            })?
            .map_err(|_| UmbraConfigError::AuthenticationFailed)?;
        let mut plaintext = Zeroizing::new(plaintext);
        let config: UmbraConfigV1 = serde_json::from_slice(&plaintext)
            .map_err(|_| UmbraConfigError::AuthenticationFailed)?;
        plaintext.zeroize();
        config
            .validate()
            .map_err(|_| UmbraConfigError::AuthenticationFailed)?;
        Ok(config)
    }

    /// Encode public ciphertext metadata only.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is not canonical base64url.
    pub fn to_json(&self) -> Result<Vec<u8>, UmbraConfigError> {
        let _ = decode_canonical(&self.ciphertext)?;
        serde_json::to_vec(self).map_err(|_| UmbraConfigError::InvalidEnvelope)
    }

    /// Parse public envelope metadata without decrypting private configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed public envelope JSON or non-canonical
    /// ciphertext encoding.
    pub fn from_json(bytes: &[u8]) -> Result<Self, UmbraConfigError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| UmbraConfigError::InvalidEnvelope)?;
        if value.format != ENVELOPE_FORMAT || value.version != 1 {
            return Err(UmbraConfigError::InvalidEnvelope);
        }
        let _ = decode_canonical(&value.ciphertext)?;
        Ok(value)
    }
}

fn key_context(vault_id: Uuid, key_id: Uuid) -> Vec<u8> {
    [CONFIG_KEY_DOMAIN, vault_id.as_bytes(), key_id.as_bytes()].concat()
}

fn aad(vault_id: Uuid, key_id: Uuid) -> Vec<u8> {
    [
        CONFIG_AAD_DOMAIN,
        vault_id.as_bytes(),
        UMBRA_CONFIG_PATH.as_bytes(),
        &[0],
        key_id.as_bytes(),
        &1_u32.to_be_bytes(),
    ]
    .concat()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-') && index > 0
        })
}

fn valid_tag_list(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1]) && values.iter().all(|value| valid_id(value))
}

fn decode_canonical(value: &str) -> Result<Vec<u8>, UmbraConfigError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| UmbraConfigError::InvalidEnvelope)?;
    if decoded.len() < sodium::XCHACHA20_TAG_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(UmbraConfigError::InvalidEnvelope);
    }
    Ok(decoded)
}

/// Config encryption errors deliberately carry no private metadata.
#[derive(Debug, Error)]
pub enum UmbraConfigError {
    #[error("invalid Umbra config")]
    InvalidConfig,
    #[error("invalid Umbra config envelope")]
    InvalidEnvelope,
    #[error("Umbra config authentication failed")]
    AuthenticationFailed,
    #[error("Umbra config cryptographic operation failed")]
    Crypto(#[from] SodiumError),
    #[error("Umbra key operation failed")]
    Key(#[from] UmbraKeyslotError),
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
    fn config_canary_stays_inside_authenticated_ciphertext() {
        let key = UmbraKey::random().expect("key");
        let vault_id = Uuid::from_bytes([1_u8; 16]);
        let key_id = Uuid::from_bytes([2_u8; 16]);
        let config = UmbraConfigV1 {
            format: CONFIG_FORMAT.to_owned(),
            version: 1,
            tag_catalog: vec![PrivateTagDefinition {
                id: "secret-tag".to_owned(),
                label: "INEX_SECRET_TAG_CANARY".to_owned(),
                description: String::new(),
                aliases: Vec::new(),
                sort_order: 1,
                default_selected: false,
                archived: false,
            }],
            annotation_profiles: Vec::new(),
            defaults: PrivateAnnotationDefaults {
                kind: PrivateAnnotationKind::Comment,
                tag_ids: vec!["secret-tag".to_owned()],
                outer: OuterMode::Drop,
                default_profile_id: String::new(),
            },
        };
        let envelope =
            EncryptedUmbraConfigV1::encrypt(vault_id, key_id, &key, &config).expect("encrypt");
        let disk = envelope.to_json().expect("encode");
        assert!(!String::from_utf8_lossy(&disk).contains("INEX_SECRET_TAG_CANARY"));
        assert_eq!(
            envelope.decrypt(vault_id, key_id, &key).expect("decrypt"),
            config
        );
        assert!(matches!(
            envelope.decrypt(Uuid::from_bytes([3_u8; 16]), key_id, &key),
            Err(UmbraConfigError::AuthenticationFailed)
        ));
    }
}
