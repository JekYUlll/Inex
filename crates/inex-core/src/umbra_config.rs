//! Encrypted Umbra tag catalog and annotation-profile configuration.

use std::collections::BTreeSet;

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
        let mut tag_ids = BTreeSet::new();
        for tag in &self.tag_catalog {
            if !valid_id(&tag.id) || tag.label.is_empty() || !tag_ids.insert(&tag.id) {
                return Err(UmbraConfigError::InvalidConfig);
            }
        }
        if !self
            .tag_catalog
            .windows(2)
            .all(|pair| (pair[0].sort_order, &pair[0].id) < (pair[1].sort_order, &pair[1].id))
        {
            return Err(UmbraConfigError::InvalidConfig);
        }
        let mut profile_ids = BTreeSet::new();
        for profile in &self.annotation_profiles {
            if !valid_id(&profile.id)
                || profile.label.is_empty()
                || !valid_tag_list(&profile.tag_ids)
                || !profile.tag_ids.iter().all(|id| tag_ids.contains(id))
                || !profile_ids.insert(&profile.id)
                || matches!(profile.outer, OuterMode::Cover) != profile.prompt_for_cover
            {
                return Err(UmbraConfigError::InvalidConfig);
            }
        }
        if !valid_tag_list(&self.defaults.tag_ids)
            || !self.defaults.tag_ids.iter().all(|id| tag_ids.contains(id))
            || (!self.defaults.default_profile_id.is_empty()
                && !profile_ids.contains(&self.defaults.default_profile_id))
        {
            return Err(UmbraConfigError::InvalidConfig);
        }
        Ok(())
    }

    /// Create a new stable private tag and retain canonical catalog order.
    ///
    /// # Errors
    ///
    /// Returns an invalid-config error for duplicate IDs or invalid fields.
    pub fn create_tag(&mut self, tag: PrivateTagDefinition) -> Result<(), UmbraConfigError> {
        if self
            .tag_catalog
            .iter()
            .any(|existing| existing.id == tag.id)
        {
            return Err(UmbraConfigError::InvalidConfig);
        }
        self.tag_catalog.push(tag);
        self.sort_tags();
        self.validate()
    }

    /// Change only a private tag's display label without changing references.
    ///
    /// # Errors
    ///
    /// Returns an invalid-config error for an absent tag or empty label.
    pub fn rename_tag(&mut self, tag_id: &str, label: String) -> Result<(), UmbraConfigError> {
        if label.is_empty() {
            return Err(UmbraConfigError::InvalidConfig);
        }
        let Some(tag) = self.tag_catalog.iter_mut().find(|tag| tag.id == tag_id) else {
            return Err(UmbraConfigError::InvalidConfig);
        };
        tag.label = label;
        self.validate()
    }

    /// Hide a private tag from default pickers while retaining old references.
    ///
    /// # Errors
    ///
    /// Returns an invalid-config error for an absent tag.
    pub fn archive_tag(&mut self, tag_id: &str) -> Result<(), UmbraConfigError> {
        let Some(tag) = self.tag_catalog.iter_mut().find(|tag| tag.id == tag_id) else {
            return Err(UmbraConfigError::InvalidConfig);
        };
        tag.archived = true;
        self.validate()
    }

    /// Apply an exact complete order to private tag definitions.
    ///
    /// # Errors
    ///
    /// Returns an invalid-config error when IDs are missing, repeated, or
    /// unknown. Stable IDs and existing document references never change.
    pub fn reorder_tags(&mut self, tag_ids: &[String]) -> Result<(), UmbraConfigError> {
        if tag_ids.len() != self.tag_catalog.len()
            || tag_ids.iter().collect::<BTreeSet<_>>().len() != tag_ids.len()
            || !tag_ids
                .iter()
                .all(|id| self.tag_catalog.iter().any(|tag| &tag.id == id))
        {
            return Err(UmbraConfigError::InvalidConfig);
        }
        for (order, id) in tag_ids.iter().enumerate() {
            let Some(tag) = self.tag_catalog.iter_mut().find(|tag| &tag.id == id) else {
                return Err(UmbraConfigError::InvalidConfig);
            };
            tag.sort_order = i32::try_from(order).map_err(|_| UmbraConfigError::InvalidConfig)?;
        }
        self.sort_tags();
        self.validate()
    }

    fn sort_tags(&mut self) {
        self.tag_catalog
            .sort_by(|left, right| (left.sort_order, &left.id).cmp(&(right.sort_order, &right.id)));
    }

    /// Add a reusable encrypted private-annotation profile.
    ///
    /// # Errors
    ///
    /// Returns an invalid-config error for duplicate IDs or invalid tag/cover
    /// references.
    pub fn create_profile(&mut self, profile: AnnotationProfile) -> Result<(), UmbraConfigError> {
        if self
            .annotation_profiles
            .iter()
            .any(|existing| existing.id == profile.id)
        {
            return Err(UmbraConfigError::InvalidConfig);
        }
        self.annotation_profiles.push(profile);
        self.annotation_profiles
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.validate()
    }

    /// Replace one profile while preserving its stable ID.
    ///
    /// # Errors
    ///
    /// Returns an invalid-config error for an absent or mismatched profile ID.
    pub fn edit_profile(
        &mut self,
        profile_id: &str,
        profile: AnnotationProfile,
    ) -> Result<(), UmbraConfigError> {
        if profile.id != profile_id {
            return Err(UmbraConfigError::InvalidConfig);
        }
        let Some(existing) = self
            .annotation_profiles
            .iter_mut()
            .find(|existing| existing.id == profile_id)
        else {
            return Err(UmbraConfigError::InvalidConfig);
        };
        *existing = profile;
        self.validate()
    }

    /// Remove a profile and clear it if it was the encrypted default.
    ///
    /// # Errors
    ///
    /// Returns an invalid-config error for an absent profile.
    pub fn remove_profile(&mut self, profile_id: &str) -> Result<(), UmbraConfigError> {
        let before = self.annotation_profiles.len();
        self.annotation_profiles
            .retain(|profile| profile.id != profile_id);
        if self.annotation_profiles.len() == before {
            return Err(UmbraConfigError::InvalidConfig);
        }
        if self.defaults.default_profile_id == profile_id {
            self.defaults.default_profile_id.clear();
        }
        self.validate()
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

    #[test]
    fn tag_catalog_mutations_preserve_ids_and_validate_references() {
        let mut config = UmbraConfigV1::empty();
        config
            .create_tag(PrivateTagDefinition {
                id: "relationship".to_owned(),
                label: "Relationship".to_owned(),
                description: String::new(),
                aliases: Vec::new(),
                sort_order: 20,
                default_selected: false,
                archived: false,
            })
            .expect("create relationship");
        config
            .create_tag(PrivateTagDefinition {
                id: "family".to_owned(),
                label: "Family".to_owned(),
                description: String::new(),
                aliases: Vec::new(),
                sort_order: 10,
                default_selected: true,
                archived: false,
            })
            .expect("create family");
        assert_eq!(config.tag_catalog[0].id, "family");
        config
            .rename_tag("relationship", "Personal relationships".to_owned())
            .expect("rename without changing stable id");
        config.archive_tag("family").expect("archive tag");
        config
            .reorder_tags(&["relationship".to_owned(), "family".to_owned()])
            .expect("reorder exact catalog");
        assert_eq!(config.tag_catalog[0].id, "relationship");
        assert_eq!(config.tag_catalog[1].id, "family");
        assert!(config.tag_catalog[1].archived);
        assert_eq!(config.tag_catalog[0].label, "Personal relationships");
        assert!(config.create_tag(config.tag_catalog[0].clone()).is_err());
        assert!(config.reorder_tags(&["relationship".to_owned()]).is_err());

        config.defaults.tag_ids = vec!["missing".to_owned()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn annotation_profiles_keep_stable_ids_and_clear_deleted_default() {
        let mut config = UmbraConfigV1::empty();
        config
            .create_tag(PrivateTagDefinition {
                id: "relationship".to_owned(),
                label: "Relationship".to_owned(),
                description: String::new(),
                aliases: Vec::new(),
                sort_order: 0,
                default_selected: false,
                archived: false,
            })
            .expect("create tag");
        let profile = AnnotationProfile {
            id: "relationship-comment".to_owned(),
            label: "Relationship comment".to_owned(),
            kind: PrivateAnnotationKind::Comment,
            tag_ids: vec!["relationship".to_owned()],
            outer: OuterMode::Drop,
            prompt_for_cover: false,
        };
        config
            .create_profile(profile.clone())
            .expect("create profile");
        config.defaults.default_profile_id = profile.id.clone();
        config.validate().expect("default profile is valid");
        let mut edited = profile.clone();
        edited.label = "Relations".to_owned();
        edited.outer = OuterMode::Cover;
        edited.prompt_for_cover = true;
        config
            .edit_profile("relationship-comment", edited)
            .expect("edit stable profile");
        assert_eq!(config.annotation_profiles[0].id, "relationship-comment");
        assert_eq!(config.annotation_profiles[0].label, "Relations");
        config
            .remove_profile("relationship-comment")
            .expect("remove profile");
        assert!(config.defaults.default_profile_id.is_empty());
        assert!(config.annotation_profiles.is_empty());
    }
}
