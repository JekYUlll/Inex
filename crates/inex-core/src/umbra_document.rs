//! Canonical Outer document container and `K_umbra`-encrypted private slots.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::sodium::{self, SodiumError};
use crate::umbra_config::{OuterMode, PrivateAnnotationKind};
use crate::umbra_keyslot::{UmbraKey, UmbraKeyslotError};
use crate::vault_config::EncodedBytes;

const DOCUMENT_FORMAT: &str = "inex-umbra-document";
const SLOT_FORMAT: &str = "inex-private-slot";
const SLOT_KEY_DOMAIN: &[u8] = b"INEX-UMBRA-SLOT-KEY-V1\0";
const SLOT_AAD_DOMAIN: &[u8] = b"INEX-UMBRA-SLOT-AAD-V1\0";

/// The Outer-visible entry for a private slot. It contains no kind, tag, time,
/// backlink, or Markdown data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OuterSlotEntry {
    pub outer: OuterSlotStrategy,
    pub umbra_cipher: UmbraSlotCipher,
}

/// Deliberately public rendering behavior.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OuterSlotStrategy {
    pub mode: OuterMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cover_text: Option<String>,
}

/// One validated private-annotation choice shared by all ranges in a single
/// atomic wrap operation. Tag IDs remain private once copied into slot payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateAnnotationSpec {
    pub kind: PrivateAnnotationKind,
    pub tag_ids: Vec<String>,
    pub outer: OuterSlotStrategy,
}

impl PrivateAnnotationSpec {
    /// Validate the v1 selection before any document mutation begins.
    ///
    /// # Errors
    ///
    /// Returns an error for unsorted/invalid tag IDs or invalid public cover
    /// semantics.
    pub fn validate(&self) -> Result<(), UmbraDocumentError> {
        if !self.tag_ids.windows(2).all(|pair| pair[0] < pair[1])
            || self.tag_ids.iter().any(|id| !valid_tag_id(id))
            || matches!(self.outer.mode, OuterMode::Cover) != self.outer.cover_text.is_some()
            || self.outer.cover_text.as_deref().is_some_and(str::is_empty)
        {
            return Err(UmbraDocumentError::InvalidPrivatePayload);
        }
        Ok(())
    }
}

/// Public AEAD metadata around private slot ciphertext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UmbraSlotCipher {
    pub alg: String,
    pub nonce: EncodedBytes<{ sodium::XCHACHA20_NONCE_BYTES }>,
    pub ciphertext: String,
}

/// Outer-document plaintext held inside the normal EDRY encryption layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UmbraDocumentV1 {
    pub format: String,
    pub version: u32,
    pub outer_markdown: String,
    pub slots: BTreeMap<String, OuterSlotEntry>,
}

/// Decrypted metadata and Markdown for a private slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateSlotPayloadV1 {
    pub format: String,
    pub version: u32,
    pub kind: PrivateAnnotationKind,
    pub tag_ids: Vec<String>,
    pub markdown: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl PrivateSlotPayloadV1 {
    /// Validate the v1 private payload before it enters encryption.
    ///
    /// # Errors
    ///
    /// Returns an error if the version, timestamps, or ordered tag IDs are
    /// invalid.
    pub fn validate(&self) -> Result<(), UmbraDocumentError> {
        if self.format != SLOT_FORMAT
            || self.version != 1
            || self.created_at_ms < 0
            || self.updated_at_ms < self.created_at_ms
        {
            return Err(UmbraDocumentError::InvalidPrivatePayload);
        }
        if !self.tag_ids.windows(2).all(|pair| pair[0] < pair[1])
            || self.tag_ids.iter().any(|id| !valid_tag_id(id))
        {
            return Err(UmbraDocumentError::InvalidPrivatePayload);
        }
        Ok(())
    }
}

impl UmbraDocumentV1 {
    /// Build an empty container around ordinary Outer Markdown.
    #[must_use]
    pub fn new(outer_markdown: String) -> Self {
        Self {
            format: DOCUMENT_FORMAT.to_owned(),
            version: 1,
            outer_markdown,
            slots: BTreeMap::new(),
        }
    }

    /// Encrypt one slot while preserving only its deliberate Outer strategy.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate/invalid slot IDs, invalid private data,
    /// or encryption failure.
    #[allow(clippy::too_many_arguments)] // explicit vault/path/key/slot binding inputs are security-relevant
    pub fn insert_private_slot(
        &mut self,
        vault_id: Uuid,
        logical_path: &str,
        key_id: Uuid,
        key: &UmbraKey,
        slot_id: String,
        outer: OuterSlotStrategy,
        payload: &PrivateSlotPayloadV1,
    ) -> Result<(), UmbraDocumentError> {
        if !valid_slot_id(&slot_id) || self.slots.contains_key(&slot_id) {
            return Err(UmbraDocumentError::InvalidOuterDocument);
        }
        payload.validate()?;
        let cipher = encrypt_slot(
            vault_id,
            logical_path,
            key_id,
            key,
            &slot_id,
            &outer,
            payload,
        )?;
        self.slots.insert(
            slot_id,
            OuterSlotEntry {
                outer,
                umbra_cipher: cipher,
            },
        );
        Ok(())
    }

    /// Decrypt one private slot only in a live Umbra session.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing slot or any vault/path/key/AAD mismatch.
    pub fn decrypt_private_slot(
        &self,
        vault_id: Uuid,
        logical_path: &str,
        key_id: Uuid,
        key: &UmbraKey,
        slot_id: &str,
    ) -> Result<PrivateSlotPayloadV1, UmbraDocumentError> {
        let entry = self
            .slots
            .get(slot_id)
            .ok_or(UmbraDocumentError::SlotNotFound)?;
        decrypt_slot(vault_id, logical_path, key_id, key, slot_id, entry)
    }

    /// Replace one private slot while preserving its stable slot ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the slot is absent, the replacement payload is
    /// invalid, or fresh private-slot encryption fails.
    #[allow(clippy::too_many_arguments)] // explicit vault/path/key/slot binding inputs are security-relevant
    pub fn replace_private_slot(
        &mut self,
        vault_id: Uuid,
        logical_path: &str,
        key_id: Uuid,
        key: &UmbraKey,
        slot_id: &str,
        outer: OuterSlotStrategy,
        payload: &PrivateSlotPayloadV1,
    ) -> Result<(), UmbraDocumentError> {
        if !valid_slot_id(slot_id) || !self.slots.contains_key(slot_id) {
            return Err(UmbraDocumentError::SlotNotFound);
        }
        payload.validate()?;
        let cipher = encrypt_slot(
            vault_id,
            logical_path,
            key_id,
            key,
            slot_id,
            &outer,
            payload,
        )?;
        self.slots.insert(
            slot_id.to_owned(),
            OuterSlotEntry {
                outer,
                umbra_cipher: cipher,
            },
        );
        Ok(())
    }

    /// Remove one complete private slot from this Outer container.
    ///
    /// Callers that unwrap content must decrypt it before removal, then commit
    /// the changed Outer projection atomically through the Vault API.
    ///
    /// # Errors
    ///
    /// Returns [`UmbraDocumentError::SlotNotFound`] for an absent or invalid
    /// stable slot ID.
    pub fn remove_private_slot(&mut self, slot_id: &str) -> Result<(), UmbraDocumentError> {
        if !valid_slot_id(slot_id) || self.slots.remove(slot_id).is_none() {
            return Err(UmbraDocumentError::SlotNotFound);
        }
        Ok(())
    }

    /// Serialize the Outer container. It intentionally has no private payload.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid container or slot identifier.
    pub fn to_json(&self) -> Result<Vec<u8>, UmbraDocumentError> {
        if self.format != DOCUMENT_FORMAT
            || self.version != 1
            || self.slots.keys().any(|id| !valid_slot_id(id))
        {
            return Err(UmbraDocumentError::InvalidOuterDocument);
        }
        serde_json::to_vec(self).map_err(|_| UmbraDocumentError::InvalidOuterDocument)
    }

    /// Parse and validate one complete Outer container without decrypting slots.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported metadata, invalid public slot IDs, or
    /// non-canonical ciphertext encodings.
    pub fn from_json(bytes: &[u8]) -> Result<Self, UmbraDocumentError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| UmbraDocumentError::InvalidOuterDocument)?;
        if value.format != DOCUMENT_FORMAT
            || value.version != 1
            || value.slots.keys().any(|id| !valid_slot_id(id))
        {
            return Err(UmbraDocumentError::InvalidOuterDocument);
        }
        for entry in value.slots.values() {
            if entry.umbra_cipher.alg != "xchacha20-poly1305" {
                return Err(UmbraDocumentError::InvalidOuterDocument);
            }
            let _ = decode_canonical(&entry.umbra_cipher.ciphertext)?;
        }
        Ok(value)
    }
}

fn encrypt_slot(
    vault_id: Uuid,
    logical_path: &str,
    key_id: Uuid,
    key: &UmbraKey,
    slot_id: &str,
    outer: &OuterSlotStrategy,
    payload: &PrivateSlotPayloadV1,
) -> Result<UmbraSlotCipher, UmbraDocumentError> {
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(payload).map_err(|_| UmbraDocumentError::InvalidPrivatePayload)?,
    );
    let nonce = sodium::random_array::<{ sodium::XCHACHA20_NONCE_BYTES }>()?;
    let derived = key.derive_subkey(&slot_key_context(vault_id, logical_path, key_id, slot_id))?;
    let aad = slot_aad(vault_id, logical_path, key_id, slot_id, outer)?;
    let ciphertext = derived
        .with_read(|bytes| sodium::xchacha20poly1305_encrypt(&plaintext, &aad, &nonce, bytes))??;
    plaintext.zeroize();
    Ok(UmbraSlotCipher {
        alg: "xchacha20-poly1305".to_owned(),
        nonce: EncodedBytes::new(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

fn decrypt_slot(
    vault_id: Uuid,
    logical_path: &str,
    key_id: Uuid,
    key: &UmbraKey,
    slot_id: &str,
    entry: &OuterSlotEntry,
) -> Result<PrivateSlotPayloadV1, UmbraDocumentError> {
    if entry.umbra_cipher.alg != "xchacha20-poly1305" {
        return Err(UmbraDocumentError::AuthenticationFailed);
    }
    let ciphertext = decode_canonical(&entry.umbra_cipher.ciphertext)?;
    let derived = key.derive_subkey(&slot_key_context(vault_id, logical_path, key_id, slot_id))?;
    let aad = slot_aad(vault_id, logical_path, key_id, slot_id, &entry.outer)?;
    let plaintext = derived
        .with_read(|bytes| {
            sodium::xchacha20poly1305_decrypt(
                &ciphertext,
                &aad,
                entry.umbra_cipher.nonce.as_array(),
                bytes,
            )
        })?
        .map_err(|_| UmbraDocumentError::AuthenticationFailed)?;
    let mut plaintext = Zeroizing::new(plaintext);
    let payload: PrivateSlotPayloadV1 =
        serde_json::from_slice(&plaintext).map_err(|_| UmbraDocumentError::AuthenticationFailed)?;
    plaintext.zeroize();
    payload
        .validate()
        .map_err(|_| UmbraDocumentError::AuthenticationFailed)?;
    Ok(payload)
}

fn slot_key_context(vault_id: Uuid, path: &str, key_id: Uuid, slot_id: &str) -> Vec<u8> {
    [
        SLOT_KEY_DOMAIN,
        vault_id.as_bytes(),
        path.as_bytes(),
        &[0],
        key_id.as_bytes(),
        slot_id.as_bytes(),
    ]
    .concat()
}
fn slot_aad(
    vault_id: Uuid,
    path: &str,
    key_id: Uuid,
    slot_id: &str,
    outer: &OuterSlotStrategy,
) -> Result<Vec<u8>, UmbraDocumentError> {
    let outer = serde_json::to_vec(outer).map_err(|_| UmbraDocumentError::InvalidOuterDocument)?;
    Ok([
        SLOT_AAD_DOMAIN,
        vault_id.as_bytes(),
        path.as_bytes(),
        &[0],
        key_id.as_bytes(),
        slot_id.as_bytes(),
        &[0],
        outer.as_slice(),
    ]
    .concat())
}
fn valid_slot_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_tag_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}
fn decode_canonical(value: &str) -> Result<Vec<u8>, UmbraDocumentError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| UmbraDocumentError::AuthenticationFailed)?;
    if decoded.len() < sodium::XCHACHA20_TAG_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(UmbraDocumentError::AuthenticationFailed);
    }
    Ok(decoded)
}

/// Slot container errors never include private Markdown or tag metadata.
#[derive(Debug, Error)]
pub enum UmbraDocumentError {
    #[error("invalid Umbra Outer document")]
    InvalidOuterDocument,
    #[error("invalid Umbra private slot payload")]
    InvalidPrivatePayload,
    #[error("Umbra private slot does not exist")]
    SlotNotFound,
    #[error("Umbra private slot authentication failed")]
    AuthenticationFailed,
    #[error("Umbra private slot cryptographic operation failed")]
    Crypto(#[from] SodiumError),
    #[error("Umbra key operation failed")]
    Key(#[from] UmbraKeyslotError),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_slot_canary_is_not_in_outer_container_and_outer_tampering_fails() {
        let key = UmbraKey::random().expect("key");
        let vault = Uuid::from_bytes([1; 16]);
        let key_id = Uuid::from_bytes([2; 16]);
        let mut document = UmbraDocumentV1::new("Public\n{{inex-private-slot:p_01}}\n".to_owned());
        let payload = PrivateSlotPayloadV1 {
            format: SLOT_FORMAT.to_owned(),
            version: 1,
            kind: PrivateAnnotationKind::Comment,
            tag_ids: vec!["secret-tag".to_owned()],
            markdown: "INEX_SECRET_SLOT_CANARY".to_owned(),
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        document
            .insert_private_slot(
                vault,
                "note.md",
                key_id,
                &key,
                "p_01".to_owned(),
                OuterSlotStrategy {
                    mode: OuterMode::Drop,
                    cover_text: None,
                },
                &payload,
            )
            .expect("insert");
        assert!(
            !String::from_utf8_lossy(&document.to_json().expect("outer"))
                .contains("INEX_SECRET_SLOT_CANARY")
        );
        assert_eq!(
            document
                .decrypt_private_slot(vault, "note.md", key_id, &key, "p_01")
                .expect("decrypt"),
            payload
        );
        let encoded = document.to_json().expect("outer encode");
        assert_eq!(
            UmbraDocumentV1::from_json(&encoded).expect("outer decode"),
            document
        );
        document.slots.get_mut("p_01").expect("slot").outer.mode = OuterMode::Placeholder;
        assert!(matches!(
            document.decrypt_private_slot(vault, "note.md", key_id, &key, "p_01"),
            Err(UmbraDocumentError::AuthenticationFailed)
        ));
    }
}
