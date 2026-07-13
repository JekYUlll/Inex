//! Deterministic EDRY v1 envelope and header encoding.
//!
//! This module deliberately treats ciphertext as opaque bytes.  It owns the
//! versioned envelope framing, canonical CBOR header, AEAD associated data, and
//! ciphertext etags; encryption and authentication live in the crypto layer.

use minicbor::{Decoder, Encoder, data::Type};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::features::{OPAQUE_ASSETS_V1, is_supported_required_feature};
use crate::path::{AssetPath, LogicalPath};

/// Four-byte EDRY file signature.
pub const EDRY_MAGIC: [u8; 4] = *b"EDRY";
/// EDRY format major version implemented by this module.
pub const EDRY_FORMAT_MAJOR: u8 = 1;
/// EDRY format minor version implemented by this module.
pub const EDRY_FORMAT_MINOR: u8 = 0;
/// Fixed envelope flags for EDRY v1.
pub const EDRY_FIXED_FLAGS: u16 = 0;
/// Size of the fixed envelope prefix in bytes.
pub const EDRY_PREFIX_LEN: usize = 12;
/// Number of entries in the EDRY v1 CBOR header map.
pub const EDRY_HEADER_FIELD_COUNT: u64 = 13;
const EDRY_HEADER_FIELD_COUNT_USIZE: usize = 13;
/// Maximum accepted canonical header size.
pub const MAX_HEADER_LEN: usize = 4_096;
/// Maximum Markdown plaintext size in v1.
pub const MAX_DOCUMENT_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;
/// Backward-compatible name for the Markdown plaintext ceiling.
pub const MAX_PLAINTEXT_LEN: usize = MAX_DOCUMENT_PLAINTEXT_LEN;
/// Maximum opaque-asset plaintext size under required feature 1.
pub const MAX_ASSET_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;
/// XChaCha20-Poly1305 authentication tag size.
pub const AEAD_TAG_LEN: usize = 16;
/// Maximum accepted Markdown ciphertext size.
pub const MAX_DOCUMENT_CIPHERTEXT_LEN: usize = MAX_DOCUMENT_PLAINTEXT_LEN + AEAD_TAG_LEN;
/// Backward-compatible name for the Markdown ciphertext ceiling.
pub const MAX_CIPHERTEXT_LEN: usize = MAX_DOCUMENT_CIPHERTEXT_LEN;
/// Maximum accepted opaque-asset ciphertext size.
pub const MAX_ASSET_CIPHERTEXT_LEN: usize = MAX_ASSET_PLAINTEXT_LEN + AEAD_TAG_LEN;
/// Exact upper bound for a complete Markdown EDRY envelope.
pub const MAX_DOCUMENT_ENVELOPE_BYTES: usize =
    EDRY_PREFIX_LEN + MAX_HEADER_LEN + MAX_DOCUMENT_CIPHERTEXT_LEN;
/// Exact upper bound for a complete opaque-asset EDRY envelope.
pub const MAX_ASSET_ENVELOPE_BYTES: usize =
    EDRY_PREFIX_LEN + MAX_HEADER_LEN + MAX_ASSET_CIPHERTEXT_LEN;
/// Domain separator prepended to EDRY v1 AEAD associated data.
pub const EDRY_AAD_DOMAIN: &[u8] = b"INEX-EDRY-FILE\0";
/// Prefix used by externally visible ciphertext etags.
pub const ETAG_PREFIX: &str = "sha256:";

const KNOWN_CONTENT_FLAG_BITS: u32 =
    ContentFlags::UNRESOLVED_MERGE.bits() | ContentFlags::DRAFT.bits();

/// File-key derivation algorithm recorded in an EDRY header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u64)]
pub enum FileKeyDerivation {
    /// Keyed BLAKE2b-256 with the EDRY v1 domain-separated input.
    Blake2b256V1 = 1,
}

impl FileKeyDerivation {
    /// Numeric identifier serialized in the EDRY header.
    #[must_use]
    pub const fn id(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for FileKeyDerivation {
    type Error = FormatError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Blake2b256V1),
            id => Err(FormatError::UnsupportedFileKeyDerivation(id)),
        }
    }
}

/// Authenticated encryption algorithm recorded in an EDRY header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u64)]
pub enum CipherSuite {
    /// libsodium XChaCha20-Poly1305-IETF.
    XChaCha20Poly1305Ietf = 1,
}

impl CipherSuite {
    /// Numeric identifier serialized in the EDRY header.
    #[must_use]
    pub const fn id(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for CipherSuite {
    type Error = FormatError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305Ietf),
            id => Err(FormatError::UnsupportedCipher(id)),
        }
    }
}

/// Plaintext interpretation recorded in an EDRY header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u64)]
pub enum PlaintextKind {
    /// Exact UTF-8 Markdown bytes, without newline normalization.
    Utf8Markdown = 1,
    /// Exact opaque asset bytes without UTF-8 interpretation.
    OpaqueAsset = 2,
}

impl PlaintextKind {
    /// Numeric identifier serialized in the EDRY header.
    #[must_use]
    pub const fn id(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for PlaintextKind {
    type Error = FormatError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Utf8Markdown),
            2 => Ok(Self::OpaqueAsset),
            id => Err(FormatError::UnsupportedPlaintextKind(id)),
        }
    }
}

/// Authenticated EDRY content flags.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ContentFlags(u32);

impl ContentFlags {
    /// No authenticated content flags.
    pub const NONE: Self = Self(0);
    /// The decrypted Markdown contains unresolved merge markers.
    pub const UNRESOLVED_MERGE: Self = Self(1 << 0);
    /// The envelope is an unsaved encrypted editor draft.
    pub const DRAFT: Self = Self(1 << 1);

    /// Construct flags from their serialized bits, rejecting unknown bits.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::UnsupportedContentFlags`] when `bits` contains a
    /// flag not defined by EDRY v1.
    pub fn from_bits(bits: u32) -> Result<Self, FormatError> {
        if bits & !KNOWN_CONTENT_FLAG_BITS != 0 {
            return Err(FormatError::UnsupportedContentFlags(bits));
        }
        Ok(Self(bits))
    }

    /// Return the serialized bitset.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Return whether all bits in `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Return whether no bits are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for ContentFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ContentFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Complete semantic EDRY v1 header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdryHeader {
    /// Vault UUID whose master key encrypts this file.
    pub vault_id: Uuid,
    /// Stable random UUID for this logical file.
    pub file_id: Uuid,
    /// Canonical logical document or asset path, excluding its physical suffix.
    pub logical_path: String,
    /// Master-key epoch used for file-key derivation.
    pub key_epoch: u32,
    /// File-key derivation algorithm.
    pub key_derivation: FileKeyDerivation,
    /// Authenticated encryption algorithm.
    pub cipher: CipherSuite,
    /// Fresh XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],
    /// Interpretation of decrypted bytes.
    pub plaintext_kind: PlaintextKind,
    /// Creation time as signed Unix milliseconds.
    pub created_at_ms: i64,
    /// Last modification time as signed Unix milliseconds.
    pub modified_at_ms: i64,
    /// Authenticated content flags.
    pub content_flags: ContentFlags,
    /// Sorted required feature identifiers.
    pub required_features: Vec<u32>,
    /// Raw base ciphertext SHA-256 for a draft, or `None` for a new draft.
    pub base_etag: Option<[u8; 32]>,
}

impl EdryHeader {
    /// Validate all EDRY v1 header invariants independent of authentication.
    ///
    /// # Errors
    ///
    /// Returns a [`FormatError`] when the logical path, content flags,
    /// required features, or draft/base-etag relationship is invalid.
    pub fn validate(&self) -> Result<(), FormatError> {
        if self.vault_id.is_nil() {
            return Err(FormatError::NilVaultId);
        }
        if self.file_id.is_nil() {
            return Err(FormatError::NilFileId);
        }
        if self.created_at_ms < 0 {
            return Err(FormatError::NegativeCreationTime(self.created_at_ms));
        }
        if self.modified_at_ms < self.created_at_ms {
            return Err(FormatError::ModificationBeforeCreation {
                created_at_ms: self.created_at_ms,
                modified_at_ms: self.modified_at_ms,
            });
        }

        ContentFlags::from_bits(self.content_flags.bits())?;

        if !strictly_increasing(&self.required_features) {
            return Err(FormatError::RequiredFeaturesNotStrictlyIncreasing);
        }
        for feature in &self.required_features {
            if !is_supported_required_feature(*feature) {
                return Err(FormatError::UnknownRequiredFeature(*feature));
            }
        }

        match self.plaintext_kind {
            PlaintextKind::Utf8Markdown => {
                LogicalPath::parse_canonical(&self.logical_path).map_err(|error| {
                    FormatError::InvalidLogicalPath {
                        reason: error.to_string(),
                    }
                })?;
                if !self.required_features.is_empty() {
                    return Err(FormatError::PlaintextProfileMismatch);
                }
            }
            PlaintextKind::OpaqueAsset => {
                AssetPath::parse_canonical(&self.logical_path).map_err(|error| {
                    FormatError::InvalidLogicalPath {
                        reason: error.to_string(),
                    }
                })?;
                if self.required_features.as_slice() != [OPAQUE_ASSETS_V1]
                    || !self.content_flags.is_empty()
                    || self.base_etag.is_some()
                {
                    return Err(FormatError::PlaintextProfileMismatch);
                }
            }
        }

        if !self.is_draft() && self.base_etag.is_some() {
            return Err(FormatError::CommittedFileHasBaseEtag);
        }

        Ok(())
    }

    /// Return whether this is an unsaved encrypted editor draft.
    #[must_use]
    pub const fn is_draft(&self) -> bool {
        self.content_flags.contains(ContentFlags::DRAFT)
    }

    /// Return whether the content has unresolved merge markers.
    #[must_use]
    pub const fn has_unresolved_merge(&self) -> bool {
        self.content_flags.contains(ContentFlags::UNRESOLVED_MERGE)
    }
}

/// Validated views into an EDRY envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeParts<'a> {
    /// Exact fixed prefix authenticated as AEAD associated data.
    pub prefix: [u8; EDRY_PREFIX_LEN],
    /// Exact canonical CBOR header authenticated as AEAD associated data.
    pub header_bytes: &'a [u8],
    /// Decoded semantic header.
    pub header: EdryHeader,
    /// Opaque ciphertext and authentication tag.
    pub ciphertext: &'a [u8],
}

impl EnvelopeParts<'_> {
    /// Construct the exact AEAD associated data for these validated parts.
    ///
    /// # Errors
    ///
    /// Returns a [`FormatError`] if the retained prefix and header no longer
    /// form a valid canonical EDRY v1 pair.
    pub fn associated_data(&self) -> Result<Vec<u8>, FormatError> {
        associated_data(&self.prefix, self.header_bytes)
    }
}

/// EDRY framing, deterministic-encoding, or semantic validation error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FormatError {
    /// Envelope has fewer bytes than the fixed prefix.
    #[error("EDRY envelope is too short: got {actual} bytes, need at least {minimum}")]
    EnvelopeTooShort { actual: usize, minimum: usize },

    /// Prefix signature is not `EDRY`.
    #[error("invalid EDRY magic {actual:02x?}")]
    InvalidMagic { actual: [u8; 4] },

    /// Prefix carries a format version this implementation cannot interpret.
    #[error("unsupported EDRY version {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },

    /// Fixed prefix flags are nonzero in v1.
    #[error("unsupported EDRY fixed flags 0x{0:04x}")]
    UnsupportedFixedFlags(u16),

    /// Declared or encoded header size is outside the v1 bound.
    #[error("EDRY header length {actual} is outside 1..={maximum}")]
    HeaderLengthOutOfRange { actual: usize, maximum: usize },

    /// Prefix declares more header bytes than are present.
    #[error(
        "truncated EDRY header: prefix declares {declared} bytes, only {available} are available"
    )]
    TruncatedHeader { declared: usize, available: usize },

    /// Opaque ciphertext length is outside the v1 bound.
    #[error("EDRY ciphertext length {actual} is outside {minimum}..={maximum}")]
    CiphertextLengthOutOfRange {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },

    /// Header length cannot be represented in the four-byte prefix field.
    #[error("EDRY header length {0} does not fit in u32")]
    HeaderLengthOverflow(usize),

    /// A supplied prefix's declared header length does not match the bytes.
    #[error("EDRY prefix declares {declared} header bytes but associated data supplied {actual}")]
    PrefixHeaderLengthMismatch { declared: usize, actual: usize },

    /// Envelope allocation length overflowed `usize`.
    #[error("EDRY envelope length overflow")]
    EnvelopeLengthOverflow,

    /// Header root is an indefinite-length CBOR map.
    #[error("EDRY header map must have a definite length")]
    IndefiniteHeaderMap,

    /// Header root map does not have all and only v1 fields.
    #[error("EDRY header map has {actual} entries; expected {expected}")]
    HeaderMapLength { actual: u64, expected: u64 },

    /// A map key is outside the frozen v1 schema.
    #[error("unknown EDRY header key {0}")]
    UnknownHeaderKey(u64),

    /// A map key occurs more than once.
    #[error("duplicate EDRY header key {0}")]
    DuplicateHeaderKey(u64),

    /// Header keys are not in deterministic ascending order.
    #[error("EDRY header key {found} is out of order; expected key {expected}")]
    HeaderKeyOutOfOrder { expected: u64, found: u64 },

    /// A CBOR item is malformed, truncated, out of range, or has the wrong type.
    #[error("invalid CBOR for EDRY header {field} at byte {offset}: {message}")]
    CborDecode {
        field: &'static str,
        offset: usize,
        message: String,
    },

    /// Encoding failed even though the in-memory writer is expected to be infallible.
    #[error("failed to encode EDRY header CBOR: {0}")]
    CborEncode(String),

    /// A fixed-size byte-string field has the wrong length.
    #[error("EDRY header {field} has {actual} bytes; expected {expected}")]
    InvalidFieldLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },

    /// Vault UUID is nil instead of a real random identity.
    #[error("EDRY vault UUID must not be nil")]
    NilVaultId,

    /// File UUID is nil instead of a real random identity.
    #[error("EDRY file UUID must not be nil")]
    NilFileId,

    /// Creation timestamp predates the Unix epoch.
    #[error("EDRY creation time must be nonnegative, got {0}")]
    NegativeCreationTime(i64),

    /// Modification timestamp precedes creation.
    #[error("EDRY modification time {modified_at_ms} precedes creation time {created_at_ms}")]
    ModificationBeforeCreation {
        created_at_ms: i64,
        modified_at_ms: i64,
    },

    /// Required feature array is indefinite-length.
    #[error("EDRY required feature array must have a definite length")]
    IndefiniteRequiredFeatures,

    /// Declared feature count is too large to process safely.
    #[error("EDRY required feature count {actual} exceeds {maximum}")]
    RequiredFeatureCountOutOfRange { actual: u64, maximum: usize },

    /// Required feature identifiers are not unique ascending values.
    #[error("EDRY required features must be strictly increasing")]
    RequiredFeaturesNotStrictlyIncreasing,

    /// A required-feature identifier is unknown to this implementation.
    #[error("unsupported required EDRY feature {0}")]
    UnknownRequiredFeature(u32),

    /// Kind, path, feature, flags, or draft state do not form one valid profile.
    #[error("EDRY plaintext kind does not match its path, features, flags, or draft state")]
    PlaintextProfileMismatch,

    /// File-key derivation identifier is unknown in v1.
    #[error("unsupported EDRY file-key derivation id {0}")]
    UnsupportedFileKeyDerivation(u64),

    /// Cipher identifier is unknown in v1.
    #[error("unsupported EDRY cipher id {0}")]
    UnsupportedCipher(u64),

    /// Plaintext-kind identifier is unknown in v1.
    #[error("unsupported EDRY plaintext kind id {0}")]
    UnsupportedPlaintextKind(u64),

    /// Content flag bitset contains bits not defined by v1.
    #[error("unsupported EDRY content flags 0x{0:08x}")]
    UnsupportedContentFlags(u32),

    /// A committed envelope carries a draft-only base etag.
    #[error("committed EDRY file must have a null base etag")]
    CommittedFileHasBaseEtag,

    /// Logical path is not canonical under the frozen cross-platform profile.
    #[error("invalid EDRY logical path: {reason}")]
    InvalidLogicalPath { reason: String },

    /// Bytes remain after the one header map item.
    #[error("EDRY header has {trailing} trailing bytes")]
    HeaderTrailingData { trailing: usize },

    /// Header semantics decode, but the original bytes are not RFC 8949 deterministic form.
    #[error("EDRY header is not deterministically encoded")]
    NonCanonicalHeader,
}

/// Encode a validated EDRY header using RFC 8949 deterministic CBOR.
///
/// # Errors
///
/// Returns a [`FormatError`] if a semantic header invariant fails or the
/// encoded header exceeds the v1 length bound.
pub fn encode_header(header: &EdryHeader) -> Result<Vec<u8>, FormatError> {
    header.validate()?;
    let bytes = encode_header_unchecked(header)?;
    validate_header_length(bytes.len())?;
    Ok(bytes)
}

/// Decode and validate an exact deterministic EDRY header byte string.
///
/// # Errors
///
/// Returns a [`FormatError`] for malformed, noncanonical, oversized, unknown,
/// unsupported, or semantically invalid header data.
pub fn decode_header(bytes: &[u8]) -> Result<EdryHeader, FormatError> {
    validate_header_length(bytes.len())?;

    let mut decoder = Decoder::new(bytes);
    let map_len = decoder
        .map()
        .map_err(|error| cbor_decode_error("map", &decoder, &error))?
        .ok_or(FormatError::IndefiniteHeaderMap)?;
    if map_len != EDRY_HEADER_FIELD_COUNT {
        return Err(FormatError::HeaderMapLength {
            actual: map_len,
            expected: EDRY_HEADER_FIELD_COUNT,
        });
    }

    let mut seen = [false; EDRY_HEADER_FIELD_COUNT_USIZE];

    read_expected_key(&mut decoder, 0, &mut seen)?;
    let vault_id = decode_uuid(&mut decoder, "key 0 (vault UUID)")?;

    read_expected_key(&mut decoder, 1, &mut seen)?;
    let file_id = decode_uuid(&mut decoder, "key 1 (file UUID)")?;

    read_expected_key(&mut decoder, 2, &mut seen)?;
    let logical_path = decoder
        .str()
        .map_err(|error| cbor_decode_error("key 2 (logical path)", &decoder, &error))?
        .to_owned();

    read_expected_key(&mut decoder, 3, &mut seen)?;
    let key_epoch = decoder
        .u32()
        .map_err(|error| cbor_decode_error("key 3 (key epoch)", &decoder, &error))?;

    read_expected_key(&mut decoder, 4, &mut seen)?;
    let key_derivation =
        FileKeyDerivation::try_from(decoder.u64().map_err(|error| {
            cbor_decode_error("key 4 (file-key derivation)", &decoder, &error)
        })?)?;

    read_expected_key(&mut decoder, 5, &mut seen)?;
    let cipher = CipherSuite::try_from(
        decoder
            .u64()
            .map_err(|error| cbor_decode_error("key 5 (cipher)", &decoder, &error))?,
    )?;

    read_expected_key(&mut decoder, 6, &mut seen)?;
    let nonce = decode_fixed_bytes::<24>(&mut decoder, "key 6 (nonce)")?;

    read_expected_key(&mut decoder, 7, &mut seen)?;
    let plaintext_kind = PlaintextKind::try_from(
        decoder
            .u64()
            .map_err(|error| cbor_decode_error("key 7 (plaintext kind)", &decoder, &error))?,
    )?;

    read_expected_key(&mut decoder, 8, &mut seen)?;
    let created_at_ms = decoder
        .i64()
        .map_err(|error| cbor_decode_error("key 8 (creation time)", &decoder, &error))?;

    read_expected_key(&mut decoder, 9, &mut seen)?;
    let modified_at_ms = decoder
        .i64()
        .map_err(|error| cbor_decode_error("key 9 (modification time)", &decoder, &error))?;

    read_expected_key(&mut decoder, 10, &mut seen)?;
    let content_flag_bits = decoder
        .u32()
        .map_err(|error| cbor_decode_error("key 10 (content flags)", &decoder, &error))?;
    let content_flags = ContentFlags::from_bits(content_flag_bits)?;

    read_expected_key(&mut decoder, 11, &mut seen)?;
    let required_features = decode_required_features(&mut decoder)?;

    read_expected_key(&mut decoder, 12, &mut seen)?;
    let base_etag = decode_optional_etag(&mut decoder)?;

    if decoder.position() != bytes.len() {
        return Err(FormatError::HeaderTrailingData {
            trailing: bytes.len() - decoder.position(),
        });
    }

    let header = EdryHeader {
        vault_id,
        file_id,
        logical_path,
        key_epoch,
        key_derivation,
        cipher,
        nonce,
        plaintext_kind,
        created_at_ms,
        modified_at_ms,
        content_flags,
        required_features,
        base_etag,
    };
    header.validate()?;

    let canonical = encode_header_unchecked(&header)?;
    if canonical != bytes {
        return Err(FormatError::NonCanonicalHeader);
    }

    Ok(header)
}

/// Build the fixed 12-byte EDRY prefix for a canonical header length.
///
/// # Errors
///
/// Returns [`FormatError::HeaderLengthOutOfRange`] when `header_len` is zero
/// or exceeds the v1 maximum.
pub fn build_prefix(header_len: usize) -> Result<[u8; EDRY_PREFIX_LEN], FormatError> {
    validate_header_length(header_len)?;
    let header_len_u32 =
        u32::try_from(header_len).map_err(|_| FormatError::HeaderLengthOverflow(header_len))?;

    let mut prefix = [0_u8; EDRY_PREFIX_LEN];
    prefix[0..4].copy_from_slice(&EDRY_MAGIC);
    prefix[4] = EDRY_FORMAT_MAJOR;
    prefix[5] = EDRY_FORMAT_MINOR;
    prefix[6..8].copy_from_slice(&EDRY_FIXED_FLAGS.to_be_bytes());
    prefix[8..12].copy_from_slice(&header_len_u32.to_be_bytes());
    Ok(prefix)
}

/// Validate an EDRY prefix and return its declared header length.
///
/// # Errors
///
/// Returns a [`FormatError`] for a bad signature, unsupported version or
/// fixed flags, or a declared header length outside the v1 bound.
pub fn parse_prefix(prefix: &[u8; EDRY_PREFIX_LEN]) -> Result<usize, FormatError> {
    let mut magic = [0_u8; 4];
    magic.copy_from_slice(&prefix[0..4]);
    if magic != EDRY_MAGIC {
        return Err(FormatError::InvalidMagic { actual: magic });
    }

    let major = prefix[4];
    let minor = prefix[5];
    if major != EDRY_FORMAT_MAJOR || minor != EDRY_FORMAT_MINOR {
        return Err(FormatError::UnsupportedVersion { major, minor });
    }

    let fixed_flags = u16::from_be_bytes([prefix[6], prefix[7]]);
    if fixed_flags != EDRY_FIXED_FLAGS {
        return Err(FormatError::UnsupportedFixedFlags(fixed_flags));
    }

    let header_len = u32::from_be_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]) as usize;
    validate_header_length(header_len)?;
    Ok(header_len)
}

/// Construct exact AEAD associated data from an exact prefix and header.
///
/// # Errors
///
/// Returns a [`FormatError`] when the prefix is invalid, its length disagrees
/// with `header_bytes`, or the supplied header is not canonical and valid.
pub fn associated_data(
    prefix: &[u8; EDRY_PREFIX_LEN],
    header_bytes: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let declared = parse_prefix(prefix)?;
    if declared != header_bytes.len() {
        return Err(FormatError::PrefixHeaderLengthMismatch {
            declared,
            actual: header_bytes.len(),
        });
    }
    // Keep the raw composition API fail-closed: callers cannot accidentally
    // authenticate a noncanonical or semantically invalid header.
    let _ = decode_header(header_bytes)?;

    let capacity = EDRY_AAD_DOMAIN
        .len()
        .checked_add(EDRY_PREFIX_LEN)
        .and_then(|length| length.checked_add(header_bytes.len()))
        .ok_or(FormatError::EnvelopeLengthOverflow)?;
    let mut aad = Vec::with_capacity(capacity);
    aad.extend_from_slice(EDRY_AAD_DOMAIN);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(header_bytes);
    Ok(aad)
}

/// Encode a header and construct its complete AEAD associated data.
///
/// # Errors
///
/// Returns a [`FormatError`] when the header cannot be validated or encoded.
pub fn associated_data_for_header(header: &EdryHeader) -> Result<Vec<u8>, FormatError> {
    let header_bytes = encode_header(header)?;
    let prefix = build_prefix(header_bytes.len())?;
    associated_data(&prefix, &header_bytes)
}

/// Assemble a complete EDRY envelope around opaque ciphertext bytes.
///
/// # Errors
///
/// Returns a [`FormatError`] when the header is invalid, the ciphertext size
/// is outside the v1 bound, or the resulting length overflows.
pub fn build_envelope(header: &EdryHeader, ciphertext: &[u8]) -> Result<Vec<u8>, FormatError> {
    let header_bytes = encode_header(header)?;
    validate_ciphertext_length(ciphertext.len(), header.plaintext_kind)?;
    let prefix = build_prefix(header_bytes.len())?;
    let capacity = EDRY_PREFIX_LEN
        .checked_add(header_bytes.len())
        .and_then(|length| length.checked_add(ciphertext.len()))
        .ok_or(FormatError::EnvelopeLengthOverflow)?;

    let mut envelope = Vec::with_capacity(capacity);
    envelope.extend_from_slice(&prefix);
    envelope.extend_from_slice(&header_bytes);
    envelope.extend_from_slice(ciphertext);
    Ok(envelope)
}

/// Split and validate EDRY framing/header while leaving crypto bytes opaque.
///
/// # Errors
///
/// Returns a [`FormatError`] for invalid/truncated framing, ciphertext outside
/// the v1 size bound, or malformed/noncanonical header bytes.
pub fn split_envelope(envelope: &[u8]) -> Result<EnvelopeParts<'_>, FormatError> {
    if envelope.len() < EDRY_PREFIX_LEN {
        return Err(FormatError::EnvelopeTooShort {
            actual: envelope.len(),
            minimum: EDRY_PREFIX_LEN,
        });
    }

    let mut prefix = [0_u8; EDRY_PREFIX_LEN];
    prefix.copy_from_slice(&envelope[..EDRY_PREFIX_LEN]);
    let header_len = parse_prefix(&prefix)?;
    let header_end = EDRY_PREFIX_LEN
        .checked_add(header_len)
        .ok_or(FormatError::EnvelopeLengthOverflow)?;
    if envelope.len() < header_end {
        return Err(FormatError::TruncatedHeader {
            declared: header_len,
            available: envelope.len() - EDRY_PREFIX_LEN,
        });
    }

    let header_bytes = &envelope[EDRY_PREFIX_LEN..header_end];
    let header = decode_header(header_bytes)?;
    let ciphertext = &envelope[header_end..];
    validate_ciphertext_length(ciphertext.len(), header.plaintext_kind)?;

    Ok(EnvelopeParts {
        prefix,
        header_bytes,
        header,
        ciphertext,
    })
}

/// Raw SHA-256 digest of a complete EDRY envelope.
#[must_use]
pub fn etag_digest(envelope: &[u8]) -> [u8; 32] {
    Sha256::digest(envelope).into()
}

/// `sha256:<lowercase-hex>` etag of a complete EDRY envelope.
#[must_use]
pub fn etag(envelope: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = etag_digest(envelope);
    let mut result = String::with_capacity(ETAG_PREFIX.len() + digest.len() * 2);
    result.push_str(ETAG_PREFIX);
    for byte in digest {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn encode_header_unchecked(header: &EdryHeader) -> Result<Vec<u8>, FormatError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(EDRY_HEADER_FIELD_COUNT)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.bytes(header.vault_id.as_bytes()))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(header.file_id.as_bytes()))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.str(&header.logical_path))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.u32(header.key_epoch))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.u64(header.key_derivation.id()))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u64(header.cipher.id()))
        .and_then(|encoder| encoder.u8(6))
        .and_then(|encoder| encoder.bytes(&header.nonce))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.u64(header.plaintext_kind.id()))
        .and_then(|encoder| encoder.u8(8))
        .and_then(|encoder| encoder.i64(header.created_at_ms))
        .and_then(|encoder| encoder.u8(9))
        .and_then(|encoder| encoder.i64(header.modified_at_ms))
        .and_then(|encoder| encoder.u8(10))
        .and_then(|encoder| encoder.u32(header.content_flags.bits()))
        .and_then(|encoder| encoder.u8(11))
        .and_then(|encoder| encoder.array(header.required_features.len() as u64))
        .map_err(|error| FormatError::CborEncode(error.to_string()))?;

    for feature in &header.required_features {
        encoder
            .u32(*feature)
            .map_err(|error| FormatError::CborEncode(error.to_string()))?;
    }

    encoder
        .u8(12)
        .map_err(|error| FormatError::CborEncode(error.to_string()))?;
    if let Some(base_etag) = header.base_etag {
        encoder
            .bytes(&base_etag)
            .map_err(|error| FormatError::CborEncode(error.to_string()))?;
    } else {
        encoder
            .null()
            .map_err(|error| FormatError::CborEncode(error.to_string()))?;
    }

    Ok(encoder.into_writer())
}

fn decode_uuid(decoder: &mut Decoder<'_>, field: &'static str) -> Result<Uuid, FormatError> {
    let bytes = decoder
        .bytes()
        .map_err(|error| cbor_decode_error(field, decoder, &error))?;
    if bytes.len() != 16 {
        return Err(FormatError::InvalidFieldLength {
            field,
            actual: bytes.len(),
            expected: 16,
        });
    }
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(bytes);
    Ok(Uuid::from_bytes(raw))
}

fn decode_fixed_bytes<const N: usize>(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<[u8; N], FormatError> {
    let bytes = decoder
        .bytes()
        .map_err(|error| cbor_decode_error(field, decoder, &error))?;
    if bytes.len() != N {
        return Err(FormatError::InvalidFieldLength {
            field,
            actual: bytes.len(),
            expected: N,
        });
    }
    let mut result = [0_u8; N];
    result.copy_from_slice(bytes);
    Ok(result)
}

fn decode_required_features(decoder: &mut Decoder<'_>) -> Result<Vec<u32>, FormatError> {
    let count = decoder
        .array()
        .map_err(|error| cbor_decode_error("key 11 (required features)", decoder, &error))?
        .ok_or(FormatError::IndefiniteRequiredFeatures)?;
    if count > MAX_HEADER_LEN as u64 {
        return Err(FormatError::RequiredFeatureCountOutOfRange {
            actual: count,
            maximum: MAX_HEADER_LEN,
        });
    }

    let count_usize =
        usize::try_from(count).map_err(|_| FormatError::RequiredFeatureCountOutOfRange {
            actual: count,
            maximum: MAX_HEADER_LEN,
        })?;
    let mut features = Vec::with_capacity(count_usize);
    for _ in 0..count {
        features.push(
            decoder.u32().map_err(|error| {
                cbor_decode_error("key 11 (required feature id)", decoder, &error)
            })?,
        );
    }

    if !strictly_increasing(&features) {
        return Err(FormatError::RequiredFeaturesNotStrictlyIncreasing);
    }
    for feature in &features {
        if !is_supported_required_feature(*feature) {
            return Err(FormatError::UnknownRequiredFeature(*feature));
        }
    }
    Ok(features)
}

fn decode_optional_etag(decoder: &mut Decoder<'_>) -> Result<Option<[u8; 32]>, FormatError> {
    match decoder
        .datatype()
        .map_err(|error| cbor_decode_error("key 12 (base etag)", decoder, &error))?
    {
        Type::Null => {
            decoder
                .null()
                .map_err(|error| cbor_decode_error("key 12 (base etag)", decoder, &error))?;
            Ok(None)
        }
        Type::Bytes => decode_fixed_bytes::<32>(decoder, "key 12 (base etag)").map(Some),
        actual => Err(FormatError::CborDecode {
            field: "key 12 (base etag)",
            offset: decoder.position(),
            message: format!("expected null or bytes, found {actual}"),
        }),
    }
}

fn read_expected_key(
    decoder: &mut Decoder<'_>,
    expected: u64,
    seen: &mut [bool; EDRY_HEADER_FIELD_COUNT_USIZE],
) -> Result<(), FormatError> {
    let key = decoder
        .u64()
        .map_err(|error| cbor_decode_error("map key", decoder, &error))?;
    let Some(seen_entry) = usize::try_from(key)
        .ok()
        .and_then(|index| seen.get_mut(index))
    else {
        return Err(FormatError::UnknownHeaderKey(key));
    };

    if *seen_entry {
        return Err(FormatError::DuplicateHeaderKey(key));
    }
    if key != expected {
        return Err(FormatError::HeaderKeyOutOfOrder {
            expected,
            found: key,
        });
    }
    *seen_entry = true;
    Ok(())
}

fn validate_header_length(length: usize) -> Result<(), FormatError> {
    if length == 0 || length > MAX_HEADER_LEN {
        return Err(FormatError::HeaderLengthOutOfRange {
            actual: length,
            maximum: MAX_HEADER_LEN,
        });
    }
    Ok(())
}

fn validate_ciphertext_length(
    length: usize,
    plaintext_kind: PlaintextKind,
) -> Result<(), FormatError> {
    let maximum = match plaintext_kind {
        PlaintextKind::Utf8Markdown => MAX_DOCUMENT_CIPHERTEXT_LEN,
        PlaintextKind::OpaqueAsset => MAX_ASSET_CIPHERTEXT_LEN,
    };
    if !(AEAD_TAG_LEN..=maximum).contains(&length) {
        return Err(FormatError::CiphertextLengthOutOfRange {
            actual: length,
            minimum: AEAD_TAG_LEN,
            maximum,
        });
    }
    Ok(())
}

fn cbor_decode_error(
    field: &'static str,
    decoder: &Decoder<'_>,
    error: &minicbor::decode::Error,
) -> FormatError {
    FormatError::CborDecode {
        field,
        offset: error.position().unwrap_or(decoder.position()),
        message: error.to_string(),
    }
}

fn strictly_increasing(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committed_header() -> EdryHeader {
        EdryHeader {
            vault_id: Uuid::from_bytes([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ]),
            file_id: Uuid::from_bytes([
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ]),
            logical_path: "notes/fixed.md".to_owned(),
            key_epoch: 0,
            key_derivation: FileKeyDerivation::Blake2b256V1,
            cipher: CipherSuite::XChaCha20Poly1305Ietf,
            nonce: [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            ],
            plaintext_kind: PlaintextKind::Utf8Markdown,
            created_at_ms: 1_783_699_200_000,
            modified_at_ms: 1_783_699_200_123,
            content_flags: ContentFlags::NONE,
            required_features: Vec::new(),
            base_etag: None,
        }
    }

    fn draft_header() -> EdryHeader {
        let mut header = committed_header();
        header.content_flags = ContentFlags::DRAFT | ContentFlags::UNRESOLVED_MERGE;
        header.base_etag = Some([0xa5; 32]);
        header
    }

    fn asset_header() -> EdryHeader {
        let mut header = committed_header();
        header.logical_path = "images/station.png".to_owned();
        header.plaintext_kind = PlaintextKind::OpaqueAsset;
        header.required_features = vec![OPAQUE_ASSETS_V1];
        header
    }

    fn encoded_header_with_mutation(mutator: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut bytes = match encode_header(&committed_header()) {
            Ok(bytes) => bytes,
            Err(error) => panic!("test header must encode: {error}"),
        };
        mutator(&mut bytes);
        bytes
    }

    fn envelope() -> Vec<u8> {
        match build_envelope(&committed_header(), &[0x5a; AEAD_TAG_LEN + 3]) {
            Ok(envelope) => envelope,
            Err(error) => panic!("test envelope must build: {error}"),
        }
    }

    #[test]
    fn fixed_header_vector_is_stable() {
        // This literal is an interoperability fixture, not produced by a second
        // encoder in the test.  It locks map length, key order, integer widths,
        // byte/text lengths, timestamps, empty array, and null representation.
        const EXPECTED: &[u8] = &[
            0xad, 0x00, 0x50, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x50, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x02, 0x6e, 0x6e, 0x6f, 0x74,
            0x65, 0x73, 0x2f, 0x66, 0x69, 0x78, 0x65, 0x64, 0x2e, 0x6d, 0x64, 0x03, 0x00, 0x04,
            0x01, 0x05, 0x01, 0x06, 0x58, 0x18, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
            0x36, 0x37, 0x07, 0x01, 0x08, 0x1b, 0x00, 0x00, 0x01, 0x9f, 0x4c, 0xc1, 0xd8, 0x00,
            0x09, 0x1b, 0x00, 0x00, 0x01, 0x9f, 0x4c, 0xc1, 0xd8, 0x7b, 0x0a, 0x00, 0x0b, 0x80,
            0x0c, 0xf6,
        ];

        let encoded = encode_header(&committed_header());
        assert_eq!(encoded.as_deref(), Ok(EXPECTED));
        assert_eq!(decode_header(EXPECTED), Ok(committed_header()));
    }

    #[test]
    fn fixed_asset_header_vector_is_stable() {
        // Independent literal fixture for the feature-1 wire extension. In
        // particular, key 7 is plaintext kind 2 and key 11 is exact `[1]`.
        const EXPECTED: &[u8] = &[
            0xad, 0x00, 0x50, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x50, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x02, 0x72, 0x69, 0x6d, 0x61,
            0x67, 0x65, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x6e,
            0x67, 0x03, 0x00, 0x04, 0x01, 0x05, 0x01, 0x06, 0x58, 0x18, 0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
            0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x07, 0x02, 0x08, 0x1b, 0x00, 0x00, 0x01, 0x9f,
            0x4c, 0xc1, 0xd8, 0x00, 0x09, 0x1b, 0x00, 0x00, 0x01, 0x9f, 0x4c, 0xc1, 0xd8, 0x7b,
            0x0a, 0x00, 0x0b, 0x81, 0x01, 0x0c, 0xf6,
        ];

        let encoded = encode_header(&asset_header());
        assert_eq!(encoded.as_deref(), Ok(EXPECTED));
        assert_eq!(decode_header(EXPECTED), Ok(asset_header()));
    }

    #[test]
    fn committed_and_draft_headers_round_trip() {
        for header in [committed_header(), draft_header(), asset_header()] {
            let encoded = encode_header(&header);
            assert!(encoded.is_ok());
            let decoded = encoded.and_then(|bytes| decode_header(&bytes));
            assert_eq!(decoded, Ok(header));
        }
    }

    #[test]
    fn prefix_is_exact_big_endian_layout() {
        assert_eq!(
            build_prefix(0x0102),
            Ok([
                b'E', b'D', b'R', b'Y', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
            ])
        );
    }

    #[test]
    fn associated_data_is_domain_prefix_and_exact_header() {
        let header = committed_header();
        let header_bytes = match encode_header(&header) {
            Ok(bytes) => bytes,
            Err(error) => panic!("header encode failed: {error}"),
        };
        let prefix = match build_prefix(header_bytes.len()) {
            Ok(prefix) => prefix,
            Err(error) => panic!("prefix build failed: {error}"),
        };
        let aad = match associated_data(&prefix, &header_bytes) {
            Ok(aad) => aad,
            Err(error) => panic!("AAD build failed: {error}"),
        };

        assert_eq!(&aad[..EDRY_AAD_DOMAIN.len()], EDRY_AAD_DOMAIN);
        assert_eq!(
            &aad[EDRY_AAD_DOMAIN.len()..EDRY_AAD_DOMAIN.len() + EDRY_PREFIX_LEN],
            prefix
        );
        assert_eq!(
            &aad[EDRY_AAD_DOMAIN.len() + EDRY_PREFIX_LEN..],
            header_bytes
        );
        assert_eq!(associated_data_for_header(&header), Ok(aad));
    }

    #[test]
    fn envelope_split_preserves_opaque_crypto_bytes() {
        let header = committed_header();
        let ciphertext = [0xca; AEAD_TAG_LEN + 17];
        let built = build_envelope(&header, &ciphertext);
        assert!(built.is_ok());
        let parts = built.as_deref().map(split_envelope);
        match parts {
            Ok(Ok(parts)) => {
                assert_eq!(parts.header, header);
                assert_eq!(parts.ciphertext, ciphertext);
                assert_eq!(parts.associated_data(), associated_data_for_header(&header));
            }
            other => panic!("envelope failed to round-trip: {other:?}"),
        }
    }

    #[test]
    fn etag_is_complete_envelope_sha256() {
        // SHA-256("abc"), locking the prefix and lowercase formatting.
        assert_eq!(
            etag(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            etag_digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn rejects_short_bad_or_unsupported_prefixes() {
        assert_eq!(
            split_envelope(&[0_u8; 11]),
            Err(FormatError::EnvelopeTooShort {
                actual: 11,
                minimum: EDRY_PREFIX_LEN,
            })
        );

        let mut invalid_magic = envelope();
        invalid_magic[0] ^= 0xff;
        assert!(matches!(
            split_envelope(&invalid_magic),
            Err(FormatError::InvalidMagic { .. })
        ));

        for (index, value) in [(4, 2), (5, 1)] {
            let mut unsupported = envelope();
            unsupported[index] = value;
            assert!(matches!(
                split_envelope(&unsupported),
                Err(FormatError::UnsupportedVersion { .. })
            ));
        }

        let mut flags = envelope();
        flags[7] = 1;
        assert_eq!(
            split_envelope(&flags),
            Err(FormatError::UnsupportedFixedFlags(1))
        );
    }

    #[test]
    fn rejects_header_and_ciphertext_length_violations() {
        let mut zero_header = envelope();
        zero_header[8..12].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            split_envelope(&zero_header),
            Err(FormatError::HeaderLengthOutOfRange {
                actual: 0,
                maximum: MAX_HEADER_LEN,
            })
        );

        let mut excessive_header = envelope();
        excessive_header[8..12].copy_from_slice(
            &(u32::try_from(MAX_HEADER_LEN + 1).unwrap_or(u32::MAX)).to_be_bytes(),
        );
        assert_eq!(
            split_envelope(&excessive_header),
            Err(FormatError::HeaderLengthOutOfRange {
                actual: MAX_HEADER_LEN + 1,
                maximum: MAX_HEADER_LEN,
            })
        );

        let mut truncated = envelope();
        let declared =
            u32::from_be_bytes([truncated[8], truncated[9], truncated[10], truncated[11]]) as usize;
        truncated.truncate(EDRY_PREFIX_LEN + declared - 1);
        assert_eq!(
            split_envelope(&truncated),
            Err(FormatError::TruncatedHeader {
                declared,
                available: declared - 1,
            })
        );

        let header = committed_header();
        assert!(matches!(
            build_envelope(&header, &[0_u8; AEAD_TAG_LEN - 1]),
            Err(FormatError::CiphertextLengthOutOfRange { .. })
        ));
        assert!(matches!(
            build_envelope(&header, &vec![0_u8; MAX_CIPHERTEXT_LEN + 1]),
            Err(FormatError::CiphertextLengthOutOfRange { .. })
        ));

        assert_eq!(MAX_DOCUMENT_PLAINTEXT_LEN, 16_777_216);
        assert_eq!(MAX_ASSET_PLAINTEXT_LEN, 67_108_864);
        assert_eq!(MAX_ASSET_ENVELOPE_BYTES, 67_112_988);
        assert!(
            validate_ciphertext_length(MAX_ASSET_CIPHERTEXT_LEN, PlaintextKind::OpaqueAsset)
                .is_ok()
        );
        assert_eq!(
            validate_ciphertext_length(MAX_ASSET_CIPHERTEXT_LEN + 1, PlaintextKind::OpaqueAsset),
            Err(FormatError::CiphertextLengthOutOfRange {
                actual: MAX_ASSET_CIPHERTEXT_LEN + 1,
                minimum: AEAD_TAG_LEN,
                maximum: MAX_ASSET_CIPHERTEXT_LEN,
            })
        );
    }

    #[test]
    fn rejects_indefinite_wrong_size_unknown_duplicate_and_ordered_maps() {
        assert_eq!(
            decode_header(&[0xbf, 0xff]),
            Err(FormatError::IndefiniteHeaderMap)
        );
        assert_eq!(
            decode_header(&[0xa0]),
            Err(FormatError::HeaderMapLength {
                actual: 0,
                expected: EDRY_HEADER_FIELD_COUNT,
            })
        );

        let unknown = encoded_header_with_mutation(|bytes| {
            // Last key 12 is the penultimate byte in the committed fixture.
            let index = bytes.len() - 2;
            bytes[index] = 13;
        });
        assert_eq!(
            decode_header(&unknown),
            Err(FormatError::UnknownHeaderKey(13))
        );

        let duplicate = encoded_header_with_mutation(|bytes| {
            // First key is byte 1; replace key 1 immediately following UUID 0.
            bytes[19] = 0;
        });
        assert_eq!(
            decode_header(&duplicate),
            Err(FormatError::DuplicateHeaderKey(0))
        );

        let out_of_order = encoded_header_with_mutation(|bytes| {
            bytes[1] = 1;
        });
        assert_eq!(
            decode_header(&out_of_order),
            Err(FormatError::HeaderKeyOutOfOrder {
                expected: 0,
                found: 1,
            })
        );
    }

    #[test]
    fn rejects_wrong_field_types_and_lengths() {
        let wrong_type = encoded_header_with_mutation(|bytes| {
            // UUID 0 byte string begins at byte 2; null is not a byte string.
            bytes[2] = 0xf6;
        });
        assert!(matches!(
            decode_header(&wrong_type),
            Err(FormatError::CborDecode {
                field: "key 0 (vault UUID)",
                ..
            })
        ));

        let short_uuid = encoded_header_with_mutation(|bytes| {
            bytes[2] = 0x4f;
            bytes.remove(18);
        });
        assert!(matches!(
            decode_header(&short_uuid),
            Err(FormatError::InvalidFieldLength {
                field: "key 0 (vault UUID)",
                actual: 15,
                expected: 16,
            })
        ));
    }

    #[test]
    fn rejects_noncanonical_and_trailing_header_bytes() {
        let canonical = match encode_header(&committed_header()) {
            Ok(bytes) => bytes,
            Err(error) => panic!("header encode failed: {error}"),
        };

        // Encode the first map key 0 non-minimally as 0x18 0x00.
        let mut noncanonical = canonical.clone();
        noncanonical.splice(1..2, [0x18, 0x00]);
        assert_eq!(
            decode_header(&noncanonical),
            Err(FormatError::NonCanonicalHeader)
        );

        let mut trailing = canonical;
        trailing.push(0xf6);
        assert_eq!(
            decode_header(&trailing),
            Err(FormatError::HeaderTrailingData { trailing: 1 })
        );
    }

    #[test]
    fn rejects_algorithm_flag_feature_and_draft_invariants() {
        let mut unknown_flags = committed_header();
        unknown_flags.content_flags = ContentFlags(1 << 2);
        assert_eq!(
            encode_header(&unknown_flags),
            Err(FormatError::UnsupportedContentFlags(1 << 2))
        );

        let mut unsorted_features = committed_header();
        unsorted_features.required_features = vec![2, 1];
        assert_eq!(
            encode_header(&unsorted_features),
            Err(FormatError::RequiredFeaturesNotStrictlyIncreasing)
        );

        let mut unknown_feature = committed_header();
        unknown_feature.required_features = vec![7];
        assert_eq!(
            encode_header(&unknown_feature),
            Err(FormatError::UnknownRequiredFeature(7))
        );

        let mut committed_with_base = committed_header();
        committed_with_base.base_etag = Some([0; 32]);
        assert_eq!(
            encode_header(&committed_with_base),
            Err(FormatError::CommittedFileHasBaseEtag)
        );

        let mut new_draft = committed_header();
        new_draft.content_flags = ContentFlags::DRAFT;
        new_draft.base_etag = None;
        assert!(encode_header(&new_draft).is_ok());

        let mut document_with_asset_feature = committed_header();
        document_with_asset_feature.required_features = vec![OPAQUE_ASSETS_V1];
        assert_eq!(
            encode_header(&document_with_asset_feature),
            Err(FormatError::PlaintextProfileMismatch)
        );

        for mutate in [
            |header: &mut EdryHeader| header.required_features.clear(),
            |header: &mut EdryHeader| header.content_flags = ContentFlags::DRAFT,
            |header: &mut EdryHeader| header.base_etag = Some([0; 32]),
        ] {
            let mut asset = asset_header();
            mutate(&mut asset);
            assert_eq!(
                encode_header(&asset),
                Err(FormatError::PlaintextProfileMismatch)
            );
        }

        let mut asset_with_markdown_path = asset_header();
        asset_with_markdown_path.logical_path = "notes/readme.md".to_owned();
        assert!(matches!(
            encode_header(&asset_with_markdown_path),
            Err(FormatError::InvalidLogicalPath { .. })
        ));
    }

    #[test]
    fn rejects_unknown_wire_ids_features_and_flags() {
        let encoded = match encode_header(&committed_header()) {
            Ok(bytes) => bytes,
            Err(error) => panic!("header encode failed: {error}"),
        };

        // Offsets are locked by `fixed_header_vector_is_stable` above.
        let mut unknown_kdf = encoded.clone();
        unknown_kdf[56] = 2;
        assert_eq!(
            decode_header(&unknown_kdf),
            Err(FormatError::UnsupportedFileKeyDerivation(2))
        );

        let mut unknown_cipher = encoded.clone();
        unknown_cipher[58] = 2;
        assert_eq!(
            decode_header(&unknown_cipher),
            Err(FormatError::UnsupportedCipher(2))
        );

        let mut unknown_kind = encoded.clone();
        unknown_kind[87] = 3;
        assert_eq!(
            decode_header(&unknown_kind),
            Err(FormatError::UnsupportedPlaintextKind(3))
        );

        let mut unknown_flags = encoded.clone();
        unknown_flags[109] = 4;
        assert_eq!(
            decode_header(&unknown_flags),
            Err(FormatError::UnsupportedContentFlags(4))
        );

        let mut unknown_feature = encoded.clone();
        unknown_feature.splice(111..112, [0x81, 0x07]);
        assert_eq!(
            decode_header(&unknown_feature),
            Err(FormatError::UnknownRequiredFeature(7))
        );

        let mut unsorted_features = encoded.clone();
        unsorted_features.splice(111..112, [0x82, 0x02, 0x01]);
        assert_eq!(
            decode_header(&unsorted_features),
            Err(FormatError::RequiredFeaturesNotStrictlyIncreasing)
        );

        let mut indefinite_features = encoded;
        indefinite_features[111] = 0x9f;
        assert_eq!(
            decode_header(&indefinite_features),
            Err(FormatError::IndefiniteRequiredFeatures)
        );
    }

    #[test]
    fn rejects_nil_ids_and_invalid_timestamps() {
        let mut nil_vault = committed_header();
        nil_vault.vault_id = Uuid::nil();
        assert_eq!(encode_header(&nil_vault), Err(FormatError::NilVaultId));

        let mut nil_file = committed_header();
        nil_file.file_id = Uuid::nil();
        assert_eq!(encode_header(&nil_file), Err(FormatError::NilFileId));

        let mut negative_creation = committed_header();
        negative_creation.created_at_ms = -1;
        assert_eq!(
            encode_header(&negative_creation),
            Err(FormatError::NegativeCreationTime(-1))
        );

        let mut time_reversal = committed_header();
        time_reversal.modified_at_ms = time_reversal.created_at_ms - 1;
        assert_eq!(
            encode_header(&time_reversal),
            Err(FormatError::ModificationBeforeCreation {
                created_at_ms: 1_783_699_200_000,
                modified_at_ms: 1_783_699_199_999,
            })
        );
    }

    #[test]
    fn rejects_invalid_logical_path_and_aad_length_mismatch() {
        let mut invalid_path = committed_header();
        invalid_path.logical_path = "../secret.md".to_owned();
        assert!(matches!(
            encode_header(&invalid_path),
            Err(FormatError::InvalidLogicalPath { .. })
        ));

        let prefix = match build_prefix(1) {
            Ok(prefix) => prefix,
            Err(error) => panic!("prefix failed: {error}"),
        };
        assert_eq!(
            associated_data(&prefix, &[0, 1]),
            Err(FormatError::PrefixHeaderLengthMismatch {
                declared: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn every_prefix_truncation_is_rejected() {
        let valid = envelope();
        for length in 0..EDRY_PREFIX_LEN {
            assert!(matches!(
                split_envelope(&valid[..length]),
                Err(FormatError::EnvelopeTooShort { .. })
            ));
        }
    }
}
