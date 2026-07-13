//! Canonical GA publication-marker v2 framing.
//!
//! This module owns only the generic marker wire. Repository-specific domains,
//! staging-name prefixes, and candidate-seal schemas remain caller policy.

use std::fmt;
use std::io::{self, Read};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::atomic::{
    FilesystemDirectoryIdentity, FilesystemFileIdentity, PublicationIdentityScheme,
    PublicationIdentityWire,
};
use crate::path::{LogicalDir, raw_portable_case_fold_key};

/// Exact GA publication-marker signature.
pub const PUBLICATION_MARKER_MAGIC: [u8; 8] = *b"INEXPUB\0";
/// Publication-marker format version implemented by this module.
pub const PUBLICATION_MARKER_VERSION: u16 = 2;
/// Smallest canonical publication-marker v2 wire.
pub const PUBLICATION_MARKER_MIN_BYTES: usize = 172;
/// Largest canonical publication-marker v2 wire.
pub const PUBLICATION_MARKER_MAX_BYTES: usize = 998;
/// Absolute read/allocation ceiling applied before retaining a marker.
pub const PUBLICATION_MARKER_READ_LIMIT_BYTES: usize = 1_024;

const FIXED_FIELDS_BYTES: usize = 136;
const DIGEST_BYTES: usize = 32;
const BASE_TOTAL_BYTES: u32 = 168;
const IDENTITY_BYTES: usize = 24;
const PUBLICATION_ID_BYTES: usize = 16;
const MAX_DOMAIN_BYTES: usize = 64;
const MAX_CHILD_NAME_BYTES: usize = 255;
const MAX_CANDIDATE_SEAL_BYTES: usize = 256;

/// Generic publication-marker validation or bounded-read failure.
///
/// The variants deliberately carry no marker bytes, filesystem identities,
/// publication identifiers, candidate seals, or digests.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicationMarkerError {
    /// The bytes are not the one canonical publication-marker v2 encoding.
    #[error("publication marker is not canonical v2")]
    InvalidFormat,

    /// The input exceeded the absolute marker read/allocation ceiling.
    #[error("publication marker exceeds the bounded-read ceiling")]
    ResourceLimit,

    /// Reading failed; only the non-sensitive I/O category is retained.
    #[error("publication marker read failed ({kind:?})")]
    Io {
        /// Stable I/O category without a path or operating-system message.
        kind: io::ErrorKind,
    },
}

/// One immutable, scheme-bound identity decoded from a marker.
///
/// There is intentionally no public constructor: callers can obtain this
/// value only by parsing a canonical marker or constructing one from typed
/// observed filesystem identities, and therefore cannot relabel raw bytes with
/// another identity scheme.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicationMarkerIdentity {
    scheme: PublicationIdentityScheme,
    bytes: [u8; IDENTITY_BYTES],
}

impl PublicationMarkerIdentity {
    fn from_observed(identity: PublicationIdentityWire) -> Self {
        Self {
            scheme: identity.scheme(),
            bytes: *identity.wire_bytes(),
        }
    }

    fn from_wire(scheme: PublicationIdentityScheme, bytes: [u8; IDENTITY_BYTES]) -> Self {
        Self { scheme, bytes }
    }

    /// Return the identity scheme that gives these bytes meaning.
    #[must_use]
    pub const fn scheme(&self) -> PublicationIdentityScheme {
        self.scheme
    }

    /// Borrow the exact canonical 24-byte wire projection.
    #[must_use]
    pub const fn wire_bytes(&self) -> &[u8; IDENTITY_BYTES] {
        &self.bytes
    }

    fn matches_wire(&self, observed: &PublicationIdentityWire) -> bool {
        self.scheme == observed.scheme() && constant_time_equal(&self.bytes, observed.wire_bytes())
    }
}

impl fmt::Debug for PublicationMarkerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationMarkerIdentity")
            .field("scheme", &self.scheme)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Borrowed, already-observed values used to create one canonical marker.
///
/// Repository-specific validation must run before constructing this generic
/// input. In particular, this type does not assign meaning to a domain or to
/// the opaque candidate seal.
///
/// Directory and regular-file roles intentionally have different Rust types.
/// This remains necessary under the Windows modern identity scheme, whose
/// opaque `FILE_ID_128` has no directory/file discriminator.
///
/// ```compile_fail
/// use inex_core::atomic::{
///     FilesystemDirectoryIdentity, FilesystemFileIdentity, PublicationIdentityScheme,
/// };
/// use inex_core::publication::PublicationMarkerV2Input;
///
/// fn cannot_put_a_directory_in_the_marker_file_role<'a>(
///     directory: &'a FilesystemDirectoryIdentity,
///     file: &'a FilesystemFileIdentity,
/// ) {
///     let _ = PublicationMarkerV2Input {
///         scheme: PublicationIdentityScheme::WindowsModernFileId128V1,
///         publication_id: [1; 16],
///         common_parent_identity: directory,
///         staging_root_identity: directory,
///         marker_parent_identity: directory,
///         marker_file_identity: directory,
///         domain: "a",
///         staging_child_name: "stage",
///         destination_child_name: "destination",
///         candidate_seal: b"seal",
///     };
/// }
/// ```
#[derive(Clone, Copy)]
pub struct PublicationMarkerV2Input<'a> {
    /// One explicit identity scheme that every typed identity must project.
    pub scheme: PublicationIdentityScheme,
    /// Nonzero CSPRNG publication identifier.
    pub publication_id: [u8; PUBLICATION_ID_BYTES],
    /// Identity of the common parent directory.
    pub common_parent_identity: &'a FilesystemDirectoryIdentity,
    /// Identity of the staging-root directory.
    pub staging_root_identity: &'a FilesystemDirectoryIdentity,
    /// Identity of the marker-parent directory.
    pub marker_parent_identity: &'a FilesystemDirectoryIdentity,
    /// Identity of the single-link regular marker file.
    pub marker_file_identity: &'a FilesystemFileIdentity,
    /// Generic caller-domain spelling.
    pub domain: &'a str,
    /// Exact staging direct-child name.
    pub staging_child_name: &'a str,
    /// Exact destination direct-child name.
    pub destination_child_name: &'a str,
    /// Nonempty caller-opaque candidate seal.
    pub candidate_seal: &'a [u8],
}

impl fmt::Debug for PublicationMarkerV2Input<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationMarkerV2Input")
            .field("scheme", &self.scheme)
            .field("publication_id", &"[REDACTED]")
            .field("identities", &"[REDACTED]")
            .field("domain_length", &self.domain.len())
            .field("staging_child_name_length", &self.staging_child_name.len())
            .field(
                "destination_child_name_length",
                &self.destination_child_name.len(),
            )
            .field("candidate_seal_length", &self.candidate_seal.len())
            .finish()
    }
}

/// One validated, canonical GA publication-marker v2 value.
#[derive(Clone)]
pub struct PublicationMarkerV2 {
    scheme: PublicationIdentityScheme,
    publication_id: [u8; PUBLICATION_ID_BYTES],
    identities: [PublicationMarkerIdentity; 4],
    domain: String,
    staging_child_name: String,
    destination_child_name: String,
    candidate_seal: Vec<u8>,
    domain_length: u16,
    staging_child_name_length: u16,
    destination_child_name_length: u16,
    candidate_seal_length: u16,
}

impl PartialEq for PublicationMarkerV2 {
    fn eq(&self, other: &Self) -> bool {
        let seal_equal = constant_time_equal(&self.candidate_seal, &other.candidate_seal);
        let other_fields_equal = self.scheme == other.scheme
            && self.publication_id == other.publication_id
            && self.identities == other.identities
            && self.domain == other.domain
            && self.staging_child_name == other.staging_child_name
            && self.destination_child_name == other.destination_child_name
            && self.domain_length == other.domain_length
            && self.staging_child_name_length == other.staging_child_name_length
            && self.destination_child_name_length == other.destination_child_name_length
            && self.candidate_seal_length == other.candidate_seal_length;
        seal_equal & other_fields_equal
    }
}

impl Eq for PublicationMarkerV2 {}

impl PublicationMarkerV2 {
    /// Validate observed values and construct one marker.
    ///
    /// This generic layer accepts any valid domain and opaque seal. A caller
    /// that owns a particular domain must enforce its exact spelling, child
    /// namespace, and seal schema before calling this function.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationMarkerError::InvalidFormat`] when an identity uses
    /// a different or noncanonical scheme, the publication id is zero, the
    /// domain/name profile is invalid, the names collide, or the seal length is
    /// outside the frozen v2 bounds.
    pub fn new(input: PublicationMarkerV2Input<'_>) -> Result<Self, PublicationMarkerError> {
        let scheme = input.scheme;
        let observed = [
            input.common_parent_identity.publication_identity(scheme),
            input.staging_root_identity.publication_identity(scheme),
            input.marker_parent_identity.publication_identity(scheme),
            input.marker_file_identity.publication_identity(scheme),
        ];
        let [
            Some(common_parent),
            Some(staging_root),
            Some(marker_parent),
            Some(marker_file),
        ] = observed
        else {
            return Err(PublicationMarkerError::InvalidFormat);
        };
        let identities = [common_parent, staging_root, marker_parent, marker_file];
        let identities = identities.map(PublicationMarkerIdentity::from_observed);
        Self::from_validated_parts(
            scheme,
            input.publication_id,
            identities,
            input.domain.as_bytes(),
            input.staging_child_name.as_bytes(),
            input.destination_child_name.as_bytes(),
            input.candidate_seal,
        )
    }

    /// Parse exactly one complete canonical marker held in memory.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationMarkerError::ResourceLimit`] above the absolute
    /// 1,024-byte ceiling. Every other malformed, unsupported, truncated,
    /// trailing, noncanonical, or digest-mismatched encoding returns
    /// [`PublicationMarkerError::InvalidFormat`].
    pub fn parse(bytes: &[u8]) -> Result<Self, PublicationMarkerError> {
        if bytes.len() > PUBLICATION_MARKER_READ_LIMIT_BYTES {
            return Err(PublicationMarkerError::ResourceLimit);
        }
        if !(PUBLICATION_MARKER_MIN_BYTES..=PUBLICATION_MARKER_MAX_BYTES).contains(&bytes.len()) {
            return Err(PublicationMarkerError::InvalidFormat);
        }
        if bytes[..8] != PUBLICATION_MARKER_MAGIC {
            return Err(PublicationMarkerError::InvalidFormat);
        }
        if read_u16(bytes, 8) != PUBLICATION_MARKER_VERSION {
            return Err(PublicationMarkerError::InvalidFormat);
        }

        let scheme = scheme_from_wire(read_u16(bytes, 10))?;
        let declared_total = usize::try_from(read_u32(bytes, 12))
            .map_err(|_| PublicationMarkerError::InvalidFormat)?;
        if declared_total != bytes.len() {
            return Err(PublicationMarkerError::InvalidFormat);
        }

        let domain_length = usize::from(read_u16(bytes, 128));
        let staging_child_name_length = usize::from(read_u16(bytes, 130));
        let destination_child_name_length = usize::from(read_u16(bytes, 132));
        let candidate_seal_length = usize::from(read_u16(bytes, 134));
        validate_field_lengths(
            domain_length,
            staging_child_name_length,
            destination_child_name_length,
            candidate_seal_length,
        )?;

        let expected_total = usize::try_from(BASE_TOTAL_BYTES)
            .ok()
            .and_then(|total| total.checked_add(domain_length))
            .and_then(|total| total.checked_add(staging_child_name_length))
            .and_then(|total| total.checked_add(destination_child_name_length))
            .and_then(|total| total.checked_add(candidate_seal_length))
            .ok_or(PublicationMarkerError::InvalidFormat)?;
        if expected_total != bytes.len() {
            return Err(PublicationMarkerError::InvalidFormat);
        }

        let digest_offset = bytes
            .len()
            .checked_sub(DIGEST_BYTES)
            .ok_or(PublicationMarkerError::InvalidFormat)?;
        let actual_digest = Sha256::digest(&bytes[..digest_offset]);
        if !constant_time_equal(actual_digest.as_slice(), &bytes[digest_offset..]) {
            return Err(PublicationMarkerError::InvalidFormat);
        }

        let mut publication_id = [0_u8; PUBLICATION_ID_BYTES];
        publication_id.copy_from_slice(&bytes[16..32]);
        let identities = [
            identity_from_slice(scheme, &bytes[32..56]),
            identity_from_slice(scheme, &bytes[56..80]),
            identity_from_slice(scheme, &bytes[80..104]),
            identity_from_slice(scheme, &bytes[104..128]),
        ];

        let domain_start = FIXED_FIELDS_BYTES;
        let domain_end = domain_start
            .checked_add(domain_length)
            .ok_or(PublicationMarkerError::InvalidFormat)?;
        let staging_end = domain_end
            .checked_add(staging_child_name_length)
            .ok_or(PublicationMarkerError::InvalidFormat)?;
        let destination_end = staging_end
            .checked_add(destination_child_name_length)
            .ok_or(PublicationMarkerError::InvalidFormat)?;
        let seal_end = destination_end
            .checked_add(candidate_seal_length)
            .ok_or(PublicationMarkerError::InvalidFormat)?;
        if seal_end != digest_offset {
            return Err(PublicationMarkerError::InvalidFormat);
        }

        Self::from_validated_parts(
            scheme,
            publication_id,
            identities,
            &bytes[domain_start..domain_end],
            &bytes[domain_end..staging_end],
            &bytes[staging_end..destination_end],
            &bytes[destination_end..seal_end],
        )
    }

    /// Read at most 1,025 bytes without a heap allocation, reject an input
    /// above the 1,024-byte ceiling, then parse the retained bounded slice.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationMarkerError::Io`] with only the I/O error category,
    /// [`PublicationMarkerError::ResourceLimit`] for an oversized stream, or
    /// the same canonical-format error as [`Self::parse`].
    pub fn read_bounded(reader: &mut impl Read) -> Result<Self, PublicationMarkerError> {
        let mut bounded = [0_u8; PUBLICATION_MARKER_READ_LIMIT_BYTES + 1];
        let mut length = 0_usize;
        while length < bounded.len() {
            match reader.read(&mut bounded[length..]) {
                Ok(0) => break,
                Ok(read) => {
                    length = length
                        .checked_add(read)
                        .ok_or(PublicationMarkerError::ResourceLimit)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(PublicationMarkerError::Io { kind: error.kind() });
                }
            }
        }
        if length > PUBLICATION_MARKER_READ_LIMIT_BYTES {
            return Err(PublicationMarkerError::ResourceLimit);
        }
        Self::parse(&bounded[..length])
    }

    /// Encode this validated value as the one canonical marker v2 wire.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let total = BASE_TOTAL_BYTES
            + u32::from(self.domain_length)
            + u32::from(self.staging_child_name_length)
            + u32::from(self.destination_child_name_length)
            + u32::from(self.candidate_seal_length);
        let mut bytes = Vec::with_capacity(PUBLICATION_MARKER_MAX_BYTES);
        bytes.extend_from_slice(&PUBLICATION_MARKER_MAGIC);
        bytes.extend_from_slice(&PUBLICATION_MARKER_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.scheme.wire_value().to_be_bytes());
        bytes.extend_from_slice(&total.to_be_bytes());
        bytes.extend_from_slice(&self.publication_id);
        for identity in &self.identities {
            bytes.extend_from_slice(identity.wire_bytes());
        }
        bytes.extend_from_slice(&self.domain_length.to_be_bytes());
        bytes.extend_from_slice(&self.staging_child_name_length.to_be_bytes());
        bytes.extend_from_slice(&self.destination_child_name_length.to_be_bytes());
        bytes.extend_from_slice(&self.candidate_seal_length.to_be_bytes());
        bytes.extend_from_slice(self.domain.as_bytes());
        bytes.extend_from_slice(self.staging_child_name.as_bytes());
        bytes.extend_from_slice(self.destination_child_name.as_bytes());
        bytes.extend_from_slice(&self.candidate_seal);
        let digest = Sha256::digest(&bytes);
        bytes.extend_from_slice(&digest);
        bytes
    }

    /// Return the one identity scheme used by every marker identity.
    #[must_use]
    pub const fn scheme(&self) -> PublicationIdentityScheme {
        self.scheme
    }

    /// Borrow the nonzero publication identifier.
    #[must_use]
    pub const fn publication_id(&self) -> &[u8; PUBLICATION_ID_BYTES] {
        &self.publication_id
    }

    /// Borrow the common-parent directory identity.
    #[must_use]
    pub const fn common_parent_identity(&self) -> &PublicationMarkerIdentity {
        &self.identities[0]
    }

    /// Borrow the staging-root directory identity.
    #[must_use]
    pub const fn staging_root_identity(&self) -> &PublicationMarkerIdentity {
        &self.identities[1]
    }

    /// Borrow the marker-parent directory identity.
    #[must_use]
    pub const fn marker_parent_identity(&self) -> &PublicationMarkerIdentity {
        &self.identities[2]
    }

    /// Borrow the single-link regular marker-file identity.
    #[must_use]
    pub const fn marker_file_identity(&self) -> &PublicationMarkerIdentity {
        &self.identities[3]
    }

    /// Match a freshly captured common-parent directory under the marker's
    /// exact scheme.
    #[must_use]
    pub fn common_parent_matches(&self, observed: &FilesystemDirectoryIdentity) -> bool {
        observed
            .publication_identity(self.scheme)
            .is_some_and(|wire| self.identities[0].matches_wire(&wire))
    }

    /// Match a freshly captured staging-root directory under the marker's
    /// exact scheme.
    #[must_use]
    pub fn staging_root_matches(&self, observed: &FilesystemDirectoryIdentity) -> bool {
        observed
            .publication_identity(self.scheme)
            .is_some_and(|wire| self.identities[1].matches_wire(&wire))
    }

    /// Match a freshly captured marker-parent directory under the marker's
    /// exact scheme.
    #[must_use]
    pub fn marker_parent_matches(&self, observed: &FilesystemDirectoryIdentity) -> bool {
        observed
            .publication_identity(self.scheme)
            .is_some_and(|wire| self.identities[2].matches_wire(&wire))
    }

    /// Match a freshly captured single-link regular marker file under the
    /// marker's exact scheme.
    #[must_use]
    pub fn marker_file_matches(&self, observed: &FilesystemFileIdentity) -> bool {
        observed
            .publication_identity(self.scheme)
            .is_some_and(|wire| self.identities[3].matches_wire(&wire))
    }

    /// Borrow the exact validated caller domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Borrow the exact canonical staging direct-child name.
    #[must_use]
    pub fn staging_child_name(&self) -> &str {
        &self.staging_child_name
    }

    /// Borrow the exact canonical destination direct-child name.
    #[must_use]
    pub fn destination_child_name(&self) -> &str {
        &self.destination_child_name
    }

    /// Compare an expected opaque seal without data-dependent early exit.
    ///
    /// The seal length is public and a different length returns immediately.
    #[must_use]
    pub fn candidate_seal_matches(&self, expected: &[u8]) -> bool {
        constant_time_equal(&self.candidate_seal, expected)
    }

    fn from_validated_parts(
        scheme: PublicationIdentityScheme,
        publication_id: [u8; PUBLICATION_ID_BYTES],
        identities: [PublicationMarkerIdentity; 4],
        domain: &[u8],
        staging_child_name: &[u8],
        destination_child_name: &[u8],
        candidate_seal: &[u8],
    ) -> Result<Self, PublicationMarkerError> {
        if publication_id.iter().all(|byte| *byte == 0) {
            return Err(PublicationMarkerError::InvalidFormat);
        }
        if identities.iter().any(|identity| identity.scheme != scheme) {
            return Err(PublicationMarkerError::InvalidFormat);
        }
        validate_identities(scheme, &identities)?;
        validate_field_lengths(
            domain.len(),
            staging_child_name.len(),
            destination_child_name.len(),
            candidate_seal.len(),
        )?;

        let domain = validate_domain(domain)?.to_owned();
        let staging_child_name = validate_child_name(staging_child_name)?.to_owned();
        let destination_child_name = validate_child_name(destination_child_name)?.to_owned();
        if staging_child_name == destination_child_name
            || raw_portable_case_fold_key(&staging_child_name)
                == raw_portable_case_fold_key(&destination_child_name)
        {
            return Err(PublicationMarkerError::InvalidFormat);
        }
        let domain_length = checked_u16_length(domain.len())?;
        let staging_child_name_length = checked_u16_length(staging_child_name.len())?;
        let destination_child_name_length = checked_u16_length(destination_child_name.len())?;
        let candidate_seal_length = checked_u16_length(candidate_seal.len())?;

        Ok(Self {
            scheme,
            publication_id,
            identities,
            domain,
            staging_child_name,
            destination_child_name,
            candidate_seal: candidate_seal.to_vec(),
            domain_length,
            staging_child_name_length,
            destination_child_name_length,
            candidate_seal_length,
        })
    }
}

impl fmt::Debug for PublicationMarkerV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationMarkerV2")
            .field("scheme", &self.scheme)
            .field("publication_id", &"[REDACTED]")
            .field("identities", &"[REDACTED]")
            .field("domain", &"[REDACTED]")
            .field("staging_child_name", &"[REDACTED]")
            .field("destination_child_name", &"[REDACTED]")
            .field("candidate_seal", &"[REDACTED]")
            .field("domain_length", &self.domain_length)
            .field("staging_child_name_length", &self.staging_child_name_length)
            .field(
                "destination_child_name_length",
                &self.destination_child_name_length,
            )
            .field("candidate_seal_length", &self.candidate_seal_length)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

fn scheme_from_wire(value: u16) -> Result<PublicationIdentityScheme, PublicationMarkerError> {
    match value {
        1 => Ok(PublicationIdentityScheme::LinuxDevInodeV1),
        2 => Ok(PublicationIdentityScheme::WindowsModernFileId128V1),
        3 => Ok(PublicationIdentityScheme::WindowsLegacyFileIndexV1),
        _ => Err(PublicationMarkerError::InvalidFormat),
    }
}

fn identity_from_slice(
    scheme: PublicationIdentityScheme,
    bytes: &[u8],
) -> PublicationMarkerIdentity {
    let mut identity = [0_u8; IDENTITY_BYTES];
    identity.copy_from_slice(bytes);
    PublicationMarkerIdentity::from_wire(scheme, identity)
}

fn validate_identities(
    scheme: PublicationIdentityScheme,
    identities: &[PublicationMarkerIdentity; 4],
) -> Result<(), PublicationMarkerError> {
    match scheme {
        PublicationIdentityScheme::LinuxDevInodeV1 => {
            validate_discriminated_identities(identities, false)
        }
        PublicationIdentityScheme::WindowsModernFileId128V1 => {
            if identities
                .iter()
                .any(|identity| identity.bytes[8..].iter().all(|byte| *byte == 0))
            {
                return Err(PublicationMarkerError::InvalidFormat);
            }
            Ok(())
        }
        PublicationIdentityScheme::WindowsLegacyFileIndexV1 => {
            validate_discriminated_identities(identities, true)
        }
    }
}

fn validate_discriminated_identities(
    identities: &[PublicationMarkerIdentity; 4],
    legacy_windows: bool,
) -> Result<(), PublicationMarkerError> {
    for (index, identity) in identities.iter().enumerate() {
        if identity.bytes[16..23].iter().any(|byte| *byte != 0) {
            return Err(PublicationMarkerError::InvalidFormat);
        }
        let expected_discriminator = if index == 3 { 2 } else { 1 };
        if identity.bytes[23] != expected_discriminator {
            return Err(PublicationMarkerError::InvalidFormat);
        }
        if legacy_windows
            && (identity.bytes[..4].iter().any(|byte| *byte != 0)
                || identity.bytes[8..16].iter().all(|byte| *byte == 0))
        {
            return Err(PublicationMarkerError::InvalidFormat);
        }
    }
    Ok(())
}

fn validate_field_lengths(
    domain: usize,
    staging_child_name: usize,
    destination_child_name: usize,
    candidate_seal: usize,
) -> Result<(), PublicationMarkerError> {
    if !(1..=MAX_DOMAIN_BYTES).contains(&domain)
        || !(1..=MAX_CHILD_NAME_BYTES).contains(&staging_child_name)
        || !(1..=MAX_CHILD_NAME_BYTES).contains(&destination_child_name)
        || !(1..=MAX_CANDIDATE_SEAL_BYTES).contains(&candidate_seal)
    {
        return Err(PublicationMarkerError::InvalidFormat);
    }
    Ok(())
}

fn validate_domain(bytes: &[u8]) -> Result<&str, PublicationMarkerError> {
    let domain = std::str::from_utf8(bytes).map_err(|_| PublicationMarkerError::InvalidFormat)?;
    let Some(first) = bytes.first() else {
        return Err(PublicationMarkerError::InvalidFormat);
    };
    let Some(last) = bytes.last() else {
        return Err(PublicationMarkerError::InvalidFormat);
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit()
        || !last.is_ascii_lowercase() && !last.is_ascii_digit()
        || bytes.iter().any(|byte| {
            !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'.' && *byte != b'-'
        })
        || bytes.windows(2).any(|pair| pair == b"..")
    {
        return Err(PublicationMarkerError::InvalidFormat);
    }
    Ok(domain)
}

fn validate_child_name(bytes: &[u8]) -> Result<&str, PublicationMarkerError> {
    let name = std::str::from_utf8(bytes).map_err(|_| PublicationMarkerError::InvalidFormat)?;
    let parsed =
        LogicalDir::parse_canonical(name).map_err(|_| PublicationMarkerError::InvalidFormat)?;
    if parsed.is_root() || parsed.components().count() != 1 || parsed.as_str() != name {
        return Err(PublicationMarkerError::InvalidFormat);
    }
    Ok(name)
}

fn checked_u16_length(length: usize) -> Result<u16, PublicationMarkerError> {
    u16::try_from(length).map_err(|_| PublicationMarkerError::InvalidFormat)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{self, Cursor, Read};
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{
        BASE_TOTAL_BYTES, DIGEST_BYTES, PUBLICATION_MARKER_MAGIC, PUBLICATION_MARKER_MAX_BYTES,
        PUBLICATION_MARKER_MIN_BYTES, PUBLICATION_MARKER_READ_LIMIT_BYTES,
        PUBLICATION_MARKER_VERSION, PublicationIdentityScheme, PublicationMarkerError,
        PublicationMarkerV2, PublicationMarkerV2Input,
    };
    use crate::atomic::{filesystem_directory_identity, filesystem_file_identity};

    const GOLDEN_MIN_HEX: &str = concat!(
        "494e45585055420000020001000000ac000102030405060708090a0b0c0d0e0f",
        "0102030405060708181716151413121100000000000000010102030405060709",
        "28272625242322210000000000000001010203040506070a3837363534333231",
        "0000000000000001010203040506070b48474645444342410000000000000002",
        "000100010001000161626364bac6a66daf1fee455f2be5972c2d6e660644114c",
        "b79dc5b3f2a9b147f772e713",
    );

    fn discriminated_identity(volume: u64, index: u64, discriminator: u8) -> [u8; 24] {
        let mut identity = [0_u8; 24];
        identity[..8].copy_from_slice(&volume.to_be_bytes());
        identity[8..16].copy_from_slice(&index.to_le_bytes());
        identity[23] = discriminator;
        identity
    }

    fn linux_identities() -> [[u8; 24]; 4] {
        [
            discriminated_identity(0x0102_0304_0506_0708, 0x1112_1314_1516_1718, 1),
            discriminated_identity(0x0102_0304_0506_0709, 0x2122_2324_2526_2728, 1),
            discriminated_identity(0x0102_0304_0506_070a, 0x3132_3334_3536_3738, 1),
            discriminated_identity(0x0102_0304_0506_070b, 0x4142_4344_4546_4748, 2),
        ]
    }

    fn modern_identities() -> [[u8; 24]; 4] {
        std::array::from_fn(|index| {
            let mut identity = [0_u8; 24];
            identity[..8].copy_from_slice(
                &u64::try_from(index + 10)
                    .expect("small test index fits")
                    .to_be_bytes(),
            );
            for (offset, byte) in identity[8..].iter_mut().enumerate() {
                *byte = u8::try_from(index * 16 + offset + 1).expect("test byte fits");
            }
            identity
        })
    }

    fn legacy_identities() -> [[u8; 24]; 4] {
        [
            discriminated_identity(0x0102_0304, 11, 1),
            discriminated_identity(0x0102_0305, 12, 1),
            discriminated_identity(0x0102_0306, 13, 1),
            discriminated_identity(0x0102_0307, 14, 2),
        ]
    }

    fn encode_wire(
        scheme: u16,
        publication_id: [u8; 16],
        identities: [[u8; 24]; 4],
        variable_fields: [&[u8]; 4],
    ) -> Vec<u8> {
        let lengths = variable_fields
            .map(|field| u16::try_from(field.len()).expect("test field length must fit the wire"));
        let total = lengths
            .iter()
            .fold(BASE_TOTAL_BYTES, |sum, length| sum + u32::from(*length));
        let mut bytes = Vec::with_capacity(usize::try_from(total).expect("test total fits usize"));
        bytes.extend_from_slice(&PUBLICATION_MARKER_MAGIC);
        bytes.extend_from_slice(&PUBLICATION_MARKER_VERSION.to_be_bytes());
        bytes.extend_from_slice(&scheme.to_be_bytes());
        bytes.extend_from_slice(&total.to_be_bytes());
        bytes.extend_from_slice(&publication_id);
        for identity in identities {
            bytes.extend_from_slice(&identity);
        }
        for length in lengths {
            bytes.extend_from_slice(&length.to_be_bytes());
        }
        for field in variable_fields {
            bytes.extend_from_slice(field);
        }
        let digest = Sha256::digest(&bytes);
        bytes.extend_from_slice(&digest);
        bytes
    }

    fn base_wire() -> Vec<u8> {
        encode_wire(
            1,
            [0x42; 16],
            linux_identities(),
            [b"inex.test.v1", b"staging", b"destination", &[0xa5; 32]],
        )
    }

    fn resign(bytes: &mut [u8]) {
        let digest_offset = bytes.len() - DIGEST_BYTES;
        let digest = Sha256::digest(&bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(&digest);
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("golden hex is ASCII");
                u8::from_str_radix(text, 16).expect("golden hex is valid")
            })
            .collect()
    }

    #[test]
    fn frozen_minimum_golden_wire_parses_and_reencodes_exactly() {
        let golden = decode_hex(GOLDEN_MIN_HEX);
        assert_eq!(golden.len(), PUBLICATION_MARKER_MIN_BYTES);

        let marker = PublicationMarkerV2::parse(&golden).expect("golden marker parses");
        assert_eq!(marker.scheme(), PublicationIdentityScheme::LinuxDevInodeV1);
        assert_eq!(marker.publication_id(), &(0_u8..16).collect::<Vec<_>>()[..]);
        assert_eq!(marker.domain(), "a");
        assert_eq!(marker.staging_child_name(), "b");
        assert_eq!(marker.destination_child_name(), "c");
        assert!(marker.candidate_seal_matches(b"d"));
        assert_eq!(marker.to_bytes(), golden);
    }

    #[test]
    fn maximum_wire_is_exactly_998_bytes() {
        let domain = "a".repeat(64);
        let staging = "s".repeat(255);
        let destination = "d".repeat(255);
        let seal = [0x5a; 256];
        let wire = encode_wire(
            1,
            [1; 16],
            linux_identities(),
            [
                domain.as_bytes(),
                staging.as_bytes(),
                destination.as_bytes(),
                &seal,
            ],
        );
        assert_eq!(wire.len(), PUBLICATION_MARKER_MAX_BYTES);
        assert_eq!(
            PublicationMarkerV2::parse(&wire)
                .expect("maximum marker parses")
                .to_bytes(),
            wire
        );
    }

    #[test]
    fn each_variable_field_enforces_its_frozen_length_range() {
        let cases = [
            encode_wire(1, [1; 16], linux_identities(), [b"", b"s", b"d", b"x"]),
            encode_wire(
                1,
                [1; 16],
                linux_identities(),
                [&[b'a'; 65], b"s", b"d", b"x"],
            ),
            encode_wire(1, [1; 16], linux_identities(), [b"a", b"", b"d", b"x"]),
            encode_wire(
                1,
                [1; 16],
                linux_identities(),
                [b"a", &[b's'; 256], b"d", b"x"],
            ),
            encode_wire(1, [1; 16], linux_identities(), [b"a", b"s", b"", b"x"]),
            encode_wire(
                1,
                [1; 16],
                linux_identities(),
                [b"a", b"s", &[b'd'; 256], b"x"],
            ),
            encode_wire(1, [1; 16], linux_identities(), [b"a", b"s", b"d", b""]),
            encode_wire(
                1,
                [1; 16],
                linux_identities(),
                [b"a", b"s", b"d", &[0_u8; 257]],
            ),
        ];
        for wire in cases {
            assert_eq!(
                PublicationMarkerV2::parse(&wire),
                Err(PublicationMarkerError::InvalidFormat)
            );
        }
    }

    #[test]
    fn framing_rejects_magic_version_scheme_total_truncation_trailing_and_digest_changes() {
        for (offset, value) in [(0, 0_u8), (9, 3), (11, 9)] {
            let mut wire = base_wire();
            wire[offset] = value;
            resign(&mut wire);
            assert_eq!(
                PublicationMarkerV2::parse(&wire),
                Err(PublicationMarkerError::InvalidFormat)
            );
        }

        let mut wrong_total = base_wire();
        wrong_total[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        resign(&mut wrong_total);
        assert_eq!(
            PublicationMarkerV2::parse(&wrong_total),
            Err(PublicationMarkerError::InvalidFormat)
        );

        let mut truncated = base_wire();
        truncated.pop();
        assert_eq!(
            PublicationMarkerV2::parse(&truncated),
            Err(PublicationMarkerError::InvalidFormat)
        );

        let mut trailing = base_wire();
        trailing.push(0);
        assert_eq!(
            PublicationMarkerV2::parse(&trailing),
            Err(PublicationMarkerError::InvalidFormat)
        );

        let mut authenticated_trailing = base_wire();
        let digest_offset = authenticated_trailing.len() - DIGEST_BYTES;
        authenticated_trailing.insert(digest_offset, 0);
        let declared = u32::try_from(authenticated_trailing.len()).expect("test length fits");
        authenticated_trailing[12..16].copy_from_slice(&declared.to_be_bytes());
        resign(&mut authenticated_trailing);
        assert_eq!(
            PublicationMarkerV2::parse(&authenticated_trailing),
            Err(PublicationMarkerError::InvalidFormat)
        );

        let mut corrupt_digest = base_wire();
        let last = corrupt_digest.len() - 1;
        corrupt_digest[last] ^= 1;
        assert_eq!(
            PublicationMarkerV2::parse(&corrupt_digest),
            Err(PublicationMarkerError::InvalidFormat)
        );
    }

    #[test]
    fn absolute_read_ceiling_is_distinct_from_canonical_maximum() {
        let over_canonical = vec![0_u8; PUBLICATION_MARKER_MAX_BYTES + 1];
        assert_eq!(
            PublicationMarkerV2::parse(&over_canonical),
            Err(PublicationMarkerError::InvalidFormat)
        );
        let over_ceiling = vec![0_u8; PUBLICATION_MARKER_READ_LIMIT_BYTES + 1];
        assert_eq!(
            PublicationMarkerV2::parse(&over_ceiling),
            Err(PublicationMarkerError::ResourceLimit)
        );
        assert_eq!(
            PublicationMarkerV2::read_bounded(&mut Cursor::new(over_ceiling)),
            Err(PublicationMarkerError::ResourceLimit)
        );
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }

    #[test]
    fn bounded_reader_roundtrips_and_redacts_io_details_to_kind() {
        let wire = base_wire();
        let marker = PublicationMarkerV2::read_bounded(&mut Cursor::new(&wire))
            .expect("bounded marker parses");
        assert_eq!(marker.to_bytes(), wire);
        assert_eq!(
            PublicationMarkerV2::read_bounded(&mut FailingReader),
            Err(PublicationMarkerError::Io {
                kind: io::ErrorKind::PermissionDenied,
            })
        );
    }

    #[test]
    fn publication_id_must_be_nonzero() {
        let wire = encode_wire(
            1,
            [0; 16],
            linux_identities(),
            [b"a", b"stage", b"dest", b"x"],
        );
        assert_eq!(
            PublicationMarkerV2::parse(&wire),
            Err(PublicationMarkerError::InvalidFormat)
        );
    }

    #[test]
    fn discriminated_schemes_enforce_padding_and_field_type() {
        let mut zero_inode = linux_identities();
        zero_inode[0][8..16].fill(0);
        let valid_zero_inode = encode_wire(1, [1; 16], zero_inode, [b"a", b"stage", b"dest", b"x"]);
        assert!(PublicationMarkerV2::parse(&valid_zero_inode).is_ok());

        for (identity_index, byte_offset, value) in [(0, 16, 1_u8), (0, 23, 2), (3, 23, 1)] {
            let mut wire = base_wire();
            wire[32 + identity_index * 24 + byte_offset] = value;
            resign(&mut wire);
            assert_eq!(
                PublicationMarkerV2::parse(&wire),
                Err(PublicationMarkerError::InvalidFormat)
            );
        }
    }

    #[test]
    fn modern_scheme_requires_nonzero_file_id_but_not_a_discriminator() {
        let identities = modern_identities();
        let wire = encode_wire(2, [1; 16], identities, [b"a", b"stage", b"dest", b"x"]);
        let marker = PublicationMarkerV2::parse(&wire).expect("modern marker parses");
        assert_eq!(
            marker.marker_file_identity().wire_bytes()[23],
            identities[3][23]
        );

        let mut zero_file_id = identities;
        zero_file_id[2][8..].fill(0);
        let invalid = encode_wire(2, [1; 16], zero_file_id, [b"a", b"stage", b"dest", b"x"]);
        assert_eq!(
            PublicationMarkerV2::parse(&invalid),
            Err(PublicationMarkerError::InvalidFormat)
        );
    }

    #[test]
    fn legacy_scheme_enforces_zero_extended_volume_nonzero_index_and_discriminator() {
        let identities = legacy_identities();
        let wire = encode_wire(3, [1; 16], identities, [b"a", b"stage", b"dest", b"x"]);
        assert!(PublicationMarkerV2::parse(&wire).is_ok());

        let mut high_volume = identities;
        high_volume[0][0] = 1;
        let mut zero_index = identities;
        zero_index[1][8..16].fill(0);
        for invalid_identities in [high_volume, zero_index] {
            let invalid = encode_wire(
                3,
                [1; 16],
                invalid_identities,
                [b"a", b"stage", b"dest", b"x"],
            );
            assert_eq!(
                PublicationMarkerV2::parse(&invalid),
                Err(PublicationMarkerError::InvalidFormat)
            );
        }
    }

    #[test]
    fn domain_profile_accepts_only_the_frozen_lowercase_ascii_grammar() {
        for valid in [b"a".as_slice(), b"a-b.c9", &[b'a'; 64]] {
            let wire = encode_wire(
                1,
                [1; 16],
                linux_identities(),
                [valid, b"stage", b"dest", b"x"],
            );
            assert!(PublicationMarkerV2::parse(&wire).is_ok(), "{valid:?}");
        }

        for invalid in [
            b"A".as_slice(),
            b".a",
            b"a.",
            b"a-",
            b"a..b",
            b"a_b",
            b"a/b",
            &[0xff],
        ] {
            let wire = encode_wire(
                1,
                [1; 16],
                linux_identities(),
                [invalid, b"stage", b"dest", b"x"],
            );
            assert_eq!(
                PublicationMarkerV2::parse(&wire),
                Err(PublicationMarkerError::InvalidFormat),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn child_names_reuse_nfc_portable_component_and_casefold_rules() {
        let valid = encode_wire(
            1,
            [1; 16],
            linux_identities(),
            [b"a", "café".as_bytes(), "数据".as_bytes(), b"x"],
        );
        assert!(PublicationMarkerV2::parse(&valid).is_ok());

        for invalid in [
            b"".as_slice(),
            b".",
            b"..",
            b"a/b",
            b"a\\b",
            b"a\0b",
            b"CON",
            b"name.",
            b".git",
            "cafe\u{301}".as_bytes(),
            &[0xff],
        ] {
            let wire = encode_wire(
                1,
                [1; 16],
                linux_identities(),
                [b"a", invalid, b"destination", b"x"],
            );
            assert_eq!(
                PublicationMarkerV2::parse(&wire),
                Err(PublicationMarkerError::InvalidFormat),
                "{invalid:?}"
            );
        }

        for (staging, destination) in [("same", "same"), ("Straße", "STRASSE")] {
            let wire = encode_wire(
                1,
                [1; 16],
                linux_identities(),
                [b"a", staging.as_bytes(), destination.as_bytes(), b"x"],
            );
            assert_eq!(
                PublicationMarkerV2::parse(&wire),
                Err(PublicationMarkerError::InvalidFormat)
            );
        }
    }

    #[test]
    fn parsed_identities_keep_the_global_scheme_and_debug_redacts_values() {
        let marker = PublicationMarkerV2::parse(&base_wire()).expect("base marker parses");
        for identity in [
            marker.common_parent_identity(),
            marker.staging_root_identity(),
            marker.marker_parent_identity(),
            marker.marker_file_identity(),
        ] {
            assert_eq!(identity.scheme(), marker.scheme());
            let debug = format!("{identity:?}");
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("01020304"));
        }

        let debug = format!("{marker:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("inex.test.v1"));
        assert!(!debug.contains(": \"staging\""));
        assert!(!debug.contains(": \"destination\""));
        assert!(!debug.contains("42424242"));
        assert!(!debug.contains("a5a5a5a5"));
    }

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn create() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!("inex-marker-{}", Uuid::new_v4()));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn constructor_accepts_only_observed_scheme_bound_identities()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = TempRoot::create()?;
        let marker_path = root.0.join("marker");
        let marker_file = File::create(&marker_path)?;
        let directory_identity = filesystem_directory_identity(&root.0)?;
        let file_identity = filesystem_file_identity(&marker_file)?;

        #[cfg(target_os = "linux")]
        let scheme = PublicationIdentityScheme::LinuxDevInodeV1;
        #[cfg(windows)]
        let scheme = [
            PublicationIdentityScheme::WindowsModernFileId128V1,
            PublicationIdentityScheme::WindowsLegacyFileIndexV1,
        ]
        .into_iter()
        .find(|candidate| {
            directory_identity
                .publication_identity(*candidate)
                .is_some()
                && file_identity.publication_identity(*candidate).is_some()
        })
        .ok_or_else(|| io::Error::other("no common publication identity scheme"))?;

        let directory_wire = directory_identity
            .publication_identity(scheme)
            .ok_or_else(|| io::Error::other("directory projection unavailable"))?;
        let file_wire = file_identity
            .publication_identity(scheme)
            .ok_or_else(|| io::Error::other("file projection unavailable"))?;
        let input = PublicationMarkerV2Input {
            scheme,
            publication_id: [7; 16],
            common_parent_identity: &directory_identity,
            staging_root_identity: &directory_identity,
            marker_parent_identity: &directory_identity,
            marker_file_identity: &file_identity,
            domain: "inex.test.v1",
            staging_child_name: "staging",
            destination_child_name: "destination",
            candidate_seal: &[0x5a; 32],
        };
        let input_debug = format!("{input:?}");
        assert!(!input_debug.contains("inex.test.v1"));
        assert!(!input_debug.contains("5a5a5a5a"));

        #[cfg(target_os = "linux")]
        let unavailable_scheme = PublicationIdentityScheme::WindowsModernFileId128V1;
        #[cfg(windows)]
        let unavailable_scheme = match scheme {
            PublicationIdentityScheme::WindowsModernFileId128V1 => {
                PublicationIdentityScheme::WindowsLegacyFileIndexV1
            }
            PublicationIdentityScheme::WindowsLegacyFileIndexV1 => {
                PublicationIdentityScheme::WindowsModernFileId128V1
            }
            PublicationIdentityScheme::LinuxDevInodeV1 => {
                return Err(io::Error::other("unexpected Windows Linux scheme").into());
            }
        };
        assert_eq!(
            PublicationMarkerV2::new(PublicationMarkerV2Input {
                scheme: unavailable_scheme,
                ..input
            }),
            Err(PublicationMarkerError::InvalidFormat)
        );

        let marker = PublicationMarkerV2::new(input)?;
        assert!(marker.common_parent_matches(&directory_identity));
        assert!(marker.staging_root_matches(&directory_identity));
        assert!(marker.marker_parent_matches(&directory_identity));
        assert!(marker.marker_file_matches(&file_identity));
        assert_eq!(
            marker.common_parent_identity().wire_bytes(),
            directory_wire.wire_bytes()
        );
        assert_eq!(
            marker.marker_file_identity().wire_bytes(),
            file_wire.wire_bytes()
        );
        assert_eq!(PublicationMarkerV2::parse(&marker.to_bytes())?, marker);
        Ok(())
    }
}
