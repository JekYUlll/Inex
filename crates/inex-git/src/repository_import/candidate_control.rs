//! Held target-control snapshots for repository-candidate-seal-v1.
//!
//! This module binds a bounded body to one exact record in the marker-free
//! physical manifest and to one descriptor-relative file opened below the
//! caller's already-held target root.  It does not acquire the mutation lock,
//! authorize publication, or claim resistance to a hostile same-UID process.
//! Those authority boundaries remain responsibilities of the later aggregate
//! and publication transaction.

use std::fmt;

#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::io::Read as _;

#[cfg(target_os = "linux")]
use inex_core::atomic::{SecureSourceChild, SecureSourceDirectory, SecureSourceFile};
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

use super::candidate_manifest::{
    MarkerFreePhysicalManifest, PhysicalRecordId, PhysicalRecordKindRef,
};
use super::candidate_seal::{CandidateSealError, GitControlRole};

const TARGET_INDEX_PATH: &str = ".git/index";
const TARGET_CONFIG_PATH: &str = ".git/config";
const TARGET_MAIN_REF_PATH: &str = ".git/refs/heads/main";
const MAX_TARGET_INDEX_BYTES: u64 = 68 * 1024 * 1024;
const MAX_TARGET_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_TARGET_CONFIG_OUTPUT_BYTES: usize = 1024 * 1024;
const TARGET_MAIN_REF_BYTES: u64 = 41;

/// One exact fresh-target `refs/heads/main` value bound to section 1.
///
/// The physical-manifest brand, record ID, and decoded commit ID stay private.
/// This value is deliberately neither `Clone` nor `Copy`: later bootstrap code
/// must consume the one result produced through the held target-root snapshot.
#[allow(
    dead_code,
    reason = "the fresh root-commit bootstrap consumes this audited slice next"
)]
pub(super) struct FreshTargetMainRef<'physical> {
    physical: &'physical MarkerFreePhysicalManifest,
    record: PhysicalRecordId,
    commit_oid: [u8; 20],
}

impl fmt::Debug for FreshTargetMainRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTargetMainRef")
            .field("physical", &"[REDACTED]")
            .field("record", &"[REDACTED]")
            .field("commit_oid", &"[REDACTED]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "the fresh root-commit bootstrap consumes this audited slice next"
)]
impl FreshTargetMainRef<'_> {
    /// Prove that this ref belongs to the exact manifest allocation.
    #[must_use]
    pub(super) fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical, physical)
    }

    /// Return the decoded non-zero SHA-1 commit ID.
    #[must_use]
    pub(super) const fn commit_oid(&self) -> [u8; 20] {
        self.commit_oid
    }
}

/// Internal callback result branded by its collection-time physical manifest.
///
/// This wrapper never crosses the `candidate_control` module boundary.  It
/// prevents the generic descriptor primitive from accidentally returning a
/// value before its post-consumption revalidation.  A callback can still copy
/// bytes into its own value; such a copy is data only and is never treated as
/// physical or publication authority.
struct BoundHeldSnapshotValue<'physical, T> {
    physical: &'physical MarkerFreePhysicalManifest,
    value: T,
}

impl<T> fmt::Debug for BoundHeldSnapshotValue<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundHeldSnapshotValue")
            .field("physical", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl<T> BoundHeldSnapshotValue<'_, T> {
    /// Prove that this result belongs to the exact manifest allocation.
    #[must_use]
    fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical, physical)
    }

    fn into_inner(self, physical: &MarkerFreePhysicalManifest) -> Result<T, CandidateSealError> {
        if !self.is_bound_to(physical) {
            return Err(CandidateSealError::InvalidRecord);
        }
        Ok(self.value)
    }
}

/// A short-lived borrowed view of one exact held physical file body.
///
/// The owned zeroizing allocation and all held descriptors remain private to
/// [`with_held_physical_snapshot`].  A consumer can neither replace the body
/// nor detach it from its physical record ID.
struct HeldPhysicalSnapshot<'physical, 'bytes> {
    physical_manifest: &'physical MarkerFreePhysicalManifest,
    physical: PhysicalRecordId,
    bytes: &'bytes [u8],
}

impl fmt::Debug for HeldPhysicalSnapshot<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeldPhysicalSnapshot")
            .field("physical", &"[REDACTED]")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl HeldPhysicalSnapshot<'_, '_> {
    /// Prove that this view belongs to the exact collection-time manifest.
    #[must_use]
    fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical_manifest, physical)
    }

    #[must_use]
    const fn physical_id(&self) -> PhysicalRecordId {
        self.physical
    }

    #[must_use]
    const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

/// A borrowed `.git/index` body bound to its section-1 physical record.
pub(super) struct HeldTargetIndexSnapshot<'physical, 'bytes> {
    physical_manifest: &'physical MarkerFreePhysicalManifest,
    physical: PhysicalRecordId,
    role: GitControlRole,
    bytes: &'bytes [u8],
}

impl fmt::Debug for HeldTargetIndexSnapshot<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeldTargetIndexSnapshot")
            .field("physical", &"[REDACTED]")
            .field("role", &self.role)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl HeldTargetIndexSnapshot<'_, '_> {
    /// Prove that this index belongs to the exact collection-time manifest.
    #[must_use]
    pub(super) fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical_manifest, physical)
    }

    #[must_use]
    pub(super) const fn role(&self) -> GitControlRole {
        self.role
    }

    /// Inspect bytes only inside this collection-time branded snapshot.
    ///
    /// The callback may copy bytes, but a copy has no held-file or manifest
    /// authority.  Production consumers return evidence that itself borrows
    /// `physical` and cannot be projected against another manifest.
    pub(super) fn inspect_bytes<T>(
        &self,
        inspect: impl FnOnce(&[u8]) -> Result<T, CandidateSealError>,
    ) -> Result<T, CandidateSealError> {
        inspect(self.bytes)
    }
}

/// A borrowed `.git/config` body bound to its section-1 physical record.
pub(super) struct HeldTargetConfigSnapshot<'physical, 'bytes> {
    physical_manifest: &'physical MarkerFreePhysicalManifest,
    physical: PhysicalRecordId,
    role: GitControlRole,
    bytes: &'bytes [u8],
}

impl fmt::Debug for HeldTargetConfigSnapshot<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeldTargetConfigSnapshot")
            .field("physical", &"[REDACTED]")
            .field("role", &self.role)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl HeldTargetConfigSnapshot<'_, '_> {
    /// Prove that this config belongs to the exact collection-time manifest.
    #[must_use]
    pub(super) fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical_manifest, physical)
    }

    #[must_use]
    pub(super) const fn role(&self) -> GitControlRole {
        self.role
    }

    /// Inspect bytes only inside this collection-time branded snapshot.
    pub(super) fn inspect_bytes<T>(
        &self,
        inspect: impl FnOnce(&[u8]) -> Result<T, CandidateSealError>,
    ) -> Result<T, CandidateSealError> {
        inspect(self.bytes)
    }
}

#[cfg(target_os = "linux")]
struct HeldAncestor {
    physical: PhysicalRecordId,
    directory: SecureSourceDirectory,
}

#[cfg(target_os = "linux")]
struct HeldSnapshotState {
    physical: PhysicalRecordId,
    file: SecureSourceFile,
    ancestors: Vec<HeldAncestor>,
    bytes: Zeroizing<Vec<u8>>,
}

/// Read and consume one exact manifest file through the same held target root.
///
/// The file is opened one component at a time relative to retained directory
/// descriptors.  Its body is read exactly once into a zeroizing allocation:
/// exactly the section-1 size is required and a one-byte read must then report
/// EOF.  After `consume` returns, the original file handle/name and every
/// retained ancestor are revalidated in reverse order before its result can be
/// released.  No second file, body, or owned path snapshot is created.
/// Consequently, a callback-time same-inode, same-length rewrite is not
/// content-rehashed by this single snapshot. It must be rejected by the later
/// held-lock full-manifest/aggregate revalidation and is covered as an explicit
/// non-authority boundary below.
#[cfg(target_os = "linux")]
fn with_held_physical_snapshot<'physical, T>(
    physical: &'physical MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    physical_id: PhysicalRecordId,
    maximum_bytes: u64,
    consume: impl FnOnce(&HeldPhysicalSnapshot<'physical, '_>) -> Result<T, CandidateSealError>,
) -> Result<BoundHeldSnapshotValue<'physical, T>, CandidateSealError> {
    with_held_physical_snapshot_with_hook(
        physical,
        held_root,
        physical_id,
        maximum_bytes,
        || Ok(()),
        || {},
        consume,
    )
}

#[cfg(target_os = "linux")]
fn with_held_physical_snapshot_with_hook<'physical, T>(
    physical: &'physical MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    physical_id: PhysicalRecordId,
    maximum_bytes: u64,
    after_exact_read: impl FnOnce() -> Result<(), CandidateSealError>,
    on_extra_byte: impl FnOnce(),
    consume: impl FnOnce(&HeldPhysicalSnapshot<'physical, '_>) -> Result<T, CandidateSealError>,
) -> Result<BoundHeldSnapshotValue<'physical, T>, CandidateSealError> {
    let state = capture_held_physical_snapshot(
        physical,
        held_root,
        physical_id,
        maximum_bytes,
        after_exact_read,
        on_extra_byte,
    )?;
    let consumed = consume(&HeldPhysicalSnapshot {
        physical_manifest: physical,
        physical: state.physical,
        bytes: state.bytes.as_slice(),
    });
    revalidate_held_snapshot(physical, held_root, &state)?;
    Ok(BoundHeldSnapshotValue {
        physical,
        value: consumed?,
    })
}

/// Non-Linux builds deliberately have no native held-handle implementation.
/// The placeholder root cannot authorize a snapshot and always fails closed.
#[cfg(not(target_os = "linux"))]
fn with_held_physical_snapshot<'physical, T>(
    _physical: &'physical MarkerFreePhysicalManifest,
    _unsupported_held_root: (),
    _physical_id: PhysicalRecordId,
    _maximum_bytes: u64,
    _consume: impl FnOnce(&HeldPhysicalSnapshot<'physical, '_>) -> Result<T, CandidateSealError>,
) -> Result<BoundHeldSnapshotValue<'physical, T>, CandidateSealError> {
    Err(CandidateSealError::InvalidContext)
}

/// Consume the one fixed section-8 index role through a held physical snapshot.
#[cfg(target_os = "linux")]
pub(super) fn with_held_target_index_snapshot<'physical, T>(
    physical: &'physical MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    consume: impl FnOnce(&HeldTargetIndexSnapshot<'physical, '_>) -> Result<T, CandidateSealError>,
) -> Result<T, CandidateSealError> {
    let physical_id = exact_file_id(physical, TARGET_INDEX_PATH)?;
    with_held_physical_snapshot(
        physical,
        held_root,
        physical_id,
        MAX_TARGET_INDEX_BYTES,
        |snapshot| {
            consume(&HeldTargetIndexSnapshot {
                physical_manifest: physical,
                physical: snapshot.physical_id(),
                role: GitControlRole::Index,
                bytes: snapshot.bytes(),
            })
        },
    )
    .and_then(|bound| bound.into_inner(physical))
}

/// Consume the one fixed section-8 config role through a <=1 MiB snapshot.
#[cfg(target_os = "linux")]
pub(super) fn with_held_target_config_snapshot<'physical, T>(
    physical: &'physical MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    consume: impl FnOnce(&HeldTargetConfigSnapshot<'physical, '_>) -> Result<T, CandidateSealError>,
) -> Result<T, CandidateSealError> {
    let physical_id = exact_file_id(physical, TARGET_CONFIG_PATH)?;
    with_held_physical_snapshot(
        physical,
        held_root,
        physical_id,
        MAX_TARGET_CONFIG_BYTES,
        |snapshot| {
            consume(&HeldTargetConfigSnapshot {
                physical_manifest: physical,
                physical: snapshot.physical_id(),
                role: GitControlRole::Config,
                bytes: snapshot.bytes(),
            })
        },
    )
    .and_then(|bound| bound.into_inner(physical))
}

/// Collect the exact fresh-target `refs/heads/main` through the held root.
///
/// Only a 41-byte body containing forty lowercase SHA-1 hexadecimal digits
/// followed by one LF is accepted. The all-zero object ID is not a Git object
/// authority and is rejected. File content, identity, namespace binding, and
/// every ancestor binding are revalidated by the descriptor-relative snapshot
/// before the typed result is released.
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "the fresh root-commit bootstrap consumes this audited slice next"
)]
pub(super) fn collect_fresh_target_main_ref<'physical>(
    physical: &'physical MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
) -> Result<FreshTargetMainRef<'physical>, CandidateSealError> {
    collect_fresh_target_main_ref_with_hook(physical, held_root, || Ok(()))
}

#[cfg(target_os = "linux")]
fn collect_fresh_target_main_ref_with_hook<'physical>(
    physical: &'physical MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    after_parse: impl FnOnce() -> Result<(), CandidateSealError>,
) -> Result<FreshTargetMainRef<'physical>, CandidateSealError> {
    let record = exact_file_id(physical, TARGET_MAIN_REF_PATH)?;
    with_held_physical_snapshot(
        physical,
        held_root,
        record,
        TARGET_MAIN_REF_BYTES,
        |snapshot| {
            let commit_oid = parse_fresh_target_main_ref(snapshot.bytes())?;
            after_parse()?;
            Ok(FreshTargetMainRef {
                physical,
                record: snapshot.physical_id(),
                commit_oid,
            })
        },
    )
    .and_then(|bound| bound.into_inner(physical))
}

fn parse_fresh_target_main_ref(body: &[u8]) -> Result<[u8; 20], CandidateSealError> {
    let hex = body
        .strip_suffix(b"\n")
        .filter(|hex| hex.len() == 40)
        .ok_or(CandidateSealError::InvalidRecord)?;
    let mut oid = [0_u8; 20];
    for (output, pair) in oid.iter_mut().zip(hex.chunks_exact(2)) {
        *output = lower_hex_nibble(pair[0])?
            .checked_shl(4)
            .ok_or(CandidateSealError::InvalidRecord)?
            | lower_hex_nibble(pair[1])?;
    }
    if oid == [0; 20] {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(oid)
}

fn lower_hex_nibble(byte: u8) -> Result<u8, CandidateSealError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CandidateSealError::InvalidRecord),
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn with_held_target_index_snapshot<'physical, T>(
    _physical: &'physical MarkerFreePhysicalManifest,
    _unsupported_held_root: (),
    _consume: impl FnOnce(&HeldTargetIndexSnapshot<'physical, '_>) -> Result<T, CandidateSealError>,
) -> Result<T, CandidateSealError> {
    Err(CandidateSealError::InvalidContext)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn with_held_target_config_snapshot<'physical, T>(
    _physical: &'physical MarkerFreePhysicalManifest,
    _unsupported_held_root: (),
    _consume: impl FnOnce(&HeldTargetConfigSnapshot<'physical, '_>) -> Result<T, CandidateSealError>,
) -> Result<T, CandidateSealError> {
    Err(CandidateSealError::InvalidContext)
}

/// Non-Linux builds expose no held-root implementation and fail closed.
#[cfg(not(target_os = "linux"))]
#[allow(
    dead_code,
    reason = "the fresh root-commit bootstrap consumes this audited slice next"
)]
pub(super) fn collect_fresh_target_main_ref(
    _physical: &MarkerFreePhysicalManifest,
    _unsupported_held_root: (),
) -> Result<FreshTargetMainRef<'_>, CandidateSealError> {
    Err(CandidateSealError::InvalidContext)
}

fn exact_file_id(
    physical: &MarkerFreePhysicalManifest,
    required_path: &str,
) -> Result<PhysicalRecordId, CandidateSealError> {
    let record = physical
        .find(required_path)
        .ok_or(CandidateSealError::InvalidRecord)?;
    if record.path != required_path || !matches!(record.kind, PhysicalRecordKindRef::File { .. }) {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(record.id)
}

#[cfg(target_os = "linux")]
fn capture_held_physical_snapshot(
    physical: &MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    physical_id: PhysicalRecordId,
    maximum_bytes: u64,
    after_exact_read: impl FnOnce() -> Result<(), CandidateSealError>,
    on_extra_byte: impl FnOnce(),
) -> Result<HeldSnapshotState, CandidateSealError> {
    if held_root.identity() != physical.root_identity() {
        return Err(CandidateSealError::InvalidRecord);
    }
    held_root
        .verify_no_alternate_data_streams()
        .map_err(|_| CandidateSealError::InvalidRecord)?;

    let expected = physical
        .record(physical_id)
        .ok_or(CandidateSealError::InvalidRecord)?;
    let PhysicalRecordKindRef::File {
        identity: expected_identity,
        size: expected_size,
        sha256: expected_sha256,
    } = expected.kind
    else {
        return Err(CandidateSealError::InvalidRecord);
    };
    if expected.path.is_empty() {
        return Err(CandidateSealError::InvalidRecord);
    }
    if expected_size > maximum_bytes {
        return Err(CandidateSealError::ResourceLimit);
    }

    let (file, ancestors) = open_bound_physical_file(physical, held_root, expected.path)?;
    let (file, bytes) = read_exact_held_body(
        file,
        expected_identity,
        expected_size,
        expected_sha256,
        after_exact_read,
        on_extra_byte,
    )?;

    Ok(HeldSnapshotState {
        physical: physical_id,
        file,
        ancestors,
        bytes,
    })
}

#[cfg(target_os = "linux")]
fn open_bound_physical_file(
    physical: &MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    path: &str,
) -> Result<(SecureSourceFile, Vec<HeldAncestor>), CandidateSealError> {
    let mut ancestors = Vec::new();
    let mut components = path.split('/').peekable();
    let mut prefix_end = 0_usize;
    loop {
        let component = components.next().ok_or(CandidateSealError::InvalidRecord)?;
        if component.is_empty() {
            return Err(CandidateSealError::InvalidRecord);
        }
        let parent = ancestors
            .last()
            .map_or(held_root, |ancestor: &HeldAncestor| &ancestor.directory);
        let child = parent
            .open_child(OsStr::new(component))
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        prefix_end = prefix_end
            .checked_add(component.len())
            .ok_or(CandidateSealError::ResourceLimit)?;

        if components.peek().is_none() {
            let SecureSourceChild::File(file) = child else {
                return Err(CandidateSealError::InvalidRecord);
            };
            return Ok((file, ancestors));
        }

        let SecureSourceChild::Directory(directory) = child else {
            return Err(CandidateSealError::InvalidRecord);
        };
        let prefix = path
            .get(..prefix_end)
            .ok_or(CandidateSealError::InvalidRecord)?;
        let expected_ancestor = physical
            .find(prefix)
            .ok_or(CandidateSealError::InvalidRecord)?;
        if !matches!(
            expected_ancestor.kind,
            PhysicalRecordKindRef::Directory(identity) if identity == directory.identity()
        ) {
            return Err(CandidateSealError::InvalidRecord);
        }
        directory
            .verify_no_alternate_data_streams()
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        ancestors
            .try_reserve(1)
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        ancestors.push(HeldAncestor {
            physical: expected_ancestor.id,
            directory,
        });
        prefix_end = prefix_end
            .checked_add(1)
            .ok_or(CandidateSealError::ResourceLimit)?;
    }
}

#[cfg(target_os = "linux")]
fn read_exact_held_body(
    mut file: SecureSourceFile,
    expected_identity: &inex_core::atomic::FilesystemFileIdentity,
    expected_size: u64,
    expected_sha256: &[u8; 32],
    after_exact_read: impl FnOnce() -> Result<(), CandidateSealError>,
    on_extra_byte: impl FnOnce(),
) -> Result<(SecureSourceFile, Zeroizing<Vec<u8>>), CandidateSealError> {
    file.verify_no_alternate_data_streams()
        .map_err(|_| CandidateSealError::InvalidRecord)?;
    if file
        .identity()
        .map_err(|_| CandidateSealError::InvalidRecord)?
        != *expected_identity
        || file
            .observed_len()
            .map_err(|_| CandidateSealError::InvalidRecord)?
            != expected_size
    {
        return Err(CandidateSealError::InvalidRecord);
    }

    let allocation =
        usize::try_from(expected_size).map_err(|_| CandidateSealError::ResourceLimit)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(allocation)
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    bytes.resize(allocation, 0);
    file.read_exact(bytes.as_mut_slice())
        .map_err(|_| CandidateSealError::InvalidRecord)?;
    after_exact_read()?;
    let mut extra = Zeroizing::new([0_u8; 1]);
    if file
        .read(&mut *extra)
        .map_err(|_| CandidateSealError::InvalidRecord)?
        != 0
    {
        on_extra_byte();
        return Err(CandidateSealError::InvalidRecord);
    }
    let observed_sha256: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
    if observed_sha256 != *expected_sha256
        || file
            .identity()
            .map_err(|_| CandidateSealError::InvalidRecord)?
            != *expected_identity
        || file
            .observed_len()
            .map_err(|_| CandidateSealError::InvalidRecord)?
            != expected_size
        || file.verify_no_alternate_data_streams().is_err()
    {
        return Err(CandidateSealError::InvalidRecord);
    }

    Ok((file, bytes))
}

#[cfg(target_os = "linux")]
fn revalidate_held_snapshot(
    physical: &MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    snapshot: &HeldSnapshotState,
) -> Result<(), CandidateSealError> {
    let expected = physical
        .record(snapshot.physical)
        .ok_or(CandidateSealError::InvalidRecord)?;
    let PhysicalRecordKindRef::File {
        identity: expected_identity,
        size: expected_size,
        ..
    } = expected.kind
    else {
        return Err(CandidateSealError::InvalidRecord);
    };
    if snapshot
        .file
        .identity()
        .map_err(|_| CandidateSealError::InvalidRecord)?
        != *expected_identity
        || snapshot
            .file
            .observed_len()
            .map_err(|_| CandidateSealError::InvalidRecord)?
            != expected_size
        || snapshot.file.verify_no_alternate_data_streams().is_err()
    {
        return Err(CandidateSealError::InvalidRecord);
    }

    for ancestor in snapshot.ancestors.iter().rev() {
        let expected = physical
            .record(ancestor.physical)
            .ok_or(CandidateSealError::InvalidRecord)?;
        if !matches!(
            expected.kind,
            PhysicalRecordKindRef::Directory(identity) if identity == ancestor.directory.identity()
        ) || ancestor
            .directory
            .verify_no_alternate_data_streams()
            .is_err()
        {
            return Err(CandidateSealError::InvalidRecord);
        }
    }
    if held_root.identity() != physical.root_identity()
        || held_root.verify_no_alternate_data_streams().is_err()
    {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

/// Validate `git config --file - --no-includes --null --list` output.
///
/// The caller must obtain `output` by feeding bytes lent through
/// [`HeldTargetConfigSnapshot::inspect_bytes`] to Git over stdin. This pure
/// parser performs no pathname-based Git access. `expected_driver_command` is
/// computed by the caller from the already selected executable, keeping
/// environment and process authority outside the parser.
pub(super) fn validate_target_config_output(
    output: &[u8],
    expected_driver_command: &str,
) -> Result<(), CandidateSealError> {
    if output.len() > MAX_TARGET_CONFIG_OUTPUT_BYTES {
        return Err(CandidateSealError::ResourceLimit);
    }
    if output.is_empty() || !output.ends_with(&[0]) {
        return Err(CandidateSealError::InvalidRecord);
    }

    let mut required = 0_u16;
    #[cfg(windows)]
    let mut optional = 0_u8;
    for record in output[..output.len() - 1].split(|byte| *byte == 0) {
        if record.is_empty() {
            return Err(CandidateSealError::InvalidRecord);
        }
        let newline = record
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(CandidateSealError::InvalidRecord)?;
        let key = std::str::from_utf8(&record[..newline])
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        let value = std::str::from_utf8(&record[newline + 1..])
            .map_err(|_| CandidateSealError::InvalidRecord)?;

        let bit = if key.eq_ignore_ascii_case("core.repositoryformatversion") {
            require_config_value(value, "0")?;
            0b00_0001
        } else if key.eq_ignore_ascii_case("core.filemode") {
            #[cfg(windows)]
            require_config_value(value, "false")?;
            #[cfg(not(windows))]
            require_config_value(value, "true")?;
            0b00_0010
        } else if key.eq_ignore_ascii_case("core.bare") {
            require_config_value(value, "false")?;
            0b00_0100
        } else if key.eq_ignore_ascii_case("core.logallrefupdates") {
            require_config_value(value, "true")?;
            0b00_1000
        } else if key.eq_ignore_ascii_case("merge.inex.name") {
            require_config_value(value, super::DRIVER_NAME)?;
            0b01_0000
        } else if key.eq_ignore_ascii_case("merge.inex.driver") {
            require_config_value(value, expected_driver_command)?;
            0b10_0000
        } else {
            #[cfg(windows)]
            {
                let optional_bit = if key.eq_ignore_ascii_case("core.longpaths") {
                    require_config_value(value, "true")?;
                    0b001
                } else if key.eq_ignore_ascii_case("core.symlinks") {
                    require_boolean_config_value(value)?;
                    0b010
                } else if key.eq_ignore_ascii_case("core.ignorecase") {
                    require_boolean_config_value(value)?;
                    0b100
                } else {
                    return Err(CandidateSealError::InvalidRecord);
                };
                if optional & optional_bit != 0 {
                    return Err(CandidateSealError::InvalidRecord);
                }
                optional |= optional_bit;
                continue;
            }
            #[cfg(not(windows))]
            {
                return Err(CandidateSealError::InvalidRecord);
            }
        };
        if required & bit != 0 {
            return Err(CandidateSealError::InvalidRecord);
        }
        required |= bit;
    }

    if required != 0b11_1111 {
        return Err(CandidateSealError::InvalidRecord);
    }
    #[cfg(windows)]
    if optional & 0b001 == 0 {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

fn require_config_value(value: &str, expected: &str) -> Result<(), CandidateSealError> {
    (value == expected)
        .then_some(())
        .ok_or(CandidateSealError::InvalidRecord)
}

#[cfg(windows)]
fn require_boolean_config_value(value: &str) -> Result<(), CandidateSealError> {
    matches!(value, "true" | "false")
        .then_some(())
        .ok_or(CandidateSealError::InvalidRecord)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::repository_import::candidate_manifest::collect_marker_free_physical_manifest;
    use inex_core::atomic::{
        VAULT_LOCAL_DIRECTORY, VAULT_MUTATION_LOCK_FILE, open_secure_source_root,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-candidate-control-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory creates");
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

    fn create_fifo(path: &Path) {
        let status = Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(path)
            .status()
            .expect("mkfifo starts");
        assert!(status.success(), "mkfifo succeeds");
    }

    fn fixture(index: &[u8], config: &[u8]) -> TestDirectory {
        let target = TestDirectory::new();
        fs::create_dir(target.path().join(".git")).expect("Git directory creates");
        fs::write(target.path().join(TARGET_INDEX_PATH), index).expect("index writes");
        fs::write(target.path().join(TARGET_CONFIG_PATH), config).expect("config writes");
        fs::create_dir(target.path().join(VAULT_LOCAL_DIRECTORY))
            .expect("private directory creates");
        fs::write(
            target
                .path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(VAULT_MUTATION_LOCK_FILE),
            b"",
        )
        .expect("empty mutation lock writes");
        target
    }

    fn main_ref_fixture(body: &[u8]) -> TestDirectory {
        let target = fixture(b"index", b"config");
        let main_ref = target.path().join(TARGET_MAIN_REF_PATH);
        fs::create_dir_all(main_ref.parent().expect("main ref has a parent"))
            .expect("main ref parents create");
        fs::write(main_ref, body).expect("main ref writes");
        target
    }

    fn physical_and_root(
        target: &TestDirectory,
    ) -> (MarkerFreePhysicalManifest, SecureSourceDirectory) {
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        let root = open_secure_source_root(target.path()).expect("held target root opens");
        (physical, root)
    }

    fn record_id(physical: &MarkerFreePhysicalManifest, path: &str) -> PhysicalRecordId {
        physical.find(path).expect("fixture record exists").id
    }

    #[test]
    fn exact_index_and_config_snapshots_borrow_bytes_and_redact_debug() {
        let index = b"DIRC\0private-index-body";
        let config = b"[core]\n\trepositoryformatversion = 0\n";
        let target = fixture(index, config);
        let (physical, root) = physical_and_root(&target);

        with_held_target_index_snapshot(&physical, &root, |snapshot| {
            assert!(snapshot.is_bound_to(&physical));
            assert_eq!(snapshot.role(), GitControlRole::Index);
            snapshot.inspect_bytes(|bytes| {
                assert_eq!(bytes, index);
                Ok(())
            })?;
            let debug = format!("{snapshot:?}");
            assert!(!debug.contains("private-index-body"));
            assert!(debug.contains("[REDACTED]"));
            Ok(())
        })
        .expect("exact held index succeeds");

        with_held_target_config_snapshot(&physical, &root, |snapshot| {
            assert!(snapshot.is_bound_to(&physical));
            assert_eq!(snapshot.role(), GitControlRole::Config);
            snapshot.inspect_bytes(|bytes| {
                assert_eq!(bytes, config);
                Ok(())
            })?;
            let debug = format!("{snapshot:?}");
            assert!(!debug.contains("repositoryformatversion"));
            assert!(debug.contains("[REDACTED]"));
            Ok(())
        })
        .expect("exact held config succeeds");
    }

    #[test]
    fn fresh_target_main_ref_accepts_only_the_exact_branded_record() {
        const MAIN_REF: &[u8; 41] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let target = main_ref_fixture(MAIN_REF);
        let (physical, root) = physical_and_root(&target);

        let main_ref = collect_fresh_target_main_ref(&physical, &root)
            .expect("canonical fresh-target main ref collects");
        assert!(main_ref.is_bound_to(&physical));
        assert_eq!(main_ref.record, record_id(&physical, TARGET_MAIN_REF_PATH));
        assert_eq!(main_ref.commit_oid(), [0xaa; 20]);

        let debug = format!("{main_ref:?}");
        assert!(debug.contains("FreshTargetMainRef"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("aaaaaaaa"));
        assert!(!debug.contains("170"));
    }

    #[test]
    fn fresh_target_main_ref_rejects_noncanonical_bodies_and_kind() {
        for body in [
            b"0000000000000000000000000000000000000000\n".as_slice(),
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n".as_slice(),
            b"gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n".as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n".as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n".as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n".as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n!".as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
        ] {
            let target = main_ref_fixture(body);
            let (physical, root) = physical_and_root(&target);
            assert!(
                collect_fresh_target_main_ref(&physical, &root).is_err(),
                "noncanonical body must fail closed"
            );
        }

        let target = main_ref_fixture(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
        let main_ref = target.path().join(TARGET_MAIN_REF_PATH);
        fs::remove_file(&main_ref).expect("main ref removes");
        fs::create_dir(&main_ref).expect("directory replacement creates");
        let (physical, root) = physical_and_root(&target);
        assert!(matches!(
            collect_fresh_target_main_ref(&physical, &root),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[test]
    fn fresh_target_main_ref_rejects_pre_collection_hash_and_identity_drift() {
        const MAIN_REF: &[u8; 41] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";

        let target = main_ref_fixture(MAIN_REF);
        let (physical, root) = physical_and_root(&target);
        fs::write(
            target.path().join(TARGET_MAIN_REF_PATH),
            b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .expect("same-inode same-length pre-collection rewrite succeeds");
        assert!(matches!(
            collect_fresh_target_main_ref(&physical, &root),
            Err(CandidateSealError::InvalidRecord)
        ));

        let target = main_ref_fixture(MAIN_REF);
        let (physical, root) = physical_and_root(&target);
        let main_ref = target.path().join(TARGET_MAIN_REF_PATH);
        fs::rename(&main_ref, target.path().join(".git/refs/heads/old-main"))
            .expect("original main ref retains a name");
        fs::write(&main_ref, MAIN_REF).expect("same-body replacement writes");
        assert!(matches!(
            collect_fresh_target_main_ref(&physical, &root),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[test]
    fn fresh_target_main_ref_brand_is_manifest_allocation_specific() {
        const MAIN_REF: &[u8; 41] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let first_target = main_ref_fixture(MAIN_REF);
        let second_target = main_ref_fixture(MAIN_REF);
        let (first, first_root) = physical_and_root(&first_target);
        let (second, second_root) = physical_and_root(&second_target);

        let main_ref = collect_fresh_target_main_ref(&first, &first_root)
            .expect("first branded main ref collects");
        assert!(main_ref.is_bound_to(&first));
        assert!(!main_ref.is_bound_to(&second));
        assert!(matches!(
            collect_fresh_target_main_ref(&first, &second_root),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[test]
    fn fresh_target_main_ref_rejects_callback_namespace_drift() {
        const MAIN_REF: &[u8; 41] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";

        let target = main_ref_fixture(MAIN_REF);
        let (physical, root) = physical_and_root(&target);
        let main_ref = target.path().join(TARGET_MAIN_REF_PATH);
        let replacement = collect_fresh_target_main_ref_with_hook(&physical, &root, || {
            fs::rename(&main_ref, target.path().join(".git/refs/heads/held-main"))
                .map_err(|_| CandidateSealError::InvalidRecord)?;
            fs::write(&main_ref, MAIN_REF).map_err(|_| CandidateSealError::InvalidRecord)
        });
        assert!(matches!(
            replacement,
            Err(CandidateSealError::InvalidRecord)
        ));

        let target = main_ref_fixture(MAIN_REF);
        let (physical, root) = physical_and_root(&target);
        let refs = target.path().join(".git/refs");
        let ancestor_rebind = collect_fresh_target_main_ref_with_hook(&physical, &root, || {
            fs::rename(&refs, target.path().join(".git/held-refs"))
                .map_err(|_| CandidateSealError::InvalidRecord)?;
            fs::create_dir_all(refs.join("heads"))
                .map_err(|_| CandidateSealError::InvalidRecord)?;
            fs::write(refs.join("heads/main"), MAIN_REF)
                .map_err(|_| CandidateSealError::InvalidRecord)
        });
        assert!(matches!(
            ancestor_rebind,
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[test]
    fn callback_same_inode_rewrite_is_left_to_whole_manifest_revalidation() {
        const MAIN_REF: &[u8; 41] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let target = main_ref_fixture(MAIN_REF);
        let (physical, root) = physical_and_root(&target);
        let main_ref_path = target.path().join(TARGET_MAIN_REF_PATH);

        let main_ref = collect_fresh_target_main_ref_with_hook(&physical, &root, || {
            fs::write(
                &main_ref_path,
                b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            )
            .map_err(|_| CandidateSealError::InvalidRecord)
        })
        .expect("the single snapshot does not claim a callback-time second content hash");
        assert_eq!(main_ref.commit_oid(), [0xaa; 20]);
        assert!(physical.require_current_exact(target.path()).is_err());
    }

    #[test]
    fn exact_limit_succeeds_and_one_byte_over_fails_closed() {
        let target = fixture(b"12345", b"config");
        let (physical, root) = physical_and_root(&target);
        let index_id = record_id(&physical, TARGET_INDEX_PATH);
        let bound = with_held_physical_snapshot(&physical, &root, index_id, 5, |snapshot| {
            assert!(snapshot.is_bound_to(&physical));
            assert_eq!(snapshot.bytes(), b"12345");
            Ok(())
        })
        .expect("exact maximum is accepted and EOF is proved");
        assert!(bound.is_bound_to(&physical));
        assert!(matches!(
            with_held_physical_snapshot(&physical, &root, index_id, 4, |_| Ok(())),
            Err(CandidateSealError::ResourceLimit)
        ));
    }

    #[test]
    fn extra_probe_rejects_append_after_exact_read() {
        let target = fixture(b"12345", b"config");
        let (physical, root) = physical_and_root(&target);
        let index_id = record_id(&physical, TARGET_INDEX_PATH);
        let index_path = target.path().join(TARGET_INDEX_PATH);
        let extra_branch = Cell::new(false);
        let result = with_held_physical_snapshot_with_hook(
            &physical,
            &root,
            index_id,
            5,
            || {
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(&index_path)
                    .map_err(|_| CandidateSealError::InvalidRecord)?;
                file.write_all(b"!")
                    .map_err(|_| CandidateSealError::InvalidRecord)
            },
            || extra_branch.set(true),
            |_| Ok(()),
        );
        assert!(matches!(result, Err(CandidateSealError::InvalidRecord)));
        assert!(
            extra_branch.get(),
            "the one-byte EOF probe observed the append"
        );
    }

    #[test]
    fn missing_role_path_and_directory_kind_are_rejected() {
        let target = fixture(b"index", b"config");
        let (physical, root) = physical_and_root(&target);
        let git_id = record_id(&physical, ".git");

        assert!(matches!(
            exact_file_id(&physical, ".git/missing"),
            Err(CandidateSealError::InvalidRecord)
        ));
        assert!(matches!(
            exact_file_id(&physical, ".git"),
            Err(CandidateSealError::InvalidRecord)
        ));
        assert!(matches!(
            with_held_physical_snapshot(&physical, &root, git_id, 1024, |_| Ok(())),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[test]
    fn same_bytes_replacement_and_ancestor_rebind_fail_post_consume() {
        let target = fixture(b"same-index", b"config");
        let (physical, root) = physical_and_root(&target);
        let index_path = target.path().join(TARGET_INDEX_PATH);
        let held_index = target.path().join(".git/held-index");
        let replaced = with_held_target_index_snapshot(&physical, &root, |_| {
            fs::rename(&index_path, &held_index).expect("original index retains a name");
            fs::write(&index_path, b"same-index").expect("byte-identical replacement writes");
            Ok(())
        });
        assert!(matches!(replaced, Err(CandidateSealError::InvalidRecord)));

        let target = fixture(b"same-index", b"config");
        let (physical, root) = physical_and_root(&target);
        let git = target.path().join(".git");
        let held_git = target.path().join("held-git");
        let rebound = with_held_target_index_snapshot(&physical, &root, |_| {
            fs::rename(&git, &held_git).expect("original Git directory retains a name");
            fs::create_dir(&git).expect("replacement Git directory creates");
            fs::write(git.join("index"), b"same-index").expect("replacement index writes");
            Ok(())
        });
        assert!(matches!(rebound, Err(CandidateSealError::InvalidRecord)));
    }

    #[test]
    fn same_inode_same_length_content_drift_is_rejected_by_initial_sha() {
        let target = fixture(b"before", b"config");
        let (physical, root) = physical_and_root(&target);
        fs::write(target.path().join(TARGET_INDEX_PATH), b"AFTER!")
            .expect("same inode is rewritten at the same length");
        assert!(matches!(
            with_held_target_index_snapshot(&physical, &root, |_| Ok(())),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[test]
    fn callback_time_same_inode_rewrite_requires_later_full_revalidation() {
        let target = fixture(b"before", b"config");
        let (physical, root) = physical_and_root(&target);
        with_held_target_index_snapshot(&physical, &root, |snapshot| {
            snapshot.inspect_bytes(|bytes| {
                assert_eq!(bytes, b"before");
                Ok(())
            })?;
            fs::write(target.path().join(TARGET_INDEX_PATH), b"AFTER!")
                .expect("callback rewrites the same inode at the same length");
            Ok(())
        })
        .expect("single snapshot does not claim a callback-time second content hash");
        assert!(physical.require_current_exact(target.path()).is_err());
    }

    #[test]
    fn hardlink_symlink_and_fifo_replacements_are_rejected() {
        let target = fixture(b"index", b"config");
        let (physical, root) = physical_and_root(&target);
        let index = target.path().join(TARGET_INDEX_PATH);
        let hardlink = target.path().join(".git/index-hardlink");
        fs::hard_link(&index, &hardlink).expect("hard link creates");
        assert!(matches!(
            with_held_target_index_snapshot(&physical, &root, |_| Ok(())),
            Err(CandidateSealError::InvalidRecord)
        ));

        let target = fixture(b"index", b"config");
        let (physical, root) = physical_and_root(&target);
        let index = target.path().join(TARGET_INDEX_PATH);
        fs::remove_file(&index).expect("index removes");
        symlink("config", &index).expect("index symlink creates");
        assert!(matches!(
            with_held_target_index_snapshot(&physical, &root, |_| Ok(())),
            Err(CandidateSealError::InvalidRecord)
        ));

        let target = fixture(b"index", b"config");
        let (physical, root) = physical_and_root(&target);
        let index = target.path().join(TARGET_INDEX_PATH);
        fs::remove_file(&index).expect("index removes");
        create_fifo(&index);
        assert!(matches!(
            with_held_target_index_snapshot(&physical, &root, |_| Ok(())),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[test]
    fn same_layout_snapshots_reject_a_different_manifest_brand() {
        let first_target = fixture(b"same-index", b"same-config");
        let second_target = fixture(b"same-index", b"same-config");
        let (first, first_root) = physical_and_root(&first_target);
        let (second, _) = physical_and_root(&second_target);
        assert_ne!(first.root_identity(), second.root_identity());

        with_held_target_index_snapshot(&first, &first_root, |snapshot| {
            assert!(snapshot.is_bound_to(&first));
            assert!(!snapshot.is_bound_to(&second));
            snapshot.inspect_bytes(|bytes| {
                assert_eq!(bytes, b"same-index");
                Ok(())
            })
        })
        .expect("first index remains bound to first manifest");

        with_held_target_config_snapshot(&first, &first_root, |snapshot| {
            assert!(snapshot.is_bound_to(&first));
            assert!(!snapshot.is_bound_to(&second));
            Ok(())
        })
        .expect("first config remains bound to first manifest");
    }

    #[test]
    fn config_output_parser_accepts_only_the_canonical_allowlist() {
        let driver = "'/opt/inex' merge-driver";
        let mut output = Vec::new();
        for (key, value) in [
            ("core.repositoryformatversion", "0"),
            ("core.filemode", "true"),
            ("core.bare", "false"),
            ("core.logallrefupdates", "true"),
            ("merge.inex.name", super::super::DRIVER_NAME),
            ("merge.inex.driver", driver),
        ] {
            output.extend_from_slice(key.as_bytes());
            output.push(b'\n');
            output.extend_from_slice(value.as_bytes());
            output.push(0);
        }
        validate_target_config_output(&output, driver).expect("canonical config output validates");

        let mut duplicate = output.clone();
        duplicate.extend_from_slice(b"core.bare\nfalse\0");
        assert_eq!(
            validate_target_config_output(&duplicate, driver),
            Err(CandidateSealError::InvalidRecord)
        );
        let mut unknown = output.clone();
        unknown.extend_from_slice(b"include.path\n/tmp/hostile\0");
        assert_eq!(
            validate_target_config_output(&unknown, driver),
            Err(CandidateSealError::InvalidRecord)
        );
        assert_eq!(
            validate_target_config_output(&output[..output.len() - 1], driver),
            Err(CandidateSealError::InvalidRecord)
        );
        assert_eq!(
            validate_target_config_output(&output, "wrong driver"),
            Err(CandidateSealError::InvalidRecord)
        );
    }

    #[test]
    fn held_snapshot_source_keeps_handle_only_ads_checks() {
        let source = include_str!("candidate_control.rs");
        assert!(source.matches("verify_no_alternate_data_streams").count() >= 7);
        assert!(!source.contains(&["std::fs", "::read("].concat()));
        assert!(!source.contains(&["File", "::open("].concat()));
    }
}
