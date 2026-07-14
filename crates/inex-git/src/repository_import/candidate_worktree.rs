//! Fresh, path-borrowing evidence for candidate-seal sections 2, 4, and 5.
//!
//! This is an independently auditable assembler slice, not a publication
//! authority. The caller supplies one already-held target-root descriptor and
//! one transient raw-index body. Raw index paths are compared with paths
//! borrowed from the sole [`MarkerFreePhysicalManifest`]. Tracked files are
//! reopened below that held root and hashed through a bounded buffer. The
//! retained evidence owns only physical record IDs and fixed-size digests.
//!
//! Publication wiring must additionally prove that the transient index body
//! came from the same held target, revalidate the complete physical baseline
//! while the mutation lock is held, and keep that authority through marker
//! publication. The hostile same-UID swap-and-restore boundary also remains a
//! later process/authority gate. This module intentionally does not claim
//! those later steps. This slice does bind `.gitattributes` and `.gitignore`
//! to the target's canonical bytes. `vault.json` remains bound to its physical
//! identity, size, digest, and blob OID here; authenticated vault semantics are
//! deliberately a later assembler responsibility.

use std::cmp::Ordering;
use std::fmt;

#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::io::Read as _;

use inex_core::atomic::{PublicationIdentityScheme, VAULT_LOCAL_DIRECTORY};
#[cfg(target_os = "linux")]
use inex_core::atomic::{SecureSourceChild, SecureSourceDirectory, SecureSourceFile};
use inex_core::path::{PortableCaseFoldFingerprint, raw_portable_case_fold_fingerprint};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use crate::raw_index::{RawIndexError, validate_target_sha1_index_paths};

use super::candidate_manifest::{
    MarkerFreePhysicalManifest, PhysicalRecordId, PhysicalRecordKindRef,
};
use super::candidate_seal::{
    CandidateFileIdentity, CandidateSealError, IndexRecord, TreeRecord, WorktreeClass,
    WorktreeRecord,
};
use super::{TARGET_ATTRIBUTES, TARGET_IGNORE};

const GIT_DIRECTORY: &str = ".git";
const VAULT_METADATA_FILE: &str = "vault.json";
const MAX_TRACKED_RECORDS: usize = 100_003;
const MAX_TREE_RECORDS: usize = 1_000_000;
const MAX_SEMANTIC_PATH_BYTES: usize = 1_024;
const MAX_MARKDOWN_FILE_COMPONENT_BYTES: usize = 251;
const MAX_ASSET_FILE_COMPONENT_BYTES: usize = 245;
const MAX_PATH_BUDGET: usize = 256 * 1024 * 1024;
const MAX_BODY_BYTES: u64 = 68 * 1024 * 1024;
#[cfg(target_os = "linux")]
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const MARKDOWN_CIPHERTEXT_SUFFIX: &str = ".md.enc";
const ASSET_CIPHERTEXT_SUFFIX: &str = ".asset.enc";

/// Fixed-size section-2/4 evidence bound to one physical manifest record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct FreshTrackedEvidence {
    physical: PhysicalRecordId,
    class: WorktreeClass,
    blob_oid: [u8; 20],
}

impl fmt::Debug for FreshTrackedEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTrackedEvidence")
            .field("physical", &self.physical)
            .field("class", &self.class)
            .field("blob_oid", &"[REDACTED]")
            .finish()
    }
}

impl FreshTrackedEvidence {
    /// Borrow the canonical path only while projecting sections 2 and 4.
    fn project<'a>(
        &self,
        physical: &'a MarkerFreePhysicalManifest,
        scheme: PublicationIdentityScheme,
    ) -> Result<(WorktreeRecord<'a>, IndexRecord<'a>), CandidateSealError> {
        let record = physical
            .record(self.physical)
            .ok_or(CandidateSealError::InvalidRecord)?;
        let PhysicalRecordKindRef::File {
            identity,
            size,
            sha256,
        } = record.kind
        else {
            return Err(CandidateSealError::InvalidRecord);
        };
        let reserved = ReservedFingerprints::new();
        if classify_file(record.path, reserved)? != FileDisposition::Tracked(self.class)
            || is_zero_oid(&self.blob_oid)
        {
            return Err(CandidateSealError::InvalidRecord);
        }
        let identity = CandidateFileIdentity::from_observed(identity, scheme)?;
        Ok((
            WorktreeRecord {
                path: record.path,
                class: self.class,
                identity,
                size,
                sha256: *sha256,
                blob_oid: self.blob_oid,
            },
            IndexRecord {
                path: record.path,
                blob_oid: self.blob_oid,
            },
        ))
    }
}

/// Fixed-size section-5 evidence bound to one physical directory record.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct FreshTreeEvidence {
    directory: PhysicalRecordId,
    tree_oid: [u8; 20],
    raw_size: u64,
    raw_sha256: [u8; 32],
}

impl fmt::Debug for FreshTreeEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTreeEvidence")
            .field("directory", &self.directory)
            .field("tree_oid", &"[REDACTED]")
            .field("raw_size", &self.raw_size)
            .field("raw_sha256", &"[REDACTED]")
            .finish()
    }
}

impl FreshTreeEvidence {
    /// Borrow the canonical directory path only while projecting section 5.
    fn project<'a>(
        &self,
        physical: &'a MarkerFreePhysicalManifest,
    ) -> Result<TreeRecord<'a>, CandidateSealError> {
        let record = physical
            .record(self.directory)
            .ok_or(CandidateSealError::InvalidRecord)?;
        if !matches!(record.kind, PhysicalRecordKindRef::Directory(_))
            || record.path.len() > MAX_SEMANTIC_PATH_BYTES
            || self.raw_size > MAX_BODY_BYTES
            || is_zero_oid(&self.tree_oid)
        {
            return Err(CandidateSealError::InvalidRecord);
        }
        Ok(TreeRecord {
            path: record.path,
            tree_oid: self.tree_oid,
            raw_size: self.raw_size,
            raw_sha256: self.raw_sha256,
        })
    }
}

/// Opaque section-2/4 evidence tied to the one manifest that lent its paths.
pub(super) struct FreshTrackedManifest<'a> {
    physical: &'a MarkerFreePhysicalManifest,
    records: Vec<FreshTrackedEvidence>,
}

impl fmt::Debug for FreshTrackedManifest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTrackedManifest")
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl<'a> FreshTrackedManifest<'a> {
    /// Project the bound evidence without allowing record IDs or OIDs to be
    /// substituted against a different physical manifest.
    pub(super) fn project(
        &self,
        scheme: PublicationIdentityScheme,
    ) -> Result<(Vec<WorktreeRecord<'a>>, Vec<IndexRecord<'a>>), CandidateSealError> {
        validate_fresh_tracked_evidence(self.physical, &self.records)?;
        let mut worktree = Vec::new();
        let mut index = Vec::new();
        worktree
            .try_reserve_exact(self.records.len())
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        index
            .try_reserve_exact(self.records.len())
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        for record in &self.records {
            let (worktree_record, index_record) = record.project(self.physical, scheme)?;
            worktree.push(worktree_record);
            index.push(index_record);
        }
        Ok((worktree, index))
    }
}

/// Opaque section-5 evidence tied to the same physical manifest.
pub(super) struct FreshTreeManifest<'a> {
    physical: &'a MarkerFreePhysicalManifest,
    records: Vec<FreshTreeEvidence>,
}

impl fmt::Debug for FreshTreeManifest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTreeManifest")
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl<'a> FreshTreeManifest<'a> {
    /// Project root-first canonical section-5 records from the bound manifest.
    pub(super) fn project(&self) -> Result<Vec<TreeRecord<'a>>, CandidateSealError> {
        let mut trees = Vec::new();
        trees
            .try_reserve_exact(self.records.len())
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        for record in &self.records {
            trees.push(record.project(self.physical)?);
        }
        Ok(trees)
    }
}

#[derive(Clone, Copy)]
struct ClassifiedTracked {
    physical: PhysicalRecordId,
    class: WorktreeClass,
}

/// Validate one transient raw index and bind every index OID to a freshly
/// streamed file below the same already-held target-root descriptor.
///
/// The index body is borrowed and is never retained by the returned evidence.
/// Its descriptor/identity/control-manifest binding remains a caller-owned
/// section-8 responsibility.
#[cfg(target_os = "linux")]
pub(super) fn collect_fresh_tracked_evidence<'a>(
    physical: &'a MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    raw_index: &[u8],
) -> Result<FreshTrackedManifest<'a>, CandidateSealError> {
    if held_root.identity() != physical.root_identity() {
        return Err(CandidateSealError::InvalidRecord);
    }
    held_root
        .verify_no_alternate_data_streams()
        .map_err(|_| CandidateSealError::InvalidRecord)?;

    let classified = classify_tracked_records(physical)?;
    let mut expected_paths = Vec::new();
    expected_paths
        .try_reserve_exact(classified.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for tracked in &classified {
        let record = physical
            .record(tracked.physical)
            .ok_or(CandidateSealError::InvalidRecord)?;
        expected_paths.push(record.path.as_bytes());
    }
    let summary = validate_target_sha1_index_paths(raw_index, &expected_paths)
        .map_err(map_raw_index_error)?;
    drop(expected_paths);
    if summary.oids.len() != classified.len() {
        return Err(CandidateSealError::InvalidRecord);
    }

    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(classified.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for (tracked, index_oid) in classified.into_iter().zip(summary.oids) {
        let blob_oid = stream_bound_blob(physical, held_root, tracked.physical)?;
        if blob_oid != index_oid || is_zero_oid(&blob_oid) {
            return Err(CandidateSealError::InvalidRecord);
        }
        evidence.push(FreshTrackedEvidence {
            physical: tracked.physical,
            class: tracked.class,
            blob_oid,
        });
    }
    held_root
        .verify_no_alternate_data_streams()
        .map_err(|_| CandidateSealError::InvalidRecord)?;
    validate_fresh_tracked_evidence(physical, &evidence)?;
    Ok(FreshTrackedManifest {
        physical,
        records: evidence,
    })
}

#[cfg(target_os = "linux")]
const fn map_raw_index_error(error: RawIndexError) -> CandidateSealError {
    match error {
        RawIndexError::ResourceLimit => CandidateSealError::ResourceLimit,
        RawIndexError::Malformed | RawIndexError::Unsupported => CandidateSealError::InvalidRecord,
    }
}

#[cfg(target_os = "linux")]
fn stream_bound_blob(
    physical: &MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    physical_id: PhysicalRecordId,
) -> Result<[u8; 20], CandidateSealError> {
    stream_bound_blob_with_hook(physical, held_root, physical_id, || {})
}

#[cfg(target_os = "linux")]
fn stream_bound_blob_with_hook(
    physical: &MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    physical_id: PhysicalRecordId,
    after_stream: impl FnOnce(),
) -> Result<[u8; 20], CandidateSealError> {
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
    if expected_size > MAX_BODY_BYTES {
        return Err(CandidateSealError::ResourceLimit);
    }

    let (mut file, directories) = open_bound_file(physical, held_root, expected.path)?;
    file.verify_no_alternate_data_streams()
        .map_err(|_| CandidateSealError::InvalidRecord)?;
    if file
        .observed_len()
        .map_err(|_| CandidateSealError::InvalidRecord)?
        != expected_size
        || file
            .identity()
            .map_err(|_| CandidateSealError::InvalidRecord)?
            != *expected_identity
    {
        return Err(CandidateSealError::InvalidRecord);
    }

    let mut typed_sha1 = Sha1::new();
    typed_sha1.update(b"blob ");
    let mut decimal = [0_u8; 20];
    typed_sha1.update(decimal_u64(expected_size, &mut decimal));
    typed_sha1.update([0]);
    let mut raw_sha256 = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0_u8; STREAM_BUFFER_BYTES]);
    let mut observed = 0_u64;
    loop {
        let read = file
            .read(buffer.as_mut_slice())
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(read).map_err(|_| CandidateSealError::ResourceLimit)?)
            .filter(|value| *value <= expected_size)
            .ok_or(CandidateSealError::InvalidRecord)?;
        typed_sha1.update(&buffer[..read]);
        raw_sha256.update(&buffer[..read]);
    }
    let observed_sha256: [u8; 32] = raw_sha256.finalize().into();
    after_stream();
    if observed != expected_size
        || observed_sha256 != *expected_sha256
        || file
            .observed_len()
            .map_err(|_| CandidateSealError::InvalidRecord)?
            != expected_size
        || file
            .identity()
            .map_err(|_| CandidateSealError::InvalidRecord)?
            != *expected_identity
        || file.verify_no_alternate_data_streams().is_err()
    {
        return Err(CandidateSealError::InvalidRecord);
    }
    for directory in directories.iter().rev() {
        directory
            .verify_no_alternate_data_streams()
            .map_err(|_| CandidateSealError::InvalidRecord)?;
    }
    held_root
        .verify_no_alternate_data_streams()
        .map_err(|_| CandidateSealError::InvalidRecord)?;
    Ok(typed_sha1.finalize().into())
}

#[cfg(target_os = "linux")]
fn open_bound_file(
    physical: &MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    path: &str,
) -> Result<(SecureSourceFile, Vec<SecureSourceDirectory>), CandidateSealError> {
    let mut directories = Vec::new();
    let mut components = path.split('/').peekable();
    let mut prefix_end = 0_usize;
    while let Some(component) = components.next() {
        if component.is_empty() {
            return Err(CandidateSealError::InvalidRecord);
        }
        let parent = directories.last().unwrap_or(held_root);
        let child = parent
            .open_child(OsStr::new(component))
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        prefix_end = prefix_end
            .checked_add(component.len())
            .ok_or(CandidateSealError::ResourceLimit)?;
        if components.peek().is_none() {
            return match child {
                SecureSourceChild::File(file) => Ok((file, directories)),
                SecureSourceChild::Directory(_) | SecureSourceChild::Other => {
                    Err(CandidateSealError::InvalidRecord)
                }
            };
        }

        let SecureSourceChild::Directory(directory) = child else {
            return Err(CandidateSealError::InvalidRecord);
        };
        let expected_directory = physical
            .find(
                path.get(..prefix_end)
                    .ok_or(CandidateSealError::InvalidRecord)?,
            )
            .ok_or(CandidateSealError::InvalidRecord)?;
        if !matches!(
            expected_directory.kind,
            PhysicalRecordKindRef::Directory(identity) if identity == directory.identity()
        ) {
            return Err(CandidateSealError::InvalidRecord);
        }
        directory
            .verify_no_alternate_data_streams()
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        directories
            .try_reserve(1)
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        directories.push(directory);
        prefix_end = prefix_end
            .checked_add(1)
            .ok_or(CandidateSealError::ResourceLimit)?;
    }
    Err(CandidateSealError::InvalidRecord)
}

/// Validate exact section-2/4 membership without retaining path bytes.
fn validate_fresh_tracked_evidence(
    physical: &MarkerFreePhysicalManifest,
    evidence: &[FreshTrackedEvidence],
) -> Result<(), CandidateSealError> {
    if evidence.len() > MAX_TRACKED_RECORDS {
        return Err(CandidateSealError::ResourceLimit);
    }
    let reserved = ReservedFingerprints::new();
    let mut evidence_index = 0_usize;
    let mut path_budget = 0_usize;
    let mut metadata = 0_u8;

    for record in physical.records() {
        if !matches!(record.kind, PhysicalRecordKindRef::File { .. }) {
            continue;
        }
        let FileDisposition::Tracked(class) = classify_file(record.path, reserved)? else {
            continue;
        };
        let tracked = evidence
            .get(evidence_index)
            .ok_or(CandidateSealError::InvalidRecord)?;
        if tracked.physical != record.id || tracked.class != class || is_zero_oid(&tracked.blob_oid)
        {
            return Err(CandidateSealError::InvalidRecord);
        }
        path_budget = advance_path_budget(path_budget, record.path.len())?;
        if class == WorktreeClass::ManagedMetadata {
            require_canonical_managed_metadata(record.path, record.kind)?;
            let bit = managed_metadata_bit(record.path).ok_or(CandidateSealError::InvalidRecord)?;
            if metadata & bit != 0 {
                return Err(CandidateSealError::InvalidRecord);
            }
            metadata |= bit;
        }
        evidence_index = evidence_index
            .checked_add(1)
            .ok_or(CandidateSealError::ResourceLimit)?;
    }
    if evidence_index != evidence.len() || metadata != 0b111 {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

fn classify_tracked_records(
    physical: &MarkerFreePhysicalManifest,
) -> Result<Vec<ClassifiedTracked>, CandidateSealError> {
    let mut classified = Vec::new();
    classified
        .try_reserve(physical.records().len().min(MAX_TRACKED_RECORDS))
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    let reserved = ReservedFingerprints::new();
    let mut path_budget = 0_usize;
    let mut metadata = 0_u8;
    for record in physical.records() {
        if !matches!(record.kind, PhysicalRecordKindRef::File { .. }) {
            continue;
        }
        let FileDisposition::Tracked(class) = classify_file(record.path, reserved)? else {
            continue;
        };
        if classified.len() >= MAX_TRACKED_RECORDS {
            return Err(CandidateSealError::ResourceLimit);
        }
        path_budget = advance_path_budget(path_budget, record.path.len())?;
        if class == WorktreeClass::ManagedMetadata {
            require_canonical_managed_metadata(record.path, record.kind)?;
            let bit = managed_metadata_bit(record.path).ok_or(CandidateSealError::InvalidRecord)?;
            if metadata & bit != 0 {
                return Err(CandidateSealError::InvalidRecord);
            }
            metadata |= bit;
        }
        classified.push(ClassifiedTracked {
            physical: record.id,
            class,
        });
    }
    if metadata != 0b111 {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(classified)
}

/// Construct section-5 evidence from fixed-size parent/child ID edges.
///
/// Each tree body is sized in a first pass and fed directly into typed SHA-1
/// and raw SHA-256 in a second pass. No raw tree body is ever constructed.
pub(super) fn construct_fresh_tree_evidence<'a>(
    tracked: &FreshTrackedManifest<'a>,
) -> Result<FreshTreeManifest<'a>, CandidateSealError> {
    let physical = tracked.physical;
    let tracked = tracked.records.as_slice();
    validate_fresh_tracked_evidence(physical, tracked)?;
    let reserved = ReservedFingerprints::new();
    let directory_ids = relevant_directory_ids(physical, tracked)?;
    if directory_ids.len() > MAX_TREE_RECORDS {
        return Err(CandidateSealError::ResourceLimit);
    }
    require_exact_content_directories(physical, &directory_ids, reserved)?;
    let nodes = directory_nodes(physical, &directory_ids)?;
    let mut file_edges = tracked_edges(physical, tracked, &directory_ids)?;
    let mut directory_edges = child_directory_edges(&nodes)?;
    file_edges.sort_unstable_by_key(|edge| (edge.parent, edge.child));
    directory_edges.sort_unstable_by_key(|edge| (edge.parent, edge.child));

    let mut traversal = Vec::new();
    traversal
        .try_reserve_exact(nodes.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    traversal.extend(0..nodes.len());
    traversal.sort_unstable_by(|left, right| {
        nodes[*right]
            .depth
            .cmp(&nodes[*left].depth)
            .then_with(|| nodes[*left].directory.cmp(&nodes[*right].directory))
    });

    let mut computed: Vec<Option<TreeDigest>> = Vec::new();
    computed
        .try_reserve_exact(nodes.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    computed.resize(nodes.len(), None);
    for node_index in traversal {
        let current = nodes[node_index].directory;
        let file_range = edge_range(&file_edges, current, |edge| edge.parent);
        let directory_range = edge_range(&directory_edges, current, |edge| edge.parent);
        let capacity = file_range
            .len()
            .checked_add(directory_range.len())
            .ok_or(CandidateSealError::ResourceLimit)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        for edge in &file_edges[file_range] {
            entries.push(FreshTreeEntry {
                physical: edge.child,
                oid: edge.oid,
                directory: false,
            });
        }
        for edge in &directory_edges[directory_range] {
            let digest = computed
                .get(edge.child_index)
                .copied()
                .flatten()
                .ok_or(CandidateSealError::InvalidRecord)?;
            entries.push(FreshTreeEntry {
                physical: edge.child,
                oid: digest.tree_oid,
                directory: true,
            });
        }
        let (tree_oid, raw_size, raw_sha256) = stream_canonical_tree(physical, &mut entries)?;
        computed[node_index] = Some(TreeDigest {
            tree_oid,
            raw_size,
            raw_sha256,
        });
    }

    let mut trees = Vec::new();
    trees
        .try_reserve_exact(nodes.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    let mut path_budget = 0_usize;
    for (node, digest) in nodes.iter().zip(computed) {
        let digest = digest.ok_or(CandidateSealError::InvalidRecord)?;
        let record = physical
            .record(node.directory)
            .ok_or(CandidateSealError::InvalidRecord)?;
        path_budget = advance_path_budget(path_budget, record.path.len())?;
        trees.push(FreshTreeEvidence {
            directory: node.directory,
            tree_oid: digest.tree_oid,
            raw_size: digest.raw_size,
            raw_sha256: digest.raw_sha256,
        });
    }
    if trees.first().is_none_or(|tree| {
        physical
            .record(tree.directory)
            .is_none_or(|record| !record.path.is_empty())
    }) {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(FreshTreeManifest {
        physical,
        records: trees,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FileDisposition {
    Control,
    Tracked(WorktreeClass),
}

#[derive(Clone, Copy)]
struct ReservedFingerprints {
    git: PortableCaseFoldFingerprint,
    local: PortableCaseFoldFingerprint,
    vault_metadata: PortableCaseFoldFingerprint,
}

impl ReservedFingerprints {
    fn new() -> Self {
        Self {
            git: raw_portable_case_fold_fingerprint(GIT_DIRECTORY),
            local: raw_portable_case_fold_fingerprint(VAULT_LOCAL_DIRECTORY),
            vault_metadata: raw_portable_case_fold_fingerprint(VAULT_METADATA_FILE),
        }
    }
}

fn classify_file(
    path: &str,
    reserved: ReservedFingerprints,
) -> Result<FileDisposition, CandidateSealError> {
    if is_control_path(path) {
        return Ok(FileDisposition::Control);
    }
    if managed_metadata_bit(path).is_some() {
        return Ok(FileDisposition::Tracked(WorktreeClass::ManagedMetadata));
    }
    let (class, semantic_path, maximum_final_component) =
        if path.ends_with(MARKDOWN_CIPHERTEXT_SUFFIX) {
            let semantic = path
                .strip_suffix(".enc")
                .ok_or(CandidateSealError::InvalidRecord)?;
            (
                WorktreeClass::MarkdownEnvelope,
                semantic,
                MAX_MARKDOWN_FILE_COMPONENT_BYTES,
            )
        } else if let Some(semantic) = path.strip_suffix(ASSET_CIPHERTEXT_SUFFIX) {
            if semantic.as_bytes().ends_with(b".md") {
                return Err(CandidateSealError::InvalidRecord);
            }
            (
                WorktreeClass::AssetEnvelope,
                semantic,
                MAX_ASSET_FILE_COMPONENT_BYTES,
            )
        } else {
            return Err(CandidateSealError::InvalidRecord);
        };
    if class == WorktreeClass::MarkdownEnvelope && !path.ends_with(MARKDOWN_CIPHERTEXT_SUFFIX) {
        return Err(CandidateSealError::InvalidRecord);
    }
    validate_semantic_content_path(path, semantic_path, maximum_final_component, reserved)?;
    Ok(FileDisposition::Tracked(class))
}

fn validate_semantic_content_path(
    physical_path: &str,
    semantic_path: &str,
    maximum_final_component: usize,
    reserved: ReservedFingerprints,
) -> Result<(), CandidateSealError> {
    if physical_path.is_empty()
        || semantic_path.is_empty()
        || physical_path.len() > MAX_SEMANTIC_PATH_BYTES
        || semantic_path.len() > MAX_SEMANTIC_PATH_BYTES
    {
        return Err(
            if physical_path.len() > MAX_SEMANTIC_PATH_BYTES
                || semantic_path.len() > MAX_SEMANTIC_PATH_BYTES
            {
                CandidateSealError::ResourceLimit
            } else {
                CandidateSealError::InvalidRecord
            },
        );
    }
    let mut components = semantic_path.split('/').peekable();
    let mut index = 0_usize;
    while let Some(component) = components.next() {
        let fingerprint = raw_portable_case_fold_fingerprint(component);
        if fingerprint == reserved.git || fingerprint == reserved.local {
            return Err(CandidateSealError::InvalidRecord);
        }
        if index == 0 && fingerprint == reserved.vault_metadata {
            return Err(CandidateSealError::InvalidRecord);
        }
        if components.peek().is_none()
            && (component.is_empty()
                || component.len() > maximum_final_component
                || component.ends_with(['.', ' ']))
        {
            return Err(if component.len() > maximum_final_component {
                CandidateSealError::ResourceLimit
            } else {
                CandidateSealError::InvalidRecord
            });
        }
        index = index
            .checked_add(1)
            .ok_or(CandidateSealError::ResourceLimit)?;
    }
    Ok(())
}

fn is_control_path(path: &str) -> bool {
    [GIT_DIRECTORY, VAULT_LOCAL_DIRECTORY]
        .into_iter()
        .any(|root| {
            path == root
                || path
                    .strip_prefix(root)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
}

fn managed_metadata_bit(path: &str) -> Option<u8> {
    match path {
        ".gitattributes" => Some(0b001),
        ".gitignore" => Some(0b010),
        VAULT_METADATA_FILE => Some(0b100),
        _ => None,
    }
}

fn require_canonical_managed_metadata(
    path: &str,
    kind: PhysicalRecordKindRef<'_>,
) -> Result<(), CandidateSealError> {
    let expected = match path {
        ".gitattributes" => Some(TARGET_ATTRIBUTES),
        ".gitignore" => Some(TARGET_IGNORE),
        VAULT_METADATA_FILE => None,
        _ => return Err(CandidateSealError::InvalidRecord),
    };
    let Some(expected) = expected else {
        return Ok(());
    };
    let PhysicalRecordKindRef::File { size, sha256, .. } = kind else {
        return Err(CandidateSealError::InvalidRecord);
    };
    let expected_size =
        u64::try_from(expected.len()).map_err(|_| CandidateSealError::ResourceLimit)?;
    let expected_sha256: [u8; 32] = Sha256::digest(expected).into();
    if size != expected_size || *sha256 != expected_sha256 {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

fn relevant_directory_ids(
    physical: &MarkerFreePhysicalManifest,
    tracked: &[FreshTrackedEvidence],
) -> Result<Vec<PhysicalRecordId>, CandidateSealError> {
    let root = physical.find("").ok_or(CandidateSealError::InvalidRecord)?;
    if !matches!(root.kind, PhysicalRecordKindRef::Directory(_)) {
        return Err(CandidateSealError::InvalidRecord);
    }
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(physical.directory_count().min(MAX_TREE_RECORDS))
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for record in physical.records() {
        if matches!(record.kind, PhysicalRecordKindRef::Directory(_))
            && (record.path.is_empty() || !is_control_path(record.path))
        {
            if candidates.len() >= MAX_TREE_RECORDS {
                return Err(CandidateSealError::ResourceLimit);
            }
            candidates.push(record.id);
        }
    }
    if candidates.first().copied() != Some(root.id) {
        return Err(CandidateSealError::InvalidRecord);
    }
    let mut relevant = Vec::new();
    relevant
        .try_reserve_exact(candidates.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    relevant.resize(candidates.len(), false);
    relevant[0] = true;
    for evidence in tracked {
        let record = physical
            .record(evidence.physical)
            .ok_or(CandidateSealError::InvalidRecord)?;
        let mut path = record.path;
        loop {
            let parent = parent_path(path);
            let directory = physical
                .find(parent)
                .ok_or(CandidateSealError::InvalidRecord)?;
            if !matches!(directory.kind, PhysicalRecordKindRef::Directory(_)) {
                return Err(CandidateSealError::InvalidRecord);
            }
            let index = candidates
                .binary_search(&directory.id)
                .map_err(|_| CandidateSealError::InvalidRecord)?;
            if relevant[index] {
                break;
            }
            relevant[index] = true;
            if parent.is_empty() {
                break;
            }
            path = parent;
        }
    }
    let mut directories = Vec::new();
    directories
        .try_reserve_exact(relevant.iter().filter(|value| **value).count())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for (directory, include) in candidates.into_iter().zip(relevant) {
        if include {
            directories.push(directory);
        }
    }
    Ok(directories)
}

fn require_exact_content_directories(
    physical: &MarkerFreePhysicalManifest,
    relevant: &[PhysicalRecordId],
    reserved: ReservedFingerprints,
) -> Result<(), CandidateSealError> {
    for record in physical.records() {
        if !matches!(record.kind, PhysicalRecordKindRef::Directory(_))
            || record.path.is_empty()
            || is_control_path(record.path)
        {
            continue;
        }
        validate_content_directory_path(record.path, reserved)?;
        if relevant.binary_search(&record.id).is_err() {
            return Err(CandidateSealError::InvalidRecord);
        }
    }
    Ok(())
}

fn validate_content_directory_path(
    path: &str,
    reserved: ReservedFingerprints,
) -> Result<(), CandidateSealError> {
    if path.is_empty() || path.len() > MAX_SEMANTIC_PATH_BYTES {
        return Err(if path.len() > MAX_SEMANTIC_PATH_BYTES {
            CandidateSealError::ResourceLimit
        } else {
            CandidateSealError::InvalidRecord
        });
    }
    for (index, component) in path.split('/').enumerate() {
        let fingerprint = raw_portable_case_fold_fingerprint(component);
        if fingerprint == reserved.git
            || fingerprint == reserved.local
            || (index == 0 && fingerprint == reserved.vault_metadata)
        {
            return Err(CandidateSealError::InvalidRecord);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DirectoryNode {
    directory: PhysicalRecordId,
    parent: Option<PhysicalRecordId>,
    depth: usize,
}

fn directory_nodes(
    physical: &MarkerFreePhysicalManifest,
    directory_ids: &[PhysicalRecordId],
) -> Result<Vec<DirectoryNode>, CandidateSealError> {
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(directory_ids.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for directory in directory_ids {
        let record = physical
            .record(*directory)
            .ok_or(CandidateSealError::InvalidRecord)?;
        if !matches!(record.kind, PhysicalRecordKindRef::Directory(_)) {
            return Err(CandidateSealError::InvalidRecord);
        }
        let parent = if record.path.is_empty() {
            None
        } else {
            let parent = physical
                .find(parent_path(record.path))
                .ok_or(CandidateSealError::InvalidRecord)?;
            if directory_ids.binary_search(&parent.id).is_err() {
                return Err(CandidateSealError::InvalidRecord);
            }
            Some(parent.id)
        };
        nodes.push(DirectoryNode {
            directory: *directory,
            parent,
            depth: path_depth(record.path),
        });
    }
    if nodes.first().is_none_or(|node| {
        node.parent.is_some()
            || physical
                .record(node.directory)
                .is_none_or(|record| !record.path.is_empty())
    }) {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(nodes)
}

#[derive(Clone, Copy)]
struct TrackedEdge {
    parent: PhysicalRecordId,
    child: PhysicalRecordId,
    oid: [u8; 20],
}

fn tracked_edges(
    physical: &MarkerFreePhysicalManifest,
    tracked: &[FreshTrackedEvidence],
    directories: &[PhysicalRecordId],
) -> Result<Vec<TrackedEdge>, CandidateSealError> {
    let mut edges = Vec::new();
    edges
        .try_reserve_exact(tracked.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for tracked in tracked {
        let record = physical
            .record(tracked.physical)
            .ok_or(CandidateSealError::InvalidRecord)?;
        let parent = physical
            .find(parent_path(record.path))
            .ok_or(CandidateSealError::InvalidRecord)?;
        if directories.binary_search(&parent.id).is_err() {
            return Err(CandidateSealError::InvalidRecord);
        }
        edges.push(TrackedEdge {
            parent: parent.id,
            child: tracked.physical,
            oid: tracked.blob_oid,
        });
    }
    Ok(edges)
}

#[derive(Clone, Copy)]
struct DirectoryEdge {
    parent: PhysicalRecordId,
    child: PhysicalRecordId,
    child_index: usize,
}

fn child_directory_edges(
    nodes: &[DirectoryNode],
) -> Result<Vec<DirectoryEdge>, CandidateSealError> {
    let mut edges = Vec::new();
    edges
        .try_reserve_exact(nodes.len().saturating_sub(1))
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for (child_index, node) in nodes.iter().enumerate() {
        if let Some(parent) = node.parent {
            edges.push(DirectoryEdge {
                parent,
                child: node.directory,
                child_index,
            });
        }
    }
    Ok(edges)
}

fn edge_range<T>(
    edges: &[T],
    parent: PhysicalRecordId,
    key: impl Fn(&T) -> PhysicalRecordId,
) -> std::ops::Range<usize> {
    let start = edges.partition_point(|edge| key(edge) < parent);
    let end = edges.partition_point(|edge| key(edge) <= parent);
    start..end
}

#[derive(Clone, Copy)]
struct TreeDigest {
    tree_oid: [u8; 20],
    raw_size: u64,
    raw_sha256: [u8; 32],
}

#[derive(Clone, Copy)]
struct FreshTreeEntry {
    physical: PhysicalRecordId,
    oid: [u8; 20],
    directory: bool,
}

fn stream_canonical_tree(
    physical: &MarkerFreePhysicalManifest,
    entries: &mut [FreshTreeEntry],
) -> Result<([u8; 20], u64, [u8; 32]), CandidateSealError> {
    for entry in entries.iter() {
        validate_tree_entry(physical, *entry)?;
    }
    entries.sort_unstable_by(|left, right| tree_entry_order(physical, *left, *right));
    for pair in entries.windows(2) {
        if tree_entry_name(physical, pair[0])? == tree_entry_name(physical, pair[1])? {
            return Err(CandidateSealError::InvalidRecord);
        }
    }

    let mut raw_size = 0_u64;
    for entry in entries.iter() {
        let name = tree_entry_name(physical, *entry)?;
        let mode_length = if entry.directory { 6_u64 } else { 7_u64 };
        let name_length =
            u64::try_from(name.len()).map_err(|_| CandidateSealError::ResourceLimit)?;
        raw_size = raw_size
            .checked_add(mode_length)
            .and_then(|size| size.checked_add(name_length))
            .and_then(|size| size.checked_add(1 + 20))
            .filter(|size| *size <= MAX_BODY_BYTES)
            .ok_or(CandidateSealError::ResourceLimit)?;
    }

    let mut typed_sha1 = Sha1::new();
    typed_sha1.update(b"tree ");
    let mut decimal = [0_u8; 20];
    typed_sha1.update(decimal_u64(raw_size, &mut decimal));
    typed_sha1.update([0]);
    let mut raw_sha256 = Sha256::new();
    for entry in entries.iter() {
        let name = tree_entry_name(physical, *entry)?;
        let mode: &[u8] = if entry.directory {
            b"40000 "
        } else {
            b"100644 "
        };
        update_tree_hashes(&mut typed_sha1, &mut raw_sha256, mode);
        update_tree_hashes(&mut typed_sha1, &mut raw_sha256, name.as_bytes());
        update_tree_hashes(&mut typed_sha1, &mut raw_sha256, &[0]);
        update_tree_hashes(&mut typed_sha1, &mut raw_sha256, &entry.oid);
    }
    Ok((
        typed_sha1.finalize().into(),
        raw_size,
        raw_sha256.finalize().into(),
    ))
}

fn validate_tree_entry(
    physical: &MarkerFreePhysicalManifest,
    entry: FreshTreeEntry,
) -> Result<(), CandidateSealError> {
    let record = physical
        .record(entry.physical)
        .ok_or(CandidateSealError::InvalidRecord)?;
    let kind_matches =
        matches!(record.kind, PhysicalRecordKindRef::Directory(_)) == entry.directory;
    let name = record.path.rsplit('/').next().unwrap_or_default();
    if !kind_matches || name.is_empty() || name.as_bytes().contains(&0) || is_zero_oid(&entry.oid) {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

fn tree_entry_name(
    physical: &MarkerFreePhysicalManifest,
    entry: FreshTreeEntry,
) -> Result<&str, CandidateSealError> {
    physical
        .record(entry.physical)
        .and_then(|record| record.path.rsplit('/').next())
        .filter(|name| !name.is_empty())
        .ok_or(CandidateSealError::InvalidRecord)
}

fn tree_entry_order(
    physical: &MarkerFreePhysicalManifest,
    left: FreshTreeEntry,
    right: FreshTreeEntry,
) -> Ordering {
    let Some(left_name) = physical
        .record(left.physical)
        .and_then(|record| record.path.rsplit('/').next())
    else {
        return Ordering::Equal;
    };
    let Some(right_name) = physical
        .record(right.physical)
        .and_then(|record| record.path.rsplit('/').next())
    else {
        return Ordering::Equal;
    };
    left_name
        .bytes()
        .chain(left.directory.then_some(b'/'))
        .cmp(right_name.bytes().chain(right.directory.then_some(b'/')))
}

fn update_tree_hashes(typed_sha1: &mut Sha1, raw_sha256: &mut Sha256, bytes: &[u8]) {
    typed_sha1.update(bytes);
    raw_sha256.update(bytes);
}

fn decimal_u64(mut value: u64, buffer: &mut [u8; 20]) -> &[u8] {
    let mut cursor = buffer.len();
    loop {
        cursor -= 1;
        buffer[cursor] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        if value == 0 {
            return &buffer[cursor..];
        }
    }
}

fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn path_depth(path: &str) -> usize {
    if path.is_empty() {
        0
    } else {
        path.bytes().filter(|byte| *byte == b'/').count() + 1
    }
}

fn advance_path_budget(current: usize, added: usize) -> Result<usize, CandidateSealError> {
    current
        .checked_add(added)
        .filter(|total| *total <= MAX_PATH_BUDGET)
        .ok_or(CandidateSealError::ResourceLimit)
}

fn is_zero_oid(oid: &[u8; 20]) -> bool {
    oid.iter().all(|byte| *byte == 0)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use inex_core::atomic::{
        PublicationIdentityScheme, VAULT_MUTATION_LOCK_FILE, open_secure_source_root,
    };
    use sha1::{Digest as _, Sha1};
    use sha2::Sha256;

    use super::super::candidate_manifest::collect_marker_free_physical_manifest;
    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const EMPTY_BLOB_OID: [u8; 20] = [
        0xe6, 0x9d, 0xe2, 0x9b, 0xb2, 0xd1, 0xd6, 0x43, 0x4b, 0x8b, 0x29, 0xae, 0x77, 0x5a, 0xd8,
        0xc2, 0xe4, 0x8c, 0x53, 0x91,
    ];

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, AtomicOrdering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-candidate-worktree-{label}-{}-{sequence}",
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

    fn minimal_candidate(label: &str) -> TestDirectory {
        let target = TestDirectory::new(label);
        fs::create_dir(target.path().join(GIT_DIRECTORY)).expect("git directory creates");
        fs::create_dir(target.path().join(VAULT_LOCAL_DIRECTORY))
            .expect("private directory creates");
        fs::write(
            target
                .path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(VAULT_MUTATION_LOCK_FILE),
            [],
        )
        .expect("empty mutation lock writes");
        fs::write(target.path().join(".gitattributes"), TARGET_ATTRIBUTES)
            .expect("canonical attributes write");
        fs::write(target.path().join(".gitignore"), TARGET_IGNORE)
            .expect("canonical ignore writes");
        fs::write(target.path().join(VAULT_METADATA_FILE), b"{}\n").expect("metadata writes");
        target
    }

    fn populated_candidate(label: &str) -> TestDirectory {
        let target = minimal_candidate(label);
        fs::create_dir_all(target.path().join("docs/deep")).expect("document parents create");
        fs::create_dir(target.path().join("images")).expect("asset parent creates");
        fs::write(target.path().join("docs/deep/empty.md.enc"), [])
            .expect("empty encrypted document writes");
        fs::write(
            target.path().join("images/field.bin.asset.enc"),
            [0_u8, 1, 2, 0xff],
        )
        .expect("encrypted asset writes");
        target
    }

    fn typed_blob_oid(body: &[u8]) -> [u8; 20] {
        let mut typed = Sha1::new();
        typed.update(format!("blob {}\0", body.len()).as_bytes());
        typed.update(body);
        typed.finalize().into()
    }

    fn manifest_index_entries(
        physical: &MarkerFreePhysicalManifest,
        root: &Path,
    ) -> Vec<(Vec<u8>, [u8; 20])> {
        let reserved = ReservedFingerprints::new();
        physical
            .records()
            .filter(|record| matches!(record.kind, PhysicalRecordKindRef::File { .. }))
            .filter_map(|record| match classify_file(record.path, reserved) {
                Ok(FileDisposition::Control) => None,
                Ok(FileDisposition::Tracked(_)) => Some(record.path),
                Err(error) => panic!("fixture path classification failed: {error}"),
            })
            .map(|path| {
                let body = fs::read(root.join(path)).expect("fixture tracked file reads");
                (path.as_bytes().to_vec(), typed_blob_oid(&body))
            })
            .collect()
    }

    fn index_v2(entries: &[(Vec<u8>, [u8; 20])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"DIRC");
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(entries.len())
                .expect("test entry count fits")
                .to_be_bytes(),
        );
        for (path, oid) in entries {
            bytes.extend_from_slice(&[0_u8; 24]);
            bytes.extend_from_slice(&0o100_644_u32.to_be_bytes());
            bytes.extend_from_slice(&[0_u8; 12]);
            bytes.extend_from_slice(oid);
            let name_length =
                u16::try_from(path.len().min(0x0fff)).expect("test path length fits index flags");
            bytes.extend_from_slice(&name_length.to_be_bytes());
            bytes.extend_from_slice(path);
            let unpadded = 62 + path.len();
            bytes.resize(bytes.len() + 8 - unpadded % 8, 0);
        }
        let checksum = Sha1::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    fn collect_fixture<'a>(
        target: &TestDirectory,
        physical: &'a MarkerFreePhysicalManifest,
        index: &[u8],
    ) -> FreshTrackedManifest<'a> {
        let held_root = open_secure_source_root(target.path()).expect("held root opens");
        collect_fresh_tracked_evidence(physical, &held_root, index)
            .expect("fresh tracked evidence collects")
    }

    #[test]
    fn passed_held_root_and_transient_index_produce_manifest_bound_slice_evidence() {
        let target = populated_candidate("happy");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical fixture collects");
        let index = index_v2(&manifest_index_entries(&physical, target.path()));
        // Binding these borrowed bytes to the physical `.git/index` record and
        // section 8 deliberately belongs to the later caller-side assembler.
        let tracked = collect_fixture(&target, &physical, &index);

        assert_eq!(tracked.records.len(), 5);
        let (worktree, projected_index) = tracked
            .project(PublicationIdentityScheme::LinuxDevInodeV1)
            .expect("bound tracked evidence projects");
        assert_eq!(worktree.len(), projected_index.len());
        assert!(worktree.iter().zip(&projected_index).all(|(left, right)| {
            left.path == right.path
                && left.blob_oid == right.blob_oid
                && !is_zero_oid(&left.blob_oid)
        }));
        assert_eq!(
            worktree
                .iter()
                .find(|record| record.path == "docs/deep/empty.md.enc")
                .expect("empty blob record exists")
                .blob_oid,
            EMPTY_BLOB_OID
        );

        let trees = construct_fresh_tree_evidence(&tracked).expect("fresh trees construct");
        let projected = trees.project().expect("bound trees project");
        let paths: Vec<_> = projected.iter().map(|record| record.path).collect();
        assert_eq!(paths, ["", "docs", "docs/deep", "images"]);
        assert!(
            projected
                .iter()
                .all(|record| !is_zero_oid(&record.tree_oid))
        );

        let tracked_debug = format!("{tracked:?}");
        let tree_debug = format!("{trees:?}");
        assert!(tracked_debug.contains("record_count: 5"));
        assert!(tree_debug.contains("record_count: 4"));
        assert!(!tracked_debug.contains("docs/deep"));
        assert!(!tree_debug.contains("images"));
    }

    #[test]
    fn raw_index_path_oid_and_checksum_mismatches_fail_closed() {
        let target = populated_candidate("bad-index");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical fixture collects");
        let entries = manifest_index_entries(&physical, target.path());
        let held_root = open_secure_source_root(target.path()).expect("held root opens");

        let mut wrong_path_entries = entries.clone();
        wrong_path_entries[1].0 = b".gitignorf".to_vec();
        assert_eq!(
            collect_fresh_tracked_evidence(&physical, &held_root, &index_v2(&wrong_path_entries))
                .expect_err("wrong index path rejects"),
            CandidateSealError::InvalidRecord
        );

        let mut wrong_oid_entries = entries.clone();
        wrong_oid_entries[0].1[0] ^= 1;
        assert_eq!(
            collect_fresh_tracked_evidence(&physical, &held_root, &index_v2(&wrong_oid_entries))
                .expect_err("unbound index oid rejects"),
            CandidateSealError::InvalidRecord
        );

        let mut bad_checksum = index_v2(&entries);
        let last = bad_checksum.len() - 1;
        bad_checksum[last] ^= 1;
        assert_eq!(
            collect_fresh_tracked_evidence(&physical, &held_root, &bad_checksum)
                .expect_err("bad checksum rejects"),
            CandidateSealError::InvalidRecord
        );

        let mut zero_oid_entries = entries;
        zero_oid_entries[0].1 = [0_u8; 20];
        assert_eq!(
            collect_fresh_tracked_evidence(&physical, &held_root, &index_v2(&zero_oid_entries))
                .expect_err("zero oid rejects"),
            CandidateSealError::InvalidRecord
        );
    }

    fn assert_wrong_managed_metadata_rejected(label: &str, path: &str, canonical: &[u8]) {
        let target = populated_candidate(label);
        let mut wrong = canonical.to_vec();
        wrong[0] ^= 1;
        assert_eq!(wrong.len(), canonical.len());
        fs::write(target.path().join(path), &wrong).expect("same-size wrong metadata writes");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("wrong metadata physical fixture collects");
        let index = index_v2(&manifest_index_entries(&physical, target.path()));
        let held_root = open_secure_source_root(target.path()).expect("fixture root holds");
        assert_eq!(
            collect_fresh_tracked_evidence(&physical, &held_root, &index)
                .expect_err("wrong managed metadata body rejects"),
            CandidateSealError::InvalidRecord
        );
    }

    #[test]
    fn managed_attributes_require_exact_canonical_digest() {
        assert_wrong_managed_metadata_rejected(
            "wrong-attributes",
            ".gitattributes",
            TARGET_ATTRIBUTES,
        );
    }

    #[test]
    fn managed_ignore_requires_exact_canonical_digest() {
        assert_wrong_managed_metadata_rejected("wrong-ignore", ".gitignore", TARGET_IGNORE);
    }

    #[test]
    fn streamed_blob_rejects_content_inode_and_ancestor_drift() {
        let changed = populated_candidate("content-drift");
        let changed_physical = collect_marker_free_physical_manifest(changed.path())
            .expect("changed fixture baseline collects");
        let changed_index = index_v2(&manifest_index_entries(&changed_physical, changed.path()));
        let changed_root =
            open_secure_source_root(changed.path()).expect("changed fixture root holds");
        fs::write(changed.path().join("docs/deep/empty.md.enc"), b"changed")
            .expect("same inode content changes");
        assert_eq!(
            collect_fresh_tracked_evidence(&changed_physical, &changed_root, &changed_index)
                .expect_err("same inode content drift rejects"),
            CandidateSealError::InvalidRecord
        );

        let replaced = populated_candidate("inode-drift");
        let replaced_physical = collect_marker_free_physical_manifest(replaced.path())
            .expect("replacement fixture baseline collects");
        let replaced_index = index_v2(&manifest_index_entries(&replaced_physical, replaced.path()));
        let replaced_root =
            open_secure_source_root(replaced.path()).expect("replacement fixture root holds");
        let asset = replaced.path().join("images/field.bin.asset.enc");
        let original_asset = fs::File::open(&asset).expect("original asset inode stays held");
        fs::remove_file(&asset).expect("old asset removes");
        fs::write(&asset, [0_u8, 1, 2, 0xff]).expect("same bytes replacement writes");
        assert_eq!(
            collect_fresh_tracked_evidence(&replaced_physical, &replaced_root, &replaced_index)
                .expect_err("same bytes replacement inode rejects"),
            CandidateSealError::InvalidRecord
        );
        drop(original_asset);

        let rebound = populated_candidate("ancestor-drift");
        let rebound_physical = collect_marker_free_physical_manifest(rebound.path())
            .expect("ancestor fixture baseline collects");
        let rebound_index = index_v2(&manifest_index_entries(&rebound_physical, rebound.path()));
        let rebound_root =
            open_secure_source_root(rebound.path()).expect("ancestor fixture root holds");
        fs::rename(
            rebound.path().join("docs"),
            rebound.path().join("held-docs"),
        )
        .expect("original ancestor holds under another name");
        fs::create_dir_all(rebound.path().join("docs/deep")).expect("replacement ancestor creates");
        fs::write(rebound.path().join("docs/deep/empty.md.enc"), [])
            .expect("replacement descendant writes");
        assert_eq!(
            collect_fresh_tracked_evidence(&rebound_physical, &rebound_root, &rebound_index)
                .expect_err("ancestor identity drift rejects"),
            CandidateSealError::InvalidRecord
        );
    }

    #[test]
    fn semantic_aliases_and_empty_content_directories_fail_closed() {
        for (label, path) in [
            ("asset-markdown", "bad.md.asset.enc"),
            ("asset-reserved", ".git.asset.enc"),
            ("asset-metadata", "vault.json.asset.enc"),
            ("asset-trailing-dot", "bad..asset.enc"),
        ] {
            let target = minimal_candidate(label);
            fs::write(target.path().join(path), b"ciphertext").expect("invalid fixture writes");
            let physical = collect_marker_free_physical_manifest(target.path())
                .expect("invalid physical fixture still collects");
            assert!(matches!(
                classify_tracked_records(&physical),
                Err(CandidateSealError::InvalidRecord)
            ));
        }

        let target = populated_candidate("empty-directory");
        fs::create_dir(target.path().join("orphan")).expect("empty content directory creates");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("empty-directory physical fixture collects");
        let index = index_v2(&manifest_index_entries(&physical, target.path()));
        let tracked = collect_fixture(&target, &physical, &index);
        assert_eq!(
            construct_fresh_tree_evidence(&tracked).expect_err("untracked empty directory rejects"),
            CandidateSealError::InvalidRecord
        );
    }

    #[test]
    fn tree_stream_uses_git_directory_slash_order_without_retaining_body() {
        let target = minimal_candidate("tree-order");
        fs::create_dir(target.path().join("foo")).expect("foo directory creates");
        fs::write(target.path().join("foo/child.md.enc"), b"child")
            .expect("child ciphertext writes");
        fs::write(target.path().join("foo.md.enc"), b"root-file")
            .expect("prefix file ciphertext writes");
        fs::write(target.path().join("foo0.md.enc"), b"post-directory")
            .expect("post-directory ciphertext writes");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("tree fixture physical manifest collects");
        let index = index_v2(&manifest_index_entries(&physical, target.path()));
        let tracked = collect_fixture(&target, &physical, &index);
        let trees = construct_fresh_tree_evidence(&tracked).expect("trees construct");
        let projected_trees = trees.project().expect("trees project");
        let projected_tracked = tracked
            .project(PublicationIdentityScheme::LinuxDevInodeV1)
            .expect("tracked projects")
            .0;

        let oid_for_file = |path: &str| {
            projected_tracked
                .iter()
                .find(|record| record.path == path)
                .expect("expected root file exists")
                .blob_oid
        };
        let child_tree_oid = projected_trees
            .iter()
            .find(|tree| tree.path == "foo")
            .expect("foo tree exists")
            .tree_oid;
        let root_tree = projected_trees
            .first()
            .filter(|tree| tree.path.is_empty())
            .expect("root tree is first");

        let mut raw = Vec::new();
        for (mode, name, oid) in [
            (
                b"100644 ".as_slice(),
                ".gitattributes",
                oid_for_file(".gitattributes"),
            ),
            (
                b"100644 ".as_slice(),
                ".gitignore",
                oid_for_file(".gitignore"),
            ),
            (
                b"100644 ".as_slice(),
                "foo.md.enc",
                oid_for_file("foo.md.enc"),
            ),
            (b"40000 ".as_slice(), "foo", child_tree_oid),
            (
                b"100644 ".as_slice(),
                "foo0.md.enc",
                oid_for_file("foo0.md.enc"),
            ),
            (
                b"100644 ".as_slice(),
                "vault.json",
                oid_for_file("vault.json"),
            ),
        ] {
            raw.extend_from_slice(mode);
            raw.extend_from_slice(name.as_bytes());
            raw.push(0);
            raw.extend_from_slice(&oid);
        }
        let mut typed = Sha1::new();
        typed.update(format!("tree {}\0", raw.len()).as_bytes());
        typed.update(&raw);
        assert_eq!(root_tree.raw_size, raw.len() as u64);
        assert_eq!(root_tree.tree_oid, <[u8; 20]>::from(typed.finalize()));
        assert_eq!(root_tree.raw_sha256, <[u8; 32]>::from(Sha256::digest(&raw)));
    }

    #[test]
    fn reverse_ancestor_verification_rejects_rebind_after_streaming() {
        let target = populated_candidate("post-stream-ancestor-drift");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("post-stream fixture baseline collects");
        let held_root = open_secure_source_root(target.path()).expect("fixture root holds");
        let tracked = classify_tracked_records(&physical).expect("fixture classifies");
        let file = tracked
            .iter()
            .find_map(|tracked| {
                physical
                    .record(tracked.physical)
                    .filter(|record| record.path == "docs/deep/empty.md.enc")
                    .map(|_| tracked.physical)
            })
            .expect("deep tracked file resolves");

        let result = stream_bound_blob_with_hook(&physical, &held_root, file, || {
            fs::rename(target.path().join("docs"), target.path().join("held-docs"))
                .expect("streamed ancestor moves");
            fs::create_dir_all(target.path().join("docs/deep"))
                .expect("replacement ancestor creates");
            fs::write(target.path().join("docs/deep/empty.md.enc"), [])
                .expect("replacement descendant writes");
        });
        assert_eq!(result, Err(CandidateSealError::InvalidRecord));
    }
}
