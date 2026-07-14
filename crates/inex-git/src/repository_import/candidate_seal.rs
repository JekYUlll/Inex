//! Canonical repository-candidate-seal-v1 stream encoding.
//!
//! This module deliberately owns the caller-domain stream grammar and consumes
//! already-audited, role-typed records. Its validation is defense in depth, not
//! a complete candidate audit: cross-section exact inventory and semantic
//! consistency remain the next physical/Git collector slice's responsibility.
//! Encoding never retains the serialized stream or any target body; production
//! output is only one SHA-256 digest.

use std::collections::BTreeSet;

use inex_core::atomic::{
    FilesystemDirectoryIdentity, FilesystemFileIdentity, PublicationIdentityScheme,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::is_nfc;

const MAGIC: [u8; 8] = *b"INEXCS1\0";
const VERSION: u16 = 1;
const DOMAIN: &[u8; 25] = b"inex.repository-import.v1";
const TERMINATOR: [u8; 5] = [0xff, 0, 0, 0, 0];

const MAX_PHYSICAL_RECORDS: usize = 1_000_000;
const MAX_TRACKED_RECORDS: usize = 100_003;
const MAX_OBJECT_RECORDS: usize = 1_000_000;
const MAX_GIT_CONTROL_RECORDS: usize = 1_000_000;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_PHYSICAL_PATH_BYTES: usize = 1_034;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_DEPTH: usize = 128;
const MAX_PATH_BUDGET: usize = 256 * 1024 * 1024;
const MAX_BODY_BYTES: u64 = 68 * 1024 * 1024;
const REGULAR_MODE: u32 = 0o100_644;
const EMPTY_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Scrubbed failure from the private v1 stream encoder.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum CandidateSealError {
    #[error("repository candidate-seal context is invalid")]
    InvalidContext,
    #[error("repository candidate-seal record is invalid")]
    InvalidRecord,
    #[error("repository candidate-seal records are not canonical")]
    NonCanonicalOrder,
    #[error("repository candidate-seal resource bound was exceeded")]
    ResourceLimit,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SealIdentity {
    scheme: PublicationIdentityScheme,
    bytes: [u8; 24],
}

impl SealIdentity {
    fn from_directory(
        identity: &FilesystemDirectoryIdentity,
        scheme: PublicationIdentityScheme,
    ) -> Result<Self, CandidateSealError> {
        let wire = identity
            .publication_identity(scheme)
            .ok_or(CandidateSealError::InvalidContext)?;
        Ok(Self {
            scheme,
            bytes: *wire.wire_bytes(),
        })
    }

    fn from_file(
        identity: &FilesystemFileIdentity,
        scheme: PublicationIdentityScheme,
    ) -> Result<Self, CandidateSealError> {
        let wire = identity
            .publication_identity(scheme)
            .ok_or(CandidateSealError::InvalidContext)?;
        Ok(Self {
            scheme,
            bytes: *wire.wire_bytes(),
        })
    }

    #[cfg(test)]
    const fn synthetic(scheme: PublicationIdentityScheme, discriminator: u8, seed: u8) -> Self {
        let bytes = match scheme {
            PublicationIdentityScheme::LinuxDevInodeV1 => [
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                seed,
                seed,
                0x17,
                0x16,
                0x15,
                0x14,
                0x13,
                0x12,
                0x11,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                discriminator,
            ],
            PublicationIdentityScheme::WindowsModernFileId128V1 => {
                // Modern FILE_ID_128 values are opaque and have no role
                // discriminator; they only need to be nonzero.
                [
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    seed,
                    seed.wrapping_add(1),
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    seed.wrapping_add(2),
                ]
            }
            PublicationIdentityScheme::WindowsLegacyFileIndexV1 => [
                0,
                0,
                0,
                0,
                1,
                2,
                3,
                seed,
                seed,
                0x17,
                0x16,
                0x15,
                0x14,
                0x13,
                0x12,
                0x11,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                discriminator,
            ],
        };
        Self { scheme, bytes }
    }
}

impl std::fmt::Debug for SealIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealIdentity")
            .field("scheme", &self.scheme)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Scheme-bound directory identity accepted by directory record roles only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CandidateDirectoryIdentity(SealIdentity);

impl CandidateDirectoryIdentity {
    pub(super) fn from_observed(
        identity: &FilesystemDirectoryIdentity,
        scheme: PublicationIdentityScheme,
    ) -> Result<Self, CandidateSealError> {
        SealIdentity::from_directory(identity, scheme).map(Self)
    }

    #[cfg(test)]
    const fn synthetic(scheme: PublicationIdentityScheme, seed: u8) -> Self {
        Self(SealIdentity::synthetic(scheme, 1, seed))
    }
}

/// Scheme-bound regular-file identity accepted by file record roles only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CandidateFileIdentity(SealIdentity);

impl CandidateFileIdentity {
    pub(super) fn from_observed(
        identity: &FilesystemFileIdentity,
        scheme: PublicationIdentityScheme,
    ) -> Result<Self, CandidateSealError> {
        SealIdentity::from_file(identity, scheme).map(Self)
    }

    #[cfg(test)]
    const fn synthetic(scheme: PublicationIdentityScheme, seed: u8) -> Self {
        Self(SealIdentity::synthetic(scheme, 2, seed))
    }
}

/// Exact prefix inputs supplied by the generic publication claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CandidateSealContext {
    pub(super) scheme: PublicationIdentityScheme,
    pub(super) publication_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PhysicalRecordKind {
    Directory(CandidateDirectoryIdentity),
    File {
        identity: CandidateFileIdentity,
        size: u64,
        sha256: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PhysicalRecord<'a> {
    pub(super) path: &'a str,
    pub(super) kind: PhysicalRecordKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum WorktreeClass {
    ManagedMetadata = 1,
    MarkdownEnvelope = 2,
    AssetEnvelope = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorktreeRecord<'a> {
    pub(super) path: &'a str,
    pub(super) class: WorktreeClass,
    pub(super) identity: CandidateFileIdentity,
    pub(super) size: u64,
    pub(super) sha256: [u8; 32],
    pub(super) blob_oid: [u8; 20],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HeadRefsRecord {
    pub(super) commit_oid: [u8; 20],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IndexRecord<'a> {
    pub(super) path: &'a str,
    pub(super) blob_oid: [u8; 20],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TreeRecord<'a> {
    pub(super) path: &'a str,
    pub(super) tree_oid: [u8; 20],
    pub(super) raw_size: u64,
    pub(super) raw_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootCommitRecord {
    pub(super) commit_oid: [u8; 20],
    pub(super) tree_oid: [u8; 20],
    pub(super) raw_size: u64,
    pub(super) raw_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ObjectKind {
    Blob = 1,
    Tree = 2,
    Commit = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ObjectRecord {
    pub(super) oid: [u8; 20],
    pub(super) kind: ObjectKind,
    pub(super) raw_size: u64,
    pub(super) raw_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum GitControlRole {
    Head = 1,
    Config = 2,
    Index = 3,
    MainRef = 4,
    LooseObject = 5,
    StructuralDirectory = 6,
    EmptyHooks = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GitControlRecordKind {
    Directory(CandidateDirectoryIdentity),
    File {
        identity: CandidateFileIdentity,
        size: u64,
        sha256: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GitControlRecord<'a> {
    pub(super) path: &'a str,
    pub(super) role: GitControlRole,
    pub(super) kind: GitControlRecordKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PrivateBaselineRecord {
    pub(super) identity: CandidateFileIdentity,
}

/// Borrowed, already-audited role records for all nine v1 sections.
///
/// This container does not prove exact inventory or complete semantic
/// consistency across sections. The next collector slice must establish those
/// properties before constructing it; encoder checks are only defense in depth.
#[derive(Clone, Copy, Debug)]
pub(super) struct CandidateSealManifest<'a> {
    pub(super) physical: &'a [PhysicalRecord<'a>],
    pub(super) worktree: &'a [WorktreeRecord<'a>],
    pub(super) head_refs: HeadRefsRecord,
    pub(super) index: &'a [IndexRecord<'a>],
    pub(super) trees: &'a [TreeRecord<'a>],
    pub(super) root_commit: RootCommitRecord,
    pub(super) objects: &'a [ObjectRecord],
    pub(super) git_control: &'a [GitControlRecord<'a>],
    pub(super) private_baseline: PrivateBaselineRecord,
}

/// Incrementally encode and hash one canonical repository candidate seal.
pub(super) fn encode_candidate_seal_v1(
    context: CandidateSealContext,
    manifest: CandidateSealManifest<'_>,
) -> Result<[u8; 32], CandidateSealError> {
    let mut sink = DigestSink(Sha256::new());
    encode_stream(&mut sink, context, manifest)?;
    Ok(sink.0.finalize().into())
}

trait SealSink {
    fn put(&mut self, bytes: &[u8]);
}

struct DigestSink(Sha256);

impl SealSink for DigestSink {
    fn put(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

fn encode_stream(
    sink: &mut impl SealSink,
    context: CandidateSealContext,
    manifest: CandidateSealManifest<'_>,
) -> Result<(), CandidateSealError> {
    if context.publication_id.iter().all(|byte| *byte == 0) {
        return Err(CandidateSealError::InvalidContext);
    }
    validate_manifest(context.scheme, &manifest)?;

    sink.put(&MAGIC);
    put_u16(sink, VERSION);
    put_u16(sink, context.scheme.wire_value());
    put_u16(
        sink,
        u16::try_from(DOMAIN.len()).map_err(|_| CandidateSealError::InvalidContext)?,
    );
    sink.put(DOMAIN);
    sink.put(&context.publication_id);

    encode_physical(sink, manifest.physical)?;
    encode_worktree(sink, manifest.worktree)?;
    encode_head_refs(sink, manifest.head_refs);
    encode_index(sink, manifest.index)?;
    encode_trees(sink, manifest.trees)?;
    encode_root_commit(sink, manifest.root_commit);
    encode_objects(sink, manifest.objects)?;
    encode_git_control(sink, manifest.git_control)?;
    encode_private_baseline(sink, manifest.private_baseline);
    sink.put(&TERMINATOR);
    Ok(())
}

fn validate_manifest(
    scheme: PublicationIdentityScheme,
    manifest: &CandidateSealManifest<'_>,
) -> Result<(), CandidateSealError> {
    if manifest.physical.is_empty() || manifest.trees.is_empty() {
        return Err(CandidateSealError::InvalidRecord);
    }
    if !matches!(
        manifest.physical[0],
        PhysicalRecord {
            path: "",
            kind: PhysicalRecordKind::Directory(_)
        }
    ) || !manifest.trees[0].path.is_empty()
    {
        return Err(CandidateSealError::InvalidRecord);
    }
    let directory_count = manifest
        .physical
        .iter()
        .filter(|record| matches!(record.kind, PhysicalRecordKind::Directory(_)))
        .count();
    if manifest.trees.len() > directory_count
        || manifest.worktree.len() != manifest.index.len()
        || manifest.head_refs.commit_oid != manifest.root_commit.commit_oid
        || manifest.trees[0].tree_oid != manifest.root_commit.tree_oid
    {
        return Err(CandidateSealError::InvalidRecord);
    }
    validate_raw_size(manifest.root_commit.raw_size)?;
    for (worktree, index) in manifest.worktree.iter().zip(manifest.index) {
        if worktree.path != index.path || worktree.blob_oid != index.blob_oid {
            return Err(CandidateSealError::InvalidRecord);
        }
    }
    validate_identity_schemes(scheme, manifest)?;
    validate_object_references(manifest)?;
    Ok(())
}

fn validate_identity_schemes(
    scheme: PublicationIdentityScheme,
    manifest: &CandidateSealManifest<'_>,
) -> Result<(), CandidateSealError> {
    let identity_matches = |identity: SealIdentity| identity.scheme == scheme;
    for record in manifest.physical {
        let identity = match record.kind {
            PhysicalRecordKind::Directory(identity) => identity.0,
            PhysicalRecordKind::File { identity, .. } => identity.0,
        };
        if !identity_matches(identity) {
            return Err(CandidateSealError::InvalidContext);
        }
    }
    if manifest
        .worktree
        .iter()
        .any(|record| !identity_matches(record.identity.0))
        || manifest.git_control.iter().any(|record| {
            !identity_matches(match record.kind {
                GitControlRecordKind::Directory(identity) => identity.0,
                GitControlRecordKind::File { identity, .. } => identity.0,
            })
        })
        || !identity_matches(manifest.private_baseline.identity.0)
    {
        return Err(CandidateSealError::InvalidContext);
    }
    Ok(())
}

fn validate_object_references(
    manifest: &CandidateSealManifest<'_>,
) -> Result<(), CandidateSealError> {
    if manifest
        .objects
        .windows(2)
        .any(|pair| pair[0].oid >= pair[1].oid)
    {
        return Err(CandidateSealError::NonCanonicalOrder);
    }
    let find = |oid: &[u8; 20]| {
        manifest
            .objects
            .binary_search_by_key(oid, |record| record.oid)
            .ok()
            .and_then(|index| manifest.objects.get(index))
    };
    for record in manifest.worktree {
        if !matches!(
            find(&record.blob_oid),
            Some(object)
                if object.kind == ObjectKind::Blob
                    && object.raw_size == record.size
                    && object.raw_sha256 == record.sha256
        ) {
            return Err(CandidateSealError::InvalidRecord);
        }
    }
    for record in manifest.trees {
        if !matches!(
            find(&record.tree_oid),
            Some(object)
                if object.kind == ObjectKind::Tree
                    && object.raw_size == record.raw_size
                    && object.raw_sha256 == record.raw_sha256
        ) {
            return Err(CandidateSealError::InvalidRecord);
        }
    }
    if !matches!(
        find(&manifest.root_commit.commit_oid),
        Some(object)
            if object.kind == ObjectKind::Commit
                && object.raw_size == manifest.root_commit.raw_size
                && object.raw_sha256 == manifest.root_commit.raw_sha256
    ) {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

fn encode_physical(
    sink: &mut impl SealSink,
    records: &[PhysicalRecord<'_>],
) -> Result<(), CandidateSealError> {
    section_header(sink, 1, records.len(), MAX_PHYSICAL_RECORDS)?;
    validate_path_records(records, |record| record.path, true, MAX_PHYSICAL_PATH_BYTES)?;
    for record in records {
        let payload_length = path_payload_length(record.path, 67)?;
        put_u32(sink, payload_length);
        put_path(sink, record.path)?;
        match record.kind {
            PhysicalRecordKind::Directory(identity) => {
                sink.put(&[1]);
                sink.put(&identity.0.bytes);
                put_u64(sink, 0);
                sink.put(&[0; 32]);
            }
            PhysicalRecordKind::File {
                identity,
                size,
                sha256,
            } => {
                if size > MAX_BODY_BYTES {
                    return Err(CandidateSealError::ResourceLimit);
                }
                sink.put(&[2]);
                sink.put(&identity.0.bytes);
                put_u64(sink, size);
                sink.put(&sha256);
            }
        }
    }
    Ok(())
}

fn encode_worktree(
    sink: &mut impl SealSink,
    records: &[WorktreeRecord<'_>],
) -> Result<(), CandidateSealError> {
    section_header(sink, 2, records.len(), MAX_TRACKED_RECORDS)?;
    validate_path_records(records, |record| record.path, false, MAX_PATH_BYTES)?;
    let mut metadata = BTreeSet::new();
    for record in records {
        validate_worktree_class(record, &mut metadata)?;
        validate_raw_size(record.size)?;
        if record.blob_oid.iter().all(|byte| *byte == 0) {
            return Err(CandidateSealError::InvalidRecord);
        }
        put_u32(sink, path_payload_length(record.path, 91)?);
        put_path(sink, record.path)?;
        sink.put(&[record.class as u8]);
        put_u32(sink, REGULAR_MODE);
        sink.put(&record.identity.0.bytes);
        put_u64(sink, record.size);
        sink.put(&record.sha256);
        sink.put(&record.blob_oid);
    }
    if metadata != BTreeSet::from([".gitattributes", ".gitignore", "vault.json"]) {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

fn validate_worktree_class<'a>(
    record: &WorktreeRecord<'a>,
    metadata: &mut BTreeSet<&'a str>,
) -> Result<(), CandidateSealError> {
    match record.class {
        WorktreeClass::ManagedMetadata => {
            if !matches!(record.path, ".gitattributes" | ".gitignore" | "vault.json")
                || !metadata.insert(record.path)
            {
                return Err(CandidateSealError::InvalidRecord);
            }
        }
        WorktreeClass::MarkdownEnvelope if !record.path.ends_with(".md.enc") => {
            return Err(CandidateSealError::InvalidRecord);
        }
        WorktreeClass::AssetEnvelope if !record.path.ends_with(".asset.enc") => {
            return Err(CandidateSealError::InvalidRecord);
        }
        WorktreeClass::MarkdownEnvelope | WorktreeClass::AssetEnvelope => {}
    }
    Ok(())
}

fn encode_head_refs(sink: &mut impl SealSink, record: HeadRefsRecord) {
    section_header_infallible(sink, 3, 1);
    put_u32(sink, 63);
    sink.put(&[1]);
    put_u16(sink, 15);
    sink.put(b"refs/heads/main");
    put_u32(sink, 1);
    put_u16(sink, 15);
    sink.put(b"refs/heads/main");
    sink.put(&record.commit_oid);
    put_u32(sink, 0);
}

fn encode_index(
    sink: &mut impl SealSink,
    records: &[IndexRecord<'_>],
) -> Result<(), CandidateSealError> {
    section_header(sink, 4, records.len(), MAX_TRACKED_RECORDS)?;
    validate_path_records(records, |record| record.path, false, MAX_PATH_BYTES)?;
    for record in records {
        if record.blob_oid.iter().all(|byte| *byte == 0) {
            return Err(CandidateSealError::InvalidRecord);
        }
        put_u32(sink, path_payload_length(record.path, 31)?);
        put_path(sink, record.path)?;
        put_u32(sink, REGULAR_MODE);
        sink.put(&[0]);
        put_u32(sink, 0);
        sink.put(&record.blob_oid);
    }
    Ok(())
}

fn encode_trees(
    sink: &mut impl SealSink,
    records: &[TreeRecord<'_>],
) -> Result<(), CandidateSealError> {
    section_header(sink, 5, records.len(), MAX_PHYSICAL_RECORDS)?;
    validate_path_records(records, |record| record.path, true, MAX_PATH_BYTES)?;
    for record in records {
        if record.tree_oid.iter().all(|byte| *byte == 0) {
            return Err(CandidateSealError::InvalidRecord);
        }
        validate_raw_size(record.raw_size)?;
        put_u32(sink, path_payload_length(record.path, 62)?);
        put_path(sink, record.path)?;
        sink.put(&record.tree_oid);
        put_u64(sink, record.raw_size);
        sink.put(&record.raw_sha256);
    }
    Ok(())
}

fn encode_root_commit(sink: &mut impl SealSink, record: RootCommitRecord) {
    section_header_infallible(sink, 6, 1);
    put_u32(sink, 84);
    sink.put(&record.commit_oid);
    sink.put(&record.tree_oid);
    put_u32(sink, 0);
    put_u64(sink, record.raw_size);
    sink.put(&record.raw_sha256);
}

fn encode_objects(
    sink: &mut impl SealSink,
    records: &[ObjectRecord],
) -> Result<(), CandidateSealError> {
    section_header(sink, 7, records.len(), MAX_OBJECT_RECORDS)?;
    for record in records {
        if record.oid.iter().all(|byte| *byte == 0) {
            return Err(CandidateSealError::InvalidRecord);
        }
        validate_raw_size(record.raw_size)?;
        put_u32(sink, 61);
        sink.put(&record.oid);
        sink.put(&[record.kind as u8]);
        put_u64(sink, record.raw_size);
        sink.put(&record.raw_sha256);
    }
    Ok(())
}

fn encode_git_control(
    sink: &mut impl SealSink,
    records: &[GitControlRecord<'_>],
) -> Result<(), CandidateSealError> {
    section_header(sink, 8, records.len(), MAX_GIT_CONTROL_RECORDS)?;
    validate_path_records(records, |record| record.path, false, MAX_PATH_BYTES)?;
    for record in records {
        validate_git_control_role(record)?;
        put_u32(sink, path_payload_length(record.path, 68)?);
        put_path(sink, record.path)?;
        sink.put(&[record.role as u8]);
        match record.kind {
            GitControlRecordKind::Directory(identity) => {
                sink.put(&[1]);
                sink.put(&identity.0.bytes);
                put_u64(sink, 0);
                sink.put(&[0; 32]);
            }
            GitControlRecordKind::File {
                identity,
                size,
                sha256,
            } => {
                if size > MAX_BODY_BYTES {
                    return Err(CandidateSealError::ResourceLimit);
                }
                sink.put(&[2]);
                sink.put(&identity.0.bytes);
                put_u64(sink, size);
                sink.put(&sha256);
            }
        }
    }
    Ok(())
}

fn validate_git_control_role(record: &GitControlRecord<'_>) -> Result<(), CandidateSealError> {
    let directory = matches!(record.kind, GitControlRecordKind::Directory(_));
    let valid = match record.role {
        GitControlRole::Head => record.path == "HEAD" && !directory,
        GitControlRole::Config => record.path == "config" && !directory,
        GitControlRole::Index => record.path == "index" && !directory,
        GitControlRole::MainRef => record.path == "refs/heads/main" && !directory,
        GitControlRole::StructuralDirectory => {
            directory
                && matches!(
                    record.path,
                    "objects"
                        | "objects/info"
                        | "objects/pack"
                        | "refs"
                        | "refs/heads"
                        | "refs/tags"
                )
        }
        GitControlRole::EmptyHooks => record.path == "inex-empty-hooks" && directory,
        GitControlRole::LooseObject => validate_loose_object_path(record.path, directory),
    };
    valid.then_some(()).ok_or(CandidateSealError::InvalidRecord)
}

fn validate_loose_object_path(path: &str, directory: bool) -> bool {
    let Some(rest) = path.strip_prefix("objects/") else {
        return false;
    };
    if directory {
        return rest.len() == 2 && rest.bytes().all(is_lower_hex);
    }
    let Some((prefix, suffix)) = rest.split_once('/') else {
        return false;
    };
    prefix.len() == 2
        && suffix.len() == 38
        && prefix.bytes().chain(suffix.bytes()).all(is_lower_hex)
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn encode_private_baseline(sink: &mut impl SealSink, record: PrivateBaselineRecord) {
    section_header_infallible(sink, 9, 1);
    put_u32(sink, 80);
    put_u16(sink, 13);
    sink.put(b"mutation.lock");
    sink.put(&[2]);
    sink.put(&record.identity.0.bytes);
    put_u64(sink, 0);
    sink.put(&EMPTY_SHA256);
}

fn section_header(
    sink: &mut impl SealSink,
    tag: u8,
    count: usize,
    maximum: usize,
) -> Result<(), CandidateSealError> {
    if count > maximum {
        return Err(CandidateSealError::ResourceLimit);
    }
    let count = u32::try_from(count).map_err(|_| CandidateSealError::ResourceLimit)?;
    section_header_infallible(sink, tag, count);
    Ok(())
}

fn section_header_infallible(sink: &mut impl SealSink, tag: u8, count: u32) {
    sink.put(&[tag]);
    put_u32(sink, count);
}

fn validate_path_records<T>(
    records: &[T],
    path: impl Fn(&T) -> &str,
    allow_root: bool,
    maximum_path_bytes: usize,
) -> Result<(), CandidateSealError> {
    let mut previous: Option<&[u8]> = None;
    let mut budget = 0_usize;
    for record in records {
        let candidate = path(record);
        validate_path(candidate, allow_root, maximum_path_bytes)?;
        if previous.is_some_and(|value| value >= candidate.as_bytes()) {
            return Err(CandidateSealError::NonCanonicalOrder);
        }
        budget = budget
            .checked_add(candidate.len())
            .filter(|value| *value <= MAX_PATH_BUDGET)
            .ok_or(CandidateSealError::ResourceLimit)?;
        previous = Some(candidate.as_bytes());
    }
    Ok(())
}

fn validate_path(
    path: &str,
    allow_root: bool,
    maximum_path_bytes: usize,
) -> Result<(), CandidateSealError> {
    if path.is_empty() {
        return allow_root
            .then_some(())
            .ok_or(CandidateSealError::InvalidRecord);
    }
    if path.len() > maximum_path_bytes || !is_nfc(path) || path.contains('\\') {
        return Err(if path.len() > maximum_path_bytes {
            CandidateSealError::ResourceLimit
        } else {
            CandidateSealError::InvalidRecord
        });
    }
    let mut depth = 0_usize;
    for component in path.split('/') {
        depth = depth
            .checked_add(1)
            .filter(|value| *value <= MAX_DEPTH)
            .ok_or(CandidateSealError::ResourceLimit)?;
        validate_component(component)?;
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<(), CandidateSealError> {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.len() > MAX_COMPONENT_BYTES
        || component.starts_with(' ')
        || component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        })
    {
        return Err(if component.len() > MAX_COMPONENT_BYTES {
            CandidateSealError::ResourceLimit
        } else {
            CandidateSealError::InvalidRecord
        });
    }
    let basename = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ');
    if is_windows_device_basename(basename) {
        return Err(CandidateSealError::InvalidRecord);
    }
    let bytes = basename.as_bytes();
    if matches!(bytes.last(), Some(b'0'..=b'9'))
        && bytes.get(bytes.len().saturating_sub(2)) == Some(&b'~')
    {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

fn is_windows_device_basename(basename: &str) -> bool {
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|value| basename.eq_ignore_ascii_case(value))
    {
        return true;
    }
    let Some(prefix) = basename.get(..3) else {
        return false;
    };
    let Some(suffix) = basename.get(3..) else {
        return false;
    };
    (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
        && (matches!(suffix.as_bytes(), [b'1'..=b'9']) || matches!(suffix, "¹" | "²" | "³"))
}

fn validate_raw_size(size: u64) -> Result<(), CandidateSealError> {
    if size <= MAX_BODY_BYTES {
        Ok(())
    } else {
        Err(CandidateSealError::ResourceLimit)
    }
}

fn path_payload_length(path: &str, fixed: u32) -> Result<u32, CandidateSealError> {
    fixed
        .checked_add(u32::try_from(path.len()).map_err(|_| CandidateSealError::ResourceLimit)?)
        .ok_or(CandidateSealError::ResourceLimit)
}

fn put_path(sink: &mut impl SealSink, path: &str) -> Result<(), CandidateSealError> {
    put_u16(
        sink,
        u16::try_from(path.len()).map_err(|_| CandidateSealError::ResourceLimit)?,
    );
    sink.put(path.as_bytes());
    Ok(())
}

fn put_u16(sink: &mut impl SealSink, value: u16) {
    sink.put(&value.to_be_bytes());
}

fn put_u32(sink: &mut impl SealSink, value: u32) {
    sink.put(&value.to_be_bytes());
}

fn put_u64(sink: &mut impl SealSink, value: u64) {
    sink.put(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEME: PublicationIdentityScheme = PublicationIdentityScheme::LinuxDevInodeV1;
    const FILE: CandidateFileIdentity = CandidateFileIdentity::synthetic(SCHEME, 0x22);
    const DIRECTORY: CandidateDirectoryIdentity =
        CandidateDirectoryIdentity::synthetic(SCHEME, 0x11);
    const DIRECTORY_WIRE: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x11, 0x11, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    const BLOB_A: [u8; 20] = [0x10; 20];
    const BLOB_B: [u8; 20] = [0x20; 20];
    const BLOB_C: [u8; 20] = [0x30; 20];
    const TREE: [u8; 20] = [0x40; 20];
    const COMMIT: [u8; 20] = [0x50; 20];

    struct VecSink(Vec<u8>);

    impl SealSink for VecSink {
        fn put(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one complete nine-section golden fixture is easier to audit contiguously"
    )]
    fn fixture() -> CandidateSealManifest<'static> {
        static PHYSICAL: [PhysicalRecord<'static>; 1] = [PhysicalRecord {
            path: "",
            kind: PhysicalRecordKind::Directory(DIRECTORY),
        }];
        static WORKTREE: [WorktreeRecord<'static>; 3] = [
            WorktreeRecord {
                path: ".gitattributes",
                class: WorktreeClass::ManagedMetadata,
                identity: FILE,
                size: 1,
                sha256: [0xa1; 32],
                blob_oid: BLOB_A,
            },
            WorktreeRecord {
                path: ".gitignore",
                class: WorktreeClass::ManagedMetadata,
                identity: FILE,
                size: 2,
                sha256: [0xa2; 32],
                blob_oid: BLOB_B,
            },
            WorktreeRecord {
                path: "vault.json",
                class: WorktreeClass::ManagedMetadata,
                identity: FILE,
                size: 3,
                sha256: [0xa3; 32],
                blob_oid: BLOB_C,
            },
        ];
        static INDEX: [IndexRecord<'static>; 3] = [
            IndexRecord {
                path: ".gitattributes",
                blob_oid: BLOB_A,
            },
            IndexRecord {
                path: ".gitignore",
                blob_oid: BLOB_B,
            },
            IndexRecord {
                path: "vault.json",
                blob_oid: BLOB_C,
            },
        ];
        static TREES: [TreeRecord<'static>; 1] = [TreeRecord {
            path: "",
            tree_oid: TREE,
            raw_size: 7,
            raw_sha256: [0xb1; 32],
        }];
        static OBJECTS: [ObjectRecord; 5] = [
            ObjectRecord {
                oid: BLOB_A,
                kind: ObjectKind::Blob,
                raw_size: 1,
                raw_sha256: [0xa1; 32],
            },
            ObjectRecord {
                oid: BLOB_B,
                kind: ObjectKind::Blob,
                raw_size: 2,
                raw_sha256: [0xa2; 32],
            },
            ObjectRecord {
                oid: BLOB_C,
                kind: ObjectKind::Blob,
                raw_size: 3,
                raw_sha256: [0xa3; 32],
            },
            ObjectRecord {
                oid: TREE,
                kind: ObjectKind::Tree,
                raw_size: 7,
                raw_sha256: [0xb1; 32],
            },
            ObjectRecord {
                oid: COMMIT,
                kind: ObjectKind::Commit,
                raw_size: 11,
                raw_sha256: [0xc1; 32],
            },
        ];
        static GIT_CONTROL: [GitControlRecord<'static>; 2] = [
            GitControlRecord {
                path: "HEAD",
                role: GitControlRole::Head,
                kind: GitControlRecordKind::File {
                    identity: FILE,
                    size: 21,
                    sha256: [0xd1; 32],
                },
            },
            GitControlRecord {
                path: "objects",
                role: GitControlRole::StructuralDirectory,
                kind: GitControlRecordKind::Directory(DIRECTORY),
            },
        ];
        CandidateSealManifest {
            physical: &PHYSICAL,
            worktree: &WORKTREE,
            head_refs: HeadRefsRecord { commit_oid: COMMIT },
            index: &INDEX,
            trees: &TREES,
            root_commit: RootCommitRecord {
                commit_oid: COMMIT,
                tree_oid: TREE,
                raw_size: 11,
                raw_sha256: [0xc1; 32],
            },
            objects: &OBJECTS,
            git_control: &GIT_CONTROL,
            private_baseline: PrivateBaselineRecord { identity: FILE },
        }
    }

    fn context() -> CandidateSealContext {
        CandidateSealContext {
            scheme: SCHEME,
            publication_id: [0x77; 16],
        }
    }

    fn stream(manifest: CandidateSealManifest<'_>) -> Result<Vec<u8>, CandidateSealError> {
        let mut sink = VecSink(Vec::new());
        encode_stream(&mut sink, context(), manifest)?;
        Ok(sink.0)
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("test offset has four bytes"),
        )
    }

    #[test]
    fn golden_stream_has_frozen_prefix_sections_terminator_and_digest() {
        let bytes = stream(fixture()).expect("canonical fixture encodes");
        assert_eq!(&bytes[..8], b"INEXCS1\0");
        assert_eq!(&bytes[8..14], &[0, 1, 0, 1, 0, 25]);
        assert_eq!(&bytes[14..39], DOMAIN);
        assert_eq!(&bytes[39..55], &[0x77; 16]);
        assert_eq!(DIRECTORY.0.bytes, DIRECTORY_WIRE);
        assert_eq!(&bytes[67..91], &DIRECTORY_WIRE);
        assert_eq!(&bytes[bytes.len() - 5..], &TERMINATOR);
        let mut offset = 55;
        for expected_tag in 1_u8..=9 {
            assert_eq!(bytes[offset], expected_tag);
            let count = usize::try_from(u32_at(&bytes, offset + 1)).expect("count fits usize");
            offset += 5;
            for _ in 0..count {
                let record_length =
                    usize::try_from(u32_at(&bytes, offset)).expect("record length fits usize");
                offset += 4 + record_length;
            }
        }
        assert_eq!(&bytes[offset..], &TERMINATOR);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&bytes)),
            encode_candidate_seal_v1(context(), fixture()).expect("fixture hashes")
        );
        assert_eq!(
            encode_candidate_seal_v1(context(), fixture()).expect("fixture hashes"),
            [
                0x2d, 0xc5, 0xf2, 0x49, 0xcb, 0x21, 0x5a, 0x17, 0x2b, 0xc3, 0x04, 0xc8, 0x9b, 0xfa,
                0x25, 0x45, 0x7f, 0x8d, 0x25, 0x49, 0x7b, 0x83, 0xc7, 0x81, 0x59, 0x06, 0x8e, 0x51,
                0x8c, 0x8d, 0x82, 0x10,
            ]
        );
    }

    #[test]
    fn rejects_zero_publication_id_mixed_scheme_and_record_drift() {
        let mut zero = context();
        zero.publication_id = [0; 16];
        assert_eq!(
            encode_candidate_seal_v1(zero, fixture()),
            Err(CandidateSealError::InvalidContext)
        );

        let foreign = CandidateDirectoryIdentity::synthetic(
            PublicationIdentityScheme::WindowsLegacyFileIndexV1,
            9,
        );
        let physical = [PhysicalRecord {
            path: "",
            kind: PhysicalRecordKind::Directory(foreign),
        }];
        let mut mixed = fixture();
        mixed.physical = &physical;
        assert_eq!(
            encode_candidate_seal_v1(context(), mixed),
            Err(CandidateSealError::InvalidContext)
        );

        let bad_index = [IndexRecord {
            path: "vault.json",
            blob_oid: BLOB_C,
        }];
        let mut drift = fixture();
        drift.index = &bad_index;
        assert_eq!(
            encode_candidate_seal_v1(context(), drift),
            Err(CandidateSealError::InvalidRecord)
        );
    }

    #[test]
    fn rejects_noncanonical_path_oid_role_and_body_boundaries() {
        let physical = [
            PhysicalRecord {
                path: "",
                kind: PhysicalRecordKind::Directory(DIRECTORY),
            },
            PhysicalRecord {
                path: "z",
                kind: PhysicalRecordKind::Directory(DIRECTORY),
            },
            PhysicalRecord {
                path: "a",
                kind: PhysicalRecordKind::Directory(DIRECTORY),
            },
        ];
        let mut manifest = fixture();
        manifest.physical = &physical;
        assert_eq!(
            encode_candidate_seal_v1(context(), manifest),
            Err(CandidateSealError::NonCanonicalOrder)
        );

        let bad_role = [GitControlRecord {
            path: "config",
            role: GitControlRole::Head,
            kind: GitControlRecordKind::File {
                identity: FILE,
                size: 1,
                sha256: [1; 32],
            },
        }];
        let mut manifest = fixture();
        manifest.git_control = &bad_role;
        assert_eq!(
            encode_candidate_seal_v1(context(), manifest),
            Err(CandidateSealError::InvalidRecord)
        );

        let mut oversized = fixture().objects.to_vec();
        oversized[0].raw_size = MAX_BODY_BYTES + 1;
        let mut oversized_worktree = fixture().worktree.to_vec();
        oversized_worktree[0].size = MAX_BODY_BYTES + 1;
        let mut manifest = fixture();
        manifest.objects = &oversized;
        manifest.worktree = &oversized_worktree;
        assert_eq!(
            encode_candidate_seal_v1(context(), manifest),
            Err(CandidateSealError::ResourceLimit)
        );
    }

    #[test]
    fn framing_uses_big_endian_lengths_and_exact_record_sizes() {
        let bytes = stream(fixture()).expect("canonical fixture encodes");
        let section_one = 55;
        assert_eq!(&bytes[section_one..section_one + 5], &[1, 0, 0, 0, 1]);
        assert_eq!(
            &bytes[section_one + 5..section_one + 9],
            &67_u32.to_be_bytes()
        );
        assert_eq!(&bytes[section_one + 9..section_one + 11], &[0, 0]);
        let section_two = section_one + 5 + 4 + 67;
        assert_eq!(&bytes[section_two..section_two + 5], &[2, 0, 0, 0, 3]);
        assert_eq!(
            &bytes[section_two + 5..section_two + 9],
            &(91_u32 + 14).to_be_bytes()
        );
    }

    #[test]
    fn role_specific_identity_constructors_accept_observed_types()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::{self, File};

        let root =
            std::env::temp_dir().join(format!("inex-candidate-seal-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root)?;
        let file_path = root.join("file");
        let file = File::create(&file_path)?;
        let directory = inex_core::atomic::filesystem_directory_identity(&root)?;
        let file = inex_core::atomic::filesystem_file_identity(&file)?;
        let scheme = [
            PublicationIdentityScheme::LinuxDevInodeV1,
            PublicationIdentityScheme::WindowsModernFileId128V1,
            PublicationIdentityScheme::WindowsLegacyFileIndexV1,
        ]
        .into_iter()
        .find(|candidate| {
            directory.publication_identity(*candidate).is_some()
                && file.publication_identity(*candidate).is_some()
        })
        .ok_or("no common identity scheme")?;
        let directory = CandidateDirectoryIdentity::from_observed(&directory, scheme)?;
        let file = CandidateFileIdentity::from_observed(&file, scheme)?;
        assert_eq!(directory.0.scheme, scheme);
        assert_eq!(file.0.scheme, scheme);
        fs::remove_file(file_path)?;
        fs::remove_dir(root)?;
        Ok(())
    }
}
