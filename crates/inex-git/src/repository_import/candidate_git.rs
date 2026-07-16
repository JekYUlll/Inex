//! Fixed-size Git evidence for candidate-seal sections 3, 6, 7, and 8.
//!
//! Evidence in this module owns no path, object body, or borrowed view. Paths
//! are resolved through stable section-1 record IDs and borrowed only while
//! validating or projecting a seal record. The object verifier hashes caller-
//! supplied chunks and never retains them.
//!
//! Runtime object bodies can additionally be proven by the opaque
//! [`FreshRuntimeObjectProof`]. That proof is currently a trusted-local Linux
//! preview: the inherited legacy batch supervisor has a per-operation deadline
//! for the direct child, but a hostile descendant that inherits stdout/stderr
//! can still keep a reader join blocked after that child is killed. This module
//! does not claim process-tree-safe termination until that supervisor is
//! replaced.

use std::cmp::Ordering;
use std::fmt;

use inex_core::atomic::PublicationIdentityScheme;
#[cfg(target_os = "linux")]
use inex_core::atomic::SecureSourceDirectory;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

#[cfg(target_os = "linux")]
use super::candidate_control::collect_fresh_target_main_ref;
use super::candidate_manifest::{
    MarkerFreePhysicalManifest, PhysicalRecordId, PhysicalRecordKindRef, PhysicalRecordRef,
};
use super::candidate_seal::{
    CandidateDirectoryIdentity, CandidateFileIdentity, CandidateSealError, GitControlRecord,
    GitControlRecordKind, GitControlRole, HeadRefsRecord, ObjectKind, ObjectRecord,
    RootCommitRecord,
};
#[cfg(target_os = "linux")]
use super::candidate_vault_authority::{
    FreshTargetConfigCollectionError, collect_fresh_target_config_evidence,
};
use super::candidate_worktree::{FreshTrackedManifest, FreshTreeManifest};
#[cfg(target_os = "linux")]
use super::{GitRunner, RepositoryImportError};

mod runtime_object_proof;

#[allow(
    unused_imports,
    reason = "the publication aggregate and runtime collector are wired in adjacent slices"
)]
pub(super) use runtime_object_proof::FreshRuntimeObjectProof;
#[cfg(target_os = "linux")]
#[allow(
    unused_imports,
    reason = "the runtime collector is wired into the publication transaction in the next slice"
)]
pub(super) use runtime_object_proof::prove_fresh_runtime_objects;
#[cfg(test)]
#[allow(
    unused_imports,
    reason = "aggregate integration tests consume the test-only proof witness"
)]
pub(super) use runtime_object_proof::prove_fresh_runtime_objects_for_test;

const MAX_OBJECT_RECORDS: usize = 1_000_000;
const MAX_GIT_CONTROL_RECORDS: usize = 1_000_000;
const MAX_RAW_OBJECT_BYTES: u64 = 68 * 1024 * 1024;
const MAX_CANONICAL_ROOT_COMMIT_BYTES: usize = 512;
const GIT_PREFIX: &str = ".git/";
const GIT_ROOT: &str = ".git";
const LOOSE_OBJECT_PATH_PREFIX: &[u8] = b".git/objects/";
const LOOSE_OBJECT_PATH_BYTES: usize = LOOSE_OBJECT_PATH_PREFIX.len() + 41;
const IMPORT_MESSAGE: &[u8] = b"Initialize encrypted Inex vault\n";
const AUTHOR_PREFIX: &[u8] = b"author Inex Repository Import <inex-import@localhost.invalid> ";
const COMMITTER_PREFIX: &[u8] =
    b"committer Inex Repository Import <inex-import@localhost.invalid> ";
const UTC_SUFFIX: &[u8] = b" +0000";
const HEAD_BODY: &[u8] = b"ref: refs/heads/main\n";

/// Fixed-size section-3/6 evidence parsed from the exact canonical commit.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct FreshRootCommitEvidence {
    commit_oid: [u8; 20],
    tree_oid: [u8; 20],
    raw_size: u64,
    raw_sha256: [u8; 32],
}

impl fmt::Debug for FreshRootCommitEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshRootCommitEvidence")
            .field("commit_oid", &"[REDACTED]")
            .field("tree_oid", &"[REDACTED]")
            .field("raw_size", &self.raw_size)
            .field("raw_sha256", &"[REDACTED]")
            .finish()
    }
}

impl FreshRootCommitEvidence {
    pub(super) const fn commit_oid(&self) -> [u8; 20] {
        self.commit_oid
    }

    pub(super) const fn tree_oid(&self) -> [u8; 20] {
        self.tree_oid
    }

    pub(super) const fn raw_size(&self) -> u64 {
        self.raw_size
    }

    pub(super) const fn raw_sha256(&self) -> [u8; 32] {
        self.raw_sha256
    }

    fn project(self) -> (HeadRefsRecord, RootCommitRecord) {
        (
            HeadRefsRecord {
                commit_oid: self.commit_oid,
            },
            RootCommitRecord {
                commit_oid: self.commit_oid,
                tree_oid: self.tree_oid,
                raw_size: self.raw_size,
                raw_sha256: self.raw_sha256,
            },
        )
    }

    fn object_record(self) -> ObjectRecord {
        ObjectRecord {
            oid: self.commit_oid,
            kind: ObjectKind::Commit,
            raw_size: self.raw_size,
            raw_sha256: self.raw_sha256,
        }
    }
}

/// One exact loose-object file bound to its fixed-size section-7 record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct FreshObjectEvidence {
    loose_file: PhysicalRecordId,
    record: ObjectRecord,
}

impl fmt::Debug for FreshObjectEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshObjectEvidence")
            .field("loose_file", &self.loose_file)
            .field("oid", &"[REDACTED]")
            .field("kind", &self.record.kind)
            .field("raw_size", &self.record.raw_size)
            .field("raw_sha256", &"[REDACTED]")
            .finish()
    }
}

impl FreshObjectEvidence {
    fn project(
        self,
        physical: &MarkerFreePhysicalManifest,
    ) -> Result<ObjectRecord, CandidateSealError> {
        let record = physical
            .record(self.loose_file)
            .ok_or(CandidateSealError::InvalidRecord)?;
        let GitControlClassification::LooseObject(oid) = classify_git_control(record)? else {
            return Err(CandidateSealError::InvalidRecord);
        };
        if oid != self.record.oid {
            return Err(CandidateSealError::InvalidRecord);
        }
        validate_object_record(self.record)?;
        Ok(self.record)
    }
}

/// One section-8 role bound to a canonical section-1 record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct FreshGitControlEvidence {
    physical: PhysicalRecordId,
    role: GitControlRole,
}

impl fmt::Debug for FreshGitControlEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshGitControlEvidence")
            .field("physical", &self.physical)
            .field("role", &self.role)
            .finish()
    }
}

impl FreshGitControlEvidence {
    fn project(
        self,
        physical: &MarkerFreePhysicalManifest,
        scheme: PublicationIdentityScheme,
    ) -> Result<GitControlRecord<'_>, CandidateSealError> {
        let record = physical
            .record(self.physical)
            .ok_or(CandidateSealError::InvalidRecord)?;
        let relative = git_relative_path(record.path)?;
        if classify_git_control(record)?.role() != self.role {
            return Err(CandidateSealError::InvalidRecord);
        }
        let kind = match record.kind {
            PhysicalRecordKindRef::Directory(identity) => GitControlRecordKind::Directory(
                CandidateDirectoryIdentity::from_observed(identity, scheme)?,
            ),
            PhysicalRecordKindRef::File {
                identity,
                size,
                sha256,
            } => GitControlRecordKind::File {
                identity: CandidateFileIdentity::from_observed(identity, scheme)?,
                size,
                sha256: *sha256,
            },
        };
        Ok(GitControlRecord {
            path: relative,
            role: self.role,
            kind,
        })
    }
}

/// Opaque proof that one physical manifest contains only the frozen fresh-Git
/// control shape.
///
/// This preflight deliberately proves path shape rather than object reachability:
/// a later exact scan binds the main-ref body and the complete semantic object
/// union. The proof implements neither `Clone` nor `Copy`, retains no path or
/// object body, and remains permanently branded to the exact manifest borrow.
pub(super) struct FreshGitControlShape<'physical> {
    physical: &'physical MarkerFreePhysicalManifest,
    loose_object_count: usize,
    fanout: [u64; 4],
}

impl fmt::Debug for FreshGitControlShape<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshGitControlShape")
            .field("physical", &"[BOUND MANIFEST]")
            .field("loose_objects", &self.loose_object_count)
            .field("fanout", &"[REDACTED]")
            .finish()
    }
}

impl FreshGitControlShape<'_> {
    /// Prove exact manifest branding using pointer identity, not an equal-
    /// looking record layout.
    pub(super) fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical, physical)
    }

    /// Require one exact lowercase loose-object file in this same branded
    /// physical manifest. No record ID or caller-selected manifest escapes.
    pub(super) fn require_loose_object(&self, oid: [u8; 20]) -> Result<(), CandidateSealError> {
        if !fanout_contains(&self.fanout, oid[0]) {
            return Err(CandidateSealError::InvalidRecord);
        }
        let mut path = [0_u8; LOOSE_OBJECT_PATH_BYTES];
        let path = canonical_loose_object_path(oid, &mut path)?;
        let record = self
            .physical
            .find(path)
            .ok_or(CandidateSealError::InvalidRecord)?;
        match classify_git_control(record)? {
            GitControlClassification::LooseObject(observed) if observed == oid => Ok(()),
            _ => Err(CandidateSealError::InvalidRecord),
        }
    }
}

/// Opaque Git evidence permanently bound to one section-1 manifest.
pub(super) struct FreshGitManifest<'physical> {
    physical: &'physical MarkerFreePhysicalManifest,
    root_commit: FreshRootCommitEvidence,
    objects: Vec<FreshObjectEvidence>,
    git_control: Vec<FreshGitControlEvidence>,
}

impl fmt::Debug for FreshGitManifest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshGitManifest")
            .field("physical", &"[BOUND MANIFEST]")
            .field("root_commit", &"[REDACTED]")
            .field("objects", &self.objects.len())
            .field("git_control", &self.git_control.len())
            .finish()
    }
}

/// Borrowed-path projection into candidate-seal sections 3, 6, 7, and 8.
pub(super) struct CandidateGitProjection<'a> {
    pub(super) head_refs: HeadRefsRecord,
    pub(super) root_commit: RootCommitRecord,
    pub(super) objects: Vec<ObjectRecord>,
    pub(super) git_control: Vec<GitControlRecord<'a>>,
}

impl fmt::Debug for CandidateGitProjection<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateGitProjection")
            .field("head_refs", &"[REDACTED]")
            .field("root_commit", &"[REDACTED]")
            .field("objects", &self.objects.len())
            .field("git_control", &self.git_control.len())
            .finish()
    }
}

impl<'physical> FreshGitManifest<'physical> {
    /// Prove exact physical-manifest identity using pointer identity, not an
    /// equal-looking record layout.
    pub(super) fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical, physical)
    }

    fn project(
        &self,
        scheme: PublicationIdentityScheme,
    ) -> Result<CandidateGitProjection<'physical>, CandidateSealError> {
        validate_fresh_git_manifest(self)?;
        let (head_refs, root_commit) = self.root_commit.project();
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(self.objects.len())
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        for evidence in &self.objects {
            objects.push(evidence.project(self.physical)?);
        }
        let mut git_control = Vec::new();
        git_control
            .try_reserve_exact(self.git_control.len())
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        for evidence in &self.git_control {
            git_control.push(evidence.project(self.physical, scheme)?);
        }
        Ok(CandidateGitProjection {
            head_refs,
            root_commit,
            objects,
            git_control,
        })
    }

    fn require_exact_content_objects<'content>(
        &self,
        tracked: &FreshTrackedManifest<'content>,
        trees: &FreshTreeManifest<'content>,
    ) -> Result<(), CandidateSealError> {
        if !tracked.is_bound_to(self.physical) || !trees.is_bound_to(self.physical) {
            return Err(CandidateSealError::InvalidRecord);
        }
        let expected =
            canonical_object_union_from_views(self.physical, tracked, trees, self.root_commit)?;
        if expected.len() != self.objects.len()
            || expected
                .iter()
                .zip(&self.objects)
                .any(|(expected, observed)| *expected != observed.record)
        {
            return Err(CandidateSealError::InvalidRecord);
        }
        Ok(())
    }

    /// Project sections 3/6/7/8 only after re-deriving the complete object
    /// union from the opaque tracked/tree views used by the aggregate.
    fn project_for_seal<'content>(
        &self,
        scheme: PublicationIdentityScheme,
        tracked: &FreshTrackedManifest<'content>,
        trees: &FreshTreeManifest<'content>,
    ) -> Result<CandidateGitProjection<'physical>, CandidateSealError> {
        self.require_exact_content_objects(tracked, trees)?;
        self.project(scheme)
    }

    #[cfg(test)]
    pub(super) fn forge_object_union_for_test(&mut self) {
        if let Some(object) = self.objects.first_mut() {
            object.record.oid = [0; 20];
        }
    }
}

/// Parse the one allowed parentless root commit and derive its exact digests.
///
/// The grammar requires one lowercase SHA-1 tree, identical canonical `i64`
/// author/committer timestamps, UTC `+0000`, the fixed import identity and
/// message, and no parent, extra header, or trailing byte.
pub(super) fn parse_canonical_root_commit(
    body: &[u8],
) -> Result<FreshRootCommitEvidence, CandidateSealError> {
    if body.len() > MAX_CANONICAL_ROOT_COMMIT_BYTES {
        return Err(CandidateSealError::ResourceLimit);
    }
    let (tree_line, rest) = take_line(body)?;
    let tree_hex = tree_line
        .strip_prefix(b"tree ")
        .filter(|hex| hex.len() == 40)
        .ok_or(CandidateSealError::InvalidRecord)?;
    let tree_oid = decode_lower_hex_oid(tree_hex)?;

    let (author_line, rest) = take_line(rest)?;
    let author_timestamp = canonical_timestamp(author_line, AUTHOR_PREFIX)?;
    let (committer_line, rest) = take_line(rest)?;
    let committer_timestamp = canonical_timestamp(committer_line, COMMITTER_PREFIX)?;
    if author_timestamp != committer_timestamp
        || !rest.starts_with(b"\n")
        || &rest[1..] != IMPORT_MESSAGE
    {
        return Err(CandidateSealError::InvalidRecord);
    }

    let raw_size = u64::try_from(body.len()).map_err(|_| CandidateSealError::ResourceLimit)?;
    let commit_oid = typed_object_oid(ObjectKind::Commit, raw_size, body);
    Ok(FreshRootCommitEvidence {
        commit_oid,
        tree_oid,
        raw_size,
        raw_sha256: raw_sha256(body),
    })
}

/// Bootstrap the canonical root commit from one held fresh target.
///
/// This is the sole target-only production constructor for
/// [`FreshRootCommitEvidence`]. It first rejects every Git control shape
/// outside the frozen loose-object profile, then binds canonical config and
/// `refs/heads/main` snapshots to the exact same physical-manifest allocation.
/// Only after those pathname-free proofs agree does it permit the fixed
/// `git cat-file commit <oid>` reader under an exact current-root guard.
///
/// The bounded command inherits the existing trusted-local supervision
/// boundary: the direct child has a deadline, but a hostile descendant that
/// retains stdout can still delay the reader join. This proof grants no
/// publication authority and retains no path, command output, config body, or
/// commit body.
#[cfg(target_os = "linux")]
pub(super) fn collect_fresh_target_root_commit_evidence(
    physical: &MarkerFreePhysicalManifest,
    held_root: &SecureSourceDirectory,
    runner: &GitRunner,
) -> Result<FreshRootCommitEvidence, RepositoryImportError> {
    let shape =
        preflight_fresh_git_control_shape(physical).map_err(map_bootstrap_candidate_error)?;
    let config = collect_fresh_target_config_evidence(physical, held_root, runner)
        .map_err(map_bootstrap_config_error)?;
    let main_ref = collect_fresh_target_main_ref(physical, held_root)
        .map_err(map_bootstrap_candidate_error)?;

    if !shape.is_bound_to(physical)
        || !config.is_bound_to(physical)
        || !main_ref.is_bound_to(physical)
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    config
        .role(physical)
        .map_err(map_bootstrap_candidate_error)?;
    shape
        .require_loose_object(main_ref.commit_oid())
        .map_err(map_bootstrap_candidate_error)?;

    let root_guard = runner.target_root_identity_guard(physical.root_identity())?;
    let encoded_ref = main_ref_body(main_ref.commit_oid());
    let encoded_ref = std::str::from_utf8(&encoded_ref[..40])
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    let body = root_guard.read_canonical_root_commit(encoded_ref)?;
    let root_commit =
        parse_canonical_root_commit(body.as_slice()).map_err(map_bootstrap_candidate_error)?;
    drop(body);
    if root_commit.commit_oid() != main_ref.commit_oid() {
        return Err(RepositoryImportError::TargetAuditFailed);
    }

    root_guard.verify()?;
    held_root
        .verify_no_alternate_data_streams()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    if held_root.identity() != physical.root_identity() {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    Ok(root_commit)
}

/// Non-Linux builds have no held-root or target-command authority.
#[cfg(not(target_os = "linux"))]
pub(super) fn collect_fresh_target_root_commit_evidence(
    _physical: &MarkerFreePhysicalManifest,
    _unsupported_held_root: (),
    _runner: &super::GitRunner,
) -> Result<FreshRootCommitEvidence, super::RepositoryImportError> {
    Err(super::RepositoryImportError::TargetAuditFailed)
}

#[cfg(target_os = "linux")]
fn map_bootstrap_candidate_error(error: CandidateSealError) -> RepositoryImportError {
    if matches!(error, CandidateSealError::ResourceLimit) {
        RepositoryImportError::ResourceLimit
    } else {
        RepositoryImportError::TargetAuditFailed
    }
}

#[cfg(target_os = "linux")]
fn map_bootstrap_config_error(error: FreshTargetConfigCollectionError) -> RepositoryImportError {
    match error {
        FreshTargetConfigCollectionError::Candidate(error) => map_bootstrap_candidate_error(error),
        FreshTargetConfigCollectionError::Repository(RepositoryImportError::ResourceLimit) => {
            RepositoryImportError::ResourceLimit
        }
        FreshTargetConfigCollectionError::Repository(RepositoryImportError::TargetAuditFailed) => {
            RepositoryImportError::TargetAuditFailed
        }
        FreshTargetConfigCollectionError::Repository(
            error @ (RepositoryImportError::Io { .. }
            | RepositoryImportError::GitCommandFailed { .. }),
        ) => error,
        FreshTargetConfigCollectionError::Repository(_) => RepositoryImportError::TargetAuditFailed,
    }
}

/// Construct exact sections 7/8 evidence from opaque tracked/tree views.
///
/// The complete semantic object union is derived internally from sections 2
/// and 5 plus the parser-only root commit. There is no production entry point
/// accepting arbitrary `ObjectRecord` arrays. Exact duplicate records collapse;
/// an OID collision with different kind, size, or digest fails closed. The
/// physical manifest must contain exactly one matching loose file for every
/// unique object and no other `.git` entry outside the frozen control graph.
pub(super) fn collect_fresh_git_evidence<'physical>(
    physical: &'physical MarkerFreePhysicalManifest,
    tracked: &FreshTrackedManifest<'physical>,
    trees: &FreshTreeManifest<'physical>,
    root_commit: FreshRootCommitEvidence,
) -> Result<FreshGitManifest<'physical>, CandidateSealError> {
    let expected = canonical_object_union_from_views(physical, tracked, trees, root_commit)?;
    collect_fresh_git_evidence_from_union(physical, &expected, root_commit)
}

fn collect_fresh_git_evidence_from_union<'physical>(
    physical: &'physical MarkerFreePhysicalManifest,
    expected: &[ObjectRecord],
    root_commit: FreshRootCommitEvidence,
) -> Result<FreshGitManifest<'physical>, CandidateSealError> {
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(expected.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    let mut git_control = Vec::new();
    scan_exact_git_control(
        physical,
        expected,
        root_commit.commit_oid,
        |record, role, object| {
            git_control
                .try_reserve(1)
                .map_err(|_| CandidateSealError::ResourceLimit)?;
            git_control.push(FreshGitControlEvidence {
                physical: record.id,
                role,
            });
            if let Some(object) = object {
                objects
                    .try_reserve(1)
                    .map_err(|_| CandidateSealError::ResourceLimit)?;
                objects.push(FreshObjectEvidence {
                    loose_file: record.id,
                    record: object,
                });
            }
            Ok(())
        },
    )?;
    objects.sort_unstable_by_key(|object| object.record.oid);
    if objects.len() != expected.len()
        || objects
            .iter()
            .zip(expected)
            .any(|(observed, expected)| observed.record != *expected)
    {
        return Err(CandidateSealError::InvalidRecord);
    }
    let evidence = FreshGitManifest {
        physical,
        root_commit,
        objects,
        git_control,
    };
    validate_fresh_git_manifest(&evidence)?;
    Ok(evidence)
}

fn canonical_object_union_from_views(
    physical: &MarkerFreePhysicalManifest,
    tracked: &FreshTrackedManifest<'_>,
    trees: &FreshTreeManifest<'_>,
    root_commit: FreshRootCommitEvidence,
) -> Result<Vec<ObjectRecord>, CandidateSealError> {
    if !tracked.is_bound_to(physical) || !trees.is_bound_to(physical) {
        return Err(CandidateSealError::InvalidRecord);
    }
    let mut blobs = Vec::new();
    tracked.visit_blob_objects(|record| {
        blobs
            .try_reserve(1)
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        blobs.push(record);
        Ok(())
    })?;
    let mut tree_objects = Vec::new();
    trees.visit_tree_objects(|record| {
        tree_objects
            .try_reserve(1)
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        tree_objects.push(record);
        Ok(())
    })?;
    canonical_object_union(&blobs, &tree_objects, root_commit)
}

/// Revalidate pure manifest-ID evidence without reading the filesystem.
pub(super) fn validate_fresh_git_manifest(
    evidence: &FreshGitManifest<'_>,
) -> Result<(), CandidateSealError> {
    if evidence.objects.len() > MAX_OBJECT_RECORDS
        || evidence.git_control.len() > MAX_GIT_CONTROL_RECORDS
        || evidence.objects.is_empty()
    {
        return Err(CandidateSealError::ResourceLimit);
    }
    validate_root_commit_evidence(evidence.root_commit)?;
    if evidence
        .objects
        .windows(2)
        .any(|pair| pair[0].record.oid >= pair[1].record.oid)
    {
        return Err(CandidateSealError::NonCanonicalOrder);
    }
    let commit = evidence.root_commit.object_record();
    if !matches!(
        find_object(evidence.objects.as_slice(), &commit.oid),
        Some(record) if record == commit
    ) || !matches!(
        find_object(evidence.objects.as_slice(), &evidence.root_commit.tree_oid),
        Some(record) if record.kind == ObjectKind::Tree
    ) {
        return Err(CandidateSealError::InvalidRecord);
    }
    for object in &evidence.objects {
        validate_object_record(object.record)?;
    }

    let mut control_index = 0_usize;
    let mut object_count = 0_usize;
    scan_exact_git_control(
        evidence.physical,
        evidence.objects.as_slice(),
        evidence.root_commit.commit_oid,
        |record, role, object| {
            let control = evidence
                .git_control
                .get(control_index)
                .ok_or(CandidateSealError::InvalidRecord)?;
            if control.physical != record.id || control.role != role {
                return Err(CandidateSealError::InvalidRecord);
            }
            control_index = control_index
                .checked_add(1)
                .ok_or(CandidateSealError::ResourceLimit)?;
            if let Some(expected) = object {
                let observed = find_object_evidence(evidence.objects.as_slice(), &expected.oid)
                    .ok_or(CandidateSealError::InvalidRecord)?;
                if observed.loose_file != record.id || observed.record != expected {
                    return Err(CandidateSealError::InvalidRecord);
                }
                object_count = object_count
                    .checked_add(1)
                    .ok_or(CandidateSealError::ResourceLimit)?;
            }
            Ok(())
        },
    )?;
    if control_index != evidence.git_control.len() || object_count != evidence.objects.len() {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

/// Incremental raw/typed object proof. No body byte survives `update`.
pub(super) struct StreamingObjectVerifier {
    expected: ObjectRecord,
    remaining: u64,
    typed: Sha1,
    raw: Sha256,
    failed: bool,
}

impl fmt::Debug for StreamingObjectVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamingObjectVerifier")
            .field("expected", &"[REDACTED]")
            .field("remaining", &self.remaining)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl StreamingObjectVerifier {
    pub(super) fn new(expected: ObjectRecord) -> Result<Self, CandidateSealError> {
        Self::new_with_limit(expected, MAX_RAW_OBJECT_BYTES)
    }

    fn new_with_limit(
        expected: ObjectRecord,
        maximum_raw_bytes: u64,
    ) -> Result<Self, CandidateSealError> {
        validate_object_record_with_limit(expected, maximum_raw_bytes)?;
        let mut typed = Sha1::new();
        typed.update(object_kind_name(expected.kind));
        typed.update(b" ");
        let mut decimal = [0_u8; 20];
        typed.update(decimal_u64(expected.raw_size, &mut decimal));
        typed.update([0]);
        Ok(Self {
            expected,
            remaining: expected.raw_size,
            typed,
            raw: Sha256::new(),
            failed: false,
        })
    }

    pub(super) fn update(&mut self, chunk: &[u8]) -> Result<(), CandidateSealError> {
        let length = u64::try_from(chunk.len()).map_err(|_| CandidateSealError::ResourceLimit)?;
        if self.failed || length > self.remaining {
            self.failed = true;
            return Err(CandidateSealError::InvalidRecord);
        }
        self.remaining -= length;
        self.typed.update(chunk);
        self.raw.update(chunk);
        Ok(())
    }

    pub(super) fn finish(self) -> Result<(), CandidateSealError> {
        let typed: [u8; 20] = self.typed.finalize().into();
        let raw: [u8; 32] = self.raw.finalize().into();
        if self.failed
            || self.remaining != 0
            || typed != self.expected.oid
            || raw != self.expected.raw_sha256
        {
            return Err(CandidateSealError::InvalidRecord);
        }
        Ok(())
    }
}

fn canonical_object_union(
    blobs: &[ObjectRecord],
    trees: &[ObjectRecord],
    root_commit: FreshRootCommitEvidence,
) -> Result<Vec<ObjectRecord>, CandidateSealError> {
    let total = blobs
        .len()
        .checked_add(trees.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(CandidateSealError::ResourceLimit)?;
    if total > MAX_OBJECT_RECORDS {
        return Err(CandidateSealError::ResourceLimit);
    }
    validate_root_commit_evidence(root_commit)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(total)
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for record in blobs {
        if record.kind != ObjectKind::Blob {
            return Err(CandidateSealError::InvalidRecord);
        }
        validate_object_record(*record)?;
        records.push(*record);
    }
    for record in trees {
        if record.kind != ObjectKind::Tree {
            return Err(CandidateSealError::InvalidRecord);
        }
        validate_object_record(*record)?;
        records.push(*record);
    }
    if !trees
        .iter()
        .any(|record| record.oid == root_commit.tree_oid)
    {
        return Err(CandidateSealError::InvalidRecord);
    }
    records.push(root_commit.object_record());
    records.sort_unstable_by_key(|record| record.oid);
    let mut unique: Vec<ObjectRecord> = Vec::new();
    unique
        .try_reserve_exact(records.len())
        .map_err(|_| CandidateSealError::ResourceLimit)?;
    for record in records {
        match unique.last() {
            Some(previous) if previous.oid == record.oid && *previous != record => {
                return Err(CandidateSealError::InvalidRecord);
            }
            Some(previous) if previous.oid == record.oid => {}
            _ => unique.push(record),
        }
    }
    Ok(unique)
}

#[cfg(test)]
fn collect_fresh_git_evidence_from_records_for_test<'physical>(
    physical: &'physical MarkerFreePhysicalManifest,
    blob_objects: &[ObjectRecord],
    tree_objects: &[ObjectRecord],
    root_commit: FreshRootCommitEvidence,
) -> Result<FreshGitManifest<'physical>, CandidateSealError> {
    let expected = canonical_object_union(blob_objects, tree_objects, root_commit)?;
    collect_fresh_git_evidence_from_union(physical, &expected, root_commit)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GitControlClassification {
    Head,
    Config,
    Index,
    MainRef,
    Objects,
    ObjectsInfo,
    ObjectsPack,
    Refs,
    RefsHeads,
    RefsTags,
    EmptyHooks,
    LooseFanout(u8),
    LooseObject([u8; 20]),
}

impl GitControlClassification {
    const fn role(self) -> GitControlRole {
        match self {
            Self::Head => GitControlRole::Head,
            Self::Config => GitControlRole::Config,
            Self::Index => GitControlRole::Index,
            Self::MainRef => GitControlRole::MainRef,
            Self::Objects
            | Self::ObjectsInfo
            | Self::ObjectsPack
            | Self::Refs
            | Self::RefsHeads
            | Self::RefsTags => GitControlRole::StructuralDirectory,
            Self::EmptyHooks => GitControlRole::EmptyHooks,
            Self::LooseFanout(_) | Self::LooseObject(_) => GitControlRole::LooseObject,
        }
    }
}

/// Classify the sole frozen allowlist for fresh-target Git control records.
///
/// `HEAD` is content-bound here because its body is target-independent. The
/// main-ref body is intentionally bound later by the exact scan, after a
/// target-only caller has safely bootstrapped the candidate commit OID.
fn classify_git_control(
    record: PhysicalRecordRef<'_>,
) -> Result<GitControlClassification, CandidateSealError> {
    let relative = git_relative_path(record.path)?;
    let classification = match relative {
        "HEAD" => {
            require_file_body(record.kind, HEAD_BODY)?;
            GitControlClassification::Head
        }
        "config" => {
            require_file(record.kind)?;
            GitControlClassification::Config
        }
        "index" => {
            require_file(record.kind)?;
            GitControlClassification::Index
        }
        "refs/heads/main" => {
            require_file(record.kind)?;
            GitControlClassification::MainRef
        }
        "objects" => {
            require_directory(record.kind)?;
            GitControlClassification::Objects
        }
        "objects/info" => {
            require_directory(record.kind)?;
            GitControlClassification::ObjectsInfo
        }
        "objects/pack" => {
            require_directory(record.kind)?;
            GitControlClassification::ObjectsPack
        }
        "refs" => {
            require_directory(record.kind)?;
            GitControlClassification::Refs
        }
        "refs/heads" => {
            require_directory(record.kind)?;
            GitControlClassification::RefsHeads
        }
        "refs/tags" => {
            require_directory(record.kind)?;
            GitControlClassification::RefsTags
        }
        "inex-empty-hooks" => {
            require_directory(record.kind)?;
            GitControlClassification::EmptyHooks
        }
        _ => match loose_fanout(relative, record.kind)? {
            Some(prefix) => GitControlClassification::LooseFanout(prefix),
            None => GitControlClassification::LooseObject(loose_object_oid(record)?),
        },
    };
    Ok(classification)
}

/// Prove the exact fresh-target Git control shape before any commit body or
/// reachability evidence is trusted.
///
/// The allowed graph is four fixed files, six structural directories, one
/// empty hooks directory, and a lowercase loose-object graph whose two-digit
/// fanout set exactly equals the prefixes used by its `2/38` object files.
/// Syntactically valid unreachable loose objects are shape-valid here and are
/// rejected later by [`scan_exact_git_control`].
pub(super) fn preflight_fresh_git_control_shape(
    physical: &MarkerFreePhysicalManifest,
) -> Result<FreshGitControlShape<'_>, CandidateSealError> {
    let git_root = physical
        .find(GIT_ROOT)
        .ok_or(CandidateSealError::InvalidRecord)?;
    require_directory(git_root.kind)?;

    let mut fixed_files = 0_u8;
    let mut structural_directories = 0_u8;
    let mut hooks = false;
    let mut observed_fanout = [0_u64; 4];
    let mut required_fanout = [0_u64; 4];
    let mut controls = 0_usize;
    let mut loose_object_count = 0_usize;

    for record in physical.records() {
        if record.path == GIT_ROOT {
            continue;
        }
        if !record.path.starts_with(GIT_PREFIX) {
            continue;
        }
        controls = controls
            .checked_add(1)
            .filter(|count| *count <= MAX_GIT_CONTROL_RECORDS)
            .ok_or(CandidateSealError::ResourceLimit)?;
        match classify_git_control(record)? {
            GitControlClassification::Head => set_once(&mut fixed_files, 0b0001)?,
            GitControlClassification::Config => set_once(&mut fixed_files, 0b0010)?,
            GitControlClassification::Index => set_once(&mut fixed_files, 0b0100)?,
            GitControlClassification::MainRef => set_once(&mut fixed_files, 0b1000)?,
            GitControlClassification::Objects => {
                set_once(&mut structural_directories, 0b00_0001)?;
            }
            GitControlClassification::ObjectsInfo => {
                set_once(&mut structural_directories, 0b00_0010)?;
            }
            GitControlClassification::ObjectsPack => {
                set_once(&mut structural_directories, 0b00_0100)?;
            }
            GitControlClassification::Refs => {
                set_once(&mut structural_directories, 0b00_1000)?;
            }
            GitControlClassification::RefsHeads => {
                set_once(&mut structural_directories, 0b01_0000)?;
            }
            GitControlClassification::RefsTags => {
                set_once(&mut structural_directories, 0b10_0000)?;
            }
            GitControlClassification::EmptyHooks => {
                if std::mem::replace(&mut hooks, true) {
                    return Err(CandidateSealError::InvalidRecord);
                }
            }
            GitControlClassification::LooseFanout(prefix) => {
                if !insert_fanout(&mut observed_fanout, prefix) {
                    return Err(CandidateSealError::InvalidRecord);
                }
            }
            GitControlClassification::LooseObject(oid) => {
                let _ = insert_fanout(&mut required_fanout, oid[0]);
                loose_object_count = loose_object_count
                    .checked_add(1)
                    .filter(|count| *count <= MAX_OBJECT_RECORDS)
                    .ok_or(CandidateSealError::ResourceLimit)?;
            }
        }
    }

    let expected_controls = 11_usize
        .checked_add(fanout_count(&observed_fanout))
        .and_then(|count| count.checked_add(loose_object_count))
        .ok_or(CandidateSealError::ResourceLimit)?;
    if fixed_files != 0b1111
        || structural_directories != 0b11_1111
        || !hooks
        || observed_fanout != required_fanout
        || controls != expected_controls
    {
        return Err(CandidateSealError::InvalidRecord);
    }

    Ok(FreshGitControlShape {
        physical,
        loose_object_count,
        fanout: observed_fanout,
    })
}

trait SortedObjectSet {
    fn object_count(&self) -> usize;
    fn object_at(&self, index: usize) -> ObjectRecord;
}

impl SortedObjectSet for [ObjectRecord] {
    fn object_count(&self) -> usize {
        self.len()
    }

    fn object_at(&self, index: usize) -> ObjectRecord {
        self[index]
    }
}

impl SortedObjectSet for [FreshObjectEvidence] {
    fn object_count(&self) -> usize {
        self.len()
    }

    fn object_at(&self, index: usize) -> ObjectRecord {
        self[index].record
    }
}

fn scan_exact_git_control<S, F>(
    physical: &MarkerFreePhysicalManifest,
    objects: &S,
    commit_oid: [u8; 20],
    mut visit: F,
) -> Result<(), CandidateSealError>
where
    S: SortedObjectSet + ?Sized,
    F: FnMut(
        PhysicalRecordRef<'_>,
        GitControlRole,
        Option<ObjectRecord>,
    ) -> Result<(), CandidateSealError>,
{
    if objects.object_count() > MAX_OBJECT_RECORDS {
        return Err(CandidateSealError::ResourceLimit);
    }
    preflight_fresh_git_control_shape(physical)?;

    for index in 0..objects.object_count() {
        let object = objects.object_at(index);
        validate_object_record(object)?;
        if index > 0 && objects.object_at(index - 1).oid >= object.oid {
            return Err(CandidateSealError::NonCanonicalOrder);
        }
    }
    let mut loose_objects = 0_usize;

    for record in physical.records() {
        if record.path == GIT_ROOT {
            continue;
        }
        if !record.path.starts_with(GIT_PREFIX) {
            continue;
        }
        let classification = classify_git_control(record)?;
        let object = match classification {
            GitControlClassification::MainRef => {
                let body = main_ref_body(commit_oid);
                require_file_body(record.kind, &body)?;
                None
            }
            GitControlClassification::LooseObject(oid) => {
                let object = find_object(objects, &oid).ok_or(CandidateSealError::InvalidRecord)?;
                loose_objects = loose_objects
                    .checked_add(1)
                    .ok_or(CandidateSealError::ResourceLimit)?;
                Some(object)
            }
            _ => None,
        };
        visit(record, classification.role(), object)?;
    }
    if loose_objects != objects.object_count() {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(())
}

fn validate_root_commit_evidence(
    evidence: FreshRootCommitEvidence,
) -> Result<(), CandidateSealError> {
    if is_zero_oid(&evidence.commit_oid)
        || is_zero_oid(&evidence.tree_oid)
        || evidence.raw_size > MAX_RAW_OBJECT_BYTES
    {
        return Err(if evidence.raw_size > MAX_RAW_OBJECT_BYTES {
            CandidateSealError::ResourceLimit
        } else {
            CandidateSealError::InvalidRecord
        });
    }
    Ok(())
}

fn validate_object_record(record: ObjectRecord) -> Result<(), CandidateSealError> {
    validate_object_record_with_limit(record, MAX_RAW_OBJECT_BYTES)
}

fn validate_object_record_with_limit(
    record: ObjectRecord,
    maximum_raw_bytes: u64,
) -> Result<(), CandidateSealError> {
    if is_zero_oid(&record.oid) || record.raw_size > maximum_raw_bytes {
        return Err(if record.raw_size > maximum_raw_bytes {
            CandidateSealError::ResourceLimit
        } else {
            CandidateSealError::InvalidRecord
        });
    }
    Ok(())
}

fn find_object<S: SortedObjectSet + ?Sized>(objects: &S, oid: &[u8; 20]) -> Option<ObjectRecord> {
    let mut low = 0_usize;
    let mut high = objects.object_count();
    while low < high {
        let middle = low + (high - low) / 2;
        let record = objects.object_at(middle);
        match record.oid.cmp(oid) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return Some(record),
        }
    }
    None
}

fn find_object_evidence<'a>(
    objects: &'a [FreshObjectEvidence],
    oid: &[u8; 20],
) -> Option<&'a FreshObjectEvidence> {
    objects
        .binary_search_by_key(oid, |object| object.record.oid)
        .ok()
        .and_then(|index| objects.get(index))
}

fn insert_fanout(bitmap: &mut [u64; 4], prefix: u8) -> bool {
    let word = usize::from(prefix / 64);
    let mask = 1_u64 << u32::from(prefix % 64);
    let newly_inserted = bitmap[word] & mask == 0;
    bitmap[word] |= mask;
    newly_inserted
}

fn fanout_contains(bitmap: &[u64; 4], prefix: u8) -> bool {
    let word = usize::from(prefix / 64);
    let mask = 1_u64 << u32::from(prefix % 64);
    bitmap[word] & mask != 0
}

fn fanout_count(bitmap: &[u64; 4]) -> usize {
    (0_u8..=u8::MAX)
        .filter(|prefix| fanout_contains(bitmap, *prefix))
        .count()
}

fn canonical_loose_object_path(
    oid: [u8; 20],
    scratch: &mut [u8; LOOSE_OBJECT_PATH_BYTES],
) -> Result<&str, CandidateSealError> {
    scratch[..LOOSE_OBJECT_PATH_PREFIX.len()].copy_from_slice(LOOSE_OBJECT_PATH_PREFIX);
    let mut cursor = LOOSE_OBJECT_PATH_PREFIX.len();
    for (index, byte) in oid.into_iter().enumerate() {
        if index == 1 {
            scratch[cursor] = b'/';
            cursor += 1;
        }
        scratch[cursor] = lower_hex(byte >> 4);
        scratch[cursor + 1] = lower_hex(byte & 0x0f);
        cursor += 2;
    }
    if cursor != scratch.len() {
        return Err(CandidateSealError::InvalidRecord);
    }
    std::str::from_utf8(scratch).map_err(|_| CandidateSealError::InvalidRecord)
}

fn loose_fanout(
    relative: &str,
    kind: PhysicalRecordKindRef<'_>,
) -> Result<Option<u8>, CandidateSealError> {
    let Some(hex) = relative.strip_prefix("objects/") else {
        return Ok(None);
    };
    if hex.len() != 2 || hex.contains('/') {
        return Ok(None);
    }
    if !matches!(kind, PhysicalRecordKindRef::Directory(_)) {
        return Err(CandidateSealError::InvalidRecord);
    }
    let bytes = hex.as_bytes();
    Ok(Some((hex_nibble(bytes[0])? << 4) | hex_nibble(bytes[1])?))
}

fn loose_object_oid(record: PhysicalRecordRef<'_>) -> Result<[u8; 20], CandidateSealError> {
    if !matches!(record.kind, PhysicalRecordKindRef::File { .. }) {
        return Err(CandidateSealError::InvalidRecord);
    }
    let relative = git_relative_path(record.path)?;
    let encoded = relative
        .strip_prefix("objects/")
        .ok_or(CandidateSealError::InvalidRecord)?;
    let (prefix, suffix) = encoded
        .split_once('/')
        .ok_or(CandidateSealError::InvalidRecord)?;
    if prefix.len() != 2 || suffix.len() != 38 || suffix.contains('/') {
        return Err(CandidateSealError::InvalidRecord);
    }
    let mut full = [0_u8; 40];
    full[..2].copy_from_slice(prefix.as_bytes());
    full[2..].copy_from_slice(suffix.as_bytes());
    decode_lower_hex_oid(&full)
}

fn git_relative_path(path: &str) -> Result<&str, CandidateSealError> {
    path.strip_prefix(GIT_PREFIX)
        .filter(|relative| !relative.is_empty())
        .ok_or(CandidateSealError::InvalidRecord)
}

fn require_directory(kind: PhysicalRecordKindRef<'_>) -> Result<(), CandidateSealError> {
    matches!(kind, PhysicalRecordKindRef::Directory(_))
        .then_some(())
        .ok_or(CandidateSealError::InvalidRecord)
}

fn require_file(kind: PhysicalRecordKindRef<'_>) -> Result<(), CandidateSealError> {
    matches!(kind, PhysicalRecordKindRef::File { .. })
        .then_some(())
        .ok_or(CandidateSealError::InvalidRecord)
}

fn require_file_body(
    kind: PhysicalRecordKindRef<'_>,
    body: &[u8],
) -> Result<(), CandidateSealError> {
    let PhysicalRecordKindRef::File { size, sha256, .. } = kind else {
        return Err(CandidateSealError::InvalidRecord);
    };
    let expected_size = u64::try_from(body.len()).map_err(|_| CandidateSealError::ResourceLimit)?;
    if size == expected_size && sha256 == &raw_sha256(body) {
        Ok(())
    } else {
        Err(CandidateSealError::InvalidRecord)
    }
}

fn set_once(mask: &mut u8, bit: u8) -> Result<(), CandidateSealError> {
    if *mask & bit != 0 {
        return Err(CandidateSealError::InvalidRecord);
    }
    *mask |= bit;
    Ok(())
}

fn main_ref_body(oid: [u8; 20]) -> [u8; 41] {
    let mut body = [0_u8; 41];
    for (index, byte) in oid.into_iter().enumerate() {
        body[index * 2] = lower_hex(byte >> 4);
        body[index * 2 + 1] = lower_hex(byte & 0x0f);
    }
    body[40] = b'\n';
    body
}

fn take_line(bytes: &[u8]) -> Result<(&[u8], &[u8]), CandidateSealError> {
    let newline = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(CandidateSealError::InvalidRecord)?;
    Ok((&bytes[..newline], &bytes[newline + 1..]))
}

fn canonical_timestamp<'a>(line: &'a [u8], prefix: &[u8]) -> Result<&'a [u8], CandidateSealError> {
    let timestamp = line
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(UTC_SUFFIX))
        .ok_or(CandidateSealError::InvalidRecord)?;
    if timestamp.is_empty()
        || timestamp == b"-0"
        || (timestamp[0] == b'-'
            && (timestamp.len() == 1
                || timestamp[1] == b'0'
                || !timestamp[1..].iter().all(u8::is_ascii_digit)))
        || (timestamp[0] != b'-'
            && ((timestamp.len() > 1 && timestamp[0] == b'0')
                || !timestamp.iter().all(u8::is_ascii_digit)))
        || std::str::from_utf8(timestamp)
            .ok()
            .and_then(|text| text.parse::<i64>().ok())
            .is_none()
    {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(timestamp)
}

fn typed_object_oid(kind: ObjectKind, size: u64, body: &[u8]) -> [u8; 20] {
    let mut digest = Sha1::new();
    digest.update(object_kind_name(kind));
    digest.update(b" ");
    let mut decimal = [0_u8; 20];
    digest.update(decimal_u64(size, &mut decimal));
    digest.update([0]);
    digest.update(body);
    digest.finalize().into()
}

fn raw_sha256(body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(body);
    digest.finalize().into()
}

fn object_kind_name(kind: ObjectKind) -> &'static [u8] {
    match kind {
        ObjectKind::Blob => b"blob",
        ObjectKind::Tree => b"tree",
        ObjectKind::Commit => b"commit",
    }
}

fn decimal_u64(value: u64, scratch: &mut [u8; 20]) -> &[u8] {
    let mut cursor = scratch.len();
    let mut remaining = value;
    loop {
        cursor -= 1;
        scratch[cursor] = b'0' + u8::try_from(remaining % 10).unwrap_or(0);
        remaining /= 10;
        if remaining == 0 {
            return &scratch[cursor..];
        }
    }
}

fn decode_lower_hex_oid(encoded: &[u8]) -> Result<[u8; 20], CandidateSealError> {
    if encoded.len() != 40 || !encoded.iter().all(|byte| is_lower_hex(*byte)) {
        return Err(CandidateSealError::InvalidRecord);
    }
    let mut oid = [0_u8; 20];
    for (index, byte) in oid.iter_mut().enumerate() {
        *byte = (hex_nibble(encoded[index * 2])? << 4) | hex_nibble(encoded[index * 2 + 1])?;
    }
    if is_zero_oid(&oid) {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(oid)
}

fn hex_nibble(byte: u8) -> Result<u8, CandidateSealError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CandidateSealError::InvalidRecord),
    }
}

const fn lower_hex(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + nibble - 10,
    }
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn is_zero_oid(oid: &[u8; 20]) -> bool {
    oid.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::io::Write as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;
    #[cfg(target_os = "linux")]
    use std::path::{Path, PathBuf};
    #[cfg(target_os = "linux")]
    use std::process::{Command, Stdio};
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};

    use super::*;
    #[cfg(target_os = "linux")]
    use crate::repository_import::candidate_manifest::collect_marker_free_physical_manifest;
    #[cfg(target_os = "linux")]
    use inex_core::atomic::{
        PublicationIdentityScheme, VAULT_LOCAL_DIRECTORY, VAULT_MUTATION_LOCK_FILE,
        open_secure_source_root,
    };

    #[cfg(target_os = "linux")]
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    struct TestDirectory(PathBuf);

    #[cfg(target_os = "linux")]
    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, AtomicOrdering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-candidate-git-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory creates");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn object(kind: ObjectKind, body: &[u8]) -> ObjectRecord {
        let raw_size = u64::try_from(body.len()).expect("test body length fits");
        ObjectRecord {
            oid: typed_object_oid(kind, raw_size, body),
            kind,
            raw_size,
            raw_sha256: raw_sha256(body),
        }
    }

    fn canonical_commit(tree_oid: [u8; 20], timestamp: &str) -> Vec<u8> {
        let tree = main_ref_body(tree_oid);
        let tree = std::str::from_utf8(&tree[..40]).expect("hex is utf8");
        format!(
            "tree {tree}\nauthor Inex Repository Import <inex-import@localhost.invalid> {timestamp} +0000\ncommitter Inex Repository Import <inex-import@localhost.invalid> {timestamp} +0000\n\nInitialize encrypted Inex vault\n"
        )
        .into_bytes()
    }

    #[cfg(target_os = "linux")]
    fn write(path: &std::path::Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent creates");
        }
        fs::write(path, bytes).expect("fixture writes");
    }

    #[cfg(target_os = "linux")]
    fn add_loose(root: &std::path::Path, record: ObjectRecord) {
        let body = main_ref_body(record.oid);
        let hex = std::str::from_utf8(&body[..40]).expect("hex is utf8");
        write(
            &root.join(format!(".git/objects/{}/{}", &hex[..2], &hex[2..])),
            b"bounded compressed placeholder",
        );
    }

    #[cfg(target_os = "linux")]
    fn exact_fixture(records: &[ObjectRecord], commit: FreshRootCommitEvidence) -> TestDirectory {
        let target = TestDirectory::new();
        let root = target.path();
        write(
            &root
                .join(VAULT_LOCAL_DIRECTORY)
                .join(VAULT_MUTATION_LOCK_FILE),
            b"",
        );
        for directory in [
            ".git/objects/info",
            ".git/objects/pack",
            ".git/inex-empty-hooks",
            ".git/refs/heads",
            ".git/refs/tags",
        ] {
            fs::create_dir_all(root.join(directory)).expect("control directory creates");
        }
        write(&root.join(".git/HEAD"), HEAD_BODY);
        write(
            &root.join(".git/config"),
            b"[core]\n\trepositoryformatversion = 0\n",
        );
        write(&root.join(".git/index"), b"DIRC placeholder");
        write(
            &root.join(".git/refs/heads/main"),
            &main_ref_body(commit.commit_oid()),
        );
        for record in records {
            add_loose(root, *record);
        }
        target
    }

    #[cfg(target_os = "linux")]
    struct BootstrapFixture {
        root: TestDirectory,
        repository: crate::repository_import::TargetRepository,
        executable: PathBuf,
    }

    #[cfg(target_os = "linux")]
    fn bootstrap_fixture() -> BootstrapFixture {
        let root = TestDirectory::new();
        fs::create_dir(root.path().join(VAULT_LOCAL_DIRECTORY)).expect("private directory creates");
        write(
            &root
                .path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(VAULT_MUTATION_LOCK_FILE),
            b"",
        );
        write(&root.path().join("vault.json"), b"fresh target metadata");
        let repository = crate::repository_import::initialize_and_audit_target(
            root.path(),
            &[PathBuf::from("vault.json")],
            1_784_044_800,
        )
        .expect("real canonical target initializes");
        let executable = crate::repository_import::discover_git_executable()
            .expect("real Git executable resolves");
        BootstrapFixture {
            root,
            repository,
            executable,
        }
    }

    #[cfg(target_os = "linux")]
    fn physical_and_held_root(
        fixture: &BootstrapFixture,
    ) -> (MarkerFreePhysicalManifest, SecureSourceDirectory) {
        let physical = collect_marker_free_physical_manifest(fixture.root.path())
            .expect("fresh target physical manifest collects");
        let held_root =
            open_secure_source_root(fixture.root.path()).expect("fresh target root holds");
        (physical, held_root)
    }

    #[cfg(target_os = "linux")]
    fn loose_path(root: &Path, oid: &str) -> PathBuf {
        root.join(".git/objects").join(&oid[..2]).join(&oid[2..])
    }

    #[cfg(target_os = "linux")]
    fn hash_literal_object(fixture: &BootstrapFixture, kind: &str, body: &[u8]) -> String {
        let mut child = Command::new(&fixture.executable)
            .current_dir(fixture.root.path())
            .args(["hash-object", "-t", kind, "--literally", "-w", "--stdin"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", super::super::null_device())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("literal hash-object starts");
        child
            .stdin
            .take()
            .expect("literal hash-object stdin exists")
            .write_all(body)
            .expect("literal object body writes");
        let output = child
            .wait_with_output()
            .expect("literal hash-object completes");
        assert!(output.status.success(), "literal hash-object succeeds");
        let oid = std::str::from_utf8(&output.stdout)
            .expect("literal object id is UTF-8")
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        assert_eq!(oid.len(), 40);
        oid
    }

    #[cfg(target_os = "linux")]
    fn replace_main_ref_object(fixture: &BootstrapFixture, kind: &str, body: &[u8]) -> String {
        let main_ref = fixture.root.path().join(".git/refs/heads/main");
        let previous = fs::read_to_string(&main_ref)
            .expect("current main ref reads")
            .trim()
            .to_owned();
        let oid = hash_literal_object(fixture, kind, body);
        write(&main_ref, format!("{oid}\n").as_bytes());
        if previous != oid {
            let previous_path = loose_path(fixture.root.path(), &previous);
            fs::remove_file(&previous_path).expect("previous root object removes");
            let fanout = previous_path.parent().expect("loose object has fanout");
            if fs::read_dir(fanout).expect("fanout reads").next().is_none() {
                fs::remove_dir(fanout).expect("unused fanout removes");
            }
        }
        oid
    }

    #[cfg(target_os = "linux")]
    fn create_git_spy(real_git: &Path, directory: &TestDirectory) -> PathBuf {
        let spy = directory.path().join("git-spy");
        let real = real_git
            .to_str()
            .expect("real Git path is UTF-8")
            .replace('\'', "'\"'\"'");
        let script = format!(
            "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\" >> \"$0.log\"; done\nprintf '%s\\n' -- >> \"$0.log\"\ncase \" $* \" in\n  *\" cat-file commit \"*) if IFS= read -r unexpected; then exit 98; fi ;;\nesac\nexec '{real}' \"$@\"\n"
        );
        fs::write(&spy, script).expect("Git spy writes");
        let mut permissions = fs::metadata(&spy)
            .expect("Git spy metadata reads")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&spy, permissions).expect("Git spy becomes executable");
        spy
    }

    #[cfg(target_os = "linux")]
    fn spy_commands(spy: &Path) -> Vec<Vec<String>> {
        let log = fs::read_to_string(format!("{}.log", spy.display())).expect("Git spy log reads");
        let mut commands = Vec::new();
        let mut current = Vec::new();
        for line in log.lines() {
            if line == "--" {
                commands.push(std::mem::take(&mut current));
            } else {
                current.push(line.to_owned());
            }
        }
        assert!(current.is_empty(), "every logged command is terminated");
        commands
    }

    #[test]
    fn canonical_commit_parser_accepts_i64_edges_and_rejects_noncanonical_forms() {
        let tree = object(ObjectKind::Tree, b"");
        for timestamp in [i64::MIN.to_string(), "0".to_owned(), i64::MAX.to_string()] {
            let body = canonical_commit(tree.oid, &timestamp);
            let parsed = parse_canonical_root_commit(&body).expect("canonical commit parses");
            assert_eq!(parsed.tree_oid(), tree.oid);
            assert_eq!(parsed.commit_oid(), object(ObjectKind::Commit, &body).oid);
            assert_eq!(parsed.raw_size(), body.len() as u64);
            assert_eq!(parsed.raw_sha256(), raw_sha256(&body));
        }

        for timestamp in ["00", "01", "-0", "+1", "9223372036854775808"] {
            assert_eq!(
                parse_canonical_root_commit(&canonical_commit(tree.oid, timestamp)),
                Err(CandidateSealError::InvalidRecord)
            );
        }
        let mut parent = canonical_commit(tree.oid, "1");
        let insertion = parent
            .windows(7)
            .position(|window| window == b"author ")
            .expect("author exists");
        parent.splice(
            insertion..insertion,
            b"parent 1111111111111111111111111111111111111111\n"
                .iter()
                .copied(),
        );
        assert_eq!(
            parse_canonical_root_commit(&parent),
            Err(CandidateSealError::InvalidRecord)
        );
        let mut trailing = canonical_commit(tree.oid, "1");
        trailing.push(b'!');
        assert_eq!(
            parse_canonical_root_commit(&trailing),
            Err(CandidateSealError::InvalidRecord)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_root_commit_bootstrap_reads_one_real_canonical_commit_with_fixed_commands() {
        let fixture = bootstrap_fixture();
        let spy_directory = TestDirectory::new();
        let spy = create_git_spy(&fixture.executable, &spy_directory);
        let runner = GitRunner::target(spy.clone(), fixture.root.path().to_path_buf())
            .expect("spy target runner binds");
        let (physical, held_root) = physical_and_held_root(&fixture);

        let observed = collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner)
            .expect("real canonical commit bootstraps");
        let expected = parse_canonical_root_commit(fixture.repository.commit_bytes.as_slice())
            .expect("creation proof contains canonical commit");
        assert_eq!(observed, expected);

        let oid = fixture.repository.root_commit_oid().to_owned();
        assert_eq!(
            spy_commands(&spy),
            vec![
                vec![
                    "config".to_owned(),
                    "--file".to_owned(),
                    "-".to_owned(),
                    "--no-includes".to_owned(),
                    "--null".to_owned(),
                    "--list".to_owned(),
                ],
                vec![
                    "-c".to_owned(),
                    "core.fsmonitor=false".to_owned(),
                    "-c".to_owned(),
                    "protocol.allow=never".to_owned(),
                    "-c".to_owned(),
                    "submodule.recurse=false".to_owned(),
                    "-c".to_owned(),
                    "core.splitIndex=false".to_owned(),
                    "-c".to_owned(),
                    "core.hooksPath=.git/inex-empty-hooks".to_owned(),
                    "cat-file".to_owned(),
                    "commit".to_owned(),
                    oid,
                ],
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_root_commit_bootstrap_rejects_bounds_type_corruption_and_noncanonical_grammar() {
        let fixture = bootstrap_fixture();
        let runner = GitRunner::target(
            fixture.executable.clone(),
            fixture.root.path().to_path_buf(),
        )
        .expect("real target runner binds");
        let canonical = fixture.repository.commit_bytes.as_slice().to_vec();

        let mut parent = canonical.clone();
        let author = parent
            .windows(b"author ".len())
            .position(|window| window == b"author ")
            .expect("canonical author header exists");
        parent.splice(
            author..author,
            b"parent 1111111111111111111111111111111111111111\n"
                .iter()
                .copied(),
        );

        let mut extra_header = canonical.clone();
        let author = extra_header
            .windows(b"author ".len())
            .position(|window| window == b"author ")
            .expect("canonical author header exists");
        extra_header.splice(author..author, b"encoding UTF-8\n".iter().copied());

        let timezone = String::from_utf8(canonical.clone())
            .expect("canonical commit is UTF-8")
            .replace(" +0000", " +0100")
            .into_bytes();
        let mut tree = canonical.clone();
        let tree_end = tree
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("tree header ends");
        tree[5..tree_end].make_ascii_uppercase();
        let mut trailing = canonical.clone();
        trailing.push(b'!');

        let over_limit = vec![b'x'; MAX_CANONICAL_ROOT_COMMIT_BYTES + 1];
        replace_main_ref_object(&fixture, "commit", &over_limit);
        let (physical, held_root) = physical_and_held_root(&fixture);
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner),
            Err(RepositoryImportError::ResourceLimit)
        ));

        for body in [&parent, &extra_header, &timezone, &tree, &trailing] {
            replace_main_ref_object(&fixture, "commit", body);
            let (physical, held_root) = physical_and_held_root(&fixture);
            assert!(matches!(
                collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner),
                Err(RepositoryImportError::TargetAuditFailed)
            ));
        }

        replace_main_ref_object(&fixture, "blob", b"wrong target object type");
        let (physical, held_root) = physical_and_held_root(&fixture);
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner),
            Err(RepositoryImportError::GitCommandFailed {
                operation: crate::repository_import::RepositoryGitOperation::AuditTarget
            })
        ));

        let oid = replace_main_ref_object(&fixture, "commit", &canonical);
        let loose = loose_path(fixture.root.path(), &oid);
        let compressed = fs::read(&loose).expect("canonical loose commit reads");
        let original_permissions = fs::metadata(&loose)
            .expect("canonical loose commit metadata reads")
            .permissions();
        let mut writable_permissions = original_permissions.clone();
        writable_permissions.set_mode(0o600);
        fs::set_permissions(&loose, writable_permissions)
            .expect("canonical loose commit becomes writable");
        fs::write(&loose, b"not a zlib object").expect("loose commit corrupts");
        let (physical, held_root) = physical_and_held_root(&fixture);
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner),
            Err(RepositoryImportError::GitCommandFailed {
                operation: crate::repository_import::RepositoryGitOperation::AuditTarget
            })
        ));
        fs::write(&loose, compressed).expect("canonical loose commit restores");
        fs::set_permissions(loose, original_permissions)
            .expect("canonical loose commit permissions restore");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_root_commit_bootstrap_rejects_shape_and_config_before_cat_file() {
        let fixture = bootstrap_fixture();
        let spy_directory = TestDirectory::new();
        let spy = create_git_spy(&fixture.executable, &spy_directory);
        let runner = GitRunner::target(spy.clone(), fixture.root.path().to_path_buf())
            .expect("spy target runner binds");

        let alternates = fixture.root.path().join(".git/objects/info/alternates");
        write(&alternates, b"/forbidden/alternate\n");
        let (physical, held_root) = physical_and_held_root(&fixture);
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert!(!PathBuf::from(format!("{}.log", spy.display())).exists());
        fs::remove_file(alternates).expect("forbidden alternate removes");

        let pack = fixture
            .root
            .path()
            .join(".git/objects/pack/pack-deadbeef.pack");
        write(&pack, b"forbidden pack");
        let (physical, held_root) = physical_and_held_root(&fixture);
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert!(!PathBuf::from(format!("{}.log", spy.display())).exists());
        fs::remove_file(pack).expect("forbidden pack removes");

        let config_path = fixture.root.path().join(".git/config");
        let mut config = fs::read(&config_path).expect("canonical config reads");
        config.extend_from_slice(b"[remote \"origin\"]\n\turl = https://invalid.example/\n");
        fs::write(&config_path, config).expect("invalid extra config writes");
        let (physical, held_root) = physical_and_held_root(&fixture);
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        let commands = spy_commands(&spy);
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            ["config", "--file", "-", "--no-includes", "--null", "--list"]
        );
        assert!(
            commands
                .iter()
                .flatten()
                .all(|argument| argument != "cat-file")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_root_commit_bootstrap_requires_typed_oid_and_common_live_root() {
        let fixture = bootstrap_fixture();
        let substitute = canonical_commit(
            parse_canonical_root_commit(fixture.repository.commit_bytes.as_slice())
                .expect("creation commit parses")
                .tree_oid(),
            "1784044801",
        );
        let spy_directory = TestDirectory::new();
        let spy = spy_directory.path().join("substitute-git");
        let body_path = PathBuf::from(format!("{}.body", spy.display()));
        fs::write(&body_path, substitute).expect("substitute commit body writes");
        let real = fixture
            .executable
            .to_str()
            .expect("real Git path is UTF-8")
            .replace('\'', "'\"'\"'");
        fs::write(
            &spy,
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" cat-file commit \"*) cat \"$0.body\"; exit 0 ;; esac\nexec '{real}' \"$@\"\n"
            ),
        )
        .expect("substitute Git spy writes");
        let mut permissions = fs::metadata(&spy)
            .expect("substitute spy metadata reads")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&spy, permissions).expect("substitute spy becomes executable");
        let runner = GitRunner::target(spy, fixture.root.path().to_path_buf())
            .expect("substitute target runner binds");
        let (physical, held_root) = physical_and_held_root(&fixture);
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner),
            Err(RepositoryImportError::TargetAuditFailed)
        ));

        let other = bootstrap_fixture();
        let other_runner =
            GitRunner::target(other.executable.clone(), other.root.path().to_path_buf())
                .expect("other target runner binds");
        let (physical, held_root) = physical_and_held_root(&fixture);
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &other_runner),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_root_commit_bootstrap_preserves_config_git_and_io_errors() {
        let fixture = bootstrap_fixture();
        let (physical, held_root) = physical_and_held_root(&fixture);
        let missing_runner = GitRunner::target(
            fixture.root.path().join("missing-config-git"),
            fixture.root.path().to_path_buf(),
        )
        .expect("target runner binds independently of executable spawn");
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &missing_runner),
            Err(RepositoryImportError::Io {
                operation: crate::repository_import::RepositoryIoOperation::SpawnGit,
                kind: std::io::ErrorKind::NotFound,
            })
        ));

        let wrapper_directory = TestDirectory::new();
        let wrapper = wrapper_directory.path().join("failing-config-git");
        fs::write(&wrapper, "#!/bin/sh\nexit 73\n").expect("failing config wrapper writes");
        let mut permissions = fs::metadata(&wrapper)
            .expect("failing config wrapper metadata reads")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&wrapper, permissions)
            .expect("failing config wrapper becomes executable");
        let failed_runner = GitRunner::target(wrapper, fixture.root.path().to_path_buf())
            .expect("failing config target runner binds");
        assert!(matches!(
            collect_fresh_target_root_commit_evidence(&physical, &held_root, &failed_runner),
            Err(RepositoryImportError::GitCommandFailed {
                operation: crate::repository_import::RepositoryGitOperation::InspectConfiguration
            })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_root_commit_bootstrap_rejects_root_rename_inside_command_window() {
        let fixture = bootstrap_fixture();
        let wrapper_directory = TestDirectory::new();
        let wrapper = wrapper_directory.path().join("gated-root-git");
        let ready = wrapper_directory.path().join("cat-file-ready");
        let release = wrapper_directory.path().join("cat-file-release");
        let body = wrapper_directory.path().join("canonical-commit-body");
        fs::write(&body, fixture.repository.commit_bytes.as_slice())
            .expect("canonical wrapper body writes");

        let shell_quote = |path: &Path| {
            format!(
                "'{}'",
                path.to_str()
                    .expect("test path is UTF-8")
                    .replace('\'', "'\"'\"'")
            )
        };
        let real = shell_quote(&fixture.executable);
        let ready_argument = shell_quote(&ready);
        let release_argument = shell_quote(&release);
        let body_argument = shell_quote(&body);
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\ncase \" $* \" in\n  *\" cat-file commit \"*)\n    : > {ready_argument}\n    while [ ! -e {release_argument} ]; do :; done\n    /bin/cat {body_argument}\n    exit 0\n    ;;\nesac\nexec {real} \"$@\"\n"
            ),
        )
        .expect("gated Git wrapper writes");
        let mut permissions = fs::metadata(&wrapper)
            .expect("gated Git wrapper metadata reads")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&wrapper, permissions).expect("gated Git wrapper becomes executable");

        let runner = GitRunner::target(wrapper, fixture.root.path().to_path_buf())
            .expect("gated target runner binds");
        let (physical, held_root) = physical_and_held_root(&fixture);
        let moved = fixture
            .root
            .path()
            .with_extension("command-window-old-root");
        let root_for_thread = fixture.root.path().to_path_buf();
        let moved_for_thread = moved.clone();
        let ready_for_thread = ready.clone();
        let release_for_thread = release.clone();
        let outcome = std::thread::scope(|scope| {
            let renamer = scope.spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !ready_for_thread.exists() {
                    if Instant::now() >= deadline {
                        let _ = fs::write(&release_for_thread, []);
                        return Err("cat-file wrapper did not enter its command window");
                    }
                    std::thread::yield_now();
                }
                fs::rename(&root_for_thread, &moved_for_thread)
                    .map_err(|_| "target root did not rename")?;
                fs::write(&release_for_thread, [])
                    .map_err(|_| "cat-file wrapper did not release")?;
                Ok::<(), &'static str>(())
            });
            let outcome = collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner);
            renamer
                .join()
                .expect("command-window renamer does not panic")
                .expect("command-window rename and release succeed");
            outcome
        });
        assert!(matches!(
            outcome,
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert!(!fixture.root.path().exists());
        assert!(moved.exists());
        fs::rename(&moved, fixture.root.path()).expect("target root restores for cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_root_identity_guard_rejects_unheld_hooks_and_old_renamed_root() {
        let fixture = bootstrap_fixture();
        let (physical, _held_root) = physical_and_held_root(&fixture);
        let uninitialized = GitRunner::target_uninitialized(
            fixture.executable.clone(),
            fixture.root.path().to_path_buf(),
        );
        assert!(matches!(
            uninitialized.target_root_identity_guard(physical.root_identity()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));

        let missing_runner = GitRunner::target(
            fixture.root.path().join("missing-git-executable"),
            fixture.root.path().to_path_buf(),
        )
        .expect("target root can bind before the fixed executable is spawned");
        let missing_guard = missing_runner
            .target_root_identity_guard(physical.root_identity())
            .expect("missing-executable guard still binds the exact root");
        assert!(matches!(
            missing_guard.read_canonical_root_commit(fixture.repository.root_commit_oid()),
            Err(RepositoryImportError::Io {
                operation: crate::repository_import::RepositoryIoOperation::SpawnGit,
                kind: std::io::ErrorKind::NotFound,
            })
        ));

        let runner = GitRunner::target(
            fixture.executable.clone(),
            fixture.root.path().to_path_buf(),
        )
        .expect("target runner binds");
        let guard = runner
            .target_root_identity_guard(physical.root_identity())
            .expect("exact root guard binds");
        let moved = fixture.root.path().with_extension("held-old-root");
        fs::rename(fixture.root.path(), &moved).expect("target root renames");
        assert!(matches!(
            guard.verify(),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        fs::rename(&moved, fixture.root.path()).expect("target root restores for cleanup");

        write(
            &fixture.root.path().join(".git/inex-empty-hooks/pre-commit"),
            b"#!/bin/sh\nexit 99\n",
        );
        assert!(matches!(
            runner.target_root_identity_guard(physical.root_identity()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn target_root_commit_bootstrap_api_accepts_no_vault_source_or_password_authority() {
        let source = include_str!("candidate_git.rs");
        let start = source
            .find("pub(super) fn collect_fresh_target_root_commit_evidence(")
            .expect("Linux bootstrap signature exists");
        let signature = source[start..]
            .split_once(") -> Result<FreshRootCommitEvidence, RepositoryImportError>")
            .map(|(signature, _)| signature)
            .expect("Linux bootstrap signature is bounded");
        assert!(signature.contains("physical: &MarkerFreePhysicalManifest"));
        assert!(signature.contains("held_root: &SecureSourceDirectory"));
        assert!(signature.contains("runner: &GitRunner"));
        assert!(!signature.contains("Vault"));
        assert!(!signature.contains("SourceSnapshot"));
        assert!(!signature.contains("password"));
    }

    #[test]
    fn streaming_verifier_is_chunk_boundary_independent_and_fail_closed() {
        let body = vec![0xa5; 68 * 1024 + 3];
        let expected = object(ObjectKind::Blob, &body);
        let mut verifier = StreamingObjectVerifier::new(expected).expect("verifier starts");
        for chunk in body.chunks(16 * 1024) {
            verifier.update(chunk).expect("chunk verifies");
        }
        verifier.finish().expect("exact stream verifies");

        let mut truncated = StreamingObjectVerifier::new(expected).expect("verifier starts");
        truncated
            .update(&body[..body.len() - 1])
            .expect("prefix accepted");
        assert_eq!(truncated.finish(), Err(CandidateSealError::InvalidRecord));

        let mut overrun = StreamingObjectVerifier::new(expected).expect("verifier starts");
        assert_eq!(
            overrun.update(&vec![0; body.len() + 1]),
            Err(CandidateSealError::InvalidRecord)
        );

        let wrong_kind = ObjectRecord {
            kind: ObjectKind::Tree,
            ..expected
        };
        let mut verifier = StreamingObjectVerifier::new(wrong_kind).expect("verifier starts");
        verifier.update(&body).expect("body length matches");
        assert_eq!(verifier.finish(), Err(CandidateSealError::InvalidRecord));

        let mut wrong_raw_sha = expected;
        wrong_raw_sha.raw_sha256[0] ^= 0xff;
        let mut verifier = StreamingObjectVerifier::new(wrong_raw_sha).expect("verifier starts");
        verifier.update(&body).expect("body length matches");
        assert_eq!(verifier.finish(), Err(CandidateSealError::InvalidRecord));
    }

    #[test]
    fn streaming_verifier_enforces_exact_raw_size_boundary_without_large_allocation() {
        let body = vec![0x5a; 4_096];
        let exact = object(ObjectKind::Blob, &body);
        let mut verifier = StreamingObjectVerifier::new_with_limit(exact, 4_096)
            .expect("injected exact boundary starts");
        verifier.update(&body).expect("exact boundary streams");
        verifier.finish().expect("exact boundary verifies");

        let plus_one = ObjectRecord {
            raw_size: 4_097,
            ..exact
        };
        assert!(matches!(
            StreamingObjectVerifier::new_with_limit(plus_one, 4_096),
            Err(CandidateSealError::ResourceLimit)
        ));

        let exact_frozen_limit = ObjectRecord {
            raw_size: MAX_RAW_OBJECT_BYTES,
            ..exact
        };
        assert!(StreamingObjectVerifier::new(exact_frozen_limit).is_ok());
        let frozen_plus_one = ObjectRecord {
            raw_size: MAX_RAW_OBJECT_BYTES + 1,
            ..exact
        };
        assert!(matches!(
            StreamingObjectVerifier::new(frozen_plus_one),
            Err(CandidateSealError::ResourceLimit)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_control_graph_projects_only_borrowed_paths() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit_body = canonical_commit(tree.oid, "1784044800");
        let commit = parse_canonical_root_commit(&commit_body).expect("commit parses");
        let commit_record = commit.object_record();
        let target = exact_fixture(&[blob, tree, commit_record], commit);
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        let evidence = collect_fresh_git_evidence_from_records_for_test(
            &physical,
            &[blob, blob],
            &[tree],
            commit,
        )
        .expect("exact Git evidence collects");
        assert_eq!(evidence.objects.len(), 3);
        assert!(
            evidence
                .objects
                .windows(2)
                .all(|pair| pair[0].record.oid < pair[1].record.oid)
        );
        let projection = evidence
            .project(PublicationIdentityScheme::LinuxDevInodeV1)
            .expect("evidence projects");
        assert_eq!(projection.head_refs.commit_oid, commit.commit_oid());
        assert_eq!(projection.root_commit.tree_oid, tree.oid);
        assert_eq!(projection.objects.len(), 3);
        assert_eq!(
            projection
                .git_control
                .iter()
                .filter(|record| record.role == GitControlRole::StructuralDirectory)
                .count(),
            6
        );
        assert!(projection.git_control.iter().all(|record| {
            !record.path.starts_with(GIT_PREFIX) && !record.path.starts_with('/')
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn control_shape_is_manifest_branded_requires_exact_loose_files_and_redacts_debug() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit = parse_canonical_root_commit(&canonical_commit(tree.oid, "1784044800"))
            .expect("commit parses");
        let records = [blob, tree, commit.object_record()];
        let first_target = exact_fixture(&records, commit);
        let first = collect_marker_free_physical_manifest(first_target.path())
            .expect("first physical manifest collects");
        let shape =
            preflight_fresh_git_control_shape(&first).expect("exact control shape preflights");
        assert!(shape.is_bound_to(&first));
        for record in records {
            shape
                .require_loose_object(record.oid)
                .expect("exact branded loose file exists");
        }

        let only_second = object(ObjectKind::Blob, b"second-only");
        let second_records = [blob, only_second, tree, commit.object_record()];
        let second_target = exact_fixture(&second_records, commit);
        let second = collect_marker_free_physical_manifest(second_target.path())
            .expect("second physical manifest collects");
        assert!(!shape.is_bound_to(&second));
        assert_eq!(
            shape.require_loose_object(only_second.oid),
            Err(CandidateSealError::InvalidRecord)
        );

        let debug = format!("{shape:?}");
        let blob_hex = main_ref_body(blob.oid);
        let blob_hex = std::str::from_utf8(&blob_hex[..40]).expect("hex is UTF-8");
        assert!(debug.contains("[BOUND MANIFEST]"));
        assert!(debug.contains("loose_objects: 3"));
        assert!(!debug.contains(".git"));
        assert!(!debug.contains(blob_hex));

        assert_eq!(
            std::mem::size_of::<FreshGitControlShape<'_>>(),
            std::mem::size_of::<&MarkerFreePhysicalManifest>()
                + std::mem::size_of::<usize>()
                + std::mem::size_of::<[u64; 4]>()
        );
        let source = include_str!("candidate_git.rs");
        let declaration = source
            .find("pub(super) struct FreshGitControlShape")
            .expect("shape declaration exists");
        let previous_item = source[..declaration]
            .rfind("\n}\n")
            .expect("preceding item ends");
        assert!(!source[previous_item..declaration].contains("#[derive("));
        let declaration_end = source[declaration..]
            .find("\n}\n")
            .map(|offset| declaration + offset)
            .expect("shape declaration ends");
        assert!(!source[declaration..declaration_end].contains("Vec<"));
        assert!(!source.contains(&["impl Clone", " for FreshGitControlShape"].concat()));
        assert!(!source.contains(&["impl Copy", " for FreshGitControlShape"].concat()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shape_preflight_allows_syntactic_extra_loose_but_exact_scan_rejects_it() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit =
            parse_canonical_root_commit(&canonical_commit(tree.oid, "1")).expect("commit parses");
        let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
        let unreachable = object(ObjectKind::Blob, b"syntactically-valid-unreachable");
        add_loose(target.path(), unreachable);
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        let shape = preflight_fresh_git_control_shape(&physical)
            .expect("shape accepts syntactically valid loose object");
        shape
            .require_loose_object(unreachable.oid)
            .expect("preflight retains exact loose location");
        assert!(matches!(
            collect_fresh_git_evidence_from_records_for_test(&physical, &[blob], &[tree], commit,),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shape_preflight_defers_only_main_ref_value_to_exact_scan() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit =
            parse_canonical_root_commit(&canonical_commit(tree.oid, "1")).expect("commit parses");
        let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
        write(
            &target.path().join(".git/refs/heads/main"),
            b"1111111111111111111111111111111111111111\n",
        );
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        preflight_fresh_git_control_shape(&physical)
            .expect("main ref is an exact fixed file before value bootstrap");
        assert!(matches!(
            collect_fresh_git_evidence_from_records_for_test(&physical, &[blob], &[tree], commit,),
            Err(CandidateSealError::InvalidRecord)
        ));

        let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
        write(&target.path().join(".git/HEAD"), b"ref: refs/heads/other\n");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        assert_eq!(
            preflight_fresh_git_control_shape(&physical).map(|_| ()),
            Err(CandidateSealError::InvalidRecord)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shape_preflight_rejects_forbidden_names_uppercase_and_invalid_kinds() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit =
            parse_canonical_root_commit(&canonical_commit(tree.oid, "1")).expect("commit parses");
        let records = [blob, tree, commit.object_record()];
        for relative in [
            ".git/objects/info/alternates",
            ".git/objects/pack/pack-deadbeef.pack",
            ".git/commondir",
            ".git/config.worktree",
            ".git/packed-refs",
            ".git/shallow",
            ".git/info/grafts",
            ".git/refs/replace/1111111111111111111111111111111111111111",
            ".git/logs/HEAD",
            ".git/refs/heads/other",
            ".git/hooks/pre-commit",
            ".git/modules/child/config",
            ".git/inex-empty-hooks/pre-commit",
        ] {
            let target = exact_fixture(&records, commit);
            write(&target.path().join(relative), b"forbidden\n");
            let physical = collect_marker_free_physical_manifest(target.path())
                .expect("forbidden fixture remains physically collectable");
            assert!(
                preflight_fresh_git_control_shape(&physical).is_err(),
                "forbidden Git control path passed: {relative}"
            );
        }

        let used_prefixes = records.map(|record| record.oid[0]);
        let uppercase_prefix = (0xa0_u8..=0xff)
            .find(|candidate| !used_prefixes.contains(candidate))
            .expect("an alphabetic unused prefix exists");
        let uppercase_prefix = format!("{uppercase_prefix:02X}");
        let target = exact_fixture(&records, commit);
        write(
            &target.path().join(format!(
                ".git/objects/{uppercase_prefix}/11111111111111111111111111111111111111"
            )),
            b"forbidden\n",
        );
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("uppercase fixture remains physically collectable");
        assert!(preflight_fresh_git_control_shape(&physical).is_err());

        let target = exact_fixture(&records, commit);
        let config = target.path().join(".git/config");
        fs::remove_file(&config).expect("config file removes");
        fs::create_dir(&config).expect("wrong-kind config directory creates");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("wrong-kind fixture remains physically collectable");
        assert!(preflight_fresh_git_control_shape(&physical).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shape_preflight_requires_fanout_set_to_match_loose_prefixes_exactly() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit =
            parse_canonical_root_commit(&canonical_commit(tree.oid, "1")).expect("commit parses");
        let records = [blob, tree, commit.object_record()];
        let unused = (0_u8..=u8::MAX)
            .find(|candidate| records.iter().all(|record| record.oid[0] != *candidate))
            .expect("unused fanout exists");
        let target = exact_fixture(&records, commit);
        fs::create_dir(target.path().join(format!(".git/objects/{unused:02x}")))
            .expect("extra empty fanout creates");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        assert_eq!(
            preflight_fresh_git_control_shape(&physical).map(|_| ()),
            Err(CandidateSealError::InvalidRecord)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bound_manifest_cannot_project_against_same_layout_different_identities() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit = parse_canonical_root_commit(&canonical_commit(tree.oid, "1784044800"))
            .expect("commit parses");
        let records = [blob, tree, commit.object_record()];
        let first_target = exact_fixture(&records, commit);
        let second_target = exact_fixture(&records, commit);
        let first = collect_marker_free_physical_manifest(first_target.path())
            .expect("first physical manifest collects");
        let second = collect_marker_free_physical_manifest(second_target.path())
            .expect("second physical manifest collects");

        let bound =
            collect_fresh_git_evidence_from_records_for_test(&first, &[blob], &[tree], commit)
                .expect("Git evidence binds first manifest");
        // There is intentionally no physical-manifest argument here: a caller
        // cannot ask this evidence to project against `second`.
        let projection = bound
            .project(PublicationIdentityScheme::LinuxDevInodeV1)
            .expect("bound evidence projects");
        let projected_head = projection
            .git_control
            .iter()
            .find(|record| record.path == "HEAD")
            .expect("HEAD projects");
        let GitControlRecordKind::File {
            identity: projected_identity,
            ..
        } = projected_head.kind
        else {
            panic!("HEAD projects as file");
        };
        let first_head = first.find(".git/HEAD").expect("first HEAD exists");
        let second_head = second.find(".git/HEAD").expect("second HEAD exists");
        let PhysicalRecordKindRef::File {
            identity: first_identity,
            ..
        } = first_head.kind
        else {
            panic!("first HEAD is file");
        };
        let PhysicalRecordKindRef::File {
            identity: second_identity,
            ..
        } = second_head.kind
        else {
            panic!("second HEAD is file");
        };
        let first_identity = CandidateFileIdentity::from_observed(
            first_identity,
            PublicationIdentityScheme::LinuxDevInodeV1,
        )
        .expect("first identity projects");
        let second_identity = CandidateFileIdentity::from_observed(
            second_identity,
            PublicationIdentityScheme::LinuxDevInodeV1,
        )
        .expect("second identity projects");
        assert_eq!(projected_identity, first_identity);
        assert_ne!(projected_identity, second_identity);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conflicting_oid_evidence_and_extra_control_state_are_rejected() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit_body = canonical_commit(tree.oid, "1");
        let commit = parse_canonical_root_commit(&commit_body).expect("commit parses");
        let conflict = ObjectRecord {
            kind: ObjectKind::Tree,
            ..blob
        };
        assert_eq!(
            canonical_object_union(&[blob], &[conflict, tree], commit),
            Err(CandidateSealError::InvalidRecord)
        );
        assert_eq!(
            canonical_object_union(&[blob], &[], commit),
            Err(CandidateSealError::InvalidRecord)
        );

        let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
        fs::create_dir_all(target.path().join(".git/logs"))
            .expect("extra control directory creates");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        assert!(matches!(
            collect_fresh_git_evidence_from_records_for_test(&physical, &[blob], &[tree], commit,),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn extra_unreachable_loose_object_and_nonempty_hooks_are_rejected() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit_body = canonical_commit(tree.oid, "1");
        let commit = parse_canonical_root_commit(&commit_body).expect("commit parses");
        let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
        add_loose(target.path(), object(ObjectKind::Blob, b"unreachable"));
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        assert!(matches!(
            collect_fresh_git_evidence_from_records_for_test(&physical, &[blob], &[tree], commit,),
            Err(CandidateSealError::InvalidRecord)
        ));

        let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
        write(
            &target.path().join(".git/inex-empty-hooks/pre-commit"),
            b"exit 0\n",
        );
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        assert!(matches!(
            collect_fresh_git_evidence_from_records_for_test(&physical, &[blob], &[tree], commit,),
            Err(CandidateSealError::InvalidRecord)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pack_alternates_and_unknown_control_entries_are_rejected() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit =
            parse_canonical_root_commit(&canonical_commit(tree.oid, "1")).expect("commit parses");
        for relative in [
            ".git/objects/pack/pack-deadbeef.pack",
            ".git/objects/info/alternates",
            ".git/unknown-control",
        ] {
            let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
            write(&target.path().join(relative), b"forbidden\n");
            let physical = collect_marker_free_physical_manifest(target.path())
                .expect("physical manifest collects");
            assert!(matches!(
                collect_fresh_git_evidence_from_records_for_test(
                    &physical,
                    &[blob],
                    &[tree],
                    commit,
                ),
                Err(CandidateSealError::InvalidRecord)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn head_and_main_ref_are_bound_to_canonical_bytes() {
        let blob = object(ObjectKind::Blob, b"ciphertext");
        let tree = object(ObjectKind::Tree, b"");
        let commit_body = canonical_commit(tree.oid, "1");
        let commit = parse_canonical_root_commit(&commit_body).expect("commit parses");
        let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
        write(&target.path().join(".git/HEAD"), b"ref: refs/heads/other\n");
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        assert!(matches!(
            collect_fresh_git_evidence_from_records_for_test(&physical, &[blob], &[tree], commit,),
            Err(CandidateSealError::InvalidRecord)
        ));

        let target = exact_fixture(&[blob, tree, commit.object_record()], commit);
        write(
            &target.path().join(".git/refs/heads/main"),
            b"1111111111111111111111111111111111111111\n",
        );
        let physical = collect_marker_free_physical_manifest(target.path())
            .expect("physical manifest collects");
        assert!(matches!(
            collect_fresh_git_evidence_from_records_for_test(&physical, &[blob], &[tree], commit,),
            Err(CandidateSealError::InvalidRecord)
        ));
    }
}
