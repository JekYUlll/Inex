//! Opaque runtime proof for every object in one fresh Git manifest.
//!
//! Construction drives the legacy target `git cat-file --batch` transport over
//! the manifest's complete sorted/unique object set. Each response is consumed
//! through the transport's fixed 16 KiB buffer and requires an exact canonical
//! header, exact body length and digests, one trailing LF, and final EOF after
//! stdin is closed. The proof is created only after every object and batch
//! shutdown have succeeded.
//!
//! This is intentionally a trusted-local Linux preview. `TargetObjectBatch`
//! supervises one dedicated Git process group with a deadline and terminates
//! that group before joining its bounded readers. A hostile descendant that
//! escapes the group remains outside this Linux preview's authority; the proof
//! consequently does not establish hostile process-tree containment, a total
//! wall-clock bound, mutation-lock authority, or publication authority.

use std::fmt;

#[cfg(target_os = "linux")]
use inex_core::atomic::open_secure_source_root;

use super::{
    CandidateGitProjection, FreshGitManifest, ObjectKind, ObjectRecord,
    validate_fresh_git_manifest, validate_object_record,
};
#[cfg(any(target_os = "linux", test))]
use crate::repository_import::TargetObjectExpectation;
use crate::repository_import::candidate_manifest::MarkerFreePhysicalManifest;
use crate::repository_import::candidate_seal::CandidateSealError;
use crate::repository_import::candidate_worktree::{FreshTrackedManifest, FreshTreeManifest};
#[cfg(target_os = "linux")]
use crate::repository_import::{GitRunner, TargetObjectBatch};
use crate::repository_import::{RepositoryImportError, TARGET_OBJECT_STREAM_CHUNK_BYTES};

const _: () = assert!(TARGET_OBJECT_STREAM_CHUNK_BYTES == 16 * 1024);

/// Successful runtime verification permanently bound to one Git manifest.
///
/// It owns no body, path, process, lock, or publication capability.
pub(in crate::repository_import) struct FreshRuntimeObjectProof<'manifest, 'physical> {
    git: &'manifest FreshGitManifest<'physical>,
    verified_objects: usize,
}

impl fmt::Debug for FreshRuntimeObjectProof<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshRuntimeObjectProof")
            .field("git", &"[BOUND MANIFEST]")
            .field("verified_objects", &self.verified_objects)
            .finish_non_exhaustive()
    }
}

impl<'physical> FreshRuntimeObjectProof<'_, 'physical> {
    pub(in crate::repository_import) fn is_bound_to(
        &self,
        physical: &MarkerFreePhysicalManifest,
    ) -> bool {
        self.git.is_bound_to(physical)
    }

    /// Revalidate the complete Git evidence and return only its bounded
    /// object count. No manifest borrow or object record escapes.
    pub(in crate::repository_import) fn checked_object_count(
        &self,
    ) -> Result<u32, CandidateSealError> {
        validate_fresh_git_manifest(self.git)?;
        if self.verified_objects != self.git.objects.len() {
            return Err(CandidateSealError::InvalidRecord);
        }
        u32::try_from(self.verified_objects).map_err(|_| CandidateSealError::ResourceLimit)
    }

    /// Project Git seal sections only through this completed runtime proof.
    pub(in crate::repository_import) fn project_for_seal<'content>(
        &self,
        scheme: inex_core::atomic::PublicationIdentityScheme,
        tracked: &FreshTrackedManifest<'content>,
        trees: &FreshTreeManifest<'content>,
    ) -> Result<CandidateGitProjection<'physical>, CandidateSealError> {
        if self.verified_objects != self.git.objects.len() {
            return Err(CandidateSealError::InvalidRecord);
        }
        self.git.project_for_seal(scheme, tracked, trees)
    }
}

trait RuntimeObjectBatch {
    fn prove(&mut self, expected: ObjectRecord) -> Result<(), RepositoryImportError>;
    fn finish(self) -> Result<(), RepositoryImportError>;
}

#[cfg(target_os = "linux")]
struct GitTargetObjectBatch<'runner>(TargetObjectBatch<'runner>);

#[cfg(target_os = "linux")]
impl RuntimeObjectBatch for GitTargetObjectBatch<'_> {
    fn prove(&mut self, expected: ObjectRecord) -> Result<(), RepositoryImportError> {
        let encoded = lower_hex_oid(expected.oid);
        let oid =
            std::str::from_utf8(&encoded).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        self.0.prove(
            oid,
            TargetObjectExpectation {
                object_type: object_kind_name(expected.kind),
                size: expected.raw_size,
                sha256: expected.raw_sha256,
            },
        )
    }

    fn finish(self) -> Result<(), RepositoryImportError> {
        self.0.finish()
    }
}

struct CompletedRuntimeObjectSet {
    verified_objects: usize,
}

fn prove_complete_object_set(
    objects: impl ExactSizeIterator<Item = ObjectRecord>,
    mut batch: impl RuntimeObjectBatch,
) -> Result<CompletedRuntimeObjectSet, RepositoryImportError> {
    let expected_count = objects.len();
    let mut previous = None;
    let mut verified_objects = 0_usize;
    for object in objects {
        validate_object_record(object).map_err(map_candidate_error)?;
        if previous.is_some_and(|oid| oid >= object.oid) {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        batch.prove(object)?;
        previous = Some(object.oid);
        verified_objects = verified_objects
            .checked_add(1)
            .ok_or(RepositoryImportError::ResourceLimit)?;
    }
    if verified_objects != expected_count {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    batch.finish()?;
    Ok(CompletedRuntimeObjectSet { verified_objects })
}

/// Prove every runtime object for one exact fresh Git manifest.
///
/// The target runner is bound to the manifest's physical root before spawning
/// and after batch completion. This check is cooperative only; pathname swap
/// and restore by a hostile same-UID process remains outside this preview.
#[cfg(target_os = "linux")]
pub(in crate::repository_import) fn prove_fresh_runtime_objects<'manifest, 'physical>(
    git: &'manifest FreshGitManifest<'physical>,
    tracked: &FreshTrackedManifest<'physical>,
    trees: &FreshTreeManifest<'physical>,
    runner: &GitRunner,
) -> Result<FreshRuntimeObjectProof<'manifest, 'physical>, RepositoryImportError> {
    validate_fresh_git_manifest(git).map_err(map_candidate_error)?;
    git.require_exact_content_objects(tracked, trees)
        .map_err(map_candidate_error)?;
    require_runner_root_binding(git, runner)?;
    let batch = runner.target_object_batch()?;
    let completed = prove_complete_object_set(
        git.objects.iter().map(|evidence| evidence.record),
        GitTargetObjectBatch(batch),
    )?;
    require_runner_root_binding(git, runner)?;
    Ok(FreshRuntimeObjectProof {
        git,
        verified_objects: completed.verified_objects,
    })
}

#[cfg(target_os = "linux")]
fn require_runner_root_binding(
    git: &FreshGitManifest<'_>,
    runner: &GitRunner,
) -> Result<(), RepositoryImportError> {
    let held = open_secure_source_root(&runner.root)
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    if !runner.target || held.identity() != git.physical.root_identity() {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    held.verify_binding()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)
}

/// Test-only state-machine witness for aggregate tests that do not launch Git.
/// Runtime protocol tests below cover the exact batch framing separately.
#[cfg(test)]
pub(in crate::repository_import) fn prove_fresh_runtime_objects_for_test<'manifest, 'physical>(
    git: &'manifest FreshGitManifest<'physical>,
    tracked: &FreshTrackedManifest<'physical>,
    trees: &FreshTreeManifest<'physical>,
) -> Result<FreshRuntimeObjectProof<'manifest, 'physical>, CandidateSealError> {
    validate_fresh_git_manifest(git)?;
    git.require_exact_content_objects(tracked, trees)?;
    let completed = prove_complete_object_set(
        git.objects.iter().map(|evidence| evidence.record),
        TestRuntimeObjectBatch,
    )
    .map_err(|error| map_runtime_error_for_test(&error))?;
    Ok(FreshRuntimeObjectProof {
        git,
        verified_objects: completed.verified_objects,
    })
}

#[cfg(test)]
struct TestRuntimeObjectBatch;

#[cfg(test)]
impl RuntimeObjectBatch for TestRuntimeObjectBatch {
    fn prove(&mut self, _expected: ObjectRecord) -> Result<(), RepositoryImportError> {
        Ok(())
    }

    fn finish(self) -> Result<(), RepositoryImportError> {
        Ok(())
    }
}

#[cfg(test)]
fn map_runtime_error_for_test(error: &RepositoryImportError) -> CandidateSealError {
    match error {
        RepositoryImportError::ResourceLimit => CandidateSealError::ResourceLimit,
        _ => CandidateSealError::InvalidRecord,
    }
}

const fn object_kind_name(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Blob => "blob",
        ObjectKind::Tree => "tree",
        ObjectKind::Commit => "commit",
    }
}

fn lower_hex_oid(oid: [u8; 20]) -> [u8; 40] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 40];
    for (index, byte) in oid.into_iter().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    encoded
}

const fn map_candidate_error(error: CandidateSealError) -> RepositoryImportError {
    match error {
        CandidateSealError::ResourceLimit => RepositoryImportError::ResourceLimit,
        CandidateSealError::InvalidContext
        | CandidateSealError::InvalidRecord
        | CandidateSealError::NonCanonicalOrder => RepositoryImportError::TargetAuditFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    use sha1::{Digest as _, Sha1};
    use sha2::Sha256;

    use super::*;
    use crate::repository_import::{BatchReadError, read_batch_eof, read_batch_object_proof};

    #[derive(Default)]
    struct MockState {
        calls: Vec<[u8; 20]>,
        finish_calls: usize,
    }

    struct MockBatch {
        state: Rc<RefCell<MockState>>,
        fail_at: Option<usize>,
        fail_finish: bool,
    }

    impl RuntimeObjectBatch for MockBatch {
        fn prove(&mut self, expected: ObjectRecord) -> Result<(), RepositoryImportError> {
            let mut state = self.state.borrow_mut();
            if self.fail_at == Some(state.calls.len()) {
                return Err(RepositoryImportError::TargetAuditFailed);
            }
            state.calls.push(expected.oid);
            Ok(())
        }

        fn finish(self) -> Result<(), RepositoryImportError> {
            self.state.borrow_mut().finish_calls += 1;
            if self.fail_finish {
                Err(RepositoryImportError::TargetAuditFailed)
            } else {
                Ok(())
            }
        }
    }

    fn record(seed: u8) -> ObjectRecord {
        ObjectRecord {
            oid: [seed; 20],
            kind: ObjectKind::Blob,
            raw_size: u64::from(seed),
            raw_sha256: [seed; 32],
        }
    }

    fn mock(state: Rc<RefCell<MockState>>, fail_at: Option<usize>, fail_finish: bool) -> MockBatch {
        MockBatch {
            state,
            fail_at,
            fail_finish,
        }
    }

    #[test]
    fn proof_state_requires_complete_sorted_unique_iteration_and_successful_finish() {
        let records = [record(1), record(2), record(3)];
        let state = Rc::new(RefCell::new(MockState::default()));
        let completed =
            prove_complete_object_set(records.into_iter(), mock(Rc::clone(&state), None, false))
                .expect("complete batch proves");
        assert_eq!(completed.verified_objects, records.len());
        assert_eq!(state.borrow().calls, records.map(|record| record.oid));
        assert_eq!(state.borrow().finish_calls, 1);

        for invalid in [
            [record(2), record(1), record(3)],
            [record(1), record(1), record(3)],
        ] {
            let state = Rc::new(RefCell::new(MockState::default()));
            assert!(matches!(
                prove_complete_object_set(
                    invalid.into_iter(),
                    mock(Rc::clone(&state), None, false)
                ),
                Err(RepositoryImportError::TargetAuditFailed)
            ));
            assert_eq!(state.borrow().finish_calls, 0);
        }

        let state = Rc::new(RefCell::new(MockState::default()));
        assert!(matches!(
            prove_complete_object_set(records.into_iter(), mock(Rc::clone(&state), Some(1), false)),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert_eq!(state.borrow().calls.len(), 1);
        assert_eq!(state.borrow().finish_calls, 0);

        let state = Rc::new(RefCell::new(MockState::default()));
        assert!(matches!(
            prove_complete_object_set(records.into_iter(), mock(Rc::clone(&state), None, true)),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert_eq!(state.borrow().calls.len(), records.len());
        assert_eq!(state.borrow().finish_calls, 1);
    }

    fn transcript_record(body: &[u8]) -> ObjectRecord {
        let raw_size = u64::try_from(body.len()).expect("body length fits");
        let mut typed = Sha1::new();
        typed.update(b"blob ");
        typed.update(raw_size.to_string().as_bytes());
        typed.update([0]);
        typed.update(body);
        ObjectRecord {
            oid: typed.finalize().into(),
            kind: ObjectKind::Blob,
            raw_size,
            raw_sha256: Sha256::digest(body).into(),
        }
    }

    fn transcript(record: ObjectRecord, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(lower_hex_oid(record.oid));
        bytes.extend(format!(" blob {}\n", record.raw_size).as_bytes());
        bytes.extend(body);
        bytes.push(b'\n');
        bytes
    }

    fn read_transcript(bytes: &[u8], record: ObjectRecord) -> Result<(), BatchReadError> {
        let encoded = lower_hex_oid(record.oid);
        let oid = std::str::from_utf8(&encoded).expect("lower hex is UTF-8");
        let expectation = TargetObjectExpectation {
            object_type: object_kind_name(record.kind),
            size: record.raw_size,
            sha256: record.raw_sha256,
        };
        let mut cursor = Cursor::new(bytes);
        read_batch_object_proof(&mut cursor, oid, &record.oid, expectation)?;
        read_batch_eof(&mut cursor)
    }

    #[test]
    fn fixed_16k_stream_requires_exact_header_body_lf_and_final_eof() {
        let body = vec![0x5a; TARGET_OBJECT_STREAM_CHUNK_BYTES * 2 + 7];
        let record = transcript_record(&body);
        let exact = transcript(record, &body);
        read_transcript(&exact, record).expect("exact transcript proves and reaches EOF");

        let mut wrong_header = exact.clone();
        wrong_header[0] = b'f';
        assert!(read_transcript(&wrong_header, record).is_err());

        let mut wrong_body = exact.clone();
        let header_length = 40 + format!(" blob {}\n", record.raw_size).len();
        wrong_body[header_length + TARGET_OBJECT_STREAM_CHUNK_BYTES] ^= 1;
        assert!(read_transcript(&wrong_body, record).is_err());

        let mut missing_lf = exact.clone();
        missing_lf.pop();
        assert!(read_transcript(&missing_lf, record).is_err());

        let mut trailing = exact;
        trailing.push(b'!');
        assert!(read_transcript(&trailing, record).is_err());
    }

    #[test]
    fn runtime_proof_contract_documents_process_group_boundary() {
        let source = include_str!("runtime_object_proof.rs");
        assert!(source.contains("dedicated Git process group"));
        assert!(source.contains("escapes the group"));
        assert!(source.contains("does not establish hostile process tree containment"));
        assert!(source.contains("TARGET_OBJECT_STREAM_CHUNK_BYTES == 16 * 1024"));
    }

    #[test]
    fn proof_debug_is_redacted_and_not_cloneable_by_contract() {
        let source = include_str!("runtime_object_proof.rs");
        let declaration = source
            .find("struct FreshRuntimeObjectProof")
            .expect("proof declaration exists");
        let preceding = &source[declaration.saturating_sub(160)..declaration];
        assert!(!preceding.contains("Clone"));
        assert!(!preceding.contains("Copy"));
        assert!(source.contains("[BOUND MANIFEST]"));
    }
}
