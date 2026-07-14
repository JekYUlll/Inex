//! One-shot pure-content aggregation for repository-candidate-seal-v1.
//!
//! This module is the only production constructor of the private nine-section
//! encoder manifest. It binds the physical, tracked, tree, and Git evidence to
//! the same [`MarkerFreePhysicalManifest`] with pointer identity, projects each
//! section exactly once, and immediately hashes the projection.
//!
//! The result proves only the candidate content represented by those immutable
//! evidence values. It does **not** prove that a mutation lock is currently
//! held, does not carry publication authority, and must not be treated as
//! permission to write or publish a marker. A later transaction must retain
//! the required lock/handle authority and revalidate the target before use.

use std::fmt;

use super::{
    CandidateSealContext, CandidateSealError, CandidateSealManifest, encode_candidate_seal_v1,
};
use crate::repository_import::candidate_git::FreshGitManifest;
use crate::repository_import::candidate_manifest::MarkerFreePhysicalManifest;
use crate::repository_import::candidate_worktree::{FreshTrackedManifest, FreshTreeManifest};

/// A pure-content digest with no lock or publication capability.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::repository_import) struct CandidateContentSeal([u8; 32]);

impl CandidateContentSeal {
    pub(in crate::repository_import) const fn into_digest(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for CandidateContentSeal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CandidateContentSeal")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Project all nine sections once and hash their canonical content stream.
///
/// This function deliberately accepts no lock guard, publication claim, marker
/// path, or writer. Success is evidence of content equality only.
pub(in crate::repository_import) fn aggregate_candidate_content_seal_v1<'physical>(
    context: CandidateSealContext,
    physical: &'physical MarkerFreePhysicalManifest,
    tracked: &FreshTrackedManifest<'physical>,
    trees: &FreshTreeManifest<'physical>,
    git: &FreshGitManifest<'physical>,
) -> Result<CandidateContentSeal, CandidateSealError> {
    if !tracked.is_bound_to(physical) || !trees.is_bound_to(physical) || !git.is_bound_to(physical)
    {
        return Err(CandidateSealError::InvalidRecord);
    }

    let physical_projection = physical.project(context.scheme)?;
    let (worktree, index) = tracked.project(context.scheme)?;
    let tree_records = trees.project()?;
    let git_projection = git.project_for_seal(context.scheme, tracked, trees)?;

    let manifest = CandidateSealManifest {
        physical: &physical_projection.physical,
        worktree: &worktree,
        head_refs: git_projection.head_refs,
        index: &index,
        trees: &tree_records,
        root_commit: git_projection.root_commit,
        objects: &git_projection.objects,
        git_control: &git_projection.git_control,
        private_baseline: physical_projection.private_baseline,
    };
    encode_candidate_seal_v1(context, manifest).map(CandidateContentSeal)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fmt::Write as _;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use inex_core::atomic::{
        PublicationIdentityScheme, VAULT_LOCAL_DIRECTORY, VAULT_MUTATION_LOCK_FILE,
        open_secure_source_root,
    };
    use sha1::{Digest as _, Sha1};
    use sha2::Sha256;

    use super::super::{CandidateSealManifest, ObjectKind, ObjectRecord, encode_candidate_seal_v1};
    use super::*;
    use crate::repository_import::candidate_git::{
        FreshRootCommitEvidence, collect_fresh_git_evidence, parse_canonical_root_commit,
    };
    use crate::repository_import::candidate_manifest::collect_marker_free_physical_manifest;
    use crate::repository_import::candidate_worktree::{
        collect_fresh_tracked_evidence, construct_fresh_tree_evidence,
    };
    use crate::repository_import::{TARGET_ATTRIBUTES, TARGET_IGNORE};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-candidate-aggregate-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test root creates");
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

    struct Fixture {
        target: TestDirectory,
        raw_index: Vec<u8>,
        root_commit: FreshRootCommitEvidence,
    }

    fn context() -> CandidateSealContext {
        CandidateSealContext {
            scheme: PublicationIdentityScheme::LinuxDevInodeV1,
            publication_id: [0x71; 16],
        }
    }

    fn raw_sha256(body: &[u8]) -> [u8; 32] {
        Sha256::digest(body).into()
    }

    fn object(kind: ObjectKind, body: &[u8]) -> ObjectRecord {
        let raw_size = u64::try_from(body.len()).expect("test body length fits");
        let mut typed = Sha1::new();
        let name: &[u8] = match kind {
            ObjectKind::Blob => b"blob",
            ObjectKind::Tree => b"tree",
            ObjectKind::Commit => b"commit",
        };
        typed.update(name);
        typed.update(b" ");
        typed.update(raw_size.to_string().as_bytes());
        typed.update([0]);
        typed.update(body);
        ObjectRecord {
            oid: typed.finalize().into(),
            kind,
            raw_size,
            raw_sha256: raw_sha256(body),
        }
    }

    fn lower_hex(oid: [u8; 20]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(40);
        for byte in oid {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    fn write(path: &Path, body: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent creates");
        }
        fs::write(path, body).expect("fixture body writes");
    }

    fn index_v2(entries: &[(&str, ObjectRecord)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"DIRC");
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(entries.len())
                .expect("test entry count fits")
                .to_be_bytes(),
        );
        for (path, object) in entries {
            bytes.extend_from_slice(&[0_u8; 24]);
            bytes.extend_from_slice(&0o100_644_u32.to_be_bytes());
            bytes.extend_from_slice(&[0_u8; 12]);
            bytes.extend_from_slice(&object.oid);
            let path = path.as_bytes();
            bytes.extend_from_slice(
                &u16::try_from(path.len())
                    .expect("test path length fits")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(path);
            let unpadded = 62 + path.len();
            bytes.resize(bytes.len() + 8 - unpadded % 8, 0);
        }
        let checksum = Sha1::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    fn root_tree(entries: &[(&str, ObjectRecord)]) -> (Vec<u8>, ObjectRecord) {
        let mut raw = Vec::new();
        for (path, object) in entries {
            raw.extend_from_slice(b"100644 ");
            raw.extend_from_slice(path.as_bytes());
            raw.push(0);
            raw.extend_from_slice(&object.oid);
        }
        let record = object(ObjectKind::Tree, &raw);
        (raw, record)
    }

    fn canonical_commit(tree_oid: [u8; 20]) -> Vec<u8> {
        format!(
            "tree {}\nauthor Inex Repository Import <inex-import@localhost.invalid> 0 +0000\ncommitter Inex Repository Import <inex-import@localhost.invalid> 0 +0000\n\nInitialize encrypted Inex vault\n",
            lower_hex(tree_oid)
        )
        .into_bytes()
    }

    fn fixture(label: &str) -> Fixture {
        let target = TestDirectory::new(label);
        let root = target.path();
        let tracked_bodies: [(&str, &[u8]); 5] = [
            (".gitattributes", TARGET_ATTRIBUTES),
            (".gitignore", TARGET_IGNORE),
            ("image.png.asset.enc", &[0, 1, 2, 0xff]),
            ("note.md.enc", b"ciphertext"),
            ("vault.json", b"{}\n"),
        ];
        let mut entries = Vec::new();
        for (path, body) in tracked_bodies {
            write(&root.join(path), body);
            entries.push((path, object(ObjectKind::Blob, body)));
        }
        entries.sort_unstable_by_key(|(path, _)| path.as_bytes());
        let raw_index = index_v2(&entries);
        let (_tree_body, tree) = root_tree(&entries);
        let commit_body = canonical_commit(tree.oid);
        let root_commit =
            parse_canonical_root_commit(&commit_body).expect("canonical root commit parses");
        let commit = object(ObjectKind::Commit, &commit_body);
        assert_eq!(root_commit.commit_oid(), commit.oid);

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
            fs::create_dir_all(root.join(directory)).expect("Git control directory creates");
        }
        write(&root.join(".git/HEAD"), b"ref: refs/heads/main\n");
        write(
            &root.join(".git/config"),
            b"[core]\n\trepositoryformatversion = 0\n",
        );
        write(&root.join(".git/index"), &raw_index);
        write(
            &root.join(".git/refs/heads/main"),
            format!("{}\n", lower_hex(commit.oid)).as_bytes(),
        );

        let mut objects: Vec<_> = entries.iter().map(|(_, record)| *record).collect();
        objects.extend([tree, commit]);
        objects.sort_unstable_by_key(|record| record.oid);
        objects.dedup_by_key(|record| record.oid);
        for record in objects {
            let encoded = lower_hex(record.oid);
            write(
                &root.join(format!(".git/objects/{}/{}", &encoded[..2], &encoded[2..])),
                b"bounded compressed placeholder",
            );
        }
        Fixture {
            target,
            raw_index,
            root_commit,
        }
    }

    fn with_evidence<R>(
        fixture: &Fixture,
        visit: impl FnOnce(
            &MarkerFreePhysicalManifest,
            &FreshTrackedManifest<'_>,
            &FreshTreeManifest<'_>,
            FreshGitManifest<'_>,
        ) -> R,
    ) -> R {
        let physical = collect_marker_free_physical_manifest(fixture.target.path())
            .expect("physical evidence collects");
        let held = open_secure_source_root(fixture.target.path()).expect("target root holds");
        let tracked = collect_fresh_tracked_evidence(&physical, &held, &fixture.raw_index)
            .expect("tracked evidence collects");
        let trees = construct_fresh_tree_evidence(&tracked).expect("tree evidence constructs");
        let git = collect_fresh_git_evidence(&physical, &tracked, &trees, fixture.root_commit)
            .expect("Git evidence collects from opaque views");
        visit(&physical, &tracked, &trees, git)
    }

    #[test]
    fn one_shot_projection_matches_private_golden_encoder() {
        let fixture = fixture("golden");
        with_evidence(&fixture, |physical, tracked, trees, git| {
            let actual =
                aggregate_candidate_content_seal_v1(context(), physical, tracked, trees, &git)
                    .expect("one-shot aggregate hashes");

            let physical_projection = physical
                .project(context().scheme)
                .expect("physical projects");
            let (worktree, index) = tracked.project(context().scheme).expect("tracked projects");
            let tree_records = trees.project().expect("trees project");
            let git_projection = git
                .project_for_seal(context().scheme, tracked, trees)
                .expect("Git projects against the same views");
            let expected = encode_candidate_seal_v1(
                context(),
                CandidateSealManifest {
                    physical: &physical_projection.physical,
                    worktree: &worktree,
                    head_refs: git_projection.head_refs,
                    index: &index,
                    trees: &tree_records,
                    root_commit: git_projection.root_commit,
                    objects: &git_projection.objects,
                    git_control: &git_projection.git_control,
                    private_baseline: physical_projection.private_baseline,
                },
            )
            .expect("private golden projection hashes");
            assert_eq!(actual.into_digest(), expected);
            assert_ne!(expected, [0; 32]);
        });
    }

    #[test]
    fn same_layout_different_manifest_mix_is_rejected_by_pointer_identity() {
        let first = fixture("mix-first");
        let second = fixture("mix-second");
        with_evidence(&first, |first_physical, _, _, _| {
            with_evidence(&second, |_, second_tracked, second_trees, second_git| {
                assert_eq!(
                    aggregate_candidate_content_seal_v1(
                        context(),
                        first_physical,
                        second_tracked,
                        second_trees,
                        &second_git,
                    ),
                    Err(CandidateSealError::InvalidRecord)
                );
            });
        });
    }

    #[test]
    fn forged_git_object_union_is_rejected_against_opaque_content_views() {
        let fixture = fixture("forged-union");
        with_evidence(&fixture, |physical, tracked, trees, mut git| {
            git.forge_object_union_for_test();
            assert_eq!(
                aggregate_candidate_content_seal_v1(context(), physical, tracked, trees, &git),
                Err(CandidateSealError::InvalidRecord)
            );
        });
    }

    #[test]
    fn content_seal_debug_never_reveals_digest_or_paths() {
        let fixture = fixture("redaction");
        with_evidence(&fixture, |physical, tracked, trees, git| {
            let seal =
                aggregate_candidate_content_seal_v1(context(), physical, tracked, trees, &git)
                    .expect("aggregate hashes");
            let mut digest_hex = String::new();
            for byte in seal.into_digest() {
                write!(&mut digest_hex, "{byte:02x}").expect("writing into String is infallible");
            }
            let debug = format!("{seal:?}");
            assert_eq!(debug, "CandidateContentSeal(\"[REDACTED]\")");
            assert!(!debug.contains(&digest_hex));
            assert!(!debug.contains("note.md.enc"));
        });
    }
}
