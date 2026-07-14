//! Read-only full fresh-candidate audit under one held publication marker.
//!
//! The collector borrows the complete marker authority, projects the marker-
//! free nine-section candidate exactly once, and returns only a fixed-size
//! summary after a final marker-aware whole-tree revalidation. It performs no
//! publication, recovery, cleanup, synchronization, or marker mutation.

use std::fmt;
use std::path::Path;

#[cfg(target_os = "linux")]
use inex_core::atomic::HeldPublicationMarkerV2;

use super::RepositoryImportError;
#[cfg(target_os = "linux")]
use super::candidate_git::{
    collect_fresh_git_evidence, collect_fresh_target_root_commit_evidence,
    prove_fresh_runtime_objects,
};
#[cfg(target_os = "linux")]
use super::candidate_manifest::collect_held_marker_physical_manifest;
use super::candidate_seal::{CandidateContentSeal, CandidateSealContext};
#[cfg(target_os = "linux")]
use super::candidate_seal::{CandidateSealError, DOMAIN, aggregate_candidate_content_seal_v1};
#[cfg(target_os = "linux")]
use super::candidate_worktree::{collect_fresh_tracked_evidence, construct_fresh_tree_evidence};
#[cfg(target_os = "linux")]
use super::{GitRunner, canonical_normal_directory, discover_git_executable};

/// Fixed-size result of one complete marker-aware fresh target audit.
///
/// This value deliberately owns no path, string, vector, handle, lock, marker,
/// process, or borrowed reference. It is neither `Clone` nor `Copy`.
pub(super) struct FreshMarkerCandidateAudit {
    context: CandidateSealContext,
    content_seal: CandidateContentSeal,
    worktree_files: u32,
    encrypted_markdown: u32,
    encrypted_assets: u32,
    git_objects: u32,
    root_commit_oid: [u8; 20],
}

/// One fixed candidate-summary field that changed across held-state reviews.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CandidateSummaryMismatch {
    Context,
    ContentSeal,
    RootCommit,
    WorktreeCount,
    MarkdownCount,
    AssetCount,
    GitObjectCount,
}

impl FreshMarkerCandidateAudit {
    #[cfg(test)]
    pub(super) const fn test_only_synthetic(
        context: CandidateSealContext,
        content_seal: [u8; 32],
        root_commit_oid: [u8; 20],
        worktree_files: u32,
        encrypted_markdown: u32,
        encrypted_assets: u32,
        git_objects: u32,
    ) -> Self {
        Self {
            context,
            content_seal: CandidateContentSeal::test_only_synthetic(content_seal),
            worktree_files,
            encrypted_markdown,
            encrypted_assets,
            git_objects,
            root_commit_oid,
        }
    }

    pub(super) const fn context(&self) -> CandidateSealContext {
        self.context
    }

    pub(super) const fn content_seal(&self) -> [u8; 32] {
        self.content_seal.into_digest()
    }

    pub(super) const fn worktree_files(&self) -> u32 {
        self.worktree_files
    }

    pub(super) const fn encrypted_markdown(&self) -> u32 {
        self.encrypted_markdown
    }

    pub(super) const fn encrypted_assets(&self) -> u32 {
        self.encrypted_assets
    }

    pub(super) const fn git_objects(&self) -> u32 {
        self.git_objects
    }

    pub(super) const fn root_commit_oid(&self) -> [u8; 20] {
        self.root_commit_oid
    }
}

impl fmt::Debug for FreshMarkerCandidateAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshMarkerCandidateAudit")
            .field("context", &"[REDACTED]")
            .field("content_seal", &"[REDACTED]")
            .field("worktree_files", &self.worktree_files)
            .field("encrypted_markdown", &self.encrypted_markdown)
            .field("encrypted_assets", &self.encrypted_assets)
            .field("git_objects", &self.git_objects)
            .field("root_commit_oid", &"[REDACTED]")
            .finish()
    }
}

/// Compare every fixed field produced by two complete nine-section audits.
pub(super) fn compare_candidate_summaries(
    current: &FreshMarkerCandidateAudit,
    expected: &FreshMarkerCandidateAudit,
) -> Result<(), CandidateSummaryMismatch> {
    if current.context() != expected.context() {
        Err(CandidateSummaryMismatch::Context)
    } else if current.content_seal() != expected.content_seal() {
        Err(CandidateSummaryMismatch::ContentSeal)
    } else if current.root_commit_oid() != expected.root_commit_oid() {
        Err(CandidateSummaryMismatch::RootCommit)
    } else if current.worktree_files() != expected.worktree_files() {
        Err(CandidateSummaryMismatch::WorktreeCount)
    } else if current.encrypted_markdown() != expected.encrypted_markdown() {
        Err(CandidateSummaryMismatch::MarkdownCount)
    } else if current.encrypted_assets() != expected.encrypted_assets() {
        Err(CandidateSummaryMismatch::AssetCount)
    } else if current.git_objects() != expected.git_objects() {
        Err(CandidateSummaryMismatch::GitObjectCount)
    } else {
        Ok(())
    }
}

/// Audit one complete fresh target while borrowing its exact held v2 marker.
///
/// This is a read-only evidence operation. The held marker remains owned by
/// the caller on both success and failure.
#[cfg(target_os = "linux")]
pub(super) fn audit_fresh_marker_candidate(
    current_root: &Path,
    held_marker: &HeldPublicationMarkerV2,
) -> Result<FreshMarkerCandidateAudit, RepositoryImportError> {
    audit_fresh_marker_candidate_impl(
        current_root,
        held_marker,
        |root| {
            let executable = discover_git_executable()
                .map_err(|_| RepositoryImportError::GitExecutableUnavailable)?;
            GitRunner::target(executable, root.to_path_buf())
        },
        || {},
    )
}

#[cfg(not(target_os = "linux"))]
pub(super) fn audit_fresh_marker_candidate(
    _current_root: &Path,
    _unsupported_marker: (),
) -> Result<FreshMarkerCandidateAudit, RepositoryImportError> {
    Err(RepositoryImportError::TargetAuditFailed)
}

#[cfg(target_os = "linux")]
fn audit_fresh_marker_candidate_impl(
    current_root: &Path,
    held_marker: &HeldPublicationMarkerV2,
    make_runner: impl FnOnce(&Path) -> Result<GitRunner, RepositoryImportError>,
    after_aggregate: impl FnOnce(),
) -> Result<FreshMarkerCandidateAudit, RepositoryImportError> {
    let root = canonical_normal_directory(current_root, RepositoryImportError::TargetAuditFailed)?;
    held_marker
        .revalidate_at(&root)
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    let marker = held_marker.marker();
    if marker.domain() != DOMAIN {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let context = CandidateSealContext {
        scheme: marker.scheme(),
        publication_id: *marker.publication_id(),
    };

    // Exactly one physical collection owns the marker omission and the final
    // exact revalidation. Every later evidence value borrows this allocation.
    let marker_physical = collect_held_marker_physical_manifest(&root, held_marker)?;
    let (
        content_seal,
        root_commit_oid,
        worktree_files,
        encrypted_markdown,
        encrypted_assets,
        git_objects,
    ) = {
        let runner = make_runner(&root)?;
        let physical = marker_physical.physical();
        let root_commit = collect_fresh_target_root_commit_evidence(
            physical,
            marker_physical.held_root(),
            &runner,
        )?;
        let root_commit_oid = root_commit.commit_oid();
        let tracked = collect_fresh_tracked_evidence(physical, marker_physical.held_root())
            .map_err(map_candidate_error)?;
        let trees = construct_fresh_tree_evidence(&tracked).map_err(map_candidate_error)?;
        let git = collect_fresh_git_evidence(physical, &tracked, &trees, root_commit)
            .map_err(map_candidate_error)?;
        let runtime = prove_fresh_runtime_objects(&git, &tracked, &trees, &runner)?;
        let content_seal =
            aggregate_candidate_content_seal_v1(context, physical, &tracked, &trees, &runtime)
                .map_err(map_candidate_error)?;
        let (worktree_files, encrypted_markdown, encrypted_assets) =
            tracked.checked_counts().map_err(map_candidate_error)?;
        let git_objects = runtime
            .checked_object_count()
            .map_err(map_candidate_error)?;
        after_aggregate();
        (
            content_seal,
            root_commit_oid,
            worktree_files,
            encrypted_markdown,
            encrypted_assets,
            git_objects,
        )
    };

    marker_physical.require_current_exact(&root)?;

    // No filesystem or process operation occurs after the final exact check.
    // Marker comparison is the core primitive's constant-time seal compare.
    if !marker.candidate_seal_matches(&content_seal.into_digest()) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    Ok(FreshMarkerCandidateAudit {
        context,
        content_seal,
        worktree_files,
        encrypted_markdown,
        encrypted_assets,
        git_objects,
        root_commit_oid,
    })
}

#[cfg(target_os = "linux")]
const fn map_candidate_error(error: CandidateSealError) -> RepositoryImportError {
    match error {
        CandidateSealError::ResourceLimit => RepositoryImportError::ResourceLimit,
        CandidateSealError::InvalidContext
        | CandidateSealError::InvalidRecord
        | CandidateSealError::NonCanonicalOrder => RepositoryImportError::TargetAuditFailed,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use inex_core::atomic::{
        ExistingVaultMutationLock, HeldPublicationMarkerV2CreateInput, IMPORT_PUBLISH_MARKER_V2,
        PublicationIdentityScheme, VAULT_LOCAL_DIRECTORY, filesystem_directory_identity,
        open_secure_source_root,
    };
    use inex_core::crypto::VaultContentProfile;
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault::Vault;
    use inex_core::vault_config::KdfPolicy;

    use super::*;
    use crate::repository_import::candidate_manifest::collect_marker_free_physical_manifest;
    use crate::repository_import::{
        RepositoryGitOperation, RepositoryIoOperation, initialize_and_audit_target,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const PASSWORD: &[u8] = b"fresh marker audit test password";
    const PUBLICATION_ID: [u8; 16] = [0x6d; 16];

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-fresh-marker-audit-{label}-{}-{sequence}",
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

    fn policy() -> KdfPolicy {
        KdfPolicy {
            min_creation_ops_limit: 1,
            min_creation_mem_limit_bytes: 8 * 1024,
            max_creation_ops_limit: 2,
            max_creation_mem_limit_bytes: 64 * 1024,
            max_unlock_ops_limit: 2,
            max_unlock_mem_limit_bytes: 64 * 1024,
        }
    }

    fn create_target(label: &str) -> TestDirectory {
        let root = TestDirectory::new(label);
        let vault = Vault::create_with_profile_and_params(
            root.path(),
            PASSWORD,
            1_784_044_800_000,
            VaultContentProfile::OpaqueAssetsV1,
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            },
            policy(),
        )
        .expect("test vault creates");
        drop(vault);
        for (relative, body) in [
            ("notes/a.md.enc", b"first-ciphertext".as_slice()),
            ("notes/b.md.enc", b"second-ciphertext".as_slice()),
            ("media/p.png.asset.enc", b"asset-ciphertext".as_slice()),
        ] {
            let path = root.path().join(relative);
            fs::create_dir_all(path.parent().expect("content has parent"))
                .expect("content parent creates");
            fs::write(path, body).expect("content writes");
        }
        initialize_and_audit_target(
            root.path(),
            &[
                PathBuf::from("vault.json"),
                PathBuf::from("notes/a.md.enc"),
                PathBuf::from("notes/b.md.enc"),
                PathBuf::from("media/p.png.asset.enc"),
            ],
            1_784_044_800,
        )
        .expect("fresh canonical target initializes");
        root
    }

    fn real_runner(root: &Path) -> Result<GitRunner, RepositoryImportError> {
        let executable = discover_git_executable()
            .map_err(|_| RepositoryImportError::GitExecutableUnavailable)?;
        GitRunner::target(executable, root.to_path_buf())
    }

    fn expected_summary(root: &Path) -> ([u8; 32], [u8; 20], (u32, u32, u32), u32) {
        let context = CandidateSealContext {
            scheme: PublicationIdentityScheme::LinuxDevInodeV1,
            publication_id: PUBLICATION_ID,
        };
        let physical =
            collect_marker_free_physical_manifest(root).expect("marker-free physical collects");
        let held_root = open_secure_source_root(root).expect("root descriptor holds");
        let runner = real_runner(root).expect("real target runner binds");
        let commit = collect_fresh_target_root_commit_evidence(&physical, &held_root, &runner)
            .expect("root commit bootstraps");
        let root_commit_oid = commit.commit_oid();
        let tracked = collect_fresh_tracked_evidence(&physical, &held_root)
            .expect("tracked evidence collects");
        let trees = construct_fresh_tree_evidence(&tracked).expect("tree evidence constructs");
        let git = collect_fresh_git_evidence(&physical, &tracked, &trees, commit)
            .expect("Git evidence collects");
        let runtime = prove_fresh_runtime_objects(&git, &tracked, &trees, &runner)
            .expect("runtime objects prove");
        let seal =
            aggregate_candidate_content_seal_v1(context, &physical, &tracked, &trees, &runtime)
                .expect("candidate aggregates")
                .into_digest();
        let counts = tracked.checked_counts().expect("tracked counts validate");
        let objects = runtime
            .checked_object_count()
            .expect("object count validates");
        (seal, root_commit_oid, counts, objects)
    }

    fn create_marker(
        root: &Path,
        destination_child_name: &str,
        domain: &str,
        seal: &[u8],
    ) -> inex_core::atomic::HeldPublicationMarkerV2 {
        create_marker_with_publication_id(
            root,
            destination_child_name,
            domain,
            PUBLICATION_ID,
            seal,
        )
    }

    fn create_marker_with_publication_id(
        root: &Path,
        destination_child_name: &str,
        domain: &str,
        publication_id: [u8; 16],
        seal: &[u8],
    ) -> inex_core::atomic::HeldPublicationMarkerV2 {
        let physical =
            collect_marker_free_physical_manifest(root).expect("marker-free physical collects");
        let held_root = open_secure_source_root(root).expect("root descriptor holds");
        let mutation_lock = ExistingVaultMutationLock::acquire(
            root,
            physical.root_identity(),
            physical.local_identity(),
            physical.lock_identity(),
        )
        .expect("existing mutation lock holds");
        let common_parent_identity =
            filesystem_directory_identity(root.parent().expect("fixture root has common parent"))
                .expect("common parent identity captures");
        let staging_child_name = root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("staging child name is portable");
        mutation_lock
            .create_held_publication_marker_v2(
                root,
                held_root,
                HeldPublicationMarkerV2CreateInput {
                    scheme: PublicationIdentityScheme::LinuxDevInodeV1,
                    publication_id,
                    common_parent_identity: &common_parent_identity,
                    staging_child_name,
                    destination_child_name,
                    domain,
                    candidate_seal: seal,
                },
            )
            .expect("held marker creates")
    }

    #[test]
    fn real_fresh_audit_returns_exact_fixed_summary_and_redacts_debug() {
        let root = create_target("success");
        let (seal, root_commit_oid, counts, objects) = expected_summary(root.path());
        assert_eq!(counts, (6, 2, 1));
        let marker = create_marker(root.path(), "fresh-audit-destination", &domain(), &seal);

        let audit = audit_fresh_marker_candidate(root.path(), &marker)
            .expect("complete held-marker audit succeeds");
        assert_eq!(
            audit.context().scheme,
            PublicationIdentityScheme::LinuxDevInodeV1
        );
        assert_eq!(audit.context().publication_id, PUBLICATION_ID);
        assert_eq!(audit.content_seal(), seal);
        assert_eq!(audit.worktree_files(), 6);
        assert_eq!(audit.encrypted_markdown(), 2);
        assert_eq!(audit.encrypted_assets(), 1);
        assert_eq!(audit.git_objects(), objects);
        assert_eq!(audit.root_commit_oid(), root_commit_oid);

        let debug = format!("{audit:?}");
        assert!(debug.contains("worktree_files: 6"));
        assert!(debug.contains("encrypted_markdown: 2"));
        assert!(debug.contains("encrypted_assets: 1"));
        assert!(!debug.contains(&hex(&seal)));
        assert!(!debug.contains(&hex(&root_commit_oid)));
        assert!(!debug.contains(root.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn final_exact_rejects_equal_length_post_aggregate_rewrite_and_keeps_marker() {
        let root = create_target("final-exact");
        let (seal, _, _, _) = expected_summary(root.path());
        let marker = create_marker(root.path(), "final-exact-destination", &domain(), &seal);
        let content = root.path().join("notes/a.md.enc");
        let original = fs::read(&content).expect("content reads");
        let replacement = vec![b'x'; original.len()];

        let result = audit_fresh_marker_candidate_impl(root.path(), &marker, real_runner, || {
            fs::write(&content, &replacement).expect("equal-length rewrite succeeds");
        });
        assert!(matches!(
            result,
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert!(
            root.path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V2)
                .is_file()
        );
        assert!(marker.revalidate_at(root.path()).is_ok());
    }

    #[test]
    fn canonical_destination_root_is_accepted_after_whole_root_rename() {
        let mut root = create_target("rename-source");
        let (seal, _, _, _) = expected_summary(root.path());
        let destination_name = format!(
            "inex-fresh-marker-audit-rename-destination-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        );
        let destination = root
            .path()
            .parent()
            .expect("root has parent")
            .join(&destination_name);
        let marker = create_marker(root.path(), &destination_name, &domain(), &seal);
        fs::rename(root.path(), &destination).expect("whole root renames");
        root.0 = destination;

        let audit = audit_fresh_marker_candidate(root.path(), &marker)
            .expect("held marker audits at authorized destination");
        assert_eq!(audit.content_seal(), seal);
    }

    #[test]
    fn wrong_domain_returns_before_runner_construction() {
        let root = create_target("wrong-domain");
        let marker = create_marker(
            root.path(),
            "wrong-domain-destination",
            "inex.repository-import.other",
            &[0xa7; 32],
        );
        let runner_calls = Cell::new(0_u32);
        let result = audit_fresh_marker_candidate_impl(
            root.path(),
            &marker,
            |_| {
                runner_calls.set(runner_calls.get() + 1);
                Err(RepositoryImportError::TargetAuditFailed)
            },
            || {},
        );
        assert!(matches!(
            result,
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert_eq!(runner_calls.get(), 0);
        assert!(marker.revalidate_at(root.path()).is_ok());
    }

    #[test]
    fn wrong_and_non_32_byte_seals_fail_without_removing_marker() {
        for (label, candidate_seal) in [
            ("wrong-seal", vec![0x19; 32]),
            ("short-seal", vec![0x19; 31]),
        ] {
            let root = create_target(label);
            let marker = create_marker(
                root.path(),
                &format!("{label}-destination"),
                &domain(),
                &candidate_seal,
            );
            assert!(matches!(
                audit_fresh_marker_candidate(root.path(), &marker),
                Err(RepositoryImportError::TargetAuditFailed)
            ));
            assert!(marker.revalidate_at(root.path()).is_ok());
            assert!(
                root.path()
                    .join(VAULT_LOCAL_DIRECTORY)
                    .join(IMPORT_PUBLISH_MARKER_V2)
                    .is_file()
            );
        }
    }

    #[test]
    fn changed_publication_id_with_old_seal_fails_without_removing_marker() {
        let root = create_target("changed-publication-id");
        let (seal_for_original_id, _, _, _) = expected_summary(root.path());
        let marker = create_marker_with_publication_id(
            root.path(),
            "changed-publication-id-destination",
            &domain(),
            [0x6e; 16],
            &seal_for_original_id,
        );

        assert!(matches!(
            audit_fresh_marker_candidate(root.path(), &marker),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert!(marker.revalidate_at(root.path()).is_ok());
        assert!(
            root.path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V2)
                .is_file()
        );
    }

    #[test]
    fn missing_executable_and_config_failure_are_preserved() {
        let missing = create_target("missing-executable");
        let marker = create_marker(
            missing.path(),
            "missing-executable-destination",
            &domain(),
            &[0x55; 32],
        );
        let result = audit_fresh_marker_candidate_impl(
            missing.path(),
            &marker,
            |root| GitRunner::target(root.join("missing-git"), root.to_path_buf()),
            || {},
        );
        assert!(matches!(
            result,
            Err(RepositoryImportError::Io {
                operation: RepositoryIoOperation::SpawnGit,
                kind: std::io::ErrorKind::NotFound,
            })
        ));
        assert!(marker.revalidate_at(missing.path()).is_ok());

        let failed = create_target("config-failure");
        let failed_marker = create_marker(
            failed.path(),
            "config-failure-destination",
            &domain(),
            &[0x56; 32],
        );
        let scripts = TestDirectory::new("config-failure-script");
        let script = scripts.path().join("git-fails");
        write_executable(&script, "#!/bin/sh\nexit 23\n");
        let result = audit_fresh_marker_candidate_impl(
            failed.path(),
            &failed_marker,
            |root| GitRunner::target(script, root.to_path_buf()),
            || {},
        );
        assert!(matches!(
            result,
            Err(RepositoryImportError::GitCommandFailed {
                operation: RepositoryGitOperation::InspectConfiguration,
            })
        ));
        assert!(failed_marker.revalidate_at(failed.path()).is_ok());
    }

    #[test]
    fn runtime_object_command_failure_is_preserved() {
        let root = create_target("object-failure");
        let marker = create_marker(
            root.path(),
            "object-failure-destination",
            &domain(),
            &[0x57; 32],
        );
        let real = discover_git_executable().expect("Git resolves");
        let scripts = TestDirectory::new("object-failure-script");
        let proxy = scripts.path().join("git-object-fails");
        let escaped = real
            .to_str()
            .expect("Git path is UTF-8")
            .replace('\'', "'\"'\"'");
        write_executable(
            &proxy,
            &format!(
                "#!/bin/sh\ncase \" $* \" in\n  *\" cat-file --batch \"*) '{escaped}' \"$@\"; status=$?; [ \"$status\" -eq 0 ] || exit \"$status\"; exit 23 ;;\nesac\nexec '{escaped}' \"$@\"\n"
            ),
        );
        let result = audit_fresh_marker_candidate_impl(
            root.path(),
            &marker,
            |root| GitRunner::target(proxy, root.to_path_buf()),
            || {},
        );
        assert!(matches!(
            result,
            Err(RepositoryImportError::GitCommandFailed {
                operation: RepositoryGitOperation::AuditTarget,
            })
        ));
        assert!(marker.revalidate_at(root.path()).is_ok());
    }

    #[test]
    fn production_api_is_narrow_fixed_size_and_non_clone() {
        let source = include_str!("candidate_fresh_audit.rs");
        let production = source
            .split("#[cfg(all(test, target_os = \"linux\"))]")
            .next()
            .expect("production prefix exists");
        let signature = production
            .split("pub(super) fn audit_fresh_marker_candidate(")
            .nth(1)
            .expect("audit entry point exists")
            .split('{')
            .next()
            .expect("audit signature terminates");
        for forbidden in [
            "Vault",
            "password",
            "profile",
            "source",
            "TargetRepository",
            "PathBuf",
            "String",
            "Vec<",
        ] {
            assert!(
                !signature.contains(forbidden),
                "forbidden input: {forbidden}"
            );
        }
        assert!(signature.contains("&HeldPublicationMarkerV2"));
        assert!(!production.contains("collect_marker_free_physical_manifest"));
        assert!(!production.contains("initialize_and_audit_target"));
        assert!(!production.contains("acquire("));
        assert!(!production.contains("remove_"));
        assert!(!production.contains("rename("));

        let declaration = production
            .split("pub(super) struct FreshMarkerCandidateAudit")
            .nth(1)
            .expect("summary exists")
            .split("impl FreshMarkerCandidateAudit")
            .next()
            .expect("summary declaration terminates");
        for forbidden in ["Path", "String", "Vec", "Secure", "Held", "&'"] {
            assert!(
                !declaration.contains(forbidden),
                "retained capability: {forbidden}"
            );
        }
        let prefix = production
            .split("pub(super) struct FreshMarkerCandidateAudit")
            .next()
            .expect("summary prefix exists");
        let nearby = prefix.rsplit('\n').take(3).collect::<Vec<_>>().join("\n");
        assert!(!nearby.contains("derive(Clone"));
        assert!(!nearby.contains("derive(Copy"));
        assert_eq!(std::mem::size_of::<FreshMarkerCandidateAudit>(), 88);
    }

    fn domain() -> String {
        DOMAIN.to_owned()
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("String write is infallible");
        }
        output
    }

    fn write_executable(path: &Path, body: &str) {
        fs::write(path, body).expect("script writes");
        let mut permissions = fs::metadata(path)
            .expect("script metadata reads")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).expect("script becomes executable");
    }
}
