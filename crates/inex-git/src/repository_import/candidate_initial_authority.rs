//! Held initial-process authority for one marker-free repository candidate.
//!
//! Construction starts from one complete marker-free physical manifest, opens
//! one root descriptor, and acquires the exact pre-existing mutation lock from
//! that manifest. All worktree, tree, Git, runtime-object, authenticated-vault,
//! and candidate-seal evidence is then constructed inside the held-lock scope.
//! A final whole-tree exact revalidation succeeds before the owned manifest,
//! root descriptor, content seal, and still-held lock can enter this type.
//!
//! This is deliberately not marker or publication authority. It creates no
//! path, writes no marker, performs no move, and exposes no detached lock. A
//! later initial-only typestate must consume it. Fresh reconciliation cannot
//! construct it: the only constructor requires the process-local opaque
//! [`TargetRepository`] produced during initial creation and an authenticated
//! [`Vault`], while a marker-bearing target is rejected by the marker-free
//! collector before lock acquisition.
//!
//! The lock serializes cooperative Inex writers only. A hostile same-UID
//! process can ignore it and can still attempt swap-and-restore races; the
//! unkeyed content seal is not a MAC. Runtime Git supervision also retains the
//! documented trusted-local boundary where a hostile descendant can inherit a
//! pipe and keep a reader join blocked after the direct child is terminated.

use std::fmt;
use std::path::Path;

use inex_core::atomic::ExistingVaultMutationLockError;
use inex_core::crypto::VaultContentProfile;
use inex_core::vault::Vault;
use thiserror::Error;

use super::candidate_seal::{CandidateSealContext, CandidateSealError};
use super::{RepositoryImportError, TargetRepository};

/// Scrubbed failure while converting marker-free evidence into held initial
/// authority.
///
/// The existing-only lock error is retained without remapping so callers can
/// distinguish `Busy`, `Unsupported`, and the exact scrubbed I/O class.
#[derive(Debug, Error)]
pub(super) enum InitialCandidateAuthorityError {
    /// The existing-only lock could not be acquired or revalidated.
    #[error("initial repository candidate mutation lock failed")]
    Lock(#[source] ExistingVaultMutationLockError),
    /// Candidate evidence or its seal context was invalid.
    #[error(transparent)]
    Candidate(#[from] CandidateSealError),
    /// Marker-free target collection or runtime Git proof failed.
    #[error(transparent)]
    Repository(#[from] RepositoryImportError),
}

impl From<ExistingVaultMutationLockError> for InitialCandidateAuthorityError {
    fn from(error: ExistingVaultMutationLockError) -> Self {
        Self::Lock(error)
    }
}

/// Opaque marker-free initial authority that continuously owns the exact
/// existing mutation lock.
///
/// This type intentionally implements neither `Clone` nor `Copy`. Its fields
/// are private, and the only production constructor performs the complete
/// held-lock proof. The lock field is declared last so normal field drop order
/// releases every other retained proof before releasing the cooperative lock.
#[must_use]
#[cfg(target_os = "linux")]
pub(super) struct InitialCandidateAuthority {
    root: std::path::PathBuf,
    physical: super::candidate_manifest::MarkerFreePhysicalManifest,
    held_root: inex_core::atomic::SecureSourceDirectory,
    context: CandidateSealContext,
    root_commit: super::candidate_git::FreshRootCommitEvidence,
    content_seal: super::candidate_seal::CandidateContentSeal,
    mutation_lock: inex_core::atomic::ExistingVaultMutationLock,
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub(super) struct InitialCandidateAuthority {
    _unsupported: (),
}

impl fmt::Debug for InitialCandidateAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitialCandidateAuthority")
            .field("root", &"[REDACTED]")
            .field("physical", &"[REDACTED]")
            .field("held_root", &"[REDACTED]")
            .field("context", &"[REDACTED]")
            .field("root_commit", &"[REDACTED]")
            .field("content_seal", &"[REDACTED]")
            .field("mutation_lock", &"[HELD]")
            .finish_non_exhaustive()
    }
}

/// Acquire complete held initial authority for one marker-free candidate.
///
/// The `target` seed is the opaque process-local result of initial target
/// creation. It supplies only the canonical root-commit body; the held runtime
/// object proof and final physical revalidation independently bind that seed
/// to the current target. No prebuilt runtime, vault/config, or content-seal
/// proof is accepted.
#[cfg(target_os = "linux")]
pub(super) fn acquire_initial_candidate_authority(
    root: &Path,
    target: &TargetRepository,
    vault: &Vault,
    expected_profile: VaultContentProfile,
    context: CandidateSealContext,
) -> Result<InitialCandidateAuthority, InitialCandidateAuthorityError> {
    acquire_initial_candidate_authority_impl(
        InitialCandidateInputs {
            root,
            target,
            vault,
            expected_profile,
            context,
        },
        |_, _| {},
        |_, _| {},
        |_, _| {},
    )
}

/// Fail closed before touching a target on platforms whose held traversal and
/// runtime-object authority are not implemented yet.
#[cfg(not(target_os = "linux"))]
pub(super) fn acquire_initial_candidate_authority(
    root: &Path,
    target: &TargetRepository,
    vault: &Vault,
    expected_profile: VaultContentProfile,
    context: CandidateSealContext,
) -> Result<InitialCandidateAuthority, InitialCandidateAuthorityError> {
    let _ = (root, target, vault, expected_profile, context);
    Err(InitialCandidateAuthorityError::Lock(
        ExistingVaultMutationLockError::Unsupported,
    ))
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct InitialCandidateInputs<'a> {
    root: &'a Path,
    target: &'a TargetRepository,
    vault: &'a Vault,
    expected_profile: VaultContentProfile,
    context: CandidateSealContext,
}

#[cfg(target_os = "linux")]
fn acquire_initial_candidate_authority_impl<BeforeLock, AfterLock, AfterRuntime>(
    inputs: InitialCandidateInputs<'_>,
    before_lock: BeforeLock,
    after_lock: AfterLock,
    after_runtime: AfterRuntime,
) -> Result<InitialCandidateAuthority, InitialCandidateAuthorityError>
where
    BeforeLock: FnOnce(&Path, &super::candidate_manifest::MarkerFreePhysicalManifest),
    AfterLock: FnOnce(&Path, &super::candidate_manifest::MarkerFreePhysicalManifest),
    AfterRuntime: FnOnce(&Path, &super::candidate_manifest::MarkerFreePhysicalManifest),
{
    use inex_core::atomic::{ExistingVaultMutationLock, open_secure_source_root};

    use super::candidate_git::{
        collect_fresh_git_evidence, parse_canonical_root_commit, prove_fresh_runtime_objects,
    };
    use super::candidate_manifest::collect_marker_free_physical_manifest;
    use super::candidate_seal::aggregate_candidate_content_seal_v1;
    use super::candidate_vault_authority::collect_authenticated_vault_config_authority;
    use super::candidate_worktree::{
        collect_fresh_tracked_evidence, construct_fresh_tree_evidence,
    };
    use super::{GitRunner, canonical_normal_directory, decode_sha1_oid, discover_git_executable};

    let InitialCandidateInputs {
        root,
        target,
        vault,
        expected_profile,
        context,
    } = inputs;

    let root = canonical_normal_directory(root, RepositoryImportError::TargetAuditFailed)?;
    let physical = collect_marker_free_physical_manifest(&root)?;
    if target.root_identity != *physical.root_identity() {
        return Err(CandidateSealError::InvalidContext.into());
    }

    let held_root =
        open_secure_source_root(&root).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    held_root
        .verify_no_alternate_data_streams()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    if held_root.identity() != physical.root_identity() {
        return Err(CandidateSealError::InvalidContext.into());
    }

    before_lock(&root, &physical);
    let mutation_lock = ExistingVaultMutationLock::acquire(
        &root,
        physical.root_identity(),
        physical.local_identity(),
        physical.lock_identity(),
    )?;
    mutation_lock.revalidate(&root)?;
    held_root
        .verify_no_alternate_data_streams()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    physical.require_current_exact(&root)?;
    after_lock(&root, &physical);

    let (content_seal, root_commit) = {
        let executable = discover_git_executable()
            .map_err(|_| RepositoryImportError::GitExecutableUnavailable)?;
        let runner = GitRunner::target(executable, root.clone())?;
        let tracked = collect_fresh_tracked_evidence(&physical, &held_root)?;
        let trees = construct_fresh_tree_evidence(&tracked)?;
        let root_commit = parse_canonical_root_commit(target.commit_bytes.as_slice())?;
        if decode_sha1_oid(&target.root_commit_oid)? != root_commit.commit_oid() {
            return Err(CandidateSealError::InvalidRecord.into());
        }
        let git = collect_fresh_git_evidence(&physical, &tracked, &trees, root_commit)?;
        let authenticated =
            collect_authenticated_vault_config_authority(&physical, &held_root, vault, &runner)?;
        authenticated.require_profile(&physical, expected_profile)?;
        let runtime = prove_fresh_runtime_objects(&git, &tracked, &trees, &runner)?;
        let content_seal =
            aggregate_candidate_content_seal_v1(context, &physical, &tracked, &trees, &runtime)?;
        after_runtime(&root, &physical);
        (content_seal, root_commit)
    };

    // These are the last endpoint checks before the final whole-tree exact
    // proof. No filesystem operation occurs between that proof and moving the
    // owned values into the authority.
    held_root
        .verify_no_alternate_data_streams()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    mutation_lock.revalidate(&root)?;
    physical.require_current_exact(&root)?;

    Ok(InitialCandidateAuthority {
        root,
        physical,
        held_root,
        context,
        root_commit,
        content_seal,
        mutation_lock,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fmt::Write as _;
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use inex_core::atomic::{
        ExistingVaultMutationLock, ExistingVaultMutationLockError, IMPORT_PUBLISH_MARKER_V1,
        IMPORT_PUBLISH_MARKER_V2, PublicationIdentityScheme, VAULT_LOCAL_DIRECTORY,
        VAULT_MUTATION_LOCK_FILE, filesystem_directory_identity, filesystem_file_identity,
    };
    use inex_core::crypto::VaultContentProfile;
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault::Vault;
    use inex_core::vault_config::KdfPolicy;

    use super::super::candidate_manifest::{
        MarkerFreePhysicalManifest, collect_marker_free_physical_manifest,
    };
    use super::super::candidate_seal::{CandidateSealContext, CandidateSealError};
    use super::super::{RepositoryImportError, TargetRepository, initialize_and_audit_target};
    use super::{
        InitialCandidateAuthority, InitialCandidateAuthorityError, InitialCandidateInputs,
        acquire_initial_candidate_authority, acquire_initial_candidate_authority_impl,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const PASSWORD: &[u8] = b"initial candidate authority test password";
    const CREATED_AT_MS: i64 = 1_784_044_800_000;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-initial-candidate-authority-{label}-{}-{nonce}",
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

    struct Fixture {
        vault: Vault,
        target: TargetRepository,
        root: TestDirectory,
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

    fn fixture(label: &str) -> Fixture {
        let root = TestDirectory::new(label);
        let vault = Vault::create_with_profile_and_params(
            root.path(),
            PASSWORD,
            CREATED_AT_MS,
            VaultContentProfile::DocumentsOnly,
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            },
            policy(),
        )
        .expect("vault creates");
        let target = initialize_and_audit_target(
            root.path(),
            &[
                PathBuf::from(".gitattributes"),
                PathBuf::from(".gitignore"),
                PathBuf::from("vault.json"),
            ],
            CREATED_AT_MS.div_euclid(1_000),
        )
        .expect("target initializes and audits");
        Fixture {
            vault,
            target,
            root,
        }
    }

    fn context() -> CandidateSealContext {
        CandidateSealContext {
            scheme: PublicationIdentityScheme::LinuxDevInodeV1,
            publication_id: [0x5a; 16],
        }
    }

    fn lock_path(root: &Path) -> PathBuf {
        root.join(VAULT_LOCAL_DIRECTORY)
            .join(VAULT_MUTATION_LOCK_FILE)
    }

    fn acquire_from_manifest(
        root: &Path,
        physical: &MarkerFreePhysicalManifest,
    ) -> Result<ExistingVaultMutationLock, ExistingVaultMutationLockError> {
        ExistingVaultMutationLock::acquire(
            root,
            physical.root_identity(),
            physical.local_identity(),
            physical.lock_identity(),
        )
    }

    fn assert_no_marker(root: &Path) {
        assert!(
            !root
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V1)
                .exists()
        );
        assert!(
            !root
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V2)
                .exists()
        );
    }

    fn assert_lock_available(root: &Path) {
        let physical = collect_marker_free_physical_manifest(root)
            .expect("current marker-free physical manifest collects");
        drop(acquire_from_manifest(root, &physical).expect("mutation lock is available"));
    }

    fn lower_hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }

    #[test]
    fn real_runtime_authority_holds_exact_lock_until_drop_and_is_redacted() {
        let fixture = fixture("runtime-happy");
        let authority = acquire_initial_candidate_authority_impl(
            InitialCandidateInputs {
                root: fixture.root.path(),
                target: &fixture.target,
                vault: &fixture.vault,
                expected_profile: VaultContentProfile::DocumentsOnly,
                context: context(),
            },
            |_, _| {},
            |root, physical| {
                assert!(matches!(
                    acquire_from_manifest(root, physical),
                    Err(ExistingVaultMutationLockError::Busy)
                ));
            },
            |_, _| {},
        )
        .expect("real Git runtime authority constructs");

        assert_no_marker(fixture.root.path());
        authority
            .physical
            .require_current_exact(fixture.root.path())
            .expect("authority retains the exact physical baseline");
        assert_ne!(authority.content_seal.into_digest(), [0; 32]);
        assert_eq!(
            authority.root_commit.commit_oid(),
            super::super::decode_sha1_oid(fixture.target.root_commit_oid())
                .expect("target oid decodes")
        );
        assert!(matches!(
            acquire_from_manifest(fixture.root.path(), &authority.physical),
            Err(ExistingVaultMutationLockError::Busy)
        ));

        let root_identity = authority.physical.root_identity().clone();
        let local_identity = authority.physical.local_identity().clone();
        let lock_identity = authority.physical.lock_identity().clone();
        let debug = format!("{authority:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("[HELD]"));
        assert!(!debug.contains(fixture.root.path().to_string_lossy().as_ref()));
        assert!(!debug.contains(&lower_hex(&authority.content_seal.into_digest())));

        drop(authority);
        drop(
            ExistingVaultMutationLock::acquire(
                fixture.root.path(),
                &root_identity,
                &local_identity,
                &lock_identity,
            )
            .expect("lock reacquires after authority drop"),
        );
    }

    #[test]
    fn wrong_target_root_vault_root_and_profile_never_produce_authority() {
        let first = fixture("wrong-root-a");
        let second = fixture("wrong-root-b");

        assert!(matches!(
            acquire_initial_candidate_authority(
                first.root.path(),
                &second.target,
                &first.vault,
                VaultContentProfile::DocumentsOnly,
                context(),
            ),
            Err(InitialCandidateAuthorityError::Candidate(
                CandidateSealError::InvalidContext
            ))
        ));
        assert_lock_available(first.root.path());

        assert!(matches!(
            acquire_initial_candidate_authority(
                first.root.path(),
                &first.target,
                &second.vault,
                VaultContentProfile::DocumentsOnly,
                context(),
            ),
            Err(InitialCandidateAuthorityError::Candidate(
                CandidateSealError::InvalidContext
            ))
        ));
        assert_lock_available(first.root.path());

        assert!(matches!(
            acquire_initial_candidate_authority(
                first.root.path(),
                &first.target,
                &first.vault,
                VaultContentProfile::OpaqueAssetsV1,
                context(),
            ),
            Err(InitialCandidateAuthorityError::Candidate(
                CandidateSealError::InvalidContext
            ))
        ));
        assert_lock_available(first.root.path());
        assert_no_marker(first.root.path());
    }

    #[test]
    fn wrong_target_commit_manifest_is_rejected_inside_lock_scope() {
        let first = fixture("wrong-manifest-a");
        let second = fixture("wrong-manifest-b");
        assert_ne!(
            first.target.root_commit_oid(),
            second.target.root_commit_oid()
        );

        let mut wrong_manifest = first.target.clone();
        wrong_manifest.commit_bytes = second.target.commit_bytes.clone();
        assert!(matches!(
            acquire_initial_candidate_authority(
                first.root.path(),
                &wrong_manifest,
                &first.vault,
                VaultContentProfile::DocumentsOnly,
                context(),
            ),
            Err(InitialCandidateAuthorityError::Candidate(
                CandidateSealError::InvalidRecord
            ))
        ));
        assert_lock_available(first.root.path());
        assert_no_marker(first.root.path());
    }

    #[test]
    fn missing_core_lock_error_is_preserved() {
        let missing = fixture("lock-missing");
        let result = acquire_initial_candidate_authority_impl(
            InitialCandidateInputs {
                root: missing.root.path(),
                target: &missing.target,
                vault: &missing.vault,
                expected_profile: VaultContentProfile::DocumentsOnly,
                context: context(),
            },
            |root, _| fs::remove_file(lock_path(root)).expect("lock removes"),
            |_, _| {},
            |_, _| {},
        );
        assert!(matches!(
            result,
            Err(InitialCandidateAuthorityError::Lock(
                ExistingVaultMutationLockError::Io(ref error)
            )) if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(!lock_path(missing.root.path()).exists());
        assert_no_marker(missing.root.path());
    }

    #[test]
    fn nonzero_core_lock_error_is_preserved() {
        let nonzero = fixture("lock-nonzero");
        let result = acquire_initial_candidate_authority_impl(
            InitialCandidateInputs {
                root: nonzero.root.path(),
                target: &nonzero.target,
                vault: &nonzero.vault,
                expected_profile: VaultContentProfile::DocumentsOnly,
                context: context(),
            },
            |root, _| fs::write(lock_path(root), b"not empty").expect("lock changes"),
            |_, _| {},
            |_, _| {},
        );
        assert!(matches!(
            result,
            Err(InitialCandidateAuthorityError::Lock(
                ExistingVaultMutationLockError::UnsafeLock
            ))
        ));
        assert_eq!(
            fs::read(lock_path(nonzero.root.path())).expect("changed lock reads"),
            b"not empty"
        );
        assert_no_marker(nonzero.root.path());
    }

    #[test]
    fn hardlinked_core_lock_error_is_preserved() {
        let hardlink = fixture("lock-hardlink");
        let alias = hardlink
            .root
            .path()
            .join(VAULT_LOCAL_DIRECTORY)
            .join("lock-alias");
        let result = acquire_initial_candidate_authority_impl(
            InitialCandidateInputs {
                root: hardlink.root.path(),
                target: &hardlink.target,
                vault: &hardlink.vault,
                expected_profile: VaultContentProfile::DocumentsOnly,
                context: context(),
            },
            |root, _| fs::hard_link(lock_path(root), &alias).expect("hard link creates"),
            |_, _| {},
            |_, _| {},
        );
        assert!(matches!(
            result,
            Err(InitialCandidateAuthorityError::Lock(
                ExistingVaultMutationLockError::UnsafeLock
            ))
        ));
        assert!(alias.exists());
        assert_no_marker(hardlink.root.path());
    }

    #[test]
    fn symlinked_core_lock_error_is_preserved() {
        let symlink = fixture("lock-symlink");
        let replacement = symlink
            .root
            .path()
            .join(VAULT_LOCAL_DIRECTORY)
            .join("replacement-lock");
        let result = acquire_initial_candidate_authority_impl(
            InitialCandidateInputs {
                root: symlink.root.path(),
                target: &symlink.target,
                vault: &symlink.vault,
                expected_profile: VaultContentProfile::DocumentsOnly,
                context: context(),
            },
            |root, _| {
                use std::os::unix::fs::symlink;

                fs::write(&replacement, []).expect("replacement creates");
                fs::remove_file(lock_path(root)).expect("original lock removes");
                symlink(&replacement, lock_path(root)).expect("symlink creates");
            },
            |_, _| {},
            |_, _| {},
        );
        assert!(matches!(
            result,
            Err(InitialCandidateAuthorityError::Lock(
                ExistingVaultMutationLockError::Io(_)
                    | ExistingVaultMutationLockError::UnsafeLock
                    | ExistingVaultMutationLockError::LockIdentityMismatch
            ))
        ));
        assert!(
            fs::symlink_metadata(lock_path(symlink.root.path()))
                .expect("symlink remains")
                .file_type()
                .is_symlink()
        );
        assert_no_marker(symlink.root.path());
    }

    #[test]
    fn already_busy_lock_is_returned_without_mutation() {
        let fixture = fixture("lock-busy");
        let physical =
            collect_marker_free_physical_manifest(fixture.root.path()).expect("baseline collects");
        let held = acquire_from_manifest(fixture.root.path(), &physical).expect("lock holds");
        assert!(matches!(
            acquire_initial_candidate_authority(
                fixture.root.path(),
                &fixture.target,
                &fixture.vault,
                VaultContentProfile::DocumentsOnly,
                context(),
            ),
            Err(InitialCandidateAuthorityError::Lock(
                ExistingVaultMutationLockError::Busy
            ))
        ));
        assert_no_marker(fixture.root.path());
        drop(held);
        assert_lock_available(fixture.root.path());
    }

    #[test]
    fn persistent_post_runtime_tamper_is_rejected_by_final_physical_exact() {
        let fixture = fixture("post-runtime-tamper");
        let config = fixture.root.path().join(".git/config");
        let result = acquire_initial_candidate_authority_impl(
            InitialCandidateInputs {
                root: fixture.root.path(),
                target: &fixture.target,
                vault: &fixture.vault,
                expected_profile: VaultContentProfile::DocumentsOnly,
                context: context(),
            },
            |_, _| {},
            |_, _| {},
            |_, _| {
                fs::write(&config, b"persistent post-runtime tamper\n").expect("config tampers");
            },
        );
        assert!(matches!(
            result,
            Err(InitialCandidateAuthorityError::Repository(
                RepositoryImportError::TargetAuditFailed
            ))
        ));
        assert_eq!(
            fs::read(&config).expect("tampered config reads"),
            b"persistent post-runtime tamper\n"
        );
        assert_no_marker(fixture.root.path());

        let current = collect_marker_free_physical_manifest(fixture.root.path())
            .expect("tampered marker-free target still inventories");
        drop(
            acquire_from_manifest(fixture.root.path(), &current)
                .expect("failed authority released lock"),
        );
    }

    #[test]
    fn existing_marker_is_rejected_before_lock_and_left_byte_exact() {
        let fixture = fixture("marker-present");
        let root_identity =
            filesystem_directory_identity(fixture.root.path()).expect("root identity captures");
        let local = fixture.root.path().join(VAULT_LOCAL_DIRECTORY);
        let local_identity =
            filesystem_directory_identity(&local).expect("local identity captures");
        let lock = File::open(lock_path(fixture.root.path())).expect("lock opens");
        let lock_identity = filesystem_file_identity(&lock).expect("lock identity captures");
        drop(lock);

        let marker = local.join(IMPORT_PUBLISH_MARKER_V2);
        let marker_bytes = b"marker state belongs to a later typestate";
        fs::write(&marker, marker_bytes).expect("marker fixture creates");
        assert!(matches!(
            acquire_initial_candidate_authority(
                fixture.root.path(),
                &fixture.target,
                &fixture.vault,
                VaultContentProfile::DocumentsOnly,
                context(),
            ),
            Err(InitialCandidateAuthorityError::Repository(
                RepositoryImportError::TargetAuditFailed
            ))
        ));
        assert_eq!(fs::read(&marker).expect("marker reads"), marker_bytes);
        drop(
            ExistingVaultMutationLock::acquire(
                fixture.root.path(),
                &root_identity,
                &local_identity,
                &lock_identity,
            )
            .expect("initial collector did not acquire or mutate the lock"),
        );
    }

    #[test]
    fn production_constructor_matches_tested_implementation() {
        let fixture = fixture("production-constructor");
        let authority: InitialCandidateAuthority = acquire_initial_candidate_authority(
            fixture.root.path(),
            &fixture.target,
            &fixture.vault,
            VaultContentProfile::DocumentsOnly,
            context(),
        )
        .expect("production constructor succeeds");
        assert_eq!(authority.context, context());
        assert_eq!(authority.root, fixture.root.path());
        authority
            .held_root
            .verify_binding()
            .expect("retained held root remains bound");
        authority
            .mutation_lock
            .revalidate(fixture.root.path())
            .expect("retained mutation lock remains bound");
        assert_no_marker(fixture.root.path());
    }
}
