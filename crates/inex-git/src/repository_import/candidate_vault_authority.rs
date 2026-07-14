//! Target-only canonical config evidence and initial authenticated authority.
//!
//! The target-only constructor binds canonical `.git/config` bytes to one
//! marker-free physical manifest without accepting a [`Vault`] or password.
//! The initial-only constructor composes that evidence with one independently
//! unlocked [`Vault`] and the exact authenticated `vault.json` record.  Both
//! are short-lived process-local proofs, not persistent publication claims,
//! and retain no password, master key, filesystem path, body, or Git output.
//!
//! A fresh publication reconciliation must not construct or require this
//! value: it instead relies on the durable marker claim and a fresh target-only
//! candidate-seal audit.  This value is only an initial-publication gate after
//! the caller has completed its independent vault content audit.

use std::fmt;

use inex_core::crypto::VaultContentProfile;
use inex_core::features::OPAQUE_ASSETS_V1;
use inex_core::vault::Vault;

use super::candidate_manifest::{
    MarkerFreePhysicalManifest, PhysicalRecordId, PhysicalRecordKindRef,
};
use super::candidate_seal::CandidateSealError;

const VAULT_JSON_PATH: &str = "vault.json";
const TARGET_CONFIG_PATH: &str = ".git/config";

/// Target-only evidence for one exact canonical `.git/config` record.
///
/// The manifest brand and opaque record ID are private. This type deliberately
/// implements neither `Clone` nor `Copy`; detached config bytes or Git output
/// are never retained as authority.
#[must_use]
pub(super) struct FreshTargetConfigEvidence<'physical> {
    physical: &'physical MarkerFreePhysicalManifest,
    record: PhysicalRecordId,
}

impl fmt::Debug for FreshTargetConfigEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTargetConfigEvidence")
            .field("physical", &"[REDACTED]")
            .field("record", &"[REDACTED]")
            .finish()
    }
}

impl FreshTargetConfigEvidence<'_> {
    /// Prove that this evidence belongs to the exact manifest allocation.
    #[must_use]
    pub(super) fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical, physical)
    }

    /// Recheck the fixed config role in the exact branded manifest.
    pub(super) fn role(
        &self,
        physical: &MarkerFreePhysicalManifest,
    ) -> Result<super::candidate_seal::GitControlRole, CandidateSealError> {
        if !self.is_bound_to(physical)
            || !record_is_exact_file(physical, self.record, TARGET_CONFIG_PATH)
        {
            return Err(CandidateSealError::InvalidContext);
        }
        Ok(super::candidate_seal::GitControlRole::Config)
    }
}

/// Initial-process proof that authenticated vault metadata and canonical Git
/// configuration belong to one exact marker-free physical manifest.
///
/// The opaque record IDs are meaningful only together with the borrowed
/// manifest allocation.  They are never exposed independently, so callers
/// cannot rebind them to a separately collected manifest.
#[must_use]
pub(super) struct AuthenticatedVaultConfigAuthority<'physical> {
    physical: &'physical MarkerFreePhysicalManifest,
    vault_json: PhysicalRecordId,
    git_config: FreshTargetConfigEvidence<'physical>,
    profile: VaultContentProfile,
}

impl fmt::Debug for AuthenticatedVaultConfigAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedVaultConfigAuthority")
            .field("physical", &"[REDACTED]")
            .field("vault_json", &"[REDACTED]")
            .field("git_config", &"[REDACTED]")
            .field("profile", &self.profile)
            .finish()
    }
}

impl AuthenticatedVaultConfigAuthority<'_> {
    /// Prove that this authority belongs to the exact manifest allocation.
    #[must_use]
    pub(super) fn is_bound_to(&self, physical: &MarkerFreePhysicalManifest) -> bool {
        std::ptr::eq(self.physical, physical)
    }

    /// Require the authenticated content profile expected by the import plan.
    ///
    /// This also rechecks that both opaque record IDs still resolve to their
    /// fixed roles in the same immutable manifest.  It does not re-open paths;
    /// the later held-lock aggregate revalidation owns that checkpoint.
    pub(super) fn require_profile(
        &self,
        physical: &MarkerFreePhysicalManifest,
        expected: VaultContentProfile,
    ) -> Result<(), CandidateSealError> {
        if !self.is_bound_to(physical)
            || self.profile != expected
            || !record_is_exact_file(physical, self.vault_json, VAULT_JSON_PATH)
        {
            return Err(CandidateSealError::InvalidContext);
        }
        if self.git_config.role(physical)? != super::candidate_seal::GitControlRole::Config {
            return Err(CandidateSealError::InvalidContext);
        }
        Ok(())
    }
}

fn record_is_exact_file(
    physical: &MarkerFreePhysicalManifest,
    id: PhysicalRecordId,
    path: &str,
) -> bool {
    physical.record(id).is_some_and(|record| {
        record.path == path && matches!(record.kind, PhysicalRecordKindRef::File { .. })
    })
}

fn exact_file_id(
    physical: &MarkerFreePhysicalManifest,
    path: &str,
) -> Result<PhysicalRecordId, CandidateSealError> {
    let record = physical
        .find(path)
        .ok_or(CandidateSealError::InvalidRecord)?;
    if record.path != path || !matches!(record.kind, PhysicalRecordKindRef::File { .. }) {
        return Err(CandidateSealError::InvalidRecord);
    }
    Ok(record.id)
}

fn authenticated_profile(vault: &Vault) -> Result<VaultContentProfile, CandidateSealError> {
    match vault.config().required_features.as_slice() {
        [] => Ok(VaultContentProfile::DocumentsOnly),
        [OPAQUE_ASSETS_V1] => Ok(VaultContentProfile::OpaqueAssetsV1),
        _ => Err(CandidateSealError::InvalidContext),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsStr;
    use std::io::Read as _;

    use inex_core::atomic::{
        SecureSourceChild, SecureSourceDirectory, filesystem_directory_identity,
    };
    use inex_core::format::ETAG_PREFIX;
    use inex_core::vault_config::MAX_VAULT_JSON_BYTES;
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::super::candidate_control::{
        validate_target_config_output, with_held_target_config_snapshot,
    };
    use super::super::candidate_seal::GitControlRole;
    use super::super::{GitRunner, RepositoryImportError};
    use super::{
        AuthenticatedVaultConfigAuthority, CandidateSealError, FreshTargetConfigEvidence,
        MarkerFreePhysicalManifest, PhysicalRecordId, PhysicalRecordKindRef, TARGET_CONFIG_PATH,
        VAULT_JSON_PATH, authenticated_profile, exact_file_id,
    };
    use inex_core::vault::Vault;

    const MAX_TARGET_CONFIG_OUTPUT_BYTES: usize = 1024 * 1024;

    /// Collect target-only canonical config evidence without vault authority.
    pub(in crate::repository_import) fn collect_fresh_target_config_evidence<'physical>(
        physical: &'physical MarkerFreePhysicalManifest,
        held_root: &SecureSourceDirectory,
        runner: &GitRunner,
    ) -> Result<FreshTargetConfigEvidence<'physical>, CandidateSealError> {
        require_target_common_root(physical, held_root, runner)?;

        let record = exact_file_id(physical, TARGET_CONFIG_PATH)?;
        let expected_driver = super::super::super::installed_driver_command()
            .map_err(|_| CandidateSealError::InvalidContext)?;
        with_held_target_config_snapshot(physical, held_root, |snapshot| {
            if !snapshot.is_bound_to(physical) || snapshot.role() != GitControlRole::Config {
                return Err(CandidateSealError::InvalidContext);
            }
            snapshot.inspect_bytes(|bytes| {
                let output = runner
                    .run_isolated_stdin_config(bytes, MAX_TARGET_CONFIG_OUTPUT_BYTES)
                    .map_err(|error| map_repository_error(&error))?;
                validate_target_config_output(output.as_slice(), &expected_driver)
            })
        })?;

        require_target_common_root(physical, held_root, runner)?;
        held_root
            .verify_no_alternate_data_streams()
            .map_err(|_| CandidateSealError::InvalidRecord)?;

        let evidence = FreshTargetConfigEvidence { physical, record };
        if evidence.role(physical)? != GitControlRole::Config {
            return Err(CandidateSealError::InvalidContext);
        }
        Ok(evidence)
    }

    /// Capture initial-only authenticated metadata/config authority.
    ///
    /// The caller must invoke this only after its independent fresh-vault
    /// content audit.  The type intentionally proves authenticated metadata,
    /// not that the caller compared every decrypted envelope with its source
    /// plan.  That ordering remains a higher-level typestate obligation.
    pub(in crate::repository_import) fn collect_authenticated_vault_config_authority<'physical>(
        physical: &'physical MarkerFreePhysicalManifest,
        held_root: &SecureSourceDirectory,
        vault: &Vault,
        runner: &GitRunner,
    ) -> Result<AuthenticatedVaultConfigAuthority<'physical>, CandidateSealError> {
        let git_config = collect_fresh_target_config_evidence(physical, held_root, runner)?;
        require_common_root(physical, held_root, vault, runner)?;

        let vault_json = exact_file_id(physical, VAULT_JSON_PATH)?;
        verify_held_vault_json(physical, held_root, vault_json, vault)?;
        let profile = authenticated_profile(vault)?;

        require_common_root(physical, held_root, vault, runner)?;
        physical
            .require_current_exact(vault.root())
            .map_err(|error| map_repository_error(&error))?;
        held_root
            .verify_no_alternate_data_streams()
            .map_err(|_| CandidateSealError::InvalidRecord)?;

        Ok(AuthenticatedVaultConfigAuthority {
            physical,
            vault_json,
            git_config,
            profile,
        })
    }

    fn map_repository_error(error: &RepositoryImportError) -> CandidateSealError {
        if matches!(error, RepositoryImportError::ResourceLimit) {
            CandidateSealError::ResourceLimit
        } else {
            CandidateSealError::InvalidRecord
        }
    }

    fn require_common_root(
        physical: &MarkerFreePhysicalManifest,
        held_root: &SecureSourceDirectory,
        vault: &Vault,
        runner: &GitRunner,
    ) -> Result<(), CandidateSealError> {
        require_target_common_root(physical, held_root, runner)?;
        if filesystem_directory_identity(vault.root()).ok().as_ref()
            != Some(physical.root_identity())
        {
            return Err(CandidateSealError::InvalidContext);
        }
        Ok(())
    }

    fn require_target_common_root(
        physical: &MarkerFreePhysicalManifest,
        held_root: &SecureSourceDirectory,
        runner: &GitRunner,
    ) -> Result<(), CandidateSealError> {
        held_root
            .verify_binding()
            .map_err(|_| CandidateSealError::InvalidContext)?;
        if held_root.identity() != physical.root_identity()
            || !runner.target
            || runner.target_hooks.is_none()
            || filesystem_directory_identity(&runner.root).ok().as_ref()
                != Some(physical.root_identity())
        {
            return Err(CandidateSealError::InvalidContext);
        }
        runner
            .verify_runtime_bindings()
            .map_err(|_| CandidateSealError::InvalidContext)
    }

    fn verify_held_vault_json(
        physical: &MarkerFreePhysicalManifest,
        held_root: &SecureSourceDirectory,
        id: PhysicalRecordId,
        vault: &Vault,
    ) -> Result<(), CandidateSealError> {
        let record = physical
            .record(id)
            .ok_or(CandidateSealError::InvalidRecord)?;
        if record.path != VAULT_JSON_PATH {
            return Err(CandidateSealError::InvalidRecord);
        }
        let PhysicalRecordKindRef::File {
            identity,
            size,
            sha256,
        } = record.kind
        else {
            return Err(CandidateSealError::InvalidRecord);
        };
        if size > u64::try_from(MAX_VAULT_JSON_BYTES).unwrap_or(u64::MAX) {
            return Err(CandidateSealError::ResourceLimit);
        }

        held_root
            .verify_binding()
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        let SecureSourceChild::File(mut file) = held_root
            .open_child(OsStr::new(VAULT_JSON_PATH))
            .map_err(|_| CandidateSealError::InvalidRecord)?
        else {
            return Err(CandidateSealError::InvalidRecord);
        };
        file.verify_no_alternate_data_streams()
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        if file.identity().ok().as_ref() != Some(identity) || file.observed_len().ok() != Some(size)
        {
            return Err(CandidateSealError::InvalidRecord);
        }

        let length = usize::try_from(size).map_err(|_| CandidateSealError::ResourceLimit)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        bytes.resize(length, 0);
        file.read_exact(bytes.as_mut_slice())
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        let mut extra = Zeroizing::new([0_u8; 1]);
        if file
            .read(extra.as_mut_slice())
            .map_err(|_| CandidateSealError::InvalidRecord)?
            != 0
        {
            return Err(CandidateSealError::InvalidRecord);
        }
        let observed_sha256: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        drop(bytes);
        if &observed_sha256 != sha256
            || decode_config_etag(&vault.config_etag()).as_ref() != Some(sha256)
        {
            return Err(CandidateSealError::InvalidRecord);
        }

        file.verify_no_alternate_data_streams()
            .map_err(|_| CandidateSealError::InvalidRecord)?;
        if file.identity().ok().as_ref() != Some(identity) || file.observed_len().ok() != Some(size)
        {
            return Err(CandidateSealError::InvalidRecord);
        }
        held_root
            .verify_binding()
            .map_err(|_| CandidateSealError::InvalidRecord)
    }

    fn decode_config_etag(value: &str) -> Option<[u8; 32]> {
        let hexadecimal = value.strip_prefix(ETAG_PREFIX)?;
        if hexadecimal.len() != 64
            || !hexadecimal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let mut digest = [0_u8; 32];
        for (index, pair) in hexadecimal.as_bytes().chunks_exact(2).enumerate() {
            digest[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Some(digest)
    }

    fn hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::path::{Path, PathBuf};
        use std::process::Command;
        use std::sync::atomic::{AtomicU64, Ordering};

        use inex_core::atomic::{
            ExistingVaultMutationLock, HeldPublicationMarkerV2, HeldPublicationMarkerV2CreateInput,
            PublicationIdentityScheme, SecureSourceDirectory, filesystem_directory_identity,
        };
        use inex_core::crypto::VaultContentProfile;
        use inex_core::sodium::Argon2idParams;
        use inex_core::vault::Vault;
        use inex_core::vault_config::KdfPolicy;

        use super::super::super::candidate_manifest::{
            collect_held_marker_physical_manifest, collect_marker_free_physical_manifest,
        };
        use super::super::super::candidate_seal::{CandidateSealError, GitControlRole};
        use super::super::super::{GitRunner, discover_git_executable};
        use super::super::{
            MarkerFreePhysicalManifest, TARGET_CONFIG_PATH, VAULT_JSON_PATH,
            collect_authenticated_vault_config_authority, collect_fresh_target_config_evidence,
        };

        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        const PASSWORD: &[u8] = b"test-only vault authority password";

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new(label: &str) -> Self {
                let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "inex-candidate-vault-authority-{label}-{}-{nonce}",
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
            root: TestDirectory,
            vault: Vault,
            runner: GitRunner,
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

        fn fixture(label: &str, profile: VaultContentProfile) -> Fixture {
            let root = TestDirectory::new(label);
            let vault = Vault::create_with_profile_and_params(
                root.path(),
                PASSWORD,
                1_784_044_800_000,
                profile,
                Argon2idParams {
                    ops_limit: 1,
                    mem_limit_bytes: 8 * 1024,
                },
                policy(),
            )
            .expect("vault creates");

            let template = TestDirectory::new("template");
            let executable = discover_git_executable().expect("Git resolves");
            let init = Command::new(&executable)
                .arg("init")
                .arg("--quiet")
                .arg("--object-format=sha1")
                .arg("--initial-branch=main")
                .arg(format!("--template={}", template.path().display()))
                .arg(root.path())
                .status()
                .expect("git init runs");
            assert!(init.success(), "git init succeeds");
            fs::create_dir(root.path().join(".git/inex-empty-hooks"))
                .expect("empty hooks directory creates");

            let driver = super::super::super::super::installed_driver_command()
                .expect("driver command derives");
            for (key, value) in [
                ("merge.inex.name", super::super::super::super::DRIVER_NAME),
                ("merge.inex.driver", driver.as_str()),
            ] {
                let status = Command::new(&executable)
                    .current_dir(root.path())
                    .args(["config", "--local", "--replace-all", key, value])
                    .status()
                    .expect("git config runs");
                assert!(status.success(), "git config succeeds");
            }

            let runner = GitRunner::target(executable, root.path().to_path_buf())
                .expect("target runner binds");
            Fixture {
                root,
                vault,
                runner,
            }
        }

        fn physical_and_root(
            fixture: &Fixture,
        ) -> (MarkerFreePhysicalManifest, SecureSourceDirectory) {
            let physical = collect_marker_free_physical_manifest(fixture.root.path())
                .expect("physical manifest collects");
            let held_root = inex_core::atomic::open_secure_source_root(fixture.root.path())
                .expect("held root opens");
            (physical, held_root)
        }

        fn create_held_marker(fixture: &Fixture) -> HeldPublicationMarkerV2 {
            let physical = collect_marker_free_physical_manifest(fixture.root.path())
                .expect("marker-free fixture collects");
            let held_root = inex_core::atomic::open_secure_source_root(fixture.root.path())
                .expect("fixture root holds");
            let mutation_lock = ExistingVaultMutationLock::acquire(
                fixture.root.path(),
                physical.root_identity(),
                physical.local_identity(),
                physical.lock_identity(),
            )
            .expect("existing mutation lock holds");
            let common_parent_identity = filesystem_directory_identity(
                fixture
                    .root
                    .path()
                    .parent()
                    .expect("fixture root has a parent"),
            )
            .expect("common-parent identity captures");
            let staging_child_name = fixture
                .root
                .path()
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .expect("fixture root has a portable child name");
            mutation_lock
                .create_held_publication_marker_v2(
                    fixture.root.path(),
                    held_root,
                    HeldPublicationMarkerV2CreateInput {
                        scheme: PublicationIdentityScheme::LinuxDevInodeV1,
                        publication_id: [0x6d; 16],
                        common_parent_identity: &common_parent_identity,
                        staging_child_name,
                        destination_child_name: "fresh-marker-aware-destination",
                        domain: "inex.repository-import.v1",
                        candidate_seal: &[0xa7; 32],
                    },
                )
                .expect("held v2 publication marker creates")
        }

        #[test]
        fn fresh_target_config_is_branded_role_checked_and_redacted() {
            let first = fixture("fresh-first", VaultContentProfile::DocumentsOnly);
            let (first_physical, first_root) = physical_and_root(&first);
            let evidence =
                collect_fresh_target_config_evidence(&first_physical, &first_root, &first.runner)
                    .expect("fresh target config evidence collects");
            assert!(evidence.is_bound_to(&first_physical));
            assert_eq!(evidence.role(&first_physical), Ok(GitControlRole::Config));

            let debug = format!("{evidence:?}");
            assert!(debug.contains("FreshTargetConfigEvidence"));
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains(TARGET_CONFIG_PATH));
            assert!(!debug.contains("merge.inex"));

            let second = fixture("fresh-second", VaultContentProfile::DocumentsOnly);
            let (second_physical, _second_root) = physical_and_root(&second);
            assert!(!evidence.is_bound_to(&second_physical));
            assert_eq!(
                evidence.role(&second_physical),
                Err(CandidateSealError::InvalidContext)
            );
        }

        #[test]
        fn fresh_target_config_composes_with_held_marker_manifest() {
            let fixture = fixture("fresh-held-marker", VaultContentProfile::DocumentsOnly);
            let held_marker = create_held_marker(&fixture);
            let marker_present =
                collect_held_marker_physical_manifest(fixture.root.path(), &held_marker)
                    .expect("held-marker physical projection collects");

            let evidence = collect_fresh_target_config_evidence(
                marker_present.physical(),
                marker_present.held_root(),
                &fixture.runner,
            )
            .expect("target-only config accepts exact held-marker projection");
            assert!(evidence.is_bound_to(marker_present.physical()));
            assert_eq!(
                evidence.role(marker_present.physical()),
                Ok(GitControlRole::Config)
            );
            marker_present
                .require_current_exact(fixture.root.path())
                .expect("outer held-marker authority owns final whole-tree exactness");
        }

        #[test]
        fn fresh_target_config_rejects_invalid_config_and_cross_root_inputs() {
            let invalid = fixture("fresh-invalid", VaultContentProfile::DocumentsOnly);
            let config = invalid.root.path().join(TARGET_CONFIG_PATH);
            let mut bytes = fs::read(&config).expect("config reads");
            bytes.extend_from_slice(b"\n[include]\n\tpath = /tmp/hostile\n");
            fs::write(&config, bytes).expect("unsafe config writes");
            let (invalid_physical, invalid_root) = physical_and_root(&invalid);
            assert!(matches!(
                collect_fresh_target_config_evidence(
                    &invalid_physical,
                    &invalid_root,
                    &invalid.runner
                ),
                Err(CandidateSealError::InvalidRecord)
            ));

            let first = fixture("fresh-root-a", VaultContentProfile::DocumentsOnly);
            let second = fixture("fresh-root-b", VaultContentProfile::DocumentsOnly);
            let (first_physical, first_root) = physical_and_root(&first);
            let (_second_physical, second_root) = physical_and_root(&second);
            assert_eq!(
                collect_fresh_target_config_evidence(&first_physical, &first_root, &second.runner)
                    .err(),
                Some(CandidateSealError::InvalidContext)
            );
            assert_eq!(
                collect_fresh_target_config_evidence(&first_physical, &second_root, &first.runner)
                    .err(),
                Some(CandidateSealError::InvalidContext)
            );
        }

        #[test]
        fn production_api_keeps_target_config_vault_free_and_single_sourced() {
            let source = include_str!("candidate_vault_authority.rs");
            let production = source
                .split_once("\n    #[cfg(test)]")
                .map_or(source, |(production, _)| production);
            let fresh = production
                .split_once(
                    "pub(in crate::repository_import) fn collect_fresh_target_config_evidence",
                )
                .and_then(|(_, tail)| {
                    tail.split_once(
                        "\n    /// Capture initial-only authenticated metadata/config authority.",
                    )
                })
                .map_or_else(
                    || panic!("fresh target config source boundary changed"),
                    |(fresh, _)| fresh,
                );
            assert!(!fresh.contains("Vault"));
            assert!(!fresh.contains("password"));
            assert_eq!(fresh.matches("run_isolated_stdin_config").count(), 1);
            assert_eq!(fresh.matches("validate_target_config_output").count(), 1);
            assert_eq!(fresh.matches("installed_driver_command").count(), 1);
            assert!(!fresh.contains("require_current_exact"));

            let initial = production
                .split_once(
                    "pub(in crate::repository_import) fn collect_authenticated_vault_config_authority",
                )
                .and_then(|(_, tail)| tail.split_once("\n    fn map_repository_error"))
                .map_or_else(
                    || panic!("initial authority source boundary changed"),
                    |(initial, _)| initial,
                );
            assert_eq!(
                initial
                    .matches("collect_fresh_target_config_evidence")
                    .count(),
                1
            );
            assert!(!initial.contains("run_isolated_stdin_config"));
            assert!(!initial.contains("validate_target_config_output"));
            assert_eq!(initial.matches("require_current_exact").count(), 1);

            let declaration = production
                .split_once("pub(super) struct FreshTargetConfigEvidence")
                .and_then(|(_, tail)| {
                    tail.split_once("impl fmt::Debug for FreshTargetConfigEvidence")
                })
                .map_or_else(
                    || panic!("fresh evidence declaration boundary changed"),
                    |(declaration, _)| declaration,
                );
            assert!(!declaration.contains("derive"));
            assert!(!production.contains("impl Clone for FreshTargetConfigEvidence"));
        }

        #[test]
        fn exact_authority_is_manifest_branded_profiled_and_redacted() {
            let first = fixture("first", VaultContentProfile::OpaqueAssetsV1);
            let first_physical = collect_marker_free_physical_manifest(first.root.path())
                .expect("first physical manifest collects");
            let first_root = inex_core::atomic::open_secure_source_root(first.root.path())
                .expect("first held root opens");
            let authority = collect_authenticated_vault_config_authority(
                &first_physical,
                &first_root,
                &first.vault,
                &first.runner,
            )
            .expect("authority collects");
            authority
                .require_profile(&first_physical, VaultContentProfile::OpaqueAssetsV1)
                .expect("asset profile matches");
            assert_eq!(
                authority.require_profile(&first_physical, VaultContentProfile::DocumentsOnly),
                Err(CandidateSealError::InvalidContext)
            );

            let second = fixture("second", VaultContentProfile::OpaqueAssetsV1);
            let second_physical = collect_marker_free_physical_manifest(second.root.path())
                .expect("second physical manifest collects");
            assert!(!authority.is_bound_to(&second_physical));
            assert_eq!(
                authority.require_profile(&second_physical, VaultContentProfile::OpaqueAssetsV1),
                Err(CandidateSealError::InvalidContext)
            );

            let debug = format!("{authority:?}");
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("vault.json"));
            assert!(!debug.contains(".git/config"));
            assert!(!debug.contains("password"));
        }

        #[test]
        fn stale_authenticated_vault_etag_is_rejected() {
            let fixture = fixture("stale-etag", VaultContentProfile::DocumentsOnly);
            fs::write(
                fixture.root.path().join(VAULT_JSON_PATH),
                b"different bytes\n",
            )
            .expect("vault metadata changes");
            let physical = collect_marker_free_physical_manifest(fixture.root.path())
                .expect("mutated physical manifest collects");
            let held_root = inex_core::atomic::open_secure_source_root(fixture.root.path())
                .expect("held root opens");
            assert!(matches!(
                collect_authenticated_vault_config_authority(
                    &physical,
                    &held_root,
                    &fixture.vault,
                    &fixture.runner
                ),
                Err(CandidateSealError::InvalidRecord)
            ));
        }

        #[test]
        fn noncanonical_held_git_config_is_rejected() {
            let fixture = fixture("unsafe-config", VaultContentProfile::DocumentsOnly);
            let config = fixture.root.path().join(TARGET_CONFIG_PATH);
            let mut bytes = fs::read(&config).expect("config reads");
            bytes.extend_from_slice(b"\n[include]\n\tpath = /tmp/hostile\n");
            fs::write(&config, bytes).expect("unsafe config writes");
            let physical = collect_marker_free_physical_manifest(fixture.root.path())
                .expect("physical manifest collects");
            let held_root = inex_core::atomic::open_secure_source_root(fixture.root.path())
                .expect("held root opens");
            assert!(matches!(
                collect_authenticated_vault_config_authority(
                    &physical,
                    &held_root,
                    &fixture.vault,
                    &fixture.runner
                ),
                Err(CandidateSealError::InvalidRecord)
            ));
        }

        #[test]
        fn authority_rejects_vault_and_runner_from_other_roots() {
            let first = fixture("root-a", VaultContentProfile::DocumentsOnly);
            let second = fixture("root-b", VaultContentProfile::DocumentsOnly);
            let physical = collect_marker_free_physical_manifest(first.root.path())
                .expect("physical manifest collects");
            let held_root = inex_core::atomic::open_secure_source_root(first.root.path())
                .expect("held root opens");
            assert_eq!(
                collect_authenticated_vault_config_authority(
                    &physical,
                    &held_root,
                    &second.vault,
                    &first.runner
                )
                .err(),
                Some(CandidateSealError::InvalidContext)
            );
            assert_eq!(
                collect_authenticated_vault_config_authority(
                    &physical,
                    &held_root,
                    &first.vault,
                    &second.runner
                )
                .err(),
                Some(CandidateSealError::InvalidContext)
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(
    unused_imports,
    reason = "the unified initial-publication assembler consumes this frozen authority next"
)]
pub(super) use linux::{
    collect_authenticated_vault_config_authority, collect_fresh_target_config_evidence,
};

#[cfg(not(target_os = "linux"))]
pub(super) fn collect_fresh_target_config_evidence(
    _physical: &MarkerFreePhysicalManifest,
    _unsupported_held_root: (),
    _unsupported_runner: (),
) -> Result<FreshTargetConfigEvidence<'_>, CandidateSealError> {
    Err(CandidateSealError::InvalidContext)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn collect_authenticated_vault_config_authority<'physical>(
    _physical: &'physical MarkerFreePhysicalManifest,
    _unsupported_held_root: (),
    _vault: &Vault,
    _unsupported_runner: (),
) -> Result<AuthenticatedVaultConfigAuthority<'physical>, CandidateSealError> {
    Err(CandidateSealError::InvalidContext)
}
