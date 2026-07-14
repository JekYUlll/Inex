//! Initial-only authenticated vault and target-config authority.
//!
//! This module deliberately produces a short-lived process-local proof, not a
//! persistent publication claim.  The constructor binds one independently
//! unlocked [`Vault`] to the exact `vault.json` record in a marker-free
//! physical manifest, then parses the exact held `.git/config` bytes through
//! Git's stdin-only `--file - --no-includes` interface.  Returned authority
//! retains no password, master key, filesystem path, file body, or Git output.
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
    git_config: PhysicalRecordId,
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
            || !record_is_exact_file(physical, self.git_config, TARGET_CONFIG_PATH)
        {
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
        AuthenticatedVaultConfigAuthority, CandidateSealError, MarkerFreePhysicalManifest,
        PhysicalRecordId, PhysicalRecordKindRef, TARGET_CONFIG_PATH, VAULT_JSON_PATH,
        authenticated_profile, exact_file_id,
    };
    use inex_core::vault::Vault;

    const MAX_TARGET_CONFIG_OUTPUT_BYTES: usize = 1024 * 1024;

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
        require_common_root(physical, held_root, vault, runner)?;

        let vault_json = exact_file_id(physical, VAULT_JSON_PATH)?;
        verify_held_vault_json(physical, held_root, vault_json, vault)?;

        let git_config = exact_file_id(physical, TARGET_CONFIG_PATH)?;
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
            profile: authenticated_profile(vault)?,
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
        held_root
            .verify_binding()
            .map_err(|_| CandidateSealError::InvalidContext)?;
        if held_root.identity() != physical.root_identity()
            || !runner.target
            || runner.target_hooks.is_none()
            || filesystem_directory_identity(vault.root()).ok().as_ref()
                != Some(physical.root_identity())
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

        use inex_core::crypto::VaultContentProfile;
        use inex_core::sodium::Argon2idParams;
        use inex_core::vault::Vault;
        use inex_core::vault_config::KdfPolicy;

        use super::super::super::candidate_manifest::collect_marker_free_physical_manifest;
        use super::super::super::candidate_seal::CandidateSealError;
        use super::super::super::{GitRunner, discover_git_executable};
        use super::super::{
            TARGET_CONFIG_PATH, VAULT_JSON_PATH, collect_authenticated_vault_config_authority,
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
pub(super) use linux::collect_authenticated_vault_config_authority;

#[cfg(not(target_os = "linux"))]
pub(super) fn collect_authenticated_vault_config_authority<'physical>(
    _physical: &'physical MarkerFreePhysicalManifest,
    _unsupported_held_root: (),
    _vault: &Vault,
    _unsupported_runner: (),
) -> Result<AuthenticatedVaultConfigAuthority<'physical>, CandidateSealError> {
    Err(CandidateSealError::InvalidContext)
}
