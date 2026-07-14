//! Existing-only publication authority for one fresh repository candidate.
//!
//! The fresh entry point accepts only destination coordinates. It opens the
//! exact pre-existing mutation lock and canonical v2 marker through the core
//! fused opener, validates repository policy from the held marker, performs a
//! complete marker-aware target audit, and returns one linear owner. It never
//! accepts or constructs source-import, vault-unlock, KDF, publication-id,
//! content-seal, root-commit, or count evidence.
//!
//! Once opening succeeds, every failure retains that same marker and mutation
//! lock in a terminal owner. The owner exposes neither cleanup nor a forward
//! transition, so a rejected claim cannot be relabelled as published.

use std::fmt;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use inex_core::atomic::{ExistingPublicationMarkerV2OpenError, FilesystemDirectoryIdentity};
#[cfg(target_os = "linux")]
use inex_core::atomic::{
    HeldPublicationMarkerV2, HeldPublicationMarkerV2Error, IMPORT_STAGING_PREFIX,
    open_existing_publication_marker_v2,
};
#[cfg(target_os = "linux")]
use inex_core::path::raw_portable_case_fold_key;

#[cfg(target_os = "linux")]
use super::RepositoryImportError;
#[cfg(target_os = "linux")]
use super::candidate_fresh_audit::{FreshMarkerCandidateAudit, audit_fresh_marker_candidate};
#[cfg(target_os = "linux")]
use super::candidate_seal::DOMAIN;

/// Shared repository-level child-name policy used by initial and fresh claims.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CandidatePublicationNameError {
    InvalidStagingName,
    ReservedDestinationName,
}

/// Extract and validate the exact import-staging basename from a root path.
#[cfg(target_os = "linux")]
pub(super) fn validated_staging_child_name_from_root(
    root: &Path,
) -> Result<String, CandidatePublicationNameError> {
    let name = root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(CandidatePublicationNameError::InvalidStagingName)?;
    validate_staging_child_name(name)?;
    Ok(name.to_owned())
}

/// Require `.inex-import-staging-` followed by exactly 32 lowercase hex bytes.
#[cfg(target_os = "linux")]
pub(super) fn validate_staging_child_name(name: &str) -> Result<(), CandidatePublicationNameError> {
    name.strip_prefix(IMPORT_STAGING_PREFIX)
        .filter(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map(|_| ())
        .ok_or(CandidatePublicationNameError::InvalidStagingName)
}

/// Reject destination names that portable-fold beneath the staging prefix.
#[cfg(target_os = "linux")]
pub(super) fn require_unreserved_destination_child_name(
    destination_child_name: &str,
) -> Result<(), CandidatePublicationNameError> {
    let destination = raw_portable_case_fold_key(destination_child_name);
    let reserved = raw_portable_case_fold_key(IMPORT_STAGING_PREFIX);
    if destination.as_str().starts_with(reserved.as_str()) {
        Err(CandidatePublicationNameError::ReservedDestinationName)
    } else {
        Ok(())
    }
}

/// Caller-owned coordinates for opening one already-published candidate.
///
/// The input intentionally contains no source, authentication, construction,
/// marker-body, or expected candidate-summary fields. All such evidence is
/// derived from the existing destination while the exact lock remains held.
#[derive(Clone, Copy)]
pub(super) struct FreshExistingClaimInput<'a> {
    pub(super) destination_root: &'a Path,
    pub(super) common_parent_identity: &'a FilesystemDirectoryIdentity,
    pub(super) destination_child_name: &'a str,
}

impl fmt::Debug for FreshExistingClaimInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshExistingClaimInput")
            .field("destination_root", &"[REDACTED]")
            .field("common_parent_identity", &"[REDACTED]")
            .field("destination_child_name", &"[REDACTED]")
            .finish()
    }
}

/// Fixed post-open failure category retained beside the live marker owner.
#[cfg(target_os = "linux")]
pub(super) enum FreshExistingPostOpenFailure {
    DomainMismatch,
    InvalidStagingName,
    DestinationMismatch,
    ReservedDestinationName,
    CommonParentMismatch,
    PublishedRole(HeldPublicationMarkerV2Error),
    FreshAudit(RepositoryImportError),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for FreshExistingPostOpenFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DomainMismatch => "FreshExistingPostOpenFailure::DomainMismatch",
            Self::InvalidStagingName => "FreshExistingPostOpenFailure::InvalidStagingName",
            Self::DestinationMismatch => "FreshExistingPostOpenFailure::DestinationMismatch",
            Self::ReservedDestinationName => {
                "FreshExistingPostOpenFailure::ReservedDestinationName"
            }
            Self::CommonParentMismatch => "FreshExistingPostOpenFailure::CommonParentMismatch",
            Self::PublishedRole(_) => "FreshExistingPostOpenFailure::PublishedRole(..)",
            Self::FreshAudit(_) => "FreshExistingPostOpenFailure::FreshAudit(..)",
        })
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for FreshExistingPostOpenFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DomainMismatch => "fresh candidate marker domain is invalid",
            Self::InvalidStagingName => "fresh candidate staging name is invalid",
            Self::DestinationMismatch => "fresh candidate destination does not match",
            Self::ReservedDestinationName => "fresh candidate destination is reserved",
            Self::CommonParentMismatch => "fresh candidate common parent does not match",
            Self::PublishedRole(_) => "fresh candidate publication role is invalid",
            Self::FreshAudit(_) => "fresh candidate audit failed",
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for FreshExistingPostOpenFailure {}

/// Terminal owner for a fresh claim rejected after the fused open succeeded.
///
/// No method exposes the held marker, performs cleanup, or advances the state.
/// The marker is deliberately the final field so the mutation lock it owns is
/// released only after the retained failure category.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct FailedHeldFreshExistingClaim {
    failure: FreshExistingPostOpenFailure,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl FailedHeldFreshExistingClaim {
    pub(super) const fn failure(&self) -> &FreshExistingPostOpenFailure {
        &self.failure
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for FailedHeldFreshExistingClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedHeldFreshExistingClaim")
            .field("failure", &self.failure)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Failure while opening and auditing one existing published candidate.
pub(super) enum FreshExistingClaimError {
    Open(ExistingPublicationMarkerV2OpenError),
    #[cfg(target_os = "linux")]
    PostOpen(Box<FailedHeldFreshExistingClaim>),
}

impl fmt::Debug for FreshExistingClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(_) => formatter.write_str("FreshExistingClaimError::Open(..)"),
            #[cfg(target_os = "linux")]
            Self::PostOpen(owner) => formatter.debug_tuple("PostOpen").field(owner).finish(),
        }
    }
}

impl fmt::Display for FreshExistingClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Open(_) => "fresh existing candidate could not be opened",
            #[cfg(target_os = "linux")]
            Self::PostOpen(_) => "fresh existing candidate failed after opening",
        })
    }
}

impl std::error::Error for FreshExistingClaimError {}

/// Complete existing destination authority with its exact v2 marker retained.
///
/// This linear value is the shared back-half state for fresh reconciliation
/// and, later, a successfully moved initial candidate. It is intentionally
/// neither `Clone` nor `Copy`; the held marker is the final field.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct PublishedWithMarker {
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub(super) struct PublishedWithMarker {
    _unsupported: std::convert::Infallible,
}

#[cfg(target_os = "linux")]
impl PublishedWithMarker {
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) const fn audit(&self) -> &FreshMarkerCandidateAudit {
        &self.audit
    }

    pub(super) const fn held_marker(&self) -> &HeldPublicationMarkerV2 {
        &self.held_marker
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PublishedWithMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedWithMarker")
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

#[cfg(not(target_os = "linux"))]
impl fmt::Debug for PublishedWithMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublishedWithMarker { unsupported: true }")
    }
}

/// Open and fully audit one existing published repository candidate.
///
/// Linux uses the core fused opener. Other targets fail closed before any
/// repository-specific transition can be constructed.
pub(super) fn claim_fresh_existing_candidate(
    input: FreshExistingClaimInput<'_>,
) -> Result<PublishedWithMarker, FreshExistingClaimError> {
    #[cfg(target_os = "linux")]
    {
        claim_fresh_existing_candidate_impl(input, |_, _| {}, |_, _, _| {})
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = input;
        Err(FreshExistingClaimError::Open(
            ExistingPublicationMarkerV2OpenError::Unsupported,
        ))
    }
}

#[cfg(target_os = "linux")]
fn claim_fresh_existing_candidate_impl<AfterOpen, AfterAudit>(
    input: FreshExistingClaimInput<'_>,
    after_open: AfterOpen,
    after_audit: AfterAudit,
) -> Result<PublishedWithMarker, FreshExistingClaimError>
where
    AfterOpen: FnOnce(&Path, &HeldPublicationMarkerV2),
    AfterAudit: FnOnce(&Path, &HeldPublicationMarkerV2, &FreshMarkerCandidateAudit),
{
    let root = input.destination_root.to_path_buf();
    let held_marker =
        open_existing_publication_marker_v2(&root).map_err(FreshExistingClaimError::Open)?;
    after_open(&root, &held_marker);

    let marker = held_marker.marker();
    if marker.domain() != DOMAIN {
        return Err(failed_post_open_claim(
            FreshExistingPostOpenFailure::DomainMismatch,
            held_marker,
        ));
    }
    if validate_staging_child_name(marker.staging_child_name()).is_err() {
        return Err(failed_post_open_claim(
            FreshExistingPostOpenFailure::InvalidStagingName,
            held_marker,
        ));
    }
    let root_name_matches = root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name == input.destination_child_name);
    if !root_name_matches || marker.destination_child_name() != input.destination_child_name {
        return Err(failed_post_open_claim(
            FreshExistingPostOpenFailure::DestinationMismatch,
            held_marker,
        ));
    }
    if require_unreserved_destination_child_name(marker.destination_child_name()).is_err() {
        return Err(failed_post_open_claim(
            FreshExistingPostOpenFailure::ReservedDestinationName,
            held_marker,
        ));
    }
    if !marker.common_parent_matches(input.common_parent_identity) {
        return Err(failed_post_open_claim(
            FreshExistingPostOpenFailure::CommonParentMismatch,
            held_marker,
        ));
    }
    if let Err(error) = held_marker.require_published_at(&root) {
        return Err(failed_post_open_claim(
            FreshExistingPostOpenFailure::PublishedRole(error),
            held_marker,
        ));
    }

    let audit = match audit_fresh_marker_candidate(&root, &held_marker) {
        Ok(audit) => audit,
        Err(error) => {
            return Err(failed_post_open_claim(
                FreshExistingPostOpenFailure::FreshAudit(error),
                held_marker,
            ));
        }
    };
    after_audit(&root, &held_marker, &audit);
    if let Err(error) = held_marker.require_published_at(&root) {
        return Err(failed_post_open_claim(
            FreshExistingPostOpenFailure::PublishedRole(error),
            held_marker,
        ));
    }

    Ok(PublishedWithMarker {
        root,
        audit,
        held_marker,
    })
}

#[cfg(target_os = "linux")]
fn failed_post_open_claim(
    failure: FreshExistingPostOpenFailure,
    held_marker: HeldPublicationMarkerV2,
) -> FreshExistingClaimError {
    FreshExistingClaimError::PostOpen(Box::new(FailedHeldFreshExistingClaim {
        failure,
        held_marker,
    }))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use inex_core::atomic::{
        ExistingVaultMutationLock, ExistingVaultMutationLockError, FilesystemFileIdentity,
        IMPORT_PUBLISH_MARKER_V2, PublicationIdentityScheme, VAULT_LOCAL_DIRECTORY,
        filesystem_directory_identity,
    };
    use inex_core::crypto::VaultContentProfile;
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault::Vault;
    use inex_core::vault_config::KdfPolicy;

    use super::super::candidate_initial_authority::{
        InitialCandidateClaimInput, acquire_initial_candidate_authority, claim_initial_candidate,
    };
    use super::super::candidate_manifest::collect_marker_free_physical_manifest;
    use super::super::candidate_seal::CandidateSealContext;
    use super::super::initialize_and_audit_target;
    use super::*;

    const PASSWORD: &[u8] = b"fresh existing authority test password";
    const CREATED_AT_MS: i64 = 1_784_044_800_000;

    struct ExpectedAudit {
        context: CandidateSealContext,
        content_seal: [u8; 32],
        root_commit_oid: [u8; 20],
        counts: (u32, u32, u32, u32),
    }

    struct PublishedFixture {
        parent: PathBuf,
        destination_root: PathBuf,
        destination_child_name: String,
        common_parent_identity: FilesystemDirectoryIdentity,
        baseline: (
            FilesystemDirectoryIdentity,
            FilesystemDirectoryIdentity,
            FilesystemFileIdentity,
        ),
        staging_child_name: String,
        expected: ExpectedAudit,
    }

    impl PublishedFixture {
        fn input(&self) -> FreshExistingClaimInput<'_> {
            FreshExistingClaimInput {
                destination_root: &self.destination_root,
                common_parent_identity: &self.common_parent_identity,
                destination_child_name: &self.destination_child_name,
            }
        }

        fn marker_path(&self) -> PathBuf {
            self.destination_root
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V2)
        }

        fn assert_lock_busy(&self) {
            assert!(matches!(
                ExistingVaultMutationLock::acquire(
                    &self.destination_root,
                    &self.baseline.0,
                    &self.baseline.1,
                    &self.baseline.2,
                ),
                Err(ExistingVaultMutationLockError::Busy)
            ));
        }

        fn assert_lock_available(&self) {
            drop(
                ExistingVaultMutationLock::acquire(
                    &self.destination_root,
                    &self.baseline.0,
                    &self.baseline.1,
                    &self.baseline.2,
                )
                .expect("terminal owner drop releases the exact lock"),
            );
        }
    }

    impl Drop for PublishedFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.parent);
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

    fn fixture(label: &str) -> PublishedFixture {
        let token = uuid::Uuid::new_v4().simple().to_string();
        let parent = std::env::temp_dir().join(format!(
            "inex-fresh-existing-authority-{label}-{}-{token}",
            std::process::id()
        ));
        fs::create_dir(&parent).expect("fixture parent creates");
        let staging_child_name = format!("{IMPORT_STAGING_PREFIX}{token}");
        let staging_root = parent.join(&staging_child_name);
        fs::create_dir(&staging_root).expect("fixture staging root creates");
        let destination_child_name = format!("published-{label}-{token}");
        let destination_root = parent.join(&destination_child_name);

        let vault = Vault::create_with_profile_and_params(
            &staging_root,
            PASSWORD,
            CREATED_AT_MS,
            VaultContentProfile::DocumentsOnly,
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            },
            policy(),
        )
        .expect("fixture vault creates");
        let target = initialize_and_audit_target(
            &staging_root,
            &[
                PathBuf::from(".gitattributes"),
                PathBuf::from(".gitignore"),
                PathBuf::from("vault.json"),
            ],
            CREATED_AT_MS.div_euclid(1_000),
        )
        .expect("fixture target initializes and audits");
        let physical = collect_marker_free_physical_manifest(&staging_root)
            .expect("fixture marker-free manifest collects");
        let baseline = (
            physical.root_identity().clone(),
            physical.local_identity().clone(),
            physical.lock_identity().clone(),
        );
        drop(physical);
        let common_parent_identity =
            filesystem_directory_identity(&parent).expect("fixture parent identity captures");
        let context = CandidateSealContext {
            scheme: PublicationIdentityScheme::LinuxDevInodeV1,
            publication_id: [0x73; 16],
        };
        let authority = acquire_initial_candidate_authority(
            &staging_root,
            &target,
            &vault,
            VaultContentProfile::DocumentsOnly,
            context,
        )
        .expect("fixture initial authority constructs");
        let claim = claim_initial_candidate(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity: &common_parent_identity,
                destination_child_name: &destination_child_name,
            },
        )
        .expect("fixture initial claim constructs");
        let expected = ExpectedAudit {
            context: claim.audit().context(),
            content_seal: claim.audit().content_seal(),
            root_commit_oid: claim.audit().root_commit_oid(),
            counts: (
                claim.audit().worktree_files(),
                claim.audit().encrypted_markdown(),
                claim.audit().encrypted_assets(),
                claim.audit().git_objects(),
            ),
        };
        fs::rename(&staging_root, &destination_root)
            .expect("fixture performs whole-root publication rename");
        claim
            .held_marker()
            .require_published_at(&destination_root)
            .expect("fixture claim validates in destination role");
        drop(claim);
        drop(target);
        drop(vault);

        PublishedFixture {
            parent,
            destination_root,
            destination_child_name,
            common_parent_identity,
            baseline,
            staging_child_name,
            expected,
        }
    }

    #[test]
    fn fresh_existing_claim_retains_post_open_failure_then_builds_published_owner() {
        let fixture = fixture("happy");
        let wrong_destination = claim_fresh_existing_candidate(FreshExistingClaimInput {
            destination_root: &fixture.destination_root,
            common_parent_identity: &fixture.common_parent_identity,
            destination_child_name: "wrong-destination",
        });
        let failed = match wrong_destination {
            Err(FreshExistingClaimError::PostOpen(owner)) => owner,
            other => panic!("expected owning destination error, got {other:?}"),
        };
        assert!(matches!(
            failed.failure(),
            FreshExistingPostOpenFailure::DestinationMismatch
        ));
        assert!(fixture.marker_path().is_file());
        fixture.assert_lock_busy();
        drop(failed);
        fixture.assert_lock_available();

        let wrong_parent = filesystem_directory_identity(&fixture.destination_root)
            .expect("wrong parent identity captures");
        let rejected = claim_fresh_existing_candidate(FreshExistingClaimInput {
            destination_root: &fixture.destination_root,
            common_parent_identity: &wrong_parent,
            destination_child_name: &fixture.destination_child_name,
        });
        let failed = match rejected {
            Err(FreshExistingClaimError::PostOpen(owner)) => owner,
            other => panic!("expected owning post-open error, got {other:?}"),
        };
        assert!(matches!(
            failed.failure(),
            FreshExistingPostOpenFailure::CommonParentMismatch
        ));
        assert!(fixture.marker_path().is_file());
        fixture.assert_lock_busy();
        let debug = format!("{failed:?}");
        assert!(!debug.contains(fixture.destination_root.to_string_lossy().as_ref()));
        drop(failed);
        fixture.assert_lock_available();

        let published = claim_fresh_existing_candidate(fixture.input())
            .expect("fresh existing claim constructs published owner");
        assert_eq!(published.root(), fixture.destination_root);
        assert_eq!(published.audit().context(), fixture.expected.context);
        assert_eq!(
            published.audit().content_seal(),
            fixture.expected.content_seal
        );
        assert_eq!(
            published.audit().root_commit_oid(),
            fixture.expected.root_commit_oid
        );
        assert_eq!(
            (
                published.audit().worktree_files(),
                published.audit().encrypted_markdown(),
                published.audit().encrypted_assets(),
                published.audit().git_objects(),
            ),
            fixture.expected.counts
        );
        assert_eq!(published.held_marker().marker().domain(), DOMAIN);
        assert_eq!(
            published.held_marker().marker().destination_child_name(),
            fixture.destination_child_name
        );
        fixture.assert_lock_busy();
        let debug = format!("{published:?}");
        assert!(!debug.contains(fixture.destination_root.to_string_lossy().as_ref()));
        drop(published);
        fixture.assert_lock_available();
    }

    #[test]
    fn staging_reappearance_after_audit_returns_terminal_held_owner() {
        let fixture = fixture("staging-reappears");
        let staging = fixture.parent.join(&fixture.staging_child_name);
        let result = claim_fresh_existing_candidate_impl(
            fixture.input(),
            |_, _| {},
            |_, _, _| {
                fs::create_dir(&staging).expect("foreign staging name reappears");
            },
        );
        let failed = match result {
            Err(FreshExistingClaimError::PostOpen(owner)) => owner,
            other => panic!("expected owning published-role error, got {other:?}"),
        };
        assert!(matches!(
            failed.failure(),
            FreshExistingPostOpenFailure::PublishedRole(_)
        ));
        assert!(fixture.marker_path().is_file());
        assert!(staging.is_dir());
        fixture.assert_lock_busy();

        fs::remove_dir(&staging).expect("foreign staging canary cleans up");
        drop(failed);
        fixture.assert_lock_available();
    }

    #[test]
    fn shared_name_policy_is_frozen() {
        let valid = format!("{IMPORT_STAGING_PREFIX}0123456789abcdef0123456789abcdef");
        assert_eq!(validate_staging_child_name(&valid), Ok(()));
        for invalid in [
            format!("{IMPORT_STAGING_PREFIX}0123456789abcdef0123456789abcde"),
            format!("{IMPORT_STAGING_PREFIX}0123456789abcdef0123456789abcdef0"),
            format!("{IMPORT_STAGING_PREFIX}0123456789abcdef0123456789abcdeF"),
            ".INEX-IMPORT-STAGING-0123456789abcdef0123456789abcdef".to_owned(),
        ] {
            assert_eq!(
                validate_staging_child_name(&invalid),
                Err(CandidatePublicationNameError::InvalidStagingName)
            );
        }
        assert_eq!(require_unreserved_destination_child_name("notes"), Ok(()));
        assert_eq!(
            require_unreserved_destination_child_name(".INEX-IMPORT-STAGING-foreign"),
            Err(CandidatePublicationNameError::ReservedDestinationName)
        );
    }

    #[test]
    fn fresh_api_surface_and_transition_order_are_frozen() {
        let source = include_str!("candidate_publication_authority.rs");
        let input = source
            .split("pub(super) struct FreshExistingClaimInput")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for FreshExistingClaimInput")
                    .next()
            })
            .expect("fresh input source exists");
        for forbidden in [
            "source:",
            "vault:",
            "password:",
            "kdf:",
            "publication_id:",
            "candidate_seal:",
            "root_commit:",
            "worktree_files:",
            "encrypted_markdown:",
            "encrypted_assets:",
            "git_objects:",
        ] {
            assert!(
                !input.contains(forbidden),
                "forbidden fresh input: {forbidden}"
            );
        }

        let published = source
            .split("pub(super) struct PublishedWithMarker")
            .nth(1)
            .and_then(|tail| tail.split("impl PublishedWithMarker").next())
            .expect("published owner source exists");
        assert!(!published.contains("derive(Clone"));
        assert!(!published.contains("derive(Copy"));
        assert!(
            published.find("audit:").expect("audit field")
                < published.find("held_marker:").expect("held marker field")
        );

        let failed = source
            .split("pub(super) struct FailedHeldFreshExistingClaim")
            .nth(1)
            .and_then(|tail| tail.split("impl FailedHeldFreshExistingClaim").next())
            .expect("failed owner source exists");
        assert!(!failed.contains("derive(Clone"));
        assert!(!failed.contains("derive(Copy"));
        assert!(
            failed.find("failure:").expect("failure field")
                < failed.find("held_marker:").expect("held marker field")
        );
        let failed_drop = ["impl Drop for ", "FailedHeldFreshExistingClaim"].concat();
        let published_drop = ["impl Drop for ", "PublishedWithMarker"].concat();
        assert!(!source.contains(&failed_drop));
        assert!(!source.contains(&published_drop));

        let transition = source
            .split("fn claim_fresh_existing_candidate_impl")
            .nth(1)
            .and_then(|tail| tail.split("fn failed_post_open_claim").next())
            .expect("fresh transition source exists");
        let open = transition
            .find("open_existing_publication_marker_v2")
            .expect("fused opener is used");
        let domain = transition
            .find("marker.domain()")
            .expect("domain validates");
        let staging = transition
            .find("validate_staging_child_name")
            .expect("staging validates");
        let destination = transition
            .find("marker.destination_child_name() != input.destination_child_name")
            .expect("destination validates");
        let reserved = transition
            .find("require_unreserved_destination_child_name")
            .expect("reserved destination validates");
        let common_parent = transition
            .find("marker.common_parent_matches")
            .expect("common parent validates");
        let first_published = transition
            .find("held_marker.require_published_at")
            .expect("published role validates before audit");
        let audit = transition
            .find("audit_fresh_marker_candidate")
            .expect("fresh audit runs");
        let second_published = transition
            .rfind("held_marker.require_published_at")
            .expect("published role validates after audit");
        assert!(
            open < domain
                && domain < staging
                && staging < destination
                && destination < reserved
                && reserved < common_parent
                && common_parent < first_published
                && first_published < audit
                && audit < second_published
        );
        assert_ne!(first_published, second_published);
        assert!(!transition.contains("drop(held_marker)"));
    }
}
