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
#[cfg(target_os = "linux")]
use std::io;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use inex_core::atomic::{ExistingPublicationMarkerV2OpenError, FilesystemDirectoryIdentity};
#[cfg(target_os = "linux")]
use inex_core::atomic::{
    HeldPublicationMarkerV2, HeldPublicationMarkerV2Error, HeldPublicationMarkerV2UnlinkOutcome,
    IMPORT_STAGING_PREFIX, PostUnlinkMarkerParentSyncOutcome, PostUnlinkPublicationMarkerV2Error,
    SyncedPostUnlinkPublicationMarkerV2, TerminalPublicationMarkerV2Authority,
    UnsyncedPostUnlinkPublicationMarkerV2, open_existing_publication_marker_v2,
};
#[cfg(target_os = "linux")]
use inex_core::path::raw_portable_case_fold_key;

#[cfg(target_os = "linux")]
use super::RepositoryImportError;
#[cfg(target_os = "linux")]
use super::candidate_fresh_audit::{
    CandidateSummaryMismatch, FreshMarkerCandidateAudit, audit_fresh_marker_candidate,
    audit_post_unlink_candidate, compare_candidate_summaries,
};
#[cfg(target_os = "linux")]
use super::candidate_initial_authority::VerifiedInitialMove;
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
    /// Consume the private proof emitted by the initial no-replace transition.
    pub(super) fn from_verified_initial_move(token: VerifiedInitialMove) -> Self {
        let (root, audit, held_marker) = token.into_published_parts();
        Self {
            root,
            audit,
            held_marker,
        }
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) const fn audit(&self) -> &FreshMarkerCandidateAudit {
        &self.audit
    }

    pub(super) const fn held_marker(&self) -> &HeldPublicationMarkerV2 {
        &self.held_marker
    }

    /// Consume this published claim into an explicit durability attempt.
    pub(super) fn synchronize(self) -> PublicationDurabilityOutcome {
        synchronize_published_candidate_impl(self, |root, held_marker| {
            held_marker.synchronize_published_root_and_common_parent_at(root)
        })
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

/// Fixed, source-free form of one held-marker failure.
///
/// Raw `io::Error` values are reduced to their stable class immediately when
/// they cross from core into repository publication state.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicationMarkerFailureKind {
    InvalidInput,
    NamespaceConflict,
    AuthorityChanged,
    Io(io::ErrorKind),
}

#[cfg(target_os = "linux")]
impl From<HeldPublicationMarkerV2Error> for PublicationMarkerFailureKind {
    fn from(error: HeldPublicationMarkerV2Error) -> Self {
        match error {
            HeldPublicationMarkerV2Error::InvalidInput => Self::InvalidInput,
            HeldPublicationMarkerV2Error::NamespaceConflict => Self::NamespaceConflict,
            HeldPublicationMarkerV2Error::AuthorityChanged => Self::AuthorityChanged,
            HeldPublicationMarkerV2Error::Io(source) => Self::Io(source.kind()),
        }
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for PublicationMarkerFailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "publication marker input is invalid",
            Self::NamespaceConflict => "publication marker namespace conflicts",
            Self::AuthorityChanged => "publication marker authority changed",
            Self::Io(_) => "publication marker I/O failed",
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for PublicationMarkerFailureKind {}

/// A complete published-state review failure that prevents a forward state.
#[cfg(target_os = "linux")]
pub(super) enum PublishedCandidateReviewFailure {
    PublishedRole(PublicationMarkerFailureKind),
    FreshAudit(RepositoryImportError),
    SummaryMismatch(CandidateSummaryMismatch),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PublishedCandidateReviewFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublishedRole(kind) => {
                formatter.debug_tuple("PublishedRole").field(kind).finish()
            }
            Self::FreshAudit(_) => formatter.write_str("FreshAudit(..)"),
            Self::SummaryMismatch(field) => formatter
                .debug_tuple("SummaryMismatch")
                .field(field)
                .finish(),
        }
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for PublishedCandidateReviewFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PublishedRole(_) => "published role changed during complete review",
            Self::FreshAudit(_) => "published candidate audit failed during complete review",
            Self::SummaryMismatch(_) => {
                "published candidate summary changed during complete review"
            }
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for PublishedCandidateReviewFailure {}

/// Published state whose held root and common-parent barriers both completed.
///
/// This is the only owner eligible for the exact marker-unlink transition. It
/// exposes no owned marker, extraction API, or cleanup operation.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct PublicationDurableWithMarker {
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl PublicationDurableWithMarker {
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) const fn audit(&self) -> &FreshMarkerCandidateAudit {
        &self.audit
    }

    /// Consume durable marker authority into one exact unlink attempt.
    pub(super) fn unlink_marker(self) -> PublicationMarkerUnlinkOutcome {
        unlink_publication_marker_impl(self, |held_marker, root| {
            held_marker.unlink_exact_published_marker_at(root)
        })
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PublicationDurableWithMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationDurableWithMarker")
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Fixed terminal category from the durable-only marker unlink transition.
#[cfg(target_os = "linux")]
pub(super) enum PublicationMarkerUnlinkFailure {
    PreUnlinkReview(PublishedCandidateReviewFailure),
    NotRemovedReview(PublishedCandidateReviewFailure),
    ReplacementRetained,
    PostStateIndeterminate,
    ParentSyncReplacementRetained,
    ParentSyncPostStateIndeterminate,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PublicationMarkerUnlinkFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreUnlinkReview(failure) => formatter
                .debug_tuple("PreUnlinkReview")
                .field(failure)
                .finish(),
            Self::NotRemovedReview(failure) => formatter
                .debug_tuple("NotRemovedReview")
                .field(failure)
                .finish(),
            Self::ReplacementRetained => formatter.write_str("ReplacementRetained"),
            Self::PostStateIndeterminate => formatter.write_str("PostStateIndeterminate"),
            Self::ParentSyncReplacementRetained => {
                formatter.write_str("ParentSyncReplacementRetained")
            }
            Self::ParentSyncPostStateIndeterminate => {
                formatter.write_str("ParentSyncPostStateIndeterminate")
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for PublicationMarkerUnlinkFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PreUnlinkReview(_) => "published candidate failed its pre-unlink review",
            Self::NotRemovedReview(_) => {
                "published candidate failed review after marker was not removed"
            }
            Self::ReplacementRetained => "publication marker replacement was retained",
            Self::PostStateIndeterminate => "publication marker post-state is indeterminate",
            Self::ParentSyncReplacementRetained => {
                "publication marker replacement appeared during parent-sync retry"
            }
            Self::ParentSyncPostStateIndeterminate => {
                "publication marker state became indeterminate during parent-sync retry"
            }
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for PublicationMarkerUnlinkFailure {}

/// Internal terminal authority retained until the scrubbed result is emitted.
#[cfg(target_os = "linux")]
enum TerminalPublicationAuthority {
    Held(HeldPublicationMarkerV2),
    Core(TerminalPublicationMarkerV2Authority),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for TerminalPublicationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Held(_) => "TerminalPublicationAuthority::Held(..)",
            Self::Core(_) => "TerminalPublicationAuthority::Core(..)",
        })
    }
}

/// Terminal marker-unlink owner with no cleanup or forward transition.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct FailedPublicationMarkerUnlink {
    failure: PublicationMarkerUnlinkFailure,
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    authority: TerminalPublicationAuthority,
}

#[cfg(target_os = "linux")]
impl FailedPublicationMarkerUnlink {
    pub(super) const fn failure(&self) -> &PublicationMarkerUnlinkFailure {
        &self.failure
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for FailedPublicationMarkerUnlink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedPublicationMarkerUnlink")
            .field("failure", &self.failure)
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("authority", &self.authority)
            .finish()
    }
}

/// Exact marker absence with marker-parent synchronization confirmed.
///
/// This state is only pending the later marker-free clean audit. It is not a
/// success claim and exposes only borrowed root and prior-audit summaries.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct CleanAuditPending {
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    authority: SyncedPostUnlinkPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl CleanAuditPending {
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) const fn audit(&self) -> &FreshMarkerCandidateAudit {
        &self.audit
    }

    /// Consume synchronized marker-free authority into one complete clean
    /// audit attempt.
    pub(super) fn audit_clean(self) -> CleanAuditOutcome {
        audit_clean_candidate_impl(self, audit_post_unlink_candidate)
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for CleanAuditPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanAuditPending")
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("authority", &"[HELD]")
            .finish()
    }
}

/// Terminal category from one marker-free clean audit attempt.
#[cfg(target_os = "linux")]
pub(super) enum CleanAuditTerminalFailure {
    AuditFailedAndAuthorityLost {
        audit: RepositoryImportError,
        authority: PostUnlinkPublicationMarkerV2Error,
    },
    SummaryMismatch(CandidateSummaryMismatch),
    FinalAuthority(PostUnlinkPublicationMarkerV2Error),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for CleanAuditTerminalFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuditFailedAndAuthorityLost { authority, .. } => formatter
                .debug_struct("AuditFailedAndAuthorityLost")
                .field("audit", &"[REDACTED]")
                .field("authority", authority)
                .finish(),
            Self::SummaryMismatch(field) => formatter
                .debug_tuple("SummaryMismatch")
                .field(field)
                .finish(),
            Self::FinalAuthority(error) => formatter
                .debug_tuple("FinalAuthority")
                .field(error)
                .finish(),
        }
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for CleanAuditTerminalFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuditFailedAndAuthorityLost { .. } => {
                "clean audit failed and retained authority changed"
            }
            Self::SummaryMismatch(_) => "clean audit candidate summary changed",
            Self::FinalAuthority(_) => "clean audit final authority changed",
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for CleanAuditTerminalFailure {}

/// Terminal clean-audit owner with synchronized post-unlink authority retained.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct FailedCleanAudit {
    failure: CleanAuditTerminalFailure,
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    authority: SyncedPostUnlinkPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl FailedCleanAudit {
    pub(super) const fn failure(&self) -> &CleanAuditTerminalFailure {
        &self.failure
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for FailedCleanAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedCleanAudit")
            .field("failure", &self.failure)
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("authority", &"[HELD]")
            .finish()
    }
}

/// Complete marker-free published candidate with clean authority retained.
///
/// This private value is consumed only by the high-level transaction driver
/// and exposes no raw authority, marker reconstruction, unlink, or
/// synchronization API.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct PublishedClean {
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    authority: SyncedPostUnlinkPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl PublishedClean {
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) const fn audit(&self) -> &FreshMarkerCandidateAudit {
        &self.audit
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PublishedClean {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedClean")
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("authority", &"[HELD]")
            .finish()
    }
}

/// Consuming outcome of one marker-free clean audit attempt.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) enum CleanAuditOutcome {
    PublishedClean(PublishedClean),
    Retryable(CleanAuditPending),
    Terminal(Box<FailedCleanAudit>),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for CleanAuditOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublishedClean(owner) => formatter
                .debug_tuple("PublishedClean")
                .field(owner)
                .finish(),
            Self::Retryable(owner) => formatter.debug_tuple("Retryable").field(owner).finish(),
            Self::Terminal(owner) => formatter.debug_tuple("Terminal").field(owner).finish(),
        }
    }
}

#[cfg(target_os = "linux")]
fn audit_clean_candidate_impl<AuditDriver>(
    pending: CleanAuditPending,
    audit_driver: AuditDriver,
) -> CleanAuditOutcome
where
    AuditDriver: FnOnce(
        &Path,
        &SyncedPostUnlinkPublicationMarkerV2,
    ) -> Result<FreshMarkerCandidateAudit, RepositoryImportError>,
{
    let CleanAuditPending {
        root,
        audit,
        authority,
    } = pending;
    let clean_audit = match audit_driver(&root, &authority) {
        Ok(clean_audit) => clean_audit,
        Err(audit_failure) => {
            return match authority.revalidate_absent_at(&root) {
                Ok(()) | Err(PostUnlinkPublicationMarkerV2Error::Indeterminate) => {
                    CleanAuditOutcome::Retryable(CleanAuditPending {
                        root,
                        audit,
                        authority,
                    })
                }
                Err(authority_failure) => terminal_clean_audit(
                    root,
                    audit,
                    CleanAuditTerminalFailure::AuditFailedAndAuthorityLost {
                        audit: audit_failure,
                        authority: authority_failure,
                    },
                    authority,
                ),
            };
        }
    };

    let mismatch = compare_candidate_summaries(&clean_audit, &audit).err();
    let final_authority = authority.revalidate_absent_at(&root);
    if let Some(mismatch) = mismatch {
        return terminal_clean_audit(
            root,
            audit,
            CleanAuditTerminalFailure::SummaryMismatch(mismatch),
            authority,
        );
    }
    match final_authority {
        Ok(()) => CleanAuditOutcome::PublishedClean(PublishedClean {
            root,
            audit: clean_audit,
            authority,
        }),
        Err(PostUnlinkPublicationMarkerV2Error::Indeterminate) => {
            CleanAuditOutcome::Retryable(CleanAuditPending {
                root,
                audit: clean_audit,
                authority,
            })
        }
        Err(error) => terminal_clean_audit(
            root,
            clean_audit,
            CleanAuditTerminalFailure::FinalAuthority(error),
            authority,
        ),
    }
}

#[cfg(target_os = "linux")]
fn terminal_clean_audit(
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    failure: CleanAuditTerminalFailure,
    authority: SyncedPostUnlinkPublicationMarkerV2,
) -> CleanAuditOutcome {
    CleanAuditOutcome::Terminal(Box::new(FailedCleanAudit {
        failure,
        root,
        audit,
        authority,
    }))
}

/// Exact marker absence whose held parent synchronization is unconfirmed.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct ParentSyncPending {
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    authority: UnsyncedPostUnlinkPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl ParentSyncPending {
    /// Consume this owner into one held marker-parent sync retry.
    pub(super) fn retry_parent_sync(self) -> PublicationParentSyncOutcome {
        let Self {
            root,
            audit,
            authority,
        } = self;
        let outcome = authority.retry_marker_parent_sync_at(&root);
        map_parent_sync_outcome(root, audit, outcome)
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for ParentSyncPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParentSyncPending")
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("authority", &"[HELD]")
            .finish()
    }
}

/// High-level mapping of all five exact core unlink outcomes.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) enum PublicationMarkerUnlinkOutcome {
    NotRemoved(PublicationDurableWithMarker),
    CleanAuditPending(CleanAuditPending),
    ParentSyncPending(ParentSyncPending),
    Terminal(Box<FailedPublicationMarkerUnlink>),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PublicationMarkerUnlinkOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRemoved(owner) => formatter.debug_tuple("NotRemoved").field(owner).finish(),
            Self::CleanAuditPending(owner) => formatter
                .debug_tuple("CleanAuditPending")
                .field(owner)
                .finish(),
            Self::ParentSyncPending(owner) => formatter
                .debug_tuple("ParentSyncPending")
                .field(owner)
                .finish(),
            Self::Terminal(owner) => formatter.debug_tuple("Terminal").field(owner).finish(),
        }
    }
}

/// Mapping of all four core marker-parent retry outcomes.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) enum PublicationParentSyncOutcome {
    CleanAuditPending(CleanAuditPending),
    ParentSyncPending(ParentSyncPending),
    Terminal(Box<FailedPublicationMarkerUnlink>),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PublicationParentSyncOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CleanAuditPending(owner) => formatter
                .debug_tuple("CleanAuditPending")
                .field(owner)
                .finish(),
            Self::ParentSyncPending(owner) => formatter
                .debug_tuple("ParentSyncPending")
                .field(owner)
                .finish(),
            Self::Terminal(owner) => formatter.debug_tuple("Terminal").field(owner).finish(),
        }
    }
}

#[cfg(target_os = "linux")]
fn unlink_publication_marker_impl<UnlinkDriver>(
    durable: PublicationDurableWithMarker,
    unlink_driver: UnlinkDriver,
) -> PublicationMarkerUnlinkOutcome
where
    UnlinkDriver: FnOnce(HeldPublicationMarkerV2, &Path) -> HeldPublicationMarkerV2UnlinkOutcome,
{
    let PublicationDurableWithMarker {
        root,
        audit,
        held_marker,
    } = durable;
    let reviewed_audit = match review_published_candidate(&root, &held_marker, &audit) {
        Ok(reviewed_audit) => reviewed_audit,
        Err(failure) => {
            return terminal_marker_unlink(
                root,
                audit,
                PublicationMarkerUnlinkFailure::PreUnlinkReview(failure),
                TerminalPublicationAuthority::Held(held_marker),
            );
        }
    };

    match unlink_driver(held_marker, &root) {
        HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(held_marker) => {
            match review_published_candidate(&root, &held_marker, &reviewed_audit) {
                Ok(post_audit) => {
                    PublicationMarkerUnlinkOutcome::NotRemoved(PublicationDurableWithMarker {
                        root,
                        audit: post_audit,
                        held_marker,
                    })
                }
                Err(failure) => terminal_marker_unlink(
                    root,
                    reviewed_audit,
                    PublicationMarkerUnlinkFailure::NotRemovedReview(failure),
                    TerminalPublicationAuthority::Held(held_marker),
                ),
            }
        }
        HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced(authority) => {
            PublicationMarkerUnlinkOutcome::CleanAuditPending(CleanAuditPending {
                root,
                audit: reviewed_audit,
                authority,
            })
        }
        HeldPublicationMarkerV2UnlinkOutcome::RemovedButParentSyncIndeterminate(authority) => {
            PublicationMarkerUnlinkOutcome::ParentSyncPending(ParentSyncPending {
                root,
                audit: reviewed_audit,
                authority,
            })
        }
        HeldPublicationMarkerV2UnlinkOutcome::ReplacementRetained(authority) => {
            terminal_marker_unlink(
                root,
                reviewed_audit,
                PublicationMarkerUnlinkFailure::ReplacementRetained,
                TerminalPublicationAuthority::Core(authority),
            )
        }
        HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate(authority) => {
            terminal_marker_unlink(
                root,
                reviewed_audit,
                PublicationMarkerUnlinkFailure::PostStateIndeterminate,
                TerminalPublicationAuthority::Core(authority),
            )
        }
    }
}

#[cfg(target_os = "linux")]
fn map_parent_sync_outcome(
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    outcome: PostUnlinkMarkerParentSyncOutcome,
) -> PublicationParentSyncOutcome {
    match outcome {
        PostUnlinkMarkerParentSyncOutcome::Synced(authority) => {
            PublicationParentSyncOutcome::CleanAuditPending(CleanAuditPending {
                root,
                audit,
                authority,
            })
        }
        PostUnlinkMarkerParentSyncOutcome::StillIndeterminate(authority) => {
            PublicationParentSyncOutcome::ParentSyncPending(ParentSyncPending {
                root,
                audit,
                authority,
            })
        }
        PostUnlinkMarkerParentSyncOutcome::ReplacementRetained(authority) => {
            PublicationParentSyncOutcome::Terminal(Box::new(FailedPublicationMarkerUnlink {
                failure: PublicationMarkerUnlinkFailure::ParentSyncReplacementRetained,
                root,
                audit,
                authority: TerminalPublicationAuthority::Core(authority),
            }))
        }
        PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate(authority) => {
            PublicationParentSyncOutcome::Terminal(Box::new(FailedPublicationMarkerUnlink {
                failure: PublicationMarkerUnlinkFailure::ParentSyncPostStateIndeterminate,
                root,
                audit,
                authority: TerminalPublicationAuthority::Core(authority),
            }))
        }
    }
}

#[cfg(target_os = "linux")]
fn terminal_marker_unlink(
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    failure: PublicationMarkerUnlinkFailure,
    authority: TerminalPublicationAuthority,
) -> PublicationMarkerUnlinkOutcome {
    PublicationMarkerUnlinkOutcome::Terminal(Box::new(FailedPublicationMarkerUnlink {
        failure,
        root,
        audit,
        authority,
    }))
}

/// The only owner allowed to retry an unconfirmed durability attempt.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct RetryablePublicationDurability {
    sync_failure: PublicationMarkerFailureKind,
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl RetryablePublicationDurability {
    pub(super) const fn failure(&self) -> PublicationMarkerFailureKind {
        self.sync_failure
    }

    pub(super) fn retry(self) -> PublicationDurabilityOutcome {
        PublishedWithMarker {
            root: self.root,
            audit: self.audit,
            held_marker: self.held_marker,
        }
        .synchronize()
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for RetryablePublicationDurability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetryablePublicationDurability")
            .field("sync_failure", &self.sync_failure)
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Terminal owner when the unified review fails after a durability attempt.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct FailedPublicationDurability {
    sync_failure: Option<PublicationMarkerFailureKind>,
    review_failure: PublishedCandidateReviewFailure,
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl FailedPublicationDurability {
    pub(super) const fn sync_failure(&self) -> Option<PublicationMarkerFailureKind> {
        self.sync_failure
    }

    pub(super) const fn review_failure(&self) -> &PublishedCandidateReviewFailure {
        &self.review_failure
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for FailedPublicationDurability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedPublicationDurability")
            .field("sync_failure", &self.sync_failure)
            .field("review_failure", &self.review_failure)
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Consuming result of one held-root and held-common-parent durability attempt.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) enum PublicationDurabilityOutcome {
    Durable(PublicationDurableWithMarker),
    Retryable(RetryablePublicationDurability),
    Terminal(Box<FailedPublicationDurability>),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PublicationDurabilityOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Durable(owner) => formatter.debug_tuple("Durable").field(owner).finish(),
            Self::Retryable(owner) => formatter.debug_tuple("Retryable").field(owner).finish(),
            Self::Terminal(owner) => formatter.debug_tuple("Terminal").field(owner).finish(),
        }
    }
}

#[cfg(target_os = "linux")]
fn synchronize_published_candidate_impl<SyncDriver>(
    published: PublishedWithMarker,
    sync_driver: SyncDriver,
) -> PublicationDurabilityOutcome
where
    SyncDriver: FnOnce(&Path, &HeldPublicationMarkerV2) -> Result<(), HeldPublicationMarkerV2Error>,
{
    let PublishedWithMarker {
        root,
        audit,
        held_marker,
    } = published;
    let sync_failure = sync_driver(&root, &held_marker)
        .err()
        .map(PublicationMarkerFailureKind::from);

    match review_published_candidate(&root, &held_marker, &audit) {
        Err(review_failure) => {
            PublicationDurabilityOutcome::Terminal(Box::new(FailedPublicationDurability {
                sync_failure,
                review_failure,
                root,
                audit,
                held_marker,
            }))
        }
        Ok(reviewed_audit) => match sync_failure {
            Some(sync_failure) => {
                PublicationDurabilityOutcome::Retryable(RetryablePublicationDurability {
                    sync_failure,
                    root,
                    audit: reviewed_audit,
                    held_marker,
                })
            }
            None => PublicationDurabilityOutcome::Durable(PublicationDurableWithMarker {
                root,
                audit: reviewed_audit,
                held_marker,
            }),
        },
    }
}

#[cfg(target_os = "linux")]
fn review_published_candidate(
    root: &Path,
    held_marker: &HeldPublicationMarkerV2,
    expected: &FreshMarkerCandidateAudit,
) -> Result<FreshMarkerCandidateAudit, PublishedCandidateReviewFailure> {
    held_marker
        .require_published_at(root)
        .map_err(PublicationMarkerFailureKind::from)
        .map_err(PublishedCandidateReviewFailure::PublishedRole)?;
    let audit = audit_fresh_marker_candidate(root, held_marker)
        .map_err(PublishedCandidateReviewFailure::FreshAudit)?;
    compare_candidate_summaries(&audit, expected)
        .map_err(PublishedCandidateReviewFailure::SummaryMismatch)?;
    held_marker
        .require_published_at(root)
        .map_err(PublicationMarkerFailureKind::from)
        .map_err(PublishedCandidateReviewFailure::PublishedRole)?;
    Ok(audit)
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
pub(crate) mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::path::PathBuf;

    use inex_core::atomic::{
        ExistingVaultMutationLock, ExistingVaultMutationLockError, FilesystemFileIdentity,
        IMPORT_PUBLISH_MARKER_V2, PublicationIdentityScheme, VAULT_LOCAL_DIRECTORY,
        filesystem_directory_identity, filesystem_file_identity,
    };
    use inex_core::crypto::VaultContentProfile;
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault::Vault;
    use inex_core::vault_config::KdfPolicy;

    use super::super::candidate_initial_authority::{
        InitialCandidateClaimInput, InitialCandidatePublishOutcome, StagingAuditedClaim,
        acquire_initial_candidate_authority, claim_initial_candidate, publish_initial_candidate,
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

    pub(crate) struct PublishedFixture {
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
        marker_bytes: Vec<u8>,
        marker_identity: FilesystemFileIdentity,
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

        fn assert_marker_unchanged(&self) {
            let marker_path = self.marker_path();
            assert_eq!(
                fs::read(&marker_path).expect("held marker bytes read"),
                self.marker_bytes
            );
            let marker_file = fs::File::open(&marker_path).expect("held marker opens");
            assert_eq!(
                filesystem_file_identity(&marker_file).expect("held marker identity captures"),
                self.marker_identity
            );
        }

        pub(crate) fn assert_lock_busy(&self) {
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

        pub(crate) fn assert_lock_available(&self) {
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

    impl PublishedFixture {
        pub(crate) fn coordinates(&self) -> (&Path, &FilesystemDirectoryIdentity, &str) {
            (
                &self.destination_root,
                &self.common_parent_identity,
                &self.destination_child_name,
            )
        }

        pub(crate) const fn expected_counts(&self) -> (u32, u32, u32, u32) {
            self.expected.counts
        }

        pub(crate) const fn expected_root_commit_oid(&self) -> [u8; 20] {
            self.expected.root_commit_oid
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

    fn claimed_fixture(label: &str) -> (PublishedFixture, StagingAuditedClaim) {
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
        let marker_path = staging_root
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);
        let marker_bytes = fs::read(&marker_path).expect("canonical marker bytes capture");
        let marker_file = fs::File::open(&marker_path).expect("canonical marker opens");
        let marker_identity =
            filesystem_file_identity(&marker_file).expect("canonical marker identity captures");
        drop(marker_file);
        drop(target);
        drop(vault);

        (
            PublishedFixture {
                parent,
                destination_root,
                destination_child_name,
                common_parent_identity,
                baseline,
                staging_child_name,
                expected,
                marker_bytes,
                marker_identity,
            },
            claim,
        )
    }

    pub(crate) fn fixture(label: &str) -> PublishedFixture {
        let (fixture, claim) = claimed_fixture(label);
        fs::rename(claim.root(), &fixture.destination_root)
            .expect("fixture performs whole-root publication rename");
        claim
            .held_marker()
            .require_published_at(&fixture.destination_root)
            .expect("fixture claim validates in destination role");
        drop(claim);
        fixture
    }

    fn fresh_published(fixture: &PublishedFixture) -> PublishedWithMarker {
        claim_fresh_existing_candidate(fixture.input())
            .expect("fresh existing claim constructs published owner")
    }

    fn fresh_durable(fixture: &PublishedFixture) -> PublicationDurableWithMarker {
        match fresh_published(fixture).synchronize() {
            PublicationDurabilityOutcome::Durable(owner) => owner,
            other => panic!("expected fixture durable owner, got {other:?}"),
        }
    }

    fn clean_pending(fixture: &PublishedFixture) -> CleanAuditPending {
        match fresh_durable(fixture).unlink_marker() {
            PublicationMarkerUnlinkOutcome::CleanAuditPending(owner) => owner,
            other => panic!("expected fixture clean-audit pending owner, got {other:?}"),
        }
    }

    fn synthetic_summary_mismatch(
        expected: &FreshMarkerCandidateAudit,
        mismatch: CandidateSummaryMismatch,
    ) -> FreshMarkerCandidateAudit {
        let mut context = expected.context();
        let mut seal = expected.content_seal();
        let mut oid = expected.root_commit_oid();
        let mut worktree = expected.worktree_files();
        let mut markdown = expected.encrypted_markdown();
        let mut assets = expected.encrypted_assets();
        let mut objects = expected.git_objects();
        match mismatch {
            CandidateSummaryMismatch::Context => context.publication_id[0] ^= 1,
            CandidateSummaryMismatch::ContentSeal => seal[0] ^= 1,
            CandidateSummaryMismatch::RootCommit => oid[0] ^= 1,
            CandidateSummaryMismatch::WorktreeCount => worktree = worktree.saturating_add(1),
            CandidateSummaryMismatch::MarkdownCount => markdown = markdown.saturating_add(1),
            CandidateSummaryMismatch::AssetCount => assets = assets.saturating_add(1),
            CandidateSummaryMismatch::GitObjectCount => objects = objects.saturating_add(1),
        }
        FreshMarkerCandidateAudit::test_only_synthetic(
            context, seal, oid, worktree, markdown, assets, objects,
        )
    }

    fn assert_expected_audit(audit: &FreshMarkerCandidateAudit, expected: &ExpectedAudit) {
        assert_eq!(audit.context(), expected.context);
        assert_eq!(audit.content_seal(), expected.content_seal);
        assert_eq!(audit.root_commit_oid(), expected.root_commit_oid);
        assert_eq!(
            (
                audit.worktree_files(),
                audit.encrypted_markdown(),
                audit.encrypted_assets(),
                audit.git_objects(),
            ),
            expected.counts
        );
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
    fn durability_real_fresh_and_initial_states_reach_only_durable_owner() {
        let fresh_fixture = fixture("durability-real-fresh");
        let durable = match fresh_published(&fresh_fixture).synchronize() {
            PublicationDurabilityOutcome::Durable(owner) => owner,
            other => panic!("expected fresh durable owner, got {other:?}"),
        };
        assert_eq!(durable.root(), fresh_fixture.destination_root);
        assert_expected_audit(durable.audit(), &fresh_fixture.expected);
        assert!(fresh_fixture.marker_path().is_file());
        fresh_fixture.assert_marker_unchanged();
        fresh_fixture.assert_lock_busy();
        let debug = format!("{durable:?}");
        assert!(!debug.contains(fresh_fixture.destination_root.to_string_lossy().as_ref()));
        drop(durable);
        fresh_fixture.assert_lock_available();

        let (initial_fixture, claim) = claimed_fixture("durability-real-initial");
        let published = match publish_initial_candidate(claim) {
            InitialCandidatePublishOutcome::Published(owner) => owner,
            other => panic!("expected initial published owner, got {other:?}"),
        };
        let durable = match published.synchronize() {
            PublicationDurabilityOutcome::Durable(owner) => owner,
            other => panic!("expected initial durable owner, got {other:?}"),
        };
        assert_eq!(durable.root(), initial_fixture.destination_root);
        assert_expected_audit(durable.audit(), &initial_fixture.expected);
        assert!(initial_fixture.marker_path().is_file());
        initial_fixture.assert_marker_unchanged();
        initial_fixture.assert_lock_busy();
        drop(durable);
        initial_fixture.assert_lock_available();
    }

    #[test]
    fn durability_sync_errors_before_and_after_effect_are_retryable_and_scrubbed() {
        for normalized in [
            PublicationMarkerFailureKind::InvalidInput,
            PublicationMarkerFailureKind::NamespaceConflict,
            PublicationMarkerFailureKind::AuthorityChanged,
            PublicationMarkerFailureKind::Io(io::ErrorKind::PermissionDenied),
        ] {
            assert!(std::error::Error::source(&normalized).is_none());
        }

        let before_fixture = fixture("durability-retry-before");
        let retry =
            match synchronize_published_candidate_impl(fresh_published(&before_fixture), |_, _| {
                Err(HeldPublicationMarkerV2Error::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret before-sync source",
                )))
            }) {
                PublicationDurabilityOutcome::Retryable(owner) => owner,
                other => panic!("expected before-effect retry owner, got {other:?}"),
            };
        assert_eq!(
            retry.failure(),
            PublicationMarkerFailureKind::Io(io::ErrorKind::PermissionDenied)
        );
        assert!(!format!("{retry:?}").contains("secret before-sync source"));
        assert!(before_fixture.marker_path().is_file());
        before_fixture.assert_marker_unchanged();
        before_fixture.assert_lock_busy();
        let normalized_failure = retry.failure();
        assert!(std::error::Error::source(&normalized_failure).is_none());
        let durable = match retry.retry() {
            PublicationDurabilityOutcome::Durable(owner) => owner,
            other => panic!("expected before-effect retry to become durable, got {other:?}"),
        };
        before_fixture.assert_lock_busy();
        drop(durable);
        before_fixture.assert_lock_available();

        let after_fixture = fixture("durability-retry-after");
        let retry = match synchronize_published_candidate_impl(
            fresh_published(&after_fixture),
            |root, held_marker| {
                held_marker
                    .synchronize_published_root_and_common_parent_at(root)
                    .expect("simulated effect completes");
                Err(HeldPublicationMarkerV2Error::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "secret after-sync source",
                )))
            },
        ) {
            PublicationDurabilityOutcome::Retryable(owner) => owner,
            other => panic!("expected after-effect retry owner, got {other:?}"),
        };
        assert_eq!(
            retry.failure(),
            PublicationMarkerFailureKind::Io(io::ErrorKind::Interrupted)
        );
        assert!(!format!("{retry:?}").contains("secret after-sync source"));
        assert!(after_fixture.marker_path().is_file());
        after_fixture.assert_marker_unchanged();
        after_fixture.assert_lock_busy();
        let durable = match retry.retry() {
            PublicationDurabilityOutcome::Durable(owner) => owner,
            other => panic!("expected after-effect retry to become durable, got {other:?}"),
        };
        drop(durable);
        after_fixture.assert_lock_available();
    }

    #[test]
    fn durability_ok_or_error_with_staging_drift_is_terminal() {
        for (label, sync_fails) in [
            ("durability-staging-ok", false),
            ("durability-staging-error", true),
        ] {
            let fixture = fixture(label);
            let staging = fixture.parent.join(&fixture.staging_child_name);
            let terminal =
                match synchronize_published_candidate_impl(fresh_published(&fixture), |_, _| {
                    fs::create_dir(&staging).expect("foreign staging name reappears");
                    if sync_fails {
                        Err(HeldPublicationMarkerV2Error::Io(io::Error::other(
                            "secret staging sync source",
                        )))
                    } else {
                        Ok(())
                    }
                }) {
                    PublicationDurabilityOutcome::Terminal(owner) => owner,
                    other => panic!("expected staging-drift terminal owner, got {other:?}"),
                };
            assert!(matches!(
                terminal.review_failure(),
                PublishedCandidateReviewFailure::PublishedRole(
                    PublicationMarkerFailureKind::NamespaceConflict
                        | PublicationMarkerFailureKind::AuthorityChanged
                        | PublicationMarkerFailureKind::Io(_)
                )
            ));
            assert_eq!(terminal.sync_failure().is_some(), sync_fails);
            assert!(!format!("{terminal:?}").contains("secret staging sync source"));
            assert!(fixture.marker_path().is_file());
            fixture.assert_marker_unchanged();
            fixture.assert_lock_busy();
            fs::remove_dir(&staging).expect("foreign staging canary removes");
            drop(terminal);
            fixture.assert_lock_available();
        }
    }

    #[test]
    fn durability_ok_or_error_with_content_drift_is_terminal() {
        for (label, sync_fails) in [
            ("durability-content-ok", false),
            ("durability-content-error", true),
        ] {
            let fixture = fixture(label);
            let terminal =
                match synchronize_published_candidate_impl(fresh_published(&fixture), |root, _| {
                    fs::write(root.join(".gitattributes"), b"post-sync content drift\n")
                        .expect("published candidate content drifts");
                    if sync_fails {
                        Err(HeldPublicationMarkerV2Error::Io(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "secret content sync source",
                        )))
                    } else {
                        Ok(())
                    }
                }) {
                    PublicationDurabilityOutcome::Terminal(owner) => owner,
                    other => panic!("expected content-drift terminal owner, got {other:?}"),
                };
            assert!(matches!(
                terminal.review_failure(),
                PublishedCandidateReviewFailure::FreshAudit(_)
            ));
            assert_eq!(terminal.sync_failure().is_some(), sync_fails);
            assert!(!format!("{terminal:?}").contains("secret content sync source"));
            assert!(fixture.marker_path().is_file());
            fixture.assert_marker_unchanged();
            fixture.assert_lock_busy();
            drop(terminal);
            fixture.assert_lock_available();
        }
    }

    #[test]
    fn durability_api_surface_and_review_order_are_frozen() {
        let source = include_str!("candidate_publication_authority.rs");
        let production = source
            .split("pub(super) fn synchronize(self)")
            .nth(1)
            .and_then(|tail| tail.split("impl fmt::Debug for PublishedWithMarker").next())
            .expect("production synchronize entry point exists");
        assert!(production.contains("synchronize_published_root_and_common_parent_at(root)"));
        assert!(!production.contains("sync_directory"));
        assert!(!production.contains("remove"));
        assert!(!production.contains("unlink"));

        let transition = source
            .split("fn synchronize_published_candidate_impl")
            .nth(1)
            .and_then(|tail| tail.split("fn review_published_candidate").next())
            .expect("durability transition exists");
        let sync = transition.find("sync_driver").expect("sync driver runs");
        let normalize = transition
            .find(".map(PublicationMarkerFailureKind::from)")
            .expect("sync error normalizes");
        let review = transition
            .find("review_published_candidate")
            .expect("unified review runs");
        assert!(sync < normalize && normalize < review);
        for forbidden in ["remove_file", "unlink", "into_parts", "drop(held_marker)"] {
            assert!(
                !transition.contains(forbidden),
                "forbidden transition API: {forbidden}"
            );
        }

        let review = source
            .split("fn review_published_candidate")
            .nth(1)
            .and_then(|tail| tail.split("/// Open and fully audit").next())
            .expect("unified review exists");
        let first_role = review
            .find("require_published_at")
            .expect("first role check exists");
        let audit = review
            .find("audit_fresh_marker_candidate")
            .expect("fresh audit exists");
        let compare = review
            .find("compare_candidate_summaries")
            .expect("shared comparison exists");
        let second_role = review
            .rfind("require_published_at")
            .expect("second role check exists");
        assert!(first_role < audit && audit < compare && compare < second_role);
        assert_ne!(first_role, second_role);

        for owner_name in [
            "PublicationDurableWithMarker",
            "RetryablePublicationDurability",
            "FailedPublicationDurability",
        ] {
            let owner = source
                .split(&format!("pub(super) struct {owner_name}"))
                .nth(1)
                .and_then(|tail| tail.split(&format!("impl {owner_name}")).next())
                .expect("durability owner source exists");
            assert!(!owner.contains("derive(Clone"));
            assert!(!owner.contains("derive(Copy"));
            assert!(
                owner.find("audit:").expect("audit field")
                    < owner.find("held_marker:").expect("marker field")
            );
            assert!(!source.contains(&format!("impl Drop for {owner_name}")));
        }
        let durable_impl = source
            .split("impl PublicationDurableWithMarker")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for PublicationDurableWithMarker")
                    .next()
            })
            .expect("durable implementation exists");
        assert!(!durable_impl.contains("held_marker("));
        assert!(!durable_impl.contains("into_parts"));
        assert_eq!(
            durable_impl
                .matches("unlink_exact_published_marker_at")
                .count(),
            1
        );
        let terminal_impl = source
            .split("impl FailedPublicationDurability")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for FailedPublicationDurability")
                    .next()
            })
            .expect("terminal implementation exists");
        assert!(!terminal_impl.contains("retry"));
        assert!(!terminal_impl.contains("cleanup"));
        assert!(!terminal_impl.contains("unlink"));
    }

    #[test]
    fn marker_unlink_real_durable_reaches_only_clean_audit_pending() {
        let fixture = fixture("unlink-real-clean-pending");
        let pending = match fresh_durable(&fixture).unlink_marker() {
            PublicationMarkerUnlinkOutcome::CleanAuditPending(owner) => owner,
            other => panic!("expected clean-audit-pending owner, got {other:?}"),
        };
        assert_eq!(pending.root(), fixture.destination_root);
        assert_expected_audit(pending.audit(), &fixture.expected);
        assert!(!fixture.marker_path().exists());
        fixture.assert_lock_busy();
        let debug = format!("{pending:?}");
        assert!(!debug.contains(fixture.destination_root.to_string_lossy().as_ref()));
        assert!(!debug.to_ascii_lowercase().contains("success"));
        drop(pending);
        fixture.assert_lock_available();
    }

    #[test]
    fn marker_unlink_pre_review_drift_never_calls_driver() {
        let fixture = fixture("unlink-pre-review-drift");
        let durable = fresh_durable(&fixture);
        fs::write(
            fixture.destination_root.join(".gitattributes"),
            b"pre-unlink drift\n",
        )
        .expect("published content drifts before unlink");
        let driver_called = Cell::new(false);
        let terminal = match unlink_publication_marker_impl(durable, |held_marker, _| {
            driver_called.set(true);
            HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(held_marker)
        }) {
            PublicationMarkerUnlinkOutcome::Terminal(owner) => owner,
            other => panic!("expected pre-review terminal owner, got {other:?}"),
        };
        assert!(!driver_called.get());
        assert!(matches!(
            terminal.failure(),
            PublicationMarkerUnlinkFailure::PreUnlinkReview(
                PublishedCandidateReviewFailure::FreshAudit(_)
            )
        ));
        fixture.assert_marker_unchanged();
        fixture.assert_lock_busy();
        drop(terminal);
        fixture.assert_lock_available();
    }

    #[test]
    fn marker_unlink_not_removed_returns_durable_then_real_unlink() {
        let fixture = fixture("unlink-not-removed-retry");
        let durable =
            match unlink_publication_marker_impl(fresh_durable(&fixture), |held_marker, _| {
                HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(held_marker)
            }) {
                PublicationMarkerUnlinkOutcome::NotRemoved(owner) => owner,
                other => panic!("expected durable not-removed owner, got {other:?}"),
            };
        fixture.assert_marker_unchanged();
        fixture.assert_lock_busy();

        let pending = match durable.unlink_marker() {
            PublicationMarkerUnlinkOutcome::CleanAuditPending(owner) => owner,
            other => panic!("expected real retry to reach clean audit pending, got {other:?}"),
        };
        assert!(!fixture.marker_path().exists());
        fixture.assert_lock_busy();
        drop(pending);
        fixture.assert_lock_available();
    }

    #[test]
    fn marker_unlink_not_removed_post_review_drift_is_terminal() {
        let fixture = fixture("unlink-not-removed-drift");
        let terminal =
            match unlink_publication_marker_impl(fresh_durable(&fixture), |held_marker, root| {
                fs::write(root.join(".gitattributes"), b"not-removed drift\n")
                    .expect("published content drifts after synthetic not-removed");
                HeldPublicationMarkerV2UnlinkOutcome::NotRemoved(held_marker)
            }) {
                PublicationMarkerUnlinkOutcome::Terminal(owner) => owner,
                other => panic!("expected not-removed review terminal owner, got {other:?}"),
            };
        assert!(matches!(
            terminal.failure(),
            PublicationMarkerUnlinkFailure::NotRemovedReview(
                PublishedCandidateReviewFailure::FreshAudit(_)
            )
        ));
        fixture.assert_marker_unchanged();
        fixture.assert_lock_busy();
        drop(terminal);
        fixture.assert_lock_available();
    }

    #[test]
    fn clean_audit_real_marker_free_candidate_reaches_published_clean() {
        let fixture = fixture("clean-audit-real");
        let published = match clean_pending(&fixture).audit_clean() {
            CleanAuditOutcome::PublishedClean(owner) => owner,
            other => panic!("expected published-clean owner, got {other:?}"),
        };
        assert_eq!(published.root(), fixture.destination_root);
        assert_expected_audit(published.audit(), &fixture.expected);
        assert!(!fixture.marker_path().exists());
        fixture.assert_lock_busy();
        let debug = format!("{published:?}");
        assert!(!debug.contains(fixture.destination_root.to_string_lossy().as_ref()));
        drop(published);
        fixture.assert_lock_available();
    }

    #[test]
    fn clean_audit_error_with_exact_absence_is_retryable_then_clean() {
        let fixture = fixture("clean-audit-retry");
        let retry = match audit_clean_candidate_impl(clean_pending(&fixture), |_, _| {
            Err(RepositoryImportError::TargetAuditFailed)
        }) {
            CleanAuditOutcome::Retryable(owner) => owner,
            other => panic!("expected retryable clean audit, got {other:?}"),
        };
        assert!(!fixture.marker_path().exists());
        fixture.assert_lock_busy();
        let published = match retry.audit_clean() {
            CleanAuditOutcome::PublishedClean(owner) => owner,
            other => panic!("expected clean retry to publish, got {other:?}"),
        };
        assert_expected_audit(published.audit(), &fixture.expected);
        assert!(!fixture.marker_path().exists());
        fixture.assert_lock_busy();
        drop(published);
        fixture.assert_lock_available();
    }

    #[test]
    fn clean_audit_error_with_replacement_is_terminal_and_preserves_replacement() {
        use super::super::candidate_manifest::collect_synced_post_unlink_physical_manifest;

        let fixture = fixture("clean-audit-replacement");
        let pending = clean_pending(&fixture);
        let replacement = b"foreign post-unlink marker replacement";
        fs::write(fixture.marker_path(), replacement).expect("replacement marker creates");
        assert!(
            collect_synced_post_unlink_physical_manifest(
                &fixture.destination_root,
                &pending.authority,
            )
            .is_err()
        );
        let terminal = match audit_clean_candidate_impl(pending, |_, _| {
            Err(RepositoryImportError::TargetAuditFailed)
        }) {
            CleanAuditOutcome::Terminal(owner) => owner,
            other => panic!("expected replacement terminal owner, got {other:?}"),
        };
        assert!(matches!(
            terminal.failure(),
            CleanAuditTerminalFailure::AuditFailedAndAuthorityLost {
                authority: PostUnlinkPublicationMarkerV2Error::NamespaceConflict,
                ..
            }
        ));
        assert_eq!(
            fs::read(fixture.marker_path()).expect("replacement marker reads"),
            replacement
        );
        fixture.assert_lock_busy();
        drop(terminal);
        fixture.assert_lock_available();
    }

    #[test]
    fn clean_audit_all_summary_mismatches_are_terminal() {
        for (index, mismatch) in [
            CandidateSummaryMismatch::Context,
            CandidateSummaryMismatch::ContentSeal,
            CandidateSummaryMismatch::RootCommit,
            CandidateSummaryMismatch::WorktreeCount,
            CandidateSummaryMismatch::MarkdownCount,
            CandidateSummaryMismatch::AssetCount,
            CandidateSummaryMismatch::GitObjectCount,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = fixture(&format!("clean-audit-mismatch-{index}"));
            let pending = clean_pending(&fixture);
            let synthetic = synthetic_summary_mismatch(pending.audit(), mismatch);
            let terminal = match audit_clean_candidate_impl(pending, |_, _| Ok(synthetic)) {
                CleanAuditOutcome::Terminal(owner) => owner,
                other => panic!("expected summary-mismatch terminal owner, got {other:?}"),
            };
            assert!(matches!(
                terminal.failure(),
                CleanAuditTerminalFailure::SummaryMismatch(actual) if *actual == mismatch
            ));
            assert!(!fixture.marker_path().exists());
            fixture.assert_lock_busy();
            drop(terminal);
            fixture.assert_lock_available();
        }
    }

    #[test]
    fn post_unlink_physical_wrapper_rejects_root_rebind() {
        use super::super::candidate_manifest::collect_synced_post_unlink_physical_manifest;

        let fixture = fixture("clean-audit-root-rebind");
        let pending = clean_pending(&fixture);
        let displaced = fixture.parent.join("displaced-published-root");
        fs::rename(&fixture.destination_root, &displaced).expect("published root displaces");
        fs::create_dir(&fixture.destination_root).expect("foreign root replacement creates");
        assert!(
            collect_synced_post_unlink_physical_manifest(
                &fixture.destination_root,
                &pending.authority,
            )
            .is_err()
        );
        drop(pending);
    }

    #[test]
    fn clean_audit_and_post_unlink_collector_surfaces_are_frozen() {
        let publication = include_str!("candidate_publication_authority.rs");
        let clean_impl = publication
            .split("impl CleanAuditPending")
            .nth(1)
            .and_then(|tail| tail.split("impl fmt::Debug for CleanAuditPending").next())
            .expect("clean pending implementation exists");
        assert!(clean_impl.contains("pub(super) fn audit_clean(self)"));
        assert!(clean_impl.contains("audit_post_unlink_candidate"));
        for forbidden in [
            "unlink_exact_published_marker_at",
            "retry_marker_parent_sync_at",
            "sync_directory",
            "authority(",
            "into_parts",
        ] {
            assert!(
                !clean_impl.contains(forbidden),
                "clean audit escalation: {forbidden}"
            );
        }

        for owner_name in ["PublishedClean", "FailedCleanAudit"] {
            let owner = publication
                .split(&format!("pub(super) struct {owner_name}"))
                .nth(1)
                .and_then(|tail| tail.split(&format!("impl {owner_name}")).next())
                .expect("clean owner source exists");
            assert!(!owner.contains("derive(Clone"));
            assert!(!owner.contains("derive(Copy"));
            assert!(
                owner.find("audit:").expect("audit field")
                    < owner.find("authority:").expect("authority final field")
            );
            assert!(!publication.contains(&format!("impl Drop for {owner_name}")));
            assert!(!publication.contains(&format!("ManuallyDrop<{owner_name}")));
        }
        let published_impl = publication
            .split("impl PublishedClean")
            .nth(1)
            .and_then(|tail| tail.split("impl fmt::Debug for PublishedClean").next())
            .expect("published clean implementation exists");
        for forbidden in [
            "authority(",
            "into_parts",
            "marker",
            "unlink",
            "sync",
            "reconstruct",
        ] {
            assert!(
                !published_impl.contains(forbidden),
                "published clean escalation: {forbidden}"
            );
        }

        let manifest = include_str!("candidate_manifest.rs");
        let collector = manifest
            .split("pub(super) fn collect_synced_post_unlink_physical_manifest")
            .nth(1)
            .and_then(|tail| tail.split("fn require_post_unlink_physical_binding").next())
            .expect("post-unlink collector exists");
        assert!(collector.contains("held_root_view_at"));
        assert!(collector.contains("PhysicalMarkerPolicy::Forbidden"));
        assert!(collector.matches("revalidate_absent_at").count() >= 3);
        assert!(collector.contains("require_current_exact_from_held"));
        assert!(!collector.contains("collect_marker_free_physical_manifest"));
        assert!(!collector.contains("open_secure_source_root"));

        let wrapper = manifest
            .split("pub(super) struct SyncedPostUnlinkPhysicalManifest")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for SyncedPostUnlinkPhysicalManifest")
                    .next()
            })
            .expect("post-unlink wrapper exists");
        assert!(
            wrapper.find("held_root:").expect("held root field")
                < wrapper
                    .find("authority:")
                    .expect("borrowed authority final")
        );
        assert!(!wrapper.contains("derive(Clone"));
        assert!(!wrapper.contains("derive(Copy"));
        assert!(!manifest.contains("impl Drop for SyncedPostUnlinkPhysicalManifest"));
        assert!(!manifest.contains("ManuallyDrop<SyncedPostUnlinkPhysicalManifest"));
    }

    #[test]
    fn clean_audit_transition_and_fresh_source_contract_are_frozen() {
        let publication = include_str!("candidate_publication_authority.rs");
        let clean_transition = publication
            .split("fn audit_clean_candidate_impl")
            .nth(1)
            .and_then(|tail| tail.split("fn terminal_clean_audit").next())
            .expect("clean audit transition exists");
        let audit_driver = clean_transition
            .find("audit_driver(&root, &authority)")
            .expect("private audit driver is used");
        let error_revalidate = clean_transition
            .find("authority.revalidate_absent_at(&root)")
            .expect("audit error immediately revalidates absence");
        let compare = clean_transition
            .find("compare_candidate_summaries")
            .expect("shared summary comparison is used");
        let final_revalidate = clean_transition
            .rfind("authority.revalidate_absent_at(&root)")
            .expect("successful audit has final absent revalidation");
        assert!(audit_driver < error_revalidate && error_revalidate < compare);
        assert!(compare < final_revalidate);
        assert!(clean_transition.contains("PostUnlinkPublicationMarkerV2Error::Indeterminate"));
        for forbidden in [
            "unlink_exact_published_marker_at",
            "retry_marker_parent_sync_at",
            "sync_directory",
            "open_existing_publication_marker_v2",
            "drop(authority)",
        ] {
            assert!(!clean_transition.contains(forbidden));
        }

        let fresh = include_str!("candidate_fresh_audit.rs");
        let post_unlink_audit = fresh
            .split("fn audit_post_unlink_candidate_impl")
            .nth(1)
            .and_then(|tail| tail.split("fn assemble_candidate_summary").next())
            .expect("post-unlink fresh audit exists");
        assert!(post_unlink_audit.contains("collect_synced_post_unlink_physical_manifest"));
        assert!(post_unlink_audit.contains("marker_free.require_current_exact"));
        assert!(post_unlink_audit.contains("marker.candidate_seal_matches"));
        assert!(post_unlink_audit.matches("revalidate_absent_at").count() >= 2);
        assert!(!post_unlink_audit.contains("collect_marker_free_physical_manifest"));
        assert!(!post_unlink_audit.contains("collect_held_marker_physical_manifest"));
        assert!(!post_unlink_audit.contains("open_secure_source_root"));
    }

    #[test]
    fn marker_unlink_and_parent_sync_api_surfaces_are_frozen() {
        let source = include_str!("candidate_publication_authority.rs");
        let durable_impl = source
            .split("impl PublicationDurableWithMarker")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for PublicationDurableWithMarker")
                    .next()
            })
            .expect("durable implementation exists");
        assert_eq!(
            durable_impl
                .matches("unlink_exact_published_marker_at")
                .count(),
            1
        );

        let transition = source
            .split("fn unlink_publication_marker_impl")
            .nth(1)
            .and_then(|tail| tail.split("fn map_parent_sync_outcome").next())
            .expect("unlink transition exists");
        let pre_review = transition
            .find("review_published_candidate")
            .expect("pre-unlink review exists");
        let driver = transition
            .find("unlink_driver(held_marker")
            .expect("unlink driver exists");
        assert!(pre_review < driver);
        for variant in [
            "HeldPublicationMarkerV2UnlinkOutcome::NotRemoved",
            "HeldPublicationMarkerV2UnlinkOutcome::RemovedAndParentSynced",
            "HeldPublicationMarkerV2UnlinkOutcome::RemovedButParentSyncIndeterminate",
            "HeldPublicationMarkerV2UnlinkOutcome::ReplacementRetained",
            "HeldPublicationMarkerV2UnlinkOutcome::PostStateIndeterminate",
        ] {
            assert!(
                transition.contains(variant),
                "missing unlink mapping: {variant}"
            );
        }
        assert!(!transition.contains("unlink_exact_published_marker_at"));
        assert!(!transition.contains("clean_audit"));

        let parent_mapping = source
            .split("fn map_parent_sync_outcome")
            .nth(1)
            .and_then(|tail| tail.split("fn terminal_marker_unlink").next())
            .expect("parent-sync mapping exists");
        for variant in [
            "PostUnlinkMarkerParentSyncOutcome::Synced",
            "PostUnlinkMarkerParentSyncOutcome::StillIndeterminate",
            "PostUnlinkMarkerParentSyncOutcome::ReplacementRetained",
            "PostUnlinkMarkerParentSyncOutcome::PostStateIndeterminate",
        ] {
            assert!(
                parent_mapping.contains(variant),
                "missing parent-sync mapping: {variant}"
            );
        }
    }

    #[test]
    fn marker_unlink_pending_owner_surfaces_are_frozen() {
        let source = include_str!("candidate_publication_authority.rs");
        for owner_name in [
            "CleanAuditPending",
            "ParentSyncPending",
            "FailedPublicationMarkerUnlink",
        ] {
            let owner = source
                .split(&format!("pub(super) struct {owner_name}"))
                .nth(1)
                .and_then(|tail| tail.split(&format!("impl {owner_name}")).next())
                .expect("post-unlink owner source exists");
            assert!(!owner.contains("derive(Clone"));
            assert!(!owner.contains("derive(Copy"));
            assert!(
                owner.find("audit:").expect("audit field")
                    < owner
                        .find("authority:")
                        .expect("authority is the final field")
            );
            assert!(!source.contains(&format!("impl Drop for {owner_name}")));
        }
        let clean_impl = source
            .split("impl CleanAuditPending")
            .nth(1)
            .and_then(|tail| tail.split("impl fmt::Debug for CleanAuditPending").next())
            .expect("clean pending implementation exists");
        for forbidden in [
            "success",
            "clean_claim",
            "pub(super) fn unlink_marker",
            "unlink_exact_published_marker_at",
            "retry_parent_sync",
            "authority(",
        ] {
            assert!(
                !clean_impl.contains(forbidden),
                "clean pending escalation: {forbidden}"
            );
        }
        let parent_impl = source
            .split("impl ParentSyncPending")
            .nth(1)
            .and_then(|tail| tail.split("impl fmt::Debug for ParentSyncPending").next())
            .expect("parent pending implementation exists");
        assert!(parent_impl.contains("pub(super) fn retry_parent_sync(self)"));
        for forbidden in ["unlink_marker", "clean", "authority(", "into_parts"] {
            assert!(
                !parent_impl.contains(forbidden),
                "parent pending escalation: {forbidden}"
            );
        }
        let terminal_impl = source
            .split("impl FailedPublicationMarkerUnlink")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for FailedPublicationMarkerUnlink")
                    .next()
            })
            .expect("unlink terminal implementation exists");
        for forbidden in ["retry", "cleanup", "unlink", "authority(", "into_parts"] {
            assert!(
                !terminal_impl.contains(forbidden),
                "terminal escalation: {forbidden}"
            );
        }
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
