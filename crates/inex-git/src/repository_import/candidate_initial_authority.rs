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
#[cfg(target_os = "linux")]
use std::io;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use inex_core::atomic::ExistingVaultMutationLockError;
#[cfg(target_os = "linux")]
use inex_core::atomic::{
    AtomicDirectoryPublishError, AtomicDirectoryPublishOutcome, FilesystemDirectoryIdentity,
    HeldPublicationMarkerV2, HeldPublicationMarkerV2CreateInput, HeldPublicationMarkerV2Error,
    atomic_move_verified_directory_no_replace_checked,
};
use inex_core::crypto::VaultContentProfile;
use inex_core::vault::Vault;
use thiserror::Error;

#[cfg(target_os = "linux")]
use super::candidate_fresh_audit::{
    CandidateSummaryMismatch, FreshMarkerCandidateAudit, audit_fresh_marker_candidate,
    compare_candidate_summaries,
};
#[cfg(target_os = "linux")]
use super::candidate_seal::DOMAIN;
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
    worktree_files: u32,
    encrypted_markdown: u32,
    encrypted_assets: u32,
    git_objects: u32,
    mutation_lock: inex_core::atomic::ExistingVaultMutationLock,
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub(super) struct InitialCandidateAuthority {
    _unsupported: (),
}

#[cfg(target_os = "linux")]
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
            .field("worktree_files", &self.worktree_files)
            .field("encrypted_markdown", &self.encrypted_markdown)
            .field("encrypted_assets", &self.encrypted_assets)
            .field("git_objects", &self.git_objects)
            .field("mutation_lock", &"[HELD]")
            .finish_non_exhaustive()
    }
}

#[cfg(not(target_os = "linux"))]
impl fmt::Debug for InitialCandidateAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitialCandidateAuthority { unsupported: true }")
    }
}

/// Caller-owned sibling publication coordinates for one initial claim.
///
/// The claim transition derives the staging name, domain, publication id,
/// identity scheme, and candidate seal from the held authority itself. The
/// caller supplies only the already-audited common-parent identity and exact
/// destination child selected by the outer transaction.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(super) struct InitialCandidateClaimInput<'a> {
    pub(super) common_parent_identity: &'a FilesystemDirectoryIdentity,
    pub(super) destination_child_name: &'a str,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for InitialCandidateClaimInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitialCandidateClaimInput")
            .field("common_parent_identity", &"[REDACTED]")
            .field("destination_child_name", &"[REDACTED]")
            .finish()
    }
}

/// Failure before a publication marker was created.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum InitialCandidateClaimPreflightError {
    #[error("initial repository candidate staging name is invalid")]
    InvalidStagingName,
    #[error("initial repository candidate destination uses the reserved staging prefix")]
    ReservedDestinationName,
    #[error("initial repository candidate changed before marker creation")]
    CandidateChanged,
}

/// Fixed post-marker failure category retained beside the live marker owner.
#[cfg(target_os = "linux")]
pub(super) enum InitialCandidatePostMarkerFailure {
    FreshAudit(RepositoryImportError),
    ContextMismatch,
    ContentSealMismatch,
    RootCommitMismatch,
    WorktreeCountMismatch,
    MarkdownCountMismatch,
    AssetCountMismatch,
    GitObjectCountMismatch,
    DestinationObservation(HeldPublicationMarkerV2Error),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for InitialCandidatePostMarkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FreshAudit(_) => "InitialCandidatePostMarkerFailure::FreshAudit(..)",
            Self::ContextMismatch => "InitialCandidatePostMarkerFailure::ContextMismatch",
            Self::ContentSealMismatch => "InitialCandidatePostMarkerFailure::ContentSealMismatch",
            Self::RootCommitMismatch => "InitialCandidatePostMarkerFailure::RootCommitMismatch",
            Self::WorktreeCountMismatch => {
                "InitialCandidatePostMarkerFailure::WorktreeCountMismatch"
            }
            Self::MarkdownCountMismatch => {
                "InitialCandidatePostMarkerFailure::MarkdownCountMismatch"
            }
            Self::AssetCountMismatch => "InitialCandidatePostMarkerFailure::AssetCountMismatch",
            Self::GitObjectCountMismatch => {
                "InitialCandidatePostMarkerFailure::GitObjectCountMismatch"
            }
            Self::DestinationObservation(_) => {
                "InitialCandidatePostMarkerFailure::DestinationObservation(..)"
            }
        })
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for InitialCandidatePostMarkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FreshAudit(_) => "fresh marker-aware candidate audit failed",
            Self::ContextMismatch => "candidate claim context changed",
            Self::ContentSealMismatch => "candidate content seal changed",
            Self::RootCommitMismatch => "candidate root commit changed",
            Self::WorktreeCountMismatch => "candidate worktree count changed",
            Self::MarkdownCountMismatch => "candidate Markdown count changed",
            Self::AssetCountMismatch => "candidate asset count changed",
            Self::GitObjectCountMismatch => "candidate Git object count changed",
            Self::DestinationObservation(_) => "candidate destination absence became indeterminate",
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for InitialCandidatePostMarkerFailure {}

/// Terminal owner for an initial claim that failed after marker creation.
///
/// No API exposes the marker for cleanup, reconstruction, or publication. The
/// exact held marker and its existing-only mutation lock remain alive until
/// this value is dropped; `held_marker` is deliberately the last field.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct FailedHeldInitialClaim {
    failure: InitialCandidatePostMarkerFailure,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl FailedHeldInitialClaim {
    pub(super) const fn failure(&self) -> &InitialCandidatePostMarkerFailure {
        &self.failure
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for FailedHeldInitialClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedHeldInitialClaim")
            .field("failure", &self.failure)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Failure while consuming initial authority into a staging claim.
#[cfg(target_os = "linux")]
pub(super) enum InitialCandidateClaimError {
    PreMarker(InitialCandidateClaimPreflightError),
    MarkerCreation(HeldPublicationMarkerV2Error),
    PostMarker(Box<FailedHeldInitialClaim>),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for InitialCandidateClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreMarker(error) => formatter.debug_tuple("PreMarker").field(error).finish(),
            Self::MarkerCreation(_) => formatter.write_str("MarkerCreation(..)"),
            Self::PostMarker(owner) => formatter.debug_tuple("PostMarker").field(owner).finish(),
        }
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for InitialCandidateClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PreMarker(_) => "initial candidate claim failed before marker creation",
            Self::MarkerCreation(_) => "initial candidate marker creation failed",
            Self::PostMarker(_) => "initial candidate claim failed after marker creation",
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for InitialCandidateClaimError {}

/// Complete marker-aware staging claim eligible for a later no-replace move.
///
/// This type is intentionally neither `Clone` nor `Copy`. The fixed-size fresh
/// audit is bound to the marker's exact context and seal, while the held marker
/// retains all directory handles and the same mutation lock. Absence was only
/// observed, never reserved; the publication transition must revalidate and
/// use a no-replace whole-root move.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct StagingAuditedClaim {
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl StagingAuditedClaim {
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
impl fmt::Debug for StagingAuditedClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagingAuditedClaim")
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Scrubbed terminal reason retained beside the exact publication authority.
///
/// In particular, the generic move's original `io::Error` is never retained:
/// only its stable [`io::ErrorKind`] crosses this safety boundary.
#[cfg(target_os = "linux")]
pub(super) enum InitialCandidatePublishFailure {
    InvalidDerivedDestination,
    CriticalAuditNotRunExactlyOnce,
    CriticalSourceMismatch,
    CriticalDestinationObservation(HeldPublicationMarkerV2Error),
    CriticalFreshAudit(RepositoryImportError),
    CriticalSummaryMismatch(CandidateSummaryMismatch),
    DestinationExists,
    IndeterminateMove,
    InvalidMovePaths,
    MoveIo(io::ErrorKind),
    PublishedCleanupFailed,
    RetryDestinationObservation(HeldPublicationMarkerV2Error),
    RetryFreshAudit(RepositoryImportError),
    RetrySummaryMismatch(CandidateSummaryMismatch),
    PublishedRole(HeldPublicationMarkerV2Error),
    PublishedFreshAudit(RepositoryImportError),
    PublishedSummaryMismatch(CandidateSummaryMismatch),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for InitialCandidatePublishFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDerivedDestination => {
                "InitialCandidatePublishFailure::InvalidDerivedDestination"
            }
            Self::CriticalAuditNotRunExactlyOnce => {
                "InitialCandidatePublishFailure::CriticalAuditNotRunExactlyOnce"
            }
            Self::CriticalSourceMismatch => {
                "InitialCandidatePublishFailure::CriticalSourceMismatch"
            }
            Self::CriticalDestinationObservation(_) => {
                "InitialCandidatePublishFailure::CriticalDestinationObservation(..)"
            }
            Self::CriticalFreshAudit(_) => "InitialCandidatePublishFailure::CriticalFreshAudit(..)",
            Self::CriticalSummaryMismatch(_) => {
                "InitialCandidatePublishFailure::CriticalSummaryMismatch(..)"
            }
            Self::DestinationExists => "InitialCandidatePublishFailure::DestinationExists",
            Self::IndeterminateMove => "InitialCandidatePublishFailure::IndeterminateMove",
            Self::InvalidMovePaths => "InitialCandidatePublishFailure::InvalidMovePaths",
            Self::MoveIo(_) => "InitialCandidatePublishFailure::MoveIo(..)",
            Self::PublishedCleanupFailed => {
                "InitialCandidatePublishFailure::PublishedCleanupFailed"
            }
            Self::RetryDestinationObservation(_) => {
                "InitialCandidatePublishFailure::RetryDestinationObservation(..)"
            }
            Self::RetryFreshAudit(_) => "InitialCandidatePublishFailure::RetryFreshAudit(..)",
            Self::RetrySummaryMismatch(_) => {
                "InitialCandidatePublishFailure::RetrySummaryMismatch(..)"
            }
            Self::PublishedRole(_) => "InitialCandidatePublishFailure::PublishedRole(..)",
            Self::PublishedFreshAudit(_) => {
                "InitialCandidatePublishFailure::PublishedFreshAudit(..)"
            }
            Self::PublishedSummaryMismatch(_) => {
                "InitialCandidatePublishFailure::PublishedSummaryMismatch(..)"
            }
        })
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for InitialCandidatePublishFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDerivedDestination => "initial publication destination is invalid",
            Self::CriticalAuditNotRunExactlyOnce => {
                "initial publication critical audit count is invalid"
            }
            Self::CriticalSourceMismatch => "initial publication source changed",
            Self::CriticalDestinationObservation(_) => {
                "initial publication destination observation failed"
            }
            Self::CriticalFreshAudit(_) => "initial publication critical audit failed",
            Self::CriticalSummaryMismatch(_) => "initial publication critical summary changed",
            Self::DestinationExists => "initial publication destination exists",
            Self::IndeterminateMove => "initial publication move is indeterminate",
            Self::InvalidMovePaths => "initial publication move paths are invalid",
            Self::MoveIo(_) => "initial publication move I/O failed",
            Self::PublishedCleanupFailed => "initial publication cleanup failed",
            Self::RetryDestinationObservation(_) => {
                "initial publication retry destination observation failed"
            }
            Self::RetryFreshAudit(_) => "initial publication retry audit failed",
            Self::RetrySummaryMismatch(_) => "initial publication retry summary changed",
            Self::PublishedRole(_) => "initial publication destination role is invalid",
            Self::PublishedFreshAudit(_) => "initial publication destination audit failed",
            Self::PublishedSummaryMismatch(_) => "initial publication destination summary changed",
        })
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for InitialCandidatePublishFailure {}

/// The only state allowed to retry a move proven not to have happened.
///
/// It exposes only a consuming retry. The exact marker and mutation lock are
/// continuously retained and are deliberately the final field.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct RetryableInitialPublication {
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl RetryableInitialPublication {
    pub(super) fn retry(self) -> InitialCandidatePublishOutcome {
        publish_initial_candidate(StagingAuditedClaim {
            root: self.root,
            audit: self.audit,
            held_marker: self.held_marker,
        })
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for RetryableInitialPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetryableInitialPublication")
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Terminal owner for every failed or indeterminate initial publication.
///
/// No method performs cleanup, extracts authority, or advances this state.
/// The same held marker and mutation lock remain live until drop.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct FailedHeldInitialPublication {
    failure: InitialCandidatePublishFailure,
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl FailedHeldInitialPublication {
    pub(super) const fn failure(&self) -> &InitialCandidatePublishFailure {
        &self.failure
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for FailedHeldInitialPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedHeldInitialPublication")
            .field("failure", &self.failure)
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Consuming result of one initial no-replace publication attempt.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) enum InitialCandidatePublishOutcome {
    Published(super::candidate_publication_authority::PublishedWithMarker),
    NotMoved(RetryableInitialPublication),
    Terminal(Box<FailedHeldInitialPublication>),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for InitialCandidatePublishOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Published(owner) => formatter.debug_tuple("Published").field(owner).finish(),
            Self::NotMoved(owner) => formatter.debug_tuple("NotMoved").field(owner).finish(),
            Self::Terminal(owner) => formatter.debug_tuple("Terminal").field(owner).finish(),
        }
    }
}

/// Unforgeable handoff produced only after the exact post-move checks.
///
/// The constructor is private to this module. The sibling publication module
/// can only consume a token that this transition has already constructed.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct VerifiedInitialMove {
    root: PathBuf,
    audit: FreshMarkerCandidateAudit,
    held_marker: HeldPublicationMarkerV2,
}

#[cfg(target_os = "linux")]
impl VerifiedInitialMove {
    fn after_complete_post_move_review(
        root: PathBuf,
        audit: FreshMarkerCandidateAudit,
        held_marker: HeldPublicationMarkerV2,
    ) -> Self {
        Self {
            root,
            audit,
            held_marker,
        }
    }

    pub(super) fn into_published_parts(
        self,
    ) -> (PathBuf, FreshMarkerCandidateAudit, HeldPublicationMarkerV2) {
        (self.root, self.audit, self.held_marker)
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for VerifiedInitialMove {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedInitialMove")
            .field("root", &"[REDACTED]")
            .field("audit", &self.audit)
            .field("held_marker", &"[HELD]")
            .finish()
    }
}

/// Consume a staging claim into a no-replace publication attempt.
///
/// The destination is not caller supplied: it is derived from the claim root's
/// parent and the destination child recorded in the continuously held marker.
/// A successful generic move is only a namespace fact; its parent-sync status
/// is intentionally discarded and does not confer durability.
#[cfg(target_os = "linux")]
pub(super) fn publish_initial_candidate(
    claim: StagingAuditedClaim,
) -> InitialCandidatePublishOutcome {
    publish_initial_candidate_impl(claim, |source, destination, critical_audit| {
        atomic_move_verified_directory_no_replace_checked(source, destination, |current| {
            critical_audit(current)
        })
    })
}

#[cfg(target_os = "linux")]
fn publish_initial_candidate_impl<MoveDriver>(
    claim: StagingAuditedClaim,
    move_driver: MoveDriver,
) -> InitialCandidatePublishOutcome
where
    MoveDriver: FnOnce(
        &Path,
        &Path,
        &mut dyn FnMut(&Path) -> io::Result<()>,
    ) -> Result<AtomicDirectoryPublishOutcome, AtomicDirectoryPublishError>,
{
    let destination = match claim.root.parent() {
        Some(parent) => parent.join(claim.held_marker.marker().destination_child_name()),
        None => {
            return terminal_initial_publication(
                claim,
                InitialCandidatePublishFailure::InvalidDerivedDestination,
            );
        }
    };

    let critical_failure = std::cell::RefCell::new(None);
    let critical_calls = std::cell::Cell::new(0_u8);
    let mut critical_audit = |current: &Path| -> io::Result<()> {
        let prior_calls = critical_calls.get();
        critical_calls.set(prior_calls.saturating_add(1));
        if prior_calls != 0 {
            *critical_failure.borrow_mut() =
                Some(InitialCandidatePublishFailure::CriticalAuditNotRunExactlyOnce);
            return Err(io::Error::other("initial publication audit rejected"));
        }
        let failure = critical_initial_publication_review(current, &claim);
        if let Err(failure) = failure {
            *critical_failure.borrow_mut() = Some(failure);
            return Err(io::Error::other("initial publication audit rejected"));
        }
        Ok(())
    };
    let move_result = move_driver(&claim.root, &destination, &mut critical_audit);

    let critical_call_count = critical_calls.get();
    if critical_call_count > 1 {
        return terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::CriticalAuditNotRunExactlyOnce,
        );
    }
    if let Some(failure) = critical_failure.into_inner() {
        return terminal_initial_publication(claim, failure);
    }
    // The generic primitive may reject paths or a pre-existing destination
    // while resolving its preflight, before it owns enough authority to invoke
    // the callback. Those terminal errors retain their precise scrubbed class.
    // A successful or retryable namespace result, however, is invalid unless
    // the critical audit ran exactly once.
    if critical_call_count == 0
        && matches!(
            &move_result,
            Ok(_) | Err(AtomicDirectoryPublishError::NotMoved)
        )
    {
        return terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::CriticalAuditNotRunExactlyOnce,
        );
    }

    match move_result {
        Ok(_) => reconcile_published_initial_candidate(claim, destination),
        Err(AtomicDirectoryPublishError::NotMoved) => reconcile_not_moved_initial_candidate(claim),
        Err(AtomicDirectoryPublishError::DestinationExists) => {
            terminal_initial_publication(claim, InitialCandidatePublishFailure::DestinationExists)
        }
        Err(AtomicDirectoryPublishError::Indeterminate) => {
            terminal_initial_publication(claim, InitialCandidatePublishFailure::IndeterminateMove)
        }
        Err(AtomicDirectoryPublishError::InvalidPaths) => {
            terminal_initial_publication(claim, InitialCandidatePublishFailure::InvalidMovePaths)
        }
        Err(AtomicDirectoryPublishError::Io { source }) => terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::MoveIo(source.kind()),
        ),
        Err(AtomicDirectoryPublishError::PublishedCleanupFailed) => terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::PublishedCleanupFailed,
        ),
    }
}

#[cfg(target_os = "linux")]
fn critical_initial_publication_review(
    current: &Path,
    claim: &StagingAuditedClaim,
) -> Result<(), InitialCandidatePublishFailure> {
    if current != claim.root {
        return Err(InitialCandidatePublishFailure::CriticalSourceMismatch);
    }
    claim
        .held_marker
        .require_destination_absent_at(current)
        .map_err(InitialCandidatePublishFailure::CriticalDestinationObservation)?;
    let audit = audit_fresh_marker_candidate(current, &claim.held_marker)
        .map_err(InitialCandidatePublishFailure::CriticalFreshAudit)?;
    compare_candidate_summaries(&audit, &claim.audit)
        .map_err(InitialCandidatePublishFailure::CriticalSummaryMismatch)?;
    claim
        .held_marker
        .require_destination_absent_at(current)
        .map_err(InitialCandidatePublishFailure::CriticalDestinationObservation)
}

#[cfg(target_os = "linux")]
fn reconcile_not_moved_initial_candidate(
    claim: StagingAuditedClaim,
) -> InitialCandidatePublishOutcome {
    if let Err(error) = claim.held_marker.require_destination_absent_at(&claim.root) {
        return terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::RetryDestinationObservation(error),
        );
    }
    let audit = match audit_fresh_marker_candidate(&claim.root, &claim.held_marker) {
        Ok(audit) => audit,
        Err(error) => {
            return terminal_initial_publication(
                claim,
                InitialCandidatePublishFailure::RetryFreshAudit(error),
            );
        }
    };
    if let Err(mismatch) = compare_candidate_summaries(&audit, &claim.audit) {
        return terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::RetrySummaryMismatch(mismatch),
        );
    }
    if let Err(error) = claim.held_marker.require_destination_absent_at(&claim.root) {
        return terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::RetryDestinationObservation(error),
        );
    }
    InitialCandidatePublishOutcome::NotMoved(RetryableInitialPublication {
        root: claim.root,
        audit,
        held_marker: claim.held_marker,
    })
}

#[cfg(target_os = "linux")]
fn reconcile_published_initial_candidate(
    mut claim: StagingAuditedClaim,
    destination: PathBuf,
) -> InitialCandidatePublishOutcome {
    // The generic success proves the exact held root now occupies destination.
    // Every later terminal owner must therefore record that actual root, not
    // the now-absent staging pathname.
    claim.root.clone_from(&destination);
    if let Err(error) = claim.held_marker.require_published_at(&destination) {
        return terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::PublishedRole(error),
        );
    }
    let audit = match audit_fresh_marker_candidate(&destination, &claim.held_marker) {
        Ok(audit) => audit,
        Err(error) => {
            return terminal_initial_publication(
                claim,
                InitialCandidatePublishFailure::PublishedFreshAudit(error),
            );
        }
    };
    if let Err(mismatch) = compare_candidate_summaries(&audit, &claim.audit) {
        return terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::PublishedSummaryMismatch(mismatch),
        );
    }
    if let Err(error) = claim.held_marker.require_published_at(&destination) {
        return terminal_initial_publication(
            claim,
            InitialCandidatePublishFailure::PublishedRole(error),
        );
    }

    let token =
        VerifiedInitialMove::after_complete_post_move_review(destination, audit, claim.held_marker);
    InitialCandidatePublishOutcome::Published(
        super::candidate_publication_authority::PublishedWithMarker::from_verified_initial_move(
            token,
        ),
    )
}

#[cfg(target_os = "linux")]
fn terminal_initial_publication(
    claim: StagingAuditedClaim,
    failure: InitialCandidatePublishFailure,
) -> InitialCandidatePublishOutcome {
    InitialCandidatePublishOutcome::Terminal(Box::new(FailedHeldInitialPublication {
        failure,
        root: claim.root,
        audit: claim.audit,
        held_marker: claim.held_marker,
    }))
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

/// Consume one marker-free initial authority into a complete staging claim.
///
/// The marker-free manifest is revalidated and then explicitly released before
/// the marker-aware fresh audit, bounding peak retained manifest memory. Once
/// the core returns a held marker, every later failure owns that exact marker
/// and the same mutation lock until the caller emits its terminal result.
#[cfg(target_os = "linux")]
pub(super) fn claim_initial_candidate(
    authority: InitialCandidateAuthority,
    input: InitialCandidateClaimInput<'_>,
) -> Result<StagingAuditedClaim, InitialCandidateClaimError> {
    claim_initial_candidate_impl(authority, input, |_, _| {}, |_, _, _| {})
}

#[cfg(target_os = "linux")]
fn claim_initial_candidate_impl<AfterMarker, AfterAudit>(
    authority: InitialCandidateAuthority,
    input: InitialCandidateClaimInput<'_>,
    after_marker: AfterMarker,
    after_audit: AfterAudit,
) -> Result<StagingAuditedClaim, InitialCandidateClaimError>
where
    AfterMarker: FnOnce(&Path, &HeldPublicationMarkerV2),
    AfterAudit: FnOnce(&Path, &HeldPublicationMarkerV2, &FreshMarkerCandidateAudit),
{
    let InitialCandidateAuthority {
        root,
        physical,
        held_root,
        context,
        root_commit,
        content_seal,
        worktree_files,
        encrypted_markdown,
        encrypted_assets,
        git_objects,
        mutation_lock,
    } = authority;

    let staging_child_name = repository_staging_child_name(&root)?;
    require_unreserved_destination(input.destination_child_name)?;
    physical.require_current_exact(&root).map_err(|_| {
        InitialCandidateClaimError::PreMarker(InitialCandidateClaimPreflightError::CandidateChanged)
    })?;
    held_root.verify_no_alternate_data_streams().map_err(|_| {
        InitialCandidateClaimError::PreMarker(InitialCandidateClaimPreflightError::CandidateChanged)
    })?;
    mutation_lock.revalidate(&root).map_err(|_| {
        InitialCandidateClaimError::PreMarker(InitialCandidateClaimPreflightError::CandidateChanged)
    })?;

    let expected_content_seal = content_seal.into_digest();
    let expected_root_commit = root_commit.commit_oid();
    // The fresh collector owns the only large manifest after this point.
    drop(physical);

    let held_marker = mutation_lock
        .create_held_publication_marker_v2(
            &root,
            held_root,
            HeldPublicationMarkerV2CreateInput {
                scheme: context.scheme,
                publication_id: context.publication_id,
                common_parent_identity: input.common_parent_identity,
                staging_child_name: &staging_child_name,
                destination_child_name: input.destination_child_name,
                domain: DOMAIN,
                candidate_seal: &expected_content_seal,
            },
        )
        .map_err(InitialCandidateClaimError::MarkerCreation)?;

    after_marker(&root, &held_marker);
    let audit = match audit_fresh_marker_candidate(&root, &held_marker) {
        Ok(audit) => audit,
        Err(error) => {
            return Err(failed_post_marker_claim(
                InitialCandidatePostMarkerFailure::FreshAudit(error),
                held_marker,
            ));
        }
    };

    let mismatch = if audit.context() != context {
        Some(InitialCandidatePostMarkerFailure::ContextMismatch)
    } else if audit.content_seal() != expected_content_seal {
        Some(InitialCandidatePostMarkerFailure::ContentSealMismatch)
    } else if audit.root_commit_oid() != expected_root_commit {
        Some(InitialCandidatePostMarkerFailure::RootCommitMismatch)
    } else if audit.worktree_files() != worktree_files {
        Some(InitialCandidatePostMarkerFailure::WorktreeCountMismatch)
    } else if audit.encrypted_markdown() != encrypted_markdown {
        Some(InitialCandidatePostMarkerFailure::MarkdownCountMismatch)
    } else if audit.encrypted_assets() != encrypted_assets {
        Some(InitialCandidatePostMarkerFailure::AssetCountMismatch)
    } else if audit.git_objects() != git_objects {
        Some(InitialCandidatePostMarkerFailure::GitObjectCountMismatch)
    } else {
        None
    };
    if let Some(failure) = mismatch {
        return Err(failed_post_marker_claim(failure, held_marker));
    }

    after_audit(&root, &held_marker, &audit);
    if let Err(error) = held_marker.require_destination_absent_at(&root) {
        return Err(failed_post_marker_claim(
            InitialCandidatePostMarkerFailure::DestinationObservation(error),
            held_marker,
        ));
    }

    Ok(StagingAuditedClaim {
        root,
        audit,
        held_marker,
    })
}

#[cfg(target_os = "linux")]
fn repository_staging_child_name(root: &Path) -> Result<String, InitialCandidateClaimError> {
    super::candidate_publication_authority::validated_staging_child_name_from_root(root).map_err(
        |_| {
            InitialCandidateClaimError::PreMarker(
                InitialCandidateClaimPreflightError::InvalidStagingName,
            )
        },
    )
}

#[cfg(target_os = "linux")]
fn require_unreserved_destination(
    destination_child_name: &str,
) -> Result<(), InitialCandidateClaimError> {
    super::candidate_publication_authority::require_unreserved_destination_child_name(
        destination_child_name,
    )
    .map_err(|_| {
        InitialCandidateClaimError::PreMarker(
            InitialCandidateClaimPreflightError::ReservedDestinationName,
        )
    })
}

#[cfg(target_os = "linux")]
fn failed_post_marker_claim(
    failure: InitialCandidatePostMarkerFailure,
    held_marker: HeldPublicationMarkerV2,
) -> InitialCandidateClaimError {
    InitialCandidateClaimError::PostMarker(Box::new(FailedHeldInitialClaim {
        failure,
        held_marker,
    }))
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

    let (
        content_seal,
        root_commit,
        worktree_files,
        encrypted_markdown,
        encrypted_assets,
        git_objects,
    ) = {
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
        let (worktree_files, encrypted_markdown, encrypted_assets) = tracked.checked_counts()?;
        let git_objects = runtime.checked_object_count()?;
        after_runtime(&root, &physical);
        (
            content_seal,
            root_commit,
            worktree_files,
            encrypted_markdown,
            encrypted_assets,
            git_objects,
        )
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
        worktree_files,
        encrypted_markdown,
        encrypted_assets,
        git_objects,
        mutation_lock,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fmt::Write as _;
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};

    use inex_core::atomic::{
        AtomicDirectoryPublishError, AtomicDirectoryPublishOutcome, ExistingVaultMutationLock,
        ExistingVaultMutationLockError, FilesystemDirectoryIdentity, FilesystemFileIdentity,
        IMPORT_PUBLISH_MARKER_V1, IMPORT_PUBLISH_MARKER_V2, IMPORT_STAGING_PREFIX,
        ParentSyncStatus, PublicationIdentityScheme, VAULT_LOCAL_DIRECTORY,
        VAULT_MUTATION_LOCK_FILE, filesystem_directory_identity, filesystem_file_identity,
    };
    use inex_core::crypto::VaultContentProfile;
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault::Vault;
    use inex_core::vault_config::KdfPolicy;

    use super::super::candidate_fresh_audit::{
        CandidateSummaryMismatch, compare_candidate_summaries,
    };
    use super::super::candidate_manifest::{
        MarkerFreePhysicalManifest, collect_marker_free_physical_manifest,
    };
    use super::super::candidate_seal::{CandidateSealContext, CandidateSealError};
    use super::super::{RepositoryImportError, TargetRepository, initialize_and_audit_target};
    use super::{
        InitialCandidateAuthority, InitialCandidateAuthorityError, InitialCandidateClaimError,
        InitialCandidateClaimInput, InitialCandidateClaimPreflightError, InitialCandidateInputs,
        InitialCandidatePostMarkerFailure, InitialCandidatePublishFailure,
        InitialCandidatePublishOutcome, acquire_initial_candidate_authority,
        acquire_initial_candidate_authority_impl, claim_initial_candidate,
        claim_initial_candidate_impl, publish_initial_candidate, publish_initial_candidate_impl,
    };

    const PASSWORD: &[u8] = b"initial candidate authority test password";
    const CREATED_AT_MS: i64 = 1_784_044_800_000;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(_label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "{IMPORT_STAGING_PREFIX}{}",
                uuid::Uuid::new_v4().simple()
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

    fn acquire_fixture_authority(fixture: &Fixture) -> InitialCandidateAuthority {
        acquire_fixture_authority_with_context(fixture, context())
    }

    fn acquire_fixture_authority_with_context(
        fixture: &Fixture,
        seal_context: CandidateSealContext,
    ) -> InitialCandidateAuthority {
        acquire_initial_candidate_authority(
            fixture.root.path(),
            &fixture.target,
            &fixture.vault,
            VaultContentProfile::DocumentsOnly,
            seal_context,
        )
        .expect("fixture initial authority constructs")
    }

    fn authority_baseline(
        authority: &InitialCandidateAuthority,
    ) -> (
        FilesystemDirectoryIdentity,
        FilesystemDirectoryIdentity,
        FilesystemFileIdentity,
    ) {
        (
            authority.physical.root_identity().clone(),
            authority.physical.local_identity().clone(),
            authority.physical.lock_identity().clone(),
        )
    }

    fn assert_baseline_lock_busy(
        root: &Path,
        baseline: &(
            FilesystemDirectoryIdentity,
            FilesystemDirectoryIdentity,
            FilesystemFileIdentity,
        ),
    ) {
        assert!(matches!(
            ExistingVaultMutationLock::acquire(root, &baseline.0, &baseline.1, &baseline.2),
            Err(ExistingVaultMutationLockError::Busy)
        ));
    }

    fn destination_name(label: &str) -> String {
        format!(
            "inex-initial-claim-{label}-{}",
            uuid::Uuid::new_v4().simple()
        )
    }

    type LockBaseline = (
        FilesystemDirectoryIdentity,
        FilesystemDirectoryIdentity,
        FilesystemFileIdentity,
    );

    fn claimed_fixture(
        label: &str,
    ) -> (Fixture, super::StagingAuditedClaim, LockBaseline, PathBuf) {
        claimed_fixture_with_context(label, context())
    }

    fn claimed_fixture_with_context(
        label: &str,
        seal_context: CandidateSealContext,
    ) -> (Fixture, super::StagingAuditedClaim, LockBaseline, PathBuf) {
        let fixture = fixture(label);
        let authority = acquire_fixture_authority_with_context(&fixture, seal_context);
        let baseline = authority_baseline(&authority);
        let parent = fixture
            .root
            .path()
            .parent()
            .expect("staging fixture has a parent");
        let parent_identity = filesystem_directory_identity(parent).expect("parent identity");
        let destination_child_name = destination_name(label);
        let destination = parent.join(&destination_child_name);
        let claim = claim_initial_candidate(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity: &parent_identity,
                destination_child_name: &destination_child_name,
            },
        )
        .expect("fixture initial claim constructs");
        (fixture, claim, baseline, destination)
    }

    fn remove_published_fixture(destination: &Path) {
        fs::remove_dir_all(destination).expect("published fixture removes");
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
    fn initial_authority_consumes_into_exact_marker_aware_staging_claim() {
        let fixture = fixture("claim-happy");
        let authority = acquire_fixture_authority(&fixture);
        let baseline = authority_baseline(&authority);
        let expected_context = authority.context;
        let expected_seal = authority.content_seal.into_digest();
        let expected_root_commit = authority.root_commit.commit_oid();
        let expected_counts = (
            authority.worktree_files,
            authority.encrypted_markdown,
            authority.encrypted_assets,
            authority.git_objects,
        );
        let parent = fixture
            .root
            .path()
            .parent()
            .expect("staging root has a parent");
        let parent_identity = filesystem_directory_identity(parent).expect("parent identity");
        let destination_name = destination_name("happy");
        let destination = parent.join(&destination_name);

        let claim = claim_initial_candidate(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity: &parent_identity,
                destination_child_name: &destination_name,
            },
        )
        .expect("initial authority becomes staging claim");

        assert_eq!(claim.root(), fixture.root.path());
        assert_eq!(claim.audit().context(), expected_context);
        assert_eq!(claim.audit().content_seal(), expected_seal);
        assert_eq!(claim.audit().root_commit_oid(), expected_root_commit);
        assert_eq!(
            (
                claim.audit().worktree_files(),
                claim.audit().encrypted_markdown(),
                claim.audit().encrypted_assets(),
                claim.audit().git_objects(),
            ),
            expected_counts
        );
        assert_eq!(claim.held_marker().marker().domain(), super::DOMAIN);
        assert_eq!(
            claim.held_marker().marker().destination_child_name(),
            destination_name
        );
        assert!(
            claim
                .held_marker()
                .marker()
                .candidate_seal_matches(&expected_seal)
        );
        assert!(!destination.exists());
        assert!(
            fixture
                .root
                .path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V2)
                .is_file()
        );
        assert_baseline_lock_busy(fixture.root.path(), &baseline);
        let debug = format!("{claim:?}");
        assert!(!debug.contains(fixture.root.path().to_string_lossy().as_ref()));
        assert!(!debug.contains(&lower_hex(&expected_seal)));

        drop(claim);
        drop(
            ExistingVaultMutationLock::acquire(
                fixture.root.path(),
                &baseline.0,
                &baseline.1,
                &baseline.2,
            )
            .expect("claim drop releases lock"),
        );
    }

    #[test]
    fn initial_publication_real_move_builds_shared_owner_and_holds_lock() {
        let (fixture, claim, baseline, destination) = claimed_fixture("publish-real");
        let staging = fixture.root.path().to_path_buf();
        let expected = (
            claim.audit().context(),
            claim.audit().content_seal(),
            claim.audit().root_commit_oid(),
            claim.audit().worktree_files(),
            claim.audit().encrypted_markdown(),
            claim.audit().encrypted_assets(),
            claim.audit().git_objects(),
        );

        let published = match publish_initial_candidate(claim) {
            InitialCandidatePublishOutcome::Published(owner) => owner,
            other => panic!("expected published owner, got {other:?}"),
        };
        assert_eq!(published.root(), destination);
        assert!(!staging.exists());
        assert!(
            destination
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V2)
                .is_file()
        );
        assert_eq!(
            (
                published.audit().context(),
                published.audit().content_seal(),
                published.audit().root_commit_oid(),
                published.audit().worktree_files(),
                published.audit().encrypted_markdown(),
                published.audit().encrypted_assets(),
                published.audit().git_objects(),
            ),
            expected
        );
        assert_baseline_lock_busy(&destination, &baseline);
        let debug = format!("{published:?}");
        assert!(!debug.contains(destination.to_string_lossy().as_ref()));

        drop(published);
        drop(
            ExistingVaultMutationLock::acquire(&destination, &baseline.0, &baseline.1, &baseline.2)
                .expect("published owner drop releases the exact lock"),
        );
        remove_published_fixture(&destination);
    }

    #[test]
    fn initial_publication_ignores_not_synced_without_claiming_durability() {
        let (_fixture, claim, baseline, destination) = claimed_fixture("publish-not-synced");
        let published =
            match publish_initial_candidate_impl(claim, |source, destination, critical_audit| {
                critical_audit(source).expect("critical audit accepts candidate");
                fs::rename(source, destination).expect("simulated no-replace move succeeds");
                Ok(AtomicDirectoryPublishOutcome {
                    parent_sync: ParentSyncStatus::NotSynced,
                })
            }) {
                InitialCandidatePublishOutcome::Published(owner) => owner,
                other => panic!("expected marker-held nondurable state, got {other:?}"),
            };
        assert_eq!(published.root(), destination);
        assert_baseline_lock_busy(&destination, &baseline);
        drop(published);
        remove_published_fixture(&destination);
    }

    #[test]
    fn initial_publication_not_moved_is_the_only_retryable_outcome() {
        let (_fixture, claim, baseline, destination) = claimed_fixture("publish-retry");
        let staging = claim.root().to_path_buf();
        let retry = match publish_initial_candidate_impl(claim, |source, _, critical_audit| {
            critical_audit(source).expect("critical audit accepts candidate");
            Err(AtomicDirectoryPublishError::NotMoved)
        }) {
            InitialCandidatePublishOutcome::NotMoved(owner) => owner,
            other => panic!("expected unique retry owner, got {other:?}"),
        };
        assert!(staging.is_dir());
        assert!(!destination.exists());
        assert_baseline_lock_busy(&staging, &baseline);

        let published = match retry.retry() {
            InitialCandidatePublishOutcome::Published(owner) => owner,
            other => panic!("expected consuming retry to publish, got {other:?}"),
        };
        assert!(!staging.exists());
        assert_eq!(published.root(), destination);
        assert_baseline_lock_busy(&destination, &baseline);
        drop(published);
        remove_published_fixture(&destination);
    }

    #[test]
    fn initial_publication_not_moved_recheck_drift_is_terminal() {
        let (_fixture, claim, baseline, destination) =
            claimed_fixture("publish-retry-recheck-drift");
        let staging = claim.root().to_path_buf();
        let terminal = match publish_initial_candidate_impl(claim, |source, _, critical_audit| {
            critical_audit(source).expect("critical audit accepts candidate");
            fs::write(source.join(".gitattributes"), b"retry recheck drift\n")
                .expect("candidate drifts after namespace attempt");
            Err(AtomicDirectoryPublishError::NotMoved)
        }) {
            InitialCandidatePublishOutcome::Terminal(owner) => owner,
            other => panic!("expected terminal retry recheck owner, got {other:?}"),
        };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::RetryFreshAudit(_)
        ));
        assert!(staging.is_dir());
        assert!(!destination.exists());
        assert_baseline_lock_busy(&staging, &baseline);
        drop(terminal);
    }

    #[test]
    fn initial_publication_critical_drift_and_destination_conflict_are_terminal() {
        let (drift_fixture, drift_claim, drift_baseline, _) =
            claimed_fixture("publish-critical-drift");
        let drift_root = drift_claim.root().to_path_buf();
        let terminal =
            match publish_initial_candidate_impl(drift_claim, |source, _, critical_audit| {
                fs::write(source.join(".gitattributes"), b"critical drift\n")
                    .expect("critical candidate drifts");
                let error = critical_audit(source).expect_err("critical audit rejects drift");
                Err(AtomicDirectoryPublishError::Io { source: error })
            }) {
                InitialCandidatePublishOutcome::Terminal(owner) => owner,
                other => panic!("expected terminal drift owner, got {other:?}"),
            };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::CriticalFreshAudit(_)
        ));
        assert_baseline_lock_busy(&drift_root, &drift_baseline);
        let debug = format!("{terminal:?}");
        assert!(!debug.contains(drift_root.to_string_lossy().as_ref()));
        drop(terminal);
        drop(drift_fixture);

        let (_conflict_fixture, conflict_claim, conflict_baseline, conflict_destination) =
            claimed_fixture("publish-conflict");
        let conflict_root = conflict_claim.root().to_path_buf();
        let terminal = match publish_initial_candidate_impl(
            conflict_claim,
            |source, destination, critical_audit| {
                critical_audit(source).expect("critical audit accepts candidate");
                fs::write(destination, b"foreign destination canary")
                    .expect("foreign destination appears");
                Err(AtomicDirectoryPublishError::DestinationExists)
            },
        ) {
            InitialCandidatePublishOutcome::Terminal(owner) => owner,
            other => panic!("expected terminal conflict owner, got {other:?}"),
        };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::DestinationExists
        ));
        assert_eq!(
            fs::read(&conflict_destination).expect("foreign destination reads"),
            b"foreign destination canary"
        );
        assert_baseline_lock_busy(&conflict_root, &conflict_baseline);
        fs::remove_file(&conflict_destination).expect("foreign destination removes");
        drop(terminal);
    }

    #[test]
    fn initial_publication_real_preflight_preserves_post_claim_destination() {
        let (_fixture, claim, baseline, destination) =
            claimed_fixture("publish-real-preflight-conflict");
        let staging = claim.root().to_path_buf();
        fs::write(&destination, b"post-claim foreign destination")
            .expect("foreign destination appears after claim");

        let terminal = match publish_initial_candidate(claim) {
            InitialCandidatePublishOutcome::Terminal(owner) => owner,
            other => panic!("expected real preflight terminal owner, got {other:?}"),
        };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::DestinationExists
        ));
        assert_eq!(
            fs::read(&destination).expect("foreign destination reads"),
            b"post-claim foreign destination"
        );
        assert!(staging.is_dir());
        assert_baseline_lock_busy(&staging, &baseline);
        fs::remove_file(&destination).expect("foreign destination removes");
        drop(terminal);
    }

    #[test]
    fn initial_publication_zero_call_preflight_errors_keep_generic_class() {
        for (label, injected, expected) in [
            (
                "publish-zero-invalid",
                AtomicDirectoryPublishError::InvalidPaths,
                0_u8,
            ),
            (
                "publish-zero-io",
                AtomicDirectoryPublishError::Io {
                    source: std::io::Error::new(
                        std::io::ErrorKind::ReadOnlyFilesystem,
                        "secret zero-call generic source",
                    ),
                },
                1_u8,
            ),
            (
                "publish-zero-indeterminate",
                AtomicDirectoryPublishError::Indeterminate,
                2_u8,
            ),
        ] {
            let (_fixture, claim, baseline, destination) = claimed_fixture(label);
            let staging = claim.root().to_path_buf();
            let terminal = match publish_initial_candidate_impl(claim, |_, _, _| Err(injected)) {
                InitialCandidatePublishOutcome::Terminal(owner) => owner,
                other => panic!("expected zero-call terminal owner, got {other:?}"),
            };
            match (terminal.failure(), expected) {
                (InitialCandidatePublishFailure::InvalidMovePaths, 0)
                | (InitialCandidatePublishFailure::IndeterminateMove, 2) => {}
                (InitialCandidatePublishFailure::MoveIo(kind), 1) => {
                    assert_eq!(*kind, std::io::ErrorKind::ReadOnlyFilesystem);
                }
                (other, expected) => {
                    panic!("unexpected zero-call mapping {other:?} / {expected}")
                }
            }
            assert!(!format!("{terminal:?}").contains("secret zero-call generic source"));
            assert!(staging.is_dir());
            assert!(!destination.exists());
            assert_baseline_lock_busy(&staging, &baseline);
            drop(terminal);
        }
    }

    #[test]
    fn initial_publication_zero_or_multiple_call_retry_contract_is_terminal() {
        let (_fixture, claim, baseline, destination) =
            claimed_fixture("publish-zero-call-not-moved");
        let staging = claim.root().to_path_buf();
        let terminal = match publish_initial_candidate_impl(claim, |_, _, _| {
            Err(AtomicDirectoryPublishError::NotMoved)
        }) {
            InitialCandidatePublishOutcome::Terminal(owner) => owner,
            other => panic!("expected zero-call NotMoved terminal owner, got {other:?}"),
        };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::CriticalAuditNotRunExactlyOnce
        ));
        assert!(staging.is_dir());
        assert!(!destination.exists());
        assert_baseline_lock_busy(&staging, &baseline);
        drop(terminal);

        let (_fixture, claim, baseline, destination) =
            claimed_fixture("publish-multiple-call-not-moved");
        let staging = claim.root().to_path_buf();
        let terminal = match publish_initial_candidate_impl(claim, |source, _, critical_audit| {
            critical_audit(source).expect("first critical audit succeeds");
            assert!(critical_audit(source).is_err());
            Err(AtomicDirectoryPublishError::NotMoved)
        }) {
            InitialCandidatePublishOutcome::Terminal(owner) => owner,
            other => panic!("expected repeated-call terminal owner, got {other:?}"),
        };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::CriticalAuditNotRunExactlyOnce
        ));
        assert!(staging.is_dir());
        assert!(!destination.exists());
        assert_baseline_lock_busy(&staging, &baseline);
        drop(terminal);
    }

    #[test]
    fn initial_publication_indeterminate_and_post_move_staging_are_terminal() {
        let (_fixture, claim, baseline, destination) = claimed_fixture("publish-indeterminate");
        let terminal =
            match publish_initial_candidate_impl(claim, |source, destination, critical_audit| {
                critical_audit(source).expect("critical audit accepts candidate");
                fs::rename(source, destination).expect("candidate physically moves");
                Err(AtomicDirectoryPublishError::Indeterminate)
            }) {
                InitialCandidatePublishOutcome::Terminal(owner) => owner,
                other => panic!("expected terminal indeterminate owner, got {other:?}"),
            };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::IndeterminateMove
        ));
        assert_baseline_lock_busy(&destination, &baseline);
        drop(terminal);
        remove_published_fixture(&destination);

        let (_fixture, claim, baseline, destination) = claimed_fixture("publish-staging-reappears");
        let staging = claim.root().to_path_buf();
        let terminal =
            match publish_initial_candidate_impl(claim, |source, destination, critical_audit| {
                critical_audit(source).expect("critical audit accepts candidate");
                fs::rename(source, destination).expect("candidate physically moves");
                fs::create_dir(source).expect("foreign staging name reappears");
                Ok(AtomicDirectoryPublishOutcome {
                    parent_sync: ParentSyncStatus::Synced,
                })
            }) {
                InitialCandidatePublishOutcome::Terminal(owner) => owner,
                other => panic!("expected terminal post-move role owner, got {other:?}"),
            };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::PublishedRole(_)
        ));
        assert_eq!(terminal.root, destination);
        assert!(staging.is_dir());
        assert_baseline_lock_busy(&destination, &baseline);
        fs::remove_dir(&staging).expect("foreign staging canary removes");
        drop(terminal);
        remove_published_fixture(&destination);
    }

    #[test]
    fn initial_publication_scrubs_all_remaining_generic_move_failures() {
        for (label, injected, expected_kind) in [
            (
                "publish-invalid-paths",
                AtomicDirectoryPublishError::InvalidPaths,
                None,
            ),
            (
                "publish-move-io",
                AtomicDirectoryPublishError::Io {
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "secret generic move source",
                    ),
                },
                Some(std::io::ErrorKind::PermissionDenied),
            ),
            (
                "publish-cleanup-failed",
                AtomicDirectoryPublishError::PublishedCleanupFailed,
                None,
            ),
        ] {
            let (_fixture, claim, baseline, destination) = claimed_fixture(label);
            let staging = claim.root().to_path_buf();
            let terminal =
                match publish_initial_candidate_impl(claim, |source, _, critical_audit| {
                    critical_audit(source).expect("critical audit accepts candidate");
                    Err(injected)
                }) {
                    InitialCandidatePublishOutcome::Terminal(owner) => owner,
                    other => panic!("expected scrubbed terminal owner, got {other:?}"),
                };
            match (terminal.failure(), expected_kind) {
                (
                    InitialCandidatePublishFailure::InvalidMovePaths
                    | InitialCandidatePublishFailure::PublishedCleanupFailed,
                    None,
                ) => {}
                (InitialCandidatePublishFailure::MoveIo(actual), Some(expected)) => {
                    assert_eq!(*actual, expected);
                }
                (other, expected) => panic!("unexpected mapping {other:?} / {expected:?}"),
            }
            assert!(!format!("{terminal:?}").contains("secret generic move source"));
            assert!(staging.is_dir());
            assert!(!destination.exists());
            assert_baseline_lock_busy(&staging, &baseline);
            drop(terminal);
        }
    }

    #[test]
    fn initial_publication_summary_mismatch_is_terminal_before_move() {
        let (_fixture, mut claim, baseline, destination) = claimed_fixture("publish-mismatch-a");
        let alternate_context = CandidateSealContext {
            scheme: PublicationIdentityScheme::LinuxDevInodeV1,
            publication_id: [0xa7; 16],
        };
        let (_other_fixture, mut other_claim, _, _) =
            claimed_fixture_with_context("publish-mismatch-b", alternate_context);
        std::mem::swap(&mut claim.audit, &mut other_claim.audit);
        drop(other_claim);
        let staging = claim.root().to_path_buf();

        let terminal = match publish_initial_candidate_impl(claim, |source, _, critical_audit| {
            let error = critical_audit(source).expect_err("summary mismatch rejects");
            Err(AtomicDirectoryPublishError::Io { source: error })
        }) {
            InitialCandidatePublishOutcome::Terminal(owner) => owner,
            other => panic!("expected terminal summary owner, got {other:?}"),
        };
        assert!(matches!(
            terminal.failure(),
            InitialCandidatePublishFailure::CriticalSummaryMismatch(
                CandidateSummaryMismatch::Context
            )
        ));
        assert!(staging.is_dir());
        assert!(!destination.exists());
        assert_baseline_lock_busy(&staging, &baseline);
        drop(terminal);
    }

    #[test]
    fn initial_publication_compares_every_summary_field_directly() {
        use super::super::candidate_fresh_audit::FreshMarkerCandidateAudit;

        let expected_context = context();
        let different_context = CandidateSealContext {
            scheme: PublicationIdentityScheme::LinuxDevInodeV1,
            publication_id: [0xc3; 16],
        };
        let synthetic = |seal, oid, worktree, markdown, assets, objects| {
            FreshMarkerCandidateAudit::test_only_synthetic(
                expected_context,
                seal,
                oid,
                worktree,
                markdown,
                assets,
                objects,
            )
        };
        let cases = [
            (
                FreshMarkerCandidateAudit::test_only_synthetic(
                    different_context,
                    [0x11; 32],
                    [0x22; 20],
                    3,
                    4,
                    5,
                    6,
                ),
                CandidateSummaryMismatch::Context,
            ),
            (
                synthetic([0x12; 32], [0x22; 20], 3, 4, 5, 6),
                CandidateSummaryMismatch::ContentSeal,
            ),
            (
                synthetic([0x11; 32], [0x23; 20], 3, 4, 5, 6),
                CandidateSummaryMismatch::RootCommit,
            ),
            (
                synthetic([0x11; 32], [0x22; 20], 7, 4, 5, 6),
                CandidateSummaryMismatch::WorktreeCount,
            ),
            (
                synthetic([0x11; 32], [0x22; 20], 3, 7, 5, 6),
                CandidateSummaryMismatch::MarkdownCount,
            ),
            (
                synthetic([0x11; 32], [0x22; 20], 3, 4, 7, 6),
                CandidateSummaryMismatch::AssetCount,
            ),
            (
                synthetic([0x11; 32], [0x22; 20], 3, 4, 5, 7),
                CandidateSummaryMismatch::GitObjectCount,
            ),
        ];
        for (current, expected_mismatch) in cases {
            let expected = synthetic([0x11; 32], [0x22; 20], 3, 4, 5, 6);
            assert_eq!(
                compare_candidate_summaries(&current, &expected),
                Err(expected_mismatch)
            );
        }
    }

    #[test]
    fn initial_publication_api_and_transition_order_are_frozen() {
        let source = include_str!("candidate_initial_authority.rs");
        let input = source
            .split("pub(super) fn publish_initial_candidate(")
            .nth(1)
            .and_then(|tail| tail.split("fn publish_initial_candidate_impl").next())
            .expect("publication entry point exists");
        assert!(input.contains("claim: StagingAuditedClaim"));
        assert!(!input.contains("destination:"));
        assert!(!input.contains("target:"));

        let critical = source
            .split("fn critical_initial_publication_review")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn reconcile_not_moved_initial_candidate")
                    .next()
            })
            .expect("critical review exists");
        let first_absence = critical
            .find("require_destination_absent_at")
            .expect("first destination check exists");
        let audit = critical
            .find("audit_fresh_marker_candidate")
            .expect("fresh audit exists");
        let compare = critical
            .find("compare_candidate_summaries")
            .expect("summary comparison exists");
        let second_absence = critical
            .rfind("require_destination_absent_at")
            .expect("second destination check exists");
        assert!(first_absence < audit && audit < compare && compare < second_absence);
        assert_ne!(first_absence, second_absence);

        let comparison = include_str!("candidate_fresh_audit.rs")
            .split("fn compare_candidate_summaries")
            .nth(1)
            .and_then(|tail| tail.split("/// Audit one complete fresh target").next())
            .expect("summary comparison exists");
        for field in [
            "context()",
            "content_seal()",
            "root_commit_oid()",
            "worktree_files()",
            "encrypted_markdown()",
            "encrypted_assets()",
            "git_objects()",
        ] {
            assert!(comparison.contains(field), "missing comparison: {field}");
        }

        for owner_name in [
            "RetryableInitialPublication",
            "FailedHeldInitialPublication",
            "VerifiedInitialMove",
        ] {
            let owner = source
                .split(&format!("pub(super) struct {owner_name}"))
                .nth(1)
                .and_then(|tail| tail.split(&format!("impl {owner_name}")).next())
                .expect("linear owner source exists");
            assert!(!owner.contains("derive(Clone"));
            assert!(!owner.contains("derive(Copy"));
            assert!(
                owner.find("audit:").expect("audit field")
                    < owner.find("held_marker:").expect("held marker field")
            );
            let custom_drop = format!("impl Drop for {owner_name}");
            assert!(!source.contains(&custom_drop));
        }
        let terminal_impl = source
            .split("impl FailedHeldInitialPublication")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for FailedHeldInitialPublication")
                    .next()
            })
            .expect("terminal implementation exists");
        assert!(!terminal_impl.contains("retry"));
        assert!(!terminal_impl.contains("cleanup"));
        assert!(!terminal_impl.contains("extract"));

        let transition = source
            .split("fn publish_initial_candidate_impl")
            .nth(1)
            .and_then(|tail| tail.split("fn critical_initial_publication_review").next())
            .expect("move transition exists");
        assert!(transition.contains("marker().destination_child_name()"));
        assert!(transition.contains("Ok(_) =>"));
        assert!(!transition.contains("parent_sync"));
        assert!(transition.contains("MoveIo(source.kind())"));
        assert!(!transition.contains("MoveIo(source)"));
    }

    #[test]
    fn post_marker_fresh_failure_retains_marker_and_lock_owner() {
        let fixture = fixture("claim-post-marker-failure");
        let authority = acquire_fixture_authority(&fixture);
        let baseline = authority_baseline(&authority);
        let parent_identity = filesystem_directory_identity(
            fixture
                .root
                .path()
                .parent()
                .expect("staging root has a parent"),
        )
        .expect("parent identity");
        let destination_name = destination_name("post-marker-failure");
        let marker_path = fixture
            .root
            .path()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2);

        let result = claim_initial_candidate_impl(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity: &parent_identity,
                destination_child_name: &destination_name,
            },
            |root, _| {
                fs::write(root.join(".gitattributes"), b"post-marker tamper\n")
                    .expect("candidate tampers");
            },
            |_, _, _| {},
        );
        let owner = match result {
            Err(InitialCandidateClaimError::PostMarker(owner)) => owner,
            other => panic!("expected owning post-marker error, got {other:?}"),
        };
        assert!(matches!(
            owner.failure(),
            InitialCandidatePostMarkerFailure::FreshAudit(_)
        ));
        assert!(marker_path.is_file());
        assert_baseline_lock_busy(fixture.root.path(), &baseline);
        let debug = format!("{owner:?}");
        assert!(!debug.contains(fixture.root.path().to_string_lossy().as_ref()));

        drop(owner);
        drop(
            ExistingVaultMutationLock::acquire(
                fixture.root.path(),
                &baseline.0,
                &baseline.1,
                &baseline.2,
            )
            .expect("failed owner drop releases lock"),
        );
    }

    #[test]
    fn post_audit_destination_appearance_is_preserved_with_live_owner() {
        let fixture = fixture("claim-destination-appeared");
        let authority = acquire_fixture_authority(&fixture);
        let baseline = authority_baseline(&authority);
        let parent = fixture
            .root
            .path()
            .parent()
            .expect("staging root has a parent");
        let parent_identity = filesystem_directory_identity(parent).expect("parent identity");
        let destination_name = destination_name("appeared");
        let destination = parent.join(&destination_name);

        let result = claim_initial_candidate_impl(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity: &parent_identity,
                destination_child_name: &destination_name,
            },
            |_, _| {},
            |_, _, _| {
                fs::write(&destination, b"foreign-destination-canary")
                    .expect("foreign destination appears");
            },
        );
        let owner = match result {
            Err(InitialCandidateClaimError::PostMarker(owner)) => owner,
            other => panic!("expected owning destination error, got {other:?}"),
        };
        assert!(matches!(
            owner.failure(),
            InitialCandidatePostMarkerFailure::DestinationObservation(_)
        ));
        assert_eq!(
            fs::read(&destination).expect("foreign destination reads"),
            b"foreign-destination-canary"
        );
        assert_baseline_lock_busy(fixture.root.path(), &baseline);
        assert!(
            fixture
                .root
                .path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V2)
                .is_file()
        );

        fs::remove_file(&destination).expect("foreign destination test cleanup");
        drop(owner);
        drop(
            ExistingVaultMutationLock::acquire(
                fixture.root.path(),
                &baseline.0,
                &baseline.1,
                &baseline.2,
            )
            .expect("failed owner drop releases lock"),
        );
    }

    #[test]
    fn initial_and_fresh_count_mismatch_fails_with_live_owner() {
        let fixture = fixture("claim-count-mismatch");
        let mut authority = acquire_fixture_authority(&fixture);
        let baseline = authority_baseline(&authority);
        authority.git_objects = authority
            .git_objects
            .checked_add(1)
            .expect("fixture object count has headroom");
        let parent_identity = filesystem_directory_identity(
            fixture
                .root
                .path()
                .parent()
                .expect("staging root has a parent"),
        )
        .expect("parent identity");
        let destination_name = destination_name("count-mismatch");
        let result = claim_initial_candidate(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity: &parent_identity,
                destination_child_name: &destination_name,
            },
        );
        let owner = match result {
            Err(InitialCandidateClaimError::PostMarker(owner)) => owner,
            other => panic!("expected owning count mismatch, got {other:?}"),
        };
        assert!(matches!(
            owner.failure(),
            InitialCandidatePostMarkerFailure::GitObjectCountMismatch
        ));
        assert_baseline_lock_busy(fixture.root.path(), &baseline);
        drop(owner);
    }

    #[test]
    fn pre_marker_destination_conflicts_and_reserved_prefixes_create_nothing() {
        let occupied = fixture("claim-preexisting-destination");
        let authority = acquire_fixture_authority(&occupied);
        let baseline = authority_baseline(&authority);
        let parent = occupied
            .root
            .path()
            .parent()
            .expect("staging root has a parent");
        let parent_identity = filesystem_directory_identity(parent).expect("parent identity");
        let destination_name = destination_name("occupied");
        let destination = parent.join(&destination_name);
        fs::write(&destination, b"foreign-destination-canary")
            .expect("foreign destination creates");
        let result = claim_initial_candidate(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity: &parent_identity,
                destination_child_name: &destination_name,
            },
        );
        assert!(matches!(
            result,
            Err(InitialCandidateClaimError::MarkerCreation(
                inex_core::atomic::HeldPublicationMarkerV2Error::NamespaceConflict
            ))
        ));
        assert_eq!(
            fs::read(&destination).expect("foreign destination reads"),
            b"foreign-destination-canary"
        );
        assert_no_marker(occupied.root.path());
        drop(
            ExistingVaultMutationLock::acquire(
                occupied.root.path(),
                &baseline.0,
                &baseline.1,
                &baseline.2,
            )
            .expect("pre-marker conflict releases lock"),
        );
        fs::remove_file(&destination).expect("foreign destination test cleanup");

        let reserved = fixture("claim-reserved-destination");
        let authority = acquire_fixture_authority(&reserved);
        let baseline = authority_baseline(&authority);
        let parent_identity = filesystem_directory_identity(
            reserved
                .root
                .path()
                .parent()
                .expect("staging root has a parent"),
        )
        .expect("parent identity");
        let result = claim_initial_candidate(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity: &parent_identity,
                destination_child_name: ".INEX-IMPORT-STAGING-foreign",
            },
        );
        assert!(matches!(
            result,
            Err(InitialCandidateClaimError::PreMarker(
                InitialCandidateClaimPreflightError::ReservedDestinationName
            ))
        ));
        assert_no_marker(reserved.root.path());
        drop(
            ExistingVaultMutationLock::acquire(
                reserved.root.path(),
                &baseline.0,
                &baseline.1,
                &baseline.2,
            )
            .expect("reserved preflight releases lock"),
        );
    }

    #[test]
    fn staging_claim_api_is_linear_and_drops_large_manifest_before_fresh_audit() {
        let source = include_str!("candidate_initial_authority.rs");
        let claim = source
            .split("pub(super) struct StagingAuditedClaim")
            .nth(1)
            .and_then(|tail| tail.split("impl StagingAuditedClaim").next())
            .expect("claim source exists");
        assert!(!claim.contains("derive(Clone"));
        assert!(!claim.contains("derive(Copy"));
        assert!(
            claim.find("audit:").expect("audit field")
                < claim.find("held_marker:").expect("marker field")
        );
        let claim_drop = ["impl Drop for ", "StagingAuditedClaim"].concat();
        let failed_drop = ["impl Drop for ", "FailedHeldInitialClaim"].concat();
        assert!(!source.contains(&claim_drop));
        assert!(!source.contains(&failed_drop));
        let transition = source
            .split("fn claim_initial_candidate_impl")
            .nth(1)
            .and_then(|tail| tail.split("fn repository_staging_child_name").next())
            .expect("claim transition source exists");
        assert!(
            transition.find("drop(physical);").expect("physical drops")
                < transition
                    .find("create_held_publication_marker_v2")
                    .expect("marker creates")
        );
        assert!(!transition.contains("drop(held_marker)"));
    }

    #[test]
    fn repository_staging_name_requires_exact_lowercase_32_hex_suffix() {
        let valid_name = format!("{IMPORT_STAGING_PREFIX}0123456789abcdef0123456789abcdef");
        let valid = Path::new("/tmp").join(&valid_name);
        assert_eq!(
            super::repository_staging_child_name(&valid).expect("exact staging name validates"),
            valid_name
        );

        for invalid in [
            format!("{IMPORT_STAGING_PREFIX}0123456789abcdef0123456789abcde"),
            format!("{IMPORT_STAGING_PREFIX}0123456789abcdef0123456789abcdef0"),
            format!("{IMPORT_STAGING_PREFIX}0123456789abcdef0123456789abcdeF"),
            ".INEX-IMPORT-STAGING-0123456789abcdef0123456789abcdef".to_owned(),
        ] {
            assert!(matches!(
                super::repository_staging_child_name(&Path::new("/tmp").join(invalid)),
                Err(InitialCandidateClaimError::PreMarker(
                    InitialCandidateClaimPreflightError::InvalidStagingName
                ))
            ));
        }
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
