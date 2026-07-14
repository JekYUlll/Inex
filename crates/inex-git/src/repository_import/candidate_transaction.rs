//! Complete same-process v2 publication driver for one initial repository candidate.
//!
//! This module is the only production layer that sequences the private
//! publication typestates. It never exposes a marker, lock, core authority, or
//! retry owner to callers. Success and every failure that has acquired linear
//! publication authority retain the last owner until the caller has emitted
//! its terminal result and drops the value.

use std::fmt;
use std::path::Path;

use inex_core::atomic::FilesystemDirectoryIdentity;
#[cfg(target_os = "linux")]
use inex_core::atomic::{PostUnlinkPublicationMarkerV2Error, PublicationIdentityScheme};
use inex_core::crypto::VaultContentProfile;
use inex_core::vault::Vault;
#[cfg(target_os = "linux")]
use uuid::Uuid;

use super::TargetRepository;
#[cfg(target_os = "linux")]
use super::candidate_initial_authority::{
    FailedHeldInitialPublication, InitialCandidateClaimError, InitialCandidateClaimInput,
    InitialCandidatePublishFailure, InitialCandidatePublishOutcome, RetryableInitialPublication,
    acquire_initial_candidate_authority, claim_initial_candidate, publish_initial_candidate,
};
#[cfg(target_os = "linux")]
use super::candidate_publication_authority::{
    CleanAuditOutcome, CleanAuditPending, CleanAuditTerminalFailure, FailedCleanAudit,
    FailedPublicationDurability, FailedPublicationMarkerUnlink, FreshExistingClaimError,
    FreshExistingClaimInput, ParentSyncPending, PublicationDurabilityOutcome,
    PublicationDurableWithMarker, PublicationMarkerUnlinkFailure, PublicationMarkerUnlinkOutcome,
    PublicationParentSyncOutcome, PublishedClean, PublishedWithMarker,
    RetryablePublicationDurability, claim_fresh_existing_candidate,
};
#[cfg(target_os = "linux")]
use super::candidate_seal::CandidateSealContext;

/// Maximum number of immediate, same-process attempts for an explicitly
/// retryable typestate, including the first attempt.
///
/// Retrying never reconstructs a marker or reacquires a lock. Every attempt
/// consumes and returns the same linear authority. A still-retryable final
/// result is retained for terminal output rather than looped indefinitely.
#[cfg(any(target_os = "linux", test))]
const SAME_PROCESS_ATTEMPTS: usize = 3;

/// Return whether this build implements the held-handle v2 publication path.
///
/// Callers use this gate before password prompting or persistent staging
/// creation. The publication function independently fails closed as defense in
/// depth when invoked on an unsupported target.
#[must_use]
pub const fn initial_repository_publication_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Stable high-level category for a v2 initial-publication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryCandidatePublicationFailureKind {
    /// The platform does not yet implement the required held traversal.
    UnsupportedPlatform,
    /// Marker-free candidate authority could not be acquired.
    InitialAuthorityRejected,
    /// The initial authority could not be converted into a durable marker claim.
    InitialClaimRejected,
    /// An existing canonical v2 claim could not be opened and fully audited.
    ExistingClaimRejected,
    /// The verified no-replace move remained provably not performed.
    InitialPublicationNotMoved,
    /// The destination appeared before the verified no-replace move.
    DestinationExists,
    /// The whole-root publication result could not be determined.
    PublicationIndeterminate,
    /// A pre- or post-move publication proof was rejected.
    InitialPublicationRejected,
    /// Destination/common-parent durability remained retryable.
    PublicationDurabilityIndeterminate,
    /// A complete post-sync review rejected the published candidate.
    PublicationDurabilityRejected,
    /// The exact old marker remained present after bounded attempts.
    PublicationMarkerRetained,
    /// A marker replacement was observed and preserved.
    PublicationMarkerReplaced,
    /// Marker unlink post-state could not be classified.
    PublicationMarkerPostStateIndeterminate,
    /// Marker-parent synchronization or clean audit remained retryable.
    PostUnlinkIndeterminate,
    /// A terminal clean-audit proof rejected the published candidate.
    CleanAuditRejected,
}

impl fmt::Display for RepositoryCandidatePublicationFailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "repository publication is unsupported on this platform",
            Self::InitialAuthorityRejected => {
                "initial repository publication authority was rejected"
            }
            Self::InitialClaimRejected => "initial repository publication claim was rejected",
            Self::ExistingClaimRejected => "existing repository publication claim was rejected",
            Self::InitialPublicationNotMoved => "repository publication was not performed",
            Self::DestinationExists => "repository publication destination exists",
            Self::PublicationIndeterminate => "repository publication outcome is indeterminate",
            Self::InitialPublicationRejected => "initial repository publication proof was rejected",
            Self::PublicationDurabilityIndeterminate => {
                "repository publication durability is indeterminate"
            }
            Self::PublicationDurabilityRejected => {
                "repository publication durability proof was rejected"
            }
            Self::PublicationMarkerRetained => "repository publication marker remains",
            Self::PublicationMarkerReplaced => "repository publication marker was replaced",
            Self::PublicationMarkerPostStateIndeterminate => {
                "repository publication marker post-state is indeterminate"
            }
            Self::PostUnlinkIndeterminate => {
                "post-unlink repository publication state is indeterminate"
            }
            Self::CleanAuditRejected => "repository publication clean audit was rejected",
        })
    }
}

#[cfg(target_os = "linux")]
enum RetainedPublicationOwner {
    None,
    InitialClaim(Box<InitialCandidateClaimError>),
    FreshClaim(Box<FreshExistingClaimError>),
    InitialRetry(RetryableInitialPublication),
    InitialTerminal(Box<FailedHeldInitialPublication>),
    DurabilityRetry(RetryablePublicationDurability),
    DurabilityTerminal(Box<FailedPublicationDurability>),
    MarkerRetained(PublicationDurableWithMarker),
    MarkerTerminal(Box<FailedPublicationMarkerUnlink>),
    ParentSyncRetry(ParentSyncPending),
    CleanRetry(CleanAuditPending),
    CleanTerminal(Box<FailedCleanAudit>),
}

#[cfg(target_os = "linux")]
impl fmt::Debug for RetainedPublicationOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("RetainedPublicationOwner::None"),
            Self::InitialClaim(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::InitialClaim")
                .field(owner)
                .finish(),
            Self::FreshClaim(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::FreshClaim")
                .field(owner)
                .finish(),
            Self::InitialRetry(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::InitialRetry")
                .field(owner)
                .finish(),
            Self::InitialTerminal(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::InitialTerminal")
                .field(owner)
                .finish(),
            Self::DurabilityRetry(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::DurabilityRetry")
                .field(owner)
                .finish(),
            Self::DurabilityTerminal(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::DurabilityTerminal")
                .field(owner)
                .finish(),
            Self::MarkerRetained(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::MarkerRetained")
                .field(owner)
                .finish(),
            Self::MarkerTerminal(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::MarkerTerminal")
                .field(owner)
                .finish(),
            Self::ParentSyncRetry(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::ParentSyncRetry")
                .field(owner)
                .finish(),
            Self::CleanRetry(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::CleanRetry")
                .field(owner)
                .finish(),
            Self::CleanTerminal(owner) => formatter
                .debug_tuple("RetainedPublicationOwner::CleanTerminal")
                .field(owner)
                .finish(),
        }
    }
}

/// Opaque failure result retained until terminal output has been emitted.
///
/// Once publication authority exists, this value owns it. Failures that occur
/// before authority acquisition carry only their scrubbed category.
#[must_use]
pub struct RepositoryCandidatePublicationFailure {
    kind: RepositoryCandidatePublicationFailureKind,
    #[cfg(target_os = "linux")]
    owner: Box<RetainedPublicationOwner>,
}

impl RepositoryCandidatePublicationFailure {
    /// Return the fixed scrubbed failure category.
    #[must_use]
    pub const fn kind(&self) -> RepositoryCandidatePublicationFailureKind {
        self.kind
    }

    #[cfg(target_os = "linux")]
    fn retained(
        kind: RepositoryCandidatePublicationFailureKind,
        owner: RetainedPublicationOwner,
    ) -> Self {
        Self {
            kind,
            owner: Box::new(owner),
        }
    }

    #[cfg(not(target_os = "linux"))]
    const fn unsupported() -> Self {
        Self {
            kind: RepositoryCandidatePublicationFailureKind::UnsupportedPlatform,
        }
    }
}

impl fmt::Debug for RepositoryCandidatePublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RepositoryCandidatePublicationFailure");
        debug.field("kind", &self.kind);
        #[cfg(target_os = "linux")]
        debug.field("owner", &self.owner);
        debug.finish()
    }
}

impl fmt::Display for RepositoryCandidatePublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for RepositoryCandidatePublicationFailure {}

/// Complete marker-free publication retained through caller acknowledgement.
///
/// This value is intentionally neither `Clone` nor `Copy`. It exposes only the
/// fixed target-derived summary; the clean authority and mutation lock remain
/// private and are released only when this value is dropped.
#[must_use]
pub struct PublishedRepositoryCandidate {
    worktree_files: u32,
    encrypted_markdown: u32,
    encrypted_assets: u32,
    git_objects: u32,
    root_commit_oid: [u8; 20],
    #[cfg(target_os = "linux")]
    authority: PublishedClean,
}

impl PublishedRepositoryCandidate {
    /// Return the exact worktree-file count from the final nine-section audit.
    #[must_use]
    pub const fn worktree_files(&self) -> u32 {
        self.worktree_files
    }

    /// Return the exact encrypted Markdown count from the final audit.
    #[must_use]
    pub const fn encrypted_markdown(&self) -> u32 {
        self.encrypted_markdown
    }

    /// Return the exact encrypted asset count from the final audit.
    #[must_use]
    pub const fn encrypted_assets(&self) -> u32 {
        self.encrypted_assets
    }

    /// Return the exact Git-object count from the final audit.
    #[must_use]
    pub const fn git_objects(&self) -> u32 {
        self.git_objects
    }

    /// Return the final parentless SHA-1 root commit in lowercase hexadecimal.
    #[must_use]
    pub fn root_commit_oid(&self) -> String {
        lower_hex(&self.root_commit_oid)
    }

    #[cfg(target_os = "linux")]
    fn from_clean(authority: PublishedClean) -> Self {
        let audit = authority.audit();
        Self {
            worktree_files: audit.worktree_files(),
            encrypted_markdown: audit.encrypted_markdown(),
            encrypted_assets: audit.encrypted_assets(),
            git_objects: audit.git_objects(),
            root_commit_oid: audit.root_commit_oid(),
            authority,
        }
    }
}

impl fmt::Debug for PublishedRepositoryCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PublishedRepositoryCandidate");
        debug
            .field("worktree_files", &self.worktree_files)
            .field("encrypted_markdown", &self.encrypted_markdown)
            .field("encrypted_assets", &self.encrypted_assets)
            .field("git_objects", &self.git_objects)
            .field("root_commit_oid", &"[REDACTED]");
        #[cfg(target_os = "linux")]
        debug.field("authority", &self.authority);
        debug.finish()
    }
}

/// Read-only target-derived snapshot for an existing canonical v2 claim.
///
/// The existing-only lock and held marker remain live only while the complete
/// fresh audit and final role revalidation run. They are released before this
/// fixed summary is returned. This type carries no cleanup or forward
/// publication authority.
#[must_use]
pub struct ExistingRepositoryCandidatePreview {
    worktree_files: u32,
    encrypted_markdown: u32,
    encrypted_assets: u32,
    git_objects: u32,
    root_commit_oid: [u8; 20],
}

impl ExistingRepositoryCandidatePreview {
    /// Return the exact worktree-file count from the held fresh audit.
    #[must_use]
    pub const fn worktree_files(&self) -> u32 {
        self.worktree_files
    }

    /// Return the exact encrypted Markdown count from the held fresh audit.
    #[must_use]
    pub const fn encrypted_markdown(&self) -> u32 {
        self.encrypted_markdown
    }

    /// Return the exact encrypted asset count from the held fresh audit.
    #[must_use]
    pub const fn encrypted_assets(&self) -> u32 {
        self.encrypted_assets
    }

    /// Return the exact Git-object count from the held fresh audit.
    #[must_use]
    pub const fn git_objects(&self) -> u32 {
        self.git_objects
    }

    /// Return the audited parentless SHA-1 root commit in lowercase hexadecimal.
    #[must_use]
    pub fn root_commit_oid(&self) -> String {
        lower_hex(&self.root_commit_oid)
    }

    #[cfg(target_os = "linux")]
    fn from_published(published: &PublishedWithMarker) -> Self {
        let audit = published.audit();
        Self {
            worktree_files: audit.worktree_files(),
            encrypted_markdown: audit.encrypted_markdown(),
            encrypted_assets: audit.encrypted_assets(),
            git_objects: audit.git_objects(),
            root_commit_oid: audit.root_commit_oid(),
        }
    }
}

impl fmt::Debug for ExistingRepositoryCandidatePreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExistingRepositoryCandidatePreview")
            .field("worktree_files", &self.worktree_files)
            .field("encrypted_markdown", &self.encrypted_markdown)
            .field("encrypted_assets", &self.encrypted_assets)
            .field("git_objects", &self.git_objects)
            .field("root_commit_oid", &"[REDACTED]")
            .finish()
    }
}

/// Consume one audited initial candidate through the complete v2 publication
/// state machine.
///
/// The caller supplies only its already-bound target/vault evidence and the
/// sibling coordinates selected by the outer transaction. The publication id
/// and identity scheme are generated internally. The same mutation lock is
/// retained from initial authority acquisition through the returned success or
/// failure owner.
///
/// # Errors
///
/// Returns an opaque failure owner that retains any live publication authority
/// until the caller has emitted its terminal result and drops the value.
pub fn publish_initial_repository_candidate(
    staging_root: &Path,
    target: &TargetRepository,
    vault: &Vault,
    expected_profile: VaultContentProfile,
    common_parent_identity: &FilesystemDirectoryIdentity,
    destination_child_name: &str,
) -> Result<PublishedRepositoryCandidate, RepositoryCandidatePublicationFailure> {
    #[cfg(target_os = "linux")]
    {
        let context = CandidateSealContext {
            scheme: PublicationIdentityScheme::LinuxDevInodeV1,
            publication_id: *Uuid::new_v4().as_bytes(),
        };
        let authority = acquire_initial_candidate_authority(
            staging_root,
            target,
            vault,
            expected_profile,
            context,
        )
        .map_err(|_| {
            RepositoryCandidatePublicationFailure::retained(
                RepositoryCandidatePublicationFailureKind::InitialAuthorityRejected,
                RetainedPublicationOwner::None,
            )
        })?;
        let claim = claim_initial_candidate(
            authority,
            InitialCandidateClaimInput {
                common_parent_identity,
                destination_child_name,
            },
        )
        .map_err(|error| {
            RepositoryCandidatePublicationFailure::retained(
                RepositoryCandidatePublicationFailureKind::InitialClaimRejected,
                RetainedPublicationOwner::InitialClaim(Box::new(error)),
            )
        })?;
        let published = drive_initial_publication(claim)?;
        let durable = drive_publication_durability(published)?;
        let clean_pending = drive_marker_cleanup(durable)?;
        drive_clean_audit(clean_pending).map(PublishedRepositoryCandidate::from_clean)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            staging_root,
            target,
            vault,
            expected_profile,
            common_parent_identity,
            destination_child_name,
        );
        Err(RepositoryCandidatePublicationFailure::unsupported())
    }
}

/// Reconcile one existing canonical v2 repository publication claim.
///
/// This target-only path accepts no source repository, password, vault, KDF,
/// candidate seed, or caller-provided seal. Linux opens the pre-existing lock
/// and marker through the fused existing-only guard, rebuilds the complete
/// target audit, confirms publication durability, removes only the exact held
/// marker, synchronizes its parent, and performs the marker-free clean audit.
///
/// # Errors
///
/// Returns an opaque failure owner that retains any acquired publication
/// authority until the caller has emitted its terminal result and drops it.
pub fn reconcile_existing_repository_candidate(
    destination_root: &Path,
    common_parent_identity: &FilesystemDirectoryIdentity,
    destination_child_name: &str,
) -> Result<PublishedRepositoryCandidate, RepositoryCandidatePublicationFailure> {
    #[cfg(target_os = "linux")]
    {
        let published = claim_fresh_existing_candidate(FreshExistingClaimInput {
            destination_root,
            common_parent_identity,
            destination_child_name,
        })
        .map_err(|error| {
            RepositoryCandidatePublicationFailure::retained(
                RepositoryCandidatePublicationFailureKind::ExistingClaimRejected,
                RetainedPublicationOwner::FreshClaim(Box::new(error)),
            )
        })?;
        let durable = drive_publication_durability(published)?;
        let clean_pending = drive_marker_cleanup(durable)?;
        drive_clean_audit(clean_pending).map(PublishedRepositoryCandidate::from_clean)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            destination_root,
            common_parent_identity,
            destination_child_name,
        );
        Err(RepositoryCandidatePublicationFailure::unsupported())
    }
}

/// Audit one existing canonical v2 claim without synchronizing or removing it.
///
/// The returned snapshot is target-derived and authority-free. Linux releases
/// the existing-only lock only after the full held audit and final published
/// role check complete. No source, password, KDF, vault unlock, staging,
/// synchronization, or cleanup operation is performed.
///
/// # Errors
///
/// Returns an opaque failure owner that retains any acquired authority until
/// the caller has emitted its terminal preview result and drops it.
pub fn preview_existing_repository_candidate(
    destination_root: &Path,
    common_parent_identity: &FilesystemDirectoryIdentity,
    destination_child_name: &str,
) -> Result<ExistingRepositoryCandidatePreview, RepositoryCandidatePublicationFailure> {
    #[cfg(target_os = "linux")]
    {
        let published = claim_fresh_existing_candidate(FreshExistingClaimInput {
            destination_root,
            common_parent_identity,
            destination_child_name,
        })
        .map_err(|error| {
            RepositoryCandidatePublicationFailure::retained(
                RepositoryCandidatePublicationFailureKind::ExistingClaimRejected,
                RetainedPublicationOwner::FreshClaim(Box::new(error)),
            )
        })?;
        let preview = ExistingRepositoryCandidatePreview::from_published(&published);
        drop(published);
        Ok(preview)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            destination_root,
            common_parent_identity,
            destination_child_name,
        );
        Err(RepositoryCandidatePublicationFailure::unsupported())
    }
}

#[cfg(target_os = "linux")]
fn drive_initial_publication(
    claim: super::candidate_initial_authority::StagingAuditedClaim,
) -> Result<PublishedWithMarker, RepositoryCandidatePublicationFailure> {
    let mut outcome = publish_initial_candidate(claim);
    for attempt in 1..=SAME_PROCESS_ATTEMPTS {
        match outcome {
            InitialCandidatePublishOutcome::Published(owner) => return Ok(owner),
            InitialCandidatePublishOutcome::Terminal(owner) => {
                let kind = match owner.failure() {
                    InitialCandidatePublishFailure::DestinationExists => {
                        RepositoryCandidatePublicationFailureKind::DestinationExists
                    }
                    InitialCandidatePublishFailure::IndeterminateMove
                    | InitialCandidatePublishFailure::PublishedCleanupFailed => {
                        RepositoryCandidatePublicationFailureKind::PublicationIndeterminate
                    }
                    _ => RepositoryCandidatePublicationFailureKind::InitialPublicationRejected,
                };
                return Err(RepositoryCandidatePublicationFailure::retained(
                    kind,
                    RetainedPublicationOwner::InitialTerminal(owner),
                ));
            }
            InitialCandidatePublishOutcome::NotMoved(owner) if attempt < SAME_PROCESS_ATTEMPTS => {
                outcome = owner.retry();
            }
            InitialCandidatePublishOutcome::NotMoved(owner) => {
                return Err(RepositoryCandidatePublicationFailure::retained(
                    RepositoryCandidatePublicationFailureKind::InitialPublicationNotMoved,
                    RetainedPublicationOwner::InitialRetry(owner),
                ));
            }
        }
    }
    unreachable!("the bounded initial-publication loop always returns")
}

#[cfg(target_os = "linux")]
fn drive_publication_durability(
    published: PublishedWithMarker,
) -> Result<PublicationDurableWithMarker, RepositoryCandidatePublicationFailure> {
    let mut outcome = published.synchronize();
    for attempt in 1..=SAME_PROCESS_ATTEMPTS {
        match outcome {
            PublicationDurabilityOutcome::Durable(owner) => return Ok(owner),
            PublicationDurabilityOutcome::Terminal(owner) => {
                return Err(RepositoryCandidatePublicationFailure::retained(
                    RepositoryCandidatePublicationFailureKind::PublicationDurabilityRejected,
                    RetainedPublicationOwner::DurabilityTerminal(owner),
                ));
            }
            PublicationDurabilityOutcome::Retryable(owner) if attempt < SAME_PROCESS_ATTEMPTS => {
                outcome = owner.retry();
            }
            PublicationDurabilityOutcome::Retryable(owner) => {
                return Err(RepositoryCandidatePublicationFailure::retained(
                    RepositoryCandidatePublicationFailureKind::PublicationDurabilityIndeterminate,
                    RetainedPublicationOwner::DurabilityRetry(owner),
                ));
            }
        }
    }
    unreachable!("the bounded durability loop always returns")
}

#[cfg(target_os = "linux")]
fn drive_marker_cleanup(
    durable: PublicationDurableWithMarker,
) -> Result<CleanAuditPending, RepositoryCandidatePublicationFailure> {
    let mut outcome = durable.unlink_marker();
    for attempt in 1..=SAME_PROCESS_ATTEMPTS {
        match outcome {
            PublicationMarkerUnlinkOutcome::CleanAuditPending(owner) => return Ok(owner),
            PublicationMarkerUnlinkOutcome::ParentSyncPending(owner) => {
                return drive_parent_sync(owner);
            }
            PublicationMarkerUnlinkOutcome::Terminal(owner) => {
                return Err(marker_terminal_failure(owner));
            }
            PublicationMarkerUnlinkOutcome::NotRemoved(owner)
                if attempt < SAME_PROCESS_ATTEMPTS =>
            {
                outcome = owner.unlink_marker();
            }
            PublicationMarkerUnlinkOutcome::NotRemoved(owner) => {
                return Err(RepositoryCandidatePublicationFailure::retained(
                    RepositoryCandidatePublicationFailureKind::PublicationMarkerRetained,
                    RetainedPublicationOwner::MarkerRetained(owner),
                ));
            }
        }
    }
    unreachable!("the bounded marker-cleanup loop always returns")
}

#[cfg(target_os = "linux")]
fn drive_parent_sync(
    pending: ParentSyncPending,
) -> Result<CleanAuditPending, RepositoryCandidatePublicationFailure> {
    let mut outcome = pending.retry_parent_sync();
    for attempt in 1..=SAME_PROCESS_ATTEMPTS {
        match outcome {
            PublicationParentSyncOutcome::CleanAuditPending(owner) => return Ok(owner),
            PublicationParentSyncOutcome::Terminal(owner) => {
                return Err(marker_terminal_failure(owner));
            }
            PublicationParentSyncOutcome::ParentSyncPending(owner)
                if attempt < SAME_PROCESS_ATTEMPTS =>
            {
                outcome = owner.retry_parent_sync();
            }
            PublicationParentSyncOutcome::ParentSyncPending(owner) => {
                return Err(RepositoryCandidatePublicationFailure::retained(
                    RepositoryCandidatePublicationFailureKind::PostUnlinkIndeterminate,
                    RetainedPublicationOwner::ParentSyncRetry(owner),
                ));
            }
        }
    }
    unreachable!("the bounded marker-parent loop always returns")
}

#[cfg(target_os = "linux")]
fn marker_terminal_failure(
    owner: Box<FailedPublicationMarkerUnlink>,
) -> RepositoryCandidatePublicationFailure {
    let kind = match owner.failure() {
        PublicationMarkerUnlinkFailure::ReplacementRetained
        | PublicationMarkerUnlinkFailure::ParentSyncReplacementRetained => {
            RepositoryCandidatePublicationFailureKind::PublicationMarkerReplaced
        }
        PublicationMarkerUnlinkFailure::PostStateIndeterminate
        | PublicationMarkerUnlinkFailure::ParentSyncPostStateIndeterminate => {
            RepositoryCandidatePublicationFailureKind::PublicationMarkerPostStateIndeterminate
        }
        PublicationMarkerUnlinkFailure::PreUnlinkReview(_)
        | PublicationMarkerUnlinkFailure::NotRemovedReview(_) => {
            RepositoryCandidatePublicationFailureKind::PublicationDurabilityRejected
        }
    };
    RepositoryCandidatePublicationFailure::retained(
        kind,
        RetainedPublicationOwner::MarkerTerminal(owner),
    )
}

#[cfg(target_os = "linux")]
fn drive_clean_audit(
    pending: CleanAuditPending,
) -> Result<PublishedClean, RepositoryCandidatePublicationFailure> {
    let mut outcome = pending.audit_clean();
    for attempt in 1..=SAME_PROCESS_ATTEMPTS {
        match outcome {
            CleanAuditOutcome::PublishedClean(owner) => return Ok(owner),
            CleanAuditOutcome::Terminal(owner) => {
                let kind = clean_terminal_kind(owner.failure());
                return Err(RepositoryCandidatePublicationFailure::retained(
                    kind,
                    RetainedPublicationOwner::CleanTerminal(owner),
                ));
            }
            CleanAuditOutcome::Retryable(owner) if attempt < SAME_PROCESS_ATTEMPTS => {
                outcome = owner.audit_clean();
            }
            CleanAuditOutcome::Retryable(owner) => {
                return Err(RepositoryCandidatePublicationFailure::retained(
                    RepositoryCandidatePublicationFailureKind::PostUnlinkIndeterminate,
                    RetainedPublicationOwner::CleanRetry(owner),
                ));
            }
        }
    }
    unreachable!("the bounded clean-audit loop always returns")
}

#[cfg(target_os = "linux")]
fn clean_terminal_kind(
    failure: &CleanAuditTerminalFailure,
) -> RepositoryCandidatePublicationFailureKind {
    match failure {
        CleanAuditTerminalFailure::AuditFailedAndAuthorityLost {
            authority: PostUnlinkPublicationMarkerV2Error::NamespaceConflict,
            ..
        }
        | CleanAuditTerminalFailure::FinalAuthority(
            PostUnlinkPublicationMarkerV2Error::NamespaceConflict,
        ) => RepositoryCandidatePublicationFailureKind::PublicationMarkerReplaced,
        CleanAuditTerminalFailure::AuditFailedAndAuthorityLost { .. }
        | CleanAuditTerminalFailure::SummaryMismatch(_)
        | CleanAuditTerminalFailure::FinalAuthority(_) => {
            RepositoryCandidatePublicationFailureKind::CleanAuditRejected
        }
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_oid_projection_is_exact() {
        assert_eq!(lower_hex(&[0x00, 0x09, 0x10, 0xab, 0xff]), "000910abff");
    }

    #[test]
    fn public_owner_source_contract_is_linear_and_authority_last() {
        let source = include_str!("candidate_transaction.rs");
        let published = source
            .split("pub struct PublishedRepositoryCandidate")
            .nth(1)
            .and_then(|tail| tail.split("impl PublishedRepositoryCandidate").next())
            .expect("published owner exists");
        assert!(!published.contains("derive(Clone"));
        assert!(!published.contains("derive(Copy"));
        assert!(
            published.find("root_commit_oid:").expect("summary field")
                < published.find("authority:").expect("authority field")
        );
        let implementation = source
            .split("impl PublishedRepositoryCandidate")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for PublishedRepositoryCandidate")
                    .next()
            })
            .expect("published implementation exists");
        for forbidden in ["into_parts", "authority(", "unlink", "sync", "marker"] {
            assert!(
                !implementation.contains(forbidden),
                "public escalation: {forbidden}"
            );
        }
    }

    #[test]
    fn composition_order_and_retry_bound_are_frozen() {
        assert_eq!(SAME_PROCESS_ATTEMPTS, 3);
        let source = include_str!("candidate_transaction.rs");
        let entry = source
            .split("pub fn publish_initial_repository_candidate")
            .nth(1)
            .and_then(|tail| tail.split("fn drive_initial_publication").next())
            .expect("production entry exists");
        let authority = entry
            .find("acquire_initial_candidate_authority(")
            .expect("authority");
        let claim = entry.find("claim_initial_candidate(").expect("claim");
        let publication = entry
            .find("drive_initial_publication(claim)")
            .expect("publication");
        let durability = entry
            .find("drive_publication_durability(published)")
            .expect("durability");
        let cleanup = entry
            .find("drive_marker_cleanup(durable)")
            .expect("cleanup");
        let clean = entry
            .find("drive_clean_audit(clean_pending)")
            .expect("clean");
        assert!(authority < claim && claim < publication && publication < durability);
        assert!(durability < cleanup && cleanup < clean);
        assert!(!entry.contains("atomic_publish_directory_no_replace_checked"));
        assert!(!entry.contains("IMPORT_PUBLISH_MARKER_V1"));

        let reconcile = source
            .split("pub fn reconcile_existing_repository_candidate")
            .nth(1)
            .and_then(|tail| {
                tail.split("/// Audit one existing canonical v2 claim")
                    .next()
            })
            .expect("fresh reconcile entry exists");
        let claim = reconcile
            .find("claim_fresh_existing_candidate(")
            .expect("fresh claim");
        let durability = reconcile
            .find("drive_publication_durability(published)")
            .expect("fresh durability");
        let cleanup = reconcile
            .find("drive_marker_cleanup(durable)")
            .expect("fresh cleanup");
        let clean = reconcile
            .find("drive_clean_audit(clean_pending)")
            .expect("fresh clean audit");
        assert!(claim < durability && durability < cleanup && cleanup < clean);
        for forbidden in ["source", "password", "Vault", "Kdf", "TargetRepository"] {
            assert!(
                !reconcile.contains(forbidden),
                "fresh reconcile accepts forbidden authority: {forbidden}"
            );
        }

        let preview = source
            .split("pub fn preview_existing_repository_candidate")
            .nth(1)
            .and_then(|tail| tail.split("fn drive_initial_publication").next())
            .expect("fresh preview entry exists");
        assert!(preview.contains("claim_fresh_existing_candidate("));
        assert!(preview.contains("drop(published);"));
        for forbidden in [
            "drive_publication_durability",
            "drive_marker_cleanup",
            "drive_clean_audit",
            ".synchronize(",
            ".unlink_marker(",
        ] {
            assert!(
                !preview.contains(forbidden),
                "fresh preview gained mutation authority: {forbidden}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_reconcile_reaches_clean_and_holds_the_lock_until_drop() {
        use inex_core::atomic::IMPORT_PUBLISH_MARKER_V2;

        let fixture =
            super::super::candidate_publication_authority::tests::fixture("transaction-reconcile");
        let (destination, parent_identity, child_name) = fixture.coordinates();
        let reconciled =
            reconcile_existing_repository_candidate(destination, parent_identity, child_name)
                .unwrap_or_else(|error| panic!("fresh reconcile failed: {error:?}"));
        let (worktree, markdown, assets, objects) = fixture.expected_counts();
        assert_eq!(reconciled.worktree_files(), worktree);
        assert_eq!(reconciled.encrypted_markdown(), markdown);
        assert_eq!(reconciled.encrypted_assets(), assets);
        assert_eq!(reconciled.git_objects(), objects);
        assert_eq!(
            reconciled.root_commit_oid(),
            lower_hex(&fixture.expected_root_commit_oid())
        );
        assert!(
            !destination
                .join(inex_core::atomic::VAULT_LOCAL_DIRECTORY)
                .join(IMPORT_PUBLISH_MARKER_V2)
                .exists()
        );
        fixture.assert_lock_busy();
        drop(reconciled);
        fixture.assert_lock_available();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_preview_audits_without_removing_the_marker() {
        let fixture =
            super::super::candidate_publication_authority::tests::fixture("transaction-preview");
        let (destination, parent_identity, child_name) = fixture.coordinates();
        let preview =
            preview_existing_repository_candidate(destination, parent_identity, child_name)
                .unwrap_or_else(|error| panic!("fresh preview failed: {error:?}"));
        let (worktree, markdown, assets, objects) = fixture.expected_counts();
        assert_eq!(preview.worktree_files(), worktree);
        assert_eq!(preview.encrypted_markdown(), markdown);
        assert_eq!(preview.encrypted_assets(), assets);
        assert_eq!(preview.git_objects(), objects);
        assert_eq!(
            preview.root_commit_oid(),
            lower_hex(&fixture.expected_root_commit_oid())
        );
        fixture.assert_marker_unchanged();
        fixture.assert_lock_available();
    }
}
