use std::ffi::OsStr;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::*;

const CONTROL_FILE: &str = "v5-force-kill-control.json";
const CONTROL_STAGING_FILE: &str = "v5-force-kill-control.staging";
const WRITER_READY_FILE: &str = "v5-force-kill-writer.ready";
const WRITER_READY_STAGING_FILE: &str = "v5-force-kill-writer.ready.staging";
const WRITER_ARMED_FILE: &str = "v5-force-kill-writer.armed";
const WRITER_ARMED_STAGING_FILE: &str = "v5-force-kill-writer.armed.staging";
const RECOVERY_FIRST_READY_FILE: &str = "v5-force-kill-recovery-first.ready";
const RECOVERY_FIRST_READY_STAGING_FILE: &str =
    "v5-force-kill-recovery-first.ready.staging";
const RECOVERY_SECOND_READY_FILE: &str = "v5-force-kill-recovery-second.ready";
const RECOVERY_SECOND_READY_STAGING_FILE: &str =
    "v5-force-kill-recovery-second.ready.staging";
const LATER_UNRELATED_PATH: &str = "later-force-kill-unrelated.bin";
const LATER_UNRELATED_BYTES: &[u8] = b"independent encrypted-owner sentinel\n";
const CHILD_TIMEOUT: Duration = Duration::from_secs(45);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ForceKillTarget {
    CandidateScratchCreated,
    CandidateCopied,
    CandidateMutated,
    CandidateManifestWritten,
    CandidateBeforePublish,
    CandidateCriticalAudit,
    CandidateAfterPublish,
    PublishScratchCreated,
    PublishCandidateCopied,
    PublishBeforePublish,
    PublishCriticalAudit,
    PublishAfterPublish,
    MarkerScratchCreated,
    MarkerWritten,
    MarkerBeforeMove,
    MarkerCriticalAudit,
    MarkerAfterMove,
    MarkerPostAudit,
    JournalScratchCreated,
    JournalWritten,
    JournalBeforeMove,
    JournalCriticalAudit,
    JournalAfterMove,
    JournalPostAudit,
    WorktreeOneOfOne,
    WorktreeOneOfTwo,
    WorktreeTwoOfTwo,
    PostBeforePublishOverMarker,
    PostAfterPublishOverMarker,
    PostBeforePublishOverIndex,
    PostAfterPublishOverIndex,
    PostAfterInitialLiveIndexClassification,
    PostAfterFinalLiveIndexClassification,
    CleanupFullJ,
    CleanupFullR,
    CleanupManifestR,
    CleanupEmptyR,
    ReceiptOnly,
    Clean,
}

impl ForceKillTarget {
    fn matches_composite_checkpoint(self, checkpoint: V5WriterCheckpoint) -> bool {
        matches!(
            (self, checkpoint),
            (
                Self::WorktreeOneOfOne,
                V5WriterCheckpoint::WorktreeMutation {
                    completed: 1,
                    total: 1,
                }
            ) | (
                Self::WorktreeOneOfTwo,
                V5WriterCheckpoint::WorktreeMutation {
                    completed: 1,
                    total: 2,
                }
            ) | (
                Self::WorktreeTwoOfTwo,
                V5WriterCheckpoint::WorktreeMutation {
                    completed: 2,
                    total: 2,
                }
            ) | (
                Self::PostAfterFinalLiveIndexClassification,
                V5WriterCheckpoint::LiveIndexPublished
            ) | (
                Self::CleanupFullJ,
                V5WriterCheckpoint::CleanupAdvanced(V5CleanupState::CleanupFullJ)
            ) | (
                Self::CleanupFullR,
                V5WriterCheckpoint::CleanupAdvanced(V5CleanupState::CleanupFullR)
            ) | (
                Self::CleanupManifestR,
                V5WriterCheckpoint::CleanupAdvanced(V5CleanupState::CleanupManifestR)
            ) | (
                Self::CleanupEmptyR,
                V5WriterCheckpoint::CleanupAdvanced(V5CleanupState::CleanupEmptyR)
            ) | (
                Self::ReceiptOnly,
                V5WriterCheckpoint::CleanupAdvanced(V5CleanupState::ReceiptOnly)
            ) | (
                Self::Clean,
                V5WriterCheckpoint::CleanupAdvanced(V5CleanupState::Clean)
            )
        )
    }

    fn expects_pending_recovery(self) -> bool {
        !matches!(
            self,
            Self::CandidateScratchCreated
                | Self::CandidateCopied
                | Self::CandidateMutated
                | Self::CandidateManifestWritten
                | Self::CandidateBeforePublish
                | Self::CandidateCriticalAudit
                | Self::Clean
        )
    }

    fn retained_scratch_after_recovery(self) -> usize {
        usize::from(matches!(
            self,
            Self::CandidateScratchCreated
                | Self::CandidateCopied
                | Self::CandidateMutated
                | Self::CandidateManifestWritten
                | Self::CandidateBeforePublish
                | Self::CandidateCriticalAudit
                | Self::PublishScratchCreated
                | Self::PublishCandidateCopied
                | Self::PublishBeforePublish
                | Self::PublishCriticalAudit
                | Self::MarkerScratchCreated
                | Self::MarkerWritten
                | Self::MarkerBeforeMove
                | Self::MarkerCriticalAudit
                | Self::JournalScratchCreated
                | Self::JournalWritten
                | Self::JournalBeforeMove
                | Self::JournalCriticalAudit
        ))
    }

    fn is_pre_stable(self) -> bool {
        !self.expects_pending_recovery() && self != Self::Clean
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ForceKillScenario {
    target: ForceKillTarget,
    later_unrelated: bool,
}

impl ForceKillScenario {
    fn validate(&self) {
        assert!(
            !self.later_unrelated
                || self.target == ForceKillTarget::PostAfterFinalLiveIndexClassification,
            "LaterUnrelated is valid only after live-index publication"
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ForceKillControl {
    version: u32,
    nonce: String,
    object_format: GitObjectFormat,
    payload_sha256: String,
    vault_root: PathBuf,
    payload: MergeJournalPayload,
    scenario: ForceKillScenario,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ChildRole {
    Writer,
    WriterArmed,
    RecoveryFirst,
    RecoverySecond,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadyRecord {
    version: u32,
    nonce: String,
    pid: u32,
    role: ChildRole,
    scenario: ForceKillScenario,
    object_format: GitObjectFormat,
    payload_sha256: String,
    vault_root: PathBuf,
}

struct ForceKillWriterHooks {
    ready_path: PathBuf,
    armed_path: PathBuf,
    ready: ReadyRecord,
}

impl ForceKillWriterHooks {
    fn stop(&self) -> ! {
        write_ready(&self.ready_path, &self.ready)
            .expect("writer readiness publishes durably");
        let mut armed = self.ready.clone();
        armed.role = ChildRole::WriterArmed;
        write_ready(&self.armed_path, &armed).expect("post-sync writer ACK publishes");
        park_forever();
    }
}

impl V5WriterHooks for ForceKillWriterHooks {
    fn checkpoint(
        &mut self,
        checkpoint: V5WriterCheckpoint,
        context: &V5WriterContext<'_>,
    ) -> Result<(), GitError> {
        if !self
            .ready
            .scenario
            .target
            .matches_composite_checkpoint(checkpoint)
            || (matches!(checkpoint, V5WriterCheckpoint::LiveIndexPublished)
                && !self.ready.scenario.later_unrelated)
        {
            return Ok(());
        }
        if self.ready.scenario.later_unrelated {
            assert_eq!(
                self.ready.scenario.target,
                ForceKillTarget::PostAfterFinalLiveIndexClassification
            );
            fs::write(
                context.vault.root().join(LATER_UNRELATED_PATH),
                LATER_UNRELATED_BYTES,
            )
            .expect("later-unrelated worktree sentinel writes");
            assert!(test_git(
                context.vault.root(),
                ["add", LATER_UNRELATED_PATH]
            ));
            assert_eq!(
                inspect_v5_postjournal_state(context.guard, context.vault.root())
                    .expect("later-unrelated post-journal state inspects"),
                Some(V5PostJournalState::LaterUnrelated)
            );
        }
        self.stop();
    }
}

struct ComponentForceKillHooks<'a> {
    writer: &'a ForceKillWriterHooks,
}

impl ComponentForceKillHooks<'_> {
    fn stop_if(&self, target: ForceKillTarget) {
        if self.writer.ready.scenario.target == target {
            self.writer.stop();
        }
    }
}

impl candidate_bundle_v5::CandidateBundlePrepareHooksV5 for ComponentForceKillHooks<'_> {
    fn next_token(&mut self) -> String {
        Uuid::new_v4().simple().to_string()
    }

    fn checkpoint(
        &mut self,
        checkpoint: candidate_bundle_v5::CandidateBundlePrepareCheckpointV5,
        _context: &candidate_bundle_v5::CandidateBundlePrepareContextV5<'_>,
    ) -> Result<(), GitError> {
        let target = match checkpoint {
            candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::ScratchCreated => {
                ForceKillTarget::CandidateScratchCreated
            }
            candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::CandidateCopied => {
                ForceKillTarget::CandidateCopied
            }
            candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::CandidateMutated => {
                ForceKillTarget::CandidateMutated
            }
            candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::ManifestWritten => {
                ForceKillTarget::CandidateManifestWritten
            }
            candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::BeforePublish => {
                ForceKillTarget::CandidateBeforePublish
            }
            candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::CriticalAudit => {
                ForceKillTarget::CandidateCriticalAudit
            }
            candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::AfterPublish => {
                ForceKillTarget::CandidateAfterPublish
            }
        };
        self.stop_if(target);
        Ok(())
    }
}

impl candidate_bundle_v5::CandidatePublishStagingHooksV5 for ComponentForceKillHooks<'_> {
    fn next_token(&mut self) -> String {
        Uuid::new_v4().simple().to_string()
    }

    fn checkpoint(
        &mut self,
        checkpoint: candidate_bundle_v5::CandidatePublishStagingCheckpointV5,
        _context: &candidate_bundle_v5::CandidatePublishStagingContextV5<'_>,
    ) -> Result<(), GitError> {
        let target = match checkpoint {
            candidate_bundle_v5::CandidatePublishStagingCheckpointV5::ScratchCreated => {
                ForceKillTarget::PublishScratchCreated
            }
            candidate_bundle_v5::CandidatePublishStagingCheckpointV5::CandidateCopied => {
                ForceKillTarget::PublishCandidateCopied
            }
            candidate_bundle_v5::CandidatePublishStagingCheckpointV5::BeforePublish => {
                ForceKillTarget::PublishBeforePublish
            }
            candidate_bundle_v5::CandidatePublishStagingCheckpointV5::CriticalAudit => {
                ForceKillTarget::PublishCriticalAudit
            }
            candidate_bundle_v5::CandidatePublishStagingCheckpointV5::AfterPublish => {
                ForceKillTarget::PublishAfterPublish
            }
        };
        self.stop_if(target);
        Ok(())
    }
}

impl candidate_bundle_v5::IndexLockMarkerHooksV5 for ComponentForceKillHooks<'_> {
    fn next_token(&mut self) -> String {
        Uuid::new_v4().simple().to_string()
    }

    fn checkpoint(
        &mut self,
        checkpoint: candidate_bundle_v5::IndexLockMarkerCheckpointV5,
        _context: &candidate_bundle_v5::IndexLockMarkerContextV5<'_>,
    ) -> Result<(), GitError> {
        let target = match checkpoint {
            candidate_bundle_v5::IndexLockMarkerCheckpointV5::ScratchCreated => {
                ForceKillTarget::MarkerScratchCreated
            }
            candidate_bundle_v5::IndexLockMarkerCheckpointV5::MarkerWritten => {
                ForceKillTarget::MarkerWritten
            }
            candidate_bundle_v5::IndexLockMarkerCheckpointV5::BeforeMove => {
                ForceKillTarget::MarkerBeforeMove
            }
            candidate_bundle_v5::IndexLockMarkerCheckpointV5::CriticalAudit => {
                ForceKillTarget::MarkerCriticalAudit
            }
            candidate_bundle_v5::IndexLockMarkerCheckpointV5::AfterMove => {
                ForceKillTarget::MarkerAfterMove
            }
            candidate_bundle_v5::IndexLockMarkerCheckpointV5::PostAudit => {
                ForceKillTarget::MarkerPostAudit
            }
        };
        self.stop_if(target);
        Ok(())
    }
}

impl DurableJournalHooksV5 for ComponentForceKillHooks<'_> {
    fn next_token(&mut self) -> String {
        Uuid::new_v4().simple().to_string()
    }

    fn checkpoint(
        &mut self,
        checkpoint: DurableJournalCheckpointV5,
        _context: &DurableJournalContextV5<'_>,
    ) -> Result<(), GitError> {
        let target = match checkpoint {
            DurableJournalCheckpointV5::ScratchCreated => {
                ForceKillTarget::JournalScratchCreated
            }
            DurableJournalCheckpointV5::JournalWritten => ForceKillTarget::JournalWritten,
            DurableJournalCheckpointV5::BeforeMove => ForceKillTarget::JournalBeforeMove,
            DurableJournalCheckpointV5::CriticalAudit => ForceKillTarget::JournalCriticalAudit,
            DurableJournalCheckpointV5::AfterMove => ForceKillTarget::JournalAfterMove,
            DurableJournalCheckpointV5::PostAudit => ForceKillTarget::JournalPostAudit,
        };
        self.stop_if(target);
        Ok(())
    }
}

impl candidate_bundle_v5::PostJournalIndexHooksV5 for ComponentForceKillHooks<'_> {
    fn checkpoint(
        &mut self,
        checkpoint: candidate_bundle_v5::PostJournalIndexCheckpointV5,
        _context: &candidate_bundle_v5::PostJournalIndexContextV5<'_>,
    ) -> Result<(), GitError> {
        let target = match checkpoint {
            candidate_bundle_v5::PostJournalIndexCheckpointV5::BeforePublishOverMarker => {
                ForceKillTarget::PostBeforePublishOverMarker
            }
            candidate_bundle_v5::PostJournalIndexCheckpointV5::AfterPublishOverMarker => {
                ForceKillTarget::PostAfterPublishOverMarker
            }
            candidate_bundle_v5::PostJournalIndexCheckpointV5::BeforePublishOverIndex => {
                ForceKillTarget::PostBeforePublishOverIndex
            }
            candidate_bundle_v5::PostJournalIndexCheckpointV5::AfterPublishOverIndex => {
                ForceKillTarget::PostAfterPublishOverIndex
            }
            candidate_bundle_v5::PostJournalIndexCheckpointV5::AfterInitialLiveIndexClassification => {
                ForceKillTarget::PostAfterInitialLiveIndexClassification
            }
            candidate_bundle_v5::PostJournalIndexCheckpointV5::AfterFinalLiveIndexClassification => {
                ForceKillTarget::PostAfterFinalLiveIndexClassification
            }
        };
        if !self.writer.ready.scenario.later_unrelated {
            self.stop_if(target);
        }
        Ok(())
    }
}

fn park_forever() -> ! {
    loop {
        thread::park();
    }
}

fn write_atomic_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("control path has no parent"))?;
    let staging_name = match path.file_name().and_then(OsStr::to_str) {
        Some(WRITER_READY_FILE) => WRITER_READY_STAGING_FILE,
        Some(WRITER_ARMED_FILE) => WRITER_ARMED_STAGING_FILE,
        Some(RECOVERY_FIRST_READY_FILE) => RECOVERY_FIRST_READY_STAGING_FILE,
        Some(RECOVERY_SECOND_READY_FILE) => RECOVERY_SECOND_READY_STAGING_FILE,
        Some(CONTROL_FILE) => CONTROL_STAGING_FILE,
        _ => return Err(io::Error::other("unexpected force-kill control path")),
    };
    let staging = parent.join(staging_name);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    let staged_file = File::open(&staging)?;
    let outcome = atomic_move_verified_file_no_replace(&staging, &staged_file, path)?;
    drop(staged_file);
    if outcome.source_parent_sync != ParentSyncStatus::Synced
        || outcome.destination_parent_sync != ParentSyncStatus::Synced
    {
        return Err(io::Error::other(
            "force-kill publication parent sync was not confirmed",
        ));
    }
    sync_directory(parent)
}

fn write_ready(path: &Path, ready: &ReadyRecord) -> io::Result<()> {
    let bytes = serde_json::to_vec(ready).map_err(io::Error::other)?;
    write_atomic_synced(path, &bytes)
}

fn read_control() -> Option<ForceKillControl> {
    let path = std::env::current_dir()
        .expect("force-kill child current directory resolves")
        .join(CONTROL_FILE);
    if !path.exists() {
        return None;
    }
    let bytes = fs::read(path).expect("force-kill control reads");
    let control: ForceKillControl =
        serde_json::from_slice(&bytes).expect("force-kill control parses strictly");
    validate_control(&control);
    Some(control)
}

fn validate_nonce(nonce: &str) {
    assert_eq!(nonce.len(), 32, "force-kill nonce length is canonical");
    assert!(
        nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "force-kill nonce is lowercase hexadecimal"
    );
    assert!(Uuid::parse_str(nonce).is_ok(), "force-kill nonce parses");
}

fn validate_control(control: &ForceKillControl) {
    assert_eq!(control.version, 1, "force-kill control version is exact");
    validate_nonce(&control.nonce);
    control.scenario.validate();
    assert_eq!(payload_object_format(&control.payload), control.object_format);
    assert_eq!(
        payload_sha256(&control.payload),
        control.payload_sha256,
        "force-kill payload digest binds canonical serialized payload"
    );
    assert!(control.vault_root.is_absolute());
    assert_eq!(
        fs::canonicalize(&control.vault_root).expect("controlled vault root canonicalizes"),
        control.vault_root,
        "controlled vault root uses canonical spelling"
    );
}

fn payload_object_format(payload: &MergeJournalPayload) -> GitObjectFormat {
    match payload {
        MergeJournalPayload::InPlace(journal) => match journal.result_oid.len() {
            40 => GitObjectFormat::Sha1,
            64 => GitObjectFormat::Sha256,
            length => panic!("force-kill payload has unsupported OID length {length}"),
        },
        MergeJournalPayload::Rename(journal) => journal.provenance.object_format,
        MergeJournalPayload::DetectedRename(journal) => journal.provenance.object_format,
    }
}

fn payload_sha256(payload: &MergeJournalPayload) -> String {
    let bytes = serde_json::to_vec(payload).expect("force-kill payload serializes canonically");
    hex_digest(digest(&bytes))
}

fn ready_record(control: &ForceKillControl, role: ChildRole) -> ReadyRecord {
    ready_record_for_pid(control, role, std::process::id())
}

fn ready_record_for_pid(control: &ForceKillControl, role: ChildRole, pid: u32) -> ReadyRecord {
    ReadyRecord {
        version: 1,
        nonce: control.nonce.clone(),
        pid,
        role,
        scenario: control.scenario.clone(),
        object_format: control.object_format,
        payload_sha256: control.payload_sha256.clone(),
        vault_root: control.vault_root.clone(),
    }
}

fn read_and_validate_ready(path: &Path, expected: &ReadyRecord) {
    let bytes = fs::read(path).expect("child readiness reads");
    let actual: ReadyRecord =
        serde_json::from_slice(&bytes).expect("child readiness parses strictly");
    validate_nonce(&actual.nonce);
    actual.scenario.validate();
    assert_eq!(actual, *expected, "child readiness binds the exact case");
}

fn read_and_validate_ready_ignoring_pid(path: &Path, expected: &ReadyRecord) {
    let bytes = fs::read(path).expect("prior child readiness reads");
    let mut actual: ReadyRecord =
        serde_json::from_slice(&bytes).expect("prior child readiness parses strictly");
    validate_nonce(&actual.nonce);
    actual.scenario.validate();
    actual.pid = 0;
    assert_eq!(actual, *expected, "prior readiness binds the exact case");
}

fn unlock_controlled_vault(control: &ForceKillControl) -> Vault {
    Vault::unlock(
        &control.vault_root,
        PASSWORD,
        None,
        KdfPolicy::default(),
    )
    .expect("force-kill child unlocks vault")
}

fn commit_payload_v5_force_kill_test(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    payload: &MergeJournalPayload,
    hooks: &mut ForceKillWriterHooks,
) -> Result<(), GitError> {
    if vault.root() != git.root || !guard.is_for_root(vault.root()) {
        return Err(GitError::RecoveryConflict);
    }
    let prepared = {
        let mut component = ComponentForceKillHooks { writer: hooks };
        candidate_bundle_v5::prepare_candidate_bundle_v5_with_hooks(
            guard,
            git,
            payload,
            &mut component,
        )?
    };
    if read_v5_prejournal_state_from_disk(guard, vault.root())?
        != Some(V5PreJournalState::StableOnly)
    {
        return Err(GitError::RecoveryConflict);
    }
    let context = V5WriterContext { vault, git, guard };
    hooks.checkpoint(V5WriterCheckpoint::CandidatePrepared, &context)?;

    let publish = {
        let mut component = ComponentForceKillHooks { writer: hooks };
        candidate_bundle_v5::prepare_candidate_publish_staging_v5_with_hooks(
            guard,
            git,
            &prepared.transaction_reference,
            &prepared.inventory,
            &mut component,
        )?
    };
    if read_v5_prejournal_state_from_disk(guard, vault.root())?
        != Some(V5PreJournalState::PublishReady)
    {
        return Err(GitError::RecoveryConflict);
    }
    hooks.checkpoint(V5WriterCheckpoint::PublishPrepared, &context)?;

    let marker = {
        let mut component = ComponentForceKillHooks { writer: hooks };
        candidate_bundle_v5::acquire_index_lock_marker_v5_with_hooks(
            guard,
            git,
            &prepared.transaction_reference,
            &prepared.inventory,
            &publish,
            &mut component,
        )?
    };
    if read_v5_prejournal_state_from_disk(guard, vault.root())?
        != Some(V5PreJournalState::MarkerNoJournal)
    {
        return Err(GitError::RecoveryConflict);
    }
    hooks.checkpoint(V5WriterCheckpoint::MarkerAcquired, &context)?;

    {
        let mut component = ComponentForceKillHooks { writer: hooks };
        publish_durable_journal_v5_with_hooks(
            vault,
            git,
            guard,
            &prepared.transaction_reference,
            &prepared.inventory,
            &publish,
            &marker,
            &mut component,
        )?;
    }
    if read_v5_prejournal_state_from_disk(guard, vault.root())?
        != Some(V5PreJournalState::JournalReady)
    {
        return Err(GitError::RecoveryConflict);
    }
    hooks.checkpoint(V5WriterCheckpoint::JournalPublished, &context)?;
    drop(marker);
    drop(publish);
    drop(prepared);

    recover_postjournal_force_kill_test(vault, git, guard, hooks)?;
    advance_v5_cleanup_to_clean_with_hooks(vault, git, guard, hooks)?;
    if inspect_held_v5_cleanup_state(vault.root())?.kind() != V5CleanupState::Clean {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn recover_postjournal_force_kill_test(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    hooks: &mut ForceKillWriterHooks,
) -> Result<(), GitError> {
    let reference = load_v5_reference_from_disk(vault.root())?;
    let held_journal = load_held_bundle_journal_v5(vault.root(), &reference)?;
    let payload = v5_payload_from_reference(vault.root(), &reference)?;
    if inspect_v5_postjournal_state(guard, vault.root())?
        != Some(V5PostJournalState::JournalReady)
    {
        return Err(GitError::RecoveryConflict);
    }
    revalidate_held_bundle_journal_v5(vault.root(), &held_journal)?;
    prepare_payload_worktree_for_v5_index_with_hooks(vault, git, guard, &payload, hooks)?;
    revalidate_held_bundle_journal_v5(vault.root(), &held_journal)?;
    let loaded = candidate_bundle_v5::load_candidate_publish_staging_with_journal_v5(
        guard, git, &reference,
    )?;
    let marker = candidate_bundle_v5::load_acquired_index_lock_marker_with_journal_v5(
        guard,
        git,
        &reference,
        &loaded.inventory,
        &loaded.staging,
    )?;
    verify_payload_ready_for_v5_index(vault, git, guard, &payload)?;
    revalidate_held_bundle_journal_v5(vault.root(), &held_journal)?;
    {
        let authorization = candidate_bundle_v5::PostJournalIndexAuthorizationV5::new(
            &held_journal.file,
            || {
                revalidate_held_bundle_journal_v5(vault.root(), &held_journal)?;
                verify_payload_ready_for_v5_index(vault, git, guard, &payload)?;
                revalidate_held_bundle_journal_v5(vault.root(), &held_journal)
            },
        );
        let mut component = ComponentForceKillHooks { writer: hooks };
        candidate_bundle_v5::publish_staging_over_marker_with_journal_v5_with_hooks(
            guard,
            git,
            &reference,
            loaded,
            marker,
            authorization,
            &mut component,
        )?;
    }
    let context = V5WriterContext { vault, git, guard };
    hooks.checkpoint(V5WriterCheckpoint::CandidatePublishedToLock, &context)?;
    if inspect_v5_postjournal_state(guard, vault.root())?
        != Some(V5PostJournalState::CandidateInLock)
    {
        return Err(GitError::RecoveryConflict);
    }

    let loaded = candidate_bundle_v5::load_candidate_index_lock_with_journal_v5(
        guard, git, &reference,
    )?;
    revalidate_held_bundle_journal_v5(vault.root(), &held_journal)?;
    verify_payload_ready_for_v5_index(vault, git, guard, &payload)?;
    {
        let mut component = ComponentForceKillHooks { writer: hooks };
        candidate_bundle_v5::publish_candidate_lock_over_live_index_with_journal_v5_with_hooks(
            guard,
            git,
            &reference,
            loaded,
            &held_journal.file,
            || {
                revalidate_held_bundle_journal_v5(vault.root(), &held_journal)?;
                verify_payload_ready_for_v5_index(vault, git, guard, &payload)?;
                revalidate_held_bundle_journal_v5(vault.root(), &held_journal)
            },
            &mut component,
        )?;
    }
    hooks.checkpoint(V5WriterCheckpoint::LiveIndexPublished, &context)?;
    let completed = inspect_v5_postjournal_state(guard, vault.root())?
        .ok_or(GitError::RecoveryConflict)?;
    if !matches!(
        completed,
        V5PostJournalState::ExactFinal | V5PostJournalState::LaterUnrelated
    ) {
        return Err(GitError::RecoveryConflict);
    }
    revalidate_held_bundle_journal_v5(vault.root(), &held_journal)?;
    verify_payload_completed_v5(vault, git, guard, &payload)?;
    revalidate_held_bundle_journal_v5(vault.root(), &held_journal)
}

#[test]
#[ignore = "spawned only by the force-kill parent harness"]
fn force_kill_writer_child() {
    let Some(control) = read_control() else {
        return;
    };
    let ready_path = std::env::current_dir()
        .expect("writer control directory resolves")
        .join(WRITER_READY_FILE);
    let armed_path = std::env::current_dir()
        .expect("writer control directory resolves")
        .join(WRITER_ARMED_FILE);
    let vault = unlock_controlled_vault(&control);
    let git = Git::open(&control.vault_root).expect("force-kill writer opens Git");
    let guard = VaultMutationGuard::acquire(&control.vault_root)
        .expect("force-kill writer acquires mutation guard");
    let ready = ready_record(&control, ChildRole::Writer);
    let mut hooks = ForceKillWriterHooks {
        ready_path,
        armed_path,
        ready,
    };
    let result = commit_payload_v5_force_kill_test(
        &vault,
        &git,
        &guard,
        &control.payload,
        &mut hooks,
    );
    panic!(
        "writer returned without reaching force-kill target {:?}: {result:?}",
        control.scenario.target
    );
}

#[test]
#[ignore = "spawned only by the force-kill parent harness"]
fn force_kill_recovery_child() {
    let Some(control) = read_control() else {
        return;
    };
    let control_directory = std::env::current_dir().expect("recovery control directory resolves");
    let first_ready = control_directory.join(RECOVERY_FIRST_READY_FILE);
    let second_ready = control_directory.join(RECOVERY_SECOND_READY_FILE);
    let (role, ready_path, expected_recovered) = match (first_ready.exists(), second_ready.exists()) {
        (false, false) => (
            ChildRole::RecoveryFirst,
            first_ready,
            usize::from(control.scenario.target.expects_pending_recovery()),
        ),
        (true, false) => {
            let first = ready_record_for_pid(&control, ChildRole::RecoveryFirst, 0);
            read_and_validate_ready_ignoring_pid(&first_ready, &first);
            (ChildRole::RecoverySecond, second_ready, 0)
        }
        (_, true) => panic!("invalid recovery child ordinal state"),
    };
    let status_before = recovery_status(&control.vault_root)
        .expect("fresh child classifies force-killed state");
    assert_eq!(
        status_before.pending_transaction,
        expected_recovered == 1
    );
    assert_eq!(
        status_before.retained_candidate_scratch_count,
        control.scenario.target.retained_scratch_after_recovery()
    );
    let vault = unlock_controlled_vault(&control);
    let git = Git::open(&control.vault_root).expect("fresh recovery child opens Git");
    let later_stage = control
        .scenario
        .later_unrelated
        .then(|| exact_later_unrelated_stage(&git));
    let recovered = recover(&vault).expect("fresh child performs one public recovery");
    assert_eq!(recovered.recovered_transactions, expected_recovered);
    assert_no_secret_canaries(&control.vault_root, &control_directory);
    if let Some(expected) = later_stage.as_ref() {
        assert_eq!(&exact_later_unrelated_stage(&git), expected);
    }
    let status_after = recovery_status(&control.vault_root)
        .expect("fresh child classifies clean state");
    assert!(!status_after.pending_transaction);
    assert_eq!(
        status_after.retained_candidate_scratch_count,
        control.scenario.target.retained_scratch_after_recovery()
    );
    if control.scenario.target.is_pre_stable() {
        assert_pre_candidate_disk_state(&vault);
    } else {
        assert_final_disk_state(
            &vault,
            &control.payload,
            control.scenario.later_unrelated,
        );
    }
    write_ready(&ready_path, &ready_record(&control, role))
        .expect("recovery readiness publishes durably");
}

fn assert_pre_candidate_disk_state(vault: &Vault) {
    assert_eq!(
        inspect_held_v5_cleanup_state(vault.root())
            .expect("pre-candidate namespace inspects")
            .kind(),
        V5CleanupState::Clean
    );
    assert!(
        exact_reserved_private_names(vault.root())
            .expect("pre-candidate reserved namespace inspects")
            .is_empty()
    );
    drop(
        VaultMutationGuard::acquire(vault.root())
            .expect("pre-candidate force-killed guard is released"),
    );
    assert_no_raw_vault_plaintext(vault.root());
}

fn assert_final_disk_state(vault: &Vault, payload: &MergeJournalPayload, later_unrelated: bool) {
    let git = Git::open(vault.root()).expect("final Git state opens");
    assert!(
        git.unmerged_entries()
            .expect("final index stages inspect")
            .is_empty()
    );
    assert_eq!(
        inspect_held_v5_cleanup_state(vault.root())
            .expect("final v5 namespace inspects")
            .kind(),
        V5CleanupState::Clean
    );
    assert!(
        exact_reserved_private_names(vault.root())
            .expect("final reserved namespace inspects")
            .is_empty()
    );
    let guard = VaultMutationGuard::acquire(vault.root())
        .expect("force-killed writer mutation guard is released");
    verify_payload_completed_v5(vault, &git, &guard, payload)
        .expect("force-killed payload completes exactly");
    if later_unrelated {
        assert_eq!(
            fs::read(vault.root().join(LATER_UNRELATED_PATH))
                .expect("later-unrelated worktree sentinel reads"),
            LATER_UNRELATED_BYTES
        );
        assert!(
            index_entry_map(&git)
                .expect("later-unrelated index inspects")
                .contains_key(&(LATER_UNRELATED_PATH.to_owned(), 0))
        );
    }
    assert_no_raw_vault_plaintext(vault.root());
}

fn exact_later_unrelated_stage(git: &Git) -> StageEntry {
    index_entry_map(git)
        .expect("later-unrelated exact stage map inspects")
        .remove(&(LATER_UNRELATED_PATH.to_owned(), 0))
        .expect("later-unrelated exact stage entry exists")
}

fn secret_canaries() -> [&'static [u8]; 6] {
    [
        PASSWORD,
        b"base\n",
        b"first\nbase\nlast\n",
        b"first\nbase\ntheirs changed\n",
        b"<<<<<<< ours\nours\n",
        b"ours\n=======\ntheirs\n",
    ]
}

fn assert_bytes_have_no_secret_canaries(label: &Path, bytes: &[u8]) {
    for canary in secret_canaries() {
        assert!(
            !bytes
                .windows(canary.len())
                .any(|window| window == canary),
            "vault plaintext/password canary found in {}",
            label.display()
        );
    }
}

fn assert_regular_tree_has_no_secret_canaries(root: &Path) {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory).expect("canary audit directory enumerates") {
            let entry = entry.expect("canary audit entry reads");
            let metadata = fs::symlink_metadata(entry.path())
                .expect("canary audit metadata reads without following links");
            if metadata.file_type().is_dir() {
                directories.push(entry.path());
                continue;
            }
            if !metadata.file_type().is_file() {
                continue;
            }
            let bytes = fs::read(entry.path()).expect("canary audit regular file reads");
            assert_bytes_have_no_secret_canaries(&entry.path(), &bytes);
        }
    }
}

fn assert_all_git_objects_have_no_secret_canaries(root: &Path) {
    let output = Command::new("git")
        .current_dir(root)
        .args(["cat-file", "--batch-all-objects", "--batch"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("all Git objects decompress for canary audit");
    assert!(
        output.status.success(),
        "Git object canary audit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_bytes_have_no_secret_canaries(
        &root.join(".git-all-objects-decompressed"),
        &output.stdout,
    );
}

fn assert_no_secret_canaries(vault_root: &Path, control_root: &Path) {
    assert_regular_tree_has_no_secret_canaries(vault_root);
    assert_regular_tree_has_no_secret_canaries(control_root);
    assert_all_git_objects_have_no_secret_canaries(vault_root);
}

fn assert_no_raw_vault_plaintext(root: &Path) {
    assert_regular_tree_has_no_secret_canaries(root);
}

fn child_command(control_directory: &Path, test_name: &str) -> Command {
    let executable = std::env::current_exe().expect("current test executable resolves");
    let mut command = Command::new(executable);
    command
        .current_dir(control_directory)
        .args([
            "--ignored",
            "--exact",
            test_name,
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn(mut command: Command) -> io::Result<Self> {
        command.spawn().map(|child| Self { child: Some(child) })
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child guard remains armed")
    }

    fn id(&self) -> u32 {
        self.child
            .as_ref()
            .expect("child guard remains armed")
            .id()
    }

    fn kill_and_wait(&mut self) -> io::Result<ExitStatus> {
        let mut child = self.child.take().expect("child guard remains armed");
        let killed = child.kill();
        let waited = child.wait();
        killed?;
        waited
    }

    fn wait_after_exit(&mut self) -> io::Result<ExitStatus> {
        self.child
            .take()
            .expect("child guard remains armed")
            .wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_for_ready(child: &mut ChildGuard, ready_path: &Path, expected: &ReadyRecord) {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if ready_path.exists() {
            read_and_validate_ready(ready_path, expected);
            assert!(
                child
                    .child_mut()
                    .try_wait()
                    .expect("ready child liveness rechecks")
                    .is_none(),
                "writer child exited after publishing readiness"
            );
            return;
        }
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .expect("writer child status polls")
        {
            panic!("writer child exited before force-kill boundary: {status:?}");
        }
        assert!(
            Instant::now() < deadline,
            "writer child did not reach force-kill boundary before timeout"
        );
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

fn wait_for_recovery(
    child: &mut ChildGuard,
    ready_path: &Path,
    expected: &ReadyRecord,
) -> ExitStatus {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let mut ready = false;
    loop {
        if !ready && ready_path.exists() {
            read_and_validate_ready(ready_path, expected);
            ready = true;
        }
        if let Some(_status) = child
            .child_mut()
            .try_wait()
            .expect("recovery child status polls")
        {
            let status = child
                .wait_after_exit()
                .expect("completed recovery child reaps");
            assert!(ready, "recovery child exited without durable completion signal");
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "recovery child did not finish before timeout"
        );
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn assert_no_child_processes(pid: u32) {
    let task_root = PathBuf::from(format!("/proc/{pid}/task"));
    for task in fs::read_dir(task_root).expect("writer child task table inspects") {
        let task = task.expect("writer child task entry reads");
        let path = task.path().join("children");
        let children = match fs::read_to_string(&path) {
            Ok(children) => children,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => panic!("writer child task descendants unreadable: {error:?}"),
        };
        assert!(
            children.trim().is_empty(),
            "force-kill checkpoint retains child processes in {path:?}: {children}"
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn assert_no_child_processes(_pid: u32) {}

fn write_control(directory: &Path, control: &ForceKillControl) {
    validate_control(control);
    let bytes = serde_json::to_vec(control).expect("force-kill control serializes");
    write_atomic_synced(&directory.join(CONTROL_FILE), &bytes)
        .expect("force-kill control publishes durably");
}

#[derive(Debug, Eq, PartialEq)]
struct PreStableSnapshot {
    index: Vec<u8>,
    worktree: BTreeMap<PathBuf, Vec<u8>>,
}

fn pre_stable_snapshot(root: &Path) -> PreStableSnapshot {
    let mut worktree = BTreeMap::new();
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory).expect("pre-stable worktree enumerates") {
            let entry = entry.expect("pre-stable worktree entry reads");
            if directory == root
                && matches!(
                    entry.file_name().to_str(),
                    Some(".git" | VAULT_LOCAL_DIRECTORY)
                )
            {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())
                .expect("pre-stable worktree metadata reads");
            if metadata.file_type().is_dir() {
                directories.push(entry.path());
            } else if metadata.file_type().is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .expect("pre-stable path remains under root")
                    .to_path_buf();
                worktree.insert(
                    relative,
                    fs::read(entry.path()).expect("pre-stable worktree file snapshots"),
                );
            }
        }
    }
    PreStableSnapshot {
        index: fs::read(index_path(root)).expect("pre-stable live index snapshots"),
        worktree,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keep one auditable parent/three-child force-kill protocol"
)]
fn run_force_kill_case(
    object_format: GitObjectFormat,
    kind: CandidatePayloadKindV5,
    target: ForceKillTarget,
    later_unrelated: bool,
) {
    assert!(
        !later_unrelated
            || target == ForceKillTarget::PostAfterFinalLiveIndexClassification
    );
    let fixture = ProductionEntryFixtureV5::create(object_format, kind);
    let control_directory = TestDirectory::new();
    let vault_root = fs::canonicalize(fixture.vault().root())
        .expect("force-kill vault root canonicalizes before control publication");
    let control_root = fs::canonicalize(control_directory.path())
        .expect("force-kill control root canonicalizes before publication");
    let control = ForceKillControl {
        version: 1,
        nonce: Uuid::new_v4().simple().to_string(),
        object_format,
        payload_sha256: payload_sha256(&fixture.payload()),
        vault_root,
        payload: fixture.payload(),
        scenario: ForceKillScenario {
            target,
            later_unrelated,
        },
    };
    let pre_stable = target
        .is_pre_stable()
        .then(|| pre_stable_snapshot(&control.vault_root));
    write_control(&control_root, &control);

    let writer_command = child_command(
        &control_root,
        "tests::v5_force_kill_tests::force_kill_writer_child",
    );
    let mut writer =
        ChildGuard::spawn(writer_command).expect("force-kill writer child spawns under guard");
    let writer_ready = ready_record_for_pid(&control, ChildRole::Writer, writer.id());
    wait_for_ready(
        &mut writer,
        &control_root.join(WRITER_READY_FILE),
        &writer_ready,
    );
    let writer_armed = ready_record_for_pid(&control, ChildRole::WriterArmed, writer.id());
    wait_for_ready(
        &mut writer,
        &control_root.join(WRITER_ARMED_FILE),
        &writer_armed,
    );
    assert_no_child_processes(writer.id());
    let killed = writer
        .kill_and_wait()
        .expect("force-kill writer terminates and reaps");
    assert!(!killed.success(), "force-killed writer must not exit cleanly");

    let expected_later_stage = later_unrelated.then(|| exact_later_unrelated_stage(fixture.git()));
    assert_no_secret_canaries(&control.vault_root, &control_root);

    let first_recovery_command = child_command(
        &control_root,
        "tests::v5_force_kill_tests::force_kill_recovery_child",
    );
    let mut first_recovery = ChildGuard::spawn(first_recovery_command)
        .expect("first fresh recovery child spawns under process guard");
    let first_ready =
        ready_record_for_pid(&control, ChildRole::RecoveryFirst, first_recovery.id());
    let first_recovered = wait_for_recovery(
        &mut first_recovery,
        &control_root.join(RECOVERY_FIRST_READY_FILE),
        &first_ready,
    );
    assert!(
        first_recovered.success(),
        "first fresh recovery child failed: {first_recovered:?}"
    );

    let second_recovery_command = child_command(
        &control_root,
        "tests::v5_force_kill_tests::force_kill_recovery_child",
    );
    let mut second_recovery = ChildGuard::spawn(second_recovery_command)
        .expect("second fresh recovery child spawns under process guard");
    let second_ready =
        ready_record_for_pid(&control, ChildRole::RecoverySecond, second_recovery.id());
    let second_recovered = wait_for_recovery(
        &mut second_recovery,
        &control_root.join(RECOVERY_SECOND_READY_FILE),
        &second_ready,
    );
    assert!(
        second_recovered.success(),
        "second fresh recovery child failed: {second_recovered:?}"
    );
    if let Some(expected) = expected_later_stage.as_ref() {
        assert_eq!(&exact_later_unrelated_stage(fixture.git()), expected);
    }

    if let Some(expected) = pre_stable.as_ref() {
        assert_eq!(
            &pre_stable_snapshot(&control.vault_root),
            expected,
            "pre-stable force-kill preserves original worktree and live index"
        );
        fixture
            .commit()
            .expect("fresh merge continues after pre-stable force-kill");
    }
    fixture.assert_clean_completed();
    assert_final_disk_state(fixture.vault(), &fixture.payload(), later_unrelated);
    assert_eq!(
        recover(fixture.vault())
            .expect("clean public recovery remains idempotent")
            .recovered_transactions,
        0
    );
    assert_no_secret_canaries(&control.vault_root, &control_root);
    let fixture_root = control.vault_root.clone();
    drop(fixture);
    remove_directory_checked(&fixture_root);
    drop(control_directory);
    remove_directory_checked(&control_root);
}

fn remove_directory_checked(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match fs::remove_dir_all(path) {
            Ok(()) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error)
                if Instant::now() < deadline
                    && matches!(
                        error.kind(),
                        io::ErrorKind::PermissionDenied
                            | io::ErrorKind::DirectoryNotEmpty
                            | io::ErrorKind::Other
                    ) =>
            {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                panic!("force-kill directory cleanup failed for {path:?}: {error:?}");
            }
        }
    }
    assert!(!path.exists(), "force-kill directory remains after cleanup");
}

fn force_kill_targets(kind: CandidatePayloadKindV5) -> Vec<(ForceKillTarget, bool)> {
    let mut targets = vec![
        (ForceKillTarget::CandidateScratchCreated, false),
        (ForceKillTarget::CandidateCopied, false),
        (ForceKillTarget::CandidateMutated, false),
        (ForceKillTarget::CandidateManifestWritten, false),
        (ForceKillTarget::CandidateBeforePublish, false),
        (ForceKillTarget::CandidateCriticalAudit, false),
        (ForceKillTarget::CandidateAfterPublish, false),
        (ForceKillTarget::PublishScratchCreated, false),
        (ForceKillTarget::PublishCandidateCopied, false),
        (ForceKillTarget::PublishBeforePublish, false),
        (ForceKillTarget::PublishCriticalAudit, false),
        (ForceKillTarget::PublishAfterPublish, false),
        (ForceKillTarget::MarkerScratchCreated, false),
        (ForceKillTarget::MarkerWritten, false),
        (ForceKillTarget::MarkerBeforeMove, false),
        (ForceKillTarget::MarkerCriticalAudit, false),
        (ForceKillTarget::MarkerAfterMove, false),
        (ForceKillTarget::MarkerPostAudit, false),
        (ForceKillTarget::JournalScratchCreated, false),
        (ForceKillTarget::JournalWritten, false),
        (ForceKillTarget::JournalBeforeMove, false),
        (ForceKillTarget::JournalCriticalAudit, false),
        (ForceKillTarget::JournalAfterMove, false),
        (ForceKillTarget::JournalPostAudit, false),
    ];
    match kind {
        CandidatePayloadKindV5::InPlace | CandidatePayloadKindV5::DetectedRename => {
            targets.push((ForceKillTarget::WorktreeOneOfOne, false));
        }
        CandidatePayloadKindV5::SplitRename => {
            targets.push((ForceKillTarget::WorktreeOneOfTwo, false));
            targets.push((ForceKillTarget::WorktreeTwoOfTwo, false));
        }
    }
    targets.extend([
        (ForceKillTarget::PostBeforePublishOverMarker, false),
        (ForceKillTarget::PostAfterPublishOverMarker, false),
        (ForceKillTarget::PostBeforePublishOverIndex, false),
        (ForceKillTarget::PostAfterPublishOverIndex, false),
        (
            ForceKillTarget::PostAfterInitialLiveIndexClassification,
            false,
        ),
        (
            ForceKillTarget::PostAfterFinalLiveIndexClassification,
            false,
        ),
        (ForceKillTarget::CleanupFullJ, false),
        (ForceKillTarget::CleanupFullR, false),
        (ForceKillTarget::CleanupManifestR, false),
        (ForceKillTarget::CleanupEmptyR, false),
        (ForceKillTarget::ReceiptOnly, false),
        (ForceKillTarget::Clean, false),
        (
            ForceKillTarget::PostAfterFinalLiveIndexClassification,
            true,
        ),
    ]);
    targets
}

fn run_force_kill_evidence_shard(
    object_format: GitObjectFormat,
    kind: CandidatePayloadKindV5,
) {
    for (target, later_unrelated) in force_kill_targets(kind) {
        run_force_kill_case(object_format, kind, target, later_unrelated);
    }
}

const fn object_format_label(object_format: GitObjectFormat) -> &'static str {
    match object_format {
        GitObjectFormat::Sha1 => "sha1",
        GitObjectFormat::Sha256 => "sha256",
    }
}

const fn payload_kind_label(kind: CandidatePayloadKindV5) -> &'static str {
    match kind {
        CandidatePayloadKindV5::InPlace => "in_place",
        CandidatePayloadKindV5::DetectedRename => "detected_rename",
        CandidatePayloadKindV5::SplitRename => "split_rename",
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "spell the frozen Cartesian checkpoint set independently"
)]
fn v5_force_kill_matrix_has_exact_machine_coverage() {
    let common = BTreeSet::from([
        ForceKillTarget::CandidateScratchCreated,
        ForceKillTarget::CandidateCopied,
        ForceKillTarget::CandidateMutated,
        ForceKillTarget::CandidateManifestWritten,
        ForceKillTarget::CandidateBeforePublish,
        ForceKillTarget::CandidateCriticalAudit,
        ForceKillTarget::CandidateAfterPublish,
        ForceKillTarget::PublishScratchCreated,
        ForceKillTarget::PublishCandidateCopied,
        ForceKillTarget::PublishBeforePublish,
        ForceKillTarget::PublishCriticalAudit,
        ForceKillTarget::PublishAfterPublish,
        ForceKillTarget::MarkerScratchCreated,
        ForceKillTarget::MarkerWritten,
        ForceKillTarget::MarkerBeforeMove,
        ForceKillTarget::MarkerCriticalAudit,
        ForceKillTarget::MarkerAfterMove,
        ForceKillTarget::MarkerPostAudit,
        ForceKillTarget::JournalScratchCreated,
        ForceKillTarget::JournalWritten,
        ForceKillTarget::JournalBeforeMove,
        ForceKillTarget::JournalCriticalAudit,
        ForceKillTarget::JournalAfterMove,
        ForceKillTarget::JournalPostAudit,
        ForceKillTarget::PostBeforePublishOverMarker,
        ForceKillTarget::PostAfterPublishOverMarker,
        ForceKillTarget::PostBeforePublishOverIndex,
        ForceKillTarget::PostAfterPublishOverIndex,
        ForceKillTarget::PostAfterInitialLiveIndexClassification,
        ForceKillTarget::PostAfterFinalLiveIndexClassification,
        ForceKillTarget::CleanupFullJ,
        ForceKillTarget::CleanupFullR,
        ForceKillTarget::CleanupManifestR,
        ForceKillTarget::CleanupEmptyR,
        ForceKillTarget::ReceiptOnly,
        ForceKillTarget::Clean,
    ]);
    assert_eq!(common.len(), 36);
    let mut cases = BTreeSet::new();
    for object_format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for kind in [
            CandidatePayloadKindV5::InPlace,
            CandidatePayloadKindV5::DetectedRename,
            CandidatePayloadKindV5::SplitRename,
        ] {
            let targets = force_kill_targets(kind);
            let actual = targets.iter().copied().collect::<BTreeSet<_>>();
            assert_eq!(actual.len(), targets.len(), "case table has no duplicates");
            let mut expected = common
                .iter()
                .copied()
                .map(|target| (target, false))
                .collect::<BTreeSet<_>>();
            match kind {
                CandidatePayloadKindV5::InPlace
                | CandidatePayloadKindV5::DetectedRename => {
                    expected.insert((ForceKillTarget::WorktreeOneOfOne, false));
                }
                CandidatePayloadKindV5::SplitRename => {
                    expected.insert((ForceKillTarget::WorktreeOneOfTwo, false));
                    expected.insert((ForceKillTarget::WorktreeTwoOfTwo, false));
                }
            }
            expected.insert((
                ForceKillTarget::PostAfterFinalLiveIndexClassification,
                true,
            ));
            assert_eq!(actual, expected, "payload shard equals frozen Cartesian set");
            for (target, later_unrelated) in targets {
                assert!(cases.insert((
                    object_format_label(object_format),
                    payload_kind_label(kind),
                    target,
                    later_unrelated,
                )));
            }
        }
    }
    assert_eq!(cases.len(), 230);
    assert_eq!(
        cases
            .iter()
            .filter(|(_, _, target, _)| *target == ForceKillTarget::Clean)
            .count(),
        6
    );
    assert_eq!(
        cases
            .iter()
            .filter(|(_, _, target, _)| matches!(
                target,
                ForceKillTarget::WorktreeOneOfTwo | ForceKillTarget::WorktreeTwoOfTwo
            ))
            .count(),
        4
    );
    assert_eq!(
        cases
            .iter()
            .filter(|(_, _, target, later)| {
                *target == ForceKillTarget::PostAfterFinalLiveIndexClassification && *later
            })
            .count(),
        6
    );
    for target in common {
        assert_eq!(
            cases
                .iter()
                .filter(|(_, _, actual, later)| *actual == target && !*later)
                .count(),
            6,
            "common checkpoint is Cartesian across format and payload"
        );
    }
}

#[test]
fn v5_force_kill_representative_boundaries_recover_in_fresh_processes() {
    for (object_format, kind, target, later_unrelated) in [
        (
            GitObjectFormat::Sha1,
            CandidatePayloadKindV5::InPlace,
            ForceKillTarget::CandidateCriticalAudit,
            false,
        ),
        (
            GitObjectFormat::Sha1,
            CandidatePayloadKindV5::InPlace,
            ForceKillTarget::JournalCriticalAudit,
            false,
        ),
        (
            GitObjectFormat::Sha1,
            CandidatePayloadKindV5::SplitRename,
            ForceKillTarget::WorktreeOneOfTwo,
            false,
        ),
        (
            GitObjectFormat::Sha256,
            CandidatePayloadKindV5::DetectedRename,
            ForceKillTarget::PostAfterFinalLiveIndexClassification,
            true,
        ),
        (
            GitObjectFormat::Sha256,
            CandidatePayloadKindV5::SplitRename,
            ForceKillTarget::CleanupManifestR,
            false,
        ),
        (
            GitObjectFormat::Sha1,
            CandidatePayloadKindV5::DetectedRename,
            ForceKillTarget::Clean,
            false,
        ),
    ] {
        run_force_kill_case(object_format, kind, target, later_unrelated);
    }
}

macro_rules! force_kill_evidence_shard {
    ($name:ident, $format:expr, $kind:expr) => {
        #[test]
        #[ignore = "full native force-kill matrix; run six shards in parallel"]
        fn $name() {
            run_force_kill_evidence_shard($format, $kind);
        }
    };
}

force_kill_evidence_shard!(
    v5_force_kill_full_sha1_in_place,
    GitObjectFormat::Sha1,
    CandidatePayloadKindV5::InPlace
);
force_kill_evidence_shard!(
    v5_force_kill_full_sha1_detected_rename,
    GitObjectFormat::Sha1,
    CandidatePayloadKindV5::DetectedRename
);
force_kill_evidence_shard!(
    v5_force_kill_full_sha1_split_rename,
    GitObjectFormat::Sha1,
    CandidatePayloadKindV5::SplitRename
);
force_kill_evidence_shard!(
    v5_force_kill_full_sha256_in_place,
    GitObjectFormat::Sha256,
    CandidatePayloadKindV5::InPlace
);
force_kill_evidence_shard!(
    v5_force_kill_full_sha256_detected_rename,
    GitObjectFormat::Sha256,
    CandidatePayloadKindV5::DetectedRename
);
force_kill_evidence_shard!(
    v5_force_kill_full_sha256_split_rename,
    GitObjectFormat::Sha256,
    CandidatePayloadKindV5::SplitRename
);
