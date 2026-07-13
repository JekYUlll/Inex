use std::ffi::OsStr;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::*;

const CONTROL_FILE: &str = "v5-force-kill-control.json";
const CONTROL_STAGING_FILE: &str = "v5-force-kill-control.staging";
const SETUP_REQUEST_FILE: &str = "v5-force-kill-setup-request.json";
const SETUP_REQUEST_STAGING_FILE: &str = "v5-force-kill-setup-request.staging";
const SETUP_READY_FILE: &str = "v5-force-kill-setup.ready";
const SETUP_READY_STAGING_FILE: &str = "v5-force-kill-setup.ready.staging";
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
const FINAL_READY_FILE: &str = "v5-force-kill-final.ready";
const FINAL_READY_STAGING_FILE: &str = "v5-force-kill-final.ready.staging";
const LATER_STAGE_FILE: &str = "v5-force-kill-later-stage.json";
const LATER_STAGE_STAGING_FILE: &str = "v5-force-kill-later-stage.staging";
const LATER_UNRELATED_PATH: &str = "later-force-kill-unrelated.bin";
const LATER_UNRELATED_BYTES: &[u8] = b"independent encrypted-owner sentinel\n";
const FORCE_KILL_IN_PLACE_LOGICAL_PATH: &str = "opaque-entry.md";
const FORCE_KILL_IN_PLACE_BASE_PLAINTEXT: &[u8] = b"inex-v5-force-kill-base-left-7f40c92d\n\
inex-v5-force-kill-shared-center-b183e6a4\n\
inex-v5-force-kill-base-right-54d91a0e\n";
const FORCE_KILL_IN_PLACE_OURS_PLAINTEXT: &[u8] = b"inex-v5-force-kill-left-variant-260ac7e1\n\
inex-v5-force-kill-shared-center-b183e6a4\n\
inex-v5-force-kill-base-right-54d91a0e\n";
const FORCE_KILL_IN_PLACE_THEIRS_PLAINTEXT: &[u8] = b"inex-v5-force-kill-base-left-7f40c92d\n\
inex-v5-force-kill-shared-center-b183e6a4\n\
inex-v5-force-kill-right-variant-c09b3f72\n";
const FORCE_KILL_IN_PLACE_MERGED_PLAINTEXT: &[u8] = b"inex-v5-force-kill-left-variant-260ac7e1\n\
inex-v5-force-kill-shared-center-b183e6a4\n\
inex-v5-force-kill-right-variant-c09b3f72\n";
const FORCE_KILL_RENAME_DESTINATION_LOGICAL_PATH: &str = "renamed file.md";
const FORCE_KILL_RENAME_BASE_PLAINTEXT: &[u8] = b"first\nbase\nlast\n";
const FORCE_KILL_RENAME_MERGED_PLAINTEXT: &[u8] = b"first\nbase\ntheirs changed\n";
const PASSWORD_PREFIX_FRAGMENT: &[u8] = b"recovery test";
const PASSWORD_SUFFIX_FRAGMENT: &[u8] = b"test password";
const IN_PLACE_BASE_LEFT_FRAGMENT: &[u8] = b"base-left-7f40c92d";
const IN_PLACE_SHARED_CENTER_FRAGMENT: &[u8] = b"shared-center-b183e6a4";
const IN_PLACE_BASE_RIGHT_FRAGMENT: &[u8] = b"base-right-54d91a0e";
const IN_PLACE_LEFT_VARIANT_FRAGMENT: &[u8] = b"left-variant-260ac7e1";
const IN_PLACE_RIGHT_VARIANT_FRAGMENT: &[u8] = b"right-variant-c09b3f72";
const RENAME_SHARED_PREFIX_FRAGMENT: &[u8] = b"first\nbase";
const RENAME_BASE_TAIL_FRAGMENT: &[u8] = b"base\nlast";
const RENAME_MERGED_TAIL_FRAGMENT: &[u8] = b"theirs changed";
const CHILD_TIMEOUT: Duration = Duration::from_secs(45);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);
const CHILD_TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_GUARD_TEST_ENV: &str = "INEX_V5_FORCE_KILL_GUARD_CHILD";
const CHILD_GUARD_TEST_VALUE: &str = "park-until-bounded-kill";
const CHILD_GUARD_READY_ENV: &str = "INEX_V5_FORCE_KILL_GUARD_READY";
const CHILD_GUARD_READY_BYTES: &[u8] = b"force-kill-guard-child-parked\n";

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
struct SetupRequest {
    version: u32,
    nonce: String,
    object_format: GitObjectFormat,
    payload_kind: ForceKillPayloadKind,
    scenario: ForceKillScenario,
    fixture_owner_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ForceKillPayloadKind {
    InPlace,
    DetectedRename,
    SplitRename,
}

impl From<CandidatePayloadKindV5> for ForceKillPayloadKind {
    fn from(value: CandidatePayloadKindV5) -> Self {
        match value {
            CandidatePayloadKindV5::InPlace => Self::InPlace,
            CandidatePayloadKindV5::DetectedRename => Self::DetectedRename,
            CandidatePayloadKindV5::SplitRename => Self::SplitRename,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ForceKillControl {
    version: u32,
    nonce: String,
    object_format: GitObjectFormat,
    payload_sha256: String,
    pre_stable_snapshot_sha256: String,
    vault_root: PathBuf,
    payload: MergeJournalPayload,
    scenario: ForceKillScenario,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ChildRole {
    Setup,
    Writer,
    WriterArmed,
    RecoveryFirst,
    RecoverySecond,
    FinalVerifier,
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
    pre_stable_snapshot_sha256: String,
    vault_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaterStageEvidence {
    version: u32,
    nonce: String,
    object_format: GitObjectFormat,
    payload_sha256: String,
    vault_root: PathBuf,
    stage: StageEntry,
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
        Some(SETUP_REQUEST_FILE) => SETUP_REQUEST_STAGING_FILE,
        Some(SETUP_READY_FILE) => SETUP_READY_STAGING_FILE,
        Some(WRITER_READY_FILE) => WRITER_READY_STAGING_FILE,
        Some(WRITER_ARMED_FILE) => WRITER_ARMED_STAGING_FILE,
        Some(RECOVERY_FIRST_READY_FILE) => RECOVERY_FIRST_READY_STAGING_FILE,
        Some(RECOVERY_SECOND_READY_FILE) => RECOVERY_SECOND_READY_STAGING_FILE,
        Some(FINAL_READY_FILE) => FINAL_READY_STAGING_FILE,
        Some(LATER_STAGE_FILE) => LATER_STAGE_STAGING_FILE,
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
    if !path
        .try_exists()
        .expect("force-kill control metadata inspects")
    {
        return None;
    }
    Some(read_control_at(&path))
}

fn read_control_at(path: &Path) -> ForceKillControl {
    let bytes = fs::read(path).expect("force-kill control reads");
    let control: ForceKillControl =
        serde_json::from_slice(&bytes).expect("force-kill control parses strictly");
    validate_control(&control);
    control
}

fn read_setup_request() -> Option<SetupRequest> {
    let path = std::env::current_dir()
        .expect("setup child current directory resolves")
        .join(SETUP_REQUEST_FILE);
    if !path
        .try_exists()
        .expect("force-kill setup request metadata inspects")
    {
        return None;
    }
    let bytes = fs::read(path).expect("force-kill setup request reads");
    let request: SetupRequest =
        serde_json::from_slice(&bytes).expect("force-kill setup request parses strictly");
    validate_setup_request(&request);
    Some(request)
}

fn validate_setup_request(request: &SetupRequest) {
    assert_eq!(request.version, 1, "force-kill setup version is exact");
    validate_nonce(&request.nonce);
    request.scenario.validate();
    assert!(
        request.fixture_owner_root.is_absolute(),
        "fixture owner root is absolute"
    );
    assert_eq!(
        fs::canonicalize(&request.fixture_owner_root)
            .expect("fixture owner root canonicalizes before setup"),
        request.fixture_owner_root,
        "fixture owner root uses canonical spelling"
    );
}

fn write_setup_request(directory: &Path, request: &SetupRequest) {
    validate_setup_request(request);
    let bytes = serde_json::to_vec(request).expect("force-kill setup request serializes");
    write_atomic_synced(&directory.join(SETUP_REQUEST_FILE), &bytes)
        .expect("force-kill setup request publishes durably");
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
    validate_sha256(&control.pre_stable_snapshot_sha256);
    assert!(control.vault_root.is_absolute());
    assert_eq!(
        fs::canonicalize(&control.vault_root).expect("controlled vault root canonicalizes"),
        control.vault_root,
        "controlled vault root uses canonical spelling"
    );
}

fn validate_sha256(value: &str) {
    assert_eq!(value.len(), 64, "SHA-256 evidence length is canonical");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "SHA-256 evidence is lowercase hexadecimal"
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

fn force_kill_payload_kind(payload: &MergeJournalPayload) -> ForceKillPayloadKind {
    match payload {
        MergeJournalPayload::InPlace(_) => ForceKillPayloadKind::InPlace,
        MergeJournalPayload::DetectedRename(_) => ForceKillPayloadKind::DetectedRename,
        MergeJournalPayload::Rename(_) => ForceKillPayloadKind::SplitRename,
    }
}

fn validate_control_against_setup(control: &ForceKillControl, request: &SetupRequest) {
    validate_control(control);
    validate_setup_request(request);
    assert_eq!(control.nonce, request.nonce);
    assert_eq!(control.object_format, request.object_format);
    assert_eq!(force_kill_payload_kind(&control.payload), request.payload_kind);
    assert_eq!(control.scenario, request.scenario);
    assert_eq!(
        control.vault_root.parent(),
        Some(request.fixture_owner_root.as_path()),
        "setup repository is a direct child of the parent-owned fixture root"
    );
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
        pre_stable_snapshot_sha256: control.pre_stable_snapshot_sha256.clone(),
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

fn assert_bound_secret_fragments(
    body_label: &str,
    actual: &[u8],
    expected: &[u8],
    fragments: &[(&str, &[u8])],
) {
    assert_eq!(actual, expected, "{body_label} binds the exact plaintext body");
    for &(fragment_label, fragment) in fragments {
        assert!(
            actual
                .windows(fragment.len())
                .any(|window| window == fragment),
            "{fragment_label} is present in the decrypted {body_label} body"
        );
    }
}

fn assert_force_kill_in_place_fragment_binding(actual: &[u8], expected: &[u8]) {
    let (body_label, fragments): (&str, &[(&str, &[u8])]) =
        if expected == FORCE_KILL_IN_PLACE_BASE_PLAINTEXT {
            (
                "in-place base",
                &[
                    ("in-place base-left fragment", IN_PLACE_BASE_LEFT_FRAGMENT),
                    (
                        "in-place shared-center fragment",
                        IN_PLACE_SHARED_CENTER_FRAGMENT,
                    ),
                    (
                        "in-place base-right fragment",
                        IN_PLACE_BASE_RIGHT_FRAGMENT,
                    ),
                ],
            )
        } else if expected == FORCE_KILL_IN_PLACE_OURS_PLAINTEXT {
            (
                "in-place ours",
                &[
                    (
                        "in-place left-variant fragment",
                        IN_PLACE_LEFT_VARIANT_FRAGMENT,
                    ),
                    (
                        "in-place shared-center fragment",
                        IN_PLACE_SHARED_CENTER_FRAGMENT,
                    ),
                    (
                        "in-place base-right fragment",
                        IN_PLACE_BASE_RIGHT_FRAGMENT,
                    ),
                ],
            )
        } else if expected == FORCE_KILL_IN_PLACE_THEIRS_PLAINTEXT {
            (
                "in-place theirs",
                &[
                    ("in-place base-left fragment", IN_PLACE_BASE_LEFT_FRAGMENT),
                    (
                        "in-place shared-center fragment",
                        IN_PLACE_SHARED_CENTER_FRAGMENT,
                    ),
                    (
                        "in-place right-variant fragment",
                        IN_PLACE_RIGHT_VARIANT_FRAGMENT,
                    ),
                ],
            )
        } else if expected == FORCE_KILL_IN_PLACE_MERGED_PLAINTEXT {
            (
                "in-place merged",
                &[
                    (
                        "in-place left-variant fragment",
                        IN_PLACE_LEFT_VARIANT_FRAGMENT,
                    ),
                    (
                        "in-place shared-center fragment",
                        IN_PLACE_SHARED_CENTER_FRAGMENT,
                    ),
                    (
                        "in-place right-variant fragment",
                        IN_PLACE_RIGHT_VARIANT_FRAGMENT,
                    ),
                ],
            )
        } else {
            panic!("unexpected force-kill in-place plaintext body")
        };
    assert_bound_secret_fragments(body_label, actual, expected, fragments);
}

fn assert_force_kill_rename_fragment_binding(actual: &[u8], expected: &[u8]) {
    let (body_label, fragments): (&str, &[(&str, &[u8])]) =
        if expected == FORCE_KILL_RENAME_BASE_PLAINTEXT {
            (
                "rename base",
                &[
                    ("rename shared-prefix fragment", RENAME_SHARED_PREFIX_FRAGMENT),
                    ("rename base-tail fragment", RENAME_BASE_TAIL_FRAGMENT),
                ],
            )
        } else if expected == FORCE_KILL_RENAME_MERGED_PLAINTEXT {
            (
                "rename merged",
                &[
                    ("rename shared-prefix fragment", RENAME_SHARED_PREFIX_FRAGMENT),
                    (
                        "rename merged-tail fragment",
                        RENAME_MERGED_TAIL_FRAGMENT,
                    ),
                ],
            )
        } else {
            panic!("unexpected force-kill rename plaintext body")
        };
    assert_bound_secret_fragments(body_label, actual, expected, fragments);
}

fn classify_and_bind_force_kill_rename_body(actual: &[u8]) -> (bool, bool) {
    if actual == FORCE_KILL_RENAME_BASE_PLAINTEXT {
        assert_force_kill_rename_fragment_binding(actual, FORCE_KILL_RENAME_BASE_PLAINTEXT);
        (true, false)
    } else if actual == FORCE_KILL_RENAME_MERGED_PLAINTEXT {
        assert_force_kill_rename_fragment_binding(actual, FORCE_KILL_RENAME_MERGED_PLAINTEXT);
        (false, true)
    } else {
        (false, false)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keep the neutral Git history and bound plaintext stages auditable together"
)]
fn create_force_kill_in_place_fixture(
    object_format: GitObjectFormat,
) -> InPlaceProductionEntryFixtureV5 {
    let directory = TestDirectory::new();
    initialize_test_repository_with_format(directory.path(), object_format);
    assert!(test_git(
        directory.path(),
        ["symbolic-ref", "HEAD", "refs/heads/anchor"]
    ));
    let mut vault = Vault::create_with_params(
        directory.path(),
        PASSWORD,
        1_783_699_200_000,
        Argon2idParams {
            ops_limit: 1,
            mem_limit_bytes: 8 * 1024,
        },
        test_policy(),
    )
    .expect("force-kill in-place vault creates");
    let logical = LogicalPath::parse_canonical(FORCE_KILL_IN_PLACE_LOGICAL_PATH)
        .expect("force-kill in-place path is valid");
    let physical_path = format!("{FORCE_KILL_IN_PLACE_LOGICAL_PATH}.enc");
    vault
        .create_document(
            &logical,
            FORCE_KILL_IN_PLACE_BASE_PLAINTEXT,
            1_783_699_201_000,
        )
        .expect("force-kill in-place base document creates");
    drop(vault);
    fs::write(
        directory.path().join(GIT_ATTRIBUTES_FILE),
        format!("{ATTRIBUTES_RULE}\n"),
    )
    .expect("force-kill attributes write succeeds");
    assert!(test_git(directory.path(), ["add", "--all"]));
    assert!(test_git(
        directory.path(),
        ["commit", "-q", "-m", "checkpoint-zero"]
    ));

    assert!(test_git(
        directory.path(),
        ["checkout", "-q", "-b", "leftlane"]
    ));
    save_test_document_at(
        directory.path(),
        &logical,
        FORCE_KILL_IN_PLACE_OURS_PLAINTEXT,
        1_783_699_202_000,
    );
    assert!(test_git(directory.path(), ["add", &physical_path]));
    assert!(test_git(
        directory.path(),
        ["commit", "-q", "-m", "checkpoint-left"]
    ));

    assert!(test_git(
        directory.path(),
        ["checkout", "-q", "anchor"]
    ));
    assert!(test_git(
        directory.path(),
        ["checkout", "-q", "-b", "rightlane"]
    ));
    save_test_document_at(
        directory.path(),
        &logical,
        FORCE_KILL_IN_PLACE_THEIRS_PLAINTEXT,
        1_783_699_203_000,
    );
    assert!(test_git(directory.path(), ["add", &physical_path]));
    assert!(test_git(
        directory.path(),
        ["commit", "-q", "-m", "checkpoint-right"]
    ));

    assert!(test_git(
        directory.path(),
        ["checkout", "-q", "leftlane"]
    ));
    assert!(test_git(
        directory.path(),
        [
            "config",
            "--local",
            "merge.inex.driver",
            "git config --get inex.driver.must.fail",
        ]
    ));
    assert!(!test_git(
        directory.path(),
        ["merge", "--no-edit", "rightlane"]
    ));

    let vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .expect("force-kill in-place vault unlocks");
    let git = Git::open(directory.path()).expect("force-kill in-place Git repository opens");
    let conflict = git
        .unmerged_entries()
        .expect("force-kill in-place conflict enumerates")
        .into_values()
        .next()
        .expect("force-kill in-place conflict exists");
    let identities =
        tracked_identity_index(&vault, &git).expect("force-kill in-place identities inspect");
    let prepared = prepare_result(&vault, &git, &conflict, &identities, 1_783_699_204_000)
        .expect("force-kill in-place result prepares");
    for (ciphertext, expected_plaintext) in prepared.stage_ciphertexts.iter().zip([
        FORCE_KILL_IN_PLACE_BASE_PLAINTEXT,
        FORCE_KILL_IN_PLACE_OURS_PLAINTEXT,
        FORCE_KILL_IN_PLACE_THEIRS_PLAINTEXT,
    ]) {
        let document = vault
            .authenticate_committed_envelope(
                &logical,
                ciphertext
                    .as_ref()
                    .expect("force-kill in-place stage ciphertext exists"),
            )
            .expect("force-kill in-place stage authenticates");
        assert_force_kill_in_place_fragment_binding(
            document.plaintext.as_slice(),
            expected_plaintext,
        );
    }
    assert!(!prepared.unresolved, "force-kill in-place merge is clean");
    let merged = vault
        .authenticate_committed_envelope(&logical, &prepared.encrypted.bytes)
        .expect("force-kill in-place result authenticates");
    assert_force_kill_in_place_fragment_binding(
        merged.plaintext.as_slice(),
        FORCE_KILL_IN_PLACE_MERGED_PLAINTEXT,
    );
    drop(merged);
    let expected =
        expected_worktree_digest(&prepared).expect("force-kill in-place worktree stage exists");
    let result_digest = digest(&prepared.encrypted.bytes);
    let journal = MergeJournal {
        version: 1,
        physical_path: conflict.physical_path.clone(),
        result_mode: result_mode(&conflict)
            .expect("force-kill in-place result mode exists")
            .to_owned(),
        stages: conflict.stages.clone(),
        expected_worktree_sha256: hex_digest(expected),
        result_oid: prepared.result_oid.clone(),
        result_sha256: hex_digest(result_digest),
    };
    InPlaceProductionEntryFixtureV5 {
        _directory: directory,
        vault,
        git,
        conflict,
        prepared,
        journal,
    }
}

fn create_force_kill_fixture(
    object_format: GitObjectFormat,
    kind: ForceKillPayloadKind,
) -> ProductionEntryFixtureV5 {
    match kind {
        ForceKillPayloadKind::InPlace => {
            ProductionEntryFixtureV5::InPlace(create_force_kill_in_place_fixture(object_format))
        }
        ForceKillPayloadKind::DetectedRename => ProductionEntryFixtureV5::DetectedRename(
            create_detected_rename_recovery_fixture_with_format(object_format),
        ),
        ForceKillPayloadKind::SplitRename => ProductionEntryFixtureV5::SplitRename(
            create_rename_recovery_fixture_with_format(object_format),
        ),
    }
}

fn assert_force_kill_rename_canaries(fixture: &ProductionEntryFixtureV5) {
    match fixture {
        ProductionEntryFixtureV5::DetectedRename(fixture) => {
            let mut saw_base = false;
            let mut saw_merged = false;
            for (path, ciphertext) in fixture
                .stage_paths
                .iter()
                .zip(fixture.prepared.stage_ciphertexts.iter())
            {
                let (Some(path), Some(ciphertext)) = (path.as_ref(), ciphertext.as_ref()) else {
                    continue;
                };
                let document = fixture
                    .vault
                    .authenticate_committed_envelope(path, ciphertext)
                    .expect("force-kill detected-rename stage authenticates");
                let (is_base, is_merged) =
                    classify_and_bind_force_kill_rename_body(document.plaintext.as_slice());
                saw_base |= is_base;
                saw_merged |= is_merged;
            }
            assert!(saw_base, "detected-rename base canary binds a real stage");
            assert!(
                saw_merged,
                "detected-rename merged canary binds a real stage"
            );
            let result = fixture
                .vault
                .authenticate_committed_envelope(
                    &fixture.destination_path,
                    &fixture.prepared.encrypted.bytes,
                )
                .expect("force-kill detected-rename result authenticates");
            assert_force_kill_rename_fragment_binding(
                result.plaintext.as_slice(),
                FORCE_KILL_RENAME_MERGED_PLAINTEXT,
            );
        }
        ProductionEntryFixtureV5::SplitRename(fixture) => {
            let mut saw_base = false;
            let mut saw_merged = false;
            for ciphertext in fixture.prepared.source_stage_ciphertexts.iter().flatten() {
                let document = fixture
                    .vault
                    .authenticate_committed_envelope(&fixture.source.logical_path, ciphertext)
                    .expect("force-kill split-rename source stage authenticates");
                let (is_base, is_merged) =
                    classify_and_bind_force_kill_rename_body(document.plaintext.as_slice());
                saw_base |= is_base;
                saw_merged |= is_merged;
            }
            let destination = fixture
                .vault
                .authenticate_committed_envelope(
                    &fixture.destination.logical_path,
                    &fixture.prepared.destination_ciphertext,
                )
                .expect("force-kill split-rename destination authenticates");
            if destination.plaintext.as_slice() == FORCE_KILL_RENAME_BASE_PLAINTEXT {
                assert_force_kill_rename_fragment_binding(
                    destination.plaintext.as_slice(),
                    FORCE_KILL_RENAME_BASE_PLAINTEXT,
                );
                saw_base = true;
            }
            assert!(saw_base, "split-rename base canary binds a real stage");
            assert!(saw_merged, "split-rename merged canary binds a real stage");
            let result = fixture
                .vault
                .authenticate_committed_envelope(
                    &fixture.destination_path,
                    &fixture.prepared.encrypted.bytes,
                )
                .expect("force-kill split-rename result authenticates");
            assert_force_kill_rename_fragment_binding(
                result.plaintext.as_slice(),
                FORCE_KILL_RENAME_MERGED_PLAINTEXT,
            );
        }
        ProductionEntryFixtureV5::InPlace(_) => {}
    }
}

fn detach_fixture_directory(fixture: ProductionEntryFixtureV5) {
    let directory = match fixture {
        ProductionEntryFixtureV5::InPlace(InPlaceProductionEntryFixtureV5 {
            _directory: directory,
            ..
        })
        | ProductionEntryFixtureV5::DetectedRename(DetectedRenameRecoveryFixture {
            _directory: directory,
            ..
        })
        | ProductionEntryFixtureV5::SplitRename(RenameRecoveryFixture {
            _directory: directory,
            ..
        }) => directory,
    };
    std::mem::forget(directory);
}

#[test]
#[ignore = "spawned only by the force-kill parent harness"]
fn force_kill_setup_child() {
    let Some(request) = read_setup_request() else {
        return;
    };
    let control_directory =
        std::env::current_dir().expect("setup child control directory resolves");
    assert_eq!(
        fs::canonicalize(std::env::temp_dir()).expect("setup child temp root canonicalizes"),
        request.fixture_owner_root,
        "setup child creates every fixture beneath the parent-owned root"
    );
    let fixture = create_force_kill_fixture(request.object_format, request.payload_kind);
    assert_force_kill_rename_canaries(&fixture);
    let payload = fixture.payload();
    let vault_root = fs::canonicalize(fixture.vault().root())
        .expect("setup child vault root canonicalizes");
    let control = ForceKillControl {
        version: 1,
        nonce: request.nonce,
        object_format: request.object_format,
        payload_sha256: payload_sha256(&payload),
        pre_stable_snapshot_sha256: pre_stable_snapshot_sha256(&vault_root),
        vault_root,
        payload,
        scenario: request.scenario,
    };
    validate_control(&control);
    write_control(&control_directory, &control);
    write_ready(
        &control_directory.join(SETUP_READY_FILE),
        &ready_record(&control, ChildRole::Setup),
    )
    .expect("setup readiness publishes durably");
    detach_fixture_directory(fixture);
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
    let first_exists = first_ready
        .try_exists()
        .expect("first recovery readiness metadata inspects");
    let second_exists = second_ready
        .try_exists()
        .expect("second recovery readiness metadata inspects");
    let (role, ready_path, expected_recovered) = match (first_exists, second_exists) {
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
    let later_stage = control.scenario.later_unrelated.then(|| {
        let actual = exact_later_unrelated_stage(&git);
        match role {
            ChildRole::RecoveryFirst => {
                write_later_stage_evidence(&control_directory, &control, &actual);
            }
            ChildRole::RecoverySecond => {
                assert_eq!(
                    actual,
                    read_later_stage_evidence(&control_directory, &control)
                );
            }
            ChildRole::Setup
            | ChildRole::Writer
            | ChildRole::WriterArmed
            | ChildRole::FinalVerifier => panic!("invalid recovery child role"),
        }
        actual
    });
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

#[test]
#[ignore = "spawned only by the force-kill parent harness"]
fn force_kill_final_verifier_child() {
    let Some(control) = read_control() else {
        return;
    };
    let control_directory =
        std::env::current_dir().expect("final verifier control directory resolves");
    let vault = unlock_controlled_vault(&control);
    let git = Git::open(&control.vault_root).expect("final verifier opens Git");
    if control.scenario.target.is_pre_stable() {
        assert_eq!(
            pre_stable_snapshot_sha256(&control.vault_root),
            control.pre_stable_snapshot_sha256,
            "pre-stable worktree file bytes and live-index bytes remain exact before the fresh merge"
        );
        let guard = VaultMutationGuard::acquire(&control.vault_root)
            .expect("final verifier acquires fresh merge guard");
        commit_payload_v5(
            &vault,
            &git,
            &guard,
            control.payload.clone(),
        )
        .expect("fresh merge continues after pre-stable force-kill");
    }
    let status = recovery_status(&control.vault_root).expect("final recovery status inspects");
    assert!(!status.pending_transaction);
    assert_eq!(
        status.retained_candidate_scratch_count,
        control.scenario.target.retained_scratch_after_recovery()
    );
    if control.scenario.later_unrelated {
        assert_eq!(
            exact_later_unrelated_stage(&git),
            read_later_stage_evidence(&control_directory, &control)
        );
    } else {
        assert!(
            !control_directory
                .join(LATER_STAGE_FILE)
                .try_exists()
                .expect("unexpected later-stage evidence metadata inspects"),
            "non-later force-kill case must not publish later-stage evidence"
        );
    }
    assert_final_disk_state(&vault, &control.payload, control.scenario.later_unrelated);
    assert_force_kill_final_plaintext(&vault, &control.payload);
    assert_no_secret_canaries(&control.vault_root, &control_directory);
    write_ready(
        &control_directory.join(FINAL_READY_FILE),
        &ready_record(&control, ChildRole::FinalVerifier),
    )
    .expect("final verifier readiness publishes durably");
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

fn assert_force_kill_final_plaintext(vault: &Vault, payload: &MergeJournalPayload) {
    let (logical_path, expected) = match payload {
        MergeJournalPayload::InPlace(journal) => {
            assert_eq!(
                journal.physical_path,
                format!("{FORCE_KILL_IN_PLACE_LOGICAL_PATH}.enc")
            );
            (
                FORCE_KILL_IN_PLACE_LOGICAL_PATH,
                FORCE_KILL_IN_PLACE_MERGED_PLAINTEXT,
            )
        }
        MergeJournalPayload::Rename(journal) => {
            assert_eq!(
                journal.destination_physical_path,
                format!("{FORCE_KILL_RENAME_DESTINATION_LOGICAL_PATH}.enc")
            );
            (
                FORCE_KILL_RENAME_DESTINATION_LOGICAL_PATH,
                FORCE_KILL_RENAME_MERGED_PLAINTEXT,
            )
        }
        MergeJournalPayload::DetectedRename(journal) => {
            assert_eq!(
                journal.destination_physical_path,
                format!("{FORCE_KILL_RENAME_DESTINATION_LOGICAL_PATH}.enc")
            );
            (
                FORCE_KILL_RENAME_DESTINATION_LOGICAL_PATH,
                FORCE_KILL_RENAME_MERGED_PLAINTEXT,
            )
        }
    };
    let logical =
        LogicalPath::parse_canonical(logical_path).expect("force-kill final path is valid");
    let document = vault
        .read(&logical)
        .expect("force-kill final plaintext authenticates");
    assert_eq!(document.plaintext.as_slice(), expected);
}

fn exact_later_unrelated_stage(git: &Git) -> StageEntry {
    index_entry_map(git)
        .expect("later-unrelated exact stage map inspects")
        .remove(&(LATER_UNRELATED_PATH.to_owned(), 0))
        .expect("later-unrelated exact stage entry exists")
}

fn write_later_stage_evidence(
    control_directory: &Path,
    control: &ForceKillControl,
    stage: &StageEntry,
) {
    let evidence = LaterStageEvidence {
        version: 1,
        nonce: control.nonce.clone(),
        object_format: control.object_format,
        payload_sha256: control.payload_sha256.clone(),
        vault_root: control.vault_root.clone(),
        stage: stage.clone(),
    };
    let bytes = serde_json::to_vec(&evidence).expect("later stage evidence serializes");
    write_atomic_synced(&control_directory.join(LATER_STAGE_FILE), &bytes)
        .expect("later stage evidence publishes durably");
}

fn read_later_stage_evidence(
    control_directory: &Path,
    control: &ForceKillControl,
) -> StageEntry {
    let bytes = fs::read(control_directory.join(LATER_STAGE_FILE))
        .expect("later stage evidence reads");
    let evidence: LaterStageEvidence =
        serde_json::from_slice(&bytes).expect("later stage evidence parses strictly");
    assert_eq!(evidence.version, 1);
    validate_nonce(&evidence.nonce);
    assert_eq!(evidence.nonce, control.nonce);
    assert_eq!(evidence.object_format, control.object_format);
    assert_eq!(evidence.payload_sha256, control.payload_sha256);
    assert_eq!(evidence.vault_root, control.vault_root);
    evidence.stage
}

fn secret_canaries() -> &'static [(&'static str, &'static [u8])] {
    &[
        ("password", PASSWORD),
        ("in-place base", FORCE_KILL_IN_PLACE_BASE_PLAINTEXT),
        ("in-place ours", FORCE_KILL_IN_PLACE_OURS_PLAINTEXT),
        (
            "in-place theirs",
            FORCE_KILL_IN_PLACE_THEIRS_PLAINTEXT,
        ),
        (
            "in-place merged",
            FORCE_KILL_IN_PLACE_MERGED_PLAINTEXT,
        ),
        ("rename base", FORCE_KILL_RENAME_BASE_PLAINTEXT),
        ("rename merged", FORCE_KILL_RENAME_MERGED_PLAINTEXT),
        ("password prefix fragment", PASSWORD_PREFIX_FRAGMENT),
        ("password suffix fragment", PASSWORD_SUFFIX_FRAGMENT),
        (
            "in-place base-left fragment",
            IN_PLACE_BASE_LEFT_FRAGMENT,
        ),
        (
            "in-place shared-center fragment",
            IN_PLACE_SHARED_CENTER_FRAGMENT,
        ),
        (
            "in-place base-right fragment",
            IN_PLACE_BASE_RIGHT_FRAGMENT,
        ),
        (
            "in-place left-variant fragment",
            IN_PLACE_LEFT_VARIANT_FRAGMENT,
        ),
        (
            "in-place right-variant fragment",
            IN_PLACE_RIGHT_VARIANT_FRAGMENT,
        ),
        (
            "rename shared-prefix fragment",
            RENAME_SHARED_PREFIX_FRAGMENT,
        ),
        ("rename base-tail fragment", RENAME_BASE_TAIL_FRAGMENT),
        (
            "rename merged-tail fragment",
            RENAME_MERGED_TAIL_FRAGMENT,
        ),
    ]
}

fn assert_bytes_have_no_secret_canaries(label: &Path, bytes: &[u8]) {
    for &(name, canary) in secret_canaries() {
        assert!(
            !bytes
                .windows(canary.len())
                .any(|window| window == canary),
            "{name} plaintext/password canary found in {}",
            label.display()
        );
    }
}

fn matching_secret_canary_names(bytes: &[u8]) -> Vec<&'static str> {
    secret_canaries()
        .iter()
        .filter_map(|&(name, canary)| {
            bytes
                .windows(canary.len())
                .any(|window| window == canary)
                .then_some(name)
        })
        .collect()
}

fn read_regular_tree_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
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
            files.push((entry.path(), bytes));
        }
    }
    files
}

fn assert_regular_tree_has_no_secret_canaries(root: &Path) {
    for (path, bytes) in read_regular_tree_files(root) {
        assert_bytes_have_no_secret_canaries(&path, &bytes);
    }
}

fn read_all_git_objects(root: &Path) -> Vec<u8> {
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
    output.stdout
}

fn assert_all_git_objects_have_no_secret_canaries(root: &Path) {
    let bytes = read_all_git_objects(root);
    assert_bytes_have_no_secret_canaries(
        &root.join(".git-all-objects-decompressed"),
        &bytes,
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

type ChildDropEvidence = Arc<Mutex<Option<(u32, Result<ExitStatus, String>)>>>;

struct ChildGuard {
    child: Option<Child>,
    drop_evidence: Option<ChildDropEvidence>,
}

fn terminate_child_bounded(child: &mut Child) -> io::Result<ExitStatus> {
    let pid = child.id();
    let deadline = Instant::now() + CHILD_TERMINATION_TIMEOUT;
    let mut last_kill_error = None;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if let Err(error) = child.kill() {
            last_kill_error = Some(error);
        }
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "child {pid} did not terminate within {CHILD_TERMINATION_TIMEOUT:?}; \
                     last kill error: {last_kill_error:?}"
                ),
            ));
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

impl ChildGuard {
    fn spawn(mut command: Command) -> io::Result<Self> {
        command.spawn().map(|child| Self {
            child: Some(child),
            drop_evidence: None,
        })
    }

    fn spawn_with_drop_evidence(
        mut command: Command,
        drop_evidence: ChildDropEvidence,
    ) -> io::Result<Self> {
        command.spawn().map(|child| Self {
            child: Some(child),
            drop_evidence: Some(drop_evidence),
        })
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
        let status = terminate_child_bounded(self.child_mut())?;
        drop(self.child.take().expect("terminated child guard disarms"));
        Ok(status)
    }

    fn disarm_reaped(&mut self, status: ExitStatus) -> ExitStatus {
        drop(self.child.take().expect("reaped child guard disarms"));
        status
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let pid = child.id();
            let result = terminate_child_bounded(child).map_err(|error| error.to_string());
            if let Some(evidence) = self.drop_evidence.as_ref()
                && let Ok(mut slot) = evidence.lock()
            {
                *slot = Some((pid, result));
            }
        }
        drop(self.child.take());
    }
}

struct DetachedFixtureCleanupGuard {
    root: Option<PathBuf>,
}

impl DetachedFixtureCleanupGuard {
    fn new(root: PathBuf) -> Self {
        Self { root: Some(root) }
    }

    fn disarm(&mut self) {
        assert!(
            self.root.take().is_some(),
            "detached fixture cleanup guard remains armed"
        );
    }
}

impl Drop for DetachedFixtureCleanupGuard {
    fn drop(&mut self) {
        if let Some(root) = self.root.take() {
            remove_directory_best_effort(&root);
        }
    }
}

fn wait_for_setup_child(
    child: &mut ChildGuard,
    control_root: &Path,
    request: &SetupRequest,
) -> ForceKillControl {
    let setup_pid = child.id();
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .expect("setup child status polls")
        {
            break child.disarm_reaped(status);
        }
        assert!(
            Instant::now() < deadline,
            "setup child did not finish before timeout"
        );
        thread::sleep(CHILD_POLL_INTERVAL);
    };
    assert!(status.success(), "setup child failed: {status:?}");
    let control = read_control_at(&control_root.join(CONTROL_FILE));
    validate_control_against_setup(&control, request);
    read_and_validate_ready(
        &control_root.join(SETUP_READY_FILE),
        &ready_record_for_pid(&control, ChildRole::Setup, setup_pid),
    );
    control
}

fn wait_for_ready(child: &mut ChildGuard, ready_path: &Path, expected: &ReadyRecord) {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if ready_path
            .try_exists()
            .expect("writer readiness metadata inspects")
        {
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

fn wait_for_completed_child(
    child: &mut ChildGuard,
    ready_path: &Path,
    expected: &ReadyRecord,
) -> ExitStatus {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let mut ready = false;
    loop {
        if !ready
            && ready_path
                .try_exists()
                .expect("completed child readiness metadata inspects")
        {
            read_and_validate_ready(ready_path, expected);
            ready = true;
        }
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .expect("recovery child status polls")
        {
            let status = child.disarm_reaped(status);
            assert!(
                ready,
                "force-kill child exited without durable completion signal"
            );
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "force-kill child did not finish before timeout"
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
fn assert_no_child_processes(_pid: u32) {
    // Intentionally not evidence for Windows-native process-tree termination. That
    // remains gated on a Job Object active-process-zero barrier in the Windows shard.
}

fn write_control(directory: &Path, control: &ForceKillControl) {
    validate_control(control);
    let bytes = serde_json::to_vec(control).expect("force-kill control serializes");
    write_atomic_synced(&directory.join(CONTROL_FILE), &bytes)
        .expect("force-kill control publishes durably");
}

#[derive(Debug, Eq, PartialEq, Serialize)]
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

fn pre_stable_snapshot_sha256(root: &Path) -> String {
    let bytes = serde_json::to_vec(&pre_stable_snapshot(root))
        .expect("pre-stable snapshot serializes canonically");
    hex_digest(digest(&bytes))
}

#[allow(
    clippy::too_many_lines,
    reason = "keep one auditable setup/writer/recovery/verifier protocol"
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
    let control_directory = TestDirectory::new();
    let control_root = fs::canonicalize(control_directory.path())
        .expect("force-kill control root canonicalizes before publication");
    let fixture_owner_root = control_root.join("fixture-owner");
    fs::create_dir(&fixture_owner_root).expect("parent-owned fixture root creates");
    sync_directory(&control_root).expect("parent-owned fixture root publication syncs");
    let fixture_owner_root = fs::canonicalize(fixture_owner_root)
        .expect("parent-owned fixture root canonicalizes");
    // Declared before setup and every later ChildGuard: unwind always bounds/reaps a
    // live child before removing the complete parent-owned fixture subtree.
    let mut fixture_cleanup = DetachedFixtureCleanupGuard::new(fixture_owner_root.clone());
    let setup_request = SetupRequest {
        version: 1,
        nonce: Uuid::new_v4().simple().to_string(),
        object_format,
        payload_kind: kind.into(),
        scenario: ForceKillScenario {
            target,
            later_unrelated,
        },
        fixture_owner_root: fixture_owner_root.clone(),
    };
    write_setup_request(&control_root, &setup_request);
    let mut setup_command = child_command(
        &control_root,
        "tests::v5_force_kill_tests::force_kill_setup_child",
    );
    setup_command
        .env("TMPDIR", &fixture_owner_root)
        .env("TMP", &fixture_owner_root)
        .env("TEMP", &fixture_owner_root);
    let mut setup = ChildGuard::spawn(setup_command)
        .expect("force-kill setup child spawns under process guard");
    let control = wait_for_setup_child(&mut setup, &control_root, &setup_request);
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

    assert_no_secret_canaries(&control.vault_root, &control_root);

    let first_recovery_command = child_command(
        &control_root,
        "tests::v5_force_kill_tests::force_kill_recovery_child",
    );
    let mut first_recovery = ChildGuard::spawn(first_recovery_command)
        .expect("first fresh recovery child spawns under process guard");
    let first_ready =
        ready_record_for_pid(&control, ChildRole::RecoveryFirst, first_recovery.id());
    let first_recovered = wait_for_completed_child(
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
    let second_recovered = wait_for_completed_child(
        &mut second_recovery,
        &control_root.join(RECOVERY_SECOND_READY_FILE),
        &second_ready,
    );
    assert!(
        second_recovered.success(),
        "second fresh recovery child failed: {second_recovered:?}"
    );
    if target.is_pre_stable() {
        assert_eq!(
            pre_stable_snapshot_sha256(&control.vault_root),
            control.pre_stable_snapshot_sha256,
            "pre-stable force-kill preserves original worktree file bytes and live-index bytes"
        );
    }

    let final_command = child_command(
        &control_root,
        "tests::v5_force_kill_tests::force_kill_final_verifier_child",
    );
    let mut final_verifier = ChildGuard::spawn(final_command)
        .expect("fresh final verifier child spawns under process guard");
    let final_ready = ready_record_for_pid(
        &control,
        ChildRole::FinalVerifier,
        final_verifier.id(),
    );
    let final_status = wait_for_completed_child(
        &mut final_verifier,
        &control_root.join(FINAL_READY_FILE),
        &final_ready,
    );
    assert!(
        final_status.success(),
        "fresh final verifier child failed: {final_status:?}"
    );
    assert_no_secret_canaries(&control.vault_root, &control_root);
    let fixture_root = control.vault_root.clone();
    remove_directory_checked(&fixture_root);
    remove_directory_checked(&fixture_owner_root);
    fixture_cleanup.disarm();
    drop(control_directory);
    remove_directory_checked(&control_root);
}

fn remove_directory_best_effort(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) => {
                if error.kind() == io::ErrorKind::NotFound {
                    return;
                }
                if Instant::now() < deadline
                    && matches!(
                        error.kind(),
                        io::ErrorKind::PermissionDenied
                            | io::ErrorKind::DirectoryNotEmpty
                            | io::ErrorKind::Other
                    )
                {
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                return;
            }
        }
    }
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
    assert!(
        !path
            .try_exists()
            .expect("force-kill cleanup path metadata remains readable"),
        "force-kill directory remains after cleanup"
    );
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
fn v5_force_kill_canaries_are_long_distinct_and_have_no_metadata_exemptions() {
    let canaries = secret_canaries();
    assert_eq!(
        canaries
            .iter()
            .map(|(name, _)| *name)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "password",
            "in-place base",
            "in-place ours",
            "in-place theirs",
            "in-place merged",
            "rename base",
            "rename merged",
            "password prefix fragment",
            "password suffix fragment",
            "in-place base-left fragment",
            "in-place shared-center fragment",
            "in-place base-right fragment",
            "in-place left-variant fragment",
            "in-place right-variant fragment",
            "rename shared-prefix fragment",
            "rename base-tail fragment",
            "rename merged-tail fragment",
        ])
    );
    assert_bound_secret_fragments(
        "password",
        PASSWORD,
        PASSWORD,
        &[
            ("password prefix fragment", PASSWORD_PREFIX_FRAGMENT),
            ("password suffix fragment", PASSWORD_SUFFIX_FRAGMENT),
        ],
    );
    for (index, (name, canary)) in canaries.iter().enumerate() {
        assert!(
            canary.len() >= 9,
            "{name} canary is long enough to avoid ciphertext noise"
        );
        for (other_index, (other_name, other)) in canaries.iter().enumerate() {
            if index == other_index {
                continue;
            }
            assert!(
                canary != other,
                "{name} and {other_name} use distinct canary bytes"
            );
        }
    }

    let former_exemptions: &[&[&str]] = &[
        &[".git", "config"],
        &[".git", "COMMIT_EDITMSG"],
        &[".git", "MERGE_MSG"],
        &[".git", "logs", "HEAD"],
    ];
    for components in former_exemptions {
        let directory = TestDirectory::new();
        let path = components
            .iter()
            .fold(directory.path().to_path_buf(), |path, component| {
                path.join(component)
            });
        fs::create_dir_all(path.parent().expect("metadata parent exists"))
            .expect("metadata parent creates");
        let mut file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)
            .expect("metadata mutation file creates");
        file.write_all(b"neutral Git metadata prefix\n")
            .expect("metadata prefix appends");
        file.write_all(IN_PLACE_LEFT_VARIANT_FRAGMENT)
            .expect("partial plaintext canary appends to metadata");
        file.sync_all().expect("metadata mutation syncs");
        drop(file);
        let files = read_regular_tree_files(directory.path());
        let (_, bytes) = files
            .iter()
            .find(|(candidate, _)| candidate == &path)
            .expect("raw tree enumerator includes the former metadata exemption");
        assert_eq!(
            matching_secret_canary_names(bytes),
            ["in-place left-variant fragment"],
            "raw mutation contains exactly the intended partial canary"
        );
        assert!(
            std::panic::catch_unwind(|| assert_bytes_have_no_secret_canaries(&path, bytes))
                .is_err(),
            "raw detector rejects an enumerated partial canary in {path:?}"
        );
    }
}

#[test]
fn v5_force_kill_all_object_scan_rejects_partial_canary_in_unreachable_blob() {
    let directory = TestDirectory::new();
    initialize_test_repository_with_format(directory.path(), GitObjectFormat::Sha1);
    let input_path = directory.path().join("unreachable-fragment.bin");
    fs::write(&input_path, IN_PLACE_RIGHT_VARIANT_FRAGMENT)
        .expect("unreachable object mutation fixture writes only the fragment");
    let hash = Command::new("git")
        .current_dir(directory.path())
        .args(["hash-object", "-w", "unreachable-fragment.bin"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("partial fragment writes as an unreachable Git blob");
    assert!(
        hash.status.success(),
        "hash-object failed: {}",
        String::from_utf8_lossy(&hash.stderr)
    );
    let oid = String::from_utf8(hash.stdout)
        .expect("unreachable object OID is UTF-8")
        .trim()
        .to_owned();
    assert!(!oid.is_empty(), "unreachable object OID is non-empty");
    fs::remove_file(&input_path).expect("unreachable object input file removes");
    let reachable = Command::new("git")
        .current_dir(directory.path())
        .args(["rev-list", "--objects", "--all"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("reachable Git objects enumerate");
    assert!(
        reachable.status.success(),
        "reachable object enumeration failed: {}",
        String::from_utf8_lossy(&reachable.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&reachable.stdout).contains(&oid),
        "partial-canary blob is unreachable from every ref"
    );
    let bytes = read_all_git_objects(directory.path());
    assert_eq!(
        matching_secret_canary_names(&bytes),
        ["in-place right-variant fragment"],
        "decompressed all-object stream contains exactly the intended partial canary"
    );
    let label = directory.path().join(".git-all-objects-decompressed");
    assert!(
        std::panic::catch_unwind(|| assert_bytes_have_no_secret_canaries(&label, &bytes)).is_err(),
        "detector rejects the proven partial canary in the decompressed unreachable blob"
    );
}

#[test]
#[ignore = "spawned only by the bounded ChildGuard regression"]
fn force_kill_child_guard_park_child() {
    if std::env::var_os(CHILD_GUARD_TEST_ENV).as_deref()
        != Some(OsStr::new(CHILD_GUARD_TEST_VALUE))
    {
        return;
    }
    let ready_path = PathBuf::from(
        std::env::var_os(CHILD_GUARD_READY_ENV)
            .expect("guard regression child receives a ready path"),
    );
    let mut ready = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&ready_path)
        .expect("guard regression child readiness creates");
    ready
        .write_all(CHILD_GUARD_READY_BYTES)
        .expect("guard regression child readiness writes");
    ready.flush().expect("guard regression readiness flushes");
    ready
        .sync_all()
        .expect("guard regression child readiness syncs");
    drop(ready);
    sync_directory(
        ready_path
            .parent()
            .expect("guard regression ready path has a parent"),
    )
    .expect("guard regression readiness parent syncs");
    park_forever();
}

fn guarded_park_child_command(ready_path: &Path) -> Command {
    let executable = std::env::current_exe().expect("current test executable resolves");
    let mut command = Command::new(executable);
    command
        .args([
            "--ignored",
            "--exact",
            "tests::v5_force_kill_tests::force_kill_child_guard_park_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_GUARD_TEST_ENV, CHILD_GUARD_TEST_VALUE)
        .env(CHILD_GUARD_READY_ENV, ready_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn wait_for_guard_child_ready(child: &mut ChildGuard, ready_path: &Path) {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if ready_path
            .try_exists()
            .expect("guard child readiness metadata inspects")
        {
            assert_eq!(
                fs::read(ready_path).expect("guard child readiness reads"),
                CHILD_GUARD_READY_BYTES,
                "guard child durably acknowledges its parked boundary"
            );
            assert!(
                child
                    .child_mut()
                    .try_wait()
                    .expect("guard child liveness rechecks")
                    .is_none(),
                "guard child remains live after publishing readiness"
            );
            return;
        }
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .expect("guard child status polls")
        {
            panic!("guard child exited before its parked boundary: {status:?}");
        }
        assert!(
            Instant::now() < deadline,
            "guard child did not acknowledge its parked boundary"
        );
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

#[test]
fn v5_force_kill_child_guard_terminates_ready_child_without_blocking_wait() {
    let directory = TestDirectory::new();
    let ready_path = directory.path().join("guard-child.ready");
    let command = guarded_park_child_command(&ready_path);
    let mut child = ChildGuard::spawn(command).expect("guard regression child spawns");
    wait_for_guard_child_ready(&mut child, &ready_path);
    let started = Instant::now();
    let status = child
        .kill_and_wait()
        .expect("guard regression child terminates within the bounded deadline");
    assert!(!status.success(), "guard regression child is force-killed");
    assert!(
        started.elapsed() <= CHILD_TERMINATION_TIMEOUT + Duration::from_secs(1),
        "bounded child termination completes within the declared deadline"
    );
}

#[test]
fn v5_force_kill_child_guard_drop_terminates_and_reaps_ready_child() {
    let directory = TestDirectory::new();
    let ready_path = directory.path().join("guard-drop-child.ready");
    let evidence: ChildDropEvidence = Arc::new(Mutex::new(None));
    let pid;
    {
        let command = guarded_park_child_command(&ready_path);
        let mut child = ChildGuard::spawn_with_drop_evidence(command, Arc::clone(&evidence))
            .expect("drop-path guard regression child spawns");
        pid = child.id();
        wait_for_guard_child_ready(&mut child, &ready_path);
    }
    let (reaped_pid, result) = evidence
        .lock()
        .expect("drop-path child evidence lock is healthy")
        .take()
        .expect("ChildGuard Drop records bounded try-wait evidence");
    assert_eq!(reaped_pid, pid, "Drop evidence binds the exact child PID");
    let status = result.expect("ChildGuard Drop terminates and reaps the ready child");
    assert!(!status.success(), "Drop-path guard child is force-killed");
    #[cfg(target_os = "linux")]
    assert!(
        !PathBuf::from(format!("/proc/{pid}"))
            .try_exists()
            .expect("reaped guard child process metadata inspects"),
        "reaped guard child no longer has a process table entry"
    );
}

#[test]
fn v5_force_kill_detached_fixture_guard_cleans_up_on_unwind_path() {
    let parent = TestDirectory::new();
    let detached = parent.path().join("detached-fixture");
    fs::create_dir(&detached).expect("detached cleanup regression directory creates");
    fs::write(detached.join("sentinel.bin"), b"opaque\n")
        .expect("detached cleanup regression sentinel writes");
    let unwind = std::panic::catch_unwind(|| {
        let _cleanup = DetachedFixtureCleanupGuard::new(detached.clone());
        panic!("intentional detached fixture unwind regression");
    });
    assert!(unwind.is_err(), "cleanup regression exercises a real unwind");
    assert!(
        !detached
            .try_exists()
            .expect("detached cleanup regression metadata inspects"),
        "armed detached fixture guard removes the fixture tree"
    );
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
