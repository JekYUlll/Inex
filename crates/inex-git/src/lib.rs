//! Explicit, ciphertext-only Git integration for Inex vaults.
//!
//! Normal Git merge drivers run while the vault is locked, so the shipped
//! `inex merge-driver` deliberately does nothing and reports a conflict. This
//! crate implements the separate, password-gated `inex git merge` workflow:
//! Git index stages are read as bounded ciphertext blobs, authenticated and
//! decrypted in memory, merged in memory, re-encrypted, written to Git's object
//! database, and then committed to the worktree/index under a recoverable
//! ciphertext-only journal.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use inex_core::atomic::{
    AtomicFileMoveOutcome, CurrentTarget, GIT_ATTRIBUTES_FILE, GIT_IGNORE_FILE, ParentSyncStatus,
    VAULT_LOCAL_DIRECTORY, VaultMutationGuard, WriteCondition,
    atomic_move_verified_file_no_replace, atomic_replace_verified_file,
    open_file_matches_path_and_is_single_link, path_is_supported_local_filesystem, sync_directory,
};
use inex_core::crypto::{DecryptedDocument, EncryptedDocument};
use inex_core::format;
use inex_core::path::{LogicalPath, MAX_LOGICAL_PATH_BYTES};
use inex_core::tree::{self, TreeEntryKind};
use inex_core::vault::{MAX_EDRY_ENVELOPE_BYTES, Vault, VaultError};
use inex_core::vault_config::{KdfPolicy, MAX_VAULT_JSON_BYTES, VaultConfig};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

mod candidate_bundle_v5;

/// Exact repository attribute installed for encrypted Markdown objects.
pub const ATTRIBUTES_RULE: &str = "*.md.enc -text -diff merge=inex";

/// Exact repository-local ignore rule for private runtime state.
pub const IGNORE_RULE: &str = "/.vault-local/";

const DRIVER_NAME: &str = "Inex encrypted Markdown (locked-safe)";
const JOURNAL_FILE: &str = "git-merge-journal-v1.json";
const JOURNAL_STAGING_PREFIX: &str = "git-merge-journal-stage-v4-";
const PRELOCK_RESERVATION_FILE: &str = "git-index-prelock-v4.json";
const PRELOCK_RESERVATION_STAGING_PREFIX: &str = "git-index-prelock-stage-v4-";
const CANDIDATE_INITIAL_RECEIPT_PREFIX: &str = "git-index-candidate-initial-v4-";
const CANDIDATE_FINAL_RECEIPT_PREFIX: &str = "git-index-candidate-final-v4-";
const INDEX_CANDIDATE_PREFIX: &str = "git-index-candidate-v4-";
const INDEX_MARKER_PREFIX: &str = "git-index-lock-marker-v4-";
const INDEX_LOCK_MARKER_MAGIC: &[u8] = b"INEXIDX4\0";
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPOSITORY_METADATA_BYTES: usize = 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 64 * 1024;
const MAX_PRELOCK_RESERVATION_BYTES: usize = 1024;
const MAX_CONFLICTS: usize = 100_000;
const MAX_GIT_PATH_BYTES: usize = MAX_LOGICAL_PATH_BYTES + ".enc".len();
const MINIMUM_GIT_VERSION: (u32, u32) = (2, 36);
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_mins(1);
// Windows CreateProcess limits the complete command line to 32,767 UTF-16
// code units. Keep a 50% margin for platform quoting and implementation
// details, and budget each argument for its worst-case quoting expansion.
const MAX_CHECK_ATTR_COMMAND_UNITS: usize = 16 * 1024;
const CHECK_ATTR_ARGUMENTS: [&str; 6] = ["check-attr", "-z", "text", "diff", "merge", "--"];
const GIT_COMMAND_PREFIX_ARGUMENTS: [&str; 2] = ["-c", "core.fsmonitor=false"];

/// Result of explicit repository-local driver installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallReport {
    /// Whether `.gitattributes` needed a ciphertext rule append.
    pub attributes_changed: bool,
    /// Whether `.gitignore` needed the private-state rule append.
    pub ignore_changed: bool,
}

/// Result of an explicit unlocked merge pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MergeReport {
    /// Number of pending transactions recovered before new work.
    pub recovered_transactions: usize,
    /// Number of clean three-way results encrypted and staged.
    pub clean_results: usize,
    /// Number of encrypted unresolved-marker results staged.
    pub unresolved_results: usize,
}

/// Result of an explicit recovery command.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Number of pending transactions completed (zero or one per invocation).
    pub recovered_transactions: usize,
}

/// Locked-safe summary of recoverable Git state and retained v5 scratch data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryStatus {
    /// Whether one legacy or immutable-bundle transaction is pending.
    pub pending_transaction: bool,
    /// Number of exact-name unpublished v5 scratch entries retained in place.
    pub retained_candidate_scratch_count: usize,
}

/// A scrubbed Git integration failure.
#[derive(Debug, Error)]
pub enum GitError {
    /// No absolute, regular Git executable could be resolved.
    #[error("a regular Git executable could not be resolved")]
    GitExecutableUnavailable,
    /// Older Git versions do not treat `core.fsmonitor=false` as a boolean.
    #[error("Git 2.36 or newer is required for safe encrypted merge plumbing")]
    UnsupportedGitVersion,
    /// The running Inex binary cannot be installed as a fixed driver path.
    #[error("the running Inex executable cannot be installed as a safe Git driver")]
    DriverExecutableUnavailable,
    /// The selected vault root is not a normal local directory.
    #[error("the vault root is not a safe directory")]
    UnsafeRoot,
    /// The selected vault is not exactly the repository worktree root.
    #[error("the vault must be the top-level Git worktree")]
    NotRepositoryRoot,
    /// A bounded Git plumbing command failed.
    #[error("Git plumbing failed during {operation}")]
    GitCommandFailed {
        /// Fixed operation category; no arguments or output are retained.
        operation: GitOperation,
    },
    /// A Git command exceeded its operation-specific output bound.
    #[error("Git plumbing output exceeded its bound during {operation}")]
    GitOutputTooLarge {
        /// Fixed operation category; no output bytes are retained.
        operation: GitOperation,
    },
    /// Git emitted bytes outside the strict plumbing grammar.
    #[error("Git returned malformed plumbing output")]
    MalformedGitOutput,
    /// An unmerged path or mode is outside the Inex portable profile.
    #[error("Git contains an unsupported encrypted conflict entry")]
    UnsupportedConflictEntry,
    /// A conflict stage failed EDRY authentication in the selected vault.
    #[error("an encrypted Git stage failed vault authentication")]
    StageAuthenticationFailed,
    /// Git index stages changed after the merge plan was prepared.
    #[error("Git index conflict stages changed concurrently")]
    IndexChanged,
    /// The worktree no longer contains the expected conflict ciphertext.
    #[error("the encrypted worktree file changed concurrently")]
    WorktreeChanged,
    /// A pending journal cannot be reconciled without overwriting newer state.
    #[error("pending encrypted merge recovery conflicts with current repository state")]
    RecoveryConflict,
    /// A pending journal is truncated, noncanonical, or otherwise invalid.
    #[error("pending encrypted merge recovery metadata is invalid")]
    InvalidJournal,
    /// A visible commit lacks a confirmed filesystem durability barrier.
    #[error(
        "encrypted merge state is visible but crash durability is not confirmed; recovery journal retained"
    )]
    DurabilityNotConfirmed,
    /// A second transaction was attempted while a journal already exists.
    #[error("an encrypted merge recovery transaction is already pending")]
    JournalAlreadyExists,
    /// Repository metadata is too large, non-UTF-8, or unsafe to update.
    #[error("repository Git metadata is unsafe or exceeds its bound")]
    UnsafeRepositoryMetadata,
    /// Effective attributes do not force ciphertext-safe handling.
    #[error("effective Git attributes do not select the locked-safe Inex driver")]
    IneffectiveAttributes,
    /// Split indexes reference a second file outside the durability model.
    #[error("Git split-index repositories are unsupported for durable encrypted merges")]
    SplitIndexUnsupported,
    /// The merged body exceeded the frozen EDRY plaintext limit.
    #[error("three-way merge output exceeds the EDRY v1 plaintext limit")]
    MergeOutputTooLarge,
    /// An authenticated unresolved result still needs editor resolution.
    #[error("encrypted merge conflicts remain")]
    UnresolvedResults,
    /// Core vault validation or an encrypted write failed.
    #[error("encrypted vault merge operation failed")]
    Vault(#[source] VaultError),
    /// A scrubbed filesystem operation failed.
    #[error("Git integration I/O failed during {operation}: {kind:?}")]
    Io {
        /// Fixed operation category.
        operation: GitIoOperation,
        /// Stable standard-library error class.
        kind: io::ErrorKind,
    },
}

impl From<VaultError> for GitError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

/// Fixed Git plumbing operation names used in scrubbed diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitOperation {
    DiscoverRepository,
    ConfigureRepository,
    InspectHistory,
    ReadIndex,
    ReadObject,
    WriteObject,
    UpdateIndex,
}

impl fmt::Display for GitOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DiscoverRepository => "repository discovery",
            Self::ConfigureRepository => "repository-local configuration",
            Self::InspectHistory => "merge history inspection",
            Self::ReadIndex => "index inspection",
            Self::ReadObject => "encrypted object read",
            Self::WriteObject => "encrypted object write",
            Self::UpdateIndex => "index update",
        })
    }
}

/// Fixed filesystem operation names used in scrubbed diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitIoOperation {
    ResolveRoot,
    InspectMetadata,
    ReadMetadata,
    WriteJournal,
    ReadJournal,
    RemoveJournal,
    SyncGitState,
    SpawnGit,
    CommunicateGit,
}

impl fmt::Display for GitIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResolveRoot => "resolving the vault root",
            Self::InspectMetadata => "inspecting repository metadata",
            Self::ReadMetadata => "reading bounded repository metadata",
            Self::WriteJournal => "writing encrypted merge recovery metadata",
            Self::ReadJournal => "reading encrypted merge recovery metadata",
            Self::RemoveJournal => "removing encrypted merge recovery metadata",
            Self::SyncGitState => "synchronizing Git object and index state",
            Self::SpawnGit => "starting Git plumbing",
            Self::CommunicateGit => "communicating with Git plumbing",
        })
    }
}

/// Install the locked-safe merge driver into one repository only.
///
/// `.gitattributes` and `.gitignore` are updated by verified atomic metadata
/// replacement. Git configuration is written with `--local`; global and
/// system configuration are disabled for every subprocess.
///
/// # Errors
///
/// Returns [`GitError`] for an unsafe root/metadata file, a non-root worktree,
/// a failed local Git command, or post-write verification mismatch.
pub fn install_driver(vault_root: &Path) -> Result<InstallReport, GitError> {
    let git = Git::open(vault_root)?;
    validate_locked_vault_metadata(&git.root)?;
    let driver_command = installed_driver_command()?;
    let vault_tree =
        tree::scan_vault_tree(&git.root).map_err(|_| GitError::UnsafeRepositoryMetadata)?;
    git.sync_configuration()?;
    let ignore_changed = ensure_repository_line(&git.root, GIT_IGNORE_FILE, IGNORE_RULE)?;
    let attributes_changed =
        ensure_repository_line(&git.root, GIT_ATTRIBUTES_FILE, ATTRIBUTES_RULE)?;
    sync_directory(&git.root).map_err(|_| GitError::DurabilityNotConfirmed)?;

    git.configure("merge.inex.name", DRIVER_NAME)?;
    git.configure("merge.inex.driver", &driver_command)?;
    #[cfg(windows)]
    git.configure("core.longPaths", "true")?;
    git.sync_configuration()?;

    git.verify_configuration("merge.inex.name", DRIVER_NAME)?;
    git.verify_configuration("merge.inex.driver", &driver_command)?;
    git.verify_attributes_for_path("__inex_probe__.md.enc")?;
    git.verify_attributes_for_path("__inex_probe__/entry.md.enc")?;
    let physical_paths = vault_tree
        .entries()
        .iter()
        .filter(|entry| entry.kind() == TreeEntryKind::File)
        .map(|entry| format!("{}.enc", entry.logical_path()))
        .collect::<Vec<_>>();
    let paths = physical_paths
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    git.verify_attributes_for_paths(&paths)?;
    #[cfg(windows)]
    git.verify_configuration("core.longPaths", "true")?;

    Ok(InstallReport {
        attributes_changed,
        ignore_changed,
    })
}

fn validate_locked_vault_metadata(root: &Path) -> Result<(), GitError> {
    let path = root.join(inex_core::vault::VAULT_CONFIG_FILE);
    let bytes = read_regular_bounded(&path, MAX_VAULT_JSON_BYTES)
        .map_err(|_| GitError::UnsafeRepositoryMetadata)?;
    VaultConfig::parse_untrusted(&bytes, KdfPolicy::default())
        .map_err(|_| GitError::UnsafeRepositoryMetadata)?;
    Ok(())
}

/// Recover any one pending ciphertext-only worktree/index transaction.
///
/// Recovery requires an unlocked vault so the Git object recorded by the
/// journal can be authenticated before it is written or staged.
///
/// # Errors
///
/// Returns [`GitError`] when journal, index, worktree, or object state cannot
/// be reconciled without overwriting a concurrent change.
pub fn recover(vault: &Vault) -> Result<RecoveryReport, GitError> {
    let git = Git::open(vault.root())?;
    let recovered = recover_pending(vault, &git)?;
    Ok(RecoveryReport {
        recovered_transactions: usize::from(recovered),
    })
}

/// Inspect locked-safe Git recovery state without mutating it.
///
/// This check reads only bounded path/OID/ciphertext-digest metadata. It does
/// not start Git, unlock a vault, remove retained v5 scratch entries, or mutate
/// recovery state. A pending result still requires [`recover`] with an
/// authenticated vault once the corresponding recovery writer is available.
///
/// # Errors
///
/// Returns [`GitError`] when active state is ambiguous, link-like,
/// hard-linked, oversized, truncated, or fails its strict versioned schema.
pub fn recovery_status(vault_root: &Path) -> Result<RecoveryStatus, GitError> {
    let _guard = VaultMutationGuard::acquire(vault_root).map_err(map_atomic_error)?;
    let v5 = candidate_bundle_v5::inspect_candidate_bundle_namespace_v5(vault_root)?;
    let (legacy_pending, matching_v5_journal) =
        legacy_has_pending_recovery(vault_root, v5.stable_bundle_basename.as_deref())?;
    if v5.stable_bundle_basename.is_some() && legacy_pending && !matching_v5_journal {
        return Err(GitError::RecoveryConflict);
    }
    Ok(RecoveryStatus {
        pending_transaction: legacy_pending || v5.stable_bundle_basename.is_some(),
        retained_candidate_scratch_count: v5.retained_scratch_count,
    })
}

/// Inspect whether a structurally valid encrypted merge transaction is pending.
///
/// This compatibility wrapper preserves the pre-v5 boolean API. Retained
/// unpublished v5 scratch entries are reported by [`recovery_status`] but do
/// not themselves count as pending recovery.
///
/// # Errors
///
/// Returns [`GitError`] under the same fail-closed conditions as
/// [`recovery_status`].
pub fn has_pending_recovery(vault_root: &Path) -> Result<bool, GitError> {
    Ok(recovery_status(vault_root)?.pending_transaction)
}

fn validate_v5_journal_stable_bundle(
    vault_root: &Path,
    stable_bundle_basename: &str,
    journal: &BundleMergeJournalV5,
) -> Result<(), GitError> {
    if journal.reference.bundle_basename != stable_bundle_basename {
        return Err(GitError::RecoveryConflict);
    }
    let inventory = candidate_bundle_v5::validate_candidate_bundle_inventory_v5(
        vault_root,
        stable_bundle_basename,
        Some(&journal.reference.manifest),
    )?;
    if inventory.manifest.object_format != journal.reference.object_format
        || inventory.manifest.token != journal.reference.token
    {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn legacy_has_pending_recovery(
    vault_root: &Path,
    ignored_v5_stable_basename: Option<&str>,
) -> Result<(bool, bool), GitError> {
    let mut reserved_names = exact_reserved_private_names(vault_root)?;
    if let Some(basename) = ignored_v5_stable_basename
        && !reserved_names.remove(basename)
    {
        return Err(GitError::RecoveryConflict);
    }
    let pending = read_journal(vault_root)?;
    let prelock = read_prelock_reservation(vault_root)?;
    if let Some(pending) = &pending {
        if let PendingMergeJournal::BundleV5(journal) = pending {
            if prelock.is_some()
                || ignored_v5_stable_basename != Some(journal.reference.bundle_basename.as_str())
                || reserved_names != BTreeSet::from([JOURNAL_FILE.to_owned()])
            {
                return Err(GitError::RecoveryConflict);
            }
            validate_v5_journal_stable_bundle(
                vault_root,
                &journal.reference.bundle_basename,
                journal,
            )?;
            return Ok((true, true));
        }
        if let Some(reservation) = &prelock {
            let PendingMergeJournal::Cas(journal) = pending else {
                return Err(GitError::RecoveryConflict);
            };
            if !prelock_matches_cas_journal(reservation, journal) {
                return Err(GitError::RecoveryConflict);
            }
            validate_prelock_private_inventory(vault_root, reservation, true, false)?;
            for (phase, expected) in [
                (
                    CandidateReceiptPhase::Initial,
                    initial_candidate_receipt(reservation),
                ),
                (
                    CandidateReceiptPhase::Final,
                    final_candidate_receipt(
                        reservation,
                        journal.candidate_index_size,
                        &journal.candidate_index_sha256,
                    ),
                ),
            ] {
                if let Some(actual) =
                    read_candidate_receipt(vault_root, &reservation.lock_token, phase)?
                    && actual != expected
                {
                    return Err(GitError::RecoveryConflict);
                }
            }
        } else if reserved_names.iter().any(|name| {
            name == PRELOCK_RESERVATION_FILE
                || name.starts_with(PRELOCK_RESERVATION_STAGING_PREFIX)
                || name.starts_with(CANDIDATE_INITIAL_RECEIPT_PREFIX)
                || name.starts_with(CANDIDATE_FINAL_RECEIPT_PREFIX)
        }) {
            return Err(GitError::RecoveryConflict);
        }
        return Ok((true, false));
    }
    if let Some(reservation) = &prelock {
        validate_prelock_private_inventory(vault_root, reservation, false, false)?;
        if !path_entry_is_absent(&prelock_reservation_staging_path(
            vault_root,
            &reservation.lock_token,
        ))? {
            return Err(GitError::RecoveryConflict);
        }
        validate_prelock_owned_files(vault_root, reservation)?;
        return Ok((true, false));
    }
    match inspect_orphan_prelock_staging(vault_root, &reserved_names)? {
        OrphanPrelockStaging::Exact { .. } => return Ok((true, false)),
        OrphanPrelockStaging::Conflict => return Err(GitError::RecoveryConflict),
        OrphanPrelockStaging::None => {}
    }
    if !matches!(
        inspect_abandoned_cas_reservation(vault_root)?,
        AbandonedCasReservation::None
    ) {
        return Ok((true, false));
    }
    if reserved_names.is_empty() {
        Ok((false, false))
    } else {
        Err(GitError::RecoveryConflict)
    }
}

/// Resolve all currently unmerged encrypted Markdown paths in memory.
///
/// Clean results and diff3 conflict-marker results are both committed as EDRY
/// ciphertext and staged at index stage zero. Conflict results carry the
/// authenticated `UNRESOLVED_MERGE` flag and are counted separately.
///
/// # Errors
///
/// Returns [`GitError`] for invalid/authentication-failing stages, unsupported
/// path/mode conflicts, concurrent index/worktree changes, or a failed
/// recoverable transaction. A successfully encrypted unresolved result is not
/// itself an error; callers use [`MergeReport::unresolved_results`] to choose a
/// nonzero CLI status.
pub fn merge(vault: &Vault, modified_at_ms: i64) -> Result<MergeReport, GitError> {
    let git = Git::open(vault.root())?;
    let recovered = recover_pending(vault, &git)?;
    let tree_guard = VaultMutationGuard::acquire(vault.root()).map_err(map_atomic_error)?;
    tree::scan_vault_tree(vault.root()).map_err(|_| GitError::UnsupportedConflictEntry)?;
    drop(tree_guard);
    let conflicts = git.unmerged_entries()?;
    validate_conflict_set(&conflicts)?;
    reject_conflict_stage_zero(&git, &conflicts)?;
    let tracked_identities = tracked_identity_index(vault, &git)?;
    let plans = preflight_conflict_identities(vault, &git, &conflicts, &tracked_identities)?;
    let attribute_paths = merge_plan_attribute_paths(&plans)?;
    let attribute_path_refs = attribute_paths
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    git.verify_attributes_for_paths(&attribute_path_refs)?;
    let mut report = MergeReport {
        recovered_transactions: usize::from(recovered),
        ..MergeReport::default()
    };

    for plan in plans {
        let unresolved = match plan {
            MergePlan::InPlace { conflict } => {
                let prepared =
                    prepare_result(vault, &git, &conflict, &tracked_identities, modified_at_ms)?;
                commit_result(vault, &git, &conflict, &prepared)?;
                prepared.unresolved
            }
            MergePlan::DetectedRename {
                conflict,
                stage_paths,
                renamed_side,
                provenance,
            } => {
                let prepared = prepare_detected_rename_result(
                    vault,
                    &git,
                    &conflict,
                    &stage_paths,
                    renamed_side,
                    modified_at_ms,
                )?;
                commit_detected_rename_result(
                    vault,
                    &git,
                    &conflict,
                    &stage_paths,
                    renamed_side,
                    &provenance,
                    &prepared,
                )?;
                prepared.unresolved
            }
            MergePlan::SplitRename {
                source,
                destination,
                renamed_side,
                provenance,
            } => {
                let prepared = prepare_split_rename_result(
                    vault,
                    &git,
                    &source,
                    &destination,
                    renamed_side,
                    modified_at_ms,
                )?;
                commit_split_rename_result(
                    vault,
                    &git,
                    &source,
                    &destination,
                    renamed_side,
                    &provenance,
                    &prepared,
                )?;
                prepared.unresolved
            }
        };
        if unresolved {
            report.unresolved_results = report.unresolved_results.saturating_add(1);
        } else {
            report.clean_results = report.clean_results.saturating_add(1);
        }
    }
    Ok(report)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StageEntry {
    mode: String,
    oid: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl GitObjectFormat {
    const fn oid_hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RenameProvenance {
    object_format: GitObjectFormat,
    ours_commit: String,
    theirs_commit: String,
    base_commit: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConflictEntry {
    physical_path: String,
    logical_path: LogicalPath,
    stages: [Option<StageEntry>; 3],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrackedIdentity {
    physical_path: String,
    logical_path: LogicalPath,
    entry: StageEntry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedStageIdentity {
    logical_path: LogicalPath,
    file_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum RenameSide {
    Ours,
    Theirs,
}

impl RenameSide {
    const fn stage_index(self) -> usize {
        match self {
            Self::Ours => 1,
            Self::Theirs => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MergePlan {
    InPlace {
        conflict: ConflictEntry,
    },
    DetectedRename {
        conflict: ConflictEntry,
        stage_paths: [Option<LogicalPath>; 3],
        renamed_side: RenameSide,
        provenance: RenameProvenance,
    },
    SplitRename {
        source: ConflictEntry,
        destination: TrackedIdentity,
        renamed_side: RenameSide,
        provenance: RenameProvenance,
    },
}

struct PreparedResult {
    encrypted: EncryptedDocument,
    result_oid: String,
    file_id: String,
    unresolved: bool,
    stage_ciphertexts: [Option<Vec<u8>>; 3],
}

struct PreparedRenameResult {
    encrypted: EncryptedDocument,
    result_oid: String,
    file_id: String,
    unresolved: bool,
    source_stage_ciphertexts: [Option<Vec<u8>>; 3],
    destination_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MergeJournal {
    version: u32,
    physical_path: String,
    result_mode: String,
    stages: [Option<StageEntry>; 3],
    expected_worktree_sha256: String,
    result_oid: String,
    result_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RenameMergeJournal {
    version: u32,
    source_physical_path: String,
    destination_physical_path: String,
    result_mode: String,
    source_stages: [Option<StageEntry>; 3],
    destination_stage: StageEntry,
    renamed_side: RenameSide,
    provenance: RenameProvenance,
    file_id: String,
    expected_source_worktree_sha256: Option<String>,
    expected_destination_worktree_sha256: String,
    result_oid: String,
    result_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DetectedRenameJournal {
    version: u32,
    source_physical_path: String,
    destination_physical_path: String,
    result_mode: String,
    stages: [Option<StageEntry>; 3],
    renamed_side: RenameSide,
    provenance: RenameProvenance,
    file_id: String,
    expected_destination_worktree_sha256: String,
    result_oid: String,
    result_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    content = "payload",
    rename_all = "snake_case"
)]
enum MergeJournalPayload {
    InPlace(MergeJournal),
    Rename(RenameMergeJournal),
    DetectedRename(DetectedRenameJournal),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CasMergeJournal {
    version: u32,
    object_format: GitObjectFormat,
    lock_token: String,
    lock_marker_sha256: String,
    candidate_file: String,
    expected_index_sha256: String,
    expected_index_size: u64,
    candidate_index_sha256: String,
    candidate_index_size: u64,
    transaction: MergeJournalPayload,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleMergeJournalV5 {
    version: u32,
    reference: candidate_bundle_v5::CandidateBundleTransactionReferenceV5,
    index_lock_marker: candidate_bundle_v5::CanonicalBytesReferenceV5,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PreLockReservation {
    version: u32,
    object_format: GitObjectFormat,
    lock_token: String,
    candidate_file: String,
    expected_index_sha256: String,
    expected_index_size: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CandidateReceiptPhase {
    Initial,
    Final,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateOwnershipReceipt {
    version: u32,
    phase: CandidateReceiptPhase,
    lock_token: String,
    candidate_file: String,
    candidate_index_sha256: String,
    candidate_index_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingMergeJournal {
    InPlace(MergeJournal),
    Rename(RenameMergeJournal),
    DetectedRename(DetectedRenameJournal),
    Cas(CasMergeJournal),
    BundleV5(BundleMergeJournalV5),
}

struct PreparedIndexCas {
    root: PathBuf,
    prelock: PreLockReservation,
    object_format: GitObjectFormat,
    lock_token: String,
    lock_marker_sha256: String,
    candidate_file: String,
    expected_index_sha256: String,
    expected_index_size: u64,
    candidate_index_sha256: String,
    candidate_index_size: u64,
    armed: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PreLockOwnershipPhase {
    Reservation,
    Candidate,
    InitialReceipt,
    FinalReceipt,
    MarkerStaging,
}

struct PreLockReservationGuard {
    root: PathBuf,
    reservation: PreLockReservation,
    phase: PreLockOwnershipPhase,
    armed: bool,
}

impl PreLockReservationGuard {
    fn new(root: PathBuf, reservation: PreLockReservation) -> Self {
        Self {
            root,
            reservation,
            phase: PreLockOwnershipPhase::Reservation,
            armed: true,
        }
    }

    fn candidate_created(&mut self) {
        self.phase = PreLockOwnershipPhase::Candidate;
    }

    fn initial_receipt_created(&mut self) {
        self.phase = PreLockOwnershipPhase::InitialReceipt;
    }

    fn final_receipt_created(&mut self) {
        self.phase = PreLockOwnershipPhase::FinalReceipt;
    }

    fn marker_staging_created(&mut self) {
        self.phase = PreLockOwnershipPhase::MarkerStaging;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PreLockReservationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = abort_owned_prelock_reservation(&self.root, &self.reservation, self.phase);
    }
}

impl PreparedIndexCas {
    fn journal(&self, transaction: MergeJournalPayload) -> CasMergeJournal {
        CasMergeJournal {
            version: 4,
            object_format: self.object_format,
            lock_token: self.lock_token.clone(),
            lock_marker_sha256: self.lock_marker_sha256.clone(),
            candidate_file: self.candidate_file.clone(),
            expected_index_sha256: self.expected_index_sha256.clone(),
            expected_index_size: self.expected_index_size,
            candidate_index_sha256: self.candidate_index_sha256.clone(),
            candidate_index_size: self.candidate_index_size,
            transaction,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PreparedIndexCas {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if !matches!(read_journal(&self.root), Ok(None)) {
            return;
        }
        let marker = index_lock_marker_bytes(
            &self.lock_token,
            self.expected_index_size,
            &self.expected_index_sha256,
            self.candidate_index_size,
            &self.candidate_index_sha256,
        );
        match remove_regular_file_if_exact(&index_lock_path(&self.root), &marker) {
            Ok(true) => {
                let _ = abort_owned_prelock_reservation(
                    &self.root,
                    &self.prelock,
                    PreLockOwnershipPhase::FinalReceipt,
                );
            }
            Ok(false) if matches!(path_entry_is_absent(&index_lock_path(&self.root)), Ok(true)) => {
                let _ = abort_owned_prelock_reservation(
                    &self.root,
                    &self.prelock,
                    PreLockOwnershipPhase::FinalReceipt,
                );
            }
            Ok(false) | Err(_) => {}
        }
    }
}

#[derive(Clone, Copy)]
enum IndexMutation<'a> {
    Upsert {
        physical_path: &'a str,
        mode: &'a str,
        oid: &'a str,
    },
    Rename {
        source_physical_path: &'a str,
        destination_physical_path: &'a str,
        mode: &'a str,
        oid: &'a str,
    },
}

struct AuthenticatedRenameRecovery {
    source: ConflictEntry,
    destination: TrackedIdentity,
    result: Vec<u8>,
    result_digest: [u8; 32],
    expected_source_state: CurrentTarget,
    expected_destination_digest: [u8; 32],
    file_id: String,
}

struct AuthenticatedDetectedRenameRecovery {
    conflict: ConflictEntry,
    source_logical_path: LogicalPath,
    result: Vec<u8>,
    result_digest: [u8; 32],
    expected_destination_digest: [u8; 32],
    file_id: String,
}

struct Git {
    executable: PathBuf,
    root: PathBuf,
    object_format: GitObjectFormat,
    index_file: Option<PathBuf>,
}

impl Git {
    fn open(root: &Path) -> Result<Self, GitError> {
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| io_error(GitIoOperation::ResolveRoot, &error))?;
        if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
            return Err(GitError::UnsafeRoot);
        }
        let root = fs::canonicalize(root)
            .map_err(|error| io_error(GitIoOperation::ResolveRoot, &error))?;
        let metadata = fs::symlink_metadata(&root)
            .map_err(|error| io_error(GitIoOperation::ResolveRoot, &error))?;
        if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
            return Err(GitError::UnsafeRoot);
        }
        validate_git_directory(&root)?;
        let mut git = Self {
            executable: discover_git_executable()?,
            root,
            object_format: GitObjectFormat::Sha1,
            index_file: None,
        };
        git.ensure_supported_version()?;
        let object_format = git.run(
            GitOperation::DiscoverRepository,
            ["rev-parse", "--show-object-format"],
            None,
            16,
        )?;
        git.object_format = match one_text_line(&object_format)? {
            "sha1" => GitObjectFormat::Sha1,
            "sha256" => GitObjectFormat::Sha256,
            _ => return Err(GitError::MalformedGitOutput),
        };
        git.ensure_full_index()?;
        let inside = git.run(
            GitOperation::DiscoverRepository,
            ["rev-parse", "--is-inside-work-tree"],
            None,
            16,
        )?;
        if inside.as_slice() != b"true\n" && inside.as_slice() != b"true\r\n" {
            return Err(GitError::NotRepositoryRoot);
        }
        let prefix = git.run(
            GitOperation::DiscoverRepository,
            ["rev-parse", "--show-prefix"],
            None,
            MAX_GIT_PATH_BYTES,
        )?;
        if !matches!(prefix.as_slice(), b"\n" | b"\r\n") {
            return Err(GitError::NotRepositoryRoot);
        }
        Ok(git)
    }

    fn ensure_supported_version(&self) -> Result<(), GitError> {
        let output = self.run(GitOperation::DiscoverRepository, ["version"], None, 256)?;
        validate_git_version(&output)
    }

    fn validate_oid(&self, oid: &str) -> Result<(), GitError> {
        validate_oid(oid)?;
        if oid.len() != self.object_format.oid_hex_len() {
            return Err(GitError::MalformedGitOutput);
        }
        Ok(())
    }

    fn with_index_file(&self, index_file: PathBuf) -> Result<Self, GitError> {
        if !index_file.is_absolute() || index_file.parent().is_none() {
            return Err(GitError::UnsafeRepositoryMetadata);
        }
        Ok(Self {
            executable: self.executable.clone(),
            root: self.root.clone(),
            object_format: self.object_format,
            index_file: Some(index_file),
        })
    }

    fn index_path(&self) -> PathBuf {
        self.index_file
            .clone()
            .unwrap_or_else(|| self.root.join(".git").join("index"))
    }

    fn ensure_full_index(&self) -> Result<(), GitError> {
        let configured = self.run(
            GitOperation::ConfigureRepository,
            [
                "config",
                "--type=bool",
                "--default=false",
                "--get",
                "core.splitIndex",
            ],
            None,
            16,
        )?;
        match one_text_line(&configured)? {
            "false" => {}
            "true" => return Err(GitError::SplitIndexUnsupported),
            _ => return Err(GitError::MalformedGitOutput),
        }
        let shared_index = self.run(
            GitOperation::ReadIndex,
            ["rev-parse", "--shared-index-path"],
            None,
            MAX_GIT_PATH_BYTES,
        )?;
        if !matches!(shared_index.as_slice(), b"" | b"\n" | b"\r\n") {
            return Err(GitError::SplitIndexUnsupported);
        }
        let git_directory = self.root.join(".git");
        let entries = fs::read_dir(&git_directory)
            .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
        for (count, entry) in entries.enumerate() {
            if count >= MAX_CONFLICTS {
                return Err(GitError::SplitIndexUnsupported);
            }
            let entry = entry.map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
            if entry.file_name().to_str().is_some_and(|name| {
                name.as_bytes()
                    .get(.."sharedindex.".len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"sharedindex."))
            }) {
                return Err(GitError::SplitIndexUnsupported);
            }
        }
        Ok(())
    }

    fn configure(&self, key: &str, value: &str) -> Result<(), GitError> {
        self.run(
            GitOperation::ConfigureRepository,
            ["config", "--local", "--replace-all", key, value],
            None,
            1024,
        )?;
        Ok(())
    }

    fn verify_configuration(&self, key: &str, expected: &str) -> Result<(), GitError> {
        let output = self.run(
            GitOperation::ConfigureRepository,
            ["config", "--local", "--get", key],
            None,
            4096,
        )?;
        let value = one_text_line(&output)?;
        if value == expected {
            Ok(())
        } else {
            Err(GitError::MalformedGitOutput)
        }
    }

    fn verify_attributes_for_path(&self, physical_path: &str) -> Result<(), GitError> {
        self.verify_attributes_for_paths(&[physical_path])
    }

    fn verify_attributes_for_paths(&self, physical_paths: &[&str]) -> Result<(), GitError> {
        if physical_paths.is_empty() {
            return Ok(());
        }
        for path in physical_paths {
            validate_physical_path(path)?;
        }
        let mut start = 0;
        while start < physical_paths.len() {
            let end = next_attribute_batch_end(&self.executable, physical_paths, start)?;
            self.verify_attribute_batch(&physical_paths[start..end])?;
            start = end;
        }
        Ok(())
    }

    fn verify_attribute_batch(&self, physical_paths: &[&str]) -> Result<(), GitError> {
        debug_assert!(!physical_paths.is_empty());
        let mut arguments = CHECK_ATTR_ARGUMENTS
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let mut maximum_output = 128_usize;
        for path in physical_paths {
            maximum_output = maximum_output.saturating_add(path.len().saturating_mul(3) + 64);
            arguments.push(OsString::from(path));
        }
        let output = self.run_os(
            GitOperation::ConfigureRepository,
            &arguments,
            None,
            maximum_output,
        )?;
        let records = nul_records(&output)?;
        let expected = [
            ("text".as_bytes(), "unset".as_bytes()),
            ("diff".as_bytes(), "unset".as_bytes()),
            ("merge".as_bytes(), "inex".as_bytes()),
        ];
        if records.len() != expected.len() * 3 * physical_paths.len() {
            return Err(GitError::IneffectiveAttributes);
        }
        for (path_records, physical_path) in
            records.chunks_exact(expected.len() * 3).zip(physical_paths)
        {
            for (chunk, (attribute, value)) in path_records.chunks_exact(3).zip(expected) {
                if chunk[0] != physical_path.as_bytes()
                    || chunk[1] != attribute
                    || chunk[2] != value
                {
                    return Err(GitError::IneffectiveAttributes);
                }
            }
        }
        Ok(())
    }

    fn unmerged_entries(&self) -> Result<BTreeMap<String, ConflictEntry>, GitError> {
        let output = self.run(
            GitOperation::ReadIndex,
            ["ls-files", "-u", "-z"],
            None,
            MAX_GIT_OUTPUT_BYTES,
        )?;
        let entries = parse_unmerged_entries(&output)?;
        for stage in entries
            .values()
            .flat_map(|conflict| conflict.stages.iter().flatten())
        {
            self.validate_oid(&stage.oid)?;
        }
        Ok(entries)
    }

    fn staged_entries(&self) -> Result<Vec<(u8, StageEntry, String)>, GitError> {
        let output = self.run(
            GitOperation::ReadIndex,
            ["ls-files", "-s", "-z"],
            None,
            MAX_GIT_OUTPUT_BYTES,
        )?;
        let mut entries = Vec::new();
        for_each_nul_record(&output, |record| {
            let ((stage, entry), path) = parse_index_record(record)?;
            if entries.len() >= MAX_CONFLICTS {
                return Err(GitError::GitOutputTooLarge {
                    operation: GitOperation::ReadIndex,
                });
            }
            entries.push((stage, entry, path));
            Ok(())
        })?;
        for (_, entry, _) in &entries {
            self.validate_oid(&entry.oid)?;
        }
        Ok(entries)
    }

    fn read_object(&self, oid: &str) -> Result<Vec<u8>, GitError> {
        self.validate_oid(oid)?;
        self.run(
            GitOperation::ReadObject,
            ["cat-file", "blob", oid],
            None,
            MAX_EDRY_ENVELOPE_BYTES,
        )
    }

    fn write_object(&self, ciphertext: &[u8]) -> Result<String, GitError> {
        let output = self.run(
            GitOperation::WriteObject,
            ["hash-object", "-w", "--stdin"],
            Some(ciphertext),
            128,
        )?;
        let oid = one_text_line(&output)?.to_owned();
        self.validate_oid(&oid)?;
        let verified = self.read_object(&oid)?;
        if verified != ciphertext {
            return Err(GitError::MalformedGitOutput);
        }
        self.sync_object(&oid)?;
        Ok(oid)
    }

    fn stage_zero(&self, physical_path: &str) -> Result<Option<StageEntry>, GitError> {
        validate_physical_path(physical_path)?;
        let output = self.run_os(
            GitOperation::ReadIndex,
            &[
                OsString::from("ls-files"),
                OsString::from("-s"),
                OsString::from("-z"),
                OsString::from("--"),
                OsString::from(physical_path),
            ],
            None,
            4096 + physical_path.len(),
        )?;
        if output.is_empty() {
            return Ok(None);
        }
        let records = nul_records(&output)?;
        let mut stage_zero = None;
        for record in records {
            let ((stage, entry), path) = parse_index_record(record)?;
            if path != physical_path {
                return Err(GitError::MalformedGitOutput);
            }
            validate_mode(&entry.mode)?;
            self.validate_oid(&entry.oid)?;
            if stage == 0 && stage_zero.replace(entry).is_some() {
                return Err(GitError::MalformedGitOutput);
            }
        }
        Ok(stage_zero)
    }

    fn resolve_commit(&self, revision: &str) -> Result<String, GitError> {
        if !matches!(revision, "HEAD" | "MERGE_HEAD") {
            return Err(GitError::UnsupportedConflictEntry);
        }
        let revision = format!("{revision}^{{commit}}");
        let output = self.run_os(
            GitOperation::InspectHistory,
            &[
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from(revision),
            ],
            None,
            256,
        )?;
        let oid = one_text_line(&output)?.to_owned();
        self.validate_oid(&oid)?;
        Ok(oid)
    }

    fn single_merge_head(&self) -> Result<String, GitError> {
        let bytes = read_regular_bounded(
            &self.root.join(".git").join("MERGE_HEAD"),
            MAX_REPOSITORY_METADATA_BYTES,
        )?;
        let oid = one_text_line(&bytes)?.to_owned();
        self.validate_oid(&oid)?;
        let resolved = self.resolve_commit("MERGE_HEAD")?;
        if resolved != oid {
            return Err(GitError::UnsupportedConflictEntry);
        }
        Ok(oid)
    }

    fn unique_merge_base(&self, ours: &str, theirs: &str) -> Result<String, GitError> {
        self.validate_oid(ours)?;
        self.validate_oid(theirs)?;
        if ours.len() != theirs.len() {
            return Err(GitError::UnsupportedConflictEntry);
        }
        let output = self.run_os(
            GitOperation::InspectHistory,
            &[
                OsString::from("merge-base"),
                OsString::from("--all"),
                OsString::from(ours),
                OsString::from(theirs),
            ],
            None,
            1024,
        )?;
        let base = one_text_line(&output)?.to_owned();
        self.validate_oid(&base)?;
        if base.len() != ours.len() {
            return Err(GitError::UnsupportedConflictEntry);
        }
        Ok(base)
    }

    fn tree_entry(
        &self,
        commit: &str,
        physical_path: &str,
    ) -> Result<Option<StageEntry>, GitError> {
        self.validate_oid(commit)?;
        validate_physical_path(physical_path)?;
        let output = self.run_os(
            GitOperation::InspectHistory,
            &[
                OsString::from("ls-tree"),
                OsString::from("-z"),
                OsString::from("--full-tree"),
                OsString::from(commit),
                OsString::from("--"),
                OsString::from(physical_path),
            ],
            None,
            4096_usize.saturating_add(physical_path.len()),
        )?;
        if output.is_empty() {
            return Ok(None);
        }
        let records = nul_records(&output)?;
        if records.len() != 1 {
            return Err(GitError::MalformedGitOutput);
        }
        let record = records[0];
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(GitError::MalformedGitOutput)?;
        if &record[tab.saturating_add(1)..] != physical_path.as_bytes() {
            return Err(GitError::MalformedGitOutput);
        }
        let metadata =
            std::str::from_utf8(&record[..tab]).map_err(|_| GitError::MalformedGitOutput)?;
        let mut fields = metadata.split(' ');
        let mode = fields.next().ok_or(GitError::MalformedGitOutput)?;
        let object_type = fields.next().ok_or(GitError::MalformedGitOutput)?;
        let oid = fields.next().ok_or(GitError::MalformedGitOutput)?;
        if fields.next().is_some() || object_type != "blob" {
            return Err(GitError::UnsupportedConflictEntry);
        }
        validate_mode(mode)?;
        self.validate_oid(oid)?;
        if oid.len() != commit.len() {
            return Err(GitError::UnsupportedConflictEntry);
        }
        Ok(Some(StageEntry {
            mode: mode.to_owned(),
            oid: oid.to_owned(),
        }))
    }

    fn update_index(&self, physical_path: &str, mode: &str, oid: &str) -> Result<(), GitError> {
        if self.index_file.is_none() {
            match read_journal(&self.root)? {
                Some(PendingMergeJournal::Cas(journal)) => {
                    return publish_cas_index(
                        self,
                        &journal,
                        IndexMutation::Upsert {
                            physical_path,
                            mode,
                            oid,
                        },
                    );
                }
                Some(PendingMergeJournal::BundleV5(_)) => {
                    return Err(GitError::RecoveryConflict);
                }
                Some(
                    PendingMergeJournal::InPlace(_)
                    | PendingMergeJournal::Rename(_)
                    | PendingMergeJournal::DetectedRename(_),
                )
                | None => {}
            }
        }
        self.update_index_direct(physical_path, mode, oid)
    }

    fn update_index_direct(
        &self,
        physical_path: &str,
        mode: &str,
        oid: &str,
    ) -> Result<(), GitError> {
        validate_physical_path(physical_path)?;
        validate_mode(mode)?;
        self.validate_oid(oid)?;
        self.ensure_full_index()?;
        let mut input = Vec::with_capacity(mode.len() + oid.len() + physical_path.len() + 3);
        input.extend_from_slice(mode.as_bytes());
        input.push(b' ');
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\t');
        input.extend_from_slice(physical_path.as_bytes());
        input.push(0);
        self.run(
            GitOperation::UpdateIndex,
            ["update-index", "-z", "--index-info"],
            Some(&input),
            1024,
        )?;
        self.sync_index()?;
        Ok(())
    }

    fn update_index_rename(
        &self,
        source_physical_path: &str,
        destination_physical_path: &str,
        mode: &str,
        oid: &str,
    ) -> Result<(), GitError> {
        if self.index_file.is_none() {
            match read_journal(&self.root)? {
                Some(PendingMergeJournal::Cas(journal)) => {
                    return publish_cas_index(
                        self,
                        &journal,
                        IndexMutation::Rename {
                            source_physical_path,
                            destination_physical_path,
                            mode,
                            oid,
                        },
                    );
                }
                Some(PendingMergeJournal::BundleV5(_)) => {
                    return Err(GitError::RecoveryConflict);
                }
                Some(
                    PendingMergeJournal::InPlace(_)
                    | PendingMergeJournal::Rename(_)
                    | PendingMergeJournal::DetectedRename(_),
                )
                | None => {}
            }
        }
        self.update_index_rename_direct(source_physical_path, destination_physical_path, mode, oid)
    }

    fn update_index_rename_direct(
        &self,
        source_physical_path: &str,
        destination_physical_path: &str,
        mode: &str,
        oid: &str,
    ) -> Result<(), GitError> {
        validate_physical_path(source_physical_path)?;
        validate_physical_path(destination_physical_path)?;
        if source_physical_path == destination_physical_path {
            return Err(GitError::UnsupportedConflictEntry);
        }
        validate_mode(mode)?;
        self.validate_oid(oid)?;
        self.ensure_full_index()?;

        // `--index-info` applies all records under one Git index lock and
        // publishes one replacement index. Mode zero removes every stage for
        // the source path; the all-zero object id must match the repository's
        // SHA-1 or SHA-256 object-id width.
        let zero_oid = "0".repeat(oid.len());
        let mut input = Vec::with_capacity(
            source_physical_path
                .len()
                .saturating_add(destination_physical_path.len())
                .saturating_add(oid.len().saturating_mul(2))
                .saturating_add(mode.len())
                .saturating_add(8),
        );
        input.extend_from_slice(b"0 ");
        input.extend_from_slice(zero_oid.as_bytes());
        input.push(b'\t');
        input.extend_from_slice(source_physical_path.as_bytes());
        input.push(0);
        input.extend_from_slice(mode.as_bytes());
        input.push(b' ');
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\t');
        input.extend_from_slice(destination_physical_path.as_bytes());
        input.push(0);
        self.run(
            GitOperation::UpdateIndex,
            ["update-index", "-z", "--index-info"],
            Some(&input),
            1024,
        )?;
        self.sync_index()?;
        Ok(())
    }

    fn sync_object(&self, oid: &str) -> Result<(), GitError> {
        self.validate_oid(oid)?;
        let object_directory = self.root.join(".git").join("objects");
        let fanout = object_directory.join(&oid[..2]);
        let object = fanout.join(&oid[2..]);
        validate_local_directory(&object_directory)?;
        validate_local_directory(&fanout)?;
        sync_regular_file(&object, 32 * 1024 * 1024)?;
        sync_directory(&fanout).map_err(|_| GitError::DurabilityNotConfirmed)?;
        sync_directory(&object_directory).map_err(|_| GitError::DurabilityNotConfirmed)
    }

    fn sync_index(&self) -> Result<(), GitError> {
        self.ensure_full_index()?;
        let index = self.index_path();
        let parent = index.parent().ok_or(GitError::DurabilityNotConfirmed)?;
        validate_local_directory(parent)?;
        sync_regular_file(&index, MAX_GIT_OUTPUT_BYTES)?;
        sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)
    }

    fn sync_configuration(&self) -> Result<(), GitError> {
        let git_directory = self.root.join(".git");
        validate_local_directory(&git_directory)?;
        sync_regular_file(&git_directory.join("config"), MAX_REPOSITORY_METADATA_BYTES)?;
        sync_directory(&git_directory).map_err(|_| GitError::DurabilityNotConfirmed)
    }

    fn run<const N: usize>(
        &self,
        operation: GitOperation,
        arguments: [&str; N],
        input: Option<&[u8]>,
        maximum_output: usize,
    ) -> Result<Vec<u8>, GitError> {
        let arguments = arguments.map(OsString::from);
        self.run_os(operation, &arguments, input, maximum_output)
    }

    #[allow(clippy::too_many_lines)] // Keep bounded subprocess teardown in one audited path.
    fn run_os(
        &self,
        operation: GitOperation,
        arguments: &[OsString],
        input: Option<&[u8]>,
        maximum_output: usize,
    ) -> Result<Vec<u8>, GitError> {
        let mut command = Command::new(&self.executable);
        command
            .current_dir(&self.root)
            .args(GIT_COMMAND_PREFIX_ARGUMENTS);
        if self.index_file.is_some() {
            command.args(["-c", "core.splitIndex=false"]);
        }
        command
            .args(arguments)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_PAGER", "cat")
            .env("PAGER", "cat")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(index_file) = &self.index_file {
            command.env("GIT_INDEX_FILE", index_file);
        }
        copy_platform_process_environment(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| io_error(GitIoOperation::SpawnGit, &error))?;
        let stdout = child.stdout.take().ok_or(GitError::Io {
            operation: GitIoOperation::CommunicateGit,
            kind: io::ErrorKind::BrokenPipe,
        })?;
        let mut child_stdin = child.stdin.take();
        let output_too_large = AtomicBool::new(false);
        let (read_result, write_result, status, timed_out) = std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let mut stdout = stdout;
                let mut output = Vec::with_capacity(maximum_output.min(64 * 1024));
                let result = read_bounded(&mut stdout, &mut output, maximum_output);
                if matches!(result, Err(ReadBoundedError::TooLarge)) {
                    output_too_large.store(true, Ordering::Release);
                }
                (result, output)
            });
            let writer = input.map(|bytes| {
                let stdin = child_stdin.take();
                scope.spawn(move || -> io::Result<()> {
                    let mut stdin = stdin.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "Git stdin unavailable")
                    })?;
                    stdin.write_all(bytes)?;
                    stdin.flush()
                })
            });

            let deadline = Instant::now() + GIT_COMMAND_TIMEOUT;
            let (status, timed_out) = loop {
                if output_too_large.load(Ordering::Acquire) {
                    let _ = child.kill();
                    let status = child
                        .wait()
                        .map_err(|error| io_error(GitIoOperation::CommunicateGit, &error))?;
                    break (status, false);
                }
                if let Some(status) = child
                    .try_wait()
                    .map_err(|error| io_error(GitIoOperation::CommunicateGit, &error))?
                {
                    break (status, false);
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let status = child
                        .wait()
                        .map_err(|error| io_error(GitIoOperation::CommunicateGit, &error))?;
                    break (status, true);
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let read = reader.join().map_err(|_| GitError::Io {
                operation: GitIoOperation::CommunicateGit,
                kind: io::ErrorKind::Other,
            })?;
            let write = writer.map(std::thread::ScopedJoinHandle::join).transpose();
            Ok::<_, GitError>((read, write, status, timed_out))
        })?;
        let (read_result, output) = read_result;
        if timed_out {
            return Err(GitError::GitCommandFailed { operation });
        }
        match read_result {
            Ok(()) => {}
            Err(ReadBoundedError::TooLarge) => {
                return Err(GitError::GitOutputTooLarge { operation });
            }
            Err(ReadBoundedError::Io(error)) => {
                return Err(io_error(GitIoOperation::CommunicateGit, &error));
            }
        }
        let written = write_result.map_err(|_| GitError::Io {
            operation: GitIoOperation::CommunicateGit,
            kind: io::ErrorKind::Other,
        });
        let written = written?;
        if let Some(written) = written {
            written.map_err(|error| io_error(GitIoOperation::CommunicateGit, &error))?;
        }
        if !status.success() {
            return Err(GitError::GitCommandFailed { operation });
        }
        Ok(output)
    }
}

fn validate_git_directory(root: &Path) -> Result<(), GitError> {
    let git_directory = root.join(".git");
    validate_local_directory(&git_directory).map_err(|_| GitError::NotRepositoryRoot)
}

fn validate_local_directory(directory: &Path) -> Result<(), GitError> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| GitError::DurabilityNotConfirmed)?;
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        return Err(GitError::DurabilityNotConfirmed);
    }
    if !path_is_supported_local_filesystem(directory)
        .map_err(|error| io_error(GitIoOperation::ResolveRoot, &error))?
    {
        return Err(GitError::DurabilityNotConfirmed);
    }
    Ok(())
}

#[cfg(not(windows))]
fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0
}

enum ReadBoundedError {
    TooLarge,
    Io(io::Error),
}

fn read_bounded(
    reader: &mut impl Read,
    output: &mut Vec<u8>,
    maximum: usize,
) -> Result<(), ReadBoundedError> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(ReadBoundedError::Io)?;
        if read == 0 {
            return Ok(());
        }
        if output.len().saturating_add(read) > maximum {
            return Err(ReadBoundedError::TooLarge);
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn next_attribute_batch_end(
    executable: &Path,
    physical_paths: &[&str],
    start: usize,
) -> Result<usize, GitError> {
    if start >= physical_paths.len() {
        return Ok(start);
    }
    let mut command_units = conservative_argument_units(executable.as_os_str());
    for argument in GIT_COMMAND_PREFIX_ARGUMENTS {
        command_units =
            command_units.saturating_add(conservative_argument_units(OsStr::new(argument)));
    }
    for argument in CHECK_ATTR_ARGUMENTS {
        command_units =
            command_units.saturating_add(conservative_argument_units(OsStr::new(argument)));
    }
    if command_units >= MAX_CHECK_ATTR_COMMAND_UNITS {
        return Err(GitError::GitExecutableUnavailable);
    }

    let mut end = start;
    while end < physical_paths.len() {
        let path_units = conservative_argument_units(OsStr::new(physical_paths[end]));
        if command_units.saturating_add(path_units) > MAX_CHECK_ATTR_COMMAND_UNITS {
            break;
        }
        command_units = command_units.saturating_add(path_units);
        end = end.saturating_add(1);
    }
    if end == start {
        Err(GitError::UnsupportedConflictEntry)
    } else {
        Ok(end)
    }
}

fn conservative_argument_units(argument: &OsStr) -> usize {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        // Rust's Windows process launcher may quote an argument and double
        // every backslash adjacent to a quote or the closing delimiter.
        argument
            .encode_wide()
            .count()
            .saturating_mul(2)
            .saturating_add(3)
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let native_units = argument.as_bytes().len().saturating_add(1);
        let windows_upper_bound = argument
            .to_string_lossy()
            .encode_utf16()
            .count()
            .saturating_mul(2)
            .saturating_add(3);
        native_units.max(windows_upper_bound)
    }
    #[cfg(not(any(unix, windows)))]
    {
        argument
            .to_string_lossy()
            .encode_utf16()
            .count()
            .saturating_mul(2)
            .saturating_add(3)
    }
}

fn discover_git_executable() -> Result<PathBuf, GitError> {
    if let Some(configured) = std::env::var_os("INEX_GIT_PATH") {
        let configured = PathBuf::from(configured);
        if !configured.is_absolute() {
            return Err(GitError::GitExecutableUnavailable);
        }
        return canonical_regular_executable(&configured);
    }

    let path = std::env::var_os("PATH").ok_or(GitError::GitExecutableUnavailable)?;
    for directory in std::env::split_paths(&path) {
        for name in git_executable_names() {
            let candidate = directory.join(name);
            if let Ok(executable) = canonical_regular_executable(&candidate) {
                return Ok(executable);
            }
        }
    }
    Err(GitError::GitExecutableUnavailable)
}

fn installed_driver_command() -> Result<String, GitError> {
    let executable = std::env::current_exe()
        .map_err(|_| GitError::DriverExecutableUnavailable)
        .and_then(|path| {
            fs::canonicalize(path).map_err(|_| GitError::DriverExecutableUnavailable)
        })?;
    let metadata = fs::metadata(&executable).map_err(|_| GitError::DriverExecutableUnavailable)?;
    if !metadata.file_type().is_file() {
        return Err(GitError::DriverExecutableUnavailable);
    }
    driver_command_for_canonical_executable(&executable)
}

fn driver_command_for_canonical_executable(executable: &Path) -> Result<String, GitError> {
    let text = executable
        .to_str()
        .ok_or(GitError::DriverExecutableUnavailable)?;
    // Git expands merge-driver `%` placeholders before shell parsing, so
    // quoting cannot make a percent-bearing executable path literal.
    if text.contains('%') {
        return Err(GitError::DriverExecutableUnavailable);
    }
    Ok(format!("{} merge-driver", shell_quote(text)))
}

fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len().saturating_add(2));
    quoted.push('\'');
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

fn canonical_regular_executable(path: &Path) -> Result<PathBuf, GitError> {
    let canonical = fs::canonicalize(path).map_err(|_| GitError::GitExecutableUnavailable)?;
    let metadata = fs::metadata(&canonical).map_err(|_| GitError::GitExecutableUnavailable)?;
    if !canonical.is_absolute() || !metadata.file_type().is_file() {
        return Err(GitError::GitExecutableUnavailable);
    }
    Ok(canonical)
}

#[cfg(windows)]
fn git_executable_names() -> &'static [&'static str] {
    &["git.exe"]
}

#[cfg(not(windows))]
fn git_executable_names() -> &'static [&'static str] {
    &["git"]
}

fn copy_platform_process_environment(command: &mut Command) {
    #[cfg(windows)]
    for name in ["SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(not(windows))]
    if let Some(value) = std::env::var_os("TMPDIR") {
        command.env("TMPDIR", value);
    }
}

fn ensure_repository_line(root: &Path, name: &str, required: &str) -> Result<bool, GitError> {
    let target = root.join(name);
    let current = read_repository_metadata(&target)?;
    let Some(mut replacement) = append_line_if_missing(&current, required)? else {
        return Ok(false);
    };
    let condition = if current.is_empty() && !target.exists() {
        WriteCondition::IfNoneMatch
    } else {
        WriteCondition::IfMatch(digest(&current))
    };
    let guard = VaultMutationGuard::acquire(root).map_err(map_atomic_error)?;
    let outcome = guard
        .write(&target, &replacement, condition)
        .map_err(map_atomic_error)?;
    if outcome.parent_sync != ParentSyncStatus::Synced {
        return Err(GitError::DurabilityNotConfirmed);
    }
    replacement.fill(0);
    Ok(true)
}

fn read_repository_metadata(path: &Path) -> Result<Vec<u8>, GitError> {
    read_regular_bounded(path, MAX_REPOSITORY_METADATA_BYTES)
}

fn sync_regular_file(path: &Path, maximum: usize) -> Result<(), GitError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| GitError::DurabilityNotConfirmed)?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
    {
        return Err(GitError::DurabilityNotConfirmed);
    }
    let file = open_file_for_sync(path)?;
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|_| GitError::DurabilityNotConfirmed)?
    {
        return Err(GitError::DurabilityNotConfirmed);
    }
    file.sync_all()
        .map_err(|_| GitError::DurabilityNotConfirmed)
}

#[cfg(not(windows))]
fn open_file_for_sync(path: &Path) -> Result<File, GitError> {
    File::open(path).map_err(|_| GitError::DurabilityNotConfirmed)
}

#[cfg(windows)]
fn open_file_for_sync(path: &Path) -> Result<File, GitError> {
    // `File::sync_all` delegates to FlushFileBuffers, whose Windows contract
    // requires a handle opened with GENERIC_WRITE even though Inex never
    // changes these bytes during the durability checkpoint.
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| GitError::DurabilityNotConfirmed)
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, GitError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if maximum == MAX_REPOSITORY_METADATA_BYTES {
                return Ok(Vec::new());
            }
            return Err(GitError::UnsafeRepositoryMetadata);
        }
        Err(error) => return Err(io_error(GitIoOperation::InspectMetadata, &error)),
    };
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
    {
        return Err(GitError::UnsafeRepositoryMetadata);
    }
    let file = File::open(path).map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Err(GitError::UnsafeRepositoryMetadata);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    (&file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if bytes.len() > maximum || std::str::from_utf8(&bytes).is_err() {
        return Err(GitError::UnsafeRepositoryMetadata);
    }
    Ok(bytes)
}

fn append_line_if_missing(current: &[u8], required: &str) -> Result<Option<Vec<u8>>, GitError> {
    let text = std::str::from_utf8(current).map_err(|_| GitError::UnsafeRepositoryMetadata)?;
    // Keeping the managed rule last is material for `.gitattributes`: later
    // matching rules take precedence one attribute at a time. Re-running the
    // installer after a user edit safely restores the Inex rule as the final
    // line without trying to interpret Git's full wildcard grammar.
    if text.lines().next_back() == Some(required) {
        return Ok(None);
    }
    let extra = required.len().saturating_add(1);
    if current.len().saturating_add(extra).saturating_add(1) > MAX_REPOSITORY_METADATA_BYTES {
        return Err(GitError::UnsafeRepositoryMetadata);
    }
    let mut replacement = current.to_vec();
    if !replacement.is_empty() && !replacement.ends_with(b"\n") {
        replacement.push(b'\n');
    }
    replacement.extend_from_slice(required.as_bytes());
    replacement.push(b'\n');
    Ok(Some(replacement))
}

fn parse_unmerged_entries(output: &[u8]) -> Result<BTreeMap<String, ConflictEntry>, GitError> {
    let mut conflicts = BTreeMap::<String, ConflictEntry>::new();
    let mut path_bytes = 0_usize;
    for_each_nul_record(output, |record| {
        let ((stage, entry), physical_path) = parse_index_record(record)?;
        if !(1..=3).contains(&stage) {
            return Err(GitError::MalformedGitOutput);
        }
        path_bytes = path_bytes.saturating_add(physical_path.len());
        if path_bytes > MAX_GIT_OUTPUT_BYTES {
            return Err(GitError::GitOutputTooLarge {
                operation: GitOperation::ReadIndex,
            });
        }
        let logical_path = validate_physical_path(&physical_path)?;
        let conflict = conflicts
            .entry(physical_path.clone())
            .or_insert_with(|| ConflictEntry {
                physical_path,
                logical_path,
                stages: [None, None, None],
            });
        let slot = usize::from(stage - 1);
        if conflict.stages[slot].replace(entry).is_some() {
            return Err(GitError::MalformedGitOutput);
        }
        if conflicts.len() > MAX_CONFLICTS {
            return Err(GitError::GitOutputTooLarge {
                operation: GitOperation::ReadIndex,
            });
        }
        Ok(())
    })?;
    for conflict in conflicts.values() {
        validate_conflict_modes(&conflict.stages)?;
    }
    Ok(conflicts)
}

fn validate_conflict_set(conflicts: &BTreeMap<String, ConflictEntry>) -> Result<(), GitError> {
    let mut folded = BTreeMap::new();
    for conflict in conflicts.values() {
        let key = conflict.logical_path.case_fold_key();
        if folded.insert(key, conflict.logical_path.as_str()).is_some() {
            return Err(GitError::UnsupportedConflictEntry);
        }
    }
    Ok(())
}

fn reject_conflict_stage_zero(
    git: &Git,
    conflicts: &BTreeMap<String, ConflictEntry>,
) -> Result<(), GitError> {
    for (stage, _, physical_path) in git.staged_entries()? {
        if stage == 0 && conflicts.contains_key(&physical_path) {
            return Err(GitError::UnsupportedConflictEntry);
        }
    }
    Ok(())
}

fn nul_records(output: &[u8]) -> Result<Vec<&[u8]>, GitError> {
    let mut records = Vec::new();
    for_each_nul_record(output, |record| {
        records.push(record);
        Ok(())
    })?;
    Ok(records)
}

fn for_each_nul_record<'a>(
    output: &'a [u8],
    mut visit: impl FnMut(&'a [u8]) -> Result<(), GitError>,
) -> Result<(), GitError> {
    if output.is_empty() {
        return Ok(());
    }
    if !output.ends_with(&[0]) {
        return Err(GitError::MalformedGitOutput);
    }
    let mut start = 0_usize;
    for (index, byte) in output.iter().enumerate() {
        if *byte != 0 {
            continue;
        }
        if index == start {
            return Err(GitError::MalformedGitOutput);
        }
        visit(&output[start..index])?;
        start = index.saturating_add(1);
    }
    if start == output.len() {
        Ok(())
    } else {
        Err(GitError::MalformedGitOutput)
    }
}

fn parse_index_record(record: &[u8]) -> Result<((u8, StageEntry), String), GitError> {
    let tab = record
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or(GitError::MalformedGitOutput)?;
    let metadata = std::str::from_utf8(&record[..tab]).map_err(|_| GitError::MalformedGitOutput)?;
    let physical_path = std::str::from_utf8(&record[tab + 1..])
        .map_err(|_| GitError::UnsupportedConflictEntry)?
        .to_owned();
    let mut fields = metadata.split(' ');
    let mode = fields.next().ok_or(GitError::MalformedGitOutput)?;
    let oid = fields.next().ok_or(GitError::MalformedGitOutput)?;
    let stage = fields.next().ok_or(GitError::MalformedGitOutput)?;
    if fields.next().is_some() {
        return Err(GitError::MalformedGitOutput);
    }
    if mode.len() != 6 || !mode.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(GitError::MalformedGitOutput);
    }
    validate_oid(oid)?;
    let stage = stage
        .parse::<u8>()
        .map_err(|_| GitError::MalformedGitOutput)?;
    Ok((
        (
            stage,
            StageEntry {
                mode: mode.to_owned(),
                oid: oid.to_owned(),
            },
        ),
        physical_path,
    ))
}

fn validate_physical_path(path: &str) -> Result<LogicalPath, GitError> {
    if path.is_empty() || path.len() > MAX_GIT_PATH_BYTES || path.as_bytes().contains(&0) {
        return Err(GitError::UnsupportedConflictEntry);
    }
    LogicalPath::from_ciphertext_relative_path(Path::new(path))
        .map_err(|_| GitError::UnsupportedConflictEntry)
}

fn validate_mode(mode: &str) -> Result<(), GitError> {
    if mode == "100644" {
        Ok(())
    } else {
        Err(GitError::UnsupportedConflictEntry)
    }
}

fn validate_oid(oid: &str) -> Result<(), GitError> {
    if matches!(oid.len(), 40 | 64)
        && oid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(GitError::MalformedGitOutput)
    }
}

fn validate_conflict_modes(stages: &[Option<StageEntry>; 3]) -> Result<(), GitError> {
    if stages.iter().flatten().count() < 2 || (stages[1].is_none() && stages[2].is_none()) {
        return Err(GitError::UnsupportedConflictEntry);
    }
    for stage in stages.iter().flatten() {
        validate_mode(&stage.mode)?;
    }
    let mut modes = stages
        .iter()
        .filter_map(Option::as_ref)
        .map(|entry| entry.mode.as_str());
    let first = modes.next().ok_or(GitError::UnsupportedConflictEntry)?;
    if modes.all(|mode| mode == first) {
        Ok(())
    } else {
        Err(GitError::UnsupportedConflictEntry)
    }
}

fn prepare_result(
    vault: &Vault,
    git: &Git,
    conflict: &ConflictEntry,
    tracked_identities: &BTreeMap<String, TrackedIdentity>,
    modified_at_ms: i64,
) -> Result<PreparedResult, GitError> {
    let stage_paths = std::array::from_fn(|index| {
        conflict.stages[index]
            .as_ref()
            .map(|_| conflict.logical_path.clone())
    });
    prepare_result_for_paths(
        vault,
        git,
        conflict,
        &stage_paths,
        None,
        Some(tracked_identities),
        modified_at_ms,
    )
}

fn prepare_detected_rename_result(
    vault: &Vault,
    git: &Git,
    conflict: &ConflictEntry,
    stage_paths: &[Option<LogicalPath>; 3],
    renamed_side: RenameSide,
    modified_at_ms: i64,
) -> Result<PreparedResult, GitError> {
    prepare_result_for_paths(
        vault,
        git,
        conflict,
        stage_paths,
        Some(renamed_side.stage_index()),
        None,
        modified_at_ms,
    )
}

fn prepare_result_for_paths(
    vault: &Vault,
    git: &Git,
    conflict: &ConflictEntry,
    stage_paths: &[Option<LogicalPath>; 3],
    identity_stage: Option<usize>,
    tracked_identities: Option<&BTreeMap<String, TrackedIdentity>>,
    modified_at_ms: i64,
) -> Result<PreparedResult, GitError> {
    let mut stage_ciphertexts: [Option<Vec<u8>>; 3] = [None, None, None];
    let mut documents: [Option<DecryptedDocument>; 3] = [None, None, None];
    for (index, stage) in conflict.stages.iter().enumerate() {
        if let Some(stage) = stage {
            let logical_path = stage_paths[index]
                .as_ref()
                .ok_or(GitError::UnsupportedConflictEntry)?;
            let ciphertext = git.read_object(&stage.oid)?;
            let document = vault
                .authenticate_committed_envelope(logical_path, &ciphertext)
                .map_err(|_| GitError::StageAuthenticationFailed)?;
            stage_ciphertexts[index] = Some(ciphertext);
            documents[index] = Some(document);
        } else if stage_paths[index].is_some() {
            return Err(GitError::UnsupportedConflictEntry);
        }
    }
    if let Some(tracked_identities) = tracked_identities {
        for document in documents.iter().flatten() {
            if tracked_identities
                .get(&document.header.file_id.to_string())
                .is_some_and(|tracked| tracked.logical_path != conflict.logical_path)
            {
                return Err(GitError::UnsupportedConflictEntry);
            }
        }
    }

    let identity = if let Some(index) = identity_stage {
        documents
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(GitError::UnsupportedConflictEntry)?
    } else {
        documents[1]
            .as_ref()
            .or(documents[2].as_ref())
            .or(documents[0].as_ref())
            .ok_or(GitError::UnsupportedConflictEntry)?
    };
    if identity.header.logical_path != conflict.logical_path.as_str() {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let file_id = identity.header.file_id.to_string();
    let (encrypted, unresolved) = merge_and_encrypt_documents(
        vault,
        &conflict.logical_path,
        &documents,
        identity,
        modified_at_ms,
    )?;
    drop(documents);
    let result_oid = git.write_object(&encrypted.bytes)?;
    Ok(PreparedResult {
        encrypted,
        result_oid,
        file_id,
        unresolved,
        stage_ciphertexts,
    })
}

fn prepare_split_rename_result(
    vault: &Vault,
    git: &Git,
    source: &ConflictEntry,
    destination: &TrackedIdentity,
    renamed_side: RenameSide,
    modified_at_ms: i64,
) -> Result<PreparedRenameResult, GitError> {
    let mut source_stage_ciphertexts: [Option<Vec<u8>>; 3] = [None, None, None];
    let mut source_documents: [Option<DecryptedDocument>; 3] = [None, None, None];
    for (index, stage) in source.stages.iter().enumerate() {
        if let Some(stage) = stage {
            let ciphertext = git.read_object(&stage.oid)?;
            let document = vault
                .authenticate_committed_envelope(&source.logical_path, &ciphertext)
                .map_err(|_| GitError::StageAuthenticationFailed)?;
            source_stage_ciphertexts[index] = Some(ciphertext);
            source_documents[index] = Some(document);
        }
    }
    let destination_ciphertext = git.read_object(&destination.entry.oid)?;
    let destination_document = vault
        .authenticate_committed_envelope(&destination.logical_path, &destination_ciphertext)
        .map_err(|_| GitError::StageAuthenticationFailed)?;
    let destination_file_id = destination_document.header.file_id;
    if source_documents
        .iter()
        .flatten()
        .any(|document| document.header.file_id != destination_file_id)
        || source_documents[0].is_none()
        || source_documents[renamed_side.stage_index()].is_some()
    {
        return Err(GitError::UnsupportedConflictEntry);
    }

    let mut documents: [Option<DecryptedDocument>; 3] = [None, None, None];
    documents[0] = source_documents[0].take();
    match renamed_side {
        RenameSide::Ours => {
            documents[1] = Some(destination_document);
            documents[2] = source_documents[2].take();
        }
        RenameSide::Theirs => {
            documents[1] = source_documents[1].take();
            documents[2] = Some(destination_document);
        }
    }
    let identity = documents[renamed_side.stage_index()]
        .as_ref()
        .ok_or(GitError::UnsupportedConflictEntry)?;
    let file_id = identity.header.file_id.to_string();
    let (encrypted, unresolved) = merge_and_encrypt_documents(
        vault,
        &destination.logical_path,
        &documents,
        identity,
        modified_at_ms,
    )?;
    drop(documents);
    drop(source_documents);
    let result_oid = git.write_object(&encrypted.bytes)?;
    Ok(PreparedRenameResult {
        encrypted,
        result_oid,
        file_id,
        unresolved,
        source_stage_ciphertexts,
        destination_ciphertext,
    })
}

fn merge_and_encrypt_documents(
    vault: &Vault,
    output_path: &LogicalPath,
    documents: &[Option<DecryptedDocument>; 3],
    identity: &DecryptedDocument,
    modified_at_ms: i64,
) -> Result<(EncryptedDocument, bool), GitError> {
    let ancestor = plaintext_or_empty(documents[0].as_ref())?;
    let ours = plaintext_or_empty(documents[1].as_ref())?;
    let theirs = plaintext_or_empty(documents[2].as_ref())?;
    let inherited_unresolved = documents.iter().flatten().any(|document| {
        document
            .header
            .content_flags
            .contains(inex_core::format::ContentFlags::UNRESOLVED_MERGE)
    });
    let (merged, diff3_conflicted) = match diffy::merge(ancestor, ours, theirs) {
        Ok(clean) => (Zeroizing::new(clean), false),
        Err(conflicted) => (Zeroizing::new(conflicted), true),
    };
    let unresolved =
        should_flag_merge_result(diff3_conflicted, inherited_unresolved, merged.as_bytes());
    if merged.len() > format::MAX_PLAINTEXT_LEN {
        return Err(GitError::MergeOutputTooLarge);
    }
    let encrypted = vault.encrypt_merge_result(
        output_path,
        &identity.header,
        merged.as_bytes(),
        modified_at_ms.max(identity.header.created_at_ms),
        unresolved,
    )?;
    drop(merged);
    Ok((encrypted, unresolved))
}

fn tracked_identity_index(
    vault: &Vault,
    git: &Git,
) -> Result<BTreeMap<String, TrackedIdentity>, GitError> {
    let mut identities = BTreeMap::new();
    for (stage, entry, physical_path) in git.staged_entries()? {
        if stage != 0 || !physical_path.ends_with(".md.enc") {
            continue;
        }
        validate_mode(&entry.mode)?;
        let logical_path = validate_physical_path(&physical_path)?;
        let ciphertext = git.read_object(&entry.oid)?;
        let parts =
            format::split_envelope(&ciphertext).map_err(|_| GitError::UnsupportedConflictEntry)?;
        if parts.header.vault_id != vault.config().vault_id
            || parts.header.key_epoch != vault.config().key_epoch
            || parts.header.logical_path != logical_path.as_str()
            || parts.header.is_draft()
        {
            return Err(GitError::UnsupportedConflictEntry);
        }
        let file_id = parts.header.file_id.to_string();
        if identities
            .insert(
                file_id,
                TrackedIdentity {
                    physical_path,
                    logical_path,
                    entry,
                },
            )
            .is_some()
        {
            return Err(GitError::UnsupportedConflictEntry);
        }
    }
    Ok(identities)
}

fn verify_tracked_identity_owner(
    vault: &Vault,
    git: &Git,
    file_id: &str,
    expected_physical_path: Option<&str>,
) -> Result<(), GitError> {
    let identities = tracked_identity_index(vault, git)?;
    match (identities.get(file_id), expected_physical_path) {
        (None, None) => Ok(()),
        (Some(identity), Some(expected)) if identity.physical_path == expected => Ok(()),
        _ => Err(GitError::IndexChanged),
    }
}

fn verify_worktree_identity_owner(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    file_id: &str,
    allowed_physical_paths: &[&str],
) -> Result<(), GitError> {
    let allowed = allowed_physical_paths
        .iter()
        .map(|path| validate_physical_path(path).map(|logical| logical.case_fold_key()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let unmerged = git.unmerged_entries()?;
    let tree = tree::scan_vault_tree(vault.root()).map_err(|_| GitError::WorktreeChanged)?;
    for entry in tree.entries() {
        if entry.kind() != TreeEntryKind::File {
            continue;
        }
        let logical_path = LogicalPath::parse_canonical(entry.logical_path())
            .map_err(|_| GitError::WorktreeChanged)?;
        let folded = logical_path.case_fold_key();
        if allowed.contains(&folded) {
            continue;
        }
        let physical_path = physical_path_for_logical(&logical_path);
        if let Some(conflict) = unmerged.get(&physical_path) {
            let target = vault
                .root()
                .join(logical_path.to_ciphertext_relative_path());
            let CurrentTarget::File(actual) = guard.inspect(&target).map_err(map_atomic_error)?
            else {
                return Err(GitError::WorktreeChanged);
            };
            let mut matched_stage = false;
            for stage in conflict.stages.iter().flatten() {
                let ciphertext = git.read_object(&stage.oid)?;
                if digest(&ciphertext) != actual {
                    continue;
                }
                matched_stage = true;
                if authenticate_stage_identity(vault, git, stage)?.file_id == file_id {
                    return Err(GitError::WorktreeChanged);
                }
            }
            if !matched_stage {
                return Err(GitError::WorktreeChanged);
            }
            continue;
        }
        let document = vault
            .read(&logical_path)
            .map_err(|_| GitError::WorktreeChanged)?;
        if document.header.file_id.to_string() == file_id {
            return Err(GitError::WorktreeChanged);
        }
    }
    Ok(())
}

fn verify_merge_identity_owners(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    file_id: &str,
    expected_index_path: Option<&str>,
    allowed_worktree_paths: &[&str],
) -> Result<(), GitError> {
    verify_tracked_identity_owner(vault, git, file_id, expected_index_path)?;
    verify_worktree_identity_owner(vault, git, guard, file_id, allowed_worktree_paths)
}

fn preflight_conflict_identities(
    vault: &Vault,
    git: &Git,
    conflicts: &BTreeMap<String, ConflictEntry>,
    tracked_identities: &BTreeMap<String, TrackedIdentity>,
) -> Result<Vec<MergePlan>, GitError> {
    let authenticated = authenticate_conflict_identities(vault, git, conflicts)?;
    let mut plans = Vec::with_capacity(conflicts.len());
    let mut claimed_paths = BTreeSet::new();
    for conflict in conflicts.values() {
        let stages = authenticated
            .get(&conflict.physical_path)
            .ok_or(GitError::UnsupportedConflictEntry)?;
        let plan =
            classify_conflict_plan(vault, git, conflicts, tracked_identities, conflict, stages)?;
        for path in merge_plan_paths(&plan) {
            if !claimed_paths.insert(path.case_fold_key()) {
                return Err(GitError::UnsupportedConflictEntry);
            }
        }
        plans.push(plan);
    }
    Ok(plans)
}

fn authenticate_conflict_identities(
    vault: &Vault,
    git: &Git,
    conflicts: &BTreeMap<String, ConflictEntry>,
) -> Result<BTreeMap<String, [Option<AuthenticatedStageIdentity>; 3]>, GitError> {
    let mut authenticated = BTreeMap::new();
    let mut conflict_identity_owners = BTreeMap::<String, String>::new();
    for conflict in conflicts.values() {
        let mut stages: [Option<AuthenticatedStageIdentity>; 3] = std::array::from_fn(|_| None);
        let mut identities_in_conflict = BTreeSet::new();
        for (index, stage) in conflict.stages.iter().enumerate() {
            if let Some(stage) = stage {
                let identity = authenticate_stage_identity(vault, git, stage)?;
                identities_in_conflict.insert(identity.file_id.clone());
                stages[index] = Some(identity);
            }
        }
        for file_id in identities_in_conflict {
            match conflict_identity_owners.get(&file_id) {
                Some(existing) if existing != &conflict.physical_path => {
                    return Err(GitError::UnsupportedConflictEntry);
                }
                Some(_) => {}
                None => {
                    conflict_identity_owners.insert(file_id, conflict.physical_path.clone());
                }
            }
        }
        authenticated.insert(conflict.physical_path.clone(), stages);
    }
    Ok(authenticated)
}

fn classify_conflict_plan(
    vault: &Vault,
    git: &Git,
    conflicts: &BTreeMap<String, ConflictEntry>,
    tracked_identities: &BTreeMap<String, TrackedIdentity>,
    conflict: &ConflictEntry,
    stages: &[Option<AuthenticatedStageIdentity>; 3],
) -> Result<MergePlan, GitError> {
    if stages
        .iter()
        .flatten()
        .all(|stage| stage.logical_path == conflict.logical_path)
    {
        classify_same_path_plan(vault, git, conflicts, tracked_identities, conflict, stages)
    } else {
        classify_detected_rename_plan(git, conflicts, tracked_identities, conflict, stages)
    }
}

fn classify_same_path_plan(
    vault: &Vault,
    git: &Git,
    conflicts: &BTreeMap<String, ConflictEntry>,
    tracked_identities: &BTreeMap<String, TrackedIdentity>,
    conflict: &ConflictEntry,
    stages: &[Option<AuthenticatedStageIdentity>; 3],
) -> Result<MergePlan, GitError> {
    let cross_path_ids = stages
        .iter()
        .flatten()
        .filter(|stage| {
            tracked_identities
                .get(&stage.file_id)
                .is_some_and(|tracked| tracked.logical_path != conflict.logical_path)
        })
        .map(|stage| stage.file_id.clone())
        .collect::<BTreeSet<_>>();
    if cross_path_ids.is_empty() {
        return Ok(MergePlan::InPlace {
            conflict: conflict.clone(),
        });
    }
    if cross_path_ids.len() != 1
        || conflict.stages[0].is_none()
        || conflict.stages[1].is_some() == conflict.stages[2].is_some()
    {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let file_id = cross_path_ids
        .first()
        .ok_or(GitError::UnsupportedConflictEntry)?;
    if stages
        .iter()
        .flatten()
        .any(|stage| &stage.file_id != file_id)
    {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let destination = tracked_identities
        .get(file_id)
        .ok_or(GitError::UnsupportedConflictEntry)?
        .clone();
    if conflicts.contains_key(&destination.physical_path)
        || destination.logical_path == conflict.logical_path
        || destination.logical_path.case_fold_key() == conflict.logical_path.case_fold_key()
    {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let destination_identity = authenticate_stage_identity(vault, git, &destination.entry)?;
    if destination_identity.logical_path != destination.logical_path
        || &destination_identity.file_id != file_id
    {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let renamed_side = if conflict.stages[1].is_none() {
        RenameSide::Ours
    } else {
        RenameSide::Theirs
    };
    let ancestor = conflict.stages[0]
        .as_ref()
        .ok_or(GitError::UnsupportedConflictEntry)?;
    let other_source = conflict.stages[match renamed_side {
        RenameSide::Ours => RenameSide::Theirs.stage_index(),
        RenameSide::Theirs => RenameSide::Ours.stage_index(),
    }]
    .as_ref()
    .ok_or(GitError::UnsupportedConflictEntry)?;
    let provenance = current_rename_provenance(git)?;
    verify_rename_provenance(
        git,
        &provenance,
        &conflict.physical_path,
        &destination.physical_path,
        [ancestor, &destination.entry, other_source],
        renamed_side,
    )?;
    Ok(MergePlan::SplitRename {
        source: conflict.clone(),
        destination,
        renamed_side,
        provenance,
    })
}

fn classify_detected_rename_plan(
    git: &Git,
    conflicts: &BTreeMap<String, ConflictEntry>,
    tracked_identities: &BTreeMap<String, TrackedIdentity>,
    conflict: &ConflictEntry,
    stages: &[Option<AuthenticatedStageIdentity>; 3],
) -> Result<MergePlan, GitError> {
    let ancestor = stages[0]
        .as_ref()
        .ok_or(GitError::UnsupportedConflictEntry)?;
    let ours = stages[1]
        .as_ref()
        .ok_or(GitError::UnsupportedConflictEntry)?;
    let theirs = stages[2]
        .as_ref()
        .ok_or(GitError::UnsupportedConflictEntry)?;
    if ours.file_id != ancestor.file_id || theirs.file_id != ancestor.file_id {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let (destination, renamed_side) = if ours.logical_path != ancestor.logical_path
        && theirs.logical_path == ancestor.logical_path
    {
        (&ours.logical_path, RenameSide::Ours)
    } else if theirs.logical_path != ancestor.logical_path
        && ours.logical_path == ancestor.logical_path
    {
        (&theirs.logical_path, RenameSide::Theirs)
    } else {
        return Err(GitError::UnsupportedConflictEntry);
    };
    if destination != &conflict.logical_path
        || destination.case_fold_key() == ancestor.logical_path.case_fold_key()
        || stages.iter().flatten().any(|stage| {
            stage.logical_path != ancestor.logical_path && stage.logical_path != *destination
        })
        || tracked_identities.contains_key(&ancestor.file_id)
    {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let source_physical = physical_path_for_logical(&ancestor.logical_path);
    if conflicts
        .get(&source_physical)
        .is_some_and(|other| other.physical_path != conflict.physical_path)
    {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let provenance = current_rename_provenance(git)?;
    verify_rename_provenance(
        git,
        &provenance,
        &source_physical,
        &conflict.physical_path,
        [
            conflict.stages[0]
                .as_ref()
                .ok_or(GitError::UnsupportedConflictEntry)?,
            conflict.stages[renamed_side.stage_index()]
                .as_ref()
                .ok_or(GitError::UnsupportedConflictEntry)?,
            conflict.stages[match renamed_side {
                RenameSide::Ours => RenameSide::Theirs.stage_index(),
                RenameSide::Theirs => RenameSide::Ours.stage_index(),
            }]
            .as_ref()
            .ok_or(GitError::UnsupportedConflictEntry)?,
        ],
        renamed_side,
    )?;
    Ok(MergePlan::DetectedRename {
        conflict: conflict.clone(),
        stage_paths: std::array::from_fn(|index| {
            stages[index]
                .as_ref()
                .map(|stage| stage.logical_path.clone())
        }),
        renamed_side,
        provenance,
    })
}

fn current_rename_provenance(git: &Git) -> Result<RenameProvenance, GitError> {
    let ours_commit = git.resolve_commit("HEAD")?;
    let theirs_commit = git.single_merge_head()?;
    let base_commit = git.unique_merge_base(&ours_commit, &theirs_commit)?;
    Ok(RenameProvenance {
        object_format: git.object_format,
        ours_commit,
        theirs_commit,
        base_commit,
    })
}

fn verify_rename_provenance(
    git: &Git,
    provenance: &RenameProvenance,
    source_physical_path: &str,
    destination_physical_path: &str,
    tree_entries: [&StageEntry; 3],
    renamed_side: RenameSide,
) -> Result<(), GitError> {
    let [ancestor, renamed_entry, other_source] = tree_entries;
    validate_physical_path(source_physical_path)?;
    validate_physical_path(destination_physical_path)?;
    if source_physical_path == destination_physical_path {
        return Err(GitError::UnsupportedConflictEntry);
    }
    validate_rename_provenance(git, provenance)?;
    let (renamed_commit, other_commit) = match renamed_side {
        RenameSide::Ours => (&provenance.ours_commit, &provenance.theirs_commit),
        RenameSide::Theirs => (&provenance.theirs_commit, &provenance.ours_commit),
    };
    if git
        .tree_entry(&provenance.base_commit, source_physical_path)?
        .as_ref()
        != Some(ancestor)
        || git
            .tree_entry(&provenance.base_commit, destination_physical_path)?
            .is_some()
        || git
            .tree_entry(renamed_commit, source_physical_path)?
            .is_some()
        || git
            .tree_entry(renamed_commit, destination_physical_path)?
            .as_ref()
            != Some(renamed_entry)
        || git.tree_entry(other_commit, source_physical_path)?.as_ref() != Some(other_source)
        || git
            .tree_entry(other_commit, destination_physical_path)?
            .is_some()
    {
        return Err(GitError::UnsupportedConflictEntry);
    }
    Ok(())
}

fn validate_rename_provenance(git: &Git, provenance: &RenameProvenance) -> Result<(), GitError> {
    if provenance.object_format != git.object_format {
        return Err(GitError::UnsupportedConflictEntry);
    }
    for oid in [
        &provenance.ours_commit,
        &provenance.theirs_commit,
        &provenance.base_commit,
    ] {
        git.validate_oid(oid)?;
    }
    let base = git.unique_merge_base(&provenance.ours_commit, &provenance.theirs_commit)?;
    if base != provenance.base_commit {
        return Err(GitError::UnsupportedConflictEntry);
    }
    Ok(())
}

fn verify_active_rename_provenance(git: &Git, expected: &RenameProvenance) -> Result<(), GitError> {
    if current_rename_provenance(git)? != *expected {
        return Err(GitError::IndexChanged);
    }
    Ok(())
}

fn authenticate_stage_identity(
    vault: &Vault,
    git: &Git,
    stage: &StageEntry,
) -> Result<AuthenticatedStageIdentity, GitError> {
    let ciphertext = git.read_object(&stage.oid)?;
    let parts =
        format::split_envelope(&ciphertext).map_err(|_| GitError::StageAuthenticationFailed)?;
    let logical_path = LogicalPath::parse_canonical(&parts.header.logical_path)
        .map_err(|_| GitError::StageAuthenticationFailed)?;
    let document = vault
        .authenticate_committed_envelope(&logical_path, &ciphertext)
        .map_err(|_| GitError::StageAuthenticationFailed)?;
    let file_id = document.header.file_id.to_string();
    drop(document);
    Ok(AuthenticatedStageIdentity {
        logical_path,
        file_id,
    })
}

fn physical_path_for_logical(logical_path: &LogicalPath) -> String {
    format!("{}.enc", logical_path.as_str())
}

fn merge_plan_paths(plan: &MergePlan) -> Vec<&LogicalPath> {
    match plan {
        MergePlan::InPlace { conflict } => vec![&conflict.logical_path],
        MergePlan::DetectedRename {
            conflict,
            stage_paths,
            ..
        } => {
            let mut paths = vec![&conflict.logical_path];
            for path in stage_paths.iter().flatten() {
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
            paths
        }
        MergePlan::SplitRename {
            source,
            destination,
            ..
        } => vec![&source.logical_path, &destination.logical_path],
    }
}

fn merge_plan_attribute_paths(plans: &[MergePlan]) -> Result<Vec<String>, GitError> {
    let mut paths = BTreeSet::new();
    for plan in plans {
        for logical_path in merge_plan_paths(plan) {
            let physical_path = physical_path_for_logical(logical_path);
            validate_physical_path(&physical_path)?;
            paths.insert(physical_path);
        }
    }
    Ok(paths.into_iter().collect())
}

fn plaintext_or_empty(document: Option<&DecryptedDocument>) -> Result<&str, GitError> {
    document.map_or(Ok(""), |document| {
        std::str::from_utf8(document.plaintext.as_slice())
            .map_err(|_| GitError::StageAuthenticationFailed)
    })
}

fn should_flag_merge_result(
    diff3_conflicted: bool,
    inherited_unresolved: bool,
    plaintext: &[u8],
) -> bool {
    diff3_conflicted
        || (inherited_unresolved
            && plaintext.split(|byte| *byte == b'\n').any(|line| {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                line.starts_with(b"<<<<<<< ")
                    || line.starts_with(b"||||||| ")
                    || line == b"======="
                    || line.starts_with(b">>>>>>> ")
            }))
}

fn result_mode(conflict: &ConflictEntry) -> Result<&str, GitError> {
    conflict.stages[1]
        .as_ref()
        .or(conflict.stages[2].as_ref())
        .or(conflict.stages[0].as_ref())
        .map(|entry| entry.mode.as_str())
        .ok_or(GitError::UnsupportedConflictEntry)
}

fn expected_worktree_digest(prepared: &PreparedResult) -> Option<[u8; 32]> {
    prepared.stage_ciphertexts[1]
        .as_ref()
        .or(prepared.stage_ciphertexts[2].as_ref())
        .map(|bytes| digest(bytes))
}

fn index_path(root: &Path) -> PathBuf {
    root.join(".git").join("index")
}

fn index_lock_path(root: &Path) -> PathBuf {
    root.join(".git").join("index.lock")
}

fn index_candidate_path(root: &Path, candidate_file: &str) -> PathBuf {
    root.join(VAULT_LOCAL_DIRECTORY).join(candidate_file)
}

fn prelock_reservation_path(root: &Path) -> PathBuf {
    root.join(VAULT_LOCAL_DIRECTORY)
        .join(PRELOCK_RESERVATION_FILE)
}

fn prelock_reservation_staging_path(root: &Path, lock_token: &str) -> PathBuf {
    root.join(VAULT_LOCAL_DIRECTORY)
        .join(format!("{PRELOCK_RESERVATION_STAGING_PREFIX}{lock_token}"))
}

fn candidate_receipt_path(root: &Path, lock_token: &str, phase: CandidateReceiptPhase) -> PathBuf {
    let prefix = match phase {
        CandidateReceiptPhase::Initial => CANDIDATE_INITIAL_RECEIPT_PREFIX,
        CandidateReceiptPhase::Final => CANDIDATE_FINAL_RECEIPT_PREFIX,
    };
    root.join(VAULT_LOCAL_DIRECTORY)
        .join(format!("{prefix}{lock_token}"))
}

fn index_marker_staging_path(root: &Path, lock_token: &str) -> PathBuf {
    root.join(VAULT_LOCAL_DIRECTORY)
        .join(format!("{INDEX_MARKER_PREFIX}{lock_token}"))
}

fn index_lock_marker_bytes(
    lock_token: &str,
    expected_index_size: u64,
    expected_index_sha256: &str,
    candidate_index_size: u64,
    candidate_index_sha256: &str,
) -> Vec<u8> {
    let mut marker = Vec::with_capacity(INDEX_LOCK_MARKER_MAGIC.len() + 256);
    marker.extend_from_slice(INDEX_LOCK_MARKER_MAGIC);
    marker.extend_from_slice(lock_token.as_bytes());
    marker.push(b'\n');
    marker.extend_from_slice(expected_index_size.to_string().as_bytes());
    marker.push(b'\n');
    marker.extend_from_slice(expected_index_sha256.as_bytes());
    marker.push(b'\n');
    marker.extend_from_slice(candidate_index_size.to_string().as_bytes());
    marker.push(b'\n');
    marker.extend_from_slice(candidate_index_sha256.as_bytes());
    marker.push(b'\n');
    marker
}

struct ParsedIndexLockMarker {
    lock_token: String,
    expected_index_size: u64,
    expected_index_sha256: String,
    candidate_index_size: u64,
    candidate_index_sha256: String,
}

fn parse_index_lock_marker(bytes: &[u8]) -> Result<ParsedIndexLockMarker, GitError> {
    let body = bytes
        .strip_prefix(INDEX_LOCK_MARKER_MAGIC)
        .ok_or(GitError::InvalidJournal)?;
    let text = std::str::from_utf8(body).map_err(|_| GitError::InvalidJournal)?;
    let mut lines = text.split('\n');
    let lock_token = lines.next().ok_or(GitError::InvalidJournal)?.to_owned();
    validate_lock_token(&lock_token)?;
    let expected_size_text = lines.next().ok_or(GitError::InvalidJournal)?;
    let expected_index_sha256 = lines.next().ok_or(GitError::InvalidJournal)?.to_owned();
    let candidate_size_text = lines.next().ok_or(GitError::InvalidJournal)?;
    let candidate_index_sha256 = lines.next().ok_or(GitError::InvalidJournal)?.to_owned();
    if lines.next() != Some("") || lines.next().is_some() {
        return Err(GitError::InvalidJournal);
    }
    let expected_index_size = expected_size_text
        .parse::<u64>()
        .map_err(|_| GitError::InvalidJournal)?;
    let candidate_index_size = candidate_size_text
        .parse::<u64>()
        .map_err(|_| GitError::InvalidJournal)?;
    if expected_size_text != expected_index_size.to_string()
        || candidate_size_text != candidate_index_size.to_string()
        || expected_index_size == 0
        || candidate_index_size == 0
        || expected_index_size > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
        || candidate_index_size > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
        || expected_index_sha256 == candidate_index_sha256
    {
        return Err(GitError::InvalidJournal);
    }
    parse_hex_digest(&expected_index_sha256)?;
    parse_hex_digest(&candidate_index_sha256)?;
    Ok(ParsedIndexLockMarker {
        lock_token,
        expected_index_size,
        expected_index_sha256,
        candidate_index_size,
        candidate_index_sha256,
    })
}

struct IndexSnapshot {
    bytes: Vec<u8>,
    size: u64,
    sha256: String,
}

fn read_regular_exact(path: &Path, expected_size: usize) -> Result<Vec<u8>, GitError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() != u64::try_from(expected_size).unwrap_or(u64::MAX)
    {
        return Err(GitError::IndexChanged);
    }
    let mut file =
        File::open(path).map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Err(GitError::IndexChanged);
    }
    let mut bytes = Vec::with_capacity(expected_size);
    (&mut file)
        .take(
            u64::try_from(expected_size)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if bytes.len() != expected_size {
        return Err(GitError::IndexChanged);
    }
    Ok(bytes)
}

fn remove_regular_file_if_exact(path: &Path, expected: &[u8]) -> Result<bool, GitError> {
    let actual = match read_regular_exact(path, expected.len()) {
        Ok(actual) => actual,
        Err(GitError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }) => return Ok(false),
        Err(error) => return Err(error),
    };
    if actual != expected {
        return Ok(false);
    }
    fs::remove_file(path).map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    if let Some(parent) = path.parent() {
        sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)?;
    }
    Ok(true)
}

fn remove_regular_file_if_digest(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<bool, GitError> {
    let actual = match read_index_snapshot(path) {
        Ok(actual) => actual,
        Err(GitError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }) => return Ok(false),
        Err(error) => return Err(error),
    };
    if actual.size != expected_size || actual.sha256 != expected_sha256 {
        return Ok(false);
    }
    fs::remove_file(path).map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    if let Some(parent) = path.parent() {
        sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)?;
    }
    Ok(true)
}

fn appended_lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

fn read_index_snapshot(path: &Path) -> Result<IndexSnapshot, GitError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::IndexChanged);
    }
    let file = File::open(path).map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Err(GitError::IndexChanged);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_GIT_OUTPUT_BYTES)
            .min(MAX_GIT_OUTPUT_BYTES),
    );
    (&file)
        .take(
            u64::try_from(MAX_GIT_OUTPUT_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if bytes.len() > MAX_GIT_OUTPUT_BYTES
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len()
    {
        return Err(GitError::IndexChanged);
    }
    Ok(IndexSnapshot {
        size: metadata.len(),
        sha256: hex_digest(digest(&bytes)),
        bytes,
    })
}

fn validate_lock_token(lock_token: &str) -> Result<(), GitError> {
    if lock_token.len() != 32
        || !lock_token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GitError::InvalidJournal);
    }
    Ok(())
}

fn validate_candidate_file(lock_token: &str, candidate_file: &str) -> Result<(), GitError> {
    validate_lock_token(lock_token)?;
    if candidate_file == format!("{INDEX_CANDIDATE_PREFIX}{lock_token}") {
        Ok(())
    } else {
        Err(GitError::InvalidJournal)
    }
}

fn validate_prelock_reservation(reservation: &PreLockReservation) -> Result<(), GitError> {
    if reservation.version != 4 {
        return Err(GitError::InvalidJournal);
    }
    validate_candidate_file(&reservation.lock_token, &reservation.candidate_file)?;
    parse_hex_digest(&reservation.expected_index_sha256)?;
    if reservation.expected_index_size == 0
        || reservation.expected_index_size > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    Ok(())
}

fn validate_candidate_receipt(receipt: &CandidateOwnershipReceipt) -> Result<(), GitError> {
    if receipt.version != 4 {
        return Err(GitError::InvalidJournal);
    }
    validate_candidate_file(&receipt.lock_token, &receipt.candidate_file)?;
    parse_hex_digest(&receipt.candidate_index_sha256)?;
    if receipt.candidate_index_size == 0
        || receipt.candidate_index_size > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    Ok(())
}

fn receipt_matches_reservation(
    receipt: &CandidateOwnershipReceipt,
    reservation: &PreLockReservation,
) -> bool {
    receipt.version == reservation.version
        && receipt.lock_token == reservation.lock_token
        && receipt.candidate_file == reservation.candidate_file
        && (receipt.phase != CandidateReceiptPhase::Initial
            || (receipt.candidate_index_size == reservation.expected_index_size
                && receipt.candidate_index_sha256 == reservation.expected_index_sha256))
        && (receipt.phase != CandidateReceiptPhase::Final
            || receipt.candidate_index_sha256 != reservation.expected_index_sha256)
}

fn initial_candidate_receipt(reservation: &PreLockReservation) -> CandidateOwnershipReceipt {
    CandidateOwnershipReceipt {
        version: 4,
        phase: CandidateReceiptPhase::Initial,
        lock_token: reservation.lock_token.clone(),
        candidate_file: reservation.candidate_file.clone(),
        candidate_index_sha256: reservation.expected_index_sha256.clone(),
        candidate_index_size: reservation.expected_index_size,
    }
}

fn final_candidate_receipt(
    reservation: &PreLockReservation,
    candidate_index_size: u64,
    candidate_index_sha256: &str,
) -> CandidateOwnershipReceipt {
    CandidateOwnershipReceipt {
        version: 4,
        phase: CandidateReceiptPhase::Final,
        lock_token: reservation.lock_token.clone(),
        candidate_file: reservation.candidate_file.clone(),
        candidate_index_sha256: candidate_index_sha256.to_owned(),
        candidate_index_size,
    }
}

fn prelock_matches_cas_journal(
    reservation: &PreLockReservation,
    journal: &CasMergeJournal,
) -> bool {
    reservation.version == journal.version
        && reservation.object_format == journal.object_format
        && reservation.lock_token == journal.lock_token
        && reservation.candidate_file == journal.candidate_file
        && reservation.expected_index_sha256 == journal.expected_index_sha256
        && reservation.expected_index_size == journal.expected_index_size
}

fn validate_payload(payload: &MergeJournalPayload) -> Result<(), GitError> {
    match payload {
        MergeJournalPayload::InPlace(journal) => validate_journal(journal),
        MergeJournalPayload::Rename(journal) => validate_rename_journal(journal),
        MergeJournalPayload::DetectedRename(journal) => validate_detected_rename_journal(journal),
    }
}

fn payload_oids(payload: &MergeJournalPayload) -> Vec<&str> {
    match payload {
        MergeJournalPayload::InPlace(journal) => journal
            .stages
            .iter()
            .flatten()
            .map(|entry| entry.oid.as_str())
            .chain(std::iter::once(journal.result_oid.as_str()))
            .collect(),
        MergeJournalPayload::Rename(journal) => journal
            .source_stages
            .iter()
            .flatten()
            .map(|entry| entry.oid.as_str())
            .chain(std::iter::once(journal.destination_stage.oid.as_str()))
            .chain(std::iter::once(journal.result_oid.as_str()))
            .collect(),
        MergeJournalPayload::DetectedRename(journal) => journal
            .stages
            .iter()
            .flatten()
            .map(|entry| entry.oid.as_str())
            .chain(std::iter::once(journal.result_oid.as_str()))
            .collect(),
    }
}

fn payload_rename_provenance(payload: &MergeJournalPayload) -> Option<&RenameProvenance> {
    match payload {
        MergeJournalPayload::InPlace(_) => None,
        MergeJournalPayload::Rename(journal) => Some(&journal.provenance),
        MergeJournalPayload::DetectedRename(journal) => Some(&journal.provenance),
    }
}

fn validate_cas_journal(journal: &CasMergeJournal) -> Result<(), GitError> {
    if journal.version != 4 {
        return Err(GitError::InvalidJournal);
    }
    validate_candidate_file(&journal.lock_token, &journal.candidate_file)?;
    let marker = index_lock_marker_bytes(
        &journal.lock_token,
        journal.expected_index_size,
        &journal.expected_index_sha256,
        journal.candidate_index_size,
        &journal.candidate_index_sha256,
    );
    if journal.lock_marker_sha256 != hex_digest(digest(&marker)) {
        return Err(GitError::InvalidJournal);
    }
    parse_hex_digest(&journal.expected_index_sha256)?;
    parse_hex_digest(&journal.candidate_index_sha256)?;
    if journal.expected_index_sha256 == journal.candidate_index_sha256
        || journal.expected_index_size == 0
        || journal.candidate_index_size == 0
        || journal.expected_index_size > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
        || journal.candidate_index_size > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    validate_payload(&journal.transaction)?;
    let oid_width = journal.object_format.oid_hex_len();
    if payload_oids(&journal.transaction)
        .iter()
        .any(|oid| oid.len() != oid_width)
    {
        return Err(GitError::InvalidJournal);
    }
    if let Some(provenance) = payload_rename_provenance(&journal.transaction) {
        if provenance.object_format != journal.object_format {
            return Err(GitError::InvalidJournal);
        }
        for oid in [
            &provenance.ours_commit,
            &provenance.theirs_commit,
            &provenance.base_commit,
        ] {
            validate_oid(oid).map_err(|_| GitError::InvalidJournal)?;
            if oid.len() != oid_width {
                return Err(GitError::InvalidJournal);
            }
        }
    }
    Ok(())
}

fn validate_bundle_journal_v5(journal: &BundleMergeJournalV5) -> Result<(), GitError> {
    if journal.version != 5 {
        return Err(GitError::InvalidJournal);
    }
    candidate_bundle_v5::validate_candidate_bundle_transaction_reference_v5(&journal.reference)?;
    candidate_bundle_v5::validate_canonical_bytes_reference_v5(&journal.index_lock_marker)?;
    let marker = candidate_bundle_v5::index_lock_marker_bytes_v5(&journal.reference)?;
    if candidate_bundle_v5::canonical_bytes_reference_v5(&marker)? != journal.index_lock_marker {
        return Err(GitError::InvalidJournal);
    }
    Ok(())
}

fn serialize_bundle_journal_v5(journal: &BundleMergeJournalV5) -> Result<Vec<u8>, GitError> {
    validate_bundle_journal_v5(journal)?;
    let bytes = serde_json::to_vec(journal).map_err(|_| GitError::InvalidJournal)?;
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return Err(GitError::InvalidJournal);
    }
    Ok(bytes)
}

fn index_entry_map(git: &Git) -> Result<BTreeMap<(String, u8), StageEntry>, GitError> {
    let mut map = BTreeMap::new();
    for (stage, entry, path) in git.staged_entries()? {
        if map.insert((path, stage), entry).is_some() {
            return Err(GitError::MalformedGitOutput);
        }
    }
    Ok(map)
}

fn apply_payload_to_index(git: &Git, payload: &MergeJournalPayload) -> Result<(), GitError> {
    match payload {
        MergeJournalPayload::InPlace(journal) => git.update_index_direct(
            &journal.physical_path,
            &journal.result_mode,
            &journal.result_oid,
        ),
        MergeJournalPayload::Rename(journal) => git.update_index_rename_direct(
            &journal.source_physical_path,
            &journal.destination_physical_path,
            &journal.result_mode,
            &journal.result_oid,
        ),
        MergeJournalPayload::DetectedRename(journal) => git.update_index_direct(
            &journal.destination_physical_path,
            &journal.result_mode,
            &journal.result_oid,
        ),
    }
}

fn verify_candidate_index(
    git: &Git,
    payload: &MergeJournalPayload,
    before: &BTreeMap<(String, u8), StageEntry>,
) -> Result<(), GitError> {
    let mut expected = before.clone();
    let (source, destination, mode, oid) = match payload {
        MergeJournalPayload::InPlace(journal) => (
            None,
            journal.physical_path.as_str(),
            journal.result_mode.as_str(),
            journal.result_oid.as_str(),
        ),
        MergeJournalPayload::Rename(journal) => (
            Some(journal.source_physical_path.as_str()),
            journal.destination_physical_path.as_str(),
            journal.result_mode.as_str(),
            journal.result_oid.as_str(),
        ),
        MergeJournalPayload::DetectedRename(journal) => (
            None,
            journal.destination_physical_path.as_str(),
            journal.result_mode.as_str(),
            journal.result_oid.as_str(),
        ),
    };
    expected.retain(|(path, _), _| {
        path != destination && source.is_none_or(|source_path| path != source_path)
    });
    expected.insert(
        (destination.to_owned(), 0),
        StageEntry {
            mode: mode.to_owned(),
            oid: oid.to_owned(),
        },
    );
    git.ensure_full_index()?;
    if index_entry_map(git)? != expected {
        return Err(GitError::IndexChanged);
    }
    Ok(())
}

fn create_private_file(path: &Path, bytes: &[u8]) -> Result<File, GitError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
    restrict_file_permissions_best_effort(&file);
    if let Err(error) = file
        .write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = sync_directory(parent);
        }
        return Err(io_error(GitIoOperation::WriteJournal, &error));
    }
    Ok(file)
}

fn prelock_reservation_bytes(reservation: &PreLockReservation) -> Result<Vec<u8>, GitError> {
    validate_prelock_reservation(reservation)?;
    let bytes = serde_json::to_vec(reservation).map_err(|_| GitError::InvalidJournal)?;
    if bytes.is_empty() || bytes.len() > MAX_PRELOCK_RESERVATION_BYTES {
        return Err(GitError::InvalidJournal);
    }
    Ok(bytes)
}

fn read_prelock_reservation_file(path: &Path) -> Result<PreLockReservation, GitError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > u64::try_from(MAX_PRELOCK_RESERVATION_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    let file = File::open(path).map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?;
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?
    {
        return Err(GitError::InvalidJournal);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_PRELOCK_RESERVATION_BYTES)
            .min(MAX_PRELOCK_RESERVATION_BYTES),
    );
    (&file)
        .take(
            u64::try_from(MAX_PRELOCK_RESERVATION_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?;
    if bytes.len() != usize::try_from(metadata.len()).unwrap_or(usize::MAX)
        || bytes.len() > MAX_PRELOCK_RESERVATION_BYTES
    {
        return Err(GitError::InvalidJournal);
    }
    let value = parse_duplicate_free_json(&bytes)?;
    let reservation = serde_json::from_value::<PreLockReservation>(value)
        .map_err(|_| GitError::InvalidJournal)?;
    validate_prelock_reservation(&reservation)?;
    if prelock_reservation_bytes(&reservation)? != bytes {
        return Err(GitError::InvalidJournal);
    }
    Ok(reservation)
}

fn read_prelock_reservation(root: &Path) -> Result<Option<PreLockReservation>, GitError> {
    let path = prelock_reservation_path(root);
    match fs::symlink_metadata(&path) {
        Ok(_) => read_prelock_reservation_file(&path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(GitIoOperation::ReadJournal, &error)),
    }
}

fn candidate_receipt_bytes(receipt: &CandidateOwnershipReceipt) -> Result<Vec<u8>, GitError> {
    validate_candidate_receipt(receipt)?;
    let bytes = serde_json::to_vec(receipt).map_err(|_| GitError::InvalidJournal)?;
    if bytes.is_empty() || bytes.len() > MAX_PRELOCK_RESERVATION_BYTES {
        return Err(GitError::InvalidJournal);
    }
    Ok(bytes)
}

fn read_candidate_receipt(
    root: &Path,
    lock_token: &str,
    phase: CandidateReceiptPhase,
) -> Result<Option<CandidateOwnershipReceipt>, GitError> {
    let path = candidate_receipt_path(root, lock_token, phase);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(GitIoOperation::ReadJournal, &error)),
    };
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > u64::try_from(MAX_PRELOCK_RESERVATION_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    let file = File::open(&path).map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?;
    if !open_file_matches_path_and_is_single_link(&path, &file)
        .map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?
    {
        return Err(GitError::InvalidJournal);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_PRELOCK_RESERVATION_BYTES)
            .min(MAX_PRELOCK_RESERVATION_BYTES),
    );
    (&file)
        .take(
            u64::try_from(MAX_PRELOCK_RESERVATION_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?;
    if bytes.len() != usize::try_from(metadata.len()).unwrap_or(usize::MAX)
        || bytes.len() > MAX_PRELOCK_RESERVATION_BYTES
    {
        return Err(GitError::InvalidJournal);
    }
    let value = parse_duplicate_free_json(&bytes)?;
    let receipt = serde_json::from_value::<CandidateOwnershipReceipt>(value)
        .map_err(|_| GitError::InvalidJournal)?;
    validate_candidate_receipt(&receipt)?;
    if receipt.phase != phase
        || receipt.lock_token != lock_token
        || candidate_receipt_bytes(&receipt)? != bytes
    {
        return Err(GitError::InvalidJournal);
    }
    Ok(Some(receipt))
}

fn install_candidate_receipt(
    root: &Path,
    receipt: &CandidateOwnershipReceipt,
) -> Result<(), GitError> {
    let path = candidate_receipt_path(root, &receipt.lock_token, receipt.phase);
    match fs::symlink_metadata(&path) {
        Ok(_) => return Err(GitError::RecoveryConflict),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(GitIoOperation::InspectMetadata, &error)),
    }
    let bytes = candidate_receipt_bytes(receipt)?;
    let file = create_private_file(&path, &bytes)?;
    if !open_file_matches_path_and_is_single_link(&path, &file)
        .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Err(GitError::RecoveryConflict);
    }
    drop(file);
    sync_directory(&root.join(VAULT_LOCAL_DIRECTORY))
        .map_err(|_| GitError::DurabilityNotConfirmed)?;
    if read_regular_exact(&path, bytes.len())? != bytes {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn remove_candidate_receipt_exact(
    root: &Path,
    receipt: &CandidateOwnershipReceipt,
) -> Result<(), GitError> {
    let bytes = candidate_receipt_bytes(receipt)?;
    let path = candidate_receipt_path(root, &receipt.lock_token, receipt.phase);
    if !remove_regular_file_if_exact(&path, &bytes)? {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn install_prelock_reservation(
    root: &Path,
    reservation: &PreLockReservation,
) -> Result<(), GitError> {
    match fs::symlink_metadata(prelock_reservation_path(root)) {
        Ok(_) => return Err(GitError::JournalAlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(GitIoOperation::InspectMetadata, &error)),
    }
    let bytes = prelock_reservation_bytes(reservation)?;
    let staging_path = prelock_reservation_staging_path(root, &reservation.lock_token);
    let stable_path = prelock_reservation_path(root);
    let staging_file = create_private_file(&staging_path, &bytes)?;
    let move_result =
        atomic_move_verified_file_no_replace(&staging_path, &staging_file, &stable_path);
    drop(staging_file);
    match move_result {
        Ok(outcome) => {
            require_file_move_durability(outcome)?;
            if read_regular_exact(&stable_path, bytes.len())? != bytes {
                return Err(GitError::InvalidJournal);
            }
            Ok(())
        }
        Err(error) => {
            let stable_is_exact = matches!(
                read_regular_exact(&stable_path, bytes.len()),
                Ok(actual) if actual == bytes
            );
            let staging_is_exact = matches!(
                read_regular_exact(&staging_path, bytes.len()),
                Ok(actual) if actual == bytes
            );
            if stable_is_exact && !staging_is_exact {
                return Err(GitError::DurabilityNotConfirmed);
            }
            if staging_is_exact && !stable_is_exact {
                let _ = remove_regular_file_if_exact(&staging_path, &bytes);
                return if error.kind() == io::ErrorKind::AlreadyExists {
                    Err(GitError::JournalAlreadyExists)
                } else {
                    Err(io_error(GitIoOperation::WriteJournal, &error))
                };
            }
            Err(GitError::RecoveryConflict)
        }
    }
}

fn remove_prelock_reservation_exact(
    root: &Path,
    reservation: &PreLockReservation,
) -> Result<(), GitError> {
    let bytes = prelock_reservation_bytes(reservation)?;
    if !remove_regular_file_if_exact(&prelock_reservation_path(root), &bytes)? {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn remove_prelock_after_stable_journal(
    root: &Path,
    reservation: &PreLockReservation,
    journal: &CasMergeJournal,
) -> Result<(), GitError> {
    if !prelock_matches_cas_journal(reservation, journal)
        || !path_entry_is_absent(&prelock_reservation_staging_path(
            root,
            &reservation.lock_token,
        ))?
    {
        return Err(GitError::RecoveryConflict);
    }
    match read_journal(root)? {
        Some(PendingMergeJournal::Cas(actual)) if actual == *journal => {}
        _ => return Err(GitError::RecoveryConflict),
    }
    validate_prelock_private_inventory(root, reservation, true, false)?;
    let candidate = index_candidate_path(root, &reservation.candidate_file);
    for path in [
        appended_lock_path(&candidate),
        index_marker_staging_path(root, &reservation.lock_token),
    ] {
        if !path_entry_is_absent(&path)? {
            return Err(GitError::RecoveryConflict);
        }
    }
    let expected_initial = initial_candidate_receipt(reservation);
    let expected_final = final_candidate_receipt(
        reservation,
        journal.candidate_index_size,
        &journal.candidate_index_sha256,
    );
    let initial = read_candidate_receipt(
        root,
        &reservation.lock_token,
        CandidateReceiptPhase::Initial,
    )?;
    let final_receipt =
        read_candidate_receipt(root, &reservation.lock_token, CandidateReceiptPhase::Final)?;
    if initial
        .as_ref()
        .is_some_and(|actual| actual != &expected_initial)
        || final_receipt
            .as_ref()
            .is_some_and(|actual| actual != &expected_final)
    {
        return Err(GitError::RecoveryConflict);
    }
    if let Some(receipt) = &final_receipt {
        remove_candidate_receipt_exact(root, receipt)?;
    }
    if let Some(receipt) = &initial {
        remove_candidate_receipt_exact(root, receipt)?;
    }
    remove_prelock_reservation_exact(root, reservation)
}

fn path_entry_is_absent(path: &Path) -> Result<bool, GitError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(io_error(GitIoOperation::InspectMetadata, &error)),
    }
}

fn ascii_casefold_starts_with(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn exact_reserved_private_names(root: &Path) -> Result<BTreeSet<String>, GitError> {
    let stable_names = [PRELOCK_RESERVATION_FILE, JOURNAL_FILE];
    let prefixes = [
        PRELOCK_RESERVATION_STAGING_PREFIX,
        CANDIDATE_INITIAL_RECEIPT_PREFIX,
        CANDIDATE_FINAL_RECEIPT_PREFIX,
        INDEX_CANDIDATE_PREFIX,
        INDEX_MARKER_PREFIX,
        JOURNAL_STAGING_PREFIX,
    ];
    let local = root.join(VAULT_LOCAL_DIRECTORY);
    let entries =
        fs::read_dir(&local).map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
    let mut reserved_names = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(GitError::RecoveryConflict)?;
        let mut reserved = false;
        for stable in stable_names {
            if name.eq_ignore_ascii_case(stable) {
                if name != stable {
                    return Err(GitError::RecoveryConflict);
                }
                reserved = true;
            }
        }
        for prefix in prefixes {
            if ascii_casefold_starts_with(name, prefix) {
                if !name.starts_with(prefix) {
                    return Err(GitError::RecoveryConflict);
                }
                reserved = true;
            }
        }
        if reserved && !reserved_names.insert(name.to_owned()) {
            return Err(GitError::RecoveryConflict);
        }
    }
    Ok(reserved_names)
}

enum OrphanPrelockStaging {
    None,
    Exact {
        reservation: PreLockReservation,
        path: PathBuf,
    },
    Conflict,
}

fn inspect_orphan_prelock_staging(
    root: &Path,
    reserved_names: &BTreeSet<String>,
) -> Result<OrphanPrelockStaging, GitError> {
    let staging_names = reserved_names
        .iter()
        .filter(|name| name.starts_with(PRELOCK_RESERVATION_STAGING_PREFIX))
        .collect::<Vec<_>>();
    if staging_names.is_empty() {
        return Ok(OrphanPrelockStaging::None);
    }
    if staging_names.len() != 1
        || reserved_names.len() != 1
        || !path_entry_is_absent(&prelock_reservation_path(root))?
        || !path_entry_is_absent(&journal_path(root))?
        || !path_entry_is_absent(&index_lock_path(root))?
    {
        return Ok(OrphanPrelockStaging::Conflict);
    }
    let name = staging_names[0];
    let Some(lock_token) = name.strip_prefix(PRELOCK_RESERVATION_STAGING_PREFIX) else {
        return Ok(OrphanPrelockStaging::Conflict);
    };
    if validate_lock_token(lock_token).is_err() {
        return Ok(OrphanPrelockStaging::Conflict);
    }
    let path = root.join(VAULT_LOCAL_DIRECTORY).join(name);
    let reservation = read_prelock_reservation_file(&path)?;
    if reservation.lock_token != lock_token {
        return Ok(OrphanPrelockStaging::Conflict);
    }
    let live = read_index_snapshot(&index_path(root))?;
    if !snapshot_matches(
        &live,
        reservation.expected_index_size,
        &reservation.expected_index_sha256,
    ) {
        return Ok(OrphanPrelockStaging::Conflict);
    }
    Ok(OrphanPrelockStaging::Exact { reservation, path })
}

fn recover_orphan_prelock_staging(
    object_format: GitObjectFormat,
    reservation: &PreLockReservation,
    path: &Path,
) -> Result<(), GitError> {
    if reservation.object_format != object_format
        || read_prelock_reservation_file(path)? != *reservation
    {
        return Err(GitError::RecoveryConflict);
    }
    let bytes = prelock_reservation_bytes(reservation)?;
    if !remove_regular_file_if_exact(path, &bytes)? {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn validate_prelock_private_inventory(
    root: &Path,
    reservation: &PreLockReservation,
    allow_stable_journal: bool,
    allow_journal_staging: bool,
) -> Result<(), GitError> {
    let candidate_lock = appended_lock_path(Path::new(&reservation.candidate_file));
    let candidate_lock = candidate_lock
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(GitError::RecoveryConflict)?;
    let mut allowed = BTreeSet::from([
        PRELOCK_RESERVATION_FILE.to_owned(),
        reservation.candidate_file.clone(),
        candidate_lock.to_owned(),
        format!(
            "{CANDIDATE_INITIAL_RECEIPT_PREFIX}{}",
            reservation.lock_token
        ),
        format!("{CANDIDATE_FINAL_RECEIPT_PREFIX}{}", reservation.lock_token),
        format!("{INDEX_MARKER_PREFIX}{}", reservation.lock_token),
        format!(
            "{PRELOCK_RESERVATION_STAGING_PREFIX}{}",
            reservation.lock_token
        ),
    ]);
    if allow_journal_staging {
        allowed.insert(format!(
            "{JOURNAL_STAGING_PREFIX}{}",
            reservation.lock_token
        ));
    }
    if allow_stable_journal {
        allowed.insert(JOURNAL_FILE.to_owned());
    }
    for name in exact_reserved_private_names(root)? {
        if !allowed.contains(&name) {
            return Err(GitError::RecoveryConflict);
        }
    }
    Ok(())
}

fn validate_prelock_owned_files(
    root: &Path,
    reservation: &PreLockReservation,
) -> Result<
    (
        Option<CandidateOwnershipReceipt>,
        Option<CandidateOwnershipReceipt>,
    ),
    GitError,
> {
    let initial = read_candidate_receipt(
        root,
        &reservation.lock_token,
        CandidateReceiptPhase::Initial,
    )?;
    let final_receipt =
        read_candidate_receipt(root, &reservation.lock_token, CandidateReceiptPhase::Final)?;
    if initial
        .as_ref()
        .is_some_and(|receipt| !receipt_matches_reservation(receipt, reservation))
        || final_receipt
            .as_ref()
            .is_some_and(|receipt| !receipt_matches_reservation(receipt, reservation))
        || (final_receipt.is_some() && initial.is_none())
    {
        return Err(GitError::RecoveryConflict);
    }
    let candidate_path = index_candidate_path(root, &reservation.candidate_file);
    if !path_entry_is_absent(&appended_lock_path(&candidate_path))? {
        return Err(GitError::RecoveryConflict);
    }
    let expected_candidate = final_receipt.as_ref().or(initial.as_ref());
    if let Some(expected) = expected_candidate {
        if let Some(snapshot) = optional_index_snapshot(&candidate_path)?
            && !snapshot_matches(
                &snapshot,
                expected.candidate_index_size,
                &expected.candidate_index_sha256,
            )
        {
            return Err(GitError::RecoveryConflict);
        }
    } else if !path_entry_is_absent(&candidate_path)? {
        return Err(GitError::RecoveryConflict);
    }
    let marker_path = index_marker_staging_path(root, &reservation.lock_token);
    if let Some(final_receipt) = &final_receipt {
        if !path_entry_is_absent(&marker_path)? {
            let marker = index_lock_marker_bytes(
                &reservation.lock_token,
                reservation.expected_index_size,
                &reservation.expected_index_sha256,
                final_receipt.candidate_index_size,
                &final_receipt.candidate_index_sha256,
            );
            if read_regular_exact(&marker_path, marker.len())? != marker {
                return Err(GitError::RecoveryConflict);
            }
        }
    } else if !path_entry_is_absent(&marker_path)? {
        return Err(GitError::RecoveryConflict);
    }
    Ok((initial, final_receipt))
}

fn remove_verified_candidate_if_present(
    root: &Path,
    receipt: &CandidateOwnershipReceipt,
) -> Result<(), GitError> {
    let path = index_candidate_path(root, &receipt.candidate_file);
    if path_entry_is_absent(&path)? {
        return Ok(());
    }
    if !remove_regular_file_if_digest(
        &path,
        receipt.candidate_index_size,
        &receipt.candidate_index_sha256,
    )? {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn remove_verified_marker_if_present(
    root: &Path,
    reservation: &PreLockReservation,
    final_receipt: &CandidateOwnershipReceipt,
) -> Result<(), GitError> {
    let path = index_marker_staging_path(root, &reservation.lock_token);
    if path_entry_is_absent(&path)? {
        return Ok(());
    }
    let marker = index_lock_marker_bytes(
        &reservation.lock_token,
        reservation.expected_index_size,
        &reservation.expected_index_sha256,
        final_receipt.candidate_index_size,
        &final_receipt.candidate_index_sha256,
    );
    if !remove_regular_file_if_exact(&path, &marker)? {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn clean_verified_prelock_owned_files(
    root: &Path,
    reservation: &PreLockReservation,
) -> Result<(), GitError> {
    let (initial, final_receipt) = validate_prelock_owned_files(root, reservation)?;
    if let Some(final_receipt) = &final_receipt {
        remove_verified_marker_if_present(root, reservation, final_receipt)?;
    }
    if let Some(candidate_receipt) = final_receipt.as_ref().or(initial.as_ref()) {
        remove_verified_candidate_if_present(root, candidate_receipt)?;
    }
    if let Some(receipt) = &final_receipt {
        remove_candidate_receipt_exact(root, receipt)?;
    }
    if let Some(receipt) = &initial {
        remove_candidate_receipt_exact(root, receipt)?;
    }
    Ok(())
}

fn index_lock_may_belong_to_prelock(
    root: &Path,
    reservation: &PreLockReservation,
) -> Result<bool, GitError> {
    let path = index_lock_path(root);
    let metadata = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Ok(metadata) => metadata,
        Err(error) => return Err(io_error(GitIoOperation::InspectMetadata, &error)),
    };
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > 512
    {
        return Ok(false);
    }
    let bytes = read_regular_exact(
        &path,
        usize::try_from(metadata.len()).map_err(|_| GitError::RecoveryConflict)?,
    )?;
    if !bytes.starts_with(INDEX_LOCK_MARKER_MAGIC) {
        return Ok(false);
    }
    let parsed = parse_index_lock_marker(&bytes).map_err(|_| GitError::RecoveryConflict)?;
    Ok(parsed.lock_token == reservation.lock_token)
}

fn abort_owned_prelock_reservation(
    root: &Path,
    reservation: &PreLockReservation,
    phase: PreLockOwnershipPhase,
) -> Result<(), GitError> {
    validate_prelock_reservation(reservation)?;
    if read_prelock_reservation(root)?.as_ref() != Some(reservation)
        || !path_entry_is_absent(&journal_path(root))?
        || index_lock_may_belong_to_prelock(root, reservation)?
    {
        return Err(GitError::RecoveryConflict);
    }
    validate_prelock_private_inventory(root, reservation, false, false)?;
    let candidate_path = index_candidate_path(root, &reservation.candidate_file);
    let initial = read_candidate_receipt(
        root,
        &reservation.lock_token,
        CandidateReceiptPhase::Initial,
    )?;
    let final_receipt =
        read_candidate_receipt(root, &reservation.lock_token, CandidateReceiptPhase::Final)?;
    let marker_path = index_marker_staging_path(root, &reservation.lock_token);
    let candidate_created = phase >= PreLockOwnershipPhase::Candidate;
    let initial_receipt_created = phase >= PreLockOwnershipPhase::InitialReceipt;
    let final_receipt_created = phase >= PreLockOwnershipPhase::FinalReceipt;
    let marker_staging_created = phase == PreLockOwnershipPhase::MarkerStaging;
    if initial.is_some() != initial_receipt_created
        || final_receipt.is_some() != final_receipt_created
        || path_entry_is_absent(&marker_path)? == marker_staging_created
        || !path_entry_is_absent(&prelock_reservation_staging_path(
            root,
            &reservation.lock_token,
        ))?
        || !path_entry_is_absent(&appended_lock_path(&candidate_path))?
    {
        return Err(GitError::RecoveryConflict);
    }
    if candidate_created {
        let expected = final_receipt
            .as_ref()
            .or(initial.as_ref())
            .cloned()
            .unwrap_or_else(|| initial_candidate_receipt(reservation));
        let snapshot = read_index_snapshot(&candidate_path)?;
        if !snapshot_matches(
            &snapshot,
            expected.candidate_index_size,
            &expected.candidate_index_sha256,
        ) {
            return Err(GitError::RecoveryConflict);
        }
    } else if !path_entry_is_absent(&candidate_path)? {
        return Err(GitError::RecoveryConflict);
    }
    if marker_staging_created {
        let final_receipt = final_receipt.as_ref().ok_or(GitError::RecoveryConflict)?;
        remove_verified_marker_if_present(root, reservation, final_receipt)?;
    }
    if candidate_created {
        let expected = final_receipt
            .as_ref()
            .or(initial.as_ref())
            .cloned()
            .unwrap_or_else(|| initial_candidate_receipt(reservation));
        remove_verified_candidate_if_present(root, &expected)?;
    }
    if let Some(receipt) = &final_receipt {
        remove_candidate_receipt_exact(root, receipt)?;
    }
    if let Some(receipt) = &initial {
        remove_candidate_receipt_exact(root, receipt)?;
    }
    remove_prelock_reservation_exact(root, reservation)
}

fn recover_prelock_without_index_lock(
    root: &Path,
    reservation: &PreLockReservation,
) -> Result<(), GitError> {
    validate_prelock_reservation(reservation)?;
    if read_prelock_reservation(root)?.as_ref() != Some(reservation)
        || !path_entry_is_absent(&index_lock_path(root))?
        || !path_entry_is_absent(&journal_path(root))?
    {
        return Err(GitError::RecoveryConflict);
    }
    validate_prelock_private_inventory(root, reservation, false, false)?;
    if !path_entry_is_absent(&prelock_reservation_staging_path(
        root,
        &reservation.lock_token,
    ))? {
        return Err(GitError::RecoveryConflict);
    }
    let live = read_index_snapshot(&index_path(root))?;
    if !snapshot_matches(
        &live,
        reservation.expected_index_size,
        &reservation.expected_index_sha256,
    ) {
        return Err(GitError::RecoveryConflict);
    }
    let journal_staging = root.join(VAULT_LOCAL_DIRECTORY).join(format!(
        "{JOURNAL_STAGING_PREFIX}{}",
        reservation.lock_token
    ));
    if !path_entry_is_absent(&journal_staging)? {
        return Err(GitError::RecoveryConflict);
    }
    clean_verified_prelock_owned_files(root, reservation)?;
    remove_prelock_reservation_exact(root, reservation)
}

fn prepare_index_cas(
    git: &Git,
    transaction: &MergeJournalPayload,
) -> Result<PreparedIndexCas, GitError> {
    prepare_index_cas_with_hook(git, transaction, || Ok(()))
}

#[allow(clippy::too_many_lines)] // Keep candidate preparation and real-lock acquisition adjacent.
fn prepare_index_cas_with_hook<F>(
    git: &Git,
    transaction: &MergeJournalPayload,
    before_lock: F,
) -> Result<PreparedIndexCas, GitError>
where
    F: FnOnce() -> Result<(), GitError>,
{
    validate_payload(transaction)?;
    ensure_no_journal(&git.root)?;
    git.ensure_full_index()?;
    let old = read_index_snapshot(&index_path(&git.root))?;
    let local = git.root.join(VAULT_LOCAL_DIRECTORY);
    validate_local_directory(&local)?;
    if !exact_reserved_private_names(&git.root)?.is_empty() {
        return Err(GitError::RecoveryConflict);
    }

    let lock_token = Uuid::new_v4().simple().to_string();
    let candidate_file = format!("{INDEX_CANDIDATE_PREFIX}{lock_token}");
    let prelock = PreLockReservation {
        version: 4,
        object_format: git.object_format,
        lock_token: lock_token.clone(),
        candidate_file: candidate_file.clone(),
        expected_index_sha256: old.sha256.clone(),
        expected_index_size: old.size,
    };
    install_prelock_reservation(&git.root, &prelock)?;
    let mut prelock_guard = PreLockReservationGuard::new(git.root.clone(), prelock.clone());
    validate_prelock_private_inventory(&git.root, &prelock, false, false)?;
    let candidate_path = index_candidate_path(&git.root, &candidate_file);
    let marker_path = index_marker_staging_path(&git.root, &lock_token);
    let candidate_file_handle = create_private_file(&candidate_path, &old.bytes)?;
    prelock_guard.candidate_created();
    drop(candidate_file_handle);
    sync_directory(&local).map_err(|_| GitError::DurabilityNotConfirmed)?;
    let initial_candidate = read_index_snapshot(&candidate_path)?;
    if !snapshot_matches(&initial_candidate, old.size, &old.sha256) {
        return Err(GitError::RecoveryConflict);
    }
    let initial_receipt = initial_candidate_receipt(&prelock);
    install_candidate_receipt(&git.root, &initial_receipt)?;
    prelock_guard.initial_receipt_created();

    let candidate_git = git.with_index_file(candidate_path.clone())?;
    let before = index_entry_map(&candidate_git)?;
    apply_payload_to_index(&candidate_git, transaction)?;
    verify_candidate_index(&candidate_git, transaction, &before)?;
    let candidate = read_index_snapshot(&candidate_path)?;
    if candidate.sha256 == old.sha256 {
        return Err(GitError::IndexChanged);
    }
    let final_receipt = final_candidate_receipt(&prelock, candidate.size, &candidate.sha256);
    install_candidate_receipt(&git.root, &final_receipt)?;
    prelock_guard.final_receipt_created();
    before_lock()?;

    let marker = index_lock_marker_bytes(
        &lock_token,
        old.size,
        &old.sha256,
        candidate.size,
        &candidate.sha256,
    );
    let marker_file = create_private_file(&marker_path, &marker)?;
    prelock_guard.marker_staging_created();
    sync_directory(&local).map_err(|_| GitError::DurabilityNotConfirmed)?;
    let lock_path = index_lock_path(&git.root);
    let move_result = atomic_move_verified_file_no_replace(&marker_path, &marker_file, &lock_path);
    drop(marker_file);
    let namespace_durable = match move_result {
        Ok(outcome) => require_file_move_durability(outcome).is_ok(),
        Err(error) => {
            let lock_has_marker = matches!(
                read_regular_exact(&lock_path, marker.len()),
                Ok(actual) if actual == marker
            );
            let staging_has_marker = matches!(
                read_regular_exact(&marker_path, marker.len()),
                Ok(actual) if actual == marker
            );
            if lock_has_marker && !staging_has_marker {
                sync_directory(&local).is_ok() && sync_directory(&git.root.join(".git")).is_ok()
            } else if staging_has_marker && !lock_has_marker {
                return if error.kind() == io::ErrorKind::AlreadyExists {
                    Err(GitError::IndexChanged)
                } else {
                    Err(io_error(GitIoOperation::SyncGitState, &error))
                };
            } else {
                prelock_guard.disarm();
                return Err(GitError::RecoveryConflict);
            }
        }
    };

    let mut prepared = PreparedIndexCas {
        root: git.root.clone(),
        prelock,
        object_format: git.object_format,
        lock_token,
        lock_marker_sha256: hex_digest(digest(&marker)),
        candidate_file,
        expected_index_sha256: old.sha256.clone(),
        expected_index_size: old.size,
        candidate_index_sha256: candidate.sha256,
        candidate_index_size: candidate.size,
        armed: true,
    };
    prelock_guard.disarm();
    if !namespace_durable {
        prepared.disarm();
        return Err(GitError::DurabilityNotConfirmed);
    }
    if read_regular_exact(&lock_path, marker.len())? != marker {
        return Err(GitError::IndexChanged);
    }
    let locked_old = read_index_snapshot(&index_path(&git.root))?;
    if locked_old.sha256 != old.sha256 || locked_old.size != old.size {
        return Err(GitError::IndexChanged);
    }
    git.ensure_full_index()?;
    verify_candidate_index(&candidate_git, transaction, &before)?;
    let locked_candidate = read_index_snapshot(&candidate_path)?;
    if locked_candidate.sha256 != prepared.candidate_index_sha256
        || locked_candidate.size != prepared.candidate_index_size
    {
        return Err(GitError::IndexChanged);
    }
    Ok(prepared)
}

fn write_cas_journal(
    root: &Path,
    prepared: &mut PreparedIndexCas,
    transaction: MergeJournalPayload,
) -> Result<PendingMergeJournal, GitError> {
    let pending = PendingMergeJournal::Cas(prepared.journal(transaction));
    match write_journal(root, &pending) {
        Ok(()) => {
            prepared.disarm();
            let PendingMergeJournal::Cas(journal) = &pending else {
                return Err(GitError::InvalidJournal);
            };
            remove_prelock_after_stable_journal(root, &prepared.prelock, journal)?;
            Ok(pending)
        }
        Err(error) => {
            let exact_journal_is_visible = matches!(
                read_journal(root),
                Ok(Some(ref actual)) if actual == &pending
            );
            if exact_journal_is_visible
                || (!matches!(&error, GitError::JournalAlreadyExists)
                    && fs::symlink_metadata(journal_path(root)).is_ok())
            {
                prepared.disarm();
            }
            if exact_journal_is_visible && let PendingMergeJournal::Cas(journal) = &pending {
                let _ = remove_prelock_after_stable_journal(root, &prepared.prelock, journal);
            }
            Err(error)
        }
    }
}

fn mutation_matches_payload(mutation: IndexMutation<'_>, payload: &MergeJournalPayload) -> bool {
    match (mutation, payload) {
        (
            IndexMutation::Upsert {
                physical_path,
                mode,
                oid,
            },
            MergeJournalPayload::InPlace(journal),
        ) => {
            physical_path == journal.physical_path
                && mode == journal.result_mode
                && oid == journal.result_oid
        }
        (
            IndexMutation::Upsert {
                physical_path,
                mode,
                oid,
            },
            MergeJournalPayload::DetectedRename(journal),
        ) => {
            physical_path == journal.destination_physical_path
                && mode == journal.result_mode
                && oid == journal.result_oid
        }
        (
            IndexMutation::Rename {
                source_physical_path,
                destination_physical_path,
                mode,
                oid,
            },
            MergeJournalPayload::Rename(journal),
        ) => {
            source_physical_path == journal.source_physical_path
                && destination_physical_path == journal.destination_physical_path
                && mode == journal.result_mode
                && oid == journal.result_oid
        }
        (IndexMutation::Upsert { .. }, MergeJournalPayload::Rename(_))
        | (IndexMutation::Rename { .. }, MergeJournalPayload::InPlace(_))
        | (IndexMutation::Rename { .. }, MergeJournalPayload::DetectedRename(_)) => false,
    }
}

fn optional_index_snapshot(path: &Path) -> Result<Option<IndexSnapshot>, GitError> {
    match read_index_snapshot(path) {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(GitError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }) => Ok(None),
        Err(error) => Err(error),
    }
}

enum AbandonedCasReservation {
    None,
    Exact {
        marker: Vec<u8>,
        lock_token: String,
        candidate_file: String,
        expected_index_size: u64,
        expected_index_sha256: String,
        candidate_path: PathBuf,
        candidate_size: u64,
        candidate_sha256: String,
        journal_staging_path: Option<PathBuf>,
    },
    Conflict,
}

fn inspect_abandoned_cas_reservation(root: &Path) -> Result<AbandonedCasReservation, GitError> {
    let lock_path = index_lock_path(root);
    let metadata = match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(AbandonedCasReservation::None);
        }
        Err(error) => return Err(io_error(GitIoOperation::InspectMetadata, &error)),
    };
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > 512
    {
        return Ok(AbandonedCasReservation::None);
    }
    let mut file =
        File::open(&lock_path).map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if !open_file_matches_path_and_is_single_link(&lock_path, &file)
        .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Ok(AbandonedCasReservation::None);
    }
    let mut marker = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(512));
    (&mut file)
        .take(513)
        .read_to_end(&mut marker)
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if !marker.starts_with(INDEX_LOCK_MARKER_MAGIC) {
        return Ok(AbandonedCasReservation::None);
    }
    let Ok(parsed) = parse_index_lock_marker(&marker) else {
        return Ok(AbandonedCasReservation::Conflict);
    };
    let candidate_file = format!("{INDEX_CANDIDATE_PREFIX}{}", parsed.lock_token);
    let candidate_path = index_candidate_path(root, &candidate_file);
    if !path_entry_is_absent(&index_marker_staging_path(root, &parsed.lock_token))? {
        return Ok(AbandonedCasReservation::Conflict);
    }
    let Ok(Some(candidate)) = optional_index_snapshot(&candidate_path) else {
        return Ok(AbandonedCasReservation::Conflict);
    };
    let Ok(live) = read_index_snapshot(&index_path(root)) else {
        return Ok(AbandonedCasReservation::Conflict);
    };
    if !snapshot_matches(
        &live,
        parsed.expected_index_size,
        &parsed.expected_index_sha256,
    ) || !snapshot_matches(
        &candidate,
        parsed.candidate_index_size,
        &parsed.candidate_index_sha256,
    ) {
        return Ok(AbandonedCasReservation::Conflict);
    }
    let journal_staging_path = root
        .join(VAULT_LOCAL_DIRECTORY)
        .join(format!("{JOURNAL_STAGING_PREFIX}{}", parsed.lock_token));
    let journal_staging_path = match fs::symlink_metadata(&journal_staging_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Ok(metadata) if !is_link_or_reparse_point(&metadata) && metadata.file_type().is_file() => {
            Some(journal_staging_path)
        }
        Ok(_) => return Ok(AbandonedCasReservation::Conflict),
        Err(error) => return Err(io_error(GitIoOperation::InspectMetadata, &error)),
    };
    Ok(AbandonedCasReservation::Exact {
        marker,
        lock_token: parsed.lock_token,
        candidate_file,
        expected_index_size: parsed.expected_index_size,
        expected_index_sha256: parsed.expected_index_sha256,
        candidate_path,
        candidate_size: parsed.candidate_index_size,
        candidate_sha256: parsed.candidate_index_sha256,
        journal_staging_path,
    })
}

fn recover_abandoned_cas_reservation(
    root: &Path,
    object_format: GitObjectFormat,
) -> Result<bool, GitError> {
    let prelock = read_prelock_reservation(root)?;
    match inspect_abandoned_cas_reservation(root)? {
        AbandonedCasReservation::None => {
            let Some(reservation) = prelock else {
                return Ok(false);
            };
            if reservation.object_format != object_format {
                return Err(GitError::RecoveryConflict);
            }
            recover_prelock_without_index_lock(root, &reservation)?;
            Ok(true)
        }
        AbandonedCasReservation::Conflict => Err(GitError::RecoveryConflict),
        AbandonedCasReservation::Exact {
            marker,
            lock_token,
            candidate_file,
            expected_index_size,
            expected_index_sha256,
            candidate_path,
            candidate_size,
            candidate_sha256,
            journal_staging_path,
        } => {
            if let Some(reservation) = &prelock
                && (reservation.object_format != object_format
                    || reservation.lock_token != lock_token
                    || reservation.candidate_file != candidate_file
                    || reservation.expected_index_size != expected_index_size
                    || reservation.expected_index_sha256 != expected_index_sha256)
            {
                return Err(GitError::RecoveryConflict);
            }
            if let Some(reservation) = &prelock {
                validate_prelock_private_inventory(root, reservation, false, true)?;
                let initial = read_candidate_receipt(
                    root,
                    &reservation.lock_token,
                    CandidateReceiptPhase::Initial,
                )?
                .ok_or(GitError::RecoveryConflict)?;
                let final_receipt = read_candidate_receipt(
                    root,
                    &reservation.lock_token,
                    CandidateReceiptPhase::Final,
                )?
                .ok_or(GitError::RecoveryConflict)?;
                if initial != initial_candidate_receipt(reservation)
                    || final_receipt
                        != final_candidate_receipt(reservation, candidate_size, &candidate_sha256)
                {
                    return Err(GitError::RecoveryConflict);
                }
            }
            if let Some(staging_path) = journal_staging_path {
                let pending = read_journal_file(&staging_path)?;
                let PendingMergeJournal::Cas(journal) = pending else {
                    return Err(GitError::RecoveryConflict);
                };
                if journal.lock_token != lock_token
                    || journal.candidate_file != candidate_file
                    || journal.expected_index_size != expected_index_size
                    || journal.expected_index_sha256 != expected_index_sha256
                    || journal.candidate_index_size != candidate_size
                    || journal.candidate_index_sha256 != candidate_sha256
                {
                    return Err(GitError::RecoveryConflict);
                }
                let bytes = serde_json::to_vec(&journal).map_err(|_| GitError::InvalidJournal)?;
                if read_regular_exact(&staging_path, bytes.len())? != bytes
                    || !remove_regular_file_if_exact(&staging_path, &bytes)?
                {
                    return Err(GitError::RecoveryConflict);
                }
            }
            if !remove_regular_file_if_exact(&index_lock_path(root), &marker)? {
                return Err(GitError::RecoveryConflict);
            }
            if !remove_regular_file_if_digest(&candidate_path, candidate_size, &candidate_sha256)? {
                return Err(GitError::RecoveryConflict);
            }
            if let Some(reservation) = &prelock {
                let final_receipt =
                    final_candidate_receipt(reservation, candidate_size, &candidate_sha256);
                let initial = initial_candidate_receipt(reservation);
                remove_candidate_receipt_exact(root, &final_receipt)?;
                remove_candidate_receipt_exact(root, &initial)?;
                remove_prelock_reservation_exact(root, reservation)?;
            }
            Ok(true)
        }
    }
}

fn snapshot_matches(snapshot: &IndexSnapshot, size: u64, sha256: &str) -> bool {
    snapshot.size == size && snapshot.sha256 == sha256
}

fn require_file_move_durability(outcome: AtomicFileMoveOutcome) -> Result<(), GitError> {
    if outcome.source_parent_sync == ParentSyncStatus::Synced
        && outcome.destination_parent_sync == ParentSyncStatus::Synced
    {
        Ok(())
    } else {
        Err(GitError::DurabilityNotConfirmed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CasIndexLockState {
    Absent,
    Marker,
    Candidate,
    Foreign,
}

fn classify_cas_index_lock(
    root: &Path,
    journal: &CasMergeJournal,
) -> Result<CasIndexLockState, GitError> {
    let path = index_lock_path(root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CasIndexLockState::Absent);
        }
        Err(error) => return Err(io_error(GitIoOperation::InspectMetadata, &error)),
    };
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
    {
        return Ok(CasIndexLockState::Foreign);
    }
    let snapshot = match read_index_snapshot(&path) {
        Ok(snapshot) => snapshot,
        Err(GitError::IndexChanged) => return Ok(CasIndexLockState::Foreign),
        Err(error) => return Err(error),
    };
    let marker_size = u64::try_from(
        index_lock_marker_bytes(
            &journal.lock_token,
            journal.expected_index_size,
            &journal.expected_index_sha256,
            journal.candidate_index_size,
            &journal.candidate_index_sha256,
        )
        .len(),
    )
    .unwrap_or(u64::MAX);
    if snapshot.size == marker_size && snapshot.sha256 == journal.lock_marker_sha256 {
        Ok(CasIndexLockState::Marker)
    } else if snapshot_matches(
        &snapshot,
        journal.candidate_index_size,
        &journal.candidate_index_sha256,
    ) {
        Ok(CasIndexLockState::Candidate)
    } else {
        Ok(CasIndexLockState::Foreign)
    }
}

fn reconcile_candidate_to_lock_error(
    root: &Path,
    journal: &CasMergeJournal,
    error: &io::Error,
) -> Result<(), GitError> {
    let lock = optional_index_snapshot(&index_lock_path(root));
    let candidate = optional_index_snapshot(&index_candidate_path(root, &journal.candidate_file));
    match (lock, candidate) {
        (Ok(Some(lock)), Ok(None))
            if snapshot_matches(
                &lock,
                journal.candidate_index_size,
                &journal.candidate_index_sha256,
            ) =>
        {
            Err(GitError::DurabilityNotConfirmed)
        }
        (Ok(Some(lock)), Ok(Some(candidate)))
            if lock.size
                == u64::try_from(
                    index_lock_marker_bytes(
                        &journal.lock_token,
                        journal.expected_index_size,
                        &journal.expected_index_sha256,
                        journal.candidate_index_size,
                        &journal.candidate_index_sha256,
                    )
                    .len(),
                )
                .unwrap_or(u64::MAX)
                && lock.sha256 == journal.lock_marker_sha256
                && snapshot_matches(
                    &candidate,
                    journal.candidate_index_size,
                    &journal.candidate_index_sha256,
                ) =>
        {
            Err(io_error(GitIoOperation::SyncGitState, error))
        }
        _ => Err(GitError::RecoveryConflict),
    }
}

fn reconcile_lock_to_index_error(
    root: &Path,
    journal: &CasMergeJournal,
    error: &io::Error,
) -> Result<(), GitError> {
    let live = read_index_snapshot(&index_path(root));
    let lock = optional_index_snapshot(&index_lock_path(root));
    match (live, lock) {
        (Ok(live), Ok(None))
            if snapshot_matches(
                &live,
                journal.candidate_index_size,
                &journal.candidate_index_sha256,
            ) =>
        {
            Err(GitError::DurabilityNotConfirmed)
        }
        (Ok(live), Ok(Some(lock)))
            if snapshot_matches(
                &live,
                journal.expected_index_size,
                &journal.expected_index_sha256,
            ) && snapshot_matches(
                &lock,
                journal.candidate_index_size,
                &journal.candidate_index_sha256,
            ) =>
        {
            Err(io_error(GitIoOperation::SyncGitState, error))
        }
        _ => Err(GitError::RecoveryConflict),
    }
}

#[allow(clippy::too_many_lines)] // Keep the two physical index publication transitions adjacent.
fn publish_cas_index(
    git: &Git,
    journal: &CasMergeJournal,
    mutation: IndexMutation<'_>,
) -> Result<(), GitError> {
    validate_cas_journal(journal)?;
    if journal.object_format != git.object_format
        || !mutation_matches_payload(mutation, &journal.transaction)
    {
        return Err(GitError::RecoveryConflict);
    }
    git.ensure_full_index()?;
    let live = read_index_snapshot(&index_path(&git.root))?;
    if snapshot_matches(
        &live,
        journal.candidate_index_size,
        &journal.candidate_index_sha256,
    ) {
        git.sync_index()?;
        return Ok(());
    }
    if !snapshot_matches(
        &live,
        journal.expected_index_size,
        &journal.expected_index_sha256,
    ) {
        return Err(GitError::RecoveryConflict);
    }

    let lock_path = index_lock_path(&git.root);
    let candidate_path = index_candidate_path(&git.root, &journal.candidate_file);
    let lock = optional_index_snapshot(&lock_path)?;
    let candidate = optional_index_snapshot(&candidate_path)?;
    let lock_has_marker = lock.as_ref().is_some_and(|snapshot| {
        snapshot.size
            == u64::try_from(
                index_lock_marker_bytes(
                    &journal.lock_token,
                    journal.expected_index_size,
                    &journal.expected_index_sha256,
                    journal.candidate_index_size,
                    &journal.candidate_index_sha256,
                )
                .len(),
            )
            .unwrap_or(u64::MAX)
            && snapshot.sha256 == journal.lock_marker_sha256
    });
    let lock_has_candidate = lock.as_ref().is_some_and(|snapshot| {
        snapshot_matches(
            snapshot,
            journal.candidate_index_size,
            &journal.candidate_index_sha256,
        )
    });
    let candidate_is_final = candidate.as_ref().is_some_and(|snapshot| {
        snapshot_matches(
            snapshot,
            journal.candidate_index_size,
            &journal.candidate_index_sha256,
        )
    });

    let candidate_index_path = if lock_has_marker && candidate_is_final {
        candidate_path.clone()
    } else if lock_has_candidate && candidate.is_none() {
        lock_path.clone()
    } else {
        return Err(GitError::RecoveryConflict);
    };
    let before = index_entry_map(git)?;
    let candidate_git = git.with_index_file(candidate_index_path)?;
    verify_candidate_index(&candidate_git, &journal.transaction, &before)?;

    if lock_has_marker && candidate_is_final {
        let source = File::open(&candidate_path)
            .map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
        let destination = File::open(&lock_path)
            .map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
        let outcome =
            match atomic_replace_verified_file(&candidate_path, source, &lock_path, destination) {
                Ok(outcome) => outcome,
                Err(error) => {
                    return reconcile_candidate_to_lock_error(&git.root, journal, &error);
                }
            };
        require_file_move_durability(outcome)?;
    }

    let lock = optional_index_snapshot(&lock_path)?;
    if !lock.as_ref().is_some_and(|snapshot| {
        snapshot_matches(
            snapshot,
            journal.candidate_index_size,
            &journal.candidate_index_sha256,
        )
    }) || optional_index_snapshot(&candidate_path)?.is_some()
    {
        return Err(GitError::RecoveryConflict);
    }
    sync_regular_file(&lock_path, MAX_GIT_OUTPUT_BYTES)?;
    let live = read_index_snapshot(&index_path(&git.root))?;
    if !snapshot_matches(
        &live,
        journal.expected_index_size,
        &journal.expected_index_sha256,
    ) {
        return Err(GitError::RecoveryConflict);
    }

    let source =
        File::open(&lock_path).map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    let destination = File::open(index_path(&git.root))
        .map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    let outcome =
        match atomic_replace_verified_file(&lock_path, source, &index_path(&git.root), destination)
        {
            Ok(outcome) => outcome,
            Err(error) => return reconcile_lock_to_index_error(&git.root, journal, &error),
        };
    require_file_move_durability(outcome)?;
    let final_index = read_index_snapshot(&index_path(&git.root))?;
    if !snapshot_matches(
        &final_index,
        journal.candidate_index_size,
        &journal.candidate_index_sha256,
    ) || optional_index_snapshot(&lock_path)?.is_some()
    {
        return Err(GitError::RecoveryConflict);
    }
    git.sync_index()
}

fn commit_result(
    vault: &Vault,
    git: &Git,
    conflict: &ConflictEntry,
    prepared: &PreparedResult,
) -> Result<(), GitError> {
    let guard = VaultMutationGuard::acquire(vault.root()).map_err(map_atomic_error)?;
    ensure_no_journal(vault.root())?;
    let current = git.unmerged_entries()?;
    if current.get(&conflict.physical_path) != Some(conflict)
        || git.stage_zero(&conflict.physical_path)?.is_some()
    {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        None,
        &[&conflict.physical_path],
    )?;

    let target = vault
        .root()
        .join(conflict.logical_path.to_ciphertext_relative_path());
    let expected = expected_worktree_digest(prepared).ok_or(GitError::UnsupportedConflictEntry)?;
    let current_target = guard.inspect(&target).map_err(map_atomic_error)?;
    let condition = match current_target {
        CurrentTarget::File(actual) if actual == expected => WriteCondition::IfMatch(expected),
        _ => return Err(GitError::WorktreeChanged),
    };
    let result_digest = digest(&prepared.encrypted.bytes);
    let journal = MergeJournal {
        version: 1,
        physical_path: conflict.physical_path.clone(),
        result_mode: result_mode(conflict)?.to_owned(),
        stages: conflict.stages.clone(),
        expected_worktree_sha256: hex_digest(expected),
        result_oid: prepared.result_oid.clone(),
        result_sha256: hex_digest(result_digest),
    };
    let transaction = MergeJournalPayload::InPlace(journal.clone());
    let mut prepared_index = prepare_index_cas(git, &transaction)?;
    if git.unmerged_entries()?.get(&conflict.physical_path) != Some(conflict)
        || git.stage_zero(&conflict.physical_path)?.is_some()
    {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        None,
        &[&conflict.physical_path],
    )?;
    git.verify_attributes_for_path(&conflict.physical_path)?;
    let pending = write_cas_journal(vault.root(), &mut prepared_index, transaction)?;

    let outcome = guard
        .write(&target, &prepared.encrypted.bytes, condition)
        .map_err(map_atomic_error)?;
    if outcome.parent_sync != ParentSyncStatus::Synced {
        return Err(GitError::DurabilityNotConfirmed);
    }
    if git.unmerged_entries()?.get(&conflict.physical_path) != Some(conflict)
        || git.stage_zero(&conflict.physical_path)?.is_some()
    {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        None,
        &[&conflict.physical_path],
    )?;
    git.update_index(
        &conflict.physical_path,
        &journal.result_mode,
        &prepared.result_oid,
    )?;
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        Some(&conflict.physical_path),
        &[&conflict.physical_path],
    )?;
    verify_committed_state(git, &guard, &target, &journal, result_digest)?;
    remove_journal(vault.root(), &pending)
}

#[allow(clippy::too_many_lines)] // Keep the ordered crash transaction visible in one state machine.
fn commit_detected_rename_result(
    vault: &Vault,
    git: &Git,
    conflict: &ConflictEntry,
    stage_paths: &[Option<LogicalPath>; 3],
    renamed_side: RenameSide,
    provenance: &RenameProvenance,
    prepared: &PreparedResult,
) -> Result<(), GitError> {
    let source_logical_path = stage_paths[0]
        .as_ref()
        .ok_or(GitError::UnsupportedConflictEntry)?;
    if stage_paths[renamed_side.stage_index()].as_ref() != Some(&conflict.logical_path)
        || stage_paths[match renamed_side {
            RenameSide::Ours => RenameSide::Theirs.stage_index(),
            RenameSide::Theirs => RenameSide::Ours.stage_index(),
        }]
        .as_ref()
            != Some(source_logical_path)
    {
        return Err(GitError::UnsupportedConflictEntry);
    }
    let source_physical_path = physical_path_for_logical(source_logical_path);
    let guard = VaultMutationGuard::acquire(vault.root()).map_err(map_atomic_error)?;
    ensure_no_journal(vault.root())?;
    if !detected_index_is_original(git, conflict, &source_physical_path)? {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        None,
        &[&source_physical_path, &conflict.physical_path],
    )?;
    verify_active_rename_provenance(git, provenance)?;
    verify_rename_provenance(
        git,
        provenance,
        &source_physical_path,
        &conflict.physical_path,
        [
            conflict.stages[0]
                .as_ref()
                .ok_or(GitError::UnsupportedConflictEntry)?,
            conflict.stages[renamed_side.stage_index()]
                .as_ref()
                .ok_or(GitError::UnsupportedConflictEntry)?,
            conflict.stages[match renamed_side {
                RenameSide::Ours => RenameSide::Theirs.stage_index(),
                RenameSide::Theirs => RenameSide::Ours.stage_index(),
            }]
            .as_ref()
            .ok_or(GitError::UnsupportedConflictEntry)?,
        ],
        renamed_side,
    )?;

    let source_target = vault
        .root()
        .join(source_logical_path.to_ciphertext_relative_path());
    let destination_target = vault
        .root()
        .join(conflict.logical_path.to_ciphertext_relative_path());
    if guard.inspect(&source_target).map_err(map_atomic_error)? != CurrentTarget::Absent {
        return Err(GitError::WorktreeChanged);
    }
    sync_directory(
        source_target
            .parent()
            .ok_or(GitError::DurabilityNotConfirmed)?,
    )
    .map_err(|_| GitError::DurabilityNotConfirmed)?;
    let expected_destination_digest =
        expected_worktree_digest(prepared).ok_or(GitError::UnsupportedConflictEntry)?;
    if guard
        .inspect(&destination_target)
        .map_err(map_atomic_error)?
        != CurrentTarget::File(expected_destination_digest)
    {
        return Err(GitError::WorktreeChanged);
    }
    let result_digest = digest(&prepared.encrypted.bytes);
    let journal = DetectedRenameJournal {
        version: 3,
        source_physical_path: source_physical_path.clone(),
        destination_physical_path: conflict.physical_path.clone(),
        result_mode: result_mode(conflict)?.to_owned(),
        stages: conflict.stages.clone(),
        renamed_side,
        provenance: provenance.clone(),
        file_id: prepared.file_id.clone(),
        expected_destination_worktree_sha256: hex_digest(expected_destination_digest),
        result_oid: prepared.result_oid.clone(),
        result_sha256: hex_digest(result_digest),
    };
    let transaction = MergeJournalPayload::DetectedRename(journal.clone());
    let mut prepared_index = prepare_index_cas(git, &transaction)?;
    if !detected_index_is_original(git, conflict, &source_physical_path)? {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        None,
        &[&source_physical_path, &conflict.physical_path],
    )?;
    verify_active_rename_provenance(git, provenance)?;
    git.verify_attributes_for_paths(&[&source_physical_path, &conflict.physical_path])?;
    let pending = write_cas_journal(vault.root(), &mut prepared_index, transaction)?;

    let outcome = guard
        .write(
            &destination_target,
            &prepared.encrypted.bytes,
            WriteCondition::IfMatch(expected_destination_digest),
        )
        .map_err(map_atomic_error)?;
    if outcome.parent_sync != ParentSyncStatus::Synced {
        return Err(GitError::DurabilityNotConfirmed);
    }
    if guard.inspect(&source_target).map_err(map_atomic_error)? != CurrentTarget::Absent {
        return Err(GitError::WorktreeChanged);
    }
    sync_directory(
        source_target
            .parent()
            .ok_or(GitError::DurabilityNotConfirmed)?,
    )
    .map_err(|_| GitError::DurabilityNotConfirmed)?;
    if !detected_index_is_original(git, conflict, &source_physical_path)? {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        None,
        &[&source_physical_path, &conflict.physical_path],
    )?;
    verify_active_rename_provenance(git, provenance)?;
    git.update_index(
        &conflict.physical_path,
        &journal.result_mode,
        &journal.result_oid,
    )?;
    verify_detected_rename_committed_state(
        vault,
        git,
        &guard,
        &source_target,
        &destination_target,
        &journal,
        result_digest,
    )?;
    remove_journal(vault.root(), &pending)
}

fn detected_index_is_original(
    git: &Git,
    conflict: &ConflictEntry,
    source_physical_path: &str,
) -> Result<bool, GitError> {
    let unmerged = git.unmerged_entries()?;
    if unmerged.get(&conflict.physical_path) != Some(conflict)
        || unmerged.contains_key(source_physical_path)
        || git.stage_zero(&conflict.physical_path)?.is_some()
    {
        return Ok(false);
    }
    Ok(git.stage_zero(source_physical_path)?.is_none())
}

fn detected_index_is_final(git: &Git, journal: &DetectedRenameJournal) -> Result<bool, GitError> {
    let unmerged = git.unmerged_entries()?;
    if unmerged.contains_key(&journal.source_physical_path)
        || unmerged.contains_key(&journal.destination_physical_path)
        || git.stage_zero(&journal.source_physical_path)?.is_some()
    {
        return Ok(false);
    }
    Ok(git
        .stage_zero(&journal.destination_physical_path)?
        .is_some_and(|entry| entry.mode == journal.result_mode && entry.oid == journal.result_oid))
}

#[allow(clippy::too_many_lines)] // Keep the ordered crash transaction visible in one state machine.
fn commit_split_rename_result(
    vault: &Vault,
    git: &Git,
    source: &ConflictEntry,
    destination: &TrackedIdentity,
    renamed_side: RenameSide,
    provenance: &RenameProvenance,
    prepared: &PreparedRenameResult,
) -> Result<(), GitError> {
    let guard = VaultMutationGuard::acquire(vault.root()).map_err(map_atomic_error)?;
    ensure_no_journal(vault.root())?;
    if !split_index_is_original(git, source, destination)? {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        Some(&destination.physical_path),
        &[&source.physical_path, &destination.physical_path],
    )?;
    verify_active_rename_provenance(git, provenance)?;
    verify_rename_provenance(
        git,
        provenance,
        &source.physical_path,
        &destination.physical_path,
        [
            source.stages[0]
                .as_ref()
                .ok_or(GitError::UnsupportedConflictEntry)?,
            &destination.entry,
            source.stages[match renamed_side {
                RenameSide::Ours => RenameSide::Theirs.stage_index(),
                RenameSide::Theirs => RenameSide::Ours.stage_index(),
            }]
            .as_ref()
            .ok_or(GitError::UnsupportedConflictEntry)?,
        ],
        renamed_side,
    )?;

    let source_target = vault
        .root()
        .join(source.logical_path.to_ciphertext_relative_path());
    let destination_target = vault
        .root()
        .join(destination.logical_path.to_ciphertext_relative_path());
    let expected_source_digest = prepared.source_stage_ciphertexts[1]
        .as_ref()
        .or(prepared.source_stage_ciphertexts[2].as_ref())
        .map(|bytes| digest(bytes));
    let source_state = guard.inspect(&source_target).map_err(map_atomic_error)?;
    let expected_source_worktree_sha256 = match source_state {
        CurrentTarget::File(actual) if Some(actual) == expected_source_digest => {
            Some(hex_digest(actual))
        }
        CurrentTarget::Absent if renamed_side == RenameSide::Ours => None,
        CurrentTarget::Absent | CurrentTarget::File(_) | CurrentTarget::Other => {
            return Err(GitError::WorktreeChanged);
        }
    };
    let expected_destination_digest = digest(&prepared.destination_ciphertext);
    if guard
        .inspect(&destination_target)
        .map_err(map_atomic_error)?
        != CurrentTarget::File(expected_destination_digest)
    {
        return Err(GitError::WorktreeChanged);
    }

    let result_digest = digest(&prepared.encrypted.bytes);
    let journal = RenameMergeJournal {
        version: 2,
        source_physical_path: source.physical_path.clone(),
        destination_physical_path: destination.physical_path.clone(),
        result_mode: destination.entry.mode.clone(),
        source_stages: source.stages.clone(),
        destination_stage: destination.entry.clone(),
        renamed_side,
        provenance: provenance.clone(),
        file_id: prepared.file_id.clone(),
        expected_source_worktree_sha256,
        expected_destination_worktree_sha256: hex_digest(expected_destination_digest),
        result_oid: prepared.result_oid.clone(),
        result_sha256: hex_digest(result_digest),
    };
    let transaction = MergeJournalPayload::Rename(journal.clone());
    let mut prepared_index = prepare_index_cas(git, &transaction)?;
    if !split_index_is_original(git, source, destination)? {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        Some(&destination.physical_path),
        &[&source.physical_path, &destination.physical_path],
    )?;
    verify_active_rename_provenance(git, provenance)?;
    git.verify_attributes_for_paths(&[&source.physical_path, &destination.physical_path])?;
    let pending = write_cas_journal(vault.root(), &mut prepared_index, transaction)?;

    let destination_outcome = guard
        .write(
            &destination_target,
            &prepared.encrypted.bytes,
            WriteCondition::IfMatch(expected_destination_digest),
        )
        .map_err(map_atomic_error)?;
    if destination_outcome.parent_sync != ParentSyncStatus::Synced {
        return Err(GitError::DurabilityNotConfirmed);
    }
    match source_state {
        CurrentTarget::File(expected) => {
            let outcome = guard
                .delete(&source_target, WriteCondition::IfMatch(expected))
                .map_err(map_atomic_error)?;
            if outcome.parent_sync != ParentSyncStatus::Synced {
                return Err(GitError::DurabilityNotConfirmed);
            }
        }
        CurrentTarget::Absent => {
            let parent = source_target.parent().ok_or(GitError::RecoveryConflict)?;
            sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)?;
        }
        CurrentTarget::Other => return Err(GitError::WorktreeChanged),
    }

    if !split_index_is_original(git, source, destination)? {
        return Err(GitError::IndexChanged);
    }
    verify_merge_identity_owners(
        vault,
        git,
        &guard,
        &prepared.file_id,
        Some(&destination.physical_path),
        &[&source.physical_path, &destination.physical_path],
    )?;
    verify_active_rename_provenance(git, provenance)?;
    git.update_index_rename(
        &source.physical_path,
        &destination.physical_path,
        &journal.result_mode,
        &journal.result_oid,
    )?;
    verify_split_rename_committed_state(
        vault,
        git,
        &guard,
        &source_target,
        &destination_target,
        &journal,
        result_digest,
    )?;
    remove_journal(vault.root(), &pending)
}

fn split_index_is_original(
    git: &Git,
    source: &ConflictEntry,
    destination: &TrackedIdentity,
) -> Result<bool, GitError> {
    let unmerged = git.unmerged_entries()?;
    if unmerged.get(&source.physical_path) != Some(source)
        || unmerged.contains_key(&destination.physical_path)
        || git.stage_zero(&source.physical_path)?.is_some()
    {
        return Ok(false);
    }
    Ok(git.stage_zero(&destination.physical_path)?.as_ref() == Some(&destination.entry))
}

fn recover_payload_pending(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    payload: &MergeJournalPayload,
) -> Result<(), GitError> {
    match payload {
        MergeJournalPayload::InPlace(journal) => {
            recover_in_place_pending(vault, git, guard, journal)
        }
        MergeJournalPayload::Rename(journal) => {
            recover_split_rename_pending(vault, git, guard, journal)
        }
        MergeJournalPayload::DetectedRename(journal) => {
            recover_detected_rename_pending(vault, git, guard, journal)
        }
    }
}

fn payload_index_result_is_present(
    git: &Git,
    payload: &MergeJournalPayload,
) -> Result<bool, GitError> {
    match payload {
        MergeJournalPayload::InPlace(journal) => {
            if git.unmerged_entries()?.contains_key(&journal.physical_path) {
                return Ok(false);
            }
            Ok(git
                .stage_zero(&journal.physical_path)?
                .is_some_and(|entry| {
                    entry.mode == journal.result_mode && entry.oid == journal.result_oid
                }))
        }
        MergeJournalPayload::Rename(journal) => split_index_is_final(git, journal),
        MergeJournalPayload::DetectedRename(journal) => detected_index_is_final(git, journal),
    }
}

fn recover_cas_pending(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    journal: &CasMergeJournal,
) -> Result<(), GitError> {
    validate_cas_journal(journal)?;
    if journal.object_format != git.object_format {
        return Err(GitError::InvalidJournal);
    }
    git.ensure_full_index()?;
    let live = read_index_snapshot(&index_path(&git.root))?;
    let candidate_path = index_candidate_path(&git.root, &journal.candidate_file);
    let lock_path = index_lock_path(&git.root);
    let candidate = optional_index_snapshot(&candidate_path)?;
    let lock_state = classify_cas_index_lock(&git.root, journal)?;
    let lock_has_marker = lock_state == CasIndexLockState::Marker;
    let lock_has_candidate = lock_state == CasIndexLockState::Candidate;
    let candidate_is_final = candidate.as_ref().is_some_and(|candidate| {
        snapshot_matches(
            candidate,
            journal.candidate_index_size,
            &journal.candidate_index_sha256,
        )
    });
    let live_is_old = snapshot_matches(
        &live,
        journal.expected_index_size,
        &journal.expected_index_sha256,
    );
    let live_is_final = snapshot_matches(
        &live,
        journal.candidate_index_size,
        &journal.candidate_index_sha256,
    );

    if live_is_old {
        let candidate_index_path = if lock_has_marker && candidate_is_final {
            candidate_path.clone()
        } else if lock_has_candidate && candidate.is_none() {
            lock_path.clone()
        } else {
            return Err(GitError::RecoveryConflict);
        };
        let before = index_entry_map(git)?;
        let candidate_git = git.with_index_file(candidate_index_path)?;
        verify_candidate_index(&candidate_git, &journal.transaction, &before)?;
        return recover_payload_pending(vault, git, guard, &journal.transaction);
    }

    if live_is_final {
        if candidate.is_some() || lock_has_marker || lock_has_candidate {
            return Err(GitError::RecoveryConflict);
        }
        return recover_payload_pending(vault, git, guard, &journal.transaction);
    }

    if candidate.is_none()
        && !lock_has_marker
        && !lock_has_candidate
        && payload_index_result_is_present(git, &journal.transaction)?
    {
        return recover_payload_pending(vault, git, guard, &journal.transaction);
    }
    Err(GitError::RecoveryConflict)
}

fn recover_pending(vault: &Vault, git: &Git) -> Result<bool, GitError> {
    let guard = VaultMutationGuard::acquire(vault.root()).map_err(map_atomic_error)?;
    let reserved_names = exact_reserved_private_names(vault.root())?;
    let Some(pending) = read_journal(vault.root())? else {
        if read_prelock_reservation(vault.root())?.is_none() {
            match inspect_orphan_prelock_staging(vault.root(), &reserved_names)? {
                OrphanPrelockStaging::Exact { reservation, path } => {
                    recover_orphan_prelock_staging(git.object_format, &reservation, &path)?;
                    return Ok(true);
                }
                OrphanPrelockStaging::Conflict => return Err(GitError::RecoveryConflict),
                OrphanPrelockStaging::None => {}
            }
        }
        let recovered = recover_abandoned_cas_reservation(vault.root(), git.object_format)?;
        if !recovered && !reserved_names.is_empty() {
            return Err(GitError::RecoveryConflict);
        }
        return Ok(recovered);
    };
    let prelock = read_prelock_reservation(vault.root())?;
    if prelock.is_none()
        && reserved_names.iter().any(|name| {
            name.starts_with(PRELOCK_RESERVATION_STAGING_PREFIX)
                || name.starts_with(CANDIDATE_INITIAL_RECEIPT_PREFIX)
                || name.starts_with(CANDIDATE_FINAL_RECEIPT_PREFIX)
        })
    {
        return Err(GitError::RecoveryConflict);
    }
    match &pending {
        PendingMergeJournal::InPlace(journal) => {
            if prelock.is_some() {
                return Err(GitError::RecoveryConflict);
            }
            recover_in_place_pending(vault, git, &guard, journal)?;
        }
        PendingMergeJournal::Rename(journal) => {
            if prelock.is_some() {
                return Err(GitError::RecoveryConflict);
            }
            recover_split_rename_pending(vault, git, &guard, journal)?;
        }
        PendingMergeJournal::DetectedRename(journal) => {
            if prelock.is_some() {
                return Err(GitError::RecoveryConflict);
            }
            recover_detected_rename_pending(vault, git, &guard, journal)?;
        }
        PendingMergeJournal::Cas(journal) => {
            if let Some(reservation) = &prelock {
                remove_prelock_after_stable_journal(vault.root(), reservation, journal)?;
            }
            recover_cas_pending(vault, git, &guard, journal)?;
        }
        PendingMergeJournal::BundleV5(_) => return Err(GitError::RecoveryConflict),
    }
    remove_journal(vault.root(), &pending)?;
    Ok(true)
}

#[allow(clippy::too_many_lines)] // Authentication and forward recovery share one audit sequence.
fn recover_in_place_pending(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    journal: &MergeJournal,
) -> Result<(), GitError> {
    validate_journal(journal)?;
    git.validate_oid(&journal.result_oid)
        .map_err(|_| GitError::InvalidJournal)?;
    for stage in journal.stages.iter().flatten() {
        git.validate_oid(&stage.oid)
            .map_err(|_| GitError::InvalidJournal)?;
    }
    let logical_path = validate_physical_path(&journal.physical_path)?;
    let result = git.read_object(&journal.result_oid)?;
    let result_digest = digest(&result);
    if hex_digest(result_digest) != journal.result_sha256 {
        return Err(GitError::RecoveryConflict);
    }
    let result_document = vault
        .authenticate_committed_envelope(&logical_path, &result)
        .map_err(|_| GitError::RecoveryConflict)?;
    let file_id = result_document.header.file_id.to_string();
    let identity_stage = journal.stages[1]
        .as_ref()
        .or(journal.stages[2].as_ref())
        .or(journal.stages[0].as_ref())
        .ok_or(GitError::RecoveryConflict)?;
    let identity_ciphertext = git.read_object(&identity_stage.oid)?;
    let identity_document = vault
        .authenticate_committed_envelope(&logical_path, &identity_ciphertext)
        .map_err(|_| GitError::RecoveryConflict)?;
    if identity_document.header.file_id.to_string() != file_id {
        return Err(GitError::RecoveryConflict);
    }
    let expected_stage = journal.stages[1]
        .as_ref()
        .or(journal.stages[2].as_ref())
        .ok_or(GitError::RecoveryConflict)?;
    let expected_ciphertext = git.read_object(&expected_stage.oid)?;
    if hex_digest(digest(&expected_ciphertext)) != journal.expected_worktree_sha256 {
        return Err(GitError::RecoveryConflict);
    }

    let target = vault
        .root()
        .join(logical_path.to_ciphertext_relative_path());
    let unmerged = git.unmerged_entries()?;
    let current_conflict = unmerged.get(&journal.physical_path);
    let stage_zero = git.stage_zero(&journal.physical_path)?;
    if current_conflict.is_some() && stage_zero.is_some() {
        return Err(GitError::RecoveryConflict);
    }
    let index_done = stage_zero
        .as_ref()
        .is_some_and(|entry| entry.mode == journal.result_mode && entry.oid == journal.result_oid)
        && current_conflict.is_none();
    if !index_done {
        let expected = ConflictEntry {
            physical_path: journal.physical_path.clone(),
            logical_path: logical_path.clone(),
            stages: journal.stages.clone(),
        };
        if current_conflict != Some(&expected) {
            return Err(GitError::RecoveryConflict);
        }
    }
    verify_merge_identity_owners(
        vault,
        git,
        guard,
        &file_id,
        index_done.then_some(journal.physical_path.as_str()),
        &[&journal.physical_path],
    )
    .map_err(|_| GitError::RecoveryConflict)?;

    let current_target = guard.inspect(&target).map_err(map_atomic_error)?;
    let worktree_done =
        matches!(current_target, CurrentTarget::File(actual) if actual == result_digest);
    if !worktree_done {
        let condition = match current_target {
            CurrentTarget::File(actual)
                if parse_hex_digest(&journal.expected_worktree_sha256)? == actual =>
            {
                WriteCondition::IfMatch(actual)
            }
            _ => return Err(GitError::RecoveryConflict),
        };
        let outcome = guard
            .write(&target, &result, condition)
            .map_err(map_atomic_error)?;
        if outcome.parent_sync != ParentSyncStatus::Synced {
            return Err(GitError::DurabilityNotConfirmed);
        }
    }
    if !index_done {
        if git
            .unmerged_entries()?
            .get(&journal.physical_path)
            .map(|entry| &entry.stages)
            != Some(&journal.stages)
        {
            return Err(GitError::RecoveryConflict);
        }
        verify_merge_identity_owners(vault, git, guard, &file_id, None, &[&journal.physical_path])
            .map_err(|_| GitError::RecoveryConflict)?;
        git.update_index(
            &journal.physical_path,
            &journal.result_mode,
            &journal.result_oid,
        )?;
    }
    verify_merge_identity_owners(
        vault,
        git,
        guard,
        &file_id,
        Some(&journal.physical_path),
        &[&journal.physical_path],
    )
    .map_err(|_| GitError::RecoveryConflict)?;
    verify_committed_state(git, guard, &target, journal, result_digest)?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Recovery order is security-critical and intentionally linear.
fn recover_detected_rename_pending(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    journal: &DetectedRenameJournal,
) -> Result<(), GitError> {
    let authenticated = authenticate_detected_rename_recovery(vault, git, journal)?;
    let index_original =
        detected_index_is_original(git, &authenticated.conflict, &journal.source_physical_path)?;
    let index_final = detected_index_is_final(git, journal)?;
    if index_original == index_final {
        return Err(GitError::RecoveryConflict);
    }
    if index_original {
        verify_active_rename_provenance(git, &journal.provenance)
            .map_err(|_| GitError::RecoveryConflict)?;
    }
    verify_merge_identity_owners(
        vault,
        git,
        guard,
        &authenticated.file_id,
        index_final.then_some(journal.destination_physical_path.as_str()),
        &[
            &journal.source_physical_path,
            &journal.destination_physical_path,
        ],
    )
    .map_err(|_| GitError::RecoveryConflict)?;

    let source_target = vault.root().join(
        authenticated
            .source_logical_path
            .to_ciphertext_relative_path(),
    );
    let destination_target = vault.root().join(
        authenticated
            .conflict
            .logical_path
            .to_ciphertext_relative_path(),
    );
    if guard.inspect(&source_target).map_err(map_atomic_error)? != CurrentTarget::Absent {
        return Err(GitError::RecoveryConflict);
    }
    sync_directory(source_target.parent().ok_or(GitError::RecoveryConflict)?)
        .map_err(|_| GitError::DurabilityNotConfirmed)?;
    let destination_state = guard
        .inspect(&destination_target)
        .map_err(map_atomic_error)?;
    if index_final {
        if destination_state != CurrentTarget::File(authenticated.result_digest) {
            return Err(GitError::RecoveryConflict);
        }
        return verify_detected_rename_committed_state(
            vault,
            git,
            guard,
            &source_target,
            &destination_target,
            journal,
            authenticated.result_digest,
        );
    }

    match destination_state {
        CurrentTarget::File(actual) if actual == authenticated.expected_destination_digest => {
            let outcome = guard
                .write(
                    &destination_target,
                    &authenticated.result,
                    WriteCondition::IfMatch(authenticated.expected_destination_digest),
                )
                .map_err(map_atomic_error)?;
            if outcome.parent_sync != ParentSyncStatus::Synced {
                return Err(GitError::DurabilityNotConfirmed);
            }
        }
        CurrentTarget::File(actual) if actual == authenticated.result_digest => {
            sync_directory(
                destination_target
                    .parent()
                    .ok_or(GitError::RecoveryConflict)?,
            )
            .map_err(|_| GitError::DurabilityNotConfirmed)?;
        }
        CurrentTarget::Absent | CurrentTarget::File(_) | CurrentTarget::Other => {
            return Err(GitError::RecoveryConflict);
        }
    }
    if guard.inspect(&source_target).map_err(map_atomic_error)? != CurrentTarget::Absent {
        return Err(GitError::RecoveryConflict);
    }
    sync_directory(source_target.parent().ok_or(GitError::RecoveryConflict)?)
        .map_err(|_| GitError::DurabilityNotConfirmed)?;
    if !detected_index_is_original(git, &authenticated.conflict, &journal.source_physical_path)? {
        if detected_index_is_final(git, journal)? {
            return verify_detected_rename_committed_state(
                vault,
                git,
                guard,
                &source_target,
                &destination_target,
                journal,
                authenticated.result_digest,
            );
        }
        return Err(GitError::RecoveryConflict);
    }
    verify_merge_identity_owners(
        vault,
        git,
        guard,
        &authenticated.file_id,
        None,
        &[
            &journal.source_physical_path,
            &journal.destination_physical_path,
        ],
    )
    .map_err(|_| GitError::RecoveryConflict)?;
    git.update_index(
        &journal.destination_physical_path,
        &journal.result_mode,
        &journal.result_oid,
    )?;
    verify_detected_rename_committed_state(
        vault,
        git,
        guard,
        &source_target,
        &destination_target,
        journal,
        authenticated.result_digest,
    )
}

fn authenticate_detected_rename_recovery(
    vault: &Vault,
    git: &Git,
    journal: &DetectedRenameJournal,
) -> Result<AuthenticatedDetectedRenameRecovery, GitError> {
    validate_detected_rename_journal(journal)?;
    git.validate_oid(&journal.result_oid)
        .map_err(|_| GitError::InvalidJournal)?;
    for stage in journal.stages.iter().flatten() {
        git.validate_oid(&stage.oid)
            .map_err(|_| GitError::InvalidJournal)?;
    }
    validate_rename_provenance(git, &journal.provenance).map_err(|_| GitError::InvalidJournal)?;
    let source_logical_path = validate_physical_path(&journal.source_physical_path)?;
    let destination_logical_path = validate_physical_path(&journal.destination_physical_path)?;
    let mut identities: [Option<AuthenticatedStageIdentity>; 3] = std::array::from_fn(|_| None);
    for (index, stage) in journal.stages.iter().enumerate() {
        identities[index] = Some(authenticate_stage_identity(
            vault,
            git,
            stage.as_ref().ok_or(GitError::RecoveryConflict)?,
        )?);
    }
    let ancestor = identities[0].as_ref().ok_or(GitError::RecoveryConflict)?;
    let renamed = identities[journal.renamed_side.stage_index()]
        .as_ref()
        .ok_or(GitError::RecoveryConflict)?;
    let other_index = match journal.renamed_side {
        RenameSide::Ours => RenameSide::Theirs.stage_index(),
        RenameSide::Theirs => RenameSide::Ours.stage_index(),
    };
    let other = identities[other_index]
        .as_ref()
        .ok_or(GitError::RecoveryConflict)?;
    if ancestor.logical_path != source_logical_path
        || other.logical_path != source_logical_path
        || renamed.logical_path != destination_logical_path
        || ancestor.file_id != renamed.file_id
        || ancestor.file_id != other.file_id
        || journal.file_id != ancestor.file_id
    {
        return Err(GitError::RecoveryConflict);
    }
    verify_rename_provenance(
        git,
        &journal.provenance,
        &journal.source_physical_path,
        &journal.destination_physical_path,
        [
            journal.stages[0]
                .as_ref()
                .ok_or(GitError::RecoveryConflict)?,
            journal.stages[journal.renamed_side.stage_index()]
                .as_ref()
                .ok_or(GitError::RecoveryConflict)?,
            journal.stages[other_index]
                .as_ref()
                .ok_or(GitError::RecoveryConflict)?,
        ],
        journal.renamed_side,
    )
    .map_err(|_| GitError::RecoveryConflict)?;

    let result = git.read_object(&journal.result_oid)?;
    let result_digest = digest(&result);
    if hex_digest(result_digest) != journal.result_sha256 {
        return Err(GitError::RecoveryConflict);
    }
    let result_document = vault
        .authenticate_committed_envelope(&destination_logical_path, &result)
        .map_err(|_| GitError::RecoveryConflict)?;
    if result_document.header.file_id.to_string() != ancestor.file_id {
        return Err(GitError::RecoveryConflict);
    }
    let expected_ciphertext = git.read_object(
        &journal.stages[1]
            .as_ref()
            .or(journal.stages[2].as_ref())
            .ok_or(GitError::RecoveryConflict)?
            .oid,
    )?;
    let expected_destination_digest =
        parse_hex_digest(&journal.expected_destination_worktree_sha256)
            .map_err(|_| GitError::RecoveryConflict)?;
    if digest(&expected_ciphertext) != expected_destination_digest {
        return Err(GitError::RecoveryConflict);
    }
    Ok(AuthenticatedDetectedRenameRecovery {
        conflict: ConflictEntry {
            physical_path: journal.destination_physical_path.clone(),
            logical_path: destination_logical_path,
            stages: journal.stages.clone(),
        },
        source_logical_path,
        result,
        result_digest,
        expected_destination_digest,
        file_id: ancestor.file_id.clone(),
    })
}

#[allow(clippy::too_many_lines)] // Recovery order is security-critical and intentionally linear.
fn recover_split_rename_pending(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    journal: &RenameMergeJournal,
) -> Result<(), GitError> {
    let authenticated = authenticate_rename_recovery(vault, git, journal)?;
    let index_original =
        split_index_is_original(git, &authenticated.source, &authenticated.destination)?;
    let index_final = split_index_is_final(git, journal)?;
    if index_original == index_final {
        return Err(GitError::RecoveryConflict);
    }
    if index_original {
        verify_active_rename_provenance(git, &journal.provenance)
            .map_err(|_| GitError::RecoveryConflict)?;
    }
    verify_merge_identity_owners(
        vault,
        git,
        guard,
        &authenticated.file_id,
        Some(&journal.destination_physical_path),
        &[
            &journal.source_physical_path,
            &journal.destination_physical_path,
        ],
    )
    .map_err(|_| GitError::RecoveryConflict)?;

    let source_target = vault.root().join(
        authenticated
            .source
            .logical_path
            .to_ciphertext_relative_path(),
    );
    let destination_target = vault.root().join(
        authenticated
            .destination
            .logical_path
            .to_ciphertext_relative_path(),
    );
    let source_state = guard.inspect(&source_target).map_err(map_atomic_error)?;
    let destination_state = guard
        .inspect(&destination_target)
        .map_err(map_atomic_error)?;
    if index_final {
        if source_state != CurrentTarget::Absent
            || destination_state != CurrentTarget::File(authenticated.result_digest)
        {
            return Err(GitError::RecoveryConflict);
        }
        return verify_split_rename_committed_state(
            vault,
            git,
            guard,
            &source_target,
            &destination_target,
            journal,
            authenticated.result_digest,
        );
    }

    advance_split_rename_worktree(
        guard,
        &source_target,
        &destination_target,
        source_state,
        destination_state,
        &authenticated,
    )?;

    if !split_index_is_original(git, &authenticated.source, &authenticated.destination)? {
        if split_index_is_final(git, journal)? {
            return verify_split_rename_committed_state(
                vault,
                git,
                guard,
                &source_target,
                &destination_target,
                journal,
                authenticated.result_digest,
            );
        }
        return Err(GitError::RecoveryConflict);
    }
    verify_merge_identity_owners(
        vault,
        git,
        guard,
        &authenticated.file_id,
        Some(&journal.destination_physical_path),
        &[
            &journal.source_physical_path,
            &journal.destination_physical_path,
        ],
    )
    .map_err(|_| GitError::RecoveryConflict)?;
    git.update_index_rename(
        &journal.source_physical_path,
        &journal.destination_physical_path,
        &journal.result_mode,
        &journal.result_oid,
    )?;
    verify_split_rename_committed_state(
        vault,
        git,
        guard,
        &source_target,
        &destination_target,
        journal,
        authenticated.result_digest,
    )
}

fn authenticate_rename_recovery(
    vault: &Vault,
    git: &Git,
    journal: &RenameMergeJournal,
) -> Result<AuthenticatedRenameRecovery, GitError> {
    validate_rename_journal(journal)?;
    git.validate_oid(&journal.result_oid)
        .map_err(|_| GitError::InvalidJournal)?;
    git.validate_oid(&journal.destination_stage.oid)
        .map_err(|_| GitError::InvalidJournal)?;
    for stage in journal.source_stages.iter().flatten() {
        git.validate_oid(&stage.oid)
            .map_err(|_| GitError::InvalidJournal)?;
    }
    validate_rename_provenance(git, &journal.provenance).map_err(|_| GitError::InvalidJournal)?;
    let source_logical = validate_physical_path(&journal.source_physical_path)?;
    let destination_logical = validate_physical_path(&journal.destination_physical_path)?;
    let result = git.read_object(&journal.result_oid)?;
    let result_digest = digest(&result);
    if hex_digest(result_digest) != journal.result_sha256 {
        return Err(GitError::RecoveryConflict);
    }
    let result_document = vault
        .authenticate_committed_envelope(&destination_logical, &result)
        .map_err(|_| GitError::RecoveryConflict)?;

    let mut source_ciphertexts: [Option<Vec<u8>>; 3] = [None, None, None];
    let mut expected_file_id = None;
    for (index, stage) in journal.source_stages.iter().enumerate() {
        if let Some(stage) = stage {
            let ciphertext = git.read_object(&stage.oid)?;
            let document = vault
                .authenticate_committed_envelope(&source_logical, &ciphertext)
                .map_err(|_| GitError::RecoveryConflict)?;
            let file_id = document.header.file_id.to_string();
            if expected_file_id
                .as_ref()
                .is_some_and(|expected| expected != &file_id)
            {
                return Err(GitError::RecoveryConflict);
            }
            expected_file_id.get_or_insert(file_id);
            source_ciphertexts[index] = Some(ciphertext);
        }
    }
    let destination_ciphertext = git.read_object(&journal.destination_stage.oid)?;
    let destination_document = vault
        .authenticate_committed_envelope(&destination_logical, &destination_ciphertext)
        .map_err(|_| GitError::RecoveryConflict)?;
    let expected_file_id = expected_file_id.ok_or(GitError::RecoveryConflict)?;
    if destination_document.header.file_id.to_string() != expected_file_id
        || result_document.header.file_id.to_string() != expected_file_id
        || journal.file_id != expected_file_id
    {
        return Err(GitError::RecoveryConflict);
    }
    verify_rename_provenance(
        git,
        &journal.provenance,
        &journal.source_physical_path,
        &journal.destination_physical_path,
        [
            journal.source_stages[0]
                .as_ref()
                .ok_or(GitError::RecoveryConflict)?,
            &journal.destination_stage,
            journal.source_stages[match journal.renamed_side {
                RenameSide::Ours => RenameSide::Theirs.stage_index(),
                RenameSide::Theirs => RenameSide::Ours.stage_index(),
            }]
            .as_ref()
            .ok_or(GitError::RecoveryConflict)?,
        ],
        journal.renamed_side,
    )
    .map_err(|_| GitError::RecoveryConflict)?;
    let expected_source_digest = source_ciphertexts[1]
        .as_ref()
        .or(source_ciphertexts[2].as_ref())
        .map(|bytes| digest(bytes))
        .ok_or(GitError::RecoveryConflict)?;
    let expected_source_state = expected_rename_source_state(journal, expected_source_digest)?;
    let expected_destination_digest =
        parse_hex_digest(&journal.expected_destination_worktree_sha256)
            .map_err(|_| GitError::RecoveryConflict)?;
    if digest(&destination_ciphertext) != expected_destination_digest {
        return Err(GitError::RecoveryConflict);
    }
    Ok(AuthenticatedRenameRecovery {
        source: ConflictEntry {
            physical_path: journal.source_physical_path.clone(),
            logical_path: source_logical,
            stages: journal.source_stages.clone(),
        },
        destination: TrackedIdentity {
            physical_path: journal.destination_physical_path.clone(),
            logical_path: destination_logical,
            entry: journal.destination_stage.clone(),
        },
        result,
        result_digest,
        expected_source_state,
        expected_destination_digest,
        file_id: expected_file_id,
    })
}

fn expected_rename_source_state(
    journal: &RenameMergeJournal,
    expected_source_digest: [u8; 32],
) -> Result<CurrentTarget, GitError> {
    match &journal.expected_source_worktree_sha256 {
        Some(encoded) => {
            let recorded = parse_hex_digest(encoded).map_err(|_| GitError::RecoveryConflict)?;
            if recorded != expected_source_digest {
                return Err(GitError::RecoveryConflict);
            }
            Ok(CurrentTarget::File(recorded))
        }
        None if journal.renamed_side == RenameSide::Ours => Ok(CurrentTarget::Absent),
        None => Err(GitError::RecoveryConflict),
    }
}

fn advance_split_rename_worktree(
    guard: &VaultMutationGuard,
    source_target: &Path,
    destination_target: &Path,
    source_state: CurrentTarget,
    destination_state: CurrentTarget,
    authenticated: &AuthenticatedRenameRecovery,
) -> Result<(), GitError> {
    match destination_state {
        CurrentTarget::File(actual) if actual == authenticated.expected_destination_digest => {
            if source_state != authenticated.expected_source_state {
                return Err(GitError::RecoveryConflict);
            }
            let outcome = guard
                .write(
                    destination_target,
                    &authenticated.result,
                    WriteCondition::IfMatch(authenticated.expected_destination_digest),
                )
                .map_err(map_atomic_error)?;
            if outcome.parent_sync != ParentSyncStatus::Synced {
                return Err(GitError::DurabilityNotConfirmed);
            }
        }
        CurrentTarget::File(actual) if actual == authenticated.result_digest => {
            let parent = destination_target
                .parent()
                .ok_or(GitError::RecoveryConflict)?;
            sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)?;
        }
        CurrentTarget::Absent | CurrentTarget::File(_) | CurrentTarget::Other => {
            return Err(GitError::RecoveryConflict);
        }
    }
    match guard.inspect(source_target).map_err(map_atomic_error)? {
        CurrentTarget::File(actual)
            if authenticated.expected_source_state == CurrentTarget::File(actual) =>
        {
            let outcome = guard
                .delete(source_target, WriteCondition::IfMatch(actual))
                .map_err(map_atomic_error)?;
            if outcome.parent_sync != ParentSyncStatus::Synced {
                return Err(GitError::DurabilityNotConfirmed);
            }
        }
        CurrentTarget::Absent => {
            let parent = source_target.parent().ok_or(GitError::RecoveryConflict)?;
            sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)?;
        }
        CurrentTarget::File(_) | CurrentTarget::Other => {
            return Err(GitError::RecoveryConflict);
        }
    }
    Ok(())
}

fn verify_committed_state(
    git: &Git,
    guard: &VaultMutationGuard,
    target: &Path,
    journal: &MergeJournal,
    result_digest: [u8; 32],
) -> Result<(), GitError> {
    if !matches!(
        guard.inspect(target).map_err(map_atomic_error)?,
        CurrentTarget::File(actual) if actual == result_digest
    ) {
        return Err(GitError::RecoveryConflict);
    }
    let parent = target.parent().ok_or(GitError::RecoveryConflict)?;
    sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)?;
    if git.unmerged_entries()?.contains_key(&journal.physical_path) {
        return Err(GitError::RecoveryConflict);
    }
    let Some(stage_zero) = git.stage_zero(&journal.physical_path)? else {
        return Err(GitError::RecoveryConflict);
    };
    if stage_zero.mode != journal.result_mode || stage_zero.oid != journal.result_oid {
        return Err(GitError::RecoveryConflict);
    }
    git.sync_object(&journal.result_oid)?;
    git.sync_index()?;
    Ok(())
}

fn verify_detected_rename_committed_state(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    source_target: &Path,
    destination_target: &Path,
    journal: &DetectedRenameJournal,
    result_digest: [u8; 32],
) -> Result<(), GitError> {
    if guard.inspect(source_target).map_err(map_atomic_error)? != CurrentTarget::Absent
        || guard
            .inspect(destination_target)
            .map_err(map_atomic_error)?
            != CurrentTarget::File(result_digest)
    {
        return Err(GitError::RecoveryConflict);
    }
    for target in [source_target, destination_target] {
        let parent = target.parent().ok_or(GitError::RecoveryConflict)?;
        sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)?;
    }
    if !detected_index_is_final(git, journal)? {
        return Err(GitError::RecoveryConflict);
    }
    verify_merge_identity_owners(
        vault,
        git,
        guard,
        &journal.file_id,
        Some(&journal.destination_physical_path),
        &[
            &journal.source_physical_path,
            &journal.destination_physical_path,
        ],
    )
    .map_err(|_| GitError::RecoveryConflict)?;
    git.sync_object(&journal.result_oid)?;
    git.sync_index()?;
    Ok(())
}

fn split_index_is_final(git: &Git, journal: &RenameMergeJournal) -> Result<bool, GitError> {
    let unmerged = git.unmerged_entries()?;
    if unmerged.contains_key(&journal.source_physical_path)
        || unmerged.contains_key(&journal.destination_physical_path)
    {
        return Ok(false);
    }
    if git.stage_zero(&journal.source_physical_path)?.is_some() {
        return Ok(false);
    }
    Ok(git
        .stage_zero(&journal.destination_physical_path)?
        .is_some_and(|entry| entry.mode == journal.result_mode && entry.oid == journal.result_oid))
}

fn verify_split_rename_committed_state(
    vault: &Vault,
    git: &Git,
    guard: &VaultMutationGuard,
    source_target: &Path,
    destination_target: &Path,
    journal: &RenameMergeJournal,
    result_digest: [u8; 32],
) -> Result<(), GitError> {
    if guard.inspect(source_target).map_err(map_atomic_error)? != CurrentTarget::Absent
        || guard
            .inspect(destination_target)
            .map_err(map_atomic_error)?
            != CurrentTarget::File(result_digest)
    {
        return Err(GitError::RecoveryConflict);
    }
    for target in [source_target, destination_target] {
        let parent = target.parent().ok_or(GitError::RecoveryConflict)?;
        sync_directory(parent).map_err(|_| GitError::DurabilityNotConfirmed)?;
    }
    if !split_index_is_final(git, journal)? {
        return Err(GitError::RecoveryConflict);
    }
    verify_merge_identity_owners(
        vault,
        git,
        guard,
        &journal.file_id,
        Some(&journal.destination_physical_path),
        &[
            &journal.source_physical_path,
            &journal.destination_physical_path,
        ],
    )
    .map_err(|_| GitError::RecoveryConflict)?;
    git.sync_object(&journal.result_oid)?;
    git.sync_index()?;
    Ok(())
}

fn validate_journal(journal: &MergeJournal) -> Result<(), GitError> {
    if journal.version != 1 {
        return Err(GitError::InvalidJournal);
    }
    validate_physical_path(&journal.physical_path).map_err(|_| GitError::InvalidJournal)?;
    validate_mode(&journal.result_mode).map_err(|_| GitError::InvalidJournal)?;
    validate_oid(&journal.result_oid).map_err(|_| GitError::InvalidJournal)?;
    let oid_width = journal.result_oid.len();
    parse_hex_digest(&journal.result_sha256).map_err(|_| GitError::InvalidJournal)?;
    parse_hex_digest(&journal.expected_worktree_sha256).map_err(|_| GitError::InvalidJournal)?;
    validate_conflict_modes(&journal.stages).map_err(|_| GitError::InvalidJournal)?;
    for stage in journal.stages.iter().flatten() {
        validate_mode(&stage.mode).map_err(|_| GitError::InvalidJournal)?;
        validate_oid(&stage.oid).map_err(|_| GitError::InvalidJournal)?;
        if stage.oid.len() != oid_width {
            return Err(GitError::InvalidJournal);
        }
    }
    Ok(())
}

fn validate_rename_journal(journal: &RenameMergeJournal) -> Result<(), GitError> {
    if journal.version != 2 {
        return Err(GitError::InvalidJournal);
    }
    let source = validate_physical_path(&journal.source_physical_path)
        .map_err(|_| GitError::InvalidJournal)?;
    let destination = validate_physical_path(&journal.destination_physical_path)
        .map_err(|_| GitError::InvalidJournal)?;
    if source == destination || source.case_fold_key() == destination.case_fold_key() {
        return Err(GitError::InvalidJournal);
    }
    validate_mode(&journal.result_mode).map_err(|_| GitError::InvalidJournal)?;
    validate_mode(&journal.destination_stage.mode).map_err(|_| GitError::InvalidJournal)?;
    validate_oid(&journal.destination_stage.oid).map_err(|_| GitError::InvalidJournal)?;
    validate_oid(&journal.result_oid).map_err(|_| GitError::InvalidJournal)?;
    let oid_width = journal.result_oid.len();
    if journal.destination_stage.oid.len() != oid_width
        || journal
            .source_stages
            .iter()
            .flatten()
            .any(|stage| stage.oid.len() != oid_width)
    {
        return Err(GitError::InvalidJournal);
    }
    parse_hex_digest(&journal.result_sha256).map_err(|_| GitError::InvalidJournal)?;
    parse_hex_digest(&journal.expected_destination_worktree_sha256)
        .map_err(|_| GitError::InvalidJournal)?;
    if let Some(expected) = &journal.expected_source_worktree_sha256 {
        parse_hex_digest(expected).map_err(|_| GitError::InvalidJournal)?;
    } else if journal.renamed_side != RenameSide::Ours {
        return Err(GitError::InvalidJournal);
    }
    validate_conflict_modes(&journal.source_stages).map_err(|_| GitError::InvalidJournal)?;
    if journal.source_stages[0].is_none()
        || journal.source_stages[journal.renamed_side.stage_index()].is_some()
        || journal.source_stages[match journal.renamed_side {
            RenameSide::Ours => RenameSide::Theirs.stage_index(),
            RenameSide::Theirs => RenameSide::Ours.stage_index(),
        }]
        .is_none()
    {
        return Err(GitError::InvalidJournal);
    }
    for stage in journal.source_stages.iter().flatten() {
        validate_mode(&stage.mode).map_err(|_| GitError::InvalidJournal)?;
        validate_oid(&stage.oid).map_err(|_| GitError::InvalidJournal)?;
        if stage.mode != journal.result_mode {
            return Err(GitError::InvalidJournal);
        }
    }
    if journal.destination_stage.mode != journal.result_mode {
        return Err(GitError::InvalidJournal);
    }
    Ok(())
}

fn validate_detected_rename_journal(journal: &DetectedRenameJournal) -> Result<(), GitError> {
    if journal.version != 3 {
        return Err(GitError::InvalidJournal);
    }
    let source = validate_physical_path(&journal.source_physical_path)
        .map_err(|_| GitError::InvalidJournal)?;
    let destination = validate_physical_path(&journal.destination_physical_path)
        .map_err(|_| GitError::InvalidJournal)?;
    if source == destination || source.case_fold_key() == destination.case_fold_key() {
        return Err(GitError::InvalidJournal);
    }
    validate_mode(&journal.result_mode).map_err(|_| GitError::InvalidJournal)?;
    validate_oid(&journal.result_oid).map_err(|_| GitError::InvalidJournal)?;
    let oid_width = journal.result_oid.len();
    parse_hex_digest(&journal.result_sha256).map_err(|_| GitError::InvalidJournal)?;
    parse_hex_digest(&journal.expected_destination_worktree_sha256)
        .map_err(|_| GitError::InvalidJournal)?;
    if journal.stages.iter().any(Option::is_none) {
        return Err(GitError::InvalidJournal);
    }
    for stage in journal.stages.iter().flatten() {
        validate_mode(&stage.mode).map_err(|_| GitError::InvalidJournal)?;
        validate_oid(&stage.oid).map_err(|_| GitError::InvalidJournal)?;
        if stage.mode != journal.result_mode || stage.oid.len() != oid_width {
            return Err(GitError::InvalidJournal);
        }
    }
    Ok(())
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(VAULT_LOCAL_DIRECTORY).join(JOURNAL_FILE)
}

fn journal_staging_path(root: &Path, journal: &PendingMergeJournal) -> PathBuf {
    let suffix = match journal {
        PendingMergeJournal::Cas(journal) => journal.lock_token.clone(),
        PendingMergeJournal::BundleV5(journal) => journal.reference.token.clone(),
        PendingMergeJournal::InPlace(_)
        | PendingMergeJournal::Rename(_)
        | PendingMergeJournal::DetectedRename(_) => Uuid::new_v4().simple().to_string(),
    };
    root.join(VAULT_LOCAL_DIRECTORY)
        .join(format!("{JOURNAL_STAGING_PREFIX}{suffix}"))
}

fn ensure_no_journal(root: &Path) -> Result<(), GitError> {
    match fs::symlink_metadata(journal_path(root)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(GitError::JournalAlreadyExists),
        Err(error) => Err(io_error(GitIoOperation::ReadJournal, &error)),
    }
}

fn write_journal(root: &Path, journal: &PendingMergeJournal) -> Result<(), GitError> {
    ensure_no_journal(root)?;
    let local = root.join(VAULT_LOCAL_DIRECTORY);
    let local_metadata = fs::symlink_metadata(&local)
        .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
    if is_link_or_reparse_point(&local_metadata) || !local_metadata.file_type().is_dir() {
        return Err(GitError::InvalidJournal);
    }
    let bytes = match journal {
        PendingMergeJournal::InPlace(journal) => {
            serde_json::to_vec(journal).map_err(|_| GitError::InvalidJournal)?
        }
        PendingMergeJournal::Rename(journal) => {
            serde_json::to_vec(journal).map_err(|_| GitError::InvalidJournal)?
        }
        PendingMergeJournal::DetectedRename(journal) => {
            serde_json::to_vec(journal).map_err(|_| GitError::InvalidJournal)?
        }
        PendingMergeJournal::Cas(journal) => {
            serde_json::to_vec(journal).map_err(|_| GitError::InvalidJournal)?
        }
        PendingMergeJournal::BundleV5(journal) => serialize_bundle_journal_v5(journal)?,
    };
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(GitError::InvalidJournal);
    }
    let path = journal_path(root);
    let staging_path = journal_staging_path(root, journal);
    let staging_file = create_private_file(&staging_path, &bytes)?;
    let move_result = atomic_move_verified_file_no_replace(&staging_path, &staging_file, &path);
    drop(staging_file);
    match move_result {
        Ok(outcome) => {
            require_file_move_durability(outcome)?;
            if read_regular_exact(&path, bytes.len())? != bytes {
                return Err(GitError::InvalidJournal);
            }
            Ok(())
        }
        Err(error) => {
            if matches!(read_regular_exact(&path, bytes.len()), Ok(actual) if actual == bytes) {
                return Err(GitError::DurabilityNotConfirmed);
            }
            let _ = remove_regular_file_if_exact(&staging_path, &bytes);
            if error.kind() == io::ErrorKind::AlreadyExists {
                Err(GitError::JournalAlreadyExists)
            } else {
                Err(io_error(GitIoOperation::WriteJournal, &error))
            }
        }
    }
}

struct DuplicateRejectingJson(serde_json::Value);

impl<'de> Deserialize<'de> for DuplicateRejectingJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingJsonVisitor)
    }
}

struct DuplicateRejectingJsonVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingJsonVisitor {
    type Value = DuplicateRejectingJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duplicate-free JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson(serde_json::Value::Number(
            value.into(),
        )))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson(serde_json::Value::Number(
            value.into(),
        )))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(|number| DuplicateRejectingJson(serde_json::Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateRejectingJson(serde_json::Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateRejectingJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DuplicateRejectingJson>()? {
            values.push(value.0);
        }
        Ok(DuplicateRejectingJson(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value::<DuplicateRejectingJson>()?;
            values.insert(key, value.0);
        }
        Ok(DuplicateRejectingJson(serde_json::Value::Object(values)))
    }
}

fn parse_duplicate_free_json(bytes: &[u8]) -> Result<serde_json::Value, GitError> {
    serde_json::from_slice::<DuplicateRejectingJson>(bytes)
        .map(|value| value.0)
        .map_err(|_| GitError::InvalidJournal)
}

fn read_journal(root: &Path) -> Result<Option<PendingMergeJournal>, GitError> {
    let path = journal_path(root);
    match fs::symlink_metadata(&path) {
        Ok(_) => read_journal_file(&path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(GitIoOperation::ReadJournal, &error)),
    }
}

fn read_journal_file(path: &Path) -> Result<PendingMergeJournal, GitError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(MAX_JOURNAL_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    let file = File::open(path).map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?;
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?
    {
        return Err(GitError::InvalidJournal);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_JOURNAL_BYTES)
            .min(MAX_JOURNAL_BYTES),
    );
    (&file)
        .take(
            u64::try_from(MAX_JOURNAL_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(GitIoOperation::ReadJournal, &error))?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(GitError::InvalidJournal);
    }
    let value = parse_duplicate_free_json(&bytes)?;
    let version = value
        .as_object()
        .and_then(|object| object.get("version"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or(GitError::InvalidJournal)?;
    let journal = match version {
        1 => {
            let journal = serde_json::from_value::<MergeJournal>(value)
                .map_err(|_| GitError::InvalidJournal)?;
            validate_journal(&journal)?;
            PendingMergeJournal::InPlace(journal)
        }
        2 => {
            let journal = serde_json::from_value::<RenameMergeJournal>(value)
                .map_err(|_| GitError::InvalidJournal)?;
            validate_rename_journal(&journal)?;
            PendingMergeJournal::Rename(journal)
        }
        3 => {
            let journal = serde_json::from_value::<DetectedRenameJournal>(value)
                .map_err(|_| GitError::InvalidJournal)?;
            validate_detected_rename_journal(&journal)?;
            PendingMergeJournal::DetectedRename(journal)
        }
        4 => {
            let journal = serde_json::from_value::<CasMergeJournal>(value)
                .map_err(|_| GitError::InvalidJournal)?;
            validate_cas_journal(&journal)?;
            PendingMergeJournal::Cas(journal)
        }
        5 => {
            let journal = serde_json::from_value::<BundleMergeJournalV5>(value)
                .map_err(|_| GitError::InvalidJournal)?;
            validate_bundle_journal_v5(&journal)?;
            if serialize_bundle_journal_v5(&journal)? != bytes {
                return Err(GitError::InvalidJournal);
            }
            PendingMergeJournal::BundleV5(journal)
        }
        _ => return Err(GitError::InvalidJournal),
    };
    Ok(journal)
}

fn remove_journal(root: &Path, expected: &PendingMergeJournal) -> Result<(), GitError> {
    if read_journal(root)?.as_ref() != Some(expected) {
        return Err(GitError::RecoveryConflict);
    }
    if let PendingMergeJournal::Cas(journal) = expected {
        if optional_index_snapshot(&index_candidate_path(root, &journal.candidate_file))?.is_some()
        {
            return Err(GitError::RecoveryConflict);
        }
        if matches!(
            classify_cas_index_lock(root, journal)?,
            CasIndexLockState::Marker | CasIndexLockState::Candidate
        ) {
            return Err(GitError::RecoveryConflict);
        }
    }
    if matches!(expected, PendingMergeJournal::BundleV5(_)) {
        return Err(GitError::RecoveryConflict);
    }
    let path = journal_path(root);
    fs::remove_file(path).map_err(|error| io_error(GitIoOperation::RemoveJournal, &error))?;
    sync_directory(&root.join(VAULT_LOCAL_DIRECTORY))
        .map_err(|error| io_error(GitIoOperation::RemoveJournal, &error))
}

fn one_text_line(output: &[u8]) -> Result<&str, GitError> {
    let output = if let Some(without) = output.strip_suffix(b"\r\n") {
        without
    } else if let Some(without) = output.strip_suffix(b"\n") {
        without
    } else {
        return Err(GitError::MalformedGitOutput);
    };
    if output.is_empty()
        || output.contains(&b'\n')
        || output.contains(&b'\r')
        || output.contains(&0)
    {
        return Err(GitError::MalformedGitOutput);
    }
    std::str::from_utf8(output).map_err(|_| GitError::MalformedGitOutput)
}

fn validate_git_version(output: &[u8]) -> Result<(), GitError> {
    let line = one_text_line(output)?;
    let version = line
        .strip_prefix("git version ")
        .ok_or(GitError::MalformedGitOutput)?;
    let mut components = version.split('.');
    let major = components
        .next()
        .ok_or(GitError::MalformedGitOutput)?
        .parse::<u32>()
        .map_err(|_| GitError::MalformedGitOutput)?;
    let minor = components
        .next()
        .ok_or(GitError::MalformedGitOutput)?
        .parse::<u32>()
        .map_err(|_| GitError::MalformedGitOutput)?;
    if (major, minor) >= MINIMUM_GIT_VERSION {
        Ok(())
    } else {
        Err(GitError::UnsupportedGitVersion)
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_hex_digest(value: &str) -> Result<[u8; 32], GitError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GitError::InvalidJournal);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(GitError::InvalidJournal)?;
        let low = hex_nibble(pair[1]).ok_or(GitError::InvalidJournal)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn map_atomic_error(_error: inex_core::atomic::AtomicWriteError) -> GitError {
    GitError::Io {
        operation: GitIoOperation::InspectMetadata,
        kind: io::ErrorKind::Other,
    }
}

fn io_error(operation: GitIoOperation, error: &io::Error) -> GitError {
    GitError::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(unix)]
fn restrict_file_permissions_best_effort(file: &File) {
    use std::os::unix::fs::PermissionsExt;

    let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file_permissions_best_effort(_file: &File) {}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::process::Command as TestCommand;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use inex_core::sodium::Argon2idParams;
    use inex_core::vault_config::KdfPolicy;

    use super::*;

    const PASSWORD: &[u8] = b"recovery test password";
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "inex-git-recovery-test-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("test directory creation succeeds");
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

    fn test_policy() -> KdfPolicy {
        KdfPolicy {
            min_creation_ops_limit: 1,
            min_creation_mem_limit_bytes: 8 * 1024,
            max_creation_ops_limit: 4,
            max_creation_mem_limit_bytes: 64 * 1024 * 1024,
            max_unlock_ops_limit: 4,
            max_unlock_mem_limit_bytes: 64 * 1024 * 1024,
        }
    }

    fn test_git<const N: usize>(root: &Path, arguments: [&str; N]) -> bool {
        TestCommand::new("git")
            .current_dir(root)
            .args(arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("Git test command starts")
            .success()
    }

    fn save_test_document(root: &Path, plaintext: &[u8], modified_at_ms: i64) {
        let logical = LogicalPath::parse_canonical("entry.md").expect("test path is valid");
        let mut vault =
            Vault::unlock(root, PASSWORD, None, KdfPolicy::default()).expect("test vault unlocks");
        let current = vault.read(&logical).expect("test document reads");
        let etag = current.etag.clone();
        drop(current);
        vault
            .save_document(&logical, plaintext, &etag, modified_at_ms)
            .expect("test document saves");
    }

    fn initialize_test_repository(root: &Path) {
        initialize_test_repository_with_format(root, GitObjectFormat::Sha1);
    }

    fn initialize_test_repository_with_format(root: &Path, object_format: GitObjectFormat) {
        match object_format {
            GitObjectFormat::Sha1 => assert!(test_git(root, ["init", "-q"])),
            GitObjectFormat::Sha256 => {
                assert!(test_git(root, ["init", "-q", "--object-format=sha256"]));
            }
        }
        assert!(test_git(
            root,
            ["symbolic-ref", "HEAD", "refs/heads/baseline"]
        ));
        assert!(test_git(
            root,
            ["config", "user.email", "inex-tests@example.invalid"]
        ));
        assert!(test_git(root, ["config", "user.name", "Inex Tests"]));
    }

    fn create_conflicted_repository() -> (TestDirectory, Vault) {
        create_conflicted_repository_with_format(GitObjectFormat::Sha1)
    }

    fn create_conflicted_repository_with_format(
        object_format: GitObjectFormat,
    ) -> (TestDirectory, Vault) {
        let directory = TestDirectory::new();
        initialize_test_repository_with_format(directory.path(), object_format);
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
        .expect("test vault creates");
        let logical = LogicalPath::parse_canonical("entry.md").expect("test path is valid");
        vault
            .create_document(&logical, b"base\n", 1_783_699_201_000)
            .expect("base document creates");
        drop(vault);
        fs::write(
            directory.path().join(GIT_ATTRIBUTES_FILE),
            format!("{ATTRIBUTES_RULE}\n"),
        )
        .expect("attributes write succeeds");
        assert!(test_git(directory.path(), ["add", "--all"]));
        assert!(test_git(
            directory.path(),
            ["commit", "-q", "-m", "baseline"]
        ));
        assert!(test_git(directory.path(), ["checkout", "-q", "-b", "ours"]));
        save_test_document(directory.path(), b"ours\n", 1_783_699_202_000);
        assert!(test_git(directory.path(), ["add", "entry.md.enc"]));
        assert!(test_git(directory.path(), ["commit", "-q", "-m", "ours"]));
        assert!(test_git(directory.path(), ["checkout", "-q", "baseline"]));
        assert!(test_git(
            directory.path(),
            ["checkout", "-q", "-b", "theirs"]
        ));
        save_test_document(directory.path(), b"theirs\n", 1_783_699_203_000);
        assert!(test_git(directory.path(), ["add", "entry.md.enc"]));
        assert!(test_git(directory.path(), ["commit", "-q", "-m", "theirs"]));
        assert!(test_git(directory.path(), ["checkout", "-q", "ours"]));
        assert!(test_git(
            directory.path(),
            [
                "config",
                "--local",
                "merge.inex.driver",
                "git config --get inex.driver.must.fail"
            ]
        ));
        assert!(!test_git(
            directory.path(),
            ["merge", "--no-edit", "theirs"]
        ));
        let vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
            .expect("conflicted vault unlocks");
        (directory, vault)
    }

    fn create_rename_modify_repository(
        detect_renames: bool,
    ) -> (TestDirectory, Vault, LogicalPath, LogicalPath, String) {
        create_rename_modify_repository_with_format(detect_renames, GitObjectFormat::Sha1)
    }

    fn create_rename_modify_repository_with_format(
        detect_renames: bool,
        object_format: GitObjectFormat,
    ) -> (TestDirectory, Vault, LogicalPath, LogicalPath, String) {
        let directory = TestDirectory::new();
        initialize_test_repository_with_format(directory.path(), object_format);
        let source = LogicalPath::parse_canonical("entry.md").expect("source path is valid");
        let destination =
            LogicalPath::parse_canonical("renamed file.md").expect("destination path is valid");
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
        .expect("rename test vault creates");
        let created = vault
            .create_document(&source, b"first\nbase\nlast\n", 1_783_699_201_000)
            .expect("rename base document creates");
        let file_id = created.header.file_id.to_string();
        drop(vault);
        fs::write(
            directory.path().join(GIT_ATTRIBUTES_FILE),
            format!("{ATTRIBUTES_RULE}\n"),
        )
        .expect("attributes write succeeds");
        assert!(test_git(directory.path(), ["add", "--all"]));
        assert!(test_git(
            directory.path(),
            ["commit", "-q", "-m", "baseline"]
        ));

        assert!(test_git(directory.path(), ["checkout", "-q", "-b", "ours"]));
        let mut vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
            .expect("ours rename vault unlocks");
        let current = vault.read(&source).expect("rename source reads");
        vault
            .rename_document(&source, &destination, &current.etag, 1_783_699_202_000)
            .expect("ours rename succeeds");
        drop(current);
        drop(vault);
        assert!(test_git(directory.path(), ["add", "--all"]));
        assert!(test_git(
            directory.path(),
            ["commit", "-q", "-m", "ours rename"]
        ));

        assert!(test_git(directory.path(), ["checkout", "-q", "baseline"]));
        assert!(test_git(
            directory.path(),
            ["checkout", "-q", "-b", "theirs"]
        ));
        save_test_document(
            directory.path(),
            b"first\nbase\ntheirs changed\n",
            1_783_699_203_000,
        );
        assert!(test_git(directory.path(), ["add", "entry.md.enc"]));
        assert!(test_git(
            directory.path(),
            ["commit", "-q", "-m", "theirs modify"]
        ));
        assert!(test_git(directory.path(), ["checkout", "-q", "ours"]));
        assert!(test_git(
            directory.path(),
            [
                "config",
                "--local",
                "merge.inex.driver",
                "git config --get inex.driver.must.fail"
            ]
        ));
        let mut command = TestCommand::new("git");
        command
            .current_dir(directory.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if detect_renames {
            command.args(["merge", "--no-edit", "theirs"]);
        } else {
            command.args([
                "merge",
                "-s",
                "recursive",
                "-Xno-renames",
                "--no-edit",
                "theirs",
            ]);
        }
        assert!(!command.status().expect("rename merge starts").success());
        if detect_renames {
            force_detected_rename_conflict(directory.path(), &source, &destination);
        }
        let vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
            .expect("rename conflict vault unlocks");
        (directory, vault, source, destination, file_id)
    }

    fn force_detected_rename_conflict(
        root: &Path,
        source: &LogicalPath,
        destination: &LogicalPath,
    ) {
        // EDRY's fresh nonce normally defeats similarity detection. Normalize
        // the real no-rename result into the exact unmerged index shape Git
        // emits when its rename detector does match: stages 1/2/3 all live at
        // D, while the authenticated ancestor/other-side envelopes remain
        // bound to S.
        let git = Git::open(root).expect("Git fixture opens");
        let source_physical = physical_path_for_logical(source);
        let destination_physical = physical_path_for_logical(destination);
        let conflicts = git.unmerged_entries().expect("source conflict enumerates");
        let source_conflict = conflicts
            .get(&source_physical)
            .expect("source conflict exists");
        let destination_stage = git
            .stage_zero(&destination_physical)
            .expect("destination stage inspects")
            .expect("destination stage exists");
        let ancestor = source_conflict.stages[0]
            .as_ref()
            .expect("source ancestor exists");
        let theirs = source_conflict.stages[2]
            .as_ref()
            .expect("source other side exists");
        let zero_oid = "0".repeat(destination_stage.oid.len());
        let mut input = Vec::new();
        for path in [&source_physical, &destination_physical] {
            input.extend_from_slice(b"0 ");
            input.extend_from_slice(zero_oid.as_bytes());
            input.push(b'\t');
            input.extend_from_slice(path.as_bytes());
            input.push(0);
        }
        for (stage, entry) in [(1_u8, ancestor), (2, &destination_stage), (3, theirs)] {
            input.extend_from_slice(entry.mode.as_bytes());
            input.push(b' ');
            input.extend_from_slice(entry.oid.as_bytes());
            input.push(b' ');
            input.extend_from_slice(stage.to_string().as_bytes());
            input.push(b'\t');
            input.extend_from_slice(destination_physical.as_bytes());
            input.push(0);
        }
        git.run(
            GitOperation::UpdateIndex,
            ["update-index", "-z", "--index-info"],
            Some(&input),
            1024,
        )
        .expect("detected rename index fixture installs");
        git.sync_index().expect("detected fixture index syncs");
        fs::remove_file(root.join(source.to_ciphertext_relative_path()))
            .expect("detected fixture source worktree is absent");
        sync_directory(root).expect("detected fixture worktree parent syncs");
    }

    struct RenameRecoveryFixture {
        _directory: TestDirectory,
        vault: Vault,
        git: Git,
        source: ConflictEntry,
        destination: TrackedIdentity,
        destination_path: LogicalPath,
        prepared: PreparedRenameResult,
        source_target: PathBuf,
        destination_target: PathBuf,
        expected_source: [u8; 32],
        expected_destination: [u8; 32],
        result_digest: [u8; 32],
        journal: RenameMergeJournal,
    }

    impl RenameRecoveryFixture {
        fn write_journal(&self) {
            write_journal(
                self.vault.root(),
                &PendingMergeJournal::Rename(self.journal.clone()),
            )
            .expect("rename journal syncs");
        }

        fn write_result_to_destination(&self) {
            let guard = VaultMutationGuard::acquire(self.vault.root())
                .expect("destination write lock acquires");
            guard
                .write(
                    &self.destination_target,
                    &self.prepared.encrypted.bytes,
                    WriteCondition::IfMatch(self.expected_destination),
                )
                .expect("destination ciphertext commits");
        }

        fn delete_source(&self) {
            let guard = VaultMutationGuard::acquire(self.vault.root())
                .expect("source delete lock acquires");
            guard
                .delete(
                    &self.source_target,
                    WriteCondition::IfMatch(self.expected_source),
                )
                .expect("source ciphertext deletes");
        }

        fn update_index(&self) {
            self.git
                .update_index_rename(
                    &self.source.physical_path,
                    &self.destination.physical_path,
                    &self.journal.result_mode,
                    &self.journal.result_oid,
                )
                .expect("rename index commits");
        }

        fn ciphertext_for_third_owner(&self, logical_path: &LogicalPath) -> Vec<u8> {
            let destination = self
                .vault
                .authenticate_committed_envelope(
                    &self.destination.logical_path,
                    &self.prepared.destination_ciphertext,
                )
                .expect("destination identity authenticates");
            let mut identity = destination.header.clone();
            identity.logical_path = logical_path.as_str().to_owned();
            self.vault
                .encrypt_merge_result(
                    logical_path,
                    &identity,
                    b"third owner",
                    1_783_699_205_000,
                    false,
                )
                .expect("third owner encrypts")
                .bytes
        }

        fn assert_original_index(&self) {
            assert!(
                split_index_is_original(&self.git, &self.source, &self.destination)
                    .expect("original split index inspects")
            );
            assert!(
                !split_index_is_final(&self.git, &self.journal)
                    .expect("final split index inspects")
            );
        }

        fn assert_final_state(&self) {
            assert!(!self.source_target.exists());
            assert_eq!(
                VaultMutationGuard::acquire(self.vault.root())
                    .expect("final-state lock acquires")
                    .inspect(&self.destination_target)
                    .expect("final destination inspects"),
                CurrentTarget::File(self.result_digest)
            );
            assert_eq!(
                fs::read(&self.destination_target).expect("final destination reads"),
                self.prepared.encrypted.bytes
            );
            assert!(
                split_index_is_final(&self.git, &self.journal).expect("final split index verifies")
            );
            let document = self
                .vault
                .read(&self.destination_path)
                .expect("recovered destination authenticates");
            assert_eq!(
                document.plaintext.as_slice(),
                b"first\nbase\ntheirs changed\n"
            );
        }
    }

    fn create_rename_recovery_fixture() -> RenameRecoveryFixture {
        let (directory, vault, source_path, destination_path, _) =
            create_rename_modify_repository(false);
        let git = Git::open(directory.path()).expect("Git repository opens");
        let conflicts = git.unmerged_entries().expect("split conflict enumerates");
        let source = conflicts
            .get(&physical_path_for_logical(&source_path))
            .expect("source conflict exists")
            .clone();
        let tracked = tracked_identity_index(&vault, &git).expect("identities inspect");
        let destination = tracked
            .values()
            .find(|tracked| tracked.logical_path == destination_path)
            .expect("destination identity exists")
            .clone();
        let prepared = prepare_split_rename_result(
            &vault,
            &git,
            &source,
            &destination,
            RenameSide::Ours,
            1_783_699_204_000,
        )
        .expect("split result prepares");
        let source_target = vault
            .root()
            .join(source.logical_path.to_ciphertext_relative_path());
        let destination_target = vault
            .root()
            .join(destination.logical_path.to_ciphertext_relative_path());
        let expected_source = digest(
            prepared.source_stage_ciphertexts[2]
                .as_ref()
                .expect("theirs source ciphertext exists"),
        );
        let expected_destination = digest(&prepared.destination_ciphertext);
        let result_digest = digest(&prepared.encrypted.bytes);
        let provenance = current_rename_provenance(&git).expect("merge provenance inspects");
        let journal = RenameMergeJournal {
            version: 2,
            source_physical_path: source.physical_path.clone(),
            destination_physical_path: destination.physical_path.clone(),
            result_mode: destination.entry.mode.clone(),
            source_stages: source.stages.clone(),
            destination_stage: destination.entry.clone(),
            renamed_side: RenameSide::Ours,
            provenance,
            file_id: prepared.file_id.clone(),
            expected_source_worktree_sha256: Some(hex_digest(expected_source)),
            expected_destination_worktree_sha256: hex_digest(expected_destination),
            result_oid: prepared.result_oid.clone(),
            result_sha256: hex_digest(result_digest),
        };
        RenameRecoveryFixture {
            _directory: directory,
            vault,
            git,
            source,
            destination,
            destination_path,
            prepared,
            source_target,
            destination_target,
            expected_source,
            expected_destination,
            result_digest,
            journal,
        }
    }

    struct CandidateBundlePreparationFixture {
        _directory: TestDirectory,
        vault: Vault,
        git: Git,
        transaction: MergeJournalPayload,
    }

    fn create_candidate_bundle_preparation_fixture(
        object_format: GitObjectFormat,
    ) -> CandidateBundlePreparationFixture {
        let (directory, vault) = create_conflicted_repository_with_format(object_format);
        let git = Git::open(directory.path()).expect("candidate bundle Git repository opens");
        let conflict = git
            .unmerged_entries()
            .expect("candidate bundle conflict enumerates")
            .into_values()
            .next()
            .expect("candidate bundle has one conflict");
        let identities =
            tracked_identity_index(&vault, &git).expect("candidate bundle identities inspect");
        let prepared = prepare_result(&vault, &git, &conflict, &identities, 1_783_699_204_000)
            .expect("candidate bundle merge result prepares");
        let expected = expected_worktree_digest(&prepared).expect("worktree stage exists");
        let result_digest = digest(&prepared.encrypted.bytes);
        let transaction = MergeJournalPayload::InPlace(MergeJournal {
            version: 1,
            physical_path: conflict.physical_path.clone(),
            result_mode: result_mode(&conflict)
                .expect("result mode exists")
                .to_owned(),
            stages: conflict.stages.clone(),
            expected_worktree_sha256: hex_digest(expected),
            result_oid: prepared.result_oid.clone(),
            result_sha256: hex_digest(result_digest),
        });
        CandidateBundlePreparationFixture {
            _directory: directory,
            vault,
            git,
            transaction,
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CandidateBundleTestAction {
        FailAt(candidate_bundle_v5::CandidateBundlePrepareCheckpointV5),
        PartialCandidate,
        CandidateLock,
        PartialManifest,
        CandidateTamper,
        ManifestTamper,
        SourceSwap,
        ParentSwap,
        StableCollision,
        StableCloneSwap,
        LiveIndexDrift,
    }

    #[derive(Debug)]
    enum CandidateBundleRelocation {
        Source { held: PathBuf, replacement: PathBuf },
        Parent { held: PathBuf, replacement: PathBuf },
        StableClone { held: PathBuf, replacement: PathBuf },
    }

    #[derive(Debug)]
    struct CandidateBundleTestHooks {
        tokens: VecDeque<String>,
        action: Option<CandidateBundleTestAction>,
        action_fired: bool,
        scratch_identity: Option<inex_core::atomic::FilesystemDirectoryIdentity>,
        relocation: Option<CandidateBundleRelocation>,
    }

    impl CandidateBundleTestHooks {
        fn new(action: Option<CandidateBundleTestAction>) -> Self {
            Self {
                tokens: VecDeque::new(),
                action,
                action_fired: false,
                scratch_identity: None,
                relocation: None,
            }
        }

        fn with_tokens(tokens: impl IntoIterator<Item = &'static str>) -> Self {
            Self {
                tokens: tokens.into_iter().map(str::to_owned).collect(),
                ..Self::new(None)
            }
        }

        fn restore_relocation(&mut self) {
            match self.relocation.take() {
                Some(CandidateBundleRelocation::Source { held, replacement }) => {
                    fs::remove_dir(&replacement).expect("source-swap replacement removes");
                    fs::rename(held, replacement).expect("source-swap scratch restores");
                }
                Some(CandidateBundleRelocation::Parent { held, replacement }) => {
                    fs::remove_dir(&replacement).expect("parent-swap replacement removes");
                    fs::rename(held, replacement).expect("parent-swap local directory restores");
                }
                Some(CandidateBundleRelocation::StableClone { held, replacement }) => {
                    fs::remove_file(
                        replacement.join(candidate_bundle_v5::CANDIDATE_BUNDLE_INDEX_V5),
                    )
                    .expect("stable-clone candidate removes");
                    fs::remove_file(
                        replacement.join(candidate_bundle_v5::CANDIDATE_BUNDLE_MANIFEST_V5),
                    )
                    .expect("stable-clone manifest removes");
                    fs::remove_dir(&replacement).expect("stable-clone directory removes");
                    fs::rename(held, replacement).expect("original stable directory restores");
                }
                None => {}
            }
        }
    }

    impl candidate_bundle_v5::CandidateBundlePrepareHooksV5 for CandidateBundleTestHooks {
        fn next_token(&mut self) -> String {
            self.tokens
                .pop_front()
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string())
        }

        #[allow(
            clippy::too_many_lines,
            reason = "keep the fault actions adjacent so every retained-state mutation is auditable"
        )]
        fn checkpoint(
            &mut self,
            checkpoint: candidate_bundle_v5::CandidateBundlePrepareCheckpointV5,
            context: &candidate_bundle_v5::CandidateBundlePrepareContextV5<'_>,
        ) -> Result<(), GitError> {
            if checkpoint == candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::ScratchCreated
                && self.scratch_identity.is_none()
            {
                self.scratch_identity = Some(
                    inex_core::atomic::filesystem_directory_identity(context.scratch_path)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?,
                );
            }
            let Some(action) = self.action else {
                return Ok(());
            };
            if self.action_fired {
                return Ok(());
            }
            let matches = match action {
                CandidateBundleTestAction::FailAt(expected) => checkpoint == expected,
                CandidateBundleTestAction::PartialCandidate => {
                    checkpoint
                        == candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::ScratchCreated
                }
                CandidateBundleTestAction::CandidateLock => {
                    checkpoint
                        == candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::CandidateCopied
                }
                CandidateBundleTestAction::PartialManifest => {
                    checkpoint
                        == candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::CandidateMutated
                }
                CandidateBundleTestAction::CandidateTamper
                | CandidateBundleTestAction::ManifestTamper
                | CandidateBundleTestAction::SourceSwap
                | CandidateBundleTestAction::ParentSwap => {
                    checkpoint
                        == candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::CriticalAudit
                }
                CandidateBundleTestAction::StableCollision
                | CandidateBundleTestAction::LiveIndexDrift => {
                    checkpoint
                        == candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::BeforePublish
                }
                CandidateBundleTestAction::StableCloneSwap => {
                    checkpoint
                        == candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::AfterPublish
                }
            };
            if !matches {
                return Ok(());
            }
            self.action_fired = true;
            match action {
                CandidateBundleTestAction::FailAt(_) => {
                    return Err(GitError::DurabilityNotConfirmed);
                }
                CandidateBundleTestAction::PartialCandidate => {
                    fs::write(context.candidate_path, b"partial candidate index")
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                }
                CandidateBundleTestAction::CandidateLock => {
                    fs::write(
                        appended_lock_path(context.candidate_path),
                        b"foreign candidate lock",
                    )
                    .map_err(|_| GitError::DurabilityNotConfirmed)?;
                }
                CandidateBundleTestAction::PartialManifest => {
                    fs::write(context.manifest_path, b"{\"version\":5")
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                }
                CandidateBundleTestAction::CandidateTamper => {
                    let mut bytes = fs::read(context.candidate_path)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    bytes[0] ^= 1;
                    fs::write(context.candidate_path, bytes)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                }
                CandidateBundleTestAction::ManifestTamper => {
                    let mut bytes = fs::read(context.manifest_path)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    bytes[0] ^= 1;
                    fs::write(context.manifest_path, bytes)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                }
                CandidateBundleTestAction::SourceSwap => {
                    let held = context
                        .root
                        .join(format!("held-v5-source-{}", Uuid::new_v4().simple()));
                    fs::rename(context.scratch_path, &held)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    fs::create_dir(context.scratch_path)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    self.relocation = Some(CandidateBundleRelocation::Source {
                        held,
                        replacement: context.scratch_path.to_path_buf(),
                    });
                }
                CandidateBundleTestAction::ParentSwap => {
                    let held = context
                        .root
                        .join(format!("held-v5-parent-{}", Uuid::new_v4().simple()));
                    fs::rename(context.local, &held)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    fs::create_dir(context.local).map_err(|_| GitError::DurabilityNotConfirmed)?;
                    self.relocation = Some(CandidateBundleRelocation::Parent {
                        held,
                        replacement: context.local.to_path_buf(),
                    });
                }
                CandidateBundleTestAction::StableCollision => {
                    fs::create_dir(context.stable_path)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    fs::write(context.stable_path.join("foreign"), b"foreign stable owner")
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                }
                CandidateBundleTestAction::StableCloneSwap => {
                    let clone = context
                        .root
                        .join(format!("foreign-v5-clone-{}", Uuid::new_v4().simple()));
                    let held = context
                        .root
                        .join(format!("held-v5-stable-{}", Uuid::new_v4().simple()));
                    fs::create_dir(&clone).map_err(|_| GitError::DurabilityNotConfirmed)?;
                    for member in [
                        candidate_bundle_v5::CANDIDATE_BUNDLE_INDEX_V5,
                        candidate_bundle_v5::CANDIDATE_BUNDLE_MANIFEST_V5,
                    ] {
                        fs::copy(context.stable_path.join(member), clone.join(member))
                            .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    }
                    fs::rename(context.stable_path, &held)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    fs::rename(&clone, context.stable_path)
                        .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    self.relocation = Some(CandidateBundleRelocation::StableClone {
                        held,
                        replacement: context.stable_path.to_path_buf(),
                    });
                }
                CandidateBundleTestAction::LiveIndexDrift => {
                    fs::write(
                        context.root.join("external-index-owner.bin"),
                        b"ciphertext-only external index owner",
                    )
                    .map_err(|_| GitError::DurabilityNotConfirmed)?;
                    if !test_git(context.root, ["add", "external-index-owner.bin"]) {
                        return Err(GitError::DurabilityNotConfirmed);
                    }
                }
            }
            Ok(())
        }
    }

    fn candidate_bundle_scratch_paths(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root.join(VAULT_LOCAL_DIRECTORY))
            .expect("candidate namespace enumerates")
            .map(|entry| entry.expect("candidate namespace entry reads"))
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                name.starts_with(candidate_bundle_v5::CANDIDATE_BUNDLE_SCRATCH_PREFIX_V5)
                    .then(|| entry.path())
            })
            .collect()
    }

    fn prepare_test_candidate_bundle(
        fixture: &CandidateBundlePreparationFixture,
        hooks: &mut CandidateBundleTestHooks,
    ) -> Result<candidate_bundle_v5::PreparedCandidateBundleV5, GitError> {
        let guard = VaultMutationGuard::acquire(fixture.vault.root())
            .expect("candidate bundle mutation guard acquires");
        candidate_bundle_v5::prepare_candidate_bundle_v5_with_hooks(
            &guard,
            &fixture.git,
            &fixture.transaction,
            hooks,
        )
    }

    fn bundle_journal_v5(
        prepared: &candidate_bundle_v5::PreparedCandidateBundleV5,
    ) -> BundleMergeJournalV5 {
        BundleMergeJournalV5 {
            version: 5,
            reference: prepared.transaction_reference.clone(),
            index_lock_marker: prepared.index_lock_marker_reference.clone(),
        }
    }

    struct DetectedRenameRecoveryFixture {
        _directory: TestDirectory,
        vault: Vault,
        git: Git,
        destination_path: LogicalPath,
        conflict: ConflictEntry,
        prepared: PreparedResult,
        source_target: PathBuf,
        destination_target: PathBuf,
        source_ciphertext: Vec<u8>,
        expected_destination: [u8; 32],
        result_digest: [u8; 32],
        journal: DetectedRenameJournal,
    }

    impl DetectedRenameRecoveryFixture {
        fn write_journal(&self) {
            write_journal(
                self.vault.root(),
                &PendingMergeJournal::DetectedRename(self.journal.clone()),
            )
            .expect("detected rename journal syncs");
        }

        fn write_result_to_destination(&self) {
            let guard = VaultMutationGuard::acquire(self.vault.root())
                .expect("detected destination lock acquires");
            guard
                .write(
                    &self.destination_target,
                    &self.prepared.encrypted.bytes,
                    WriteCondition::IfMatch(self.expected_destination),
                )
                .expect("detected destination commits");
        }

        fn update_index(&self) {
            self.git
                .update_index(
                    &self.conflict.physical_path,
                    &self.journal.result_mode,
                    &self.journal.result_oid,
                )
                .expect("detected rename index commits");
        }

        fn assert_original_index(&self) {
            assert!(
                detected_index_is_original(
                    &self.git,
                    &self.conflict,
                    &self.journal.source_physical_path,
                )
                .expect("detected original index inspects")
            );
            assert!(
                !detected_index_is_final(&self.git, &self.journal)
                    .expect("detected final index inspects")
            );
        }

        fn assert_final_state(&self) {
            assert!(!self.source_target.exists());
            assert_eq!(
                VaultMutationGuard::acquire(self.vault.root())
                    .expect("detected final lock acquires")
                    .inspect(&self.destination_target)
                    .expect("detected destination inspects"),
                CurrentTarget::File(self.result_digest)
            );
            assert!(
                detected_index_is_final(&self.git, &self.journal)
                    .expect("detected final index verifies")
            );
            let document = self
                .vault
                .read(&self.destination_path)
                .expect("detected destination authenticates");
            assert_eq!(
                document.plaintext.as_slice(),
                b"first\nbase\ntheirs changed\n"
            );
        }
    }

    fn create_detected_rename_recovery_fixture() -> DetectedRenameRecoveryFixture {
        let (directory, vault, source_path, destination_path, _) =
            create_rename_modify_repository(true);
        let git = Git::open(directory.path()).expect("Git repository opens");
        let conflicts = git
            .unmerged_entries()
            .expect("detected conflict enumerates");
        let tracked = tracked_identity_index(&vault, &git).expect("tracked identities inspect");
        let mut plans = preflight_conflict_identities(&vault, &git, &conflicts, &tracked)
            .expect("detected plan preflights");
        let MergePlan::DetectedRename {
            conflict,
            stage_paths,
            renamed_side,
            provenance,
        } = plans.pop().expect("one detected plan exists")
        else {
            panic!("expected detected rename plan");
        };
        assert!(plans.is_empty());
        let prepared = prepare_detected_rename_result(
            &vault,
            &git,
            &conflict,
            &stage_paths,
            renamed_side,
            1_783_699_204_000,
        )
        .expect("detected result prepares");
        let source_target = vault.root().join(source_path.to_ciphertext_relative_path());
        let destination_target = vault
            .root()
            .join(destination_path.to_ciphertext_relative_path());
        let source_ciphertext = prepared.stage_ciphertexts[match renamed_side {
            RenameSide::Ours => RenameSide::Theirs.stage_index(),
            RenameSide::Theirs => RenameSide::Ours.stage_index(),
        }]
        .as_ref()
        .expect("source-bound stage exists")
        .clone();
        let expected_destination =
            expected_worktree_digest(&prepared).expect("detected worktree stage exists");
        let result_digest = digest(&prepared.encrypted.bytes);
        let journal = DetectedRenameJournal {
            version: 3,
            source_physical_path: physical_path_for_logical(&source_path),
            destination_physical_path: conflict.physical_path.clone(),
            result_mode: result_mode(&conflict)
                .expect("result mode exists")
                .to_owned(),
            stages: conflict.stages.clone(),
            renamed_side,
            provenance,
            file_id: prepared.file_id.clone(),
            expected_destination_worktree_sha256: hex_digest(expected_destination),
            result_oid: prepared.result_oid.clone(),
            result_sha256: hex_digest(result_digest),
        };
        DetectedRenameRecoveryFixture {
            _directory: directory,
            vault,
            git,
            destination_path,
            conflict,
            prepared,
            source_target,
            destination_target,
            source_ciphertext,
            expected_destination,
            result_digest,
            journal,
        }
    }

    fn install_rename_cas_journal(fixture: &RenameRecoveryFixture) -> CasMergeJournal {
        let transaction = MergeJournalPayload::Rename(fixture.journal.clone());
        let mut prepared = prepare_index_cas(&fixture.git, &transaction)
            .expect("rename CAS candidate and index lock prepare");
        let pending = write_cas_journal(fixture.vault.root(), &mut prepared, transaction)
            .expect("rename CAS journal syncs");
        let PendingMergeJournal::Cas(journal) = pending else {
            panic!("expected CAS journal");
        };
        assert!(!prelock_reservation_path(fixture.vault.root()).exists());
        journal
    }

    fn test_prelock_reservation(fixture: &RenameRecoveryFixture) -> PreLockReservation {
        let old = read_index_snapshot(&index_path(fixture.vault.root()))
            .expect("old index snapshots for prelock fixture");
        let lock_token = Uuid::new_v4().simple().to_string();
        PreLockReservation {
            version: 4,
            object_format: fixture.git.object_format,
            candidate_file: format!("{INDEX_CANDIDATE_PREFIX}{lock_token}"),
            lock_token,
            expected_index_sha256: old.sha256,
            expected_index_size: old.size,
        }
    }

    fn install_test_prelock_reservation(fixture: &RenameRecoveryFixture) -> PreLockReservation {
        let reservation = test_prelock_reservation(fixture);
        install_prelock_reservation(fixture.vault.root(), &reservation)
            .expect("prelock fixture publishes durably");
        reservation
    }

    fn assert_no_cas_private_files(root: &Path) {
        assert!(!index_lock_path(root).exists());
        let local = root.join(VAULT_LOCAL_DIRECTORY);
        assert!(
            fs::read_dir(local)
                .expect("private directory enumerates")
                .all(|entry| {
                    let name = entry.expect("private entry reads").file_name();
                    let name = name.to_string_lossy();
                    !name.starts_with(INDEX_CANDIDATE_PREFIX)
                        && !name.starts_with(INDEX_MARKER_PREFIX)
                        && !name.starts_with(JOURNAL_STAGING_PREFIX)
                        && !name.starts_with(PRELOCK_RESERVATION_STAGING_PREFIX)
                        && !name.starts_with(CANDIDATE_INITIAL_RECEIPT_PREFIX)
                        && !name.starts_with(CANDIDATE_FINAL_RECEIPT_PREFIX)
                        && name != PRELOCK_RESERVATION_FILE
                })
        );
    }

    #[test]
    fn parses_unmerged_index_records_and_rejects_non_edry_paths() {
        let oid = "0123456789abcdef0123456789abcdef01234567";
        let bytes = format!(
            "100644 {oid} 1\tnotes/a.md.enc\0\
             100644 {oid} 2\tnotes/a.md.enc\0\
             100644 {oid} 3\tnotes/a.md.enc\0"
        );
        let parsed = parse_unmerged_entries(bytes.as_bytes()).expect("valid stages parse");
        let entry = parsed.get("notes/a.md.enc").expect("path exists");
        assert_eq!(entry.logical_path.as_str(), "notes/a.md");
        assert!(entry.stages.iter().all(Option::is_some));

        let plaintext = format!("100644 {oid} 2\tnotes/a.md\0");
        assert!(matches!(
            parse_unmerged_entries(plaintext.as_bytes()),
            Err(GitError::UnsupportedConflictEntry)
        ));

        let aliases = format!(
            "100644 {oid} 1\tA.md.enc\0\
             100644 {oid} 2\tA.md.enc\0\
             100644 {oid} 1\ta.md.enc\0\
             100644 {oid} 2\ta.md.enc\0"
        );
        let aliases = parse_unmerged_entries(aliases.as_bytes()).expect("records parse");
        assert!(matches!(
            validate_conflict_set(&aliases),
            Err(GitError::UnsupportedConflictEntry)
        ));

        let independent = format!(
            "100644 {oid} 2\tfirst.md.enc\0\
             100644 {oid} 3\tfirst.md.enc\0\
             100644 {oid} 2\tsecond.md.enc\0\
             100644 {oid} 3\tsecond.md.enc\0"
        );
        let independent =
            parse_unmerged_entries(independent.as_bytes()).expect("independent records parse");
        assert!(validate_conflict_set(&independent).is_ok());
    }

    #[test]
    fn driver_command_rejects_percent_in_canonical_executable_path() {
        for executable in [
            Path::new("/opt/inex/%A/inex"),
            Path::new("/opt/inex/100%/inex"),
        ] {
            assert!(matches!(
                driver_command_for_canonical_executable(executable),
                Err(GitError::DriverExecutableUnavailable)
            ));
        }

        assert_eq!(
            driver_command_for_canonical_executable(Path::new("/path with space/it's/inex"))
                .expect("safe driver path formats"),
            "'/path with space/it'\\''s/inex' merge-driver"
        );
    }

    #[test]
    fn repository_lines_are_idempotent_and_bounded() {
        assert_eq!(
            append_line_if_missing(b"# existing\n", ATTRIBUTES_RULE)
                .expect("append succeeds")
                .expect("line was missing"),
            b"# existing\n*.md.enc -text -diff merge=inex\n"
        );
        assert_eq!(
            shell_quote("/path with space/inex"),
            "'/path with space/inex'"
        );
        assert_eq!(shell_quote("/path/it's/inex"), "'/path/it'\\''s/inex'");
        assert!(
            append_line_if_missing(
                b"# existing\n*.md.enc -text -diff merge=inex\n",
                ATTRIBUTES_RULE
            )
            .expect("existing line succeeds")
            .is_none()
        );
        assert_eq!(
            append_line_if_missing(
                b"*.md.enc -text -diff merge=inex\n*.md.enc merge=other\n",
                ATTRIBUTES_RULE
            )
            .expect("precedence repair succeeds")
            .expect("managed line must be restored last"),
            b"*.md.enc -text -diff merge=inex\n*.md.enc merge=other\n*.md.enc -text -diff merge=inex\n"
        );
    }

    #[test]
    fn check_attr_batches_respect_conservative_encoded_command_budget() {
        let directory_component = "a".repeat(240);
        let physical_paths = (0..64)
            .map(|index| {
                format!(
                    "{directory_component}/{directory_component}/{directory_component}/{}-{index:04}.md.enc",
                    "b".repeat(230)
                )
            })
            .collect::<Vec<_>>();
        let paths = physical_paths
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let executable = Path::new("C:\\Program Files\\Git\\cmd\\git.exe");
        let mut start = 0;
        let mut batches = 0;
        while start < paths.len() {
            let end = next_attribute_batch_end(executable, &paths, start)
                .expect("long valid paths can be safely batched");
            let mut units = conservative_argument_units(executable.as_os_str());
            for argument in GIT_COMMAND_PREFIX_ARGUMENTS {
                units = units.saturating_add(conservative_argument_units(OsStr::new(argument)));
            }
            for argument in CHECK_ATTR_ARGUMENTS {
                units = units.saturating_add(conservative_argument_units(OsStr::new(argument)));
            }
            for path in &paths[start..end] {
                validate_physical_path(path).expect("generated path is portable");
                units = units.saturating_add(conservative_argument_units(OsStr::new(path)));
            }
            assert!(units <= MAX_CHECK_ATTR_COMMAND_UNITS);
            assert!(end - start < 256);
            start = end;
            batches += 1;
        }
        assert!(batches > 1);
    }

    #[test]
    fn journal_digest_codec_is_canonical() {
        let bytes = [0xab; 32];
        let encoded = hex_digest(bytes);
        assert_eq!(parse_hex_digest(&encoded).expect("digest parses"), bytes);
        assert!(parse_hex_digest(&encoded.to_uppercase()).is_err());
    }

    #[test]
    fn git_version_floor_freezes_fsmonitor_disable_semantics() {
        assert!(validate_git_version(b"git version 2.36.0\n").is_ok());
        assert!(validate_git_version(b"git version 2.43.0.windows.1\r\n").is_ok());
        assert!(validate_git_version(b"git version 3.0.0\n").is_ok());
        assert!(matches!(
            validate_git_version(b"git version 2.35.9\n"),
            Err(GitError::UnsupportedGitVersion)
        ));
        assert!(matches!(
            validate_git_version(b"git version unknown\n"),
            Err(GitError::MalformedGitOutput)
        ));
    }

    #[test]
    fn repository_object_format_rejects_sha256_prefixes_before_git_reads() {
        let directory = TestDirectory::new();
        assert!(test_git(
            directory.path(),
            ["init", "-q", "--object-format=sha256"]
        ));
        let git = Git::open(directory.path()).expect("SHA-256 Git repository opens");
        assert_eq!(git.object_format, GitObjectFormat::Sha256);
        let full_oid = git
            .write_object(b"repository-width regression fixture")
            .expect("SHA-256 object writes");
        assert_eq!(full_oid.len(), 64);
        let prefix = &full_oid[..40];
        assert!(test_git(directory.path(), ["cat-file", "blob", prefix]));
        assert!(matches!(
            git.read_object(prefix),
            Err(GitError::MalformedGitOutput)
        ));
    }

    #[test]
    fn diff3_conflicts_are_memory_values_and_never_files() {
        let merged =
            diffy::merge("base\n", "ours\n", "theirs\n").expect_err("overlapping edits conflict");
        assert!(merged.contains("<<<<<<< ours"));
        assert!(merged.contains("||||||| original"));
        assert!(merged.contains(">>>>>>> theirs"));
        assert!(should_flag_merge_result(true, false, b"resolved\n"));
        assert!(should_flag_merge_result(
            false,
            true,
            b"<<<<<<< ours\nbody\n>>>>>>> theirs\n"
        ));
        assert!(!should_flag_merge_result(
            false,
            false,
            b"<<<<<<< ordinary prose\n"
        ));
        assert!(!should_flag_merge_result(false, true, b"resolved\n"));
    }

    #[test]
    fn split_index_is_rejected_before_encrypted_merge_mutation() {
        let (directory, vault) = create_conflicted_repository();
        let target = vault.root().join("entry.md.enc");
        let worktree_before = fs::read(&target).expect("conflicted worktree reads");
        let has_shared_index = || {
            fs::read_dir(directory.path().join(".git"))
                .expect("Git directory reads")
                .any(|entry| {
                    entry
                        .expect("Git directory entry reads")
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with("sharedindex."))
                })
        };
        assert!(!has_shared_index());
        assert!(test_git(
            directory.path(),
            ["config", "core.splitIndex", "true"]
        ));
        assert!(matches!(
            Git::open(directory.path()),
            Err(GitError::SplitIndexUnsupported)
        ));
        assert!(!has_shared_index());

        assert!(test_git(
            directory.path(),
            ["config", "core.splitIndex", "false"]
        ));
        assert!(test_git(
            directory.path(),
            ["update-index", "--split-index"]
        ));
        assert!(has_shared_index());
        assert!(matches!(
            Git::open(directory.path()),
            Err(GitError::SplitIndexUnsupported)
        ));
        assert_eq!(
            fs::read(&target).expect("conflicted worktree re-reads"),
            worktree_before
        );
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
        assert_no_cas_private_files(vault.root());
    }

    #[cfg(unix)]
    #[test]
    fn repository_fsmonitor_hook_is_disabled_for_every_git_invocation() {
        use std::os::unix::fs::PermissionsExt as _;

        let (directory, _vault) = create_conflicted_repository();
        let hook = directory.path().join("fsmonitor-canary.sh");
        let marker = directory.path().join("fsmonitor-ran");
        let marker_text = marker
            .to_str()
            .expect("temporary marker path is UTF-8 for shell fixture");
        fs::write(
            &hook,
            format!("#!/bin/sh\n: > {}\nexit 1\n", shell_quote(marker_text)),
        )
        .expect("fsmonitor fixture writes");
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))
            .expect("fsmonitor fixture is executable");
        let hook_text = hook
            .to_str()
            .expect("temporary hook path is UTF-8 for Git fixture");
        assert!(test_git(
            directory.path(),
            ["config", "core.fsmonitor", hook_text]
        ));
        assert!(test_git(directory.path(), ["ls-files", "-s"]));
        assert!(marker.is_file());
        fs::remove_file(&marker).expect("marker reset succeeds");

        let git = Git::open(directory.path()).expect("safe Git wrapper opens");
        git.staged_entries()
            .expect("index inspection remains in-process");
        assert!(!marker.exists());
    }

    #[test]
    fn recovery_finishes_after_worktree_commit_before_index_update() {
        let (directory, vault) = create_conflicted_repository();
        let git = Git::open(directory.path()).expect("Git repository opens");
        let conflicts = git.unmerged_entries().expect("conflicts enumerate");
        let conflict = conflicts.values().next().expect("one conflict").clone();
        let identities = tracked_identity_index(&vault, &git).expect("identities inspect");
        let prepared = prepare_result(&vault, &git, &conflict, &identities, 1_783_699_204_000)
            .expect("result prepares");
        let guard = VaultMutationGuard::acquire(vault.root()).expect("vault lock acquires");
        let target = vault
            .root()
            .join(conflict.logical_path.to_ciphertext_relative_path());
        let expected = expected_worktree_digest(&prepared).expect("ours stage exists");
        assert!(matches!(
            guard.inspect(&target),
            Ok(CurrentTarget::File(actual)) if actual == expected
        ));
        let result_digest = digest(&prepared.encrypted.bytes);
        let journal = MergeJournal {
            version: 1,
            physical_path: conflict.physical_path.clone(),
            result_mode: result_mode(&conflict).expect("mode exists").to_owned(),
            stages: conflict.stages.clone(),
            expected_worktree_sha256: hex_digest(expected),
            result_oid: prepared.result_oid.clone(),
            result_sha256: hex_digest(result_digest),
        };
        write_journal(vault.root(), &PendingMergeJournal::InPlace(journal.clone()))
            .expect("journal syncs");
        guard
            .write(
                &target,
                &prepared.encrypted.bytes,
                WriteCondition::IfMatch(expected),
            )
            .expect("worktree ciphertext commits");
        drop(guard);

        assert!(journal_path(vault.root()).is_file());
        assert!(
            git.unmerged_entries()
                .expect("stages remain")
                .contains_key(&conflict.physical_path)
        );
        assert!(recover_pending(&vault, &git).expect("recovery succeeds"));
        assert!(!journal_path(vault.root()).exists());
        assert!(git.unmerged_entries().expect("stages inspect").is_empty());
        let stage_zero = git
            .stage_zero(&conflict.physical_path)
            .expect("stage zero inspects")
            .expect("stage zero exists");
        assert_eq!(stage_zero.oid, prepared.result_oid);
        assert!(matches!(
            VaultMutationGuard::acquire(vault.root())
                .expect("post-recovery lock acquires")
                .inspect(&target),
            Ok(CurrentTarget::File(actual)) if actual == result_digest
        ));
    }

    #[test]
    fn in_place_merge_uses_index_cas_and_cleans_private_transaction_files() {
        let (directory, vault) = create_conflicted_repository();
        let git = Git::open(directory.path()).expect("Git repository opens");

        let report = merge(&vault, 1_783_699_204_000).expect("in-place conflict encrypts");
        assert_eq!(report.clean_results, 0);
        assert_eq!(report.unresolved_results, 1);
        assert!(git.unmerged_entries().expect("index verifies").is_empty());
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
        assert_no_cas_private_files(vault.root());
    }

    #[test]
    fn in_place_v4_recovery_advances_from_durable_marker() {
        let (directory, vault) = create_conflicted_repository();
        let git = Git::open(directory.path()).expect("Git repository opens");
        let conflict = git
            .unmerged_entries()
            .expect("conflicts enumerate")
            .into_values()
            .next()
            .expect("one conflict exists");
        let identities = tracked_identity_index(&vault, &git).expect("identities inspect");
        let prepared = prepare_result(&vault, &git, &conflict, &identities, 1_783_699_204_000)
            .expect("in-place result prepares");
        let expected = expected_worktree_digest(&prepared).expect("worktree stage exists");
        let result_digest = digest(&prepared.encrypted.bytes);
        let inner = MergeJournal {
            version: 1,
            physical_path: conflict.physical_path.clone(),
            result_mode: result_mode(&conflict).expect("mode exists").to_owned(),
            stages: conflict.stages.clone(),
            expected_worktree_sha256: hex_digest(expected),
            result_oid: prepared.result_oid.clone(),
            result_sha256: hex_digest(result_digest),
        };
        let transaction = MergeJournalPayload::InPlace(inner);
        let mut index_cas = prepare_index_cas(&git, &transaction).expect("in-place CAS prepares");
        write_cas_journal(vault.root(), &mut index_cas, transaction)
            .expect("in-place v4 journal writes");

        assert!(recover_pending(&vault, &git).expect("in-place v4 recovery succeeds"));
        assert!(git.unmerged_entries().expect("index verifies").is_empty());
        assert_eq!(
            VaultMutationGuard::acquire(vault.root())
                .expect("worktree guard acquires")
                .inspect(&vault.root().join("entry.md.enc"))
                .expect("result inspects"),
            CurrentTarget::File(result_digest)
        );
        assert_no_cas_private_files(vault.root());
    }

    #[test]
    fn sha256_in_place_merge_uses_full_width_cas_journal_binding() {
        let (directory, vault) = create_conflicted_repository_with_format(GitObjectFormat::Sha256);
        let git = Git::open(directory.path()).expect("SHA-256 repository opens");
        assert_eq!(git.object_format, GitObjectFormat::Sha256);

        let report = merge(&vault, 1_783_699_204_000).expect("SHA-256 conflict encrypts");
        assert_eq!(report.unresolved_results, 1);
        let stage_zero = git
            .stage_zero("entry.md.enc")
            .expect("stage zero inspects")
            .expect("stage zero exists");
        assert_eq!(stage_zero.oid.len(), 64);
        assert_no_cas_private_files(vault.root());
    }

    #[test]
    fn detected_rename_modify_merges_at_authenticated_destination() {
        let (directory, vault, source, destination, file_id) =
            create_rename_modify_repository(true);
        let git = Git::open(directory.path()).expect("Git repository opens");
        let conflicts = git
            .unmerged_entries()
            .expect("detected conflict enumerates");
        assert!(!conflicts.contains_key(&physical_path_for_logical(&source)));
        let detected = conflicts
            .get(&physical_path_for_logical(&destination))
            .expect("detected rename is represented at destination");
        assert!(detected.stages.iter().all(Option::is_some));
        let tracked = tracked_identity_index(&vault, &git).expect("stage zero identities inspect");
        let plans = preflight_conflict_identities(&vault, &git, &conflicts, &tracked)
            .expect("detected rename preflight succeeds");
        assert!(matches!(
            plans.as_slice(),
            [MergePlan::DetectedRename {
                renamed_side: RenameSide::Ours,
                ..
            }]
        ));

        let report = merge(&vault, 1_783_699_204_000).expect("detected rename merges");
        assert_eq!(report.clean_results, 1);
        assert_eq!(report.unresolved_results, 0);
        assert!(!directory.path().join("entry.md.enc").exists());
        let document = vault
            .read(&destination)
            .expect("detected rename result authenticates");
        assert_eq!(document.header.file_id.to_string(), file_id);
        assert_eq!(
            document.plaintext.as_slice(),
            b"first\nbase\ntheirs changed\n"
        );
        assert!(git.unmerged_entries().expect("index verifies").is_empty());
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
        assert_no_cas_private_files(vault.root());
    }

    #[test]
    fn detected_rename_rejects_restored_source_without_touching_destination_or_index() {
        let (directory, vault, source, destination, _) = create_rename_modify_repository(true);
        let git = Git::open(directory.path()).expect("Git repository opens");
        let conflicts = git
            .unmerged_entries()
            .expect("detected conflict enumerates");
        let conflict = conflicts
            .get(&physical_path_for_logical(&destination))
            .expect("detected destination conflict exists");
        let source_stage = conflict.stages[2]
            .as_ref()
            .expect("source-bound other-side stage exists");
        let source_ciphertext = git
            .read_object(&source_stage.oid)
            .expect("source-bound stage reads");
        let source_target = vault.root().join(source.to_ciphertext_relative_path());
        let destination_target = vault.root().join(destination.to_ciphertext_relative_path());
        let destination_before =
            fs::read(&destination_target).expect("destination ciphertext snapshots");
        fs::write(&source_target, &source_ciphertext).expect("restored source fixture writes");

        assert!(matches!(
            merge(&vault, 1_783_699_204_000),
            Err(GitError::WorktreeChanged)
        ));
        assert_eq!(
            fs::read(&source_target).expect("restored source re-reads"),
            source_ciphertext
        );
        assert_eq!(
            fs::read(&destination_target).expect("destination re-reads"),
            destination_before
        );
        assert_eq!(
            git.unmerged_entries().expect("index re-inspects"),
            conflicts
        );
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
        assert_no_cas_private_files(vault.root());
    }

    #[test]
    fn detected_rename_recovery_finishes_from_journal_only() {
        let fixture = create_detected_rename_recovery_fixture();
        fixture.assert_original_index();
        fixture.write_journal();

        assert!(recover_pending(&fixture.vault, &fixture.git).expect("v3 recovery succeeds"));
        assert!(!journal_path(fixture.vault.root()).exists());
        fixture.assert_final_state();
    }

    #[test]
    fn detected_rename_recovery_finishes_after_destination_write() {
        let fixture = create_detected_rename_recovery_fixture();
        fixture.write_journal();
        fixture.write_result_to_destination();
        fixture.assert_original_index();

        assert!(recover_pending(&fixture.vault, &fixture.git).expect("v3 recovery succeeds"));
        assert!(!journal_path(fixture.vault.root()).exists());
        fixture.assert_final_state();
    }

    #[test]
    fn detected_rename_final_recovery_survives_merge_commit_ref_transition() {
        let fixture = create_detected_rename_recovery_fixture();
        fixture.write_journal();
        fixture.write_result_to_destination();
        fixture.update_index();
        fixture.assert_final_state();
        assert!(test_git(
            fixture.vault.root(),
            ["commit", "-q", "-m", "resolved detected rename"]
        ));

        assert!(recover_pending(&fixture.vault, &fixture.git).expect("v3 final recovery succeeds"));
        assert!(!journal_path(fixture.vault.root()).exists());
        fixture.assert_final_state();
    }

    #[test]
    fn detected_rename_recovery_rejects_restored_source_before_destination_mutation() {
        let fixture = create_detected_rename_recovery_fixture();
        fixture.write_journal();
        let destination_before =
            fs::read(&fixture.destination_target).expect("detected destination snapshots");
        fs::write(&fixture.source_target, &fixture.source_ciphertext)
            .expect("detected source restores");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(journal_path(fixture.vault.root()).is_file());
        assert_eq!(
            fs::read(&fixture.source_target).expect("detected source re-reads"),
            fixture.source_ciphertext
        );
        assert_eq!(
            fs::read(&fixture.destination_target).expect("detected destination re-reads"),
            destination_before
        );
        fixture.assert_original_index();
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The adversarial history is clearest as one real Git fixture.
    fn split_rename_rejects_destination_that_already_existed_in_merge_base() {
        let directory = TestDirectory::new();
        initialize_test_repository(directory.path());
        let source = LogicalPath::parse_canonical("entry.md").expect("source path parses");
        let destination =
            LogicalPath::parse_canonical("historical.md").expect("destination path parses");
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
        .expect("adversarial vault creates");
        vault
            .create_document(&source, b"base\n", 1_783_699_201_000)
            .expect("source document creates");
        let source_document = vault.read(&source).expect("source identity reads");
        let mut duplicate_identity = source_document.header.clone();
        duplicate_identity.logical_path = destination.as_str().to_owned();
        let historical_destination = vault
            .encrypt_merge_result(
                &destination,
                &duplicate_identity,
                b"historical duplicate\n",
                1_783_699_201_500,
                false,
            )
            .expect("historical destination encrypts");
        drop(source_document);
        fs::write(
            directory
                .path()
                .join(destination.to_ciphertext_relative_path()),
            &historical_destination.bytes,
        )
        .expect("historical destination writes");
        drop(vault);
        fs::write(
            directory.path().join(GIT_ATTRIBUTES_FILE),
            format!("{ATTRIBUTES_RULE}\n"),
        )
        .expect("attributes write succeeds");
        assert!(test_git(directory.path(), ["add", "--all"]));
        assert!(test_git(
            directory.path(),
            ["commit", "-q", "-m", "baseline with historical duplicate"]
        ));

        assert!(test_git(directory.path(), ["checkout", "-q", "-b", "ours"]));
        let mut ours = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
            .expect("ours vault unlocks");
        let current = ours.read(&source).expect("ours source reads");
        ours.delete_document(&source, &current.etag)
            .expect("ours source deletes");
        drop(current);
        drop(ours);
        assert!(test_git(directory.path(), ["add", "--all"]));
        assert!(test_git(
            directory.path(),
            ["commit", "-q", "-m", "ours deletes source"]
        ));

        assert!(test_git(directory.path(), ["checkout", "-q", "baseline"]));
        assert!(test_git(
            directory.path(),
            ["checkout", "-q", "-b", "theirs"]
        ));
        save_test_document(directory.path(), b"theirs modifies\n", 1_783_699_202_000);
        assert!(test_git(directory.path(), ["add", "entry.md.enc"]));
        assert!(test_git(
            directory.path(),
            ["commit", "-q", "-m", "theirs modifies source"]
        ));
        assert!(test_git(directory.path(), ["checkout", "-q", "ours"]));
        assert!(test_git(
            directory.path(),
            [
                "config",
                "--local",
                "merge.inex.driver",
                "git config --get inex.driver.must.fail"
            ]
        ));
        let mut merge_command = TestCommand::new("git");
        merge_command
            .current_dir(directory.path())
            .args([
                "merge",
                "-s",
                "recursive",
                "-Xno-renames",
                "--no-edit",
                "theirs",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert!(
            !merge_command
                .status()
                .expect("adversarial merge starts")
                .success()
        );
        let vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
            .expect("conflicted vault unlocks");
        let git = Git::open(directory.path()).expect("Git repository opens");
        let index_before = git.unmerged_entries().expect("index snapshots");
        let source_before =
            fs::read(directory.path().join("entry.md.enc")).expect("source worktree snapshots");
        let destination_before = fs::read(directory.path().join("historical.md.enc"))
            .expect("destination worktree snapshots");

        assert!(matches!(
            merge(&vault, 1_783_699_203_000),
            Err(GitError::UnsupportedConflictEntry)
        ));
        assert_eq!(
            git.unmerged_entries().expect("index re-inspects"),
            index_before
        );
        assert_eq!(
            fs::read(directory.path().join("entry.md.enc")).expect("source re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(directory.path().join("historical.md.enc")).expect("destination re-reads"),
            destination_before
        );
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The malformed real-index shape needs an end-to-end fixture.
    fn conflict_path_with_stage_zero_is_rejected_before_any_merge_mutation() {
        let (directory, mut vault, source, destination, _) = create_rename_modify_repository(false);
        let git = Git::open(directory.path()).expect("Git repository opens");
        let source_physical_path = physical_path_for_logical(&source);
        let destination_physical_path = physical_path_for_logical(&destination);
        let source_conflict = git
            .unmerged_entries()
            .expect("source conflict enumerates")
            .remove(&source_physical_path)
            .expect("source conflict exists");
        let destination_stage = git
            .stage_zero(&destination_physical_path)
            .expect("destination stage inspects")
            .expect("destination stage exists");
        let donor_path =
            LogicalPath::parse_canonical("stage-zero donor.md").expect("donor path parses");
        vault
            .create_document(&donor_path, b"unrelated identity", 1_783_699_204_000)
            .expect("donor identity creates");
        let donor = vault.read(&donor_path).expect("donor identity reads");
        let donor_etag = donor.etag.clone();
        let donor_file_id = donor.header.file_id;
        let mut source_identity = donor.header.clone();
        source_identity.logical_path = source.as_str().to_owned();
        drop(donor);
        let unexpected_stage_zero = vault
            .encrypt_merge_result(
                &source,
                &source_identity,
                b"unexpected stage zero",
                1_783_699_204_500,
                false,
            )
            .expect("unexpected source stage-zero encrypts");
        vault
            .delete_document(&donor_path, &donor_etag)
            .expect("donor worktree entry deletes");
        let unexpected_stage_zero_oid = git
            .write_object(&unexpected_stage_zero.bytes)
            .expect("unexpected source stage-zero object writes");
        let original_source_stage = source_conflict.stages[2]
            .as_ref()
            .expect("source other-side stage exists");
        let original_source_ciphertext = git
            .read_object(&original_source_stage.oid)
            .expect("source conflict stage reads");
        let original_source_document = vault
            .authenticate_committed_envelope(&source, &original_source_ciphertext)
            .expect("source conflict stage authenticates");
        assert_ne!(original_source_document.header.file_id, donor_file_id);
        let mut input = format!(
            "{} {} 0\t{}\0",
            destination_stage.mode, unexpected_stage_zero_oid, source_physical_path
        )
        .into_bytes();
        for (index, stage) in source_conflict.stages.iter().enumerate() {
            let Some(stage) = stage else {
                continue;
            };
            input.extend_from_slice(
                format!(
                    "{} {} {}\t{}\0",
                    stage.mode,
                    stage.oid,
                    index.saturating_add(1),
                    source_physical_path
                )
                .as_bytes(),
            );
        }
        git.run(
            GitOperation::UpdateIndex,
            ["update-index", "-z", "--index-info"],
            Some(&input),
            1024,
        )
        .expect("coexisting stage-zero fixture installs");
        git.sync_index().expect("malicious index fixture syncs");
        assert!(
            git.stage_zero(&source_physical_path)
                .expect("source stage-zero inspects")
                .is_some()
        );
        assert!(
            git.unmerged_entries()
                .expect("source conflict still exists")
                .contains_key(&source_physical_path)
        );
        let index_before = git.staged_entries().expect("index snapshots");
        let source_target = vault.root().join(source.to_ciphertext_relative_path());
        let destination_target = vault.root().join(destination.to_ciphertext_relative_path());
        let source_before = fs::read(&source_target).expect("source ciphertext snapshots");
        let destination_before =
            fs::read(&destination_target).expect("destination ciphertext snapshots");

        assert!(matches!(
            merge(&vault, 1_783_699_204_000),
            Err(GitError::UnsupportedConflictEntry)
        ));
        assert_eq!(
            git.staged_entries().expect("index re-inspects"),
            index_before
        );
        assert_eq!(
            fs::read(&source_target).expect("source ciphertext re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(&destination_target).expect("destination ciphertext re-reads"),
            destination_before
        );
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
    }

    #[test]
    fn split_rename_modify_commits_two_path_ciphertext_transaction() {
        let (directory, vault, source, destination, file_id) =
            create_rename_modify_repository(false);
        let git = Git::open(directory.path()).expect("Git repository opens");
        let conflicts = git.unmerged_entries().expect("split conflict enumerates");
        let split = conflicts
            .get(&physical_path_for_logical(&source))
            .expect("source delete/modify conflict exists");
        assert!(split.stages[0].is_some());
        assert!(split.stages[1].is_none());
        assert!(split.stages[2].is_some());
        let tracked = tracked_identity_index(&vault, &git).expect("stage zero identities inspect");
        assert_eq!(
            tracked
                .get(&file_id)
                .expect("destination identity is tracked")
                .logical_path,
            destination
        );
        let plans = preflight_conflict_identities(&vault, &git, &conflicts, &tracked)
            .expect("split rename preflight succeeds");
        assert!(matches!(
            plans.as_slice(),
            [MergePlan::SplitRename {
                renamed_side: RenameSide::Ours,
                ..
            }]
        ));

        let report = merge(&vault, 1_783_699_204_000).expect("split rename merges");
        assert_eq!(report.clean_results, 1);
        assert_eq!(report.unresolved_results, 0);
        assert!(!directory.path().join("entry.md.enc").exists());
        let document = vault
            .read(&destination)
            .expect("split rename result authenticates");
        assert_eq!(document.header.file_id.to_string(), file_id);
        assert_eq!(
            document.plaintext.as_slice(),
            b"first\nbase\ntheirs changed\n"
        );
        assert!(git.unmerged_entries().expect("index verifies").is_empty());
        assert!(
            git.stage_zero(&physical_path_for_logical(&source))
                .expect("source index inspects")
                .is_none()
        );
        assert!(
            git.stage_zero(&physical_path_for_logical(&destination))
                .expect("destination index inspects")
                .is_some()
        );
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
        assert_no_cas_private_files(vault.root());
    }

    #[test]
    fn sha256_repository_completes_split_rename_modify_transaction() {
        let (directory, vault, source, destination, file_id) =
            create_rename_modify_repository_with_format(false, GitObjectFormat::Sha256);
        let git = Git::open(directory.path()).expect("SHA-256 Git repository opens");
        assert_eq!(git.object_format, GitObjectFormat::Sha256);
        let conflicts = git
            .unmerged_entries()
            .expect("SHA-256 split conflict enumerates");
        assert!(conflicts.contains_key(&physical_path_for_logical(&source)));
        assert!(
            conflicts
                .values()
                .flat_map(|conflict| conflict.stages.iter().flatten())
                .all(|stage| stage.oid.len() == 64)
        );

        let report = merge(&vault, 1_783_699_204_000).expect("SHA-256 split rename merges");
        assert_eq!(report.clean_results, 1);
        assert_eq!(report.unresolved_results, 0);
        assert!(!directory.path().join("entry.md.enc").exists());
        let document = vault
            .read(&destination)
            .expect("SHA-256 destination authenticates");
        assert_eq!(document.header.file_id.to_string(), file_id);
        assert_eq!(
            document.plaintext.as_slice(),
            b"first\nbase\ntheirs changed\n"
        );
        let stage_zero = git
            .stage_zero(&physical_path_for_logical(&destination))
            .expect("SHA-256 destination index inspects")
            .expect("SHA-256 destination stage exists");
        assert_eq!(stage_zero.oid.len(), 64);
        assert!(git.unmerged_entries().expect("index verifies").is_empty());
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
    }

    #[test]
    fn split_rename_recovery_finishes_from_journal_only() {
        let fixture = create_rename_recovery_fixture();
        fixture.assert_original_index();
        fixture.write_journal();

        assert!(recover_pending(&fixture.vault, &fixture.git).expect("rename recovery succeeds"));
        assert!(!journal_path(fixture.vault.root()).exists());
        fixture.assert_final_state();
    }

    #[test]
    fn split_rename_recovery_finishes_after_destination_before_source_delete() {
        let fixture = create_rename_recovery_fixture();
        fixture.write_journal();
        fixture.write_result_to_destination();

        assert_eq!(
            fs::read(&fixture.source_target).expect("source remains before recovery"),
            fixture.prepared.source_stage_ciphertexts[2]
                .as_ref()
                .expect("source ciphertext remains")
                .as_slice()
        );
        fixture.assert_original_index();
        assert!(recover_pending(&fixture.vault, &fixture.git).expect("rename recovery succeeds"));
        assert!(!journal_path(fixture.vault.root()).exists());
        fixture.assert_final_state();
    }

    #[test]
    fn split_rename_recovery_finishes_after_source_delete_before_index_update() {
        let fixture = create_rename_recovery_fixture();
        fixture.write_journal();
        fixture.write_result_to_destination();
        fixture.delete_source();

        assert!(!fixture.source_target.exists());
        fixture.assert_original_index();
        assert!(recover_pending(&fixture.vault, &fixture.git).expect("rename recovery succeeds"));
        assert!(!journal_path(fixture.vault.root()).exists());
        fixture.assert_final_state();
    }

    #[test]
    fn split_rename_recovery_cleans_journal_after_index_commit() {
        let fixture = create_rename_recovery_fixture();
        fixture.write_journal();
        fixture.write_result_to_destination();
        fixture.delete_source();
        fixture.update_index();

        fixture.assert_final_state();
        assert!(journal_path(fixture.vault.root()).is_file());
        assert!(recover_pending(&fixture.vault, &fixture.git).expect("rename recovery succeeds"));
        assert!(!journal_path(fixture.vault.root()).exists());
        fixture.assert_final_state();
    }

    #[test]
    fn split_rename_final_recovery_survives_merge_commit_ref_transition() {
        let fixture = create_rename_recovery_fixture();
        fixture.write_journal();
        fixture.write_result_to_destination();
        fixture.delete_source();
        fixture.update_index();
        fixture.assert_final_state();
        assert!(test_git(
            fixture.vault.root(),
            ["commit", "-q", "-m", "resolved encrypted rename"]
        ));

        assert!(recover_pending(&fixture.vault, &fixture.git).expect("final recovery succeeds"));
        assert!(!journal_path(fixture.vault.root()).exists());
        fixture.assert_final_state();
    }

    #[test]
    fn split_rename_recovery_rejects_concurrent_destination_change_without_mutation() {
        let fixture = create_rename_recovery_fixture();
        fixture.write_journal();
        let source_before = fs::read(&fixture.source_target).expect("source ciphertext snapshots");
        let tampered = b"INEX_RECOVERY_CONCURRENT_CHANGE_CANARY";
        fs::write(&fixture.destination_target, tampered)
            .expect("concurrent destination fixture writes");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(journal_path(fixture.vault.root()).is_file());
        assert_eq!(
            fs::read(&fixture.source_target).expect("source ciphertext re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(&fixture.destination_target).expect("destination re-reads"),
            tampered
        );
        fixture.assert_original_index();
    }

    #[test]
    fn split_rename_recovery_rejects_untracked_third_identity_owner_before_mutation() {
        let fixture = create_rename_recovery_fixture();
        fixture.write_journal();
        let source_before = fs::read(&fixture.source_target).expect("source ciphertext snapshots");
        let destination_before =
            fs::read(&fixture.destination_target).expect("destination ciphertext snapshots");
        let third_path = LogicalPath::parse_canonical("third owner.md").expect("third path parses");
        let third_ciphertext = fixture.ciphertext_for_third_owner(&third_path);
        fs::write(
            fixture
                .vault
                .root()
                .join(third_path.to_ciphertext_relative_path()),
            &third_ciphertext,
        )
        .expect("untracked third owner writes");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(journal_path(fixture.vault.root()).is_file());
        assert_eq!(
            fs::read(&fixture.source_target).expect("source ciphertext re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(&fixture.destination_target).expect("destination ciphertext re-reads"),
            destination_before
        );
        fixture.assert_original_index();
    }

    #[test]
    fn split_rename_recovery_rejects_staged_third_identity_owner_before_mutation() {
        let fixture = create_rename_recovery_fixture();
        fixture.write_journal();
        let source_before = fs::read(&fixture.source_target).expect("source ciphertext snapshots");
        let destination_before =
            fs::read(&fixture.destination_target).expect("destination ciphertext snapshots");
        let third_path =
            LogicalPath::parse_canonical("third staged.md").expect("third path parses");
        let third_physical_path = physical_path_for_logical(&third_path);
        let third_ciphertext = fixture.ciphertext_for_third_owner(&third_path);
        let third_oid = fixture
            .git
            .write_object(&third_ciphertext)
            .expect("third owner object writes");
        fixture
            .git
            .update_index(&third_physical_path, "100644", &third_oid)
            .expect("third owner stages");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(journal_path(fixture.vault.root()).is_file());
        assert_eq!(
            fs::read(&fixture.source_target).expect("source ciphertext re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(&fixture.destination_target).expect("destination ciphertext re-reads"),
            destination_before
        );
        fixture.assert_original_index();
    }

    #[test]
    fn cas_v4_journal_round_trips_and_rejects_noncanonical_bindings() {
        let fixture = create_rename_recovery_fixture();
        let transaction = MergeJournalPayload::Rename(fixture.journal.clone());
        let prepared = prepare_index_cas(&fixture.git, &transaction)
            .expect("CAS candidate prepares for schema test");
        let journal = prepared.journal(transaction);
        validate_cas_journal(&journal).expect("canonical v4 validates");
        let bytes = serde_json::to_vec(&journal).expect("v4 serializes");
        let decoded: CasMergeJournal = serde_json::from_slice(&bytes).expect("v4 parses");
        assert_eq!(decoded, journal);
        let text = std::str::from_utf8(&bytes).expect("v4 JSON is UTF-8");
        let duplicate = text.replacen("\"version\":4", "\"version\":4,\"version\":4", 1);
        assert!(matches!(
            parse_duplicate_free_json(duplicate.as_bytes()),
            Err(GitError::InvalidJournal)
        ));
        let path = journal_path(fixture.vault.root());
        fs::write(&path, duplicate.as_bytes()).expect("duplicate journal fixture writes");
        assert!(matches!(
            read_journal(fixture.vault.root()),
            Err(GitError::InvalidJournal)
        ));
        fs::remove_file(&path).expect("duplicate fixture removes");
        let mut unknown: serde_json::Value =
            serde_json::from_slice(&bytes).expect("v4 value parses");
        unknown
            .get_mut("transaction")
            .and_then(serde_json::Value::as_object_mut)
            .expect("transaction is an object")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<CasMergeJournal>(unknown.clone()).is_err());
        fs::write(
            &path,
            serde_json::to_vec(&unknown).expect("unknown-field fixture serializes"),
        )
        .expect("unknown-field fixture writes");
        assert!(matches!(
            read_journal(fixture.vault.root()),
            Err(GitError::InvalidJournal)
        ));
        fs::remove_file(&path).expect("unknown-field fixture removes");
        for replacement in ["true", "4.0", "\"4\""] {
            let invalid_version =
                text.replacen("\"version\":4", &format!("\"version\":{replacement}"), 1);
            fs::write(&path, invalid_version).expect("invalid version fixture writes");
            assert!(matches!(
                read_journal(fixture.vault.root()),
                Err(GitError::InvalidJournal)
            ));
            fs::remove_file(&path).expect("invalid version fixture removes");
        }

        let mut bad_candidate = journal.clone();
        bad_candidate.candidate_file = "../index".to_owned();
        assert!(matches!(
            validate_cas_journal(&bad_candidate),
            Err(GitError::InvalidJournal)
        ));
        let mut same_digest = journal.clone();
        same_digest.candidate_index_sha256 = same_digest.expected_index_sha256.clone();
        assert!(matches!(
            validate_cas_journal(&same_digest),
            Err(GitError::InvalidJournal)
        ));
        let mut wrong_format = journal.clone();
        wrong_format.object_format = GitObjectFormat::Sha256;
        assert!(matches!(
            validate_cas_journal(&wrong_format),
            Err(GitError::InvalidJournal)
        ));
        let mut wrong_provenance_format = journal.clone();
        let MergeJournalPayload::Rename(rename) = &mut wrong_provenance_format.transaction else {
            panic!("schema fixture must contain a rename transaction");
        };
        rename.provenance.object_format = GitObjectFormat::Sha256;
        assert!(matches!(
            validate_cas_journal(&wrong_provenance_format),
            Err(GitError::InvalidJournal)
        ));
        let mut wrong_provenance_oid = journal;
        let MergeJournalPayload::Rename(rename) = &mut wrong_provenance_oid.transaction else {
            panic!("schema fixture must contain a rename transaction");
        };
        rename.provenance.base_commit = "a".repeat(64);
        assert!(matches!(
            validate_cas_journal(&wrong_provenance_oid),
            Err(GitError::InvalidJournal)
        ));
    }

    #[test]
    fn cas_v4_file_move_durability_requires_both_parent_syncs() {
        for outcome in [
            AtomicFileMoveOutcome {
                source_parent_sync: ParentSyncStatus::NotSynced,
                destination_parent_sync: ParentSyncStatus::Synced,
            },
            AtomicFileMoveOutcome {
                source_parent_sync: ParentSyncStatus::Synced,
                destination_parent_sync: ParentSyncStatus::NotSynced,
            },
        ] {
            assert!(matches!(
                require_file_move_durability(outcome),
                Err(GitError::DurabilityNotConfirmed)
            ));
        }
    }

    #[test]
    fn foreign_index_lock_blocks_cas_without_mutating_repository() {
        let fixture = create_rename_recovery_fixture();
        let index_before = fs::read(index_path(fixture.vault.root())).expect("index snapshots");
        let source_before = fs::read(&fixture.source_target).expect("source snapshots");
        let destination_before =
            fs::read(&fixture.destination_target).expect("destination snapshots");
        let lock_path = index_lock_path(fixture.vault.root());
        let foreign = b"FOREIGN_GIT_INDEX_LOCK_SENTINEL";
        fs::write(&lock_path, foreign).expect("foreign lock installs");

        let transaction = MergeJournalPayload::Rename(fixture.journal.clone());
        assert!(matches!(
            prepare_index_cas(&fixture.git, &transaction),
            Err(GitError::IndexChanged)
        ));
        assert_eq!(
            fs::read(&lock_path).expect("foreign lock re-reads"),
            foreign
        );
        assert_eq!(
            fs::read(index_path(fixture.vault.root())).expect("index re-reads"),
            index_before
        );
        assert_eq!(
            fs::read(&fixture.source_target).expect("source re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(&fixture.destination_target).expect("destination re-reads"),
            destination_before
        );
        assert!(
            read_journal(fixture.vault.root())
                .expect("journal inspects")
                .is_none()
        );
        fs::remove_file(lock_path).expect("foreign lock fixture removes");
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn prelock_recovery_cleans_process_kill_state_without_running_raii() {
        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let candidate = index_candidate_path(fixture.vault.root(), &reservation.candidate_file);
        let old = read_index_snapshot(&index_path(fixture.vault.root()))
            .expect("old index snapshots for killed process fixture");
        fs::write(&candidate, &old.bytes).expect("owned candidate fixture writes");
        install_candidate_receipt(
            fixture.vault.root(),
            &initial_candidate_receipt(&reservation),
        )
        .expect("initial ownership receipt publishes");

        assert!(!index_lock_path(fixture.vault.root()).exists());
        assert!(
            has_pending_recovery(fixture.vault.root()).expect("durable prelock reports pending")
        );
        fixture.assert_original_index();

        let report = recover(&fixture.vault).expect("prelock-only state recovers");
        assert_eq!(report.recovered_transactions, 1);
        fixture.assert_original_index();
        assert!(fixture.source_target.is_file());
        assert!(fixture.destination_target.is_file());
        assert!(
            !has_pending_recovery(fixture.vault.root())
                .expect("cleaned prelock is no longer pending")
        );
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn receipt_gap_crash_states_are_visible_preserved_and_fail_closed() {
        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let candidate = index_candidate_path(fixture.vault.root(), &reservation.candidate_file);
        let old = read_index_snapshot(&index_path(fixture.vault.root()))
            .expect("old index snapshots for receipt-gap fixture");
        fs::write(&candidate, &old.bytes).expect("pre-receipt candidate fixture writes");

        assert!(matches!(
            has_pending_recovery(fixture.vault.root()),
            Err(GitError::RecoveryConflict)
        ));
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert_eq!(
            fs::read(&candidate).expect("pre-receipt candidate remains"),
            old.bytes
        );
        assert_eq!(
            read_prelock_reservation(fixture.vault.root())
                .expect("pre-receipt reservation re-reads")
                .as_ref(),
            Some(&reservation)
        );
        fixture.assert_original_index();

        install_candidate_receipt(
            fixture.vault.root(),
            &initial_candidate_receipt(&reservation),
        )
        .expect("initial receipt fixture publishes");
        let partial_candidate = b"partial candidate after Git process kill";
        fs::write(&candidate, partial_candidate).expect("partial candidate fixture writes");

        assert!(matches!(
            has_pending_recovery(fixture.vault.root()),
            Err(GitError::RecoveryConflict | GitError::IndexChanged)
        ));
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict | GitError::IndexChanged)
        ));
        assert_eq!(
            fs::read(&candidate).expect("partial candidate remains"),
            partial_candidate
        );
        assert_eq!(
            read_candidate_receipt(
                fixture.vault.root(),
                &reservation.lock_token,
                CandidateReceiptPhase::Initial,
            )
            .expect("initial receipt re-reads")
            .as_ref(),
            Some(&initial_candidate_receipt(&reservation))
        );
        fixture.assert_original_index();
    }

    #[test]
    fn exact_final_receipt_before_marker_is_recoverable() {
        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let candidate = index_candidate_path(fixture.vault.root(), &reservation.candidate_file);
        let old = read_index_snapshot(&index_path(fixture.vault.root()))
            .expect("old index snapshots for final-receipt fixture");
        fs::write(&candidate, &old.bytes).expect("candidate fixture writes");
        install_candidate_receipt(
            fixture.vault.root(),
            &initial_candidate_receipt(&reservation),
        )
        .expect("initial receipt fixture publishes");
        let candidate_git = fixture
            .git
            .with_index_file(candidate.clone())
            .expect("candidate Git fixture opens");
        let transaction = MergeJournalPayload::Rename(fixture.journal.clone());
        let before = index_entry_map(&candidate_git).expect("candidate stage map snapshots");
        apply_payload_to_index(&candidate_git, &transaction)
            .expect("candidate transaction applies");
        verify_candidate_index(&candidate_git, &transaction, &before)
            .expect("candidate transaction verifies");
        let final_candidate = read_index_snapshot(&candidate).expect("final candidate snapshots");
        install_candidate_receipt(
            fixture.vault.root(),
            &final_candidate_receipt(&reservation, final_candidate.size, &final_candidate.sha256),
        )
        .expect("final receipt fixture publishes");

        assert!(has_pending_recovery(fixture.vault.root()).expect("final receipt is pending"));
        assert!(recover_pending(&fixture.vault, &fixture.git).expect("final receipt recovers"));
        fixture.assert_original_index();
        assert_no_cas_private_files(fixture.vault.root());
        assert!(
            !has_pending_recovery(fixture.vault.root())
                .expect("final-receipt recovery leaves no pending state")
        );
    }

    #[test]
    fn partial_candidate_receipt_is_preserved_and_fails_closed() {
        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let candidate = index_candidate_path(fixture.vault.root(), &reservation.candidate_file);
        let old = read_index_snapshot(&index_path(fixture.vault.root()))
            .expect("old index snapshots for partial receipt fixture");
        fs::write(&candidate, &old.bytes).expect("candidate fixture writes");
        let receipt = initial_candidate_receipt(&reservation);
        let receipt_bytes = candidate_receipt_bytes(&receipt).expect("receipt serializes");
        let receipt_path = candidate_receipt_path(
            fixture.vault.root(),
            &reservation.lock_token,
            CandidateReceiptPhase::Initial,
        );
        let partial = &receipt_bytes[..receipt_bytes.len() / 2];
        fs::write(&receipt_path, partial).expect("partial receipt fixture writes");

        assert!(matches!(
            has_pending_recovery(fixture.vault.root()),
            Err(GitError::InvalidJournal)
        ));
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::InvalidJournal)
        ));
        assert_eq!(
            fs::read(&receipt_path).expect("partial receipt remains"),
            partial
        );
        assert_eq!(
            fs::read(&candidate).expect("candidate remains with partial receipt"),
            old.bytes
        );
        assert_eq!(
            read_prelock_reservation(fixture.vault.root())
                .expect("partial-receipt reservation re-reads")
                .as_ref(),
            Some(&reservation)
        );
        fixture.assert_original_index();
    }

    #[cfg(unix)]
    #[test]
    fn dangling_prelock_transaction_links_are_preserved_and_fail_closed() {
        use std::os::unix::fs::symlink;

        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let local = fixture.vault.root().join(VAULT_LOCAL_DIRECTORY);
        let missing_target = local.join("missing-link-target");
        let paths = [
            prelock_reservation_staging_path(fixture.vault.root(), &reservation.lock_token),
            index_marker_staging_path(fixture.vault.root(), &reservation.lock_token),
            local.join(format!(
                "{JOURNAL_STAGING_PREFIX}{}",
                reservation.lock_token
            )),
        ];

        for path in paths {
            symlink(&missing_target, &path).expect("dangling transaction link creates");
            assert!(matches!(
                has_pending_recovery(fixture.vault.root()),
                Err(GitError::RecoveryConflict | GitError::InvalidJournal)
            ));
            assert!(matches!(
                recover_pending(&fixture.vault, &fixture.git),
                Err(GitError::RecoveryConflict | GitError::InvalidJournal)
            ));
            let metadata = fs::symlink_metadata(&path).expect("dangling link remains");
            assert!(metadata.file_type().is_symlink());
            assert!(!missing_target.exists());
            fs::remove_file(path).expect("dangling link fixture removes");
        }
        fixture.assert_original_index();
    }

    #[cfg(unix)]
    #[test]
    fn dangling_journal_staging_in_abandoned_marker_state_is_preserved() {
        use std::os::unix::fs::symlink;

        let fixture = create_rename_recovery_fixture();
        let transaction = MergeJournalPayload::Rename(fixture.journal.clone());
        let mut prepared =
            prepare_index_cas(&fixture.git, &transaction).expect("CAS marker state prepares");
        let lock_token = prepared.lock_token.clone();
        let candidate = index_candidate_path(fixture.vault.root(), &prepared.candidate_file);
        let initial_receipt = candidate_receipt_path(
            fixture.vault.root(),
            &lock_token,
            CandidateReceiptPhase::Initial,
        );
        let final_receipt = candidate_receipt_path(
            fixture.vault.root(),
            &lock_token,
            CandidateReceiptPhase::Final,
        );
        prepared.disarm();
        drop(prepared);
        let local = fixture.vault.root().join(VAULT_LOCAL_DIRECTORY);
        let journal_staging = local.join(format!("{JOURNAL_STAGING_PREFIX}{lock_token}"));
        let missing_target = local.join("missing-journal-staging-target");
        symlink(&missing_target, &journal_staging)
            .expect("dangling journal staging fixture creates");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(
            fs::symlink_metadata(&journal_staging)
                .expect("dangling journal staging remains")
                .file_type()
                .is_symlink()
        );
        assert!(index_lock_path(fixture.vault.root()).is_file());
        assert!(candidate.is_file());
        assert!(initial_receipt.is_file());
        assert!(final_receipt.is_file());
        assert!(prelock_reservation_path(fixture.vault.root()).is_file());
        assert!(!missing_target.exists());
        fixture.assert_original_index();
    }

    #[test]
    fn canonical_orphan_prelock_staging_is_pending_and_recoverable() {
        let fixture = create_rename_recovery_fixture();
        let reservation = test_prelock_reservation(&fixture);
        let bytes = prelock_reservation_bytes(&reservation).expect("prelock serializes");
        let path = prelock_reservation_staging_path(fixture.vault.root(), &reservation.lock_token);
        drop(create_private_file(&path, &bytes).expect("orphan staging fixture writes"));

        assert!(has_pending_recovery(fixture.vault.root()).expect("orphan staging is pending"));
        let report = recover(&fixture.vault).expect("canonical orphan staging recovers");
        assert_eq!(report.recovered_transactions, 1);
        assert!(!path.exists());
        fixture.assert_original_index();
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn partial_or_multiple_prelock_staging_fails_closed_and_is_preserved() {
        let fixture = create_rename_recovery_fixture();
        let reservation = test_prelock_reservation(&fixture);
        let bytes = prelock_reservation_bytes(&reservation).expect("prelock serializes");
        let path = prelock_reservation_staging_path(fixture.vault.root(), &reservation.lock_token);
        fs::write(&path, &bytes[..bytes.len() / 2]).expect("partial staging fixture writes");
        assert!(has_pending_recovery(fixture.vault.root()).is_err());
        assert!(recover_pending(&fixture.vault, &fixture.git).is_err());
        assert_eq!(
            fs::read(&path).expect("partial staging remains"),
            &bytes[..bytes.len() / 2]
        );
        fs::remove_file(&path).expect("partial staging fixture removes");

        let second = test_prelock_reservation(&fixture);
        for reservation in [&reservation, &second] {
            let bytes = prelock_reservation_bytes(reservation).expect("prelock serializes");
            let path =
                prelock_reservation_staging_path(fixture.vault.root(), &reservation.lock_token);
            fs::write(path, bytes).expect("multiple staging fixture writes");
        }
        assert!(matches!(
            has_pending_recovery(fixture.vault.root()),
            Err(GitError::RecoveryConflict)
        ));
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        for reservation in [&reservation, &second] {
            assert!(
                prelock_reservation_staging_path(fixture.vault.root(), &reservation.lock_token)
                    .is_file()
            );
        }
        fixture.assert_original_index();
    }

    #[test]
    fn wrong_case_reserved_prelock_name_fails_closed_cross_platform() {
        let fixture = create_rename_recovery_fixture();
        let reservation = test_prelock_reservation(&fixture);
        let wrong_case = format!("GIT-INDEX-PRELOCK-STAGE-V4-{}", reservation.lock_token);
        let path = fixture
            .vault
            .root()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(wrong_case);
        fs::write(
            &path,
            prelock_reservation_bytes(&reservation).expect("prelock serializes"),
        )
        .expect("wrong-case staging fixture writes");

        assert!(matches!(
            has_pending_recovery(fixture.vault.root()),
            Err(GitError::RecoveryConflict)
        ));
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(path.is_file());
        fixture.assert_original_index();
    }

    #[test]
    fn raii_does_not_delete_foreign_candidate_when_create_phase_never_completed() {
        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let candidate = index_candidate_path(fixture.vault.root(), &reservation.candidate_file);
        let foreign = b"foreign same-token ordinary file";
        fs::write(&candidate, foreign).expect("foreign candidate fixture writes");
        drop(PreLockReservationGuard::new(
            fixture.vault.root().to_path_buf(),
            reservation.clone(),
        ));

        assert_eq!(
            fs::read(&candidate).expect("foreign candidate remains"),
            foreign
        );
        assert!(prelock_reservation_path(fixture.vault.root()).is_file());
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict | GitError::IndexChanged)
        ));
        fixture.assert_original_index();
    }

    #[test]
    fn prelock_recovery_preserves_hardlinked_token_file_and_fails_closed() {
        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let local = fixture.vault.root().join(VAULT_LOCAL_DIRECTORY);
        let sentinel = local.join("prelock-hardlink-sentinel");
        let candidate = index_candidate_path(fixture.vault.root(), &reservation.candidate_file);
        fs::write(&sentinel, b"foreign same-inode sentinel")
            .expect("hardlink sentinel fixture writes");
        fs::hard_link(&sentinel, &candidate).expect("candidate hardlink fixture installs");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert_eq!(
            fs::read(&sentinel).expect("sentinel re-reads"),
            b"foreign same-inode sentinel"
        );
        assert!(candidate.is_file());
        assert!(prelock_reservation_path(fixture.vault.root()).is_file());
        fixture.assert_original_index();
    }

    #[test]
    fn prelock_recovery_rejects_unrelated_reserved_transaction_file() {
        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let unrelated = fixture
            .vault
            .root()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(format!(
                "{INDEX_CANDIDATE_PREFIX}{}",
                Uuid::new_v4().simple()
            ));
        fs::write(&unrelated, b"unrelated private transaction state")
            .expect("unrelated reserved fixture writes");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(unrelated.is_file());
        assert!(prelock_reservation_path(fixture.vault.root()).is_file());
        assert_eq!(
            read_prelock_reservation(fixture.vault.root())
                .expect("prelock re-reads")
                .as_ref(),
            Some(&reservation)
        );
        fixture.assert_original_index();
    }

    #[test]
    fn malformed_prelock_reservation_is_reported_and_never_removed() {
        let fixture = create_rename_recovery_fixture();
        let path = prelock_reservation_path(fixture.vault.root());
        let malformed = b"{\"version\":4,\"version\":4}";
        fs::write(&path, malformed).expect("malformed prelock fixture writes");

        assert!(matches!(
            has_pending_recovery(fixture.vault.root()),
            Err(GitError::InvalidJournal)
        ));
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::InvalidJournal)
        ));
        assert_eq!(
            fs::read(path).expect("malformed prelock remains"),
            malformed
        );
        fixture.assert_original_index();
    }

    #[test]
    fn prelock_schema_rejects_unknown_types_and_noncanonical_json() {
        let fixture = create_rename_recovery_fixture();
        let reservation = test_prelock_reservation(&fixture);
        let canonical = prelock_reservation_bytes(&reservation).expect("prelock serializes");
        let text = std::str::from_utf8(&canonical).expect("prelock JSON is UTF-8");
        let path = prelock_reservation_path(fixture.vault.root());
        let mut mutations = vec![
            text.replacen('{', "{\"unknown\":true,", 1).into_bytes(),
            text.replacen("\"version\":4", "\"version\":true", 1)
                .into_bytes(),
            text.replacen(
                &format!(
                    "\"expected_index_size\":{}",
                    reservation.expected_index_size
                ),
                "\"expected_index_size\":1.0",
                1,
            )
            .into_bytes(),
            text.replacen("\"object_format\":\"sha1\"", "\"object_format\":7", 1)
                .into_bytes(),
        ];
        let mut missing: serde_json::Value =
            serde_json::from_slice(&canonical).expect("prelock value parses");
        missing
            .as_object_mut()
            .expect("prelock is an object")
            .remove("candidate_file");
        mutations.push(serde_json::to_vec(&missing).expect("missing-field value serializes"));
        let mut reordered: serde_json::Value =
            serde_json::from_slice(&canonical).expect("prelock value parses");
        let version = reordered
            .as_object_mut()
            .expect("prelock is an object")
            .remove("version")
            .expect("version exists");
        reordered
            .as_object_mut()
            .expect("prelock is an object")
            .insert("version".to_owned(), version);
        mutations.push(serde_json::to_vec(&reordered).expect("reordered prelock serializes"));
        let reordered = serde_json::to_vec_pretty(&reordered).expect("pretty prelock serializes");
        mutations.push(reordered);
        let mut whitespace = canonical.clone();
        whitespace.push(b'\n');
        mutations.push(whitespace);

        for mutation in mutations {
            fs::write(&path, &mutation).expect("invalid prelock fixture writes");
            assert!(matches!(
                read_prelock_reservation(fixture.vault.root()),
                Err(GitError::InvalidJournal)
            ));
            assert_eq!(fs::read(&path).expect("invalid prelock remains"), mutation);
            fs::remove_file(&path).expect("invalid prelock fixture removes");
        }
    }

    #[test]
    fn prelock_recovery_rejects_object_format_and_live_index_drift() {
        let fixture = create_rename_recovery_fixture();
        let mut wrong_format = test_prelock_reservation(&fixture);
        wrong_format.object_format = GitObjectFormat::Sha256;
        install_prelock_reservation(fixture.vault.root(), &wrong_format)
            .expect("wrong-format prelock fixture publishes");
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(prelock_reservation_path(fixture.vault.root()).is_file());
        fs::remove_file(prelock_reservation_path(fixture.vault.root()))
            .expect("wrong-format fixture removes");

        let reservation = install_test_prelock_reservation(&fixture);
        fs::write(
            fixture.vault.root().join("external-index-owner.bin"),
            b"ciphertext-only external index drift",
        )
        .expect("external index fixture writes");
        assert!(test_git(
            fixture.vault.root(),
            ["add", "external-index-owner.bin"]
        ));
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert_eq!(
            read_prelock_reservation(fixture.vault.root())
                .expect("drifted prelock re-reads")
                .as_ref(),
            Some(&reservation)
        );
    }

    #[test]
    fn prelock_recovery_preserves_state_when_live_index_is_missing() {
        let fixture = create_rename_recovery_fixture();
        let reservation = install_test_prelock_reservation(&fixture);
        let index = index_path(fixture.vault.root());
        let saved_index = fixture.vault.root().join("saved-index-for-test");
        fs::rename(&index, &saved_index).expect("live index fixture retires");

        assert!(recover_pending(&fixture.vault, &fixture.git).is_err());
        assert!(prelock_reservation_path(fixture.vault.root()).is_file());
        assert_eq!(
            read_prelock_reservation(fixture.vault.root())
                .expect("missing-index prelock re-reads")
                .as_ref(),
            Some(&reservation)
        );
        fs::rename(saved_index, index).expect("live index fixture restores");
        fixture.assert_original_index();
    }

    #[test]
    fn sha256_repository_recovers_canonical_orphan_prelock_staging() {
        let (directory, vault) = create_conflicted_repository_with_format(GitObjectFormat::Sha256);
        let git = Git::open(directory.path()).expect("SHA-256 repository opens");
        let old =
            read_index_snapshot(&index_path(directory.path())).expect("SHA-256 index snapshots");
        let lock_token = Uuid::new_v4().simple().to_string();
        let reservation = PreLockReservation {
            version: 4,
            object_format: GitObjectFormat::Sha256,
            candidate_file: format!("{INDEX_CANDIDATE_PREFIX}{lock_token}"),
            lock_token,
            expected_index_sha256: old.sha256,
            expected_index_size: old.size,
        };
        let path = prelock_reservation_staging_path(directory.path(), &reservation.lock_token);
        fs::write(
            &path,
            prelock_reservation_bytes(&reservation).expect("SHA-256 prelock serializes"),
        )
        .expect("SHA-256 orphan staging writes");

        assert!(recover_pending(&vault, &git).expect("SHA-256 orphan staging recovers"));
        assert!(!path.exists());
        assert_no_cas_private_files(directory.path());
    }

    #[test]
    fn v5_candidate_bundle_preparation_binds_real_sha1_and_sha256_stage_maps() {
        for object_format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
            let fixture = create_candidate_bundle_preparation_fixture(object_format);
            let root = fixture.vault.root();
            let old = read_index_snapshot(&index_path(root)).expect("live old index snapshots");
            let old_map = index_entry_map(&fixture.git).expect("live old stage map snapshots");
            let worktree = fs::read(root.join("entry.md.enc")).expect("worktree snapshots");
            let mut hooks = CandidateBundleTestHooks::new(None);

            let prepared = prepare_test_candidate_bundle(&fixture, &mut hooks)
                .expect("v5 candidate bundle prepares");
            let stable_path = candidate_bundle_v5::candidate_bundle_stable_path_v5(
                root,
                &prepared.bundle_basename,
            )
            .expect("stable candidate path validates");
            assert_eq!(
                hooks.scratch_identity.as_ref(),
                Some(
                    &inex_core::atomic::filesystem_directory_identity(&stable_path)
                        .expect("stable directory identity reads")
                )
            );
            candidate_bundle_v5::revalidate_prepared_candidate_bundle_v5(root, &prepared)
                .expect("held stable inventory revalidates");
            assert_eq!(prepared.inventory.manifest.object_format, object_format);
            assert_eq!(prepared.inventory.manifest.transaction, fixture.transaction);
            assert_eq!(prepared.inventory.manifest.old_index.size, old.size);
            assert_eq!(prepared.inventory.manifest.old_index.sha256, old.sha256);
            assert_eq!(
                prepared.inventory.manifest.final_index,
                candidate_bundle_v5::CandidateIndexMetadataV5 {
                    size: prepared.inventory.manifest.candidate_member.size,
                    sha256: prepared.inventory.manifest.candidate_member.sha256.clone(),
                }
            );
            candidate_bundle_v5::validate_manifest_reference_v5(
                &prepared.inventory.manifest_reference,
            )
            .expect("manifest reference validates");
            let candidate_git = fixture
                .git
                .with_index_file(stable_path.join(candidate_bundle_v5::CANDIDATE_BUNDLE_INDEX_V5))
                .expect("stable alternate index constructs");
            verify_candidate_index(&candidate_git, &fixture.transaction, &old_map)
                .expect("stable stage map matches the transaction exactly");
            let candidate = read_index_snapshot(&candidate_git.index_path())
                .expect("stable candidate snapshots");
            assert_eq!(candidate.size, prepared.inventory.manifest.final_index.size);
            assert_eq!(
                candidate.sha256,
                prepared.inventory.manifest.final_index.sha256
            );
            let live = read_index_snapshot(&index_path(root)).expect("live index re-reads");
            assert_eq!((live.size, live.sha256), (old.size, old.sha256));
            assert_eq!(
                index_entry_map(&fixture.git).expect("live stage map re-reads"),
                old_map
            );
            assert_eq!(
                fs::read(root.join("entry.md.enc")).expect("worktree re-reads"),
                worktree
            );
            assert!(!index_lock_path(root).exists());
            assert!(!journal_path(root).exists());
            assert!(!prelock_reservation_path(root).exists());
            assert!(candidate_bundle_scratch_paths(root).is_empty());
            assert_eq!(
                exact_reserved_private_names(root).expect("reserved namespace inspects"),
                BTreeSet::from([prepared.bundle_basename.clone()])
            );
            assert_eq!(
                recovery_status(root).expect("stable bundle status inspects"),
                RecoveryStatus {
                    pending_transaction: true,
                    retained_candidate_scratch_count: 0,
                }
            );
        }
    }

    #[test]
    fn v5_reference_loader_rebinds_real_sha1_and_sha256_git_semantics() {
        for object_format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
            let fixture = create_candidate_bundle_preparation_fixture(object_format);
            let root = fixture.vault.root();
            let old = read_index_snapshot(&index_path(root)).expect("live old index snapshots");
            let old_map = index_entry_map(&fixture.git).expect("live old stage map snapshots");
            let mut hooks = CandidateBundleTestHooks::new(None);
            let prepared = prepare_test_candidate_bundle(&fixture, &mut hooks)
                .expect("v5 candidate bundle prepares");
            let reference = candidate_bundle_v5::candidate_bundle_transaction_reference_v5(
                &prepared.bundle_basename,
                prepared.inventory.manifest.object_format,
                prepared.inventory.manifest_reference.clone(),
            )
            .expect("v5 transaction reference builds");
            let marker = candidate_bundle_v5::index_lock_marker_bytes_v5(&reference)
                .expect("v5 marker serializes");
            assert_eq!(prepared.transaction_reference, reference);
            assert_eq!(prepared.index_lock_marker, marker);
            assert_eq!(
                prepared.index_lock_marker_reference,
                candidate_bundle_v5::canonical_bytes_reference_v5(&marker)
                    .expect("v5 marker bytes reference rebuilds")
            );
            assert_eq!(
                candidate_bundle_v5::parse_index_lock_marker_v5(&marker).expect("v5 marker parses"),
                reference
            );

            let fresh_guard = VaultMutationGuard::acquire(root)
                .expect("fresh recovery-style mutation guard acquires");
            let loaded = candidate_bundle_v5::load_candidate_bundle_for_git_v5(
                &fresh_guard,
                &fixture.git,
                &reference,
            )
            .expect("fresh loader rebinds inventory and Git semantics");
            assert_eq!(loaded.manifest, prepared.inventory.manifest);
            assert_eq!(loaded.manifest_reference, reference.manifest);
            assert_eq!(
                read_index_snapshot(&index_path(root))
                    .map(|snapshot| (snapshot.size, snapshot.sha256))
                    .expect("live index re-reads"),
                (old.size, old.sha256)
            );
            assert_eq!(
                index_entry_map(&fixture.git).expect("live stage map re-reads"),
                old_map
            );
            assert!(!index_lock_path(root).exists());
            assert!(!journal_path(root).exists());
        }
    }

    #[test]
    fn v5_reference_loader_preserves_bundle_on_reference_or_live_index_drift() {
        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let root = fixture.vault.root();
        let mut hooks = CandidateBundleTestHooks::new(None);
        let prepared = prepare_test_candidate_bundle(&fixture, &mut hooks)
            .expect("v5 candidate bundle prepares");
        let reference = candidate_bundle_v5::candidate_bundle_transaction_reference_v5(
            &prepared.bundle_basename,
            prepared.inventory.manifest.object_format,
            prepared.inventory.manifest_reference.clone(),
        )
        .expect("v5 transaction reference builds");
        let guard = VaultMutationGuard::acquire(root).expect("v5 loader mutation guard acquires");

        let mut wrong_object_format = reference.clone();
        wrong_object_format.object_format = GitObjectFormat::Sha256;
        assert!(matches!(
            candidate_bundle_v5::load_candidate_bundle_for_git_v5(
                &guard,
                &fixture.git,
                &wrong_object_format,
            ),
            Err(GitError::InvalidJournal)
        ));

        let mut wrong_reference = reference.clone();
        wrong_reference.manifest.sha256 = hex_digest(digest(b"wrong manifest reference"));
        assert!(matches!(
            candidate_bundle_v5::load_candidate_bundle_for_git_v5(
                &guard,
                &fixture.git,
                &wrong_reference,
            ),
            Err(GitError::RecoveryConflict)
        ));
        candidate_bundle_v5::revalidate_prepared_candidate_bundle_v5(root, &prepared)
            .expect("reference mismatch preserves stable bundle");

        fs::write(
            root.join("external-v5-loader-index-owner.bin"),
            b"ciphertext-only external v5 loader drift",
        )
        .expect("external index fixture writes");
        assert!(test_git(
            root,
            ["add", "external-v5-loader-index-owner.bin"]
        ));
        assert!(matches!(
            candidate_bundle_v5::load_candidate_bundle_for_git_v5(&guard, &fixture.git, &reference,),
            Err(GitError::IndexChanged)
        ));
        candidate_bundle_v5::revalidate_prepared_candidate_bundle_v5(root, &prepared)
            .expect("live drift preserves stable bundle");
    }

    #[test]
    fn v5_stable_journal_round_trips_and_blocks_unwired_index_publication() {
        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let root = fixture.vault.root();
        let old = read_index_snapshot(&index_path(root)).expect("live old index snapshots");
        let mut hooks = CandidateBundleTestHooks::new(None);
        let prepared = prepare_test_candidate_bundle(&fixture, &mut hooks)
            .expect("v5 candidate bundle prepares");
        let journal = bundle_journal_v5(&prepared);
        let pending = PendingMergeJournal::BundleV5(journal.clone());
        write_journal(root, &pending).expect("v5 stable journal publishes");
        assert_eq!(
            read_journal(root).expect("v5 stable journal reads"),
            Some(pending)
        );
        assert_eq!(
            recovery_status(root).expect("matching stable bundle and journal inspect"),
            RecoveryStatus {
                pending_transaction: true,
                retained_candidate_scratch_count: 0,
            }
        );
        let foreign_reserved = index_marker_staging_path(root, &journal.reference.token);
        fs::write(&foreign_reserved, b"foreign reserved marker staging")
            .expect("foreign reserved fixture writes");
        assert!(matches!(
            recovery_status(root),
            Err(GitError::RecoveryConflict)
        ));
        fs::remove_file(foreign_reserved).expect("foreign reserved fixture removes");
        assert!(
            recovery_status(root)
                .expect("exact matching namespace re-inspects")
                .pending_transaction
        );
        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(journal_path(root).is_file());
        candidate_bundle_v5::revalidate_prepared_candidate_bundle_v5(root, &prepared)
            .expect("unwired recovery preserves stable bundle");

        let MergeJournalPayload::InPlace(transaction) = &prepared.inventory.manifest.transaction
        else {
            panic!("fixture must carry an in-place transaction");
        };
        assert!(matches!(
            fixture.git.update_index(
                &transaction.physical_path,
                &transaction.result_mode,
                &transaction.result_oid,
            ),
            Err(GitError::RecoveryConflict)
        ));
        assert!(matches!(
            fixture.git.update_index_rename(
                "other.md.enc",
                &transaction.physical_path,
                &transaction.result_mode,
                &transaction.result_oid,
            ),
            Err(GitError::RecoveryConflict)
        ));
        let live = read_index_snapshot(&index_path(root)).expect("live index re-reads");
        assert_eq!((live.size, live.sha256), (old.size, old.sha256));
        assert!(!index_lock_path(root).exists());
    }

    #[test]
    fn v5_stable_journal_rejects_noncanonical_and_cross_bound_references() {
        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let root = fixture.vault.root();
        let mut hooks = CandidateBundleTestHooks::new(None);
        let prepared = prepare_test_candidate_bundle(&fixture, &mut hooks)
            .expect("v5 candidate bundle prepares");
        let canonical = bundle_journal_v5(&prepared);
        let bytes = serialize_bundle_journal_v5(&canonical).expect("v5 journal serializes");

        let mut wrong_marker = canonical.clone();
        wrong_marker.index_lock_marker.sha256 = hex_digest(digest(b"wrong marker reference"));
        assert!(validate_bundle_journal_v5(&wrong_marker).is_err());
        let mut wrong_marker_size = canonical.clone();
        wrong_marker_size.index_lock_marker.size =
            wrong_marker_size.index_lock_marker.size.saturating_add(1);
        assert!(validate_bundle_journal_v5(&wrong_marker_size).is_err());

        for invalid in [
            {
                let text = std::str::from_utf8(&bytes).expect("journal is UTF-8");
                text.replacen("\"version\":5", "\"version\":5,\"version\":5", 1)
                    .into_bytes()
            },
            {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("journal value parses");
                value
                    .as_object_mut()
                    .expect("journal is an object")
                    .insert("unknown".to_owned(), serde_json::Value::Bool(true));
                serde_json::to_vec(&value).expect("unknown journal fixture serializes")
            },
            {
                let mut value = bytes.clone();
                value.push(b'\n');
                value
            },
        ] {
            fs::write(journal_path(root), invalid).expect("invalid journal fixture writes");
            assert!(read_journal(root).is_err());
            fs::remove_file(journal_path(root)).expect("invalid journal fixture removes");
        }

        let mut cross_bound = canonical;
        cross_bound.reference.object_format = GitObjectFormat::Sha256;
        let marker = candidate_bundle_v5::index_lock_marker_bytes_v5(&cross_bound.reference)
            .expect("cross-bound marker serializes structurally");
        cross_bound.index_lock_marker = candidate_bundle_v5::canonical_bytes_reference_v5(&marker)
            .expect("cross-bound marker reference builds");
        write_journal(root, &PendingMergeJournal::BundleV5(cross_bound))
            .expect("cross-bound structural journal publishes");
        assert!(matches!(
            recovery_status(root),
            Err(GitError::RecoveryConflict)
        ));
        candidate_bundle_v5::revalidate_prepared_candidate_bundle_v5(root, &prepared)
            .expect("cross-bound journal preserves stable bundle");
    }

    #[test]
    fn v5_candidate_bundle_rejects_a_guard_from_another_vault_root() {
        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let unrelated = TestDirectory::new();
        let wrong_guard = VaultMutationGuard::acquire(unrelated.path())
            .expect("unrelated mutation guard acquires");
        let mut hooks = CandidateBundleTestHooks::new(None);

        assert!(matches!(
            candidate_bundle_v5::prepare_candidate_bundle_v5_with_hooks(
                &wrong_guard,
                &fixture.git,
                &fixture.transaction,
                &mut hooks,
            ),
            Err(GitError::RecoveryConflict)
        ));
        assert!(candidate_bundle_scratch_paths(fixture.vault.root()).is_empty());
        assert!(
            !recovery_status(fixture.vault.root())
                .expect("target root remains clean")
                .pending_transaction
        );
    }

    #[test]
    fn v5_prepublish_checkpoint_failures_retain_nonblocking_scratch() {
        use candidate_bundle_v5::CandidateBundlePrepareCheckpointV5 as Point;

        for point in [
            Point::ScratchCreated,
            Point::CandidateCopied,
            Point::CandidateMutated,
            Point::ManifestWritten,
            Point::BeforePublish,
        ] {
            let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
            let root = fixture.vault.root();
            let mut fault =
                CandidateBundleTestHooks::new(Some(CandidateBundleTestAction::FailAt(point)));
            assert!(prepare_test_candidate_bundle(&fixture, &mut fault).is_err());
            let retained = candidate_bundle_scratch_paths(root);
            assert_eq!(retained.len(), 1, "{point:?} must retain its scratch");
            assert_eq!(
                recovery_status(root).expect("scratch-only status inspects"),
                RecoveryStatus {
                    pending_transaction: false,
                    retained_candidate_scratch_count: 1,
                },
                "{point:?} must not block as an active transaction"
            );
            assert!(
                exact_reserved_private_names(root)
                    .expect("legacy namespace remains clear")
                    .is_empty()
            );

            let mut next = CandidateBundleTestHooks::new(None);
            let prepared = prepare_test_candidate_bundle(&fixture, &mut next)
                .expect("a later token prepares despite retained scratch");
            assert_eq!(candidate_bundle_scratch_paths(root), retained);
            assert_eq!(
                recovery_status(root).expect("successor status inspects"),
                RecoveryStatus {
                    pending_transaction: true,
                    retained_candidate_scratch_count: 1,
                }
            );
            candidate_bundle_v5::revalidate_prepared_candidate_bundle_v5(root, &prepared)
                .expect("successor stable bundle revalidates");
        }
    }

    #[test]
    fn v5_partial_candidate_lock_and_manifest_are_retained_and_do_not_block_next_token() {
        for action in [
            CandidateBundleTestAction::PartialCandidate,
            CandidateBundleTestAction::CandidateLock,
            CandidateBundleTestAction::PartialManifest,
        ] {
            let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
            let root = fixture.vault.root();
            let mut fault = CandidateBundleTestHooks::new(Some(action));
            assert!(prepare_test_candidate_bundle(&fixture, &mut fault).is_err());
            let retained = candidate_bundle_scratch_paths(root);
            assert_eq!(retained.len(), 1, "{action:?} retains one scratch");
            let scratch = &retained[0];
            match action {
                CandidateBundleTestAction::PartialCandidate => assert_eq!(
                    fs::read(scratch.join(candidate_bundle_v5::CANDIDATE_BUNDLE_INDEX_V5))
                        .expect("partial candidate reads"),
                    b"partial candidate index"
                ),
                CandidateBundleTestAction::CandidateLock => assert_eq!(
                    fs::read(appended_lock_path(
                        &scratch.join(candidate_bundle_v5::CANDIDATE_BUNDLE_INDEX_V5)
                    ))
                    .expect("candidate lock reads"),
                    b"foreign candidate lock"
                ),
                CandidateBundleTestAction::PartialManifest => assert_eq!(
                    fs::read(scratch.join(candidate_bundle_v5::CANDIDATE_BUNDLE_MANIFEST_V5))
                        .expect("partial manifest reads"),
                    b"{\"version\":5"
                ),
                _ => unreachable!(),
            }
            assert_eq!(
                recovery_status(root).expect("partial scratch status inspects"),
                RecoveryStatus {
                    pending_transaction: false,
                    retained_candidate_scratch_count: 1,
                }
            );
            let mut next = CandidateBundleTestHooks::new(None);
            prepare_test_candidate_bundle(&fixture, &mut next)
                .expect("next token publishes beside retained partial scratch");
            assert_eq!(candidate_bundle_scratch_paths(root), retained);
        }
    }

    #[test]
    fn v5_critical_inventory_and_directory_identity_swaps_fail_closed() {
        for action in [
            CandidateBundleTestAction::CandidateTamper,
            CandidateBundleTestAction::ManifestTamper,
            CandidateBundleTestAction::SourceSwap,
            CandidateBundleTestAction::ParentSwap,
        ] {
            let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
            let root = fixture.vault.root();
            let mut fault = CandidateBundleTestHooks::new(Some(action));
            assert!(prepare_test_candidate_bundle(&fixture, &mut fault).is_err());
            fault.restore_relocation();
            assert!(
                candidate_bundle_v5::inspect_candidate_bundle_namespace_v5(root)
                    .expect("restored scratch namespace inspects")
                    .stable_bundle_basename
                    .is_none(),
                "{action:?} must not publish a stable bundle"
            );
            assert_eq!(candidate_bundle_scratch_paths(root).len(), 1);
            assert_eq!(
                recovery_status(root).expect("failed critical audit status inspects"),
                RecoveryStatus {
                    pending_transaction: false,
                    retained_candidate_scratch_count: 1,
                }
            );
        }
    }

    #[test]
    fn v5_foreign_stable_collision_is_preserved_without_replacement() {
        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let root = fixture.vault.root();
        let mut fault =
            CandidateBundleTestHooks::new(Some(CandidateBundleTestAction::StableCollision));
        assert!(prepare_test_candidate_bundle(&fixture, &mut fault).is_err());
        assert_eq!(candidate_bundle_scratch_paths(root).len(), 1);
        let stable = fs::read_dir(root.join(VAULT_LOCAL_DIRECTORY))
            .expect("candidate namespace enumerates")
            .map(|entry| entry.expect("candidate namespace entry reads"))
            .find(|entry| {
                entry.file_name().to_str().is_some_and(|name| {
                    name.starts_with(candidate_bundle_v5::CANDIDATE_BUNDLE_STABLE_PREFIX_V5)
                })
            })
            .expect("foreign stable collision remains")
            .path();
        assert_eq!(
            fs::read(stable.join("foreign")).expect("foreign stable bytes read"),
            b"foreign stable owner"
        );
        assert!(recovery_status(root).is_err());
    }

    #[test]
    fn v5_external_live_index_drift_is_preserved_and_rejected_before_publish() {
        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let root = fixture.vault.root();
        let mut fault =
            CandidateBundleTestHooks::new(Some(CandidateBundleTestAction::LiveIndexDrift));
        assert!(prepare_test_candidate_bundle(&fixture, &mut fault).is_err());
        assert!(
            index_entry_map(&fixture.git)
                .expect("external stage map inspects")
                .contains_key(&("external-index-owner.bin".to_owned(), 0))
        );
        assert_eq!(candidate_bundle_scratch_paths(root).len(), 1);
        assert!(
            !recovery_status(root)
                .expect("live-drift scratch status inspects")
                .pending_transaction
        );

        let mut next = CandidateBundleTestHooks::new(None);
        prepare_test_candidate_bundle(&fixture, &mut next)
            .expect("next preparation includes and preserves the external stage");
        assert!(
            index_entry_map(&fixture.git)
                .expect("external stage map re-inspects")
                .contains_key(&("external-index-owner.bin".to_owned(), 0))
        );
    }

    #[test]
    fn v5_token_collision_retries_without_touching_existing_scratch() {
        const COLLISION: &str = "11111111111111111111111111111111";
        const SUCCESSOR: &str = "22222222222222222222222222222222";

        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let root = fixture.vault.root();
        let existing_basename =
            candidate_bundle_v5::candidate_bundle_scratch_basename_v5(COLLISION)
                .expect("collision basename validates");
        let existing = root.join(VAULT_LOCAL_DIRECTORY).join(existing_basename);
        fs::create_dir(&existing).expect("collision scratch creates");
        fs::write(existing.join("sentinel"), b"foreign retained scratch")
            .expect("collision sentinel writes");
        let mut hooks = CandidateBundleTestHooks::with_tokens([COLLISION, SUCCESSOR]);
        let prepared = prepare_test_candidate_bundle(&fixture, &mut hooks)
            .expect("token collision retries with a new token");
        assert_eq!(prepared.inventory.manifest.token, SUCCESSOR);
        assert_eq!(
            fs::read(existing.join("sentinel")).expect("collision sentinel re-reads"),
            b"foreign retained scratch"
        );
        assert_eq!(candidate_bundle_scratch_paths(root).len(), 1);
        assert_eq!(
            recovery_status(root).expect("collision successor status inspects"),
            RecoveryStatus {
                pending_transaction: true,
                retained_candidate_scratch_count: 1,
            }
        );
    }

    #[test]
    fn v5_after_publish_error_retains_a_complete_pending_stable_bundle() {
        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let root = fixture.vault.root();
        let mut hooks = CandidateBundleTestHooks::new(Some(CandidateBundleTestAction::FailAt(
            candidate_bundle_v5::CandidateBundlePrepareCheckpointV5::AfterPublish,
        )));
        assert!(prepare_test_candidate_bundle(&fixture, &mut hooks).is_err());
        assert!(candidate_bundle_scratch_paths(root).is_empty());
        let namespace = candidate_bundle_v5::inspect_candidate_bundle_namespace_v5(root)
            .expect("post-publish stable namespace validates");
        let stable = namespace
            .stable_bundle_basename
            .expect("post-publish stable remains pending");
        candidate_bundle_v5::validate_candidate_bundle_inventory_v5(root, &stable, None)
            .expect("post-publish stable inventory remains complete");
        assert_eq!(
            recovery_status(root).expect("post-publish status inspects"),
            RecoveryStatus {
                pending_transaction: true,
                retained_candidate_scratch_count: 0,
            }
        );
    }

    #[test]
    fn v5_postpublish_byte_identical_clone_cannot_replace_the_held_identity() {
        let fixture = create_candidate_bundle_preparation_fixture(GitObjectFormat::Sha1);
        let root = fixture.vault.root();
        let mut hooks =
            CandidateBundleTestHooks::new(Some(CandidateBundleTestAction::StableCloneSwap));
        assert!(prepare_test_candidate_bundle(&fixture, &mut hooks).is_err());
        hooks.restore_relocation();

        let namespace = candidate_bundle_v5::inspect_candidate_bundle_namespace_v5(root)
            .expect("restored original stable namespace validates");
        let stable = namespace
            .stable_bundle_basename
            .expect("the original moved scratch remains stable");
        candidate_bundle_v5::validate_candidate_bundle_inventory_v5(root, &stable, None)
            .expect("restored original stable inventory validates");
        assert!(candidate_bundle_scratch_paths(root).is_empty());
        assert!(
            recovery_status(root)
                .expect("restored stable status inspects")
                .pending_transaction
        );
    }

    #[test]
    fn stable_v4_journal_recovers_if_prelock_removal_was_not_durable() {
        let fixture = create_rename_recovery_fixture();
        let transaction = MergeJournalPayload::Rename(fixture.journal.clone());
        let mut prepared =
            prepare_index_cas(&fixture.git, &transaction).expect("CAS prepares with prelock");
        let reservation = prepared.prelock.clone();
        write_cas_journal(fixture.vault.root(), &mut prepared, transaction)
            .expect("stable v4 journal publishes");
        assert!(!prelock_reservation_path(fixture.vault.root()).exists());
        install_prelock_reservation(fixture.vault.root(), &reservation)
            .expect("post-crash prelock visibility is reconstructed");

        assert!(recover_pending(&fixture.vault, &fixture.git).expect("v4 state recovers"));
        fixture.assert_final_state();
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn abandoned_prejournal_cas_reservation_is_recognized_and_cleaned() {
        let fixture = create_rename_recovery_fixture();
        let transaction = MergeJournalPayload::Rename(fixture.journal.clone());
        let mut prepared =
            prepare_index_cas(&fixture.git, &transaction).expect("prejournal reservation prepares");
        prepared.disarm();
        drop(prepared);
        assert!(!journal_path(fixture.vault.root()).exists());
        assert!(prelock_reservation_path(fixture.vault.root()).is_file());
        assert!(
            has_pending_recovery(fixture.vault.root())
                .expect("abandoned reservation reports pending")
        );
        fixture.assert_original_index();

        assert!(
            recover_pending(&fixture.vault, &fixture.git).expect("abandoned reservation cleans")
        );
        fixture.assert_original_index();
        assert!(
            !has_pending_recovery(fixture.vault.root())
                .expect("clean reservation no longer pending")
        );
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn external_index_update_before_lock_wins_without_lost_update() {
        let fixture = create_rename_recovery_fixture();
        let source_before = fs::read(&fixture.source_target).expect("source snapshots");
        let destination_before =
            fs::read(&fixture.destination_target).expect("destination snapshots");
        let transaction = MergeJournalPayload::Rename(fixture.journal.clone());
        let root = fixture.vault.root().to_path_buf();
        let result = prepare_index_cas_with_hook(&fixture.git, &transaction, || {
            fs::write(
                root.join("external.md.enc"),
                b"external ciphertext-only update",
            )
            .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
            assert!(test_git(&root, ["add", "external.md.enc"]));
            Ok(())
        });
        assert!(matches!(result, Err(GitError::IndexChanged)));
        assert!(
            fixture
                .git
                .stage_zero("external.md.enc")
                .expect("external stage inspects")
                .is_some()
        );
        assert_eq!(
            fs::read(&fixture.source_target).expect("source re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(&fixture.destination_target).expect("destination re-reads"),
            destination_before
        );
        assert!(!journal_path(fixture.vault.root()).exists());
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn cas_v4_recovery_advances_from_durable_marker_and_blocks_external_git() {
        let fixture = create_rename_recovery_fixture();
        let index_before =
            read_index_snapshot(&index_path(fixture.vault.root())).expect("old index snapshots");
        let journal = install_rename_cas_journal(&fixture);
        assert_eq!(
            classify_cas_index_lock(fixture.vault.root(), &journal)
                .expect("owned marker classifies"),
            CasIndexLockState::Marker
        );
        let unrelated = fixture.vault.root().join("unrelated.bin");
        fs::write(&unrelated, b"ciphertext-only-test-data").expect("unrelated fixture writes");
        assert!(!test_git(fixture.vault.root(), ["add", "unrelated.bin"]));
        let index_after_failed_git =
            read_index_snapshot(&index_path(fixture.vault.root())).expect("locked index re-reads");
        assert_eq!(index_after_failed_git.sha256, index_before.sha256);

        assert!(recover_pending(&fixture.vault, &fixture.git).expect("v4 recovery succeeds"));
        fixture.assert_final_state();
        assert!(!journal_path(fixture.vault.root()).exists());
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn cas_v4_recovery_publishes_candidate_already_installed_in_index_lock() {
        let fixture = create_rename_recovery_fixture();
        let journal = install_rename_cas_journal(&fixture);
        fixture.write_result_to_destination();
        fixture.delete_source();
        let candidate = index_candidate_path(fixture.vault.root(), &journal.candidate_file);
        let lock = index_lock_path(fixture.vault.root());
        let source = File::open(&candidate).expect("candidate opens");
        let destination = File::open(&lock).expect("marker opens");
        let outcome = atomic_replace_verified_file(&candidate, source, &lock, destination)
            .expect("candidate installs into index lock");
        assert_eq!(outcome.source_parent_sync, ParentSyncStatus::Synced);
        assert_eq!(outcome.destination_parent_sync, ParentSyncStatus::Synced);
        assert_eq!(
            classify_cas_index_lock(fixture.vault.root(), &journal)
                .expect("candidate lock classifies"),
            CasIndexLockState::Candidate
        );

        assert!(recover_pending(&fixture.vault, &fixture.git).expect("v4 recovery publishes"));
        fixture.assert_final_state();
        assert!(!journal_path(fixture.vault.root()).exists());
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn cas_v4_reconciles_both_index_move_error_poststates() {
        let fixture = create_rename_recovery_fixture();
        let journal = install_rename_cas_journal(&fixture);
        let injected = io::Error::other("injected namespace move error");
        assert!(matches!(
            reconcile_candidate_to_lock_error(fixture.vault.root(), &journal, &injected),
            Err(GitError::Io {
                operation: GitIoOperation::SyncGitState,
                ..
            })
        ));

        let candidate = index_candidate_path(fixture.vault.root(), &journal.candidate_file);
        let lock = index_lock_path(fixture.vault.root());
        let source = File::open(&candidate).expect("candidate opens");
        let destination = File::open(&lock).expect("marker opens");
        atomic_replace_verified_file(&candidate, source, &lock, destination)
            .expect("first move fixture commits");
        assert!(matches!(
            reconcile_candidate_to_lock_error(fixture.vault.root(), &journal, &injected),
            Err(GitError::DurabilityNotConfirmed)
        ));
        assert!(matches!(
            reconcile_lock_to_index_error(fixture.vault.root(), &journal, &injected),
            Err(GitError::Io {
                operation: GitIoOperation::SyncGitState,
                ..
            })
        ));

        let index = index_path(fixture.vault.root());
        let source = File::open(&lock).expect("candidate lock opens");
        let destination = File::open(&index).expect("old index opens");
        atomic_replace_verified_file(&lock, source, &index, destination)
            .expect("second move fixture commits");
        assert!(matches!(
            reconcile_lock_to_index_error(fixture.vault.root(), &journal, &injected),
            Err(GitError::DurabilityNotConfirmed)
        ));
    }

    #[test]
    fn cas_v4_recovery_rejects_tampered_candidate_without_worktree_mutation() {
        let fixture = create_rename_recovery_fixture();
        let source_before = fs::read(&fixture.source_target).expect("source snapshots");
        let destination_before =
            fs::read(&fixture.destination_target).expect("destination snapshots");
        let journal = install_rename_cas_journal(&fixture);
        let candidate = index_candidate_path(fixture.vault.root(), &journal.candidate_file);
        fs::write(&candidate, b"tampered candidate").expect("candidate tampers");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict | GitError::IndexChanged)
        ));
        assert_eq!(
            fs::read(&fixture.source_target).expect("source re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(&fixture.destination_target).expect("destination re-reads"),
            destination_before
        );
        fixture.assert_original_index();
        assert!(journal_path(fixture.vault.root()).is_file());
        assert_eq!(
            classify_cas_index_lock(fixture.vault.root(), &journal).expect("marker remains owned"),
            CasIndexLockState::Marker
        );
    }

    #[test]
    fn cas_v4_recovery_preserves_foreign_replacement_lock() {
        let fixture = create_rename_recovery_fixture();
        let source_before = fs::read(&fixture.source_target).expect("source snapshots");
        let destination_before =
            fs::read(&fixture.destination_target).expect("destination snapshots");
        let journal = install_rename_cas_journal(&fixture);
        let lock = index_lock_path(fixture.vault.root());
        let foreign = b"FOREIGN_REPLACEMENT_LOCK";
        fs::write(&lock, foreign).expect("owned marker is replaced by foreign bytes");

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert_eq!(fs::read(&lock).expect("foreign lock re-reads"), foreign);
        assert_eq!(
            fs::read(&fixture.source_target).expect("source re-reads"),
            source_before
        );
        assert_eq!(
            fs::read(&fixture.destination_target).expect("destination re-reads"),
            destination_before
        );
        assert!(journal_path(fixture.vault.root()).is_file());
        assert!(index_candidate_path(fixture.vault.root(), &journal.candidate_file).is_file());
    }

    #[test]
    fn cas_v4_published_receipt_preserves_later_external_index_update_and_lock() {
        let fixture = create_rename_recovery_fixture();
        let journal = install_rename_cas_journal(&fixture);
        fixture.write_result_to_destination();
        fixture.delete_source();
        fixture.update_index();
        fixture.assert_final_state();
        assert!(journal_path(fixture.vault.root()).is_file());
        assert_no_cas_private_files(fixture.vault.root());

        let unrelated = fixture.vault.root().join("later.bin");
        fs::write(&unrelated, b"later ciphertext-only state").expect("later file writes");
        assert!(test_git(fixture.vault.root(), ["add", "later.bin"]));
        let later_index =
            read_index_snapshot(&index_path(fixture.vault.root())).expect("later index snapshots");
        assert_ne!(later_index.sha256, journal.candidate_index_sha256);
        let foreign_lock = index_lock_path(fixture.vault.root());
        fs::write(&foreign_lock, b"NEW_FOREIGN_LOCK").expect("new foreign lock installs");

        assert!(
            recover_pending(&fixture.vault, &fixture.git)
                .expect("published receipt recovery succeeds")
        );
        assert_eq!(
            read_index_snapshot(&index_path(fixture.vault.root()))
                .expect("later index re-reads")
                .sha256,
            later_index.sha256
        );
        assert_eq!(
            fs::read(&foreign_lock).expect("foreign lock remains"),
            b"NEW_FOREIGN_LOCK"
        );
        assert!(!journal_path(fixture.vault.root()).exists());
    }

    #[test]
    fn cas_v4_recovery_cleans_exact_published_state() {
        let fixture = create_rename_recovery_fixture();
        let _journal = install_rename_cas_journal(&fixture);
        fixture.write_result_to_destination();
        fixture.delete_source();
        fixture.update_index();
        fixture.assert_final_state();
        assert!(journal_path(fixture.vault.root()).is_file());

        assert!(
            recover_pending(&fixture.vault, &fixture.git).expect("exact published state recovers")
        );
        fixture.assert_final_state();
        assert!(!journal_path(fixture.vault.root()).exists());
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn cas_v4_published_receipt_rejects_later_target_index_change() {
        let fixture = create_rename_recovery_fixture();
        let _journal = install_rename_cas_journal(&fixture);
        fixture.write_result_to_destination();
        fixture.delete_source();
        fixture.update_index();
        fixture.assert_final_state();
        assert!(test_git(
            fixture.vault.root(),
            [
                "update-index",
                "--force-remove",
                "--",
                "renamed file.md.enc"
            ]
        ));

        assert!(matches!(
            recover_pending(&fixture.vault, &fixture.git),
            Err(GitError::RecoveryConflict)
        ));
        assert!(journal_path(fixture.vault.root()).is_file());
        assert!(
            fixture
                .git
                .stage_zero("renamed file.md.enc")
                .expect("changed target inspects")
                .is_none()
        );
        assert_eq!(
            VaultMutationGuard::acquire(fixture.vault.root())
                .expect("worktree guard acquires")
                .inspect(&fixture.destination_target)
                .expect("destination inspects"),
            CurrentTarget::File(fixture.result_digest)
        );
        assert_no_cas_private_files(fixture.vault.root());
    }

    #[test]
    fn split_rename_journal_rejects_mixed_object_id_widths() {
        let fixture = create_rename_recovery_fixture();
        let mut journal = fixture.journal.clone();
        journal.destination_stage.oid = "a".repeat(if journal.result_oid.len() == 40 {
            64
        } else {
            40
        });

        assert!(matches!(
            validate_rename_journal(&journal),
            Err(GitError::InvalidJournal)
        ));
    }

    #[test]
    fn conflict_identity_preflight_is_global_and_read_only() {
        let (directory, vault) = create_conflicted_repository();
        let git = Git::open(directory.path()).expect("Git repository opens");
        let before = git.unmerged_entries().expect("conflicts enumerate");
        let first = before.values().next().expect("one conflict exists");
        let source = vault
            .read(&first.logical_path)
            .expect("worktree stage authenticates");
        let second_path = LogicalPath::parse_canonical("z-second.md").expect("test path is valid");
        let mut second_header = source.header.clone();
        second_header.logical_path = second_path.as_str().to_owned();
        let second_ours = vault
            .encrypt_merge_result(
                &second_path,
                &second_header,
                b"second ours\n",
                1_783_699_204_000,
                false,
            )
            .expect("same identity can be encrypted for the adversarial fixture");
        let second_theirs = vault
            .encrypt_merge_result(
                &second_path,
                &second_header,
                b"second theirs\n",
                1_783_699_205_000,
                false,
            )
            .expect("second adversarial stage encrypts");
        drop(source);
        let ours_oid = git
            .write_object(&second_ours.bytes)
            .expect("fixture object writes");
        let theirs_oid = git
            .write_object(&second_theirs.bytes)
            .expect("fixture object writes");
        let mut conflicts = before.clone();
        conflicts.insert(
            "z-second.md.enc".to_owned(),
            ConflictEntry {
                physical_path: "z-second.md.enc".to_owned(),
                logical_path: second_path,
                stages: [
                    None,
                    Some(StageEntry {
                        mode: "100644".to_owned(),
                        oid: ours_oid,
                    }),
                    Some(StageEntry {
                        mode: "100644".to_owned(),
                        oid: theirs_oid,
                    }),
                ],
            },
        );
        let tracked = tracked_identity_index(&vault, &git).expect("identities inspect");
        assert!(matches!(
            preflight_conflict_identities(&vault, &git, &conflicts, &tracked),
            Err(GitError::UnsupportedConflictEntry)
        ));
        assert_eq!(git.unmerged_entries().expect("conflicts reinspect"), before);
        assert!(!vault.root().join("z-second.md.enc").exists());
        assert!(
            read_journal(vault.root())
                .expect("journal inspects")
                .is_none()
        );
    }
}
