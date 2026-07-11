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

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use inex_core::atomic::{
    CurrentTarget, GIT_ATTRIBUTES_FILE, GIT_IGNORE_FILE, ParentSyncStatus, VAULT_LOCAL_DIRECTORY,
    VaultMutationGuard, WriteCondition, open_file_matches_path_and_is_single_link,
    path_is_supported_local_filesystem, sync_directory,
};
use inex_core::crypto::{DecryptedDocument, EncryptedDocument};
use inex_core::format;
use inex_core::path::{LogicalPath, MAX_LOGICAL_PATH_BYTES};
use inex_core::tree::{self, TreeEntryKind};
use inex_core::vault::{MAX_EDRY_ENVELOPE_BYTES, Vault, VaultError};
use inex_core::vault_config::{KdfPolicy, MAX_VAULT_JSON_BYTES, VaultConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Exact repository attribute installed for encrypted Markdown objects.
pub const ATTRIBUTES_RULE: &str = "*.md.enc -text -diff merge=inex";

/// Exact repository-local ignore rule for private runtime state.
pub const IGNORE_RULE: &str = "/.vault-local/";

const DRIVER_NAME: &str = "Inex encrypted Markdown (locked-safe)";
const JOURNAL_FILE: &str = "git-merge-journal-v1.json";
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPOSITORY_METADATA_BYTES: usize = 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 64 * 1024;
const MAX_CONFLICTS: usize = 100_000;
const MAX_GIT_PATH_BYTES: usize = MAX_LOGICAL_PATH_BYTES + ".enc".len();
const MINIMUM_GIT_VERSION: (u32, u32) = (2, 36);
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
    /// Number of pending transactions completed (zero or one in v1).
    pub recovered_transactions: usize,
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
    /// Split indexes reference a second file outside the v1 durability model.
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
    let vault_tree =
        tree::scan_vault_tree(&git.root).map_err(|_| GitError::UnsafeRepositoryMetadata)?;
    git.sync_configuration()?;
    let ignore_changed = ensure_repository_line(&git.root, GIT_IGNORE_FILE, IGNORE_RULE)?;
    let attributes_changed =
        ensure_repository_line(&git.root, GIT_ATTRIBUTES_FILE, ATTRIBUTES_RULE)?;
    sync_directory(&git.root).map_err(|_| GitError::DurabilityNotConfirmed)?;
    let driver_command = installed_driver_command()?;

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

/// Inspect whether a structurally valid encrypted merge journal is pending.
///
/// This locked-safe status check reads only bounded path/OID/ciphertext-digest
/// metadata. It does not start Git, unlock a vault, or mutate recovery state.
/// A `true` result still requires [`recover`] with an authenticated vault.
///
/// # Errors
///
/// Returns [`GitError`] when the journal entry is link-like, hard-linked,
/// oversized, truncated, or fails the strict v1 schema.
pub fn has_pending_recovery(vault_root: &Path) -> Result<bool, GitError> {
    let _guard = VaultMutationGuard::acquire(vault_root).map_err(map_atomic_error)?;
    Ok(read_journal(vault_root)?.is_some())
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
    let tracked_identities = tracked_identity_index(vault, &git)?;
    for conflict in conflicts.values() {
        git.verify_attributes_for_path(&conflict.physical_path)?;
    }
    preflight_conflict_identities(vault, &git, &conflicts, &tracked_identities)?;
    let mut report = MergeReport {
        recovered_transactions: usize::from(recovered),
        ..MergeReport::default()
    };

    for conflict in conflicts.values() {
        let prepared = prepare_result(vault, &git, conflict, &tracked_identities, modified_at_ms)?;
        commit_result(vault, &git, conflict, &prepared)?;
        if prepared.unresolved {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConflictEntry {
    physical_path: String,
    logical_path: LogicalPath,
    stages: [Option<StageEntry>; 3],
}

struct PreparedResult {
    encrypted: EncryptedDocument,
    result_oid: String,
    unresolved: bool,
    stage_ciphertexts: [Option<Vec<u8>>; 3],
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

struct Git {
    executable: PathBuf,
    root: PathBuf,
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
        let git = Self {
            executable: discover_git_executable()?,
            root,
        };
        git.ensure_supported_version()?;
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
        parse_unmerged_entries(&output)
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
        Ok(entries)
    }

    fn read_object(&self, oid: &str) -> Result<Vec<u8>, GitError> {
        validate_oid(oid)?;
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
        validate_oid(&oid)?;
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
        if records.len() != 1 {
            return Err(GitError::MalformedGitOutput);
        }
        let (stage, path) = parse_index_record(records[0])?;
        if path != physical_path || stage.0 != 0 {
            return Err(GitError::MalformedGitOutput);
        }
        validate_mode(&stage.1.mode)?;
        Ok(Some(stage.1))
    }

    fn update_index(&self, physical_path: &str, mode: &str, oid: &str) -> Result<(), GitError> {
        validate_physical_path(physical_path)?;
        validate_mode(mode)?;
        validate_oid(oid)?;
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

    fn sync_object(&self, oid: &str) -> Result<(), GitError> {
        validate_oid(oid)?;
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
        let git_directory = self.root.join(".git");
        validate_local_directory(&git_directory)?;
        sync_regular_file(&git_directory.join("index"), MAX_GIT_OUTPUT_BYTES)?;
        sync_directory(&git_directory).map_err(|_| GitError::DurabilityNotConfirmed)
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
            .args(GIT_COMMAND_PREFIX_ARGUMENTS)
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
        copy_platform_process_environment(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| io_error(GitIoOperation::SpawnGit, &error))?;
        let mut stdout = child.stdout.take().ok_or(GitError::Io {
            operation: GitIoOperation::CommunicateGit,
            kind: io::ErrorKind::BrokenPipe,
        })?;
        let mut child_stdin = child.stdin.take();
        let mut output = Vec::with_capacity(maximum_output.min(64 * 1024));
        let read_result = std::thread::scope(|scope| {
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

            let read = read_bounded(&mut stdout, &mut output, maximum_output);
            if matches!(read, Err(ReadBoundedError::TooLarge)) {
                let _ = child.kill();
            }
            let write = writer.map(std::thread::ScopedJoinHandle::join).transpose();
            (read, write)
        });
        let status = child
            .wait()
            .map_err(|error| io_error(GitIoOperation::CommunicateGit, &error))?;

        match read_result.0 {
            Ok(()) => {}
            Err(ReadBoundedError::TooLarge) => {
                return Err(GitError::GitOutputTooLarge { operation });
            }
            Err(ReadBoundedError::Io(error)) => {
                return Err(io_error(GitIoOperation::CommunicateGit, &error));
            }
        }
        let written = read_result.1.map_err(|_| GitError::Io {
            operation: GitIoOperation::CommunicateGit,
            kind: io::ErrorKind::Other,
        })?;
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
    let text = executable
        .to_str()
        .filter(|_| metadata.file_type().is_file())
        .ok_or(GitError::DriverExecutableUnavailable)?;
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
    tracked_identities: &BTreeMap<String, String>,
    modified_at_ms: i64,
) -> Result<PreparedResult, GitError> {
    let mut stage_ciphertexts: [Option<Vec<u8>>; 3] = [None, None, None];
    let mut documents: [Option<DecryptedDocument>; 3] = [None, None, None];
    for (index, stage) in conflict.stages.iter().enumerate() {
        if let Some(stage) = stage {
            let ciphertext = git.read_object(&stage.oid)?;
            let document = vault
                .authenticate_committed_envelope(&conflict.logical_path, &ciphertext)
                .map_err(|_| GitError::StageAuthenticationFailed)?;
            stage_ciphertexts[index] = Some(ciphertext);
            documents[index] = Some(document);
        }
    }
    for document in documents.iter().flatten() {
        if tracked_identities
            .get(&document.header.file_id.to_string())
            .is_some_and(|path| path != conflict.logical_path.as_str())
        {
            return Err(GitError::UnsupportedConflictEntry);
        }
    }

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
    let identity = documents[1]
        .as_ref()
        .or(documents[2].as_ref())
        .or(documents[0].as_ref())
        .ok_or(GitError::UnsupportedConflictEntry)?;
    let encrypted = vault.encrypt_merge_result(
        &conflict.logical_path,
        &identity.header,
        merged.as_bytes(),
        modified_at_ms.max(identity.header.created_at_ms),
        unresolved,
    )?;
    drop(merged);
    drop(documents);
    let result_oid = git.write_object(&encrypted.bytes)?;
    Ok(PreparedResult {
        encrypted,
        result_oid,
        unresolved,
        stage_ciphertexts,
    })
}

fn tracked_identity_index(vault: &Vault, git: &Git) -> Result<BTreeMap<String, String>, GitError> {
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
            .insert(file_id, logical_path.as_str().to_owned())
            .is_some()
        {
            return Err(GitError::UnsupportedConflictEntry);
        }
    }
    Ok(identities)
}

fn preflight_conflict_identities(
    vault: &Vault,
    git: &Git,
    conflicts: &BTreeMap<String, ConflictEntry>,
    tracked_identities: &BTreeMap<String, String>,
) -> Result<(), GitError> {
    let mut identity_paths = tracked_identities.clone();
    for conflict in conflicts.values() {
        for stage in conflict.stages.iter().flatten() {
            let ciphertext = git.read_object(&stage.oid)?;
            let document = vault
                .authenticate_committed_envelope(&conflict.logical_path, &ciphertext)
                .map_err(|_| GitError::StageAuthenticationFailed)?;
            let file_id = document.header.file_id.to_string();
            match identity_paths.get(&file_id) {
                Some(existing_path) if existing_path != conflict.logical_path.as_str() => {
                    return Err(GitError::UnsupportedConflictEntry);
                }
                Some(_) => {}
                None => {
                    identity_paths.insert(file_id, conflict.logical_path.as_str().to_owned());
                }
            }
        }
    }
    Ok(())
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

fn commit_result(
    vault: &Vault,
    git: &Git,
    conflict: &ConflictEntry,
    prepared: &PreparedResult,
) -> Result<(), GitError> {
    let guard = VaultMutationGuard::acquire(vault.root()).map_err(map_atomic_error)?;
    ensure_no_journal(vault.root())?;
    let current = git.unmerged_entries()?;
    if current.get(&conflict.physical_path) != Some(conflict) {
        return Err(GitError::IndexChanged);
    }

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
    write_journal(vault.root(), &journal)?;

    let outcome = guard
        .write(&target, &prepared.encrypted.bytes, condition)
        .map_err(map_atomic_error)?;
    if outcome.parent_sync != ParentSyncStatus::Synced {
        return Err(GitError::DurabilityNotConfirmed);
    }
    if git.unmerged_entries()?.get(&conflict.physical_path) != Some(conflict) {
        return Err(GitError::IndexChanged);
    }
    git.update_index(
        &conflict.physical_path,
        &journal.result_mode,
        &prepared.result_oid,
    )?;
    verify_committed_state(git, &guard, &target, &journal, result_digest)?;
    remove_journal(vault.root(), &journal)
}

fn recover_pending(vault: &Vault, git: &Git) -> Result<bool, GitError> {
    let guard = VaultMutationGuard::acquire(vault.root()).map_err(map_atomic_error)?;
    let Some(journal) = read_journal(vault.root())? else {
        return Ok(false);
    };
    validate_journal(&journal)?;
    let logical_path = validate_physical_path(&journal.physical_path)?;
    let result = git.read_object(&journal.result_oid)?;
    let result_digest = digest(&result);
    if hex_digest(result_digest) != journal.result_sha256 {
        return Err(GitError::RecoveryConflict);
    }
    vault
        .authenticate_committed_envelope(&logical_path, &result)
        .map_err(|_| GitError::RecoveryConflict)?;

    let target = vault
        .root()
        .join(logical_path.to_ciphertext_relative_path());
    let unmerged = git.unmerged_entries()?;
    let current_conflict = unmerged.get(&journal.physical_path);
    let stage_zero = if current_conflict.is_none() {
        git.stage_zero(&journal.physical_path)?
    } else {
        None
    };
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
        git.update_index(
            &journal.physical_path,
            &journal.result_mode,
            &journal.result_oid,
        )?;
    }
    verify_committed_state(git, &guard, &target, &journal, result_digest)?;
    remove_journal(vault.root(), &journal)?;
    Ok(true)
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

fn validate_journal(journal: &MergeJournal) -> Result<(), GitError> {
    if journal.version != 1 {
        return Err(GitError::InvalidJournal);
    }
    validate_physical_path(&journal.physical_path).map_err(|_| GitError::InvalidJournal)?;
    validate_mode(&journal.result_mode).map_err(|_| GitError::InvalidJournal)?;
    validate_oid(&journal.result_oid).map_err(|_| GitError::InvalidJournal)?;
    parse_hex_digest(&journal.result_sha256).map_err(|_| GitError::InvalidJournal)?;
    parse_hex_digest(&journal.expected_worktree_sha256).map_err(|_| GitError::InvalidJournal)?;
    validate_conflict_modes(&journal.stages).map_err(|_| GitError::InvalidJournal)?;
    for stage in journal.stages.iter().flatten() {
        validate_mode(&stage.mode).map_err(|_| GitError::InvalidJournal)?;
        validate_oid(&stage.oid).map_err(|_| GitError::InvalidJournal)?;
    }
    Ok(())
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(VAULT_LOCAL_DIRECTORY).join(JOURNAL_FILE)
}

fn ensure_no_journal(root: &Path) -> Result<(), GitError> {
    match fs::symlink_metadata(journal_path(root)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(GitError::JournalAlreadyExists),
        Err(error) => Err(io_error(GitIoOperation::ReadJournal, &error)),
    }
}

fn write_journal(root: &Path, journal: &MergeJournal) -> Result<(), GitError> {
    ensure_no_journal(root)?;
    let local = root.join(VAULT_LOCAL_DIRECTORY);
    let local_metadata = fs::symlink_metadata(&local)
        .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
    if is_link_or_reparse_point(&local_metadata) || !local_metadata.file_type().is_dir() {
        return Err(GitError::InvalidJournal);
    }
    let bytes = serde_json::to_vec(journal).map_err(|_| GitError::InvalidJournal)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(GitError::InvalidJournal);
    }
    let path = journal_path(root);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                GitError::JournalAlreadyExists
            } else {
                io_error(GitIoOperation::WriteJournal, &error)
            }
        })?;
    restrict_file_permissions_best_effort(&file);
    file.write_all(&bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
    sync_directory(&local).map_err(|error| io_error(GitIoOperation::WriteJournal, &error))
}

fn read_journal(root: &Path) -> Result<Option<MergeJournal>, GitError> {
    let path = journal_path(root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(GitIoOperation::ReadJournal, &error)),
    };
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(MAX_JOURNAL_BYTES).unwrap_or(u64::MAX)
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
    let journal =
        serde_json::from_slice::<MergeJournal>(&bytes).map_err(|_| GitError::InvalidJournal)?;
    validate_journal(&journal)?;
    Ok(Some(journal))
}

fn remove_journal(root: &Path, expected: &MergeJournal) -> Result<(), GitError> {
    if read_journal(root)?.as_ref() != Some(expected) {
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

    fn create_conflicted_repository() -> (TestDirectory, Vault) {
        let directory = TestDirectory::new();
        assert!(test_git(directory.path(), ["init", "-q"]));
        assert!(test_git(
            directory.path(),
            ["symbolic-ref", "HEAD", "refs/heads/baseline"]
        ));
        assert!(test_git(
            directory.path(),
            ["config", "user.email", "inex-tests@example.invalid"]
        ));
        assert!(test_git(
            directory.path(),
            ["config", "user.name", "Inex Tests"]
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
        write_journal(vault.root(), &journal).expect("journal syncs");
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
