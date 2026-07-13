//! Hardened Git plumbing for the repository-import snapshot transaction.
//!
//! This module deliberately exposes opaque plans. Callers may consume verified
//! source bytes and publish a complete staging root, but cannot manufacture a
//! source or target proof from untrusted Git output.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use inex_core::atomic::{
    FilesystemDirectoryIdentity, FilesystemFileIdentity, GIT_ATTRIBUTES_FILE, GIT_IGNORE_FILE,
    IMPORT_PUBLISH_MARKER, VAULT_LOCAL_DIRECTORY, VAULT_MUTATION_LOCK_FILE,
    filesystem_directory_identity, filesystem_file_identity,
    open_file_matches_path_and_is_single_link, sync_directory,
    verify_regular_file_has_no_alternate_data_streams,
};
#[cfg(target_os = "linux")]
use inex_core::atomic::{
    SecureSourceChild, SecureSourceDirectory, SecureSourceFile, open_secure_source_root,
};
use inex_core::format::{MAX_ASSET_PLAINTEXT_LEN, MAX_DOCUMENT_PLAINTEXT_LEN};
use inex_core::path::{AssetPath, LogicalPath};
#[cfg(target_os = "linux")]
use inex_core::path::{LogicalDir, raw_portable_case_fold_key};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    DRIVER_NAME, copy_platform_process_environment, discover_git_executable,
    installed_driver_command, validate_git_version,
};

const MAX_SOURCE_ENTRIES: usize = 100_000;
const MAX_CONTROL_ENTRIES: usize = 1_000_000;
const MAX_TREE_DEPTH: usize = 128;
const MAX_RETAINED_PATH_BYTES: usize = 256 * 1024 * 1024;
const MAX_GIT_OUTPUT: usize = 64 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;
const MAX_LFS_POINTER_BYTES: usize = 4096;
const MAX_TARGET_OBJECT_BYTES: usize = 68 * 1024 * 1024;
const TARGET_OBJECT_STREAM_CHUNK_BYTES: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const MAX_IMPORT_PLAINTEXT_BYTES: u64 = 4_294_967_296;
#[cfg(target_os = "linux")]
const MAX_MARKDOWN_PLAINTEXT_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_TARGET_FILE_BYTES: usize = 68 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_mins(1);
const GIT_TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
const IMPORT_AUTHOR: &str = "Inex Repository Import <inex-import@localhost.invalid>";
const IMPORT_MESSAGE: &[u8] = b"Initialize encrypted Inex vault\n";
const TARGET_TEMPLATE_PREFIX: &str = "repository-import-empty-template-";
const TARGET_EMPTY_HOOKS_DIRECTORY: &str = "inex-empty-hooks";
const TARGET_ATTRIBUTES: &[u8] = b"*.md.enc -text -diff merge=inex\n*.asset.enc binary\n";
const TARGET_IGNORE: &[u8] = b"/.vault-local/\n";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// A scrubbed repository-import failure.
#[derive(Clone, Debug, Error)]
pub enum RepositoryImportError {
    /// Git could not be resolved to one absolute regular executable.
    #[error("a regular Git executable could not be resolved")]
    GitExecutableUnavailable,
    /// Git is older than the frozen repository-import minimum.
    #[error("Git 2.36 or newer is required for repository import")]
    UnsupportedGitVersion,
    /// The source is not the top level of one ordinary local SHA-1 worktree.
    #[error("the source is not a supported top-level SHA-1 Git worktree")]
    UnsupportedSourceRepository,
    /// Source configuration or control state is unsafe for offline inspection.
    #[error("source Git control state is outside the repository-import profile")]
    UnsafeSourceControl,
    /// A tracked source path, mode, flag, or filesystem entry is unsupported.
    #[error("the source namespace is outside the repository-import profile")]
    UnsafeSourceEntry,
    /// Source content is dirty or changed after its snapshot was prepared.
    #[error("the source repository changed during repository import")]
    SourceChanged,
    /// A source content-transforming attribute is selected.
    #[error("source content-transforming Git attributes are unsupported")]
    ContentFilterUnsupported,
    /// A possible Git LFS pointer was found instead of local attachment bytes.
    #[error("a tracked source file is a possible Git LFS pointer")]
    LfsPointerUnsupported,
    /// A frozen source or Git-output resource bound was exceeded.
    #[error("repository import exceeded a frozen resource bound")]
    ResourceLimit,
    /// Git emitted bytes outside a strict plumbing grammar.
    #[error("Git returned malformed repository-import plumbing output")]
    MalformedGitOutput,
    /// One bounded Git plumbing operation failed.
    #[error("Git plumbing failed during {operation}")]
    GitCommandFailed {
        /// Fixed scrubbed operation category.
        operation: RepositoryGitOperation,
    },
    /// The staging vault is not an exact safe target candidate.
    #[error("the target staging vault is outside the repository-import profile")]
    UnsafeTarget,
    /// The fresh target repository does not match its opaque creation proof.
    #[error("the target Git repository failed its independent audit")]
    TargetAuditFailed,
    /// A recursive target durability barrier could not be established.
    #[error("the target repository durability barrier was not confirmed")]
    DurabilityNotConfirmed,
    /// A scrubbed filesystem operation failed.
    #[error("repository import I/O failed during {operation}: {kind:?}")]
    Io {
        /// Fixed scrubbed operation category.
        operation: RepositoryIoOperation,
        /// Stable standard-library error class.
        kind: io::ErrorKind,
    },
}

/// Fixed Git operation labels used by scrubbed diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryGitOperation {
    /// Resolve and prove the source repository.
    DiscoverSource,
    /// Inspect source configuration.
    InspectConfiguration,
    /// Read the source commit tree.
    ReadSourceTree,
    /// Read the source index.
    ReadSourceIndex,
    /// Bind source file and blob bytes.
    ReadSourceObject,
    /// Initialize target Git storage.
    InitializeTarget,
    /// Write target objects/index/tree/commit/ref.
    ConstructTarget,
    /// Independently audit target Git state.
    AuditTarget,
}

impl fmt::Display for RepositoryGitOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DiscoverSource => "source repository discovery",
            Self::InspectConfiguration => "source configuration inspection",
            Self::ReadSourceTree => "source tree inspection",
            Self::ReadSourceIndex => "source index inspection",
            Self::ReadSourceObject => "source object verification",
            Self::InitializeTarget => "target repository initialization",
            Self::ConstructTarget => "target root-commit construction",
            Self::AuditTarget => "target repository audit",
        })
    }
}

/// Fixed filesystem operation labels used by scrubbed diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryIoOperation {
    /// Resolve or inspect a repository root.
    InspectRoot,
    /// Enumerate a bounded namespace.
    InspectNamespace,
    /// Open or read one bounded file.
    ReadFile,
    /// Create target metadata.
    WriteTarget,
    /// Synchronize target state.
    SyncTarget,
    /// Spawn Git.
    SpawnGit,
    /// Communicate with Git.
    CommunicateGit,
}

impl fmt::Display for RepositoryIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InspectRoot => "root inspection",
            Self::InspectNamespace => "namespace inspection",
            Self::ReadFile => "bounded file read",
            Self::WriteTarget => "target metadata creation",
            Self::SyncTarget => "target synchronization",
            Self::SpawnGit => "starting Git plumbing",
            Self::CommunicateGit => "communicating with Git plumbing",
        })
    }
}

/// One exact tracked `HEAD` blob in a [`SourceSnapshot`].
#[derive(Clone, Eq, PartialEq)]
pub struct SourceSnapshotEntry {
    source_relative_path: String,
    relative_path: String,
    blob_oid: String,
    size: u64,
    sha256: [u8; 32],
    file_identity: FilesystemFileIdentity,
    markdown: bool,
}

impl fmt::Debug for SourceSnapshotEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSnapshotEntry")
            .field("path", &"[REDACTED]")
            .field("size", &self.size)
            .field("markdown", &self.markdown)
            .finish_non_exhaustive()
    }
}

impl SourceSnapshotEntry {
    /// Return the canonical vault-relative source path.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Return the raw SHA-1 blob object id bound to `HEAD` and the index.
    #[must_use]
    pub fn blob_oid(&self) -> &str {
        &self.blob_oid
    }

    /// Return the exact source body length.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the exact source body SHA-256 digest.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Return whether this source entry is exact lowercase Markdown.
    #[must_use]
    pub const fn is_markdown(&self) -> bool {
        self.markdown
    }
}

/// Opaque, fully bound snapshot of a clean source repository.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceSnapshot {
    root: PathBuf,
    root_identity: FilesystemDirectoryIdentity,
    git_identity: FilesystemDirectoryIdentity,
    git_executable: PathBuf,
    head_oid: String,
    entries: Vec<SourceSnapshotEntry>,
    directories: Vec<DirectorySeal>,
    git_control: Vec<NamespaceSeal>,
    config_sha256: [u8; 32],
    tree_sha256: [u8; 32],
    index_sha256: [u8; 32],
    normalized_path_entries: usize,
    command_binding: Arc<SourceCommandBinding>,
}

impl fmt::Debug for SourceSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSnapshot")
            .field("root", &"[REDACTED]")
            .field("entries", &self.entries.len())
            .field("directories", &self.directories.len())
            .field("normalized_path_entries", &self.normalized_path_entries)
            .finish_non_exhaustive()
    }
}

impl SourceSnapshot {
    /// Return the canonical source worktree root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the exact lowercase SHA-1 source commit id.
    #[must_use]
    pub fn head_oid(&self) -> &str {
        &self.head_oid
    }

    /// Borrow the sorted complete tracked source manifest.
    #[must_use]
    pub fn entries(&self) -> &[SourceSnapshotEntry] {
        &self.entries
    }

    /// Return the number of physical source directories below the root.
    #[must_use]
    pub fn directory_count(&self) -> usize {
        self.directories.len()
    }

    /// Return how many tracked source names were normalized to canonical NFC.
    #[must_use]
    pub const fn normalized_path_entry_count(&self) -> usize {
        self.normalized_path_entries
    }

    /// Return whether a directory identity aliases the source root or any
    /// recursively inventoried source directory.
    #[must_use]
    pub fn contains_directory_identity(&self, identity: &FilesystemDirectoryIdentity) -> bool {
        &self.root_identity == identity
            || self
                .directories
                .iter()
                .any(|directory| &directory.identity == identity)
    }

    /// Re-open and re-prove one source body against this exact snapshot.
    ///
    /// # Errors
    ///
    /// Returns a scrubbed error if the entry is foreign to this snapshot, the
    /// held source file changed, or raw Git object verification fails.
    pub fn read_entry(
        &self,
        entry: &SourceSnapshotEntry,
    ) -> Result<Zeroizing<Vec<u8>>, RepositoryImportError> {
        let expected = self
            .entries
            .binary_search_by(|candidate| candidate.relative_path.cmp(&entry.relative_path))
            .ok()
            .and_then(|index| self.entries.get(index))
            .filter(|candidate| *candidate == entry)
            .ok_or(RepositoryImportError::SourceChanged)?;
        let maximum = if expected.markdown {
            MAX_DOCUMENT_PLAINTEXT_LEN
        } else {
            MAX_ASSET_PLAINTEXT_LEN
        };
        let held = read_snapshot_source_file(
            &self.root,
            Path::new(&expected.source_relative_path),
            maximum,
            &RepositoryImportError::SourceChanged,
        )?;
        if held.identity != expected.file_identity
            || held.bytes.len() as u64 != expected.size
            || sha256(&held.bytes) != expected.sha256
        {
            return Err(RepositoryImportError::SourceChanged);
        }
        let runner = GitRunner::source_bound(
            self.git_executable.clone(),
            self.root.clone(),
            Arc::clone(&self.command_binding),
        );
        verify_source_bytes(&runner, expected, &held.bytes)?;
        Ok(held.bytes)
    }

    /// Re-plan the entire source and require exact semantic and physical identity.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryImportError::SourceChanged`] when any source
    /// identity, namespace, Git semantic map, or file body differs.
    pub fn revalidate(&self) -> Result<(), RepositoryImportError> {
        let current = plan_source_repository_with_executable(&self.root, &self.git_executable)?;
        if &current == self {
            Ok(())
        } else {
            Err(RepositoryImportError::SourceChanged)
        }
    }
}

/// Opaque proof for one complete, fresh target Git repository.
#[derive(Clone, Eq, PartialEq)]
pub struct TargetRepository {
    root_identity: FilesystemDirectoryIdentity,
    root_commit_oid: String,
    root_tree_oid: String,
    tracked: Vec<TargetTrackedEntry>,
    tree_oids: BTreeMap<String, String>,
    object_ids: BTreeMap<String, ObjectDescriptor>,
    git_control: Vec<NamespaceSeal>,
    private_control: Vec<NamespaceSeal>,
    commit_bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for TargetRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetRepository")
            .field("root", &"[REDACTED]")
            .field("root_commit", &"[REDACTED]")
            .field("root_tree", &"[REDACTED]")
            .field("tracked_entries", &self.tracked.len())
            .field("objects", &self.object_ids.len())
            .finish_non_exhaustive()
    }
}

impl TargetRepository {
    /// Return the new target's single parentless root commit id.
    #[must_use]
    pub fn root_commit_oid(&self) -> &str {
        &self.root_commit_oid
    }

    /// Return exact tracked ciphertext/metadata paths.
    #[must_use]
    pub fn tracked_paths(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.tracked
            .iter()
            .map(|entry| entry.relative_path.as_path())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectorySeal {
    relative_path: String,
    identity: FilesystemDirectoryIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NamespaceKind {
    Directory(FilesystemDirectoryIdentity),
    File(FilesystemFileIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NamespaceSeal {
    relative_path: String,
    kind: NamespaceKind,
    size: u64,
    sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetTrackedEntry {
    relative_path: PathBuf,
    size: u64,
    sha256: [u8; 32],
    blob_oid: String,
    identity: FilesystemFileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectDescriptor {
    object_type: String,
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalTreeEntry {
    name: String,
    oid: String,
    directory: bool,
}

type TargetOidByPath = BTreeMap<String, String>;

struct CanonicalTreeObject {
    oid: String,
    body: Zeroizing<Vec<u8>>,
}

type CanonicalTreesByPath = BTreeMap<String, CanonicalTreeObject>;

struct HeldFile {
    bytes: Zeroizing<Vec<u8>>,
    identity: FilesystemFileIdentity,
}

#[derive(Clone, Eq, PartialEq)]
struct BoundControlFile {
    relative_path: &'static str,
    maximum_bytes: usize,
    identity: FilesystemFileIdentity,
    size: u64,
    sha256: [u8; 32],
}

impl fmt::Debug for BoundControlFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundControlFile")
            .field("path", &"[REDACTED]")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct SourceCommandBinding {
    root: PathBuf,
    root_identity: FilesystemDirectoryIdentity,
    git_identity: FilesystemDirectoryIdentity,
    objects_identity: FilesystemDirectoryIdentity,
    config: BoundControlFile,
    head: BoundControlFile,
    index: BoundControlFile,
}

impl fmt::Debug for SourceCommandBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceCommandBinding { root: [REDACTED], .. }")
    }
}

#[cfg(target_os = "linux")]
impl BoundControlFile {
    fn capture(
        root: &Path,
        relative_path: &'static str,
        maximum_bytes: usize,
    ) -> Result<Self, RepositoryImportError> {
        let held = read_secure_relative_file(
            root,
            Path::new(relative_path),
            maximum_bytes,
            &RepositoryImportError::UnsafeSourceControl,
        )?;
        Ok(Self {
            relative_path,
            maximum_bytes,
            identity: held.identity,
            size: held.bytes.len() as u64,
            sha256: sha256(&held.bytes),
        })
    }

    fn verify(&self, root: &Path) -> Result<(), RepositoryImportError> {
        let held = read_secure_relative_file(
            root,
            Path::new(self.relative_path),
            self.maximum_bytes,
            &RepositoryImportError::SourceChanged,
        )?;
        if held.identity == self.identity
            && held.bytes.len() as u64 == self.size
            && sha256(&held.bytes) == self.sha256
        {
            Ok(())
        } else {
            Err(RepositoryImportError::SourceChanged)
        }
    }
}

#[cfg(target_os = "linux")]
impl SourceCommandBinding {
    fn capture(
        root: &Path,
        root_identity: FilesystemDirectoryIdentity,
        git_identity: FilesystemDirectoryIdentity,
    ) -> Result<Self, RepositoryImportError> {
        let observed_root = open_secure_source_root(root)
            .map_err(|_| RepositoryImportError::UnsafeSourceControl)?;
        if observed_root.identity() != &root_identity {
            return Err(RepositoryImportError::UnsafeSourceControl);
        }
        let observed_git = secure_relative_directory_identity(
            root,
            Path::new(".git"),
            &RepositoryImportError::UnsafeSourceControl,
        )?;
        if observed_git != git_identity {
            return Err(RepositoryImportError::UnsafeSourceControl);
        }
        Ok(Self {
            root: root.to_path_buf(),
            root_identity,
            git_identity,
            objects_identity: secure_relative_directory_identity(
                root,
                Path::new(".git/objects"),
                &RepositoryImportError::UnsafeSourceControl,
            )?,
            config: BoundControlFile::capture(root, ".git/config", MAX_CONFIG_BYTES)?,
            head: BoundControlFile::capture(root, ".git/HEAD", MAX_CONFIG_BYTES)?,
            index: BoundControlFile::capture(root, ".git/index", MAX_GIT_OUTPUT)?,
        })
    }

    fn verify_light(&self) -> Result<(), RepositoryImportError> {
        let root = open_secure_source_root(&self.root)
            .map_err(|_| RepositoryImportError::SourceChanged)?;
        if root.identity() != &self.root_identity
            || secure_relative_directory_identity(
                &self.root,
                Path::new(".git"),
                &RepositoryImportError::SourceChanged,
            )? != self.git_identity
            || secure_relative_directory_identity(
                &self.root,
                Path::new(".git/objects"),
                &RepositoryImportError::SourceChanged,
            )? != self.objects_identity
        {
            return Err(RepositoryImportError::SourceChanged);
        }
        self.config.verify(&self.root)?;
        self.head.verify(&self.root)?;
        self.index.verify(&self.root)
    }
}

/// Plan and fully validate one clean source repository without writing state.
///
/// # Errors
///
/// Returns a scrubbed error when the source is not inside the frozen local
/// SHA-1 profile or any bounded filesystem/Git proof fails.
pub fn plan_source_repository(source: &Path) -> Result<SourceSnapshot, RepositoryImportError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = source;
        Err(RepositoryImportError::UnsupportedSourceRepository)
    }
    #[cfg(target_os = "linux")]
    {
        let executable = discover_git_executable()
            .map_err(|_| RepositoryImportError::GitExecutableUnavailable)?;
        plan_source_repository_with_executable(source, &executable)
    }
}

#[allow(clippy::too_many_lines)]
#[cfg(target_os = "linux")]
fn plan_source_repository_with_executable(
    source: &Path,
    executable: &Path,
) -> Result<SourceSnapshot, RepositoryImportError> {
    let root =
        canonical_normal_directory(source, RepositoryImportError::UnsupportedSourceRepository)?;
    let root_identity = filesystem_directory_identity(&root)
        .map_err(|error| io_error(RepositoryIoOperation::InspectRoot, &error))?;
    let git_path = root.join(".git");
    let git_identity = filesystem_directory_identity(&git_path)
        .map_err(|_| RepositoryImportError::UnsupportedSourceRepository)?;
    require_same_filesystem(&root, &git_path, RepositoryImportError::UnsafeSourceControl)?;

    let git_control_before = inventory_namespace(&git_path, NamespacePolicy::SourceControl)?;
    reject_forbidden_source_control(&git_control_before)?;
    let config = read_snapshot_source_file(
        &root,
        Path::new(".git/config"),
        MAX_CONFIG_BYTES,
        &RepositoryImportError::UnsafeSourceControl,
    )?;
    validate_source_config(executable, &root, &config.bytes)?;
    let config_sha256 = sha256(&config.bytes);
    let command_binding = Arc::new(SourceCommandBinding::capture(
        &root,
        root_identity.clone(),
        git_identity.clone(),
    )?);
    if command_binding.config.identity != config.identity
        || command_binding.config.size != config.bytes.len() as u64
        || command_binding.config.sha256 != config_sha256
    {
        return Err(RepositoryImportError::SourceChanged);
    }
    let runner = GitRunner::source_bound(
        executable.to_path_buf(),
        root.clone(),
        Arc::clone(&command_binding),
    );
    let version = runner.run(
        RepositoryGitOperation::DiscoverSource,
        &[OsString::from("version")],
        None,
        256,
        None,
    )?;
    validate_git_version(&version).map_err(|error| match error {
        super::GitError::UnsupportedGitVersion => RepositoryImportError::UnsupportedGitVersion,
        _ => RepositoryImportError::MalformedGitOutput,
    })?;
    prove_source_endpoints(&runner, &root, &git_path)?;

    let head_oid = one_line(&runner.run(
        RepositoryGitOperation::DiscoverSource,
        &os_args(["rev-parse", "--verify", "HEAD^{commit}"]),
        None,
        128,
        None,
    )?)?
    .to_owned();
    require_sha1_oid(&head_oid)?;

    let tree_output = runner.run(
        RepositoryGitOperation::ReadSourceTree,
        &[
            OsString::from("ls-tree"),
            OsString::from("-r"),
            OsString::from("-z"),
            OsString::from("--full-tree"),
            OsString::from("-l"),
            OsString::from(&head_oid),
        ],
        None,
        MAX_GIT_OUTPUT,
        None,
    )?;
    let tree = parse_source_tree(&tree_output)?;
    if tree.is_empty() {
        return Err(RepositoryImportError::UnsafeSourceEntry);
    }

    let index_output = runner.run(
        RepositoryGitOperation::ReadSourceIndex,
        &os_args(["ls-files", "-s", "-z", "--full-name"]),
        None,
        MAX_GIT_OUTPUT,
        None,
    )?;
    let index = parse_source_index(&index_output)?;
    if tree.len() != index.len()
        || tree
            .iter()
            .any(|(path, entry)| index.get(path) != Some(&entry.oid))
    {
        return Err(RepositoryImportError::SourceChanged);
    }
    require_normal_index_tags(&runner, &tree, false)?;
    require_normal_index_tags(&runner, &tree, true)?;
    reject_source_attributes(&runner, tree.keys())?;

    let (namespace_files, directories) = inventory_source_worktree(&root, &git_identity)?;
    let expected_paths = tree.keys().cloned().collect::<BTreeSet<_>>();
    if namespace_files != expected_paths {
        return Err(RepositoryImportError::UnsafeSourceEntry);
    }

    let canonical_paths = canonical_portable_source_paths(tree.keys())?;
    let normalized_path_entries = canonical_paths
        .iter()
        .filter(|(source, canonical)| source.as_str() != canonical.as_str())
        .count();
    let mut entries = Vec::with_capacity(tree.len());
    let mut combined_bytes = 0_u64;
    let mut markdown_bytes = 0_u64;
    for (source_relative_path, tree_entry) in tree {
        let relative_path = canonical_paths
            .get(&source_relative_path)
            .ok_or(RepositoryImportError::UnsafeSourceEntry)?
            .clone();
        let markdown = source_relative_path.strip_suffix(".md").is_some();
        let maximum = if markdown {
            MAX_DOCUMENT_PLAINTEXT_LEN
        } else {
            MAX_ASSET_PLAINTEXT_LEN
        };
        let held = read_snapshot_source_file(
            &root,
            Path::new(&source_relative_path),
            maximum,
            &RepositoryImportError::UnsafeSourceEntry,
        )?;
        if held.bytes.len() as u64 != tree_entry.size {
            return Err(RepositoryImportError::SourceChanged);
        }
        if markdown && std::str::from_utf8(&held.bytes).is_err() {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
        let sha256 = sha256(&held.bytes);
        let candidate = SourceSnapshotEntry {
            source_relative_path,
            relative_path,
            blob_oid: tree_entry.oid,
            size: tree_entry.size,
            sha256,
            file_identity: held.identity,
            markdown,
        };
        verify_source_bytes(&runner, &candidate, &held.bytes)?;
        combined_bytes = combined_bytes
            .checked_add(candidate.size)
            .ok_or(RepositoryImportError::ResourceLimit)?;
        if combined_bytes > MAX_IMPORT_PLAINTEXT_BYTES {
            return Err(RepositoryImportError::ResourceLimit);
        }
        if markdown {
            markdown_bytes = markdown_bytes
                .checked_add(candidate.size)
                .ok_or(RepositoryImportError::ResourceLimit)?;
            if markdown_bytes > MAX_MARKDOWN_PLAINTEXT_BYTES {
                return Err(RepositoryImportError::ResourceLimit);
            }
        }
        entries.push(candidate);
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let git_control_after = inventory_namespace(&git_path, NamespacePolicy::SourceControl)?;
    if git_control_after != git_control_before
        || filesystem_directory_identity(&root).ok().as_ref() != Some(&root_identity)
        || filesystem_directory_identity(&git_path).ok().as_ref() != Some(&git_identity)
    {
        return Err(RepositoryImportError::SourceChanged);
    }
    let config_after = read_snapshot_source_file(
        &root,
        Path::new(".git/config"),
        MAX_CONFIG_BYTES,
        &RepositoryImportError::SourceChanged,
    )?;
    if config_after.identity != config.identity || sha256(&config_after.bytes) != config_sha256 {
        return Err(RepositoryImportError::SourceChanged);
    }

    Ok(SourceSnapshot {
        root,
        root_identity,
        git_identity,
        git_executable: executable.to_path_buf(),
        head_oid,
        entries,
        directories,
        git_control: git_control_after,
        config_sha256,
        tree_sha256: semantic_map_digest(&tree_output),
        index_sha256: semantic_map_digest(&index_output),
        normalized_path_entries,
        command_binding,
    })
}

#[cfg(not(target_os = "linux"))]
fn plan_source_repository_with_executable(
    source: &Path,
    executable: &Path,
) -> Result<SourceSnapshot, RepositoryImportError> {
    let _ = (source, executable);
    Err(RepositoryImportError::UnsupportedSourceRepository)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceTreeEntry {
    oid: String,
    size: u64,
}

#[cfg(target_os = "linux")]
fn parse_source_tree(
    output: &[u8],
) -> Result<BTreeMap<String, SourceTreeEntry>, RepositoryImportError> {
    let mut result = BTreeMap::new();
    let mut retained_path_bytes = 0_usize;
    for record in nul_records(output)? {
        if result.len() >= MAX_SOURCE_ENTRIES {
            return Err(RepositoryImportError::ResourceLimit);
        }
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(RepositoryImportError::MalformedGitOutput)?;
        let metadata = std::str::from_utf8(&record[..tab])
            .map_err(|_| RepositoryImportError::MalformedGitOutput)?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| RepositoryImportError::UnsafeSourceEntry)?;
        validate_relative_path_shape(path)?;
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != "100644" || fields[1] != "blob" {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
        require_sha1_oid(fields[2])?;
        let size = fields[3]
            .parse::<u64>()
            .map_err(|_| RepositoryImportError::MalformedGitOutput)?;
        retained_path_bytes = retained_path_bytes.saturating_add(path.len());
        if retained_path_bytes > MAX_RETAINED_PATH_BYTES
            || result
                .insert(
                    path.to_owned(),
                    SourceTreeEntry {
                        oid: fields[2].to_owned(),
                        size,
                    },
                )
                .is_some()
        {
            return Err(RepositoryImportError::ResourceLimit);
        }
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn parse_source_index(output: &[u8]) -> Result<BTreeMap<String, String>, RepositoryImportError> {
    let mut result = BTreeMap::new();
    for record in nul_records(output)? {
        if result.len() >= MAX_SOURCE_ENTRIES {
            return Err(RepositoryImportError::ResourceLimit);
        }
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(RepositoryImportError::MalformedGitOutput)?;
        let metadata = std::str::from_utf8(&record[..tab])
            .map_err(|_| RepositoryImportError::MalformedGitOutput)?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| RepositoryImportError::UnsafeSourceEntry)?;
        validate_relative_path_shape(path)?;
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 || fields[0] != "100644" || fields[2] != "0" {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
        require_sha1_oid(fields[1])?;
        if result
            .insert(path.to_owned(), fields[1].to_owned())
            .is_some()
        {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_lines)] // Keep related endpoint equivalence proofs together.
#[cfg(target_os = "linux")]
fn prove_source_endpoints(
    runner: &GitRunner,
    root: &Path,
    git_path: &Path,
) -> Result<(), RepositoryImportError> {
    let format = runner.run(
        RepositoryGitOperation::DiscoverSource,
        &os_args(["rev-parse", "--show-object-format"]),
        None,
        32,
        None,
    )?;
    if one_line(&format)? != "sha1" {
        return Err(RepositoryImportError::UnsupportedSourceRepository);
    }
    let inside = runner.run(
        RepositoryGitOperation::DiscoverSource,
        &os_args(["rev-parse", "--is-inside-work-tree"]),
        None,
        16,
        None,
    )?;
    if one_line(&inside)? != "true" {
        return Err(RepositoryImportError::UnsupportedSourceRepository);
    }
    let prefix = runner.run(
        RepositoryGitOperation::DiscoverSource,
        &os_args(["rev-parse", "--show-prefix"]),
        None,
        4096,
        None,
    )?;
    if !matches!(prefix.as_slice(), b"\n" | b"\r\n") {
        return Err(RepositoryImportError::UnsupportedSourceRepository);
    }
    let top = command_path(
        runner,
        RepositoryGitOperation::DiscoverSource,
        &["rev-parse", "--show-toplevel"],
    )?;
    let absolute_git = command_path(
        runner,
        RepositoryGitOperation::DiscoverSource,
        &["rev-parse", "--absolute-git-dir"],
    )?;
    let common = command_path(
        runner,
        RepositoryGitOperation::DiscoverSource,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    let index = command_path(
        runner,
        RepositoryGitOperation::DiscoverSource,
        &["rev-parse", "--path-format=absolute", "--git-path", "index"],
    )?;
    let objects = command_path(
        runner,
        RepositoryGitOperation::DiscoverSource,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ],
    )?;
    if fs::canonicalize(top).ok().as_deref() != Some(root)
        || fs::canonicalize(absolute_git).ok().as_deref() != Some(git_path)
        || fs::canonicalize(common).ok().as_deref() != Some(git_path)
        || index != git_path.join("index")
        || objects != git_path.join("objects")
    {
        return Err(RepositoryImportError::UnsupportedSourceRepository);
    }

    let split = runner.run(
        RepositoryGitOperation::InspectConfiguration,
        &os_args([
            "config",
            "--type=bool",
            "--default=false",
            "--get",
            "core.splitIndex",
        ]),
        None,
        16,
        None,
    )?;
    let sparse = runner.run(
        RepositoryGitOperation::InspectConfiguration,
        &os_args([
            "config",
            "--type=bool",
            "--default=false",
            "--get",
            "index.sparse",
        ]),
        None,
        16,
        None,
    )?;
    let shared = runner.run(
        RepositoryGitOperation::ReadSourceIndex,
        &os_args(["rev-parse", "--shared-index-path"]),
        None,
        4096,
        None,
    )?;
    if one_line(&split)? != "false"
        || one_line(&sparse)? != "false"
        || !matches!(shared.as_slice(), b"" | b"\n" | b"\r\n")
    {
        return Err(RepositoryImportError::UnsupportedSourceRepository);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn command_path(
    runner: &GitRunner,
    operation: RepositoryGitOperation,
    arguments: &[&str],
) -> Result<PathBuf, RepositoryImportError> {
    let output = runner.run(operation, &os_args_iter(arguments), None, 16 * 1024, None)?;
    let line = one_line(&output)?;
    if line.is_empty() {
        return Err(RepositoryImportError::MalformedGitOutput);
    }
    Ok(PathBuf::from(line))
}

#[cfg(target_os = "linux")]
fn validate_source_config(
    executable: &Path,
    root: &Path,
    config: &[u8],
) -> Result<(), RepositoryImportError> {
    let runner = GitRunner::source(executable.to_path_buf(), root.to_path_buf());
    let output = runner.run_without_prefix(
        RepositoryGitOperation::InspectConfiguration,
        &os_args(["config", "--file", "-", "--no-includes", "--null", "--list"]),
        Some(config),
        MAX_CONFIG_BYTES.saturating_mul(2),
        None,
    )?;
    let mut critical = BTreeSet::new();
    for record in nul_records(&output)? {
        let newline = record
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(RepositoryImportError::UnsafeSourceControl)?;
        let key = std::str::from_utf8(&record[..newline])
            .map_err(|_| RepositoryImportError::UnsafeSourceControl)?
            .to_ascii_lowercase();
        let value = std::str::from_utf8(&record[newline + 1..])
            .map_err(|_| RepositoryImportError::UnsafeSourceControl)?;
        let forbidden = key == "core.worktree"
            || key == "core.attributesfile"
            || key == "extensions.worktreeconfig"
            || key == "extensions.partialclone"
            || key.starts_with("include.")
            || key.starts_with("includeif.")
            || (key.starts_with("remote.") && key.ends_with(".promisor"));
        if forbidden {
            return Err(RepositoryImportError::UnsafeSourceControl);
        }
        if matches!(key.as_str(), "core.splitindex" | "index.sparse")
            && (!critical.insert(key.clone()) || value.eq_ignore_ascii_case("true"))
        {
            return Err(RepositoryImportError::UnsafeSourceControl);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_normal_index_tags(
    runner: &GitRunner,
    tree: &BTreeMap<String, SourceTreeEntry>,
    fsmonitor: bool,
) -> Result<(), RepositoryImportError> {
    let flag = if fsmonitor { "-f" } else { "-v" };
    let output = runner.run(
        RepositoryGitOperation::ReadSourceIndex,
        &[
            OsString::from("ls-files"),
            OsString::from(flag),
            OsString::from("-z"),
            OsString::from("--full-name"),
        ],
        None,
        MAX_GIT_OUTPUT,
        None,
    )?;
    let mut paths = BTreeSet::new();
    for record in nul_records(&output)? {
        if record.len() < 3 || &record[..2] != b"H " {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
        let path = std::str::from_utf8(&record[2..])
            .map_err(|_| RepositoryImportError::UnsafeSourceEntry)?;
        if !paths.insert(path.to_owned()) {
            return Err(RepositoryImportError::MalformedGitOutput);
        }
    }
    if paths == tree.keys().cloned().collect() {
        Ok(())
    } else {
        Err(RepositoryImportError::SourceChanged)
    }
}

#[cfg(target_os = "linux")]
fn reject_source_attributes<'a>(
    runner: &GitRunner,
    paths: impl Iterator<Item = &'a String>,
) -> Result<(), RepositoryImportError> {
    let mut input = Vec::new();
    let mut path_count = 0_usize;
    for path in paths {
        input.extend_from_slice(path.as_bytes());
        input.push(0);
        path_count = path_count.saturating_add(1);
    }
    let output = runner.run(
        RepositoryGitOperation::InspectConfiguration,
        &os_args([
            "check-attr",
            "--cached",
            "-z",
            "--stdin",
            "filter",
            "working-tree-encoding",
            "ident",
        ]),
        Some(&input),
        MAX_GIT_OUTPUT,
        None,
    )?;
    let records = nul_records(&output)?;
    if records.len() != path_count.saturating_mul(9) {
        return Err(RepositoryImportError::MalformedGitOutput);
    }
    for triple in records.chunks_exact(3) {
        let attribute = triple[1];
        if !matches!(attribute, b"filter" | b"working-tree-encoding" | b"ident") {
            return Err(RepositoryImportError::MalformedGitOutput);
        }
        if !matches!(triple[2], b"unspecified" | b"unset") {
            return Err(RepositoryImportError::ContentFilterUnsupported);
        }
    }
    Ok(())
}

fn verify_source_bytes(
    runner: &GitRunner,
    entry: &SourceSnapshotEntry,
    bytes: &[u8],
) -> Result<(), RepositoryImportError> {
    let hash = runner.run(
        RepositoryGitOperation::ReadSourceObject,
        &os_args(["hash-object", "--stdin", "--no-filters"]),
        Some(bytes),
        128,
        None,
    )?;
    if one_line(&hash)? != entry.blob_oid {
        return Err(RepositoryImportError::SourceChanged);
    }
    let raw = runner.run(
        RepositoryGitOperation::ReadSourceObject,
        &[
            OsString::from("cat-file"),
            OsString::from("blob"),
            OsString::from(&entry.blob_oid),
        ],
        None,
        bytes.len().saturating_add(1),
        None,
    )?;
    if raw.as_slice() != bytes || raw.len() as u64 != entry.size || sha256(&raw) != entry.sha256 {
        return Err(RepositoryImportError::SourceChanged);
    }
    if raw.len() <= MAX_LFS_POINTER_BYTES && is_possible_lfs_pointer(&raw) {
        return Err(RepositoryImportError::LfsPointerUnsupported);
    }
    Ok(())
}

fn is_possible_lfs_pointer(bytes: &[u8]) -> bool {
    let first_line_end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len());
    let mut first_line = &bytes[..first_line_end];
    if first_line.ends_with(b"\r") {
        first_line = &first_line[..first_line.len().saturating_sub(1)];
    }
    first_line == b"version https://git-lfs.github.com/spec/v1"
}

#[cfg(target_os = "linux")]
fn reject_forbidden_source_control(control: &[NamespaceSeal]) -> Result<(), RepositoryImportError> {
    let forbidden = [
        "commondir",
        "config.worktree",
        "objects/info/alternates",
        "objects/info/http-alternates",
        "info/attributes",
        "info/grafts",
        "shallow",
        "info/sparse-checkout",
        "worktrees",
        "refs/replace",
    ];
    if control.iter().any(|entry| {
        forbidden.contains(&entry.relative_path.as_str())
            || entry.relative_path.split('/').next().is_some_and(|name| {
                name.as_bytes()
                    .get(.."sharedindex.".len())
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(b"sharedindex."))
            })
            || entry
                .relative_path
                .strip_prefix("objects/pack/")
                .is_some_and(|name| name.ends_with(".promisor"))
    }) {
        Err(RepositoryImportError::UnsafeSourceControl)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum NamespacePolicy {
    #[cfg(target_os = "linux")]
    SourceControl,
    TargetGit,
    TargetPrivate,
}

#[cfg(target_os = "linux")]
fn inventory_namespace(
    root: &Path,
    policy: NamespacePolicy,
) -> Result<Vec<NamespaceSeal>, RepositoryImportError> {
    let directory = open_secure_source_root(root).map_err(|_| namespace_error(policy))?;
    let mut seals = Vec::new();
    let mut path_bytes = 0_usize;
    inventory_secure_namespace_directory(
        &directory,
        Path::new(""),
        0,
        policy,
        &mut seals,
        &mut path_bytes,
    )?;
    directory
        .verify_binding()
        .map_err(|_| namespace_error(policy))?;
    seals.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(seals)
}

#[cfg(target_os = "linux")]
fn inventory_secure_namespace_directory(
    directory: &SecureSourceDirectory,
    relative: &Path,
    depth: usize,
    policy: NamespacePolicy,
    seals: &mut Vec<NamespaceSeal>,
    path_bytes: &mut usize,
) -> Result<(), RepositoryImportError> {
    if depth > MAX_TREE_DEPTH || seals.len() >= MAX_CONTROL_ENTRIES {
        return Err(RepositoryImportError::ResourceLimit);
    }
    directory
        .verify_binding()
        .map_err(|_| namespace_error(policy))?;
    for entry in directory.read_dir().map_err(|_| namespace_error(policy))? {
        let entry = entry.map_err(|_| namespace_error(policy))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| namespace_error(policy))?;
        let child_relative = relative.join(&name);
        let relative_text = slash_path(&child_relative).ok_or_else(|| namespace_error(policy))?;
        *path_bytes = path_bytes.saturating_add(relative_text.len());
        if *path_bytes > MAX_RETAINED_PATH_BYTES || seals.len() >= MAX_CONTROL_ENTRIES {
            return Err(RepositoryImportError::ResourceLimit);
        }
        match directory
            .open_child(std::ffi::OsStr::new(&name))
            .map_err(|_| namespace_error(policy))?
        {
            SecureSourceChild::Directory(child) => {
                seals.push(NamespaceSeal {
                    relative_path: relative_text,
                    kind: NamespaceKind::Directory(child.identity().clone()),
                    size: 0,
                    sha256: None,
                });
                inventory_secure_namespace_directory(
                    &child,
                    &child_relative,
                    depth.saturating_add(1),
                    policy,
                    seals,
                    path_bytes,
                )?;
                child
                    .verify_binding()
                    .map_err(|_| namespace_error(policy))?;
            }
            SecureSourceChild::File(file) => {
                let (identity, size, digest) = hash_secure_file(file, namespace_error(policy))?;
                seals.push(NamespaceSeal {
                    relative_path: relative_text,
                    kind: NamespaceKind::File(identity),
                    size,
                    sha256: Some(digest),
                });
            }
            SecureSourceChild::Other => return Err(namespace_error(policy)),
        }
    }
    directory
        .verify_binding()
        .map_err(|_| namespace_error(policy))
}

#[cfg(not(target_os = "linux"))]
fn inventory_namespace(
    root: &Path,
    policy: NamespacePolicy,
) -> Result<Vec<NamespaceSeal>, RepositoryImportError> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| io_error(RepositoryIoOperation::InspectNamespace, &error))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
        return Err(namespace_error(policy));
    }
    let mut seals = Vec::new();
    let mut path_bytes = 0_usize;
    inventory_namespace_directory(
        root,
        root,
        &root_metadata,
        Path::new(""),
        0,
        policy,
        &mut seals,
        &mut path_bytes,
    )?;
    seals.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(seals)
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(target_os = "linux"))]
fn inventory_namespace_directory(
    root: &Path,
    directory: &Path,
    root_metadata: &fs::Metadata,
    relative: &Path,
    depth: usize,
    policy: NamespacePolicy,
    seals: &mut Vec<NamespaceSeal>,
    path_bytes: &mut usize,
) -> Result<(), RepositoryImportError> {
    if depth > MAX_TREE_DEPTH || seals.len() >= MAX_CONTROL_ENTRIES {
        return Err(RepositoryImportError::ResourceLimit);
    }
    let entries = fs::read_dir(directory)
        .map_err(|error| io_error(RepositoryIoOperation::InspectNamespace, &error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error(RepositoryIoOperation::InspectNamespace, &error))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| namespace_error(policy))?;
        let child_relative = relative.join(&name);
        let relative_text = slash_path(&child_relative).ok_or_else(|| namespace_error(policy))?;
        *path_bytes = path_bytes.saturating_add(relative_text.len());
        if *path_bytes > MAX_RETAINED_PATH_BYTES || seals.len() >= MAX_CONTROL_ENTRIES {
            return Err(RepositoryImportError::ResourceLimit);
        }
        let path = root.join(&child_relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error(RepositoryIoOperation::InspectNamespace, &error))?;
        require_same_filesystem_metadata(root_metadata, &metadata, namespace_error(policy))?;
        if metadata.file_type().is_symlink() {
            return Err(namespace_error(policy));
        }
        if metadata.file_type().is_dir() {
            let identity =
                filesystem_directory_identity(&path).map_err(|_| namespace_error(policy))?;
            seals.push(NamespaceSeal {
                relative_path: relative_text,
                kind: NamespaceKind::Directory(identity),
                size: 0,
                sha256: None,
            });
            inventory_namespace_directory(
                root,
                &path,
                root_metadata,
                &child_relative,
                depth.saturating_add(1),
                policy,
                seals,
                path_bytes,
            )?;
        } else if metadata.file_type().is_file() {
            let (identity, digest) = hash_bound_regular_file(&path, namespace_error(policy))?;
            seals.push(NamespaceSeal {
                relative_path: relative_text,
                kind: NamespaceKind::File(identity),
                size: metadata.len(),
                sha256: Some(digest),
            });
        } else {
            return Err(namespace_error(policy));
        }
    }
    Ok(())
}

fn namespace_error(policy: NamespacePolicy) -> RepositoryImportError {
    match policy {
        #[cfg(target_os = "linux")]
        NamespacePolicy::SourceControl => RepositoryImportError::UnsafeSourceControl,
        NamespacePolicy::TargetGit | NamespacePolicy::TargetPrivate => {
            RepositoryImportError::TargetAuditFailed
        }
    }
}

#[cfg(target_os = "linux")]
fn inventory_source_worktree(
    root: &Path,
    expected_git_identity: &FilesystemDirectoryIdentity,
) -> Result<(BTreeSet<String>, Vec<DirectorySeal>), RepositoryImportError> {
    let root = open_secure_source_root(root)
        .map_err(|_| RepositoryImportError::UnsupportedSourceRepository)?;
    let mut files = BTreeSet::new();
    let mut directories = Vec::new();
    let mut entries = 0_usize;
    let mut path_bytes = 0_usize;
    inventory_secure_source_directory(
        &root,
        Path::new(""),
        0,
        expected_git_identity,
        &mut files,
        &mut directories,
        &mut entries,
        &mut path_bytes,
    )?;
    root.verify_binding()
        .map_err(|_| RepositoryImportError::SourceChanged)?;
    directories.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok((files, directories))
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn inventory_secure_source_directory(
    directory: &SecureSourceDirectory,
    relative: &Path,
    depth: usize,
    expected_git_identity: &FilesystemDirectoryIdentity,
    files: &mut BTreeSet<String>,
    directories: &mut Vec<DirectorySeal>,
    entries: &mut usize,
    path_bytes: &mut usize,
) -> Result<(), RepositoryImportError> {
    if depth > MAX_TREE_DEPTH {
        return Err(RepositoryImportError::ResourceLimit);
    }
    directory
        .verify_binding()
        .map_err(|_| RepositoryImportError::SourceChanged)?;
    for entry in directory
        .read_dir()
        .map_err(|error| io_error(RepositoryIoOperation::InspectNamespace, &error))?
    {
        let entry =
            entry.map_err(|error| io_error(RepositoryIoOperation::InspectNamespace, &error))?;
        *entries = entries.saturating_add(1);
        if *entries > MAX_SOURCE_ENTRIES.saturating_mul(2) {
            return Err(RepositoryImportError::ResourceLimit);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RepositoryImportError::UnsafeSourceEntry)?;
        let child_relative = relative.join(&name);
        let relative_text =
            slash_path(&child_relative).ok_or(RepositoryImportError::UnsafeSourceEntry)?;
        *path_bytes = path_bytes.saturating_add(relative_text.len());
        if *path_bytes > MAX_RETAINED_PATH_BYTES {
            return Err(RepositoryImportError::ResourceLimit);
        }
        let child = directory
            .open_child(std::ffi::OsStr::new(&name))
            .map_err(|_| RepositoryImportError::UnsafeSourceEntry)?;
        if relative.as_os_str().is_empty() && name == ".git" {
            let SecureSourceChild::Directory(git) = child else {
                return Err(RepositoryImportError::UnsafeSourceControl);
            };
            if git.identity() != expected_git_identity {
                return Err(RepositoryImportError::SourceChanged);
            }
            git.verify_binding()
                .map_err(|_| RepositoryImportError::SourceChanged)?;
            continue;
        }
        match child {
            SecureSourceChild::Directory(child) => {
                directories.push(DirectorySeal {
                    relative_path: relative_text,
                    identity: child.identity().clone(),
                });
                inventory_secure_source_directory(
                    &child,
                    &child_relative,
                    depth.saturating_add(1),
                    expected_git_identity,
                    files,
                    directories,
                    entries,
                    path_bytes,
                )?;
                child
                    .verify_binding()
                    .map_err(|_| RepositoryImportError::SourceChanged)?;
            }
            SecureSourceChild::File(file) => {
                file.verify_binding()
                    .map_err(|_| RepositoryImportError::SourceChanged)?;
                files.insert(relative_text);
            }
            SecureSourceChild::Other => return Err(RepositoryImportError::UnsafeSourceEntry),
        }
    }
    directory
        .verify_binding()
        .map_err(|_| RepositoryImportError::SourceChanged)
}

#[cfg(target_os = "linux")]
fn canonical_portable_source_paths<'a>(
    paths: impl Iterator<Item = &'a String>,
) -> Result<BTreeMap<String, String>, RepositoryImportError> {
    let mut logical_folded = BTreeMap::new();
    let mut physical_folded = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut canonical_paths = BTreeMap::new();
    for path in paths {
        validate_relative_path_shape(path)?;
        let (canonical, logical_key, physical) = if path.strip_suffix(".md").is_some() {
            let logical =
                LogicalPath::parse(path).map_err(|_| RepositoryImportError::UnsafeSourceEntry)?;
            (
                logical.as_str().to_owned(),
                logical.case_fold_key(),
                logical.to_ciphertext_relative_path(),
            )
        } else {
            let asset =
                AssetPath::parse(path).map_err(|_| RepositoryImportError::UnsafeSourceEntry)?;
            (
                asset.as_str().to_owned(),
                asset.case_fold_key(),
                asset.to_ciphertext_relative_path(),
            )
        };
        if logical_folded.insert(logical_key, path.clone()).is_some()
            || canonical_paths.insert(path.clone(), canonical).is_some()
        {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
        let physical_text =
            slash_path(&physical).ok_or(RepositoryImportError::UnsafeSourceEntry)?;
        if physical_folded
            .insert(raw_portable_case_fold_key(&physical_text), path.clone())
            .is_some()
        {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
        let mut parent = Path::new(path).parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            let text = slash_path(directory).ok_or(RepositoryImportError::UnsafeSourceEntry)?;
            let canonical_directory = LogicalDir::parse(&text)
                .map_err(|_| RepositoryImportError::UnsafeSourceEntry)?
                .as_str()
                .to_owned();
            if let Some((existing_source, _)) = directories.insert(
                raw_portable_case_fold_key(&canonical_directory),
                (text.clone(), canonical_directory.clone()),
            ) && existing_source != text
            {
                return Err(RepositoryImportError::UnsafeSourceEntry);
            }
            parent = directory.parent();
        }
    }
    for (_, directory) in directories.into_values() {
        let key = raw_portable_case_fold_key(&directory);
        if physical_folded.insert(key, directory).is_some() {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
    }
    Ok(canonical_paths)
}

#[cfg(target_os = "linux")]
fn validate_relative_path_shape(path: &str) -> Result<(), RepositoryImportError> {
    if path.is_empty()
        || path.as_bytes().contains(&0)
        || path.contains('\\')
        || Path::new(path).is_absolute()
        || path.split('/').count() > MAX_TREE_DEPTH
    {
        return Err(RepositoryImportError::UnsafeSourceEntry);
    }
    for component in Path::new(path).components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(RepositoryImportError::UnsafeSourceEntry);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_snapshot_source_file(
    root: &Path,
    relative: &Path,
    maximum: usize,
    unsafe_error: &RepositoryImportError,
) -> Result<HeldFile, RepositoryImportError> {
    read_secure_relative_file(root, relative, maximum, unsafe_error)
}

#[cfg(not(target_os = "linux"))]
fn read_snapshot_source_file(
    root: &Path,
    relative: &Path,
    maximum: usize,
    unsafe_error: &RepositoryImportError,
) -> Result<HeldFile, RepositoryImportError> {
    let _ = (root, relative, maximum, unsafe_error);
    Err(RepositoryImportError::UnsupportedSourceRepository)
}

#[cfg(target_os = "linux")]
fn read_secure_relative_file(
    root: &Path,
    relative: &Path,
    maximum: usize,
    unsafe_error: &RepositoryImportError,
) -> Result<HeldFile, RepositoryImportError> {
    let root = open_secure_source_root(root).map_err(|_| unsafe_error.clone())?;
    let mut directories = vec![root];
    let mut components = relative.components().peekable();
    let mut file = None;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(unsafe_error.clone());
        };
        let child = directories
            .last()
            .ok_or_else(|| unsafe_error.clone())?
            .open_child(name)
            .map_err(|_| unsafe_error.clone())?;
        if components.peek().is_some() {
            let SecureSourceChild::Directory(directory) = child else {
                return Err(unsafe_error.clone());
            };
            directories.push(directory);
        } else {
            let SecureSourceChild::File(opened) = child else {
                return Err(unsafe_error.clone());
            };
            file = Some(opened);
        }
    }
    let mut file = file.ok_or_else(|| unsafe_error.clone())?;
    let length = file.observed_len().map_err(|_| unsafe_error.clone())?;
    if length > u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(unsafe_error.clone());
    }
    let length = usize::try_from(length).map_err(|_| unsafe_error.clone())?;
    file.verify_binding().map_err(|_| unsafe_error.clone())?;
    let identity = file.identity().map_err(|_| unsafe_error.clone())?;
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    file.read_exact(bytes.as_mut_slice())
        .map_err(|_| unsafe_error.clone())?;
    let mut extra = Zeroizing::new([0_u8; 1]);
    if file
        .read(extra.as_mut_slice())
        .map_err(|_| unsafe_error.clone())?
        != 0
    {
        return Err(unsafe_error.clone());
    }
    file.verify_binding().map_err(|_| unsafe_error.clone())?;
    if file.identity().map_err(|_| unsafe_error.clone())? != identity {
        return Err(unsafe_error.clone());
    }
    for directory in directories.iter().rev() {
        directory
            .verify_binding()
            .map_err(|_| unsafe_error.clone())?;
    }
    Ok(HeldFile { bytes, identity })
}

#[cfg(target_os = "linux")]
fn secure_relative_directory_identity(
    root: &Path,
    relative: &Path,
    unsafe_error: &RepositoryImportError,
) -> Result<FilesystemDirectoryIdentity, RepositoryImportError> {
    let root = open_secure_source_root(root).map_err(|_| unsafe_error.clone())?;
    let mut directories = vec![root];
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(unsafe_error.clone());
        };
        let child = directories
            .last()
            .ok_or_else(|| unsafe_error.clone())?
            .open_child(name)
            .map_err(|_| unsafe_error.clone())?;
        let SecureSourceChild::Directory(child) = child else {
            return Err(unsafe_error.clone());
        };
        directories.push(child);
    }
    let identity = directories
        .last()
        .ok_or_else(|| unsafe_error.clone())?
        .identity()
        .clone();
    for directory in directories.iter().rev() {
        directory
            .verify_binding()
            .map_err(|_| unsafe_error.clone())?;
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn hash_secure_file(
    mut file: SecureSourceFile,
    unsafe_error: RepositoryImportError,
) -> Result<(FilesystemFileIdentity, u64, [u8; 32]), RepositoryImportError> {
    let expected = file.observed_len().map_err(|_| unsafe_error.clone())?;
    file.verify_binding().map_err(|_| unsafe_error.clone())?;
    let identity = file.identity().map_err(|_| unsafe_error.clone())?;
    let mut digest = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    loop {
        let read = file
            .read(buffer.as_mut_slice())
            .map_err(|_| unsafe_error.clone())?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .ok_or(RepositoryImportError::ResourceLimit)?;
        digest.update(&buffer[..read]);
    }
    if observed != expected
        || file.identity().map_err(|_| unsafe_error.clone())? != identity
        || file.verify_binding().is_err()
    {
        return Err(unsafe_error);
    }
    Ok((identity, observed, digest.finalize().into()))
}

fn read_bound_regular_file(
    path: &Path,
    maximum: usize,
    unsafe_error: RepositoryImportError,
) -> Result<HeldFile, RepositoryImportError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| unsafe_error.clone())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
    {
        return Err(unsafe_error.clone());
    }
    let file =
        File::open(path).map_err(|error| io_error(RepositoryIoOperation::ReadFile, &error))?;
    if !open_file_matches_path_and_is_single_link(path, &file).map_err(|_| unsafe_error.clone())? {
        return Err(unsafe_error.clone());
    }
    verify_regular_file_has_no_alternate_data_streams(path, &file)
        .map_err(|_| unsafe_error.clone())?;
    let identity = filesystem_file_identity(&file).map_err(|_| unsafe_error.clone())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    ));
    (&file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(RepositoryIoOperation::ReadFile, &error))?;
    if bytes.len() > maximum
        || bytes.len() as u64 != metadata.len()
        || !open_file_matches_path_and_is_single_link(path, &file)
            .map_err(|_| unsafe_error.clone())?
        || filesystem_file_identity(&file).ok().as_ref() != Some(&identity)
    {
        return Err(unsafe_error);
    }
    Ok(HeldFile { bytes, identity })
}

#[cfg(not(target_os = "linux"))]
fn hash_bound_regular_file(
    path: &Path,
    unsafe_error: RepositoryImportError,
) -> Result<(FilesystemFileIdentity, [u8; 32]), RepositoryImportError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| unsafe_error.clone())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(unsafe_error.clone());
    }
    let mut file =
        File::open(path).map_err(|error| io_error(RepositoryIoOperation::ReadFile, &error))?;
    if !open_file_matches_path_and_is_single_link(path, &file).map_err(|_| unsafe_error.clone())? {
        return Err(unsafe_error.clone());
    }
    verify_regular_file_has_no_alternate_data_streams(path, &file)
        .map_err(|_| unsafe_error.clone())?;
    let identity = filesystem_file_identity(&file).map_err(|_| unsafe_error.clone())?;
    let mut digest = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    loop {
        let read = file
            .read(buffer.as_mut_slice())
            .map_err(|error| io_error(RepositoryIoOperation::ReadFile, &error))?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .ok_or(RepositoryImportError::ResourceLimit)?;
        digest.update(&buffer[..read]);
    }
    if observed != metadata.len()
        || !open_file_matches_path_and_is_single_link(path, &file)
            .map_err(|_| unsafe_error.clone())?
        || filesystem_file_identity(&file).ok().as_ref() != Some(&identity)
    {
        return Err(unsafe_error);
    }
    Ok((identity, digest.finalize().into()))
}

fn canonical_normal_directory(
    path: &Path,
    unsafe_error: RepositoryImportError,
) -> Result<PathBuf, RepositoryImportError> {
    let absolute = lexical_absolute_path(path, unsafe_error.clone())?;
    validate_directory_ancestor_chain(&absolute, unsafe_error.clone())?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|_| unsafe_error.clone())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(unsafe_error.clone());
    }
    let canonical = fs::canonicalize(&absolute)
        .map_err(|error| io_error(RepositoryIoOperation::InspectRoot, &error))?;
    let canonical_metadata = fs::symlink_metadata(&canonical).map_err(|_| unsafe_error.clone())?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.file_type().is_dir() {
        return Err(unsafe_error);
    }
    Ok(canonical)
}

fn lexical_absolute_path(
    path: &Path,
    unsafe_error: RepositoryImportError,
) -> Result<PathBuf, RepositoryImportError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_error(RepositoryIoOperation::InspectRoot, &error))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(unsafe_error);
                }
            }
            Component::Normal(name) => normalized.push(name),
        }
    }
    if normalized.is_absolute() {
        Ok(normalized)
    } else {
        Err(unsafe_error)
    }
}

fn validate_directory_ancestor_chain(
    path: &Path,
    unsafe_error: RepositoryImportError,
) -> Result<(), RepositoryImportError> {
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| unsafe_error.clone())?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(unsafe_error);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_same_filesystem(
    first: &Path,
    second: &Path,
    error: RepositoryImportError,
) -> Result<(), RepositoryImportError> {
    use std::os::unix::fs::MetadataExt as _;
    let first_metadata = fs::symlink_metadata(first).map_err(|_| error.clone())?;
    let second_metadata = fs::symlink_metadata(second).map_err(|_| error.clone())?;
    if first_metadata.dev() == second_metadata.dev() {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
fn require_same_filesystem(
    _first: &Path,
    _second: &Path,
    error: RepositoryImportError,
) -> Result<(), RepositoryImportError> {
    Err(error)
}

#[cfg(not(target_os = "linux"))]
fn require_same_filesystem_metadata(
    _first: &fs::Metadata,
    _second: &fs::Metadata,
    error: RepositoryImportError,
) -> Result<(), RepositoryImportError> {
    Err(error)
}

/// Initialize a fresh target Git repository inside a complete staging vault,
/// then establish recursive durability and independently audit it.
///
/// # Errors
///
/// Returns a scrubbed error if the staging allowlist is unsafe, Git cannot
/// construct the exact root commit, or independent/durability audits fail.
#[allow(clippy::too_many_lines)] // One construction transaction, audited in fixed order.
pub fn initialize_and_audit_target(
    staging_root: &Path,
    tracked_relative_paths: &[PathBuf],
    import_time_utc_seconds: i64,
) -> Result<TargetRepository, RepositoryImportError> {
    let executable =
        discover_git_executable().map_err(|_| RepositoryImportError::GitExecutableUnavailable)?;
    let root = canonical_normal_directory(staging_root, RepositoryImportError::UnsafeTarget)?;
    let root_identity =
        filesystem_directory_identity(&root).map_err(|_| RepositoryImportError::UnsafeTarget)?;
    require_same_filesystem(
        &root,
        &root.join(VAULT_LOCAL_DIRECTORY),
        RepositoryImportError::UnsafeTarget,
    )?;
    match fs::symlink_metadata(root.join(".git")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(RepositoryImportError::UnsafeTarget),
    }
    ensure_exact_target_metadata(&root)?;
    let paths = normalize_target_paths(tracked_relative_paths)?;
    prove_target_worktree_allowlist(&root, &paths, false)?;

    let local = root.join(VAULT_LOCAL_DIRECTORY);
    let template = local.join(format!(
        "{TARGET_TEMPLATE_PREFIX}{}",
        Uuid::new_v4().simple()
    ));
    fs::create_dir(&template)
        .map_err(|error| io_error(RepositoryIoOperation::WriteTarget, &error))?;
    sync_directory(&local).map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?;
    let init_runner = GitRunner::target_uninitialized(executable.clone(), root.clone());
    let init_result = init_runner.run_uninitialized(
        RepositoryGitOperation::InitializeTarget,
        &[
            OsString::from("init"),
            OsString::from("--quiet"),
            OsString::from("--object-format=sha1"),
            OsString::from("--initial-branch=main"),
            OsString::from(format!("--template={}", template.to_string_lossy())),
            OsString::from("."),
        ],
        None,
        1024,
        None,
    );
    let remove_template = fs::remove_dir(&template);
    init_result?;
    remove_template.map_err(|error| io_error(RepositoryIoOperation::WriteTarget, &error))?;
    drop(init_runner);
    let hooks = root.join(".git").join(TARGET_EMPTY_HOOKS_DIRECTORY);
    fs::create_dir(&hooks).map_err(|error| io_error(RepositoryIoOperation::WriteTarget, &error))?;
    sync_directory(&root.join(".git"))
        .map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?;
    let runner = GitRunner::target(executable, root.clone())?;

    let version = runner.run(
        RepositoryGitOperation::InitializeTarget,
        &os_args(["version"]),
        None,
        256,
        None,
    )?;
    validate_git_version(&version).map_err(|error| match error {
        super::GitError::UnsupportedGitVersion => RepositoryImportError::UnsupportedGitVersion,
        _ => RepositoryImportError::MalformedGitOutput,
    })?;
    let driver = installed_driver_command().map_err(|_| RepositoryImportError::UnsafeTarget)?;
    configure_target(&runner, "core.logAllRefUpdates", "false")?;
    configure_target(&runner, "merge.inex.name", DRIVER_NAME)?;
    configure_target(&runner, "merge.inex.driver", &driver)?;
    #[cfg(windows)]
    configure_target(&runner, "core.longPaths", "true")?;

    let mut tracked = Vec::with_capacity(paths.len());
    let mut index_input = Vec::new();
    for path in &paths {
        let held = inspect_target_tracked_entry(&root, path, None)?;
        let oid = one_line(&runner.run(
            RepositoryGitOperation::ConstructTarget,
            &os_args(["hash-object", "-w", "--stdin", "--no-filters"]),
            Some(&held.bytes),
            128,
            None,
        )?)?
        .to_owned();
        require_sha1_oid(&oid)?;
        let expected_oid = typed_git_object_oid("blob", held.bytes.as_slice())?;
        if oid != expected_oid {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        let relative = slash_path(path).ok_or(RepositoryImportError::UnsafeTarget)?;
        index_input.extend_from_slice(b"100644 ");
        index_input.extend_from_slice(oid.as_bytes());
        index_input.push(b'\t');
        index_input.extend_from_slice(relative.as_bytes());
        index_input.push(0);
        tracked.push(TargetTrackedEntry {
            relative_path: path.clone(),
            size: held.bytes.len() as u64,
            sha256: sha256(&held.bytes),
            blob_oid: oid,
            identity: held.identity,
        });
    }
    let expected_trees = construct_canonical_target_trees(&target_blob_manifest(&tracked)?)?;
    let expected_root_tree_oid = &expected_trees
        .get("")
        .ok_or(RepositoryImportError::TargetAuditFailed)?
        .oid;
    runner.run(
        RepositoryGitOperation::ConstructTarget,
        &os_args(["update-index", "-z", "--index-info"]),
        Some(&index_input),
        1024,
        None,
    )?;
    let root_tree_oid = one_line(&runner.run(
        RepositoryGitOperation::ConstructTarget,
        &os_args(["write-tree"]),
        None,
        128,
        None,
    )?)?
    .to_owned();
    require_sha1_oid(&root_tree_oid)?;
    if &root_tree_oid != expected_root_tree_oid {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    drop(expected_trees);
    let date = format!("{import_time_utc_seconds} +0000");
    let identity = GitIdentityEnvironment {
        author_name: "Inex Repository Import",
        author_email: "inex-import@localhost.invalid",
        author_date: &date,
        committer_name: "Inex Repository Import",
        committer_email: "inex-import@localhost.invalid",
        committer_date: &date,
    };
    let root_commit_oid = one_line(&runner.run(
        RepositoryGitOperation::ConstructTarget,
        &[
            OsString::from("commit-tree"),
            OsString::from(&root_tree_oid),
        ],
        Some(IMPORT_MESSAGE),
        128,
        Some(&identity),
    )?)?
    .to_owned();
    require_sha1_oid(&root_commit_oid)?;
    let commit_bytes = canonical_root_commit_bytes(&root_tree_oid, import_time_utc_seconds);
    if typed_git_object_oid("commit", commit_bytes.as_slice())? != root_commit_oid {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    runner.run(
        RepositoryGitOperation::ConstructTarget,
        &[
            OsString::from("update-ref"),
            OsString::from("refs/heads/main"),
            OsString::from(&root_commit_oid),
            OsString::from("0000000000000000000000000000000000000000"),
        ],
        None,
        1024,
        None,
    )?;
    configure_target(&runner, "core.logAllRefUpdates", "true")?;

    let object_ids = target_object_inventory(&runner)?;
    let mut batch = runner.target_object_batch()?;
    batch.verify(&root_commit_oid, "commit", commit_bytes.as_slice())?;
    let tree_oids = validate_expected_target_objects(
        &runner,
        &mut batch,
        &tracked,
        &root_tree_oid,
        &root_commit_oid,
        commit_bytes.len() as u64,
        &object_ids,
    )?;
    batch.finish()?;
    let git_control = inventory_namespace(&root.join(".git"), NamespacePolicy::TargetGit)?;
    let private_control = inventory_namespace(&local, NamespacePolicy::TargetPrivate)?;
    validate_target_git_control(&git_control, &object_ids)?;
    validate_target_private_control(&private_control)?;
    let target = TargetRepository {
        root_identity,
        root_commit_oid,
        root_tree_oid,
        tracked,
        tree_oids,
        object_ids,
        git_control,
        private_control,
        commit_bytes,
    };
    durably_audit_repository_import_target(&root, &target)?;
    Ok(target)
}

/// Perform a read-only independent target audit with no publication marker.
///
/// # Errors
///
/// Returns [`RepositoryImportError::TargetAuditFailed`] when current target
/// state differs from the opaque creation proof.
pub fn audit_repository_import_target(
    root: &Path,
    expected: &TargetRepository,
) -> Result<(), RepositoryImportError> {
    audit_target(root, expected, false)
}

/// Perform the critical read-only audit while the exact generic publication
/// marker is present in `.vault-local`.
///
/// # Errors
///
/// Returns a scrubbed target-audit error for a missing, malformed, or extra
/// private marker entry, or for any other target drift.
pub fn audit_repository_import_target_for_publication(
    root: &Path,
    expected: &TargetRepository,
) -> Result<(), RepositoryImportError> {
    audit_target(root, expected, true)
}

/// Sync every retained target file and every directory in postorder, then
/// repeat the complete independent target audit.
///
/// # Errors
///
/// Returns a scrubbed audit or durability error when any retained target entry
/// cannot be proven and synchronized.
pub fn durably_audit_repository_import_target(
    root: &Path,
    expected: &TargetRepository,
) -> Result<(), RepositoryImportError> {
    audit_target(root, expected, false)?;
    sync_tree_postorder(root)?;
    audit_target(root, expected, false)
}

fn ensure_exact_target_metadata(root: &Path) -> Result<(), RepositoryImportError> {
    ensure_exact_target_file(&root.join(GIT_ATTRIBUTES_FILE), TARGET_ATTRIBUTES)?;
    ensure_exact_target_file(&root.join(GIT_IGNORE_FILE), TARGET_IGNORE)
}

fn ensure_exact_target_file(path: &Path, expected: &[u8]) -> Result<(), RepositoryImportError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|error| io_error(RepositoryIoOperation::WriteTarget, &error))?;
            file.write_all(expected)
                .and_then(|()| file.sync_all())
                .map_err(|error| io_error(RepositoryIoOperation::WriteTarget, &error))?;
        }
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            let held = read_bound_regular_file(
                path,
                MAX_CONFIG_BYTES,
                RepositoryImportError::UnsafeTarget,
            )?;
            if held.bytes.as_slice() != expected {
                return Err(RepositoryImportError::UnsafeTarget);
            }
        }
        _ => return Err(RepositoryImportError::UnsafeTarget),
    }
    Ok(())
}

fn normalize_target_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, RepositoryImportError> {
    let mut normalized = BTreeSet::new();
    for path in paths {
        validate_target_relative_path(path)?;
        normalized.insert(path.clone());
    }
    normalized.insert(PathBuf::from(GIT_ATTRIBUTES_FILE));
    normalized.insert(PathBuf::from(GIT_IGNORE_FILE));
    if !normalized.contains(Path::new("vault.json")) {
        return Err(RepositoryImportError::UnsafeTarget);
    }
    if normalized.len() > MAX_SOURCE_ENTRIES.saturating_add(3) {
        return Err(RepositoryImportError::ResourceLimit);
    }
    Ok(normalized.into_iter().collect())
}

fn validate_target_relative_path(path: &Path) -> Result<(), RepositoryImportError> {
    let text = slash_path(path).ok_or(RepositoryImportError::UnsafeTarget)?;
    if text == "vault.json" || text == GIT_ATTRIBUTES_FILE || text == GIT_IGNORE_FILE {
        if path.components().count() == 1 {
            return Ok(());
        }
        return Err(RepositoryImportError::UnsafeTarget);
    }
    if text.ends_with(".md.enc") {
        LogicalPath::from_ciphertext_relative_path(path)
            .map_err(|_| RepositoryImportError::UnsafeTarget)?;
    } else if text.ends_with(".asset.enc") {
        AssetPath::from_ciphertext_relative_path(path)
            .map_err(|_| RepositoryImportError::UnsafeTarget)?;
    } else {
        return Err(RepositoryImportError::UnsafeTarget);
    }
    Ok(())
}

fn inspect_target_tracked_entry(
    root: &Path,
    path: &Path,
    expected: Option<&TargetTrackedEntry>,
) -> Result<HeldFile, RepositoryImportError> {
    let held = read_target_tracked_file(root, path)?;
    if let Some(expected) = expected
        && (expected.relative_path != path
            || expected.size != held.bytes.len() as u64
            || expected.sha256 != sha256(&held.bytes)
            || expected.identity != held.identity)
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    Ok(held)
}

#[cfg(target_os = "linux")]
fn read_target_tracked_file(root: &Path, path: &Path) -> Result<HeldFile, RepositoryImportError> {
    read_secure_relative_file(
        root,
        path,
        MAX_TARGET_FILE_BYTES,
        &RepositoryImportError::TargetAuditFailed,
    )
}

#[cfg(not(target_os = "linux"))]
fn read_target_tracked_file(root: &Path, path: &Path) -> Result<HeldFile, RepositoryImportError> {
    let _ = (root, path);
    Err(RepositoryImportError::TargetAuditFailed)
}

fn prove_target_worktree_allowlist(
    root: &Path,
    paths: &[PathBuf],
    git_required: bool,
) -> Result<(), RepositoryImportError> {
    let expected_files = paths
        .iter()
        .filter_map(|path| slash_path(path))
        .collect::<BTreeSet<_>>();
    let mut expected_directories = BTreeSet::new();
    for path in paths {
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            expected_directories
                .insert(slash_path(directory).ok_or(RepositoryImportError::TargetAuditFailed)?);
            parent = directory.parent();
        }
    }
    let mut actual_files = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    #[cfg(target_os = "linux")]
    {
        let root =
            open_secure_source_root(root).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let mut entries = 0_usize;
        let mut path_bytes = 0_usize;
        walk_secure_target_worktree(
            &root,
            Path::new(""),
            0,
            git_required,
            &mut actual_files,
            &mut actual_directories,
            &mut entries,
            &mut path_bytes,
        )?;
        root.verify_binding()
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let root_metadata =
            fs::symlink_metadata(root).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        walk_target_worktree(
            root,
            root,
            &root_metadata,
            Path::new(""),
            0,
            git_required,
            &mut actual_files,
            &mut actual_directories,
        )?;
    }
    if actual_files == expected_files && actual_directories == expected_directories {
        Ok(())
    } else {
        Err(RepositoryImportError::TargetAuditFailed)
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn walk_secure_target_worktree(
    directory: &SecureSourceDirectory,
    relative: &Path,
    depth: usize,
    git_required: bool,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
    entries: &mut usize,
    path_bytes: &mut usize,
) -> Result<(), RepositoryImportError> {
    if depth > MAX_TREE_DEPTH {
        return Err(RepositoryImportError::ResourceLimit);
    }
    directory
        .verify_binding()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    for entry in directory
        .read_dir()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?
    {
        let entry = entry.map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        *entries = entries.saturating_add(1);
        if *entries > MAX_SOURCE_ENTRIES.saturating_mul(2) {
            return Err(RepositoryImportError::ResourceLimit);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let child_relative = relative.join(&name);
        let text = slash_path(&child_relative).ok_or(RepositoryImportError::TargetAuditFailed)?;
        *path_bytes = path_bytes.saturating_add(text.len());
        if *path_bytes > MAX_RETAINED_PATH_BYTES {
            return Err(RepositoryImportError::ResourceLimit);
        }
        let child = directory
            .open_child(std::ffi::OsStr::new(&name))
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if relative.as_os_str().is_empty()
            && matches!(name.as_str(), VAULT_LOCAL_DIRECTORY | ".git")
        {
            let SecureSourceChild::Directory(control) = child else {
                return Err(RepositoryImportError::TargetAuditFailed);
            };
            if name == ".git" && !git_required {
                return Err(RepositoryImportError::TargetAuditFailed);
            }
            control
                .verify_binding()
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            continue;
        }
        match child {
            SecureSourceChild::Directory(child) => {
                directories.insert(text);
                walk_secure_target_worktree(
                    &child,
                    &child_relative,
                    depth.saturating_add(1),
                    git_required,
                    files,
                    directories,
                    entries,
                    path_bytes,
                )?;
                child
                    .verify_binding()
                    .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            }
            SecureSourceChild::File(file) => {
                file.verify_binding()
                    .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
                files.insert(text);
            }
            SecureSourceChild::Other => return Err(RepositoryImportError::TargetAuditFailed),
        }
    }
    directory
        .verify_binding()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(target_os = "linux"))]
fn walk_target_worktree(
    root: &Path,
    directory: &Path,
    root_metadata: &fs::Metadata,
    relative: &Path,
    depth: usize,
    git_required: bool,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
) -> Result<(), RepositoryImportError> {
    if depth > MAX_TREE_DEPTH {
        return Err(RepositoryImportError::ResourceLimit);
    }
    for entry in fs::read_dir(directory).map_err(|_| RepositoryImportError::TargetAuditFailed)? {
        let entry = entry.map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if relative.as_os_str().is_empty()
            && matches!(name.as_str(), VAULT_LOCAL_DIRECTORY | ".git")
        {
            let child = root.join(&name);
            filesystem_directory_identity(&child)
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            if name == ".git" && !git_required {
                return Err(RepositoryImportError::TargetAuditFailed);
            }
            continue;
        }
        let child_relative = relative.join(name);
        let text = slash_path(&child_relative).ok_or(RepositoryImportError::TargetAuditFailed)?;
        let path = root.join(&child_relative);
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        require_same_filesystem_metadata(
            root_metadata,
            &metadata,
            RepositoryImportError::TargetAuditFailed,
        )?;
        if metadata.file_type().is_symlink() {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        if metadata.file_type().is_dir() {
            filesystem_directory_identity(&path)
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            directories.insert(text);
            walk_target_worktree(
                root,
                &path,
                root_metadata,
                &child_relative,
                depth.saturating_add(1),
                git_required,
                files,
                directories,
            )?;
        } else if metadata.file_type().is_file() {
            let file = File::open(&path).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            if !open_file_matches_path_and_is_single_link(&path, &file)
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?
            {
                return Err(RepositoryImportError::TargetAuditFailed);
            }
            verify_regular_file_has_no_alternate_data_streams(&path, &file)
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            files.insert(text);
        } else {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
    }
    Ok(())
}

fn audit_target(
    root: &Path,
    expected: &TargetRepository,
    publication_marker: bool,
) -> Result<(), RepositoryImportError> {
    let root = canonical_normal_directory(root, RepositoryImportError::TargetAuditFailed)?;
    if filesystem_directory_identity(&root).ok().as_ref() != Some(&expected.root_identity) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let paths = expected
        .tracked
        .iter()
        .map(|entry| entry.relative_path.clone())
        .collect::<Vec<_>>();
    prove_target_worktree_allowlist(&root, &paths, true)?;
    let executable =
        discover_git_executable().map_err(|_| RepositoryImportError::GitExecutableUnavailable)?;
    let runner = GitRunner::target(executable, root.clone())?;
    prove_target_semantics(&runner, expected)?;
    let git_control = inventory_namespace(&root.join(".git"), NamespacePolicy::TargetGit)?;
    validate_target_git_control(&git_control, &expected.object_ids)?;
    if git_control != expected.git_control {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let private = inventory_namespace(
        &root.join(VAULT_LOCAL_DIRECTORY),
        NamespacePolicy::TargetPrivate,
    )?;
    if publication_marker {
        require_private_manifest_with_marker(&private, &expected.private_control)?;
    } else if private != expected.private_control {
        return Err(RepositoryImportError::TargetAuditFailed);
    } else {
        validate_target_private_control(&private)?;
    }
    revalidate_target_worktree(&root, expected)?;
    Ok(())
}

fn revalidate_target_worktree(
    root: &Path,
    expected: &TargetRepository,
) -> Result<(), RepositoryImportError> {
    if filesystem_directory_identity(root).ok().as_ref() != Some(&expected.root_identity) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let paths = expected
        .tracked
        .iter()
        .map(|entry| entry.relative_path.clone())
        .collect::<Vec<_>>();
    prove_target_worktree_allowlist(root, &paths, true)?;
    for entry in &expected.tracked {
        drop(inspect_target_tracked_entry(
            root,
            &entry.relative_path,
            Some(entry),
        )?);
    }
    if filesystem_directory_identity(root).ok().as_ref() != Some(&expected.root_identity) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep the independent Git invariant audit contiguous.
fn prove_target_semantics(
    runner: &GitRunner,
    expected: &TargetRepository,
) -> Result<(), RepositoryImportError> {
    let object_format = runner.run(
        RepositoryGitOperation::AuditTarget,
        &os_args(["rev-parse", "--show-object-format"]),
        None,
        32,
        None,
    )?;
    if one_line(&object_format)? != "sha1" {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let head_output = runner.run(
        RepositoryGitOperation::AuditTarget,
        &os_args(["rev-parse", "--verify", "HEAD^{commit}"]),
        None,
        128,
        None,
    )?;
    if one_line(&head_output)? != expected.root_commit_oid {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let head_file = read_bound_regular_file(
        &runner.root.join(".git/HEAD"),
        128,
        RepositoryImportError::TargetAuditFailed,
    )?;
    if head_file.bytes.as_slice() != b"ref: refs/heads/main\n" {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let refs = runner.run(
        RepositoryGitOperation::AuditTarget,
        &os_args(["for-each-ref", "--format=%(refname)"]),
        None,
        4096,
        None,
    )?;
    if refs.as_slice() != b"refs/heads/main\n" {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    if fs::symlink_metadata(runner.root.join(".git/logs")).is_ok() {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    validate_target_config(runner)?;

    let mut batch = runner.target_object_batch()?;
    batch.verify(
        &expected.root_commit_oid,
        "commit",
        expected.commit_bytes.as_slice(),
    )?;
    let index = runner.run(
        RepositoryGitOperation::AuditTarget,
        &os_args(["ls-files", "-s", "-z", "--full-name"]),
        None,
        MAX_GIT_OUTPUT,
        None,
    )?;
    let index_map = parse_target_index(&index)?;
    let tree = runner.run(
        RepositoryGitOperation::AuditTarget,
        &[
            OsString::from("ls-tree"),
            OsString::from("-r"),
            OsString::from("-z"),
            OsString::from("--full-tree"),
            OsString::from(&expected.root_commit_oid),
        ],
        None,
        MAX_GIT_OUTPUT,
        None,
    )?;
    let tree_map = parse_target_tree(&tree)?;
    let expected_map = expected
        .tracked
        .iter()
        .map(|entry| {
            (
                slash_path(&entry.relative_path).unwrap_or_default(),
                entry.blob_oid.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if index_map != expected_map || tree_map != expected_map {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    for entry in &expected.tracked {
        let body = inspect_target_tracked_entry(&runner.root, &entry.relative_path, Some(entry))?;
        if typed_git_object_oid("blob", body.bytes.as_slice())? != entry.blob_oid {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        batch.verify(&entry.blob_oid, "blob", body.bytes.as_slice())?;
    }
    let objects = target_object_inventory(runner)?;
    if objects != expected.object_ids {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    if !matches!(
        objects.get(&expected.root_commit_oid),
        Some(descriptor)
            if descriptor.object_type == "commit"
                && descriptor.size
                    == u64::try_from(expected.commit_bytes.len()).unwrap_or(u64::MAX)
    ) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let tree_oids = validate_expected_target_objects(
        runner,
        &mut batch,
        &expected.tracked,
        &expected.root_tree_oid,
        &expected.root_commit_oid,
        expected.commit_bytes.len() as u64,
        &objects,
    )?;
    if tree_oids != expected.tree_oids {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    batch.finish()?;
    Ok(())
}

fn configure_target(
    runner: &GitRunner,
    key: &str,
    value: &str,
) -> Result<(), RepositoryImportError> {
    runner.run(
        RepositoryGitOperation::ConstructTarget,
        &[
            OsString::from("config"),
            OsString::from("--local"),
            OsString::from("--replace-all"),
            OsString::from(key),
            OsString::from(value),
        ],
        None,
        1024,
        None,
    )?;
    Ok(())
}

fn validate_target_config(runner: &GitRunner) -> Result<(), RepositoryImportError> {
    let output = runner.run(
        RepositoryGitOperation::AuditTarget,
        &os_args(["config", "--local", "--null", "--list"]),
        None,
        MAX_CONFIG_BYTES,
        None,
    )?;
    let mut values = BTreeMap::<String, Vec<String>>::new();
    for record in nul_records(&output)? {
        let newline = record
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let key = std::str::from_utf8(&record[..newline])
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?
            .to_ascii_lowercase();
        let value = std::str::from_utf8(&record[newline + 1..])
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?
            .to_owned();
        let allowed = matches!(
            key.as_str(),
            "core.repositoryformatversion"
                | "core.filemode"
                | "core.bare"
                | "core.logallrefupdates"
                | "merge.inex.name"
                | "merge.inex.driver"
        ) || cfg!(windows)
            && matches!(
                key.as_str(),
                "core.longpaths" | "core.symlinks" | "core.ignorecase"
            );
        if !allowed {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        values.entry(key).or_default().push(value);
    }
    require_single_config(&values, "core.repositoryformatversion", "0")?;
    #[cfg(windows)]
    require_single_config(&values, "core.filemode", "false")?;
    #[cfg(not(windows))]
    require_single_config(&values, "core.filemode", "true")?;
    require_single_config(&values, "core.bare", "false")?;
    require_single_config(&values, "core.logallrefupdates", "true")?;
    require_single_config(&values, "merge.inex.name", DRIVER_NAME)?;
    require_single_config(
        &values,
        "merge.inex.driver",
        &installed_driver_command().map_err(|_| RepositoryImportError::TargetAuditFailed)?,
    )?;
    #[cfg(windows)]
    require_single_config(&values, "core.longpaths", "true")?;
    #[cfg(windows)]
    for key in ["core.symlinks", "core.ignorecase"] {
        if let Some(entries) = values.get(key)
            && (entries.len() != 1 || !matches!(entries[0].as_str(), "true" | "false"))
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
    }
    Ok(())
}

fn require_single_config(
    values: &BTreeMap<String, Vec<String>>,
    key: &str,
    expected: &str,
) -> Result<(), RepositoryImportError> {
    if matches!(values.get(key).map(Vec::as_slice), Some([value]) if value == expected) {
        Ok(())
    } else {
        Err(RepositoryImportError::TargetAuditFailed)
    }
}

fn parse_target_index(output: &[u8]) -> Result<BTreeMap<String, String>, RepositoryImportError> {
    let mut result = BTreeMap::new();
    for record in nul_records(output)? {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let metadata = std::str::from_utf8(&record[..tab])
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 || fields[0] != "100644" || fields[2] != "0" {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        require_sha1_oid(fields[1]).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if result
            .insert(path.to_owned(), fields[1].to_owned())
            .is_some()
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
    }
    Ok(result)
}

fn parse_target_tree(output: &[u8]) -> Result<BTreeMap<String, String>, RepositoryImportError> {
    let mut result = BTreeMap::new();
    for record in nul_records(output)? {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let metadata = std::str::from_utf8(&record[..tab])
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 || fields[0] != "100644" || fields[1] != "blob" {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        require_sha1_oid(fields[2]).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if result
            .insert(path.to_owned(), fields[2].to_owned())
            .is_some()
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
    }
    Ok(result)
}

fn target_object_inventory(
    runner: &GitRunner,
) -> Result<BTreeMap<String, ObjectDescriptor>, RepositoryImportError> {
    let output = runner.run(
        RepositoryGitOperation::AuditTarget,
        &[
            OsString::from("cat-file"),
            OsString::from("--batch-all-objects"),
            OsString::from("--batch-check=%(objectname) %(objecttype) %(objectsize)"),
        ],
        None,
        MAX_GIT_OUTPUT,
        None,
    )?;
    let text =
        std::str::from_utf8(&output).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        require_sha1_oid(fields[0]).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if !matches!(fields[1], "blob" | "tree" | "commit") {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        let size = fields[2]
            .parse::<u64>()
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if result
            .insert(
                fields[0].to_owned(),
                ObjectDescriptor {
                    object_type: fields[1].to_owned(),
                    size,
                },
            )
            .is_some()
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
    }
    Ok(result)
}

fn validate_expected_target_objects(
    runner: &GitRunner,
    batch: &mut TargetObjectBatch<'_>,
    tracked: &[TargetTrackedEntry],
    root_tree_oid: &str,
    root_commit_oid: &str,
    root_commit_size: u64,
    objects: &BTreeMap<String, ObjectDescriptor>,
) -> Result<BTreeMap<String, String>, RepositoryImportError> {
    let output = runner.run(
        RepositoryGitOperation::AuditTarget,
        &[
            OsString::from("ls-tree"),
            OsString::from("-r"),
            OsString::from("-t"),
            OsString::from("-z"),
            OsString::from("--full-tree"),
            OsString::from(root_commit_oid),
        ],
        None,
        MAX_GIT_OUTPUT,
        None,
    )?;
    let expected_blobs = target_blob_manifest(tracked)?;
    let expected_trees = construct_canonical_target_trees(&expected_blobs)?;
    let (observed_blobs, observed_trees) = parse_recursive_target_tree(&output, root_tree_oid)?;
    if observed_blobs
        != expected_blobs
            .iter()
            .map(|(path, (oid, _))| (path.clone(), oid.clone()))
            .collect::<BTreeMap<_, _>>()
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }

    let expected_tree_oids = expected_trees
        .iter()
        .map(|(path, object)| (path.clone(), object.oid.clone()))
        .collect::<BTreeMap<_, _>>();
    if observed_trees != expected_tree_oids {
        return Err(RepositoryImportError::TargetAuditFailed);
    }

    validate_target_object_inventory(
        &expected_blobs,
        &expected_trees,
        root_commit_oid,
        root_commit_size,
        objects,
    )?;
    prove_expected_target_trees(batch, &expected_trees, objects)?;
    Ok(expected_tree_oids)
}

fn target_blob_manifest(
    tracked: &[TargetTrackedEntry],
) -> Result<BTreeMap<String, (String, u64)>, RepositoryImportError> {
    let manifest = tracked
        .iter()
        .map(|entry| {
            Ok((
                slash_path(&entry.relative_path).ok_or(RepositoryImportError::TargetAuditFailed)?,
                (entry.blob_oid.clone(), entry.size),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if manifest.len() == tracked.len() {
        Ok(manifest)
    } else {
        Err(RepositoryImportError::TargetAuditFailed)
    }
}

fn parse_recursive_target_tree(
    output: &[u8],
    root_tree_oid: &str,
) -> Result<(TargetOidByPath, TargetOidByPath), RepositoryImportError> {
    let mut observed_blobs = BTreeMap::new();
    let mut observed_trees = BTreeMap::from([(String::new(), root_tree_oid.to_owned())]);
    for record in nul_records(output)? {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let fields = std::str::from_utf8(&record[..tab])
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if fields.len() != 3 {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        require_sha1_oid(fields[2]).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let destination = match (fields[0], fields[1]) {
            ("100644", "blob") => &mut observed_blobs,
            ("040000", "tree") => &mut observed_trees,
            _ => return Err(RepositoryImportError::TargetAuditFailed),
        };
        if destination
            .insert(path.to_owned(), fields[2].to_owned())
            .is_some()
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
    }
    Ok((observed_blobs, observed_trees))
}

fn validate_target_object_inventory(
    expected_blobs: &BTreeMap<String, (String, u64)>,
    expected_trees: &CanonicalTreesByPath,
    root_commit_oid: &str,
    root_commit_size: u64,
    objects: &BTreeMap<String, ObjectDescriptor>,
) -> Result<(), RepositoryImportError> {
    let mut expected_ids = BTreeSet::from([root_commit_oid.to_owned()]);
    expected_ids.extend(expected_blobs.values().map(|(oid, _)| oid.clone()));
    expected_ids.extend(expected_trees.values().map(|object| object.oid.clone()));
    if objects.keys().cloned().collect::<BTreeSet<_>>() != expected_ids {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    for (oid, size) in expected_blobs.values() {
        if !matches!(objects.get(oid), Some(descriptor) if descriptor.object_type == "blob" && descriptor.size == *size)
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
    }
    if !matches!(objects.get(root_commit_oid), Some(descriptor) if descriptor.object_type == "commit" && descriptor.size == root_commit_size)
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    Ok(())
}

fn prove_expected_target_trees(
    batch: &mut TargetObjectBatch<'_>,
    expected_trees: &CanonicalTreesByPath,
    objects: &BTreeMap<String, ObjectDescriptor>,
) -> Result<(), RepositoryImportError> {
    let mut directories = expected_trees.keys().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        target_tree_depth(right)
            .cmp(&target_tree_depth(left))
            .then_with(|| left.cmp(right))
    });
    for directory in directories {
        let object = expected_trees
            .get(directory)
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        if !matches!(objects.get(&object.oid), Some(descriptor) if descriptor.object_type == "tree" && descriptor.size == object.body.len() as u64)
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        batch.verify(&object.oid, "tree", object.body.as_slice())?;
    }
    Ok(())
}

fn construct_canonical_target_trees(
    expected_blobs: &BTreeMap<String, (String, u64)>,
) -> Result<CanonicalTreesByPath, RepositoryImportError> {
    let expected_directories = expected_target_tree_directories(expected_blobs.keys())?;
    let mut entries_by_directory = expected_directories
        .iter()
        .map(|directory| (directory.clone(), Vec::new()))
        .collect::<BTreeMap<_, Vec<CanonicalTreeEntry>>>();
    for (path, (oid, _)) in expected_blobs {
        require_sha1_oid(oid).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let (parent, name) = target_tree_parent_and_name(path)?;
        entries_by_directory
            .get_mut(parent)
            .ok_or(RepositoryImportError::TargetAuditFailed)?
            .push(CanonicalTreeEntry {
                name: name.to_owned(),
                oid: oid.clone(),
                directory: false,
            });
    }

    let mut directories = expected_directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        target_tree_depth(right)
            .cmp(&target_tree_depth(left))
            .then_with(|| left.cmp(right))
    });
    let mut objects = BTreeMap::new();
    let mut total_tree_bytes = 0_usize;
    for directory in directories {
        let mut entries = entries_by_directory
            .remove(&directory)
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let body = serialize_canonical_tree(&mut entries)?;
        total_tree_bytes = total_tree_bytes
            .checked_add(body.len())
            .filter(|total| *total <= MAX_RETAINED_PATH_BYTES)
            .ok_or(RepositoryImportError::ResourceLimit)?;
        let oid = typed_git_object_oid("tree", body.as_slice())?;
        if !directory.is_empty() {
            let (parent, name) = target_tree_parent_and_name(&directory)?;
            entries_by_directory
                .get_mut(parent)
                .ok_or(RepositoryImportError::TargetAuditFailed)?
                .push(CanonicalTreeEntry {
                    name: name.to_owned(),
                    oid: oid.clone(),
                    directory: true,
                });
        }
        objects.insert(directory, CanonicalTreeObject { oid, body });
    }
    if entries_by_directory.is_empty() {
        Ok(objects)
    } else {
        Err(RepositoryImportError::TargetAuditFailed)
    }
}

fn expected_target_tree_directories<'a>(
    paths: impl Iterator<Item = &'a String>,
) -> Result<BTreeSet<String>, RepositoryImportError> {
    let mut directories = BTreeSet::from([String::new()]);
    for path in paths {
        let mut parent = Path::new(path).parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            directories
                .insert(slash_path(directory).ok_or(RepositoryImportError::TargetAuditFailed)?);
            parent = directory.parent();
        }
    }
    Ok(directories)
}

fn target_tree_parent_and_name(path: &str) -> Result<(&str, &str), RepositoryImportError> {
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    Ok((parent, name))
}

fn target_tree_depth(path: &str) -> usize {
    if path.is_empty() {
        0
    } else {
        path.bytes().filter(|byte| *byte == b'/').count() + 1
    }
}

fn serialize_canonical_tree(
    entries: &mut [CanonicalTreeEntry],
) -> Result<Zeroizing<Vec<u8>>, RepositoryImportError> {
    entries.sort_by(|left, right| {
        left.name
            .as_bytes()
            .iter()
            .copied()
            .chain(left.directory.then_some(b'/'))
            .cmp(
                right
                    .name
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain(right.directory.then_some(b'/')),
            )
    });
    if entries.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let mut body = Zeroizing::new(Vec::new());
    for entry in entries {
        let oid = decode_sha1_oid(&entry.oid)?;
        body.extend_from_slice(if entry.directory {
            b"40000 "
        } else {
            b"100644 "
        });
        body.extend_from_slice(entry.name.as_bytes());
        body.push(0);
        body.extend_from_slice(&oid);
        if body.len() > MAX_TARGET_OBJECT_BYTES {
            return Err(RepositoryImportError::ResourceLimit);
        }
    }
    Ok(body)
}

fn decode_sha1_oid(oid: &str) -> Result<[u8; 20], RepositoryImportError> {
    require_sha1_oid(oid).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    let mut bytes = [0_u8; 20];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&oid[index * 2..index * 2 + 2], 16)
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    }
    Ok(bytes)
}

fn canonical_root_commit_bytes(root_tree_oid: &str, timestamp: i64) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        format!(
        "tree {root_tree_oid}\nauthor {IMPORT_AUTHOR} {timestamp} +0000\ncommitter {IMPORT_AUTHOR} {timestamp} +0000\n\n{}",
        std::str::from_utf8(IMPORT_MESSAGE).unwrap_or_default()
        )
        .into_bytes(),
    )
}

fn validate_target_git_control(
    control: &[NamespaceSeal],
    objects: &BTreeMap<String, ObjectDescriptor>,
) -> Result<(), RepositoryImportError> {
    let mut expected_directories = BTreeSet::from([
        "objects".to_owned(),
        "objects/info".to_owned(),
        "objects/pack".to_owned(),
        TARGET_EMPTY_HOOKS_DIRECTORY.to_owned(),
        "refs".to_owned(),
        "refs/heads".to_owned(),
        "refs/tags".to_owned(),
    ]);
    let mut expected_files = BTreeSet::from([
        "HEAD".to_owned(),
        "config".to_owned(),
        "index".to_owned(),
        "refs/heads/main".to_owned(),
    ]);
    for oid in objects.keys() {
        require_sha1_oid(oid).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        expected_directories.insert(format!("objects/{}", &oid[..2]));
        expected_files.insert(format!("objects/{}/{}", &oid[..2], &oid[2..]));
    }
    let actual_directories = control
        .iter()
        .filter(|entry| matches!(entry.kind, NamespaceKind::Directory(_)))
        .map(|entry| entry.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let actual_files = control
        .iter()
        .filter(|entry| matches!(entry.kind, NamespaceKind::File(_)))
        .map(|entry| entry.relative_path.clone())
        .collect::<BTreeSet<_>>();
    if actual_directories == expected_directories && actual_files == expected_files {
        Ok(())
    } else {
        Err(RepositoryImportError::TargetAuditFailed)
    }
}

fn validate_target_private_control(control: &[NamespaceSeal]) -> Result<(), RepositoryImportError> {
    if matches!(
        control,
        [NamespaceSeal {
            relative_path,
            kind: NamespaceKind::File(_),
            size: 0,
            sha256: Some(digest),
        }] if relative_path == VAULT_MUTATION_LOCK_FILE && *digest == sha256(&[])
    ) {
        Ok(())
    } else {
        Err(RepositoryImportError::TargetAuditFailed)
    }
}

fn require_private_manifest_with_marker(
    current: &[NamespaceSeal],
    baseline: &[NamespaceSeal],
) -> Result<(), RepositoryImportError> {
    let marker_index = current
        .iter()
        .position(|entry| entry.relative_path == IMPORT_PUBLISH_MARKER)
        .ok_or(RepositoryImportError::TargetAuditFailed)?;
    let marker = &current[marker_index];
    if marker.size != 16
        || marker.sha256.is_none()
        || !matches!(marker.kind, NamespaceKind::File(_))
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let mut without_marker = current.to_vec();
    without_marker.remove(marker_index);
    if without_marker == baseline {
        Ok(())
    } else {
        Err(RepositoryImportError::TargetAuditFailed)
    }
}

fn sync_tree_postorder(root: &Path) -> Result<(), RepositoryImportError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(RepositoryImportError::DurabilityNotConfirmed);
    }
    sync_directory_recursive(root)?;
    sync_directory(root).map_err(|_| RepositoryImportError::DurabilityNotConfirmed)
}

fn sync_directory_recursive(directory: &Path) -> Result<(), RepositoryImportError> {
    for entry in
        fs::read_dir(directory).map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?
    {
        let entry = entry.map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?;
        if metadata.file_type().is_symlink() {
            return Err(RepositoryImportError::DurabilityNotConfirmed);
        }
        if metadata.file_type().is_dir() {
            sync_directory_recursive(&path)?;
            sync_directory(&path).map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?;
        } else if metadata.file_type().is_file() {
            let file = OpenOptions::new()
                .read(true)
                .write(cfg!(windows))
                .open(&path)
                .map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?;
            if !open_file_matches_path_and_is_single_link(&path, &file)
                .map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?
            {
                return Err(RepositoryImportError::DurabilityNotConfirmed);
            }
            file.sync_all()
                .map_err(|_| RepositoryImportError::DurabilityNotConfirmed)?;
        } else {
            return Err(RepositoryImportError::DurabilityNotConfirmed);
        }
    }
    Ok(())
}

struct GitRunner {
    executable: PathBuf,
    root: PathBuf,
    target: bool,
    source_binding: Option<Arc<SourceCommandBinding>>,
    #[cfg(target_os = "linux")]
    target_hooks: Option<SecureSourceDirectory>,
}

struct GitIdentityEnvironment<'a> {
    author_name: &'a str,
    author_email: &'a str,
    author_date: &'a str,
    committer_name: &'a str,
    committer_email: &'a str,
    committer_date: &'a str,
}

impl GitRunner {
    #[cfg(target_os = "linux")]
    fn source(executable: PathBuf, root: PathBuf) -> Self {
        Self {
            executable,
            root,
            target: false,
            source_binding: None,
            #[cfg(target_os = "linux")]
            target_hooks: None,
        }
    }

    fn source_bound(
        executable: PathBuf,
        root: PathBuf,
        source_binding: Arc<SourceCommandBinding>,
    ) -> Self {
        Self {
            executable,
            root,
            target: false,
            source_binding: Some(source_binding),
            #[cfg(target_os = "linux")]
            target_hooks: None,
        }
    }

    fn target_uninitialized(executable: PathBuf, root: PathBuf) -> Self {
        Self {
            executable,
            root,
            target: true,
            source_binding: None,
            #[cfg(target_os = "linux")]
            target_hooks: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn target(executable: PathBuf, root: PathBuf) -> Result<Self, RepositoryImportError> {
        let hooks_path = root.join(".git").join(TARGET_EMPTY_HOOKS_DIRECTORY);
        let target_hooks = open_secure_source_root(&hooks_path)
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let runner = Self {
            executable,
            root,
            target: true,
            source_binding: None,
            target_hooks: Some(target_hooks),
        };
        runner.verify_runtime_bindings()?;
        Ok(runner)
    }

    #[cfg(not(target_os = "linux"))]
    fn target(executable: PathBuf, root: PathBuf) -> Result<Self, RepositoryImportError> {
        let _ = (executable, root);
        Err(RepositoryImportError::UnsafeTarget)
    }

    fn verify_runtime_bindings(&self) -> Result<(), RepositoryImportError> {
        #[cfg(target_os = "linux")]
        if let Some(binding) = &self.source_binding {
            binding.verify_light()?;
        }
        #[cfg(not(target_os = "linux"))]
        if self.source_binding.is_some() {
            return Err(RepositoryImportError::UnsupportedSourceRepository);
        }
        #[cfg(target_os = "linux")]
        if let Some(hooks) = &self.target_hooks {
            hooks
                .verify_binding()
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            let mut entries = hooks
                .read_dir()
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            if entries.next().is_some() {
                return Err(RepositoryImportError::TargetAuditFailed);
            }
            hooks
                .verify_binding()
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        }
        Ok(())
    }

    fn target_object_batch(&self) -> Result<TargetObjectBatch<'_>, RepositoryImportError> {
        self.target_object_batch_with_timeout(GIT_TIMEOUT)
    }

    fn target_object_batch_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<TargetObjectBatch<'_>, RepositoryImportError> {
        self.verify_runtime_bindings()?;
        if !self.target || timeout.is_zero() {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.root).args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "submodule.recurse=false",
            "-c",
            "core.splitIndex=false",
        ]);
        #[cfg(target_os = "linux")]
        if self.target_hooks.is_some() {
            command.args(["-c", "core.hooksPath=.git/inex-empty-hooks"]);
        }
        #[cfg(windows)]
        command.args(["-c", "core.longPaths=true"]);
        command
            .args(["cat-file", "--batch"])
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", null_device())
            .env("GIT_CONFIG_GLOBAL", null_device())
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .env("GIT_PAGER", "cat")
            .env("PAGER", "cat")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("GIT_DIR", self.root.join(".git"))
            .env("GIT_WORK_TREE", &self.root)
            .env("GIT_INDEX_FILE", self.root.join(".git/index"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        copy_platform_process_environment(&mut command);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                self.verify_runtime_bindings()?;
                return Err(io_error(RepositoryIoOperation::SpawnGit, &error));
            }
        };
        if let Err(error) = self.verify_runtime_bindings() {
            let _ = kill_and_wait(&mut child);
            return Err(error);
        }
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (Some(stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
            let _ = kill_and_wait(&mut child);
            return Err(RepositoryImportError::Io {
                operation: RepositoryIoOperation::CommunicateGit,
                kind: io::ErrorKind::BrokenPipe,
            });
        };
        let stderr_too_large = Arc::new(AtomicBool::new(false));
        let stderr_limit = Arc::clone(&stderr_too_large);
        let stderr_reader = std::thread::spawn(move || {
            let mut stderr = stderr;
            let mut output = Zeroizing::new(Vec::new());
            let result = read_output_bounded(&mut stderr, &mut output, MAX_GIT_STDERR_BYTES);
            if matches!(result, Err(ReadOutputError::TooLarge)) {
                stderr_limit.store(true, Ordering::Release);
            }
            (result, output)
        });
        Ok(TargetObjectBatch {
            runner: self,
            child: Some(child),
            stdin: Some(stdin),
            stdout,
            stderr_reader: Some(stderr_reader),
            stderr_too_large,
            timeout,
            finished: false,
        })
    }

    fn run(
        &self,
        operation: RepositoryGitOperation,
        arguments: &[OsString],
        input: Option<&[u8]>,
        maximum_output: usize,
        identity: Option<&GitIdentityEnvironment<'_>>,
    ) -> Result<Zeroizing<Vec<u8>>, RepositoryImportError> {
        self.run_inner(
            operation,
            arguments,
            input,
            maximum_output,
            identity,
            true,
            true,
        )
    }

    #[cfg(target_os = "linux")]
    fn run_without_prefix(
        &self,
        operation: RepositoryGitOperation,
        arguments: &[OsString],
        input: Option<&[u8]>,
        maximum_output: usize,
        identity: Option<&GitIdentityEnvironment<'_>>,
    ) -> Result<Zeroizing<Vec<u8>>, RepositoryImportError> {
        self.run_inner(
            operation,
            arguments,
            input,
            maximum_output,
            identity,
            false,
            false,
        )
    }

    fn run_uninitialized(
        &self,
        operation: RepositoryGitOperation,
        arguments: &[OsString],
        input: Option<&[u8]>,
        maximum_output: usize,
        identity: Option<&GitIdentityEnvironment<'_>>,
    ) -> Result<Zeroizing<Vec<u8>>, RepositoryImportError> {
        self.run_inner(
            operation,
            arguments,
            input,
            maximum_output,
            identity,
            true,
            false,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_inner(
        &self,
        operation: RepositoryGitOperation,
        arguments: &[OsString],
        input: Option<&[u8]>,
        maximum_output: usize,
        identity: Option<&GitIdentityEnvironment<'_>>,
        prefix: bool,
        repository_environment: bool,
    ) -> Result<Zeroizing<Vec<u8>>, RepositoryImportError> {
        self.verify_runtime_bindings()?;
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.root);
        if prefix {
            command.args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "protocol.allow=never",
                "-c",
                "submodule.recurse=false",
            ]);
            if self.target {
                command.args(["-c", "core.splitIndex=false"]);
                #[cfg(target_os = "linux")]
                if self.target_hooks.is_some() {
                    command.args(["-c", "core.hooksPath=.git/inex-empty-hooks"]);
                }
                #[cfg(windows)]
                command.args(["-c", "core.longPaths=true"]);
            }
        }
        command
            .args(arguments)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", null_device())
            .env("GIT_CONFIG_GLOBAL", null_device())
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_PROTOCOL_FROM_USER", "0")
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
        if self.target && repository_environment {
            command
                .env("GIT_DIR", self.root.join(".git"))
                .env("GIT_WORK_TREE", &self.root)
                .env("GIT_INDEX_FILE", self.root.join(".git/index"));
        }
        if let Some(identity) = identity {
            command
                .env("GIT_AUTHOR_NAME", identity.author_name)
                .env("GIT_AUTHOR_EMAIL", identity.author_email)
                .env("GIT_AUTHOR_DATE", identity.author_date)
                .env("GIT_COMMITTER_NAME", identity.committer_name)
                .env("GIT_COMMITTER_EMAIL", identity.committer_email)
                .env("GIT_COMMITTER_DATE", identity.committer_date);
        }
        copy_platform_process_environment(&mut command);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                self.verify_runtime_bindings()?;
                return Err(io_error(RepositoryIoOperation::SpawnGit, &error));
            }
        };
        let stdout = child.stdout.take().ok_or(RepositoryImportError::Io {
            operation: RepositoryIoOperation::CommunicateGit,
            kind: io::ErrorKind::BrokenPipe,
        })?;
        let mut child_stdin = child.stdin.take();
        let output_too_large = AtomicBool::new(false);
        let communication = std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let mut stdout = stdout;
                let mut output = Zeroizing::new(Vec::with_capacity(maximum_output.min(64 * 1024)));
                let result = read_output_bounded(&mut stdout, &mut output, maximum_output);
                if matches!(result, Err(ReadOutputError::TooLarge)) {
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
            let deadline = Instant::now() + GIT_TIMEOUT;
            let (status, timed_out) = loop {
                if output_too_large.load(Ordering::Acquire) {
                    let _ = child.kill();
                    let status = child
                        .wait()
                        .map_err(|error| io_error(RepositoryIoOperation::CommunicateGit, &error))?;
                    break (status, false);
                }
                if let Some(status) = child
                    .try_wait()
                    .map_err(|error| io_error(RepositoryIoOperation::CommunicateGit, &error))?
                {
                    break (status, false);
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let status = child
                        .wait()
                        .map_err(|error| io_error(RepositoryIoOperation::CommunicateGit, &error))?;
                    break (status, true);
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let read = reader.join().map_err(|_| RepositoryImportError::Io {
                operation: RepositoryIoOperation::CommunicateGit,
                kind: io::ErrorKind::Other,
            })?;
            let write = writer.map(std::thread::ScopedJoinHandle::join).transpose();
            Ok::<_, RepositoryImportError>((read, write, status, timed_out))
        });
        let (read_result, write_result, status, timed_out) = match communication {
            Ok(result) => result,
            Err(error) => {
                self.verify_runtime_bindings()?;
                return Err(error);
            }
        };
        self.verify_runtime_bindings()?;
        let (read_status, output) = read_result;
        if timed_out {
            return Err(RepositoryImportError::GitCommandFailed { operation });
        }
        match read_status {
            Ok(()) => {}
            Err(ReadOutputError::TooLarge) => return Err(RepositoryImportError::ResourceLimit),
            Err(ReadOutputError::Io(error)) => {
                return Err(io_error(RepositoryIoOperation::CommunicateGit, &error));
            }
        }
        let written = write_result.map_err(|_| RepositoryImportError::Io {
            operation: RepositoryIoOperation::CommunicateGit,
            kind: io::ErrorKind::Other,
        })?;
        if let Some(written) = written {
            written.map_err(|error| io_error(RepositoryIoOperation::CommunicateGit, &error))?;
        }
        if !status.success() {
            return Err(RepositoryImportError::GitCommandFailed { operation });
        }
        Ok(output)
    }
}

type BoundedStderrReader =
    std::thread::JoinHandle<(Result<(), ReadOutputError>, Zeroizing<Vec<u8>>)>;

struct TargetObjectBatch<'a> {
    runner: &'a GitRunner,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr_reader: Option<BoundedStderrReader>,
    stderr_too_large: Arc<AtomicBool>,
    timeout: Duration,
    finished: bool,
}

impl TargetObjectBatch<'_> {
    #[allow(clippy::too_many_lines)] // One bounded request/response and forced-shutdown transaction.
    fn verify(
        &mut self,
        oid: &str,
        object_type: &str,
        expected: &[u8],
    ) -> Result<(), RepositoryImportError> {
        require_sha1_oid(oid).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if !matches!(object_type, "blob" | "tree" | "commit") {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        validate_target_object_stream_length(expected.len() as u64)?;
        self.runner.verify_runtime_bindings()?;
        let stdin = self
            .stdin
            .as_mut()
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        if let Err(error) = stdin
            .write_all(oid.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
        {
            let _ = self.terminate();
            if self.finished {
                let _ = self.join_stderr();
            }
            self.runner.verify_runtime_bindings()?;
            return Err(io_error(RepositoryIoOperation::CommunicateGit, &error));
        }

        let completed = AtomicBool::new(false);
        let failed = AtomicBool::new(false);
        let stderr_too_large = Arc::clone(&self.stderr_too_large);
        let deadline = Instant::now() + self.timeout;
        let child = self
            .child
            .as_mut()
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let stdout = &mut self.stdout;
        let stdin_slot = &mut self.stdin;
        let communication = std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let result = read_batch_object_exact(stdout, oid, object_type, expected);
                if result.is_err() {
                    failed.store(true, Ordering::Release);
                }
                completed.store(true, Ordering::Release);
                result
            });
            let mut control_error = None;
            let mut reaped = false;
            loop {
                if stderr_too_large.load(Ordering::Acquire) {
                    stdin_slot.take();
                    let (error, child_reaped) =
                        shutdown_batch_child(child, RepositoryImportError::ResourceLimit);
                    control_error = Some(error);
                    reaped = child_reaped;
                    break;
                }
                if failed.load(Ordering::Acquire) {
                    stdin_slot.take();
                    let (error, child_reaped) =
                        shutdown_batch_child(child, RepositoryImportError::TargetAuditFailed);
                    control_error = Some(error);
                    reaped = child_reaped;
                    break;
                }
                match child.try_wait() {
                    Ok(Some(_status)) => {
                        stdin_slot.take();
                        control_error = Some(RepositoryImportError::GitCommandFailed {
                            operation: RepositoryGitOperation::AuditTarget,
                        });
                        reaped = true;
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        stdin_slot.take();
                        let preferred = io_error(RepositoryIoOperation::CommunicateGit, &error);
                        let (error, child_reaped) = shutdown_batch_child(child, preferred);
                        control_error = Some(error);
                        reaped = child_reaped;
                        break;
                    }
                }
                if completed.load(Ordering::Acquire) {
                    break;
                }
                if Instant::now() >= deadline {
                    stdin_slot.take();
                    let (error, child_reaped) = shutdown_batch_child(
                        child,
                        RepositoryImportError::GitCommandFailed {
                            operation: RepositoryGitOperation::AuditTarget,
                        },
                    );
                    control_error = Some(error);
                    reaped = child_reaped;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let read_result = reader.join().map_err(|_| RepositoryImportError::Io {
                operation: RepositoryIoOperation::CommunicateGit,
                kind: io::ErrorKind::Other,
            })?;
            Ok::<_, RepositoryImportError>((read_result, control_error, reaped))
        });
        let binding_result = self.runner.verify_runtime_bindings();
        binding_result?;
        let (read_result, control_error, reaped) = communication?;
        if reaped {
            self.finished = true;
            self.stdin.take();
        }
        if control_error.is_none() && read_result.is_err() && !self.finished {
            let _ = self.terminate();
        }
        let stderr_result = if self.finished {
            self.join_stderr()
        } else {
            Ok(())
        };
        self.runner.verify_runtime_bindings()?;
        if let Some(error) = control_error {
            return Err(error);
        }
        stderr_result?;
        match read_result {
            Ok(()) => Ok(()),
            Err(BatchReadError::Mismatch) => Err(RepositoryImportError::TargetAuditFailed),
            Err(BatchReadError::Io(error)) => {
                Err(io_error(RepositoryIoOperation::CommunicateGit, &error))
            }
        }
    }

    #[allow(clippy::too_many_lines)] // EOF, child, stderr, timeout, and binding checks are one close.
    fn finish(mut self) -> Result<(), RepositoryImportError> {
        self.runner.verify_runtime_bindings()?;
        self.stdin.take();
        let failed = AtomicBool::new(false);
        let stderr_too_large = Arc::clone(&self.stderr_too_large);
        let deadline = Instant::now() + self.timeout;
        let child = self
            .child
            .as_mut()
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let stdout = &mut self.stdout;
        let communication = std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let result = read_batch_eof(stdout);
                if result.is_err() {
                    failed.store(true, Ordering::Release);
                }
                result
            });
            let mut control_error = None;
            let status = loop {
                if stderr_too_large.load(Ordering::Acquire) {
                    match kill_and_wait(child) {
                        Ok(status) => {
                            control_error = Some(RepositoryImportError::ResourceLimit);
                            break Some(status);
                        }
                        Err(error) => {
                            control_error = Some(error);
                            break None;
                        }
                    }
                }
                if failed.load(Ordering::Acquire) {
                    match kill_and_wait(child) {
                        Ok(status) => {
                            control_error = Some(RepositoryImportError::TargetAuditFailed);
                            break Some(status);
                        }
                        Err(error) => {
                            control_error = Some(error);
                            break None;
                        }
                    }
                }
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) => {}
                    Err(error) => {
                        let preferred = io_error(RepositoryIoOperation::CommunicateGit, &error);
                        match kill_and_wait(child) {
                            Ok(status) => {
                                control_error = Some(preferred);
                                break Some(status);
                            }
                            Err(shutdown_error) => {
                                control_error = Some(shutdown_error);
                                break None;
                            }
                        }
                    }
                }
                if Instant::now() >= deadline {
                    match kill_and_wait(child) {
                        Ok(status) => {
                            control_error = Some(RepositoryImportError::GitCommandFailed {
                                operation: RepositoryGitOperation::AuditTarget,
                            });
                            break Some(status);
                        }
                        Err(error) => {
                            control_error = Some(error);
                            break None;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let read_result = reader.join().map_err(|_| RepositoryImportError::Io {
                operation: RepositoryIoOperation::CommunicateGit,
                kind: io::ErrorKind::Other,
            })?;
            Ok::<_, RepositoryImportError>((read_result, status, control_error))
        });
        let binding_result = self.runner.verify_runtime_bindings();
        binding_result?;
        let (read_result, status, control_error) = communication?;
        self.finished = status.is_some();
        let stderr_result = if self.finished {
            self.join_stderr()
        } else {
            Ok(())
        };
        self.runner.verify_runtime_bindings()?;
        if let Some(error) = control_error {
            return Err(error);
        }
        stderr_result?;
        let status = status.ok_or(RepositoryImportError::TargetAuditFailed)?;
        if !status.success() {
            return Err(RepositoryImportError::GitCommandFailed {
                operation: RepositoryGitOperation::AuditTarget,
            });
        }
        match read_result {
            Ok(()) => Ok(()),
            Err(BatchReadError::Mismatch) => Err(RepositoryImportError::TargetAuditFailed),
            Err(BatchReadError::Io(error)) => {
                Err(io_error(RepositoryIoOperation::CommunicateGit, &error))
            }
        }
    }

    fn terminate(&mut self) -> Result<ExitStatus, RepositoryImportError> {
        self.stdin.take();
        let child = self
            .child
            .as_mut()
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let result = kill_and_wait(child);
        self.finished = result.is_ok();
        result
    }

    fn join_stderr(&mut self) -> Result<(), RepositoryImportError> {
        if !self.finished {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        let Some(reader) = self.stderr_reader.take() else {
            return Ok(());
        };
        let (result, _output) = reader.join().map_err(|_| RepositoryImportError::Io {
            operation: RepositoryIoOperation::CommunicateGit,
            kind: io::ErrorKind::Other,
        })?;
        match result {
            Ok(()) => Ok(()),
            Err(ReadOutputError::TooLarge) => Err(RepositoryImportError::ResourceLimit),
            Err(ReadOutputError::Io(error)) => {
                Err(io_error(RepositoryIoOperation::CommunicateGit, &error))
            }
        }
    }
}

impl Drop for TargetObjectBatch<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.terminate();
        }
        if self.finished {
            let _ = self.join_stderr();
        }
    }
}

fn kill_and_wait(child: &mut Child) -> Result<ExitStatus, RepositoryImportError> {
    let deadline = Instant::now() + GIT_TERMINATION_TIMEOUT;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| io_error(RepositoryIoOperation::CommunicateGit, &error))?
        {
            return Ok(status);
        }
        let _ = child.kill();
        if let Some(status) = child
            .try_wait()
            .map_err(|error| io_error(RepositoryIoOperation::CommunicateGit, &error))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(RepositoryImportError::GitCommandFailed {
                operation: RepositoryGitOperation::AuditTarget,
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn shutdown_batch_child(
    child: &mut Child,
    preferred: RepositoryImportError,
) -> (RepositoryImportError, bool) {
    match kill_and_wait(child) {
        Ok(_) => (preferred, true),
        Err(error) => (error, false),
    }
}

#[derive(Debug)]
enum BatchReadError {
    Mismatch,
    Io(io::Error),
}

fn read_batch_object_exact(
    reader: &mut impl Read,
    expected_oid: &str,
    expected_type: &str,
    expected_body: &[u8],
) -> Result<(), BatchReadError> {
    validate_target_object_stream_length(expected_body.len() as u64)
        .map_err(|_| BatchReadError::Mismatch)?;
    let canonical_header = format!("{expected_oid} {expected_type} {}\n", expected_body.len());
    let mut buffer = Zeroizing::new([0_u8; TARGET_OBJECT_STREAM_CHUNK_BYTES]);
    read_exact_match(reader, canonical_header.as_bytes(), &mut buffer)?;
    read_exact_match(reader, expected_body, &mut buffer)?;
    let mut separator = Zeroizing::new([0_u8; 1]);
    let read = reader
        .read(separator.as_mut_slice())
        .map_err(BatchReadError::Io)?;
    if read == 1 && separator[0] == b'\n' {
        Ok(())
    } else {
        Err(BatchReadError::Mismatch)
    }
}

fn read_exact_match(
    reader: &mut impl Read,
    expected: &[u8],
    buffer: &mut [u8; TARGET_OBJECT_STREAM_CHUNK_BYTES],
) -> Result<(), BatchReadError> {
    let mut offset = 0_usize;
    while offset < expected.len() {
        let maximum = (expected.len() - offset).min(buffer.len());
        let read = reader
            .read(&mut buffer[..maximum])
            .map_err(BatchReadError::Io)?;
        if read == 0 || buffer[..read] != expected[offset..offset + read] {
            return Err(BatchReadError::Mismatch);
        }
        offset += read;
    }
    Ok(())
}

fn read_batch_eof(reader: &mut impl Read) -> Result<(), BatchReadError> {
    let mut byte = Zeroizing::new([0_u8; 1]);
    match reader
        .read(byte.as_mut_slice())
        .map_err(BatchReadError::Io)?
    {
        0 => Ok(()),
        _ => Err(BatchReadError::Mismatch),
    }
}

fn validate_target_object_stream_length(size: u64) -> Result<usize, RepositoryImportError> {
    usize::try_from(size)
        .ok()
        .filter(|size| *size <= MAX_TARGET_OBJECT_BYTES)
        .ok_or(RepositoryImportError::ResourceLimit)
}

enum ReadOutputError {
    TooLarge,
    Io(io::Error),
}

fn read_output_bounded(
    reader: &mut impl Read,
    output: &mut Vec<u8>,
    maximum: usize,
) -> Result<(), ReadOutputError> {
    let mut buffer = Zeroizing::new([0_u8; 16 * 1024]);
    loop {
        let read = reader
            .read(buffer.as_mut_slice())
            .map_err(ReadOutputError::Io)?;
        if read == 0 {
            return Ok(());
        }
        if output.len().saturating_add(read) > maximum {
            return Err(ReadOutputError::TooLarge);
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

#[cfg(windows)]
fn null_device() -> &'static str {
    "NUL"
}

#[cfg(not(windows))]
fn null_device() -> &'static str {
    "/dev/null"
}

fn os_args<const N: usize>(arguments: [&str; N]) -> [OsString; N] {
    arguments.map(OsString::from)
}

#[cfg(target_os = "linux")]
fn os_args_iter(arguments: &[&str]) -> Vec<OsString> {
    arguments.iter().map(OsString::from).collect()
}

fn one_line(output: &[u8]) -> Result<&str, RepositoryImportError> {
    let output = if let Some(stripped) = output.strip_suffix(b"\r\n") {
        stripped
    } else if let Some(stripped) = output.strip_suffix(b"\n") {
        stripped
    } else {
        output
    };
    if output.contains(&b'\n') || output.contains(&b'\r') {
        return Err(RepositoryImportError::MalformedGitOutput);
    }
    std::str::from_utf8(output).map_err(|_| RepositoryImportError::MalformedGitOutput)
}

fn nul_records(output: &[u8]) -> Result<Vec<&[u8]>, RepositoryImportError> {
    if output.is_empty() {
        return Ok(Vec::new());
    }
    if !output.ends_with(&[0]) {
        return Err(RepositoryImportError::MalformedGitOutput);
    }
    let mut result = Vec::new();
    let mut start = 0;
    for (index, byte) in output.iter().enumerate() {
        if *byte != 0 {
            continue;
        }
        if index == start {
            return Err(RepositoryImportError::MalformedGitOutput);
        }
        result.push(&output[start..index]);
        start = index.saturating_add(1);
    }
    if start == output.len() {
        Ok(result)
    } else {
        Err(RepositoryImportError::MalformedGitOutput)
    }
}

fn require_sha1_oid(oid: &str) -> Result<(), RepositoryImportError> {
    if oid.len() == 40
        && oid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(RepositoryImportError::MalformedGitOutput)
    }
}

fn slash_path(path: &Path) -> Option<String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => components.push(value.to_str()?),
            _ => return None,
        }
    }
    Some(components.join("/"))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn typed_git_object_oid(object_type: &str, body: &[u8]) -> Result<String, RepositoryImportError> {
    if !matches!(object_type, "blob" | "tree" | "commit") {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    validate_target_object_stream_length(body.len() as u64)?;
    let mut digest = Sha1::new();
    digest.update(object_type.as_bytes());
    digest.update(b" ");
    digest.update(body.len().to_string().as_bytes());
    digest.update([0]);
    digest.update(body);
    let bytes = digest.finalize();
    let mut oid = String::with_capacity(40);
    for byte in bytes {
        oid.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        oid.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    Ok(oid)
}

#[cfg(target_os = "linux")]
fn semantic_map_digest(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

fn io_error(operation: RepositoryIoOperation, error: &io::Error) -> RepositoryImportError {
    RepositoryImportError::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inex_core::crypto::VaultContentProfile;
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault::Vault;
    use inex_core::vault_config::KdfPolicy;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-repository-import-{label}-{}-{sequence}",
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

    fn test_git(root: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .current_dir(root)
            .args(arguments)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .status()
            .expect("test Git starts");
        assert!(status.success(), "test Git command failed: {arguments:?}");
    }

    #[cfg(target_os = "linux")]
    fn create_source() -> TestDirectory {
        let directory = TestDirectory::new("source");
        test_git(
            directory.path(),
            &["init", "--quiet", "--initial-branch=main"],
        );
        test_git(directory.path(), &["config", "user.name", "Source Author"]);
        test_git(
            directory.path(),
            &["config", "user.email", "source@example.invalid"],
        );
        fs::create_dir(directory.path().join("images")).expect("source directory creates");
        fs::write(directory.path().join("note.md"), b"# exact\r\n").expect("Markdown writes");
        fs::write(directory.path().join("images/pixel.bin"), [0_u8, 1, 2, 255])
            .expect("asset writes");
        fs::write(directory.path().join(".gitignore"), b"ignored.tmp\n")
            .expect("source ignore writes");
        test_git(directory.path(), &["add", "--", "."]);
        test_git(directory.path(), &["commit", "--quiet", "-m", "source"]);
        directory
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_snapshot_binds_head_index_namespace_and_raw_bytes() {
        let source = create_source();
        let snapshot = plan_source_repository(source.path()).expect("clean source plans");
        assert_eq!(snapshot.entries().len(), 3);
        assert_eq!(snapshot.directory_count(), 1);
        assert_eq!(snapshot.head_oid().len(), 40);
        let note = snapshot
            .entries()
            .iter()
            .find(|entry| entry.relative_path() == "note.md")
            .expect("note is planned");
        assert!(note.is_markdown());
        assert_eq!(
            snapshot.read_entry(note).expect("note rereads").as_slice(),
            b"# exact\r\n"
        );
        snapshot.revalidate().expect("unchanged source revalidates");

        fs::write(source.path().join("ignored.tmp"), b"ignored but untracked")
            .expect("ignored file writes");
        assert!(matches!(
            plan_source_repository(source.path()),
            Err(RepositoryImportError::UnsafeSourceEntry)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_snapshot_rejects_dirty_bytes_and_lfs_pointer() {
        let source = create_source();
        fs::write(source.path().join("note.md"), b"dirty").expect("dirty bytes write");
        assert!(matches!(
            plan_source_repository(source.path()),
            Err(RepositoryImportError::SourceChanged)
        ));

        test_git(source.path(), &["checkout", "--", "note.md"]);
        fs::write(
            source.path().join("pointer.bin"),
            b"version https://git-lfs.github.com/spec/v1\noid sha256:00\n",
        )
        .expect("pointer writes");
        test_git(source.path(), &["add", "pointer.bin"]);
        test_git(source.path(), &["commit", "--quiet", "-m", "pointer"]);
        assert!(matches!(
            plan_source_repository(source.path()),
            Err(RepositoryImportError::LfsPointerUnsupported)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_snapshot_normalizes_nfc_but_rejects_normalization_collisions() {
        let source = create_source();
        let decomposed = "cafe\u{301}.md";
        fs::write(source.path().join(decomposed), b"normalized\n").expect("decomposed path writes");
        test_git(source.path(), &["add", "--", decomposed]);
        test_git(source.path(), &["commit", "--quiet", "-m", "unicode"]);
        let snapshot =
            plan_source_repository(source.path()).expect("NFC-normalizable source plans");
        assert_eq!(snapshot.normalized_path_entry_count(), 1);
        let normalized = snapshot
            .entries()
            .iter()
            .find(|entry| entry.relative_path() == "caf\u{e9}.md")
            .expect("canonical NFC target path is exposed");
        assert_eq!(
            snapshot
                .read_entry(normalized)
                .expect("raw decomposed source rereads")
                .as_slice(),
            b"normalized\n"
        );

        fs::write(source.path().join("caf\u{e9}.md"), b"collision\n")
            .expect("composed collision writes");
        test_git(source.path(), &["add", "--", "caf\u{e9}.md"]);
        test_git(source.path(), &["commit", "--quiet", "-m", "collision"]);
        assert!(matches!(
            plan_source_repository(source.path()),
            Err(RepositoryImportError::UnsafeSourceEntry)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_snapshot_rejects_a_symlinked_ancestor_and_scrubs_debug() {
        use std::os::unix::fs::symlink;

        let source = create_source();
        let snapshot = plan_source_repository(source.path()).expect("direct source plans");
        let debug = format!("{snapshot:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(source.path().to_string_lossy().as_ref()));
        assert!(!debug.contains(snapshot.head_oid()));
        assert!(!debug.contains(snapshot.entries()[0].blob_oid()));

        let alias_holder = TestDirectory::new("ancestor-alias");
        let source_parent = source.path().parent().expect("source has parent");
        let alias_parent = alias_holder.path().join("linked-parent");
        symlink(source_parent, &alias_parent).expect("ancestor symlink creates");
        let through_alias = alias_parent.join(source.path().file_name().expect("source has name"));
        assert!(matches!(
            plan_source_repository(&through_alias),
            Err(RepositoryImportError::UnsupportedSourceRepository)
        ));

        let outside_images = alias_holder.path().join("outside-images");
        fs::create_dir(&outside_images).expect("outside directory creates");
        fs::write(outside_images.join("pixel.bin"), [0_u8, 1, 2, 255])
            .expect("outside tracked lookalike writes");
        fs::remove_dir_all(source.path().join("images")).expect("tracked directory removes");
        symlink(&outside_images, source.path().join("images"))
            .expect("tracked ancestor symlink creates");
        assert!(matches!(
            plan_source_repository(source.path()),
            Err(RepositoryImportError::UnsafeSourceEntry | RepositoryImportError::SourceChanged)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_has_one_parentless_ciphertext_only_root_and_marker_aware_audit() {
        let target = TestDirectory::new("target");
        fs::create_dir(target.path().join(VAULT_LOCAL_DIRECTORY))
            .expect("private directory creates");
        fs::write(
            target
                .path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(VAULT_MUTATION_LOCK_FILE),
            [],
        )
        .expect("mutation lock creates");
        fs::create_dir(target.path().join("images")).expect("ciphertext directory creates");
        fs::write(target.path().join("vault.json"), b"authenticated metadata")
            .expect("vault metadata writes");
        fs::write(target.path().join("note.md.enc"), b"EDRY ciphertext note")
            .expect("document ciphertext writes");
        fs::write(
            target.path().join("images/pixel.bin.asset.enc"),
            b"EDRY ciphertext asset",
        )
        .expect("asset ciphertext writes");
        let paths = vec![
            PathBuf::from("vault.json"),
            PathBuf::from("note.md.enc"),
            PathBuf::from("images/pixel.bin.asset.enc"),
        ];
        let repository = initialize_and_audit_target(target.path(), &paths, 1_784_044_800)
            .expect("target initializes and audits");
        assert_eq!(repository.root_commit_oid().len(), 40);
        assert_eq!(repository.tracked_paths().len(), 5);
        let debug = format!("{repository:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(repository.root_commit_oid()));
        assert!(!debug.contains("note.md.enc"));
        let hooks = target
            .path()
            .join(".git")
            .join(TARGET_EMPTY_HOOKS_DIRECTORY);
        assert!(hooks.is_dir());
        audit_repository_import_target(target.path(), &repository)
            .expect("ordinary target audit succeeds");

        fs::write(hooks.join("pre-commit"), b"must never execute").expect("foreign hook writes");
        assert!(audit_repository_import_target(target.path(), &repository).is_err());
        fs::remove_file(hooks.join("pre-commit")).expect("foreign hook removes");
        audit_repository_import_target(target.path(), &repository)
            .expect("empty held hook directory restores audit");

        let marker = target
            .path()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER);
        fs::write(&marker, [7_u8; 16]).expect("publication marker writes");
        audit_repository_import_target_for_publication(target.path(), &repository)
            .expect("marker-aware target audit succeeds");
        assert!(audit_repository_import_target(target.path(), &repository).is_err());
        fs::remove_file(marker).expect("publication marker removes");
        audit_repository_import_target(target.path(), &repository)
            .expect("ordinary audit recovers after marker removal");

        test_git(
            target.path(),
            &["config", "--local", "alias.unsafe", "status"],
        );
        assert!(audit_repository_import_target(target.path(), &repository).is_err());
    }

    #[test]
    fn batch_object_reader_requires_exact_header_body_separator_and_bounds() {
        let oid = "0123456789abcdef0123456789abcdef01234567";
        let exact = format!("{oid} blob 5\nhello\n");
        read_batch_object_exact(
            &mut io::Cursor::new(exact.as_bytes()),
            oid,
            "blob",
            b"hello",
        )
        .expect("exact batch response passes");

        let short = format!("{oid} blob 5\nhell");
        assert!(matches!(
            read_batch_object_exact(
                &mut io::Cursor::new(short.as_bytes()),
                oid,
                "blob",
                b"hello"
            ),
            Err(BatchReadError::Mismatch)
        ));
        let same_length_tamper = format!("{oid} blob 5\njello\n");
        assert!(matches!(
            read_batch_object_exact(
                &mut io::Cursor::new(same_length_tamper.as_bytes()),
                oid,
                "blob",
                b"hello"
            ),
            Err(BatchReadError::Mismatch)
        ));
        let extra = format!("{oid} blob 5\nhello!\n");
        assert!(matches!(
            read_batch_object_exact(
                &mut io::Cursor::new(extra.as_bytes()),
                oid,
                "blob",
                b"hello"
            ),
            Err(BatchReadError::Mismatch)
        ));
        let noncanonical = format!("{oid}\tblob 05\nhello\n");
        assert!(matches!(
            read_batch_object_exact(
                &mut io::Cursor::new(noncanonical.as_bytes()),
                oid,
                "blob",
                b"hello"
            ),
            Err(BatchReadError::Mismatch)
        ));
        let oversized = format!("{oid} blob {}\n", MAX_TARGET_OBJECT_BYTES as u64 + 1);
        assert!(matches!(
            read_batch_object_exact(&mut io::Cursor::new(oversized.as_bytes()), oid, "blob", b""),
            Err(BatchReadError::Mismatch)
        ));
        assert!(matches!(
            validate_target_object_stream_length(MAX_TARGET_OBJECT_BYTES as u64 + 1),
            Err(RepositoryImportError::ResourceLimit)
        ));
        assert!(matches!(
            read_batch_eof(&mut io::Cursor::new(b"unsolicited")),
            Err(BatchReadError::Mismatch)
        ));
    }

    #[test]
    fn canonical_tree_sort_uses_git_directory_suffix_order() {
        let mut entries = vec![
            CanonicalTreeEntry {
                name: "foo".to_owned(),
                oid: "1111111111111111111111111111111111111111".to_owned(),
                directory: true,
            },
            CanonicalTreeEntry {
                name: "foo.bar".to_owned(),
                oid: "2222222222222222222222222222222222222222".to_owned(),
                directory: false,
            },
        ];
        let body = serialize_canonical_tree(&mut entries).expect("canonical tree serializes");
        assert!(body.starts_with(b"100644 foo.bar\0"));
        assert!(
            body.windows(b"40000 foo\0".len())
                .any(|part| part == b"40000 foo\0")
        );
    }

    #[test]
    fn typed_object_sha1_matches_frozen_blob_tree_and_commit_fixtures() {
        assert_eq!(
            typed_git_object_oid("blob", b"").expect("empty blob hashes"),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
        assert_eq!(
            typed_git_object_oid("blob", &[0, 1, 2, 255]).expect("binary blob hashes"),
            "f971a5e28b6c4cb237ca3c7349e33bb600dbc907"
        );
        assert_eq!(
            typed_git_object_oid("tree", b"").expect("empty tree hashes"),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        );
        let mut tree = Zeroizing::new(b"100644 note\0".to_vec());
        tree.extend_from_slice(
            &decode_sha1_oid("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
                .expect("fixture blob id decodes"),
        );
        assert_eq!(
            typed_git_object_oid("tree", tree.as_slice()).expect("one-entry tree hashes"),
            "ad186d8087e8c97da7ccbff56e12019024bb1e67"
        );
        let commit =
            canonical_root_commit_bytes("4b825dc642cb6eb9a060e54bf8d69288fbee4904", 1_784_044_800);
        assert_eq!(commit.len(), 240);
        assert_eq!(
            typed_git_object_oid("commit", commit.as_slice()).expect("root commit hashes"),
            "632c468f6cf24bef3dd7d5b79c8a66b6a8176c34"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_tree_proof_handles_duplicate_blobs_nested_trees_and_raw_tamper() {
        let target = TestDirectory::new("nested-target");
        fs::create_dir(target.path().join(VAULT_LOCAL_DIRECTORY))
            .expect("private directory creates");
        fs::write(
            target
                .path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(VAULT_MUTATION_LOCK_FILE),
            [],
        )
        .expect("mutation lock creates");
        fs::create_dir_all(target.path().join("left")).expect("left directory creates");
        fs::create_dir_all(target.path().join("right/deep")).expect("deep directory creates");
        fs::write(target.path().join("vault.json"), b"authenticated metadata")
            .expect("vault metadata writes");
        let duplicate = b"the same opaque envelope";
        fs::write(target.path().join("left/dup.bin.asset.enc"), duplicate)
            .expect("left duplicate writes");
        fs::write(
            target.path().join("right/deep/dup.bin.asset.enc"),
            duplicate,
        )
        .expect("right duplicate writes");
        let paths = vec![
            PathBuf::from("vault.json"),
            PathBuf::from("left/dup.bin.asset.enc"),
            PathBuf::from("right/deep/dup.bin.asset.enc"),
        ];
        let repository = initialize_and_audit_target(target.path(), &paths, 1_784_044_800)
            .expect("nested duplicate target initializes and audits");
        assert_eq!(
            repository
                .tree_oids
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                String::new(),
                "left".to_owned(),
                "right".to_owned(),
                "right/deep".to_owned(),
            ])
        );
        assert_eq!(
            repository.tree_oids.get("left"),
            repository.tree_oids.get("right/deep")
        );
        audit_repository_import_target(target.path(), &repository)
            .expect("nested duplicate tree proof repeats");

        let oid = &repository.root_tree_oid;
        let loose = target
            .path()
            .join(".git/objects")
            .join(&oid[..2])
            .join(&oid[2..]);
        let mut permissions = fs::metadata(&loose)
            .expect("root tree object metadata reads")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o600);
        fs::set_permissions(&loose, permissions)
            .expect("root tree object becomes writable for tamper");
        let mut object = OpenOptions::new()
            .append(true)
            .open(loose)
            .expect("root tree object opens for tamper");
        object.write_all(b"tamper").expect("tree object tampers");
        object.sync_all().expect("tree object tamper syncs");
        assert!(audit_repository_import_target(target.path(), &repository).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn batch_object_timeout_kills_and_waits_for_child() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TestDirectory::new("batch-timeout");
        let executable = directory.path().join("blocking-git");
        fs::write(&executable, b"#!/bin/sh\nwhile :; do :; done\n")
            .expect("blocking executable writes");
        let mut permissions = fs::metadata(&executable)
            .expect("blocking executable metadata reads")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions)
            .expect("blocking executable becomes executable");
        let runner = GitRunner::target_uninitialized(executable, directory.path().to_path_buf());
        let started = Instant::now();
        let mut batch = runner
            .target_object_batch_with_timeout(Duration::from_millis(50))
            .expect("blocking batch starts");
        assert!(matches!(
            batch.verify("0123456789abcdef0123456789abcdef01234567", "blob", b""),
            Err(RepositoryImportError::GitCommandFailed {
                operation: RepositoryGitOperation::AuditTarget
            })
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn batch_object_stderr_bound_kills_and_waits_for_child() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TestDirectory::new("batch-stderr-bound");
        let executable = directory.path().join("noisy-git");
        fs::write(
            &executable,
            b"#!/bin/sh\nwhile :; do printf 0123456789abcdef >&2; done\n",
        )
        .expect("noisy executable writes");
        let mut permissions = fs::metadata(&executable)
            .expect("noisy executable metadata reads")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("noisy executable becomes executable");
        let runner = GitRunner::target_uninitialized(executable, directory.path().to_path_buf());
        let started = Instant::now();
        let mut batch = runner
            .target_object_batch_with_timeout(Duration::from_secs(2))
            .expect("noisy batch starts");
        assert!(matches!(
            batch.verify("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", "blob", b""),
            Err(RepositoryImportError::ResourceLimit)
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn install_driver_scans_feature_one_assets_and_installs_binary_rule() {
        let directory = TestDirectory::new("asset-driver");
        test_git(
            directory.path(),
            &["init", "--quiet", "--initial-branch=main"],
        );
        let policy = KdfPolicy {
            min_creation_ops_limit: 1,
            min_creation_mem_limit_bytes: 8 * 1024,
            max_creation_ops_limit: 2,
            max_creation_mem_limit_bytes: 64 * 1024,
            max_unlock_ops_limit: 2,
            max_unlock_mem_limit_bytes: 64 * 1024,
        };
        let mut vault = Vault::create_with_profile_and_params(
            directory.path(),
            b"correct horse battery staple",
            1_784_044_800_000,
            VaultContentProfile::OpaqueAssetsV1,
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            },
            policy,
        )
        .expect("asset vault creates");
        vault
            .create_import_asset(
                &AssetPath::parse_canonical("image.png").expect("asset path parses"),
                Zeroizing::new(vec![0_u8, 1, 2, 3]),
                1_784_044_801_000,
            )
            .expect("asset imports");
        drop(vault);

        let report = super::super::install_driver(directory.path())
            .expect("feature-one driver installation succeeds");
        assert!(report.attributes_changed);
        let attributes =
            fs::read(directory.path().join(GIT_ATTRIBUTES_FILE)).expect("attributes read");
        assert!(attributes.ends_with(TARGET_ATTRIBUTES));
        let output = Command::new("git")
            .current_dir(directory.path())
            .args([
                "check-attr",
                "-z",
                "text",
                "diff",
                "merge",
                "--",
                "image.png.asset.enc",
            ])
            .output()
            .expect("attribute probe runs");
        assert!(output.status.success());
        assert!(
            output
                .stdout
                .windows(b"merge\0unset\0".len())
                .any(|window| { window == b"merge\0unset\0" })
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn repository_import_source_fails_closed_without_descriptor_traversal() {
        assert!(matches!(
            plan_source_repository(Path::new("unsupported-source")),
            Err(RepositoryImportError::UnsupportedSourceRepository)
        ));
    }
}
