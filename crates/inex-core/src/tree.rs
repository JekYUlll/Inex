//! Read-only discovery of the logical vault tree.
//!
//! Discovery reads directory entries and link-aware metadata only. It never
//! opens an EDRY file and therefore cannot place ciphertext or plaintext file
//! contents in an error. Reserved implementation entries (`.git`,
//! `.vault-local`, and root `vault.json`) are omitted. Portable unrelated
//! regular files are ignored, while plaintext Markdown, ciphertext names that
//! differ only from the canonical `.md.enc` spelling, non-portable names,
//! links/reparse points, and special filesystem objects fail closed.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use crate::path::{LogicalDir, LogicalPath, PathError};

/// Default maximum number of filesystem entries inspected in one scan.
pub const DEFAULT_MAX_TREE_ENTRIES: usize = 100_000;

/// Default maximum number of components below the vault root.
pub const DEFAULT_MAX_TREE_DEPTH: usize = 128;

/// Default cumulative byte budget for inspected relative paths.
pub const DEFAULT_MAX_TREE_PATH_BYTES: usize = 32 * 1024 * 1024;

const MARKDOWN_SUFFIX: &str = ".md";
const CIPHERTEXT_SUFFIX: &str = ".md.enc";

/// Resource limits for one vault-tree scan.
///
/// `max_entries` counts every directory entry observed, including reserved or
/// unrelated entries that are not returned. This bounds work even when an
/// ignored directory contains a very large sibling set. Root is depth zero;
/// an entry directly below it is depth one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeLimits {
    /// Maximum number of directory entries inspected.
    pub max_entries: usize,
    /// Maximum number of relative path components accepted.
    pub max_depth: usize,
    /// Maximum cumulative encoded bytes across inspected relative paths.
    pub max_path_bytes: usize,
}

impl Default for TreeLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_TREE_ENTRIES,
            max_depth: DEFAULT_MAX_TREE_DEPTH,
            max_path_bytes: DEFAULT_MAX_TREE_PATH_BYTES,
        }
    }
}

/// The kind of one logical tree entry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TreeEntryKind {
    /// A logical directory, including an empty directory.
    Directory,
    /// A canonical encrypted Markdown document.
    File,
}

/// One validated logical entry returned to clients.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeEntry {
    kind: TreeEntryKind,
    logical_path: String,
}

impl TreeEntry {
    /// Return whether this entry is a directory or an encrypted Markdown file.
    #[must_use]
    pub const fn kind(&self) -> TreeEntryKind {
        self.kind
    }

    /// Return the canonical logical path.
    ///
    /// File paths include `.md` and never include physical `.enc`. Directory
    /// paths have neither a trailing slash nor a special root entry.
    #[must_use]
    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }
}

/// A complete, deterministically ordered logical vault tree.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultTree {
    entries: Vec<TreeEntry>,
}

impl VaultTree {
    /// Borrow entries sorted by canonical logical path, then kind.
    #[must_use]
    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }

    /// Consume the tree and return its sorted entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<TreeEntry> {
        self.entries
    }

    /// Return the number of logical entries, including directories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the vault contains no discoverable logical entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The filesystem operation whose non-sensitive error kind is reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeIoOperation {
    /// Inspect the vault root without following its final component.
    InspectRoot,
    /// Open a directory for read-only enumeration.
    ReadDirectory,
    /// Obtain the next directory entry.
    ReadEntry,
    /// Inspect an entry without following its final component.
    InspectEntry,
}

impl fmt::Display for TreeIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InspectRoot => "inspect root",
            Self::ReadDirectory => "read directory",
            Self::ReadEntry => "read entry",
            Self::InspectEntry => "inspect entry",
        })
    }
}

/// A safe failure while discovering a vault tree.
///
/// Errors contain at most vault-relative metadata names and an [`io::ErrorKind`].
/// They never include file bytes or an absolute vault path.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TreeError {
    /// The configured root is a symlink or Windows reparse point.
    #[error("vault root must not be a link or reparse point")]
    LinkLikeRoot,

    /// The configured root is not a normal directory.
    #[error("vault root is not a normal directory")]
    RootNotDirectory,

    /// A link or Windows reparse point was found below the root.
    #[error("vault entry `{relative_path}` must not be a link or reparse point")]
    LinkLikeEntry {
        /// Vault-relative metadata path; never document contents.
        relative_path: String,
    },

    /// A FIFO, socket, device, or another special object was found.
    #[error("vault entry `{relative_path}` is not a normal file or directory")]
    UnsupportedFileType {
        /// Vault-relative metadata path; never document contents.
        relative_path: String,
    },

    /// A reserved implementation entry used a non-canonical casing.
    #[error("vault entry `{relative_path}` aliases reserved implementation storage")]
    ReservedEntryAlias {
        /// Vault-relative metadata path; never document contents.
        relative_path: String,
    },

    /// An entry crossed from the vault root onto another mounted filesystem.
    #[error("vault entry `{relative_path}` crosses a filesystem boundary")]
    FilesystemBoundary {
        /// Vault-relative metadata path; never document contents.
        relative_path: String,
    },

    /// A physical name cannot be represented by the cross-platform profile.
    #[error("vault entry `{relative_path}` is not portable: {reason}")]
    InvalidEntry {
        /// Vault-relative metadata path; never document contents.
        relative_path: String,
        /// The logical-path invariant that failed.
        reason: PathError,
    },

    /// An encrypted Markdown candidate used a non-canonical suffix spelling.
    #[error("vault entry `{relative_path}` must use exact lowercase `.md.enc`")]
    NonCanonicalCiphertextName {
        /// Vault-relative metadata path; never document contents.
        relative_path: String,
    },

    /// A likely plaintext Markdown file was found in the ciphertext vault.
    #[error("plaintext Markdown entry `{relative_path}` is not allowed in a vault")]
    PlaintextMarkdown {
        /// Vault-relative metadata path; never document contents.
        relative_path: String,
    },

    /// More than one physical entry mapped to the same logical path.
    #[error("duplicate logical vault path `{logical_path}`")]
    DuplicateLogicalPath {
        /// The duplicated canonical logical path.
        logical_path: String,
    },

    /// Distinct logical names alias on a case-insensitive filesystem.
    #[error("logical vault paths `{first}` and `{second}` collide under Unicode case folding")]
    CaseFoldCollision {
        /// First canonical logical path in deterministic ordering.
        first: String,
        /// Second canonical logical path in deterministic ordering.
        second: String,
    },

    /// A discovered entry exceeded the configured component depth.
    #[error("vault entry `{relative_path}` has depth {actual}; configured maximum is {maximum}")]
    DepthLimitExceeded {
        /// Vault-relative metadata path; never document contents.
        relative_path: String,
        /// Number of path components below root.
        actual: usize,
        /// Configured maximum component depth.
        maximum: usize,
    },

    /// The scan inspected more entries than permitted.
    #[error("vault tree exceeds the configured {maximum}-entry limit")]
    EntryLimitExceeded {
        /// Configured maximum number of inspected entries.
        maximum: usize,
    },

    /// Cumulative relative-path storage exceeded the configured budget.
    #[error("vault tree exceeds the configured {maximum}-byte path budget")]
    PathByteLimitExceeded {
        /// Configured maximum cumulative encoded path bytes.
        maximum: usize,
    },

    /// A read-only filesystem metadata operation failed.
    #[error("vault tree I/O failed during {operation}: {kind:?}")]
    Io {
        /// The operation being performed.
        operation: TreeIoOperation,
        /// Stable error classification without OS text or an absolute path.
        kind: io::ErrorKind,
    },
}

/// Discover a vault tree with the default resource limits.
///
/// This function never opens a regular file and never follows an observed
/// symlink or Windows reparse point. The caller must serialize structural vault
/// mutations with the same vault lock used by writers so entries cannot be
/// replaced during enumeration.
///
/// # Errors
///
/// Returns [`TreeError`] when the root cannot be inspected, an I/O operation
/// fails, a link/special/non-portable/plaintext/non-canonical entry is found,
/// two logical names collide, or a default resource limit is exceeded.
pub fn scan_vault_tree(root: impl AsRef<Path>) -> Result<VaultTree, TreeError> {
    scan_vault_tree_with_limits(root, TreeLimits::default())
}

/// Discover a vault tree with explicit resource limits.
///
/// `max_entries` limits all entries inspected, not only entries returned in the
/// tree. The scan excludes exact `.git` and `.vault-local` at every depth and
/// exact root `vault.json`; any ASCII-case alias is rejected so it cannot be
/// hidden on Linux and later collide on a case-insensitive checkout.
///
/// # Errors
///
/// Returns [`TreeError`] when the root cannot be inspected, an I/O operation
/// fails, a link/special/non-portable/plaintext/non-canonical entry is found,
/// two logical names collide, or one of `limits` is exceeded.
pub fn scan_vault_tree_with_limits(
    root: impl AsRef<Path>,
    limits: TreeLimits,
) -> Result<VaultTree, TreeError> {
    let root = root.as_ref();
    let root_metadata = validate_root(root)?;
    let mount_boundary =
        MountBoundary::new(root).map_err(|error| io_error(TreeIoOperation::InspectRoot, &error))?;

    let mut scan = ScanState::new(limits, filesystem_device(&root_metadata), mount_boundary);
    while let Some(relative_directory) = scan.pending_directories.pop() {
        scan_directory(root, &relative_directory, &mut scan)?;
    }

    build_tree_from_path_lists(scan.directories, scan.ciphertext_files, limits)
}

#[derive(Debug)]
struct ScanState {
    limits: TreeLimits,
    inspected_entries: usize,
    inspected_path_bytes: usize,
    root_device: Option<u64>,
    mount_boundary: MountBoundary,
    pending_directories: Vec<PathBuf>,
    directories: Vec<PathBuf>,
    ciphertext_files: Vec<PathBuf>,
}

impl ScanState {
    fn new(limits: TreeLimits, root_device: Option<u64>, mount_boundary: MountBoundary) -> Self {
        Self {
            limits,
            inspected_entries: 0,
            inspected_path_bytes: 0,
            root_device,
            mount_boundary,
            pending_directories: vec![PathBuf::new()],
            directories: Vec::new(),
            ciphertext_files: Vec::new(),
        }
    }

    fn count_entry(&mut self) -> Result<(), TreeError> {
        self.inspected_entries = self.inspected_entries.saturating_add(1);
        if self.inspected_entries > self.limits.max_entries {
            return Err(TreeError::EntryLimitExceeded {
                maximum: self.limits.max_entries,
            });
        }
        Ok(())
    }

    fn count_path(&mut self, path: &Path) -> Result<(), TreeError> {
        self.inspected_path_bytes = self
            .inspected_path_bytes
            .saturating_add(path.as_os_str().as_encoded_bytes().len());
        if self.inspected_path_bytes > self.limits.max_path_bytes {
            return Err(TreeError::PathByteLimitExceeded {
                maximum: self.limits.max_path_bytes,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct MountBoundary {
    #[cfg(target_os = "linux")]
    canonical_root: PathBuf,
    #[cfg(target_os = "linux")]
    root_mount_id: u64,
    #[cfg(target_os = "linux")]
    mounts: Vec<(PathBuf, u64)>,
}

#[cfg(target_os = "linux")]
impl MountBoundary {
    fn new(root: &Path) -> io::Result<Self> {
        let canonical_root = fs::canonicalize(root)?;
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let mut mounts = Vec::new();
        for line in mountinfo.lines() {
            let Some((mount_fields, _)) = line.split_once(" - ") else {
                continue;
            };
            let mut fields = mount_fields.split_whitespace();
            let Some(mount_id) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            let Some(encoded_mount) = mount_fields.split_whitespace().nth(4) else {
                continue;
            };
            mounts.push((decode_mountinfo_path(encoded_mount)?, mount_id));
        }
        let root_mount_id = mount_id_for_path(&mounts, &canonical_root).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "vault mount identity is unavailable",
            )
        })?;
        Ok(Self {
            canonical_root,
            root_mount_id,
            mounts,
        })
    }

    fn contains(&self, relative_path: &Path) -> bool {
        mount_id_for_path(&self.mounts, &self.canonical_root.join(relative_path))
            == Some(self.root_mount_id)
    }
}

#[cfg(not(target_os = "linux"))]
impl MountBoundary {
    #[allow(clippy::unnecessary_wraps)]
    fn new(_root: &Path) -> io::Result<Self> {
        Ok(Self {})
    }

    #[allow(clippy::unused_self)]
    fn contains(&self, _relative_path: &Path) -> bool {
        true
    }
}

#[cfg(target_os = "linux")]
fn mount_id_for_path(mounts: &[(PathBuf, u64)], path: &Path) -> Option<u64> {
    mounts
        .iter()
        .filter(|(mount, _)| path.starts_with(mount))
        .max_by_key(|(mount, _)| mount.as_os_str().as_encoded_bytes().len())
        .map(|(_, mount_id)| *mount_id)
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(value: &str) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let digits = &bytes[index + 1..index + 4];
            if digits.iter().all(|digit| matches!(digit, b'0'..=b'7')) {
                decoded.push((digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + (digits[2] - b'0'));
                index += 4;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    if decoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mountinfo path contains NUL",
        ));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
}

fn validate_root(root: &Path) -> Result<Metadata, TreeError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| io_error(TreeIoOperation::InspectRoot, &error))?;
    if is_link_or_reparse_point(&metadata) {
        return Err(TreeError::LinkLikeRoot);
    }
    if !metadata.file_type().is_dir() {
        return Err(TreeError::RootNotDirectory);
    }
    Ok(metadata)
}

fn scan_directory(
    root: &Path,
    relative_directory: &Path,
    scan: &mut ScanState,
) -> Result<(), TreeError> {
    let physical_directory = root.join(relative_directory);
    let metadata = fs::symlink_metadata(&physical_directory)
        .map_err(|error| io_error(TreeIoOperation::InspectEntry, &error))?;
    if is_link_or_reparse_point(&metadata) {
        return if relative_directory.as_os_str().is_empty() {
            Err(TreeError::LinkLikeRoot)
        } else {
            Err(TreeError::LinkLikeEntry {
                relative_path: relative_display(relative_directory),
            })
        };
    }
    if !metadata.file_type().is_dir() {
        return Err(TreeError::UnsupportedFileType {
            relative_path: relative_display(relative_directory),
        });
    }
    ensure_scan_filesystem(
        relative_directory,
        &metadata,
        scan.root_device,
        &scan.mount_boundary,
    )?;

    let entries = fs::read_dir(physical_directory)
        .map_err(|error| io_error(TreeIoOperation::ReadDirectory, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| io_error(TreeIoOperation::ReadEntry, &error))?;
        scan.count_entry()?;
        inspect_entry(root, relative_directory, &entry.file_name(), scan)?;
    }
    Ok(())
}

fn inspect_entry(
    root: &Path,
    parent: &Path,
    file_name: &std::ffi::OsStr,
    scan: &mut ScanState,
) -> Result<(), TreeError> {
    let relative_path = parent.join(file_name);
    match reserved_entry_kind(parent, file_name) {
        ReservedEntryKind::Canonical => return Ok(()),
        ReservedEntryKind::Alias => {
            return Err(TreeError::ReservedEntryAlias {
                relative_path: relative_display(&relative_path),
            });
        }
        ReservedEntryKind::NotReserved => {}
    }
    scan.count_path(&relative_path)?;
    enforce_depth(&relative_path, scan.limits.max_depth)?;
    let physical_path = root.join(&relative_path);
    let metadata = fs::symlink_metadata(physical_path)
        .map_err(|error| io_error(TreeIoOperation::InspectEntry, &error))?;
    ensure_scan_filesystem(
        &relative_path,
        &metadata,
        scan.root_device,
        &scan.mount_boundary,
    )?;
    if is_link_or_reparse_point(&metadata) {
        return Err(TreeError::LinkLikeEntry {
            relative_path: relative_display(&relative_path),
        });
    }

    let file_type = metadata.file_type();
    if file_type.is_dir() {
        logical_directory(&relative_path)?;
        scan.directories.push(relative_path.clone());
        scan.pending_directories.push(relative_path);
        return Ok(());
    }
    if file_type.is_file() {
        return inspect_regular_file(relative_path, scan);
    }
    Err(TreeError::UnsupportedFileType {
        relative_path: relative_display(&relative_path),
    })
}

fn inspect_regular_file(relative_path: PathBuf, scan: &mut ScanState) -> Result<(), TreeError> {
    logical_directory(&relative_path)?;
    let name = relative_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| invalid_entry(&relative_path, PathError::NonUtf8CiphertextPath))?;

    if name.ends_with(CIPHERTEXT_SUFFIX) {
        LogicalPath::from_ciphertext_relative_path(&relative_path)
            .map_err(|reason| invalid_entry(&relative_path, reason))?;
        scan.ciphertext_files.push(relative_path);
        return Ok(());
    }

    let lowercase_name = name.to_ascii_lowercase();
    if lowercase_name.ends_with(CIPHERTEXT_SUFFIX) {
        return Err(TreeError::NonCanonicalCiphertextName {
            relative_path: relative_display(&relative_path),
        });
    }
    if lowercase_name.ends_with(MARKDOWN_SUFFIX) {
        return Err(TreeError::PlaintextMarkdown {
            relative_path: relative_display(&relative_path),
        });
    }

    Ok(())
}

fn build_tree_from_path_lists(
    mut directories: Vec<PathBuf>,
    mut ciphertext_files: Vec<PathBuf>,
    limits: TreeLimits,
) -> Result<VaultTree, TreeError> {
    if directories.len().saturating_add(ciphertext_files.len()) > limits.max_entries {
        return Err(TreeError::EntryLimitExceeded {
            maximum: limits.max_entries,
        });
    }
    let path_bytes = directories
        .iter()
        .chain(&ciphertext_files)
        .fold(0_usize, |total, path| {
            total.saturating_add(path.as_os_str().as_encoded_bytes().len())
        });
    if path_bytes > limits.max_path_bytes {
        return Err(TreeError::PathByteLimitExceeded {
            maximum: limits.max_path_bytes,
        });
    }

    directories.sort();
    ciphertext_files.sort();
    let mut candidates = Vec::with_capacity(directories.len() + ciphertext_files.len());

    for relative_path in directories {
        enforce_depth(&relative_path, limits.max_depth)?;
        let logical = logical_directory(&relative_path)?;
        candidates.push(TreeCandidate {
            fold_key: logical.case_fold_key().as_str().to_owned(),
            entry: TreeEntry {
                kind: TreeEntryKind::Directory,
                logical_path: logical.as_str().to_owned(),
            },
        });
    }
    for relative_path in ciphertext_files {
        enforce_depth(&relative_path, limits.max_depth)?;
        let logical = LogicalPath::from_ciphertext_relative_path(&relative_path)
            .map_err(|reason| invalid_entry(&relative_path, reason))?;
        candidates.push(TreeCandidate {
            fold_key: logical.case_fold_key().as_str().to_owned(),
            entry: TreeEntry {
                kind: TreeEntryKind::File,
                logical_path: logical.as_str().to_owned(),
            },
        });
    }

    candidates.sort_by(|left, right| {
        left.entry
            .logical_path
            .cmp(&right.entry.logical_path)
            .then(left.entry.kind.cmp(&right.entry.kind))
    });
    reject_aliases(&candidates)?;

    Ok(VaultTree {
        entries: candidates
            .into_iter()
            .map(|candidate| candidate.entry)
            .collect(),
    })
}

#[derive(Debug)]
struct TreeCandidate {
    fold_key: String,
    entry: TreeEntry,
}

fn reject_aliases(candidates: &[TreeCandidate]) -> Result<(), TreeError> {
    let mut exact_paths = BTreeMap::<&str, TreeEntryKind>::new();
    let mut folded_paths = BTreeMap::<&str, &str>::new();

    for candidate in candidates {
        let logical_path = candidate.entry.logical_path.as_str();
        if exact_paths
            .insert(logical_path, candidate.entry.kind)
            .is_some()
        {
            return Err(TreeError::DuplicateLogicalPath {
                logical_path: logical_path.to_owned(),
            });
        }

        if let Some(first) = folded_paths.insert(&candidate.fold_key, logical_path)
            && first != logical_path
        {
            return Err(TreeError::CaseFoldCollision {
                first: first.to_owned(),
                second: logical_path.to_owned(),
            });
        }
    }
    Ok(())
}

fn logical_directory(relative_path: &Path) -> Result<LogicalDir, TreeError> {
    let logical_text = normal_relative_text(relative_path)
        .map_err(|reason| invalid_entry(relative_path, reason))?;
    LogicalDir::parse_canonical(&logical_text)
        .map_err(|reason| invalid_entry(relative_path, reason))
}

fn normal_relative_text(relative_path: &Path) -> Result<String, PathError> {
    let mut components = Vec::new();
    for component in relative_path.components() {
        match component {
            Component::Normal(value) => {
                components.push(value.to_str().ok_or(PathError::NonUtf8CiphertextPath)?);
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(PathError::InvalidCiphertextPath),
        }
    }
    if components.is_empty() {
        return Err(PathError::Empty);
    }
    Ok(components.join("/"))
}

fn enforce_depth(relative_path: &Path, maximum: usize) -> Result<(), TreeError> {
    let actual = relative_path.components().count();
    if actual > maximum {
        return Err(TreeError::DepthLimitExceeded {
            relative_path: relative_display(relative_path),
            actual,
            maximum,
        });
    }
    Ok(())
}

fn ensure_scan_filesystem(
    relative_path: &Path,
    metadata: &Metadata,
    root_device: Option<u64>,
    mount_boundary: &MountBoundary,
) -> Result<(), TreeError> {
    if root_device
        .zip(filesystem_device(metadata))
        .is_some_and(|(root, current)| root != current)
    {
        return Err(TreeError::FilesystemBoundary {
            relative_path: relative_display(relative_path),
        });
    }
    if !mount_boundary.contains(relative_path) {
        return Err(TreeError::FilesystemBoundary {
            relative_path: relative_display(relative_path),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)]
fn filesystem_device(metadata: &Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;

    Some(metadata.dev())
}

#[cfg(not(target_os = "linux"))]
fn filesystem_device(_metadata: &Metadata) -> Option<u64> {
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservedEntryKind {
    NotReserved,
    Canonical,
    Alias,
}

fn reserved_entry_kind(parent: &Path, file_name: &std::ffi::OsStr) -> ReservedEntryKind {
    let Some(name) = file_name.to_str() else {
        return ReservedEntryKind::NotReserved;
    };
    let expected = if name.eq_ignore_ascii_case(".git") {
        Some(".git")
    } else if name.eq_ignore_ascii_case(".vault-local") {
        Some(".vault-local")
    } else if parent.as_os_str().is_empty() && name.eq_ignore_ascii_case("vault.json") {
        Some("vault.json")
    } else {
        None
    };
    match expected {
        Some(expected) if name == expected => ReservedEntryKind::Canonical,
        Some(_) => ReservedEntryKind::Alias,
        None => ReservedEntryKind::NotReserved,
    }
}

fn invalid_entry(relative_path: &Path, reason: PathError) -> TreeError {
    TreeError::InvalidEntry {
        relative_path: relative_display(relative_path),
        reason,
    }
}

fn relative_display(relative_path: &Path) -> String {
    let display = relative_path.to_string_lossy();
    if std::path::MAIN_SEPARATOR == '/' {
        display.into_owned()
    } else {
        display.replace(std::path::MAIN_SEPARATOR, "/")
    }
}

fn io_error(operation: TreeIoOperation, error: &io::Error) -> TreeError {
    TreeError::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(not(windows))]
fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    // `FILE_ATTRIBUTE_REPARSE_POINT`; checking the attribute also catches
    // directory junctions and other redirecting reparse tags that are not
    // necessarily classified as symbolic links by `FileType`.
    const REPARSE_POINT: u32 = 0x0000_0400;

    metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn paths(values: &[&str]) -> Vec<PathBuf> {
        values.iter().map(PathBuf::from).collect()
    }

    fn pure_tree(directories: &[&str], files: &[&str]) -> Result<VaultTree, TreeError> {
        build_tree_from_path_lists(paths(directories), paths(files), TreeLimits::default())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filesystem_device_boundary_is_rejected() {
        let temporary = TempDirectory::new();
        let root = fs::metadata(temporary.path())
            .unwrap_or_else(|error| panic!("root metadata failed: {error}"));
        let Ok(alternate) = fs::metadata("/dev/shm") else {
            return;
        };
        let Some(root_device) = filesystem_device(&root) else {
            panic!("Linux root device missing");
        };
        if filesystem_device(&alternate) == Some(root_device) {
            return;
        }
        let boundary = MountBoundary::new(temporary.path())
            .unwrap_or_else(|error| panic!("mount boundary setup failed: {error}"));
        assert!(matches!(
            ensure_scan_filesystem(
                Path::new("mounted"),
                &alternate,
                Some(root_device),
                &boundary,
            ),
            Err(TreeError::FilesystemBoundary { .. })
        ));
    }

    #[test]
    fn path_list_builder_reverse_maps_and_sorts_without_filesystem_access() {
        let tree = match pure_tree(
            &["日记", "archive", "日记/2026"],
            &["日记/2026/七月.md.enc", "z.md.enc", "archive/a.md.enc"],
        ) {
            Ok(tree) => tree,
            Err(error) => panic!("tree build failed: {error}"),
        };

        let actual: Vec<_> = tree
            .entries()
            .iter()
            .map(|entry| (entry.kind(), entry.logical_path()))
            .collect();
        assert_eq!(
            actual,
            [
                (TreeEntryKind::Directory, "archive"),
                (TreeEntryKind::File, "archive/a.md"),
                (TreeEntryKind::File, "z.md"),
                (TreeEntryKind::Directory, "日记"),
                (TreeEntryKind::Directory, "日记/2026"),
                (TreeEntryKind::File, "日记/2026/七月.md"),
            ]
        );
    }

    #[test]
    fn path_list_builder_rejects_duplicates_and_unicode_case_aliases() {
        assert_eq!(
            pure_tree(&[], &["same.md.enc", "same.md.enc"]),
            Err(TreeError::DuplicateLogicalPath {
                logical_path: "same.md".to_owned(),
            })
        );

        assert_eq!(
            pure_tree(&[], &["STRASSE.md.enc", "Straße.md.enc"]),
            Err(TreeError::CaseFoldCollision {
                first: "STRASSE.md".to_owned(),
                second: "Straße.md".to_owned(),
            })
        );

        assert_eq!(
            pure_tree(&["Notes", "notes"], &[]),
            Err(TreeError::CaseFoldCollision {
                first: "Notes".to_owned(),
                second: "notes".to_owned(),
            })
        );
    }

    #[test]
    fn path_list_builder_rejects_noncanonical_and_bounded_paths() {
        let decomposed = "cafe\u{301}.md.enc";
        assert!(matches!(
            pure_tree(&[], &[decomposed]),
            Err(TreeError::InvalidEntry {
                reason: PathError::NotNfc,
                ..
            })
        ));
        assert!(matches!(
            pure_tree(&["CON"], &[]),
            Err(TreeError::InvalidEntry {
                reason: PathError::WindowsDeviceName { .. },
                ..
            })
        ));

        assert!(matches!(
            build_tree_from_path_lists(
                paths(&["one/two"]),
                Vec::new(),
                TreeLimits {
                    max_entries: 10,
                    max_depth: 1,
                    max_path_bytes: DEFAULT_MAX_TREE_PATH_BYTES,
                },
            ),
            Err(TreeError::DepthLimitExceeded {
                actual: 2,
                maximum: 1,
                ..
            })
        ));

        assert_eq!(
            build_tree_from_path_lists(
                paths(&["one", "two"]),
                Vec::new(),
                TreeLimits {
                    max_entries: 1,
                    max_depth: 10,
                    max_path_bytes: DEFAULT_MAX_TREE_PATH_BYTES,
                },
            ),
            Err(TreeError::EntryLimitExceeded { maximum: 1 })
        );

        assert_eq!(
            build_tree_from_path_lists(
                paths(&["lengthy", "other"]),
                Vec::new(),
                TreeLimits {
                    max_entries: 10,
                    max_depth: 10,
                    max_path_bytes: 8,
                },
            ),
            Err(TreeError::PathByteLimitExceeded { maximum: 8 })
        );
    }

    #[test]
    fn serialized_tree_has_rpc_ready_stable_shape() {
        let tree = match pure_tree(&["notes"], &["notes/today.md.enc"]) {
            Ok(tree) => tree,
            Err(error) => panic!("tree build failed: {error}"),
        };
        let json = match serde_json::to_value(tree) {
            Ok(json) => json,
            Err(error) => panic!("tree serialization failed: {error}"),
        };
        assert_eq!(
            json,
            serde_json::json!({
                "entries": [
                    {"kind": "directory", "logicalPath": "notes"},
                    {"kind": "file", "logicalPath": "notes/today.md"}
                ]
            })
        );
    }

    #[test]
    fn filesystem_scan_excludes_reserved_and_ignores_portable_unrelated_files() {
        let temporary = TempDirectory::new();
        create_directory(&temporary.path().join(".git"));
        create_directory(&temporary.path().join(".vault-local"));
        create_directory(&temporary.path().join("notes"));
        write_file(&temporary.path().join("vault.json"));
        write_file(&temporary.path().join("LICENSE"));
        write_file(&temporary.path().join("notes/today.md.enc"));

        let tree = match scan_vault_tree(temporary.path()) {
            Ok(tree) => tree,
            Err(error) => panic!("filesystem tree scan failed: {error}"),
        };
        assert_eq!(
            tree.entries(),
            [
                TreeEntry {
                    kind: TreeEntryKind::Directory,
                    logical_path: "notes".to_owned(),
                },
                TreeEntry {
                    kind: TreeEntryKind::File,
                    logical_path: "notes/today.md".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn filesystem_scan_rejects_wrong_case_reserved_aliases() {
        for (name, directory) in [
            (".GIT", true),
            (".Vault-Local", true),
            ("VAULT.JSON", false),
        ] {
            let temporary = TempDirectory::new();
            let path = temporary.path().join(name);
            if directory {
                create_directory(&path);
            } else {
                write_file(&path);
            }
            assert!(matches!(
                scan_vault_tree(temporary.path()),
                Err(TreeError::ReservedEntryAlias { .. })
            ));
        }
    }

    #[test]
    fn filesystem_scan_rejects_plaintext_and_noncanonical_ciphertext_names() {
        let plaintext = TempDirectory::new();
        write_file(&plaintext.path().join("secret.md"));
        assert!(matches!(
            scan_vault_tree(plaintext.path()),
            Err(TreeError::PlaintextMarkdown { .. })
        ));

        let noncanonical = TempDirectory::new();
        write_file(&noncanonical.path().join("secret.MD.enc"));
        assert!(matches!(
            scan_vault_tree(noncanonical.path()),
            Err(TreeError::NonCanonicalCiphertextName { .. })
        ));
    }

    #[test]
    fn filesystem_scan_counts_ignored_entries_against_the_work_limit() {
        let temporary = TempDirectory::new();
        write_file(&temporary.path().join("LICENSE"));
        write_file(&temporary.path().join("vault.json"));

        assert_eq!(
            scan_vault_tree_with_limits(
                temporary.path(),
                TreeLimits {
                    max_entries: 1,
                    max_depth: 10,
                    max_path_bytes: DEFAULT_MAX_TREE_PATH_BYTES,
                },
            ),
            Err(TreeError::EntryLimitExceeded { maximum: 1 })
        );
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_scan_rejects_symlinks_without_traversing_them() {
        use std::os::unix::fs::symlink;

        let temporary = TempDirectory::new();
        let target = temporary.path().join("target");
        create_directory(&target);
        write_file(&target.join("outside.md.enc"));
        let link = temporary.path().join("linked");
        if let Err(error) = symlink(&target, &link) {
            panic!("failed to create test symlink: {error}");
        }

        assert_eq!(
            scan_vault_tree(temporary.path()),
            Err(TreeError::LinkLikeEntry {
                relative_path: "linked".to_owned(),
            })
        );
    }

    #[derive(Debug)]
    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-tree-test-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            if let Err(error) = fs::create_dir(&path) {
                panic!("failed to create temporary directory: {error}");
            }
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn create_directory(path: &Path) {
        if let Err(error) = fs::create_dir_all(path) {
            panic!("failed to create test directory: {error}");
        }
    }

    fn write_file(path: &Path) {
        if let Err(error) = fs::write(path, b"opaque test bytes") {
            panic!("failed to create test file: {error}");
        }
    }
}
