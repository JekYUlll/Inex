//! Explicit plaintext-export destination preparation.
//!
//! This module deliberately contains no encryption or decryption. It owns the
//! dangerous filesystem boundary for a user-authorized export: an absent final
//! destination and a newly allocated sibling staging root. Callers populate
//! the staging root only with fully authenticated plaintext, audit it, then
//! publish it through the generic verified no-replace directory move.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::atomic::{
    AtomicDirectoryPublishError, AtomicDirectoryPublishOutcome, FilesystemDirectoryIdentity,
    atomic_move_verified_directory_no_replace_checked, filesystem_directory_identity,
    path_is_supported_local_filesystem, sync_directory,
};

/// Prefix reserved for a plaintext export staging directory. A failed export
/// intentionally leaves this root in place for explicit user cleanup.
pub const PLAINTEXT_EXPORT_STAGING_PREFIX: &str = ".inex-plaintext-export-stage-";

const MAX_STAGING_ATTEMPTS: usize = 32;

/// Non-sensitive export destination failures.
#[derive(Debug, Error)]
pub enum PlaintextExportDestinationError {
    /// Destination did not name one absent child below an existing parent.
    #[error("plaintext export destination must name one absent child of an existing directory")]
    InvalidDestination,
    /// Export may never create plaintext within the encrypted vault root.
    #[error("plaintext export destination must be outside the encrypted vault")]
    InsideVault,
    /// The selected parent lacks the local atomic-publication contract.
    #[error("plaintext export destination parent is not a supported local filesystem")]
    UnsupportedFilesystem,
    /// A final destination already exists and must never be replaced.
    #[error("plaintext export destination already exists")]
    DestinationExists,
    /// Parent identity or final destination changed after preparation.
    #[error("plaintext export destination changed before publication")]
    DestinationChanged,
    /// A new sibling staging root could not be allocated.
    #[error("could not create plaintext export staging directory")]
    StagingCreate,
    /// A safe filesystem operation failed without exposing a physical path.
    #[error("plaintext export filesystem operation failed")]
    Io,
    /// Generic no-replace publication failed after staging was retained.
    #[error("plaintext export publication failed")]
    Publish,
}

/// One prepared, absent export destination and its retained sibling staging
/// directory. The structure does not implement `Drop`: a caller must never
/// silently delete a staging directory that may contain user-authorized
/// plaintext after an error.
pub struct PlaintextExportStaging {
    destination: PathBuf,
    parent: PathBuf,
    parent_identity: FilesystemDirectoryIdentity,
    staging: PathBuf,
    staging_identity: FilesystemDirectoryIdentity,
}

/// One audited plaintext file entry. The digest is intended for the
/// destination-local receipt, never for logs or encrypted vault metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaintextExportEntry {
    relative_path: PathBuf,
    byte_len: u64,
    sha256: [u8; 32],
}

/// Exact manifest accumulated while writing one staging tree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlaintextExportManifest {
    entries: Vec<PlaintextExportEntry>,
    directories: BTreeSet<PathBuf>,
}

/// The authorized visibility level for one explicit plaintext export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaintextExportScope {
    /// Export public Markdown and the public projection of Umbra documents.
    Outer,
    /// Export fully decrypted Umbra Markdown. Requires a live Umbra session.
    Umbra,
}

/// Non-sensitive counts describing one populated plaintext export staging
/// tree. It deliberately contains no logical paths, document text or tags.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlaintextExportSummary {
    /// Markdown documents emitted into staging.
    pub markdown_documents: usize,
    /// Opaque assets emitted into staging.
    pub assets: usize,
    /// Logical directories created or verified in staging.
    pub directories: usize,
}

impl PlaintextExportManifest {
    /// Borrow the deterministic, caller-owned file entries.
    #[must_use]
    pub fn entries(&self) -> &[PlaintextExportEntry] {
        &self.entries
    }

    /// Verify the exact staged tree against recorded bytes and synchronize it
    /// before publication.
    ///
    /// # Errors
    ///
    /// Returns an error when a path is replaced, missing, oversized, differs
    /// from its exact recorded digest, or an unexpected file, directory or
    /// link appears beneath staging.
    pub fn audit(&self, staging: &Path) -> io::Result<()> {
        let root_metadata = fs::symlink_metadata(staging)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
            return Err(io::Error::other("plaintext export staging root unsafe"));
        }
        let expected_files: BTreeSet<&Path> = self
            .entries
            .iter()
            .map(|entry| entry.relative_path.as_path())
            .collect();
        let mut expected_directories = self.directories.clone();
        expected_directories.insert(PathBuf::new());
        for entry in &self.entries {
            register_parent_directories(&mut expected_directories, &entry.relative_path);
        }
        audit_exact_tree(
            staging,
            Path::new(""),
            &expected_files,
            &expected_directories,
        )?;
        for entry in &self.entries {
            let path = staging.join(&entry.relative_path);
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.len() != entry.byte_len
            {
                return Err(io::Error::other("plaintext export staged file changed"));
            }
            let actual: [u8; 32] = Sha256::digest(fs::read(&path)?).into();
            if actual != entry.sha256 {
                return Err(io::Error::other("plaintext export staged digest changed"));
            }
        }
        sync_directories_bottom_up(staging, &expected_directories)
    }
}

/// Create one file below a prepared staging root, with a create-new, synced
/// write and a manifest entry. It accepts only portable relative components.
///
/// # Errors
///
/// Returns an error for an unsafe relative path/parent, an existing target or
/// a failed restrictive write/synchronization. No manifest entry is appended
/// unless the complete file write has been synchronized.
pub fn write_plaintext_export_file(
    staging: &Path,
    relative_path: &Path,
    bytes: &[u8],
    manifest: &mut PlaintextExportManifest,
) -> io::Result<()> {
    if relative_path.as_os_str().is_empty()
        || relative_path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "plaintext export relative path invalid",
        ));
    }
    let parent = ensure_safe_relative_parent(staging, relative_path)?;
    let target = parent.join(relative_path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "plaintext export target name missing",
        )
    })?);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    configure_restrictive_file_creation(&mut options);
    let mut file = options.open(&target)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    restrict_file_permissions_best_effort(&file);
    manifest.entries.push(PlaintextExportEntry {
        relative_path: relative_path.to_path_buf(),
        byte_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        sha256: Sha256::digest(bytes).into(),
    });
    register_parent_directories(&mut manifest.directories, relative_path);
    Ok(())
}

/// Create or verify one empty logical directory below a prepared staging root.
/// It accepts only portable relative components and records the directory for
/// exact-tree auditing.
///
/// # Errors
///
/// Returns an error when the relative directory is unsafe or an existing
/// filesystem object is not a real directory.
pub fn create_plaintext_export_directory(
    staging: &Path,
    relative_path: &Path,
    manifest: &mut PlaintextExportManifest,
) -> io::Result<()> {
    if relative_path.as_os_str().is_empty()
        || relative_path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "plaintext export relative directory invalid",
        ));
    }
    let mut current = staging.to_path_buf();
    for component in relative_path.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plaintext export relative directory invalid",
            ));
        };
        current.push(name);
        match fs::create_dir(&current) {
            Ok(()) => restrict_directory_permissions_best_effort(&current),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(io::Error::other("plaintext export directory unsafe"));
        }
    }
    manifest.directories.insert(relative_path.to_path_buf());
    Ok(())
}

fn register_parent_directories(directories: &mut BTreeSet<PathBuf>, relative_path: &Path) {
    let mut current = PathBuf::new();
    if let Some(parent) = relative_path.parent() {
        for component in parent.components() {
            let std::path::Component::Normal(name) = component else {
                return;
            };
            current.push(name);
            directories.insert(current.clone());
        }
    }
}

fn audit_exact_tree(
    root: &Path,
    relative: &Path,
    expected_files: &BTreeSet<&Path>,
    expected_directories: &BTreeSet<PathBuf>,
) -> io::Result<()> {
    let directory = root.join(relative);
    let metadata = fs::symlink_metadata(&directory)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(io::Error::other("plaintext export staged directory unsafe"));
    }
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let child_relative = relative.join(&name);
        let metadata = entry.metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::other("plaintext export staged link present"));
        }
        if metadata.file_type().is_dir() {
            if !expected_directories.contains(&child_relative) {
                return Err(io::Error::other(
                    "plaintext export staged directory unexpected",
                ));
            }
            audit_exact_tree(root, &child_relative, expected_files, expected_directories)?;
        } else if metadata.file_type().is_file() {
            if !expected_files.contains(child_relative.as_path()) {
                return Err(io::Error::other("plaintext export staged file unexpected"));
            }
        } else {
            return Err(io::Error::other("plaintext export staged entry unsafe"));
        }
    }
    Ok(())
}

fn sync_directories_bottom_up(root: &Path, directories: &BTreeSet<PathBuf>) -> io::Result<()> {
    let mut ordered: Vec<_> = directories.iter().collect();
    ordered.sort_by_key(|relative| std::cmp::Reverse(relative.components().count()));
    for relative in ordered {
        sync_directory(&root.join(relative))?;
    }
    Ok(())
}

fn ensure_safe_relative_parent(staging: &Path, relative_path: &Path) -> io::Result<PathBuf> {
    let mut current = staging.to_path_buf();
    let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));
    for component in parent.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plaintext export parent invalid",
            ));
        };
        current.push(name);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(io::Error::other("plaintext export parent unsafe"));
        }
    }
    Ok(current)
}

impl fmt::Debug for PlaintextExportStaging {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaintextExportStaging")
            .field("destination", &"[REDACTED]")
            .field("staging", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
fn configure_restrictive_file_creation(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn configure_restrictive_file_creation(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn restrict_file_permissions_best_effort(file: &fs::File) {
    use std::os::unix::fs::PermissionsExt;
    let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file_permissions_best_effort(_file: &fs::File) {}

impl PlaintextExportStaging {
    /// Validate a new plaintext export destination and allocate an empty,
    /// restrictive sibling staging root.
    ///
    /// # Errors
    ///
    /// Returns an error when either root is unsafe, the destination is not an
    /// absent sibling outside the vault, or staging allocation fails.
    pub fn prepare(
        vault_root: &Path,
        destination: &Path,
    ) -> Result<Self, PlaintextExportDestinationError> {
        let vault_root =
            fs::canonicalize(vault_root).map_err(|_| PlaintextExportDestinationError::Io)?;
        let destination_name = destination
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(PlaintextExportDestinationError::InvalidDestination)?;
        let requested_parent = destination
            .parent()
            .ok_or(PlaintextExportDestinationError::InvalidDestination)?;
        let parent = fs::canonicalize(requested_parent)
            .map_err(|_| PlaintextExportDestinationError::InvalidDestination)?;
        let final_destination = parent.join(destination_name);
        if final_destination.starts_with(&vault_root) || vault_root.starts_with(&final_destination)
        {
            return Err(PlaintextExportDestinationError::InsideVault);
        }
        if !path_is_supported_local_filesystem(&parent)
            .map_err(|_| PlaintextExportDestinationError::Io)?
        {
            return Err(PlaintextExportDestinationError::UnsupportedFilesystem);
        }
        match fs::symlink_metadata(&final_destination) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(PlaintextExportDestinationError::DestinationExists),
            Err(_) => return Err(PlaintextExportDestinationError::Io),
        }
        let parent_identity = filesystem_directory_identity(&parent)
            .map_err(|_| PlaintextExportDestinationError::Io)?;
        for _ in 0..MAX_STAGING_ATTEMPTS {
            let staging = parent.join(format!(
                "{PLAINTEXT_EXPORT_STAGING_PREFIX}{}",
                Uuid::new_v4().simple()
            ));
            match fs::create_dir(&staging) {
                Ok(()) => {
                    restrict_directory_permissions_best_effort(&staging);
                    let staging_identity = filesystem_directory_identity(&staging)
                        .map_err(|_| PlaintextExportDestinationError::Io)?;
                    return Ok(Self {
                        destination: final_destination,
                        parent,
                        parent_identity,
                        staging,
                        staging_identity,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(PlaintextExportDestinationError::StagingCreate),
            }
        }
        Err(PlaintextExportDestinationError::StagingCreate)
    }

    /// Path of the retained staging root. It is safe to populate only after
    /// authenticated data has been obtained by the caller.
    #[must_use]
    pub fn staging(&self) -> &Path {
        &self.staging
    }

    /// Final destination path, which is absent until successful publication.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Revalidate identities and final absence before a caller writes or
    /// audits sensitive plaintext into staging.
    ///
    /// # Errors
    ///
    /// Returns an error when the parent/staging identity changed or the final
    /// destination is no longer absent.
    pub fn revalidate(&self) -> Result<(), PlaintextExportDestinationError> {
        if filesystem_directory_identity(&self.parent).ok().as_ref() != Some(&self.parent_identity)
            || filesystem_directory_identity(&self.staging).ok().as_ref()
                != Some(&self.staging_identity)
        {
            return Err(PlaintextExportDestinationError::DestinationChanged);
        }
        match fs::symlink_metadata(&self.destination) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(PlaintextExportDestinationError::DestinationExists),
            Err(_) => Err(PlaintextExportDestinationError::Io),
        }
    }

    /// Audit and atomically publish the retained staging root to its absent
    /// destination. On error the staging directory remains available for
    /// explicit incident handling.
    ///
    /// # Errors
    ///
    /// Returns an error when revalidation, caller audit or verified no-replace
    /// publication fails. It never removes the staging root on failure.
    pub fn publish<F>(
        self,
        audit: F,
    ) -> Result<AtomicDirectoryPublishOutcome, PlaintextExportDestinationError>
    where
        F: FnOnce(&Path) -> io::Result<()>,
    {
        self.revalidate()?;
        atomic_move_verified_directory_no_replace_checked(
            &self.staging,
            &self.destination,
            |current| {
                self.revalidate()
                    .map_err(|_| io::Error::other("plaintext export destination changed"))?;
                audit(current)
            },
        )
        .map_err(|error| map_publication_error(&error))
    }
}

fn map_publication_error(error: &AtomicDirectoryPublishError) -> PlaintextExportDestinationError {
    match error {
        AtomicDirectoryPublishError::DestinationExists => {
            PlaintextExportDestinationError::DestinationExists
        }
        AtomicDirectoryPublishError::InvalidPaths
        | AtomicDirectoryPublishError::NotMoved
        | AtomicDirectoryPublishError::Indeterminate
        | AtomicDirectoryPublishError::PublishedCleanupFailed
        | AtomicDirectoryPublishError::Io { .. } => PlaintextExportDestinationError::Publish,
    }
}

#[cfg(unix)]
fn restrict_directory_permissions_best_effort(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_directory_permissions_best_effort(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::{
        PlaintextExportDestinationError, PlaintextExportManifest, PlaintextExportStaging,
        write_plaintext_export_file,
    };
    use std::fs;

    struct TemporaryRoot(std::path::PathBuf);

    impl TemporaryRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "inex-plaintext-export-test-{}",
                uuid::Uuid::new_v4().simple()
            ));
            fs::create_dir(&path).unwrap_or_else(|error| panic!("test root: {error}"));
            Self(path)
        }
    }

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn prepares_and_publishes_a_new_sibling_destination() {
        let root = TemporaryRoot::new();
        let vault = root.0.join("vault");
        let exports = root.0.join("exports");
        fs::create_dir(&vault).unwrap_or_else(|error| panic!("vault: {error}"));
        fs::create_dir(&exports).unwrap_or_else(|error| panic!("exports: {error}"));
        let staging = PlaintextExportStaging::prepare(&vault, &exports.join("copy"))
            .unwrap_or_else(|error| panic!("prepare: {error}"));
        assert!(staging.staging().is_dir());
        assert!(!staging.destination().exists());
        staging
            .revalidate()
            .unwrap_or_else(|error| panic!("revalidate: {error}"));
        let mut manifest = PlaintextExportManifest::default();
        write_plaintext_export_file(
            staging.staging(),
            std::path::Path::new("entry.md"),
            b"intentional plaintext\n",
            &mut manifest,
        )
        .unwrap_or_else(|error| panic!("write fixture: {error}"));
        staging
            .publish(|current| manifest.audit(current))
            .unwrap_or_else(|error| panic!("publish: {error}"));
        assert_eq!(
            fs::read(exports.join("copy/entry.md"))
                .unwrap_or_else(|error| panic!("read published fixture: {error}")),
            b"intentional plaintext\n"
        );
    }

    #[test]
    fn rejects_existing_and_vault_internal_destinations() {
        let root = TemporaryRoot::new();
        let vault = root.0.join("vault");
        let exports = root.0.join("exports");
        fs::create_dir(&vault).unwrap_or_else(|error| panic!("vault: {error}"));
        fs::create_dir(&exports).unwrap_or_else(|error| panic!("exports: {error}"));
        assert!(matches!(
            PlaintextExportStaging::prepare(&vault, &vault.join("copy")),
            Err(PlaintextExportDestinationError::InsideVault)
        ));
        let existing = exports.join("existing");
        fs::create_dir(&existing).unwrap_or_else(|error| panic!("existing: {error}"));
        assert!(matches!(
            PlaintextExportStaging::prepare(&vault, &existing),
            Err(PlaintextExportDestinationError::DestinationExists)
        ));
    }

    #[test]
    fn audit_rejects_unrecorded_staging_entries() {
        let root = TemporaryRoot::new();
        let staging = root.0.join("staging");
        fs::create_dir(&staging).unwrap_or_else(|error| panic!("staging: {error}"));
        let mut manifest = PlaintextExportManifest::default();
        write_plaintext_export_file(
            &staging,
            std::path::Path::new("nested/entry.md"),
            b"intentional plaintext\n",
            &mut manifest,
        )
        .unwrap_or_else(|error| panic!("write fixture: {error}"));
        fs::write(staging.join("unexpected.txt"), b"not in manifest")
            .unwrap_or_else(|error| panic!("inject unexpected entry: {error}"));
        assert!(manifest.audit(&staging).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn writer_rejects_symlinked_intermediate_directory() {
        use std::os::unix::fs::symlink;

        let root = TemporaryRoot::new();
        let staging = root.0.join("staging");
        let outside = root.0.join("outside");
        fs::create_dir(&staging).unwrap_or_else(|error| panic!("staging: {error}"));
        fs::create_dir(&outside).unwrap_or_else(|error| panic!("outside: {error}"));
        symlink(&outside, staging.join("nested")).unwrap_or_else(|error| panic!("link: {error}"));
        let mut manifest = PlaintextExportManifest::default();
        assert!(
            write_plaintext_export_file(
                &staging,
                std::path::Path::new("nested/entry.md"),
                b"must not escape",
                &mut manifest,
            )
            .is_err()
        );
        assert!(!outside.join("entry.md").exists());
    }
}
