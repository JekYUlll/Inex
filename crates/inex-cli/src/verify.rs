//! Locked structural vault verification without password authentication.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use inex_core::atomic::{VaultMutationGuard, open_file_matches_path_and_is_single_link};
use inex_core::format::{self, ContentFlags, FormatError};
use inex_core::path::{LogicalPath, PathError};
use inex_core::tree::{self, TreeEntryKind, TreeError};
use inex_core::vault::{MAX_EDRY_ENVELOPE_BYTES, VAULT_CONFIG_FILE};
use inex_core::vault_config::{ConfigError, KdfPolicy, MAX_VAULT_JSON_BYTES, VaultConfig};

pub(crate) struct VerificationReport {
    pub(crate) documents: usize,
    pub(crate) directories: usize,
    pub(crate) weak_kdf_slots: usize,
    pub(crate) recovered_pending_transaction: bool,
}

#[derive(Debug)]
pub(crate) enum VerifyError {
    UnsafeRoot,
    MissingMetadata,
    NonCanonicalMetadataName,
    UnsafeFile,
    FileTooLarge,
    DuplicateFileId,
    HeaderContextMismatch,
    DraftInRepository,
    Metadata(ConfigError),
    Tree(TreeError),
    Path(PathError),
    Format(FormatError),
    MutationLock,
    Io {
        operation: VerifyIoOperation,
        kind: io::ErrorKind,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VerifyIoOperation {
    Inspect,
    ResolveRoot,
    Read,
}

impl fmt::Display for VerifyIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Inspect => "inspecting vault storage",
            Self::ResolveRoot => "resolving vault root",
            Self::Read => "reading bounded vault data",
        })
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeRoot => formatter.write_str("vault root is not a safe local directory"),
            Self::MissingMetadata => formatter.write_str("vault.json does not exist"),
            Self::NonCanonicalMetadataName => {
                formatter.write_str("vault metadata name is not uniquely lowercase `vault.json`")
            }
            Self::UnsafeFile => formatter.write_str("vault contains an unsafe file entry"),
            Self::FileTooLarge => formatter.write_str("vault file exceeds its format byte limit"),
            Self::DuplicateFileId => {
                formatter.write_str("multiple encrypted documents use one file identifier")
            }
            Self::HeaderContextMismatch => formatter.write_str(
                "encrypted document header does not match vault metadata or logical path",
            ),
            Self::DraftInRepository => {
                formatter.write_str("encrypted editor draft is present in committed storage")
            }
            Self::Metadata(error) => error.fmt(formatter),
            Self::Tree(error) => error.fmt(formatter),
            Self::Path(error) => error.fmt(formatter),
            Self::Format(error) => error.fmt(formatter),
            Self::MutationLock => {
                formatter.write_str("vault mutation lock or recovery validation failed")
            }
            Self::Io { operation, kind } => {
                write!(formatter, "I/O failed while {operation}: {kind:?}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

pub(crate) fn verify_locked(root: &Path) -> Result<VerificationReport, VerifyError> {
    let root = resolve_root(root)?;
    let guard = VaultMutationGuard::acquire(&root).map_err(|_| VerifyError::MutationLock)?;
    let recovered_pending_transaction = guard.recovery_changed_repository();
    let metadata_path = root.join(VAULT_CONFIG_FILE);
    require_exact_metadata_name(&root)?;
    let metadata_bytes = read_regular_bounded(&metadata_path, MAX_VAULT_JSON_BYTES)?;
    let (config, warnings) = VaultConfig::parse_untrusted(&metadata_bytes, KdfPolicy::default())
        .map_err(VerifyError::Metadata)?;

    let tree = tree::scan_vault_tree(&root).map_err(VerifyError::Tree)?;
    let mut file_ids = HashSet::new();
    let mut documents = 0_usize;
    let mut directories = 0_usize;

    for entry in tree.entries() {
        match entry.kind() {
            TreeEntryKind::Directory => directories += 1,
            TreeEntryKind::File => {
                let logical = LogicalPath::parse_canonical(entry.logical_path())
                    .map_err(VerifyError::Path)?;
                let physical = root.join(logical.to_ciphertext_relative_path());
                let envelope = read_regular_bounded(&physical, MAX_EDRY_ENVELOPE_BYTES)?;
                let parts = format::split_envelope(&envelope).map_err(VerifyError::Format)?;
                if parts.header.vault_id != config.vault_id
                    || parts.header.key_epoch != config.key_epoch
                    || parts.header.logical_path != logical.as_str()
                {
                    return Err(VerifyError::HeaderContextMismatch);
                }
                if parts.header.content_flags.contains(ContentFlags::DRAFT) {
                    return Err(VerifyError::DraftInRepository);
                }
                if !file_ids.insert(parts.header.file_id) {
                    return Err(VerifyError::DuplicateFileId);
                }
                documents += 1;
            }
        }
    }

    drop(guard);
    Ok(VerificationReport {
        documents,
        directories,
        weak_kdf_slots: warnings.len(),
        recovered_pending_transaction,
    })
}

fn resolve_root(root: &Path) -> Result<PathBuf, VerifyError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|error| io_error(VerifyIoOperation::Inspect, &error))?;
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        return Err(VerifyError::UnsafeRoot);
    }
    let root =
        fs::canonicalize(root).map_err(|error| io_error(VerifyIoOperation::ResolveRoot, &error))?;
    let metadata = fs::symlink_metadata(&root)
        .map_err(|error| io_error(VerifyIoOperation::Inspect, &error))?;
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        return Err(VerifyError::UnsafeRoot);
    }
    Ok(root)
}

fn require_exact_metadata_name(root: &Path) -> Result<(), VerifyError> {
    let mut aliases = 0_usize;
    let mut exact = false;
    for entry in fs::read_dir(root).map_err(|error| io_error(VerifyIoOperation::Inspect, &error))? {
        let entry = entry.map_err(|error| io_error(VerifyIoOperation::Inspect, &error))?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(VAULT_CONFIG_FILE))
        {
            aliases += 1;
            exact |= name == VAULT_CONFIG_FILE;
        }
    }
    match (aliases, exact) {
        (0, _) => Err(VerifyError::MissingMetadata),
        (1, true) => Ok(()),
        _ => Err(VerifyError::NonCanonicalMetadataName),
    }
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, VerifyError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(VerifyError::MissingMetadata);
        }
        Err(error) => return Err(io_error(VerifyIoOperation::Inspect, &error)),
    };
    validate_file_metadata(&metadata, maximum)?;

    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options
        .open(path)
        .map_err(|error| io_error(VerifyIoOperation::Read, &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error(VerifyIoOperation::Inspect, &error))?;
    validate_file_metadata(&metadata, maximum)?;
    let current = open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(VerifyIoOperation::Inspect, &error))?;
    if !current {
        return Err(VerifyError::UnsafeFile);
    }

    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    (&file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(VerifyIoOperation::Read, &error))?;
    if bytes.len() > maximum {
        return Err(VerifyError::FileTooLarge);
    }
    let current = open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(VerifyIoOperation::Inspect, &error))?;
    if !current {
        return Err(VerifyError::UnsafeFile);
    }
    Ok(bytes)
}

fn validate_file_metadata(metadata: &Metadata, maximum: usize) -> Result<(), VerifyError> {
    if is_link_or_reparse_point(metadata) || !metadata.file_type().is_file() {
        return Err(VerifyError::UnsafeFile);
    }
    if metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(VerifyError::FileTooLarge);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    const O_NOFOLLOW: i32 = 0o400_000;
    options.custom_flags(O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(target_os = "linux", windows)))]
fn configure_no_follow(_options: &mut OpenOptions) {}

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

fn io_error(operation: VerifyIoOperation, error: &io::Error) -> VerifyError {
    VerifyError::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use inex_core::path::{LogicalDir, LogicalPath};
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault::Vault;

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            Self(std::env::temp_dir().join(format!(
                "inex-cli-verify-{}-{nanos}-{counter}",
                std::process::id()
            )))
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

    fn policy() -> KdfPolicy {
        KdfPolicy {
            min_creation_ops_limit: 1,
            min_creation_mem_limit_bytes: 8 * 1024,
            max_creation_ops_limit: 4,
            max_creation_mem_limit_bytes: 64 * 1024 * 1024,
            max_unlock_ops_limit: 4,
            max_unlock_mem_limit_bytes: 64 * 1024 * 1024,
        }
    }

    fn create_vault(directory: &TestDirectory) -> Vault {
        Vault::create_with_params(
            directory.path(),
            b"test password",
            1_783_699_200_000,
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            },
            policy(),
        )
        .unwrap_or_else(|error| panic!("vault create failed: {error}"))
    }

    #[test]
    fn locked_verify_checks_structure_without_password() {
        let directory = TestDirectory::new();
        let mut vault = create_vault(&directory);
        let notes = LogicalDir::parse_canonical("notes")
            .unwrap_or_else(|error| panic!("dir path failed: {error}"));
        vault
            .create_directory(&notes)
            .unwrap_or_else(|error| panic!("mkdir failed: {error}"));
        let path = LogicalPath::parse_canonical("notes/entry.md")
            .unwrap_or_else(|error| panic!("logical path failed: {error}"));
        vault
            .create_document(&path, b"secret body", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("document create failed: {error}"));
        drop(vault);

        let report = verify_locked(directory.path())
            .unwrap_or_else(|error| panic!("verify failed: {error}"));
        assert_eq!(report.documents, 1);
        assert_eq!(report.directories, 1);
        assert_eq!(report.weak_kdf_slots, 1);
        assert!(!report.recovered_pending_transaction);
    }

    #[test]
    fn locked_verify_rejects_bad_edry_prefix() {
        let directory = TestDirectory::new();
        let mut vault = create_vault(&directory);
        let path = LogicalPath::parse_canonical("entry.md")
            .unwrap_or_else(|error| panic!("logical path failed: {error}"));
        vault
            .create_document(&path, b"secret body", 1_783_699_201_000)
            .unwrap_or_else(|error| panic!("document create failed: {error}"));
        drop(vault);
        let physical = directory.path().join("entry.md.enc");
        let mut bytes =
            fs::read(&physical).unwrap_or_else(|error| panic!("ciphertext read failed: {error}"));
        bytes[0] ^= 0xff;
        fs::write(physical, bytes)
            .unwrap_or_else(|error| panic!("ciphertext write failed: {error}"));
        assert!(matches!(
            verify_locked(directory.path()),
            Err(VerifyError::Format(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn locked_verify_rejects_symlinked_metadata() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let vault = create_vault(&directory);
        drop(vault);
        let metadata = directory.path().join(VAULT_CONFIG_FILE);
        let moved = directory.path().join("metadata.bin");
        fs::rename(&metadata, &moved)
            .unwrap_or_else(|error| panic!("metadata move failed: {error}"));
        symlink(&moved, &metadata)
            .unwrap_or_else(|error| panic!("metadata symlink failed: {error}"));
        assert!(matches!(
            verify_locked(directory.path()),
            Err(VerifyError::UnsafeFile)
        ));
    }
}
