//! Marker-free physical evidence for repository-candidate-seal-v1.
//!
//! This slice inventories one complete target root and proves the only
//! private state is the empty mutation lock. It deliberately neither accepts
//! nor writes a publication marker. Marker-aware collection belongs to the
//! later publication transaction, while the mutation lock is held.

use std::fmt;
use std::path::Path;

use inex_core::atomic::{
    FilesystemDirectoryIdentity, FilesystemFileIdentity, PublicationIdentityScheme,
};
#[cfg(target_os = "linux")]
use inex_core::atomic::{
    SecureSourceChild, SecureSourceDirectory, VAULT_LOCAL_DIRECTORY, VAULT_MUTATION_LOCK_FILE,
    open_secure_source_root, path_is_supported_local_filesystem,
};
#[cfg(target_os = "linux")]
use inex_core::path::{PortableCaseFoldFingerprint, raw_portable_case_fold_fingerprint};

use super::RepositoryImportError;
#[cfg(target_os = "linux")]
use super::candidate_seal::validate_physical_record_path;
use super::candidate_seal::{
    CandidateDirectoryIdentity, CandidateFileIdentity, CandidateSealError, PhysicalRecord,
    PhysicalRecordKind, PrivateBaselineRecord,
};
#[cfg(target_os = "linux")]
use super::canonical_normal_directory;
#[cfg(target_os = "linux")]
use super::hash_secure_file;

const MAX_PHYSICAL_RECORDS: usize = 1_000_000;
const MAX_PHYSICAL_PATH_BYTES: usize = 1_034;
const MAX_PHYSICAL_DEPTH: usize = 128;
const MAX_PHYSICAL_PATH_BUDGET: usize = 256 * 1024 * 1024;
const MAX_PHYSICAL_FILE_BYTES: u64 = 68 * 1024 * 1024;
const EMPTY_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

#[derive(Clone, Copy)]
struct PhysicalManifestLimits {
    records: usize,
    path_bytes: usize,
    depth: usize,
    path_budget: usize,
    file_bytes: u64,
}

const V1_LIMITS: PhysicalManifestLimits = PhysicalManifestLimits {
    records: MAX_PHYSICAL_RECORDS,
    path_bytes: MAX_PHYSICAL_PATH_BYTES,
    depth: MAX_PHYSICAL_DEPTH,
    path_budget: MAX_PHYSICAL_PATH_BUDGET,
    file_bytes: MAX_PHYSICAL_FILE_BYTES,
};

#[derive(Eq, PartialEq)]
enum AuditedPhysicalKind {
    Directory(FilesystemDirectoryIdentity),
    File {
        identity: FilesystemFileIdentity,
        size: u64,
        sha256: [u8; 32],
    },
}

#[derive(Eq, PartialEq)]
struct AuditedPhysicalRecord {
    path: String,
    kind: AuditedPhysicalKind,
}

/// Stable index into one marker-free physical manifest.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct PhysicalRecordId(usize);

/// Borrowed physical kind; no path or identity is cloned for consumers.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PhysicalRecordKindRef<'a> {
    Directory(&'a FilesystemDirectoryIdentity),
    File {
        identity: &'a FilesystemFileIdentity,
        size: u64,
        sha256: &'a [u8; 32],
    },
}

impl fmt::Debug for PhysicalRecordKindRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(_) => formatter.write_str("Directory([REDACTED])"),
            Self::File { size, .. } => formatter
                .debug_struct("File")
                .field("identity", &"[REDACTED]")
                .field("size", size)
                .field("sha256", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Borrowed read-only view of one canonical physical record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct PhysicalRecordRef<'a> {
    pub(super) id: PhysicalRecordId,
    pub(super) path: &'a str,
    pub(super) kind: PhysicalRecordKindRef<'a>,
}

impl fmt::Debug for PhysicalRecordRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhysicalRecordRef")
            .field("id", &self.id)
            .field("path", &"[REDACTED]")
            .field("kind", &self.kind)
            .finish()
    }
}

/// Owned target-only evidence collected before any publication marker exists.
#[derive(Eq, PartialEq)]
pub(super) struct MarkerFreePhysicalManifest {
    root_identity: FilesystemDirectoryIdentity,
    local_identity: FilesystemDirectoryIdentity,
    lock_identity: FilesystemFileIdentity,
    records: Vec<AuditedPhysicalRecord>,
    owned_path_high_water: usize,
}

impl fmt::Debug for MarkerFreePhysicalManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MarkerFreePhysicalManifest")
            .field("root_identity", &"[REDACTED]")
            .field("local_identity", &"[REDACTED]")
            .field("lock_identity", &"[REDACTED]")
            .field("records", &self.records.len())
            .field("owned_path_high_water", &self.owned_path_high_water)
            .finish()
    }
}

/// Borrowed candidate-seal roles projected from one audited physical manifest.
pub(super) struct CandidatePhysicalProjection<'a> {
    pub(super) physical: Vec<PhysicalRecord<'a>>,
    pub(super) private_baseline: PrivateBaselineRecord,
}

impl fmt::Debug for CandidatePhysicalProjection<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidatePhysicalProjection")
            .field("physical_records", &self.physical.len())
            .field("private_baseline", &"[REDACTED]")
            .finish()
    }
}

impl MarkerFreePhysicalManifest {
    pub(super) fn root_identity(&self) -> &FilesystemDirectoryIdentity {
        &self.root_identity
    }

    pub(super) fn local_identity(&self) -> &FilesystemDirectoryIdentity {
        &self.local_identity
    }

    pub(super) fn lock_identity(&self) -> &FilesystemFileIdentity {
        &self.lock_identity
    }

    /// Iterate the canonical physical records without cloning retained paths.
    pub(super) fn records(
        &self,
    ) -> impl ExactSizeIterator<Item = PhysicalRecordRef<'_>> + DoubleEndedIterator + '_ {
        self.records
            .iter()
            .enumerate()
            .map(|(index, record)| physical_record_ref(PhysicalRecordId(index), record))
    }

    /// Resolve one stable record ID against this manifest.
    pub(super) fn record(&self, id: PhysicalRecordId) -> Option<PhysicalRecordRef<'_>> {
        self.records
            .get(id.0)
            .map(|record| physical_record_ref(id, record))
    }

    /// Borrow one canonical record by exact byte spelling.
    pub(super) fn find(&self, path: &str) -> Option<PhysicalRecordRef<'_>> {
        self.records
            .binary_search_by(|record| record.path.as_bytes().cmp(path.as_bytes()))
            .ok()
            .and_then(|index| self.record(PhysicalRecordId(index)))
    }

    /// Number of directory records, including the target root.
    pub(super) fn directory_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| matches!(record.kind, AuditedPhysicalKind::Directory(_)))
            .count()
    }

    /// Canonical path bytes retained by this sole owned physical manifest.
    pub(super) fn retained_path_bytes(&self) -> usize {
        self.records.iter().map(|record| record.path.len()).sum()
    }

    #[cfg(test)]
    fn owned_path_high_water(&self) -> usize {
        self.owned_path_high_water
    }

    /// Revalidate the complete target against this exact baseline.
    ///
    /// Linux walks through held descriptor-relative children and retains only
    /// one record-ID bitset plus the bounded recursion stack. It deliberately
    /// does not rebuild any second owned namespace or path manifest. Other
    /// platforms remain fail closed until their native held-handle traversal
    /// is implemented and tested.
    pub(super) fn require_current_exact(&self, root: &Path) -> Result<(), RepositoryImportError> {
        #[cfg(target_os = "linux")]
        {
            self.require_current_exact_linux(root)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, root);
            Err(RepositoryImportError::TargetAuditFailed)
        }
    }

    #[cfg(target_os = "linux")]
    fn require_current_exact_linux(&self, root: &Path) -> Result<(), RepositoryImportError> {
        let root = canonical_normal_directory(root, RepositoryImportError::TargetAuditFailed)?;
        if !path_is_supported_local_filesystem(&root)
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        let directory =
            open_secure_source_root(&root).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        if directory.identity() != &self.root_identity {
            return Err(RepositoryImportError::TargetAuditFailed);
        }

        let bit_words = self
            .records
            .len()
            .checked_add(u64::BITS as usize - 1)
            .ok_or(RepositoryImportError::ResourceLimit)?
            / u64::BITS as usize;
        let mut seen = Vec::new();
        seen.try_reserve_exact(bit_words)
            .map_err(|_| RepositoryImportError::ResourceLimit)?;
        seen.resize(bit_words, 0_u64);
        mark_physical_record_seen(&mut seen, PhysicalRecordId(0))?;
        let mut observed_records = 1_usize;
        let mut observed_path_bytes = 0_usize;

        walk_current_physical_directory(
            self,
            &directory,
            PhysicalRecordId(0),
            0,
            &mut seen,
            &mut observed_records,
            &mut observed_path_bytes,
        )?;
        directory
            .verify_no_alternate_data_streams()
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;

        if observed_records != self.records.len()
            || observed_path_bytes != self.retained_path_bytes()
            || seen.iter().enumerate().any(|(word_index, word)| {
                let first = word_index * u64::BITS as usize;
                let remaining = self.records.len().saturating_sub(first).min(64);
                let expected = if remaining == 64 {
                    u64::MAX
                } else {
                    (1_u64 << remaining).wrapping_sub(1)
                };
                *word != expected
            })
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        Ok(())
    }

    /// Bind all physical identities to the publication marker's explicit
    /// scheme and construct only the encoder roles this collector owns.
    pub(super) fn project(
        &self,
        scheme: PublicationIdentityScheme,
    ) -> Result<CandidatePhysicalProjection<'_>, CandidateSealError> {
        let mut physical = Vec::new();
        physical
            .try_reserve_exact(self.records.len())
            .map_err(|_| CandidateSealError::ResourceLimit)?;
        for record in &self.records {
            let kind = match &record.kind {
                AuditedPhysicalKind::Directory(identity) => PhysicalRecordKind::Directory(
                    CandidateDirectoryIdentity::from_observed(identity, scheme)?,
                ),
                AuditedPhysicalKind::File {
                    identity,
                    size,
                    sha256,
                } => PhysicalRecordKind::File {
                    identity: CandidateFileIdentity::from_observed(identity, scheme)?,
                    size: *size,
                    sha256: *sha256,
                },
            };
            physical.push(PhysicalRecord {
                path: record.path.as_str(),
                kind,
            });
        }
        Ok(CandidatePhysicalProjection {
            physical,
            private_baseline: PrivateBaselineRecord {
                identity: CandidateFileIdentity::from_observed(&self.lock_identity, scheme)?,
            },
        })
    }
}

fn physical_record_ref(
    id: PhysicalRecordId,
    record: &AuditedPhysicalRecord,
) -> PhysicalRecordRef<'_> {
    let kind = match &record.kind {
        AuditedPhysicalKind::Directory(identity) => PhysicalRecordKindRef::Directory(identity),
        AuditedPhysicalKind::File {
            identity,
            size,
            sha256,
        } => PhysicalRecordKindRef::File {
            identity,
            size: *size,
            sha256,
        },
    };
    PhysicalRecordRef {
        id,
        path: &record.path,
        kind,
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn walk_current_physical_directory(
    baseline: &MarkerFreePhysicalManifest,
    directory: &SecureSourceDirectory,
    parent_id: PhysicalRecordId,
    depth: usize,
    seen: &mut [u64],
    observed_records: &mut usize,
    observed_path_bytes: &mut usize,
) -> Result<(), RepositoryImportError> {
    if depth > MAX_PHYSICAL_DEPTH || *observed_records > baseline.records.len() {
        return Err(RepositoryImportError::ResourceLimit);
    }
    let parent = baseline
        .records
        .get(parent_id.0)
        .ok_or(RepositoryImportError::TargetAuditFailed)?;
    if !matches!(parent.kind, AuditedPhysicalKind::Directory(_)) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    directory
        .verify_no_alternate_data_streams()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    for entry in directory
        .read_dir()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?
    {
        let entry = entry.map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let name = entry.file_name();
        let name_text = name
            .to_str()
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        let index = baseline
            .records
            .binary_search_by(|record| {
                compare_record_path_to_child(&record.path, &parent.path, name_text)
            })
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        let id = PhysicalRecordId(index);
        let expected = &baseline.records[index];
        if expected.path.len() > MAX_PHYSICAL_PATH_BYTES {
            return Err(RepositoryImportError::ResourceLimit);
        }
        mark_physical_record_seen(seen, id)?;
        *observed_records = observed_records
            .checked_add(1)
            .filter(|count| *count <= baseline.records.len())
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        *observed_path_bytes = observed_path_bytes
            .checked_add(expected.path.len())
            .filter(|bytes| *bytes <= MAX_PHYSICAL_PATH_BUDGET)
            .ok_or(RepositoryImportError::ResourceLimit)?;

        match (
            &expected.kind,
            directory
                .open_child(&name)
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?,
        ) {
            (
                AuditedPhysicalKind::Directory(expected_identity),
                SecureSourceChild::Directory(child),
            ) if child.identity() == expected_identity => {
                walk_current_physical_directory(
                    baseline,
                    &child,
                    id,
                    depth.saturating_add(1),
                    seen,
                    observed_records,
                    observed_path_bytes,
                )?;
                child
                    .verify_no_alternate_data_streams()
                    .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            }
            (
                AuditedPhysicalKind::File {
                    identity: expected_identity,
                    size: expected_size,
                    sha256: expected_sha256,
                },
                SecureSourceChild::File(file),
            ) => {
                file.verify_no_alternate_data_streams()
                    .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
                let (identity, size, sha256) = hash_secure_file(
                    file,
                    RepositoryImportError::TargetAuditFailed,
                    Some(MAX_PHYSICAL_FILE_BYTES),
                )?;
                if &identity != expected_identity
                    || size != *expected_size
                    || sha256 != *expected_sha256
                {
                    return Err(RepositoryImportError::TargetAuditFailed);
                }
            }
            _ => return Err(RepositoryImportError::TargetAuditFailed),
        }
    }
    directory
        .verify_no_alternate_data_streams()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)
}

#[cfg(target_os = "linux")]
fn compare_record_path_to_child(
    record_path: &str,
    parent_path: &str,
    child_name: &str,
) -> std::cmp::Ordering {
    record_path.bytes().cmp(
        parent_path
            .bytes()
            .chain((!parent_path.is_empty()).then_some(b'/'))
            .chain(child_name.bytes()),
    )
}

#[cfg(target_os = "linux")]
fn mark_physical_record_seen(
    seen: &mut [u64],
    id: PhysicalRecordId,
) -> Result<(), RepositoryImportError> {
    let word = seen
        .get_mut(id.0 / u64::BITS as usize)
        .ok_or(RepositoryImportError::TargetAuditFailed)?;
    let mask = 1_u64 << (id.0 % u64::BITS as usize);
    if *word & mask != 0 {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    *word |= mask;
    Ok(())
}

/// Recursively collect one complete marker-free target without modifying it.
pub(super) fn collect_marker_free_physical_manifest(
    root: &Path,
) -> Result<MarkerFreePhysicalManifest, RepositoryImportError> {
    collect_marker_free_physical_manifest_with_limits(root, V1_LIMITS)
}

fn collect_marker_free_physical_manifest_with_limits(
    root: &Path,
    limits: PhysicalManifestLimits,
) -> Result<MarkerFreePhysicalManifest, RepositoryImportError> {
    #[cfg(target_os = "linux")]
    {
        collect_marker_free_physical_manifest_with_fingerprint(
            root,
            limits,
            raw_portable_case_fold_fingerprint,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, limits);
        Err(RepositoryImportError::TargetAuditFailed)
    }
}

#[cfg(target_os = "linux")]
struct DirectPhysicalCollector<'a, F> {
    limits: PhysicalManifestLimits,
    fingerprint: &'a F,
    records: Vec<AuditedPhysicalRecord>,
    fingerprints: Vec<PortableCaseFoldFingerprint>,
    retained_path_bytes: usize,
    owned_path_high_water: usize,
    git_fingerprint: PortableCaseFoldFingerprint,
    local_fingerprint: PortableCaseFoldFingerprint,
    local_identity: Option<FilesystemDirectoryIdentity>,
    lock_identity: Option<FilesystemFileIdentity>,
}

#[cfg(target_os = "linux")]
impl<F> DirectPhysicalCollector<'_, F>
where
    F: Fn(&str) -> PortableCaseFoldFingerprint,
{
    fn collect_directory(
        &mut self,
        directory: &SecureSourceDirectory,
        parent_id: PhysicalRecordId,
        depth: usize,
    ) -> Result<(), RepositoryImportError> {
        if depth > self.limits.depth {
            return Err(RepositoryImportError::ResourceLimit);
        }
        directory
            .verify_no_alternate_data_streams()
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
        for entry in directory
            .read_dir()
            .map_err(|_| RepositoryImportError::TargetAuditFailed)?
        {
            let entry = entry.map_err(|_| RepositoryImportError::TargetAuditFailed)?;
            let name = entry.file_name();
            let name_text = name
                .to_str()
                .ok_or(RepositoryImportError::TargetAuditFailed)?;
            self.reserve_record_and_fingerprint()?;
            let child_depth = depth
                .checked_add(1)
                .filter(|child_depth| *child_depth <= self.limits.depth)
                .ok_or(RepositoryImportError::ResourceLimit)?;
            let path = self.build_canonical_child(parent_id, name_text, child_depth)?;
            self.require_portable_path_uniqueness(&path)?;

            match directory
                .open_child(&name)
                .map_err(|_| RepositoryImportError::TargetAuditFailed)?
            {
                SecureSourceChild::Directory(child) => {
                    let identity = child.identity().clone();
                    self.require_private_directory(&path, &identity)?;
                    let id = PhysicalRecordId(self.records.len());
                    self.records.push(AuditedPhysicalRecord {
                        path,
                        kind: AuditedPhysicalKind::Directory(identity),
                    });
                    self.collect_directory(&child, id, child_depth)?;
                    child
                        .verify_no_alternate_data_streams()
                        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
                }
                SecureSourceChild::File(file) => {
                    file.verify_no_alternate_data_streams()
                        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
                    if file
                        .observed_len()
                        .map_err(|_| RepositoryImportError::TargetAuditFailed)?
                        > self.limits.file_bytes
                    {
                        return Err(RepositoryImportError::ResourceLimit);
                    }
                    let (identity, size, sha256) = hash_secure_file(
                        file,
                        RepositoryImportError::TargetAuditFailed,
                        Some(self.limits.file_bytes),
                    )?;
                    self.require_private_file(&path, &identity, size, sha256)?;
                    self.records.push(AuditedPhysicalRecord {
                        path,
                        kind: AuditedPhysicalKind::File {
                            identity,
                            size,
                            sha256,
                        },
                    });
                }
                SecureSourceChild::Other => {
                    return Err(RepositoryImportError::TargetAuditFailed);
                }
            }
        }
        directory
            .verify_no_alternate_data_streams()
            .map_err(|_| RepositoryImportError::TargetAuditFailed)
    }

    fn build_canonical_child(
        &mut self,
        parent_id: PhysicalRecordId,
        name: &str,
        depth: usize,
    ) -> Result<String, RepositoryImportError> {
        let parent = self
            .records
            .get(parent_id.0)
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        if !matches!(parent.kind, AuditedPhysicalKind::Directory(_)) {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        let separator = usize::from(!parent.path.is_empty());
        let path_length = parent
            .path
            .len()
            .checked_add(separator)
            .and_then(|length| length.checked_add(name.len()))
            .ok_or(RepositoryImportError::ResourceLimit)?;
        if path_length > self.limits.path_bytes || depth > self.limits.depth {
            return Err(RepositoryImportError::ResourceLimit);
        }
        let retained_path_bytes = advance_owned_path_budget(
            self.retained_path_bytes,
            path_length,
            self.limits.path_budget,
        )?;
        let mut path = String::new();
        path.try_reserve_exact(path_length)
            .map_err(|_| RepositoryImportError::ResourceLimit)?;
        path.push_str(&parent.path);
        if separator != 0 {
            path.push('/');
        }
        path.push_str(name);
        validate_physical_record_path(&path).map_err(map_candidate_path_error)?;
        self.retained_path_bytes = retained_path_bytes;
        self.owned_path_high_water = self.owned_path_high_water.max(retained_path_bytes);
        Ok(path)
    }

    fn reserve_record_and_fingerprint(&mut self) -> Result<(), RepositoryImportError> {
        if self.records.len() >= self.limits.records {
            return Err(RepositoryImportError::ResourceLimit);
        }
        self.records
            .try_reserve(1)
            .map_err(|_| RepositoryImportError::ResourceLimit)?;
        self.fingerprints
            .try_reserve(1)
            .map_err(|_| RepositoryImportError::ResourceLimit)
    }

    fn require_portable_path_uniqueness(
        &mut self,
        path: &str,
    ) -> Result<(), RepositoryImportError> {
        let top_level = path.split('/').next().unwrap_or_default();
        let top_fingerprint = (self.fingerprint)(top_level);
        if (top_fingerprint == self.git_fingerprint && top_level != ".git")
            || (top_fingerprint == self.local_fingerprint && top_level != VAULT_LOCAL_DIRECTORY)
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        self.fingerprints.push((self.fingerprint)(path));
        Ok(())
    }

    fn require_private_directory(
        &mut self,
        path: &str,
        identity: &FilesystemDirectoryIdentity,
    ) -> Result<(), RepositoryImportError> {
        if path == VAULT_LOCAL_DIRECTORY {
            if self.local_identity.replace(identity.clone()).is_some() {
                return Err(RepositoryImportError::TargetAuditFailed);
            }
        } else if path
            .strip_prefix(VAULT_LOCAL_DIRECTORY)
            .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        Ok(())
    }

    fn require_private_file(
        &mut self,
        path: &str,
        identity: &FilesystemFileIdentity,
        size: u64,
        sha256: [u8; 32],
    ) -> Result<(), RepositoryImportError> {
        if path == VAULT_LOCAL_DIRECTORY {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        if let Some(private_child) = path.strip_prefix(VAULT_LOCAL_DIRECTORY).and_then(|suffix| {
            suffix
                .strip_prefix('/')
                .filter(|child| !child.contains('/'))
        }) {
            if private_child != VAULT_MUTATION_LOCK_FILE
                || size != 0
                || sha256 != EMPTY_SHA256
                || self.lock_identity.replace(identity.clone()).is_some()
            {
                return Err(RepositoryImportError::TargetAuditFailed);
            }
        } else if path
            .strip_prefix(VAULT_LOCAL_DIRECTORY)
            .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
        Ok(())
    }
}

fn advance_owned_path_budget(
    retained: usize,
    added: usize,
    maximum: usize,
) -> Result<usize, RepositoryImportError> {
    retained
        .checked_add(added)
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RepositoryImportError::ResourceLimit)
}

#[cfg(target_os = "linux")]
fn collect_marker_free_physical_manifest_with_fingerprint<F>(
    root: &Path,
    limits: PhysicalManifestLimits,
    fingerprint: F,
) -> Result<MarkerFreePhysicalManifest, RepositoryImportError>
where
    F: Fn(&str) -> PortableCaseFoldFingerprint,
{
    let root = canonical_normal_directory(root, RepositoryImportError::TargetAuditFailed)?;
    if !path_is_supported_local_filesystem(&root)
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    if limits.records == 0 {
        return Err(RepositoryImportError::ResourceLimit);
    }
    let directory =
        open_secure_source_root(&root).map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    directory
        .verify_no_alternate_data_streams()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;
    let root_identity = directory.identity().clone();
    let mut records = Vec::new();
    records
        .try_reserve(1)
        .map_err(|_| RepositoryImportError::ResourceLimit)?;
    records.push(AuditedPhysicalRecord {
        path: String::new(),
        kind: AuditedPhysicalKind::Directory(root_identity.clone()),
    });
    let mut collector = DirectPhysicalCollector {
        limits,
        fingerprint: &fingerprint,
        records,
        fingerprints: Vec::new(),
        retained_path_bytes: 0,
        owned_path_high_water: 0,
        git_fingerprint: fingerprint(".git"),
        local_fingerprint: fingerprint(VAULT_LOCAL_DIRECTORY),
        local_identity: None,
        lock_identity: None,
    };
    collector.collect_directory(&directory, PhysicalRecordId(0), 0)?;
    directory
        .verify_no_alternate_data_streams()
        .map_err(|_| RepositoryImportError::TargetAuditFailed)?;

    collector.fingerprints.sort_unstable();
    if collector
        .fingerprints
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    drop(std::mem::take(&mut collector.fingerprints));
    collector
        .records
        .sort_unstable_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    require_complete_physical_parent_graph(&collector.records)?;
    let retained_path_bytes = collector
        .records
        .iter()
        .try_fold(0_usize, |total, record| {
            total
                .checked_add(record.path.len())
                .ok_or(RepositoryImportError::ResourceLimit)
        })?;
    if retained_path_bytes != collector.retained_path_bytes
        || collector.owned_path_high_water != retained_path_bytes
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    let local_identity = collector
        .local_identity
        .ok_or(RepositoryImportError::TargetAuditFailed)?;
    let lock_identity = collector
        .lock_identity
        .ok_or(RepositoryImportError::TargetAuditFailed)?;
    let manifest = MarkerFreePhysicalManifest {
        root_identity,
        local_identity,
        lock_identity,
        records: collector.records,
        owned_path_high_water: collector.owned_path_high_water,
    };
    manifest.require_current_exact(&root)?;
    Ok(manifest)
}

#[cfg(target_os = "linux")]
fn require_complete_physical_parent_graph(
    records: &[AuditedPhysicalRecord],
) -> Result<(), RepositoryImportError> {
    let Some(root) = records.first() else {
        return Err(RepositoryImportError::TargetAuditFailed);
    };
    if !root.path.is_empty() || !matches!(root.kind, AuditedPhysicalKind::Directory(_)) {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    if records
        .windows(2)
        .any(|pair| pair[0].path.as_bytes() >= pair[1].path.as_bytes())
    {
        return Err(RepositoryImportError::TargetAuditFailed);
    }
    for record in &records[1..] {
        let parent_path = record
            .path
            .rfind('/')
            .map_or("", |separator| &record.path[..separator]);
        let parent = records
            .binary_search_by(|candidate| candidate.path.as_bytes().cmp(parent_path.as_bytes()))
            .ok()
            .and_then(|index| records.get(index))
            .ok_or(RepositoryImportError::TargetAuditFailed)?;
        if !matches!(parent.kind, AuditedPhysicalKind::Directory(_)) {
            return Err(RepositoryImportError::TargetAuditFailed);
        }
    }
    Ok(())
}

fn map_candidate_path_error(error: CandidateSealError) -> RepositoryImportError {
    match error {
        CandidateSealError::ResourceLimit => RepositoryImportError::ResourceLimit,
        CandidateSealError::InvalidContext
        | CandidateSealError::InvalidRecord
        | CandidateSealError::NonCanonicalOrder => RepositoryImportError::TargetAuditFailed,
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_platform_tests {
    use super::*;

    #[test]
    fn marker_free_physical_collection_fails_closed() {
        assert!(matches!(
            collect_marker_free_physical_manifest(Path::new(".")),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use inex_core::atomic::{
        IMPORT_PUBLISH_MARKER_V1, IMPORT_PUBLISH_MARKER_V2, PublicationIdentityScheme,
        filesystem_directory_identity, filesystem_file_identity,
    };
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::repository_import::initialize_and_audit_target;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "inex-candidate-manifest-{label}-{}-{sequence}",
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

    fn minimal_target(label: &str) -> TestDirectory {
        let target = TestDirectory::new(label);
        let local = target.path().join(VAULT_LOCAL_DIRECTORY);
        fs::create_dir(&local).expect("private directory creates");
        fs::write(local.join(VAULT_MUTATION_LOCK_FILE), []).expect("empty lock creates");
        target
    }

    fn assert_resource_limit(result: &Result<MarkerFreePhysicalManifest, RepositoryImportError>) {
        assert!(matches!(result, Err(RepositoryImportError::ResourceLimit)));
    }

    fn exact_observed_limits(manifest: &MarkerFreePhysicalManifest) -> PhysicalManifestLimits {
        PhysicalManifestLimits {
            records: manifest.records.len(),
            path_bytes: manifest
                .records
                .iter()
                .map(|record| record.path.len())
                .max()
                .expect("root record exists"),
            depth: manifest
                .records
                .iter()
                .map(|record| {
                    if record.path.is_empty() {
                        0
                    } else {
                        record.path.split('/').count()
                    }
                })
                .max()
                .expect("root record exists"),
            path_budget: manifest
                .records
                .iter()
                .try_fold(0_usize, |total, record| {
                    total.checked_add(record.path.len())
                })
                .expect("test path budget fits"),
            file_bytes: manifest
                .records
                .iter()
                .filter_map(|record| match record.kind {
                    AuditedPhysicalKind::File { size, .. } => Some(size),
                    AuditedPhysicalKind::Directory(_) => None,
                })
                .max()
                .expect("lock file exists"),
        }
    }

    #[test]
    fn canonical_real_target_is_complete_sorted_projectable_and_redacted() {
        let target = minimal_target("real-target");
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
        initialize_and_audit_target(
            target.path(),
            &[
                PathBuf::from("vault.json"),
                PathBuf::from("note.md.enc"),
                PathBuf::from("images/pixel.bin.asset.enc"),
            ],
            1_784_044_800,
        )
        .expect("real target initializes");

        let manifest = collect_marker_free_physical_manifest(target.path())
            .expect("marker-free target collects");
        assert_eq!(
            manifest.records.first().map(|record| record.path.as_str()),
            Some("")
        );
        assert!(
            manifest
                .records
                .windows(2)
                .all(|pair| { pair[0].path.as_bytes() < pair[1].path.as_bytes() })
        );
        assert!(manifest.records.iter().any(|record| {
            record.path.starts_with(".git/objects/") && record.path.split('/').count() >= 3
        }));
        assert!(
            manifest
                .records
                .iter()
                .any(|record| record.path == "images/pixel.bin.asset.enc")
        );

        assert_eq!(
            manifest.root_identity(),
            &filesystem_directory_identity(target.path()).expect("root identity captures")
        );
        assert_eq!(
            manifest.local_identity(),
            &filesystem_directory_identity(&target.path().join(VAULT_LOCAL_DIRECTORY))
                .expect("local identity captures")
        );
        let lock = fs::File::open(
            target
                .path()
                .join(VAULT_LOCAL_DIRECTORY)
                .join(VAULT_MUTATION_LOCK_FILE),
        )
        .expect("lock opens");
        assert_eq!(
            manifest.lock_identity(),
            &filesystem_file_identity(&lock).expect("lock identity captures")
        );

        let scheme = PublicationIdentityScheme::LinuxDevInodeV1;
        let projection = manifest.project(scheme).expect("Linux identities project");
        assert_eq!(projection.physical.len(), manifest.records.len());
        let expected_root =
            CandidateDirectoryIdentity::from_observed(manifest.root_identity(), scheme)
                .expect("root projects");
        assert!(matches!(
            projection.physical[0].kind,
            PhysicalRecordKind::Directory(identity) if identity == expected_root
        ));
        let expected_lock = CandidateFileIdentity::from_observed(manifest.lock_identity(), scheme)
            .expect("lock projects");
        assert_eq!(projection.private_baseline.identity, expected_lock);
        assert!(projection.physical.iter().any(|record| {
            record.path == format!("{VAULT_LOCAL_DIRECTORY}/{VAULT_MUTATION_LOCK_FILE}")
                && matches!(
                    record.kind,
                    PhysicalRecordKind::File { identity, size: 0, sha256 }
                        if identity == expected_lock && sha256 == EMPTY_SHA256
                )
        }));
        assert_eq!(
            manifest
                .project(PublicationIdentityScheme::WindowsModernFileId128V1)
                .err(),
            Some(CandidateSealError::InvalidContext)
        );

        let debug = format!("{manifest:?} {projection:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(target.path().to_string_lossy().as_ref()));
        assert!(!debug.contains("note.md.enc"));
    }

    #[test]
    fn collector_recurses_streams_hashes_and_keeps_section_one_order() {
        let target = minimal_target("recursive");
        fs::create_dir_all(target.path().join("deep/nested")).expect("nested directories create");
        let body: Vec<u8> = (0_u32..131_073)
            .map(|value| value.to_le_bytes()[0])
            .collect();
        fs::write(target.path().join("deep/nested/payload.bin"), &body)
            .expect("streamed body writes");

        let manifest = collect_marker_free_physical_manifest(target.path())
            .expect("recursive target collects");
        assert!(
            manifest
                .records
                .windows(2)
                .all(|pair| { pair[0].path.as_bytes() < pair[1].path.as_bytes() })
        );
        assert!(manifest.records.iter().any(|record| record.path == "deep"));
        assert!(
            manifest
                .records
                .iter()
                .any(|record| record.path == "deep/nested")
        );
        let payload = manifest
            .records
            .iter()
            .find(|record| record.path == "deep/nested/payload.bin")
            .expect("deep file is inventoried");
        let expected_sha256: [u8; 32] = Sha256::digest(&body).into();
        assert!(matches!(
            payload.kind,
            AuditedPhysicalKind::File { size, sha256, .. }
                if size == body.len() as u64 && sha256 == expected_sha256
        ));
    }

    #[test]
    fn read_only_views_borrow_the_sole_retained_path_manifest() {
        let target = minimal_target("borrowed-view");
        fs::create_dir_all(target.path().join("deep/nested")).expect("nested directories create");
        fs::write(target.path().join("deep/nested/payload.bin"), b"payload")
            .expect("payload writes");
        let manifest =
            collect_marker_free_physical_manifest(target.path()).expect("fixture collects");

        assert_eq!(
            manifest.retained_path_bytes(),
            manifest
                .records
                .iter()
                .map(|record| record.path.len())
                .sum::<usize>()
        );
        assert_eq!(manifest.directory_count(), 4);
        assert_eq!(
            manifest.owned_path_high_water(),
            manifest.retained_path_bytes()
        );
        assert_eq!(manifest.records().len(), manifest.records.len());
        for borrowed in manifest.records() {
            let owned = &manifest.records[borrowed.id.0];
            assert_eq!(borrowed.path.as_ptr(), owned.path.as_ptr());
            assert_eq!(borrowed.path.len(), owned.path.len());
            assert_eq!(manifest.record(borrowed.id), Some(borrowed));
            let found = manifest.find(borrowed.path).expect("exact path finds");
            assert_eq!(found, borrowed);
            assert_eq!(found.path.as_ptr(), owned.path.as_ptr());
        }
        assert!(
            manifest
                .record(PhysicalRecordId(manifest.records.len()))
                .is_none()
        );
        let debug = format!("{:?}", manifest.records().last().expect("record exists"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("payload.bin"));
    }

    #[test]
    fn path_owners_are_structurally_non_clone() {
        fn preceding_derive<'a>(source: &'a str, declaration: &str) -> &'a str {
            let declaration = source.find(declaration).expect("declaration exists");
            source[..declaration]
                .lines()
                .rev()
                .find(|line| line.starts_with("#[derive("))
                .expect("derive exists")
        }

        let source = include_str!("candidate_manifest.rs");
        assert!(!preceding_derive(source, "enum AuditedPhysicalKind").contains("Clone"));
        assert!(!preceding_derive(source, "struct AuditedPhysicalRecord").contains("Clone"));
        assert!(
            !preceding_derive(source, "pub(super) struct MarkerFreePhysicalManifest")
                .contains("Clone")
        );
    }

    #[test]
    fn exact_revalidation_matches_deep_children_from_borrowed_baseline_paths() {
        let target = minimal_target("borrowed-deep-walk");
        let mut directory = target.path().to_path_buf();
        for depth in 0..64 {
            directory.push(format!("d{depth:02}"));
            fs::create_dir(&directory).expect("deep directory creates");
        }
        fs::write(directory.join("payload.bin"), b"deep payload").expect("deep payload writes");
        let manifest =
            collect_marker_free_physical_manifest(target.path()).expect("deep baseline collects");

        assert_eq!(manifest.directory_count(), 66);
        manifest
            .require_current_exact(target.path())
            .expect("deep baseline revalidates without an owned cumulative path");
        assert_eq!(
            manifest
                .records
                .binary_search_by(|record| {
                    compare_record_path_to_child(&record.path, "d00/d01", "d02")
                })
                .map(|index| manifest.records[index].path.as_str()),
            Ok("d00/d01/d02")
        );
    }

    #[test]
    fn sorted_parent_graph_requires_each_borrowed_prefix_to_be_a_directory() {
        let target = minimal_target("parent-graph");
        fs::write(target.path().join("payload.bin"), b"payload").expect("payload writes");
        let mut manifest =
            collect_marker_free_physical_manifest(target.path()).expect("baseline collects");
        let payload = manifest
            .records
            .iter_mut()
            .find(|record| record.path == "payload.bin")
            .expect("payload record exists");
        payload.path = "missing/payload.bin".to_owned();
        manifest
            .records
            .sort_unstable_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        assert!(matches!(
            require_complete_physical_parent_graph(&manifest.records),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn exact_revalidation_accepts_unchanged_and_rejects_post_baseline_addition() {
        let target = minimal_target("exact-addition");
        fs::write(target.path().join("baseline.bin"), b"baseline").expect("baseline writes");
        let manifest =
            collect_marker_free_physical_manifest(target.path()).expect("baseline collects");
        manifest
            .require_current_exact(target.path())
            .expect("unchanged baseline revalidates");

        fs::write(target.path().join("added.bin"), b"added").expect("addition writes");
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn exact_revalidation_rejects_post_baseline_deletion() {
        let target = minimal_target("exact-deletion");
        let payload = target.path().join("payload.bin");
        fs::write(&payload, b"payload").expect("payload writes");
        let manifest =
            collect_marker_free_physical_manifest(target.path()).expect("baseline collects");

        fs::remove_file(payload).expect("payload removes");
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn exact_revalidation_rejects_kind_symlink_and_hard_link_changes() {
        use std::os::unix::fs::symlink;

        let target = minimal_target("exact-kind-link");
        let outside = TestDirectory::new("exact-kind-link-outside");
        let outside_file = outside.path().join("outside.bin");
        fs::write(&outside_file, b"payload").expect("outside payload writes");
        let payload = target.path().join("payload.bin");
        fs::write(&payload, b"payload").expect("payload writes");
        let manifest =
            collect_marker_free_physical_manifest(target.path()).expect("baseline collects");

        fs::remove_file(&payload).expect("payload removes");
        fs::create_dir(&payload).expect("same-name directory creates");
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));

        fs::remove_dir(&payload).expect("same-name directory removes");
        symlink(&outside_file, &payload).expect("same-name symlink creates");
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));

        fs::remove_file(&payload).expect("same-name symlink removes");
        fs::hard_link(&outside_file, &payload).expect("same-name hard link creates");
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn exact_revalidation_rejects_same_name_inode_replacement() {
        let target = minimal_target("exact-inode");
        let payload = target.path().join("payload.bin");
        fs::write(&payload, b"same body").expect("payload writes");
        let original = fs::File::open(&payload).expect("original remains held");
        let original_identity = filesystem_file_identity(&original).expect("identity captures");
        let manifest =
            collect_marker_free_physical_manifest(target.path()).expect("baseline collects");

        fs::remove_file(&payload).expect("original unlinks");
        fs::write(&payload, b"same body").expect("replacement writes");
        let replacement = fs::File::open(&payload).expect("replacement opens");
        assert_ne!(
            filesystem_file_identity(&replacement).expect("replacement identity captures"),
            original_identity
        );
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn exact_revalidation_rejects_same_inode_body_change() {
        let target = minimal_target("exact-body");
        let payload = target.path().join("payload.bin");
        fs::write(&payload, b"first-body").expect("payload writes");
        let manifest =
            collect_marker_free_physical_manifest(target.path()).expect("baseline collects");
        let before = fs::File::open(&payload).expect("payload opens");
        let before_identity = filesystem_file_identity(&before).expect("identity captures");

        fs::write(&payload, b"other-body").expect("body changes in place");
        let after = fs::File::open(&payload).expect("changed payload opens");
        assert_eq!(
            filesystem_file_identity(&after).expect("changed identity captures"),
            before_identity
        );
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn exact_revalidation_rejects_directory_identity_change() {
        let target = minimal_target("exact-directory");
        let directory = target.path().join("content");
        fs::create_dir(&directory).expect("content directory creates");
        let held = fs::File::open(&directory).expect("original directory remains held");
        let original_identity = filesystem_directory_identity(&directory)
            .expect("original directory identity captures");
        let manifest =
            collect_marker_free_physical_manifest(target.path()).expect("baseline collects");

        fs::remove_dir(&directory).expect("original directory unlinks");
        fs::create_dir(&directory).expect("replacement directory creates");
        assert_ne!(
            filesystem_directory_identity(&directory)
                .expect("replacement directory identity captures"),
            original_identity
        );
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        drop(held);
    }

    #[test]
    fn exact_revalidation_enforces_the_68_mib_file_boundary() {
        let target = minimal_target("exact-file-limit");
        let payload = target.path().join("maximum.bin");
        let file = fs::File::create(&payload).expect("maximum file creates");
        file.set_len(MAX_PHYSICAL_FILE_BYTES)
            .expect("exact maximum sparse file sizes");
        let manifest = collect_marker_free_physical_manifest(target.path())
            .expect("exact maximum baseline collects");

        file.set_len(MAX_PHYSICAL_FILE_BYTES + 1)
            .expect("one-past maximum sparse file sizes");
        assert!(matches!(
            manifest.require_current_exact(target.path()),
            Err(RepositoryImportError::ResourceLimit)
        ));
    }

    #[test]
    fn portable_fingerprints_reject_full_path_and_parent_prefix_aliases() {
        let full = minimal_target("fold-full");
        fs::create_dir(full.path().join("Straße")).expect("first folded directory creates");
        fs::create_dir(full.path().join("STRASSE")).expect("second folded directory creates");
        assert!(matches!(
            collect_marker_free_physical_manifest(full.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));

        let prefix = minimal_target("fold-prefix");
        fs::write(prefix.path().join("Foo"), b"file").expect("folded file creates");
        fs::create_dir(prefix.path().join("foo")).expect("folded parent creates");
        fs::write(prefix.path().join("foo/child"), b"child").expect("folded child creates");
        assert!(matches!(
            collect_marker_free_physical_manifest(prefix.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn reserved_git_and_private_top_level_aliases_fail_closed() {
        for alias in [".GIT", ".VAULT-LOCAL"] {
            let target = minimal_target("reserved-fold-alias");
            fs::create_dir(target.path().join(alias)).expect("reserved alias creates");
            assert!(matches!(
                collect_marker_free_physical_manifest(target.path()),
                Err(RepositoryImportError::TargetAuditFailed)
            ));
        }
    }

    #[test]
    fn injected_fingerprint_collision_fails_closed() {
        let target = minimal_target("fingerprint-collision");
        fs::write(target.path().join("alpha"), b"alpha").expect("alpha writes");
        fs::write(target.path().join("beta"), b"beta").expect("beta writes");
        let result = collect_marker_free_physical_manifest_with_fingerprint(
            target.path(),
            V1_LIMITS,
            |path| {
                if matches!(path, "alpha" | "beta") {
                    raw_portable_case_fold_fingerprint("forced-collision")
                } else {
                    raw_portable_case_fold_fingerprint(path)
                }
            },
        );
        assert!(matches!(
            result,
            Err(RepositoryImportError::TargetAuditFailed)
        ));
    }

    #[test]
    fn every_marker_alias_and_extra_private_entry_fails_without_modification() {
        let target = minimal_target("private-extra");
        let local = target.path().join(VAULT_LOCAL_DIRECTORY);
        for name in [
            IMPORT_PUBLISH_MARKER_V1,
            IMPORT_PUBLISH_MARKER_V2,
            "IMPORT-PUBLISH-MARKER-V2",
            "import-publish-marker-v3",
            "pending-rebind-v1",
            "foreign-private-state",
        ] {
            let path = local.join(name);
            let bytes = format!("sentinel-{name}").into_bytes();
            fs::write(&path, &bytes).expect("private extra writes");
            let error = collect_marker_free_physical_manifest(target.path())
                .expect_err("private extra must fail closed");
            assert!(matches!(error, RepositoryImportError::TargetAuditFailed));
            let debug = format!("{error:?}");
            assert!(!debug.contains(target.path().to_string_lossy().as_ref()));
            assert!(!debug.contains(name));
            assert_eq!(
                fs::read(&path).expect("private extra remains readable"),
                bytes
            );
            fs::remove_file(path).expect("test extra removes");
        }

        let alias = target.path().join(".VAULT-LOCAL");
        fs::create_dir(&alias).expect("private alias creates");
        fs::write(alias.join(VAULT_MUTATION_LOCK_FILE), b"alias sentinel")
            .expect("alias contents write");
        assert!(matches!(
            collect_marker_free_physical_manifest(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert_eq!(
            fs::read(alias.join(VAULT_MUTATION_LOCK_FILE)).expect("alias remains"),
            b"alias sentinel"
        );
    }

    #[test]
    fn lock_must_exist_empty_non_link_and_single_link() {
        use std::os::unix::fs::symlink;

        let target = minimal_target("lock-shape");
        let outside = TestDirectory::new("lock-outside");
        let outside_file = outside.path().join("outside-lock");
        fs::write(&outside_file, []).expect("outside file creates");
        let lock = target
            .path()
            .join(VAULT_LOCAL_DIRECTORY)
            .join(VAULT_MUTATION_LOCK_FILE);

        fs::remove_file(&lock).expect("lock removes");
        assert!(matches!(
            collect_marker_free_physical_manifest(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));

        fs::write(&lock, b"nonempty").expect("nonempty lock writes");
        assert!(matches!(
            collect_marker_free_physical_manifest(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert_eq!(fs::read(&lock).expect("nonempty lock remains"), b"nonempty");

        fs::remove_file(&lock).expect("nonempty lock removes");
        symlink(&outside_file, &lock).expect("lock symlink creates");
        assert!(matches!(
            collect_marker_free_physical_manifest(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert_eq!(
            fs::read(&outside_file).expect("symlink target remains"),
            b""
        );

        fs::remove_file(&lock).expect("lock symlink removes");
        fs::hard_link(&outside_file, &lock).expect("hard-linked lock creates");
        assert!(matches!(
            collect_marker_free_physical_manifest(target.path()),
            Err(RepositoryImportError::TargetAuditFailed)
        ));
        assert_eq!(
            fs::read(&outside_file).expect("hard-link target remains"),
            b""
        );

        fs::remove_file(&lock).expect("hard-linked lock removes");
        fs::write(&lock, []).expect("canonical lock restores");
        collect_marker_free_physical_manifest(target.path())
            .expect("restored canonical lock collects");
    }

    #[test]
    fn injected_limits_accept_exact_boundaries_and_reject_one_less() {
        assert!(matches!(
            advance_owned_path_budget(
                MAX_PHYSICAL_PATH_BUDGET - 1,
                1,
                MAX_PHYSICAL_PATH_BUDGET,
            ),
            Ok(bytes) if bytes == MAX_PHYSICAL_PATH_BUDGET
        ));
        assert!(matches!(
            advance_owned_path_budget(MAX_PHYSICAL_PATH_BUDGET, 1, MAX_PHYSICAL_PATH_BUDGET,),
            Err(RepositoryImportError::ResourceLimit)
        ));
        assert!(matches!(
            advance_owned_path_budget(usize::MAX, 1, usize::MAX),
            Err(RepositoryImportError::ResourceLimit)
        ));
        let mut streamed = 0_u64;
        super::super::advance_bounded_stream_observation(&mut streamed, 1, Some(1))
            .expect("exact streamed byte limit passes");
        assert_eq!(streamed, 1);
        assert!(matches!(
            super::super::advance_bounded_stream_observation(&mut streamed, 1, Some(1)),
            Err(RepositoryImportError::ResourceLimit)
        ));
        assert_eq!(streamed, 1, "failed bounded read is not committed");
        let mut overflow = u64::MAX;
        assert!(matches!(
            super::super::advance_bounded_stream_observation(&mut overflow, 1, None),
            Err(RepositoryImportError::ResourceLimit)
        ));

        let target = minimal_target("small-limits");
        fs::create_dir_all(target.path().join("alpha/beta"))
            .expect("bounded nested directories create");
        fs::write(target.path().join("payload.bin"), [0x5a]).expect("bounded payload writes");
        let manifest = collect_marker_free_physical_manifest(target.path())
            .expect("fixture collects under v1 limits");
        assert_eq!(
            manifest.owned_path_high_water(),
            manifest.retained_path_bytes()
        );
        let exact = exact_observed_limits(&manifest);
        let exact_manifest =
            collect_marker_free_physical_manifest_with_limits(target.path(), exact)
                .expect("all exact observed boundaries pass");
        assert_eq!(exact_manifest.owned_path_high_water(), exact.path_budget);

        assert_resource_limit(&collect_marker_free_physical_manifest_with_limits(
            target.path(),
            PhysicalManifestLimits {
                records: exact.records - 1,
                ..exact
            },
        ));
        assert_resource_limit(&collect_marker_free_physical_manifest_with_limits(
            target.path(),
            PhysicalManifestLimits {
                path_bytes: exact.path_bytes - 1,
                ..exact
            },
        ));
        assert_resource_limit(&collect_marker_free_physical_manifest_with_limits(
            target.path(),
            PhysicalManifestLimits {
                depth: exact.depth - 1,
                ..exact
            },
        ));
        assert_resource_limit(&collect_marker_free_physical_manifest_with_limits(
            target.path(),
            PhysicalManifestLimits {
                path_budget: exact.path_budget - 1,
                ..exact
            },
        ));
        assert_resource_limit(&collect_marker_free_physical_manifest_with_limits(
            target.path(),
            PhysicalManifestLimits {
                file_bytes: exact.file_bytes - 1,
                ..exact
            },
        ));
    }
}
