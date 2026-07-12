use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use inex_core::atomic::{
    AtomicDirectoryPublishError, FilesystemDirectoryIdentity, ParentSyncStatus,
    VAULT_LOCAL_DIRECTORY, VaultMutationGuard, atomic_move_verified_directory_no_replace_checked,
    filesystem_directory_identity, open_file_matches_path_and_is_single_link, sync_directory,
};
use serde::{Deserialize, Serialize};

use super::{
    Git, GitError, GitIoOperation, GitObjectFormat, MAX_GIT_OUTPUT_BYTES, MAX_JOURNAL_BYTES,
    MergeJournalPayload, apply_payload_to_index, ascii_casefold_starts_with, digest,
    ensure_no_journal, exact_reserved_private_names, hex_digest, index_entry_map, index_path,
    io_error, is_link_or_reparse_point, parse_duplicate_free_json, parse_hex_digest, payload_oids,
    payload_rename_provenance, read_index_snapshot, restrict_file_permissions_best_effort,
    sync_regular_file, validate_local_directory, validate_lock_token, validate_oid,
    validate_payload, verify_candidate_index,
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

pub(super) const CANDIDATE_BUNDLE_SCRATCH_PREFIX_V5: &str = "git-index-candidate-scratch-v5-";
pub(super) const CANDIDATE_BUNDLE_STABLE_PREFIX_V5: &str = "git-index-candidate-v4-bundle-v5-";
pub(super) const CANDIDATE_BUNDLE_MANIFEST_V5: &str = "manifest-v5.json";
pub(super) const CANDIDATE_BUNDLE_INDEX_V5: &str = "candidate.index";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateIndexMetadataV5 {
    pub(super) size: u64,
    pub(super) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateBundleMemberMetadataV5 {
    pub(super) basename: String,
    pub(super) size: u64,
    pub(super) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateBundleManifestV5 {
    pub(super) version: u32,
    pub(super) object_format: GitObjectFormat,
    pub(super) token: String,
    pub(super) bundle_basename: String,
    pub(super) old_index: CandidateIndexMetadataV5,
    pub(super) final_index: CandidateIndexMetadataV5,
    pub(super) transaction: MergeJournalPayload,
    pub(super) candidate_member: CandidateBundleMemberMetadataV5,
}

/// Digest reference retained by the outer marker/journal rather than by the
/// manifest itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateBundleManifestReferenceV5 {
    pub(super) size: u64,
    pub(super) sha256: String,
}

/// Filesystem-inventory proof for one immutable v5 candidate bundle.
///
/// This type proves only the canonical manifest, exact member inventory,
/// single-link file identities, and recorded size/digest bindings. It does not
/// validate the candidate Git stage-map, the live expected-old index, or the
/// transaction's Git semantics. Before any mutation, the v5 writer/recovery
/// path must perform those checks in the real repository's Git context.
#[derive(Debug)]
pub(super) struct InventoryVerifiedCandidateBundleV5 {
    pub(super) manifest: CandidateBundleManifestV5,
    pub(super) manifest_reference: CandidateBundleManifestReferenceV5,
    seal: CandidateBundleInventorySealV5,
}

#[derive(Debug)]
struct CandidateBundleInventorySealV5 {
    directory_identity: FilesystemDirectoryIdentity,
    candidate_file: File,
    manifest_file: File,
}

/// Complete stable bundle prepared for the future v5 writer.
///
/// This value proves only the immutable candidate preparation boundary. The
/// future writer must still acquire the real Git index lock, revalidate the
/// live expected-old index and stage map, publish its marker/journal, and
/// advance the worktree. The current v4 production writer does not call this
/// seam.
#[allow(
    dead_code,
    reason = "the v5 preparation seam is intentionally isolated until the next writer slice"
)]
#[derive(Debug)]
pub(super) struct PreparedCandidateBundleV5 {
    pub(super) bundle_basename: String,
    pub(super) inventory: InventoryVerifiedCandidateBundleV5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CandidateBundlePrepareCheckpointV5 {
    ScratchCreated,
    CandidateCopied,
    CandidateMutated,
    ManifestWritten,
    BeforePublish,
    CriticalAudit,
    AfterPublish,
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "fault hooks inspect these paths only in the isolated v5 preparation tests"
)]
pub(super) struct CandidateBundlePrepareContextV5<'a> {
    pub(super) root: &'a Path,
    pub(super) local: &'a Path,
    pub(super) scratch_path: &'a Path,
    pub(super) stable_path: &'a Path,
    pub(super) candidate_path: &'a Path,
    pub(super) manifest_path: &'a Path,
}

pub(super) trait CandidateBundlePrepareHooksV5 {
    fn next_token(&mut self) -> String;

    fn checkpoint(
        &mut self,
        _checkpoint: CandidateBundlePrepareCheckpointV5,
        _context: &CandidateBundlePrepareContextV5<'_>,
    ) -> Result<(), GitError> {
        Ok(())
    }
}

struct ProductionCandidateBundlePrepareHooksV5;

impl CandidateBundlePrepareHooksV5 for ProductionCandidateBundlePrepareHooksV5 {
    fn next_token(&mut self) -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct CandidateBundleNamespaceStatusV5 {
    pub(super) stable_bundle_basename: Option<String>,
    pub(super) retained_scratch_count: usize,
}

fn exact_token_basename(prefix: &str, token: &str) -> Result<String, GitError> {
    validate_lock_token(token)?;
    Ok(format!("{prefix}{token}"))
}

pub(super) fn candidate_bundle_scratch_basename_v5(token: &str) -> Result<String, GitError> {
    exact_token_basename(CANDIDATE_BUNDLE_SCRATCH_PREFIX_V5, token)
}

pub(super) fn candidate_bundle_stable_basename_v5(token: &str) -> Result<String, GitError> {
    exact_token_basename(CANDIDATE_BUNDLE_STABLE_PREFIX_V5, token)
}

fn parse_candidate_bundle_scratch_basename_v5(basename: &str) -> Result<&str, GitError> {
    let token = basename
        .strip_prefix(CANDIDATE_BUNDLE_SCRATCH_PREFIX_V5)
        .ok_or(GitError::InvalidJournal)?;
    validate_lock_token(token)?;
    if basename != candidate_bundle_scratch_basename_v5(token)? {
        return Err(GitError::InvalidJournal);
    }
    Ok(token)
}

fn parse_candidate_bundle_stable_basename_v5(basename: &str) -> Result<&str, GitError> {
    let token = basename
        .strip_prefix(CANDIDATE_BUNDLE_STABLE_PREFIX_V5)
        .ok_or(GitError::InvalidJournal)?;
    validate_lock_token(token)?;
    if basename != candidate_bundle_stable_basename_v5(token)? {
        return Err(GitError::InvalidJournal);
    }
    Ok(token)
}

pub(super) fn candidate_bundle_stable_path_v5(
    root: &Path,
    bundle_basename: &str,
) -> Result<PathBuf, GitError> {
    parse_candidate_bundle_stable_basename_v5(bundle_basename)?;
    Ok(root.join(VAULT_LOCAL_DIRECTORY).join(bundle_basename))
}

pub(super) fn candidate_bundle_scratch_path_v5(
    root: &Path,
    scratch_basename: &str,
) -> Result<PathBuf, GitError> {
    parse_candidate_bundle_scratch_basename_v5(scratch_basename)?;
    Ok(root.join(VAULT_LOCAL_DIRECTORY).join(scratch_basename))
}

fn validate_index_metadata(metadata: &CandidateIndexMetadataV5) -> Result<(), GitError> {
    parse_hex_digest(&metadata.sha256)?;
    if metadata.size == 0 || metadata.size > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    Ok(())
}

fn validate_transaction_object_format(
    object_format: GitObjectFormat,
    transaction: &MergeJournalPayload,
) -> Result<(), GitError> {
    validate_payload(transaction)?;
    let oid_width = object_format.oid_hex_len();
    if payload_oids(transaction)
        .iter()
        .any(|oid| oid.len() != oid_width)
    {
        return Err(GitError::InvalidJournal);
    }
    if let Some(provenance) = payload_rename_provenance(transaction) {
        if provenance.object_format != object_format {
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

pub(super) fn validate_candidate_bundle_manifest_v5(
    manifest: &CandidateBundleManifestV5,
) -> Result<(), GitError> {
    if manifest.version != 5 {
        return Err(GitError::InvalidJournal);
    }
    let token = parse_candidate_bundle_stable_basename_v5(&manifest.bundle_basename)?;
    validate_lock_token(&manifest.token)?;
    if token != manifest.token {
        return Err(GitError::InvalidJournal);
    }
    validate_index_metadata(&manifest.old_index)?;
    validate_index_metadata(&manifest.final_index)?;
    if manifest.old_index.sha256 == manifest.final_index.sha256 {
        return Err(GitError::InvalidJournal);
    }
    if manifest.candidate_member.basename != CANDIDATE_BUNDLE_INDEX_V5
        || manifest.candidate_member.size != manifest.final_index.size
        || manifest.candidate_member.sha256 != manifest.final_index.sha256
    {
        return Err(GitError::InvalidJournal);
    }
    parse_hex_digest(&manifest.candidate_member.sha256)?;
    validate_transaction_object_format(manifest.object_format, &manifest.transaction)
}

pub(super) fn serialize_candidate_bundle_manifest_v5(
    manifest: &CandidateBundleManifestV5,
) -> Result<Vec<u8>, GitError> {
    validate_candidate_bundle_manifest_v5(manifest)?;
    let bytes = serde_json::to_vec(manifest).map_err(|_| GitError::InvalidJournal)?;
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return Err(GitError::InvalidJournal);
    }
    Ok(bytes)
}

pub(super) fn parse_candidate_bundle_manifest_v5(
    bytes: &[u8],
) -> Result<CandidateBundleManifestV5, GitError> {
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return Err(GitError::InvalidJournal);
    }
    let value = parse_duplicate_free_json(bytes)?;
    let manifest = serde_json::from_value::<CandidateBundleManifestV5>(value)
        .map_err(|_| GitError::InvalidJournal)?;
    validate_candidate_bundle_manifest_v5(&manifest)?;
    if serialize_candidate_bundle_manifest_v5(&manifest)? != bytes {
        return Err(GitError::InvalidJournal);
    }
    Ok(manifest)
}

pub(super) fn manifest_reference_v5(bytes: &[u8]) -> CandidateBundleManifestReferenceV5 {
    CandidateBundleManifestReferenceV5 {
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        sha256: hex_digest(digest(bytes)),
    }
}

pub(super) fn validate_manifest_reference_v5(
    reference: &CandidateBundleManifestReferenceV5,
) -> Result<(), GitError> {
    parse_hex_digest(&reference.sha256)?;
    if reference.size == 0 || reference.size > u64::try_from(MAX_JOURNAL_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    Ok(())
}

fn read_single_link_regular(
    path: &Path,
    maximum: usize,
    allow_empty: bool,
) -> Result<(Vec<u8>, File), GitError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GitError::InvalidJournal
        } else {
            io_error(GitIoOperation::InspectMetadata, &error)
        }
    })?;
    if is_link_or_reparse_point(&metadata)
        || !metadata.file_type().is_file()
        || (!allow_empty && metadata.len() == 0)
        || metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
    {
        return Err(GitError::InvalidJournal);
    }
    let mut file =
        File::open(path).map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Err(GitError::InvalidJournal);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    (&mut file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if bytes.len() > maximum
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len()
        || !open_file_matches_path_and_is_single_link(path, &file)
            .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Err(GitError::InvalidJournal);
    }
    Ok((bytes, file))
}

fn exact_bundle_members(path: &Path) -> Result<BTreeSet<String>, GitError> {
    let mut names = BTreeSet::new();
    let entries =
        fs::read_dir(path).map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GitError::InvalidJournal)?;
        if !names.insert(name) {
            return Err(GitError::InvalidJournal);
        }
    }
    let expected = BTreeSet::from([
        CANDIDATE_BUNDLE_INDEX_V5.to_owned(),
        CANDIDATE_BUNDLE_MANIFEST_V5.to_owned(),
    ]);
    if names != expected {
        return Err(GitError::InvalidJournal);
    }
    Ok(names)
}

/// Verifies only immutable bundle schema, member identity, and byte bindings.
///
/// This is not a Git-semantic authorization check. Callers must separately
/// validate the candidate stage-map, live expected-old index, and transaction
/// semantics in the real Git repository before performing any mutation.
fn validate_candidate_bundle_inventory_at_path_v5(
    bundle_path: &Path,
    expected_bundle_basename: &str,
    expected_manifest_reference: Option<&CandidateBundleManifestReferenceV5>,
) -> Result<InventoryVerifiedCandidateBundleV5, GitError> {
    let token = parse_candidate_bundle_stable_basename_v5(expected_bundle_basename)?;
    let directory_identity =
        filesystem_directory_identity(bundle_path).map_err(|_| GitError::InvalidJournal)?;
    exact_bundle_members(bundle_path)?;

    let manifest_path = bundle_path.join(CANDIDATE_BUNDLE_MANIFEST_V5);
    let (manifest_bytes, manifest_file) =
        read_single_link_regular(&manifest_path, MAX_JOURNAL_BYTES, false)?;
    let manifest = parse_candidate_bundle_manifest_v5(&manifest_bytes)?;
    if manifest.token != token || manifest.bundle_basename != expected_bundle_basename {
        return Err(GitError::InvalidJournal);
    }
    let manifest_reference = manifest_reference_v5(&manifest_bytes);
    validate_manifest_reference_v5(&manifest_reference)?;
    if expected_manifest_reference.is_some_and(|expected| {
        validate_manifest_reference_v5(expected).is_err() || expected != &manifest_reference
    }) {
        return Err(GitError::RecoveryConflict);
    }

    let candidate_path = bundle_path.join(CANDIDATE_BUNDLE_INDEX_V5);
    let (candidate_bytes, candidate_file) =
        read_single_link_regular(&candidate_path, MAX_GIT_OUTPUT_BYTES, false)?;
    if u64::try_from(candidate_bytes.len()).unwrap_or(u64::MAX) != manifest.candidate_member.size
        || hex_digest(digest(&candidate_bytes)) != manifest.candidate_member.sha256
    {
        return Err(GitError::InvalidJournal);
    }

    if filesystem_directory_identity(bundle_path).map_err(|_| GitError::InvalidJournal)?
        != directory_identity
    {
        return Err(GitError::RecoveryConflict);
    }
    exact_bundle_members(bundle_path)?;
    Ok(InventoryVerifiedCandidateBundleV5 {
        manifest,
        manifest_reference,
        seal: CandidateBundleInventorySealV5 {
            directory_identity,
            candidate_file,
            manifest_file,
        },
    })
}

fn held_inventory_matches_path_v5(
    bundle_path: &Path,
    expected_bundle_basename: &str,
    expected: &InventoryVerifiedCandidateBundleV5,
) -> Result<(), GitError> {
    if filesystem_directory_identity(bundle_path).map_err(|_| GitError::RecoveryConflict)?
        != expected.seal.directory_identity
    {
        return Err(GitError::RecoveryConflict);
    }
    exact_bundle_members(bundle_path)?;
    let candidate_path = bundle_path.join(CANDIDATE_BUNDLE_INDEX_V5);
    let manifest_path = bundle_path.join(CANDIDATE_BUNDLE_MANIFEST_V5);
    if !open_file_matches_path_and_is_single_link(&candidate_path, &expected.seal.candidate_file)
        .map_err(|_| GitError::RecoveryConflict)?
        || !open_file_matches_path_and_is_single_link(&manifest_path, &expected.seal.manifest_file)
            .map_err(|_| GitError::RecoveryConflict)?
    {
        return Err(GitError::RecoveryConflict);
    }
    let current = validate_candidate_bundle_inventory_at_path_v5(
        bundle_path,
        expected_bundle_basename,
        Some(&expected.manifest_reference),
    )?;
    if current.manifest != expected.manifest
        || current.manifest_reference != expected.manifest_reference
        || current.seal.directory_identity != expected.seal.directory_identity
        || !open_file_matches_path_and_is_single_link(
            &candidate_path,
            &expected.seal.candidate_file,
        )
        .map_err(|_| GitError::RecoveryConflict)?
        || !open_file_matches_path_and_is_single_link(&manifest_path, &expected.seal.manifest_file)
            .map_err(|_| GitError::RecoveryConflict)?
    {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

pub(super) fn validate_candidate_bundle_inventory_v5(
    root: &Path,
    bundle_basename: &str,
    expected_manifest_reference: Option<&CandidateBundleManifestReferenceV5>,
) -> Result<InventoryVerifiedCandidateBundleV5, GitError> {
    let bundle_path = candidate_bundle_stable_path_v5(root, bundle_basename)?;
    validate_candidate_bundle_inventory_at_path_v5(
        &bundle_path,
        bundle_basename,
        expected_manifest_reference,
    )
}

const MAX_SCRATCH_TOKEN_ATTEMPTS_V5: usize = 64;

fn exact_child_name_is_unique(parent: &Path, expected: &str) -> Result<bool, GitError> {
    let mut exact_count = 0_usize;
    let entries =
        fs::read_dir(parent).map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
        let name = entry.file_name();
        if name == expected {
            exact_count = exact_count.saturating_add(1);
            continue;
        }
        if name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
        {
            return Ok(false);
        }
    }
    Ok(exact_count == 1)
}

fn create_private_scratch_directory_v5<H: CandidateBundlePrepareHooksV5>(
    local: &Path,
    hooks: &mut H,
) -> Result<(String, String, PathBuf), GitError> {
    let parent_identity =
        filesystem_directory_identity(local).map_err(|_| GitError::DurabilityNotConfirmed)?;
    for _ in 0..MAX_SCRATCH_TOKEN_ATTEMPTS_V5 {
        let token = hooks.next_token();
        let scratch_basename = candidate_bundle_scratch_basename_v5(&token)?;
        let scratch_path = local.join(&scratch_basename);
        #[cfg(unix)]
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        match builder.create(&scratch_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(GitIoOperation::WriteJournal, &error)),
        }
        #[cfg(unix)]
        {
            fs::set_permissions(&scratch_path, fs::Permissions::from_mode(0o700))
                .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
            let mode = fs::symlink_metadata(&scratch_path)
                .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o700 {
                return Err(GitError::DurabilityNotConfirmed);
            }
        }
        validate_local_directory(&scratch_path)?;
        if filesystem_directory_identity(local).map_err(|_| GitError::DurabilityNotConfirmed)?
            != parent_identity
            || !exact_child_name_is_unique(local, &scratch_basename)?
        {
            return Err(GitError::RecoveryConflict);
        }
        sync_directory(local).map_err(|_| GitError::DurabilityNotConfirmed)?;
        return Ok((token, scratch_basename, scratch_path));
    }
    Err(GitError::RecoveryConflict)
}

fn map_directory_publish_error_v5(error: &AtomicDirectoryPublishError) -> GitError {
    match error {
        AtomicDirectoryPublishError::DestinationExists
        | AtomicDirectoryPublishError::Indeterminate => GitError::RecoveryConflict,
        AtomicDirectoryPublishError::InvalidPaths
        | AtomicDirectoryPublishError::NotMoved
        | AtomicDirectoryPublishError::PublishedCleanupFailed
        | AtomicDirectoryPublishError::Io { .. } => GitError::DurabilityNotConfirmed,
    }
}

fn checkpoint_as_io_v5<H: CandidateBundlePrepareHooksV5>(
    hooks: &mut H,
    checkpoint: CandidateBundlePrepareCheckpointV5,
    context: &CandidateBundlePrepareContextV5<'_>,
) -> io::Result<()> {
    hooks
        .checkpoint(checkpoint, context)
        .map_err(|_| io::Error::other("candidate bundle preparation checkpoint failed"))
}

fn create_private_file_retaining_v5(path: &Path, bytes: &[u8]) -> Result<File, GitError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
    restrict_file_permissions_best_effort(&file);
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
    Ok(file)
}

/// Prepare and publish one immutable v5 candidate bundle without touching the
/// real Git index lock, journal, worktree, or the current v4 writer path.
///
/// Once scratch creation succeeds, every subsequent failure deliberately
/// retains that exact partial scratch directory (or an already published
/// stable bundle) for later inspection. The caller must not infer transaction
/// ownership from an unpublished scratch entry. A future writer must still
/// acquire and bind the real Git index lock before it may authorize any
/// repository mutation. The inventory proof covers named directory entries
/// and each file's unnamed data stream; native NTFS ADS enumeration and
/// abrupt-power-loss evidence remain separate release gates.
#[allow(
    dead_code,
    reason = "the v5 preparation seam is intentionally isolated until the next writer slice"
)]
pub(super) fn prepare_candidate_bundle_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    transaction: &MergeJournalPayload,
) -> Result<PreparedCandidateBundleV5, GitError> {
    let mut hooks = ProductionCandidateBundlePrepareHooksV5;
    prepare_candidate_bundle_v5_impl(guard, git, transaction, &mut hooks)
}

#[cfg(test)]
pub(super) fn prepare_candidate_bundle_v5_with_hooks<H: CandidateBundlePrepareHooksV5>(
    guard: &VaultMutationGuard,
    git: &Git,
    transaction: &MergeJournalPayload,
    hooks: &mut H,
) -> Result<PreparedCandidateBundleV5, GitError> {
    prepare_candidate_bundle_v5_impl(guard, git, transaction, hooks)
}

#[allow(clippy::too_many_lines)]
fn prepare_candidate_bundle_v5_impl<H: CandidateBundlePrepareHooksV5>(
    guard: &VaultMutationGuard,
    git: &Git,
    transaction: &MergeJournalPayload,
    hooks: &mut H,
) -> Result<PreparedCandidateBundleV5, GitError> {
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    validate_payload(transaction)?;
    ensure_no_journal(&git.root)?;
    git.ensure_full_index()?;
    let local = git.root.join(VAULT_LOCAL_DIRECTORY);
    validate_local_directory(&local)?;
    let namespace = inspect_candidate_bundle_namespace_v5(&git.root)?;
    if namespace.stable_bundle_basename.is_some()
        || !exact_reserved_private_names(&git.root)?.is_empty()
    {
        return Err(GitError::RecoveryConflict);
    }

    let old = read_index_snapshot(&index_path(&git.root))?;
    let live_before = index_entry_map(git)?;
    let (token, _scratch_basename, scratch_path) =
        create_private_scratch_directory_v5(&local, hooks)?;
    let stable_basename = candidate_bundle_stable_basename_v5(&token)?;
    let stable_path = candidate_bundle_stable_path_v5(&git.root, &stable_basename)?;
    let candidate_path = scratch_path.join(CANDIDATE_BUNDLE_INDEX_V5);
    let manifest_path = scratch_path.join(CANDIDATE_BUNDLE_MANIFEST_V5);
    let context = CandidateBundlePrepareContextV5 {
        root: &git.root,
        local: &local,
        scratch_path: &scratch_path,
        stable_path: &stable_path,
        candidate_path: &candidate_path,
        manifest_path: &manifest_path,
    };
    hooks.checkpoint(CandidateBundlePrepareCheckpointV5::ScratchCreated, &context)?;

    let candidate_file = create_private_file_retaining_v5(&candidate_path, &old.bytes)?;
    drop(candidate_file);
    let copied = read_index_snapshot(&candidate_path)?;
    if copied.size != old.size || copied.sha256 != old.sha256 {
        return Err(GitError::IndexChanged);
    }
    hooks.checkpoint(
        CandidateBundlePrepareCheckpointV5::CandidateCopied,
        &context,
    )?;

    let candidate_git = git.with_index_file(candidate_path.clone())?;
    let candidate_before = index_entry_map(&candidate_git)?;
    if candidate_before != live_before {
        return Err(GitError::IndexChanged);
    }
    apply_payload_to_index(&candidate_git, transaction)?;
    verify_candidate_index(&candidate_git, transaction, &candidate_before)?;
    let final_index = read_index_snapshot(&candidate_path)?;
    if final_index.sha256 == old.sha256 {
        return Err(GitError::IndexChanged);
    }
    hooks.checkpoint(
        CandidateBundlePrepareCheckpointV5::CandidateMutated,
        &context,
    )?;

    let final_metadata = CandidateIndexMetadataV5 {
        size: final_index.size,
        sha256: final_index.sha256.clone(),
    };
    let manifest = CandidateBundleManifestV5 {
        version: 5,
        object_format: git.object_format,
        token,
        bundle_basename: stable_basename.clone(),
        old_index: CandidateIndexMetadataV5 {
            size: old.size,
            sha256: old.sha256.clone(),
        },
        final_index: final_metadata.clone(),
        transaction: transaction.clone(),
        candidate_member: CandidateBundleMemberMetadataV5 {
            basename: CANDIDATE_BUNDLE_INDEX_V5.to_owned(),
            size: final_metadata.size,
            sha256: final_metadata.sha256.clone(),
        },
    };
    let manifest_bytes = serialize_candidate_bundle_manifest_v5(&manifest)?;
    let manifest_reference = manifest_reference_v5(&manifest_bytes);
    let manifest_file = create_private_file_retaining_v5(&manifest_path, &manifest_bytes)?;
    drop(manifest_file);
    hooks.checkpoint(
        CandidateBundlePrepareCheckpointV5::ManifestWritten,
        &context,
    )?;

    sync_regular_file(&candidate_path, MAX_GIT_OUTPUT_BYTES)?;
    sync_regular_file(&manifest_path, MAX_JOURNAL_BYTES)?;
    sync_directory(&scratch_path).map_err(|_| GitError::DurabilityNotConfirmed)?;
    sync_directory(&local).map_err(|_| GitError::DurabilityNotConfirmed)?;
    let live_final = read_index_snapshot(&index_path(&git.root))?;
    if live_final.size != old.size
        || live_final.sha256 != old.sha256
        || index_entry_map(git)? != live_before
    {
        return Err(GitError::IndexChanged);
    }
    verify_candidate_index(&candidate_git, transaction, &candidate_before)?;
    let sealed_scratch = validate_candidate_bundle_inventory_at_path_v5(
        &scratch_path,
        &stable_basename,
        Some(&manifest_reference),
    )?;
    if sealed_scratch.manifest != manifest {
        return Err(GitError::RecoveryConflict);
    }
    hooks.checkpoint(CandidateBundlePrepareCheckpointV5::BeforePublish, &context)?;

    let outcome =
        atomic_move_verified_directory_no_replace_checked(&scratch_path, &stable_path, |current| {
            if current != scratch_path {
                return Err(io::Error::other(
                    "candidate bundle audit received a different source path",
                ));
            }
            if !guard.is_for_root(&git.root) {
                return Err(io::Error::other(
                    "vault mutation guard no longer binds the Git root",
                ));
            }
            checkpoint_as_io_v5(
                hooks,
                CandidateBundlePrepareCheckpointV5::CriticalAudit,
                &context,
            )?;
            let namespace = inspect_candidate_bundle_namespace_v5(&git.root)
                .map_err(|_| io::Error::other("candidate namespace could not be rebound"))?;
            if namespace.stable_bundle_basename.is_some()
                || !exact_reserved_private_names(&git.root)
                    .map_err(|_| io::Error::other("legacy candidate namespace changed"))?
                    .is_empty()
            {
                return Err(io::Error::other(
                    "candidate namespace changed before publication",
                ));
            }
            held_inventory_matches_path_v5(current, &stable_basename, &sealed_scratch)
                .map_err(|_| io::Error::other("candidate bundle critical audit failed"))?;
            let live = read_index_snapshot(&index_path(&git.root))
                .map_err(|_| io::Error::other("live Git index could not be rebound"))?;
            if live.size != old.size
                || live.sha256 != old.sha256
                || index_entry_map(git)
                    .map_err(|_| io::Error::other("live Git stage map could not be rebound"))?
                    != live_before
            {
                return Err(io::Error::other(
                    "live Git index changed before candidate publication",
                ));
            }
            verify_candidate_index(&candidate_git, transaction, &candidate_before)
                .map_err(|_| io::Error::other("candidate Git stage map changed"))
        })
        .map_err(|error| map_directory_publish_error_v5(&error))?;
    hooks.checkpoint(CandidateBundlePrepareCheckpointV5::AfterPublish, &context)?;
    if outcome.parent_sync != ParentSyncStatus::Synced {
        return Err(GitError::DurabilityNotConfirmed);
    }
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    held_inventory_matches_path_v5(&stable_path, &stable_basename, &sealed_scratch)?;
    let namespace = inspect_candidate_bundle_namespace_v5(&git.root)?;
    if namespace.stable_bundle_basename.as_deref() != Some(stable_basename.as_str()) {
        return Err(GitError::RecoveryConflict);
    }
    let live_after = read_index_snapshot(&index_path(&git.root))?;
    if live_after.size != old.size
        || live_after.sha256 != old.sha256
        || index_entry_map(git)? != live_before
    {
        return Err(GitError::IndexChanged);
    }
    let stable_candidate_git = git.with_index_file(stable_path.join(CANDIDATE_BUNDLE_INDEX_V5))?;
    verify_candidate_index(&stable_candidate_git, transaction, &candidate_before)?;
    let stable_inventory = validate_candidate_bundle_inventory_v5(
        &git.root,
        &stable_basename,
        Some(&manifest_reference),
    )?;
    if stable_inventory.manifest != manifest
        || stable_inventory.manifest_reference != manifest_reference
        || stable_inventory.seal.directory_identity != sealed_scratch.seal.directory_identity
    {
        return Err(GitError::RecoveryConflict);
    }
    held_inventory_matches_path_v5(&stable_path, &stable_basename, &sealed_scratch)?;
    Ok(PreparedCandidateBundleV5 {
        bundle_basename: stable_basename,
        inventory: sealed_scratch,
    })
}

#[allow(
    dead_code,
    reason = "the v5 preparation seam is intentionally isolated until the next writer slice"
)]
pub(super) fn revalidate_prepared_candidate_bundle_v5(
    root: &Path,
    prepared: &PreparedCandidateBundleV5,
) -> Result<(), GitError> {
    let stable_path = candidate_bundle_stable_path_v5(root, &prepared.bundle_basename)?;
    held_inventory_matches_path_v5(&stable_path, &prepared.bundle_basename, &prepared.inventory)
}

pub(super) fn inspect_candidate_bundle_namespace_v5(
    root: &Path,
) -> Result<CandidateBundleNamespaceStatusV5, GitError> {
    let local = root.join(VAULT_LOCAL_DIRECTORY);
    let entries =
        fs::read_dir(&local).map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
    let mut retained_scratch_count = 0_usize;
    let mut stable_bundle_basenames = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GitError::RecoveryConflict)?;
        if ascii_casefold_starts_with(&name, CANDIDATE_BUNDLE_SCRATCH_PREFIX_V5) {
            if !name.starts_with(CANDIDATE_BUNDLE_SCRATCH_PREFIX_V5) {
                return Err(GitError::RecoveryConflict);
            }
            candidate_bundle_scratch_path_v5(root, &name)
                .map_err(|_| GitError::RecoveryConflict)?;
            retained_scratch_count = retained_scratch_count.saturating_add(1);
        }
        if ascii_casefold_starts_with(&name, CANDIDATE_BUNDLE_STABLE_PREFIX_V5) {
            if !name.starts_with(CANDIDATE_BUNDLE_STABLE_PREFIX_V5) {
                return Err(GitError::RecoveryConflict);
            }
            parse_candidate_bundle_stable_basename_v5(&name)
                .map_err(|_| GitError::RecoveryConflict)?;
            stable_bundle_basenames.push(name);
        }
    }
    if stable_bundle_basenames.len() > 1 {
        return Err(GitError::RecoveryConflict);
    }
    if let Some(basename) = stable_bundle_basenames.first() {
        let verified = validate_candidate_bundle_inventory_v5(root, basename, None)?;
        if verified.manifest.bundle_basename != *basename || verified.manifest_reference.size == 0 {
            return Err(GitError::RecoveryConflict);
        }
    }
    Ok(CandidateBundleNamespaceStatusV5 {
        stable_bundle_basename: stable_bundle_basenames.pop(),
        retained_scratch_count,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{
        JOURNAL_FILE, MergeJournal, StageEntry, exact_reserved_private_names, has_pending_recovery,
        recovery_status,
    };

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let root = std::env::temp_dir().join(format!(
                "inex-git-bundle-v5-test-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir_all(root.join(VAULT_LOCAL_DIRECTORY))
                .expect("private test directory creates");
            Self(root)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn local(&self) -> PathBuf {
            self.0.join(VAULT_LOCAL_DIRECTORY)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        hex_digest(digest(bytes))
    }

    fn transaction(object_format: GitObjectFormat) -> MergeJournalPayload {
        let width = object_format.oid_hex_len();
        MergeJournalPayload::InPlace(MergeJournal {
            version: 1,
            physical_path: "entry.md.enc".to_owned(),
            result_mode: "100644".to_owned(),
            stages: [
                Some(StageEntry {
                    mode: "100644".to_owned(),
                    oid: "a".repeat(width),
                }),
                Some(StageEntry {
                    mode: "100644".to_owned(),
                    oid: "b".repeat(width),
                }),
                Some(StageEntry {
                    mode: "100644".to_owned(),
                    oid: "c".repeat(width),
                }),
            ],
            expected_worktree_sha256: sha256(b"expected worktree"),
            result_oid: "d".repeat(width),
            result_sha256: sha256(b"result ciphertext"),
        })
    }

    fn manifest(
        token: &str,
        object_format: GitObjectFormat,
        candidate: &[u8],
    ) -> CandidateBundleManifestV5 {
        let bundle_basename =
            candidate_bundle_stable_basename_v5(token).expect("test token validates");
        CandidateBundleManifestV5 {
            version: 5,
            object_format,
            token: token.to_owned(),
            bundle_basename,
            old_index: CandidateIndexMetadataV5 {
                size: 9,
                sha256: sha256(b"old index"),
            },
            final_index: CandidateIndexMetadataV5 {
                size: u64::try_from(candidate.len()).expect("candidate length fits"),
                sha256: sha256(candidate),
            },
            transaction: transaction(object_format),
            candidate_member: CandidateBundleMemberMetadataV5 {
                basename: CANDIDATE_BUNDLE_INDEX_V5.to_owned(),
                size: u64::try_from(candidate.len()).expect("candidate length fits"),
                sha256: sha256(candidate),
            },
        }
    }

    fn install_bundle(
        root: &TestRoot,
        token: &str,
    ) -> (
        String,
        CandidateBundleManifestV5,
        CandidateBundleManifestReferenceV5,
    ) {
        let candidate = b"DIRC immutable candidate index v5";
        let manifest = manifest(token, GitObjectFormat::Sha1, candidate);
        let manifest_bytes =
            serialize_candidate_bundle_manifest_v5(&manifest).expect("manifest serializes");
        let reference = manifest_reference_v5(&manifest_bytes);
        let basename = manifest.bundle_basename.clone();
        let bundle = root.local().join(&basename);
        fs::create_dir(&bundle).expect("stable bundle directory creates");
        fs::write(bundle.join(CANDIDATE_BUNDLE_INDEX_V5), candidate)
            .expect("candidate member writes");
        fs::write(bundle.join(CANDIDATE_BUNDLE_MANIFEST_V5), manifest_bytes)
            .expect("manifest member writes");
        (basename, manifest, reference)
    }

    #[test]
    fn v5_manifest_round_trips_only_as_exact_canonical_duplicate_free_json() {
        let candidate = b"canonical candidate";
        let manifest = manifest(TOKEN, GitObjectFormat::Sha1, candidate);
        let bytes =
            serialize_candidate_bundle_manifest_v5(&manifest).expect("canonical manifest emits");
        assert_eq!(
            parse_candidate_bundle_manifest_v5(&bytes).expect("canonical manifest parses"),
            manifest
        );
        let text = std::str::from_utf8(&bytes).expect("manifest is UTF-8");
        let duplicate = text.replacen("\"version\":5", "\"version\":5,\"version\":5", 1);
        assert!(parse_candidate_bundle_manifest_v5(duplicate.as_bytes()).is_err());
        let mut whitespace = bytes.clone();
        whitespace.push(b'\n');
        assert!(parse_candidate_bundle_manifest_v5(&whitespace).is_err());

        let mut unknown: serde_json::Value =
            serde_json::from_slice(&bytes).expect("manifest value parses");
        unknown
            .as_object_mut()
            .expect("manifest is an object")
            .insert(
                "manifest_sha256".to_owned(),
                serde_json::Value::String(sha256(&bytes)),
            );
        assert!(
            parse_candidate_bundle_manifest_v5(
                &serde_json::to_vec(&unknown).expect("unknown fixture emits")
            )
            .is_err()
        );
    }

    #[test]
    fn v5_manifest_rejects_noncanonical_names_metadata_and_object_format() {
        let candidate = b"candidate metadata";
        let canonical = manifest(TOKEN, GitObjectFormat::Sha1, candidate);
        for invalid in [
            {
                let mut value = canonical.clone();
                value.version = 4;
                value
            },
            {
                let mut value = canonical.clone();
                value.token = value.token.to_uppercase();
                value
            },
            {
                let mut value = canonical.clone();
                value.bundle_basename.push_str(".extra");
                value
            },
            {
                let mut value = canonical.clone();
                value.candidate_member.basename = "Candidate.index".to_owned();
                value
            },
            {
                let mut value = canonical.clone();
                value.candidate_member.size = value.candidate_member.size.saturating_add(1);
                value
            },
            {
                let mut value = canonical.clone();
                value.final_index = value.old_index.clone();
                value.candidate_member.size = value.final_index.size;
                value.candidate_member.sha256 = value.final_index.sha256.clone();
                value
            },
            {
                let mut value = canonical.clone();
                value.final_index.sha256 = value.old_index.sha256.clone();
                value.candidate_member.sha256 = value.final_index.sha256.clone();
                value
            },
            {
                let mut value = canonical.clone();
                value.object_format = GitObjectFormat::Sha256;
                value
            },
        ] {
            assert!(validate_candidate_bundle_manifest_v5(&invalid).is_err());
        }
    }

    #[test]
    fn v5_bundle_names_and_paths_are_exact_and_downgrade_visible() {
        let root = TestRoot::new();
        let stable = candidate_bundle_stable_basename_v5(TOKEN).expect("stable basename builds");
        let scratch = candidate_bundle_scratch_basename_v5(TOKEN).expect("scratch basename builds");
        assert_eq!(
            candidate_bundle_stable_path_v5(root.path(), &stable).expect("stable path validates"),
            root.local().join(&stable)
        );
        assert_eq!(
            candidate_bundle_scratch_path_v5(root.path(), &scratch)
                .expect("scratch path validates"),
            root.local().join(&scratch)
        );
        assert!(stable.starts_with(crate::INDEX_CANDIDATE_PREFIX));
        assert!(candidate_bundle_stable_basename_v5(&TOKEN.to_uppercase()).is_err());
        assert!(candidate_bundle_scratch_basename_v5("../candidate").is_err());
        assert!(candidate_bundle_stable_path_v5(root.path(), &scratch).is_err());
        assert!(candidate_bundle_scratch_path_v5(root.path(), &stable).is_err());

        let (installed, _, _) = install_bundle(&root, TOKEN);
        assert_eq!(installed, stable);
        assert!(
            exact_reserved_private_names(root.path())
                .expect("v4 namespace scanner succeeds")
                .contains(&stable),
            "the stable v5 basename must remain visible to the v4 scanner"
        );
    }

    #[test]
    fn exact_bundle_inventory_binds_members_candidate_and_outer_manifest_reference() {
        let root = TestRoot::new();
        let (basename, manifest, reference) = install_bundle(&root, TOKEN);
        let verified =
            validate_candidate_bundle_inventory_v5(root.path(), &basename, Some(&reference))
                .expect("exact bundle validates");
        assert_eq!(verified.manifest, manifest);
        assert_eq!(verified.manifest_reference, reference);

        let wrong_reference = CandidateBundleManifestReferenceV5 {
            size: reference.size,
            sha256: sha256(b"different manifest"),
        };
        assert!(
            validate_candidate_bundle_inventory_v5(root.path(), &basename, Some(&wrong_reference))
                .is_err()
        );
        fs::write(
            root.local().join(&basename).join(CANDIDATE_BUNDLE_INDEX_V5),
            b"same-size digest mutation candidate",
        )
        .expect("candidate tampers");
        assert!(validate_candidate_bundle_inventory_v5(root.path(), &basename, None).is_err());
    }

    #[test]
    fn exact_bundle_inventory_rejects_missing_extra_wrong_case_and_nonfile_members() {
        for variant in ["missing", "extra", "wrong-case", "directory"] {
            let root = TestRoot::new();
            let (basename, _, _) = install_bundle(&root, TOKEN);
            let bundle = root.local().join(&basename);
            match variant {
                "missing" => fs::remove_file(bundle.join(CANDIDATE_BUNDLE_INDEX_V5))
                    .expect("candidate removes"),
                "extra" => fs::write(bundle.join("extra"), b"extra").expect("extra writes"),
                "wrong-case" => {
                    let canonical = bundle.join(CANDIDATE_BUNDLE_MANIFEST_V5);
                    let manifest_bytes = fs::read(&canonical).expect("manifest reads");
                    fs::remove_file(&canonical).expect("canonical manifest removes");
                    fs::write(bundle.join("Manifest-v5.json"), manifest_bytes)
                        .expect("wrong-case manifest writes");
                    let enumerated = fs::read_dir(&bundle)
                        .expect("bundle enumerates")
                        .map(|entry| {
                            entry
                                .expect("bundle entry reads")
                                .file_name()
                                .into_string()
                                .expect("bundle member name is UTF-8")
                        })
                        .collect::<BTreeSet<_>>();
                    assert!(enumerated.contains("Manifest-v5.json"));
                    assert!(!enumerated.contains(CANDIDATE_BUNDLE_MANIFEST_V5));
                }
                "directory" => {
                    fs::remove_file(bundle.join(CANDIDATE_BUNDLE_INDEX_V5))
                        .expect("candidate removes");
                    fs::create_dir(bundle.join(CANDIDATE_BUNDLE_INDEX_V5))
                        .expect("candidate directory creates");
                }
                _ => unreachable!(),
            }
            assert!(
                validate_candidate_bundle_inventory_v5(root.path(), &basename, None).is_err(),
                "{variant} inventory must fail closed"
            );
            assert!(recovery_status(root.path()).is_err());
        }
    }

    #[test]
    fn exact_bundle_inventory_rejects_hardlinked_members() {
        for member in [CANDIDATE_BUNDLE_MANIFEST_V5, CANDIDATE_BUNDLE_INDEX_V5] {
            let root = TestRoot::new();
            let (basename, _, _) = install_bundle(&root, TOKEN);
            fs::hard_link(
                root.local().join(&basename).join(member),
                root.path().join(format!("outside-{member}")),
            )
            .expect("member hardlink creates");
            assert!(
                validate_candidate_bundle_inventory_v5(root.path(), &basename, None).is_err(),
                "hardlinked {member} must fail closed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn exact_bundle_inventory_rejects_symlinked_members_and_bundle_directory() {
        use std::os::unix::fs::symlink;

        for member in [CANDIDATE_BUNDLE_MANIFEST_V5, CANDIDATE_BUNDLE_INDEX_V5] {
            let root = TestRoot::new();
            let (basename, _, _) = install_bundle(&root, TOKEN);
            let member_path = root.local().join(&basename).join(member);
            let outside = root.path().join(format!("outside-{member}"));
            fs::rename(&member_path, &outside).expect("member moves outside");
            symlink(&outside, &member_path).expect("member symlink creates");
            assert!(
                validate_candidate_bundle_inventory_v5(root.path(), &basename, None).is_err(),
                "symlinked {member} must fail closed"
            );
        }

        let root = TestRoot::new();
        let (basename, _, _) = install_bundle(&root, TOKEN);
        let bundle = root.local().join(&basename);
        let outside = root.path().join("outside-bundle");
        fs::rename(&bundle, &outside).expect("bundle moves outside");
        symlink(&outside, &bundle).expect("bundle symlink creates");
        assert!(recovery_status(root.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn scratch_entries_of_every_type_are_counted_retained_and_nonblocking() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        let tokens = [
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "33333333333333333333333333333333",
            "44444444444444444444444444444444",
        ];
        let names = tokens
            .iter()
            .map(|token| candidate_bundle_scratch_basename_v5(token).expect("token validates"))
            .collect::<Vec<_>>();
        fs::write(root.local().join(&names[0]), b"partial bytes").expect("scratch file writes");
        fs::create_dir(root.local().join(&names[1])).expect("scratch directory creates");
        fs::create_dir(root.local().join(&names[2])).expect("partial scratch directory creates");
        fs::write(root.local().join(&names[2]).join("partial"), b"partial")
            .expect("partial scratch member writes");
        symlink(
            root.path().join("missing-target"),
            root.local().join(&names[3]),
        )
        .expect("dangling scratch link creates");

        let status = recovery_status(root.path()).expect("scratch-only status succeeds");
        assert_eq!(
            status,
            crate::RecoveryStatus {
                pending_transaction: false,
                retained_candidate_scratch_count: 4,
            }
        );
        assert!(!has_pending_recovery(root.path()).expect("compat status succeeds"));
        assert!(
            exact_reserved_private_names(root.path())
                .expect("legacy scanner succeeds")
                .is_empty(),
            "scratch must not block the existing v4 writer"
        );
        for name in names {
            assert!(fs::symlink_metadata(root.local().join(name)).is_ok());
        }
    }

    #[test]
    fn stable_bundle_is_pending_and_coexists_with_retained_scratch() {
        let root = TestRoot::new();
        let (basename, _, _) = install_bundle(&root, TOKEN);
        let scratch = candidate_bundle_scratch_basename_v5("11111111111111111111111111111111")
            .expect("scratch basename builds");
        fs::write(root.local().join(&scratch), b"retained partial scratch")
            .expect("scratch writes");
        let status = recovery_status(root.path()).expect("v5 status succeeds");
        assert!(status.pending_transaction);
        assert_eq!(status.retained_candidate_scratch_count, 1);
        assert!(has_pending_recovery(root.path()).expect("compat status succeeds"));
        assert!(root.local().join(basename).is_dir());
        assert!(root.local().join(scratch).is_file());
    }

    #[test]
    fn stable_namespace_rejects_wrong_case_malformed_type_and_multiple_bundles() {
        let root = TestRoot::new();
        let wrong_case = format!("git-index-candidate-v4-BUNDLE-v5-{}", "1".repeat(32));
        fs::create_dir(root.local().join(wrong_case)).expect("wrong-case directory creates");
        assert!(recovery_status(root.path()).is_err());

        let root = TestRoot::new();
        let stable = candidate_bundle_stable_basename_v5(TOKEN).expect("stable basename builds");
        fs::write(root.local().join(stable), b"not a directory").expect("stable file writes");
        assert!(recovery_status(root.path()).is_err());

        let root = TestRoot::new();
        install_bundle(&root, TOKEN);
        install_bundle(&root, "11111111111111111111111111111111");
        assert!(recovery_status(root.path()).is_err());
    }

    #[test]
    fn scratch_namespace_rejects_wrong_case_and_malformed_token_without_removal() {
        for name in [
            format!("git-index-candidate-SCRATCH-v5-{}", "1".repeat(32)),
            format!("{CANDIDATE_BUNDLE_SCRATCH_PREFIX_V5}short"),
        ] {
            let root = TestRoot::new();
            let path = root.local().join(&name);
            fs::write(&path, b"unknown scratch bytes").expect("scratch fixture writes");
            assert!(recovery_status(root.path()).is_err());
            assert!(path.is_file(), "invalid scratch is retained fail closed");
        }
    }

    #[test]
    fn legacy_v1_status_and_boolean_wrapper_remain_compatible_with_v5_scratch() {
        let root = TestRoot::new();
        let MergeJournalPayload::InPlace(journal) = transaction(GitObjectFormat::Sha1) else {
            unreachable!();
        };
        fs::write(
            root.local().join(JOURNAL_FILE),
            serde_json::to_vec(&journal).expect("legacy journal serializes"),
        )
        .expect("legacy journal writes");
        let scratch = candidate_bundle_scratch_basename_v5("11111111111111111111111111111111")
            .expect("scratch basename builds");
        fs::write(root.local().join(&scratch), b"partial scratch").expect("scratch writes");

        let status = recovery_status(root.path()).expect("legacy status succeeds");
        assert!(status.pending_transaction);
        assert_eq!(status.retained_candidate_scratch_count, 1);
        assert!(has_pending_recovery(root.path()).expect("compat wrapper succeeds"));
        assert!(root.local().join(JOURNAL_FILE).is_file());
        assert!(root.local().join(scratch).is_file());
    }

    #[test]
    fn stable_v5_and_legacy_active_state_fail_closed_together() {
        let root = TestRoot::new();
        install_bundle(&root, TOKEN);
        let MergeJournalPayload::InPlace(journal) = transaction(GitObjectFormat::Sha1) else {
            unreachable!();
        };
        fs::write(
            root.local().join(JOURNAL_FILE),
            serde_json::to_vec(&journal).expect("legacy journal serializes"),
        )
        .expect("legacy journal writes");
        assert!(recovery_status(root.path()).is_err());
        assert!(root.local().join(JOURNAL_FILE).is_file());
    }
}
