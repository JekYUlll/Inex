use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use inex_core::atomic::{
    AtomicDirectoryPublishError, AtomicFileMoveOutcome, FilesystemDirectoryIdentity,
    FilesystemFileIdentity, ParentSyncStatus, VAULT_LOCAL_DIRECTORY, VaultMutationGuard,
    atomic_move_verified_directory_no_replace_checked, atomic_move_verified_file_no_replace,
    atomic_replace_verified_file, filesystem_directory_identity, filesystem_file_identity,
    open_file_matches_path_and_is_single_link, path_matches_file_identity_and_is_single_link,
    sync_directory,
};
use inex_core::path::raw_portable_case_fold_key;
use serde::{Deserialize, Serialize};

use super::{
    Git, GitError, GitIoOperation, GitObjectFormat, JOURNAL_FILE, MAX_GIT_OUTPUT_BYTES,
    MAX_JOURNAL_BYTES, MergeJournalPayload, apply_payload_to_index, ascii_casefold_starts_with,
    digest, ensure_no_journal, exact_reserved_private_names, hex_digest, index_entry_map,
    index_lock_path, index_path, io_error, is_link_or_reparse_point, parse_duplicate_free_json,
    parse_hex_digest, path_entry_is_absent, payload_oids, payload_rename_provenance,
    read_index_snapshot, restrict_file_permissions_best_effort, sync_regular_file,
    validate_local_directory, validate_lock_token, validate_oid, validate_payload,
    verify_candidate_index,
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

pub(super) const CANDIDATE_BUNDLE_SCRATCH_PREFIX_V5: &str = "git-index-candidate-scratch-v5-";
pub(super) const CANDIDATE_BUNDLE_STABLE_PREFIX_V5: &str = "git-index-candidate-v4-bundle-v5-";
pub(super) const CANDIDATE_BUNDLE_PUBLISH_PREFIX_V5: &str = "git-index-candidate-v4-publish-v5-";
pub(super) const CANDIDATE_BUNDLE_MANIFEST_V5: &str = "manifest-v5.json";
pub(super) const CANDIDATE_BUNDLE_INDEX_V5: &str = "candidate.index";
pub(super) const INDEX_LOCK_MARKER_MAGIC_V5: &[u8] = b"INEXIDX5\0";
const MAX_INDEX_LOCK_MARKER_BYTES_V5: usize = 1024;

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

/// Canonical reference shared by the v5 index-lock marker and stable journal.
///
/// The immutable bundle manifest remains the only copy of the complete Git
/// transaction. This reference binds its exact stable namespace entry and
/// bytes without duplicating old/final index metadata or the merge payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateBundleTransactionReferenceV5 {
    pub(super) object_format: GitObjectFormat,
    pub(super) token: String,
    pub(super) bundle_basename: String,
    pub(super) manifest: CandidateBundleManifestReferenceV5,
    pub(super) publish_staging_basename: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndexLockMarkerV5 {
    pub(super) version: u32,
    pub(super) reference: CandidateBundleTransactionReferenceV5,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CanonicalBytesReferenceV5 {
    pub(super) size: u64,
    pub(super) sha256: String,
}

/// Read-only classification of the real Git index lock for one exact v5
/// transaction.
///
/// `Candidate` proves only that the lock bytes match the immutable manifest's
/// final-index size and digest. It does not prove the candidate's Git stage
/// map, the live expected-old index, or worktree ownership; the recovery
/// caller must revalidate those semantic boundaries separately before any
/// mutation.
#[allow(
    dead_code,
    reason = "the recovery-first v5 writer consumes this strict classifier in the next slice"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IndexLockStateV5 {
    Absent,
    Marker,
    Candidate,
    Foreign,
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
    pub(super) transaction_reference: CandidateBundleTransactionReferenceV5,
    pub(super) index_lock_marker: Vec<u8>,
    pub(super) index_lock_marker_reference: CanonicalBytesReferenceV5,
}

/// Held proof for the exact token-derived publish staging file.
///
/// This is still pre-lock state. It authorizes neither a real Git index-lock
/// acquisition nor any journal, worktree, or live-index mutation.
#[allow(
    dead_code,
    reason = "the next writer slice consumes the held publish-staging proof"
)]
#[derive(Debug)]
pub(super) struct PreparedCandidatePublishStagingV5 {
    pub(super) publish_staging_basename: String,
    pub(super) candidate: CandidateIndexMetadataV5,
    file: File,
}

/// Fresh-process proof for an already-published token-derived staging file.
///
/// Both the immutable bundle inventory and publish file are reopened here;
/// callers cannot accidentally reuse a pre-crash held file identity.
#[allow(
    dead_code,
    reason = "the next recovery slice consumes the fresh held publish-staging proof"
)]
#[derive(Debug)]
pub(super) struct LoadedCandidatePublishStagingV5 {
    pub(super) inventory: InventoryVerifiedCandidateBundleV5,
    pub(super) staging: PreparedCandidatePublishStagingV5,
}

/// Held proof that the exact canonical v5 marker owns the real Git index lock.
///
/// This type deliberately has no `Drop` cleanup. Once the marker is visible at
/// `.git/index.lock`, only the later durable-journal state machine may advance
/// or retire it.
#[allow(
    dead_code,
    reason = "the next recovery slice consumes the held real-index-lock proof"
)]
#[derive(Debug)]
pub(super) struct AcquiredIndexLockMarkerV5 {
    pub(super) marker: CanonicalBytesReferenceV5,
    scratch_basename: Option<String>,
    file: File,
}

/// Fresh-process proof that the immutable final candidate occupies the real
/// Git index-lock pathname while the live index is still the exact old index.
#[derive(Debug)]
pub(super) struct LoadedCandidateIndexLockV5 {
    pub(super) inventory: InventoryVerifiedCandidateBundleV5,
    file: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompletedLiveIndexStateV5 {
    ExactFinal,
    LaterUnrelated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PostJournalIndexCheckpointV5 {
    BeforePublishOverMarker,
    AfterPublishOverMarker,
    BeforePublishOverIndex,
    AfterPublishOverIndex,
}

pub(super) struct PostJournalIndexAuthorizationV5<'a, F> {
    journal_file: &'a File,
    critical_audit: F,
}

impl<'a, F> PostJournalIndexAuthorizationV5<'a, F> {
    pub(super) fn new(journal_file: &'a File, critical_audit: F) -> Self {
        Self {
            journal_file,
            critical_audit,
        }
    }
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "fault-injection tests inspect the post-journal mutation paths"
)]
pub(super) struct PostJournalIndexContextV5<'a> {
    pub(super) root: &'a Path,
    pub(super) stable_path: &'a Path,
    pub(super) publish_path: &'a Path,
    pub(super) lock_path: &'a Path,
    pub(super) index_path: &'a Path,
}

pub(super) trait PostJournalIndexHooksV5 {
    fn checkpoint(
        &mut self,
        _checkpoint: PostJournalIndexCheckpointV5,
        _context: &PostJournalIndexContextV5<'_>,
    ) -> Result<(), GitError> {
        Ok(())
    }

    fn replace(
        &mut self,
        source: &Path,
        source_file: File,
        destination: &Path,
        destination_file: File,
    ) -> io::Result<AtomicFileMoveOutcome> {
        atomic_replace_verified_file(source, source_file, destination, destination_file)
    }
}

struct ProductionPostJournalIndexHooksV5;

impl PostJournalIndexHooksV5 for ProductionPostJournalIndexHooksV5 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CandidatePublishStagingCheckpointV5 {
    ScratchCreated,
    CandidateCopied,
    BeforePublish,
    CriticalAudit,
    AfterPublish,
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "fault hooks inspect these paths only in isolated publish-staging tests"
)]
pub(super) struct CandidatePublishStagingContextV5<'a> {
    pub(super) root: &'a Path,
    pub(super) local: &'a Path,
    pub(super) stable_path: &'a Path,
    pub(super) scratch_path: &'a Path,
    pub(super) publish_path: &'a Path,
}

pub(super) trait CandidatePublishStagingHooksV5 {
    fn next_token(&mut self) -> String;

    fn checkpoint(
        &mut self,
        _checkpoint: CandidatePublishStagingCheckpointV5,
        _context: &CandidatePublishStagingContextV5<'_>,
    ) -> Result<(), GitError> {
        Ok(())
    }
}

struct ProductionCandidatePublishStagingHooksV5;

impl CandidatePublishStagingHooksV5 for ProductionCandidatePublishStagingHooksV5 {
    fn next_token(&mut self) -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IndexLockMarkerCheckpointV5 {
    ScratchCreated,
    MarkerWritten,
    BeforeMove,
    CriticalAudit,
    AfterMove,
    PostAudit,
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "fault hooks inspect these paths only in isolated marker-lock tests"
)]
pub(super) struct IndexLockMarkerContextV5<'a> {
    pub(super) root: &'a Path,
    pub(super) local: &'a Path,
    pub(super) git_directory: &'a Path,
    pub(super) stable_path: &'a Path,
    pub(super) publish_path: &'a Path,
    pub(super) scratch_path: &'a Path,
    pub(super) lock_path: &'a Path,
}

pub(super) trait IndexLockMarkerHooksV5 {
    fn next_token(&mut self) -> String;

    fn checkpoint(
        &mut self,
        _checkpoint: IndexLockMarkerCheckpointV5,
        _context: &IndexLockMarkerContextV5<'_>,
    ) -> Result<(), GitError> {
        Ok(())
    }

    fn move_marker(
        &mut self,
        source: &Path,
        source_file: &File,
        destination: &Path,
    ) -> io::Result<AtomicFileMoveOutcome> {
        atomic_move_verified_file_no_replace(source, source_file, destination)
    }
}

struct ProductionIndexLockMarkerHooksV5;

impl IndexLockMarkerHooksV5 for ProductionIndexLockMarkerHooksV5 {
    fn next_token(&mut self) -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
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
    pub(super) publish_staging_basename: Option<String>,
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

pub(super) fn candidate_bundle_publish_basename_v5(token: &str) -> Result<String, GitError> {
    exact_token_basename(CANDIDATE_BUNDLE_PUBLISH_PREFIX_V5, token)
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

fn parse_candidate_bundle_publish_basename_v5(basename: &str) -> Result<&str, GitError> {
    let token = basename
        .strip_prefix(CANDIDATE_BUNDLE_PUBLISH_PREFIX_V5)
        .ok_or(GitError::InvalidJournal)?;
    validate_lock_token(token)?;
    if basename != candidate_bundle_publish_basename_v5(token)? {
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

pub(super) fn candidate_bundle_publish_path_v5(
    root: &Path,
    publish_basename: &str,
) -> Result<PathBuf, GitError> {
    parse_candidate_bundle_publish_basename_v5(publish_basename)?;
    Ok(root.join(VAULT_LOCAL_DIRECTORY).join(publish_basename))
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

pub(super) fn candidate_bundle_transaction_reference_v5(
    bundle_basename: &str,
    object_format: GitObjectFormat,
    manifest: CandidateBundleManifestReferenceV5,
) -> Result<CandidateBundleTransactionReferenceV5, GitError> {
    let token = parse_candidate_bundle_stable_basename_v5(bundle_basename)?.to_owned();
    let publish_staging_basename = candidate_bundle_publish_basename_v5(&token)?;
    let reference = CandidateBundleTransactionReferenceV5 {
        object_format,
        token,
        bundle_basename: bundle_basename.to_owned(),
        manifest,
        publish_staging_basename,
    };
    validate_candidate_bundle_transaction_reference_v5(&reference)?;
    Ok(reference)
}

pub(super) fn validate_candidate_bundle_transaction_reference_v5(
    reference: &CandidateBundleTransactionReferenceV5,
) -> Result<(), GitError> {
    validate_lock_token(&reference.token)?;
    if reference.bundle_basename != candidate_bundle_stable_basename_v5(&reference.token)?
        || reference.publish_staging_basename
            != candidate_bundle_publish_basename_v5(&reference.token)?
    {
        return Err(GitError::InvalidJournal);
    }
    validate_manifest_reference_v5(&reference.manifest)
}

fn validate_index_lock_marker_v5(marker: &IndexLockMarkerV5) -> Result<(), GitError> {
    if marker.version != 5 {
        return Err(GitError::InvalidJournal);
    }
    validate_candidate_bundle_transaction_reference_v5(&marker.reference)
}

pub(super) fn index_lock_marker_bytes_v5(
    reference: &CandidateBundleTransactionReferenceV5,
) -> Result<Vec<u8>, GitError> {
    let marker = IndexLockMarkerV5 {
        version: 5,
        reference: reference.clone(),
    };
    validate_index_lock_marker_v5(&marker)?;
    let payload = serde_json::to_vec(&marker).map_err(|_| GitError::InvalidJournal)?;
    if payload.is_empty()
        || payload.len()
            > MAX_INDEX_LOCK_MARKER_BYTES_V5.saturating_sub(INDEX_LOCK_MARKER_MAGIC_V5.len())
    {
        return Err(GitError::InvalidJournal);
    }
    let mut bytes = Vec::with_capacity(INDEX_LOCK_MARKER_MAGIC_V5.len() + payload.len());
    bytes.extend_from_slice(INDEX_LOCK_MARKER_MAGIC_V5);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

#[allow(
    dead_code,
    reason = "the next writer slice consumes the strict marker parser after no-replace publication"
)]
pub(super) fn parse_index_lock_marker_v5(
    bytes: &[u8],
) -> Result<CandidateBundleTransactionReferenceV5, GitError> {
    let payload = bytes
        .strip_prefix(INDEX_LOCK_MARKER_MAGIC_V5)
        .ok_or(GitError::InvalidJournal)?;
    if payload.is_empty() || bytes.len() > MAX_INDEX_LOCK_MARKER_BYTES_V5 {
        return Err(GitError::InvalidJournal);
    }
    let value = parse_duplicate_free_json(payload)?;
    let marker =
        serde_json::from_value::<IndexLockMarkerV5>(value).map_err(|_| GitError::InvalidJournal)?;
    validate_index_lock_marker_v5(&marker)?;
    if index_lock_marker_bytes_v5(&marker.reference)? != bytes {
        return Err(GitError::InvalidJournal);
    }
    Ok(marker.reference)
}

fn index_lock_bytes_v5_with_hook<F>(path: &Path, after_open: F) -> Result<Option<Vec<u8>>, GitError>
where
    F: FnOnce() -> Result<(), GitError>,
{
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(GitIoOperation::InspectMetadata, &error)),
    };
    if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_file() {
        return Err(GitError::RecoveryConflict);
    }
    let mut file = File::open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            GitError::RecoveryConflict
        } else {
            io_error(GitIoOperation::ReadMetadata, &error)
        }
    })?;
    if !open_file_matches_path_and_is_single_link(path, &file)
        .map_err(|_| GitError::RecoveryConflict)?
    {
        return Err(GitError::RecoveryConflict);
    }
    after_open()?;
    if metadata.len() > u64::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(u64::MAX) {
        return Ok(Some(Vec::new()));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_GIT_OUTPUT_BYTES)
            .min(MAX_GIT_OUTPUT_BYTES),
    );
    (&mut file)
        .take(
            u64::try_from(MAX_GIT_OUTPUT_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    if bytes.len() > MAX_GIT_OUTPUT_BYTES
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len()
        || !open_file_matches_path_and_is_single_link(path, &file)
            .map_err(|_| GitError::RecoveryConflict)?
    {
        return Err(GitError::RecoveryConflict);
    }
    Ok(Some(bytes))
}

fn index_lock_bytes_v5(path: &Path) -> Result<Option<Vec<u8>>, GitError> {
    index_lock_bytes_v5_with_hook(path, || Ok(()))
}

#[cfg(all(test, unix))]
pub(super) fn index_lock_bytes_v5_after_open<F>(
    path: &Path,
    after_open: F,
) -> Result<Option<Vec<u8>>, GitError>
where
    F: FnOnce() -> Result<(), GitError>,
{
    index_lock_bytes_v5_with_hook(path, after_open)
}

/// Classifies `.git/index.lock` without changing or removing any namespace
/// entry. The immutable inventory must have been loaded for `reference`; this
/// binds an exact candidate lock to the referenced manifest's final-index
/// bytes while leaving Git stage-map validation to the caller.
#[allow(
    dead_code,
    reason = "the recovery-first v5 writer consumes this strict classifier in the next slice"
)]
pub(super) fn classify_index_lock_v5(
    root: &Path,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
) -> Result<IndexLockStateV5, GitError> {
    validate_candidate_bundle_transaction_reference_v5(reference)?;
    validate_candidate_bundle_manifest_v5(&inventory.manifest)?;
    if inventory.manifest_reference != reference.manifest
        || inventory.manifest.object_format != reference.object_format
        || inventory.manifest.token != reference.token
        || inventory.manifest.bundle_basename != reference.bundle_basename
    {
        return Err(GitError::RecoveryConflict);
    }

    let Some(bytes) = index_lock_bytes_v5(&index_lock_path(root))? else {
        return Ok(IndexLockStateV5::Absent);
    };
    if bytes.starts_with(INDEX_LOCK_MARKER_MAGIC_V5) {
        let found = parse_index_lock_marker_v5(&bytes).map_err(|_| GitError::RecoveryConflict)?;
        return Ok(if found == *reference {
            IndexLockStateV5::Marker
        } else {
            IndexLockStateV5::Foreign
        });
    }
    if !bytes.is_empty() && INDEX_LOCK_MARKER_MAGIC_V5.starts_with(&bytes) {
        return Err(GitError::RecoveryConflict);
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) == inventory.manifest.final_index.size
        && hex_digest(digest(&bytes)) == inventory.manifest.final_index.sha256
    {
        return Ok(IndexLockStateV5::Candidate);
    }
    Ok(IndexLockStateV5::Foreign)
}

pub(super) fn canonical_bytes_reference_v5(
    bytes: &[u8],
) -> Result<CanonicalBytesReferenceV5, GitError> {
    if bytes.is_empty() || bytes.len() > MAX_INDEX_LOCK_MARKER_BYTES_V5 {
        return Err(GitError::InvalidJournal);
    }
    Ok(CanonicalBytesReferenceV5 {
        size: u64::try_from(bytes.len()).map_err(|_| GitError::InvalidJournal)?,
        sha256: hex_digest(digest(bytes)),
    })
}

pub(super) fn validate_canonical_bytes_reference_v5(
    reference: &CanonicalBytesReferenceV5,
) -> Result<(), GitError> {
    parse_hex_digest(&reference.sha256)?;
    if reference.size == 0
        || reference.size > u64::try_from(MAX_INDEX_LOCK_MARKER_BYTES_V5).unwrap_or(u64::MAX)
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

fn validate_reference_inventory_binding_v5(
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
) -> Result<(), GitError> {
    validate_candidate_bundle_transaction_reference_v5(reference)?;
    validate_candidate_bundle_manifest_v5(&inventory.manifest)?;
    if inventory.manifest_reference != reference.manifest
        || inventory.manifest.object_format != reference.object_format
        || inventory.manifest.token != reference.token
        || inventory.manifest.bundle_basename != reference.bundle_basename
    {
        return Err(GitError::InvalidJournal);
    }
    Ok(())
}

fn verified_live_stage_map_v5(
    git: &Git,
    old_index: &CandidateIndexMetadataV5,
    expected: Option<&BTreeMap<(String, u8), super::StageEntry>>,
) -> Result<BTreeMap<(String, u8), super::StageEntry>, GitError> {
    let first = read_index_snapshot(&index_path(&git.root))?;
    if first.size != old_index.size || first.sha256 != old_index.sha256 {
        return Err(GitError::IndexChanged);
    }
    let stage_map = index_entry_map(git)?;
    let second = read_index_snapshot(&index_path(&git.root))?;
    if second.size != old_index.size
        || second.sha256 != old_index.sha256
        || expected.is_some_and(|expected| expected != &stage_map)
    {
        return Err(GitError::IndexChanged);
    }
    Ok(stage_map)
}

fn verify_bundle_git_semantics_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    expected_stage_map: Option<&BTreeMap<(String, u8), super::StageEntry>>,
) -> Result<BTreeMap<(String, u8), super::StageEntry>, GitError> {
    validate_reference_inventory_binding_v5(reference, inventory)?;
    if reference.object_format != git.object_format {
        return Err(GitError::InvalidJournal);
    }
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    git.ensure_full_index()?;
    let stable_path = candidate_bundle_stable_path_v5(&git.root, &reference.bundle_basename)?;
    held_inventory_matches_path_v5(&stable_path, &reference.bundle_basename, inventory)?;
    let before =
        verified_live_stage_map_v5(git, &inventory.manifest.old_index, expected_stage_map)?;
    let candidate_git = git.with_index_file(stable_path.join(CANDIDATE_BUNDLE_INDEX_V5))?;
    verify_candidate_index(&candidate_git, &inventory.manifest.transaction, &before)?;
    held_inventory_matches_path_v5(&stable_path, &reference.bundle_basename, inventory)?;
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    verified_live_stage_map_v5(git, &inventory.manifest.old_index, Some(&before))?;
    verify_candidate_index(&candidate_git, &inventory.manifest.transaction, &before)?;
    held_inventory_matches_path_v5(&stable_path, &reference.bundle_basename, inventory)?;
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    Ok(before)
}

/// Reopens a stable bundle and binds it to the current repository's exact old
/// index and expected final stage map without mutating Git or the worktree.
#[allow(
    dead_code,
    reason = "the next writer/recovery slice consumes the fresh-process semantic loader"
)]
pub(super) fn load_candidate_bundle_for_git_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
) -> Result<InventoryVerifiedCandidateBundleV5, GitError> {
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    let inventory = validate_candidate_bundle_inventory_v5(
        &git.root,
        &reference.bundle_basename,
        Some(&reference.manifest),
    )?;
    verify_bundle_git_semantics_v5(guard, git, reference, &inventory, None)?;
    Ok(inventory)
}

fn verify_candidate_publish_namespace_v5(
    root: &Path,
    reference: &CandidateBundleTransactionReferenceV5,
    published: bool,
    journal_published: bool,
) -> Result<(), GitError> {
    let namespace = inspect_candidate_bundle_namespace_v5(root)?;
    if namespace.stable_bundle_basename.as_deref() != Some(&reference.bundle_basename)
        || namespace.publish_staging_basename.as_deref()
            != published.then_some(reference.publish_staging_basename.as_str())
    {
        return Err(GitError::RecoveryConflict);
    }
    let mut expected = BTreeSet::from([reference.bundle_basename.clone()]);
    if published {
        expected.insert(reference.publish_staging_basename.clone());
    }
    if journal_published {
        expected.insert(JOURNAL_FILE.to_owned());
    }
    if exact_reserved_private_names(root)? != expected {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn create_private_publish_scratch_file_v5<H: CandidatePublishStagingHooksV5>(
    guard: &VaultMutationGuard,
    git: &Git,
    local: &Path,
    hooks: &mut H,
) -> Result<(String, PathBuf, File), GitError> {
    create_private_retained_scratch_file_v5(guard, git, local, || hooks.next_token())
}

pub(super) fn create_private_retained_scratch_file_v5<F>(
    guard: &VaultMutationGuard,
    git: &Git,
    local: &Path,
    mut next_token: F,
) -> Result<(String, PathBuf, File), GitError>
where
    F: FnMut() -> String,
{
    for _ in 0..MAX_SCRATCH_TOKEN_ATTEMPTS_V5 {
        let token = next_token();
        let scratch_basename = candidate_bundle_scratch_basename_v5(&token)?;
        let scratch_path = candidate_bundle_scratch_path_v5(&git.root, &scratch_basename)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = match options.open(&scratch_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(GitIoOperation::WriteJournal, &error)),
        };
        restrict_file_permissions_best_effort(&file);
        #[cfg(unix)]
        {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
            let mode = file
                .metadata()
                .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o600 {
                return Err(GitError::DurabilityNotConfirmed);
            }
        }
        file.sync_all()
            .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
        if !guard.is_for_root(&git.root)
            || !exact_child_name_is_unique(local, &scratch_basename)?
            || !open_file_matches_path_and_is_single_link(&scratch_path, &file)
                .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
        {
            return Err(GitError::RecoveryConflict);
        }
        sync_directory(local).map_err(|_| GitError::DurabilityNotConfirmed)?;
        return Ok((scratch_basename, scratch_path, file));
    }
    Err(GitError::RecoveryConflict)
}

fn copy_held_candidate_v5(
    inventory: &InventoryVerifiedCandidateBundleV5,
    destination: &mut File,
) -> Result<(), GitError> {
    let mut source = inventory
        .seal
        .candidate_file
        .try_clone()
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    let expected_size = inventory.manifest.final_index.size;
    let copied = io::copy(
        &mut source.take(expected_size.saturating_add(1)),
        destination,
    )
    .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))?;
    if copied != expected_size {
        return Err(GitError::RecoveryConflict);
    }
    destination
        .flush()
        .and_then(|()| destination.sync_all())
        .map_err(|error| io_error(GitIoOperation::WriteJournal, &error))
}

fn verify_candidate_publish_file_v5(
    git: &Git,
    path: &Path,
    file: &File,
    manifest: &CandidateBundleManifestV5,
    before: &BTreeMap<(String, u8), super::StageEntry>,
) -> Result<(), GitError> {
    if !open_file_matches_path_and_is_single_link(path, file)
        .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Err(GitError::RecoveryConflict);
    }
    let snapshot = read_index_snapshot(path)?;
    if snapshot.size != manifest.final_index.size || snapshot.sha256 != manifest.final_index.sha256
    {
        return Err(GitError::RecoveryConflict);
    }
    let staging_git = git.with_index_file(path.to_path_buf())?;
    verify_candidate_index(&staging_git, &manifest.transaction, before)?;
    if !open_file_matches_path_and_is_single_link(path, file)
        .map_err(|error| io_error(GitIoOperation::InspectMetadata, &error))?
    {
        return Err(GitError::RecoveryConflict);
    }
    let rebound = read_index_snapshot(path)?;
    if rebound.size != manifest.final_index.size || rebound.sha256 != manifest.final_index.sha256 {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the audit binds every independent held and namespace proof at one checkpoint"
)]
fn audit_candidate_publish_staging_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    path: &Path,
    file: &File,
    before: &BTreeMap<(String, u8), super::StageEntry>,
    published: bool,
    journal_published: bool,
) -> Result<(), GitError> {
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    verify_candidate_publish_namespace_v5(&git.root, reference, published, journal_published)?;
    verify_bundle_git_semantics_v5(guard, git, reference, inventory, Some(before))?;
    verify_candidate_publish_file_v5(git, path, file, &inventory.manifest, before)?;
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn reconcile_publish_move_error_v5(
    local: &Path,
    scratch_path: &Path,
    publish_path: &Path,
    file: &File,
    error: &io::Error,
) -> GitError {
    let source_matches =
        open_file_matches_path_and_is_single_link(scratch_path, file).unwrap_or(false);
    let destination_matches =
        open_file_matches_path_and_is_single_link(publish_path, file).unwrap_or(false);
    let source_absent = path_entry_is_absent(scratch_path).unwrap_or(false);
    let destination_absent = path_entry_is_absent(publish_path).unwrap_or(false);
    if destination_matches && source_absent {
        let _ = sync_directory(local);
        GitError::DurabilityNotConfirmed
    } else if source_matches && destination_absent {
        io_error(GitIoOperation::WriteJournal, error)
    } else {
        GitError::RecoveryConflict
    }
}

/// Copies one sealed immutable candidate to its token-derived publish staging.
///
/// The random scratch file is deliberately retained on every failure. This
/// helper never touches the real Git index lock, journal, worktree, or live
/// index and its result remains pre-lock state.
#[allow(
    dead_code,
    reason = "the next writer slice consumes the publish-staging helper"
)]
pub(super) fn prepare_candidate_publish_staging_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
) -> Result<PreparedCandidatePublishStagingV5, GitError> {
    let mut hooks = ProductionCandidatePublishStagingHooksV5;
    prepare_candidate_publish_staging_v5_impl(guard, git, reference, inventory, &mut hooks)
}

#[cfg(test)]
pub(super) fn prepare_candidate_publish_staging_v5_with_hooks<H: CandidatePublishStagingHooksV5>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    hooks: &mut H,
) -> Result<PreparedCandidatePublishStagingV5, GitError> {
    prepare_candidate_publish_staging_v5_impl(guard, git, reference, inventory, hooks)
}

#[allow(clippy::too_many_lines)]
fn prepare_candidate_publish_staging_v5_impl<H: CandidatePublishStagingHooksV5>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    hooks: &mut H,
) -> Result<PreparedCandidatePublishStagingV5, GitError> {
    validate_reference_inventory_binding_v5(reference, inventory)?;
    verify_candidate_publish_namespace_v5(&git.root, reference, false, false)?;
    let before = verify_bundle_git_semantics_v5(guard, git, reference, inventory, None)?;
    let local = git.root.join(VAULT_LOCAL_DIRECTORY);
    validate_local_directory(&local)?;
    let stable_path = candidate_bundle_stable_path_v5(&git.root, &reference.bundle_basename)?;
    let publish_path =
        candidate_bundle_publish_path_v5(&git.root, &reference.publish_staging_basename)?;
    let (_scratch_basename, scratch_path, mut scratch_file) =
        create_private_publish_scratch_file_v5(guard, git, &local, hooks)?;
    let context = CandidatePublishStagingContextV5 {
        root: &git.root,
        local: &local,
        stable_path: &stable_path,
        scratch_path: &scratch_path,
        publish_path: &publish_path,
    };
    hooks.checkpoint(
        CandidatePublishStagingCheckpointV5::ScratchCreated,
        &context,
    )?;

    copy_held_candidate_v5(inventory, &mut scratch_file)?;
    verify_candidate_publish_file_v5(
        git,
        &scratch_path,
        &scratch_file,
        &inventory.manifest,
        &before,
    )?;
    held_inventory_matches_path_v5(&stable_path, &reference.bundle_basename, inventory)?;
    hooks.checkpoint(
        CandidatePublishStagingCheckpointV5::CandidateCopied,
        &context,
    )?;
    sync_directory(&local).map_err(|_| GitError::DurabilityNotConfirmed)?;
    hooks.checkpoint(CandidatePublishStagingCheckpointV5::BeforePublish, &context)?;
    hooks.checkpoint(CandidatePublishStagingCheckpointV5::CriticalAudit, &context)?;
    audit_candidate_publish_staging_v5(
        guard,
        git,
        reference,
        inventory,
        &scratch_path,
        &scratch_file,
        &before,
        false,
        false,
    )?;

    let outcome =
        match atomic_move_verified_file_no_replace(&scratch_path, &scratch_file, &publish_path) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(reconcile_publish_move_error_v5(
                    &local,
                    &scratch_path,
                    &publish_path,
                    &scratch_file,
                    &error,
                ));
            }
        };
    hooks.checkpoint(CandidatePublishStagingCheckpointV5::AfterPublish, &context)?;
    if !path_entry_is_absent(&scratch_path)? {
        return Err(GitError::RecoveryConflict);
    }
    audit_candidate_publish_staging_v5(
        guard,
        git,
        reference,
        inventory,
        &publish_path,
        &scratch_file,
        &before,
        true,
        false,
    )?;
    if outcome.source_parent_sync != ParentSyncStatus::Synced
        || outcome.destination_parent_sync != ParentSyncStatus::Synced
    {
        return Err(GitError::DurabilityNotConfirmed);
    }
    Ok(PreparedCandidatePublishStagingV5 {
        publish_staging_basename: reference.publish_staging_basename.clone(),
        candidate: inventory.manifest.final_index.clone(),
        file: scratch_file,
    })
}

#[allow(
    dead_code,
    reason = "the next writer slice revalidates the held publish staging before lock acquisition"
)]
pub(super) fn revalidate_candidate_publish_staging_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    prepared: &PreparedCandidatePublishStagingV5,
) -> Result<(), GitError> {
    revalidate_candidate_publish_staging_v5_impl(guard, git, reference, inventory, prepared, false)
}

pub(super) fn revalidate_candidate_publish_staging_with_journal_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    prepared: &PreparedCandidatePublishStagingV5,
) -> Result<(), GitError> {
    revalidate_candidate_publish_staging_v5_impl(guard, git, reference, inventory, prepared, true)
}

fn revalidate_candidate_publish_staging_v5_impl(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    prepared: &PreparedCandidatePublishStagingV5,
    journal_published: bool,
) -> Result<(), GitError> {
    if prepared.publish_staging_basename != reference.publish_staging_basename
        || prepared.candidate != inventory.manifest.final_index
    {
        return Err(GitError::RecoveryConflict);
    }
    let before = verify_bundle_git_semantics_v5(guard, git, reference, inventory, None)?;
    let publish_path =
        candidate_bundle_publish_path_v5(&git.root, &prepared.publish_staging_basename)?;
    audit_candidate_publish_staging_v5(
        guard,
        git,
        reference,
        inventory,
        &publish_path,
        &prepared.file,
        &before,
        true,
        journal_published,
    )
}

/// Reopens and fully revalidates an already-published token-derived staging
/// file for crash recovery.
///
/// The exact namespace, immutable bundle, live expected-old stage map, and
/// publish candidate are each checked again using newly opened file handles.
#[allow(
    dead_code,
    reason = "the next recovery slice consumes the fresh-process publish-staging loader"
)]
pub(super) fn load_candidate_publish_staging_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
) -> Result<LoadedCandidatePublishStagingV5, GitError> {
    load_candidate_publish_staging_v5_impl(guard, git, reference, false)
}

/// Recovery-only fresh loader for a published candidate whose exact stable
/// v5 journal may already occupy the fixed journal pathname.
///
/// The caller must parse and bind that journal before entering this dedicated
/// capability; the function only admits the additional exact namespace entry
/// and still reopens every bundle/publish proof.
pub(super) fn load_candidate_publish_staging_with_journal_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
) -> Result<LoadedCandidatePublishStagingV5, GitError> {
    load_candidate_publish_staging_v5_impl(guard, git, reference, true)
}

fn load_candidate_publish_staging_v5_impl(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    journal_published: bool,
) -> Result<LoadedCandidatePublishStagingV5, GitError> {
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    validate_candidate_bundle_transaction_reference_v5(reference)?;
    verify_candidate_publish_namespace_v5(&git.root, reference, true, journal_published)?;
    let inventory = load_candidate_bundle_for_git_v5(guard, git, reference)?;
    let before = verify_bundle_git_semantics_v5(guard, git, reference, &inventory, None)?;
    let publish_path =
        candidate_bundle_publish_path_v5(&git.root, &reference.publish_staging_basename)?;
    let (_, publish_file) = read_single_link_regular(&publish_path, MAX_GIT_OUTPUT_BYTES, false)?;
    audit_candidate_publish_staging_v5(
        guard,
        git,
        reference,
        &inventory,
        &publish_path,
        &publish_file,
        &before,
        true,
        journal_published,
    )?;
    Ok(LoadedCandidatePublishStagingV5 {
        staging: PreparedCandidatePublishStagingV5 {
            publish_staging_basename: reference.publish_staging_basename.clone(),
            candidate: inventory.manifest.final_index.clone(),
            file: publish_file,
        },
        inventory,
    })
}

fn verify_held_index_lock_marker_file_v5(
    path: &Path,
    file: &File,
    reference: &CandidateBundleTransactionReferenceV5,
) -> Result<CanonicalBytesReferenceV5, GitError> {
    if !open_file_matches_path_and_is_single_link(path, file)
        .map_err(|_| GitError::RecoveryConflict)?
    {
        return Err(GitError::RecoveryConflict);
    }
    let (bytes, reopened) = read_single_link_regular(path, MAX_INDEX_LOCK_MARKER_BYTES_V5, false)
        .map_err(|_| GitError::RecoveryConflict)?;
    if bytes != index_lock_marker_bytes_v5(reference)?
        || !open_file_matches_path_and_is_single_link(path, &reopened)
            .map_err(|_| GitError::RecoveryConflict)?
        || !open_file_matches_path_and_is_single_link(path, file)
            .map_err(|_| GitError::RecoveryConflict)?
    {
        return Err(GitError::RecoveryConflict);
    }
    canonical_bytes_reference_v5(&bytes)
}

fn require_absent_index_lock_v5(
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
) -> Result<(), GitError> {
    match classify_index_lock_v5(&git.root, reference, inventory)? {
        IndexLockStateV5::Absent => Ok(()),
        IndexLockStateV5::Foreign => Err(GitError::IndexChanged),
        IndexLockStateV5::Marker | IndexLockStateV5::Candidate => Err(GitError::RecoveryConflict),
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_index_lock_marker_before_move_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
    scratch_path: &Path,
    scratch_file: &File,
) -> Result<(), GitError> {
    let local = git.root.join(VAULT_LOCAL_DIRECTORY);
    validate_local_directory(&local)?;
    validate_local_directory(&git.root.join(".git"))?;
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    revalidate_candidate_publish_staging_v5(guard, git, reference, inventory, publish)?;
    verify_held_index_lock_marker_file_v5(scratch_path, scratch_file, reference)?;
    require_absent_index_lock_v5(git, reference, inventory)?;
    verify_held_index_lock_marker_file_v5(scratch_path, scratch_file, reference)?;
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn audit_acquired_index_lock_marker_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
    scratch_path: Option<&Path>,
    lock_path: &Path,
    lock_file: &File,
    journal_published: bool,
) -> Result<CanonicalBytesReferenceV5, GitError> {
    let local = git.root.join(VAULT_LOCAL_DIRECTORY);
    validate_local_directory(&local)?;
    validate_local_directory(&git.root.join(".git"))?;
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    if let Some(path) = scratch_path
        && !path_entry_is_absent(path)?
    {
        return Err(GitError::RecoveryConflict);
    }
    let marker = verify_held_index_lock_marker_file_v5(lock_path, lock_file, reference)?;
    if classify_index_lock_v5(&git.root, reference, inventory)? != IndexLockStateV5::Marker {
        return Err(GitError::RecoveryConflict);
    }
    revalidate_candidate_publish_staging_v5_impl(
        guard,
        git,
        reference,
        inventory,
        publish,
        journal_published,
    )?;
    let rebound_marker = verify_held_index_lock_marker_file_v5(lock_path, lock_file, reference)?;
    if rebound_marker != marker || !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    if let Some(path) = scratch_path
        && !path_entry_is_absent(path)?
    {
        return Err(GitError::RecoveryConflict);
    }
    if !open_file_matches_path_and_is_single_link(lock_path, lock_file)
        .map_err(|_| GitError::RecoveryConflict)?
    {
        return Err(GitError::RecoveryConflict);
    }
    Ok(marker)
}

#[allow(clippy::too_many_arguments)]
fn reconcile_index_lock_marker_move_error_v5(
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    local: &Path,
    scratch_path: &Path,
    lock_path: &Path,
    scratch_file: &File,
    error: &io::Error,
) -> Result<(), GitError> {
    let source_matches =
        open_file_matches_path_and_is_single_link(scratch_path, scratch_file).unwrap_or(false);
    let destination_matches =
        open_file_matches_path_and_is_single_link(lock_path, scratch_file).unwrap_or(false);
    let source_absent = path_entry_is_absent(scratch_path).unwrap_or(false);
    let lock_state = classify_index_lock_v5(&git.root, reference, inventory)
        .map_err(|_| GitError::RecoveryConflict)?;

    if source_absent && destination_matches && lock_state == IndexLockStateV5::Marker {
        sync_directory(local).map_err(|_| GitError::DurabilityNotConfirmed)?;
        sync_directory(&git.root.join(".git")).map_err(|_| GitError::DurabilityNotConfirmed)?;
        return Ok(());
    }
    if source_matches && lock_state == IndexLockStateV5::Absent {
        return if error.kind() == io::ErrorKind::AlreadyExists {
            Err(GitError::IndexChanged)
        } else {
            Err(io_error(GitIoOperation::SyncGitState, error))
        };
    }
    if source_matches && lock_state == IndexLockStateV5::Foreign {
        return Err(GitError::IndexChanged);
    }
    Err(GitError::RecoveryConflict)
}

/// Acquires the real Git index lock with the canonical v5 marker.
///
/// The marker is first written and synchronized in a random retained scratch
/// file, then moved without replacement after rebinding every stable/publish
/// proof and the live expected-old index. This helper never writes a journal,
/// worktree file, candidate index, or live index. Once the marker becomes
/// visible it is never removed here, including on post-move failures.
#[allow(
    dead_code,
    reason = "the next recovery slice consumes the bounded marker acquisition helper"
)]
pub(super) fn acquire_index_lock_marker_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
) -> Result<AcquiredIndexLockMarkerV5, GitError> {
    let mut hooks = ProductionIndexLockMarkerHooksV5;
    acquire_index_lock_marker_v5_impl(guard, git, reference, inventory, publish, &mut hooks)
}

#[cfg(test)]
pub(super) fn acquire_index_lock_marker_v5_with_hooks<H: IndexLockMarkerHooksV5>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
    hooks: &mut H,
) -> Result<AcquiredIndexLockMarkerV5, GitError> {
    acquire_index_lock_marker_v5_impl(guard, git, reference, inventory, publish, hooks)
}

#[allow(clippy::too_many_lines)]
fn acquire_index_lock_marker_v5_impl<H: IndexLockMarkerHooksV5>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
    hooks: &mut H,
) -> Result<AcquiredIndexLockMarkerV5, GitError> {
    validate_reference_inventory_binding_v5(reference, inventory)?;
    revalidate_candidate_publish_staging_v5(guard, git, reference, inventory, publish)?;
    require_absent_index_lock_v5(git, reference, inventory)?;

    let marker_bytes = index_lock_marker_bytes_v5(reference)?;
    let expected_marker = canonical_bytes_reference_v5(&marker_bytes)?;
    let local = git.root.join(VAULT_LOCAL_DIRECTORY);
    let git_directory = git.root.join(".git");
    validate_local_directory(&local)?;
    validate_local_directory(&git_directory)?;
    let stable_path = candidate_bundle_stable_path_v5(&git.root, &reference.bundle_basename)?;
    let publish_path =
        candidate_bundle_publish_path_v5(&git.root, &reference.publish_staging_basename)?;
    let (scratch_basename, scratch_path, mut scratch_file) =
        create_private_retained_scratch_file_v5(guard, git, &local, || hooks.next_token())?;
    let lock_path = index_lock_path(&git.root);
    let context = IndexLockMarkerContextV5 {
        root: &git.root,
        local: &local,
        git_directory: &git_directory,
        stable_path: &stable_path,
        publish_path: &publish_path,
        scratch_path: &scratch_path,
        lock_path: &lock_path,
    };
    hooks.checkpoint(IndexLockMarkerCheckpointV5::ScratchCreated, &context)?;

    scratch_file
        .write_all(&marker_bytes)
        .and_then(|()| scratch_file.flush())
        .and_then(|()| scratch_file.sync_all())
        .map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    sync_directory(&local).map_err(|_| GitError::DurabilityNotConfirmed)?;
    if verify_held_index_lock_marker_file_v5(&scratch_path, &scratch_file, reference)?
        != expected_marker
    {
        return Err(GitError::RecoveryConflict);
    }
    hooks.checkpoint(IndexLockMarkerCheckpointV5::MarkerWritten, &context)?;
    hooks.checkpoint(IndexLockMarkerCheckpointV5::BeforeMove, &context)?;
    hooks.checkpoint(IndexLockMarkerCheckpointV5::CriticalAudit, &context)?;
    audit_index_lock_marker_before_move_v5(
        guard,
        git,
        reference,
        inventory,
        publish,
        &scratch_path,
        &scratch_file,
    )?;

    let parents_durable = match hooks.move_marker(&scratch_path, &scratch_file, &lock_path) {
        Ok(outcome) => {
            outcome.source_parent_sync == ParentSyncStatus::Synced
                && outcome.destination_parent_sync == ParentSyncStatus::Synced
        }
        Err(error) => {
            reconcile_index_lock_marker_move_error_v5(
                git,
                reference,
                inventory,
                &local,
                &scratch_path,
                &lock_path,
                &scratch_file,
                &error,
            )?;
            true
        }
    };
    hooks.checkpoint(IndexLockMarkerCheckpointV5::AfterMove, &context)?;
    let marker = audit_acquired_index_lock_marker_v5(
        guard,
        git,
        reference,
        inventory,
        publish,
        Some(&scratch_path),
        &lock_path,
        &scratch_file,
        false,
    )?;
    hooks.checkpoint(IndexLockMarkerCheckpointV5::PostAudit, &context)?;
    if !parents_durable {
        return Err(GitError::DurabilityNotConfirmed);
    }
    Ok(AcquiredIndexLockMarkerV5 {
        marker,
        scratch_basename: Some(scratch_basename),
        file: scratch_file,
    })
}

/// Reopens the canonical marker that already owns the real Git index lock.
///
/// This fresh-process proof binds a newly opened lock handle to the exact
/// marker bytes, immutable stable bundle, publish staging, live expected-old
/// index, and Git stage map. It deliberately has no cleanup behavior.
pub(super) fn load_acquired_index_lock_marker_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
) -> Result<AcquiredIndexLockMarkerV5, GitError> {
    load_acquired_index_lock_marker_v5_impl(guard, git, reference, inventory, publish, false)
}

pub(super) fn load_acquired_index_lock_marker_with_journal_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
) -> Result<AcquiredIndexLockMarkerV5, GitError> {
    load_acquired_index_lock_marker_v5_impl(guard, git, reference, inventory, publish, true)
}

fn load_acquired_index_lock_marker_v5_impl(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
    journal_published: bool,
) -> Result<AcquiredIndexLockMarkerV5, GitError> {
    let lock_path = index_lock_path(&git.root);
    let file =
        File::open(&lock_path).map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    let marker = audit_acquired_index_lock_marker_v5(
        guard,
        git,
        reference,
        inventory,
        publish,
        None,
        &lock_path,
        &file,
        journal_published,
    )?;
    Ok(AcquiredIndexLockMarkerV5 {
        marker,
        scratch_basename: None,
        file,
    })
}

#[allow(
    dead_code,
    reason = "the durable-journal critical audit reuses this held-lock proof"
)]
pub(super) fn revalidate_acquired_index_lock_marker_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
    acquired: &AcquiredIndexLockMarkerV5,
) -> Result<(), GitError> {
    let scratch_path = acquired
        .scratch_basename
        .as_deref()
        .map(|basename| candidate_bundle_scratch_path_v5(&git.root, basename))
        .transpose()?;
    let marker = audit_acquired_index_lock_marker_v5(
        guard,
        git,
        reference,
        inventory,
        publish,
        scratch_path.as_deref(),
        &index_lock_path(&git.root),
        &acquired.file,
        false,
    )?;
    if marker != acquired.marker {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

pub(super) fn revalidate_acquired_index_lock_marker_with_journal_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish: &PreparedCandidatePublishStagingV5,
    acquired: &AcquiredIndexLockMarkerV5,
) -> Result<(), GitError> {
    let marker = audit_acquired_index_lock_marker_v5(
        guard,
        git,
        reference,
        inventory,
        publish,
        None,
        &index_lock_path(&git.root),
        &acquired.file,
        true,
    )?;
    if marker != acquired.marker {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn load_stable_bundle_with_journal_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    publish_present: bool,
) -> Result<InventoryVerifiedCandidateBundleV5, GitError> {
    if !guard.is_for_root(&git.root) || reference.object_format != git.object_format {
        return Err(GitError::RecoveryConflict);
    }
    verify_candidate_publish_namespace_v5(&git.root, reference, publish_present, true)?;
    let inventory = validate_candidate_bundle_inventory_v5(
        &git.root,
        &reference.bundle_basename,
        Some(&reference.manifest),
    )?;
    validate_reference_inventory_binding_v5(reference, &inventory)?;
    let stable_path = candidate_bundle_stable_path_v5(&git.root, &reference.bundle_basename)?;
    held_inventory_matches_path_v5(&stable_path, &reference.bundle_basename, &inventory)?;
    git.ensure_full_index()?;
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    Ok(inventory)
}

fn verify_held_active_journal_identity_v5(git: &Git, journal_file: &File) -> Result<(), GitError> {
    let path = git.root.join(VAULT_LOCAL_DIRECTORY).join(JOURNAL_FILE);
    if !required_open_file_matches_path_v5(&path, journal_file)? {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn required_open_file_matches_path_v5(path: &Path, file: &File) -> Result<bool, GitError> {
    match open_file_matches_path_and_is_single_link(path, file) {
        Ok(matches) => Ok(matches),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(GitIoOperation::InspectMetadata, &error)),
    }
}

fn required_path_matches_file_identity_v5(
    path: &Path,
    identity: &FilesystemFileIdentity,
) -> Result<bool, GitError> {
    match path_matches_file_identity_and_is_single_link(path, identity) {
        Ok(matches) => Ok(matches),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(GitIoOperation::InspectMetadata, &error)),
    }
}

fn stable_candidate_stage_map_v5(
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
) -> Result<BTreeMap<(String, u8), super::StageEntry>, GitError> {
    let stable_path = candidate_bundle_stable_path_v5(&git.root, &reference.bundle_basename)?;
    held_inventory_matches_path_v5(&stable_path, &reference.bundle_basename, inventory)?;
    let candidate_git = git.with_index_file(stable_path.join(CANDIDATE_BUNDLE_INDEX_V5))?;
    candidate_git.ensure_full_index()?;
    let map = index_entry_map(&candidate_git)?;
    held_inventory_matches_path_v5(&stable_path, &reference.bundle_basename, inventory)?;
    Ok(map)
}

fn expected_transaction_projection_v5(
    payload: &MergeJournalPayload,
) -> BTreeMap<(String, u8), super::StageEntry> {
    let (path, mode, oid) = match payload {
        MergeJournalPayload::InPlace(journal) => (
            journal.physical_path.as_str(),
            journal.result_mode.as_str(),
            journal.result_oid.as_str(),
        ),
        MergeJournalPayload::DetectedRename(journal) => (
            journal.destination_physical_path.as_str(),
            journal.result_mode.as_str(),
            journal.result_oid.as_str(),
        ),
        MergeJournalPayload::Rename(journal) => (
            journal.destination_physical_path.as_str(),
            journal.result_mode.as_str(),
            journal.result_oid.as_str(),
        ),
    };
    BTreeMap::from([(
        (path.to_owned(), 0),
        super::StageEntry {
            mode: mode.to_owned(),
            oid: oid.to_owned(),
        },
    )])
}

fn transaction_raw_fold_keys_v5(
    payload: &MergeJournalPayload,
) -> BTreeSet<inex_core::path::CaseFoldKey> {
    let mut keys = BTreeSet::new();
    match payload {
        MergeJournalPayload::InPlace(journal) => {
            keys.insert(raw_portable_case_fold_key(&journal.physical_path));
        }
        MergeJournalPayload::DetectedRename(journal) => {
            keys.insert(raw_portable_case_fold_key(&journal.source_physical_path));
            keys.insert(raw_portable_case_fold_key(
                &journal.destination_physical_path,
            ));
        }
        MergeJournalPayload::Rename(journal) => {
            keys.insert(raw_portable_case_fold_key(&journal.source_physical_path));
            keys.insert(raw_portable_case_fold_key(
                &journal.destination_physical_path,
            ));
        }
    }
    keys
}

fn protected_stage_projection_v5(
    map: &BTreeMap<(String, u8), super::StageEntry>,
    protected: &BTreeSet<inex_core::path::CaseFoldKey>,
) -> BTreeMap<(String, u8), super::StageEntry> {
    map.iter()
        .filter(|((path, _), _)| protected.contains(&raw_portable_case_fold_key(path)))
        .map(|(key, entry)| (key.clone(), entry.clone()))
        .collect()
}

fn verify_final_candidate_projection_v5(
    payload: &MergeJournalPayload,
    candidate: &BTreeMap<(String, u8), super::StageEntry>,
) -> Result<BTreeSet<inex_core::path::CaseFoldKey>, GitError> {
    let protected = transaction_raw_fold_keys_v5(payload);
    if protected_stage_projection_v5(candidate, &protected)
        != expected_transaction_projection_v5(payload)
    {
        return Err(GitError::RecoveryConflict);
    }
    Ok(protected)
}

/// Classifies a consumed-lock live index after the immutable v5 journal. Exact
/// final bytes and later semantic changes outside the protected transaction
/// keys are accepted; every raw Unicode/case-fold alias of a protected path is
/// part of the protected projection and therefore fails on spelling drift.
pub(super) fn classify_completed_live_index_with_journal_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
) -> Result<
    (
        InventoryVerifiedCandidateBundleV5,
        CompletedLiveIndexStateV5,
    ),
    GitError,
> {
    let inventory = load_stable_bundle_with_journal_v5(guard, git, reference, false)?;
    if classify_index_lock_v5(&git.root, reference, &inventory)? != IndexLockStateV5::Absent {
        return Err(GitError::RecoveryConflict);
    }
    let first = read_index_snapshot(&index_path(&git.root))?;
    let current = index_entry_map(git)?;
    let second = read_index_snapshot(&index_path(&git.root))?;
    if first.size != second.size
        || first.sha256 != second.sha256
        || classify_index_lock_v5(&git.root, reference, &inventory)? != IndexLockStateV5::Absent
    {
        return Err(GitError::IndexChanged);
    }
    let candidate = stable_candidate_stage_map_v5(git, reference, &inventory)?;
    let protected =
        verify_final_candidate_projection_v5(&inventory.manifest.transaction, &candidate)?;
    if protected_stage_projection_v5(&current, &protected)
        != protected_stage_projection_v5(&candidate, &protected)
    {
        return Err(GitError::RecoveryConflict);
    }
    held_inventory_matches_path_v5(
        &candidate_bundle_stable_path_v5(&git.root, &reference.bundle_basename)?,
        &reference.bundle_basename,
        &inventory,
    )?;
    if !guard.is_for_root(&git.root) {
        return Err(GitError::RecoveryConflict);
    }
    let state = if first.size == inventory.manifest.final_index.size
        && first.sha256 == inventory.manifest.final_index.sha256
        && current == candidate
    {
        CompletedLiveIndexStateV5::ExactFinal
    } else {
        CompletedLiveIndexStateV5::LaterUnrelated
    };
    Ok((inventory, state))
}

fn verify_held_candidate_index_lock_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    file: &File,
) -> Result<(), GitError> {
    let lock_path = index_lock_path(&git.root);
    if !required_open_file_matches_path_v5(&lock_path, file)?
        || classify_index_lock_v5(&git.root, reference, inventory)? != IndexLockStateV5::Candidate
    {
        return Err(GitError::RecoveryConflict);
    }
    let before = verify_bundle_git_semantics_v5(guard, git, reference, inventory, None)?;
    let lock_git = git.with_index_file(lock_path.clone())?;
    verify_candidate_index(&lock_git, &inventory.manifest.transaction, &before)?;
    if index_entry_map(&lock_git)? != stable_candidate_stage_map_v5(git, reference, inventory)?
        || !required_open_file_matches_path_v5(&lock_path, file)?
        || classify_index_lock_v5(&git.root, reference, inventory)? != IndexLockStateV5::Candidate
    {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

/// Reopens the candidate occupying `.git/index.lock` and binds it to the exact
/// live-old index, immutable bundle, final stage map, and held lock identity.
pub(super) fn load_candidate_index_lock_with_journal_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
) -> Result<LoadedCandidateIndexLockV5, GitError> {
    let inventory = load_stable_bundle_with_journal_v5(guard, git, reference, false)?;
    let lock_path = index_lock_path(&git.root);
    let file =
        File::open(&lock_path).map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    verify_held_candidate_index_lock_v5(guard, git, reference, &inventory, &file)?;
    Ok(LoadedCandidateIndexLockV5 { inventory, file })
}

fn audit_candidate_over_marker_post_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    inventory: &InventoryVerifiedCandidateBundleV5,
    publish_identity: &FilesystemFileIdentity,
    marker_identity: &FilesystemFileIdentity,
    journal_file: &File,
) -> Result<(), GitError> {
    verify_candidate_publish_namespace_v5(&git.root, reference, false, true)?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    let publish_path =
        candidate_bundle_publish_path_v5(&git.root, &reference.publish_staging_basename)?;
    let lock_path = index_lock_path(&git.root);
    if !path_entry_is_absent(&publish_path)?
        || !required_path_matches_file_identity_v5(&lock_path, publish_identity)?
        || required_path_matches_file_identity_v5(&lock_path, marker_identity)?
        || classify_index_lock_v5(&git.root, reference, inventory)? != IndexLockStateV5::Candidate
    {
        return Err(GitError::RecoveryConflict);
    }
    let before = verify_bundle_git_semantics_v5(guard, git, reference, inventory, None)?;
    let lock_git = git.with_index_file(lock_path)?;
    verify_candidate_index(&lock_git, &inventory.manifest.transaction, &before)?;
    if index_entry_map(&lock_git)? != stable_candidate_stage_map_v5(git, reference, inventory)? {
        return Err(GitError::RecoveryConflict);
    }
    sync_directory(&git.root.join(VAULT_LOCAL_DIRECTORY))
        .map_err(|_| GitError::DurabilityNotConfirmed)?;
    sync_directory(&git.root.join(".git")).map_err(|_| GitError::DurabilityNotConfirmed)
}

fn audit_candidate_over_marker_pre_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    publish_identity: &FilesystemFileIdentity,
    marker_identity: &FilesystemFileIdentity,
    journal_file: &File,
) -> Result<(), GitError> {
    verify_held_active_journal_identity_v5(git, journal_file)?;
    let loaded = load_candidate_publish_staging_with_journal_v5(guard, git, reference)?;
    let publish_path =
        candidate_bundle_publish_path_v5(&git.root, &reference.publish_staging_basename)?;
    let lock_path = index_lock_path(&git.root);
    if !required_path_matches_file_identity_v5(&publish_path, publish_identity)?
        || !required_path_matches_file_identity_v5(&lock_path, marker_identity)?
        || classify_index_lock_v5(&git.root, reference, &loaded.inventory)?
            != IndexLockStateV5::Marker
    {
        return Err(GitError::RecoveryConflict);
    }
    Ok(())
}

fn is_postjournal_semantic_conflict_v5(error: &GitError) -> bool {
    matches!(
        error,
        GitError::RecoveryConflict
            | GitError::IndexChanged
            | GitError::WorktreeChanged
            | GitError::InvalidJournal
    )
}

fn reconcile_postjournal_replace_error_v5<F>(
    move_error: &io::Error,
    post_error: GitError,
    pre_audit: F,
) -> Result<(), GitError>
where
    F: FnOnce() -> Result<(), GitError>,
{
    if !is_postjournal_semantic_conflict_v5(&post_error) {
        return Err(post_error);
    }
    match pre_audit() {
        Ok(()) => Err(io_error(GitIoOperation::SyncGitState, move_error)),
        Err(error) if is_postjournal_semantic_conflict_v5(&error) => {
            Err(GitError::RecoveryConflict)
        }
        Err(error) => Err(error),
    }
}

fn verify_synced_postjournal_replace_v5(outcome: AtomicFileMoveOutcome) -> Result<(), GitError> {
    if outcome.source_parent_sync != ParentSyncStatus::Synced
        || outcome.destination_parent_sync != ParentSyncStatus::Synced
    {
        return Err(GitError::DurabilityNotConfirmed);
    }
    Ok(())
}

/// Atomically consumes the publish staging file over the held v5 marker. Both
/// path handles are consumed before the Windows namespace move; opaque file-ID
/// receipts distinguish the moved inode from byte-identical replacements.
pub(super) fn publish_staging_over_marker_with_journal_v5<F>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    loaded: LoadedCandidatePublishStagingV5,
    marker: AcquiredIndexLockMarkerV5,
    journal_file: &File,
    critical_audit: F,
) -> Result<(), GitError>
where
    F: FnMut() -> Result<(), GitError>,
{
    let mut hooks = ProductionPostJournalIndexHooksV5;
    publish_staging_over_marker_with_journal_v5_impl(
        guard,
        git,
        reference,
        loaded,
        marker,
        PostJournalIndexAuthorizationV5::new(journal_file, critical_audit),
        &mut hooks,
    )
}

#[cfg(test)]
pub(super) fn publish_staging_over_marker_with_journal_v5_with_hooks<
    H: PostJournalIndexHooksV5,
    F: FnMut() -> Result<(), GitError>,
>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    loaded: LoadedCandidatePublishStagingV5,
    marker: AcquiredIndexLockMarkerV5,
    authorization: PostJournalIndexAuthorizationV5<'_, F>,
    hooks: &mut H,
) -> Result<(), GitError> {
    publish_staging_over_marker_with_journal_v5_impl(
        guard,
        git,
        reference,
        loaded,
        marker,
        authorization,
        hooks,
    )
}

fn publish_staging_over_marker_with_journal_v5_impl<
    H: PostJournalIndexHooksV5,
    F: FnMut() -> Result<(), GitError>,
>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    loaded: LoadedCandidatePublishStagingV5,
    marker: AcquiredIndexLockMarkerV5,
    authorization: PostJournalIndexAuthorizationV5<'_, F>,
    hooks: &mut H,
) -> Result<(), GitError> {
    let PostJournalIndexAuthorizationV5 {
        journal_file,
        mut critical_audit,
    } = authorization;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    revalidate_acquired_index_lock_marker_with_journal_v5(
        guard,
        git,
        reference,
        &loaded.inventory,
        &loaded.staging,
        &marker,
    )?;
    let stable_path = candidate_bundle_stable_path_v5(&git.root, &reference.bundle_basename)?;
    let publish_path =
        candidate_bundle_publish_path_v5(&git.root, &reference.publish_staging_basename)?;
    let lock_path = index_lock_path(&git.root);
    let live_path = index_path(&git.root);
    let context = PostJournalIndexContextV5 {
        root: &git.root,
        stable_path: &stable_path,
        publish_path: &publish_path,
        lock_path: &lock_path,
        index_path: &live_path,
    };
    hooks.checkpoint(
        PostJournalIndexCheckpointV5::BeforePublishOverMarker,
        &context,
    )?;
    revalidate_acquired_index_lock_marker_with_journal_v5(
        guard,
        git,
        reference,
        &loaded.inventory,
        &loaded.staging,
        &marker,
    )?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    critical_audit()?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    let publish_identity = filesystem_file_identity(&loaded.staging.file)
        .map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    let marker_identity = filesystem_file_identity(&marker.file)
        .map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    let LoadedCandidatePublishStagingV5 { inventory, staging } = loaded;
    let PreparedCandidatePublishStagingV5 {
        file: source,
        publish_staging_basename: _,
        candidate: _,
    } = staging;
    let AcquiredIndexLockMarkerV5 {
        file: destination,
        marker: _,
        scratch_basename: _,
    } = marker;
    let move_result = hooks.replace(&publish_path, source, &lock_path, destination);
    let post = audit_candidate_over_marker_post_v5(
        guard,
        git,
        reference,
        &inventory,
        &publish_identity,
        &marker_identity,
        journal_file,
    );
    match (move_result, post) {
        (Ok(outcome), Ok(())) => verify_synced_postjournal_replace_v5(outcome)?,
        (Err(_), Ok(())) => {}
        (Err(error), Err(post_error)) => {
            return reconcile_postjournal_replace_error_v5(&error, post_error, || {
                audit_candidate_over_marker_pre_v5(
                    guard,
                    git,
                    reference,
                    &publish_identity,
                    &marker_identity,
                    journal_file,
                )
            });
        }
        (Ok(_), Err(error)) => return Err(error),
    }
    hooks.checkpoint(
        PostJournalIndexCheckpointV5::AfterPublishOverMarker,
        &context,
    )?;
    audit_candidate_over_marker_post_v5(
        guard,
        git,
        reference,
        &inventory,
        &publish_identity,
        &marker_identity,
        journal_file,
    )
}

fn open_held_live_old_index_v5(
    git: &Git,
    inventory: &InventoryVerifiedCandidateBundleV5,
) -> Result<File, GitError> {
    let path = index_path(&git.root);
    let file = File::open(&path).map_err(|error| io_error(GitIoOperation::ReadMetadata, &error))?;
    let snapshot = read_index_snapshot(&path)?;
    if snapshot.size != inventory.manifest.old_index.size
        || snapshot.sha256 != inventory.manifest.old_index.sha256
        || !required_open_file_matches_path_v5(&path, &file)?
    {
        return Err(GitError::IndexChanged);
    }
    Ok(file)
}

fn audit_candidate_lock_before_index_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    loaded: &LoadedCandidateIndexLockV5,
    live_file: &File,
) -> Result<(), GitError> {
    verify_candidate_publish_namespace_v5(&git.root, reference, false, true)?;
    verify_held_candidate_index_lock_v5(guard, git, reference, &loaded.inventory, &loaded.file)?;
    let path = index_path(&git.root);
    let snapshot = read_index_snapshot(&path)?;
    if snapshot.size != loaded.inventory.manifest.old_index.size
        || snapshot.sha256 != loaded.inventory.manifest.old_index.sha256
        || !required_open_file_matches_path_v5(&path, live_file)?
    {
        return Err(GitError::IndexChanged);
    }
    Ok(())
}

fn audit_candidate_over_live_index_post_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    candidate_identity: &FilesystemFileIdentity,
    old_live_identity: &FilesystemFileIdentity,
    journal_file: &File,
) -> Result<(), GitError> {
    verify_candidate_publish_namespace_v5(&git.root, reference, false, true)?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    let lock_path = index_lock_path(&git.root);
    let live_path = index_path(&git.root);
    if !path_entry_is_absent(&lock_path)?
        || !required_path_matches_file_identity_v5(&live_path, candidate_identity)?
        || required_path_matches_file_identity_v5(&live_path, old_live_identity)?
    {
        return Err(GitError::RecoveryConflict);
    }
    let (_, completed) = classify_completed_live_index_with_journal_v5(guard, git, reference)?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    if completed != CompletedLiveIndexStateV5::ExactFinal {
        return Err(GitError::RecoveryConflict);
    }
    sync_directory(&git.root.join(".git")).map_err(|_| GitError::DurabilityNotConfirmed)?;
    Ok(())
}

fn audit_candidate_over_live_index_final_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    candidate_identity: &FilesystemFileIdentity,
    old_live_identity: &FilesystemFileIdentity,
    journal_file: &File,
) -> Result<CompletedLiveIndexStateV5, GitError> {
    verify_candidate_publish_namespace_v5(&git.root, reference, false, true)?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    let live_path = index_path(&git.root);
    if required_path_matches_file_identity_v5(&live_path, old_live_identity)? {
        return Err(GitError::RecoveryConflict);
    }
    let candidate_matches = required_path_matches_file_identity_v5(&live_path, candidate_identity)?;
    let (_, completed) = classify_completed_live_index_with_journal_v5(guard, git, reference)?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    if !matches!(
        (completed, candidate_matches),
        (CompletedLiveIndexStateV5::ExactFinal, true)
            | (CompletedLiveIndexStateV5::LaterUnrelated, false)
    ) {
        return Err(GitError::RecoveryConflict);
    }
    sync_directory(&git.root.join(".git")).map_err(|_| GitError::DurabilityNotConfirmed)?;
    Ok(completed)
}

fn audit_candidate_lock_before_index_by_identity_v5(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    candidate_identity: &FilesystemFileIdentity,
    old_live_identity: &FilesystemFileIdentity,
    journal_file: &File,
) -> Result<(), GitError> {
    verify_held_active_journal_identity_v5(git, journal_file)?;
    let loaded = load_candidate_index_lock_with_journal_v5(guard, git, reference)?;
    let lock_path = index_lock_path(&git.root);
    let live_path = index_path(&git.root);
    if !required_path_matches_file_identity_v5(&lock_path, candidate_identity)?
        || !required_path_matches_file_identity_v5(&live_path, old_live_identity)?
    {
        return Err(GitError::RecoveryConflict);
    }
    drop(loaded);
    Ok(())
}

pub(super) fn publish_candidate_lock_over_live_index_with_journal_v5<F>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    loaded: LoadedCandidateIndexLockV5,
    journal_file: &File,
    critical_audit: F,
) -> Result<(), GitError>
where
    F: FnMut() -> Result<(), GitError>,
{
    let mut hooks = ProductionPostJournalIndexHooksV5;
    publish_candidate_lock_over_live_index_with_journal_v5_impl(
        guard,
        git,
        reference,
        loaded,
        journal_file,
        critical_audit,
        &mut hooks,
    )
}

#[cfg(test)]
pub(super) fn publish_candidate_lock_over_live_index_with_journal_v5_with_hooks<
    H: PostJournalIndexHooksV5,
    F: FnMut() -> Result<(), GitError>,
>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    loaded: LoadedCandidateIndexLockV5,
    journal_file: &File,
    critical_audit: F,
    hooks: &mut H,
) -> Result<(), GitError> {
    publish_candidate_lock_over_live_index_with_journal_v5_impl(
        guard,
        git,
        reference,
        loaded,
        journal_file,
        critical_audit,
        hooks,
    )
}

fn publish_candidate_lock_over_live_index_with_journal_v5_impl<
    H: PostJournalIndexHooksV5,
    F: FnMut() -> Result<(), GitError>,
>(
    guard: &VaultMutationGuard,
    git: &Git,
    reference: &CandidateBundleTransactionReferenceV5,
    loaded: LoadedCandidateIndexLockV5,
    journal_file: &File,
    mut critical_audit: F,
    hooks: &mut H,
) -> Result<(), GitError> {
    verify_held_active_journal_identity_v5(git, journal_file)?;
    let live_file = open_held_live_old_index_v5(git, &loaded.inventory)?;
    audit_candidate_lock_before_index_v5(guard, git, reference, &loaded, &live_file)?;
    let stable_path = candidate_bundle_stable_path_v5(&git.root, &reference.bundle_basename)?;
    let publish_path =
        candidate_bundle_publish_path_v5(&git.root, &reference.publish_staging_basename)?;
    let lock_path = index_lock_path(&git.root);
    let live_path = index_path(&git.root);
    let context = PostJournalIndexContextV5 {
        root: &git.root,
        stable_path: &stable_path,
        publish_path: &publish_path,
        lock_path: &lock_path,
        index_path: &live_path,
    };
    hooks.checkpoint(
        PostJournalIndexCheckpointV5::BeforePublishOverIndex,
        &context,
    )?;
    audit_candidate_lock_before_index_v5(guard, git, reference, &loaded, &live_file)?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    critical_audit()?;
    verify_held_active_journal_identity_v5(git, journal_file)?;
    let candidate_identity = filesystem_file_identity(&loaded.file)
        .map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    let old_live_identity = filesystem_file_identity(&live_file)
        .map_err(|error| io_error(GitIoOperation::SyncGitState, &error))?;
    let LoadedCandidateIndexLockV5 {
        inventory: _,
        file: source,
    } = loaded;
    let destination = live_file;
    let move_result = hooks.replace(&lock_path, source, &live_path, destination);
    let post = audit_candidate_over_live_index_post_v5(
        guard,
        git,
        reference,
        &candidate_identity,
        &old_live_identity,
        journal_file,
    );
    match (move_result, post) {
        (Ok(outcome), Ok(())) => verify_synced_postjournal_replace_v5(outcome)?,
        (Err(_), Ok(())) => {}
        (Err(error), Err(post_error)) => {
            return reconcile_postjournal_replace_error_v5(&error, post_error, || {
                audit_candidate_lock_before_index_by_identity_v5(
                    guard,
                    git,
                    reference,
                    &candidate_identity,
                    &old_live_identity,
                    journal_file,
                )
            });
        }
        (Ok(_), Err(error)) => return Err(error),
    }
    hooks.checkpoint(
        PostJournalIndexCheckpointV5::AfterPublishOverIndex,
        &context,
    )?;
    audit_candidate_over_live_index_final_v5(
        guard,
        git,
        reference,
        &candidate_identity,
        &old_live_identity,
        journal_file,
    )
    .map(|_| ())
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
        || namespace.publish_staging_basename.is_some()
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
    let transaction_reference = candidate_bundle_transaction_reference_v5(
        &stable_basename,
        git.object_format,
        manifest_reference.clone(),
    )?;
    let index_lock_marker = index_lock_marker_bytes_v5(&transaction_reference)?;
    let index_lock_marker_reference = canonical_bytes_reference_v5(&index_lock_marker)?;
    validate_canonical_bytes_reference_v5(&index_lock_marker_reference)?;
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
                || namespace.publish_staging_basename.is_some()
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
    if namespace.stable_bundle_basename.as_deref() != Some(stable_basename.as_str())
        || namespace.publish_staging_basename.is_some()
    {
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
        transaction_reference,
        index_lock_marker,
        index_lock_marker_reference,
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
    let mut publish_staging_basenames = Vec::new();
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
            continue;
        }
        if ascii_casefold_starts_with(&name, CANDIDATE_BUNDLE_PUBLISH_PREFIX_V5) {
            if !name.starts_with(CANDIDATE_BUNDLE_PUBLISH_PREFIX_V5) {
                return Err(GitError::RecoveryConflict);
            }
            parse_candidate_bundle_publish_basename_v5(&name)
                .map_err(|_| GitError::RecoveryConflict)?;
            publish_staging_basenames.push(name);
        }
    }
    if stable_bundle_basenames.len() > 1 || publish_staging_basenames.len() > 1 {
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
        publish_staging_basename: publish_staging_basenames.pop(),
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
    fn v5_transaction_reference_and_index_lock_marker_are_exact_and_canonical() {
        let root = TestRoot::new();
        let (bundle_basename, manifest, manifest_reference) = install_bundle(&root, TOKEN);
        let reference = candidate_bundle_transaction_reference_v5(
            &bundle_basename,
            manifest.object_format,
            manifest_reference,
        )
        .expect("transaction reference builds");
        assert_eq!(reference.token, TOKEN);
        assert_eq!(reference.bundle_basename, bundle_basename);
        assert_eq!(
            reference.publish_staging_basename,
            candidate_bundle_publish_basename_v5(TOKEN).expect("publish basename builds")
        );

        let marker = index_lock_marker_bytes_v5(&reference).expect("v5 marker serializes");
        assert!(marker.starts_with(INDEX_LOCK_MARKER_MAGIC_V5));
        assert_eq!(
            parse_index_lock_marker_v5(&marker).expect("v5 marker parses"),
            reference
        );
        let marker_reference =
            canonical_bytes_reference_v5(&marker).expect("marker bytes reference builds");
        validate_canonical_bytes_reference_v5(&marker_reference)
            .expect("marker bytes reference validates");

        let mut trailing = marker.clone();
        trailing.push(b'\n');
        assert!(parse_index_lock_marker_v5(&trailing).is_err());
        let payload = marker
            .strip_prefix(INDEX_LOCK_MARKER_MAGIC_V5)
            .expect("marker magic strips");
        let duplicate = std::str::from_utf8(payload)
            .expect("marker payload is UTF-8")
            .replacen("\"version\":5", "\"version\":5,\"version\":5", 1);
        let mut duplicate_marker = INDEX_LOCK_MARKER_MAGIC_V5.to_vec();
        duplicate_marker.extend_from_slice(duplicate.as_bytes());
        assert!(parse_index_lock_marker_v5(&duplicate_marker).is_err());

        let mut unknown: serde_json::Value =
            serde_json::from_slice(payload).expect("marker value parses");
        unknown
            .as_object_mut()
            .expect("marker is an object")
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let mut unknown_marker = INDEX_LOCK_MARKER_MAGIC_V5.to_vec();
        unknown_marker.extend_from_slice(
            &serde_json::to_vec(&unknown).expect("unknown marker fixture serializes"),
        );
        assert!(parse_index_lock_marker_v5(&unknown_marker).is_err());
    }

    #[test]
    fn v5_transaction_reference_rejects_namespace_and_manifest_aliases() {
        let root = TestRoot::new();
        let (bundle_basename, manifest, manifest_reference) = install_bundle(&root, TOKEN);
        let canonical = candidate_bundle_transaction_reference_v5(
            &bundle_basename,
            manifest.object_format,
            manifest_reference,
        )
        .expect("canonical transaction reference builds");
        for invalid in [
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
                value.publish_staging_basename.push_str(".extra");
                value
            },
            {
                let mut value = canonical.clone();
                value.manifest.size = 0;
                value
            },
            {
                let mut value = canonical.clone();
                value.manifest.sha256 = value.manifest.sha256.to_uppercase();
                value
            },
        ] {
            assert!(validate_candidate_bundle_transaction_reference_v5(&invalid).is_err());
            assert!(index_lock_marker_bytes_v5(&invalid).is_err());
        }

        let stable = candidate_bundle_stable_basename_v5(TOKEN).expect("stable basename builds");
        let publish = candidate_bundle_publish_basename_v5(TOKEN).expect("publish basename builds");
        assert!(stable.starts_with(crate::INDEX_CANDIDATE_PREFIX));
        assert!(publish.starts_with(crate::INDEX_CANDIDATE_PREFIX));
        assert_eq!(canonical.publish_staging_basename, publish);
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
        let publish = candidate_bundle_publish_basename_v5(TOKEN).expect("publish basename builds");
        assert_eq!(
            candidate_bundle_stable_path_v5(root.path(), &stable).expect("stable path validates"),
            root.local().join(&stable)
        );
        assert_eq!(
            candidate_bundle_scratch_path_v5(root.path(), &scratch)
                .expect("scratch path validates"),
            root.local().join(&scratch)
        );
        assert_eq!(
            candidate_bundle_publish_path_v5(root.path(), &publish)
                .expect("publish path validates"),
            root.local().join(&publish)
        );
        assert!(stable.starts_with(crate::INDEX_CANDIDATE_PREFIX));
        assert!(publish.starts_with(crate::INDEX_CANDIDATE_PREFIX));
        assert!(candidate_bundle_stable_basename_v5(&TOKEN.to_uppercase()).is_err());
        assert!(candidate_bundle_scratch_basename_v5("../candidate").is_err());
        assert!(candidate_bundle_stable_path_v5(root.path(), &scratch).is_err());
        assert!(candidate_bundle_scratch_path_v5(root.path(), &stable).is_err());
        assert!(candidate_bundle_publish_path_v5(root.path(), &stable).is_err());

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
    fn stable_bundle_namespace_coexists_with_retained_scratch() {
        let root = TestRoot::new();
        let (basename, _, _) = install_bundle(&root, TOKEN);
        let scratch = candidate_bundle_scratch_basename_v5("11111111111111111111111111111111")
            .expect("scratch basename builds");
        fs::write(root.local().join(&scratch), b"retained partial scratch")
            .expect("scratch writes");
        let status = inspect_candidate_bundle_namespace_v5(root.path())
            .expect("v5 namespace inspection succeeds without opening Git");
        assert_eq!(
            status.stable_bundle_basename.as_deref(),
            Some(basename.as_str())
        );
        assert_eq!(status.retained_scratch_count, 1);
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
    fn publish_namespace_reports_one_exact_name_and_rejects_aliases_or_multiples() {
        let root = TestRoot::new();
        let publish = candidate_bundle_publish_basename_v5(TOKEN).expect("publish name builds");
        fs::write(root.local().join(&publish), b"publish candidate").expect("publish file writes");
        let namespace = inspect_candidate_bundle_namespace_v5(root.path())
            .expect("one exact publish name inspects");
        assert_eq!(
            namespace.publish_staging_basename.as_deref(),
            Some(publish.as_str())
        );

        let second = candidate_bundle_publish_basename_v5("11111111111111111111111111111111")
            .expect("second publish name builds");
        fs::write(root.local().join(second), b"second publish").expect("second publish writes");
        assert!(inspect_candidate_bundle_namespace_v5(root.path()).is_err());

        for name in [
            format!("git-index-candidate-v4-PUBLISH-v5-{}", "2".repeat(32)),
            format!("{CANDIDATE_BUNDLE_PUBLISH_PREFIX_V5}short"),
        ] {
            let root = TestRoot::new();
            let path = root.local().join(&name);
            fs::write(&path, b"foreign publish alias").expect("publish alias writes");
            assert!(inspect_candidate_bundle_namespace_v5(root.path()).is_err());
            assert!(path.is_file());
        }
    }

    #[test]
    fn publish_move_error_reconciliation_distinguishes_retained_moved_and_ambiguous_state() {
        let injected = io::Error::new(io::ErrorKind::PermissionDenied, "injected move failure");

        let root = TestRoot::new();
        let source = root.local().join("retained-source");
        let destination = root.local().join("absent-destination");
        let retained = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source)
            .expect("retained source creates");
        assert!(matches!(
            reconcile_publish_move_error_v5(
                &root.local(),
                &source,
                &destination,
                &retained,
                &injected,
            ),
            GitError::Io {
                operation: GitIoOperation::WriteJournal,
                kind: io::ErrorKind::PermissionDenied,
            }
        ));

        fs::rename(&source, &destination).expect("source moves to exact destination");
        assert!(matches!(
            reconcile_publish_move_error_v5(
                &root.local(),
                &source,
                &destination,
                &retained,
                &injected,
            ),
            GitError::DurabilityNotConfirmed
        ));

        let root = TestRoot::new();
        let source = root.local().join("exact-source");
        let destination = root.local().join("foreign-destination");
        let exact = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source)
            .expect("exact source creates");
        fs::write(&destination, b"foreign owner").expect("foreign destination creates");
        assert!(matches!(
            reconcile_publish_move_error_v5(
                &root.local(),
                &source,
                &destination,
                &exact,
                &injected,
            ),
            GitError::RecoveryConflict
        ));
        assert!(source.is_file());
        assert_eq!(
            fs::read(destination).expect("foreign destination reads"),
            b"foreign owner"
        );
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

    #[test]
    fn postjournal_projection_protects_noncanonical_raw_unicode_aliases() {
        for (protected_path, alias) in [
            ("Å/Entry.md.enc", "A\u{30a}/entry.MD.ENC"),
            ("Straße/Entry.md.enc", "STRASSE/entry.md.enc"),
            ("Οσ/Entry.md.enc", "ος/ENTRY.MD.ENC"),
        ] {
            assert_eq!(
                raw_portable_case_fold_key(protected_path),
                raw_portable_case_fold_key(alias),
                "fixture must exercise one portable collision key"
            );
            let payload = MergeJournalPayload::InPlace(MergeJournal {
                version: 1,
                physical_path: protected_path.to_owned(),
                result_mode: "100644".to_owned(),
                stages: [None, None, None],
                expected_worktree_sha256: "00".repeat(32),
                result_oid: "11".repeat(20),
                result_sha256: "22".repeat(32),
            });
            let result = StageEntry {
                mode: "100644".to_owned(),
                oid: "11".repeat(20),
            };
            let candidate = BTreeMap::from([((protected_path.to_owned(), 0), result.clone())]);
            let protected = verify_final_candidate_projection_v5(&payload, &candidate)
                .expect("canonical final projection validates");
            let mut current = candidate.clone();
            current.insert((alias.to_owned(), 0), result);
            assert_ne!(
                protected_stage_projection_v5(&current, &protected),
                protected_stage_projection_v5(&candidate, &protected),
                "raw alias must remain inside the protected transaction projection"
            );
        }
    }
}
