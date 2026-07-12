use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use inex_core::atomic::{
    VAULT_LOCAL_DIRECTORY, filesystem_directory_identity, open_file_matches_path_and_is_single_link,
};
use serde::{Deserialize, Serialize};

use super::{
    GitError, GitIoOperation, GitObjectFormat, MAX_GIT_OUTPUT_BYTES, MAX_JOURNAL_BYTES,
    MergeJournalPayload, ascii_casefold_starts_with, digest, hex_digest, io_error,
    is_link_or_reparse_point, parse_duplicate_free_json, parse_hex_digest, payload_oids,
    payload_rename_provenance, validate_lock_token, validate_oid, validate_payload,
};

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

#[derive(Debug)]
pub(super) struct VerifiedCandidateBundleV5 {
    pub(super) manifest: CandidateBundleManifestV5,
    pub(super) manifest_reference: CandidateBundleManifestReferenceV5,
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
) -> Result<Vec<u8>, GitError> {
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
    Ok(bytes)
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

pub(super) fn validate_candidate_bundle_inventory_v5(
    root: &Path,
    bundle_basename: &str,
    expected_manifest_reference: Option<&CandidateBundleManifestReferenceV5>,
) -> Result<VerifiedCandidateBundleV5, GitError> {
    let bundle_path = candidate_bundle_stable_path_v5(root, bundle_basename)?;
    let token = parse_candidate_bundle_stable_basename_v5(bundle_basename)?;
    let directory_identity =
        filesystem_directory_identity(&bundle_path).map_err(|_| GitError::InvalidJournal)?;
    exact_bundle_members(&bundle_path)?;

    let manifest_path = bundle_path.join(CANDIDATE_BUNDLE_MANIFEST_V5);
    let manifest_bytes = read_single_link_regular(&manifest_path, MAX_JOURNAL_BYTES, false)?;
    let manifest = parse_candidate_bundle_manifest_v5(&manifest_bytes)?;
    if manifest.token != token || manifest.bundle_basename != bundle_basename {
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
    let candidate_bytes = read_single_link_regular(&candidate_path, MAX_GIT_OUTPUT_BYTES, false)?;
    if u64::try_from(candidate_bytes.len()).unwrap_or(u64::MAX) != manifest.candidate_member.size
        || hex_digest(digest(&candidate_bytes)) != manifest.candidate_member.sha256
    {
        return Err(GitError::InvalidJournal);
    }

    if filesystem_directory_identity(&bundle_path).map_err(|_| GitError::InvalidJournal)?
        != directory_identity
    {
        return Err(GitError::RecoveryConflict);
    }
    exact_bundle_members(&bundle_path)?;
    Ok(VerifiedCandidateBundleV5 {
        manifest,
        manifest_reference,
    })
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
            parse_candidate_bundle_scratch_basename_v5(&name)
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
        assert!(stable.starts_with(crate::INDEX_CANDIDATE_PREFIX));
        assert!(candidate_bundle_stable_basename_v5(&TOKEN.to_uppercase()).is_err());
        assert!(candidate_bundle_scratch_basename_v5("../candidate").is_err());
        assert!(candidate_bundle_stable_path_v5(root.path(), &scratch).is_err());

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
                "wrong-case" => fs::rename(
                    bundle.join(CANDIDATE_BUNDLE_MANIFEST_V5),
                    bundle.join("Manifest-v5.json"),
                )
                .expect("manifest case changes"),
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
