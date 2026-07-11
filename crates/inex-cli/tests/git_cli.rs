//! Real-process Git driver, installation, and encrypted merge coverage.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use inex_core::format::ContentFlags;
use inex_core::path::{LogicalDir, LogicalPath};
use inex_core::sodium::Argon2idParams;
use inex_core::vault::Vault;
use inex_core::vault_config::KdfPolicy;

const PASSWORD: &[u8] = b"git integration password";
static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "inex-git-cli-{label}-{}-{nanos}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("test directory creation failed: {error}"));
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

fn create_repository(initial: &[u8]) -> (TestDirectory, LogicalPath) {
    let directory = TestDirectory::new("repo");
    git(directory.path(), ["init", "-q"]);
    git(
        directory.path(),
        ["config", "user.email", "inex-tests@example.invalid"],
    );
    git(directory.path(), ["config", "user.name", "Inex Tests"]);
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
    .unwrap_or_else(|error| panic!("vault creation failed: {error}"));
    let logical = LogicalPath::parse_canonical("entry.md")
        .unwrap_or_else(|error| panic!("logical path failed: {error}"));
    vault
        .create_document(&logical, initial, 1_783_699_201_000)
        .unwrap_or_else(|error| panic!("initial document failed: {error}"));
    drop(vault);
    fs::write(
        directory.path().join(".gitattributes"),
        b"# retained attributes\n",
    )
    .unwrap_or_else(|error| panic!("existing attributes write failed: {error}"));
    fs::write(directory.path().join(".gitignore"), b"# retained ignore\n")
        .unwrap_or_else(|error| panic!("existing ignore write failed: {error}"));

    let installed = Command::new(env!("CARGO_BIN_EXE_inex"))
        .args([OsString::from("git"), OsString::from("install-driver")])
        .arg(directory.path())
        .output()
        .unwrap_or_else(|error| panic!("installer spawn failed: {error}"));
    assert!(
        installed.status.success(),
        "installer stderr: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(String::from_utf8_lossy(&installed.stdout).contains("repository-local"));
    let driver = git_output(
        directory.path(),
        ["config", "--local", "--get", "merge.inex.driver"],
    );
    let driver = std::str::from_utf8(&driver.stdout)
        .unwrap_or_else(|error| panic!("driver config UTF-8 failed: {error}"));
    let canonical_binary = fs::canonicalize(env!("CARGO_BIN_EXE_inex"))
        .unwrap_or_else(|error| panic!("test binary canonicalization failed: {error}"));
    assert!(driver.contains(canonical_binary.to_string_lossy().as_ref()));
    assert!(driver.ends_with("' merge-driver\n"));
    assert!(!driver.contains('%'));
    assert_eq!(
        fs::read_to_string(directory.path().join(".gitattributes"))
            .unwrap_or_else(|error| panic!("attributes read failed: {error}")),
        "# retained attributes\n*.md.enc -text -diff merge=inex\n"
    );
    assert_eq!(
        fs::read_to_string(directory.path().join(".gitignore"))
            .unwrap_or_else(|error| panic!("ignore read failed: {error}")),
        "# retained ignore\n/.vault-local/\n"
    );
    let reinstalled = Command::new(env!("CARGO_BIN_EXE_inex"))
        .args([OsString::from("git"), OsString::from("install-driver")])
        .arg(directory.path())
        .output()
        .unwrap_or_else(|error| panic!("reinstaller spawn failed: {error}"));
    assert!(reinstalled.status.success());
    assert!(
        String::from_utf8_lossy(&reinstalled.stdout).contains("gitattributes: already-configured")
    );
    assert!(String::from_utf8_lossy(&reinstalled.stdout).contains("gitignore: already-configured"));
    git(directory.path(), ["add", "--all"]);
    git(directory.path(), ["commit", "-q", "-m", "baseline"]);
    (directory, logical)
}

fn save(directory: &Path, logical: &LogicalPath, plaintext: &[u8], timestamp: i64) {
    let mut vault = Vault::unlock(directory, PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("vault unlock failed: {error}"));
    let current = vault
        .read(logical)
        .unwrap_or_else(|error| panic!("document read failed: {error}"));
    let etag = current.etag.clone();
    drop(current);
    vault
        .save_document(logical, plaintext, &etag, timestamp)
        .unwrap_or_else(|error| panic!("document save failed: {error}"));
}

fn git<const N: usize>(root: &Path, arguments: [&str; N]) {
    let output = git_output(root, arguments);
    assert!(
        output.status.success(),
        "git stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output<const N: usize>(root: &Path, arguments: [&str; N]) -> Output {
    Command::new("git")
        .current_dir(root)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("git spawn failed: {error}"))
}

fn git_merge_with_inex(root: &Path, branch: &str) -> Output {
    Command::new("git")
        .current_dir(root)
        .args(["merge", "--no-edit", branch])
        .output()
        .unwrap_or_else(|error| panic!("git merge spawn failed: {error}"))
}

fn run_unlocked_merge(root: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_inex"))
        .args(["git", "merge"])
        .arg(root)
        .env("INEX_PASSWORD_STDIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("unlocked merge spawn failed: {error}"));
    let mut stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("merge stdin was not piped"));
    stdin
        .write_all(PASSWORD)
        .and_then(|()| stdin.write_all(b"\n"))
        .unwrap_or_else(|error| panic!("password write failed: {error}"));
    drop(stdin);
    child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("unlocked merge wait failed: {error}"))
}

fn scan_for_canary(root: &Path, canary: &[u8]) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut matches = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("residue directory read failed: {error}"))
        {
            let entry = entry.unwrap_or_else(|error| panic!("residue entry failed: {error}"));
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("residue type failed: {error}"));
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let bytes = fs::read(entry.path())
                    .unwrap_or_else(|error| panic!("residue file read failed: {error}"));
                if bytes.windows(canary.len()).any(|window| window == canary) {
                    matches.push(entry.path());
                }
            }
        }
    }
    matches
}

#[test]
fn locked_driver_never_reads_or_changes_any_input() {
    let directory = TestDirectory::new("driver");
    let current = directory.path().join("current.md.enc");
    fs::write(&current, b"ciphertext sentinel")
        .unwrap_or_else(|error| panic!("sentinel write failed: {error}"));
    let before = fs::metadata(&current).unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let output = Command::new(env!("CARGO_BIN_EXE_inex"))
        .arg("merge-driver")
        .arg(directory.path().join("missing-ancestor"))
        .arg(&current)
        .arg(directory.path().join("missing-incoming"))
        .arg(directory.path().join("missing-logical"))
        .output()
        .unwrap_or_else(|error| panic!("driver spawn failed: {error}"));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fs::read(&current).unwrap_or_else(|error| panic!("sentinel read failed: {error}")),
        b"ciphertext sentinel"
    );
    let after = fs::metadata(&current).unwrap_or_else(|error| panic!("metadata failed: {error}"));
    assert_eq!(before.len(), after.len());
    assert_eq!(
        before.permissions().readonly(),
        after.permissions().readonly()
    );
    assert_eq!(before.modified().ok(), after.modified().ok());
    assert!(!directory.path().join(".vault-local").exists());
}

#[test]
fn installer_rejects_higher_precedence_attribute_override() {
    let (directory, _) = create_repository(b"baseline\n");
    fs::write(
        directory.path().join(".git/info/attributes"),
        b"*.md.enc merge=unexpected\n",
    )
    .unwrap_or_else(|error| panic!("info attributes write failed: {error}"));
    let output = Command::new(env!("CARGO_BIN_EXE_inex"))
        .args([OsString::from("git"), OsString::from("install-driver")])
        .arg(directory.path())
        .output()
        .unwrap_or_else(|error| panic!("installer spawn failed: {error}"));
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("effective Git attributes do not select")
    );

    fs::remove_file(directory.path().join(".git/info/attributes"))
        .unwrap_or_else(|error| panic!("info attributes cleanup failed: {error}"));
    let mut vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("nested override unlock failed: {error}"));
    let notes = LogicalDir::parse_canonical("notes")
        .unwrap_or_else(|error| panic!("notes path failed: {error}"));
    vault
        .create_directory(&notes)
        .unwrap_or_else(|error| panic!("notes directory failed: {error}"));
    let nested = LogicalPath::parse_canonical("notes/nested.md")
        .unwrap_or_else(|error| panic!("nested path failed: {error}"));
    vault
        .create_document(&nested, b"nested\n", 1_783_699_205_000)
        .unwrap_or_else(|error| panic!("nested document failed: {error}"));
    drop(vault);
    fs::write(
        directory.path().join("notes/.gitattributes"),
        b"*.md.enc merge=unexpected\n",
    )
    .unwrap_or_else(|error| panic!("nested attributes write failed: {error}"));
    let nested_output = Command::new(env!("CARGO_BIN_EXE_inex"))
        .args([OsString::from("git"), OsString::from("install-driver")])
        .arg(directory.path())
        .output()
        .unwrap_or_else(|error| panic!("nested installer spawn failed: {error}"));
    assert!(!nested_output.status.success());
    assert!(
        String::from_utf8_lossy(&nested_output.stderr)
            .contains("effective Git attributes do not select")
    );
}

#[test]
fn unlocked_clean_merge_stages_only_authenticated_ciphertext() {
    const OURS: &[u8] = b"INEX_CLEAN_OURS_CANARY_95A1\nbase\n";
    const THEIRS: &[u8] = b"base\nINEX_CLEAN_THEIRS_CANARY_41B7\n";
    let (directory, logical) = create_repository(b"base\n");
    git(directory.path(), ["checkout", "-q", "-b", "ours"]);
    save(directory.path(), &logical, OURS, 1_783_699_202_000);
    git(directory.path(), ["add", "entry.md.enc"]);
    git(directory.path(), ["commit", "-q", "-m", "ours"]);
    git(directory.path(), ["checkout", "-q", "master"]);
    git(directory.path(), ["checkout", "-q", "-b", "theirs"]);
    save(directory.path(), &logical, THEIRS, 1_783_699_203_000);
    git(directory.path(), ["add", "entry.md.enc"]);
    git(directory.path(), ["commit", "-q", "-m", "theirs"]);
    git(directory.path(), ["checkout", "-q", "ours"]);

    assert!(
        !git_merge_with_inex(directory.path(), "theirs")
            .status
            .success()
    );
    assert!(
        !git_output(directory.path(), ["ls-files", "-u"])
            .stdout
            .is_empty()
    );
    let merged = run_unlocked_merge(directory.path());
    assert!(
        merged.status.success(),
        "merge stderr: {}",
        String::from_utf8_lossy(&merged.stderr)
    );
    assert!(
        git_output(directory.path(), ["ls-files", "-u"])
            .stdout
            .is_empty()
    );

    let vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("post-merge unlock failed: {error}"));
    let document = vault
        .read(&logical)
        .unwrap_or_else(|error| panic!("post-merge read failed: {error}"));
    assert_eq!(
        document.plaintext.as_slice(),
        b"INEX_CLEAN_OURS_CANARY_95A1\nbase\nINEX_CLEAN_THEIRS_CANARY_41B7\n"
    );
    assert!(
        !document
            .header
            .content_flags
            .contains(ContentFlags::UNRESOLVED_MERGE)
    );
    assert!(scan_for_canary(directory.path(), b"INEX_CLEAN_OURS_CANARY_95A1").is_empty());
    assert!(scan_for_canary(directory.path(), b"INEX_CLEAN_THEIRS_CANARY_41B7").is_empty());
}

#[test]
fn unlocked_conflict_result_is_flagged_encrypted_and_staged() {
    const OURS: &[u8] = b"INEX_CONFLICT_OURS_CANARY_D93C\n";
    const THEIRS: &[u8] = b"INEX_CONFLICT_THEIRS_CANARY_701E\n";
    let (directory, logical) = create_repository(b"base\n");
    git(directory.path(), ["checkout", "-q", "-b", "ours"]);
    save(directory.path(), &logical, OURS, 1_783_699_202_000);
    git(directory.path(), ["add", "entry.md.enc"]);
    git(directory.path(), ["commit", "-q", "-m", "ours"]);
    git(directory.path(), ["checkout", "-q", "master"]);
    git(directory.path(), ["checkout", "-q", "-b", "theirs"]);
    save(directory.path(), &logical, THEIRS, 1_783_699_203_000);
    git(directory.path(), ["add", "entry.md.enc"]);
    git(directory.path(), ["commit", "-q", "-m", "theirs"]);
    git(directory.path(), ["checkout", "-q", "ours"]);

    assert!(
        !git_merge_with_inex(directory.path(), "theirs")
            .status
            .success()
    );
    let merged = run_unlocked_merge(directory.path());
    assert_eq!(merged.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&merged.stdout).contains("unresolved-encrypted-results: 1"));
    assert!(
        git_output(directory.path(), ["ls-files", "-u"])
            .stdout
            .is_empty()
    );

    let mut vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("post-merge unlock failed: {error}"));
    let document = vault
        .read(&logical)
        .unwrap_or_else(|error| panic!("post-merge read failed: {error}"));
    assert!(
        document
            .header
            .content_flags
            .contains(ContentFlags::UNRESOLVED_MERGE)
    );
    let plaintext = std::str::from_utf8(document.plaintext.as_slice())
        .unwrap_or_else(|error| panic!("merge result UTF-8 failed: {error}"));
    assert!(plaintext.contains("<<<<<<< ours"));
    assert!(plaintext.contains("||||||| original"));
    assert!(plaintext.contains(">>>>>>> theirs"));
    assert!(scan_for_canary(directory.path(), b"INEX_CONFLICT_OURS_CANARY_D93C").is_empty());
    assert!(scan_for_canary(directory.path(), b"INEX_CONFLICT_THEIRS_CANARY_701E").is_empty());

    let conflicted_etag = document.etag.clone();
    drop(document);
    vault
        .save_document(
            &logical,
            b"INEX_RESOLVED_CANARY_11F9\n",
            &conflicted_etag,
            1_783_699_204_000,
        )
        .unwrap_or_else(|error| panic!("resolved save failed: {error}"));
    let resolved = vault
        .read(&logical)
        .unwrap_or_else(|error| panic!("resolved read failed: {error}"));
    assert!(
        !resolved
            .header
            .content_flags
            .contains(ContentFlags::UNRESOLVED_MERGE)
    );
    assert!(scan_for_canary(directory.path(), b"INEX_RESOLVED_CANARY_11F9").is_empty());
}

#[test]
fn unlocked_add_add_uses_empty_ancestor_without_plaintext_artifacts() {
    const OURS: &[u8] = b"INEX_ADD_OURS_CANARY_2C61\n";
    const THEIRS: &[u8] = b"INEX_ADD_THEIRS_CANARY_E405\n";
    let (directory, _) = create_repository(b"baseline\n");
    let added = LogicalPath::parse_canonical("added.md")
        .unwrap_or_else(|error| panic!("logical path failed: {error}"));
    git(directory.path(), ["checkout", "-q", "-b", "ours"]);
    let mut vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("ours unlock failed: {error}"));
    vault
        .create_document(&added, OURS, 1_783_699_202_000)
        .unwrap_or_else(|error| panic!("ours create failed: {error}"));
    drop(vault);
    git(directory.path(), ["add", "added.md.enc"]);
    git(directory.path(), ["commit", "-q", "-m", "ours add"]);
    git(directory.path(), ["checkout", "-q", "master"]);
    git(directory.path(), ["checkout", "-q", "-b", "theirs"]);
    let mut vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("theirs unlock failed: {error}"));
    vault
        .create_document(&added, THEIRS, 1_783_699_203_000)
        .unwrap_or_else(|error| panic!("theirs create failed: {error}"));
    drop(vault);
    git(directory.path(), ["add", "added.md.enc"]);
    git(directory.path(), ["commit", "-q", "-m", "theirs add"]);
    git(directory.path(), ["checkout", "-q", "ours"]);

    assert!(
        !git_merge_with_inex(directory.path(), "theirs")
            .status
            .success()
    );
    let merged = run_unlocked_merge(directory.path());
    assert_eq!(merged.status.code(), Some(1));
    assert!(
        git_output(directory.path(), ["ls-files", "-u"])
            .stdout
            .is_empty()
    );
    let vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("post-merge unlock failed: {error}"));
    let document = vault
        .read(&added)
        .unwrap_or_else(|error| panic!("post-merge read failed: {error}"));
    assert!(
        document
            .header
            .content_flags
            .contains(ContentFlags::UNRESOLVED_MERGE)
    );
    assert!(scan_for_canary(directory.path(), b"INEX_ADD_OURS_CANARY_2C61").is_empty());
    assert!(scan_for_canary(directory.path(), b"INEX_ADD_THEIRS_CANARY_E405").is_empty());
}

#[test]
fn unlocked_delete_modify_conflict_replaces_only_expected_ciphertext() {
    const BASE: &[u8] = b"INEX_DELETE_BASE_CANARY_39F2\n";
    const THEIRS: &[u8] = b"INEX_DELETE_MODIFIED_CANARY_A877\n";
    let (directory, logical) = create_repository(BASE);
    git(directory.path(), ["checkout", "-q", "-b", "ours"]);
    let mut vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("delete unlock failed: {error}"));
    let current = vault
        .read(&logical)
        .unwrap_or_else(|error| panic!("delete read failed: {error}"));
    vault
        .delete_document(&logical, &current.etag)
        .unwrap_or_else(|error| panic!("delete failed: {error}"));
    drop(current);
    drop(vault);
    git(directory.path(), ["add", "-u"]);
    git(directory.path(), ["commit", "-q", "-m", "ours delete"]);
    git(directory.path(), ["checkout", "-q", "master"]);
    git(directory.path(), ["checkout", "-q", "-b", "theirs"]);
    save(directory.path(), &logical, THEIRS, 1_783_699_203_000);
    git(directory.path(), ["add", "entry.md.enc"]);
    git(directory.path(), ["commit", "-q", "-m", "theirs modify"]);
    git(directory.path(), ["checkout", "-q", "ours"]);

    assert!(
        !git_merge_with_inex(directory.path(), "theirs")
            .status
            .success()
    );
    let merged = run_unlocked_merge(directory.path());
    assert_eq!(merged.status.code(), Some(1));
    assert!(
        git_output(directory.path(), ["ls-files", "-u"])
            .stdout
            .is_empty()
    );
    let vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("post-merge unlock failed: {error}"));
    let document = vault
        .read(&logical)
        .unwrap_or_else(|error| panic!("post-merge read failed: {error}"));
    assert!(
        document
            .header
            .content_flags
            .contains(ContentFlags::UNRESOLVED_MERGE)
    );
    assert!(scan_for_canary(directory.path(), b"INEX_DELETE_BASE_CANARY_39F2").is_empty());
    assert!(scan_for_canary(directory.path(), b"INEX_DELETE_MODIFIED_CANARY_A877").is_empty());
}

#[test]
fn cross_path_rename_modify_is_detected_and_left_untouched() {
    let (directory, old_path) = create_repository(b"rename base\n");
    let new_path = LogicalPath::parse_canonical("renamed.md")
        .unwrap_or_else(|error| panic!("renamed path failed: {error}"));
    git(directory.path(), ["checkout", "-q", "-b", "ours"]);
    let mut vault = Vault::unlock(directory.path(), PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("rename unlock failed: {error}"));
    let current = vault
        .read(&old_path)
        .unwrap_or_else(|error| panic!("rename read failed: {error}"));
    vault
        .rename_document(&old_path, &new_path, &current.etag, 1_783_699_202_000)
        .unwrap_or_else(|error| panic!("rename failed: {error}"));
    drop(current);
    drop(vault);
    git(directory.path(), ["add", "--all"]);
    git(directory.path(), ["commit", "-q", "-m", "ours rename"]);
    git(directory.path(), ["checkout", "-q", "master"]);
    git(directory.path(), ["checkout", "-q", "-b", "theirs"]);
    save(
        directory.path(),
        &old_path,
        b"rename modified on theirs\n",
        1_783_699_203_000,
    );
    git(directory.path(), ["add", "entry.md.enc"]);
    git(directory.path(), ["commit", "-q", "-m", "theirs modify"]);
    git(directory.path(), ["checkout", "-q", "ours"]);
    assert!(
        !git_merge_with_inex(directory.path(), "theirs")
            .status
            .success()
    );
    let old_ciphertext = fs::read(directory.path().join("entry.md.enc"))
        .unwrap_or_else(|error| panic!("old conflict read failed: {error}"));
    let new_ciphertext = fs::read(directory.path().join("renamed.md.enc"))
        .unwrap_or_else(|error| panic!("renamed read failed: {error}"));

    let merged = run_unlocked_merge(directory.path());
    assert!(!merged.status.success());
    assert!(
        String::from_utf8_lossy(&merged.stderr).contains("unsupported encrypted conflict entry")
    );
    assert!(
        !git_output(directory.path(), ["ls-files", "-u"])
            .stdout
            .is_empty()
    );
    assert_eq!(
        fs::read(directory.path().join("entry.md.enc"))
            .unwrap_or_else(|error| panic!("old post-state read failed: {error}")),
        old_ciphertext
    );
    assert_eq!(
        fs::read(directory.path().join("renamed.md.enc"))
            .unwrap_or_else(|error| panic!("new post-state read failed: {error}")),
        new_ciphertext
    );
    assert!(
        !directory
            .path()
            .join(".vault-local/git-merge-journal-v1.json")
            .exists()
    );
}
