#![cfg(target_os = "linux")]

//! Real-process clean-HEAD repository-import coverage.

use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use inex_core::atomic::{
    IMPORT_PUBLISH_MARKER_V1, IMPORT_PUBLISH_MARKER_V2, VAULT_LOCAL_DIRECTORY,
};
use inex_core::path::{AssetPath, LogicalPath};
use inex_core::vault::Vault;
use inex_core::vault_config::KdfPolicy;

const PASSWORD: &[u8] = b"repository import integration password";
static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "inex-repository-import-{label}-{}-{nanos}-{counter}",
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

fn git(root: &Path, arguments: &[&str]) -> Output {
    let output = Command::new("git")
        .current_dir(root)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap_or_else(|error| panic!("git spawn failed: {error}"));
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn null_device() -> &'static OsStr {
    OsStr::new(if cfg!(windows) { "NUL" } else { "/dev/null" })
}

fn init_repository(root: &Path) {
    fs::create_dir(root).unwrap_or_else(|error| panic!("source creation failed: {error}"));
    git(root, &["init", "-q", "--initial-branch=main"]);
}

fn commit_all(root: &Path, message: &str) {
    git(root, &["add", "--all"]);
    git(
        root,
        &[
            "-c",
            "user.email=repository-import@example.invalid",
            "-c",
            "user.name=Repository Import Tests",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "-q",
            "-m",
            message,
        ],
    );
}

fn run_import(source: &Path, destination: &Path, dry_run: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_inex"));
    command
        .arg("import-repository")
        .arg(source)
        .arg(destination)
        .env(
            "INEX_PASSWORD_STDIN",
            if dry_run { "invalid-on-purpose" } else { "1" },
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if dry_run {
        command.arg("--dry-run");
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("inex spawn failed: {error}"));
    if dry_run {
        drop(child.stdin.take());
    } else {
        let mut stdin = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("inex stdin was not piped"));
        for _ in 0..2 {
            stdin
                .write_all(PASSWORD)
                .and_then(|()| stdin.write_all(b"\n"))
                .unwrap_or_else(|error| panic!("password write failed: {error}"));
        }
        drop(stdin);
    }
    child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("inex wait failed: {error}"))
}

fn assert_rejected_without_target(source: &Path, destination: &Path) {
    let output = run_import(source, destination, true);
    assert!(
        !output.status.success(),
        "unsafe source unexpectedly passed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!destination.exists());
}

fn run_import_without_password(source: &Path, destination: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_inex"))
        .arg("import-repository")
        .arg(source)
        .arg(destination)
        .env("INEX_PASSWORD_STDIN", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error| panic!("inex spawn failed: {error}"))
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn trustworthy_plan_password_failure_reports_last_proven_terminal_state() {
    let temporary = TestDirectory::new("password-terminal");
    let source = temporary.path().join("source");
    let destination = temporary.path().join("vault");
    init_repository(&source);
    fs::write(source.join("journal.md"), b"# Existing journal\n")
        .unwrap_or_else(|error| panic!("Markdown write failed: {error}"));
    commit_all(&source, "plaintext source");

    let output = run_import_without_password(&source, &destination);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("stdout UTF-8 failed: {error}"));
    for field in [
        "candidate-root: not-created",
        "vault-publication: not-published",
        "git-repository: not-created",
        "recovery-required: none",
    ] {
        assert_eq!(
            stdout.matches(field).count(),
            1,
            "missing terminal field: {field}"
        );
    }
    assert!(!destination.exists());
    assert_eq!(git(&source, &["status", "--porcelain"]).stdout, b"");
}

#[test]
#[allow(clippy::too_many_lines)]
fn imports_current_snapshot_into_one_parentless_ciphertext_commit() {
    let temporary = TestDirectory::new("success");
    let source = temporary.path().join("source");
    let destination = temporary.path().join("vault");
    init_repository(&source);

    let markdown_v1 = b"# Existing journal\nfirst committed version\n";
    fs::write(source.join("journal.md"), markdown_v1)
        .unwrap_or_else(|error| panic!("Markdown write failed: {error}"));
    commit_all(&source, "first plaintext commit");

    let markdown_v2 = b"# Existing journal\nsecond committed version\r\n";
    let image = b"\x89PNG\r\n\x1a\nrepository-import-image-canary";
    let json = br#"{"kind":"repository-import-json-canary"}"#;
    let source_ignore = b"local-only-pattern\n";
    let decomposed_markdown_path = "cafe\u{301}.md";
    let canonical_markdown_path = "caf\u{e9}.md";
    let decomposed_markdown = b"# Unicode path\nnormalized-import-canary\n";
    fs::write(source.join("journal.md"), markdown_v2)
        .unwrap_or_else(|error| panic!("Markdown update failed: {error}"));
    fs::create_dir(source.join("images"))
        .unwrap_or_else(|error| panic!("images directory failed: {error}"));
    fs::write(source.join("images/field.png"), image)
        .unwrap_or_else(|error| panic!("image write failed: {error}"));
    fs::write(source.join("settings.json"), json)
        .unwrap_or_else(|error| panic!("JSON write failed: {error}"));
    fs::write(source.join(".gitignore"), source_ignore)
        .unwrap_or_else(|error| panic!("source ignore write failed: {error}"));
    fs::write(source.join(decomposed_markdown_path), decomposed_markdown)
        .unwrap_or_else(|error| panic!("decomposed Markdown write failed: {error}"));
    commit_all(&source, "second plaintext commit");

    let source_head = String::from_utf8(git(&source, &["rev-parse", "HEAD"]).stdout)
        .unwrap_or_else(|error| panic!("source HEAD UTF-8 failed: {error}"));
    let source_commit_count = git(&source, &["rev-list", "--all", "--count"]).stdout;

    let dry_run = run_import(&source, &destination, true);
    assert!(
        dry_run.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_stdout = String::from_utf8(dry_run.stdout)
        .unwrap_or_else(|error| panic!("dry-run stdout UTF-8 failed: {error}"));
    assert!(dry_stdout.contains("import-mode: repository-dry-run"));
    assert!(dry_stdout.contains("source-tree-entries: 5"));
    assert!(dry_stdout.contains("markdown-files: 2"));
    assert!(dry_stdout.contains("asset-files: 3"));
    assert!(dry_stdout.contains("normalized-path-entries: 1"));
    assert!(dry_stdout.contains("password-prompted: no"));
    assert!(dry_stdout.contains("import-writes: none"));
    assert!(!destination.exists());

    let imported = run_import(&source, &destination, false);
    assert!(
        imported.status.success(),
        "import failed: {}\n{}",
        String::from_utf8_lossy(&imported.stdout),
        String::from_utf8_lossy(&imported.stderr)
    );
    let stdout = String::from_utf8(imported.stdout)
        .unwrap_or_else(|error| panic!("import stdout UTF-8 failed: {error}"));
    assert!(stdout.contains("result: repository import complete"));
    assert!(stdout.contains("committed-encrypted-markdown: 2"));
    assert!(stdout.contains("committed-encrypted-assets: 3"));
    assert!(stdout.contains("git-root-parent-count: 0"));
    assert!(stdout.contains("candidate-plaintext-file-objects: 0"));
    assert!(
        !destination
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V1)
            .exists()
    );
    assert!(
        !destination
            .join(VAULT_LOCAL_DIRECTORY)
            .join(IMPORT_PUBLISH_MARKER_V2)
            .exists()
    );
    assert!(destination.join("journal.md.enc").is_file());
    assert!(
        destination
            .join(format!("{canonical_markdown_path}.enc"))
            .is_file()
    );
    assert!(
        !destination
            .join(format!("{decomposed_markdown_path}.enc"))
            .exists()
    );
    assert!(destination.join("images/field.png.asset.enc").is_file());
    assert!(destination.join("settings.json.asset.enc").is_file());
    assert!(destination.join(".gitignore.asset.enc").is_file());
    assert!(destination.join(".gitignore").is_file());
    assert!(!destination.join("journal.md").exists());
    assert!(!destination.join("images/field.png").exists());

    let mut vault = Vault::unlock(&destination, PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("target unlock failed: {error}"));
    let markdown_path = LogicalPath::parse_canonical("journal.md")
        .unwrap_or_else(|error| panic!("Markdown path failed: {error}"));
    let recovered_markdown = vault
        .read(&markdown_path)
        .unwrap_or_else(|error| panic!("Markdown recovery failed: {error}"));
    assert_eq!(recovered_markdown.plaintext.as_slice(), markdown_v2);
    let normalized_path = LogicalPath::parse_canonical(canonical_markdown_path)
        .unwrap_or_else(|error| panic!("normalized Markdown path failed: {error}"));
    let recovered_normalized = vault
        .read(&normalized_path)
        .unwrap_or_else(|error| panic!("normalized Markdown recovery failed: {error}"));
    assert_eq!(
        recovered_normalized.plaintext.as_slice(),
        decomposed_markdown
    );
    for (path, expected) in [
        ("images/field.png", image.as_slice()),
        ("settings.json", json.as_slice()),
        (".gitignore", source_ignore.as_slice()),
    ] {
        let path = AssetPath::parse_canonical(path)
            .unwrap_or_else(|error| panic!("asset path failed: {error}"));
        let recovered = vault
            .read_asset(&path)
            .unwrap_or_else(|error| panic!("asset recovery failed: {error}"));
        assert_eq!(recovered.plaintext.as_slice(), expected);
    }
    drop(vault);

    let target_commit =
        String::from_utf8(git(&destination, &["rev-list", "--parents", "-n", "1", "HEAD"]).stdout)
            .unwrap_or_else(|error| panic!("target commit UTF-8 failed: {error}"));
    assert_eq!(target_commit.split_whitespace().count(), 1);
    assert!(stdout.contains(&format!("git-root-commit: {}", target_commit.trim())));
    assert_eq!(
        git(&destination, &["rev-list", "--all", "--count"]).stdout,
        b"1\n"
    );
    let target_files =
        String::from_utf8(git(&destination, &["-c", "core.quotePath=false", "ls-files"]).stdout)
            .unwrap_or_else(|error| panic!("target files UTF-8 failed: {error}"));
    assert!(target_files.contains("journal.md.enc\n"));
    assert!(target_files.contains(&format!("{canonical_markdown_path}.enc\n")));
    assert!(!target_files.contains(&format!("{decomposed_markdown_path}.enc\n")));
    assert!(target_files.contains("images/field.png.asset.enc\n"));
    assert!(!target_files.lines().any(|line| line == "journal.md"));
    assert!(!target_files.lines().any(|line| line == "images/field.png"));
    assert_eq!(git(&destination, &["status", "--porcelain"]).stdout, b"");

    let objects = git(
        &destination,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype)",
        ],
    );
    let objects = String::from_utf8(objects.stdout)
        .unwrap_or_else(|error| panic!("target object inventory UTF-8 failed: {error}"));
    assert!(
        !objects
            .lines()
            .any(|line| line.starts_with(source_head.trim()))
    );
    for line in objects.lines() {
        let mut fields = line.split_ascii_whitespace();
        let oid = fields
            .next()
            .unwrap_or_else(|| panic!("target object record omitted oid"));
        let kind = fields
            .next()
            .unwrap_or_else(|| panic!("target object record omitted type"));
        assert!(fields.next().is_none(), "unexpected target object fields");
        let body = git(&destination, &["cat-file", kind, oid]).stdout;
        for canary in [
            b"second committed version".as_slice(),
            b"repository-import-image-canary".as_slice(),
            b"repository-import-json-canary".as_slice(),
            b"normalized-import-canary".as_slice(),
            b"local-only-pattern".as_slice(),
        ] {
            assert!(
                !contains_subslice(&body, canary),
                "target object {oid} retained a source plaintext canary"
            );
        }
    }

    assert_eq!(
        git(&source, &["rev-parse", "HEAD"]).stdout,
        source_head.as_bytes()
    );
    assert_eq!(
        git(&source, &["rev-list", "--all", "--count"]).stdout,
        source_commit_count
    );
    assert_eq!(git(&source, &["status", "--porcelain"]).stdout, b"");
    assert_eq!(
        fs::read(source.join("journal.md"))
            .unwrap_or_else(|error| panic!("source Markdown reread failed: {error}")),
        markdown_v2
    );
    assert_eq!(
        fs::read(source.join("images/field.png"))
            .unwrap_or_else(|error| panic!("source image reread failed: {error}")),
        image
    );
    assert_eq!(
        fs::read(source.join(decomposed_markdown_path))
            .unwrap_or_else(|error| panic!("source decomposed Markdown reread failed: {error}")),
        decomposed_markdown
    );
}

#[test]
fn rejects_dirty_untracked_empty_directory_and_lfs_sources_before_destination_creation() {
    let temporary = TestDirectory::new("negative");

    let dirty = temporary.path().join("dirty");
    init_repository(&dirty);
    fs::write(dirty.join("note.md"), b"committed\n")
        .unwrap_or_else(|error| panic!("dirty baseline write failed: {error}"));
    commit_all(&dirty, "baseline");
    fs::write(dirty.join("note.md"), b"dirty\n")
        .unwrap_or_else(|error| panic!("dirty mutation write failed: {error}"));
    assert_rejected_without_target(&dirty, &temporary.path().join("dirty-target"));

    let untracked = temporary.path().join("untracked");
    init_repository(&untracked);
    fs::write(untracked.join("note.md"), b"committed\n")
        .unwrap_or_else(|error| panic!("untracked baseline write failed: {error}"));
    commit_all(&untracked, "baseline");
    fs::write(untracked.join("untracked.txt"), b"not allowed")
        .unwrap_or_else(|error| panic!("untracked entry write failed: {error}"));
    assert_rejected_without_target(&untracked, &temporary.path().join("untracked-target"));

    let empty_directory = temporary.path().join("empty-directory");
    init_repository(&empty_directory);
    fs::write(empty_directory.join("note.md"), b"committed\n")
        .unwrap_or_else(|error| panic!("empty-directory baseline write failed: {error}"));
    commit_all(&empty_directory, "baseline");
    fs::create_dir(empty_directory.join("untracked-empty"))
        .unwrap_or_else(|error| panic!("untracked empty directory failed: {error}"));
    assert_rejected_without_target(
        &empty_directory,
        &temporary.path().join("empty-directory-target"),
    );

    let lfs = temporary.path().join("lfs");
    init_repository(&lfs);
    fs::write(
        lfs.join("image.png"),
        b"version https://git-lfs.github.com/spec/v1\noid sha256:00\nsize 1\n",
    )
    .unwrap_or_else(|error| panic!("LFS pointer write failed: {error}"));
    commit_all(&lfs, "pointer");
    assert_rejected_without_target(&lfs, &temporary.path().join("lfs-target"));
}

#[cfg(unix)]
#[test]
fn rejects_tracked_symbolic_link_before_destination_creation() {
    use std::os::unix::fs::symlink;

    let temporary = TestDirectory::new("symlink");
    let source = temporary.path().join("source");
    init_repository(&source);
    fs::write(source.join("real.md"), b"real\n")
        .unwrap_or_else(|error| panic!("symlink target write failed: {error}"));
    symlink("real.md", source.join("alias.md"))
        .unwrap_or_else(|error| panic!("symlink creation failed: {error}"));
    commit_all(&source, "tracked link");
    assert_rejected_without_target(&source, &temporary.path().join("target"));
}
