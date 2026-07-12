//! Real-process copy-import coverage for the `inex` binary.

use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use inex_core::path::LogicalPath;
use inex_core::vault::Vault;
use inex_core::vault_config::KdfPolicy;

const PASSWORD: &[u8] = b"integration password";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "inex-cli-process-import-{}-{nanos}-{counter}",
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

fn run_import(source: &Path, vault: &Path, dry_run: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_inex"));
    command
        .arg("import")
        .arg(source)
        .arg(vault)
        .env("INEX_PASSWORD_STDIN", "1")
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
                .unwrap_or_else(|error| panic!("password write failed: {error}"));
            stdin
                .write_all(b"\n")
                .unwrap_or_else(|error| panic!("password terminator write failed: {error}"));
        }
        drop(stdin);
    }
    child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("inex wait failed: {error}"))
}

#[test]
fn dry_run_then_copy_import_preserves_source_and_commits_only_ciphertext() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    let notes = source.join("notes");
    fs::create_dir_all(&notes)
        .unwrap_or_else(|error| panic!("source directory creation failed: {error}"));
    let source_file = notes.join("entry.md");
    let source_bytes = b"# Process import\nplaintext canary stays in source\r\n";
    fs::write(&source_file, source_bytes)
        .unwrap_or_else(|error| panic!("source Markdown write failed: {error}"));
    fs::write(source.join("attachment.bin"), b"ignored bytes")
        .unwrap_or_else(|error| panic!("non-Markdown write failed: {error}"));
    let vault_path = directory.path().join("vault");

    let dry_run = run_import(&source, &vault_path, true);
    assert!(dry_run.status.success());
    let dry_stdout = String::from_utf8(dry_run.stdout)
        .unwrap_or_else(|error| panic!("dry-run stdout was not UTF-8: {error}"));
    assert!(dry_stdout.contains("import-mode: dry-run"));
    assert!(dry_stdout.contains("skipped-non-markdown-files: 1"));
    assert!(dry_stdout.contains("import-writes: none"));
    assert!(dry_stdout.contains("password-prompted: no"));
    assert!(dry_stdout.contains("destination-created: no"));
    assert!(!dry_stdout.contains("staging-vault:"));
    assert!(!vault_path.exists());

    let copied = run_import(&source, &vault_path, false);
    assert!(copied.status.success());
    let copy_stdout = String::from_utf8(copied.stdout)
        .unwrap_or_else(|error| panic!("copy stdout was not UTF-8: {error}"));
    assert!(copy_stdout.contains("import-mode: copy"));
    assert!(copy_stdout.contains("committed-encrypted-files: 1"));
    assert!(copy_stdout.contains("destination: published-new-vault"));
    assert!(copy_stdout.contains("source-preserved: yes"));
    assert_eq!(
        fs::read(&source_file).unwrap_or_else(|error| panic!("source reread failed: {error}")),
        source_bytes
    );
    assert!(!vault_path.join("notes/entry.md").exists());
    assert!(vault_path.join("notes/entry.md.enc").is_file());

    let vault = Vault::unlock(&vault_path, PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("post-import unlock failed: {error}"));
    let created_slot = &vault.config().key_slots[0];
    assert!((3..=20).contains(&created_slot.kdf.ops_limit));
    assert_eq!(created_slot.kdf.mem_limit_bytes, 64 * 1024 * 1024);
    let logical = LogicalPath::parse_canonical("notes/entry.md")
        .unwrap_or_else(|error| panic!("logical path failed: {error}"));
    let imported = vault
        .read(&logical)
        .unwrap_or_else(|error| panic!("imported document read failed: {error}"));
    assert_eq!(imported.plaintext.as_slice(), source_bytes);
}

#[test]
fn existing_destination_is_rejected_before_password_or_writes() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap_or_else(|error| panic!("source create failed: {error}"));
    fs::write(source.join("entry.md"), b"source")
        .unwrap_or_else(|error| panic!("source write failed: {error}"));
    let destination = directory.path().join("existing");
    fs::create_dir(&destination)
        .unwrap_or_else(|error| panic!("destination create failed: {error}"));
    fs::write(destination.join("sentinel"), b"unchanged")
        .unwrap_or_else(|error| panic!("sentinel write failed: {error}"));

    let output = run_import(&source, &destination, true);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(destination.join("sentinel"))
            .unwrap_or_else(|error| panic!("sentinel read failed: {error}")),
        b"unchanged"
    );
}

#[test]
fn process_rejects_git_injection_after_dedicated_stage_creation() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap_or_else(|error| panic!("source create failed: {error}"));
    let source_file = source.join("entry.md");
    fs::write(&source_file, b"source remains")
        .unwrap_or_else(|error| panic!("source write failed: {error}"));
    let destination = directory.path().join("vault");

    let mut child = Command::new(env!("CARGO_BIN_EXE_inex"))
        .arg("import")
        .arg(&source)
        .arg(&destination)
        .env("INEX_PASSWORD_STDIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("inex spawn failed: {error}"));
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

    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("inex stdout was not piped"));
    let mut stdout = BufReader::new(stdout);
    let mut transcript = String::new();
    let staging = loop {
        let mut line = String::new();
        let count = stdout
            .read_line(&mut line)
            .unwrap_or_else(|error| panic!("stdout read failed: {error}"));
        assert_ne!(
            count, 0,
            "process ended before revealing a created staging root"
        );
        transcript.push_str(&line);
        if let Some(name) = line.trim_end().strip_prefix("staging-vault: ") {
            let staging = directory.path().join(name);
            assert!(
                staging.is_dir(),
                "staging name must not be emitted before create-only reservation"
            );
            break staging;
        }
    };

    let injected = staging.join(".git");
    fs::create_dir(&injected).unwrap_or_else(|error| panic!("git injection failed: {error}"));
    fs::write(injected.join("plaintext.md"), b"must never publish")
        .unwrap_or_else(|error| panic!("plaintext injection failed: {error}"));
    stdout
        .read_to_string(&mut transcript)
        .unwrap_or_else(|error| panic!("stdout completion failed: {error}"));
    let status = child
        .wait()
        .unwrap_or_else(|error| panic!("inex wait failed: {error}"));
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap_or_else(|| panic!("inex stderr was not piped"))
        .read_to_string(&mut stderr)
        .unwrap_or_else(|error| panic!("stderr read failed: {error}"));

    assert!(!status.success(), "injected .git tree must fail import");
    assert!(!destination.exists());
    assert!(staging.is_dir());
    assert!(injected.join("plaintext.md").is_file());
    assert_eq!(
        fs::read(&source_file).unwrap_or_else(|error| panic!("source read failed: {error}")),
        b"source remains"
    );
    assert!(
        stderr.contains("staging") || stderr.contains("final destination was not published"),
        "unexpected scrubbed diagnostic: {stderr}"
    );
}
