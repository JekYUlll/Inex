//! Real-process coverage for the explicit plaintext-export CLI boundary.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use inex_core::path::LogicalPath;
use inex_core::sodium::Argon2idParams;
use inex_core::vault::Vault;
use inex_core::vault_config::KdfPolicy;

const PASSWORD: &[u8] = b"export integration password";
static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "inex-cli-export-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("test root: {error}"));
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
        max_creation_ops_limit: 4,
        max_creation_mem_limit_bytes: 64 * 1024 * 1024,
        max_unlock_ops_limit: 4,
        max_unlock_mem_limit_bytes: 64 * 1024 * 1024,
    }
}

#[test]
fn explicit_outer_export_publishes_plaintext_only_after_test_confirmation() {
    let root = TestDirectory::new();
    let vault_path = root.path().join("vault");
    let exports = root.path().join("exports");
    fs::create_dir(&exports).unwrap_or_else(|error| panic!("exports root: {error}"));
    let mut vault = Vault::create_with_params(
        &vault_path,
        PASSWORD,
        1_783_699_200_000,
        Argon2idParams {
            ops_limit: 1,
            mem_limit_bytes: 8 * 1024,
        },
        test_policy(),
    )
    .unwrap_or_else(|error| panic!("vault fixture: {error}"));
    vault
        .create_directory(
            &inex_core::path::LogicalDir::parse_canonical("notes")
                .unwrap_or_else(|error| panic!("directory: {error}")),
        )
        .unwrap_or_else(|error| panic!("fixture directory: {error}"));
    vault
        .create_document(
            &LogicalPath::parse_canonical("notes/entry.md")
                .unwrap_or_else(|error| panic!("logical path: {error}")),
            b"# exported canary\n",
            1_783_699_201_000,
        )
        .unwrap_or_else(|error| panic!("fixture document: {error}"));
    drop(vault);

    let destination = exports.join("copy");
    let mut child = Command::new(env!("CARGO_BIN_EXE_inex"))
        .arg("export")
        .arg(&vault_path)
        .arg(&destination)
        .arg("--scope")
        .arg("outer")
        .env("INEX_PASSWORD_STDIN", "1")
        .env("INEX_EXPORT_TEST_CONFIRM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("inex spawn: {error}"));
    let mut stdin = child.stdin.take().unwrap_or_else(|| panic!("stdin"));
    stdin
        .write_all(PASSWORD)
        .and_then(|()| stdin.write_all(b"\n"))
        .unwrap_or_else(|error| panic!("password input: {error}"));
    drop(stdin);
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("inex output: {error}"));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(destination.join("notes/entry.md"))
            .unwrap_or_else(|error| panic!("exported file: {error}")),
        b"# exported canary\n"
    );
}
