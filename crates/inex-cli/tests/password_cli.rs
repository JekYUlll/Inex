//! Real-process Argon2 calibration and password-slot coverage.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use inex_core::sodium::Argon2idParams;
use inex_core::vault::Vault;
use inex_core::vault_config::KdfPolicy;
use uuid::Uuid;

const INIT_PASSWORD: &[u8] = b"init process calibration password";
const OLD_PASSWORD: &[u8] = b"strong authenticated old password";
const NEW_PASSWORD: &[u8] = b"no downgrade replacement password";
const MIB: u64 = 1024 * 1024;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "inex-password-cli-{label}-{}-{nanos}-{counter}",
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

fn unix_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("system clock precedes Unix epoch: {error}"))
        .as_millis();
    i64::try_from(millis).unwrap_or_else(|error| panic!("timestamp does not fit i64: {error}"))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn run_inex(arguments: &[OsString], password_lines: &[&[u8]]) -> Output {
    for argument in arguments {
        for password in password_lines {
            assert!(
                !contains_bytes(argument.as_os_str().as_encoded_bytes(), password),
                "password must never be placed in argv"
            );
        }
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_inex"))
        .args(arguments)
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
    for password in password_lines {
        stdin
            .write_all(password)
            .and_then(|()| stdin.write_all(b"\n"))
            .unwrap_or_else(|error| panic!("password write failed: {error}"));
    }
    drop(stdin);

    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("inex wait failed: {error}"));
    for password in password_lines {
        assert!(
            !contains_bytes(&output.stdout, password),
            "stdout must not disclose a password"
        );
        assert!(
            !contains_bytes(&output.stderr, password),
            "stderr must not disclose a password"
        );
    }
    output
}

fn parse_new_slot(stdout: &[u8]) -> Uuid {
    let stdout = std::str::from_utf8(stdout)
        .unwrap_or_else(|error| panic!("password command stdout was not UTF-8: {error}"));
    let slot = stdout
        .lines()
        .find_map(|line| line.strip_prefix("new-slot: "))
        .unwrap_or_else(|| panic!("password command did not report new-slot: {stdout}"));
    Uuid::parse_str(slot).unwrap_or_else(|error| panic!("new-slot was not a UUID: {error}"))
}

#[test]
fn init_uses_bounded_v1_calibration_and_creates_an_unlockable_vault() {
    let directory = TestDirectory::new("init");
    let vault_path = directory.path().join("vault");
    let arguments = [OsString::from("init"), vault_path.as_os_str().to_owned()];

    let output = run_inex(&arguments, &[INIT_PASSWORD, INIT_PASSWORD]);
    assert!(
        output.status.success(),
        "init stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("vault created"));

    let vault = Vault::unlock(&vault_path, INIT_PASSWORD, None, KdfPolicy::default())
        .unwrap_or_else(|error| panic!("calibrated vault did not unlock: {error}"));
    let slot = vault
        .config()
        .key_slot(vault.unlocked_slot_id())
        .unwrap_or_else(|error| panic!("created password slot was missing: {error}"));
    assert!((3..=20).contains(&slot.kdf.ops_limit));
    assert_eq!(slot.kdf.mem_limit_bytes, 64 * MIB);
}

#[test]
fn password_add_preserves_authenticated_stronger_work_factors() {
    let directory = TestDirectory::new("no-downgrade");
    let vault_path = directory.path().join("vault");
    let stronger_params = Argon2idParams {
        ops_limit: 4,
        mem_limit_bytes: 64 * MIB + 8 * 1024,
    };
    let stronger_creation_policy = KdfPolicy {
        min_creation_ops_limit: 3,
        min_creation_mem_limit_bytes: 64 * MIB,
        max_creation_ops_limit: stronger_params.ops_limit,
        max_creation_mem_limit_bytes: stronger_params.mem_limit_bytes,
        max_unlock_ops_limit: 20,
        max_unlock_mem_limit_bytes: 1024 * MIB,
    };
    let created = Vault::create_with_params(
        &vault_path,
        OLD_PASSWORD,
        unix_time_ms(),
        stronger_params,
        stronger_creation_policy,
    )
    .unwrap_or_else(|error| panic!("stronger vault creation failed: {error}"));
    let old_slot_id = created.unlocked_slot_id();
    drop(created);

    let authenticated = Vault::unlock(
        &vault_path,
        OLD_PASSWORD,
        Some(old_slot_id),
        KdfPolicy::default(),
    )
    .unwrap_or_else(|error| panic!("stronger slot was not accepted by reader policy: {error}"));
    let old_slot = authenticated
        .config()
        .key_slot(old_slot_id)
        .unwrap_or_else(|error| panic!("authenticated old slot was missing: {error}"));
    assert_eq!(old_slot.kdf.ops_limit, stronger_params.ops_limit);
    assert_eq!(
        old_slot.kdf.mem_limit_bytes,
        stronger_params.mem_limit_bytes
    );
    drop(authenticated);

    let arguments = [
        OsString::from("password"),
        OsString::from("add"),
        vault_path.as_os_str().to_owned(),
        OsString::from("--slot"),
        OsString::from(old_slot_id.to_string()),
    ];
    let output = run_inex(&arguments, &[OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD]);
    assert!(
        output.status.success(),
        "password add stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let new_slot_id = parse_new_slot(&output.stdout);
    assert_ne!(new_slot_id, old_slot_id);

    let reopened = Vault::unlock(
        &vault_path,
        NEW_PASSWORD,
        Some(new_slot_id),
        KdfPolicy::default(),
    )
    .unwrap_or_else(|error| panic!("new password slot did not unlock: {error}"));
    assert_eq!(reopened.unlocked_slot_id(), new_slot_id);
    let old_slot = reopened
        .config()
        .key_slot(old_slot_id)
        .unwrap_or_else(|error| panic!("old password slot was not retained: {error}"));
    let new_slot = reopened
        .config()
        .key_slot(new_slot_id)
        .unwrap_or_else(|error| panic!("new password slot was missing: {error}"));
    assert!(new_slot.kdf.ops_limit >= old_slot.kdf.ops_limit);
    assert!(new_slot.kdf.mem_limit_bytes >= old_slot.kdf.mem_limit_bytes);
}
