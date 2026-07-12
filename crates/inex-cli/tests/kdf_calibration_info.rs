//! Real-process contract for public-dummy KDF calibration evidence.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use inex_core::sodium;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "inex-kdf-calibration-info-{}-{nanos}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&path)
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

fn report_value<'a>(lines: &'a [&str], index: usize, key: &str) -> &'a str {
    lines[index]
        .strip_prefix(key)
        .unwrap_or_else(|| panic!("report line {index} did not start with {key:?}"))
}

fn run_kdf_calibration_info(directory: &TestDirectory) -> Output {
    Command::new(env!("CARGO_BIN_EXE_inex"))
        .arg("kdf-calibration-info")
        .current_dir(directory.path())
        .env("INEX_PASSWORD_STDIN", "invalid-on-purpose")
        .env("INEX_QUERY_STDIN", "invalid-on-purpose")
        .env("HOME", directory.path().join("home-must-not-be-created"))
        .env(
            "XDG_CACHE_HOME",
            directory.path().join("cache-must-not-be-created"),
        )
        .env(
            "XDG_CONFIG_HOME",
            directory.path().join("config-must-not-be-created"),
        )
        .env(
            "XDG_DATA_HOME",
            directory.path().join("data-must-not-be-created"),
        )
        .env(
            "XDG_STATE_HOME",
            directory.path().join("state-must-not-be-created"),
        )
        .env(
            "USERPROFILE",
            directory.path().join("userprofile-must-not-be-created"),
        )
        .env(
            "APPDATA",
            directory.path().join("appdata-must-not-be-created"),
        )
        .env(
            "LOCALAPPDATA",
            directory.path().join("localappdata-must-not-be-created"),
        )
        .env("TMPDIR", directory.path().join("tmp-must-not-be-created"))
        .env("TEMP", directory.path().join("temp-must-not-be-created"))
        .env("TMP", directory.path().join("tmp-must-not-be-created"))
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("KDF diagnostic process failed to start: {error}"))
}

fn assert_static_report_fields(lines: &[&str]) {
    assert_eq!(
        report_value(lines, 0, "kdf-calibration-info-schema: "),
        "inex-kdf-calibration-v1"
    );
    assert_eq!(report_value(lines, 1, "product: "), "inex");
    assert_eq!(report_value(lines, 2, "version: "), "0.1.0");
    assert_eq!(
        report_value(lines, 3, "rust-target: "),
        sodium::COMPILED_RUST_TARGET
    );
    assert_eq!(
        report_value(lines, 4, "rust-debug-assertions: "),
        sodium::COMPILED_WITH_DEBUG_ASSERTIONS.to_string()
    );
    assert_eq!(report_value(lines, 5, "algorithm: "), "argon2id13");
    assert_eq!(
        report_value(lines, 6, "measurement-input: "),
        "inex-public-dummy-v1"
    );
    assert_eq!(report_value(lines, 7, "cache-scope: "), "process");
    assert_eq!(
        report_value(lines, 8, "sample-mode: "),
        "single-per-candidate"
    );
    assert_eq!(
        report_value(lines, 12, "mem-limit-bytes: "),
        sodium::V1_ARGON2ID_CALIBRATION_MEM_LIMIT_BYTES.to_string()
    );
    assert_eq!(
        report_value(lines, 13, "parallelism: "),
        sodium::V1_ARGON2ID_CALIBRATION_PARALLELISM.to_string()
    );
    assert_eq!(
        report_value(lines, 14, "target-min-ns: "),
        sodium::V1_ARGON2ID_CALIBRATION_TARGET_MIN
            .as_nanos()
            .to_string()
    );
    assert_eq!(
        report_value(lines, 15, "target-max-ns: "),
        sodium::V1_ARGON2ID_CALIBRATION_TARGET_MAX
            .as_nanos()
            .to_string()
    );
    assert_eq!(report_value(lines, 19, "end-to-end-sla: "), "false");
}

fn assert_dynamic_report_fields(lines: &[&str]) {
    let min_ops = report_value(lines, 9, "min-ops-limit: ")
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("minimum ops was invalid: {error}"));
    let max_ops = report_value(lines, 10, "max-ops-limit: ")
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("maximum ops was invalid: {error}"));
    let selected_ops = report_value(lines, 11, "selected-ops-limit: ")
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("selected ops was invalid: {error}"));
    assert_eq!(min_ops, sodium::V1_ARGON2ID_CALIBRATION_MIN_OPS_LIMIT);
    assert_eq!(max_ops, sodium::V1_ARGON2ID_CALIBRATION_MAX_OPS_LIMIT);
    assert!((min_ops..=max_ops).contains(&selected_ops));

    let target_min = report_value(lines, 14, "target-min-ns: ")
        .parse::<u128>()
        .unwrap_or_else(|error| panic!("minimum target was invalid: {error}"));
    let target_max = report_value(lines, 15, "target-max-ns: ")
        .parse::<u128>()
        .unwrap_or_else(|error| panic!("maximum target was invalid: {error}"));
    let selected_observed = report_value(lines, 16, "selected-observed-ns: ")
        .parse::<u128>()
        .unwrap_or_else(|error| panic!("selected observation was invalid: {error}"));
    let measurement_count = report_value(lines, 17, "measurement-count: ")
        .parse::<u32>()
        .unwrap_or_else(|error| panic!("measurement count was invalid: {error}"));
    let outcome = report_value(lines, 18, "outcome: ");
    assert_eq!(
        target_min,
        sodium::V1_ARGON2ID_CALIBRATION_TARGET_MIN.as_nanos()
    );
    assert_eq!(
        target_max,
        sodium::V1_ARGON2ID_CALIBRATION_TARGET_MAX.as_nanos()
    );
    assert!(selected_observed > 0);
    assert!((1..=6).contains(&measurement_count));
    match outcome {
        "target-window" => assert!((target_min..=target_max).contains(&selected_observed)),
        "minimum-above-window" => {
            assert_eq!(selected_ops, min_ops);
            assert!(selected_observed > target_max);
        }
        "interior-above-window" => {
            assert!(selected_ops > min_ops && selected_ops < max_ops);
            assert!(selected_observed > target_max);
        }
        "maximum-above-window" => {
            assert_eq!(selected_ops, max_ops);
            assert!(selected_observed > target_max);
        }
        "maximum-below-window" => {
            assert_eq!(selected_ops, max_ops);
            assert!(selected_observed < target_min);
        }
        other => panic!("unexpected KDF calibration outcome: {other}"),
    }
}

#[test]
fn kdf_calibration_info_reports_one_cached_public_dummy_decision_without_files() {
    let directory = TestDirectory::new();
    let output = run_kdf_calibration_info(&directory);

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(output.stdout.is_ascii());
    let text = std::str::from_utf8(&output.stdout)
        .unwrap_or_else(|error| panic!("KDF diagnostic output was not UTF-8: {error}"));
    assert!(text.ends_with('\n'));
    assert!(!text.ends_with("\n\n"));
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 20);
    assert_static_report_fields(&lines);
    assert_dynamic_report_fields(&lines);
    assert_eq!(
        fs::read_dir(directory.path())
            .unwrap_or_else(|error| panic!("test directory read failed: {error}"))
            .count(),
        0
    );
}

#[test]
fn kdf_calibration_info_rejects_paths_before_work_or_output() {
    let directory = TestDirectory::new();
    let absent = directory.path().join("must-remain-absent");
    let output = Command::new(env!("CARGO_BIN_EXE_inex"))
        .arg("kdf-calibration-info")
        .arg(&absent)
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("invalid KDF diagnostic process failed: {error}"));

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!absent.exists());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-remain-absent"));
}
