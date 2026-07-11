//! Process-level contract test for the shipped `inexd` stdio binary.

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use inex_core::sodium::Argon2idParams;
use inex_core::vault::Vault;
use inex_core::vault_config::KdfPolicy;
use inex_daemon::framing::{JsonObject, read_frame, write_frame};
use inex_daemon::sensitive::{encode_base64url, scrub_object};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        Self(std::env::temp_dir().join(format!(
            "inex-process-e2e-{}-{nanos}-{sequence}",
            std::process::id()
        )))
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

struct RpcChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl RpcChild {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_inexd"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("inexd spawn failed: {error}"));
        let stdin = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("inexd stdin missing"));
        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("inexd stdout missing"));
        let stderr = child.stderr.take();
        Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            stderr,
        }
    }

    fn call(&mut self, id: i64, method: &str, params: Value) -> JsonObject {
        let mut request = Map::new();
        request.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
        request.insert("id".to_owned(), Value::from(id));
        request.insert("method".to_owned(), Value::String(method.to_owned()));
        request.insert("params".to_owned(), params);
        write_frame(
            self.stdin
                .as_mut()
                .unwrap_or_else(|| panic!("inexd stdin already closed")),
            &request,
        )
        .unwrap_or_else(|error| panic!("request write failed: {error}"));
        scrub_object(&mut request);
        read_frame(&mut self.stdout)
            .unwrap_or_else(|error| panic!("response read failed: {error}"))
            .unwrap_or_else(|| panic!("inexd closed before response"))
    }

    fn finish(mut self) -> Vec<u8> {
        drop(self.stdin.take());
        let status = self
            .child
            .wait()
            .unwrap_or_else(|error| panic!("inexd wait failed: {error}"));
        assert!(status.success(), "inexd exited unsuccessfully: {status}");
        let mut stderr = Vec::new();
        if let Some(mut stream) = self.stderr.take() {
            use std::io::Read as _;
            stream
                .read_to_end(&mut stderr)
                .unwrap_or_else(|error| panic!("stderr read failed: {error}"));
        }
        stderr
    }
}

impl Drop for RpcChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

#[test]
#[allow(clippy::too_many_lines)] // One process lifecycle is easier to audit as one scenario.
fn shipped_process_negotiates_and_completes_encrypted_file_lifecycle() {
    let directory = TestDirectory::new();
    let password = b"process test password";
    drop(
        Vault::create_with_params(
            directory.path(),
            password,
            1_783_699_200_000,
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            },
            test_policy(),
        )
        .unwrap_or_else(|error| panic!("fixture vault failed: {error}")),
    );

    let mut rpc = RpcChild::spawn();
    let mut hello = rpc.call(
        1,
        "system.hello",
        object([
            ("client", Value::String("integration-test".to_owned())),
            ("clientVersion", Value::String("1".to_owned())),
            ("protocolMajor", Value::from(1)),
        ]),
    );
    assert_eq!(hello["result"]["protocolMajor"], 1);
    scrub_object(&mut hello);

    let mut unlocked = rpc.call(
        2,
        "vault.unlock",
        object([
            (
                "vaultPath",
                Value::String(directory.path().to_string_lossy().into_owned()),
            ),
            (
                "password",
                Value::String(String::from_utf8_lossy(password).into_owned()),
            ),
        ]),
    );
    let mut session = Zeroizing::new(
        unlocked["result"]["session"]
            .as_str()
            .unwrap_or_else(|| panic!("unlock session missing"))
            .to_owned(),
    );
    assert_eq!(unlocked["result"]["warnings"][0]["name"], "WEAK_KDF");
    scrub_object(&mut unlocked);

    let plaintext = b"# Process E2E\nneedle survives only in memory\n";
    let mut written = rpc.call(
        3,
        "file.write",
        object([
            ("session", Value::String(session.as_str().to_owned())),
            ("logicalPath", Value::String("entry.md".to_owned())),
            (
                "contentBase64",
                Value::String(encode_base64url(plaintext).to_string()),
            ),
            ("ifNoneMatch", Value::String("*".to_owned())),
        ]),
    );
    assert!(
        written["result"]["etag"]
            .as_str()
            .is_some_and(|etag| etag.starts_with("sha256:"))
    );
    scrub_object(&mut written);
    assert!(directory.path().join("entry.md.enc").is_file());
    assert!(!directory.path().join("entry.md").exists());

    let mut read = rpc.call(
        4,
        "file.read",
        object([
            ("session", Value::String(session.as_str().to_owned())),
            ("logicalPath", Value::String("entry.md".to_owned())),
        ]),
    );
    assert_eq!(
        read["result"]["contentBase64"],
        encode_base64url(plaintext).as_str()
    );
    scrub_object(&mut read);

    let mut search = rpc.call(
        5,
        "search.query",
        object([
            ("session", Value::String(session.as_str().to_owned())),
            ("query", Value::String("needle".to_owned())),
            ("limit", Value::from(10)),
        ]),
    );
    assert_eq!(search["result"]["results"][0]["logicalPath"], "entry.md");
    scrub_object(&mut search);

    let mut locked = rpc.call(
        6,
        "vault.lock",
        object([("session", Value::String(session.as_str().to_owned()))]),
    );
    assert_eq!(locked["result"]["ok"], true);
    scrub_object(&mut locked);
    session.zeroize();

    let mut shutdown = rpc.call(7, "system.shutdown", Value::Object(Map::new()));
    assert_eq!(shutdown["result"]["ok"], true);
    scrub_object(&mut shutdown);
    let stderr = rpc.finish();
    assert!(stderr.is_empty(), "successful process emitted stderr");
}
