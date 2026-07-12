use std::process::Command;

#[test]
fn packaged_daemon_reports_the_exact_reviewed_crypto_runtime() {
    let output = Command::new(env!("CARGO_BIN_EXE_inexd"))
        .arg("--runtime-info")
        .output()
        .unwrap_or_else(|error| panic!("runtime-info process failed to start: {error}"));

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let expected = format!(
        "runtime-info-schema: inex-runtime-v1\n\
         product: inexd\n\
         version: 0.1.0\n\
         rust-target: {}\n\
         rust-debug-assertions: {}\n\
         libsodium-version: 1.0.22\n\
         libsodium-library-major: 26\n\
         libsodium-library-minor: 4\n\
         libsodium-minimal: false\n",
        inex_core::sodium::COMPILED_RUST_TARGET,
        inex_core::sodium::COMPILED_WITH_DEBUG_ASSERTIONS,
    );
    assert_eq!(output.stdout, expected.as_bytes());
}
