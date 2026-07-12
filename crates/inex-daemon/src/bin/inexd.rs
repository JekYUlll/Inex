//! Inex local sidecar process.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::process::ExitCode;

use inex_daemon::server::{ServerExit, run_stdio};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    match (arguments.next(), arguments.next()) {
        (None, None) => {}
        (Some(argument), None) if argument == OsStr::new("--runtime-info") => {
            return write_runtime_info();
        }
        _ => {
            eprintln!("inexd: unexpected command-line argument");
            return ExitCode::from(2);
        }
    }
    match run_stdio() {
        Ok(ServerExit::CleanEof | ServerExit::ShutdownRequested) => ExitCode::SUCCESS,
        Ok(ServerExit::Desynchronized(error)) => {
            eprintln!(
                "inexd: protocol stream desynchronized ({})",
                error.stable_name()
            );
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("inexd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn write_runtime_info() -> ExitCode {
    let Ok(runtime) = inex_core::sodium::version() else {
        eprintln!("inexd: libsodium runtime validation failed");
        return ExitCode::FAILURE;
    };
    let mut stdout = io::stdout().lock();
    let written = writeln!(stdout, "runtime-info-schema: inex-runtime-v1")
        .and_then(|()| writeln!(stdout, "product: inexd"))
        .and_then(|()| writeln!(stdout, "version: {}", env!("CARGO_PKG_VERSION")))
        .and_then(|()| {
            writeln!(
                stdout,
                "rust-target: {}",
                inex_core::sodium::COMPILED_RUST_TARGET
            )
        })
        .and_then(|()| {
            writeln!(
                stdout,
                "rust-debug-assertions: {}",
                inex_core::sodium::COMPILED_WITH_DEBUG_ASSERTIONS
            )
        })
        .and_then(|()| writeln!(stdout, "libsodium-version: {}", runtime.version))
        .and_then(|()| writeln!(stdout, "libsodium-library-major: {}", runtime.library_major))
        .and_then(|()| writeln!(stdout, "libsodium-library-minor: {}", runtime.library_minor))
        .and_then(|()| writeln!(stdout, "libsodium-minimal: {}", runtime.minimal))
        .and_then(|()| stdout.flush());
    if written.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
