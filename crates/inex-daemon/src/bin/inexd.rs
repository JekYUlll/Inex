//! Inex local sidecar process.

use std::process::ExitCode;

use inex_daemon::server::{ServerExit, run_stdio};

fn main() -> ExitCode {
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
