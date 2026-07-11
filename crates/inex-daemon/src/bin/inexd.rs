//! Inex local sidecar process.

fn main() {
    // The stdio transport is wired in Phase 3. Keeping the binary present now
    // makes packaging and editor-client discovery paths testable from Phase 1.
    eprintln!("inexd: JSON-RPC transport is not implemented yet");
    std::process::exit(2);
}
