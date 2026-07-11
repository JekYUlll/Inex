//! Session management and transport-neutral JSON-RPC handling for Inex.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod framing;

/// Protocol major understood by this daemon.
pub const PROTOCOL_MAJOR: u32 = 1;
