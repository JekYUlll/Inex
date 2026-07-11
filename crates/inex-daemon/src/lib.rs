//! Session management and transport-neutral JSON-RPC handling for Inex.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod framing;
pub mod handler;
pub mod params;
pub mod protocol;
pub mod sensitive;
pub mod server;
pub mod session;

/// Protocol major understood by this daemon.
pub const PROTOCOL_MAJOR: u32 = 1;
