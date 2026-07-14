//! Storage, cryptography, and vault primitives for Inex.
//!
//! This crate is the sole authority for vault configuration, logical paths,
//! EDRY parsing, key derivation, encryption, and ciphertext writes. Editor and
//! RPC code must not duplicate these rules.

#![deny(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

/// Current EDRY envelope major version.
pub const EDRY_VERSION: u8 = 1;

/// Current vault metadata major version.
pub const VAULT_VERSION: u32 = 1;

pub mod atomic;
pub mod crypto;
pub mod features;
pub mod format;
pub mod path;
pub mod publication;
pub mod search;
#[allow(unsafe_code)]
pub mod sodium;
pub mod tree;
pub mod umbra_keyslot;
pub mod vault;
pub mod vault_config;
