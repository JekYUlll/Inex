# EDRY Encrypted Markdown Format, Version 1

Status: **frozen for v1 implementation on 2026-07-11**. Compatibility fixtures
are generated in Phase 2; any semantic change now requires an explicit format
compatibility decision.

## Encoding conventions

- Multi-byte envelope integers are unsigned big-endian.
- UUIDs are raw 16-byte RFC 4122 values in the binary header and lowercase
  hyphenated strings in `vault.json`.
- JSON binary values use unpadded base64url.
- Timestamps are signed Unix milliseconds in UTC.
- Logical paths are UTF-8 NFC with `/` separators and are validated by the
  cross-platform path profile below.

Vault configuration, password slots, master-key wrapping, and the authenticated
metadata MAC are specified separately in [`vault-v1.md`](vault-v1.md).

## File envelope

```text
offset  size     value
0       4        ASCII "EDRY"
4       1        format major = 0x01
5       1        format minor = 0x00
6       2        fixed envelope flags = 0 (u16, big-endian)
8       4        canonical CBOR header length (u32, big-endian)
12      n        canonical CBOR header
12+n    rest     XChaCha20-Poly1305-IETF ciphertext + 16-byte tag
```

The header is a definite-length canonical CBOR map. Integer keys are encoded in
ascending order; no duplicate/unknown key is valid in version 1.

| Key | Type | Meaning |
|-----|------|---------|
| 0 | bstr(16) | vault UUID |
| 1 | bstr(16) | random stable file UUID |
| 2 | tstr | normalized logical path, including `.md` but not `.enc` |
| 3 | uint | master-key epoch |
| 4 | uint | file-key derivation id; `1` = keyed BLAKE2b-256 v1 |
| 5 | uint | cipher id; `1` = XChaCha20-Poly1305-IETF |
| 6 | bstr(24) | fresh random nonce |
| 7 | uint | plaintext kind; `1` = exact UTF-8 Markdown bytes |
| 8 | int | creation time in Unix milliseconds |
| 9 | int | last modification time in Unix milliseconds |
| 10 | uint | authenticated content flags bitset |
| 11 | array(uint) | sorted required feature ids; empty in v1 |
| 12 | null or bstr(32) | base ciphertext SHA-256 for an encrypted draft |

Flag bit 0 means the decrypted Markdown contains unresolved merge markers. Bit
1 means this envelope is an unsaved editor draft, not a committed vault file.
A draft records the raw 32-byte base etag at key 12 (or null for a new file);
a committed file requires key 12 to be null and bit 1 clear. All other bits
must be zero in v1. Normal `file.read` rejects a draft envelope; only the draft
restore API accepts it.

The AEAD associated data is `"INEX-EDRY-FILE\0"`, followed by the exact 12-byte
prefix and exact canonical header. Thus magic, version, lengths, vault,
logical path, metadata, flags, algorithms, nonce, required features, and key
epoch are authenticated. Parsers decode and re-encode the header and reject it
unless bytes are identical, preventing multiple encodings of the same semantic
header. Nonzero fixed flags and unknown required features fail closed.

The password key-slot identifier is deliberately absent. Slots only wrap a
stable master key; binding files to a slot would make password removal or
replacement require rewriting files and would contradict the v1 key hierarchy.

## File-key derivation

The 32-byte file key is the explicit libsodium keyed BLAKE2b-256
(`crypto_generichash_blake2b`) output:

```text
key   = vault_master_key
input = "INEX-FILE-V1\0" || vault_uuid || u32be(key_epoch) || file_uuid
```

The domain string prevents reuse with future derivation purposes. All 128 bits
of the file UUID are included. Master-key epochs are separate key domains.

## Write and rename rules

- A new file gets a cryptographically random file UUID and nonce.
- Every encryption, including an unchanged-body save, gets a fresh nonce.
- A save preserves file UUID/creation time and updates modification time.
- A custom-editor backup is a complete EDRY envelope with the draft flag and
  base etag. It is encrypted before the editor writes to its backup location.
- A logical rename decrypts, changes the authenticated header path, encrypts
  with a fresh nonce, atomically creates/replaces the destination, verifies it,
  and only then removes the source.
- Implementations never edit a header without re-encrypting its body.
- The etag is `sha256:<lowercase-hex>` of the complete envelope.

## Cross-platform logical path profile

A valid logical path:

- is relative, NFC, 1–1024 UTF-8 bytes, has no empty/`.`/`..` component, no
  backslash, NUL/control character, trailing dot/space, or leading `/`;
- has no component beginning with ASCII space, which the Windows Object
  Manager strips during ordinary creation;
- ends in lowercase `.md`; the caller never supplies the physical `.enc`;
- has directory components no longer than 255 UTF-8 bytes and a final logical
  `.md` filename no longer than 251 bytes, reserving four bytes so the physical
  `.enc` filename remains at most 255 bytes/UTF-16 units;
- contains none of `< > : " | ? *` and no Windows device basename such as
  `CON`, `CONIN$`, `CONOUT$`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, or
  `LPT1`–`LPT9` (case-insensitive,
  including names with extensions); the superscript-digit aliases `COM¹`–
  `COM³` and `LPT¹`–`LPT³` are reserved as Windows requires;
  ASCII spaces immediately before a device-name extension do not bypass this
  rule;
- does not enter `.git`, `.vault-local`, or use root `vault.json`;
- does not use a basename ending in `~0`–`~9`, avoiding DOS 8.3 aliases that
  Git for Windows protects by default;
- does not case-fold collide with another logical path in the same vault.

This intentionally chooses the Windows/Linux intersection so the same Git
checkout has one meaning on both systems.

Version 1 freezes normalization and case comparison to Unicode 17.0.0. NFC is
provided by exactly `unicode-normalization 0.1.25`. The collision key applies
the Rust 1.97 Unicode 17 lowercase→uppercase→lowercase scalar mapping, with
default-fold exceptions for dotless i and Cherokee, then restores NFC. Builds
whose normalization or standard-library Unicode tables differ fail at compile
time; changing this contract requires an explicit format-version decision.

## Limits and rejection

Initial limits are 4096 header bytes, 16 MiB Markdown plaintext, and 16 MiB +
16 bytes ciphertext. Implementations check lengths and integer conversions
before allocation. They fail closed on unknown major/minor/cipher/KDF/kind/
flags/required feature/draft invariant,
non-canonical CBOR, mismatched vault/path/epoch, invalid UTF-8, truncated or
trailing data, and authentication failure. No partial plaintext is returned.
