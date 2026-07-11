# Compatibility Fixtures

Phase 2 commits deterministic EDRY/vault fixtures generated from test-only
constructors. Production code never permits caller-supplied salts, nonces,
keys, timestamps, or identifiers.

Each fixture directory will contain:

```text
case-name/
  vector.json       non-secret exact inputs and expected field values
  vault.json        authenticated wrapped metadata
  document.md.enc.b64  exact EDRY bytes as unpadded base64url
  expected.json     exact header/body fields and ciphertext etag
```

`v1-fixed/` is the first committed compatibility vector. Every value is public
test data, the deliberately cheap Argon2id parameters are unsafe for real
vaults, and the Rust compatibility test both regenerates the exact bytes and
reads the committed bytes through the normal v1 parser/decrypter. Textual
base64url keeps the binary fixture reviewable and portable across Git clients.

`vector.json` uses clearly labeled public test-only values for password bytes,
master key, slot/file UUIDs, salt, nonces, KDF parameters, timestamps, path,
and plaintext bytes (base64url). Fixtures are generated only by a test-only
constructor unavailable in release builds. Windows and Linux CI compare exact
SHA-256 hashes against the committed fixture manifest.

Fixture schema version 1 requires tests for:

- empty, ASCII, Chinese/emoji, combining Unicode, BOM, LF/CRLF/mixed newline;
- minimum/maximum allowed logical paths and content sizes;
- wrong password and corruption of every authenticated envelope region;
- canonical-CBOR rejection corpus;
- password-slot replacement with unchanged EDRY hash;
- committed, unresolved-conflict, and unsaved-draft EDRY flags.
