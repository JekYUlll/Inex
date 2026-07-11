# Dependency and Toolchain Policy

## Rust baseline

- Edition 2024, workspace toolchain and declared MSRV Rust 1.97.0. EDRY v1
  freezes Unicode 17 NFC/case behavior; Rust 1.97 is the first verified project
  baseline whose standard-library Unicode tables match that contract. The
  pinned libsodium build chain itself requires at least Rust 1.88.
- `Cargo.lock` is committed for reproducible application/extension binaries.
- Wire-format and cryptographic dependencies are exact-pinned; ordinary
  serialization/error/helper dependencies use compatible semver ranges and are
  frozen transitively by the lockfile.

## Cryptographic implementation

| Dependency | Policy | Purpose |
|------------|--------|---------|
| `libsodium-sys-stable = 1.24.0` | exact, default features off | Narrow audited FFI to bundled libsodium 1.0.22 APIs. |
| `minicbor = 2.2.2` | exact, manual encoder/decoder | RFC 8949 deterministic EDRY/vault AAD encoding. No HashMap/derive controls wire order. |
| `zeroize = 1.9.0` | exact | Best-effort wipe for temporary Rust-owned buffers. It is not mlock. |
| `sha2` | compatible 0.10 | Ciphertext-only etags and fixture manifests. Not password/file encryption. |
| `diffy = 0.5.0` | exact, default features only | In-memory line-based diff3 for authenticated Markdown stages. MIT OR Apache-2.0; crate MSRV 1.85, below the project Rust 1.97 baseline. |

The core wraps `sodium_init`, randombytes, explicit Argon2id13 pwhash,
XChaCha20-Poly1305-IETF, explicit BLAKE2b generic hash, secure allocation,
memory protection, and zeroing in one small FFI module. Raw pointers and sodium
constants do not escape that module. `sodiumoxide` is excluded because its own
repository marks it deprecated.

`sodium_init()` is guarded by a process-wide once cell and every public crypto
entry point verifies initialization. Keys use an RAII secure allocation that
is not Clone/Serialize and redacts Debug. Failure to lock pages is a surfaced
health warning under the documented social threat model; strict mode may fail.

## Argon2id policy

Libsodium's explicit Argon2id13 API is used, never `ALG_DEFAULT`. Its current
parallelism is fixed at one; v1 calibrates only memory and operations, and the
JSON does not promise configurable lanes. New vaults use at least 64 MiB and
operations limit 3. Readers validate a resource ceiling before calling sodium.

## Build and supply-chain checks

- Release builds use the pinned crate's bundled/static path, not a drifting
  system pkg-config dependency. Distribution builds do not enable moving
  `fetch-latest`, host-specific `optimized`, or API-reducing `minimal` features.
- CI records `sodium_version_string()` and runs an offline clean rebuild from a
  populated dependency cache.
- Linux builders require a C compiler, make, and shell. Windows uses MSVC
  artifacts/source paths supplied and verified by the pinned sys crate.
- Linux/Windows x64 are the first blocking matrix; Linux/Windows arm64 join
  before GA. Format fixtures must be byte-identical on every target.

## Git for Windows preflight

- Git 2.36 or newer is required and checked before repository plumbing. This is
  the first supported baseline where command-line `core.fsmonitor=false` has
  the boolean disable semantics used to suppress repository-configured hooks.
- A vault permits logical paths beyond legacy `MAX_PATH`. Phase 6's explicit
  `inex git install-driver` setup therefore verifies Git for Windows and writes
  repository-local `core.longPaths=true`; it does not change global Git config.
- Git for Windows' default NTFS protection remains enabled. The v1 path profile
  rejects documented DOS `~digit` names instead of advising users to disable
  `core.protectNTFS`.
- Native Windows CI must exercise add/commit/checkout on a path beyond 260 UTF-16
  code units as well as the Rust write/rebind/delete lifecycle.

## Primary references

- https://doc.libsodium.org/bindings_for_other_languages
- https://github.com/jedisct1/libsodium-sys-stable/releases/tag/1.24.0
- https://doc.libsodium.org/password_hashing/default_phf
- https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
- https://doc.libsodium.org/memory_management
- https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1
- https://github.com/bmwill/diffy/tree/0.5.0
