# Dependency and Toolchain Policy

## Rust baseline

- Edition 2024, workspace toolchain and declared MSRV Rust 1.97.0. EDRY v1
  freezes Unicode 17 NFC/case behavior; Rust 1.97 is the first verified project
  baseline whose standard-library Unicode tables match that contract. The
  pinned libsodium build chain itself requires at least Rust 1.88.
- `Cargo.lock` is committed to freeze resolved Rust inputs. A lockfile alone
  does not make compiler, linker, native library, or final archive bytes
  reproducible.
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
parallelism is fixed at one and the JSON does not promise configurable lanes.
Normal creation now fixes memory at 64 MiB and process-caches an ops-only
selection over 3–20 operations toward a 250–750 ms dummy-input KDF measurement.
Explicit RPC creation is independently capped to the same operations range and
exact memory value; it cannot consume the broader 1 GiB reader allowance.
Password add/change retains the componentwise stronger values from the
authenticated slot within reader limits. Synthetic selection tests avoid wall-
clock flakiness, and real Linux CLI processes cover calibrated init/import plus
strong-slot rewrap. Native timing/resource evidence remains a release gate.

## Build and supply-chain checks

- Release builds use the pinned crate's bundled/static path, not a drifting
  system pkg-config dependency. Distribution builds do not enable moving
  `fetch-latest`, host-specific `optimized`, or API-reducing `minimal` features.
- The configured CI is intended to record `sodium_version_string()` and run an
  offline clean rebuild from a populated dependency cache. Its four platform
  workflows have not yet been pushed/run, so this is not current evidence.
- Linux builders require a C compiler, make, and shell. Windows uses MSVC
  artifacts/source paths supplied and verified by the pinned sys crate.
- Linux/Windows x64 are the first blocking matrix; Linux/Windows arm64 join
  before GA. Format fixtures must be byte-identical on every target.
- The current strict release-tool source suite passes 60/60; `actionlint`,
  pedantic/all-features Clippy, warnings-as-errors rustdoc, and the Windows GNU
  cross-check pass. Two local system-GCC Linux x64 clean-source builds from
  `40ff728` are byte-identical and pass strict release-set/ELF/native-dependency
  audit plus executable/VSIX sidecar smoke with `dirtySourceTree=false`. The
  xlings-default local ELF embeds its build-home interpreter/RUNPATH and is
  correctly rejected as non-portable.
- A clean no-hardlinks standalone clone at harness commit `d44ead9` re-audits those
  packages, authenticates five imported/restored bodies, exercises CLI/RPC/Git
  failure nondisclosure, and reports zero sensitive-residue hits outside the
  designated plaintext source. This does not attest generated inputs or replace
  native/signing/legal gates.

## License inventory and distribution obligations

Inex itself is `GPL-3.0-only`. The following table records the direct external
Rust dependencies resolved by the current manifests; `Cargo.lock` remains the
authority for exact transitive versions in a particular artifact.

| Component | Current license expression | Distribution role |
|-----------|----------------------------|-------------------|
| `libsodium-sys-stable 1.24.0` | MIT OR Apache-2.0 | Rust FFI/build wrapper |
| bundled libsodium 1.0.22 | ISC | Native cryptographic implementation linked into release binaries |
| `minicbor 2.2.2` | BlueOak-1.0.0 | Deterministic CBOR |
| `zeroize 1.9.0` | Apache-2.0 OR MIT | Best-effort owned-buffer wiping |
| `diffy 0.5.0` | MIT OR Apache-2.0 | In-memory diff3 |
| `rpassword 7.5.4` | Apache-2.0 | Hidden CLI terminal input |
| `base64`, `serde`, `serde_json`, `sha2`, `thiserror`, `unicode-normalization`, `uuid` | MIT/Apache-2.0 combinations | Encoding, metadata, errors, hashes, Unicode, and identifiers |

Resolved transitive Cargo metadata also contains permissive license
families including 0BSD, Apache-2.0 (some with LLVM exception), BlueOak-1.0.0,
ISC, MIT, Unicode-3.0, Unlicense, and Zlib, plus disjunctive expressions that
must be resolved deliberately for distribution. Release inventory generation
filters the locked dependency graph to normal/build packages reachable for the
selected native target instead of treating every cross-target lock entry as
shipped.

The shipped VS Code bundle has no npm runtime package dependency: it uses Node
built-ins and the host-provided `vscode` API. Its pinned TypeScript, esbuild,
type, test-electron, and packaging dependencies are build/test tools and are
not copied into the curated VSIX. The Sublime runtime uses Python's standard
library and the host-provided Sublime API. Build-tool exclusion from a package
does not remove the need to review those tools' licenses and provenance in the
release process.

| Direct editor/release tool | Locked version | Declared license | Shipped in curated artifact |
|----------------------------|----------------|------------------|-----------------------------|
| `@types/node` | 26.1.1 | MIT | no |
| `@types/vscode` | 1.125.0 | MIT | no |
| `@vscode/test-electron` | 3.0.0 | MIT | no |
| `esbuild` | 0.28.1 | MIT | no |
| `typescript` | 7.0.2 | Apache-2.0 | no |
| `@vscode/vsce` | 3.9.2 | MIT | no; packaging process only |

The packaging helper generates canonical `THIRD_PARTY_LICENSES.json` from
locked offline Cargo metadata filtered by the package platform's fixed Rust
target triple, rather than the build host. Every crates.io component must have
its exact Cargo.lock checksum and an expression present in the committed
`packaging/dependency-license-policy.json`; a new source, expression, missing
checksum, duplicate component/path, or noncanonical schema fails closed. Only
the four fixed `crates/inex-*` manifests are first-party: auto-promoted or other
path/workspace dependencies are rejected. That policy is explicitly
engineering collection metadata, not legal approval. The helper also collects
the referenced complete license/NOTICE files and their SHA-256 digests into
`THIRD_PARTY_LICENSE_TEXTS/` and fails if a resolved component has no acceptable
text. The Linux x64 graph currently contains 77 Cargo components, 146 Cargo
license/NOTICE files, and the bundled libsodium 1.0.22 ISC file: 147 collected
texts total. The policy separately pins that ISC text's SHA-256. Strict
release-set audit additionally requires all three artifacts to contain the
same inventory bytes and the same `inexd` bytes.

`inex runtime-info` and `inexd --runtime-info` expose a fixed machine-readable
report. Package smoke requires the platform's fixed Rust target triple,
`rust-debug-assertions: false`, exact libsodium `1.0.22`, ABI `26.4`, and a
non-minimal build; a GNU Windows binary cannot satisfy an MSVC package, and a
merely nonempty or `1.0.x` version string is not accepted. Package construction,
release-set audit, and lifecycle evidence
emit canonical schema-v1 reports with explicit `notCovered` and trust
assumptions. Lifecycle evidence serializes its final report and scans those
bytes with the same dynamic password/session/canary variants before output.

Automated collection is not legal approval. Before public distribution, the
release owner must still:

1. resolve every `OR`/`AND` expression under a documented license-choice policy;
2. independently review attribution and redistribution obligations;
3. repeat inventory/text collection and final-archive audit for each native
   target;
4. verify the actual linked libsodium version and ISC text;
5. retain the exact lockfiles, source commit, package manifest, checksums,
   signature, and reviewed license report used for that artifact; and
6. publish through the canonical repository
   <https://github.com/JekYUlll/Inex> only after the private security-reporting
   and supported-version policies exist.

The engineering collection gate passes for the local Linux x64 checkpoint;
independent legal review and public-release approval remain pending. This
section is an engineering checklist, not legal advice.

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
- https://spdx.org/licenses/
- https://github.com/jedisct1/libsodium/blob/1.0.22/LICENSE
