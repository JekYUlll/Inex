# Inex 0.1.0 pre-alpha checkpoint notes

> **Draft, not a release approval.** No Inex version is currently supported
> for security use. The native multi-platform, persistent-editor, signing,
> legal-review, and publication gates in the release checklist remain open.

## Compatibility baseline

- On-disk content uses EDRY v1 and vault metadata v1. Unknown format versions,
  algorithms, fields, and protocol states fail closed.
- Editor clients communicate with `inexd` through the versioned JSON-RPC v1
  contract over framed stdio.
- Source builds require Rust 1.97.0. Git integration requires Git 2.36 or
  newer.
- The primary editor baseline is VS Code 1.125.0 or newer. The secondary
  Sublime Text client is experimental and is restricted to exact Build 4200.
- Native release binaries bundle libsodium 1.0.22 with ABI 26.4. The strict
  package audit rejects another runtime or a minimal build.

## Implemented security properties

- Markdown bodies are stored as authenticated XChaCha20-Poly1305 ciphertext;
  Inex-owned save, import, backup, merge, and recovery paths do not create a
  plaintext Markdown mirror.
- Required feature 1 adds authenticated opaque assets up to 64 MiB, distinct
  `.asset.enc` physical names, typed tree/RPC entries, and bounded same-vault
  PNG/JPEG/non-animated-WebP previews through revocable webview blob URLs. The
  current implementation uses authenticated whole-file asset encryption and a
  sequential 1 MiB RPC read surface; it does not promise streaming encryption.
- Linux `import-repository` can bind one clean tracked SHA-1 `HEAD` snapshot,
  accept every stage-zero `100644` file as lowercase Markdown or an opaque
  asset, construct one fresh parentless ciphertext Git commit, and publish the
  complete vault and `.git` as a single absent-root transaction. Unsupported
  modes abort instead of being skipped. The importer deliberately leaves the
  source and its plaintext history unchanged instead of copying plaintext
  objects.
- Password slots use Argon2id-derived wrapping keys around a stable random
  vault master key. Adding, changing, or removing a password slot does not
  rewrite EDRY bodies and is not master-key rotation. This describes the key
  hierarchy only; old metadata plus an old password still defeats revocation.
- New-vault creation process-caches an ops-only Argon2id calibration over 3–20
  operations at fixed 64 MiB toward a 250–750 ms public-dummy selector
  observation. Its timing includes validation, possible libsodium initialization,
  secure allocation, and Argon2id; it is not pure KDF or end-to-end latency.
  Explicit RPC creation uses the same independent cap, and password add/change
  preserves stronger authenticated slot parameters within reader limits.
- `inex kdf-calibration-info` adds a CLI-only, no-argument, strict 20-line ASCII
  diagnostic for that cached public evidence. It runs before password/query
  setup, takes no vault/password/policy input, and writes no persistent Inex
  product state, but still initializes cryptographic runtime state as needed and
  consumes CPU plus the fixed 64 MiB work-memory setting. Each invocation is a
  fresh process and does not warm later creation or daemon work.
- Logical paths are canonicalized and authenticated. File rename therefore
  decrypts and re-encrypts under the new authenticated path instead of moving
  ciphertext blindly.
- Local mutations use conditional etags, verified ciphertext staging,
  cross-process locking, and explicit recovery journals. New Git transactions
  use a v5 immutable alternate-index bundle, canonical `INEXIDX5` marker and
  journal, live-index identity checks, and a durable cleanup receipt under one
  mutation guard.
- Parsers reject duplicate or unknown security-sensitive fields,
  noncanonical identifiers, invalid UTF-8 passwords, malformed framing, and
  unsupported future states.
- Release artifacts use an allowlisted package layout, fixed native target,
  shared Rust/VSIX CLI, shared sidecar and license-inventory bindings, canonical evidence reports,
  and dynamic secret-residue scans.

## Current evidence

- The predecessor full Rust workspace aggregate passed 333/333 before Git v5;
  a current-HEAD aggregate is still required. The current default `inex-git`
  suite passes 171 with 0 failures and 12 intentionally ignored entries: six
  child-only helpers plus six full shards. All six ignored full shards were
  executed separately for the 230-case matrix below. TypeScript, Sublime
  pure-Python, and strict
  release-tool suites pass on the local Linux x64 development host.
- Linux subprocess force-kill tests prove atomic ciphertext writes expose only
  a complete old or new target at four commit boundaries. Separately, six
  native Linux Git shards cover 230 SHA-1/SHA-256 ×
  InPlace/DetectedRename/SplitRename cases spanning the writer's durable state
  matrix, using fresh recovery processes and plaintext-residue scans. A kill
  before any scratch no-replace publication may retain one orthogonal
  nonblocking entry for audit: a directory during bundle preparation or a
  regular file during publish/marker/journal preparation. Active cleanup does
  not guess-delete it. Native Windows and device power-loss remain separate
  open evidence rows.
- The Linux x64 binding workflow requires two standalone clean system-GCC
  release builds to be byte-identical and pass strict release-set,
  native-dependency, package, VSIX installation, and bundled-executable smoke
  checks.
- A third standalone clean harness clone must bind the exact source and artifact
  hashes while passing lifecycle, restore, frozen-v1, and negative
  CLI/RPC/locked-Git secret drills with zero sensitive hits outside the
  controlled plaintext source. Exact results belong in an external evidence
  record; this bundled note cannot attest its own archive.
- Native KDF evidence additionally requires exactly three ordinal fresh-process
  reports from each audited packaged CLI on Linux x64/arm64 and Windows
  x64/arm64 MSVC, with no retries or preferred-result selection. Its canonical
  JSON stays outside package inputs and binds clean source/artifact/harness,
  runtime, host, and resource observations. Wine, cross builds, and emulation
  are non-binding; recorded peak resources and the 120-second harness timeout
  are not product SLAs.
- The current KDF evidence harness is Linux-only and fails closed on Windows
  before artifact use. Suspended-before-Job assignment, a Job-empty barrier,
  and NTFS ADS residue enumeration remain required before either Windows row
  can emit evidence.

These are engineering checkpoints, not evidence for native Windows, arm64,
ReFS, physical power loss, signed distribution, or independent legal review.
The repository importer additionally remains a trusted-local Linux engineering
demo until its full source-race, force-kill/publication-ambiguity, resource, and
native Windows acceptance matrix is complete. A normal full-size MyBlog run has
passed with 323 tracked files, 306 Markdown documents, 17 assets, and the exact
25,074,521-byte image while preserving the clean 728-commit source. Marker-v2
retry/reconciliation, independent raw-tree serialization, and streaming object
comparison are implemented; complete boundary-by-boundary force-kill evidence,
hostile same-UID race closure, artifact-bound residue, and native Windows gates
remain open.

## Deferred or unsupported states

- Native Windows x64/arm64 and Linux arm64 artifact lifecycle evidence remains
  pending. Cross-compilation and Wine are not substitutes for MSVC/NTFS/ReFS
  execution.
- The four-target, three-fresh-process Argon2id diagnostic matrix remains
  pending. A fallback outcome says only that the selector returned its
  documented branch; noise, non-monotonic measurements, and unmeasured
  candidates prohibit claiming that every operations value would miss the
  window.
- Persistent packaged VS Code Hot Exit/Local History/crash recovery and the
  real InputBox/QuickPick UI matrix remain release gates on Linux and Windows.
- One exact-packaged Build 4200 Linux full-application SIGKILL/restart path has
  passed against the same isolated profile and package, including a continuous
  two-second all-view pre-unlock scan and encrypted saved-content fingerprint
  reopen. Sublime remains experimental until the keyboard/menu, real-user
  persistent-profile, Hot Exit/history/sync,
  export/macro/clipboard/draft/additional-kill, platform, and signing matrix
  passes.
- Directory rename/delete, streaming asset encryption, filename encryption,
  master-key rotation, in-place plaintext conversion, shared daemon sessions,
  and native Search-sidebar integration are not supported in v1.
- Deliberately concurrent Git porcelain, ref-only concurrency during recovery,
  native Windows Job/handle claims, NTFS/ReFS abrupt power-loss claims, and
  same-user hostile namespace replacement remain outside this checkpoint.
- The system does not protect against administrators, malware or untrusted
  editor extensions while unlocked, memory forensics, swap/hibernation, crash
  dumps, screen or clipboard capture, key logging, denial of service, or
  rollback to an older complete vault and Git history.

## Upgrade and rollback

EDRY v1 and RPC v1 remain the only accepted versions. Back up `vault.json`, all
EDRY files, Git objects/refs, and `.vault-local` recovery state before changing
versions. Do not line-merge conflicting authenticated metadata and do not
import into an existing vault. A two-version final-artifact upgrade/rollback
drill remains mandatory before this draft can become public release notes.

See the [release checklist](release-checklist.md),
[security policy](../SECURITY.md), and
[operations and recovery guide](operations-and-recovery.md) for binding status
and recovery procedures.
