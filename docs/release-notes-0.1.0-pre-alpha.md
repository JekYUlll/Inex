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
  cross-process locking, and explicit recovery journals. Git merge v4 uses an
  alternate index candidate, durable pre-lock reservation, phase-bound
  ownership receipts, and an Inex-owned real `index.lock` transaction.
- Parsers reject duplicate or unknown security-sensitive fields,
  noncanonical identifiers, invalid UTF-8 passwords, malformed framing, and
  unsupported future states.
- Release artifacts use an allowlisted package layout, fixed native target,
  shared sidecar and license-inventory bindings, canonical evidence reports,
  and dynamic secret-residue scans.

## Current evidence

- The Rust workspace, TypeScript client tests, Sublime pure-Python tests, and
  strict release-tool tests pass on the local Linux x64 development host.
- Linux subprocess force-kill tests prove atomic ciphertext writes expose only
  a complete old or new target at four commit boundaries. Git pre-lock tests
  prove ambiguous/foreign/partial/link states are detected and preserved
  rather than silently cleaned; receipt-gap automatic recovery remains open.
- The Linux x64 binding workflow requires two standalone clean system-GCC
  release builds to be byte-identical and pass strict release-set,
  native-dependency, package, VSIX installation, and bundled-sidecar smoke
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
- Directory rename/delete, attachment streaming, filename encryption,
  master-key rotation, in-place plaintext conversion, shared daemon sessions,
  and native Search-sidebar integration are not supported in v1.
- Deliberately concurrent Git porcelain, ref-only concurrency during recovery,
  native abrupt power-loss claims, receipt-gap automatic recovery, and
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
