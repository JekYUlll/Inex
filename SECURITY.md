# Security Policy and Threat Model

## Assurance status

No Inex version is currently designated supported for security use. Version
`0.1.0` is a pre-alpha development checkpoint. Linux unit/integration gates,
cross-target/Wine checks, and controlled editor harnesses provide useful
implementation evidence, but they do not satisfy native Windows/arm64,
persistent-editor-profile, complete Sublime residue, signature, or public
release gates.

In particular:

- a cross-compiled Windows binary or Wine run is not native MSVC/NTFS/ReFS
  atomicity, long-path, crash, or residue evidence;
- the VS Code Extension Host harness proves encrypted backup/recovery and
  production CRUD-action behavior against a real daemon/custom editor, but its
  workbench storage is forced in-memory, and InputBox/QuickPick mouse interaction
  is not automated; it does not prove persistent cross-process Hot Exit or
  Local History behavior;
- the Sublime pure suite passes 61/61 and an exact Build 4200 normal E2E drives
  unlock/open/edit/save/close plus folder/file create, rename, and etag-bound delete,
  with authenticated tree checks and zero scanned disk residue. Killing the
  plugin host still leaves the visible buffer actively copyable and requires a
  full Sublime restart; the client therefore remains experimental until the
  complete package canary matrix passes; and
- release-tool tests pass 60/60, `actionlint` and pedantic/all-features Clippy
  pass, and independent release-tool code review is GO. The binding artifact
  workflow requires two standalone clean system-GCC builds to be byte-identical
  and pass strict archive/native-dependency plus isolated VS Code
  install/bundled-sidecar smoke. A third standalone clean clone must bind the
  exact artifact hashes while checking authenticated import/password/restore,
  Git bundle, frozen-v1 compatibility, CLI/RPC/locked-Git negative
  nondisclosure, exact body comparison, and bounded residue. This bundled
  document does not attest its own archive; require a separately preserved
  evidence record matching `PACKAGE-MANIFEST.json` and `SHA256SUMS`. Such a
  local result is still not native Windows/arm64, persistent-profile, signed,
  published, independently built, or independently reviewed legal evidence.

The current evidence and blockers are maintained in
[`docs/release-checklist.md`](docs/release-checklist.md). Do not use Inex as the
only copy of important data.

## Intended security goal

An Inex vault protects Markdown bodies at rest from ordinary local access by a
person who does not know the vault password. Before unlock, filesystem tools,
plain text editors, sync clients, and normal Git tooling see only EDRY
ciphertext. A normal save produces ciphertext before touching the vault.

Directory names and file basenames are intentionally visible in v1. File
length, timestamps, the number of files, Git history shape, and access timing
may also be observable. Users must not put secrets in visible path names.

## Out of scope

Inex does not protect plaintext from:

- an administrator, kernel compromise, debugger, malicious editor extension,
  or malware running with the user's permissions while the vault is unlocked;
- memory forensics, cold-boot attacks, swap/hibernation capture, crash dumps,
  screen capture, clipboard monitoring, or key logging;
- weak/reused passwords or a user exporting/copying plaintext;
- plaintext backups, local history, or session recovery created by an editor
  against Inex's guidance;
- denial of service, deletion, rollback to an older valid Git commit, or
  traffic analysis.

Full-disk encryption, a trusted editor profile, OS updates, and protected
swap/hibernation remain recommended.

Release evidence has an additional host trust boundary. A binding run requires
a dedicated standalone, exclusive, quiescent checkout. From interpreter startup
until artifacts and the JSON report are captured, no editor, sync client,
watcher, sibling worktree, build process, or other process with the same OS
principal may modify the worktree, `.git`, index, refs, config, generated inputs,
target/artifact directories, `PATH`, or toolchain. Start/end identity, Git-tree,
and byte checks detect observed drift; they are not an OS lock and cannot defeat
an authorized writer that changes and restores state between samples. Manifest
source identity is provenance metadata, not an independent attestation that
generated binaries or editor bundles were built from that commit.

## Storage invariants

1. Core and clients never create a temporary plaintext `.md` file.
2. Atomic-write staging files contain complete authenticated ciphertext.
3. Search indexes and decrypted document caches are memory-only in v1.
4. Lock, idle expiry, editor close, EOF, and shutdown invalidate sessions and
   wipe owned secret buffers on a best-effort basis.
5. Passwords, session tokens, keys, and plaintext are never written to logs or
   returned in diagnostic errors.
6. Git diff/merge artifacts remain encrypted, including unresolved conflict
   text.

These are invariants of Inex-owned code and artifacts. They do not claim that
another editor extension, clipboard manager, screen recorder, accessibility
service, backup agent, terminal transcript, debugger, or operating-system
facility cannot copy plaintext while a vault is unlocked.

## Credentials and operational disclosure

Passwords are exact UTF-8 bytes and are not normalized or trimmed. There is no
password reset, escrow, recovery key, or backdoor. A usable backup requires the
matching `vault.json`, ciphertext, and at least one valid password slot/password.

CLI password and query input must not be placed in argv or environment values.
The explicit stdin modes are intended for controlled automation, but the pipe
and supplying process become part of the trusted boundary. `inex search`
prints plaintext match snippets to stdout; terminal scrollback, redirection,
and transcript capture are therefore plaintext disclosure surfaces.

Vault directory names, file basenames, file sizes, timestamps, document count,
Git history shape, and access timing are visible in v1. Do not put secrets in a
logical path, branch name, commit message, remote URL, package filename, error
report, or backup label. Git gives versioned ciphertext availability, not
rollback protection against replacing the repository with an older valid
state.

Stop every editor-integrated or command-line Git operation before running
`inex git merge` or `inex git recover` in the supported release workflow. New
transactions now generate and verify an alternate index, install an
Inex-owned marker at the real `.git/index.lock`, bind old/candidate index
digests in journal v4, and publish the candidate only after the locked
worktree/owner/provenance recheck. Before the alternate candidate is created, a
durable create-only pre-lock reservation binds its random private name and the
old index digest; a fresh process can therefore classify a pre-lock abrupt exit
without relying on destructors. Create-only initial/final ownership receipts
then bind candidate bytes before mutation and before real-lock publication;
ambiguous receipt gaps preserve all state and require investigation instead of
guessing ownership. A normal Git index writer either wins before the real lock
or fails while it is held. This does not serialize ref-only commands,
legacy v1/v2/v3 journal recovery, or a same-OS-user process that directly
unlinks or rewrites transaction files. Native Windows abrupt-kill and
power-loss behavior is also not yet binding evidence, so deliberate concurrent
Git remains outside the supported checkpoint.

Password add/change/remove operations rewrap the same stable master key; they
are not master-key rotation. A person who retains an older `vault.json` from Git
history or backup and knows its old password can recover that master key and
decrypt later same-epoch EDRY files. Removing a current slot therefore does not
revoke historical access. Master-key rotation and a supported re-encryption
migration are not implemented in this checkpoint; treat a disclosed password
plus historical metadata as a vault-key compromise.

## Editor caveat

The sidecar can control its own storage, but it cannot prove that another
extension, the OS, or a backup product never persisted a buffer. In particular,
VS Code can back up any modified ordinary working copy independently of the
`files.hotExit` shutdown setting. Inex therefore edits through a custom editor
whose backup implementation writes authenticated ciphertext; it does not expose
the writable journal as an ordinary TextDocument/FileSystemProvider. The client
also audits relevant persistence settings and runs release-time residue tests.
The Sublime client uses scratch buffers and self-managed encrypted drafts,
requires safe application-global persistence settings before writable mode,
and marks managed plaintext views with a fixed non-secret setting. Plugin-load
code and pure tests require orphaned marked views to be scrubbed before editing
resumes, or the client blocks. Exact Build 4200 black-box evidence shows a
hard boundary: after the plugin host is killed, Sublime does not restart it in
the same editor process. No Inex code is then running, the already open buffer
remains visible and actively copyable, and the user must restart the entire
Sublime application to end that editor-process plaintext lifetime. The marker
is a load-time defense, not observed same-process crash recovery or
instantaneous containment. Sublime remains experimental until the complete
black-box residue matrix passes. Its API cannot veto every application-exit
path, so safety takes precedence over guaranteeing the final unsent keystrokes
survive an abrupt exit.

## Cryptographic design

- Password KDF: Argon2id via libsodium, with parameters stored per password
  slot and a creation-time policy floor.
- Vault secret: random 256-bit master key, wrapped by a password-derived KEK.
- File encryption: random nonce and XChaCha20-Poly1305-IETF per complete file.
- File keys: domain-separated, keyed derivation from the master key and full
  128-bit random file identifier.
- Authentication: the canonical EDRY header, including vault identity and
  normalized logical path, is associated data.

Normal creation now process-caches a public-dummy-input, ops-only calibration
over 3–20 operations at fixed 64 MiB, targeting a 250–750 ms single KDF
measurement. Explicit RPC creation has the same independent cap rather than the
broader reader ceiling. Password add/change preserves the componentwise
stronger values of the authenticated slot within reader limits. Deterministic
core/handler tests plus real Linux CLI and daemon process tests cover these
paths; native platform timing and resource behavior remain release evidence
gates.

Changing a password rewraps the stable master key and does not rewrite journal
files. Master-key rotation is represented by a key epoch and is a distinct,
explicit migration that is not implemented by the current CLI.

## Reporting vulnerabilities

Do not include real passwords, keys, plaintext journals, session tokens, or
vaults in an issue. Until a private reporting channel is published, create a
minimal report stating that a security issue exists, the affected Inex/editor
version and platform, and request a private contact path. Do not include a
plaintext canary body; a path category and digest are sufficient for initial
triage.

Public distribution remains blocked until a private reporting path and a
supported-version policy are published. Security fixes must retain a minimal
reproducer using synthetic data, update the acceptance matrix, and rerun the
exact native/package/editor gate affected by the issue.
