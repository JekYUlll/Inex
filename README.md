# Inex

Inex is a cross-platform encrypted Markdown journal for Windows and Linux. A
vault is a normal Git repository containing `vault.json`, visible directory and
file names, and authenticated `*.md.enc` ciphertext. The editor clients ask a
local Rust `inexd` child process for controlled plaintext views; they do not use
a plaintext mirror directory.

> **Project status: pre-alpha development checkpoint (`0.1.0`).** The EDRY v1
> format, RPC v1, Rust core/CLI, copy import, encrypted Git merge, and both
> editor clients are implemented far enough for development testing. There is
> no supported release artifact or GA assurance yet. Do not use Inex as the
> only copy of important data.

Canonical repository: <https://github.com/JekYUlll/Inex>. The development VS
Code extension identifier continues to use publisher `horeb`.

## What is verified, and what is not

| Surface | Current evidence | Release limitation |
|---------|------------------|--------------------|
| Rust core, CLI, daemon, import, and Git | Linux tests and strict static gates pass, including authenticated detected/split rename/modify, legacy v1-v4 recovery, and the production v5 immutable candidate-bundle writer. Six native Linux SHA-1/SHA-256 shards cover 230 InPlace/DetectedRename/SplitRename OS force-kill cases spanning the durable state matrix; active transaction capabilities converge through fresh-process recovery and durable cleanup. Windows GNU compiles and selected Wine API tests pass | A kill before any scratch entry's no-replace publication may retain one orthogonal nonblocking entry for audit: a directory during bundle preparation or a regular file during publish/marker/journal preparation. Active cleanup intentionally does not guess-delete it. Native Windows still needs the same 230-case matrix with Job Object active-process-zero and handle-release proof, plus separate NTFS/ReFS write-through and power-loss evidence. OS force-kill is not power-loss evidence. Deliberate parallel Git remains outside supported use until native evidence and ref-mutation/legacy-recovery boundaries are closed |
| VS Code | 23 unit tests pass; the current local build and VS Code 1.125.0 Extension Hosts directly exercise the production CRUD actions plus encrypted backup/recovery and isolated-root residue scan | UI InputBox/QuickPick mouse interaction, persistent-profile cross-process Hot Exit/Local History/crash restore, and native Windows residue tests are pending |
| Sublime Text | 84/84 Python tests pass: 61 product tests plus 23 runner/evidence tests. On Linux, separately preserved canonical reports bind exact packaged Build 4200 normal v2, plugin-host SIGKILL v2, and full-application SIGKILL/restart v4 scenarios. Each starts from a fresh isolated profile and the same audited package bytes; restart v4 alone reuses its profile/install across both launches. It binds a subreaper/pidfd process closure, rejects root-bound survivors or mounts, scans every view continuously for two seconds before the second unlock, then reopens the same encrypted saved-content fingerprint | The plugin-host SIGKILL leaves the visible buffer copyable, cannot restart the host in-process, and requires a full Sublime restart. That is boundary evidence, not plaintext-erasure success. The passed restart is one isolated harness path, not a real-user persistent-profile result. Keyboard/menu Save and the remaining kill, profile/history/sync, full-platform, and signed-release matrix remain pending, so the client remains experimental |
| Packaging | Strict release-tool tests pass 76/76. The binding workflow requires two standalone clean builds, byte-identical binaries/packages, target-bound license and native audits, isolated editor smoke, and a third clean-clone lifecycle drill with dynamic secret scanning | Bundled documentation is intentionally non-self-attesting: accept an archive only when an external evidence record matches its `PACKAGE-MANIFEST.json` and `SHA256SUMS`. Native Windows/arm64, injected failure/two-version drills, persistent editor profiles, signatures, publication, hosted CI, and independent legal review remain pending |

The editor clients browse, create and edit encrypted Markdown, create folders,
search, and navigate. VS Code can rename/delete files from its encrypted tree;
Sublime can rename/delete only the active clean managed file. Directory
rename/delete is not exposed. These are checkpoint capabilities, not release
assurance.

The binding evidence and remaining gates are listed in the
[release checklist](docs/release-checklist.md) and
[acceptance matrix](docs/acceptance-matrix.md).

## Security boundary

Inex is designed to prevent someone who does not know the vault password from
reading journal bodies with ordinary filesystem, text-editor, sync, or Git
tools while the vault is at rest. It does not claim to resist a compromised
administrator/kernel, a malicious editor extension, live-memory forensics,
swap or crash-dump analysis, screen capture, clipboard monitoring, or key
logging. Directory names, file basenames, sizes, timestamps, and Git history
shape are intentionally visible in v1.

Password changes rewrap the stable master key; they do not revoke an old
password held together with historical `vault.json`. Master-key rotation is not
implemented in this checkpoint.

The storage invariant is:

> Inex-owned vault writes, atomic staging files, editor drafts, Git blobs,
> unresolved merge results, and indexes on disk contain ciphertext only.

Plaintext necessarily exists in editor, webview/plugin, and sidecar process
memory while unlocked. JavaScript, Python, editor internals, and operating-system
services cannot provide deterministic memory erasure. See
[`SECURITY.md`](SECURITY.md) and the
[editor security contract](docs/editor-security.md) before testing real data.

## Development quick start

Build the matched CLI and daemon from the repository root with Rust 1.97:

```sh
cargo build --release --locked -p inex-cli -p inex-daemon
```

Start with a disposable plaintext Markdown tree and an absent destination:

```sh
target/release/inex import /absolute/plaintext-source /absolute/inex-vault --dry-run
target/release/inex import /absolute/plaintext-source /absolute/inex-vault
git -C /absolute/inex-vault init
target/release/inex git install-driver /absolute/inex-vault
git -C /absolute/inex-vault add vault.json .gitattributes .gitignore '*.md.enc'
git -C /absolute/inex-vault commit -m 'Initialize encrypted Inex vault'
```

The real import prompts twice for a new password, never changes the source, and
publishes only to an absent destination after authenticating the complete
staging vault. Review skipped-file counts before treating the import as
complete. Do not put a password in argv, a shell variable, or an environment
value.

`inex kdf-calibration-info` exposes the fixed public-dummy Argon2id selection
observation for release diagnostics. It accepts no arguments, vault, password,
or policy override and does not warm the cache of a later process. Although it
writes no persistent Inex product state, it initializes cryptographic runtime
state as needed and consumes CPU and fixed 64 MiB Argon2id work memory. See the
[user guide](docs/user-guide.md) and [release checklist](docs/release-checklist.md)
for the exact output and native-evidence boundary.

Next follow the [installation guide](docs/installation.md) and
[user guide](docs/user-guide.md) for a development VS Code or experimental
Sublime setup. The quick start is not a release installation procedure.

## Components

- `inex-core`: cryptography, EDRY/vault formats, portable paths, atomic storage,
  encrypted drafts, search, and repository operations.
- `inexd`: strict Content-Length JSON-RPC sidecar with capability sessions,
  idle expiry, and memory-only plaintext state.
- `inex`: vault creation/verification, password slots, search, copy import, and
  explicit encrypted Git merge/recovery commands.
- `inex-git`: bounded system-Git plumbing, locked-safe driver installation,
  in-memory diff3, encrypted conflicts, and plaintext-free recovery journals.
- `editors/vscode`: primary custom-editor client for real `*.md.enc` resources.
- `editors/sublime`: experimental Build 4200 command/Quick Panel client.

## Documentation

- [Installation and development setup](docs/installation.md)
- [User guide](docs/user-guide.md)
- [Backup, import, Git, recovery, and upgrades](docs/operations-and-recovery.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Release checklist and current evidence](docs/release-checklist.md)
- [Draft 0.1.0 pre-alpha checkpoint notes](docs/release-notes-0.1.0-pre-alpha.md)
- [Product requirements](docs/PRD.md)
- [Architecture](docs/architecture.md)
- [Security policy](SECURITY.md)
- [Editor security contract](docs/editor-security.md)
- [Dependency, toolchain, and license policy](docs/dependencies.md)
- [EDRY v1 format](docs/spec/edry-v1.md)
- [Vault metadata v1](docs/spec/vault-v1.md)
- [JSON-RPC v1](docs/spec/json-rpc-v1.md)
- [Copy import v1](docs/spec/import-v1.md)
- [Git merge/recovery v1](docs/spec/git-merge-v1.md)
- [Acceptance matrix](docs/acceptance-matrix.md)

The implementation plan and live development record are kept in
`task_plan.md`, `findings.md`, and `progress.md`.

## License

Inex source is GPL-3.0-only. See [`LICENSE`](LICENSE). Distributed builds must
also carry the applicable third-party notices described in
[`docs/dependencies.md`](docs/dependencies.md). The committed
[`dependency-license-policy.json`](packaging/dependency-license-policy.json)
is an engineering collection allowlist, not legal approval.
