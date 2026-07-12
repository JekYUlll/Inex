# Installation and Development Setup

Inex does not yet publish supported binaries, a supported VSIX, or a Package
Control package. This document describes a source-built **development
checkpoint**, not a production installation. Use a disposable vault and keep
an independent backup of every source document.

The canonical source repository is <https://github.com/JekYUlll/Inex>. The VS
Code extension publisher remains `horeb`; that identifier is not a vault Git
remote. Configure each vault with a separate private remote chosen by its owner.

## Accepted storage-shape prerequisites

The implementation currently targets:

- local Windows or Linux filesystems only; network shares, FUSE mounts, nested
  bind mounts, symlink/junction traversal, and linked Git worktrees fail closed;
- Rust 1.97.0, whose Unicode 17 tables are part of the frozen path contract;
- a C compiler, `make`, and a shell for the pinned bundled libsodium build on
  Linux; use an MSVC Rust toolchain for a future native Windows release build;
- a Linux kernel/runtime with usable `openat2` for copy-import source and
  publication identity binding; import fails closed when it is unavailable;
- Git 2.36 or newer for encrypted merge plumbing;
- VS Code 1.125.0 or newer for the primary client;
- exactly Sublime Text Build 4200 for the experimental secondary client;
- Node.js 22 or newer and pnpm 10.32.1 only when building/testing the VS Code
  extension (`@vscode/test-electron 3.0.0` sets the effective Node floor);
- Python 3.13.14 for the release helpers; Sublime's embedded plugin runtime is
  separately pinned to Python 3.8 syntax by `.python-version`.

Linux and Windows x64 are the first intended release targets. A Linux x64
candidate is acceptable only when a separately preserved report matching its
manifest and checksums records system-GCC package/audit/smoke plus an isolated
VS Code install with bundled sidecar. Native Windows and Linux/Windows arm64
remain release gates; a successful Linux or Wine run is not evidence for them.

Do not place a vault inside a cloud-provider virtual filesystem or a directory
that contains symlinks/junctions. A normal local directory that is synchronized
by a tool which copies complete ciphertext files is the intended shape, but
concurrent sync replacement is still detected as an etag conflict and must be
resolved explicitly.

## Build the Rust programs

From the repository root:

```sh
rustc --version
cargo build --release --locked -p inex-cli -p inex-daemon
INEX="$(pwd -P)/target/release/inex"
INEXD="$(pwd -P)/target/release/inexd"
"$INEX" --version
test -x "$INEXD"
```

The outputs are `target/release/inex` and `target/release/inexd` (with `.exe`
on Windows). Keep the CLI and daemon from the same source revision. For a local
manual installation, copy both regular files into one private directory and do
not replace either with a symlink. `inex serve` accepts only a sibling `inexd`
or an explicit `INEXD_PATH`; the editor clients have their own stricter
absolute-path setting and never search `PATH`.

The POSIX examples below assume `INEX` remains set to that reviewed absolute
path in the same shell. If you copy the pair elsewhere, update `INEX` to the
absolute copied CLI path before continuing; do not rely on an unrelated `inex`
found through `PATH`.

The default build uses the pinned `libsodium-sys-stable` path and committed
`Cargo.lock`. Do not enable moving dependency features such as `fetch-latest`
for a release candidate. See [dependencies.md](dependencies.md) for the supply
chain and license policy.

The xlings-default linker on some development machines can produce an ELF whose
interpreter/RUNPATH refers to a local toolchain home. It is not portable, and
the release helper rejects it. A Linux x64 candidate must instead use a
reviewed system toolchain, for example:

```sh
env CC=/usr/bin/gcc CXX=/usr/bin/g++ \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc \
  cargo build --workspace --release --locked
```

Do not bypass the package check for ELF architecture, interpreter, or
RPATH/RUNPATH merely because an xlings-built binary starts on its build host.

On native Windows PowerShell, the same source-build check is:

```powershell
cargo build --release --locked -p inex-cli -p inex-daemon
& .\target\release\inex.exe --version
```

The repository has not yet produced binding native Windows release evidence;
these commands describe the intended MSVC build shape, not a supported binary.

### Candidate portable-binary archive

The implemented release tooling creates `inex-rust-<version>-<platform>.zip`
with `bin/inex[.exe]`, `bin/inexd[.exe]`, bundled documentation, manifests,
checksums, a target-bound resolved license inventory, the canonical engineering
license policy, and complete collected license/NOTICE texts. Current strict
release-tool source tests pass 76/76. Two clean-source system-GCC Linux x64
builds are required to be byte-for-byte identical across both binaries and all
four output files. Both must pass strict release-set/native audit, isolated VS
Code install, and executable/bundled-sidecar smoke; their manifests must record
the canonical repository, the same exact commit, and `dirtySourceTree=false`.
That source identity is provenance
metadata, not an independent attestation that generated binaries or editor
bundles were built from the commit; reproducible builds, artifact hashes and
native audits remain separate evidence.
A third clean standalone clone must bind the same source and exact artifact
hashes while authenticating all five synthetic bodies after copy import,
password rewrap, Git-bundle restore and clean regular-file tree-copy restore.
CLI wrong-password, RPC authentication-failure, and locked merge-driver
negative paths must disclose no dynamic secret. Require the separately
preserved lifecycle report before trusting a candidate; this bundled guide does
not attest its own archive. Any such result remains a local Linux normal-path
checkpoint, not native multi-platform, signing, publication, or legal evidence.
For a development candidate,
verify `SHA256SUMS` through a separate trusted channel, inspect the package
manifest/source revision, extract the complete directory, and keep both
binaries together. There are no official signatures yet, and native
multi-platform/editor-profile gates remain incomplete, so no candidate is
currently supported.

After extraction, the following fixed commands report the reviewed cryptographic
runtime without prompting for a password or starting the daemon protocol:

```sh
./bin/inex runtime-info
./bin/inexd --runtime-info
```

The packaged CLI also exposes its public-dummy KDF selector observation:

```sh
./bin/inex kdf-calibration-info
```

This is a strict no-argument command: do not append a vault, password, query, or
policy override. It runs before password/query input setup and writes no
persistent Inex product state, but it may initialize libsodium and consumes CPU,
secure allocation, and the fixed 64 MiB Argon2id memory setting. A manual run is
diagnostic only; it is a fresh process and does not warm a later `init`,
`import`, or daemon calibration.

The package smoke requires the platform's fixed Rust target triple,
`rust-debug-assertions: false`, libsodium `1.0.22`, ABI `26.4`, and
`libsodium-minimal: false` from every embedded executable copy. This prevents a
Windows GNU/debug binary from being mislabeled as the MSVC release package.

## Create a disposable vault

### Recommended: import an existing Markdown tree

The destination must not exist, and its parent must already be a supported
local directory. The source is read-only from Inex's perspective.

```sh
"$INEX" import /absolute/plaintext-source /absolute/inex-vault --dry-run
"$INEX" import /absolute/plaintext-source /absolute/inex-vault
```

PowerShell uses ordinary non-secret path variables; the password still belongs
only in Inex's later hidden prompt:

```powershell
$source = 'C:\Users\me\Journal-Plaintext'
$vault = 'C:\Users\me\Inex-Vault'
& .\target\release\inex.exe import $source $vault --dry-run
& .\target\release\inex.exe import $source $vault
git -C $vault init
& .\target\release\inex.exe git install-driver $vault
```

Read the dry-run counts carefully. Only exact lowercase UTF-8 `.md` regular
files are imported. Other regular files are counted and skipped; links,
reparse points, special entries, unsafe paths, collisions, and boundary
violations abort the import. The real run prompts for and confirms a new
password. Destructive in-place conversion and importing into an existing vault
are not implemented.

### Empty administrative vault

```sh
"$INEX" init /absolute/inex-vault
```

`init` creates and authenticates `vault.json` and prints the first password-slot
UUID. Record that UUID in a private administration record; it is not a secret,
but it is needed to disambiguate slots after adding passwords. Both editor
clients can now create the first encrypted Markdown document and folders; their
file-management limits are documented in [the user guide](user-guide.md).

The real import and `init` perform an ops-only Argon2id calibration before
reading the new password. v1 fixes memory at 64 MiB and parallelism at one and
selects operations 3–20 toward a 250–750 ms public-dummy selector observation.
That observation includes validation, possible libsodium initialization,
secure allocation, and Argon2id and ends before the derived-key allocation is
dropped; it is not pure KDF or end-to-end command latency. The full command
takes longer because it then derives the real KEK, commits metadata, and reopens
the vault for authentication. Native-platform timing and resource availability
remain part of the release matrix.

For each final native artifact set, run the reviewed
`scripts/drill_kdf_calibration.py` harness exactly once. It launches two
separate exact runtime-info probes for the packaged CLI/daemon plus exactly
three fresh packaged-CLI calibration attempts, preserves attempts 1–3 in order,
permits no retry or cherry-picking, and creates a new canonical JSON outside the
artifact/package directory. On POSIX, pre-create the private output directory
with mode `0700`:

```sh
ARTIFACT_DIR=/absolute/path/to/final/native-platform
EVIDENCE_DIR=/absolute/private/external-evidence
install -d -m 700 "$EVIDENCE_DIR"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts \
  python3.13 scripts/drill_kdf_calibration.py \
  "$ARTIFACT_DIR" --output "$EVIDENCE_DIR/kdf-calibration.json"
```

The output path itself must be absent, and POSIX verifies mode `0600`.
Run from the exact clean reviewed harness checkout. During the bounded artifact
snapshot, the four-file artifact directory must be exclusive and quiescent;
through evidence capture no same-principal writer may modify the harness. The
native host, monotonic clock, kernel, exact Python, and reviewed harness remain
explicit trust assumptions rather than independently attested inputs.

The current harness runs on native Linux x64/arm64. It deliberately fails closed
on Windows before artifact use until suspended-before-Job assignment, a
Job-empty cleanup barrier, and NTFS ADS residue enumeration are implemented and
verified. Windows x64/arm64 MSVC remain required rows; cross builds, Wine, and
emulation do not satisfy them. The report binds
the clean artifact and harness sources, harness/runtime identity, audited
artifact and packaged CLI/daemon, native host/resource observations, and all three
strict reports. Do not copy the dynamic JSON into any package input. Peak
resource observations and the 120-second harness termination timeout are
capture controls, not product performance or latency SLAs.

## Initialize Git in each clone

After import or init:

```sh
git -C /absolute/inex-vault init
"$INEX" git install-driver /absolute/inex-vault
git -C /absolute/inex-vault status
```

The installer requires the exact top-level worktree and writes only:

- the managed `*.md.enc -text -diff merge=inex` line in `.gitattributes`;
- the managed `/.vault-local/` line in `.gitignore`;
- repository-local `merge.inex.*` configuration containing the canonical
  absolute path of the current `inex` executable; and
- repository-local `core.longPaths=true` on Windows.

Commit `vault.json`, `.gitattributes`, `.gitignore`, directories as represented
by their files, and every `*.md.enc` file. Never commit `.vault-local/`. Run
`inex git install-driver` explicitly in every clone and again after moving or
replacing the `inex` executable, because local Git config and its absolute
driver path do not travel with the repository.

## VS Code development client

Build and verify the extension bundle:

```sh
cd editors/vscode
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm build
```

Set the machine-scoped `inex.sidecarPath` setting to the absolute path of the
matching regular `inexd` binary. With the extension directory loaded through an
Extension Development Host, open the **real ciphertext vault directory** as the
workspace. The extension does not support virtual or untrusted workspaces.

For example, from `editors/vscode` on Linux:

```sh
code --extensionDevelopmentPath="$PWD" /absolute/inex-vault
```

Use an otherwise clean editor profile while evaluating the checkpoint. Inex
does not globally disable Hot Exit or Local History: its custom editor writes
EDRY ciphertext for its own backup, and the real workspace resource is already
ciphertext. The automated Extension Host tests on the current local build and
1.125.0 validate that controlled backup path and directly drive the production
create/folder-create/file-rename/file-delete actions against the daemon/custom
editor. They include close refusal, rename collision, delete I/O failure
recovery, and isolated-root residue checks. They do not mouse-drive the
InputBox/QuickPick UI, and a persistent-profile cross-restart residue matrix
remains pending. Installing the checkpoint into a profile that contains
untrusted extensions is outside the security model.

A packaged extension contains the platform daemon at:

```text
bin/<node-platform>-<node-architecture>/inexd[.exe]
```

No current VSIX has been designated supported. A bundle without the correct
regular daemon is not a complete install.

### Candidate VSIX shape

The release tooling creates a platform-specific VSIX rather than one universal
extension. Its audit binds the manifest, Content Types, package identity,
version, publisher, target platform, engine, entry point, assets, and matching
sidecar. The external record for an exact candidate must additionally show a
successful isolated VS Code CLI install and bundled-sidecar smoke. An isolated
development profile can install an audited candidate with:

```sh
PLATFORM=linux-x64
code --install-extension "/path/to/inex-vscode-0.1.0-${PLATFORM}.vsix" \
  --user-data-dir /path/to/disposable-user-data \
  --extensions-dir /path/to/disposable-extensions
```

The VSIX target, host OS/architecture, and bundled daemon directory must match.
This command only installs an artifact; it does not make the persistent-profile
residue gate pass.

## Sublime Text experimental client

Use only a disposable, isolated Sublime Text Build 4200 profile. From Sublime,
choose **Preferences > Browse Packages**, copy `editors/sublime` to a directory
named `Inex`, and either:

- copy the matching regular daemon to `Inex/bin/inexd` (`inexd.exe` on
  Windows); or
- set an absolute regular `sidecar_path` in `Inex.sublime-settings`.

The following values must be set in the application-global
`Preferences.sublime-settings`, with the exact types shown:

```json
{
  "hot_exit": "disabled",
  "hot_exit_projects": false,
  "update_system_recent_files": false
}
```

Then configure the package:

```json
{
  "vault_path": "/absolute/path/to/inex-vault",
  "sidecar_path": "/absolute/path/to/inexd",
  "zenity_path": "/usr/bin/zenity",
  "draft_debounce_ms": 250
}
```

On Linux the password helper must be an audited regular `zenity` executable.
On Windows the plugin accepts only the system Windows PowerShell path and uses
a fixed masked WinForms dialog. macOS unlock is not implemented. The package
refuses writable mode on any Sublime build other than 4200 or whenever the
global persistence gate differs.

The Command Palette exposes **New Encrypted Markdown**, **New Folder**,
**Rename Active**, and **Delete Active**. Rename/delete require an active clean
writable managed file; save dirty content first. Directory rename/delete is not
implemented. Every managed plaintext view carries a fixed non-secret marker.
Plugin-load code and the pure suite require orphaned marked views to be scrubbed
before allowing editing, but exact Build 4200 does not restart a killed plugin
host inside the same editor process. After host death, no plugin code is
running: an already visible buffer remains actively copyable until the entire
Sublime application is restarted. The marker is a load-time defense, not
observed same-process crash recovery or instantaneous fail-safe isolation.

The pure-Python suite is useful for development:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=editors/sublime \
  python3 -m unittest discover -s editors/sublime/tests -v
```

It does not replace the binding open/edit/save/close/crash residue matrix. The
current pure suite passes 61/61. An isolated exact Build 4200 normal E2E passed
unlock/open/edit/save/close and used registered WindowCommands plus real InputPanel/
QuickPanel interaction for New Folder, New Markdown, rename, and etag-bound
delete. Authenticated `listTree` checks passed after each step,
`crud_complete=true`, events record `folder_created`, `markdown_created`,
`renamed`, and `deleted`, `vault_envelope=EDRY`, and `root_scan_hits=0`. Its
plugin-host SIGKILL probe is classified
`PASS_WITH_DOCUMENTED_BOUNDARY`: the host did not restart,
the visible plaintext could still be copied, a full Sublime restart was
required, `vault_envelope=EDRY`, and the roots scanned after application exit
reported zero disk hits. Its `crud_complete=false` is intentional: the crash
branch kills the host after open/edit/save, while the normal branch separately
covers CRUD. That reproduces the editor-memory/active-clipboard boundary; it is
not a crash-erasure pass. The package remains experimental until the complete
matrix passes for the exact packaged artifact and platform.

### Candidate Sublime archive shape

The release tooling produces an `inex-sublime-...zip` containing an unpacked
`Inex/` directory, not a compressed `.sublime-package`. Require the exact
candidate's external record to show content audit and bundled-sidecar smoke.
Extract the directory into the isolated profile's `Packages` directory so
`Inex/bin/inexd[.exe]` is a real regular executable. Installing the ZIP does not
promote the experimental client or replace the exact-package matrix.

## CI configuration status

The repository now contains CI/package matrices for Linux x64, Windows x64,
Linux arm64, and Windows arm64, with third-party actions pinned to immutable
commits. Push and manual tag refs bind exact `vMAJOR.MINOR.PATCH` to the parsed
workspace/package version. The required job runs the binding pedantic/
all-features and whitespace gates; each package target reruns native x64 tests
or compiles ARM test targets, enforces canonical repository/origin provenance,
and installs/smokes its platform VSIX with VS Code 1.125.0. The workflow files
pass local `actionlint`, but they have not been pushed or
executed by the remote service. Runner-label availability, native builds,
tests, and uploaded artifacts are therefore configuration intent, not binding
evidence.

## Installation sanity checks

Before using even disposable content:

1. Run `"$INEX" verify <vault>` and read its scope: it is a locked structural
   check, may recover a pending ciphertext transaction, and does not
   authenticate content.
2. Unlock through the intended editor and open an imported document.
3. Edit and save, then confirm Git sees only `*.md.enc` changes.
4. Lock the editor and confirm the document becomes a locked view.
5. Search the test profile, vault parent, temporary directory, and logs for a
   unique disposable canary. Absence in this manual check is useful diagnostic
   evidence, not a replacement for the release residue matrix.
6. Preserve the original plaintext source until the encrypted vault has been
   independently backed up, restored, unlocked, and compared.
