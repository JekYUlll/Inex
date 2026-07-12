# Release Checklist and Evidence Snapshot

This is the release decision surface for Inex. It supplements, but does not
weaken, [the binding acceptance matrix](acceptance-matrix.md). A unit test,
cross-compile, Wine run, API argument, or source audit cannot substitute for a
required native/editor/package black-box result.

## Current decision

> **NO-GO for GA, supported VS Code MVP, or supported Sublime release.**

The 2026-07-12 source checkpoint has strong Linux and cross-platform
development evidence, but the release gates below are intentionally incomplete.
The project must keep its pre-alpha warning and must not present any generated
archive as a supported install.

Status terms in this document mean:

- **verified:** the stated command/flow completed against the inspected source;
- **checkpoint:** useful implementation evidence whose platform/artifact scope
  is narrower than the binding release row;
- **partial:** some required cases passed and named cases remain;
- **pending:** no binding result is available;
- **not exposed:** required product behavior is not reachable in the current UI.

## Evidence already available

| Area | Status | Evidence and exact boundary |
|------|--------|-----------------------------|
| Linux Rust workspace | verified source checkpoint | 325/325 workspace tests pass with calibrated Argon2id creation/rewrap, index-CAS v4, native force-kill atomic-write, pre-lock ownership, and exact runtime-info regressions, plus rustfmt, all-target/all-feature pedantic Clippy with warnings denied, rustdoc warnings denied, and whitespace checks |
| EDRY/vault compatibility | checkpoint | Frozen v1 fixture rebuild/unlock/decrypt and broad format/path/tamper tests pass on Linux; Windows GNU compiles and earlier Wine suites pass, but this is not native Windows evidence |
| Import | verified source checkpoint; artifact evidence external | Copy-only absent-destination staging, re-open/seal/allowlist/publication, source-preservation, and failure-class tests pass. A binding artifact report must additionally import a five-document synthetic tree including exact 16 MiB content, preserve every source hash, and produce no plaintext Markdown in the vault; publication ambiguity and native-platform fault cases remain pending |
| Argon2id creation policy | verified Linux source checkpoint | Default create/init/import process-cache an ops-only 3–20 calibration at fixed 64 MiB toward a 250–750 ms dummy-input KDF measurement. Explicit RPC creation uses the independent 3–20/exact-64-MiB cap and fails before root creation; reader compatibility remains 20/1 GiB. Core and real CLI process tests prove password add/change retains both stronger authenticated components. Native host timing/resource behavior remains pending |
| Git | verified Linux fail-closed source checkpoint | Locked-safe driver, local installer, encrypted diff3, fixed tree provenance, full-width SHA-1/SHA-256, detected/split rename/modify, and legacy v1/v2/v3 recovery pass. New v4 transactions publish a canonical pre-lock reservation plus initial/final ownership receipts before holding the real `.git/index.lock`; Linux regressions cover orphan/partial/wrong-case/link/foreign state, pre-lock winner, lock-held Git failure, marker/candidate/published recovery, target drift, and foreign-lock preservation. A kill between candidate mutation and its matching receipt is detected and preserved as `RecoveryConflict`, not automatically recovered. Native Windows abrupt-kill/power-loss, ref-only concurrency, and legacy recovery CAS remain pending |
| VS Code unit/bundle | verified checkpoint | Strict TypeScript, 23/23 Node tests, production bundle, and integration bundle pass |
| VS Code Extension Host | partial | The current local build and 1.125.0 directly drive the production create/folder-create/file-rename/file-delete actions plus encrypted backup/recovery against the daemon/custom editor. Close refusal, rename collision, Unix delete-I/O failure recovery, command registration, and isolated-root residue pass. InputBox/QuickPick mouse interaction is not automated, and test-mode workbench storage is in-memory, so persistent cross-process restore/Local History is unproven |
| Sublime current source | partial | Pure-Python tests pass 61/61. An exact Build 4200 normal E2E drives unlock/open/edit/save/close and real-panel New Folder/New Markdown/rename/etag-delete through registered commands. `xdotool type --file -` reads the random password from its stdin and injects X11 keyboard events into the real absolute zenity masked entry; that password then joins the encoded full-root residue scan. Authenticated tree checks pass after each mutation; `folder_created`, `markdown_created`, `renamed`, and `deleted` are present, `crud_complete=true`, `vault_envelope=EDRY`, and `root_scan_hits=0`. The plugin-host SIGKILL probe remains `PASS_WITH_DOCUMENTED_BOUNDARY`: the visible buffer is copyable, the host does not restart in-process, a full Sublime restart is required, `vault_envelope=EDRY`, and roots scanned after application exit remain clean. Its `crud_complete=false` is intentional because the crash branch kills after open/edit/save; this is not crash-time plaintext erasure. The full packaged matrix is pending |
| Linux x64 packaging | binding evidence must be external | Two independent standalone system-GCC release builds must bind one clean source commit and produce byte-identical binaries, Rust ZIP, VSIX, Sublime ZIP, and SHA256SUMS. Both must pass strict release-set/native audit and isolated VS Code install/bundled-sidecar smoke; runtime must report GNU x64, release profile, and reviewed libsodium version/ABI/non-minimal status. Exact hashes cannot be self-attested by this bundled document |
| Linux x64 artifact lifecycle | binding evidence must be external | A third standalone clean clone must re-audit the exact artifact hashes and same product commit. Five expected bodies including exact 16 MiB content must authenticate after import, password rewrap, single-ref/single-commit Git bundle and clean tree-copy restores. CLI wrong-password, RPC auth-failure, locked merge-driver, driver relocation, frozen-v1, physical allowlist and descendant cleanup must pass with all three nondisclosure flags true and outside-source sensitive hits zero. Scope remains lifecycle-only, not release approval, independent build attestation, native fault-state, or two-version evidence |
| License collection | verified mechanism; artifact digest external | Strict audit requires all three packages to share one target-bound Cargo inventory, complete hashed license/NOTICE texts, and one sidecar digest. Exact counts and hashes must come from the external report matching the package manifests. Independent all-native artifact runs, legal review, and license-choice/signature policy remain pending |
| CI configuration | source-only, non-binding | Linux x64, Windows x64, Linux arm64, and Windows arm64 labels are configured; actions are immutable-SHA pinned and local `actionlint` passes. Push/manual tag refs bind the exact version; the required job runs binding source-quality gates; package targets rerun x64 native tests or ARM no-run compilation, enforce canonical provenance, and install/smoke each platform VSIX. The workflows have not been pushed or run remotely, so every matrix result remains unproven |
| Native Windows | pending | No native MSVC/NTFS/ReFS/FAT/exFAT release host result is available; GNU cross-check and Wine are non-binding |
| arm64 | pending | Linux arm64 and Windows arm64 native build/package/runtime matrices are not available |

Bundled documentation is a package input and cannot contain a binding hash of
the archive that contains it. Exact source, artifact, manifest, inventory,
sidecar, smoke, and lifecycle results therefore belong in a separately
preserved evidence record. Match that record to `PACKAGE-MANIFEST.json` and
`SHA256SUMS`; never relabel an existing package as an artifact of a later
documentation or evidence commit.

## Known release blockers

These are not documentation polish items; each changes the release decision:

1. Run all core, import, Git, daemon, fixture, long-path, Unicode, newline, and
   atomic/recovery tests on native supported Windows filesystems and MSVC.
2. Prove the final packaged VSIX plus bundled platform `inexd` in persistent
   Windows and Linux profiles across dirty close, normal restart, forced crash,
   Hot Exit, Local History, and recovery.
3. Complete the exact Sublime Build 4200 packaged open/edit/save/close/crash,
   macro/export/clipboard, draft, project/non-project, and canary residue matrix
   on every advertised OS.
4. Close the remaining GA Git transaction boundary. New v4 index updates have
   a held-lock expected-old CAS on Linux, but native Windows NTFS/ReFS
   abrupt-kill/power-loss remains unproven. Candidate/initial/final receipt-gap
   exits are visible and preserved as `RecoveryConflict` but still require
   manual investigation; legacy v1/v2/v3 recovery and concurrent ref-only
   mutation are not covered by the v4 index lock. Keep the supported
   operational rule that other Git is stopped until those cases have binding
   evidence.
5. Repeat the bounded Argon2id creation/explicit-cap/no-downgrade matrix on each
   native release target, recording hosts that select the 3/20 operation bounds
   or an interior above-window fallback because the preferred single-KDF window
   cannot be observed. Do not describe 250–750 ms as an end-to-end command
   latency SLA.
6. Build and smoke all four intended platform artifacts on their native target:
   Linux x64/arm64 and Windows x64/arm64. Verify executable architecture and
   dynamic/static native-library expectations, not only archive names.
7. Repeat the verified Linux x64 normal-path lifecycle on every native final
   artifact, then add
   publication/recovery fault-state preservation and a true two-version
   upgrade/rollback drill. A frozen-v1 read is compatibility evidence, not a
   substitute for two released program versions.
8. Complete independent legal review of the collected 77-component inventory,
   147 license/NOTICE texts, license-expression choices, and distribution
   obligations; collection is implemented but is not legal approval.
9. Push the exact clean source and pass the configured four-platform CI/package
   matrices. The local byte-identical Linux x64 pair establishes that checkpoint
   only; it does not establish hosted-runner availability or a native
   multi-platform release matrix.
10. Keep password-slot documentation explicit that rewrapping does not revoke
    an old password held with historical `vault.json`; master-key rotation is a
    separate unimplemented migration, not a hidden property of `password
    change`.
11. Establish a private vulnerability-reporting channel, supported-version
    policy, release signing keys, and a separately authenticated checksum/
    signature publication path.

## Source-quality gate

Run from a clean, reviewed commit with the pinned toolchain and lockfiles:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- \
  -D warnings -W clippy::pedantic
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
test -z "$(git status --porcelain=v1 --untracked-files=all)"
empty_tree=$(git hash-object -t tree /dev/null)
git diff --check "$empty_tree" HEAD -- .
GOBIN="$PWD/target/tools" \
  go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
test "$(target/tools/actionlint -version | sed -n '1p')" = "v1.7.12"
target/tools/actionlint .github/workflows/*.yml
```

- [ ] The commit is clean, tagged intentionally, and contains no test secret,
      canary, generated cache, build directory, editor profile, or real vault.
- [ ] `Cargo.lock`, VS Code `pnpm-lock.yaml`, and packaging-tool lockfile are
      committed and match the build.
- [ ] Every third-party CI action is pinned to a reviewed immutable commit SHA;
      a moving major-version tag is not a reproducible supply-chain pin.
- [ ] Linux x64, Linux arm64, Windows x64 MSVC, and Windows arm64 native jobs all
      run the applicable suite; a cross target is supplemental only.
- [ ] Frozen EDRY fixtures are byte-identical across targets and are opened
      without rewrite.
- [ ] Unknown format/protocol/required-feature fixtures fail closed.
- [ ] Native filesystem cases cover links/reparse points, mount boundaries,
      case aliases, long paths, atomic replace, durability classification, and
      recovery after injected interruption.
- [ ] A release build reports the reviewed libsodium version and is rebuilt
      offline from a populated, locked dependency cache.

## CLI, import, and backup gate

Maintainers can reproduce the verified Linux-only normal-path gate from a source
checkout. The tool first audits clean artifact provenance, creates only an
isolated disposable tree, never accepts a password in argv/environment, and
prints a body-free JSON summary:

```sh
ARTIFACT_DIR=/absolute/path/to/final/linux-x64
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts \
  python3.13 scripts/drill_release_lifecycle.py \
  "$ARTIFACT_DIR"
```

Run this only from the exact clean commit under review, in a dedicated
standalone, exclusive and quiescent release checkout. From interpreter startup
through artifact/report capture, no editor, sync client, watcher, sibling
worktree, build process or other same-principal writer may modify the worktree,
Git state, generated inputs, target/artifact directories, `PATH` or toolchain.
The tracked root `.gitattributes` applies `* -text` before materialization, and
the release checkout additionally requires `core.autocrlf=false`; actual
tracked bytes are hashed against the HEAD blobs, so any line-ending conversion
fails closed.
POSIX executable bits are bound on POSIX, while Windows uses its native
non-filemode checkout semantics and still binds the committed tree mode.
The command rejects special index flags,
replacement refs, redirected worktrees, non-canonical tracked bytes/modes, and
Git command output beyond its fixed safety bounds; it rehashes the complete HEAD
tree at both provenance boundaries. Those checks detect in-run drift but do not
turn a same-user-writable live checkout into an atomic snapshot. The command
fails before artifact use when the harness worktree is dirty, and it fails
closed on native Windows until Job Object descendant cleanup and NTFS ADS
residue coverage are implemented. A failure after the disposable evidence root has been created
prints and retains that private directory; early dirty-source, Windows, or path
validation rejection creates no evidence root. Inspect and remove a retained
directory explicitly after triage.

- [ ] Wrong password/slot, metadata tamper, weak KDF warning/resource ceiling,
      password add/change/remove, and "change committed, retirement deferred"
      recovery pass on each native platform.
- [ ] Conflicting `vault.json` versions are preserved and recovered by selecting
      one authenticated whole version plus CLI slot recreation; documentation
      and tests never suggest line-merging authenticated metadata.
- [ ] `inex verify` documentation and output remain explicit that it mutates
      recovery state and is structural, not authenticated.
- [ ] A disposable import covers dry-run, Unicode/newlines/empty/max-size files,
      skipped attachments, links/junctions, overlap, source mutation, existing
      destination, disk faults, publication ambiguity, and marker cleanup
      failure.
- [ ] Source hashes remain unchanged in every import result.
- [ ] For the exact candidate under review, use a third standalone clean clone to rerun the strict Linux x64
      artifact lifecycle with `dirtySourceTree=false`: import to one Git commit,
      require only `refs/heads/main` and no unreachable objects, create and
      verify both a Git bundle and clean regular-file tree copy, restore to
      new paths, relocate/reinstall the local driver, authenticate the exact
      tree and byte-compare all five expected bodies, and leave the disposable
      source hashes intact. The exact physical ciphertext allowlist and the
      sensitive content/path scan outside `plaintext-source` must also pass.
- [ ] Repeat that final-artifact lifecycle on every advertised native target and
      preserve injected import/recovery failure states, including their exact
      `.vault-local` and staging siblings.
- [ ] Documentation and help continue to reject in-place conversion and import
      into an existing vault; no release material implies otherwise.
- [ ] Backup/restore covers `vault.json`, all EDRY files, Git objects/refs, local
      driver reinstall, and failure-state preservation of `.vault-local`.

## Git gate

- [ ] Fresh clones before and after explicit `inex git install-driver` are
      tested; only local config changes locally, while managed attributes and
      ignore rules travel in Git.
- [ ] The installed driver has one canonical absolute executable word, no
      placeholders, no `PATH` lookup, and leaves every supplied path
      byte/metadata unchanged while returning conflict.
- [ ] Clean/conflicting diff3, add/add, delete/modify, Unicode/space/long path,
      concurrent mutation, attribute override, and crash recovery pass.
- [x] Rename/modify is implemented for exact detected and split Git shapes,
      with fixed tree provenance, source-aware recovery, ambiguity rejection,
      and Linux real-repository tests for both renamed sides.
- [ ] Native supported filesystems reproduce v4 marker/candidate/index
      publication and rename recovery under abrupt termination/power loss;
      ref-only concurrency and legacy-journal recovery are either serialized or
      retained as explicit no-parallel-Git scope before GA.
- [ ] Plaintext/password/query/token canaries are absent from Git argv,
      environment, stderr, object/journal/index/worktree artifacts, hooks, and
      helper processes.
- [ ] Native Windows verifies `core.longPaths`, index/object/worktree/journal
      flush behavior, interrupted transition recovery, and power-loss policy.

## VS Code gate

Run the source gates first. The named Extension Host scripts below are the
Linux/Xvfb harnesses and assume the local host at `/usr/share/code/code` plus
the downloaded 1.125 build; they are not native Windows commands. The Windows
release matrix must drive an equivalent explicit native host/profile path.

```sh
cd editors/vscode
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm build
pnpm test:extension:local
pnpm test:extension:1.125
```

- [ ] Package one platform-specific VSIX per target with exactly one matching
      regular `bin/<platform>-<architecture>/inexd[.exe]`.
- [ ] Install each VSIX into a new persistent profile; do not use only
      `extensionTestsLocationURI` test mode.
- [ ] Exercise edit/undo/save/revert, dirty close, normal restart, forced kill,
      backup restore, stale restore, lock/idle/daemon crash, search, headings,
      links, backlinks, and etag conflict.
- [ ] Exercise the actual InputBox/QuickPick UI for file/folder create, file
      rename/delete, cancellation, validation, confirmation, dirty save-before-
      rename, close refusal, collision, mutation I/O failure, and tree/tab
      recovery. Direct production-action calls are strong checkpoint evidence
      but do not prove mouse/keyboard UI wiring.
- [ ] Repeat with relevant Hot Exit and Local History settings and scan the
      vault, parent staging, temp, user/workspace storage, backup/history,
      extension state, logs, telemetry, and crash roots.
- [ ] Test Linux and native Windows with the exact advertised VS Code versions.
- [ ] Confirm no plaintext `TextDocument`, backup identifier, URI, output
      channel, memento, state, filename, log, or package member exists.
- [ ] Treat JS/webview/VS Code memory wiping as best effort; make no deterministic
      zeroization claim.

Only after those checks pass may the VS Code client be called an MVP-supported
artifact. Passing the current in-memory-storage Extension Host harness alone is
insufficient.

## Sublime gate

Run the pure suite, then the exact-package black-box matrix:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=editors/sublime \
  python3 -m unittest discover -s editors/sublime/tests -v
```

- [ ] Build 4200 is exact; the profile/data, cache, temp, D-Bus/X11 control,
      package, and vault roots are isolated from the user's real profile.
- [ ] The packaged regular `inexd` and external password helper paths are
      exercised, not source-only test doubles for the binding flow.
- [ ] Keyboard/menu Save, Save As, Save All, clipboard, HTML print/export,
      preview, macro recording/save/playback, tab/window/application close,
      project/non-project, draft matching/stale/corrupt, idle expiry, daemon and
      plugin-host crash, and forced process kill are covered.
- [ ] Markdown/folder create and clean active-file rename/delete cover success,
      validation, collision, stale etag, cancellation, durability warning, and
      residue; directory rename/delete remains explicitly unsupported or its
      release scope is revised.
- [ ] Plugin-host death is tested as distinct states: while dead, an already
      visible marked buffer can remain visible and be actively copied; exact
      Build 4200 does not restart the host in-process, so a full application
      restart is required. Plugin-load marker scrubbing must complete before
      editing or block the client, but may not be presented as an observed
      same-process crash-reload path. Documentation never calls the host-dead
      state fail-safe or a crash-erasure pass.
- [ ] A unique dynamic canary scan covers content, filenames, UTF-8/UTF-16,
      base64/base64url, hex, fragments, logs, sessions, workspace, Cache, Index,
      temp, drafts, control roots, and vault.
- [ ] The report contains only fixed event names, booleans, lengths, counts,
      and digests; no managed text is uploaded or logged.
- [ ] The complete matrix passes on every advertised OS and exact package hash.

Until every item passes, the word **experimental** must remain in the package,
README, UI status, and release notes.

## Packaging, provenance, and license gate

The packaging helpers produce one native platform set:

```sh
test "$(python3.13 --version)" = "Python 3.13.14"
pnpm --dir editors/vscode install --frozen-lockfile
pnpm --dir packaging/vsce install --frozen-lockfile
pnpm --dir editors/vscode build
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts \
  python3.13 -m unittest discover -s scripts/tests -v
PLATFORM=linux-x64
NATIVE_TARGET_DIR=/absolute/native-release-binary-directory
VSCODE_CLI=/absolute/vscode-1.125.0-cli
PYTHONPATH=scripts python3.13 scripts/package_release.py --platform "$PLATFORM" \
  --target-dir "$NATIVE_TARGET_DIR"
PYTHONPATH=scripts python3.13 scripts/audit_release_artifacts.py \
  "target/release-artifacts/$PLATFORM"
PYTHONPATH=scripts python3.13 scripts/audit_native_dependencies.py \
  --platform "$PLATFORM" "$NATIVE_TARGET_DIR/inex" "$NATIVE_TARGET_DIR/inexd"
PYTHONPATH=scripts python3.13 scripts/smoke_release_artifacts.py \
  "target/release-artifacts/$PLATFORM" --vscode-cli "$VSCODE_CLI"
```

On the current Linux x64 host, strict release-tool source tests pass 60/60.
The binding workflow requires two standalone clean-source system-GCC builds to
be byte-identical across both binaries and all four package outputs; both must
pass strict release-set/native audit and isolated VS Code CLI
install/bundled-sidecar smoke. Current validation covers VSIX control metadata,
bounded regular ZIP members and Windows-portable path/mode collisions, exact
workspace/tag parsing, canonical provenance, and PE32+ structure/import ranges;
the original malformed-VSIX and ZIP bypass samples are rejected. Independent
release-tool code review is GO. The same helper rejects the xlings-default ELF
because its interpreter/RUNPATH refers to the build user's xlings home. This is
valuable tooling evidence, not a signed, independently attested, native
multi-platform release. Exact artifact results must be read from the external
record matching the package manifests.

- [ ] The helper scripts and pinned `@vscode/vsce` lockfile are committed,
      reviewed, and tested on each native host.
- [ ] Rust ZIP, platform VSIX, and unpacked Sublime-package ZIP contain only the
      explicit allowlist, matching native daemon, project license, package
      manifest, checksums, and third-party notices.
- [ ] Each offline artifact includes (or embeds a self-contained equivalent of)
      its installation, security, backup/recovery, upgrade, troubleshooting,
      and status documentation; every relative documentation link resolves
      inside the artifact or is an intentional absolute release URL.
- [ ] The Sublime artifact is documented as an **unpacked package** because its
      child daemon must be a real executable file; no compressed
      `.sublime-package` claim is made.
- [ ] SHA-256 manifests, internal member hashes, source commit, dirty-state
      policy, version, platform, and architecture are independently verified.
- [ ] Rebuilding twice in clean environments produces the expected reproducible
      result or every nondeterministic field is documented and signed.
- [ ] The release inventory is generated from locked native-target dependencies;
      all component license-file references resolve, and the bundled libsodium
      version/license are verified at runtime and in the archive.
      Current source tooling binds fixed target triples, Cargo.lock checksums,
      an explicit non-legal-approval expression policy, exact ISC text, shared
      three-package inventory/sidecar digests, and runtime-info target/release
      profile plus `1.0.22`/ABI `26.4`; native artifact reruns remain required
      before checking this row.
- [ ] Project GPL-3.0-only terms, the collected Cargo license/NOTICE texts, and
      bundled libsodium ISC are independently reviewed for legal completeness.
      Successful automated collection is not legal approval.
- [ ] Artifacts are installed and smoke-tested offline; creating a valid ZIP or
      VSIX is not an install/runtime test.
- [ ] Checksums and signatures are published through a channel distinct from
      the artifact hosting path, with signing-key handling documented.

## Documentation and release-note gate

- [ ] README status, supported OS/architecture/editor versions, and known
      limitations match the exact artifact evidence.
- [ ] Threat model, visible metadata, memory/editor caveats, clipboard/search
      output, and lack of password recovery are prominent.
- [ ] Installation, copy import, per-clone Git setup, backup/restore, encrypted
      conflict recovery, password-slot recovery, upgrade, rollback, and
      troubleshooting have been rehearsed from the artifacts.
- [ ] Release notes state EDRY/RPC versions, required Rust/Git/editor baselines,
      bundled libsodium, fixed security issues, deferred features, and all
      incompatible or unsupported states.
- [ ] A private vulnerability reporting path and supported-version policy exist
      before public distribution.
- [ ] Every remaining acceptance-matrix exception is either closed or reflected
      by an explicit PRD/threat-model scope change; no row is silently waived.

## Promotion rules

- **Core pre-alpha exit** requires all non-editor rows through session lifecycle
  plus compatibility on native Linux and Windows.
- **VS Code MVP support** additionally requires encrypted-draft and persistent
  packaged VS Code residue rows.
- **Sublime support** requires its exact package/build/platform residue row;
  functional unit tests cannot promote it.
- **GA** requires Git, import, upgrade, packaging, recovery documentation,
  license notices, and reproducible/offline release evidence.

If evidence is missing, stale, from a different hash, from Wine instead of
native Windows, or from an unpackaged source tree instead of the final artifact,
the corresponding item remains unchecked.
