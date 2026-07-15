# Editor Integration Security Contract

The editor clients are not ordinary text-file adapters. Their first design
constraint is to prevent editor recovery/history services from persisting
plaintext outside the vault.

## VS Code strict mode

### Resource and document model

- The real workspace remains the ciphertext Git repository.
- `inex.markdownEditor` is a `CustomEditorProvider<CustomDocument>` registered
  for `**/*.md.enc` with one editor per custom document.
- The provider derives and validates a logical path relative to the selected
  vault, then sends only that logical path to `inexd`.
- It never opens decrypted content as a `TextDocument`, registers a writable
  plaintext `FileSystemProvider`, or uses `CustomTextEditorProvider`.

This distinction is mandatory. VS Code manages backup for normal TextDocument
working copies independently of the shutdown-only Hot Exit setting. A custom
document instead makes the extension responsible for save and backup.

### Dirty, undo, save, and backup

- Debounced webview edits update one extension-owned model and fire only
  `CustomDocumentContentChangeEvent`. The textarea provides local editing undo;
  v1 does not claim integration with VS Code's custom-document undo stack.
- `saveCustomDocument` calls `file.write` with the base etag. A conflict keeps
  the model dirty and never retries with force.
- `backupCustomDocument` calls `draft.encrypt`; the extension writes returned
  EDRY draft bytes to `context.destination` and returns that encrypted URI as
  the backup id. Disposal deletes ciphertext only.
- `openCustomDocument` with a backup id requests vault unlock, authenticates the
  draft, and compares its embedded base etag. A stale authenticated draft may
  open only as an explicit recovery draft; save requires a second overwrite
  confirmation and still uses the current ciphertext etag.
- Revert reloads authenticated ciphertext and discards extension-owned edits
  after explicit VS Code confirmation.

### Authenticated file management

- New Markdown uses `file.write` with `ifNoneMatch: "*"`; folder creation uses
  `file.mkdir`. A successful file create opens only the real ciphertext custom
  editor resource.
- File rename reads the authenticated source etag, requires a non-existing
  destination, coordinates any open custom document, and never replaces a
  collision. A dirty open source requires explicit Save and Rename; close
  refusal or edits racing that save abort before mutation.
- File delete uses the authenticated current etag and explicit confirmation. A
  dirty open document is refused rather than discarded implicitly.
- On a mutation error after an open tab was prepared, the client refreshes the
  authenticated tree and attempts to reopen whichever source/destination is
  proven to survive. Directory rename/delete and interactive cross-directory
  moves are not exposed.
- Filename/path and confirmation UI closes on lock. Extension Host tests drive
  these same production actions directly, but do not mouse-drive their
  InputBox/QuickPick widgets.

Plaintext is never placed in `acquireVsCodeApi().setState`, workspace/global
state, secrets storage, mementos, output channels, telemetry, diagnostics,
backup identifiers, or URI query/fragment data.

Owned Node `Buffer` allocations are overwritten on replacement, lock, and
failure paths. JavaScript strings, V8 garbage-collected copies, Chromium form
state, and VS Code internals cannot be deterministically zeroized; lock replaces
each webview document with a script-free locked page and drops owned plaintext
references as best effort. Release claims therefore rely
on isolated-profile black-box residue tests, not on an in-memory wipe claim.

### Webview restrictions

- `default-src 'none'`; explicitly add only nonce-bearing bundled script/style
  sources required by the packaged editor.
- `localResourceRoots` contains only immutable packaged media (or is empty).
- No network requests, remote fonts/assets, dynamic code, or telemetry. The
  only image source is a revocable `blob:` URL assembled from an authenticated,
  bounded same-vault opaque asset; `data:`, `file:`, web, and extension-resource
  image sources remain disabled.
- Platform/Chromium spellcheck is disabled by default.
- Markdown preview HTML and links are sanitized; command URIs are not enabled.
- `retainContextWhenHidden` remains false. The extension model, not webview
  persisted state, is authoritative.
- Links, headings, references/backlinks, and search locations are implemented
  within the controlled custom editor/panels because language providers target
  TextDocuments.

### Session and failure lifecycle

- User activity sends a throttled authenticated `system.ping`; successful
  protected RPCs renew the client's local deadline to match the daemon.
- The local deadline, `SESSION_INVALID`, child exit, stdio failure, protocol
  failure, explicit lock, and extension deactivation all invalidate the unlock
  generation, wipe owned models, close plaintext-bearing Quick Inputs, and
  replace custom-editor webview content with a locked page.
- Document open is generation-bound. A lock while `document.open` or draft
  restore is pending clears any returned plaintext and closes the stale handle
  before a custom document can join the live set.
- Manual lock/switch prompts Save All Files / explicit discard / cancel for
  dirty Inex documents. Save snapshots the current webview before encryption;
  edits that race a save re-mark the model dirty.

### Manifest and release gate

- `extensionKind: ["ui"]` so the local sidecar stays beside the local vault.
- Virtual workspaces and untrusted workspaces are unsupported.
- Search uses `inexd`'s memory index, not proposed Text/File Search APIs.
- Inex does not disable Hot Exit or Local History globally. Its custom document
  supplies only authenticated EDRY backup bytes, while the real workspace
  resource is already ciphertext; disabling Hot Exit would remove the encrypted
  recovery path without reducing a plaintext `TextDocument` surface.
- Release tests launch VS Code with isolated `--user-data-dir` and
  `--extensions-dir`, exercise dirty/crash/recovery flows, then scan all backup,
  history, storage, log, temp, and vault roots for a unique canary.
- The local, 1.125.0, and 1.126.0 Extension Hosts also use the real CLI/daemon
  for feature-1 import and asset open/chunk/close, then exercise
  create/folder-create, close-refused rename, collision, delete I/O failure
  recovery, successful rename/delete, and tree/tab cleanup. This is checkpoint
  evidence only because test-mode workbench state is memory-backed and the
  first-use UI widgets/task-terminal are not mouse-driven.
- Until that exact black-box matrix passes for the packaged VS Code/VSIX pair,
  documentation must label disk-residue assurance as pending rather than
  inferred from the API design.

## Sublime Text experimental strict mode

Sublime's pre-save and pre-close listeners are notifications and cannot veto
the default operation. The public API also cannot mark a normal buffer clean
after a custom encrypted save. Consequently, Inex does not use a normal dirty
buffer and does not promise native dirty semantics.

### Hard gate

Before inserting any plaintext, the plugin verifies application-global:

```json
{
  "hot_exit": "disabled",
  "hot_exit_projects": false,
  "remember_open_files": false,
  "update_system_recent_files": false
}
```

Build 4200 still recognizes `remember_open_files` even though it is absent from
the shipped default settings file. The gate requires Boolean `false` because
that setting can restore open views independently when Hot Exit is disabled.

Any mismatch blocks writable mode. A project/view setting is not an acceptable
substitute. Existing recent/session data is outside the plugin's ability to
erase and must be cleaned by the user/profile owner.

### Managed buffer lifecycle

- Create `new_file()`, set scratch before inserting plaintext, never assign a
  plaintext filename, and keep the physical ciphertext path out of view state
  where it could become a recent-file target.
- Set one fixed non-secret managed-plaintext marker before insertion. On plugin
  host load, scrub every orphaned marked view before enabling editing; if
  fixed-text replacement cannot be acknowledged, block the client. Pure tests
  enforce this invariant, but it is not evidence that Build 4200 restarts a
  killed host in-process.
- Track saved version/hash and dirty status in plugin memory; expose them with
  tab/status UI rather than `view.is_dirty()`.
- Rewrite Save with `on_text_command`; rewrite known Save As/Save All/close
  window commands with `on_window_command`. Pre-save is only a fail-safe alarm,
  not the security interception mechanism.
- On each edit, a short debounce writes an EDRY encrypted draft. Pre-close does
  a synchronous best-effort final draft flush, but cannot cancel closing.
- If the sidecar/draft write fails, warn immediately and retain memory while the
  view exists. An abrupt application exit may lose final edits; the plugin must
  never persist plaintext to avoid that loss.

While the plugin host is dead, none of those hooks runs. A marked buffer already
owned by the editor remains visible and actively copyable. Exact Build 4200
black-box evidence shows that a killed plugin host does not restart inside the
same editor process; the entire Sublime application must be restarted to end
that editor-process plaintext lifetime. The marker is a load-time defense, not
observed same-process crash recovery or instantaneous fail-safe containment.
That state remains inside the editor-memory/active-clipboard exclusion and the
binding crash matrix.

### Sublime file management

- New Markdown and folder commands accept a complete validated logical path and
  call create-only daemon methods.
- Rename/Delete Active require an active clean writable managed Markdown view.
  Rename is etag-bound and destination-create-only; delete is etag-bound and
  explicitly confirmed. Dirty, read-only, unmarked, named, or non-scratch views
  are refused/scrubbed as appropriate.
- Directory rename/delete is unsupported. Save As and physical `.enc` moves
  remain blocked substitutes.

### Experimental release gate

The current Python suite completes 96 tests with one platform-conditional skip.
Tests alone do not replace exact-package evidence. On Linux, separately preserved canonical reports bind three exact
packaged Build 4200 scenarios: normal schema v2, plugin-host-crash schema v2,
and full-application SIGKILL/restart schema v4. Each starts from a fresh
isolated profile and the same audited package bytes; restart v4 alone reuses
its profile/install across both launches.
The normal scenario drives unlock/open/edit/save/close and registered
WindowCommands with real InputPanel/QuickPanel interaction for New Folder, New
Markdown, rename, and etag-bound delete. Authenticated tree checks pass after
every mutation; events record `folder_created`, `markdown_created`, `renamed`,
and `deleted`, with `crud_complete=true`, `vault_envelope=EDRY`, and
`root_scan_hits=0`. The plugin-host SIGKILL scenario reports
`PASS_WITH_DOCUMENTED_BOUNDARY`,
`host_dead_clipboard_read_ok=true`, `host_dead_plaintext_copyable=true`,
`plugin_host_restarted=false`, and `sublime_restart_required=true`; roots
scanned after application exit report `root_scan_hits=0` and
`vault_envelope=EDRY`. The crash branch intentionally reports
`crud_complete=false` because it kills the host after open/edit/save; the normal
branch above covers CRUD independently. This proves the boundary was
reproduced, not that crash-time plaintext was erased.

The schema v4 flow keeps that same isolated profile and package for two
application launches. After the first encrypted save it kills the complete
profile-bound session/descendant closure through verified pidfds, stops the
private desktop and D-Bus infrastructure, and requires zero root-bound process
or mount survivors. Before the runner may answer the second password
prompt, every window and view must remain free of known content/token
fingerprints and Inex client/session/view state continuously for two seconds.
After unlock, reopening the same encrypted document must match the first
saved-content fingerprint. This passes one isolated full-application
SIGKILL/restart path; it is not evidence from a real-user persistent profile.

The remaining gate covers keyboard/menu Save, Save As, Save All,
tab/window/application close, project/non-project windows, export/macro routes,
additional daemon/plugin-host/full-application kill variants, real-user profile
Hot Exit/history/sync behavior, every advertised platform, and signing. It
scans session/workspace files, Cache, Index, temp roots, logs, and the vault for
a canary. No Sublime build is called supported until this complete
persistent-profile matrix passes; APIs marked for builds newer than the tested
baseline are not used.

## Shared client rules

- VS Code password input uses a secret InputBox; Sublime uses its reviewed
  external masked helper. Both send the value directly in one framed RPC
  request and never store it in settings/history.
- A sidecar crash makes open documents read-only until re-unlock and etag
  revalidation. Clients never retry a write without an etag.
- Lock prompts save/discard/cancel while dirty models exist. EOF/shutdown then
  closes document handles and invalidates the session.
- Clipboard/export/preview actions are explicit because they broaden plaintext
  exposure beyond the normal editor buffer.

## Primary references

- https://code.visualstudio.com/api/references/vscode-api#CustomEditorProvider
- https://code.visualstudio.com/api/extension-guides/custom-editors
- https://code.visualstudio.com/api/extension-guides/webview
- https://github.com/microsoft/vscode/blob/1.126.0/src/vs/workbench/services/workingCopy/common/workingCopyBackupTracker.ts#L82-L209
- https://www.sublimetext.com/docs/api_reference.html
- https://www.sublimetext.com/docs/api_environments.html
- https://www.sublimetext.com/docs/settings.html
- https://www.sublimetext.com/docs/safe_mode.html
