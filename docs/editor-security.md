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

- Webview edits update one extension-owned model. Each delta fires a
  `CustomDocumentEditEvent` whose undo/redo closures retain data in memory only.
- `saveCustomDocument` calls `file.write` with the base etag. A conflict keeps
  the model dirty and never retries with force.
- `backupCustomDocument` calls `draft.encrypt`; the extension writes returned
  EDRY draft bytes to `context.destination` and returns that encrypted URI as
  the backup id. Disposal deletes ciphertext only.
- `openCustomDocument` with a backup id opens locked, authenticates the draft
  after unlock, and compares its embedded base etag before offering restore.
- Revert reloads authenticated ciphertext and discards extension-owned edits
  after explicit VS Code confirmation.

Plaintext is never placed in `acquireVsCodeApi().setState`, workspace/global
state, secrets storage, mementos, output channels, telemetry, diagnostics,
backup identifiers, or URI query/fragment data.

### Webview restrictions

- `default-src 'none'`; explicitly add only nonce-bearing bundled script/style
  sources required by the packaged editor.
- `localResourceRoots` contains only immutable packaged media (or is empty).
- No network requests, remote fonts/assets, dynamic code, or telemetry.
- Markdown preview HTML and links are sanitized; command URIs are not enabled.
- `retainContextWhenHidden` remains false. The extension model, not webview
  persisted state, is authoritative.
- Links, headings, references/backlinks, and search locations are implemented
  within the controlled custom editor/panels because language providers target
  TextDocuments.

### Manifest and release gate

- `extensionKind: ["ui"]` so the local sidecar stays beside the local vault.
- Virtual workspaces and untrusted workspaces are unsupported.
- Search uses `inexd`'s memory index, not proposed Text/File Search APIs.
- Release tests launch VS Code with isolated `--user-data-dir` and
  `--extensions-dir`, exercise dirty/crash/recovery flows, then scan all backup,
  history, storage, log, temp, and vault roots for a unique canary.

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
  "update_system_recent_files": false
}
```

Any mismatch blocks writable mode. A project/view setting is not an acceptable
substitute. Existing recent/session data is outside the plugin's ability to
erase and must be cleaned by the user/profile owner.

### Managed buffer lifecycle

- Create `new_file()`, set scratch before inserting plaintext, never assign a
  plaintext filename, and keep the physical ciphertext path out of view state
  where it could become a recent-file target.
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

### Experimental release gate

Tests run on Sublime Build 4200 with `.python-version` 3.8, in Safe Mode or an
isolated data directory. They cover keyboard/menu Save, Save As, Save All,
tab/window/application close, project/non-project windows, plugin-host crash,
and forced process termination. Tests scan session/workspace files, Cache,
Index, temp roots, logs, and the vault for a canary. No Sublime build is called
supported until its exact matrix passes; APIs marked for builds newer than the
tested baseline are not used.

## Shared client rules

- Password input uses editor secret-input UI and goes directly in one framed
  RPC request; it is never stored in settings/history.
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
- https://www.sublimetext.com/docs/settings.html
- https://www.sublimetext.com/docs/safe_mode.html
