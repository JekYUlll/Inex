# Inex for Sublime Text — experimental strict client

This package is an experimental client for **Sublime Text Build 4200**. It
launches the local `inexd` process over strict Content-Length JSON-RPC, browses
the encrypted vault with Quick Panels, and edits Markdown in plugin-managed
scratch buffers. It never mounts a plaintext filesystem or assigns a plaintext
filename to a managed view.

It is intentionally fail-closed. No Sublime build is described as supported
until the exact packaged build passes the isolated-profile disk-residue matrix
described below.

## Required global preferences

Set these values in the application-wide `Preferences.sublime-settings`:

```json
{
  "hot_exit": "disabled",
  "hot_exit_projects": false,
  "remember_open_files": false,
  "update_system_recent_files": false
}
```

The values are checked by exact value and type before any plaintext is inserted
and again while a managed view is active. Project or view settings do not
satisfy this gate. Build 4200 still recognizes `remember_open_files` even though
it is not shown in the default settings file; it must be explicitly false so it
cannot restore open views independently of Hot Exit. If one value changes, Inex
drops its models and replaces the managed buffers with a fixed locked message.
Existing session, recent-file, cache, and index data predating the change remain
the profile owner's responsibility.

The package also refuses writable mode when `sublime.version()` is not exactly
`4200`; newer APIs are not assumed to preserve the tested behavior.

## Configure the package

Open `Preferences > Package Settings > Inex > Settings` (or edit
`Inex.sublime-settings`) and set:

```json
{
  "vault_path": "/absolute/path/to/ciphertext-vault",
  "sidecar_path": "/absolute/path/to/inexd",
  "zenity_path": "/usr/bin/zenity",
  "draft_debounce_ms": 250
}
```

- `vault_path` must be absolute.
- `sidecar_path` must name an absolute, non-symlink regular executable. If it
  is empty, only `bin/inexd` inside this package (`bin/inexd.exe` on Windows)
  is considered. There is no `PATH` fallback.
- On Linux, `zenity_path` may be empty only when a verified regular
  `/usr/bin/zenity` or `/usr/local/bin/zenity` exists.
- On Windows, the client accepts only the system
  `System32\WindowsPowerShell\v1.0\powershell.exe` and runs a constant WinForms
  dialog with `UseSystemPasswordChar`. The password is returned over the
  helper's stdout; it is never placed in argv, environment variables, settings,
  history, stderr, or logs.
- macOS has no reviewed secure helper in v1, so unlock is rejected.

The package never uses Sublime's ordinary visible `show_input_panel` for a
password. Python strings and the helper's immutable output bytes cannot be
deterministically zeroized, so references are kept only for the unlock call and
dropped immediately afterward. Owned `bytearray` buffers are overwritten on
replace, close, lock, and failure paths.

## Commands and data flow

- **Inex: Unlock and Browse Vault** opens the external masked password dialog,
  negotiates JSON-RPC v1 capabilities, unlocks one vault, and presents its tree
  in a Quick Panel.
- **Inex: Browse Vault** reopens the tree without another password prompt while
  the session is valid.
- **Inex: Search Vault** uses `search.query` and opens the selected logical
  Markdown location. The query and snippets remain transient UI data and are
  never logged or stored by the plugin.
- **Inex: Show Markdown Headings** parses ATX headings in memory, skips fenced
  code, and navigates through a Quick Panel. **Follow Relative/Wiki Link** does
  the same for vault-relative `.md`, heading, and `[[wiki]]` targets; URL,
  encoded, absolute, traversal, and non-portable targets are rejected.
- **Inex: Lock Vault** offers encrypted save, explicit discard, or cancel when
  plugin-owned dirty documents exist, then closes handles, locks the capability
  session, and shuts the child down.

Opening a document creates `window.new_file()`, calls `set_scratch(true)`
**before** insertion, leaves `view.file_name()` unset, and then inserts the
decoded Markdown. Logical path, document handle, etag, content, saved version,
and draft version live only in an in-process registry keyed by `view.id()`;
none are written to view settings.

Plaintext insertion does not pass Markdown in Sublime `run_command` arguments.
A random one-use token references an owned `bytearray` handoff; the TextCommand
atomically consumes the token, removes it from the registry, decodes in memory,
and wipes the owned bytes. Lock and unload wipe all unconsumed handoffs. Open
and recovery plaintext also has an explicit pending-owner registry before a
view model exists, so lock can wipe it and close its document handle without
depending on a Quick Panel cancellation callback.

Save is intercepted and becomes `file.write` with the current etag. A conflict
stays dirty and is never force-retried. Save As and buffer cloning are blocked.
Save All encrypts managed documents through Inex and separately invokes Save
only for non-Inex views. Known close commands synchronously attempt one final
encrypted draft before closing.

Build 4200 commands that export managed buffer content are rewritten to one
fixed blocking command. This includes normal/HTML clipboard copy and cut,
`html_print`, print/selection variants, export/save-selection variants, and
browser preview/context-URL commands (`open_context_url` and
`old_open_context_url`). The package does not pass the original export
arguments to another command.

Macro recording, `save_macro`, recorded-macro playback, and every
`run_macro_file` invocation are blocked whenever any managed plaintext exists.
No `res://Packages/Default` exception is trusted because unpacked package
resources can be overridden. Inex also arms a fingerprint monitor while the new
scratch view is still empty. If macro
recording was started in an ordinary buffer before the managed document opens,
the first insertion changes that fingerprint: the post-command hook stops
recording, overwrites the current macro using Build 4200's probed fresh-recording
plus dedicated no-op sequence, requires `get_macro()` to report an exact `[]`,
and immediately scrubs and locks every managed buffer. A global taint flag is
set regardless of whether that verification succeeds. Once tainted, unlock plus
all macro recording/save/playback remain blocked until the entire Sublime Text
process restarts; plugin reload does not clear the flag. If exact empty-macro
verification fails, Inex makes no erasure claim and tells the user to quit and
restart before further use.

The Build 4200 compatibility probe for this exact sequence found that a plain
empty start/stop retained the old recorded command, while the dedicated no-op
sequence returned exact `[]`. It remained `[]` after both normal relaunch and a
forced-kill relaunch, and the probe marker was absent from the isolated local
session/workspace scan. That evidence validates this narrow sanitizer behavior;
it does not replace the complete binding residue matrix below.

The authenticated `idleTimeoutMs` returned by unlock creates an epoch-bound
local monotonic deadline with a small safety margin. Successful protected RPCs
and throttled authenticated activity pings renew both daemon and local
allowance. Each local deadline is anchored to the worker thread's authenticated
response timestamp, including the initial unlock; a delayed main-thread callback
never creates extra plaintext lifetime and locks immediately if its allowance
already elapsed. A status warning appears shortly before expiry; expiry
actively hides plaintext overlays, wipes pending/open models, and locks/shuts
down the sidecar without waiting for another RPC to discover expiration. Timers
from an old client or vault epoch are inert.

Each edit schedules `draft.encrypt` after a short debounce. The returned EDRY
bytes are atomically replaced in the ciphertext-only directory
`Packages/User/InexEncryptedDrafts`; filenames are SHA-256 identifiers, not
logical or physical plaintext paths. A draft error makes the buffer read-only
and warns immediately.

Before inserting a newly opened document, Inex checks that directory for a
bounded, non-symlink regular EDRY file and sends it to `draft.decrypt` for
authenticated recovery. A malformed or unauthenticated draft aborts the open,
closes the daemon handle, and inserts no plaintext. An authenticated draft is
never restored silently: a Quick Panel offers restore-as-dirty, ciphertext-only
discard, or cancel. If its embedded base etag differs from current ciphertext,
the view is marked as stale recovery; the first restore choice is followed by a
second explicit overwrite confirmation at Save, and the write still uses the
current ciphertext etag. A clean successful save removes the verified regular
old draft file when possible.

## Sublime API boundary

Build 4200 exposes `on_text_command` and `on_window_command` rewrites, which are
the primary Save, Save As, Save All, clone, and known close defenses. Its
`on_pre_save` and `on_pre_close` notifications **cannot veto** an operation.
Therefore:

- `on_pre_save` is only an emergency alarm: it attempts an encrypted draft and
  scrubs the view to a fixed non-secret message before native saving proceeds;
- `on_pre_close` performs a synchronous best-effort encrypted draft, but an
  abrupt exit can still lose final edits;
- the plugin never writes plaintext merely to prevent data loss;
- unknown third-party commands that bypass the documented command hooks are a
  release-test concern, not something this package claims the API can prove
  impossible.

Owned byte arrays are wiped best effort. Immutable Python strings, Sublime's
buffer/undo internals, UI widgets, allocator copies, and the plugin host cannot
be deterministically zeroized. Lock replaces text and clears the exposed undo
stack as a best effort; this is not an in-memory erasure claim.

## Binding release gate

Tests must use Sublime Text Build 4200 in Safe Mode or an isolated data
directory. The packaged artifact must exercise keyboard and menu Save, Save As,
Save All, clipboard/HTML print/export blocking, matching and stale draft
recovery, local idle expiry, heading/link panels, tab/window/application close,
project and non-project windows, pre-armed macro recording from an ordinary
buffer, user-macro save/playback attempts, sidecar/plugin-host crash, and forced
process termination. After each flow, a unique canary scan covers
session/workspace files, Cache, Index, logs, temp, the encrypted-draft directory,
and the vault.

Until that black-box matrix passes for the exact package/build pair, disk
residue assurance remains **pending**. The pure-Python unit suite validates the
framing/bounds, exact gate, model/wipe behavior, atomic EDRY-only writes, error
redaction, external password command construction, and command interception;
it is necessary but not a substitute for the residue matrix.

Run the pure suite from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=editors/sublime \
  python3 -m unittest discover -s editors/sublime/tests -v
```
