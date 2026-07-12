# User Guide

This guide describes the current pre-alpha checkpoint. It assumes a vault has
already been created or copy-imported and that the matching CLI, daemon, and
editor client are configured according to [installation.md](installation.md).

## Understand the vault

A logical Markdown path such as:

```text
2026/07/2026-07-11.md
```

is stored as:

```text
2026/07/2026-07-11.md.enc
```

The directory structure and basename are visible. The file body and encrypted
drafts are EDRY envelopes authenticated against the vault identity, logical
path, key epoch, and header. Renaming a ciphertext file with ordinary filesystem
or Git commands does not produce a valid Inex rename: the logical path is
authenticated, so opening the moved blob fails closed.

`vault.json` contains password-slot wrapping metadata, not a plaintext master
key. Losing `vault.json`, every valid password, or all valid password slots is
not recoverable. Inex has no reset password, escrow, or backdoor.

## Daily VS Code workflow

1. Open the real ciphertext vault folder as a trusted local workspace.
2. Run **Inex: Unlock Vault**. Select the vault root containing `vault.json`
   and enter the password in the hidden input.
3. Use the **Inex > Encrypted Vault** tree, not Explorer text-file operations,
   to browse logical documents. **New Encrypted Markdown** creates an empty
   EDRY-backed file and opens it; **New Encrypted Folder** creates one logical
   directory. Invoke them from the tree title, a directory item, or the Command
   Palette.
4. Select a file to open the `Inex Markdown` custom editor. The real tab
   resource remains the `*.md.enc` file; decrypted text is not registered as a
   writable VS Code `TextDocument`.
5. Edit and use the normal Save command. Save takes a fresh snapshot from the
   webview, performs an etag-conditional encrypted write, and reports a conflict
   instead of overwriting externally changed ciphertext.
6. Use a file's tree action or **Inex: Rename Encrypted Markdown** for an
   authenticated same-directory file rename. If that file is open and dirty,
   the client offers Save and Rename; a close refusal or edit racing the save
   leaves the original file. **Inex: Delete Encrypted Markdown** uses an
   explicit confirmation and etag-conditional delete; it refuses dirty open
   documents.
7. Run **Inex: Search Encrypted Vault** for in-memory full-text search. The
   query input is deliberately hidden; results contain plaintext snippets in a
   transient Quick Pick.
8. Use the **Headings** and **Backlinks** buttons in the custom editor. Put the
   cursor in a relative Markdown/wiki link and Ctrl/Cmd-click it, or press
   Ctrl/Cmd+Enter, to follow it. Absolute, traversal, encoded, command, and web
   targets are rejected by the controlled navigator.
9. Before switching vaults, pulling Git changes, or leaving the machine, save
   and run **Inex: Lock Vault**. Dirty documents offer save-all, explicit
   discard, or cancel.

The sidecar returns an authenticated idle deadline. Protected activity renews
it; shortly before expiry the client warns, and expiry locks the session,
clears owned models, closes sensitive UI, and replaces open editor webviews
with a fixed locked page. Reopen a tab after unlocking again.

### VS Code backup and recovery behavior

For a dirty custom document, VS Code asks the Inex provider for a backup. Inex
first encrypts the current snapshot as an authenticated EDRY draft and writes
only those bytes to VS Code's backup destination. On restore:

- the vault must be unlocked before the draft can be authenticated;
- a matching-base draft can be reopened as dirty content;
- a stale authenticated draft requires explicit recovery and a second
  overwrite confirmation at Save; the current ciphertext etag is still used;
- a corrupted or wrong-vault draft is rejected without returning plaintext.

The automated Extension Host source gates on a controlled 1.125.0 host
exercise real backup scheduling and this exact recovery code path. They also
drive the production create/folder-create/file-rename/file-delete actions
directly against the daemon and custom editor, including close refusal, rename
collision, delete I/O failure recovery, and residue scanning. They verify the
commands are registered, but do not mouse-drive the InputBox/QuickPick UI. Test
mode forces workbench storage to be in-memory, so persistent-profile
cross-process tab restore and Local History remain release gates. For an exact
packaged VSIX, separately require an external record matching its manifest and
checksums for install/bundled-sidecar smoke; even that does not close those
gates.

### Current VS Code limitations

- The custom editor is a controlled textarea, not the normal VS Code Markdown
  text editor. Native language-service features, extensions that inspect
  TextDocuments, standard custom-editor undo integration, and ordinary Markdown
  preview are not promised.
- Save As is blocked; use the authenticated tree rename. Folder rename/delete
  and cross-directory move are not exposed by the current UI.
- Inex does not globally change Hot Exit or Local History settings.
- Clipboard, screen capture, malicious extensions, webview/editor heap copies,
  process dumps, swap, and hibernation are outside the security goal.

## Daily Sublime Text workflow

The Sublime client is experimental and limited to exact Build 4200. Do not use
it with irreplaceable plaintext until the binding residue matrix passes.

1. Verify the application-global persistence settings from
   [installation.md](installation.md), then run **Inex: Show Security Status**.
2. Run **Inex: Unlock and Browse Vault**. The password is collected by the
   reviewed external masked helper, not a Sublime input panel.
3. Select an existing document from the Quick Panel tree. Inex creates a scratch
   view with no filename and keeps logical path, handle, etag, content, and dirty
   versions in a process-local registry.
4. Use **Inex: New Encrypted Markdown** or **Inex: New Folder** with a complete
   logical path to create content. New Markdown opens as a managed scratch view.
5. Edit and press Save. The plugin intercepts known Save commands and performs
   `file.write` with the current etag. Save As and cloning are blocked. A short
   debounce also maintains an EDRY-only draft under
   `Packages/User/InexEncryptedDrafts`.
6. **Inex: Rename Active** and **Inex: Delete Active** operate only on the
   active clean writable managed file. Save first. Rename takes a complete
   logical destination; delete requires Quick Panel confirmation. Directory
   rename/delete is not supported.
7. Use **Inex: Search Vault**, **Inex: Show Markdown Headings**, or
   **Inex: Follow Relative/Wiki Link**. Search text and snippets are transient
   Sublime UI data, but the complete profile residue result remains pending.
8. Run **Inex: Lock Vault**. Dirty views offer encrypted save, explicit discard,
   or cancel. Sidecar/session failure and local idle expiry scrub and lock the
   managed views.

The plugin blocks known clipboard, HTML print, browser-preview, export,
Save As, clone, and macro persistence routes while managed plaintext exists.
This is a reviewed Build 4200 command surface, not a proof that an unknown
third-party plugin or command cannot copy Sublime's internal buffer. Use an
isolated profile without unrelated packages.

Every managed plaintext view has a fixed non-secret marker. Plugin-load code
and pure tests require orphaned marked views to be scrubbed before further
editing; failure to confirm that scrub blocks the client. Exact Build 4200 does
not, however, restart a killed plugin host in the same editor process. After
host death, no plugin code can hide the already open buffer, a black-box probe
can actively copy its visible contents, and the entire Sublime application must
be restarted to end that editor-process plaintext lifetime. The fixed marker
is therefore not observed same-process crash recovery or instantaneous
fail-safe containment.

Current checkpoint evidence is deliberately split: 84/84 Python tests pass
(61 product tests plus 23 runner/evidence tests), and separately preserved
canonical reports bind three exact packaged Build 4200 Linux scenarios: normal
schema v2, plugin-host-crash schema v2, and full-application SIGKILL/restart
schema v4. Each starts from a fresh isolated profile and the same audited
package bytes; restart v4 alone reuses its profile/install across both launches. The
normal scenario passed unlock/open/edit/save/close plus real InputPanel/QuickPanel New
Folder, New Markdown, rename, and etag-bound delete. Authenticated tree state
was checked after every mutation; the report records all four CRUD events,
`crud_complete=true`, `vault_envelope=EDRY`, and zero scanned disk residue. The
plugin-host SIGKILL scenario reproduced the copyable-buffer/restart boundary
and is recorded as `PASS_WITH_DOCUMENTED_BOUNDARY`, not as a crash-erasure
pass. That boundary is within the existing editor-memory/active-clipboard
exclusion, but is a binding reason to keep Sublime experimental.

The schema v4 flow kills the complete first session/descendant closure through
verified pidfds and starts the same isolated profile and package again. It
requires zero root-bound process or mount survivors at the restart boundaries.
Before the second unlock, every view
is scanned continuously for two seconds with no known content/token
fingerprint or Inex state. After unlock, reopening the encrypted document must
match the first saved-content fingerprint. This is one controlled harness path,
not a test of a real user's persistent profile.

Sublime cannot veto every application-exit path. A final edit may be lost on an
abrupt exit rather than written as plaintext. This is an intentional
security-over-availability choice. Keyboard/menu Save variants, the remaining
crash/export/macro/project and forced-kill paths, real-user profile Hot
Exit/history/sync behavior, other platforms, and signing remain pending. The
complete matrix must pass before the experimental label can be removed.

## CLI administration

For the POSIX examples below, set `INEX` to the reviewed absolute CLI path and
run `"$INEX" --help` first; do not silently substitute a different executable
found through `PATH`. Passwords are never accepted as arguments or environment
**values**. Interactive commands use a hidden controlling terminal. Automation
must opt into bounded stdin with `INEX_PASSWORD_STDIN=1`; protect the supplying
process, pipe, and logs.

`init`, real copy import, and password add/change may pause while Inex performs
or reuses a process-local Argon2id calibration. The 250–750 ms target is for the
public-dummy selector observation, which includes validation, possible
libsodium initialization, secure allocation, and Argon2id. It is not pure KDF
latency. The complete command also performs the real KDF, atomic metadata
commit, and authenticated reopen and can take longer. v1 keeps creation memory
at 64 MiB. Password add/change will not lower either work-factor component of
the slot used to authenticate the command.

### KDF calibration diagnostic

```sh
"$INEX" kdf-calibration-info
```

This command accepts no further arguments. It takes no vault path, password,
query, or policy override and runs before password/query input setup. It writes
one strict 20-line ASCII report to stdout and no persistent Inex product state.
It is still active cryptographic work: it may initialize libsodium and performs
one sample for each candidate the selector visits, using CPU, secure allocation,
and the fixed 64 MiB Argon2id memory setting.

`selected-observed-ns` is the monotonic observation used for the selected
decision, ending before the derived-key allocation is dropped; it is neither a
pure-Argon2 benchmark nor an end-to-end command SLA. The report can name only
`target-window`, `minimum-above-window`, `interior-above-window`,
`maximum-above-window`, or `maximum-below-window`. A fallback name means the
bounded selector returned that documented branch. It does not establish that
every operations value would miss the window, because measurements can be
noisy/non-monotonic and some candidates are not measured.

Default vault creation in one long-lived process reuses the same cached
calibration evidence. This diagnostic exits immediately, so every invocation
starts a fresh process and does not pre-calibrate a later `init`, `import`, or
daemon. Release maintainers must use the fixed three-process native evidence
procedure in the [release checklist](release-checklist.md), not manually rerun
until a preferred result appears.

### Locked structural verification

```sh
INEX=/absolute/path/to/inex
"$INEX" verify /absolute/inex-vault
```

This command does not prompt for a password and does **not** authenticate
`vault.json` or decrypt/authenticate document bodies. It acquires the mutation
lock and may recover a pending core ciphertext transaction, so it is not a pure
read-only inspection. It reports either a structurally present Git merge
journal or an Inex-marked abandoned v4 index reservation, but does not
authenticate a journal result or advance it without `inex git recover`.

### Password slots

Add a second password slot while retaining the current one:

```sh
"$INEX" password add /absolute/inex-vault --slot <current-slot-uuid>
```

Change one password by committing a new slot and then retiring the selected old
slot:

```sh
"$INEX" password change /absolute/inex-vault --slot <old-slot-uuid>
```

Remove an unwanted slot only while proving a retained slot password:

```sh
"$INEX" password remove /absolute/inex-vault <slot-to-remove-uuid> \
  --slot <retained-slot-uuid>
```

Record every printed slot UUID and durability warning before closing the
terminal. A password change never rewrites EDRY document blobs. If output says
the new slot was committed but old-slot retirement was deferred, do not repeat
the whole change blindly: retain the printed new-slot UUID, prove it unlocks,
then remove the old slot explicitly.

The new slot uses at least the calibrated v1 baseline and at least the
operations and memory costs of the authenticated old slot. A stronger
reader-compatible slot can therefore make add/change slower than fresh vault
creation; Inex preserves that cost instead of silently downgrading it.

Changing or removing a password slot is **not revocation**. The master key stays
the same, so an old password plus an old `vault.json` from Git history or backup
can recover it and decrypt later files in the same key epoch. The checkpoint
does not implement master-key rotation. If a password and historical metadata
may be compromised, protect the repository/remotes and treat the vault key as
compromised rather than relying on `password change`.

### CLI search

```sh
"$INEX" search /absolute/inex-vault --limit 20
```

The query is read from hidden input, but matching logical paths and **plaintext
snippets are printed to stdout**. Use a trusted terminal without transcript
capture and do not redirect or pipe the output unless plaintext disclosure is
intentional. For explicit stdin automation, set `INEX_QUERY_STDIN=1`; if both
stdin opt-ins are active, supply the password line first and query line second.

The hidden-terminal backend checks the 1–1024-byte password bound immediately
after Enter, whereas explicit stdin enforces its bound while reading. This
allocation distinction is documented and remains a checkpoint limitation.

## Git workflow

Git manages ciphertext only. After every successful save, ordinary Git status,
add, commit, fetch, and push can operate on the real repository. Prefer this
sequence:

1. Save all Inex documents and lock the editor.
2. Run `git status` and verify that no plaintext `.md` file exists.
3. Commit `vault.json`, `.gitattributes`, `.gitignore`, and `*.md.enc` changes.
4. Pull/fetch/merge only with a complete backup or recoverable remote history.

The installed locked merge driver intentionally returns a conflict without
reading any Git temporary path, prompting for a password, or changing `%A`.
After ordinary Git stops on encrypted conflicts, run:

```sh
"$INEX" git merge /absolute/inex-vault
```

The command unlocks explicitly, authenticates Git stages, performs diff3 in
process memory, and writes only EDRY results. A clean result is encrypted and
staged. An overlapping result contains encrypted conflict-marker plaintext and
sets an authenticated unresolved flag; the command exits nonzero. Open that
document through Inex, remove every conflict marker, save, stage the new
ciphertext, and continue the Git operation.

The current checkpoint resolves authenticated rename/modify when the unique
merge base and exact `HEAD`/`MERGE_HEAD` trees prove one source-to-destination
move, including Git's detected and split conflict representations. It fails
closed on linked/external gitdirs, split indexes, attribute overrides,
non-regular modes, historical copies, rename/rename, multiple merge bases,
ambiguous identity owners, or changed provenance. Do not run other Git
porcelain concurrently with `inex git merge` or recovery. Inex does not provide
a transparent unlocked broker for normal `git merge`.

The encrypted merge driver applies only to `*.md.enc`. A Git conflict in
`vault.json` must **not** be resolved by combining JSON or conflict-marker
lines: its complete slot set and feature state are authenticated by a metadata
MAC. Preserve both whole versions, select one complete version that can unlock
the EDRY files, then recreate any intended password slots with the CLI and
verify the resulting backup. See the operations guide before choosing a side.

See [operations-and-recovery.md](operations-and-recovery.md) before import,
backup, restore, conflict recovery, password changes, or upgrades.
