# Troubleshooting

Inex fails closed on ambiguous storage, authentication, protocol, path, and Git
states. Treat an error as a reason to inspect current ciphertext state, not as a
reason to force-write or delete recovery metadata. Never paste a real password,
session token, key, plaintext snippet, vault, or editor profile into a bug
report.

## First-response checklist

1. Stop editing and do not retry a write automatically.
2. Record the command name, fixed error text/category, exit status, Inex/editor
   versions, OS, architecture, and whether the operation may have committed.
3. Save a filesystem-level copy of the ciphertext vault, `.git`,
   `.vault-local`, and any `.inex-import-staging-*` sibling when recovery or an
   indeterminate result is involved.
4. Confirm the configured vault and daemon are absolute local paths and normal
   non-link files/directories.
5. Use a disposable copy for diagnosis. Do not use `git reset --hard`, remove a
   journal, or rename import staging as a first response.

## CLI and daemon

### `inexd` was not found or refused

- `inex serve` accepts a sibling `inexd[.exe]` or explicit `INEXD_PATH`; it
  never falls back to `PATH`.
- VS Code requires `inex.sidecarPath` to be absolute when no correctly bundled
  daemon exists at `bin/<platform>-<architecture>/inexd[.exe]`.
- Sublime requires an absolute `sidecar_path` or package-owned `bin/inexd[.exe]`.
- A symlink, directory, missing executable bit on Unix, or mismatched platform
  binary is rejected.

Use `inex --version` and the editor package version to confirm that the CLI,
daemon, and client came from the same checkpoint. Do not solve a lookup error by
putting an unverified executable earlier on `PATH`.

If Linux release packaging rejects a non-portable ELF interpreter or
RPATH/RUNPATH, rebuild with the system toolchain. The xlings-default linker on
this development machine embeds paths under the local xlings home; a binary
that starts there is not a portable release input, and the package check must
not be bypassed.

### Unlock reports authentication failure

Passwords are exact 1–1024-byte UTF-8 sequences. Inex does not trim whitespace
or normalize Unicode. Check keyboard layout, leading/trailing characters, and
the intended slot UUID. With multiple slots, pass the recorded `--slot` to CLI
administration commands when ambiguity is possible.

There is no password reset. `inex verify` can report a structurally valid vault
even when a password is wrong because it deliberately does not authenticate
metadata or bodies.

If an old password was disclosed, `inex password change` does not revoke it
against someone who retained an older `vault.json`: all slots wrap the stable
master key. Protect Git/backups and treat the vault key as compromised. A
master-key rotation/re-encryption command is not implemented in this checkpoint.

### Vault/path/filesystem is rejected

Use a normal local directory. The implementation rejects network/FUSE roots,
nested mounts, Linux bind-mount changes, symlinks, Windows junctions/reparse
points, hard links in protected locations, noncanonical reserved names, path
traversal, case-fold collisions, plaintext `.md` inside the vault, and wrong-case
`.md.enc` suffixes.

Do not work around the check by disabling Git NTFS protection or moving files
with ordinary filesystem tools. Copy a clean backup to an accepted local path
and diagnose the rejected entry by its safe relative-name error.

Linux copy import also requires usable `openat2` so absolute ancestors and
descriptor-relative traversal can reject symlinks/mount escapes. A kernel or
sandbox that blocks it is unsupported for import and fails closed; do not fall
back to a hand-renamed staging directory.

### Save reports etag conflict

Another sidecar, Git operation, sync tool, or external replacement changed the
complete ciphertext after the editor opened it. Inex does not force-retry.
Preserve unsaved work through the encrypted draft path, inspect the competing
version through a protected client, and choose an explicit merge/recovery
workflow. Do not copy plaintext to a temporary file merely to bypass the
conflict.

### Save reports durability not confirmed

The exact requested ciphertext may already be the live target even though the
platform did not confirm the parent namespace durability barrier. Do not repeat
the write blindly. Save a ciphertext snapshot, run structural verification,
unlock/read the target, and move the vault to an accepted local filesystem if this is
recurrent. Such a platform is not release-qualified until its crash matrix
passes.

### The session locks while a client appears open

Explicit lock, stdin EOF, daemon exit, protocol/framing error, idle expiry, and
editor deactivation invalidate the capability. The editor also maintains a
local authenticated deadline. Save/restore only through the encrypted draft
path, close locked tabs if necessary, and unlock a new sidecar session. Old
document handles and tokens are intentionally unusable.

### CLI search is leaking text into a terminal transcript

The query prompt is hidden, but search results intentionally print plaintext
snippets to stdout. Stop the transcript/redirect, protect or remove the output
according to local policy, and use the editor search UI for future queries. Do
not attach the transcript to an issue.

## VS Code

### Unlock is unavailable or workspace is rejected

The extension runs locally (`extensionKind: ui`) and does not support untrusted
or virtual workspaces. Open the real local ciphertext repository and deliberately
trust only that reviewed workspace/profile. Select the root containing exact
`vault.json` in **Inex: Unlock Vault**.

### A `*.md.enc` file opens as binary/text instead of Inex Markdown

Confirm the development extension is loaded, its bundle exists at
`editors/vscode/dist/extension.js`, and the file has exact lowercase
`.md.enc`. Use **Reopen Editor With > Inex Markdown** if another extension took
priority. Do not edit or save ciphertext in the ordinary text editor.

### Save As says authenticated rename is required

Save As is intentionally disabled because logical paths are authenticated. Use
**Inex: Rename Encrypted Markdown** or the file's encrypted-tree rename action.
The UI renames a file inside its current directory; folder rename/delete and
cross-directory move are not exposed. Do not rename the physical `.enc` file as
a substitute.

### Create, rename, or delete failed

All mutations are session- and etag-bound. A name collision is never replaced.
Delete refuses a dirty open document; rename offers an explicit encrypted save
first and aborts if the tab cannot close or changes again. When a rename/delete
RPC fails after an open tab was prepared, the client refreshes the authenticated
tree and tries to reopen the proven surviving source/destination. Inspect that
tree and current ciphertext before retrying. The Extension Host gate covers
close refusal, rename collision, and a Unix delete-permission failure, but not
the mouse-driven InputBox/QuickPick path.

### A backup cannot be restored

Ensure the matching vault is unlocked. A corrupted, wrong-vault, or
wrong-logical-path EDRY draft is rejected. A valid draft whose base ciphertext
changed is stale and requires explicit recovery plus a second overwrite choice.
Preserve the encrypted backup and current vault for diagnosis; never decrypt or
rewrite the backup manually.

### Hot Exit or Local History is a concern

Inex uses a custom document and writes only EDRY through its backup provider;
it does not register plaintext as a `TextDocument`. Automated tests validate
the provider backup path and direct production CRUD actions in a controlled
Extension Host. For an exact packaged VSIX, require a matching external report
for install/bundled-sidecar smoke. Neither source tests nor package smoke proves
the final persistent-profile cross-process matrix.
If evaluating stronger assurance, use an isolated profile, run a unique
synthetic canary flow, scan all roots from
[the acceptance matrix](acceptance-matrix.md), and treat the checkpoint as
pending regardless of a single clean manual run.

## Sublime Text

### The security gate refuses writable mode

The application-global preferences must be exact, including types:

```json
{
  "hot_exit": "disabled",
  "hot_exit_projects": false,
  "update_system_recent_files": false
}
```

The string `"disabled"` is not Boolean `false`. Project or view overrides do
not satisfy the gate. The package also requires exact Build 4200. Restart the
isolated profile after correcting global settings and re-run
**Inex: Show Security Status**.

### The password dialog does not open

On Linux configure an absolute non-symlink regular executable for `zenity_path`
or install it at the reviewed `/usr/bin/zenity` or `/usr/local/bin/zenity`
location. On Windows the plugin accepts only the system PowerShell executable
and its fixed masked WinForms dialog. macOS has no reviewed helper and is
rejected.

Do not replace this with Sublime's normal input panel, a shell command containing
the password, or an environment value.

### Save/export/macro/clipboard commands are blocked

This is intentional while managed plaintext exists. The plugin rewrites the
reviewed Build 4200 command surfaces to fixed blocking commands. Lock and scrub
all Inex views before using those operations on unrelated documents. If the
macro monitor taints the process, quit and restart the entire Sublime process;
reloading only the plugin does not clear the taint.

### Abrupt close lost the latest edit

Sublime's API cannot veto every application exit. Inex chooses not to persist
plaintext merely to prevent data loss. Check the authenticated encrypted draft
recovery offer on the next open. The complete close/crash residue and recovery
matrix remains pending, so do not rely on it as the sole copy.

### A plugin-host crash left a visible managed buffer

This is the reproduced exact Build 4200 editor boundary, not a crash-erasure
pass. While the plugin host is dead, no Inex code can hide an already open
editor buffer; a user or black-box probe can actively copy its visible
contents. Build 4200 did not restart the killed host inside the same editor
process, so quit and restart the entire Sublime application. Plugin-load code
and pure tests retain a fixed-marker orphan-scrub gate, but the black-box crash
path did not exercise same-process reload. Preserve isolated evidence and keep
Sublime classified experimental. The host-dead window remains part of the
editor-memory/active-clipboard exclusion and complete crash release gate.

### Sublime rename/delete is refused

Only the active clean writable managed Markdown file can be renamed or deleted.
Save it first. **Rename Active** accepts a complete logical destination and
**Delete Active** requires confirmation. Directory rename/delete is not
implemented; never substitute a physical `.enc` move.

## Git and import

### Driver install fails

Confirm Git is at least 2.36, the vault is the exact top-level normal worktree,
`.git` is local and not linked/external, and no nested or info attributes
override the managed rule. Split indexes are unsupported. Re-run installation
after moving the `inex` binary because the driver stores its canonical absolute
path in repository-local config.

### Normal Git merge always stops

That is the locked-safe design. The installed driver does not have an unlock
broker and deliberately returns conflict without reading Git paths. With a
preserved conflict index, run `inex git merge <vault>` and enter the password
explicitly.

### Encrypted merge or recovery refuses the repository

Preserve `.git`, worktree ciphertext, and `.vault-local`. Ambiguous rename
provenance, rename/rename, multiple merge bases, split index, mode, attribute,
object-format, owner, concurrent-change, or journal facts fail closed. Stop all
other Git porcelain before retrying. New v4 transactions also reject a foreign
`.git/index.lock`, a changed old/candidate index digest, or a target result that
was changed after publication. Legacy v1/v2/v3 recovery still requires an
exclusive Git worktree. If `inex git recover` reports a conflict, do not delete
the journal, candidate, or lock and do not force stage zero; compare current
OIDs/digests and the recorded fixed provenance against a copy and the
[Git recovery contract](spec/git-merge-v1.md).

### Git reports a conflict in `vault.json`

Do not merge the JSON text or slot objects. The metadata MAC authenticates the
complete slot/feature set. Preserve both whole blobs and passwords, choose one
whole version on a disposable copy, prove it unlocks the EDRY set, then recreate
missing intended slots through `inex password add`. If no whole version is
consistent, restore a known-good complete vault snapshot. `inex verify` alone
cannot prove this because it performs no authenticated unlock.

### Import reports destination exists

Import is no-replace and never resumes into an existing destination. Choose a
fresh absent destination. If the existing path came from an earlier failed run,
classify it using [operations-and-recovery.md](operations-and-recovery.md)
before touching it.

### Import skipped files

Only exact lowercase `.md` regular files are copied. Attachments and other
regular files are counted but not encrypted. Keep the plaintext source, account
for every skipped file separately, and do not declare migration complete until
an independently restored encrypted vault has been compared.

## If a plaintext canary is found on disk

Stop using the affected editor/artifact. Disconnect ordinary sync if doing so
does not destroy evidence, preserve the isolated profile and ciphertext vault,
record the path and digest without copying the canary into logs, and report the
security issue through the process in [`SECURITY.md`](../SECURITY.md). A canary
finding blocks release for that exact editor/package/platform pair; cleaning the
file does not turn the failed run into a pass.
