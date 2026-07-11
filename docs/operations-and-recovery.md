# Backup, Import, Git, Recovery, and Upgrades

Inex protects confidentiality of journal bodies at rest; it does not provide
availability, rollback protection, or a remote backup service. Operational
discipline is therefore part of the safety model. All procedures below refer
to the pre-alpha checkpoint and should first be rehearsed with a disposable
vault.

POSIX command snippets assume `INEX` is the reviewed absolute CLI path from the
matched installation, for example `INEX=/absolute/path/to/inex`; do not replace
it with an unverified executable discovered through `PATH`. PowerShell users
should invoke the matching `.exe` by its explicit path.

## Backup policy

Maintain at least two independent ciphertext copies, one outside the working
machine. A useful backup must include:

- `vault.json`;
- every committed `*.md.enc` file;
- `.gitattributes` and `.gitignore` after driver installation; and
- enough Git objects/refs to recover the intended history, if Git is the backup
  mechanism.

`vault.json` and passwords are both essential. A ciphertext tree without its
matching authenticated metadata cannot be unlocked. Multiple Git copies do not
help if every valid password is lost.

### Clean routine backup

1. Save all documents, lock every editor client, and stop any manual `inexd`.
2. Run `git status`. Do not proceed if a plaintext `.md`, an unexpected link,
   or an unknown entry exists in the vault.
3. Run `inex verify <vault>` and read its scope/output. It takes the mutation
   lock and may recover a core ciphertext transaction; it does not prove the
   password or authenticate content.
4. If `pending-git-merge-transaction` is present, finish authenticated recovery
   before creating a normal clean backup.
5. Commit the intended ciphertext state. Push to a protected remote and/or make
   an offline filesystem snapshot or Git bundle.
6. Restore that backup to a different disposable local path, run `inex verify`,
   install the local driver, unlock it, and open representative documents.

A Git-only backup omits uncommitted changes and intentionally omits
`.vault-local/`. An out-of-band archive made while the vault is clean may also
omit that private runtime directory. Do not infer authenticity from a successful
archive checksum alone; an authenticated unlock/read is the content check.

### Failure-state preservation

If a command reports an indeterminate namespace result, unconfirmed durability,
or pending recovery, stop ordinary sync/cleanup. Preserve an exact copy of:

- the entire vault including `.vault-local/`;
- the vault's parent directory entries, including any
  `.inex-import-staging-*` sibling;
- the complete `.git` directory and worktree state; and
- the command name, fixed error category, exit status, binary version, and OS
  version, without recording passwords or plaintext.

In a failure state, `.vault-local/` may contain the plaintext-free metadata
journal needed to reconcile a transaction. It can expose already-visible paths,
object IDs, and digests, but not a decrypted body. Deleting it to make
`git status` look clean can destroy recovery evidence. Work from a copy and do
not rename staging or replace a destination manually.

## Copy import

Version 1 supports only:

```text
inex import <plaintext-source> <new-vault> [--dry-run]
```

The source remains plaintext and unchanged. The destination must be absent and
its parent must already exist. In-place conversion and import into an existing
vault are rejected.

### Safe import procedure

1. Make the plaintext source read-only to ordinary users if practical and back
   it up independently.
2. Remove or separately account for attachments: exact lowercase `.md` regular
   files are imported; other regular files are counted and skipped.
3. Run `--dry-run`. Confirm entry/file/byte counts and the skipped count. Dry-run
   creates nothing and does not request a password.
4. Run the real import to the same absent destination. Enter and confirm a new
   password through the hidden prompt.
5. Preserve the printed staging name and final report. A successful result says
   the source was preserved and a new vault was published.
6. Initialize Git only after publication, run `inex git install-driver`, commit
   ciphertext, back it up, restore it elsewhere, unlock it, and compare expected
   content before deleting any plaintext source yourself.

Import limits are 100,000 inspected entries/files, depth 128, 32 MiB path
storage, 16 MiB per Markdown file, and 256 MiB total Markdown plaintext. Source
identity, links/reparse points, hard links, mount boundaries, portable paths,
case collisions, source changes, staging contents, ciphertext seals, and the
destination parent are checked before no-replace publication.

### Import failure classes

**Pre-publication failure:** the final path should be absent and a created
`.inex-import-staging-*` directory is retained. Do not rename it to the final
name. Preserve it and the source, fix the underlying fault, and rerun to a fresh
absent destination.

**Indeterminate publication:** the operating-system result and observed
identities could not prove exactly moved or exactly unmoved. Preserve every
candidate and staging directory. Run `inex verify` against any final candidate,
but remember that verification is structural and may mutate pending core state.
Audit from a copy; never resolve ambiguity by overwriting an existing name.

**Published, marker cleanup failed:** the final vault was identity-proven as
published, the staging name is absent, and a private ciphertext-only publication
marker remains. The command exits nonzero intentionally. Do not rerun import to
the same destination. Preserve the final vault, run `inex verify`, and remove
the marker only after independently auditing the namespace state described in
[the import contract](spec/import-v1.md).

## Authenticated editor file management

Create, rename, and delete through an Inex client, never by manipulating the
physical `.md.enc` path. VS Code exposes Markdown/folder creation and file
rename/delete in its encrypted tree. Its rename/delete flow coordinates open
custom-editor tabs, uses the current etag, and attempts to reopen the proven
surviving source/destination after a failed mutation. Sublime exposes
Markdown/folder creation plus active-file rename/delete, but rename/delete
require that managed file to be clean and writable.

Save As remains blocked. Directory rename/delete is not exposed, and VS Code's
interactive rename remains within the current directory. If a mutation reports
`notSynced`, the requested namespace may already be live while crash durability
is unconfirmed; preserve current ciphertext and follow the same no-blind-retry
rule used for saves. A failed ordinary filesystem rename cannot be repaired by
editing the authenticated EDRY header.

## Git setup and normal operation

Every clone requires:

```sh
"$INEX" git install-driver /absolute/inex-vault
```

This checks Git 2.36+, a normal local `.git` directory, managed attributes, and
the current absolute `inex` executable. `.gitattributes` and `.gitignore` travel
with the repository; `merge.inex.*` and Windows `core.longPaths=true` are local
configuration and do not.

Do not edit `*.md.enc` with a text editor, configure a normal text merge for
them, override attributes in nested or `.git/info/attributes` files, or disable
Git's NTFS protections. Do not move a ciphertext blob to rename a logical
document. The authenticated path would no longer match.

### Resolve an encrypted merge

1. Save and lock editor clients, then run the ordinary Git merge/rebase/pull.
2. The locked-safe driver returns nonzero and leaves the current file and index
   stages untouched.
3. Inspect `git status`, then run:

   ```sh
   "$INEX" git merge /absolute/inex-vault
   ```

4. If all diff3 results are clean, confirm Git's staged ciphertext and continue
   the Git operation.
5. If the command reports unresolved encrypted results and exits nonzero, open
   each result through an Inex editor. Resolve the visible diff3 markers, save,
   stage the new ciphertext, and continue Git.

The unresolved marker body is encrypted at rest and its EDRY flag is
authenticated. A normal editor save clears the flag only after all canonical
marker lines are absent.

The v1 unlocked merge supports bounded normal-file conflict stages. It fails
closed on split index, unsafe Git directories, attribute overrides, non-regular
modes, identity reuse, concurrent index/worktree changes, and unsupported
cross-path rename/modify cases. Native Windows and the full rename/modify
acceptance row remain pending release evidence.

### Resolve a `vault.json` conflict

The `merge=inex` rule intentionally covers `*.md.enc`, not `vault.json`.
Vault metadata contains no plaintext master key, but its complete password-slot
and feature state is authenticated. An ordinary line merge, hand-combined slot
array, or conflict marker makes it invalid and is not a recovery procedure.

Preserve the two complete Git blobs and every relevant password first. On a
disposable copy, select one **whole** metadata version, prove that it unlocks and
authenticates representative EDRY files, and only then finish the repository
conflict. Recreate any password slot that existed only on the other branch with
`inex password add`; do not copy its JSON object by hand. Back up and restore the
result before retiring either password/version. If neither whole metadata
version unlocks the current EDRY set, stop and restore a known-consistent
vault/Git snapshot.

### Recover an interrupted encrypted merge

`inex verify <vault>` reports a structurally valid pending Git journal as:

```text
pending-git-merge-transaction: present-authenticated-recovery-required
```

Authenticate and reconcile it with:

```sh
"$INEX" git recover /absolute/inex-vault
```

Recovery accepts only the recorded original or exact result worktree/index
states, re-authenticates the result EDRY object, completes a missing side, and
then removes the journal. A recovery conflict leaves the current state for
audit. Do not delete the journal, run `git reset --hard`, abort the Git operation,
or retry merge writes until the state has been copied and understood.

## Password operation recovery

Adding or changing a password commits a fresh slot before removing an old one.
The expected successful sequence is:

1. new slot metadata is atomically written and independently unlocked;
2. its UUID and parent-sync state are printed;
3. for `password change`, the selected old slot is retired separately.

If old-slot retirement fails after the new slot is committed, Inex reports a
dedicated error containing the new slot UUID. Preserve the vault and output,
prove the new password against that slot, then use `password remove` with the
new slot as the retained slot. Do not discard the old password until the final
slot set and backup have been verified.

`ParentSyncStatus::NotSynced` means the requested metadata/ciphertext was proven
complete in the live namespace, but parent-directory crash durability was not
confirmed. Do not blindly repeat the operation: first inspect/verify current
state, create a clean backup, and decide whether the platform itself is suitable
for release use.

Slot removal affects only current metadata. Git history, clones, and backups may
retain older authenticated `vault.json`; an old password plus that metadata
unwraps the same stable master key and can decrypt later same-epoch files.
Password change is therefore not a response to credential compromise. The
current CLI has no master-key rotation/re-encryption migration. Preserve
forensic state, secure repository access, and treat the vault key as compromised
instead of claiming that slot retirement revoked historical access.

## Editor draft recovery

### VS Code

Leave VS Code's backup file under its control. On reopening a dirty custom
document, unlock the matching vault and let the Inex provider authenticate the
EDRY backup. Stale-base recovery requires two explicit choices before save.
Never decrypt, copy, or rename an editor backup manually.

### Sublime Text

The plugin stores SHA-256-named EDRY files under
`Packages/User/InexEncryptedDrafts`. On open it offers restore-as-dirty,
ciphertext-only discard, or cancel. A stale draft gets an additional overwrite
confirmation at Save. Preserve this directory during diagnosis, but do not
claim it as a supported recovery mechanism until the complete Build 4200
residue matrix passes.

Managed Sublime views carry a fixed non-secret marker. Plugin-load code and pure
tests require orphaned marked views to be scrubbed before allowing new editing,
but exact Build 4200 does not restart a killed plugin host in the same editor
process. With no Inex code running, a still-visible buffer remains actively
copyable until the entire Sublime application is restarted. Current black-box
evidence records that SIGKILL result as `PASS_WITH_DOCUMENTED_BOUNDARY`, with
no scanned disk residue after application exit, not as plaintext erasure.
Preserve the distinction in incident reports; do not describe the marker as
observed same-process recovery or instantaneous crash containment.

## Upgrade and rollback procedure

EDRY v1 and RPC v1 have explicit versions. Readers fail closed on unknown
versions or required features, and opening a frozen v1 fixture must not rewrite
it. The current repository has no automatic vault-format migration command.

For any checkpoint upgrade:

1. Save, lock, stop clients, and create a tested ciphertext backup.
2. Record `inex --version`, the Git commit/artifact hashes, editor version, OS,
   architecture, and `inex verify` output.
3. Read release notes for format, protocol, Unicode/MSRV, and platform changes.
4. Replace `inex` and `inexd` as a matched pair. Replace the editor client with
   the matching revision; do not mix a new client with an unreviewed old daemon.
5. Run `inex git install-driver` again in every clone so the repository-local
   absolute driver path is current.
6. Re-run structural verification, unlock, read representative Unicode/newline
   documents, exercise save to a disposable copy, and inspect Git ciphertext.
7. Keep the pre-upgrade backup until a restore has been tested.

Rollback means restoring the complete known-good ciphertext backup and matched
program set. Do not attempt to downgrade by editing `vault.json`, EDRY headers,
or Git journals. Because Inex does not prevent rollback to an older valid Git
commit, protect remote refs and backup retention according to the value of the
journal.

See [troubleshooting.md](troubleshooting.md) for common error classes and
[release-checklist.md](release-checklist.md) for evidence that is still required
before any supported release.
