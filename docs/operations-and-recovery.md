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

For release engineering, a source checkout provides
`scripts/drill_release_lifecycle.py`. It rehearses the normal path with a final
Linux artifact, a synthetic disposable source, Git bundle and clean
regular-file tree-copy restores, and authenticated byte comparison. It refuses
a dirty harness worktree and native Windows until Windows process-tree and ADS
coverage exist. The drill captures and audits the bounded four-file artifact
set before creating secrets, requires an exact imported ciphertext layout,
accepts only one Git `main` ref/commit with no unreachable objects, and scans
content plus relative path components outside the intentionally retained
`plaintext-source`. A failure after the disposable evidence root is created
retains it and prints its path for explicit inspection and cleanup; an early
dirty-source, Windows, or input-path rejection creates no root. A successful
run removes its evidence root.

The strict Linux x64 artifact set from `40ff728` has passed this drill from
an independent no-hardlinks clone of clean harness commit `d44ead9`: all five bodies authenticated
byte-for-byte, both restore paths and driver relocation passed, frozen-v1
product bytes remained unchanged, CLI/RPC/locked-Git failure paths disclosed no
dynamic secret, and the sensitive scan found zero hits outside
`plaintext-source`. The report is lifecycle-only and is not release approval.

Treat that result as binding only from a dedicated standalone, exclusive and
quiescent release checkout. From interpreter startup through artifact/report
capture, no editor, sync client, watcher, sibling worktree, build process or
other same-principal writer may modify the worktree, Git administration state,
generated inputs, target/artifact directory, `PATH` or toolchain. The harness
samples and rehashes these boundaries but does not acquire an OS-wide lock; its
JSON therefore records this trust assumption and excludes adversarial
same-user release-host writers. The manifest source commit is not a build
attestation for binaries or generated editor bundles.

A clean passing Linux x64 result is a platform checkpoint only: it does not
simulate publication ambiguity, power loss, a real failure journal, NTFS ADS,
or rollback between two released program versions.

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

The v1 unlocked merge supports bounded normal-file stages plus authenticated
rename/modify in two Git representations: a detected three-stage destination
and a split delete/modify source with a stage-zero destination. A rename must be
proved by the unique merge base and exact `HEAD`/`MERGE_HEAD` trees; historical
copies, rename/rename, multiple merge bases, executable/mode disagreement, and
ambiguous identities fail closed. Versioned source-aware journals recover both
paths without deleting an unexpected source. Split indexes, unsafe Git
directories, attribute overrides, non-regular modes, and observed concurrent
changes also fail closed. New transactions publish a v4 pre-lock reservation
before creating the alternate-index candidate, then use an Inex-owned real
`.git/index.lock`, phase-bound candidate ownership receipts, and exact
old/candidate index digest
bindings. Ordinary index writers that win before the lock are detected by the
locked recheck; writers started while it is held fail instead of being
overwritten. Continue to avoid deliberate parallel Git: legacy v1/v2/v3
recovery and ref-only mutations are not serialized by v4, and native Windows
abrupt-kill/power-loss evidence remains pending.

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

`inex verify <vault>` reports a structurally valid pending Git journal or an
Inex-marked pre-journal v4 reservation, including the reservation that precedes
candidate creation, as:

```text
pending-git-merge-transaction: present-authenticated-recovery-required
```

Authenticate and reconcile it with:

```sh
"$INEX" git recover /absolute/inex-vault
```

For v4, recovery recognizes only `old index + pre-lock reservation` with its
token-derived transient files, `old index + marker + candidate`, `old index +
candidate lock`, or a published index whose owned names were consumed. It
re-authenticates the EDRY result, owner set, fixed rename provenance, target
stage, and worktree before moving forward. A later unrelated stage may remain;
a changed/removed result stage is a conflict. Exact abandoned pre-journal
marker/candidate state is cleaned without changing the index/worktree. Unknown
or foreign locks are preserved. A force-kill between candidate creation or
mutation and its matching ownership receipt is also preserved as a recovery
conflict; do not delete those files by hand. Legacy v1/v2/v3 journals remain readable but
must be recovered with all other Git stopped. A recovery conflict leaves the
current state for audit. Do not delete the journal, run `git reset --hard`,
abort the Git operation, or retry merge writes until the state has been copied
and understood.

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
