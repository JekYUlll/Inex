# Git merge and recovery v1

Status: **implemented pre-alpha contract on 2026-07-11**.

Git always stores and transports complete EDRY envelopes. No Inex command
creates a plaintext merge file, sends plaintext to Git, or asks Git to interpret
Markdown bodies.

## Per-clone installation

Run the following explicitly at the top-level vault worktree:

```text
inex git install-driver <vault>
```

The command first verifies that the selected directory is both a structurally
valid vault and the exact top-level worktree with a normal local `.git`
directory. Linked worktrees and external/reparse gitdirs are rejected in v1 so
the index does not escape the audited local-filesystem boundary. It then
idempotently installs:

```gitattributes
*.md.enc -text -diff merge=inex
```

```gitignore
/.vault-local/
```

Existing UTF-8 files are preserved and the managed exact line is kept last
(so later matching attributes cannot silently override it) by a same-directory,
etag-conditional atomic metadata replacement under the Inex
vault mutation lock. Links, hard links, case aliases, non-regular files,
non-UTF-8 data, files over 1 MiB, and concurrent replacements fail closed.
The installer verifies root/nested probes and every existing ciphertext path
with batched `git check-attr`. Batches use a conservative encoded-command-line
budget rather than a path-count limit, including worst-case Windows quoting
expansion; the unlocked merge repeats the check for every actual conflict path.
Higher-precedence `.git/info/attributes` and nested `.gitattributes` overrides
therefore fail closed.

Only repository-local Git configuration is written:

```ini
[merge "inex"]
    name = Inex encrypted Markdown (locked-safe)
    driver = '<absolute-current-inex-executable>' merge-driver
```

Windows also receives repository-local `core.longPaths=true`. Global and system
Git configuration are neither changed nor required. `.gitattributes` and
`.gitignore` should be committed so fresh clones inherit the data rules; each
clone still requires the explicit local-config command.

The absolute executable is canonicalized at installation and encoded as one
POSIX-shell single-quoted word (including the standard embedded-quote escape
when needed). No `%O/%A/%B/%P` placeholder appears in installed configuration,
so a conflict path cannot become shell input and merge-time `PATH` cannot select
a different `inex` binary.

## Locked-safe driver

Git invokes:

```text
'<absolute-current-inex-executable>' merge-driver
```

The compatibility form `inex merge-driver %O %A %B %P` is also accepted and
has the same no-read behavior, but the installer intentionally does not use it.

This command unconditionally:

- does not open, stat, canonicalize, hash, or modify any supplied path;
- does not inspect EDRY, request a password, consult an environment secret, or
  start/connect to `inexd`;
- leaves `%A` bytes, permissions, and timestamps unchanged; and
- emits a fixed path-free diagnostic and exits `1` so Git retains stages 1/2/3.

This is intentionally not an automatic decrypting hook. A Git process has no
authenticated unlock capability in v1.

## Explicit unlocked merge

After Git reports encrypted conflicts, run:

```text
inex git merge <vault> [--slot <uuid>]
```

The password follows the normal hidden-TTY or bounded
`INEX_PASSWORD_STDIN=1` input rule and is dropped before Git plumbing begins.
The workflow is:

1. Reconcile one pending encrypted transaction, if present.
2. Read `git ls-files -u -z` with a 64 MiB output and 100,000-conflict bound.
3. Accept only canonical UTF-8 `*.md.enc` paths, ordinary `100644` modes,
   and lowercase SHA-1/SHA-256
   object IDs.
4. Read each existing stage with `git cat-file blob <oid>`, bounded to the EDRY
   maximum, then authenticate vault id, epoch, logical path, committed kind,
   AEAD, and UTF-8 before exposing plaintext to diff3.
5. Treat a missing stage as the empty side for add/add and delete/modify
   conflicts. Use ours, then theirs, then ancestor as the stable EDRY file
   identity source.
6. Run pinned `diffy 0.5.0` diff3 in memory. Its returned `String` is wrapped in
   `Zeroizing`; all authenticated stage plaintext allocations already zeroize.
7. Encrypt with a fresh nonce. Clean output clears
   `UNRESOLVED_MERGE`; conflict-marker output sets it.
8. Send only the complete encrypted result to
   `git hash-object -w --stdin`, read the named blob back byte-for-byte with
   replacement objects disabled, synchronize its loose object and directories.
9. Recheck the exact index-stage snapshot and expected worktree ciphertext
   SHA-256 under the Inex mutation lock, synchronize a recovery journal, then
   atomically replace the worktree ciphertext and update stage zero via
   `git update-index -z --index-info`.
10. Re-read both worktree digest and index. Only then remove and synchronize the
    journal. The Git index file and `.git` directory are explicitly synchronized
    first. Any `ParentSyncStatus::NotSynced` or Git/object/index barrier failure
    retains the journal and returns nonzero for authenticated recovery.

An unresolved result is nevertheless a complete authenticated EDRY file and a
stage-zero Git object; the command exits nonzero and reports the unresolved
count. Open it through an Inex editor, remove the canonical diff3 marker lines,
and save. The ordinary authenticated `file.write` path re-encrypts the body and
clears the flag only when no marker line remains. Stage that ciphertext and
continue the Git operation. A normal file never gains the flag merely because
its body contains marker-like text.

Because every authenticated rename uses a fresh nonce and path-bound AAD, Git's
ciphertext similarity heuristic cannot reliably identify rename/modify pairs.
The merge pass inventories stage-zero EDRY file IDs, then authenticates every
conflict stage in a global preflight and compares all identities against both
that inventory and one another. If a conflicted identity exists at another
logical path, it rejects the complete pass before writing rather than creating
duplicate identities. Cross-path rename/modify,
rename/rename, executable modes, and mode disagreements therefore remain
unmerged for explicit user restructuring in this checkpoint. Split indexes are
also rejected before merge mutation: an effective `core.splitIndex=true` or any
top-level `.git/sharedindex.*` artifact fails closed because v1's durability
barrier intentionally covers one full `.git/index`. Run no other Git porcelain
in parallel with `inex git merge` or recovery: Git's own `index.lock`, exact
pre/post stage checks, worktree SHA-256 conditions, and the Inex journal detect
and fail on observed races, but Git exposes no cross-process compare-and-swap
primitive spanning both its index and the worktree.

## Subprocess boundary

Inex resolves `INEX_GIT_PATH` only when it is an explicit absolute regular
executable; otherwise it searches the parent `PATH` once and canonicalizes the
first regular `git`/`git.exe`. Every later `Command` uses that absolute path.
Git 2.36 is the enforced minimum because older releases do not give
`core.fsmonitor=false` the required boolean-disable meaning.

Each Git child receives a cleared environment and a leading
`-c core.fsmonitor=false`, so repository configuration cannot launch an
fsmonitor process during index inspection. Inex adds only fixed values for
noninteractive operation (`GIT_CONFIG_NOSYSTEM=1`, `GIT_NO_LAZY_FETCH=1`,
prompts and optional locks disabled, replacement objects disabled, pager fixed,
`C` locale) plus the minimal Windows process variables or Unix `TMPDIR` needed
to start the executable. Promisor objects therefore cannot trigger an implicit
network fetch or credential helper. No caller `GIT_*`, password, key, token,
query, or plaintext variable survives. stdout is bounded per operation; stderr
is discarded and errors retain only a fixed operation category and
`io::ErrorKind`.

## Journal and recovery

`.vault-local/git-merge-journal-v1.json` contains only:

- the portable ciphertext path and regular mode;
- the exact stage modes/object IDs;
- the expected old worktree ciphertext SHA-256;
- the new encrypted object ID and ciphertext SHA-256; and
- a format version.

It never contains a password, key, session token, decrypted bytes, snippets, or
conflict labels. The file is create-only, permission-restricted where supported,
fully flushed and synchronized before the first worktree change. A partial or
tampered journal fails closed.

On Linux, file `fsync` plus directory `fsync` covers the loose object, full index,
worktree parent, and journal parent. On Windows, files are opened with write
access solely for `FlushFileBuffers`, and directory handles use the core's
audited backup-semantics flush path. The native Windows crash/power-cut matrix
remains a Phase 7 release gate even though the Windows GNU target is
compile-checked in Phase 6.

Run:

```text
inex git recover <vault> [--slot <uuid>]
```

Locked `inex verify <vault>` reports whether a structurally valid pending Git
merge journal exists, but deliberately does not authenticate its result object
or complete the transaction without a password.

Recovery fetches the recorded Git blob, checks its ciphertext digest, and
authenticates it with the unlocked vault before mutation. It accepts only four
safe post-crash facts: original index stages or exact result stage zero, and
original/absent worktree ciphertext or exact result ciphertext. It completes
the missing side, verifies both, and removes the journal. Any other index,
worktree, object, path, mode, or digest state reports a recovery conflict and is
left untouched for audit.
