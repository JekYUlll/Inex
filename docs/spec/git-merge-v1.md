# Git merge and recovery v1

Status: **implemented pre-alpha contract updated on 2026-07-12**.

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
2. Read `git ls-files -u -z` and one complete staged-index snapshot with a
   64 MiB output and 100,000-conflict bound. Reject any physical path that has
   both stage zero and stages 1/2/3; no update may silently replace an
   unrecorded coexisting entry.
3. Accept only canonical UTF-8 `*.md.enc` paths, ordinary `100644` modes, and
   lowercase full-width object IDs matching the repository's frozen
   `rev-parse --show-object-format` result. A SHA-256 repository never accepts
   a 40-character prefix as a complete ID.
4. Read each existing stage with `git cat-file blob <oid>`, bounded to the EDRY
   maximum, then authenticate vault id, epoch, logical path, committed kind,
   AEAD, and UTF-8 before exposing plaintext to diff3.
5. Treat a missing stage as the empty side for add/add and delete/modify
   conflicts. For a rename candidate, require one unique merge base and prove
   the exact source/destination mode and object IDs in the base, `HEAD`, and
   `MERGE_HEAD` trees. Only one side may move the authenticated identity; the
   other side must modify the original source. Historical destinations,
   copies, rename/rename, ambiguous identities, and multiple merge bases fail
   closed.
6. Revalidate the target file identity across the complete stage-zero index and
   authenticated worktree. The only temporary duplicate allowed is the exact
   source/destination pair of the active split-rename transaction; any third
   tracked or untracked owner fails before mutation.
7. Use ours, then theirs, then ancestor as the stable EDRY identity source and
   run pinned `diffy 0.5.0` diff3 in memory. Its returned `String` is wrapped in
   `Zeroizing`; all authenticated stage plaintext allocations already zeroize.
8. Encrypt with a fresh nonce. Clean output clears
   `UNRESOLVED_MERGE`; conflict-marker output sets it.
9. Send only the complete encrypted result to
   `git hash-object -w --stdin`, read the named blob back byte-for-byte with
   replacement objects disabled, synchronize its loose object and directories.
10. Before creating an alternate index, atomically publish the strict
    create-only `.vault-local/git-index-prelock-v4.json` reservation. It binds
    the repository object format, a random token, that token's one permitted
    candidate basename, and the exact old-index length and SHA-256. Then copy
    the exact old index bytes to that private `GIT_INDEX_FILE`, let
    `git update-index -z --index-info` generate the final candidate there, and
    verify the complete before/after stage maps. Synchronize and bind both
    index lengths and SHA-256 digests; they must differ. A create-only initial
    ownership receipt binds the exact old-index copy before Git may mutate it;
    a second create-only receipt binds the verified final candidate before any
    real-lock marker may be created.
11. Atomically install a complete random-token marker at the real
    `.git/index.lock`. While that Git lock exists, recheck the old index,
    stage-zero owners, attributes, fixed rename provenance, candidate semantics,
    and expected worktree ciphertext. Atomically publish a complete create-only
    v4 journal, then advance the worktree. Publication is two forward-only
    namespace moves: candidate to `index.lock`, then `index.lock` over `index`.
    Re-read worktree/index and synchronize the index, `.git`, and journal parent
    before removing the journal. The pre-lock reservation is removed only after
    that exact stable v4 journal is visible. Any unconfirmed barrier retains a
    recognizable forward-recovery state and returns nonzero.

An unresolved result is nevertheless a complete authenticated EDRY file and a
stage-zero Git object; the command exits nonzero and reports the unresolved
count. Open it through an Inex editor, remove the canonical diff3 marker lines,
and save. The ordinary authenticated `file.write` path re-encrypts the body and
clears the flag only when no marker line remains. Stage that ciphertext and
continue the Git operation. A normal file never gains the flag merely because
its body contains marker-like text.

Because every authenticated rename uses a fresh nonce and path-bound AAD, Git's
ciphertext similarity heuristic is not trusted. Inex accepts both the detected
three-stage destination shape and the split source-conflict/destination-stage0
shape only after comparing their exact entries with the unique base,
`HEAD`, and `MERGE_HEAD` trees. The journal fixes those commit IDs so a final
index can still be verified after the user completes the merge commit and
`MERGE_HEAD` disappears. Rename/rename, historical destination copies,
multiple destinations/bases, executable modes, and mode disagreements remain
unsupported and fail closed.

Split indexes are rejected before merge mutation: an effective
`core.splitIndex=true` or any top-level `.git/sharedindex.*` artifact fails
closed because the durability barrier intentionally covers one full
`.git/index`; `rev-parse --shared-index-path` also has to be empty for the live
and alternate indexes. New v4 transactions implement a physical expected-old
CAS by holding the same real `index.lock` honored by ordinary Git index writers.
An external index writer that publishes before Inex acquires the real lock is
detected by the locked old-index digest/semantic recheck; a writer started
while Inex holds the lock fails. The supported workflow still
forbids deliberate parallel porcelain: ref-only operations are outside the
index lock, legacy v1/v2/v3 recovery keeps its historical update path, and
native Windows abrupt-kill/power-loss behavior is not yet binding evidence.
Direct same-user unlink/rewrite of transaction files is outside the threat
model and is not described as fail-closed concurrency.

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

The pre-journal filename `.vault-local/git-index-prelock-v4.json` contains a
strict duplicate-free canonical reservation for the one token-derived
candidate and the old-index digest/length. It is published and synchronized
before any candidate file exists. If a process dies before obtaining the real
Git lock, recovery requires the stable journal and `.git/index.lock` to be
absent and the live index to remain the exact reserved old snapshot. It then
removes only the reservation's token-derived, non-reparse, single-link regular
candidate/receipt/staging names whose bytes or digest match the recorded phase.
Unknown reserved names, malformed bytes, another object format, index drift,
links, or a conflicting journal/lock are preserved and fail closed. A kill
between candidate creation/mutation and publication of its matching ownership
receipt is visible as pending but intentionally returns a recovery conflict;
it is not silently treated as clean or deleted without proof.

The stable filename `.vault-local/git-merge-journal-v1.json` contains one strict
duplicate-free schema selected by its internal version. Versions 1, 2, and 3
remain readable for legacy in-place, split-rename, and detected-rename recovery.
Every new transaction writes v4, whose tagged inner payload is one of those
three semantic shapes and whose outer binding additionally contains:

- the exact SHA-1/SHA-256 repository object format;
- a random lock token and fixed private candidate basename;
- exact old/candidate index lengths and SHA-256 digests; and
- the complete marker SHA-256 used to recognize an owned pre-journal lock.

The inner payload contains only:

- one portable ciphertext path, or exact source/destination paths and regular
  mode;
- exact original stage modes/full object IDs and the repository object format;
- for rename transactions, side, authenticated file ID, and fixed
  base/`HEAD`/`MERGE_HEAD` commit IDs;
- expected original source/destination ciphertext state and SHA-256 digests;
- the new encrypted object ID and ciphertext SHA-256; and
- the schema version.

It never contains a password, key, session token, decrypted bytes, snippets, or
conflict labels. The complete JSON is first written, permission-restricted,
flushed, and synchronized at a private staging name, then atomically moved
no-replace to the stable create-only name before the first worktree change.
Duplicate/unknown fields, partial JSON, and tampered bindings fail closed. An
exact pre-lock reservation or marker/candidate pair abandoned before stable
journal publication is reported as pending and can be cleaned without changing
index or worktree;
unknown or foreign `index.lock` content is not intentionally removed after the
ownership check. Direct same-user namespace replacement remains outside the
threat model.

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
merge journal or an Inex-marked pre-journal v4 reservation exists. Explicit
recovery still distinguishes an exact cleanable pair from a conflicting marker
state. Verification deliberately does not authenticate a result object or
advance a transaction without a password.

Recovery first validates every recorded ID against the repository object
format, rechecks fixed tree provenance, fetches the result blob, checks its
ciphertext digest, and authenticates path/file identity. For v4 it accepts the
three physical index states `old + marker + candidate`, `old + candidate lock`,
and `final + consumed owned names`. Worktree changes move only forward. A
detected rename keeps the source absent; a split rename writes destination
before conditional source deletion. If ordinary Git legitimately changes
unrelated index entries after publication, recovery may still clear v4 only
when the exact result entry/source-removal, authenticated owners, provenance,
and final worktree all remain valid; target-entry drift is a conflict. A
foreign lock is preserved. Final-index recovery uses fixed commit IDs and does
not require a still-present `MERGE_HEAD`. Any other index, worktree, object,
path, mode, owner, provenance, format, or digest state is left untouched for
audit.
