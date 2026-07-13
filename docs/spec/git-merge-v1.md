# Git merge and recovery v1

Status: **implemented pre-alpha contract updated on 2026-07-13**.

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
10. Create a private v5 scratch directory, copy the exact old index to its
    `candidate.index`, and let `git update-index -z --index-info` generate the
    final alternate index there. Verify the complete before/after stage maps,
    then write a canonical `manifest-v5.json` binding the repository object
    format, random transaction token, stable bundle name, exact old/final index
    lengths and SHA-256 digests, candidate member metadata, and one of the three
    semantic merge payloads. Reopen and verify the scratch directory as an
    exact two-member, single-link regular-file inventory. Only then synchronize
    it and publish the whole directory by a verified no-replace move to its
    stable immutable bundle name. This current inventory covers directory
    entries and each member's unnamed data stream; native Windows enumeration
    of alternate data streams on the bundle directory and both members remains
    a release gate.
11. Copy the verified final index from the stable bundle to a separate private
    publish-staging file. Atomically install the canonical `INEXIDX5\0` marker
    at the real `.git/index.lock`, then repeat the old-index, complete stage-map,
    owner, attribute, fixed-provenance, candidate, and worktree checks. Publish
    a strict create-only v5 journal that references the immutable bundle and
    exact marker bytes before changing the worktree. Recovery and the normal
    writer share the same forward-only completion: advance the authenticated
    worktree, replace the marker with the final candidate, publish that lock
    over `.git/index`, and reconcile an exact-final or later-unrelated index.
    Durable cleanup then retires the stable bundle and journal through the
    bounded receipt-backed state machine described below. Any unconfirmed
    barrier retains a recognizable forward-recovery state and returns nonzero.

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
and alternate indexes. New v5 transactions implement a physical expected-old
CAS by holding the same real `index.lock` honored by ordinary Git index writers.
An external index writer that publishes before Inex acquires the real lock is
detected by the locked old-index digest/semantic recheck; a writer started
while Inex holds the lock fails. The supported workflow still
forbids deliberate parallel porcelain: ref-only operations are outside the
index lock, legacy v1/v2/v3/v4 recovery keeps its historical update path, and
native Windows Job Object/handle, NTFS/ReFS, abrupt-kill, and power-loss
behavior is not yet binding evidence.
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

The legacy v4 pre-journal filename
`.vault-local/git-index-prelock-v4.json` contains a strict duplicate-free
canonical reservation for one token-derived candidate and the old-index
digest/length. Its phase receipts remain readable so an interrupted v4
transaction can be preserved or recovered, including the historical
candidate/receipt gap that intentionally fails closed for manual audit. New
transactions do not create that reservation: the v5 stable immutable bundle is
the complete durable pre-lock recovery capability. Unknown reserved names,
malformed bytes, another object format, index drift, links, or a conflicting
journal/lock are preserved and fail closed.

If the process dies before any scratch entry's no-replace publication, one
token-derived unpublished entry may remain: a directory while preparing the
bundle, or a regular file while preparing publish staging, the marker, or the
journal.
It is counted by the internal recovery status but is orthogonal to the active
owned transaction and does not block a later merge. Active recovery/cleanup
intentionally leaves it rather than deleting without complete ownership proof.
The current CLI projects only the active pending boolean, so a printed `none`
is not a zero-scratch assertion.

The stable filename `.vault-local/git-merge-journal-v1.json` contains one strict
duplicate-free schema selected by its internal version. Versions 1, 2, 3, and
4 remain readable for legacy in-place, split-rename, detected-rename, and CAS
recovery. Every new transaction writes v5. Its compact outer journal contains
the exact immutable-bundle reference and canonical `INEXIDX5\0` marker
size/digest; the bundle's canonical manifest is the sole complete copy of the
semantic transaction and additionally binds:

- the exact SHA-1/SHA-256 repository object format;
- a random lock token and fixed stable-bundle/publish-staging names;
- exact old/final index lengths and SHA-256 digests;
- the exact `candidate.index` member basename, length, and SHA-256; and
- the complete in-place, detected-rename, or split-rename payload.

The inner payload contains only:

- one portable ciphertext path, or exact source/destination paths and regular
  mode;
- exact original stage modes/full object IDs and the repository object format;
- for rename transactions, side, authenticated file ID, and fixed
  base/`HEAD`/`MERGE_HEAD` commit IDs;
- expected original source/destination ciphertext state and SHA-256 digests;
- the new encrypted object ID and ciphertext SHA-256; and
- the schema version.

Neither manifest nor journal contains a password, key, session token, decrypted
bytes, snippets, or conflict labels. Canonical manifest and candidate are fully
written, permission-restricted, flushed, and inventory-verified in scratch;
the exact two-member directory is then moved no-replace to its stable name.
Marker and journal are likewise created through private retained scratch files,
strict byte validation, and verified no-replace publication. Duplicate/unknown
fields, partial data, tampered bindings, unexpected inventory, and unknown or
foreign `index.lock` content fail closed. Direct same-user namespace replacement
remains outside the threat model.

After worktree/index forward completion, v5 cleanup accepts exactly seven
physical states: `StableJ`, `CleanupFullJ`, `CleanupFullR`,
`CleanupManifestR`, `CleanupEmptyR`, `ReceiptOnly`, and `Clean`. It moves the
immutable stable bundle to its token-bound cleanup name, atomically retires the
unchanged canonical journal to a cleanup receipt, then verified-removes
`candidate.index`, `manifest-v5.json`, the empty cleanup directory, and finally
the receipt. Every edge reopens or retains identity proof, accepts only the
adjacent old/new state, rechecks the completed payload where required, and
confirms the relevant parent-directory durability before progressing. Foreign,
cross-product, linked, rebound, malformed, or non-adjacent states remain for
audit.

On Linux, file `fsync` plus directory `fsync` covers the loose object, full index,
worktree parent, bundle/journal/receipt parents, and cleanup transitions. The
native Linux force-kill harness has passed 230 cases across SHA-1 and SHA-256
repositories and all three payload shapes, including later-unrelated index
cases. That is Linux process-kill/restart evidence only; it is not power-cut
evidence. On Windows, files use `FlushFileBuffers` and directory handles use
the core's audited backup-semantics flush path, but native Job Object descendant
termination/handle-release, NTFS/ReFS, abrupt-kill, and power-loss matrices
remain Phase 7 release gates even though the Windows GNU target is
compile-checked.

Run:

```text
inex git recover <vault> [--slot <uuid>]
```

Locked `inex verify <vault>` reports whether a structurally valid pending Git
merge journal, legacy v4 reservation, v5 immutable bundle/marker prefix, or v5
cleanup capability exists. Explicit recovery still distinguishes an exact
forward-recoverable state from a conflict. Verification deliberately does not
authenticate a result object or advance a transaction without a password.

Recovery first validates every recorded ID against the repository object
format, rechecks the complete stage map and protected owner/alias projection,
fetches the result blob, checks its ciphertext digest, and authenticates
path/file identity. For v5 it can resume from stable-bundle-only,
publish-staging, `INEXIDX5\0` marker, durable-journal, worktree-prefix,
candidate-lock, exact-final/later-unrelated index, and each adjacent cleanup
state. Worktree changes move only forward. A detected rename keeps the source
absent; a split rename writes destination before conditional source deletion.
If ordinary Git legitimately changes unrelated index entries after publication,
recovery clears v5 only when the exact result entry/source-removal,
authenticated owners, provenance, and final worktree remain valid; target-entry
drift is a conflict. Final-index recovery uses fixed commit IDs and does not
require a still-present `MERGE_HEAD`. Legacy v1-v4 schemas keep their strict
historical recovery paths and must be recovered with all other Git stopped. A
foreign lock and any other index, worktree, object, path, mode, owner,
provenance, format, digest, or capability state are left untouched for audit.
