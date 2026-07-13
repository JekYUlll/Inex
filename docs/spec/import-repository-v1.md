# Repository Import v1

Status: **implementation contract frozen for the first repository-import
slice**. This contract does not change the existing
[`inex import`](import-v1.md) plaintext-tree command.

Repository import creates one new encrypted snapshot and one new Git root
commit from the exact, clean `HEAD` worktree of an existing repository. It is
not a history-rewriting or history-preserving migration.

## Command and non-goals

The only form is:

```text
inex import-repository <source-repository> <new-vault> [--dry-run]
```

The command rejects password, KDF, revision, filter, dirty-tree, history, and
in-place options. V1 has no `--revision`, `--allow-dirty`,
`--include-untracked`, `--run-filter`, `--fetch-lfs`, `--preserve-history`, or
existing-destination mode. It always selects the commit to which the source
repository's `HEAD` resolves during planning.

The command:

- requires the source to be the top level of one ordinary local Git worktree;
- requires a completely absent destination whose parent already exists on a
  supported local filesystem;
- imports every tracked file, with no skipped-file success state;
- creates a complete new Inex vault and a fresh `.git` repository containing
  exactly one parentless encrypted snapshot commit inside one private sibling
  staging root; and
- publishes that complete staging root once through the existing
  marker-bound, verified no-replace directory publication primitive.

It never modifies the source, copies source Git metadata, reuses a source
object database, or connects the new repository to a source remote. A linked
worktree whose root `.git` is a file, a bare repository, and a repository whose
top-level Git directory is outside the worktree are outside v1.

There is no repository-import finalizer, vault-side import journal, owner
record, external Git staging directory, or post-publication Git construction.
Before the single directory publication the final path is absent. After that
publication the final path is the already complete, audited vault and Git
repository. The generic directory-publication marker may reconcile an
ambiguous directory move, but it never authorizes building or modifying Git at
the final path.

Success does not erase the original disclosure surface. The source worktree,
its plaintext history, local backups, reflogs, and existing remote copies
continue to contain plaintext exactly as before. Inex never deletes, rewrites,
pushes, or disconnects them. Archiving or removing those copies is a separate,
explicit manual lifecycle after independent target verification.

`--dry-run` performs the complete source, Git, content, path, resource, and
destination validation. It reads and hashes every source file but does not ask
for a password, calibrate a KDF, create a directory, initialize Git, or write
product state.

## Frozen source profile

The source profile is deliberately narrower than general Git:

- Git object format is exactly SHA-1. `HEAD` resolves to one 40-character
  lowercase commit object id.
- The resolved absolute Git executable reports version 2.36 or newer. V1
  relies on the boolean-disable meaning of `core.fsmonitor=false`.
- Every recursively tracked entry is an ordinary stage-zero blob with exact
  mode `100644`. Executable `100755` files, symbolic-link `120000` blobs,
  gitlinks/submodules `160000`, sparse-directory entries, unmerged stages,
  intent-to-add, assume-unchanged, skip-worktree, fsmonitor-valid, split-index,
  and every other mode or entry flag fail.
- The `HEAD` tree, index, and securely opened worktree describe the same
  complete set of paths and exact bytes.
- The worktree contains only the tracked `HEAD` namespace and the exact root
  `.git` directory. Any other file, directory, ignored entry, or empty
  directory is untracked and fails. `.gitignore` is not permission to omit it.
- Every source path is UTF-8, NFC-normalizable without collision, and valid
  under the Inex Windows/Linux portable path profile. Case-fold,
  normalization, file/directory, Markdown/asset physical-name, and reserved
  storage collisions fail before any write.
- The source root, every tracked directory, and every tracked file remain on
  one filesystem. Links, reparse points, mount crossings, special objects, and
  multiply linked regular files fail.

The exact root `.git` entry is control state, not import content. Inex opens it
as a non-link local directory, captures its filesystem identity, and gives the
absolute Git executable only the repository root as its working directory. The
secure content enumerator verifies and skips this one root entry without
traversing it. A separate bounded control verifier opens only the endpoints
listed below. An entry named `.git` anywhere else is a reserved-path failure.

Before any repository-sensitive Git command, Inex opens exact
`<root>/.git/config` without following links, requires a bounded single-link
regular file on the source filesystem, and captures identity and digest. It
sends those exact held bytes on bounded stdin to
`git config --file - --no-includes --null --list` under the cleared
environment. Git parses the snapshot rather than reopening the pathname, and
this command does not discover the repository or follow includes.
`include`/`includeIf`, `core.worktree`, `core.attributesFile`, worktree config,
external object/ref storage, partial-clone/promisor keys, and malformed or
duplicate security-critical keys fail. The config identity and digest are
checked before and after discovery and at every source checkpoint.

Before the first repository-sensitive command, a no-follow physical walk
inventories the complete root `.git` namespace. It is bounded to 1,000,000
entries, 128 levels, and 256 MiB of retained canonical path bytes. Directories
and regular files stay on the captured source filesystem; symlinks,
junctions/reparse points, mount crossings, named streams, special files, case
aliases, and multiply linked files fail. The inventory includes `HEAD`, refs,
`packed-refs`, the index, info files, loose objects, packs and indexes,
commit-graphs, and multi-pack indexes. It records canonical relative name,
kind, identity, and size, excluding atime and other read-mutated values.
Security-critical held files also retain bounded content digests. The physical
manifest is re-proved at every checkpoint.

The control verifier requires canonical results for `--show-toplevel`,
`--absolute-git-dir`, absolute `--git-common-dir`, `--git-path index`, and
`--git-path objects` to equal the source root, `<root>/.git`, `<root>/.git`,
`<root>/.git/index`, and `<root>/.git/objects`. These endpoints are rebound at
every checkpoint. `.git/commondir`, `.git/worktrees`, `.git/config.worktree`,
object alternates, HTTP alternates, replace refs, grafts, shallow boundaries,
and caller object-directory/alternate environment are rejected.

Any `.git/objects/pack/*.promisor` marker is rejected. Optional cache
extensions `TREE`, `REUC`, `UNTR`, `FSMN`, `EOIE`, and `IEOT` may be accepted
but are never copied. Required lowercase `link` or `sdir`, and every unknown
required index extension, fail. Semantic `-v` and `-f` probes still require
exact uppercase `H` for every path.

Split and sparse index rejection is explicit: local `core.splitIndex` and
`index.sparse` resolve false, `git rev-parse --shared-index-path` is empty,
exact `.git/sharedindex.*` and `.git/info/sparse-checkout` are absent, and
strict index parsing rejects sparse-directory mode and extensions.

### Markdown and assets

Every tracked `100644` file is classified; success has no skipped count:

- An exact lowercase `.md` path is Markdown. Its body is valid UTF-8 and
  satisfies EDRY v1's 16 MiB per-document and 256 MiB aggregate Markdown
  limits. Exact bytes, including line endings, are encrypted as Markdown.
- Every other path is an opaque asset governed by
  [`Opaque assets v1`](opaque-assets-v1.md). Exact bytes are encrypted and
  recovered byte-for-byte; the physical path appends exact lowercase
  `.asset.enc`. Asset final components are at most 245 UTF-8 bytes. The
  per-asset maximum is 67,108,864 bytes, so the 25,074,521-byte acceptance
  image succeeds.

A vault containing at least one asset authenticates required feature `1` in
`vault.json` and every asset envelope. Markdown-only imports remain
feature-free. Repository import never upgrades an existing vault.

The combined source-body limit is exactly 4,294,967,296 bytes. The 256 MiB
Markdown aggregate remains independent. Entry, depth, path, file, and
aggregate limit failures reject the complete plan and are never skipped.

## Binding `HEAD`, index, and worktree

Neither `git status` nor unchanged `HEAD` and index bytes prove a working
file. Repository import binds all three semantic layers and each body.

### Git manifest capture

Planning uses the hardened runner to:

1. prove repository top level, Git version, and object format;
2. resolve `HEAD^{commit}` to full SHA-1 id `H`;
3. enumerate the complete recursive tree of `H` with full object ids, modes,
   types, sizes, and NUL-terminated path bytes;
4. enumerate all index stages and independent `-v` and `-f` tag/path records;
5. require one normal stage-zero `100644` index entry for each `HEAD` blob,
   with identical path and object id, and no other entry; and
6. retain SHA-256 digests of canonical `HEAD` and index semantic maps rather
   than trusting order or the mutable stat cache in `.git/index`.

The intended plumbing is equivalent to:

```text
git rev-parse --show-object-format
git rev-parse --is-inside-work-tree
git rev-parse --show-prefix
git rev-parse --verify HEAD^{commit}
git ls-tree -r -z --full-tree -l <H>
git ls-files -s -z --full-name
git ls-files -v -z --full-name
git ls-files -f -z --full-name
```

Output is bounded before retention. Parsing rejects abbreviated or uppercase
object ids, duplicates, non-NUL path framing, malformed sizes, unknown types,
and records outside the frozen profile.

### Secure namespace and per-file proof

The descriptor/FileId-based copy-import traversal skips only the captured root
`.git`, compares the remaining physical namespace with the `HEAD` map, and
captures directory identities for later revalidation. Ignored and untracked
entries are detected without Git exclude or filter machinery.

For every tracked file `P` with `HEAD` blob id `O`, Inex:

1. opens `P` through the secure source root without following links or crossing
   a mount;
2. verifies a single-link regular handle and parent-directory binding;
3. reads exactly the bounded observed length, probes for append, and computes
   the import SHA-256 digest;
4. sends those bounded bytes to `git hash-object --stdin --no-filters` without
   `-w`, pathname, or filter option and requires full id `O`;
5. reads raw blob `O` using `git cat-file blob <O>`, bounded by tree size and
   the applicable content limit;
6. requires raw length, SHA-256, and bytes to equal the securely opened file;
   and
7. rechecks file and directory bindings after the read.

This rejects dirty content and transformations including CRLF normalization,
`ident`, `working-tree-encoding`, and custom clean filters. Population rereads
both worktree file and raw blob and repeats length, digest, bytes, object id,
and namespace proofs before encryption. Stability alone is not acceptance.

### LFS and filters are rejected

No Git or Git LFS content filter is executed. Fixed-index attributes for
`filter`, `working-tree-encoding`, and `ident` are inspected; any selected
content-transforming value, including `filter=lfs`, is unsupported.

Every raw `HEAD` blob no larger than 4,096 bytes is treated as a possible LFS
pointer when its first line is exact
`version https://git-lfs.github.com/spec/v1`, terminated by LF, CRLF, or EOF.
No valid `oid` or `size` line is required to reject it. Canonical, malformed,
truncated, extension-bearing, hydrated, and unhydrated forms therefore fail
without invoking `git lfs`, fetching, or substituting worktree bytes.

The additional plumbing is equivalent to:

```text
git check-attr --cached -z --stdin filter working-tree-encoding ident
git hash-object --stdin --no-filters
git cat-file blob <O>
```

`cat-file` receives only a validated full blob id, never `--filters`,
`--textconv`, a path, or network fallback.

### Source checkpoints

The exact source root and `.git` identities, config and control inventory,
`H`, canonical tree/index digests, secure namespace, and every file proof are
revalidated:

1. after the complete dry plan;
2. immediately before reserving the sibling staging root;
3. before population and after all Markdown and assets are encrypted;
4. after independent vault reopen and full worktree/Git candidate audits; and
5. after candidate durability, immediately before final publication.

Any mismatch is `SourceChanged`. Before publication the final path remains
absent. Restoration to identical semantic maps is not ambiguity when every
secure body proof and immutable object id is also identical.

## Hardened offline Git execution

The Git executable is resolved before environment clearing, canonicalized, and
required to be an absolute regular executable. `INEX_GIT_PATH`, when present,
is already absolute. No shell is used.

Each source Git child:

- runs in the canonical source root with stdin closed unless bounded protocol
  input is required;
- starts from `env_clear()` and receives only minimum platform startup state;
- sets `GIT_CONFIG_NOSYSTEM=1`, absent global config/attributes,
  `GIT_ATTR_NOSYSTEM=1`, `GIT_NO_LAZY_FETCH=1`,
  `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`,
  `GIT_NO_REPLACE_OBJECTS=1`, `GIT_PROTOCOL_FROM_USER=0`, fixed C locale, and
  noninteractive pagers;
- overrides `core.fsmonitor=false`, `protocol.allow=never`, and
  `submodule.recurse=false`; and
- has bounded stdin/stdout, discarded scrubbed stderr, a one-minute deadline,
  and kill-and-wait teardown on timeout or excess output.

The permitted read-only commands cannot invoke aliases, hooks, editors,
pagers, external diff, credentials, transports, filters, textconv, checkout,
or submodule recursion. Import does not run source `status`, `diff`, `show`,
`archive`, `checkout`, `restore`, `add`, `commit`, `fetch`, `pull`,
`submodule`, or `git lfs`. Exact `.git/info/attributes` is absent. Required
local objects must already exist; no promisor or alternate fallback is used.

Target construction uses the same Git executable and a separate runner. Every
child starts cleared and receives the same offline, noninteractive safeguards,
plus fixed `core.hooksPath=<held-empty-directory>`. On Windows every target
child also receives leading `core.longPaths=true`. After `init`, commands
receive exact absolute staging-root `GIT_DIR`, staging-vault `GIT_WORK_TREE`,
and candidate `.git/index`; no repository discovery or source path is allowed.
Empty template and hooks directories are identity-bound and rechecked.

Target stdin/stdout are operation-specific and bounded, stderr is discarded,
and timeout teardown kills and waits. `git init` output is discarded. Allowed
target subcommands are exactly `init`, `config`, `hash-object`, `update-index`,
`write-tree`, `commit-tree`, `update-ref`, `rev-parse`, `for-each-ref`,
`ls-files`, `ls-tree`, and `cat-file`, plus fixed verification probes. No
hook, editor, pager, transport, credential helper, filter, textconv, external
diff, or source alternate can execute.

## One staging-root transaction

After source validation and normal password/KDF selection, creation performs
one prepublication transaction:

1. revalidate the absent destination, stable parent identity, non-overlap with
   source, same-filesystem requirement, and supported local filesystem;
2. reserve through create-only semantics one fresh hidden sibling staging root
   using the existing import-staging name grammar and capture its identity;
3. create the vault in that root and encrypt every planned Markdown document
   and asset without writing a plaintext source file;
4. compare every authenticated decrypted body with the planned kind, length,
   SHA-256 digest, and exact bytes, then zero/drop plaintext buffers;
5. create exact root `.gitattributes` and `.gitignore` metadata through bounded
   verified writes; `.gitignore` excludes `.vault-local/`, and attributes end
   with the managed rules below;
6. initialize a new SHA-1 Git repository as `<staging-root>/.git`, hash only the
   approved encrypted worktree, create the exact index/tree/root commit, and
   install only `refs/heads/main`;
7. drop the creating vault/session, independently unlock the staging vault,
   verify all content, close it again, and perform the physical and Git-object
   audits below;
8. recursively establish and verify durability for the complete staging root,
   including `.git`, then repeat the final source and destination-parent
   checkpoints; and
9. publish the entire staging root to the absent destination using one
   marker-bound, identity-reconciled, verified no-replace directory move.

The staging root and destination are siblings so publication cannot cross a
filesystem. `.git` is never a sibling of the vault and never moves separately.
No repository-import intent, owner, candidate manifest, completion receipt, or
other special recovery record is stored under `.vault-local` or beside the
staging root. Generic staging/publication metadata belongs only to the existing
directory-publication primitive.

## Target Git root commit

Inex initializes the worktree directly:

```text
git init --object-format=sha1 --initial-branch=main \
  --template=<held-empty-directory> <staging-root>
```

The resulting config has exact `core.bare=false`, no `core.worktree`, no
alternate, remote, include, filter, or active hook. It installs the same
locked-safe Inex merge driver as `inex git install-driver`; Windows also gets
the existing repository-local long-path setting. Initial ref creation uses a
process-local `core.logAllRefUpdates=false` override so no source-like or
initial reflog is created; final config enables the normal later policy.

Root attributes end with:

```gitattributes
*.md.enc -text -diff merge=inex
*.asset.enc binary
```

Inex hashes exact approved ciphertext and metadata using
`hash-object -w --stdin --no-filters`, builds the exact index from explicit
`100644 <oid> <path>` records, writes one tree, and calls `commit-tree` with no
`-p` parent. V1 fixes:

```text
author/committer: Inex Repository Import <inex-import@localhost.invalid>
message: Initialize encrypted Inex vault
branch: refs/heads/main
```

Author and committer timestamps are the import time in UTC. No source author,
timestamp, message, commit id, branch, tag, remote, reflog, hook, replace ref,
graft, shallow boundary, alternates file, or object is copied. The object
inventory equals the independently computed set of approved encrypted/metadata
blobs, derived trees, and one parentless commit. Natural object-id equality
with independently generated identical metadata is not evidence of copying.

Tracked worktree paths are exactly the versioned vault allowlist:
`vault.json`, `.gitattributes`, `.gitignore`, authenticated directory
metadata, planned `*.md.enc`, and planned `*.asset.enc`. `.vault-local` and
`.git` are not tracked. No source `.md` or original asset body is a target
worktree file or Git blob.

## Independent candidate audits

The creating vault object, master-key handles, sessions, and plaintext buffers
are dropped before independent verification. A fresh vault open authenticates
`vault.json`, required features, every directory record, and every planned
document/asset envelope. Decryption must recover the planned kind, logical
path, length, digest, and exact bytes. Verification closes and zeroes the
fresh session before Git and publication audits continue.

A no-follow physical walk of the entire staging root then requires:

- the exact versioned vault allowlist plus private `.vault-local` and `.git`;
- no source `.md`, original asset path, plaintext temporary/export/backup file,
  import journal, owner record, external Git staging reference, unknown entry,
  link, reparse point, named stream, multiply linked file, mount crossing, or
  case alias;
- every Markdown/asset blob to be one canonical envelope whose parser consumes
  all bytes; and
- every retained file and directory to remain bound to the staging identity
  and planned filesystem.

An independent `.git` audit requires:

- `HEAD` is exact `refs/heads/main` and resolves to the created commit;
- that commit has zero parents and the exact independently planned tree;
- refs contain only `refs/heads/main` and no reflog exists for initialization;
- index and worktree exactly match the tree;
- repository config is the canonical target config and has no source path,
  remote, alternate, include, executable filter, or active hook;
- complete no-follow Gitdir inventory contains only the canonical fresh-repo
  config/HEAD/index/ref layout, fixed empty directories, and expected loose
  objects; packfiles, unknown files, links, reparse points, named streams,
  multiply linked files, and mount crossings fail; and
- enumerating every object by full id and reading it with `cat-file` yields
  exactly the independently planned blobs, trees, and one root commit, with no
  additional reachable or unreachable object.

Every content blob object is byte-for-byte identical to one approved target
worktree file. Imported-content blobs are complete authenticated envelopes,
not byte-equal to their source bodies, have no accepted trailing bytes, and
independently decrypt to the planned source bytes. This exact inventory proof,
together with the physical walk, is the v1 full-tree and Git-object plaintext
exclusion audit; it does not rely on Git child exit status alone.

## Durability and single publication

Before publication, Inex synchronizes every retained regular file, then every
directory in postorder, including all loose Git objects, refs, index, config,
`.git`, `.vault-local`, and the staging root. It reopens and re-proves all
sealed files, inventories, identities, and the staging parent after those
barriers. An unsupported directory-sync or write-through guarantee fails the
platform gate rather than weakening it silently.

The complete source checkpoint runs after candidate audit and durability. The
destination parent identity, filesystem, absent destination, staging identity,
and exact candidate seals are re-proved immediately before publication.

The existing marker-bound directory publisher then moves the whole staging
root without replacement and synchronizes the common parent. Return values are
reconciled from names, identities, and seals:

- exact staging present and final absent is not published;
- staging absent and final equal to the bound complete candidate is published;
- both names, neither name, a foreign final, an identity mismatch, or an
  indeterminate observation is preserved and fails closed.

An error-after-effect is accepted as published only after reopening the final
root and re-proving the whole candidate identity, vault allowlist, `.git`
inventory, root commit, and parent durability. Success is reported only then.

## Failure and retry semantics

Before the single whole-root move takes effect, every ordinary error, process
kill, or retained partial staging state leaves the final destination absent.
The source is unchanged. A complete or partial hidden staging root is retained
as evidence; cleanup may remove only an exact generic-publication-owned
staging identity after no-follow classification. Name resemblance alone never
authorizes deletion.

Once the move takes effect, the final destination necessarily contains the
already complete vault and `.git`; there is no vault-without-Git or partial
final-Git state. A kill before parent sync or marker cleanup may make the CLI
result indeterminate, but it cannot expose a partially constructed repository.
The same `import-repository` invocation on retry first delegates any exact
marker-bound ambiguity to the generic publisher. It may only prove the whole
candidate already published or preserve a conflict; it never resumes Git
construction at the final path. An unrelated existing destination remains a
hard error.

There is no `finalize-repository-import` command. Normal post-success changes
belong to ordinary Inex/Git workflows and `inex verify`, not initialization
recovery.

## Stable output contract

Source absolute paths, source bodies, Git output/OIDs, semantic digests,
filter configuration, and password material are neither printed nor stored in
the target. Relative names intentionally remain visible because v1 does not
encrypt filenames. Default output prints aggregate counts. The new target root
commit id is target state and is printed canonically.

After a successful plan, dry-run and real creation print in this order:

```text
import-mode: repository-dry-run | repository-copy
source-policy: clean-head-read-only
source-object-format: sha1
source-tree-entries: <decimal>
source-index-entries: <decimal>
source-worktree-files: <decimal>
source-directories: <decimal>
markdown-files: <decimal>
asset-files: <decimal>
markdown-bytes: <decimal>
asset-bytes: <decimal>
largest-asset-bytes: <decimal>
normalized-path-entries: <decimal>
lfs-files: 0
filtered-files: 0
untracked-entries: 0
destination-policy: new-vault-new-git-root-single-atomic-publication
```

Dry-run then prints:

```text
source-revalidated: yes
source-preserved: yes
import-writes: none
password-prompted: no
destination-created: no
candidate-root: not-created
vault-publication: not-started
git-repository: not-created
recovery-required: none
result: repository import plan valid
```

Complete creation additionally prints:

```text
committed-encrypted-markdown: <decimal>
committed-encrypted-assets: <decimal>
candidate-vault-audit: passed
candidate-git-object-audit: passed
candidate-plaintext-file-objects: 0
source-revalidated: yes
source-preserved: yes
candidate-root: published
vault-publication: published
git-repository: initialized
git-root-commit: <40 lowercase hex>
git-root-parent-count: 0
git-tracked-source-plaintext-files: 0
recovery-required: none
result: repository import complete
```

After a trustworthy source plan, nonzero exits print the last proven terminal
fields before a scrubbed fixed-category diagnostic:

```text
candidate-root: not-created | retained | publication-indeterminate | published
vault-publication: not-published | indeterminate | published
git-repository: not-created | staging-incomplete | staging-audited | published
recovery-required: prepublication-cleanup | publication-reconcile | none
```

An early failure prints no source path or attacker-controlled Git text. There
is no Git-finalization output state because Git is part of the single candidate
before publication.

## Acceptance matrix

| Case | Required result |
|---|---|
| Clean SHA-1 repository with 323 tracked stage-zero `100644` files | Dry-run and import bind identical `HEAD`, index, namespace, and per-file proofs; counts are exactly 323 and no file is skipped. |
| Exact 25,074,521-byte tracked image | Classified as an opaque asset, encrypted, independently reopened, and recovered byte-for-byte; no plaintext image exists in staging, target, Git objects, output, or temporary files. |
| Markdown plus supported assets | Every tracked file appears exactly once as authenticated `*.md.enc` or `*.asset.enc`; relative structure is retained and physical names do not collide. |
| Staged change, unmerged stage, index drift, or stable/concurrent worktree modification | Rejected by semantic maps, raw object id, repeated digest/byte proof, or checkpoint; stable dirty bytes are never accepted. |
| Untracked, ignored, or empty-directory entry | Rejected after a complete bounded plan; no ignore rule silently drops it. |
| Root `.git` | Exact identity is skipped by content traversal; the control verifier audits only frozen local endpoints; no source Git metadata enters the target. |
| Nested `.git`, linked worktree, link/reparse point, hard link, mount crossing, FIFO/device/socket | Fail closed with source unchanged and final absent. |
| `100755`, `120000`, `160000`, sparse/split index, SHA-256 source repository | Rejected as outside v1. |
| LFS selection or canonical/malformed pointer; custom filter, encoding, ident, CRLF transform, textconv, external diff, fsmonitor, hook, pager, or credential sentinel | Unsupported selection or raw-OID mismatch fails; no filter, sentinel, transport, or lazy fetch executes. |
| Promisor/partial clone, missing object, HTTP/object alternate | Fails offline without prompt, credential, transport, or fetch. |
| Invalid UTF-8/path, Unicode/case collision, device name, or any resource limit | Dry plan fails before password/KDF work or writes. |
| Existing/nested/aliased destination or changed destination parent | No-replace/overlap check fails; existing bytes remain unchanged. |
| Missing/tampered ciphertext, unexpected staging entry, candidate `.git` entry, object, ref, config, or source drift | Candidate audit or checkpoint fails; final remains absent and staging evidence is retained. |
| Failure or kill during vault creation, any encryption, metadata write, Git init/config/hash/index/tree/commit/ref write, independent unlock, physical/object audit, or recursive durability barrier | Final remains absent. No operation continues at the final path. |
| Failure or kill immediately before the whole-root directory move | Final remains absent and exact staging is retained. |
| Directory move error before effect | Generic publisher proves staging present/final absent; final remains absent. |
| Error or kill after directory move effect, before parent sync, re-audit, or marker cleanup | Final is the whole audited candidate and therefore already includes complete `.git`; result is published only after identity/seal reconciliation, otherwise publication-indeterminate. |
| Injected lookalike staging/marker/final entry | Name alone grants no cleanup or overwrite authority; foreign state is preserved and fails closed. |
| Retry after generic publication ambiguity | Same command may reconcile only the exact whole candidate; it does not run a Git finalizer or mutate an unrelated existing destination. |
| Successful target Git repository | Exactly one `refs/heads/main` root commit with zero parents; exact encrypted tree/index/worktree; no source refs, remotes, alternates, objects, parents, or plaintext file object. |
| Source preservation | Tracked worktree files and root Git semantic/control manifests remain unchanged in dry-run, success, and every injected failure. |
| Linux and Windows native runs | Same logical classification, counts, canonical semantic source manifest, rejection decisions, and decrypted target bytes for the same portable source bytes; random vault ids, nonces, ciphertext, physical identities, timestamps, tree ids, and root commit ids may differ. |

Repository import is not release-approved until every row passes through the
real CLI, fault injection at every construction/durability/publication
boundary, native Linux and Windows filesystems, and residue scanning over
source, staging, final target, Git objects, process output, editor state, and
temporary directories.
