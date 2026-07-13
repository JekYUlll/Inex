# Repository Import v1

Status: **implementation contract frozen for the first repository-import
slice**. This contract does not change the existing
[`inex import`](import-v1.md) plaintext-tree command.

The source, candidate, and normal whole-root publication path are implemented
by the current Linux engineering preview. The cross-process publication
recovery requirements below are an explicit **GA target**, not a description of
the current publisher: the preview still uses a legacy random 16-byte marker
whose ownership proof depends on the creating process's held handles and
in-memory candidate seal. Until generic publication marker v2 and its fault
matrix are implemented, a post-publication nonzero result must be preserved for
manual audit and must not be treated as safe-to-rerun recovery evidence.

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
user-selectable import-into-existing mode. The GA exact-v2 reconciliation
guard below is automatic recovery, not an import mode. The command always
selects the commit to which the source repository's `HEAD` resolves during
planning.

The command:

- requires the source to be the top level of one ordinary local Git worktree;
- requires a completely absent destination whose parent already exists on a
  supported local filesystem for ordinary creation; the GA existing-only
  reconciliation guard described below is the sole existing-destination path;
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

There is no repository-import finalizer, mutable vault-side import journal,
owner record, external Git staging directory, or post-publication Git
construction. Before the single directory publication the final path is
absent. After that publication the final path is the already complete, audited
vault and Git repository. For GA, the sole persistent recovery metadata is the
immutable generic directory-publication marker v2 described below. It contains
no interpreted Git or repository state and never authorizes building,
repairing, or otherwise modifying Git at the final path.

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
  intent-to-add, assume-unchanged, skip-worktree, split-index, and every other
  mode or ordinary/extended entry flag fail. The raw index `FSMN` extension is
  forbidden, so no bitmap-derived `CE_FSMONITOR_VALID` state is accepted.
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

Any `.git/objects/pack/*.promisor` marker is rejected. The exact optional cache
extension allowlist is `TREE`, `REUC`, `UNTR`, `EOIE`, and `IEOT`; those
extensions may be accepted but are never copied. `FSMN` is forbidden because
its bitmap, rather than an ordinary per-entry flags field, supplies
`CE_FSMONITOR_VALID`. Required lowercase `link` or `sdir`, and every unknown
required index extension, fail. Semantic `-v` and `-f` probes still require
exact uppercase `H` for every path.

Split and sparse index rejection is explicit: local `core.splitIndex` and
`index.sparse` resolve false, `git rev-parse --shared-index-path` is empty,
exact `.git/sharedindex.*` and `.git/info/sparse-checkout` are absent, and
strict index parsing rejects sparse-directory mode, split/sparse extensions,
and `FSMN`.

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
No repository-import-specific intent, owner, mutable journal, candidate
manifest, or completion receipt is stored under `.vault-local` or beside the
staging root. The only persistent claim is the generic immutable publication
marker owned by the directory-publication primitive. Its caller domain and
opaque candidate seal do not expose or encode source commits, Git construction
steps, or repository-specific recovery phases.

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

### GA generic publication marker v2

GA cross-process recovery requires one fixed, canonical binary marker v2. The
current random 16-byte marker is legacy and does not satisfy this requirement.
All scalar version, scheme, total, length, and identity-volume integers use
unsigned big-endian encoding. The 16-byte normalized identity payload retains
the explicit platform byte semantics below. There is no alignment padding, and
the byte layout is exactly:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `INEXPUB\0` (`49 4e 45 58 50 55 42 00`) |
| 8 | 2 | version, exactly `2` |
| 10 | 2 | identity scheme: `1` = Linux dev/inode v1, `2` = Windows modern volume/FileId128 v1, `3` = Windows legacy volume/file-index v1 |
| 12 | 4 | total marker byte length, including the final digest |
| 16 | 16 | CSPRNG publication id; the all-zero value is forbidden |
| 32 | 24 | common-parent directory identity |
| 56 | 24 | staging-root directory identity; after the move this must equal the destination-root identity |
| 80 | 24 | marker-parent directory identity; repository import binds this to `.vault-local` |
| 104 | 24 | single-link regular marker-file identity |
| 128 | 2 | caller-domain byte length, `1..=64` |
| 130 | 2 | staging child-name byte length, `1..=255` |
| 132 | 2 | destination child-name byte length, `1..=255` |
| 134 | 2 | caller-opaque candidate-seal byte length, `1..=256` |
| 136 | variable | domain bytes, staging-name bytes, destination-name bytes, then candidate-seal bytes, with no separators or padding |
| final 32 | 32 | SHA-256 of every preceding byte from offset 0 through the final candidate-seal byte; the digest does not cover itself |

`total_length` must equal both the actual regular-file length and this exact
sum:

```text
168 + domain_length + staging_name_length + destination_name_length + seal_length
```

The generic minimum is 172 bytes and the maximum is 998 bytes;
parsers additionally enforce a 1,024-byte read/allocation ceiling before
retaining the file. Short input, a larger file, arithmetic overflow, a length
outside its field limit, a non-exact total, or trailing bytes fails before any
recovery action.

Each 24-byte identity is the canonical wire projection of the corresponding
`FilesystemDirectoryIdentity` or `FilesystemFileIdentity`: eight bytes of
`volume` in big-endian order followed by the exact 16-byte normalized
`identifier`. The scheme named at offset 10 is global to the claim: all four
marker identities and every identity emitted in candidate-seal sections 1, 2,
8, and 9 must use that one scheme. Every covered filesystem object must be
encodable under it; any mixed scheme, including modern/legacy Windows mixing
between the marker and seal, fails marker creation or recovery.

Under scheme 1, `volume` is Linux `st_dev`; identifier bytes 0 through 7 are
`st_ino.to_le_bytes()`, bytes 8 through 14 are zero, and byte 15 is `0x01` for
each directory field or `0x02` for the marker regular file, matching the
current core identity semantics. Every directory or regular-file identity in
the seal uses the same discriminator rule. Under scheme 2, `volume` is the Windows
64-bit volume serial and a nonzero modern `FILE_ID_128` is copied byte-for-byte
into `identifier`; every covered object must provide a modern nonzero
FileId128. Under scheme 3, `volume` is the zero-extended 32-bit legacy Windows
volume serial, identifier bytes 0 through 7 are the legacy file index in
little-endian order, bytes 8 through 14 are zero, and byte 15 is the directory
or regular-file discriminator used by the current core fallback; every covered
object must use that fallback. The field position does not waive a fresh no-follow
type, single-link, reparse/ADS, or same-filesystem check. A change in identity
availability or any non-exact reproduction fails closed rather than switching
schemes.

The domain is lowercase ASCII matching `[a-z0-9][a-z0-9.-]*`; its last byte is
alphanumeric, consecutive dots and leading/trailing dots are forbidden, and
repository import requires the exact 25 bytes
`inex.repository-import.v1`. Both child names are exact NFC UTF-8 bytes accepted
by the existing portable direct-component profile: they contain no NUL,
separator, `.`/`..`, control, reserved device spelling, or trailing dot/space.
The stored bytes, not a case-insensitive comparison, must equal the normalized
command child names; physical identities independently bind the objects on
case-insensitive filesystems. The staging and destination names must be
different both byte-for-byte and under the existing portable case fold.
Repository staging is exactly `.inex-import-staging-` followed by 32 lowercase
ASCII hexadecimal digits. The repository directory-publisher reserved
direct-child prefix set v1 is exactly `{ ".inex-import-staging-" }`; a
destination whose portable-casefolded name starts with that prefix is invalid.
The Inex marker-parent publisher treats the nonempty candidate seal as opaque
and compares it exactly in constant time after the repository caller recomputes
it over the whole candidate under the identity-bound marker exclusion in the
supplied domain/publication-id context.

Unknown versions or identity schemes, noncanonical domain/name bytes,
truncation, and any digest mismatch fail closed. The final SHA-256 detects torn
or corrupted encoding; without a caller-held secret it is not a MAC and does
not authenticate against a same-OS-user attacker that can rewrite both target
and marker.

#### Repository candidate seal v1

For the exact domain `inex.repository-import.v1`, the marker's opaque seal is
exactly the 32-byte SHA-256 digest of the repository-candidate-seal-v1 stream
below; `seal_length` at marker offset 134 must therefore be exactly 32 for this
domain. The stream is hashed incrementally and is not a stored manifest or an
allocation proportional to target bodies. All scalar integers use unsigned
big-endian encoding, identities use the marker's one identity scheme, SHA-1
object ids are decoded to their raw 20 bytes, and paths are the same canonical
NFC UTF-8 slash paths used by the target audit.

The stream begins with these bytes in order:

```text
8 bytes   "INEXCS1\0" (49 4e 45 58 43 53 31 00)
u16       version = 1
u16       identity_scheme = the marker scheme
u16       domain_length = 25
25 bytes  "inex.repository-import.v1"
16 bytes  publication_id = the exact marker id
```

It then contains sections 1 through 9 exactly once in ascending tag order.
Each section is `u8 tag || u32 record_count`; each record is
`u32 record_length || record_payload`. Record lengths cover only their payload,
there is no padding, records are sorted by canonical path bytes unless another
key is stated, and duplicates are invalid. The stream ends with the exact five
bytes `ff 00 00 00 00` and no other bytes.

1. **Full physical manifest (`tag=1`).** One record for the root and every
   recursively retained directory and regular file in the target, including
   the complete worktree, `.git`, `.vault-local`, and `mutation.lock`. The sole
   exclusion is the entry at exact path
   `.vault-local/import-publish-marker-v2` only after a no-follow open proves
   that entry has the exact marker-file identity currently held by this
   publisher or guard. Pathname equality alone never excludes an entry; a
   missing, replaced, aliased, or identity-mismatched marker fails the
   marker-aware audit. No legacy, staging, recovery, or other entry is
   excluded. Payload is
   `u16 path_length || path || u8 kind || identity[24] || u64 size ||
   sha256[32]`, where root has an empty path, kind 1 is directory, kind 2 is
   single-link regular file, directories use size zero and 32 zero digest
   bytes, and files use exact length and SHA-256 of all bytes.
2. **Versioned worktree allowlist (`tag=2`).** One record for every exact
   tracked ciphertext/metadata file and no untracked worktree file. Payload is
   `u16 path_length || path || u8 class || u32 mode || identity[24] ||
   u64 size || sha256[32] || blob_oid[20]`. Class 1 is exact managed metadata
   (`vault.json`, `.gitattributes`, or `.gitignore`), class 2 is a canonical
   Markdown envelope, and class 3 is a canonical asset envelope. Mode is
   exactly numeric `0o100644` (`0x000081a4` in the four-byte field). The physical manifest must contain exactly these
   worktree files plus their ancestor directories, `.git`, and `.vault-local`.
3. **HEAD and refs (`tag=3`, exactly one record).** Payload is
   `u8 object_format=1 || u16 head_length=15 || "refs/heads/main" ||
   u32 ref_count=1 || u16 ref_name_length=15 || "refs/heads/main" ||
   commit_oid[20] || u32 reflog_count=0`. No other symbolic ref, ref, tag,
   remote, replace ref, or reflog is permitted. `object_format=1` means SHA-1;
   no other object format is valid in v1.
4. **Index semantic manifest (`tag=4`).** One record per allowlisted worktree
   file, sorted by path. Payload is
   `u16 path_length || path || u32 mode=0x000081a4 || u8 stage=0 ||
   u32 flags=0 || blob_oid[20]`. The original index entry's `CE_NAMEMASK`
   pathname-length field must equal the retained canonical path byte length
   exactly. Stage is decoded separately from `CE_STAGEMASK` and serialized as
   the required zero byte. `flags` is the normalized ordinary/extended option
   value remaining after stripping only `CE_NAMEMASK` and `CE_STAGEMASK`, and
   every remaining bit must be zero. An extended flag word or `CE_EXTENDED`,
   assume-unchanged, skip-worktree, intent-to-add, sparse, split, unmerged, or
   any other ordinary/extended option is rejected rather than silently
   normalized. `CE_FSMONITOR_VALID` is not treated as an entry-flags bit: v1
   rejects the raw index `FSMN` extension and therefore never accepts its
   per-entry validity bitmap. The separately hashed physical index file and
   this semantic map must both match.
5. **Tree semantic manifest (`tag=5`).** One record for the root tree and every
   derived subtree, sorted by directory path with the root empty path first.
   Payload is `u16 path_length || path || tree_oid[20] || u64 raw_size ||
   raw_sha256[32]`. Before serialization the auditor independently constructs
   the exact raw tree body from the allowlist/index, verifies its typed SHA-1
   oid, and hashes those raw bytes.
6. **Root commit semantic manifest (`tag=6`, exactly one record).** Payload is
   `commit_oid[20] || tree_oid[20] || u32 parent_count=0 || u64 raw_size ||
   raw_sha256[32]`. Before serialization the raw commit must parse to the frozen
   import author, committer, UTC timestamp form, message, zero parents, and the
   exact root tree, and its typed SHA-1 oid must match.
7. **Complete object manifest (`tag=7`).** One record for every reachable or
   unreachable object, sorted by raw oid. Payload is
   `oid[20] || u8 type || u64 raw_size || raw_sha256[32]`, with type 1 blob,
   2 tree, and 3 commit. Each raw object body is read and typed-rehashed; the
   set must equal exactly the worktree blobs, section-5 trees, and section-6
   commit, with nothing additional.
8. **Git control manifest (`tag=8`).** One record for every `.git` descendant,
   sorted by path relative to `.git`. Payload is
   `u16 path_length || path || u8 role || u8 kind || identity[24] ||
   u64 size || sha256[32]`. The role/path/kind allowlist is exact:

   - role 1 is path `HEAD`, kind 2 regular file;
   - role 2 is path `config`, kind 2 regular file;
   - role 3 is path `index`, kind 2 regular file;
   - role 4 is path `refs/heads/main`, kind 2 regular file;
   - role 5 is either path `objects/<xx>`, kind 1 directory, where `<xx>` is
     exactly two lowercase hexadecimal bytes and at least one section-7 oid
     has that prefix, or path `objects/<xx>/<rest>`, kind 2 regular file,
     where `<rest>` is exactly 38 lowercase hexadecimal bytes. Each role-5
     regular file maps one-to-one to exactly one section-7 object and every
     section-7 object has exactly that one loose-object file;
   - role 6 is kind 1 directory and its path is exactly one of `objects`,
     `objects/info`, `objects/pack`, `refs`, `refs/heads`, or `refs/tags`; and
   - role 7 is exact path `inex-empty-hooks`, kind 1 directory, and is empty.

   All other role/path/kind combinations are rejected. Kind and
   file/directory size/digest rules equal section 1. The exact control
   allowlist and canonical config semantics are validated before
   serialization; packs and every unlisted control entry are forbidden.
9. **Private baseline (`tag=9`, exactly one record).** Payload is
   `u16 path_length || "mutation.lock" || u8 kind=2 || identity[24] ||
   u64 size=0 || sha256(empty)[32]`, where `sha256(empty)` is exact hex
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
   This repeats the lock proof deliberately:
   the physical full-tree seal and the recovery authorization both bind the
   exact pre-existing mutation-lock identity.

Sections 1, 7, and 8 each independently accept at most 1,000,000 records;
section 1's count includes its root record. Sections 2 and 4 each accept at
most 100,003 records (100,000 imported entries plus the three managed root
files), and the section-5 record count cannot exceed the number of directory
records in section 1. Depth is at most 128. A section-1 physical path is at
most 1,034 UTF-8 bytes: the 1,024-byte logical-path maximum plus the exact
10-byte `.asset.enc` suffix. Every semantic path in sections 2, 4, 5, 8, and 9
is separately limited to 1,024 UTF-8 bytes.

The path-bearing sections are exactly 1, 2, 4, 5, 8, and 9. For each of those
sections independently, the checked sum of its `path_length` values is at most
256 MiB; the section-3 HEAD/ref name bytes are not path-budget input. The
auditor never retains more than 256 MiB of canonical path bytes concurrently.
Every target regular file and every raw Git object is at most 68 MiB
(`71,303,168` bytes) and is hashed through a bounded streaming buffer. Counts,
length sums, record lengths, and path-byte sums use checked arithmetic.
Exceeding any limit fails before marker cleanup and does not weaken the
manifest.

A fresh target audit first opens the exact canonical v2 marker without
following links and holds its proved file identity for the entire traversal.
It can then reconstruct this stream using only ciphertext, filesystem
metadata/identities, and read-only local Git object/control reads. Both the
initial publisher and a fresh guard exclude the marker from section 1 only by
matching that held identity at the exact marker path; neither audit ever skips
an entry merely because its pathname resembles or equals the marker pathname.
It does not use a process-local `TargetRepository`, source Git replanning,
source plaintext, a password, or decryption. The marker domain and publication
id are explicit prefix inputs, so a changed id with an unchanged seal fails.
Because both the marker digest and this seal are unkeyed, a noncooperating
same-UID attacker able to rewrite the whole target and marker can recompute
both; candidate seal v1 is a crash-consistency and accidental-confusion proof,
not a MAC or authorization boundary against that attacker.

Marker construction and sealing occur in this exact order:

1. complete, audit, and make durable the marker-free candidate; this audit
   requires the v2 marker path to be absent and does not reserve a pathname
   exclusion, and it seals the exact pre-existing zero-byte
   `.vault-local/mutation.lock` identity as the private baseline;
2. generate the nonzero publication id;
3. use the open-existing/no-create/no-recovery API to open that exact lock
   without following links, prove its held identity equals the already sealed
   baseline identity, and acquire its platform lock with a nonblocking try-lock
   or bounded deadline; while holding it, re-prove the complete marker-free
   baseline before marker creation;
4. create the exact v2 marker with create-new semantics as an empty regular
   file, retain its no-follow handle, and capture its file identity;
5. capture and prove the common-parent, candidate-root, marker-parent, and held
   marker identities, then prove that those four identities and every identity
   that will be emitted by seal sections 1, 2, 8, and 9 are representable by
   one uniform identity scheme;
6. stream candidate seal v1 while excluding only the exact marker-path entry
   whose freshly opened no-follow identity equals the currently held marker
   identity;
7. serialize and write the canonical marker bytes, synchronize the marker,
   marker-parent directory, and staging root; and
8. recompute the seal using the same identity-bound exclusion rule, perform
   the marker-aware audit, and only then attempt the whole-root move.

The initial publisher continuously holds the same acquired mutation lock from
step 3 across marker creation and sealing, the whole-root move, post-move
audit, destination/common-parent synchronization, marker unlink,
marker-parent synchronization, clean audit, and emission of the terminal
result. It releases the lock only after that result has been emitted. A
missing, replaced, malformed, busy, or deadline-expired lock fails closed
before marker creation; this path never creates the lock, invokes normal vault
recovery, or replays private recovery state. The held-lock API must preserve
the ability to rename the enclosing staging root while the handle remains open
(including delete/rename sharing on Windows); a platform that cannot provide
that combination fails the publication platform gate before construction.

This ordering is not circular. The marker-free physical seal/private-baseline
audit has already bound the section-9 lock identity before lock acquisition;
acquiring the platform lock changes neither the lock file's identity nor its
zero-byte body. Candidate-seal section 9 later serializes and re-proves that
same held identity after marker identity is available. Any lock-identity drift,
scheme mismatch, pathname-only exclusion, marker absence/replacement, seal
mismatch, write/synchronization failure, or audit failure retains staging
evidence and grants no publication authority.

Repository import fixes the legacy marker path as
`.vault-local/import-publish-marker-v1` and the v2 path as
`.vault-local/import-publish-marker-v2`. Within `.vault-local`, the
portable-casefolded basename prefix `import-publish-marker-` is reserved; its
recognized basename set is exactly `{ "import-publish-marker-v1",
"import-publish-marker-v2" }`. The clean private baseline is exactly one
single-link, non-reparse, zero-byte regular file named `mutation.lock`, with
SHA-256 of the empty byte string and its physical file identity. The
marker-aware private inventory is exactly that same bound lock plus the one
canonical v2 marker. The candidate-seal physical manifest excludes exactly the
v2 marker entry whose identity equals the currently held marker identity and
excludes nothing by pathname alone. A legacy marker, legacy and v2
together, a portable-case alias, or any other entry under the reserved marker
prefix is a conflict; it is never silently treated as baseline state.

The reserved publication-marker namespace is also a cooperative mutation
barrier. Every ordinary
vault mutation entrypoint must inspect the reserved private namespace before
any create/recovery side effect and recheck it after acquiring its ordinary
mutation lock but before mutation or recovery. If any entry has the
portable-casefolded reserved `import-publish-marker-` prefix, including exact
legacy/v2 names, malformed bytes, aliases, and unknown versions, the ordinary
path fails closed without creating, recovering, replaying, or changing vault
state. An exact canonical v2 marker directs the caller to repository-import
`repository-reconcile`; every other reserved conflict directs the caller to
manual audit. The ordinary path must not consume or remove any marker.
The initial publisher's pre-marker lock acquisition closes the race with this
check: either an ordinary cooperative writer already owns the lock and marker
creation fails busy, or the publisher owns it and that writer cannot enter the
move-to-audit-to-unlink window. Once the canonical marker is durable and the
whole-root move has exposed the destination, a publisher crash before verified
marker unlink releases the advisory/platform lock but does not remove that
marker; subsequent ordinary mutation is therefore routed away from normal
recovery and into repository reconciliation. Before the move, final remains
absent and any marker is only staging evidence that a fresh process cannot
adopt or reconcile. A crash after marker unlink remains the separately
documented acknowledgement gap.

The identities and child-name encodings are platform-scoped namespace proofs,
not portable repository metadata. The wire proves only exact equality of the
recorded identity scheme and encoded identities on a supported local
filesystem. Operating on the same mount instance is an external operational
precondition, not a fact encoded or independently verifiable by marker v2. A
copy, restore, volume migration, unsupported identity scheme, or remount that
changes any encoded identity fails closed rather than falling back to seal-only
recovery. A remount that preserves every encoded identity is indistinguishable
to this guard and must not be claimed as detected or rejected. The opaque
candidate seal complements these identities and does not replace them: the
seal proves audited content while identities prove continuity of the observed
namespace objects.

The Inex marker-parent publisher treats the domain and candidate seal as opaque bytes. It
contains no Git command, object id, source revision, repository phase, or
mutable recovery state. The caller selects the exact domain and supplies a
read-only auditor that recomputes the candidate seal. Thus marker v2 is an
immutable generic publication claim, not a repository-import journal.

The publication id is a claim nonce, not a self-authenticating expected value.
The live publisher that created it, or a future external completion receipt,
may supply an expected id and reject a different one directly. A fresh
existing-only guard has no such external expected id: it reads the sole id from
the canonical marker and passes that exact value and domain into the caller's
seal audit. It can reject an id changed without consistently changing the
covered marker digest and caller seal, and it can reject multiple or mixed
claims, but it cannot call an otherwise canonical, internally consistent
alternative id "wrong" based on the id alone. Negative tests therefore mutate
the id while retaining an expected live id or without recomputing its dependent
seal/digest; they must not claim that a self-contained unkeyed marker supplies
an external publication-id oracle.

### GA publication state machine

| State | Required physical proof | Permitted forward action |
|---|---|---|
| `Absent` | Destination is absent and no active claim is being reconciled. | Start ordinary creation in a new staging root. |
| `StagingIncomplete` | A staging root exists but does not have a fully synchronized canonical v2 marker and matching marker-aware candidate audit. | The same live creator may continue bounded construction; after interruption a fresh process retains the evidence and does not resume, publish, or delete it by name. |
| `StagingAudited` | Destination is absent; the exact complete staging root and canonical v2 marker are durable, the caller seal matches, and this actor continuously holds the exact baseline mutation lock. | Perform the single verified no-replace whole-root move while retaining the lock. |
| `PublishedWithMarker` | Recorded staging name is absent; destination, root, marker-parent directory, marker, domain, names, identities, and caller seal all match; this actor still holds the exact mutation lock, but common-parent durability has not yet been confirmed. | Synchronize the destination and common parent while retaining the lock. |
| `PublicationDurableWithMarker` | `PublishedWithMarker` proofs and lock ownership still hold and destination/common-parent synchronization succeeded. | Remove only the exact marker currently held by this process, then synchronize its parent without releasing the lock. |
| `PostUnlinkAbsentIndeterminate` | This same live process retains the mutation lock, publication claim, expected seal, and previously held marker identity; the exact path formerly bound to that identity is absent, but marker-parent synchronization or the clean audit is indeterminate. | The live process may retry only the remaining synchronization and clean audit while retaining those proofs and the lock; it may not recreate the marker or report success. |
| `PublishedClean` | The exact path formerly bound to the marker identity previously held by this live process is absent, `.vault-local` synchronization succeeded, the clean candidate audit still matches, and the exact mutation lock remains held. | Emit the terminal success result, then release the lock. |

Both names, neither provable name, a foreign or additional entry, a malformed
or legacy marker, an identity/domain/name/seal mismatch, or any indeterminate
namespace observation before unlink is a conflict state. Conflict state is
preserved and authorizes no mutation. The narrowly defined live
`PostUnlinkAbsentIndeterminate` state is not inferable after restart and does
not authorize success.

`PublishedClean` is a transaction state, not evidence that a fresh process can
infer from an arbitrary marker-free destination. The live publisher still has
the publication claim, held identities, and expected seal when it crosses that
transition. Once those ephemeral proofs and the marker are both gone, a later
process cannot distinguish this publication from an unrelated but structurally
or semantically equivalent existing vault.

### Publication and cleanup order

The marker-bound directory publisher moves the whole staging root without
replacement. Return values are reconciled from names, identities, the exact
marker, and the caller seal:

- exact staging present and final absent is not published;
- staging absent and final equal to the bound complete candidate is published;
- both names, neither name, a foreign final, an identity mismatch, or an
  indeterminate observation is preserved and fails closed.

After the move, the publisher reopens the final root through held, no-follow
parents and re-proves the whole candidate identity, vault allowlist, `.git`
inventory, root commit, exact marker, and caller seal. It then synchronizes the
destination directory and common parent. A failed or unconfirmed common-parent
sync leaves the marker in place and returns `publication-reconcile`; marker
cleanup must never precede confirmation that the whole-root namespace move is
durable.

The publisher or fresh reconciliation guard holds the exact pre-existing
mutation lock continuously throughout every post-move proof and cleanup step.
Because every cooperative vault writer requires that same lock and ordinary
mutation also refuses exact v2, no cooperative writer can change the published
target between the move, audit, durability barriers, marker unlink, and clean
audit. The lock complements the identity/seal checks; it does not weaken the
separately documented noncooperating same-UID race boundary.

Only `PublicationDurableWithMarker` may remove the marker. "Held marker" always
means a handle opened without following links and retained by this current
publisher or fresh guard; no handle or process-local identity is presumed to
survive a process restart. Removal repeats the path/type/single-link/identity
check immediately before its pathname unlink and classifies removed,
not-removed, replacement, and indeterminate error post-states. Under the
cooperative lock protocol this prevents known replacements from being selected
for cleanup. Exact removal is followed by synchronization of `.vault-local`
and a clean final audit; implementations may additionally resynchronize the
destination and common parent, but that does not replace the required
pre-delete common-parent barrier. If the same live process proves the former
marker path absent but cannot prove the required synchronization or clean
audit, it enters `PostUnlinkAbsentIndeterminate`, not `PublishedClean`, and may
retry only those remaining barriers while it retains the claim and previously
held identity. A cleanup or synchronization failure is non-success even though
the complete repository may already be live.

The current Linux and Windows unlink APIs are pathname operations, not a kernel
compare-and-exchange between a previously opened file identity and the final
unlink. A noncooperating same-UID attacker can race after the last check and
replace the pathname before unlink. Consequently, "does not delete a
replacement" is guaranteed only for cooperative Inex writers plus the stated
final checks and error post-state reconciliation; it is not an absolute hostile
same-UID claim. Closing that check-to-unlink race requires a suitable
descriptor-relative conditional kernel primitive or a stronger OS isolation
boundary and remains a separate GA security gate.

## Failure and retry semantics

Before the single whole-root move takes effect, every ordinary error, process
kill, or retained partial staging state leaves the final destination absent.
The source is unchanged. A complete or partial hidden staging root is retained
as evidence. Only its still-live creator holding the original staging proof may
perform exact identity-bound prepublication cleanup. A fresh invocation has no
cleanup, resume, publication, or adoption authority over an interrupted
staging root, even when its name and embedded marker look canonical. Name
resemblance alone never authorizes deletion.

Once the move takes effect, the final destination necessarily contains the
already complete vault and `.git`; there is no vault-without-Git or partial
final-Git state. A kill before parent sync or marker cleanup may make the CLI
result indeterminate, but it cannot expose a partially constructed repository.

For GA, a later `import-repository` invocation checks an existing-only
reconciliation guard before ordinary existing-destination rejection. The guard
uses a new open-existing/no-create/no-recovery lock API; it must not call a
normal vault guard whose acquisition can create `mutation.lock`, recover
private ciphertext staging, or replay `pending-rebind-v1`. It opens the exact
pre-existing zero-byte `mutation.lock` without following links, proves its
single-link identity and empty digest, and attempts the existing platform lock
with a nonblocking try-lock or an explicitly bounded deadline; it never waits
indefinitely. A missing, replaced, malformed, busy, or deadline-expired lock
fails with zero persistent mutation. Exact `pending-rebind-v1`, any basename
with portable-casefolded prefix `.inex-ciphertext-stage-`,
`.inex-rebind-stage-`, or
`.inex-retired-ciphertext-`, and every other private entry beyond the exact lock
plus v2 marker also fail with zero mutation before the candidate seal is
accepted. The guard does not classify, recover, or delete those entries. The
private baseline and candidate seal bind the exact lock identity before and
after the audit. Pre-lock marker inspection is routing evidence only; after the
lock is acquired the guard freshly reopens and revalidates parent, destination,
marker parent, marker, reserved namespace, and all seal inputs before any sync
or cleanup. It retains that same lock through destination/common-parent sync,
marker unlink, marker-parent sync, clean audit, terminal-result emission, and
only then releases it.

The guard does not create a staging root, vault, Git repository, missing lock,
or other product state and never resumes construction or core recovery. Its
only permitted content/namespace mutation is verified removal of the exact
currently held v2 marker after the destination and common parent are durable,
followed by the required directory synchronization.

The guard advances only when all of the following hold: the marker is canonical
v2 for the expected caller domain and destination child; the recorded staging
child is absent; parent, destination root, `.vault-local`, and marker identities
exactly reproduce their recorded identity scheme and bytes; no conflicting
reserved entry exists; and the full caller read-only audit recomputes the
recorded opaque candidate seal. It may synchronize the exact destination and
common parent, retire the
exact marker, perform the clean audit, and report a reconciled publication. Any
mismatch preserves all state and fails closed. It never runs a Git finalizer or
mutates an unrelated existing destination.

The same-command fresh path is ordered as follows:

1. parse the two positional paths and command options, normalize absolute
   source/destination spellings and portable child names, and prove by canonical
   ancestry and available directory identities that source and destination do
   not overlap;
2. if destination is absent, continue the ordinary source-repository planning
   path; if it exists, inspect only the reserved marker/private namespace and
   dispatch an exact v2 candidate to the existing-only guard before the
   ordinary `DestinationExists` error;
3. acquire the exact pre-existing lock through the no-create/no-recovery API,
   parse and bind marker v2, and perform the complete read-only physical, Git,
   private-baseline, and candidate-seal-v1 audit;
4. derive all reconciliation counts and the existing root commit only from
   that target audit, establish destination/common-parent durability, and then
   perform the currently held marker removal, marker-parent sync, and clean
   audit; and
5. emit the independent repository-reconciliation result described below.

Steps 1 through 5 do not discover or replan the source Git repository, read a
source body, prompt for a password, calibrate or run a KDF, unlock the vault,
create a candidate, or construct Git. A marker-free, legacy, malformed, or
conflicting existing target does not fall through to ordinary creation; it
remains a hard existing-destination or reconciliation-conflict error with zero
mutation.

A fresh process that observes the marker path absent has neither the prior
marker handle nor its process-local claim, so it cannot infer
`PostUnlinkAbsentIndeterminate` or `PublishedClean`; marker absence is a hard
unattributed-existing-destination error with zero mutation. A fresh process
must not accept a marker-free existing destination as an
idempotent success, even when the vault is valid and decrypts to the same source
snapshot. The removed marker carried the only persistent publication id,
expected candidate seal, and namespace ownership binding; recomputing a seal
from the target supplies no expected value and proves equivalence rather than
provenance. Such a target is an unattributed existing destination and remains a
hard error. Consequently, deletion of the marker followed by process death
before the success acknowledgement is an explicit acknowledgement gap. Closing
that final gap would require a durable generic completion receipt or an
externally retained publication id/seal and is outside this no-receipt v1
design.

An exact legacy 16-byte marker is recognized only as
`legacy-publication-marker-unverifiable`. A fresh process does not reinterpret
it as v2, infer ownership from its name or length, upgrade it in place, or
delete it after a structural target audit. It preserves the marker and target
for explicit manual investigation. A legacy and v2 marker together, or any
unknown marker version, is a conflict. Only the original still-live legacy
publisher holding the marker handle and its in-memory candidate proof can
finish its old same-process cleanup path.

The current Linux engineering preview has neither marker v2 nor this
existing-only guard. Its `publication-reconcile` terminal state therefore
means preserve the target, staging siblings, and marker and do not blindly
rerun the command or remove the marker. The preview is not GA evidence for the
cross-process clauses above.

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

The GA existing-only path has a separate output shape and must not reuse
creation's `repository-copy`, `committed-*`, `source-revalidated`,
`git-repository: initialized`, or `result: repository import complete` fields.
After the complete target-only audit and successful cleanup it prints, in this
order:

```text
import-mode: repository-reconcile
terminal-operation: repository-reconcile
source-policy: path-disjointness-only
source-git-replanned: no
password-prompted: no
kdf-ran: no
destination-policy: existing-v2-publication-reconcile-only
publication-marker-version: 2
candidate-seal-version: repository-candidate-seal-v1
target-worktree-files: <decimal>
target-encrypted-markdown: <decimal>
target-encrypted-assets: <decimal>
target-git-objects: <decimal>
target-root-commit: <40 lowercase hex>
target-root-parent-count: 0
target-plaintext-file-objects: 0
candidate-physical-audit: passed
candidate-git-object-audit: passed
candidate-root: existing-published
vault-publication: reconciled
git-repository: existing-audited
marker-cleanup: removed
recovery-required: none
result: repository publication reconciled
```

Every count and target oid above is derived from the bounded read-only target
manifests that produce candidate seal v1. No source count is copied from a new
source plan, and no opaque seal or physical identity is printed.

After parameter/path validation reaches an existing destination, every
existing-only nonzero exit prints this independent terminal block before its
scrubbed diagnostic:

```text
import-mode: repository-reconcile
terminal-operation: repository-reconcile
marker-state: absent | legacy-unverifiable | v2-invalid | v2-conflict | v2-exact | post-unlink-absent-indeterminate
candidate-root: existing-unattributed | publication-indeterminate | existing-published
vault-publication: reconcile-not-started | reconcile-conflict | durable-with-marker | indeterminate
git-repository: existing-unaudited | existing-audited
marker-cleanup: not-attempted | retained | indeterminate
recovery-required: publication-reconcile | manual-audit
```

For a fresh process, `marker-state: absent` remains a hard
existing-destination error. `post-unlink-absent-indeterminate` is reportable
only by the same live process that previously held and removed the exact marker;
`legacy-unverifiable`, malformed, busy/missing-lock, pending core recovery, and
all foreign states use `manual-audit` and perform zero mutation. These terminal
fields describe reconciliation of an already existing root and can never be
reported as a newly initialized repository.

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
| `100755`, `120000`, `160000`, sparse/split index, raw `FSMN` index extension, SHA-256 source repository | Rejected as outside v1. `FSMN` is not accepted as an ignorable cache extension; its bitmap-derived `CE_FSMONITOR_VALID` state is never interpreted as an ordinary entry flag. |
| LFS selection or canonical/malformed pointer; custom filter, encoding, ident, CRLF transform, textconv, external diff, fsmonitor, hook, pager, or credential sentinel | Unsupported selection or raw-OID mismatch fails; no filter, sentinel, transport, or lazy fetch executes. |
| Promisor/partial clone, missing object, HTTP/object alternate | Fails offline without prompt, credential, transport, or fetch. |
| Invalid UTF-8/path, Unicode/case collision, device name, or any resource limit | Dry plan fails before password/KDF work or writes. |
| Existing/nested/aliased destination or changed destination parent | Ordinary creation fails before writes. Only the GA existing-only guard may inspect an existing direct-child destination, and it mutates nothing unless an exact v2 claim reaches `PublicationDurableWithMarker`. |
| Missing/tampered ciphertext, unexpected staging entry, candidate `.git` entry, object, ref, config, or source drift | Candidate audit or checkpoint fails; final remains absent and staging evidence is retained. |
| Failure or kill during vault creation, any encryption, metadata write, Git init/config/hash/index/tree/commit/ref write, independent unlock, physical/object audit, or recursive durability barrier | Final remains absent. No operation continues at the final path. |
| Initial publisher mutation-lock ownership | After the marker-free durable audit seals the exact baseline `mutation.lock` identity and before marker creation, the publisher acquires that existing lock with the no-create/no-recovery API and a nonblocking/bounded attempt, then re-proves the marker-free baseline under the held lock. Missing/replaced/busy/deadline state fails before marker creation. The same lock remains held across marker seal, move, post-move audit, destination/common-parent sync, marker unlink, marker-parent sync, clean audit, and terminal-result emission; no cooperative writer can enter that window. Acquisition does not change the already bound section-9 identity or zero-byte body, and native Windows proves that the held handle's delete/rename sharing permits the enclosing-root move. |
| Failure or kill while creating, finalizing, or synchronizing marker v2, or immediately before the whole-root directory move | The marker-free candidate was durable first; the publisher then acquired and held the already identity-bound existing lock without create/recovery, used create-new empty marker, held its identity, proved one scheme for marker plus seal identities, streamed the identity-excluding seal, wrote/synchronized the canonical marker, recomputed/audited, and only then became move-eligible. Any failure leaves final absent; malformed/incomplete marker state is retained only in staging and grants no publication or cleanup authority. A crash releases the OS lock but does not remove a marker not yet unlinked. |
| Directory move error before effect | The Inex marker-parent publisher proves staging present/final absent; final remains absent. |
| Error or `SIGKILL` after directory move effect and before destination/common-parent sync | Final is already the whole candidate and contains complete `.git`; exact v2 recovery reopens the recorded identities, recomputes the caller seal, synchronizes destination and common parent, and leaves the marker present on any failure. |
| Error or `SIGKILL` after common-parent sync and before marker removal | Fresh exact-v2 recovery reaches `PublicationDurableWithMarker`, opens and holds the exact marker in that new process, synchronizes `.vault-local` after removal, and repeats the clean audit. |
| Marker removal returns an error before effect, after effect, after replacement, or with indeterminate state | Exact old marker present is retained; exact absence with indeterminate sync/audit enters live-only `PostUnlinkAbsentIndeterminate` and may advance only while that process still owns the claim and previously held identity. A fresh absent path is instead a hard unattributed-existing error. A replacement observed by the cooperative final check or error post-state is preserved and fails closed. The remaining hostile same-UID check-to-unlink race is reported, not hidden behind an absolute no-replacement-deletion claim. |
| `SIGKILL` after marker removal and before cleanup sync or success acknowledgement | A later marker-free invocation reports an unattributed existing destination and performs no mutation. It does not claim idempotent success; closing this acknowledgement gap requires a separate durable completion receipt. |
| Canonical marker v2 parser | Literal `INEXPUB\0`, big-endian version/scheme/total/lengths, four exact 24-byte identity records, bounded domain/names/seal, exact total-length formula, and trailing SHA-256 coverage are accepted only within the 998-byte format maximum and 1,024-byte allocation ceiling; every offset, limit, canonical encoding, truncation, overflow, digest, and trailing-byte negative fails closed. |
| Repository candidate seal v1 | Independent fresh serialization of all nine `INEXCS1\0` sections produces the exact same 32-byte seal before and after process restart without `TargetRepository`, source Git, source plaintext, password, or decryption. Both initial and fresh audits open and hold the exact marker and exclude its section-1 entry only after identity equality, never by pathname. Mutation of any other physical path/type/identity/size/body, worktree allowlist, lock identity, SHA-1 HEAD/ref, raw index `CE_NAMEMASK` length, separate `CE_STAGEMASK` stage, normalized remaining flags, forbidden `FSMN`, tree/commit/object, exact section-8 role/path/kind control record, private baseline, domain, or publication id changes the seal or fails the audit. Exact golden streams, record/order/count/terminator negatives, independent section-1/7/8 one-million limits (section 1 includes root), section-5 directory bound, section-1 1,034-byte physical paths, 1,024-byte semantic paths, per-section 256 MiB path budgets, 100,003/68 MiB boundaries, and streaming memory limits pass. |
| Marker namespace and private baseline | Clean inventory is exact `.vault-local/mutation.lock`; marker-aware inventory is that same bound lock plus exact `import-publish-marker-v2`. Exact legacy v1, legacy+v2, case aliases, unknown reserved-prefix entries, pending staging/rebind/retired recovery state, missing/replaced/busy lock, and any extra private entry all preserve state and fail with zero mutation. Lock acquisition is nonblocking or bounded and never waits indefinitely. |
| Publication identity schemes | Linux scheme 1, Windows all-modern FileId128 scheme 2, and Windows all-legacy file-index scheme 3 round-trip exact canonical identities. The selected scheme covers all four marker identities and every identity in seal sections 1, 2, 8, and 9; any mixed scheme, availability drift, or encoded identity drift after cross-volume/copy/restore/remount fails closed. Same mount instance is an operational precondition, not a wire proof: an identity-preserving remount is undetectable and is not asserted to fail. |
| Publication child names | Staging is exact `.inex-import-staging-` plus 32 lowercase hex; staging and destination are distinct by bytes and portable case fold; a destination with the reserved staging prefix under portable case fold is rejected before writes. |
| Wrong domain, child name, externally expected publication id, parent/root/marker-parent/marker identity, candidate seal, extra reserved entry, or copied/rebound/lookalike marker/final | Name, validity, or content equivalence alone grants no cleanup authority. All foreign state is preserved and no target/Git/staging/lock is created or repaired. A fresh guard without an external expected id checks id-dependent seal/digest consistency and claim uniqueness, not whether a different internally consistent id is independently "wrong". |
| Identity drift after copy, restore, volume migration, or remount/reboot | If any encoded identity changes, automatic reconciliation fails closed rather than falling back to the opaque seal. The wire checks identity equality only; it cannot detect a remount/reboot that preserves every recorded identity. |
| Fresh retry or ordinary mutation with a reserved publication-marker entry | Parameter normalization and source/destination disjointness run first; target-only reconcile dispatches before ordinary destination-exists, source Git planning, password, KDF, or construction. For a canonical v2 marker, the open-existing/no-create/no-recovery guard binds the existing lock with a nonblocking or bounded attempt, opens and holds the marker before seal traversal, creates nothing, and its sole content/namespace mutation is removal of that exact held marker after parent durability, followed by directory sync. Every ordinary vault mutation refuses any portable-casefolded `import-publish-marker-` entry before create/recovery and again under its lock; exact canonical v2 directs to repository reconcile, while legacy, malformed, alias, or unknown reserved state directs to manual audit. Success and failure use `terminal-operation: repository-reconcile` and target-derived counts, never creation output. |
| Interrupted prepublication staging seen by a fresh process | Even an exact-looking name/marker grants no resume, adoption, publication, or cleanup permission; only the still-live creator holding the original staging proof may clean it. |
| Hostile same-UID check-to-unlink race | Cooperative writers and final/error post-state checks preserve every replacement they observe. Tests and documentation do not claim kernel CAS or absolute no-replacement deletion; this adversarial race remains an explicit GA security gate until a conditional descriptor-relative primitive or stronger isolation exists. |
| Fresh retry with a valid but marker-free target | Existing target is not accepted as this invocation's success, even when it decrypts to the same source snapshot; no mutation occurs. |
| Fresh retry with exact legacy random 16-byte marker, legacy plus v2 marker, or unknown marker version | Classified as legacy-unverifiable or conflict, retained byte-for-byte, and never upgraded or deleted automatically. Only the original still-live legacy publisher may use its held in-memory proof. |
| Current Linux engineering preview | Legacy 16-byte publication and no existing-only guard are reported honestly as non-GA; `publication-reconcile` evidence is preserved and blind rerun/manual marker deletion is prohibited. |
| Successful target Git repository | Exactly one `refs/heads/main` root commit with zero parents; exact encrypted tree/index/worktree; no source refs, remotes, alternates, objects, parents, or plaintext file object. |
| Source preservation | Tracked worktree files and root Git semantic/control manifests remain unchanged in dry-run, success, and every injected failure. |
| Linux and Windows native runs | Same logical classification, counts, canonical semantic source manifest, rejection decisions, and decrypted target bytes for the same portable source bytes; random vault ids, nonces, ciphertext, physical identities, timestamps, tree ids, and root commit ids may differ. |

Repository import is not release-approved until every row passes through the
real CLI, fault injection at every construction/durability/publication
boundary, native Linux and Windows filesystems, and residue scanning over
source, staging, final target, Git objects, process output, editor state, and
temporary directories.
