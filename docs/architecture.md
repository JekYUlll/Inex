# Inex Architecture

## Components and trust boundary

```text
real Git ciphertext vault
        ^
        | encrypted reads and atomic encrypted writes only
        v
inex-core  <---  inexd JSON-RPC/session boundary
                      ^             ^
                      |             |
              VS Code client   Sublime client
              virtual buffer   managed buffer
```

`inex-core` is the only component allowed to interpret vault configuration,
derive keys, parse EDRY, map logical paths, or write ciphertext. `inexd` owns
unlocked sessions, memory-only search state, etags, cache eviction, and the
transport-independent RPC method table. Editor clients receive logical paths
and bytes; they never receive a plaintext filesystem path or cryptographic key.

## Repository layout

```text
crates/
  inex-core/       cryptography, EDRY, vault, paths, index, merge
  inex-daemon/     session manager, RPC types/handler, inexd binary
  inex-cli/        inex administrative/import/merge-driver CLI
  inex-git/        bounded Git plumbing, encrypted merge transactions/recovery
editors/
  vscode/          TypeScript VS Code extension
  sublime/         Python Sublime Text package
docs/spec/         frozen wire/storage specifications
fixtures/          cross-language and cross-platform compatibility fixtures
```

## Vault layout

```text
vault/
  vault.json
  .gitattributes
  .gitignore
  2026/07/2026-07-10.md.enc
  topics/example.md.enc
  .vault-local/          ignored; plaintext-free locks/recovery metadata/tombstones
```

Logical `2026/07/2026-07-10.md` maps to physical
`2026/07/2026-07-10.md.enc`. The core performs this mapping only after strict
cross-platform normalization. A physical path is never accepted from RPC.

## Key hierarchy

```text
password
   |
   v Argon2id(slot parameters)
password KEK -------------------------+
                                         decrypt/authenticate
random vault master key <--- wrapped key slot in vault.json
   |
   v keyed, domain-separated derivation(vault id, epoch, file id)
per-file key
   |
   v XChaCha20-Poly1305(random nonce, canonical header AAD)
EDRY ciphertext
```

KDF parameters belong to each password slot, so adding a new password does not
change existing slots. Journal files bind to a master-key epoch, not a password
slot. Password changes therefore modify `vault.json` only. A future master-key
rotation increments the epoch and explicitly rewrites all files.

Production creation calibrates only Argon2id `opsLimit`, once per process,
against a public dummy input. v1 fixes memory at 64 MiB and parallelism at one,
searches operations 3–20 toward a 250–750 ms single-KDF measurement, and stores
the selected parameters in the new slot. Explicit new-vault APIs use that same
independent cap, while readers accept the broader compatibility ceiling.
Password add/change takes the componentwise maximum of the calibrated baseline
and the slot that authenticated the session, so rewrapping cannot silently
weaken a stronger slot.

## Save transaction

1. Validate session, logical path, UTF-8, size, and caller's expected etag.
2. Load and authenticate the current file when preserving its stable file id.
3. Build a canonical header with a fresh random nonce and updated timestamp.
4. Encrypt the complete Markdown body in memory.
5. Write the complete encrypted envelope to a unique same-directory staging
   file; flush and sync it.
6. While holding the cross-process vault mutation lock, recheck the target
   etag/absence condition and atomically replace the target.
7. Complete the platform namespace-durability barrier, compute/return the new
   ciphertext etag, and wipe owned plaintext/key buffers. Linux syncs the
   parent after `rename`; Windows uses `MoveFileExW` with
   `MOVEFILE_WRITE_THROUGH` and extended-length paths.

Staging files are ciphertext and use a non-Markdown suffix. A failure before
the replace leaves the old target untouched. Startup/verification may remove
or report abandoned encrypted staging files without decrypting them.
Windows delete/rename cleanup first write-through moves ciphertext to a unique
`.vault-local` retirement name, then deletes that tombstone best effort. A
reported move failure is followed by an exact ciphertext-etag state check; an
ambiguous state is never reported as an untouched pre-commit failure.

## Session and RPC lifecycle

- MVP runs one `inexd` child per editor window over stdio. stdout contains
  Content-Length framed JSON-RPC only; diagnostics go to scrubbed stderr.
- Unlock returns a random capability token. Every vault/file/search call must
  present it. Tokens are scoped to the daemon instance and never persisted.
- EOF, explicit lock, idle expiry, or shutdown invalidates tokens, drops the
  memory index/cache, and wipes buffers owned by the process.
- RPC is request/response and supports multiple outstanding IDs. Mutating
  operations are serialized per vault; reads may run concurrently when safe.
- The method handler is independent of stdio so a later authenticated local
  socket/named-pipe transport does not change method semantics.
- Each mutation also takes a local-filesystem OS lock under `.vault-local`, so
  independent VS Code/Sublime sidecars cannot both commit from the same etag.
- Search plaintext remains memory-only, but each query re-hashes every current
  ciphertext under the mutation guard before trusting the index. File size and
  timestamps are not accepted as a security cache key because sync tools can
  preserve them across external changes.

## Concurrency

An etag is a digest of the complete current ciphertext envelope. `file.read`
returns it; `file.write`, rename, and delete require the expected value for an
existing entry. A mismatch returns a conflict without revealing either body.
The editor must ask the user to reload/compare through a protected view.

## VS Code editing and encrypted drafts

An ordinary writable virtual TextDocument is not the primary editor surface.
VS Code's working-copy backup tracker can persist modified working copies even
when Hot Exit is disabled. The Inex extension therefore registers the
`inex.markdownEditor` CustomEditorProvider for real `file:` resources matching
`**/*.md.enc`; its document model and undo state remain controlled by the
extension/webview. Its `backupCustomDocument` implementation asks `inexd` to
encrypt the unsaved draft, then writes only that EDRY ciphertext to the backup
destination supplied by VS Code. Restore presents a locked document until the
vault is unlocked and the backup authenticates.

The extension never places plaintext in webview persisted state, workspace
state, global state, logs, telemetry, or command arguments. Markdown links,
headings, references, and search navigation are implemented inside the custom
editor/panels. A read-only virtual resource may be added only after residue
tests prove it does not create plaintext backups/history.

## Search

On unlock, the sidecar may decrypt files to build a memory-only index. Index
entries, snippets, and cached bodies are dropped on lock. Search responses are
bounded and contain logical path, line/column, match length, and a short
snippet. v1 writes no index to `.vault-local`.

## Git and merge

Git sees each `*.md.enc` as non-text and invokes a canonical absolute Inex
executable as `'<absolute-inex>' merge-driver`, with no path placeholders.
The compatibility CLI form remains `inex merge-driver %O %A %B %P`. Without a safe unlock channel the driver
does not open or stat any of the four paths, leaves `%A` byte-for-byte and
metadata-for-metadata unchanged, returns nonzero, and preserves Git index
stages 1/2/3. Installation is explicit per clone with
`inex git install-driver <vault>`; it appends tracked `-text -diff merge=inex`
and `/.vault-local/` rules by atomic metadata replacement and writes only
`git config --local` values.

`inex git merge <vault>` is the separate unlocked path. It reads stages through
bounded `ls-files -u -z` and `cat-file blob` plumbing, authenticates every EDRY
stage, proves rename provenance against the unique merge base plus exact
`HEAD`/`MERGE_HEAD` trees, and rejects tracked or untracked third owners of the
same file identity before any merge write. It performs diff3 only in zeroizing
process memory, writes only the new EDRY envelope to
`hash-object -w --stdin`, and changes the worktree/index under a
ciphertext-only `.vault-local/git-merge-journal-v1.json`. The stable filename
accepts legacy strict version 1 in-place, version 2 split-rename, and version 3
detected-rename metadata. New transactions write version 4, which wraps one of
those semantic payloads with the repository object format, a random lock
token, and exact old/candidate index SHA-256 and length bindings. A clean result
clears the merge flag. A conflict result contains encrypted diff3 markers and
sets authenticated `ContentFlags::UNRESOLVED_MERGE`; a later ordinary editor
save clears the flag only after all canonical marker lines have been removed.
`inex git recover <vault>` authenticates the journal's Git object and safely
finishes an interrupted worktree/index transition.

Git is resolved to one absolute regular executable before use. Plumbing uses a
fixed argument grammar, bounded stdin/stdout, a cleared environment with only
fixed safe Git variables, `-c core.fsmonitor=false`, and lazy fetching disabled.
Split indexes fail closed before mutation because the recovery barrier covers
one full `.git/index`. Object IDs must match the repository's full SHA-1 or
SHA-256 width; abbreviated prefixes are rejected. Diagnostics use scrubbed
stderr and validated portable paths/modes/OIDs; no password, key, session token,
or plaintext reaches Git. Fully automatic locked Git integration remains
deferred until an authenticated local broker exists. For v4, Inex first
publishes a durable token-bound pre-lock reservation, then builds the final
index through an absolute alternate `GIT_INDEX_FILE`. Initial/final
create-only ownership receipts bind the candidate before mutation and before
lock publication. Inex then owns the real `.git/index.lock` across the final
semantic recheck, worktree
advancement, and atomic candidate publication. Deliberate parallel porcelain
is still unsupported because ref-only mutations, legacy journal recovery, and
native Windows crash/power-loss behavior are not closed by that index lock.
The final cross-platform namespace move is path based after handle/path
identity validation; it is not a kernel-level handle-bound compare-exchange
against a same-OS-user process that directly rebinds transaction paths.

## Failure principles

- Fail closed on unknown versions/algorithms, non-canonical headers, invalid
  paths, truncated data, authentication errors, stale etags, and weak creation
  parameters.
- Never retry authentication or writes invisibly in a way that can overwrite a
  concurrent change.
- Never include request params or sensitive buffers in error/debug formatting.
- Import, password change, rename, and merge use prepare/verify/commit ordering;
  source deletion is always the final step of an explicitly destructive flow.
- Network filesystems are rejected/unsupported in v1 because cross-process
  locking, atomic replace, and namespace durability cannot be guaranteed.
  Linux rejects descendant mount-id/device changes as well as an unsupported
  root mount; Windows rejects reparse-point traversal and non-local drive types.
