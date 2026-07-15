# Plaintext Export v1

## Status

Planned implementation contract. This is a deliberate high-risk capability,
not an administrator bypass and not part of ordinary Inex editing or Git
integration.

## Purpose and non-goals

An already authenticated user may make an intentional, portable plaintext copy
of an encrypted vault. That copy is outside Inex's normal no-plaintext-on-disk
guarantee. Export exists for an explicit hand-off, emergency migration, or a
user-authorized backup; it is never used for viewing, Git diff, search,
preview, or editor interoperability.

v1 does not implement recovery passwords, a master-password bypass, a hidden
administrator account, exporting into the vault, incremental overwrites, or
automatic cleanup of a successfully published plaintext destination.

## Authorization and scopes

Only `inexd` writes plaintext. CLI and editor clients are untrusted UI
adapters: they request an export through one authenticated live Outer session
and do not decrypt EDRY themselves.

`outer` scope requires an unlocked Outer session and exports:

- ordinary Markdown verbatim;
- each feature-2 document as its authenticated Outer projection, never
  decrypting a private slot or catalog;
- opaque attachments after complete AEAD authentication; and
- the canonical directory hierarchy.

`umbra` scope additionally requires a live Umbra session belonging to the
same Outer session. It exports canonical Umbra Markdown projections including
private Markdown, annotation kind/tag IDs and public Outer strategy. Private
tag labels, profiles and the Umbra catalog are not exported as a configuration
file in v1. This avoids making a second, undocumented plaintext metadata
format while preserving annotations within documents.

An Outer session cannot request `umbra`, and an Umbra lock invalidates any
prepared `umbra` export before publication.

## Two-step operation

1. `vault.export.prepare` validates scope and a caller-selected destination,
   snapshots the authenticated tree, checks that the destination is absent,
   outside the vault and has a safe existing parent on a filesystem capable of
   atomic sibling publication. It returns a random, session-bound,
   single-use confirmation capability and only public counts/byte budgets.
2. The client presents a high-risk warning and receives an explicit user
   confirmation. `vault.export.commit` accepts only that capability; it
   revalidates the session, scope, vault/destination identities and final
   absence, writes a sibling staging tree, audits every exported byte and
   atomically publishes the destination.

The capability is zeroized on session lock, Umbra lock, expiry, failure and
success. It is never written to logs, settings, workspace state or a draft.
The confirmation wording must state that Inex cannot protect the destination,
that Git/backup/indexing/history services may retain it, and that deletion is
not a secure erase operation.

## Filesystem transaction

The commit path uses one new sibling staging directory beneath the selected
destination parent. Every logical tree entry is recreated below staging only
after path validation. Documents/assets are fully authenticated before their
plaintext is written, use create-new regular files with restrictive
permissions, are fsynced, and are re-read/digested for audit. Directories are
fsynced bottom-up. The final root is published exactly once with a
no-replace atomic rename and the parent is fsynced.

Any failure before final publication leaves the destination absent and retains
the clearly named staging tree for manual incident handling; Inex must never
silently delete a directory that contains plaintext. Failure after publication
returns `published-with-warning` only after confirming the final root identity
and a complete manifest audit.

The receipt contains only protocol version, scope, timestamp, exported entry
counts, aggregate byte count and per-file SHA-256 values. It lives inside the
published plaintext destination because it necessarily describes that copy;
it never enters the encrypted vault, Git commit message, editor log or VS Code
workspace storage.

## Client UX

CLI exposes `inex export <vault> <destination> --scope outer|umbra`. It uses
the normal password/session flow and requires an explicit noninteractive
opt-in environment variable only for automated tests.

VS Code contributes `Inex: Export Plaintext Copy…`, disabled while locked. It
uses a folder chooser, then scope selection. Umbra-inclusive scope is offered
only after live Umbra status verification. The final warning is a modal
confirmation whose primary button says `Export plaintext copy`; cancellation
must consume and invalidate any prepared capability. The command never calls
Git textconv, VS Code SCM diff, `workspace.fs.copy`, or a plaintext
`TextDocument`.

Sublime and Neovim may expose the same prepare/commit RPC later, but v1 first
ships CLI and VS Code with this exact confirmation contract.

## Acceptance tests

1. Outer-only export includes ordinary Markdown/assets and never contains a
   private-slot plaintext/tag canary.
2. Umbra-inclusive export rejects without live Umbra, then includes the exact
   private content/tag-ID canary after separate Umbra unlock.
3. Destination equal to, inside, or an ancestor of the vault; an existing
   destination; symlink/reparse hazards; and parent identity changes all fail
   before publication.
4. Injected write/audit/publish failures leave final destination absent and do
   not place plaintext in the vault or daemon/client logs.
5. Successful output has restrictive modes, verified manifest/receipt, exact
   Markdown/asset bytes, a clean source vault Git worktree, and no new
   plaintext files outside the selected destination or retained staging root.
6. Prepared tokens are single-use, scoped, expire on lock, and cannot upgrade
   Outer authorization to Umbra scope.
7. VS Code tests verify command gating, warnings/cancellation and that no
   regular plaintext VS Code document or SCM diff provider is created.
