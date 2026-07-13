# Opaque assets, required feature 1

Status: **frozen for implementation on 2026-07-14**. This document is the
explicit compatibility decision that extends the frozen vault and EDRY 1.0
formats without changing their major/minor version tuples.

## Scope

Opaque assets let a copy import preserve bounded non-Markdown regular files,
including raster images and other attachments, without creating a plaintext
mirror. Asset filenames and directory names remain visible, as they already do
for Markdown documents. Asset bodies are encrypted and authenticated.

Version 1 is deliberately a bounded whole-file format. It does not provide
streaming encryption, random access, editor drafts, text search, plaintext
diff, automatic export, or semantic merge. In particular,
`features.streamingBlobs` remains `false`. A future streaming-blob format must
use a separately registered required feature and specify chunk ordering,
truncation, final-tag, recovery, and upgrade semantics before enabling that
flag.

## Registered identifiers

The following identifiers are frozen:

| Registry | Identifier | Meaning |
|---|---:|---|
| `vault.json.requiredFeatures` | `1` | `opaque-assets-v1` is required to interpret the vault tree safely |
| EDRY header `required_features` | `1` | the envelope uses the opaque-asset extension |
| EDRY `plaintext_kind` | `2` | exact opaque asset bytes; no UTF-8 interpretation |

The vault format remains `{ "major": 1, "minor": 0 }`, and the EDRY prefix
remains major `1`, minor `0`. Required-feature negotiation, rather than a
version bump, is the compatibility boundary.

An asset-capable implementation accepts required feature `1` and continues to
reject every unknown required feature. Required-feature arrays remain strictly
increasing and duplicate-free.

## Vault feature contract

A vault that can contain an opaque asset MUST include `1` in
`vault.json.requiredFeatures`. A newly imported vault containing at least one
asset is created with exactly `[1]` under the currently known feature registry.
`features.filenameEncryption` and `features.streamingBlobs` remain `false`.

The required-feature array is covered by the existing master-keyed metadata
MAC. Removing, adding, or reordering a feature without recomputing that MAC
therefore fails authentication. Asset APIs MUST additionally verify that the
authenticated vault configuration contains feature `1`; an asset envelope
cannot enable the capability by itself.

An existing feature-free vault MUST NOT be upgraded implicitly by copying or
writing an asset. Enabling feature `1` in an existing vault requires a separate,
explicit, authenticated metadata transaction with the same atomicity and
re-open verification as other `vault.json` mutations. Copy import into a new,
absent destination declares the feature during initial vault creation and does
not need an upgrade transaction.

## AssetPath profile and physical mapping

`AssetPath` is an NFC, UTF-8, vault-relative logical path. It uses `/` as its
separator and inherits the EDRY v1 cross-platform path rules for empty, `.` and
`..` components, controls and NUL, forbidden Windows characters, leading or
trailing spaces/dots, device names, DOS 8.3 aliases, reserved `.git` and
`.vault-local` components, root `vault.json`, case-fold collisions, and the
1024-byte complete-path limit. The parser does not add a component-count
limit; tree discovery and import independently retain the existing maximum
depth of 128.

Unlike a Markdown `LogicalPath`, an `AssetPath` MUST NOT end in exact lowercase
`.md`. Its final component is limited to 245 UTF-8 bytes, reserving ten bytes
for the physical suffix `.asset.enc`; every other component remains limited to
255 UTF-8 bytes.

The mapping preserves all logical directory components and appends
`.asset.enc` to the final component:

```text
images/field station.png  ->  images/field station.png.asset.enc
attachments/data.csv      ->  attachments/data.csv.asset.enc
```

Reverse mapping strips one exact lowercase `.asset.enc` suffix and then
validates the resulting canonical `AssetPath`. Case variants and names that
only resemble the suffix fail closed. For example, `image.png.ASSET.ENC` is not
an asset, and `note.md.asset.enc` is invalid because its reconstructed logical
path belongs to the Markdown namespace.

The document and asset physical mappings share one normalization and portable
case-fold collision domain. A document, asset, or directory that would map to
the same logical or physical path as another entry aborts discovery or import.

An asset-enabled vault tree reports three entry kinds: `directory`, `file`,
and `asset`. The existing `file` spelling retains its frozen meaning of a
canonical encrypted Markdown document, while canonical `*.asset.enc` entries
are assets. An ordinary attachment filename such as `image.png` is never a
valid stored asset. Other unrelated regular files are not treated as assets;
outside the explicitly allowed repository and Inex metadata names, discovery
fails closed rather than silently accepting a possible plaintext attachment.

## EDRY asset envelope

Opaque assets reuse the existing EDRY prefix, canonical CBOR header, file-key
derivation, XChaCha20-Poly1305-IETF primitive, etag, and atomic ciphertext
writer. The existing domain separators remain unchanged. The authenticated
plaintext kind and required feature prevent document/asset type confusion.

An asset header MUST satisfy all of the following:

- `logical_path` is a canonical `AssetPath`;
- `plaintext_kind` is `2`;
- `required_features` is exactly `[1]`;
- `content_flags` is zero;
- `base_etag` is null;
- the envelope is committed, not a draft;
- vault id, key epoch, file id, timestamps, cipher, derivation algorithm, and
  nonce obey the existing EDRY v1 rules.

A Markdown header remains `plaintext_kind=1`, has an exact lowercase `.md`
logical path, and does not gain feature `1`. Implementations MUST reject a
kind/path/feature mismatch before returning plaintext. Asset decryption does
not perform UTF-8 validation; the returned bytes are exact and zeroizing.

Every encryption, including a byte-identical replacement or logical rename,
uses a fresh nonce. A rename preserves the random file id and creation time,
authenticates the new logical path, and re-encrypts the complete body before
the old name can be retired.

## Bounds and whole-file memory model

The frozen limits are:

```text
MAX_DOCUMENT_PLAINTEXT_LEN = 16,777,216 bytes
MAX_ASSET_PLAINTEXT_LEN    = 67,108,864 bytes
MAX_IMPORT_PLAINTEXT_BYTES =  4,294,967,296 bytes
MAX_HEADER_LEN             =      4,096 bytes
EDRY_PREFIX_LEN            =         12 bytes
AEAD_TAG_LEN               =         16 bytes
MAX_ASSET_ENVELOPE_BYTES   = 67,112,988 bytes
```

`MAX_ASSET_ENVELOPE_BYTES` is exactly:

```text
12 + 4096 + 67,108,864 + 16 = 67,112,988
```

The Markdown limit does not increase. Format framing may accept the larger
asset ceiling, but document APIs still enforce 16 MiB and asset APIs enforce
64 MiB after authenticating the plaintext kind and context.

An asset-inclusive import additionally limits the sum of all document and
asset source sizes to exactly 4 GiB. Planning accumulates that sum with checked
`u64` arithmetic and rejects the exact limit plus one, integer overflow, and
any per-kind limit violation before password collection, KDF work, destination
creation, or ciphertext staging. The existing 256 MiB aggregate Markdown
limit remains an independent bound on the document subset.

Version 1 authenticates the complete asset before exposing any plaintext byte.
It is not a streaming-storage format. With the initial reuse of the existing
combined-mode helpers, encryption can transiently hold the source plaintext,
the libsodium ciphertext, and the assembled envelope: approximately `3N`, or
192 MiB at the 64 MiB boundary. Decryption can hold the envelope and plaintext:
approximately `2N`, or 128 MiB at the boundary. Small headers, allocator
metadata, RPC chunks, and process runtime memory are additional bounded
overhead.

Implementations MAY reduce copies, for example by encrypting directly into an
allocated envelope, but MUST NOT exceed the frozen plaintext or envelope
limits. The atomic writer, staging verifier, import seal, and bounded readers
take the exact asset envelope ceiling rather than relying on the former 32 MiB
generic target limit.

Planning and source-digest passes SHOULD hash assets with a fixed-size buffer.
Population may read one complete bounded asset for whole-file encryption. Asset
imports and authenticated verification are sequential; they MUST NOT retain
multiple complete asset plaintexts concurrently.

## Copy import

Opaque assets are enabled through an explicit asset-inclusive copy-import
mode. Existing Markdown-only import behavior is not silently reinterpreted.
The dry run reports document count/bytes, asset count/bytes, excluded VCS
metadata, normalized paths, and the exact required-feature result.

Every safe regular source file is classified as either:

- a document: its basename ends in exact lowercase `.md`, its body is valid
  UTF-8, and it satisfies the 16 MiB document limit; or
- an asset: its path is a valid `AssetPath` and its exact bytes satisfy the
  64 MiB asset limit.

An unsupported or oversized regular file fails the asset-inclusive import. It
is not silently skipped. Links, reparse points, hard links, special objects,
mount-boundary crossings, path aliases, and source mutation retain the existing
fail-closed behavior.

A source file whose bytes form a possible Git LFS v1 pointer is external
content, not the attachment it names. The bounded detector examines files no
larger than 4,096 bytes and rejects a file as soon as its first line is exact
`version https://git-lfs.github.com/spec/v1`, terminated by LF, CRLF, or
end-of-file. It does not require otherwise valid `oid`, `size`, or extension
lines, so a truncated, malformed, or noncanonical pointer cannot evade
rejection. The scan is byte-based and applies to documents and assets
regardless of Git attributes.

Asset-inclusive import performs that check before password collection or
destination creation and never performs an implicit LFS/network fetch.
Fetching and checking out LFS bodies is an explicit source-repository
preparation step outside Inex. A hydrated regular file is imported by its
actual bytes even when source attributes name an LFS filter; no filter/helper
is invoked during source verification.

For a Git working tree, one exact root `.git` directory or regular Git worktree
file is excluded and counted without traversing or copying it. A link/reparse
point at that name, or `.git` below any imported directory, remains invalid.
Source Git objects, refs, reflogs, configuration, and historical plaintext are
never copied to the new vault. The destination begins a new ciphertext-only Git
history after successful publication.

Markdown bodies are imported byte-for-byte and are not rewritten. Relative
asset references therefore retain their source spelling. Editor resolution
percent-decodes each component, normalizes to NFC, rejects encoded separators,
external schemes, protocol-relative targets, and `..` escapes, then resolves
against the current document's logical parent. Broken or unsupported image
references may be reported by dry run, but do not authorize path rewriting.

The staging allowlist includes planned directories, `*.md.enc`,
`*.asset.enc`, `vault.json`, and the existing private import/mutation state—no
plaintext source file. Every asset is re-opened, authenticated, and compared
with its planned source size and digest before no-replace publication. All
source-preservation, source-rescan, destination identity, seal, publication,
and ambiguous-result rules from copy import v1 continue to apply.

## Git behavior

The installed top-level attributes include both exact managed rules:

```gitattributes
*.md.enc -text -diff merge=inex
*.asset.enc binary
```

The `binary` macro gives asset paths `-diff -merge -text`. Asset conflicts are
ordinary binary conflicts and MUST NOT invoke the Inex Markdown merge driver,
attempt a plaintext merge, or synthesize conflict markers. Conflict resolution
selects or replaces one complete authenticated asset blob explicitly.

Driver installation and verification distinguish tree entry kinds. Only
documents are required to resolve to `merge=inex`; assets are required to
resolve as binary. Both kinds remain ordinary Git blobs, and Git history never
contains decrypted asset bytes.

The v1 merge workflow resolves assets only through this dedicated command:

```text
inex git resolve-asset <vault> <logical-path> (--ours|--theirs|--delete) [--slot <uuid>]
```

Exactly one decision is required. `--ours` selects stage 2, `--theirs` selects
stage 3, and the named stage MUST exist. `--delete` selects no blob. Before any
mutation, the command takes one bounded complete index snapshot, requires the
named path to be unmerged and physical `*.asset.enc`, requires every present
stage to be mode `100644`, verifies effective `binary` attributes, and fully
authenticates every present stage blob against the unlocked vault id, epoch,
logical `AssetPath`, kind 2, feature `[1]`, and AEAD. It never accepts a
worktree file or arbitrary external replacement as the selected ciphertext.

Resolution is a new typed payload of the existing v5 immutable candidate and
journal transaction. It constructs the candidate index without changing the
real index, binds the complete original and final stage maps, writes the
selected authenticated blob (or removes the path) under the existing
worktree/index capability checks, and publishes the candidate through the
existing real `index.lock` forward-recovery protocol. Every unrelated index
entry and stage is byte-for-byte preserved. Error, process kill, or restart at
each candidate, journal, worktree, lock, and index publication checkpoint
leaves either the exact original conflict or a recoverable exact final
resolution; it never leaves a partially staged/worktree result.

`inex git merge` then performs a complete unmerged-index preflight and refuses
the entire operation if any non-document stage remains. It MUST do so before
decrypting, writing, or staging any Markdown result. This ordering prevents a
mixed asset/Markdown conflict from producing a partial Markdown merge
transaction.

Version 1 exposes asset reads and the two bounded write authorities above:
new-vault copy import and conflict-stage selection. It does not expose general
asset create, replace, rename, or delete RPCs. A future general mutation API
MUST reuse the vault mutation lock, conditional etag checks, encrypted rename
journal, atomic ciphertext writer, and authenticated re-open verification;
ordinary filesystem writes or editor backups are never an allowed shortcut.

## JSON-RPC asset capability

Asset transport is additive to protocol major 1 and is negotiated through the
exact capability string `opaqueAssetsV1`. Bulk import remains CLI-first.
Clients MUST NOT call asset methods unless both the capability and the
authenticated vault feature are present.

The existing JSON frame maximum remains 24 MiB. Complete assets are never
base64-encoded into one frame. The exact methods are:

| Method | Exact parameters | Result |
|---|---|---|
| `asset.open` | `session`, `logicalPath` | `handle`, `size`, `etag`, `metadata` |
| `asset.readChunk` | `session`, `handle`, `offset`, `maxBytes` | `offset`, `contentBase64`, `eof` |
| `asset.close` | `session`, `handle` | acknowledgement |

`asset.open` validates `AssetPath`, the vault feature, physical file safety and
size, EDRY framing, header kind/feature/path context, and whole-file AEAD before
creating a handle. It returns no body bytes. The authenticated plaintext is
held in a zeroizing session allocation only after complete authentication.

At most one asset handle and 64 MiB of asset plaintext may exist in one sidecar
session. Opening an asset while that budget is occupied fails with the normal
bounded-resource error. An implementation SHOULD clear its rebuildable
Markdown search index before allocating a large asset, so the two largest
sensitive caches do not accumulate. Handles bind to the session generation and
are wiped on explicit close, vault lock, idle expiry, sidecar shutdown, or
terminal transport failure.

`asset.readChunk` is sequential. `offset` MUST equal the handle's next unread
offset, and `maxBytes` is an integer from 1 through 1,048,576. The result echoes
the accepted offset, returns at most that many bytes as canonical unpadded
base64url, and advances the handle. `eof` is true exactly when the returned
chunk reaches the authenticated size. For a zero-byte asset, the first request
at offset zero returns an empty canonical string with `eof=true`. Repeated,
skipped, stale, out-of-range, or post-EOF reads fail closed. Callers close the
handle after EOF.

A 1 MiB raw chunk expands to approximately 1.34 MiB of base64 plus bounded JSON
overhead, well below the unchanged frame ceiling. Errors and logs contain no
asset bytes, absolute paths, request bodies, or attachment-derived text.

## VS Code image preview

The extension treats asset references as logical paths, never as plaintext
filesystem paths. It does not register a plaintext `FileSystemProvider`, widen
`localResourceRoots`, call `asWebviewUri` for a decrypted file, or write an
image cache. The extension reads sequential RPC chunks and posts bounded
`Uint8Array` messages to the owning webview without first concatenating a
complete extension-host Buffer.

The editor CSP remains closed except for in-memory image objects:

```text
default-src 'none';
style-src 'nonce-<random>';
script-src 'nonce-<random>';
img-src blob:;
```

There is no `http:`, `https:`, `data:`, `file:`, remote font, media, frame, or
connection source. The webview constructs a Blob only after every expected
chunk has arrived for the current document revision and session generation.
It creates an object URL from that Blob and never persists bytes with webview
state APIs.

Inline preview is limited to assets no larger than 33,554,432 bytes (32 MiB).
Larger assets remain safely stored and visible in the tree but are not rendered
inline by this version. Preview type comes from validated bytes, never the file
extension or an untrusted media-type string. The allowed signatures are:

- PNG: the exact eight-byte PNG signature;
- JPEG: an SOI marker followed by a valid JPEG marker stream;
- WebP: `RIFF`, a self-consistent bounded RIFF length, and `WEBP`.

GIF, SVG, XML, HTML, PDF, unknown formats, malformed marker streams, APNG, and
animated WebP are not rendered. Raster dimensions MUST be parsed before Blob
creation, with each dimension in `1..=16384` and width times height no greater
than 40,000,000 pixels. A preview rejection never drops the encrypted asset.

External Markdown image targets, protocol-relative URLs, `data:` URLs,
absolute host paths, encoded separators, and vault-root escapes are never
fetched. They remain inert editor text. Raw HTML is not a preview escape hatch.

Only the current visible/relevant images are loaded, under a 64 MiB aggregate
compressed-preview budget per panel. Byte arrays are overwritten on a
best-effort basis after message delivery or Blob construction. Object URLs are
revoked and associated arrays/references cleared on document edit, navigation,
panel hide, lock, session replacement, failed/stale transfer, or disposal.
Browser and JavaScript heap erasure remains best effort under the documented
editor threat model.

## Compatibility and failure behavior

- A new implementation opens existing feature-free vaults and preserves every
  frozen Markdown fixture byte-for-byte.
- An old implementation rejects an asset-enabled vault because required
  feature `1` is unknown. It must not unlock and silently omit assets.
- An old EDRY reader rejects an asset envelope because of its required feature,
  plaintext kind, path profile, or size bound; rejection is safe compatibility.
- A new implementation rejects an asset envelope in a feature-free vault even
  if the envelope independently authenticates.
- Removing feature `1` from `vault.json` without the master key fails metadata
  authentication. Changing an asset header kind, feature, logical path, length,
  nonce, flags, or ciphertext fails canonical validation or AEAD.
- Asset-inclusive import remains copy-only and publishes only to an absent
  destination. The source working tree and its Git history are never modified.
- No compatibility path stores a plaintext attachment beside ciphertext or
  encodes an attachment inside a synthetic Markdown document.

## Acceptance matrix

| Area | Required cases | Expected evidence |
|---|---|---|
| Format round trip | empty bytes, NUL/non-UTF-8 bytes, Unicode path, exact 25,074,521-byte image, exact 64 MiB asset | exact bytes, stable file id, fresh nonce, authenticated kind/path/feature |
| Bounds | 64 MiB, 64 MiB + 1 byte, maximum envelope, truncated envelope; aggregate 4 GiB and 4 GiB + 1 | per-file boundary succeeds; every oversized/truncated input fails before publication or plaintext return; aggregate overflow fails before password/KDF/destination work |
| Type safety | kind 1 with AssetPath, kind 2 with `.md`, missing/extra feature, nonzero flags, draft/base etag | all mismatches fail closed |
| Tampering | vault feature, header feature/path/kind/length/nonce, ciphertext/tag | metadata MAC, canonical validation, context check, or AEAD rejects with no partial plaintext |
| Paths | NFC, percent encoding, 245/246-byte final names, case collision, device/reserved names, `.asset.enc` case variants | exact portable mapping or deterministic rejection |
| Import | Markdown plus images/attachments, root `.git` directory and gitfile, canonical/noncanonical LF/CRLF Git LFS pointer, hydrated LFS body, hard link, symlink/reparse, source mutation, injected plaintext, target collision | source hashes and Git state unchanged; exact counts/digests; pointer rejected and hydrated bytes accepted without helper/network access; only ciphertext staging/final state |
| Publication failure | injected read/encrypt/seal/sync/rename/cleanup failures | absent final destination or documented retained ciphertext-only evidence; never source mutation |
| RPC | zero-byte, multi-chunk 25,074,521-byte read, 64 MiB read, wrong/repeated/skipped offset, excessive chunk, stale handle, lock/timeout/shutdown | ordered exact digest, every invalid read rejected, handle memory wiped, every frame below 24 MiB |
| Session memory | second concurrent open, search index followed by large open, close/reopen | one-handle/64-MiB budget enforced and rebuildable cache does not accumulate unboundedly |
| VS Code | PNG/JPEG/WebP, spoofed extension, SVG/HTML/data/external URL, oversized/pixel-bomb/animated image, edit/hide/lock/dispose mid-transfer | only validated Blob previews; exact CSP; no local resource roots/network fetch; URL revocation and stale-message rejection |
| Git | clean asset commit; ours/theirs/delete and missing/wrong-kind/tampered stages; Markdown beside unresolved asset; process kill at every v5 resolver edge; clone/restore | asset uses binary attributes; resolver authenticates all stages and preserves every unrelated stage; recovery yields exact old/final state; Markdown remains untouched until all assets resolve; restored ciphertext authenticates |
| Legacy | frozen v1 vault in new client; feature-1 vault and asset envelope in predecessor client | legacy opens unchanged; predecessor rejects the new required feature without silent omission |
| Residue | successful preview, cancelled preview, crash/lock, import success/failure | no plaintext attachment file, editor backup, local-history entry, log body, or temporary plaintext cache is found by bounded canary scans |
