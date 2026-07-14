# Inex Umbra v1 Storage and RPC Contract

Status: **proposed and intentionally not implemented.** This document freezes
the decisions that must be reviewed before any K_umbra, slot, RPC, or editor
code lands.

## Scope

Umbra v1 is an opt-in nested privacy layer inside an already encrypted Inex
vault. A normal vault unlock can render only the deliberately public Outer
projection. An Umbra unlock additionally authenticates a dedicated Umbra
password and permits the sidecar to decrypt private slots, encrypted tags, and
the encrypted tag/profile catalog.

Umbra v1 does not encrypt filenames, cover text, slot IDs, public slot order,
or ciphertext lengths. It does not support nested slots, inline fragments, or
external direct editing of an Umbra document.

## Feature negotiation

Required feature ID `2` is reserved for `UMBRA_PRIVATE_ANNOTATIONS_V1`.
Enabling Umbra adds `2` to the sorted, authenticated `vault.json`
`required_features` list. A client that does not understand feature `2` must
fail before rendering or mutating an Umbra-bearing vault. Existing documents
and vaults remain readable until the user explicitly enables Umbra.

Feature `1` (opaque assets) and feature `2` are independent. The only valid
required-feature sets are sorted, unique combinations supported by the reader.

## Key hierarchy and lifecycle

```text
vault password  -> Argon2id KEK -> wrapped vault master key
Umbra password  -> Argon2id KEK -> wrapped random 256-bit K_umbra
K_umbra         -> domain-separated AEAD keys for slots/config
```

Enabling Umbra prompts for and confirms a distinct Umbra password. It creates a
random 256-bit K_umbra and one or more password-wrapped Umbra key slots in
authenticated `vault.json` metadata. The exact canonical metadata fields,
Argon2id bounds, slot-ID grammar, wrapping nonce/AAD, and password-change/add/
remove APIs must match the normal password-slot discipline but use separate
`inex-umbra-*` domain labels. A vault master-key password must never derive or
substitute for K_umbra.

The ordinary vault master key authenticates the public Umbra slot metadata in
`vault.json`; the Umbra password is still required to unwrap K_umbra. The
sidecar owns K_umbra only while Umbra Mode is unlocked, stores it in protected
memory, zeroizes it on Umbra lock/session lock/EOF/shutdown, and never sends it
to editor clients. Change, recovery, and multiple-Umbra-password-slot behavior
are deferred until their exact v1 API is approved; initial implementation must
not silently create a nonrecoverable key lifecycle.

## Physical encrypted config

The logical internal path `.inex/config.umbra.inex` is reserved exclusively for
the encrypted `UmbraConfigV1` catalog/profile document. It is hidden from
ordinary tree views and cannot be created, renamed, deleted, or opened through
generic Markdown/asset APIs.

Its physical envelope is an Umbra-specific AEAD envelope, authenticated to the
vault ID, required-feature set, logical internal path, config schema version,
and a fresh random nonce. It uses a K_umbra-derived config key and a separate
domain from private slots. It contains no plaintext tag or profile metadata in
the Outer document, `vault.json`, editor settings, filesystem name, or logs.
Writes are same-directory ciphertext-only atomic replacements under the normal
vault mutation lock and must re-open/authenticate before success is reported.

## Umbra document container

An EDRY Markdown document remains encrypted with the ordinary vault master
key. For documents that contain private annotations, its authenticated
plaintext is a canonical `inex-umbra-document` v1 container rather than raw
Markdown:

```json
{
  "format": "inex-umbra-document",
  "version": 1,
  "outerMarkdown": "Public text\n{{inex-private-slot:p_01}}\n",
  "slots": {
    "p_01": {
      "outer": { "mode": "drop" },
      "umbraCipher": {
        "alg": "xchacha20-poly1305",
        "nonce": "base64url",
        "ciphertext": "base64url"
      }
    }
  }
}
```

`outerMarkdown` is the only text available in Outer Mode. A marker has one
canonical ASCII grammar and references a public opaque slot ID. Outer rendering
maps `drop`, `cover`, and `placeholder` without decrypting a slot. Cover text
is deliberately public and is serialized only in the `outer` entry.

Each `umbraCipher` decrypts under a slot-specific K_umbra-derived AEAD key to
one canonical `inex-private-slot` v1 payload. It contains kind, ordered tag
IDs, Markdown, created/updated timestamps, and future private link metadata.
No tag ID, kind, or private timestamp is duplicated into the outer container.
Slot AAD binds vault ID, logical document path, slot ID, container version, and
the canonical public Outer entry so ciphertext cannot be transplanted or have
its Outer semantics substituted.

The sidecar renders a fully unlocked Umbra projection by replacing markers with
the canonical `:::inex-private` block syntax from `docs/prd-umbra-mode.md`.
It returns a bounded RenderMap that maps projection ranges to canonical marker
and slot identities. The client never parses or writes storage containers.

Raw Markdown documents without this container remain legacy Outer documents.
The first private annotation converts one authenticated raw Markdown body into
the container in one etag-checked transaction. Existing legacy private slots,
if a predecessor implementation is ever found, must have an explicit decoder;
they are not inferred from arbitrary Markdown fences.

## Atomic mutation contract

`toggle`, `apply`, `edit`, and `remove` accept one document etag and a
RenderMap generation supplied by the current Umbra projection. The daemon:

1. verifies session, Umbra unlock, logical path, etag, map generation, and all
   public resource bounds;
2. normalizes selections and rejects partial marker/slot intersections;
3. obtains/validates an annotation spec only after all selections are known
   valid;
4. applies all ranges in memory from back to front;
5. encrypts new/changed slot payloads and serializes the canonical container;
6. atomically replaces one EDRY Markdown envelope under the vault mutation
   lock; and
7. returns a fresh projection, map generation, and ciphertext etag.

No single-range commit, config write, or editor-visible partial projection is
allowed on failure. Catalog/profile writes are independent encrypted-config
transactions unless a future compound transaction is specified and proven.

## RPC and error boundary

RPC v1 gains explicit Umbra session methods before editor wiring:

```text
umbra.enable
umbra.unlock
umbra.lock
umbra.status
umbra.config.load
umbra.config.save
umbra.annotation.apply
umbra.annotation.edit
umbra.annotation.remove
```

Requests use logical paths, session capabilities, bounded text ranges, expected
etag, and RenderMap generation. Responses never contain K_umbra, password
bytes, physical paths, or private metadata while in Outer Mode. Errors expose
only stable public classes such as `UMBRA_LOCKED`, `STALE_RENDER_MAP`,
`PARTIAL_PRIVATE_SELECTION`, and `ANNOTATION_VALIDATION_FAILED`; user values
and decrypted text are scrubbed.

## Required test evidence

- K_umbra/tag/config canaries are absent from the repository, Outer projection,
  Outer index, logs, and error messages.
- Wrong Umbra password produces neither slot/config plaintext nor partial
  metadata.
- Slot/cipher/AAD/config tampering fails closed.
- Legacy raw Markdown round-trips unchanged until first explicit annotation.
- Multi-selection failures leave the complete original EDRY envelope unchanged.
- Cross-editor tag/profile synchronization requires encrypted config unlock.
- Slot-ID, logical-path, container, and cover substitution attacks fail.
- Umbra lock clears projection maps and private client/webview state before an
  Outer projection is emitted.
