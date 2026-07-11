# Inex Local JSON-RPC Protocol, Version 1

Status: **frozen for v1 implementation on 2026-07-10**. MVP transport is
Content-Length framed JSON over child-process stdio. Semantic changes require
an explicit protocol compatibility decision.

## Framing and safety

- Each frame starts with ASCII `Content-Length: <decimal>\r\n\r\n`, followed by
  exactly that many UTF-8 JSON bytes. Header names are case-insensitive; v1
  rejects duplicate/unknown framing headers and lengths with leading signs.
- Frames are limited to 24 MiB and must contain one JSON-RPC 2.0 object with
  `jsonrpc: "2.0"`, a string or integer `id`, a known `method`, and object
  `params`. v1 rejects batch arrays and notifications.
- stdout is protocol-only. Logs use stderr and never serialize request params.
- Binary plaintext is unpadded base64url. Passwords are JSON strings only for
  the duration of `vault.unlock`/`vault.create` parsing and are wiped on a
  best-effort basis after the KDF call.
- A successful `system.hello` negotiates protocol major `1`; mismatched majors
  terminate before unlock.
- One stdio child serves at most one vault at a time. Session capabilities are
  additionally bound to that transport; they are not valid in another child.

## Capability sessions

`vault.unlock` returns a random 256-bit unpadded-base64url session token. The
token is required in every protected method, scoped to one daemon process and
vault, expires after an idle timeout, and is never persisted. An invalid token
uses the same error as an expired token.

## Core methods

| Method | Important params | Result summary |
|--------|------------------|----------------|
| `system.hello` | `client`, `clientVersion`, `protocolMajor` | server/version/capabilities |
| `system.ping` | none | monotonic health information, no secrets |
| `system.shutdown` | none | acknowledgement, then wipe and exit |
| `vault.create` | `vaultPath`, `password`, optional KDF policy | vault id and warnings |
| `vault.unlock` | `vaultPath`, `password`, optional `slotId` | session, vault id, expiry, warnings |
| `vault.lock` | `session` | acknowledgement |
| `vault.status` | `session` | vault id, counts, expiry; no key data |
| `vault.listTree` | `session`, optional `prefix` | sorted logical entries |
| `file.stat` | `session`, `logicalPath` | type, size, times, flags, etag |
| `file.read` | `session`, `logicalPath` | content, etag, metadata |
| `file.write` | `session`, path, content, exactly one of `ifMatch`/`ifNoneMatch` | new etag/metadata |
| `file.mkdir` | `session`, logical directory | acknowledgement |
| `file.rename` | `session`, from/to, `sourceEtag`, `destinationIfNoneMatch` | destination metadata |
| `file.delete` | `session`, path, `ifMatch`, recursive flag | acknowledgement |
| `document.open` | `session`, path | handle, content, etag, metadata |
| `document.close` | `session`, handle | evict owned caches and acknowledge |
| `draft.encrypt` | `session`, handle/path, content, base etag | encrypted draft envelope |
| `draft.decrypt` | `session`, path, encrypted draft envelope | content and base etag |
| `search.query` | `session`, query, limit | bounded path/range/snippet results |
| `cache.evict` | `session`, optional path | acknowledgement |

Vault administration, bulk import, verification, and Git merge-driver commands
are CLI-first in v1 so editor clients do not gain unnecessary destructive
capabilities.

## Representative exchange

```json
{"jsonrpc":"2.0","id":1,"method":"system.hello","params":{"client":"vscode","clientVersion":"0.1.0","protocolMajor":1}}
{"jsonrpc":"2.0","id":1,"result":{"server":"inexd","serverVersion":"0.1.0","protocolMajor":1,"capabilities":["vault","files","documents","encryptedDrafts","search"]}}
{"jsonrpc":"2.0","id":2,"method":"file.read","params":{"session":"...","logicalPath":"2026/07/2026-07-10.md"}}
{"jsonrpc":"2.0","id":2,"result":{"contentBase64":"IyBUaXRsZQo","etag":"sha256:...","metadata":{"createdAt":1783699200000,"modifiedAt":1783699200000,"flags":0}}}
```

`file.write.ifMatch` is required when overwriting an existing file.
`ifNoneMatch: "*"` is required for create-only behavior. The core rechecks this
condition under a cross-process vault lock immediately before replace. There is
no silent force-write in the editor protocol.

## Error model

Standard JSON-RPC parse/request/method/params errors are used where applicable.
Application errors occupy `-32000` through `-32099`.

| Code | Stable name | Meaning |
|------|-------------|---------|
| -32000 | `AUTH_FAILED` | wrong password, invalid slot, or key unwrap failure |
| -32001 | `SESSION_INVALID` | missing, expired, locked, or unknown session |
| -32002 | `VAULT_INVALID` | invalid/unsupported vault configuration |
| -32003 | `PATH_INVALID` | logical path violates the cross-platform profile |
| -32004 | `NOT_FOUND` | logical entry is absent |
| -32005 | `ALREADY_EXISTS` | create-only destination exists |
| -32006 | `ETAG_CONFLICT` | current ciphertext differs from expected etag |
| -32007 | `INTEGRITY_FAILED` | EDRY parse/authentication/path binding failed |
| -32008 | `LIMIT_EXCEEDED` | request/content/result exceeds configured limit |
| -32009 | `IO_FAILED` | safe storage operation failed |
| -32010 | `KDF_POLICY` | requested parameters violate policy/host bounds |
| -32011 | `UNSUPPORTED` | known feature is unavailable on this build/platform |
| -32012 | `BUSY` | conflicting vault mutation is already in progress |

Error `message` is fixed and safe for display. Optional `data` may contain only
the stable name and non-sensitive fields such as a logical path or current
etag; it never contains password, content, keys, tokens, raw request objects,
physical paths outside the vault, or cryptographic failure details.

## Ordering and cancellation

Mutations are serialized per vault and protected by an OS-backed cross-process
lock. Clients may pipeline requests with unique IDs; responses may be out of
order. A later protocol revision may add explicit
cancellation, but KDF and atomic commit are non-interruptible once entered.
Clients must treat disconnect during a mutation as an unknown outcome and
re-read metadata rather than retrying a write blindly.
