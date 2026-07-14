# Inex Product Requirements (MVP/GA)

## Product statement

Inex lets a person edit a Git-synchronized Markdown journal in VS Code or
Sublime Text while keeping every managed Markdown body encrypted at rest.
Vault metadata, directory names, file basenames, sizes, timestamps, and Git
history shape remain visible in v1. The editor renders a controlled plaintext
view backed by a local Rust sidecar; it never works from a plaintext mirror
directory.

## Personas and primary workflow

The primary user maintains a multi-folder personal journal or knowledge base
on Windows and Linux and uses Git for history/synchronization.

1. Open the real ciphertext repository in the editor.
2. Unlock it once for the current sidecar session with a password.
3. Browse the logical directory tree and open a virtual Markdown document.
4. Edit, follow links, and search decrypted content in the client.
5. Save synchronously; the sidecar authenticates and atomically replaces the
   encrypted file.
6. Lock or close the editor; sessions and memory-only indexes are discarded.
7. Commit/pull/push ciphertext with ordinary Git tooling.

## Requirement tiers

### P0 — security and data integrity

| ID | Requirement | Acceptance evidence |
|----|-------------|---------------------|
| P0-01 | A wrong password never yields a master key or partial plaintext. | Core and RPC negative tests. |
| P0-02 | Normal open/edit/save/close creates no plaintext filesystem file. | E2E filesystem trace and residue audit. |
| P0-03 | Every file header and body is authenticated; corruption fails closed. | Header, AAD, nonce, tag, and truncation tests. |
| P0-04 | Save is optimistic-concurrency checked and atomically replaces ciphertext. | Stale-etag and injected-write-failure tests. |
| P0-05 | Logical paths cannot escape the vault or diverge between Windows/Linux. | Traversal, reserved-name, Unicode, and case-collision tests. |
| P0-06 | Password change rewraps the master key without rewriting file blobs. | Before/after ciphertext hash test. |
| P0-07 | Secrets/plaintext never enter normal logs or JSON-RPC error data. | Redaction tests and code audit. |
| P0-08 | Import and merge failures preserve their source inputs. | Fault-injection and hash-before/after tests. |

### P1 — usable encrypted journal

| ID | Requirement | VS Code | Sublime |
|----|-------------|---------|---------|
| P1-01 | Unlock/lock and clear session state. | Required | Required |
| P1-02 | Browse logical folders and files. | Tree View | Quick Panel |
| P1-03 | Open/edit/save Markdown without a plaintext mirror or plaintext editor backup. | Custom editor + encrypted draft backup | Scratch buffer + encrypted draft (experimental until residue gate passes) |
| P1-04 | Create logical Markdown files/folders and rename/delete Markdown files. Multi-file directory rename/delete is deferred. | Required | Command based |
| P1-05 | Search plaintext using a memory-only index. | Secure extension panel | Results Quick Panel |
| P1-06 | Follow relative Markdown/wiki links and headings. | Custom-editor navigation/buttons | Commands |
| P1-07 | Detect or clearly warn about editor persistence risks. | Required | Required |
| P1-08 | Work with normal Git status/commit/pull/push on ciphertext. | Native Git workspace | External/native Git |

### P2 — delivery and recovery

- CLI creation, unlock verification, password change, integrity verification,
  safe plaintext import, and custom Git merge driver.
- Encrypted unresolved merge results that can be resolved in an editor client.
- Linux/Windows x64 and arm64 build matrix, platform-specific VSIX packages,
  Sublime package, format fixtures, upgrade notes, and recovery documentation.

## Deferred features

- encrypted filenames/directories;
- attachment streaming/chunked encryption;
- encrypted on-disk search index;
- multi-file directory rename/delete transactions;
- a bulk plaintext export command;
- OS keychain persistence and a multi-process shared unlock daemon;
- VS Code proposed/native Search provider integration;
- advanced resistance to memory/swap/dump inspection.

## Planned Umbra private annotations

The next privacy-focused milestone is specified in
[Umbra Mode and Private Annotation System](prd-umbra-mode.md). It introduces
encrypted private slots, tag catalogs, and annotation profiles only after a
dedicated K_umbra storage/RPC contract is frozen. In particular, private tags
and profile metadata are never allowed into the existing Outer projection,
search index, settings, or logs.

## Non-functional requirements

- Format and RPC versions are explicit; unknown major versions fail closed.
- The core owns all cryptography and path validation. Clients cannot select
  algorithms, nonces, file keys, or physical ciphertext paths.
- The RPC handler is transport-neutral; MVP uses Content-Length framed JSON-RPC
  on stdio and can later be hosted on Unix sockets/named pipes.
- KDF work must not block editor UI threads. Unlock progress can be cancelled
  only before or after the non-interruptible library call.
- Errors are stable machine-readable codes with human-safe messages.
- A vault remains structurally verifiable and administrable from the CLI
  without either editor. Plaintext export is not implemented in v1.
- Initial GA support is local filesystems only; network filesystem locking and
  replace semantics are not assumed safe.

## Release gate

The project must retain its pre-alpha warning until P0-01 through P0-08 pass,
cross-platform CI consumes the same frozen EDRY fixtures, an editor residue
audit is documented, and import/restore is proven on a disposable vault.
