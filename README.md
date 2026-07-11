# Inex

Inex is a cross-platform encrypted Markdown journal for Windows and Linux. A
vault is a normal Git repository containing only ciphertext. Editor clients
ask a local Rust sidecar for virtual plaintext documents; saves are encrypted
before anything is written to the vault.

> **Project status:** pre-alpha. The EDRY v1 format and RPC v1 protocol are
> being implemented. Do not use the repository as the only copy of important
> data yet.

## Security boundary

Inex is designed to prevent someone who does not know the vault password from
reading journal bodies with ordinary filesystem, editor, sync, or Git tools.
It does not claim to resist a compromised administrator/kernel, live-memory
forensics, swap or crash-dump analysis, screen capture, or key logging. See
[`SECURITY.md`](SECURITY.md) for the complete boundary.

The non-negotiable storage invariant is:

> Plaintext Markdown is passed only through the editor and controlled process
> memory. Vault writes, temporary writes, Git blobs, conflict files, and
> indexes on disk contain ciphertext only.

## Planned components

- `inex-core`: Rust vault, format, cryptography, paths, search, and merge logic.
- `inexd`: local JSON-RPC sidecar shared by editor clients.
- `inex`: CLI for vault creation, verification, password changes, import, and
  Git merge-driver integration.
- `inex-git`: bounded system-Git plumbing, locked-safe driver installation,
  in-memory diff3, encrypted conflict state, and crash recovery.
- `editors/vscode`: primary VS Code client with a ciphertext-backed custom
  editor, tree, controlled navigation, encrypted backups, and secure search UI.
- `editors/sublime`: lightweight Sublime Text client with Quick Panel browsing
  and plugin-managed buffers.

## Specifications

- [Product requirements](docs/PRD.md)
- [Architecture](docs/architecture.md)
- [Editor security contract](docs/editor-security.md)
- [EDRY v1 encrypted-file format](docs/spec/edry-v1.md)
- [Vault metadata v1](docs/spec/vault-v1.md)
- [JSON-RPC v1 protocol](docs/spec/json-rpc-v1.md)
- [Copy import v1 safety and recovery contract](docs/spec/import-v1.md)
- [Git merge and recovery v1 contract](docs/spec/git-merge-v1.md)
- [Acceptance matrix](docs/acceptance-matrix.md)

The implementation plan and live development record are kept in
`task_plan.md`, `findings.md`, and `progress.md`.

## License

GPL-3.0. See [`LICENSE`](LICENSE).
