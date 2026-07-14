# Inex for VS Code

This extension edits real `*.md.enc` files through an editable binary custom
editor. Plaintext is sent only between the local extension host, its isolated
webview, and the Rust `inexd` child process. It is never registered as a VS Code
`TextDocument` or written to a plaintext mirror.

## Current features

- Explicit vault unlock/lock with a hidden password input.
- A locked-state welcome page with explicit **Unlock** and **Initialize from an
  Existing Markdown Repository** actions; the same initializer is available by
  right-clicking a local Explorer folder, and a sole local workspace is the
  default source. Encrypted CRUD commands remain disabled until an authenticated
  vault session exists.
- Linux engineering-preview snapshot import of an existing local Markdown Git
  repository into a fresh encrypted repository through a dedicated VS Code
  process task. A fresh target must be absent; an existing real directory is
  passed only after an explicit warning so the CLI can reconcile an exact
  interrupted marker-v2 publication, while every other existing state fails
  closed. The extension
  passes an argv array directly to `inex import-repository` (never a shell
  command), so password prompts remain in the real task terminal. After a
  successful copy it offers **Open New Vault**, reloads VS Code onto the real
  ciphertext repository, and requires an explicit unlock there; it does not
  unlock the target while Explorer and Git still point at the plaintext source.
- A ciphertext-backed Tree View and editable Markdown custom editor.
- Command Palette and Tree View actions for encrypted Markdown creation,
  single-directory creation, etag-conditional rename, and non-recursive delete.
- CRUD path/name prompts are session-scoped sensitive UI; creating a document
  sends an empty Markdown payload directly to `inexd` and never creates a
  plaintext file or `TextDocument`.
- Etag-conditional encrypted saves and authenticated encrypted Hot Exit drafts.
- Startup recovery after re-unlock, including an explicit stale-draft overwrite
  confirmation when the base ciphertext changed.
- Authenticated session keepalive while editing, local idle deadline, and
  fail-closed wiping after timeout, daemon exit, protocol failure, or lock.
- In-memory search UI, heading navigation, relative Markdown/wiki links, and
  bounded backlink discovery.
- Opaque attachment discovery plus validated PNG/JPEG/WebP previews for
  relative same-vault Markdown images. Preview bytes travel in sequential
  1 MiB RPC chunks directly to a strict-CSP webview; no plaintext
  `TextDocument`, temporary file, local-resource root, or network source is
  used.
- Strict Content-Length JSON-RPC parsing, bounded request queues, and no `PATH`
  fallback for the sidecar executable.

The packaged extension expects both `inexd` and `inex` at
`bin/<platform>-<architecture>/inexd[.exe]` and
`bin/<platform>-<architecture>/inex[.exe]`. During development, set
`inex.sidecarPath` and `inex.cliPath` to absolute, regular, audited binaries
such as `/absolute/path/to/target/debug/inexd` and
`/absolute/path/to/target/debug/inex`.

## Development gates

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm build
pnpm test:extension:local
pnpm test:extension:1.125
pnpm test:extension:1.126
```

`pnpm test` covers the pure protocol, path, bounded-file, Markdown-navigation,
and child-stream layers. Extension Host and isolated-profile residue tests are
separate release gates; a green unit suite alone is not evidence that a given
VS Code build leaves no plaintext recovery/history residue.

The Linux Extension Host gate creates a clean synthetic Git repository with two
Markdown files and a valid relative PNG, imports it through the real
`inex import-repository` CLI, deletes the plaintext source, and opens the real
ciphertext vault as the only VS Code workspace. A safe observation proxy
forwards bytes unchanged to the real `inexd` while recording only RPC method
names and bounded asset-read metadata. The gate proves unlock, authenticated
asset discovery, `asset.open`/1 MiB `asset.readChunk`/`asset.close`, editor
hide-and-reveal restart, lock/shutdown ordering, encrypted CRUD, and a real EDRY
backup/recovery-and-save path. It runs with isolated HOME, XDG,
Windows-profile, temporary, user-data, extension, and vault directories, then
scans file contents, entry names, and complete stdout/stderr streams for the
dynamic canary and its UTF-8, UTF-16, base64, base64url, hex, and high-entropy
fragment forms.

The locked import Task terminal still requires a packaged Linux manual
acceptance pass because its password is deliberately read from a hidden real
TTY; the automated host must not add a password-injection backdoor. Browser
rendering itself also remains in the manual visual pass. Automated tests bind
the command contribution, path policy, Task event coordination, post-import
workspace-transition helper, real sidecar preview RPCs, image parsing,
stale-transfer rejection, and handle cleanup. The host integration invokes the
real CLI directly rather than driving the folder picker or Task UI, and must not
be described as mouse-driving the password prompt.

VS Code forces application, profile, and workspace storage to be in-memory
whenever `extensionTestsLocationURI` is present. Consequently,
`@vscode/test-electron` cannot prove cross-process dirty-tab restoration: there
is no persisted editor-layout database for a second process to restore. The
automated gate therefore verifies VS Code's real backup scheduling and the
provider's exact `backupId` recovery path, while a release audit must still run
the manual cross-restart Hot Exit matrix documented in `editor-security.md`.

## Security limitations

JavaScript strings, Chromium textarea storage, the extension host heap, and VS
Code internals cannot provide deterministic zeroization. Inex overwrites owned
`Buffer` objects and replaces webview contents with a locked page on lock as
best effort, while the Rust
sidecar owns cryptographic keys in protected memory. The threat model does not
cover malicious extensions, debugger/admin access, process dumps, swap,
hibernation, clipboard use, screen capture, or keylogging. Spellcheck is off in
the Inex editor to avoid platform spelling-service disclosure.

See [`../../docs/editor-security.md`](../../docs/editor-security.md) for the
release contract and residue-audit matrix.
