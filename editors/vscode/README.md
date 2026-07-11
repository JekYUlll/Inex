# Inex for VS Code

This extension edits real `*.md.enc` files through an editable binary custom
editor. Plaintext is sent only between the local extension host, its isolated
webview, and the Rust `inexd` child process. It is never registered as a VS Code
`TextDocument` or written to a plaintext mirror.

## Current features

- Explicit vault unlock/lock with a hidden password input.
- A ciphertext-backed Tree View and editable Markdown custom editor.
- Etag-conditional encrypted saves and authenticated encrypted Hot Exit drafts.
- Startup recovery after re-unlock, including an explicit stale-draft overwrite
  confirmation when the base ciphertext changed.
- Authenticated session keepalive while editing, local idle deadline, and
  fail-closed wiping after timeout, daemon exit, protocol failure, or lock.
- In-memory search UI, heading navigation, relative Markdown/wiki links, and
  bounded backlink discovery.
- Strict Content-Length JSON-RPC parsing, bounded request queues, and no `PATH`
  fallback for the sidecar executable.

The packaged extension expects `inexd` at
`bin/<platform>-<architecture>/inexd[.exe]`. During development, set
`inex.sidecarPath` to an absolute, regular, audited binary such as
`/absolute/path/to/target/debug/inexd`.

## Development gates

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm build
pnpm test:extension:local
pnpm test:extension:1.125
```

`pnpm test` covers the pure protocol, path, bounded-file, Markdown-navigation,
and child-stream layers. Extension Host and isolated-profile residue tests are
separate release gates; a green unit suite alone is not evidence that a given
VS Code build leaves no plaintext recovery/history residue.

The Extension Host gate creates a new encrypted vault through `inex import`,
lets VS Code schedule a real EDRY custom-editor backup, and exercises the same
`openCustomDocument(...backupId...)` recovery-and-save path after locking and
re-unlocking. It runs with isolated HOME, XDG, Windows-profile, temporary,
user-data, extension, and vault directories, then scans file contents, entry
names, and complete stdout/stderr streams for the dynamic canary and its UTF-8,
UTF-16, base64, base64url, hex, and high-entropy fragment forms.

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
