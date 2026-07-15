# VS Code Secure Revision Compare v1

## Scope

The ordinary VS Code Source Control view continues to operate on ciphertext
files. For `*.md.enc`, its binary diff is deliberate: Inex must not register a
plaintext `TextDocument`, `FileSystemProvider`, or normal VS Code diff URI just
to make a decrypted revision readable.

This specification defines the future Inex-owned compare path for an unlocked
vault. It is a separate command, not an override of Git's SCM/diff behavior.

## User flow

`Inex: Compare Encrypted Revision…` is available only while the Outer vault is
unlocked. The command accepts exactly one active Inex Markdown custom editor
and offers only public revision selectors initially:

1. `Working copy vs HEAD`
2. `HEAD vs first parent` (disabled when HEAD has no parent)

Selecting a comparison asks the authenticated daemon to read the exact Git
blob(s), authenticate/decrypt both envelopes for the active logical path, and
return bounded comparison projections. The extension renders them in an
Inex-owned read-only webview. The view displays only fixed labels (`Working
copy`, `HEAD`, `Parent`) and line-oriented diff structure; it must never put
the selected revision, object ID, logical path, or plaintext into a URI,
window title, output channel, QuickPick detail cache, workspace state, or
native VS Code diff editor.

Closing the view, locking Outer, locking Umbra, switching vaults, daemon exit,
or an RPC protocol failure replaces it with a script-free locked page and
releases its extension-owned byte buffers.

## Umbra rules

An Umbra feature-2 document has two distinct compare scopes:

- `Outer compare` decrypts the authenticated document envelope and renders the
  public Outer projection only. It never loads `K_umbra`.
- `Umbra compare` is an explicit second choice, requires a live Umbra session,
  and compares fully unlocked Umbra projections in the same controlled
  webview.

The command must not silently upgrade an Outer compare to Umbra scope. Private
slot bodies, kind, tags, profile metadata, private timestamps, links, and
Umbra index data remain absent from Outer compare requests and responses.

## Daemon contract

The daemon, rather than the extension, owns Git subprocess execution. This
prevents an editor client from passing shell syntax, arbitrary filesystem paths,
or a plaintext temporary file to Git.

The initial RPC surface is intentionally narrow:

```text
revision.compare.outer
revision.compare.umbra
```

Required parameters are an authenticated session, canonical logical path, and
a closed `RevisionPair` enum. A v1 client cannot submit arbitrary revision
expressions, object IDs, `--pathspec`, command arguments, environment values,
or physical paths. The daemon maps a logical Markdown path to its canonical
encrypted repository path and invokes Git without a shell, bounded stdout and
stderr, interactive prompts, pager, external diff/textconv/filter helpers,
replacement refs, global/system configuration, or lazy fetch.

Every returned historical ciphertext envelope is passed through
`Vault::authenticate_committed_envelope` (or the authenticated Umbra container
path) before any projection is emitted. Missing paths, non-blob objects,
oversized output, malformed Git state, changed repository identity, failed
authentication, and unsupported document features fail closed without a
partial projection.

Responses carry two bounded `Zeroizing<String>` projections, fixed revision
roles, and no Git object identifier. The extension must validate exact response
shape and dispose these values on all error/lock paths.

## Git-state boundary

This is a read-only convenience operation, not a substitute for the existing
authenticated merge workflow. It must refuse an unsafe Git control layout,
linked/external gitdir, active merge/rebase/cherry-pick state, split index,
submodule, or non-regular encrypted target. It never writes the worktree,
index, refs, configuration, attributes, or a temporary plaintext file.

`Working copy` means the currently authenticated on-disk envelope, not an
unsaved webview model. Unsaved changes remain the custom editor's ordinary
dirty-state concern; v1 compare refuses a dirty active document rather than
copying its plaintext into another lifecycle.

## Required evidence

- Unit tests reject arbitrary revision text and physical paths before Git.
- Integration tests create a real encrypted Git vault with two commits and
  prove current/HEAD and HEAD/parent projections are correct.
- A private canary and private tag canary appear in Umbra compare only after an
  independent Umbra unlock, never in Outer compare, responses while locked,
  Git output, or logs.
- Extension Host tests prove every compare view is an Inex webview rather than
  a plaintext TextDocument/diff editor, and lock/dispose removes its content.
- Release residue scans include compare canaries in backups, Local History,
  workspace storage, logs, cache, temporary directories, and the vault.

Until this evidence exists, the package documentation must describe ordinary
VS Code SCM diff as ciphertext-only and direct users to `git` merge recovery
for historical conflict handling.
