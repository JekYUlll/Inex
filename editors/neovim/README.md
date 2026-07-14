# Inex for Neovim — early Lua client

This is the final-priority Inex editor client. It will only communicate with
the local `inexd` JSON-RPC sidecar; it does not parse EDRY containers, derive
keys, or access `.inex` configuration directly.

Install this directory as a Neovim runtime plugin, then configure an absolute
regular sidecar path:

```lua
require("inex").setup({
  sidecar_path = "/absolute/path/to/inexd",
  vault_path = "/absolute/path/to/ciphertext-vault",
})
```

Commands currently available:

- `:InexStart` starts `inexd` and requires a strict `system.hello` handshake.
- `:InexStatus` rechecks the live sidecar.
- `:InexUnlock` prompts with Neovim's `inputsecret()` and unlocks only the
  Outer session through `vault.unlock`.
- `:InexOpen path/to/note.md` opens a normal Outer Markdown projection in an
  unnamed, unlisted buffer with swap/undo persistence disabled and wipe-on-hide.
- `:InexBrowse` shows authenticated vault entries in a nofile scratch buffer;
  press Enter on a Markdown file to open it. The tree is wiped on lock/stop.
- `:InexSearch` uses a masked query prompt and displays in-memory sidecar hits
  in a wipe-on-lock nofile buffer; press Enter on a result to open its document.
- `:InexNew path/to/note.md` creates an empty ordinary Markdown document through
  daemon `file.write` and opens it with the same buffer restrictions.
- `:InexSave` (or normal `:write`) persists the active ordinary document through
  an ETag-conditional `file.write`; the `inex://` buffer is `acwrite`, not a
  local plaintext file.
- `:InexLock` closes daemon document handles, wipes managed buffers, then locks
  the Outer session.
- `:InexStop` terminates the local RPC process and drops pending callbacks.

`InexOpen` and `InexNew` take an Inex logical Markdown path (for example,
`entry.md`), not a local plaintext filesystem path. `InexNew` currently expects
an existing parent directory; directory browsing/creation is a later MVP
command. These commands intentionally do not offer ordinary filesystem
completion.

The current MVP intentionally rejects feature-2/Umbra documents. Umbra and
search follow only through the same authenticated session
and RenderMap boundaries already used by the CLI and VS Code clients. Neovim's
cmdline, undo, shada, LSP, plugins, terminal, and OS memory remain separate
residue boundaries; do not enable other plugins on an Inex buffer until the
explicit Neovim host-residue gate is implemented. Do not point the plugin at a
shell wrapper or a relative path.

Run the transport smoke with an exact sidecar binary:

```sh
INEX_SIDECAR=/absolute/path/to/inexd \
  nvim --headless --clean --cmd 'set rtp^=/path/to/Inex/editors/neovim' \
  -l /path/to/Inex/editors/neovim/tests/headless_smoke.lua
```
