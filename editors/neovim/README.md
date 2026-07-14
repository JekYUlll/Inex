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
- `:InexLock` closes daemon document handles, wipes managed buffers, then locks
  the Outer session.
- `:InexStop` terminates the local RPC process and drops pending callbacks.

The current MVP intentionally rejects feature-2/Umbra documents. Umbra, save,
search, and editable buffers follow only through the same authenticated session
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
