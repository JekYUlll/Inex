# Inex for Neovim — early Lua client

This is the final-priority Inex editor client. It will only communicate with
the local `inexd` JSON-RPC sidecar; it does not parse EDRY containers, derive
keys, or access `.inex` configuration directly.

Install this directory as a Neovim runtime plugin, then configure an absolute
regular sidecar path:

```lua
require("inex").setup({
  sidecar_path = "/absolute/path/to/inexd",
})
```

Commands currently available:

- `:InexStart` starts `inexd` and requires a strict `system.hello` handshake.
- `:InexStatus` rechecks the live sidecar.
- `:InexStop` terminates the local RPC process and drops pending callbacks.

The first MVP slice intentionally exposes no plaintext vault buffer, password
input, Outer mode, or Umbra mode. Those follow only through the same
authenticated session and RenderMap boundaries already used by the CLI and VS
Code clients. Do not point the plugin at a shell wrapper or a relative path.
