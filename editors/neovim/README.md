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
- `:InexMkdir path/to/directory` creates one authenticated Inex directory through
  daemon `file.mkdir`; create parent directories explicitly before using `InexNew`.
- `:InexSave` (or normal `:write`) persists the active ordinary document through
  an ETag-conditional `file.write`; the `inex://` buffer is `acwrite`, not a
  local plaintext file.
- `:InexLock` closes daemon document handles, wipes managed buffers, then locks
  the Outer session.
- `:InexUmbraStatus`, `:InexUnlockUmbra`, and `:InexLockUmbra` manage the
  independent Umbra keyslot. First initialization displays the unrecoverable
  password warning; Umbra lock leaves the Outer session available.
- `:InexEnableUmbra` enables private annotations only after Umbra is unlocked.
  `:InexConvertUmbra` converts the current saved normal document, then opens a
  daemon-rendered `inex-umbra://` projection. `:InexOpenUmbra path/to/note.md`
  opens an existing feature-2 document. These projections are read-only in this
  milestone, are nofile/unlisted/no-swap/no-undo buffers, and are wiped when
  either Umbra or Outer is locked.
- Lua callers can use `require("inex").apply_private_annotation(selections, spec)`
  and `remove_private_annotation(selections)` to forward an authenticated
  projection/ETag/RenderMap mutation to the daemon; the plugin also exposes
  `:InexApplyPrivateAnnotation startByte endByte` and
  `:InexRemovePrivateAnnotation startByte endByte` with the safe default
  `comment`/no-tags/`drop` spec. Byte-range commands are an interim testing
  surface. `:InexTogglePrivateAnnotation` consumes one non-empty visual range:
  ordinary projection text receives the same default annotation, a range that
  exactly equals a RenderMap private block requests confirmation then removes
  it, an in-block range uses the daemon edit route, and partial private overlap
  is rejected. It deliberately installs no hard-coded mapping; users may map
  the command normally. `:InexEditPrivateAnnotation startByte endByte` is the
  equivalent explicit default-spec test surface. `:InexChoosePrivateAnnotationProfile
  startByte endByte` displays profiles only from the live encrypted Umbra
  catalog; `:InexApplyPrivateAnnotationProfile startByte endByte profileId`
  permits normal user mappings. `:InexChoosePrivateAnnotation startByte endByte`
  provides the stateful kind/tag/Outer picker: kind and Outer are exclusive,
  active tags can be toggled independently, and only `Apply` sends the final
  canonical spec to the daemon. Profile and picker data is transient and is
  not cached in Neovim settings or module state.
- `:InexStop` terminates the local RPC process and drops pending callbacks.

`InexOpen`, `InexNew`, and `InexMkdir` take Inex logical paths (for example,
`entry.md`), not a local plaintext filesystem path. `InexNew` currently expects
an existing parent directory; directory browsing/creation is a later MVP
command. These commands intentionally do not offer ordinary filesystem
completion.

The current MVP renders feature-2/Umbra documents only through an authenticated
daemon projection and validates the accompanying RenderMap before display. It
does not edit/save arbitrary Umbra Markdown; private annotation mutations and
the transient picker surfaces above remain authenticated daemon operations.
Tag/profile management UI and the explicit Neovim host-residue gate remain
behind the CLI/VS Code milestones. Neovim's
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
