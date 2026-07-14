local sidecar = vim.env.INEX_SIDECAR
local vault = vim.env.INEX_TEST_VAULT
local password = vim.env.INEX_TEST_PASSWORD

assert(type(sidecar) == "string" and sidecar:sub(1, 1) == "/", "INEX_SIDECAR must be absolute")
assert(type(vault) == "string" and vault:sub(1, 1) == "/", "INEX_TEST_VAULT must be absolute")
assert(type(password) == "string" and password ~= "", "INEX_TEST_PASSWORD is required")

local inex = require("inex")
inex.setup({ sidecar_path = sidecar, vault_path = vault })
inex.unlock(password)
password = ""

assert(vim.wait(5000, inex.is_unlocked, 10), "Inex Outer vault unlock timed out")
inex.create_document("first.md")

assert(vim.wait(5000, function()
  return inex.is_managed_buffer(vim.api.nvim_get_current_buf())
end, 10), "Inex document creation/open timed out")

local buffer = vim.api.nvim_get_current_buf()
assert(vim.api.nvim_buf_get_name(buffer) == "inex://first.md", "Inex buffer name is invalid")
assert(vim.bo[buffer].swapfile == false, "Inex buffer must disable swap")
assert(vim.bo[buffer].undofile == false, "Inex buffer must disable persistent undo")
assert(vim.bo[buffer].bufhidden == "wipe", "Inex buffer must wipe when hidden")
assert(vim.bo[buffer].buflisted == false, "Inex buffer must not be listed")
assert(vim.bo[buffer].modeline == false, "Inex buffer must disable modelines")
assert(vim.bo[buffer].buftype == "acwrite", "Inex buffer must intercept writes")
assert(vim.bo[buffer].modifiable == true, "Outer MVP buffer must be editable")
assert(not vim.bo[buffer].modified, "Inex buffer must be clean after opening")
assert(vim.deep_equal(vim.api.nvim_buf_get_lines(buffer, 0, -1, false), { "" }), "new document must be empty")

vim.api.nvim_buf_set_lines(buffer, 0, -1, false, { "# Updated", "秘密 Markdown" })
assert(vim.bo[buffer].modified, "buffer edit must become dirty")
vim.cmd("write")
assert(vim.wait(5000, function() return not vim.bo[buffer].modified end, 10), "Inex save timed out")

inex.lock()
assert(not inex.is_unlocked(), "Inex lock must clear the active session before RPC completion")
assert(vim.wait(5000, function()
  return not vim.api.nvim_buf_is_valid(buffer)
end, 10), "Inex lock must wipe the managed buffer")
inex.unlock(vim.env.INEX_TEST_PASSWORD)
assert(vim.wait(5000, inex.is_unlocked, 10), "Inex Outer vault re-unlock timed out")
inex.open_document("first.md")
assert(vim.wait(5000, function()
  return inex.is_managed_buffer(vim.api.nvim_get_current_buf())
end, 10), "Inex document re-open timed out")
assert(vim.deep_equal(vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, -1, false), { "# Updated", "秘密 Markdown" }), "encrypted save must persist through lock/reopen")
inex.lock()
inex.stop()
