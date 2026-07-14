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
inex.unlock_umbra(vim.env.INEX_TEST_UMBRA_PASSWORD, true)
assert(vim.wait(5000, inex.is_umbra_unlocked, 10), "Inex Umbra initialization/unlock timed out")
assert(inex.is_unlocked(), "Umbra unlock must retain Outer session")
inex.lock_umbra()
assert(not inex.is_umbra_unlocked(), "Umbra lock must clear local Umbra state before RPC completion")
assert(inex.is_unlocked(), "Umbra lock must retain Outer session")
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

local document_window = vim.api.nvim_get_current_win()
inex.browse()
assert(vim.wait(5000, function()
  return inex.is_tree_buffer(vim.api.nvim_get_current_buf())
end, 10), "Inex tree browse timed out")
local tree_buffer = vim.api.nvim_get_current_buf()
assert(vim.bo[tree_buffer].buftype == "nofile", "Inex tree must not be a filesystem buffer")
assert(vim.bo[tree_buffer].swapfile == false and vim.bo[tree_buffer].undofile == false and vim.bo[tree_buffer].bufhidden == "wipe" and vim.bo[tree_buffer].buflisted == false and vim.bo[tree_buffer].modeline == false and vim.bo[tree_buffer].modifiable == false, "Inex tree buffer protections are invalid")
assert(vim.deep_equal(vim.api.nvim_buf_get_lines(tree_buffer, 0, -1, false), { "[M] first.md" }), "Inex tree must contain the authenticated Markdown entry")
vim.api.nvim_set_current_win(document_window)

vim.api.nvim_buf_set_lines(buffer, 0, -1, false, { "# Updated", "秘密 Markdown" })
assert(vim.bo[buffer].modified, "buffer edit must become dirty")
vim.cmd("write")
assert(vim.wait(5000, function() return not vim.bo[buffer].modified end, 10), "Inex save timed out")

inex.search("秘密")
assert(vim.wait(5000, function()
  return inex.is_search_buffer(vim.api.nvim_get_current_buf())
end, 10), "Inex search timed out")
local search_buffer = vim.api.nvim_get_current_buf()
assert(vim.bo[search_buffer].buftype == "nofile", "Inex search must not be a filesystem buffer")
assert(vim.bo[search_buffer].swapfile == false and vim.bo[search_buffer].undofile == false and vim.bo[search_buffer].bufhidden == "wipe" and vim.bo[search_buffer].buflisted == false and vim.bo[search_buffer].modeline == false and vim.bo[search_buffer].modifiable == false, "Inex search buffer protections are invalid")
assert(vim.api.nvim_buf_get_lines(search_buffer, 0, -1, false)[1]:find("秘密 Markdown", 1, true), "Inex search must show the authenticated result")
vim.api.nvim_set_current_win(document_window)

inex.create_directory("notes")
inex.browse()
assert(vim.wait(5000, function()
  return inex.is_tree_buffer(vim.api.nvim_get_current_buf())
end, 10), "Inex updated tree browse timed out")
tree_buffer = vim.api.nvim_get_current_buf()
assert(table.concat(vim.api.nvim_buf_get_lines(tree_buffer, 0, -1, false), "\n"):find("[D] notes", 1, true), "Inex tree must show the created directory")
vim.api.nvim_set_current_win(document_window)

inex.lock()
assert(not inex.is_unlocked(), "Inex lock must clear the active session before RPC completion")
assert(vim.wait(5000, function()
  return not vim.api.nvim_buf_is_valid(buffer)
end, 10), "Inex lock must wipe the managed buffer")
assert(not vim.api.nvim_buf_is_valid(tree_buffer), "Inex lock must wipe the tree buffer")
assert(not vim.api.nvim_buf_is_valid(search_buffer), "Inex lock must wipe the search buffer")
inex.unlock(vim.env.INEX_TEST_PASSWORD)
assert(vim.wait(5000, inex.is_unlocked, 10), "Inex Outer vault re-unlock timed out")
assert(not inex.is_umbra_unlocked(), "Outer lock must clear local Umbra state")
inex.open_document("first.md")
assert(vim.wait(5000, function()
  return inex.is_managed_buffer(vim.api.nvim_get_current_buf())
end, 10), "Inex document re-open timed out")
assert(vim.deep_equal(vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, -1, false), { "# Updated", "秘密 Markdown" }), "encrypted save must persist through lock/reopen")

inex.unlock_umbra(vim.env.INEX_TEST_UMBRA_PASSWORD, true)
assert(vim.wait(5000, inex.is_umbra_unlocked, 10), "Inex Umbra re-unlock timed out")
inex.enable_umbra()
assert(vim.wait(5000, inex.is_umbra_enabled, 10), "Inex Umbra enable timed out")
buffer = vim.api.nvim_get_current_buf()
inex.convert_current_document_to_umbra()
assert(vim.wait(5000, function()
  return inex.is_umbra_buffer(vim.api.nvim_get_current_buf())
end, 10), "Inex Umbra conversion/open timed out")
local private_buffer = vim.api.nvim_get_current_buf()
assert(vim.api.nvim_buf_get_name(private_buffer) == "inex-umbra://first.md", "Inex Umbra buffer name is invalid")
assert(vim.bo[private_buffer].buftype == "nofile" and vim.bo[private_buffer].swapfile == false and vim.bo[private_buffer].undofile == false and vim.bo[private_buffer].bufhidden == "wipe" and vim.bo[private_buffer].buflisted == false and vim.bo[private_buffer].modeline == false and vim.bo[private_buffer].modifiable == false, "Inex Umbra buffer protections are invalid")
assert(vim.deep_equal(vim.api.nvim_buf_get_lines(private_buffer, 0, -1, false), { "# Updated", "秘密 Markdown" }), "Inex Umbra projection must retain the authenticated Markdown")
assert(not vim.api.nvim_buf_is_valid(buffer), "normal buffer must be wiped after Umbra conversion")
assert(vim.fn.setpos("'<", {0, 1, 1, 0}) == 0, "cannot set visual start mark")
assert(vim.fn.setpos("'>", {0, 2, #"秘密 Markdown", 0}) == 0, "cannot set visual end mark")
inex.toggle_private_annotation()
assert(vim.wait(5000, function()
  return #inex.private_slot_ranges(private_buffer) == 1
end, 10), "Inex private annotation apply timed out")
local private_ranges = inex.private_slot_ranges(private_buffer)
assert(table.concat(vim.api.nvim_buf_get_lines(private_buffer, 0, -1, false), "\n"):find(":::inex-private", 1, true), "Inex annotation must use daemon projection")
local function mark_projection_byte(name, byte_offset)
  local consumed = 0
  local lines = vim.api.nvim_buf_get_lines(private_buffer, 0, -1, false)
  for row, line in ipairs(lines) do
    if byte_offset <= consumed + #line then
      local column = byte_offset - consumed
      if column == #line then
        column = column - 1
      end
      assert(vim.fn.setpos("'" .. name, {0, row, column + 1, 0}) == 0, "cannot set visual mark")
      return
    end
    consumed = consumed + #line + 1
  end
  error("projection offset cannot be marked")
end
mark_projection_byte("<", private_ranges[1].startByte)
mark_projection_byte(">", private_ranges[1].endByte - 1)
assert(vim.api.nvim_buf_get_mark(private_buffer, "<")[1] > 0 and vim.api.nvim_buf_get_mark(private_buffer, ">")[1] > 0, "visual marks were not installed")
local original_confirm = vim.fn.confirm
vim.fn.confirm = function() return 1 end
inex.toggle_private_annotation("V")
vim.fn.confirm = original_confirm
assert(vim.wait(5000, function()
  return #inex.private_slot_ranges(private_buffer) == 0
end, 10), "Inex private annotation remove timed out")
assert(vim.deep_equal(vim.api.nvim_buf_get_lines(private_buffer, 0, -1, false), { "# Updated", "秘密 Markdown" }), "Inex annotation remove must restore daemon projection")
inex.lock_umbra()
assert(not inex.is_umbra_unlocked(), "Inex Umbra lock must clear local state")
assert(vim.wait(5000, function() return not vim.api.nvim_buf_is_valid(private_buffer) end, 10), "Inex Umbra lock must wipe private projection")
assert(inex.is_unlocked(), "Inex Umbra lock must retain Outer after projection wipe")
inex.lock()
inex.stop()
