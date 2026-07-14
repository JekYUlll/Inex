if vim.g.loaded_inex_plugin then
  return
end
vim.g.loaded_inex_plugin = true

local inex = require("inex")

vim.api.nvim_create_user_command("InexStart", function()
  inex.start()
end, { desc = "Start the Inex local sidecar" })

vim.api.nvim_create_user_command("InexStatus", function()
  inex.status()
end, { desc = "Show Inex sidecar status" })

vim.api.nvim_create_user_command("InexUnlock", function()
  inex.unlock()
end, { desc = "Unlock an Inex Outer vault" })

vim.api.nvim_create_user_command("InexLock", function()
  inex.lock()
end, { desc = "Lock Inex Outer vault and wipe managed buffers" })

vim.api.nvim_create_user_command("InexOpen", function(arguments)
  inex.open_document(arguments.args)
end, { nargs = 1, desc = "Open an Inex Markdown document" })

vim.api.nvim_create_user_command("InexBrowse", function()
  inex.browse()
end, { desc = "Browse the unlocked Inex vault in a wipe-on-lock buffer" })

vim.api.nvim_create_user_command("InexSearch", function()
  inex.search()
end, { desc = "Search the unlocked Inex vault with a masked query prompt" })

vim.api.nvim_create_user_command("InexNew", function(arguments)
  inex.create_document(arguments.args)
end, { nargs = 1, desc = "Create and open an empty Inex Markdown document" })

vim.api.nvim_create_user_command("InexSave", function()
  inex.save_buffer()
end, { desc = "Save the current Inex document through the local sidecar" })

vim.api.nvim_create_user_command("InexStop", function()
  inex.stop()
end, { desc = "Stop and clear the Inex local sidecar" })
