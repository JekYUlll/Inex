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

vim.api.nvim_create_user_command("InexStop", function()
  inex.stop()
end, { desc = "Stop and clear the Inex local sidecar" })
