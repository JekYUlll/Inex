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

vim.api.nvim_create_user_command("InexUmbraStatus", function()
  inex.umbra_status()
end, { desc = "Show Inex Umbra lock status" })

vim.api.nvim_create_user_command("InexUnlockUmbra", function()
  inex.unlock_umbra()
end, { desc = "Initialize or unlock the independent Inex Umbra keyslot" })

vim.api.nvim_create_user_command("InexLockUmbra", function()
  inex.lock_umbra()
end, { desc = "Lock Inex Umbra while keeping the Outer vault unlocked" })

vim.api.nvim_create_user_command("InexEnableUmbra", function()
  inex.enable_umbra()
end, { desc = "Enable Umbra private annotations for this vault" })

vim.api.nvim_create_user_command("InexOpenUmbra", function(arguments)
  inex.open_umbra_document(arguments.args)
end, { nargs = 1, desc = "Open a read-only Inex Umbra projection" })

vim.api.nvim_create_user_command("InexConvertUmbra", function()
  inex.convert_current_document_to_umbra()
end, { desc = "Convert the current saved Inex document to Umbra" })

vim.api.nvim_create_user_command("InexTogglePrivateAnnotation", function()
  inex.toggle_private_annotation()
end, { range = false, desc = "Toggle the visual Inex private annotation" })

vim.api.nvim_create_user_command("InexApplyDefaultPrivateAnnotation", function(arguments)
  if #arguments.fargs ~= 2 then
    vim.notify("InexApplyDefaultPrivateAnnotation requires startByte and endByte", vim.log.levels.ERROR)
    return
  end
  inex.apply_default_private_annotation({{
    startByte = tonumber(arguments.fargs[1]), endByte = tonumber(arguments.fargs[2]),
  }})
end, { nargs = "*", desc = "Apply the encrypted Umbra default annotation" })

vim.api.nvim_create_user_command("InexChoosePrivateAnnotationProfile", function(arguments)
  if #arguments.fargs ~= 2 then
    vim.notify("InexChoosePrivateAnnotationProfile requires startByte and endByte", vim.log.levels.ERROR)
    return
  end
  inex.choose_private_annotation_profile({{
    startByte = tonumber(arguments.fargs[1]), endByte = tonumber(arguments.fargs[2]),
  }})
end, { nargs = "*", desc = "Choose an encrypted Umbra annotation profile" })

vim.api.nvim_create_user_command("InexChoosePrivateAnnotation", function(arguments)
  if #arguments.fargs ~= 2 then
    vim.notify("InexChoosePrivateAnnotation requires startByte and endByte", vim.log.levels.ERROR)
    return
  end
  inex.choose_private_annotation({{
    startByte = tonumber(arguments.fargs[1]), endByte = tonumber(arguments.fargs[2]),
  }})
end, { nargs = "*", desc = "Choose an encrypted Umbra annotation" })

vim.api.nvim_create_user_command("InexApplyPrivateAnnotationProfile", function(arguments)
  if #arguments.fargs ~= 3 then
    vim.notify("InexApplyPrivateAnnotationProfile requires startByte endByte profileId", vim.log.levels.ERROR)
    return
  end
  inex.apply_private_annotation_profile({{
    startByte = tonumber(arguments.fargs[1]), endByte = tonumber(arguments.fargs[2]),
  }}, arguments.fargs[3])
end, { nargs = "*", desc = "Apply an encrypted Umbra annotation profile" })

vim.api.nvim_create_user_command("InexApplyPrivateAnnotation", function(arguments)
  if #arguments.fargs ~= 2 then
    vim.notify("InexApplyPrivateAnnotation requires startByte and endByte", vim.log.levels.ERROR)
    return
  end
  local start_byte, end_byte = tonumber(arguments.fargs[1]), tonumber(arguments.fargs[2])
  inex.apply_private_annotation(
    {{ startByte = start_byte, endByte = end_byte }},
    { kind = "comment", tagIds = {}, outer = { mode = "drop" } }
  )
end, { nargs = "*", desc = "Apply a default private annotation to a byte range" })

vim.api.nvim_create_user_command("InexRemovePrivateAnnotation", function(arguments)
  if #arguments.fargs ~= 2 then
    vim.notify("InexRemovePrivateAnnotation requires startByte and endByte", vim.log.levels.ERROR)
    return
  end
  local start_byte, end_byte = tonumber(arguments.fargs[1]), tonumber(arguments.fargs[2])
  inex.remove_private_annotation({{ startByte = start_byte, endByte = end_byte }})
end, { nargs = "*", desc = "Remove a private annotation from a complete byte range" })

vim.api.nvim_create_user_command("InexEditPrivateAnnotation", function(arguments)
  if #arguments.fargs ~= 2 then
    vim.notify("InexEditPrivateAnnotation requires startByte and endByte", vim.log.levels.ERROR)
    return
  end
  inex.edit_private_annotation(
    {{ startByte = tonumber(arguments.fargs[1]), endByte = tonumber(arguments.fargs[2]) }},
    { kind = "comment", tagIds = {}, outer = { mode = "drop" } }
  )
end, { nargs = "*", desc = "Edit a private annotation with the default spec" })

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

vim.api.nvim_create_user_command("InexMkdir", function(arguments)
  inex.create_directory(arguments.args)
end, { nargs = 1, desc = "Create an Inex directory through the local sidecar" })

vim.api.nvim_create_user_command("InexSave", function()
  inex.save_buffer()
end, { desc = "Save the current Inex document through the local sidecar" })

vim.api.nvim_create_user_command("InexStop", function()
  inex.stop()
end, { desc = "Stop and clear the Inex local sidecar" })
