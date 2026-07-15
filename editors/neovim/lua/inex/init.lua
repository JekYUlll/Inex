local rpc = require("inex.rpc")

local M = {}
local configuration = { sidecar_path = "", vault_path = "" }
local session = nil
local umbra_unlocked = false
local umbra_enabled = false
local documents = {}
local tree_buffers = {}
local search_buffers = {}
local private_buffers = {}
local MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
local MAX_DOCUMENT_BASE64_BYTES = 4 * math.ceil(MAX_DOCUMENT_BYTES / 3)
local MAX_TREE_ENTRIES = 100000
local SESSION_RE = "^[A-Za-z0-9_-]+$"
local ETAG_RE = "^sha256:[a-f0-9]+$"
local HELLO_PARAMS = { client = "neovim", clientVersion = "0.1.0", protocolMajor = 1 }
local decode_base64url

local function clear_document(buffer)
  local document = documents[buffer]
  documents[buffer] = nil
  if document and session and rpc.started() then
    rpc.request("document.close", { session = session, handle = document.handle }, function() end)
  end
end

local function wipe_documents()
  local buffers = {}
  for buffer, _ in pairs(documents) do
    table.insert(buffers, buffer)
  end
  for _, buffer in ipairs(buffers) do
    clear_document(buffer)
    if vim.api.nvim_buf_is_valid(buffer) then
      vim.api.nvim_buf_delete(buffer, { force = true })
    end
  end
end

local function wipe_tree_buffers()
  local buffers = {}
  for buffer, _ in pairs(tree_buffers) do
    table.insert(buffers, buffer)
  end
  for _, buffer in ipairs(buffers) do
    tree_buffers[buffer] = nil
    if vim.api.nvim_buf_is_valid(buffer) then
      vim.api.nvim_buf_delete(buffer, { force = true })
    end
  end
end

local function wipe_search_buffers()
  local buffers = {}
  for buffer, _ in pairs(search_buffers) do
    table.insert(buffers, buffer)
  end
  for _, buffer in ipairs(buffers) do
    search_buffers[buffer] = nil
    if vim.api.nvim_buf_is_valid(buffer) then
      vim.api.nvim_buf_delete(buffer, { force = true })
    end
  end
end

local function wipe_private_buffers()
  local buffers = {}
  for buffer, _ in pairs(private_buffers) do
    table.insert(buffers, buffer)
  end
  for _, buffer in ipairs(buffers) do
    private_buffers[buffer] = nil
    if vim.api.nvim_buf_is_valid(buffer) then
      vim.api.nvim_buf_delete(buffer, { force = true })
    end
  end
end

local function ensure_started(callback)
  if rpc.started() then
    callback(true)
    return
  end
  rpc.start(configuration.sidecar_path, function(ok, error)
    if not ok then
      vim.notify(error, vim.log.levels.ERROR)
      callback(false)
      return
    end
    rpc.request("system.hello", HELLO_PARAMS, function(result, request_error)
      if request_error or type(result) ~= "table" or result.server ~= "inexd" or result.protocolMajor ~= 1 then
        vim.notify(request_error or "Inex sidecar handshake failed", vim.log.levels.ERROR)
        rpc.stop()
        callback(false)
        return
      end
      callback(true)
    end)
  end)
end

local function valid_logical_path(logical_path)
  return type(logical_path) == "string"
    and logical_path:match("^[^/][^\\]*%.md$")
    and not logical_path:find("//", 1, true)
    and not logical_path:find("..", 1, true)
end

local function valid_tree_path(logical_path)
  return type(logical_path) == "string"
    and #logical_path > 0
    and #logical_path <= 4096
    and logical_path:sub(1, 1) ~= "/"
    and not logical_path:find("\\", 1, true)
    and not logical_path:find("//", 1, true)
    and not logical_path:find("..", 1, true)
    and not logical_path:find("%c")
end

local function has_exact_keys(value, expected)
  if type(value) ~= "table" then
    return false
  end
  local count = 0
  for key, _ in pairs(value) do
    if not expected[key] then
      return false
    end
    count = count + 1
  end
  return count == expected.count
end

local function valid_umbra_status(value)
  return has_exact_keys(value, { initialized = true, unlocked = true, count = 2 })
    and type(value.initialized) == "boolean"
    and type(value.unlocked) == "boolean"
    and (value.initialized or not value.unlocked)
end

local function valid_metadata(value, logical_path)
  return has_exact_keys(value, { fileId = true, logicalPath = true, createdAt = true, modifiedAt = true, flags = true, count = 5 })
    and value.logicalPath == logical_path
    and (value.flags == 0 or value.flags == 1)
    and type(value.fileId) == "string" and value.fileId:match("^[0-9a-f][0-9a-f-]+$")
    and type(value.createdAt) == "number" and type(value.modifiedAt) == "number"
    and value.createdAt % 1 == 0 and value.modifiedAt % 1 == 0
    and value.createdAt >= 0 and value.modifiedAt >= 0
end

local function metadata_reason(value, logical_path)
  if type(value) ~= "table" then return "not object" end
  if not has_exact_keys(value, { fileId = true, logicalPath = true, createdAt = true, modifiedAt = true, flags = true, count = 5 }) then return "shape" end
  if value.logicalPath ~= logical_path then return "path" end
  if value.flags ~= 0 and value.flags ~= 1 then return "flags" end
  if type(value.fileId) ~= "string" or not value.fileId:match("^[0-9a-f][0-9a-f-]+$") then return "file id" end
  if type(value.createdAt) ~= "number" or type(value.modifiedAt) ~= "number" or value.createdAt % 1 ~= 0 or value.modifiedAt % 1 ~= 0 or value.createdAt < 0 or value.modifiedAt < 0 then return "timestamps" end
  return "unknown"
end

local function valid_range(start_byte, end_byte)
  return type(start_byte) == "number" and type(end_byte) == "number"
    and start_byte % 1 == 0 and end_byte % 1 == 0
    and start_byte >= 0 and end_byte > start_byte and end_byte <= MAX_DOCUMENT_BYTES
end

local function valid_tag_id(value)
  return type(value) == "string" and value:match("^[a-z0-9][a-z0-9._-]{0,63}$") ~= nil
end

local function valid_annotation_spec(value)
  if not has_exact_keys(value, { kind = true, tagIds = true, outer = true, count = 3 })
    or (value.kind ~= "block" and value.kind ~= "comment") or type(value.tagIds) ~= "table"
    or #value.tagIds > 4096 or type(value.outer) ~= "table" then
    return false
  end
  local previous = nil
  for _, tag_id in ipairs(value.tagIds) do
    if not valid_tag_id(tag_id) or (previous and previous >= tag_id) then
      return false
    end
    previous = tag_id
  end
  if value.outer.mode == "cover" then
    return has_exact_keys(value.outer, { mode = true, coverText = true, count = 2 })
      and type(value.outer.coverText) == "string" and #value.outer.coverText > 0
      and #value.outer.coverText <= 4096 and not value.outer.coverText:find("%z")
  end
  return has_exact_keys(value.outer, { mode = true, count = 1 })
    and (value.outer.mode == "drop" or value.outer.mode == "placeholder")
end

local function valid_umbra_config(value)
  if not has_exact_keys(value, { tags = true, profiles = true, defaults = true, count = 3 })
    or type(value.tags) ~= "table" or type(value.profiles) ~= "table" or type(value.defaults) ~= "table"
    or #value.tags > 4096 or #value.profiles > 4096 then
    return false
  end
  local tags, profiles = {}, {}
  for _, tag in ipairs(value.tags) do
    if not has_exact_keys(tag, { id = true, label = true, description = true, aliases = true, sortOrder = true, defaultSelected = true, archived = true, count = 7 })
      or not valid_tag_id(tag.id) or tags[tag.id] or type(tag.label) ~= "string" or #tag.label == 0 or #tag.label > 4096
      or type(tag.description) ~= "string" or #tag.description > 16384 or type(tag.aliases) ~= "table" or #tag.aliases > 256
      or type(tag.sortOrder) ~= "number" or tag.sortOrder % 1 ~= 0 or type(tag.defaultSelected) ~= "boolean" or type(tag.archived) ~= "boolean" then return false end
    tags[tag.id] = true
  end
  local function canonical_tag_ids(ids)
    if type(ids) ~= "table" or #ids > 4096 then return false end
    local previous = nil
    for _, id in ipairs(ids) do if not tags[id] or (previous and previous >= id) then return false end; previous = id end
    return true
  end
  for _, profile in ipairs(value.profiles) do
    if not has_exact_keys(profile, { id = true, label = true, kind = true, tagIds = true, outer = true, promptForCover = true, count = 6 })
      or not valid_tag_id(profile.id) or profiles[profile.id] or type(profile.label) ~= "string" or #profile.label == 0 or #profile.label > 4096
      or (profile.kind ~= "block" and profile.kind ~= "comment") or not canonical_tag_ids(profile.tagIds)
      or (profile.outer ~= "drop" and profile.outer ~= "cover" and profile.outer ~= "placeholder") or type(profile.promptForCover) ~= "boolean"
      or ((profile.outer == "cover") ~= profile.promptForCover) then return false end
    profiles[profile.id] = true
  end
  local defaults = value.defaults
  return has_exact_keys(defaults, { kind = true, tagIds = true, outer = true, defaultProfileId = true, count = 4 })
    and (defaults.kind == "block" or defaults.kind == "comment") and canonical_tag_ids(defaults.tagIds)
    and (defaults.outer == "drop" or defaults.outer == "cover" or defaults.outer == "placeholder")
    and type(defaults.defaultProfileId) == "string" and (defaults.defaultProfileId == "" or profiles[defaults.defaultProfileId] == true)
end

-- Validate every private projection boundary before displaying it. The map is
-- deliberately not retained by this read-only MVP, so lock needs to wipe only
-- the buffer that contains the daemon-rendered projection.
local function valid_render_map(value, projection_bytes)
  if not has_exact_keys(value, { generationBase64 = true, projectionBytes = true, privateSlots = true, outerSegments = true, count = 4 })
    or type(value.generationBase64) ~= "string" or type(value.projectionBytes) ~= "number"
    or value.projectionBytes % 1 ~= 0 or value.projectionBytes ~= projection_bytes
    or value.projectionBytes < 0 or value.projectionBytes > MAX_DOCUMENT_BYTES
    or type(value.privateSlots) ~= "table" or type(value.outerSegments) ~= "table" then
    return false
  end
  local generation = decode_base64url(value.generationBase64)
  if not generation or #generation ~= 32 then
    return false
  end
  generation = ""
  if #value.privateSlots > 4096 or #value.outerSegments > 4096 then
    return false
  end
  for _, slot in ipairs(value.privateSlots) do
    if not has_exact_keys(slot, { slotId = true, startByte = true, endByte = true, count = 3 })
      or type(slot.slotId) ~= "string" or #slot.slotId == 0 or #slot.slotId > 256
      or not valid_range(slot.startByte, slot.endByte) then
      return false
    end
  end
  for _, segment in ipairs(value.outerSegments) do
    if not has_exact_keys(segment, { projectionStartByte = true, projectionEndByte = true, outerStartByte = true, outerEndByte = true, count = 4 })
      or not valid_range(segment.projectionStartByte, segment.projectionEndByte)
      or type(segment.outerStartByte) ~= "number" or type(segment.outerEndByte) ~= "number"
      or segment.outerStartByte % 1 ~= 0 or segment.outerEndByte % 1 ~= 0
      or segment.outerStartByte < 0 or segment.outerEndByte < segment.outerStartByte or segment.outerEndByte > MAX_DOCUMENT_BYTES then
      return false
    end
  end
  return true
end

local function tree_entry_label(kind, logical_path)
  if kind == "directory" then
    return "[D] " .. logical_path
  end
  if kind == "file" then
    return "[M] " .. logical_path
  end
  return "[A] " .. logical_path
end

local function encode_base64url(value)
  if type(value) ~= "string" or #value > MAX_DOCUMENT_BYTES then
    return nil
  end
  local ok, encoded = pcall(vim.base64.encode, value)
  if not ok or type(encoded) ~= "string" then
    return nil
  end
  return encoded:gsub("%+", "-"):gsub("/", "_"):gsub("=+$", "")
end

decode_base64url = function(value)
  if type(value) ~= "string" or #value > MAX_DOCUMENT_BASE64_BYTES or not value:match("^[A-Za-z0-9_-]*$") or #value % 4 == 1 then
    return nil
  end
  local padded = value:gsub("-", "+"):gsub("_", "/")
  local remainder = #padded % 4
  if remainder ~= 0 then
    padded = padded .. string.rep("=", 4 - remainder)
  end
  local ok, decoded = pcall(vim.base64.decode, padded)
  if not ok or type(decoded) ~= "string" or #decoded > MAX_DOCUMENT_BYTES then
    return nil
  end
  if encode_base64url(decoded) ~= value then
    return nil
  end
  return decoded
end

function M.setup(options)
  configuration = vim.tbl_deep_extend("force", configuration, options or {})
end

function M.start()
  ensure_started(function(ok)
    if ok then
      vim.notify("Inex sidecar is ready", vim.log.levels.INFO)
    end
  end)
end

function M.status()
  if not rpc.started() then
    vim.notify("Inex sidecar is stopped", vim.log.levels.INFO)
    return
  end
  rpc.request("system.hello", HELLO_PARAMS, function(result, error)
    vim.notify(error or (result and "Inex sidecar is ready") or "Inex sidecar status is unavailable", error and vim.log.levels.ERROR or vim.log.levels.INFO)
  end)
end

function M.stop()
  wipe_private_buffers()
  wipe_search_buffers()
  wipe_tree_buffers()
  wipe_documents()
  umbra_unlocked = false
  umbra_enabled = false
  session = nil
  rpc.stop()
end

function M.unlock(password)
  if type(configuration.vault_path) ~= "string" or configuration.vault_path:sub(1, 1) ~= "/" then
    vim.notify("inex.vault_path must be an absolute path", vim.log.levels.ERROR)
    return
  end
  ensure_started(function(ok)
    if not ok then
      return
    end
    if session then
      vim.notify("Inex vault is already unlocked", vim.log.levels.INFO)
      return
    end
    password = password or vim.fn.inputsecret("Inex Outer password: ")
    if password == "" then
      return
    end
    rpc.request("vault.unlock", { vaultPath = configuration.vault_path, password = password }, function(result, error)
      password = ""
      if error or type(result) ~= "table" or type(result.session) ~= "string" or #result.session ~= 43 or not result.session:match(SESSION_RE) then
        vim.notify(error or "Inex vault unlock failed", vim.log.levels.ERROR)
        return
      end
      session = result.session
      vim.notify("Inex Outer vault unlocked", vim.log.levels.INFO)
    end)
  end)
end

function M.lock()
  wipe_private_buffers()
  wipe_search_buffers()
  wipe_tree_buffers()
  wipe_documents()
  umbra_unlocked = false
  umbra_enabled = false
  local active_session = session
  session = nil
  if active_session and rpc.started() then
    rpc.request("vault.lock", { session = active_session }, function(_, error)
      vim.notify(error or "Inex Outer vault locked", error and vim.log.levels.ERROR or vim.log.levels.INFO)
    end)
  end
end

function M.umbra_status()
  if not session then
    vim.notify("Unlock an Inex Outer vault before checking Umbra", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("umbra.status", { session = active_session }, function(result, error)
    if error or session ~= active_session or not valid_umbra_status(result) then
      vim.notify(error or "Inex Umbra status is invalid", vim.log.levels.ERROR)
      return
    end
    umbra_unlocked = result.unlocked
    vim.notify(result.unlocked and "Inex Umbra is unlocked" or (result.initialized and "Inex Umbra is locked" or "Inex Umbra is not initialized"), vim.log.levels.INFO)
  end)
end

function M.unlock_umbra(password, initialization_confirmed)
  if not session then
    vim.notify("Unlock an Inex Outer vault before unlocking Umbra", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("umbra.status", { session = active_session }, function(status, status_error)
    if status_error or session ~= active_session or not valid_umbra_status(status) then
      vim.notify(status_error or "Inex Umbra status is invalid", vim.log.levels.ERROR)
      return
    end
    if status.unlocked then
      umbra_unlocked = true
      vim.notify("Inex Umbra is already unlocked", vim.log.levels.INFO)
      return
    end
    local initializing = not status.initialized
    if initializing and not initialization_confirmed and vim.fn.confirm("Umbra 密码无法恢复。遗忘该密码将永久失去所有 Umbra 私密内容。", "&Continue\n&Cancel", 2) ~= 1 then
      return
    end
    password = password or vim.fn.inputsecret(initializing and "Create Inex Umbra password: " or "Inex Umbra password: ")
    if password == "" then
      return
    end
    local method = initializing and "umbra.initialize" or "umbra.unlock"
    rpc.request(method, { session = active_session, password = password }, function(result, error)
      password = ""
      if error or session ~= active_session or not valid_umbra_status(result) or not result.initialized or not result.unlocked then
        vim.notify(error or "Inex Umbra unlock failed", vim.log.levels.ERROR)
        return
      end
      umbra_unlocked = true
      vim.notify("Inex Umbra unlocked", vim.log.levels.INFO)
    end)
  end)
end

function M.lock_umbra()
  if not session then
    umbra_unlocked = false
    umbra_enabled = false
    return
  end
  local active_session = session
  wipe_private_buffers()
  umbra_unlocked = false
  umbra_enabled = false
  rpc.request("umbra.lock", { session = active_session }, function(result, error)
    if error or session ~= active_session or not has_exact_keys(result, { ok = true, unlocked = true, count = 2 }) or result.ok ~= true or result.unlocked ~= false then
      vim.notify(error or "Inex Umbra lock failed", vim.log.levels.ERROR)
      return
    end
    vim.notify("Inex Umbra locked", vim.log.levels.INFO)
  end)
end

function M.enable_umbra()
  if not session or not umbra_unlocked then
    vim.notify("Unlock Inex Umbra before enabling private annotations", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("umbra.enable", { session = active_session }, function(result, error)
    if error or session ~= active_session or not umbra_unlocked
      or not has_exact_keys(result, { ok = true, durability = true, count = 2 })
      or result.ok ~= true or (result.durability ~= "synced" and result.durability ~= "notSynced") then
      vim.notify(error or "Inex Umbra enable failed", vim.log.levels.ERROR)
      return
    end
    umbra_enabled = true
    vim.notify("Inex Umbra private annotations enabled", vim.log.levels.INFO)
  end)
end

function M.load_umbra_annotation_config(callback)
  if not session or not umbra_unlocked then
    vim.notify("Unlock Inex Umbra before loading private annotations", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("umbra.config.get", { session = active_session }, function(result, error)
    if error or session ~= active_session or not umbra_unlocked or not valid_umbra_config(result) then
      vim.notify(error or "Inex Umbra catalog response is invalid", vim.log.levels.ERROR)
      return
    end
    callback(result)
  end)
end

function M.apply_default_private_annotation(selections)
  M.load_umbra_annotation_config(function(config)
    local defaults = config.defaults
    M.apply_private_annotation(selections, {
      kind = defaults.kind,
      tagIds = defaults.tagIds,
      outer = { mode = defaults.outer },
    })
    -- Do not retain catalog labels, profiles, or tag IDs after constructing the
    -- one-shot daemon request.
    config = nil
  end)
end

local function apply_profile_with_config(selections, config, profile_id)
  local profile = nil
  for _, candidate in ipairs(config.profiles) do
    if candidate.id == profile_id then
      profile = candidate
      break
    end
  end
  if not profile then
    config = nil
    vim.notify("Inex private annotation profile is unavailable", vim.log.levels.ERROR)
    return
  end
  local spec = { kind = profile.kind, tagIds = profile.tagIds, outer = { mode = profile.outer } }
  if profile.promptForCover then
    vim.ui.input({ prompt = "Public cover text: " }, function(cover_text)
      if type(cover_text) == "string" and #cover_text > 0 and #cover_text <= 4096 and not cover_text:find("%z") then
        spec.outer.coverText = cover_text
        M.apply_private_annotation(selections, spec)
      elseif cover_text ~= nil then
        vim.notify("Inex public cover text is invalid", vim.log.levels.ERROR)
      end
      cover_text, spec, config = nil, nil, nil
    end)
    return
  end
  M.apply_private_annotation(selections, spec)
  spec, config = nil, nil
end

-- Profile names and tag IDs originate only in the live Umbra RPC response.
-- They are retained by the picker callback for this one interaction and are
-- never copied into Neovim options, globals, shada, or module state.
function M.apply_private_annotation_profile(selections, profile_id)
  if not valid_tag_id(profile_id) then
    vim.notify("Inex private annotation profile ID is invalid", vim.log.levels.ERROR)
    return
  end
  M.load_umbra_annotation_config(function(config)
    apply_profile_with_config(selections, config, profile_id)
  end)
end

function M.choose_private_annotation_profile(selections)
  M.load_umbra_annotation_config(function(config)
    if #config.profiles == 0 then
      config = nil
      vim.notify("No Inex private annotation profiles are configured", vim.log.levels.WARN)
      return
    end
    vim.ui.select(config.profiles, {
      prompt = "Inex private annotation profile",
      format_item = function(profile) return profile.label end,
    }, function(profile)
      if profile then
        apply_profile_with_config(selections, config, profile.id)
      else
        config = nil
      end
    end)
  end)
end

function M.choose_private_annotation(selections)
  M.load_umbra_annotation_config(function(config)
    local state = { kind = config.defaults.kind, outer = config.defaults.outer, tags = {} }
    for _, tag_id in ipairs(config.defaults.tagIds) do state.tags[tag_id] = true end
    local function apply()
      local tag_ids = {}
      for tag_id, selected in pairs(state.tags) do if selected then table.insert(tag_ids, tag_id) end end
      table.sort(tag_ids)
      local spec = { kind = state.kind, tagIds = tag_ids, outer = { mode = state.outer } }
      if state.outer == "cover" then
        vim.ui.input({ prompt = "Public cover text: " }, function(cover_text)
          if type(cover_text) == "string" and #cover_text > 0 and #cover_text <= 4096 and not cover_text:find("%z") then
            spec.outer.coverText = cover_text
            M.apply_private_annotation(selections, spec)
          elseif cover_text ~= nil then
            vim.notify("Inex public cover text is invalid", vim.log.levels.ERROR)
          end
          cover_text, spec, state, config = nil, nil, nil, nil
        end)
      else
        M.apply_private_annotation(selections, spec)
        spec, state, config = nil, nil, nil
      end
    end
    local show_picker
    show_picker = function()
      local items = {
        { group = "kind", value = "comment", label = (state.kind == "comment" and "[x] " or "[ ] ") .. "Kind: private comment" },
        { group = "kind", value = "block", label = (state.kind == "block" and "[x] " or "[ ] ") .. "Kind: private block" },
      }
      for _, tag in ipairs(config.tags) do
        if not tag.archived then
          table.insert(items, { group = "tag", value = tag.id, label = (state.tags[tag.id] and "[x] " or "[ ] ") .. "Tag: " .. tag.label })
        end
      end
      for _, outer in ipairs({ "drop", "placeholder", "cover" }) do
        table.insert(items, { group = "outer", value = outer, label = (state.outer == outer and "[x] " or "[ ] ") .. "Outer: " .. outer })
      end
      table.insert(items, { group = "done", label = "Apply" })
      vim.ui.select(items, { prompt = "Configure Inex private annotation", format_item = function(item) return item.label end }, function(item)
        if not item then state, config = nil, nil; return end
        if item.group == "done" then apply(); return end
        if item.group == "kind" then state.kind = item.value
        elseif item.group == "outer" then state.outer = item.value
        else state.tags[item.value] = not state.tags[item.value] end
        show_picker()
      end)
    end
    show_picker()
  end)
end

local function umbra_config_mutation(method, params, success_message, callback)
  if not session or not umbra_unlocked then
    vim.notify("Unlock Inex Umbra before changing private tags", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  params.session = active_session
  rpc.request(method, params, function(result, error)
    if error or session ~= active_session or not umbra_unlocked
      or not has_exact_keys(result, { ok = true, count = 1 }) or result.ok ~= true then
      vim.notify(error or "Inex private catalog update failed", vim.log.levels.ERROR)
      return
    end
    vim.notify(success_message, vim.log.levels.INFO)
    callback()
  end)
end

-- The catalog is loaded anew after every mutation. Labels and IDs are never
-- copied into Neovim options, globals, shada, or a module cache.
function M.manage_private_tags()
  local function show_menu()
    M.load_umbra_annotation_config(function(config)
      local items = {
        { action = "create", label = "Create private tag" },
        { action = "rename", label = "Rename private tag" },
        { action = "archive", label = "Archive private tag" },
        { action = "reorder", label = "Reorder private tags" },
      }
      vim.ui.select(items, {
        prompt = "Manage Inex private tags",
        format_item = function(item) return item.label end,
      }, function(item)
        if not item then config = nil; return end
        if item.action == "create" then
          vim.ui.input({ prompt = "Private tag label: " }, function(label)
            if type(label) ~= "string" or #label == 0 or #label > 4096 or label:find("%z") then config = nil; return end
            vim.ui.input({ prompt = "Stable private tag ID: ", default = "tag" }, function(tag_id)
              if not valid_tag_id(tag_id) then vim.notify("Inex private tag ID is invalid", vim.log.levels.ERROR); config = nil; return end
              umbra_config_mutation("umbra.tag.create", {
                id = tag_id, label = label, description = "", aliases = {},
                sortOrder = (#config.tags + 1) * 10, defaultSelected = false, archived = false,
              }, "Inex private tag created", function() config = nil; show_menu() end)
            end)
          end)
          return
        end
        if #config.tags == 0 then vim.notify("No Inex private tags are configured", vim.log.levels.WARN); config = nil; return end
        vim.ui.select(config.tags, {
          prompt = "Select Inex private tag",
          format_item = function(tag) return tag.label .. (tag.archived and " (archived)" or "") end,
        }, function(tag)
          if not tag then config = nil; return end
          if item.action == "rename" then
            vim.ui.input({ prompt = "New private tag label: ", default = tag.label }, function(label)
              if type(label) ~= "string" or #label == 0 or #label > 4096 or label:find("%z") then config = nil; return end
              umbra_config_mutation("umbra.tag.rename", { tagId = tag.id, label = label }, "Inex private tag renamed", function() config = nil; show_menu() end)
            end)
          elseif item.action == "archive" then
            umbra_config_mutation("umbra.tag.archive", { tagId = tag.id }, "Inex private tag archived", function() config = nil; show_menu() end)
          else
            local reordered = {}
            for _, candidate in ipairs(config.tags) do table.insert(reordered, candidate.id) end
            local old_index
            for index, candidate in ipairs(reordered) do if candidate == tag.id then old_index = index end end
            vim.ui.input({ prompt = "New tag position (1-" .. #reordered .. "): ", default = tostring(old_index) }, function(position)
              local target = tonumber(position)
              if not target or target % 1 ~= 0 or target < 1 or target > #reordered then config = nil; return end
              table.remove(reordered, old_index); table.insert(reordered, target, tag.id)
              umbra_config_mutation("umbra.tag.reorder", { tagIds = reordered }, "Inex private tags reordered", function() config, reordered = nil, nil; show_menu() end)
            end)
          end
        end)
      end)
    end)
  end
  show_menu()
end

local function parse_umbra_projection(logical_path, result)
  if not has_exact_keys(result, { contentBase64 = true, etag = true, metadata = true, renderMap = true, count = 4 })
    or type(result.etag) ~= "string" or not result.etag:match(ETAG_RE)
    or not valid_metadata(result.metadata, logical_path) then
    return nil, "metadata " .. metadata_reason(type(result) == "table" and result.metadata or nil, logical_path)
  end
  local content = decode_base64url(result.contentBase64)
  if not content then
    return nil, "content"
  end
  if not valid_render_map(result.renderMap, #content) then
    content = ""
    return nil, "render map"
  end
  return { content = content, etag = result.etag, render_map = result.renderMap }
end

local function show_umbra_projection(logical_path, result)
  local projection = parse_umbra_projection(logical_path, result)
  if not projection then
    return nil
  end
  local buffer = vim.api.nvim_create_buf(false, true)
  vim.bo[buffer].buftype = "nofile"
  vim.bo[buffer].swapfile = false
  vim.bo[buffer].undofile = false
  vim.bo[buffer].bufhidden = "wipe"
  vim.bo[buffer].buflisted = false
  vim.bo[buffer].modeline = false
  vim.bo[buffer].modifiable = true
  vim.api.nvim_buf_set_name(buffer, "inex-umbra://" .. logical_path)
  vim.api.nvim_buf_set_lines(buffer, 0, -1, false, vim.split(projection.content, "\n", { plain = true }))
  projection.content = ""
  vim.bo[buffer].modifiable = false
  vim.bo[buffer].modified = false
  private_buffers[buffer] = { logical_path = logical_path, etag = projection.etag, render_map = projection.render_map }
  vim.api.nvim_create_autocmd("BufWipeout", { buffer = buffer, once = true, callback = function()
    private_buffers[buffer] = nil
  end })
  local opened, split_error = pcall(vim.cmd, "botright vsplit")
  if not opened then
    private_buffers[buffer] = nil
    vim.api.nvim_buf_delete(buffer, { force = true })
    vim.notify(split_error or "Inex Umbra projection window could not be opened", vim.log.levels.ERROR)
    return nil
  end
  vim.api.nvim_set_current_buf(buffer)
  return buffer
end

local function replace_umbra_projection(buffer, document, result)
  local projection, reason = parse_umbra_projection(document.logical_path, {
    contentBase64 = result.contentBase64,
    etag = result.etag,
    metadata = result.metadata,
    renderMap = result.renderMap,
  })
  if not projection then
    return false, reason
  end
  if not vim.api.nvim_buf_is_valid(buffer) or private_buffers[buffer] ~= document then
    return false, "buffer identity"
  end
  vim.bo[buffer].modifiable = true
  vim.api.nvim_buf_set_lines(buffer, 0, -1, false, vim.split(projection.content, "\n", { plain = true }))
  projection.content = ""
  vim.bo[buffer].modifiable = false
  vim.bo[buffer].modified = false
  document.etag = projection.etag
  document.render_map = projection.render_map
  return true
end

local function mutate_private_annotation(method, selections, spec)
  if not session or not umbra_unlocked then
    vim.notify("Unlock Inex Umbra before changing a private annotation", vim.log.levels.ERROR)
    return
  end
  if type(selections) ~= "table" or #selections == 0 or #selections > 4096 then
    vim.notify("Inex private annotation selections are invalid", vim.log.levels.ERROR)
    return
  end
  if spec and not valid_annotation_spec(spec) then
    vim.notify("Inex private annotation specification is invalid", vim.log.levels.ERROR)
    return
  end
  local buffer = vim.api.nvim_get_current_buf()
  local document = private_buffers[buffer]
  if not document or vim.bo[buffer].modified or not valid_render_map(document.render_map, #table.concat(vim.api.nvim_buf_get_lines(buffer, 0, -1, false), "\n")) then
    vim.notify("Current buffer is not a clean authenticated Umbra projection", vim.log.levels.ERROR)
    return
  end
  local content = table.concat(vim.api.nvim_buf_get_lines(buffer, 0, -1, false), "\n")
  local content_base64 = encode_base64url(content)
  content = ""
  if not content_base64 then
    vim.notify("Inex Umbra projection exceeds its limit", vim.log.levels.ERROR)
    return
  end
  local checked_selections = {}
  for _, selection in ipairs(selections) do
    if not has_exact_keys(selection, { startByte = true, endByte = true, count = 2 }) or not valid_range(selection.startByte, selection.endByte) then
      content_base64 = ""
      vim.notify("Inex private annotation selections are invalid", vim.log.levels.ERROR)
      return
    end
    table.insert(checked_selections, { startByte = selection.startByte, endByte = selection.endByte })
  end
  local active_session, expected_etag = session, document.etag
  local params = {
    session = active_session,
    logicalPath = document.logical_path,
    ifMatch = expected_etag,
    contentBase64 = content_base64,
    renderMap = document.render_map,
    selections = checked_selections,
    mergeAdjacent = false,
  }
  if spec then
    params.spec = spec
  end
  rpc.request(method, params, function(result, error)
    content_base64 = ""
    if error then
      vim.notify(error, vim.log.levels.ERROR)
      return
    end
    if session ~= active_session or not umbra_unlocked or private_buffers[buffer] ~= document then
      vim.notify("Inex private annotation result arrived after lock or buffer replacement", vim.log.levels.ERROR)
      return
    end
    if not has_exact_keys(result, { contentBase64 = true, etag = true, metadata = true, renderMap = true, durability = true, count = 5 })
      or (result.durability ~= "synced" and result.durability ~= "notSynced") then
      vim.notify("Inex private annotation response is invalid", vim.log.levels.ERROR)
      return
    end
    local replaced, reason = replace_umbra_projection(buffer, document, result)
    if not replaced then
      vim.notify("Inex private annotation projection is invalid: " .. (reason or "unknown"), vim.log.levels.ERROR)
      return
    end
    vim.notify("Inex private annotation updated", vim.log.levels.INFO)
  end)
end

function M.apply_private_annotation(selections, spec)
  mutate_private_annotation("umbra.annotation.apply", selections, spec)
end

function M.remove_private_annotation(selections)
  mutate_private_annotation("umbra.annotation.remove", selections, nil)
end

function M.edit_private_annotation(selections, spec)
  mutate_private_annotation("umbra.annotation.edit", selections, spec)
end

local function visual_selection_range(buffer, selection_mode)
  local start_mark = vim.api.nvim_buf_get_mark(buffer, "<")
  local end_mark = vim.api.nvim_buf_get_mark(buffer, ">")
  -- nvim_buf_get_mark returns a 1-based row and a 0-based byte column.
  local start_row, start_column = start_mark[1] - 1, start_mark[2]
  local end_row, end_column = end_mark[1] - 1, end_mark[2]
  if start_row < 0 or end_row < 0 or start_row > end_row or (start_row == end_row and start_column > end_column) then
    return nil, "mark order"
  end
  local start_offset = vim.api.nvim_buf_get_offset(buffer, start_row) + start_column
  if selection_mode == "V" then
    local line_count = vim.api.nvim_buf_line_count(buffer)
    local end_offset
    if end_row + 1 < line_count then
      end_offset = vim.api.nvim_buf_get_offset(buffer, end_row + 1)
    else
      local final_line = vim.api.nvim_buf_get_lines(buffer, end_row, end_row + 1, false)[1]
      end_offset = vim.api.nvim_buf_get_offset(buffer, end_row) + #final_line
    end
    if not valid_range(vim.api.nvim_buf_get_offset(buffer, start_row), end_offset) then
      return nil, "line range"
    end
    return { startByte = vim.api.nvim_buf_get_offset(buffer, start_row), endByte = end_offset }
  end
  local last_line = vim.api.nvim_buf_get_lines(buffer, end_row, end_row + 1, false)[1]
  if type(last_line) ~= "string" or end_column < 0 or end_column >= #last_line then
    return nil, "end column"
  end
  local next_column = vim.fn.byteidx(last_line, vim.fn.charidx(last_line, end_column) + 1)
  if next_column < 0 then
    next_column = #last_line
  end
  local end_offset = vim.api.nvim_buf_get_offset(buffer, end_row) + next_column
  if not valid_range(start_offset, end_offset) then
    return nil, "byte range"
  end
  return { startByte = start_offset, endByte = end_offset }
end

local function private_selection_class(document, selection)
  local complete = false
  for _, slot in ipairs(document.render_map.privateSlots) do
    if selection.startByte == slot.startByte and selection.endByte == slot.endByte then
      complete = true
    elseif selection.startByte >= slot.startByte and selection.endByte <= slot.endByte then
      return "inside"
    elseif selection.startByte < slot.endByte and slot.startByte < selection.endByte then
      return "partial"
    end
  end
  return complete and "complete" or "plain"
end

function M.toggle_private_annotation(selection_mode)
  if not session or not umbra_unlocked then
    vim.notify("Unlock Inex Umbra before changing a private annotation", vim.log.levels.ERROR)
    return
  end
  local buffer = vim.api.nvim_get_current_buf()
  local document = private_buffers[buffer]
  local selection, selection_error
  if document then
    selection, selection_error = visual_selection_range(buffer, selection_mode or vim.fn.visualmode())
  else
    selection_error = "buffer"
  end
  if not selection then
    vim.notify("Select one non-empty Inex Umbra range before toggling a private annotation: " .. selection_error, vim.log.levels.ERROR)
    return
  end
  local class = private_selection_class(document, selection)
  if class == "partial" then
    vim.notify("Selection partially crosses an Inex private block", vim.log.levels.ERROR)
    return
  end
  if class == "complete" then
    if vim.fn.confirm("Remove this private annotation and restore it to Umbra Markdown?", "&Remove\n&Cancel", 2) ~= 1 then
      return
    end
    M.remove_private_annotation({ selection })
    return
  end
  if class == "inside" then
    M.edit_private_annotation({ selection }, { kind = "comment", tagIds = {}, outer = { mode = "drop" } })
    return
  end
  M.apply_private_annotation({ selection }, { kind = "comment", tagIds = {}, outer = { mode = "drop" } })
end

function M.open_umbra_document(logical_path)
  if not session or not umbra_unlocked then
    vim.notify("Unlock Inex Umbra before opening a private projection", vim.log.levels.ERROR)
    return
  end
  if not valid_logical_path(logical_path) then
    vim.notify("Inex logical Markdown path is invalid", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("umbra.document.open", { session = active_session, logicalPath = logical_path }, function(result, error)
    if error or session ~= active_session or not umbra_unlocked or not show_umbra_projection(logical_path, result) then
      vim.notify(error or "Inex Umbra projection is invalid", vim.log.levels.ERROR)
    end
  end)
end

function M.convert_current_document_to_umbra()
  if not session or not umbra_unlocked or not umbra_enabled then
    vim.notify("Unlock and enable Inex Umbra before converting a document", vim.log.levels.ERROR)
    return
  end
  local buffer = vim.api.nvim_get_current_buf()
  local document = documents[buffer]
  if not document or vim.bo[buffer].modified or document.saving then
    vim.notify("Save an ordinary Inex document before converting it to Umbra", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("umbra.document.convert", { session = active_session, logicalPath = document.logical_path, ifMatch = document.etag }, function(result, error)
    if error or session ~= active_session or not umbra_unlocked or not umbra_enabled
      or type(result) ~= "table" or type(result.etag) ~= "string" or not result.etag:match(ETAG_RE)
      or not valid_metadata(result.metadata, document.logical_path)
      or (result.durability ~= "synced" and result.durability ~= "notSynced") then
      vim.notify(error or "Inex Umbra conversion failed", vim.log.levels.ERROR)
      return
    end
    rpc.request("umbra.document.open", { session = active_session, logicalPath = document.logical_path }, function(projection, open_error)
      if open_error or session ~= active_session or not umbra_unlocked or documents[buffer] ~= document then
        vim.notify(open_error or "Inex Umbra conversion projection failed; locking vault", vim.log.levels.ERROR)
        M.lock()
        return
      end
      local private_buffer = show_umbra_projection(document.logical_path, projection)
      if not private_buffer then
        vim.notify("Inex Umbra conversion projection is invalid; locking vault", vim.log.levels.ERROR)
        M.lock()
        return
      end
      clear_document(buffer)
      if vim.api.nvim_buf_is_valid(buffer) then
        vim.api.nvim_buf_delete(buffer, { force = true })
      end
    end)
  end)
end

function M.search(query)
  if not session then
    vim.notify("Unlock an Inex Outer vault before searching", vim.log.levels.ERROR)
    return
  end
  query = query or vim.fn.inputsecret("Inex search: ")
  if type(query) ~= "string" or #query == 0 or #query > 4096 or query:find("%c") then
    query = ""
    vim.notify("Inex search query is invalid", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("search.query", {
    session = active_session,
    query = query,
    limit = 100,
    caseSensitive = false,
    snippetByteLimit = 4096,
  }, function(result, error)
    query = ""
    if error or session ~= active_session or not has_exact_keys(result, { results = true, count = 1 }) or type(result.results) ~= "table" or #result.results > 100 then
      vim.notify(error or "Inex search response is invalid", vim.log.levels.ERROR)
      return
    end
    local hits = {}
    for _, hit in ipairs(result.results) do
      if not has_exact_keys(hit, { logicalPath = true, startByte = true, endByte = true, line = true, utf16Column = true, snippet = true, count = 6 }) or type(hit.logicalPath) ~= "string" or type(hit.snippet) ~= "string" or not valid_logical_path(hit.logicalPath) or #hit.snippet > 8192 or hit.snippet:find("%z") or type(hit.startByte) ~= "number" or type(hit.endByte) ~= "number" or type(hit.line) ~= "number" or type(hit.utf16Column) ~= "number" or hit.startByte < 0 or hit.endByte < hit.startByte or hit.endByte > MAX_DOCUMENT_BYTES or hit.line < 0 or hit.utf16Column < 0 or hit.startByte % 1 ~= 0 or hit.endByte % 1 ~= 0 or hit.line % 1 ~= 0 or hit.utf16Column % 1 ~= 0 then
        vim.notify("Inex search response is invalid", vim.log.levels.ERROR)
        return
      end
      table.insert(hits, {
        logical_path = hit.logicalPath,
        line = hit.line,
        utf16_column = hit.utf16Column,
        snippet = hit.snippet:gsub("%c", " "),
      })
    end
    wipe_search_buffers()
    local buffer = vim.api.nvim_create_buf(false, true)
    vim.bo[buffer].buftype = "nofile"
    vim.bo[buffer].swapfile = false
    vim.bo[buffer].undofile = false
    vim.bo[buffer].bufhidden = "wipe"
    vim.bo[buffer].buflisted = false
    vim.bo[buffer].modeline = false
    vim.bo[buffer].modifiable = true
    vim.api.nvim_buf_set_name(buffer, "inex-search://results")
    local lines = {}
    for _, hit in ipairs(hits) do
      table.insert(lines, string.format("[M] %s:%d:%d %s", hit.logical_path, hit.line + 1, hit.utf16_column, hit.snippet))
    end
    if #lines == 0 then
      lines = { "No Inex results" }
    end
    vim.api.nvim_buf_set_lines(buffer, 0, -1, false, lines)
    vim.bo[buffer].modifiable = false
    vim.bo[buffer].modified = false
    search_buffers[buffer] = hits
    vim.api.nvim_create_autocmd("BufWipeout", { buffer = buffer, once = true, callback = function()
      search_buffers[buffer] = nil
    end })
    vim.keymap.set("n", "<CR>", function()
      local line = vim.api.nvim_win_get_cursor(0)[1]
      local hit = search_buffers[buffer] and search_buffers[buffer][line]
      if hit then
        M.open_document(hit.logical_path)
      end
    end, { buffer = buffer, silent = true, desc = "Open selected Inex search result" })
    local opened, split_error = pcall(vim.cmd, "botright vsplit")
    if not opened then
      search_buffers[buffer] = nil
      vim.api.nvim_buf_delete(buffer, { force = true })
      vim.notify(split_error or "Inex search window could not be opened", vim.log.levels.ERROR)
      return
    end
    vim.api.nvim_set_current_buf(buffer)
  end)
end

function M.browse()
  if not session then
    vim.notify("Unlock an Inex Outer vault before browsing", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("vault.listTree", { session = active_session }, function(result, error)
    if error or session ~= active_session or not has_exact_keys(result, { entries = true, count = 1 }) or type(result.entries) ~= "table" or #result.entries > MAX_TREE_ENTRIES then
      vim.notify(error or "Inex vault tree response is invalid", vim.log.levels.ERROR)
      return
    end
    local entries, seen = {}, {}
    for _, entry in ipairs(result.entries) do
      if not has_exact_keys(entry, { kind = true, logicalPath = true, count = 2 }) or type(entry.kind) ~= "string" or type(entry.logicalPath) ~= "string" or (entry.kind ~= "directory" and entry.kind ~= "file" and entry.kind ~= "asset") or not valid_tree_path(entry.logicalPath) then
        vim.notify("Inex vault tree response is invalid", vim.log.levels.ERROR)
        return
      end
      local identity = entry.kind .. "\0" .. entry.logicalPath
      if seen[identity] then
        vim.notify("Inex vault tree has duplicate entries", vim.log.levels.ERROR)
        return
      end
      seen[identity] = true
      table.insert(entries, { kind = entry.kind, logical_path = entry.logicalPath })
    end
    wipe_tree_buffers()
    local buffer = vim.api.nvim_create_buf(false, true)
    vim.bo[buffer].buftype = "nofile"
    vim.bo[buffer].swapfile = false
    vim.bo[buffer].undofile = false
    vim.bo[buffer].bufhidden = "wipe"
    vim.bo[buffer].buflisted = false
    vim.bo[buffer].modeline = false
    vim.bo[buffer].modifiable = true
    vim.api.nvim_buf_set_name(buffer, "inex-tree://vault")
    local lines = {}
    for _, entry in ipairs(entries) do
      table.insert(lines, tree_entry_label(entry.kind, entry.logical_path))
    end
    vim.api.nvim_buf_set_lines(buffer, 0, -1, false, lines)
    vim.bo[buffer].modifiable = false
    vim.bo[buffer].modified = false
    tree_buffers[buffer] = entries
    vim.api.nvim_create_autocmd("BufWipeout", { buffer = buffer, once = true, callback = function()
      tree_buffers[buffer] = nil
    end })
    vim.keymap.set("n", "<CR>", function()
      local line = vim.api.nvim_win_get_cursor(0)[1]
      local entry = tree_buffers[buffer] and tree_buffers[buffer][line]
      if entry and entry.kind == "file" and valid_logical_path(entry.logical_path) then
        M.open_document(entry.logical_path)
      elseif entry then
        vim.notify("This Inex tree entry cannot be opened as a Markdown document", vim.log.levels.INFO)
      end
    end, { buffer = buffer, silent = true, desc = "Open selected Inex Markdown document" })
    local opened, split_error = pcall(vim.cmd, "botright vsplit")
    if not opened then
      tree_buffers[buffer] = nil
      vim.api.nvim_buf_delete(buffer, { force = true })
      vim.notify(split_error or "Inex tree window could not be opened", vim.log.levels.ERROR)
      return
    end
    vim.api.nvim_set_current_buf(buffer)
  end)
end

function M.open_document(logical_path)
  if not session then
    vim.notify("Unlock an Inex Outer vault before opening a document", vim.log.levels.ERROR)
    return
  end
  if not valid_logical_path(logical_path) then
    vim.notify("Inex logical Markdown path is invalid", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("document.open", { session = active_session, logicalPath = logical_path }, function(result, error)
    if error or session ~= active_session or type(result) ~= "table" then
      vim.notify(error or "Inex document open failed", vim.log.levels.ERROR)
      return
    end
    if type(result.contentBase64) ~= "string" or type(result.handle) ~= "string" or #result.handle ~= 22 or not result.handle:match(SESSION_RE) or type(result.etag) ~= "string" or not result.etag:match(ETAG_RE) or type(result.metadata) ~= "table" or result.metadata.logicalPath ~= logical_path or (result.metadata.flags ~= 0 and result.metadata.flags ~= 1) then
      vim.notify("Inex document response is invalid", vim.log.levels.ERROR)
      return
    end
    local content = decode_base64url(result.contentBase64)
    if not content then
      vim.notify("Inex document content is invalid", vim.log.levels.ERROR)
      return
    end
    local buffer = vim.api.nvim_create_buf(false, true)
    vim.bo[buffer].buftype = "acwrite"
    vim.bo[buffer].swapfile = false
    vim.bo[buffer].undofile = false
    vim.bo[buffer].bufhidden = "wipe"
    vim.bo[buffer].buflisted = false
    vim.bo[buffer].modeline = false
    vim.bo[buffer].modifiable = true
    vim.api.nvim_buf_set_name(buffer, "inex://" .. logical_path)
    vim.api.nvim_buf_set_lines(buffer, 0, -1, false, vim.split(content, "\n", { plain = true }))
    vim.bo[buffer].modified = false
    documents[buffer] = { handle = result.handle, etag = result.etag, logical_path = logical_path }
    vim.api.nvim_create_autocmd("BufWriteCmd", { buffer = buffer, callback = function()
      M.save_buffer(buffer)
    end })
    vim.api.nvim_create_autocmd("BufWipeout", { buffer = buffer, once = true, callback = function()
      clear_document(buffer)
    end })
    vim.api.nvim_set_current_buf(buffer)
  end)
end

function M.save_buffer(buffer)
  buffer = buffer or vim.api.nvim_get_current_buf()
  local document = documents[buffer]
  if not document or not session or document.saving then
    if not document then
      vim.notify("Current buffer is not an Inex document", vim.log.levels.ERROR)
    end
    return
  end
  if not vim.api.nvim_buf_is_valid(buffer) then
    return
  end
  local content = table.concat(vim.api.nvim_buf_get_lines(buffer, 0, -1, false), "\n")
  local content_base64 = encode_base64url(content)
  content = ""
  if not content_base64 then
    vim.notify("Inex document content exceeds its limit", vim.log.levels.ERROR)
    return
  end
  document.saving = true
  local active_session, expected_etag = session, document.etag
  rpc.request("file.write", {
    session = active_session,
    logicalPath = document.logical_path,
    contentBase64 = content_base64,
    ifMatch = expected_etag,
  }, function(result, error)
    content_base64 = ""
    if document then
      document.saving = false
    end
    if error or session ~= active_session or documents[buffer] ~= document or type(result) ~= "table" or type(result.etag) ~= "string" or not result.etag:match(ETAG_RE) or type(result.metadata) ~= "table" or result.metadata.logicalPath ~= document.logical_path or (result.metadata.flags ~= 0 and result.metadata.flags ~= 1) or (result.durability ~= "synced" and result.durability ~= "notSynced") then
      vim.notify(error or "Inex document save failed", vim.log.levels.ERROR)
      return
    end
    document.etag = result.etag
    if vim.api.nvim_buf_is_valid(buffer) then
      vim.bo[buffer].modified = false
    end
    vim.notify("Inex document saved", vim.log.levels.INFO)
  end)
end

function M.create_document(logical_path)
  if not session then
    vim.notify("Unlock an Inex Outer vault before creating a document", vim.log.levels.ERROR)
    return
  end
  if not valid_logical_path(logical_path) then
    vim.notify("Inex logical Markdown path is invalid", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("file.write", {
    session = active_session,
    logicalPath = logical_path,
    contentBase64 = "",
    ifNoneMatch = "*",
  }, function(result, error)
    if error or session ~= active_session or type(result) ~= "table" or type(result.etag) ~= "string" or not result.etag:match(ETAG_RE) or type(result.metadata) ~= "table" or result.metadata.logicalPath ~= logical_path or (result.metadata.flags ~= 0 and result.metadata.flags ~= 1) or (result.durability ~= "synced" and result.durability ~= "notSynced") then
      vim.notify(error or "Inex document creation failed", vim.log.levels.ERROR)
      return
    end
    M.open_document(logical_path)
  end)
end

function M.create_directory(logical_path)
  if not session then
    vim.notify("Unlock an Inex Outer vault before creating a directory", vim.log.levels.ERROR)
    return
  end
  if not valid_tree_path(logical_path) then
    vim.notify("Inex logical directory path is invalid", vim.log.levels.ERROR)
    return
  end
  local active_session = session
  rpc.request("file.mkdir", { session = active_session, logicalPath = logical_path }, function(result, error)
    if error or session ~= active_session or not has_exact_keys(result, { ok = true, count = 1 }) or result.ok ~= true then
      vim.notify(error or "Inex directory creation failed", vim.log.levels.ERROR)
      return
    end
    vim.notify("Inex directory created", vim.log.levels.INFO)
  end)
end

function M.is_unlocked()
  return session ~= nil
end

function M.is_umbra_unlocked()
  return umbra_unlocked
end

function M.is_umbra_enabled()
  return umbra_enabled
end

function M.is_managed_buffer(buffer)
  return documents[buffer] ~= nil
end

function M.is_tree_buffer(buffer)
  return tree_buffers[buffer] ~= nil
end

function M.is_search_buffer(buffer)
  return search_buffers[buffer] ~= nil
end

function M.is_umbra_buffer(buffer)
  return private_buffers[buffer] ~= nil
end

function M.private_slot_ranges(buffer)
  buffer = buffer or vim.api.nvim_get_current_buf()
  local document = private_buffers[buffer]
  if not document or not umbra_unlocked then
    return {}
  end
  local ranges = {}
  for _, slot in ipairs(document.render_map.privateSlots) do
    table.insert(ranges, { startByte = slot.startByte, endByte = slot.endByte })
  end
  return ranges
end

return M
