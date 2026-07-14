local rpc = require("inex.rpc")

local M = {}
local configuration = { sidecar_path = "", vault_path = "" }
local session = nil
local documents = {}
local tree_buffers = {}
local search_buffers = {}
local MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
local MAX_DOCUMENT_BASE64_BYTES = 4 * math.ceil(MAX_DOCUMENT_BYTES / 3)
local MAX_TREE_ENTRIES = 100000
local SESSION_RE = "^[A-Za-z0-9_-]+$"
local ETAG_RE = "^sha256:[a-f0-9]+$"
local HELLO_PARAMS = { client = "neovim", clientVersion = "0.1.0", protocolMajor = 1 }

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

local function decode_base64url(value)
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
  wipe_search_buffers()
  wipe_tree_buffers()
  wipe_documents()
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
  wipe_search_buffers()
  wipe_tree_buffers()
  wipe_documents()
  local active_session = session
  session = nil
  if active_session and rpc.started() then
    rpc.request("vault.lock", { session = active_session }, function(_, error)
      vim.notify(error or "Inex Outer vault locked", error and vim.log.levels.ERROR or vim.log.levels.INFO)
    end)
  end
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

function M.is_managed_buffer(buffer)
  return documents[buffer] ~= nil
end

function M.is_tree_buffer(buffer)
  return tree_buffers[buffer] ~= nil
end

function M.is_search_buffer(buffer)
  return search_buffers[buffer] ~= nil
end

return M
