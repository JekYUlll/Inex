local rpc = require("inex.rpc")

local M = {}
local configuration = { sidecar_path = "", vault_path = "" }
local session = nil
local documents = {}
local MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
local MAX_DOCUMENT_BASE64_BYTES = 4 * math.ceil(MAX_DOCUMENT_BYTES / 3)
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
  wipe_documents()
  local active_session = session
  session = nil
  if active_session and rpc.started() then
    rpc.request("vault.lock", { session = active_session }, function(_, error)
      vim.notify(error or "Inex Outer vault locked", error and vim.log.levels.ERROR or vim.log.levels.INFO)
    end)
  end
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
    vim.bo[buffer].swapfile = false
    vim.bo[buffer].undofile = false
    vim.bo[buffer].bufhidden = "wipe"
    vim.bo[buffer].buflisted = false
    vim.bo[buffer].modeline = false
    vim.bo[buffer].modifiable = true
    vim.api.nvim_buf_set_name(buffer, "inex://" .. logical_path)
    vim.api.nvim_buf_set_lines(buffer, 0, -1, false, vim.split(content, "\n", { plain = true }))
    vim.bo[buffer].modifiable = false
    vim.bo[buffer].modified = false
    documents[buffer] = { handle = result.handle, etag = result.etag, logical_path = logical_path }
    vim.api.nvim_create_autocmd("BufWipeout", { buffer = buffer, once = true, callback = function()
      clear_document(buffer)
    end })
    vim.api.nvim_set_current_buf(buffer)
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
    -- The daemon accepts canonical non-empty base64url only. A newline renders
    -- as an empty Markdown buffer while preserving that protocol invariant.
    contentBase64 = "Cg",
    ifNoneMatch = "*",
  }, function(result, error)
    if error or session ~= active_session or type(result) ~= "table" or type(result.etag) ~= "string" or not result.etag:match(ETAG_RE) or type(result.metadata) ~= "table" or result.metadata.logicalPath ~= logical_path or (result.metadata.flags ~= 0 and result.metadata.flags ~= 1) or (result.durability ~= "synced" and result.durability ~= "notSynced") then
      vim.notify(error or "Inex document creation failed", vim.log.levels.ERROR)
      return
    end
    M.open_document(logical_path)
  end)
end

function M.is_unlocked()
  return session ~= nil
end

function M.is_managed_buffer(buffer)
  return documents[buffer] ~= nil
end

return M
