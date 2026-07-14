local uv = vim.uv

local M = {}
local MAX_FRAME_BYTES = 24 * 1024 * 1024
local MAX_HEADER_BYTES = 8 * 1024

local state = {
  handle = nil,
  stdin = nil,
  stdout = nil,
  buffer = "",
  next_id = 1,
  pending = {},
}

local function fail_all(message)
  for _, callback in pairs(state.pending) do
    callback(nil, message)
  end
  state.pending = {}
end

local function reset(message)
  if state.stdout then
    state.stdout:read_stop()
    state.stdout:close()
  end
  if state.stdin then
    state.stdin:close()
  end
  if state.handle then
    state.handle:close()
  end
  state.handle, state.stdin, state.stdout = nil, nil, nil
  state.buffer = ""
  fail_all(message)
end

local function parse_frames()
  while true do
    local boundary = state.buffer:find("\r\n\r\n", 1, true)
    if not boundary then
      if #state.buffer > MAX_HEADER_BYTES then
        reset("Inex RPC header exceeds its limit")
      end
      return
    end
    local header = state.buffer:sub(1, boundary + 3)
    local length = header:match("^Content%-Length:%s*(%d+)\r\n\r\n$")
    if not length then
      reset("Inex RPC response header is invalid")
      return
    end
    length = tonumber(length)
    if not length or length > MAX_FRAME_BYTES then
      reset("Inex RPC response exceeds its limit")
      return
    end
    local frame_end = boundary + 3 + length
    if #state.buffer < frame_end then
      return
    end
    local body = state.buffer:sub(boundary + 4, frame_end)
    state.buffer = state.buffer:sub(frame_end + 1)
    local ok, response = pcall(vim.json.decode, body)
    if not ok or type(response) ~= "table" or response.jsonrpc ~= "2.0" or type(response.id) ~= "number" then
      reset("Inex RPC response is invalid")
      return
    end
    local callback = state.pending[response.id]
    state.pending[response.id] = nil
    if callback then
      if response.error then
        callback(nil, "Inex RPC request failed")
      elseif response.result == nil then
        callback(nil, "Inex RPC result is missing")
      else
        callback(response.result, nil)
      end
    end
  end
end

function M.started()
  return state.handle ~= nil
end

function M.start(path, on_ready)
  if M.started() then
    on_ready(true, nil)
    return
  end
  if type(path) ~= "string" or path:sub(1, 1) ~= "/" then
    on_ready(false, "inex.sidecar_path must be an absolute path")
    return
  end
  local stat = uv.fs_stat(path)
  if not stat or stat.type ~= "file" then
    on_ready(false, "Inex sidecar is not a regular file")
    return
  end
  local stdin, stdout = uv.new_pipe(false), uv.new_pipe(false)
  local handle, spawn_error = uv.spawn(path, { stdio = { stdin, stdout, nil } }, function()
    vim.schedule(function()
      reset("Inex sidecar exited")
    end)
  end)
  if not handle then
    stdin:close()
    stdout:close()
    on_ready(false, spawn_error or "Inex sidecar failed to start")
    return
  end
  state.handle, state.stdin, state.stdout = handle, stdin, stdout
  stdout:read_start(function(error, data)
    if error then
      vim.schedule(function()
        reset("Inex sidecar output failed")
      end)
    elseif data then
      state.buffer = state.buffer .. data
      vim.schedule(parse_frames)
    end
  end)
  on_ready(true, nil)
end

function M.request(method, params, callback)
  if not M.started() then
    callback(nil, "Inex sidecar is not running")
    return
  end
  if type(method) ~= "string" or type(params) ~= "table" then
    callback(nil, "Inex RPC request is invalid")
    return
  end
  local id = state.next_id
  state.next_id = state.next_id + 1
  local ok, body = pcall(vim.json.encode, { jsonrpc = "2.0", id = id, method = method, params = params })
  if not ok or #body > MAX_FRAME_BYTES then
    callback(nil, "Inex RPC request is invalid")
    return
  end
  state.pending[id] = callback
  state.stdin:write("Content-Length: " .. #body .. "\r\n\r\n" .. body)
end

function M.stop()
  if M.started() then
    M.request("system.shutdown", {}, function() end)
  end
  reset("Inex sidecar was stopped")
end

return M
