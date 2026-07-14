local sidecar = vim.env.INEX_SIDECAR
assert(type(sidecar) == "string" and sidecar:sub(1, 1) == "/", "INEX_SIDECAR must be absolute")

local rpc = require("inex.rpc")
local done = false
local failed = nil

rpc.start(sidecar, function(ok, error)
  if not ok then
    failed, done = error, true
    return
  end
  rpc.request("system.hello", {
    client = "neovim-headless-test",
    clientVersion = "0.1.0",
    protocolMajor = 1,
  }, function(result, request_error)
    if request_error or type(result) ~= "table" or result.server ~= "inexd" or result.protocolMajor ~= 1 then
      failed = request_error or "Inex hello response is invalid"
    end
    rpc.stop()
    done = true
  end)
end)

assert(vim.wait(3000, function() return done end, 10), "Inex sidecar smoke timed out")
assert(not failed, failed)
