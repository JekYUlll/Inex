local rpc = require("inex.rpc")

local M = {}
local configuration = { sidecar_path = "" }
local HELLO_PARAMS = { client = "neovim", clientVersion = "0.1.0", protocolMajor = 1 }

function M.setup(options)
  configuration = vim.tbl_deep_extend("force", configuration, options or {})
end

function M.start()
  rpc.start(configuration.sidecar_path, function(ok, error)
    if not ok then
      vim.notify(error, vim.log.levels.ERROR)
      return
    end
    rpc.request("system.hello", HELLO_PARAMS, function(result, request_error)
      if request_error or type(result) ~= "table" or result.server ~= "inexd" or result.protocolMajor ~= 1 then
        vim.notify(request_error or "Inex sidecar handshake failed", vim.log.levels.ERROR)
        rpc.stop()
        return
      end
      vim.notify("Inex sidecar is ready", vim.log.levels.INFO)
    end)
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
  rpc.stop()
end

return M
