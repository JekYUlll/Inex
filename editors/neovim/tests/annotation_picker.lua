-- Stateful private-annotation picker regression. This replaces only the UI
-- and RPC boundaries: production code must keep encrypted catalog values
-- transient and submit one exact annotation spec on acceptance.
local inex = require("inex")

local original_load = inex.load_umbra_annotation_config
local original_apply = inex.apply_private_annotation
local original_select = vim.ui.select
local config = {
  tags = {
    { id = "family", label = "Family", description = "", aliases = {}, sortOrder = 10, defaultSelected = false, archived = false },
    { id = "relationship", label = "Relationship", description = "", aliases = {}, sortOrder = 20, defaultSelected = false, archived = false },
    { id = "archived", label = "Archived", description = "", aliases = {}, sortOrder = 30, defaultSelected = false, archived = true },
  },
  profiles = {},
  defaults = { kind = "comment", tagIds = {}, outer = "drop", defaultProfileId = "" },
}
local selections = {{ startByte = 4, endByte = 16 }}
local applied = nil
local sequence = {
  { group = "tag", value = "relationship" }, { group = "tag", value = "family" },
  { group = "kind", value = "block" }, { group = "outer", value = "placeholder" }, { group = "done" },
}
local step = 0

inex.load_umbra_annotation_config = function(callback) callback(config) end
inex.apply_private_annotation = function(actual_selections, spec)
  applied = { selections = actual_selections, spec = spec }
end
vim.ui.select = function(items, options, callback)
  assert(options.prompt == "Configure Inex private annotation", "picker prompt is invalid")
  step = step + 1
  local wanted = sequence[step]
  assert(wanted, "picker received an unexpected extra step")
  local selected = nil
  for _, item in ipairs(items) do
    assert(not item.label:find("Archived", 1, true), "archived tag leaked into picker")
    if item.group == wanted.group and item.value == wanted.value then selected = item end
  end
  assert(selected, "picker item is missing")
  callback(selected)
end

inex.choose_private_annotation(selections)
assert(step == #sequence, "picker did not complete every selection")
assert(applied and applied.selections == selections, "picker did not preserve selections")
assert(applied.spec.kind == "block", "picker kind selection was lost")
assert(applied.spec.outer.mode == "placeholder", "picker outer selection was lost")
assert(vim.deep_equal(applied.spec.tagIds, { "family", "relationship" }), "picker tags must be canonical and sorted")

local cancel_applied = false
inex.apply_private_annotation = function() cancel_applied = true end
vim.ui.select = function(_, _, callback) callback(nil) end
inex.choose_private_annotation(selections)
assert(not cancel_applied, "picker cancellation must not mutate private annotations")

vim.ui.select = original_select
inex.apply_private_annotation = original_apply
inex.load_umbra_annotation_config = original_load
