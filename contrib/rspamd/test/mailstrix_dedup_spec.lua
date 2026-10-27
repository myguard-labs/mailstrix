#!/usr/bin/env lua
--[[
mailstrix_dedup_spec.lua — loads the production Rspamd plugin with mocked
Rspamd APIs and exercises its registered callback. Scanner match identity is
(namespace, rule): same-named rules from different source files must survive,
while repeated reports of the same identity must collapse.

Run: lua5.4 contrib/rspamd/test/mailstrix_dedup_spec.lua
The optional first argument selects a plugin path for isolated mutation tests.
--]]

local here = arg[0]:match("^(.*)/[^/]*$") or "."
local plugin = arg[1] or here .. "/../plugins/mailstrix.lua"
local function noop() end

package.loaded.rspamd_logger = { errx = noop, warnx = noop, infox = noop }
package.loaded.rspamd_regexp = { create_cached = function() return {} end }
package.loaded.rspamd_util = { encode_base64 = function(s) return s end }
package.loaded.lua_cfg_utils = { push_config_error = noop }
package.loaded.lua_util = {
  override_defaults = function(defaults, opts)
    for k, v in pairs(opts) do
      if type(v) == type(defaults[k]) then defaults[k] = v end
    end
    return defaults
  end,
}

local failures = 0
local assertions = 0
local function check(cond, msg)
  assertions = assertions + 1
  if not cond then
    io.stderr:write("FAIL: " .. msg .. "\n")
    failures = failures + 1
  end
end

local function run(matches)
  local callback
  local requests = 0
  local results = {}

  package.loaded.rspamd_http = {
    request = function(req)
      requests = requests + 1
      req.callback(nil, 200, "synthetic")
      return true
    end,
  }
  package.loaded.ucl = {
    parser = function()
      return {
        parse_string = function() return true end,
        get_object = function() return { matches = matches } end,
      }
    end,
  }
  rspamd_config = {
    get_all_opt = function()
      return { scan_parts = false }
    end,
    register_symbol = function(_, symbol)
      if symbol.callback then callback = symbol.callback end
      return 1
    end,
  }

  local chunk, load_err = loadfile(plugin)
  check(chunk ~= nil, "production plugin loads: " .. tostring(load_err))
  if not chunk then return results, requests end
  local ok, run_err = pcall(chunk)
  check(ok, "production plugin initializes: " .. tostring(run_err))
  check(type(callback) == "function", "production callback is registered")
  if not ok or type(callback) ~= "function" then return results, requests end

  callback({
    get_user = noop,
    get_content = function() return "synthetic mail" end,
    get_parts = function() return {} end,
    insert_result = function(_, symbol, weight, opts)
      results[symbol] = { weight = weight, opts = opts }
    end,
  })
  return results, requests
end

local function options_for(matches)
  local results, requests = run(matches)
  check(requests == 1, "production callback submits exactly one message scan")
  return results.STRIX and results.STRIX.opts or {}, results
end

-- Positive regression case: namespace is part of a scanner match's identity.
local opts = options_for({
  { rule = "http", namespace = "rulesA.yar" },
  { rule = "http", namespace = "rulesB.yar" },
})
check(#opts == 2, "same rule from different namespaces must both survive")
check(opts[1] == "http (rulesA.yar)", "first namespace remains visible")
check(opts[2] == "http (rulesB.yar)", "second namespace remains visible")

-- Duplicate reports from multiple scanned buffers collapse to one option.
opts = options_for({
  { rule = "Cobalt_Strike", namespace = "apt.yar" },
  { rule = "Cobalt_Strike", namespace = "apt.yar" },
})
check(#opts == 1, "identical namespace and rule must deduplicate")
check(opts[1] == "Cobalt_Strike (apt.yar)", "deduplicated option keeps provenance")

-- The other identity axis remains significant too.
opts = options_for({
  { rule = "alpha", namespace = "shared.yar" },
  { rule = "beta", namespace = "shared.yar" },
})
check(#opts == 2, "different rules in one namespace must both survive")

-- Boundary: absent and empty namespaces are the same normalized identity.
opts = options_for({
  { rule = "unnamed", namespace = nil },
  { rule = "unnamed", namespace = "" },
})
check(#opts == 1, "missing and empty namespaces must deduplicate")
check(opts[1] == "unnamed", "empty namespace must not add provenance text")

-- Negative: malformed scanner records without a rule never emit a result.
local _, results = options_for({
  { namespace = "rulesA.yar" },
  { namespace = "rulesB.yar", meta = { score = 100 } },
})
check(next(results) == nil, "matches without a rule must be ignored")

if failures > 0 then
  io.stderr:write(failures .. " of " .. assertions .. " assertions failed\n")
  os.exit(1)
end
print("mailstrix_dedup_spec: " .. assertions .. " production-callback assertions passed")
