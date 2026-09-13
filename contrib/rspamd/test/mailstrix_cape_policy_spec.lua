#!/usr/bin/env lua
-- Load the actual plugin with mocked Rspamd APIs. This proves plugin behavior,
-- not UCL conversion, rspamadm configtest, or daemon process startup rejection.
local here = arg[0]:match("^(.*)/[^/]*$") or "."
local plugin = arg[1] or here .. "/../plugins/mailstrix.lua"
local preflight = arg[2] or here .. "/../mailstrix-preflight.lua"
local function noop() end
package.loaded.rspamd_logger = { errx = noop, warnx = noop, infox = noop }
package.loaded.rspamd_regexp = { create_cached = function() return {} end }
package.loaded.rspamd_util = {}
package.loaded.lua_util = {
  override_defaults = function(defaults, opts)
    -- Retain default on type mismatch, exercising validation of the raw value.
    for k, v in pairs(opts) do
      if type(v) == type(defaults[k]) then defaults[k] = v end
    end
    return defaults
  end,
}

local function test(name, opts, valid, disabled)
  local errors, symbols, requests, results = {}, {}, {}, {}
  package.loaded.lua_cfg_utils = {
    push_config_error = function(module, err)
      assert(module == "mailstrix")
      errors[#errors + 1] = err
    end,
  }
  package.loaded.rspamd_http = {
    request = function(req)
      requests[#requests + 1] = req
      req.callback(nil, 200, "synthetic response")
      return true
    end,
  }
  package.loaded.ucl = {
    parser = function()
      return {
        parse_string = function() return true end,
        get_object = function() return { matches = { { rule = "trojan_test" } } } end,
      }
    end,
  }
  rspamd_config = {
    get_all_opt = function() return opts end,
    register_symbol = function(_, sym) symbols[#symbols + 1] = sym; return #symbols end,
  }
  -- Invalid policy must not even attempt token_file resolution.
  local env = setmetatable({
    io = { open = function() error("unexpected token file access: " .. name) end },
  }, { __index = _G })
  local chunk = assert(loadfile(preflight, "t", env))
  if setfenv then setfenv(chunk, env) end -- Lua 5.1 ignores loadfile's environment argument.
  if getfenv then assert(getfenv(chunk) == env, "preflight environment isolation") end
  local preflight_ok, preflight_err = pcall(chunk)
  assert(preflight_ok == valid, name .. ": preflight validity mismatch: " .. tostring(preflight_err))
  if not valid then
    assert(tostring(preflight_err):find("unsupported cape_policy: adapter requires static-only", 1, true),
        name .. ": preflight must raise policy error")
    assert(#errors == 1, name .. ": preflight must record config error")
  end
  assert(#symbols == 0 and #requests == 0, name .. ": preflight must only validate")
  errors = {}
  chunk = assert(loadfile(plugin, "t", env))
  if setfenv then setfenv(chunk, env) end
  if getfenv then assert(getfenv(chunk) == env, "plugin environment isolation") end
  local ok, err = pcall(chunk)
  assert(ok == valid, name .. ": plugin validity mismatch: " .. tostring(err))
  if not valid then
    assert(tostring(err):find("unsupported cape_policy: adapter requires static-only", 1, true),
        name .. ": plugin must raise policy error")
    assert(#errors == 1 and errors[1] == "unsupported cape_policy: adapter requires static-only",
        name .. ": unsupported policy must record config error")
    assert(#symbols == 0 and #requests == 0, name .. ": invalid policy registered or requested")
  elseif disabled then
    assert(#errors == 0 and #symbols == 0 and #requests == 0, name .. ": disabled behavior changed")
  else
    assert(#errors == 0 and #symbols == 10, name .. ": supported policy registration changed")
    symbols[1].callback({
      get_user = noop,
      get_content = function() return "synthetic mail" end,
      get_parts = function() return {} end,
      insert_result = function(_, sym) results[#results + 1] = sym end,
    })
    assert(#requests == 1 and requests[1].url == "http://127.0.0.1:8079/scan"
        and requests[1].body == "synthetic mail" and requests[1].method == "POST",
        name .. ": expected one static scan only")
    assert(#results == 1 and results[1] == "STRIX_MALWARE", name .. ": static action changed")
  end
end

test("absent section", nil, true)
test("default", {}, true)
test("empty", { cape_policy = "" }, true)
test("static-only", { cape_policy = "static-only" }, true)
test("disabled", { scan_message = false, scan_parts = false }, true, true)
for _, policy in ipairs({ "quarantine", "quarantine-pending", "tempfail", "typo", " static-only",
  "STATIC-ONLY", false, true, 0, {}, { "static-only" } }) do
  test("invalid " .. type(policy) .. " " .. tostring(policy), { cape_policy = policy }, false)
end
test("invalid before secret", { cape_policy = "tempfail", token_file = "unused-synthetic-path" }, false)
test("invalid even disabled", { cape_policy = "tempfail", scan_message = false, scan_parts = false }, false)
print("mailstrix_cape_policy_spec: OK (mock APIs; no real Rspamd process proof)")
