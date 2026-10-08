#!/usr/bin/env lua
--[[
mailstrix_degraded_spec.lua (AUD-12a) - loads the REAL rspamd plugin with mocked
Rspamd APIs and proves that a degraded /scan reply (incomplete|error|busy) with
no actionable match is reported as the zero-weight STRIX_UNKNOWN symbol (option =
reason), never silently clean, while an actionable match in a degraded reply is
still a normal detection. Transport / non-200 / parse failures are deliberately
unchanged (README contract covers only degraded replies).

Run: lua5.4 contrib/rspamd/test/mailstrix_degraded_spec.lua  (also lua5.1)
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
local function check(cond, msg)
  if not cond then
    io.stderr:write("FAIL: " .. msg .. "\n")
    failures = failures + 1
  end
end

-- replies: list of response objects, one per /scan request in order; a table
-- {err=..} / {code=..} simulates transport / HTTP failure.
local function run(replies, with_part)
  local symbols, registered = {}, {}
  local n = 0
  package.loaded.rspamd_http = {
    request = function(req)
      n = n + 1
      local r = replies[n] or { obj = { matches = {} } }
      if r.err then
        req.callback("boom", nil, nil)
      else
        req.callback(nil, r.code or 200, "synthetic")
      end
      return true
    end,
  }
  local cur
  package.loaded.ucl = {
    parser = function()
      return {
        parse_string = function() cur = replies[n]; return not (cur and cur.badjson) end,
        get_object = function() return cur.obj end,
      }
    end,
  }
  rspamd_config = {
    get_all_opt = function() return {} end,
    register_symbol = function(_, sym)
      registered[#registered + 1] = sym
      return #registered
    end,
  }
  local chunk = assert(loadfile(plugin))
  assert(pcall(chunk))
  local cb
  for _, s in ipairs(registered) do if s.callback then cb = s.callback end end
  local parts = {}
  if with_part then
    parts[1] = {
      get_content = function() return string.rep("x", 200) end,
      get_digest = function() return "d1" end,
      get_filename = function() return nil end,
    }
  end
  cb({
    get_user = noop,
    get_content = function() return "synthetic mail" end,
    get_parts = function() return parts end,
    insert_result = function(_, sym, w, opts) symbols[sym] = { w = w, opts = opts } end,
  })
  return symbols, registered
end

local function M(extra) return { matches = extra.matches or {}, degraded = extra.degraded } end
local canary = { rule = "Shadow", meta = { mailstrix_canary = "1" } }
local allow = { rule = "MAILSTRIX_SCAN_DEGRADED", meta = { mailstrix_allow = "1", reason = "busy" } }
local real = { rule = "trojan_test" }

local s, reg = run({ { obj = M({ degraded = "incomplete" }) } })
check(s.STRIX_UNKNOWN and s.STRIX_UNKNOWN.opts[1] == "incomplete", "degraded + no match -> STRIX_UNKNOWN(incomplete)")
check(s.STRIX_UNKNOWN and s.STRIX_UNKNOWN.w == 1.0, "unknown weight is 1.0 (groups.conf scores it 0)")
local found = false
for _, r in ipairs(reg) do if r.name == "STRIX_UNKNOWN" and r.type == "virtual" then found = true end end
check(found, "STRIX_UNKNOWN is registered as a virtual child symbol")

s = run({ { obj = M({ degraded = "busy" }) } })
check(s.STRIX_UNKNOWN and s.STRIX_UNKNOWN.opts[1] == "busy", "reason busy is the option")

s = run({ { obj = M({ degraded = "error", matches = { real } }) } })
check(s.STRIX_MALWARE ~= nil, "degraded + actionable match still fires the detection")
check(s.STRIX_UNKNOWN == nil, "degraded + actionable match does not raise unknown")

s = run({ { obj = M({ degraded = "error", matches = { canary } }) } })
check(s.STRIX_CANARY ~= nil and s.STRIX_UNKNOWN ~= nil, "degraded + only canary -> canary kept AND unknown")

s = run({ { obj = M({ degraded = "busy", matches = { allow } }) } })
check(s.STRIX_ALLOWLISTED ~= nil and s.STRIX_UNKNOWN ~= nil, "degraded + only log-only marker -> unknown")

s = run({ { obj = M({}) } })
check(next(s) == nil, "not degraded + no match -> nothing")

s = run({ { obj = M({ degraded = "" }) } })
check(next(s) == nil, "empty degraded string ignored")
for _, bad in ipairs({ 0, 1, true, false, { "x" } }) do
  s = run({ { obj = M({ degraded = bad }) } })
  check(next(s) == nil, "malformed degraded type ignored: " .. type(bad))
end

-- Multi-job: one job degraded, another job clean -> unknown; another actionable -> none.
s = run({ { obj = M({ degraded = "incomplete" }) }, { obj = M({}) } }, true)
check(s.STRIX_UNKNOWN ~= nil, "one degraded job among clean jobs -> unknown")
s = run({ { obj = M({ degraded = "incomplete" }) }, { obj = M({ matches = { real } }) } }, true)
check(s.STRIX_UNKNOWN == nil and s.STRIX_MALWARE ~= nil, "degraded job + actionable in another job -> detection only")

-- Unchanged behaviour: transport error / non-200 / parse failure stay silent.
s = run({ { err = true } })
check(next(s) == nil, "transport error unchanged (no symbol)")
s = run({ { code = 500, obj = M({ degraded = "error" }) } })
check(next(s) == nil, "non-200 unchanged (no symbol)")
s = run({ { badjson = true, obj = M({ degraded = "error" }) } })
check(next(s) == nil, "parse failure unchanged (no symbol)")

if failures > 0 then os.exit(1) end
print("mailstrix_degraded_spec: OK (mock APIs; no real Rspamd process proof)")
