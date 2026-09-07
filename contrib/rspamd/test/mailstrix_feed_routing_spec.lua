#!/usr/bin/env lua
--[[
mailstrix_feed_routing_spec.lua — standalone test (plain lua5.4, no rspamd) that the
strixd synthetic feed rules route to their own dedicated scoring symbols instead
of falling through the generic YARA tier classification.

strixd emits synthetic rule names per feed:
  URLHAUS_*       -> URLHAUS_MALWARE_URL
  MALWAREBAZAAR_* -> MALWAREBAZAAR_MALWARE
  THREATFOX_*     -> THREATFOX_IOC      (added: was falling through to YARA tiers)

Two layers, so neither the plugin branch NOR the groups.conf weight can silently
regress:
  (1) contract mirror — route() reproduces the prefix dispatch in
      process_results and asserts each synthetic prefix lands on its feed symbol,
      NOT the generic default;
  (2) source grounding — parse the actual plugin + groups.conf and assert the
      THREATFOX_ branch exists, canary/allowlist routing exists, the symbols are
      registered, and groups.conf defines weights for them.

Run: lua5.4 rspamd/test/mailstrix_feed_routing_spec.lua   (exit 0 = pass, 1 = fail)
--]]

local failures = 0
local function check(cond, msg)
  if not cond then
    io.stderr:write("FAIL: " .. msg .. "\n")
    failures = failures + 1
  end
end

-- (1) Contract mirror. MUST stay in lockstep with the prefix dispatch in
-- mailstrix.lua process_results (sub(1,N) comparisons). Generic = default tier.
local SYM = {
  urlhaus   = "URLHAUS_MALWARE_URL",
  mbazaar   = "MALWAREBAZAAR_MALWARE",
  threatfox = "THREATFOX_IOC",
  canary    = "STRIX_CANARY",
  allow     = "STRIX_ALLOWLISTED",
  default   = "STRIX",
}
local function route(rule, meta)
  local is_canary = type(meta) == "table" and meta.mailstrix_canary == "1"
  local is_allowlisted = type(meta) == "table" and meta.mailstrix_allow == "1"
  if rule:sub(1, 8) == "URLHAUS_" then return is_canary and SYM.canary or is_allowlisted and SYM.allow or SYM.urlhaus end
  if rule:sub(1, 14) == "MALWAREBAZAAR_" then return is_canary and SYM.canary or is_allowlisted and SYM.allow or SYM.mbazaar end
  if rule:sub(1, 10) == "THREATFOX_" then return is_canary and SYM.canary or is_allowlisted and SYM.allow or SYM.threatfox end
  if is_canary then return SYM.canary end
  if is_allowlisted then return SYM.allow end
  return SYM.default
end

-- Every synthetic rule name strixd actually emits (see internal/threatfox,
-- internal/urlhaus, internal/mbazaar Rule()).
check(route("THREATFOX_IOC_URL") == SYM.threatfox, "THREATFOX_IOC_URL -> THREATFOX_IOC")
check(route("THREATFOX_IOC_DOMAIN") == SYM.threatfox, "THREATFOX_IOC_DOMAIN -> THREATFOX_IOC")
check(route("THREATFOX_IOC_URL_DEOBF") == SYM.threatfox, "THREATFOX_IOC_URL_DEOBF -> THREATFOX_IOC")
-- The regression these guards against: a feed hit landing on the generic tier.
check(route("THREATFOX_IOC_URL") ~= SYM.default, "ThreatFox must NOT fall through to generic YARA")
-- Neighbouring prefixes must not be mis-routed.
check(route("Cobalt_Strike") == SYM.default, "a normal rule still routes to the default tier")
check(route("URLHAUS_MALWARE_URL") == SYM.urlhaus, "URLhaus still routes to its own symbol")
check(route("MALWAREBAZAAR_MALWARE") == SYM.mbazaar, "MalwareBazaar still routes to its own symbol")
for _, rule in ipairs({ "URLHAUS_MALWARE_URL", "MALWAREBAZAAR_MALWARE", "THREATFOX_IOC_URL", "Normal_Yara" }) do
  check(route(rule, { mailstrix_canary = "1" }) == SYM.canary, rule .. " canary -> STRIX_CANARY")
  check(route(rule, { mailstrix_allow = "1" }) == SYM.allow, rule .. " allowlist -> STRIX_ALLOWLISTED")
  check(route(rule, { mailstrix_canary = "1", mailstrix_allow = "1" }) == SYM.canary, rule .. " canary wins over allowlist")
end

-- (2) Source grounding. Resolve paths relative to this script so it runs from
-- any CWD (CI invokes it from the repo root).
local here = arg[0]:match("^(.*)/[^/]*$") or "."
local function slurp(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local s = f:read("*a"); f:close(); return s
end

local plugin = slurp(here .. "/../plugins/mailstrix.lua")
check(plugin ~= nil, "mailstrix.lua plugin readable")
if plugin then
  check(plugin:find('"THREATFOX_"', 1, true) ~= nil, "plugin has a THREATFOX_ routing branch")
  check(plugin:find("threatfox_symbol", 1, true) ~= nil, "plugin defines threatfox_symbol")
  check(plugin:find("canary_symbol", 1, true) ~= nil, "plugin defines canary_symbol")
  check(plugin:find("mailstrix_canary", 1, true) ~= nil, "plugin routes mailstrix_canary metadata")
  check(plugin:find("is_allowlisted", 1, true) ~= nil, "plugin routes mailstrix_allow metadata")
  -- The symbol must be registered (virtual child) so rspamd scores it.
  check(plugin:find("settings.threatfox_symbol,", 1, true) ~= nil, "threatfox_symbol registered")
  check(plugin:find("settings.canary_symbol,", 1, true) ~= nil, "canary_symbol registered")
  check(plugin:find("settings.allow_symbol,", 1, true) ~= nil, "allow_symbol registered")
  -- Feodo support was removed: no FEODO_ branch / symbol may remain.
  check(plugin:find("FEODO", 1, true) == nil, "plugin has no residual FEODO reference")
  check(plugin:find("feodo", 1, true) == nil, "plugin has no residual feodo reference")
end

local groups = slurp(here .. "/../local.d/groups.conf")
check(groups ~= nil, "groups.conf readable")
local sample = slurp(here .. "/../rspamd.conf.local")
check(sample ~= nil, "rspamd.conf.local readable")
if sample and plugin and groups then
  -- Read active assignments, not comments or a mirrored default constant.
  local configured = sample:match('\n%s*symbol%s*=%s*"([%w_]+)"%s*;')
  local default = plugin:match('\n%s*symbol%s*=%s*"([%w_]+)"%s*,')
  check(configured ~= nil and configured == default,
    "sample symbol must match the plugin default")
  local block = configured and groups:match('"' .. configured .. '"%s*{([^{}]*)}')
  check(block ~= nil and block:find("weight%s*=") ~= nil,
    "sample symbol must have a weighted groups.conf entry")
end
if groups then
  -- Assert each feed symbol has a weight line within its block.
  local function has_weighted_symbol(name)
    local block = groups:match('"' .. name .. '"%s*{(.-)}')
    return block ~= nil and block:find("weight%s*=") ~= nil
  end
  check(has_weighted_symbol("THREATFOX_IOC"), "groups.conf defines a weight for THREATFOX_IOC")
  check(has_weighted_symbol("STRIX_ALLOWLISTED"), "groups.conf defines a weight for STRIX_ALLOWLISTED")
  check(has_weighted_symbol("STRIX_CANARY"), "groups.conf defines a weight for STRIX_CANARY")
  local block = groups:match('"STRIX_CANARY"%s*{(.-)}')
  check(block ~= nil and block:find("weight%s*=%s*0%.0") ~= nil, "STRIX_CANARY weight is 0.0")
  check(groups:find("FEODO", 1, true) == nil, "groups.conf has no residual FEODO symbol")
end

if failures > 0 then
  io.stderr:write(failures .. " assertion(s) failed\n")
  os.exit(1)
end
print("mailstrix_feed_routing_spec: all assertions passed")
