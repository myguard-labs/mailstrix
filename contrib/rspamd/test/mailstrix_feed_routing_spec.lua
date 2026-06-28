#!/usr/bin/env lua
--[[
mailstrix_feed_routing_spec.lua — standalone test (plain lua5.4, no rspamd) that the
strixd synthetic feed rules route to their own dedicated scoring symbols instead
of falling through the generic YARA tier classification.

strixd emits synthetic rule names per feed:
  URLHAUS_*       -> URLHAUS_MALWARE_URL
  MALWAREBAZAAR_* -> MALWAREBAZAAR_MALWARE
  THREATFOX_*     -> THREATFOX_IOC      (added: was falling through to YARA tiers)
  FEODO_*         -> FEODO_CC_IP        (added: was falling through to YARA tiers)

Two layers, so neither the plugin branch NOR the groups.conf weight can silently
regress:
  (1) contract mirror — route() reproduces the prefix dispatch in
      process_results and asserts each synthetic prefix lands on its feed symbol,
      NOT the generic default;
  (2) source grounding — parse the actual plugin + groups.conf and assert the
      THREATFOX_/FEODO_ branches exist, the symbols are registered, and
      groups.conf defines a weight for each.

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
  feodo     = "FEODO_CC_IP",
  default   = "STRIX",
}
local function route(rule)
  if rule:sub(1, 8) == "URLHAUS_" then return SYM.urlhaus end
  if rule:sub(1, 14) == "MALWAREBAZAAR_" then return SYM.mbazaar end
  if rule:sub(1, 10) == "THREATFOX_" then return SYM.threatfox end
  if rule:sub(1, 6) == "FEODO_" then return SYM.feodo end
  return SYM.default
end

-- Every synthetic rule name strixd actually emits (see internal/threatfox,
-- internal/feodo, internal/urlhaus, internal/mbazaar Rule()).
check(route("THREATFOX_IOC_URL") == SYM.threatfox, "THREATFOX_IOC_URL -> THREATFOX_IOC")
check(route("THREATFOX_IOC_DOMAIN") == SYM.threatfox, "THREATFOX_IOC_DOMAIN -> THREATFOX_IOC")
check(route("THREATFOX_IOC_URL_DEOBF") == SYM.threatfox, "THREATFOX_IOC_URL_DEOBF -> THREATFOX_IOC")
check(route("FEODO_CC_IP") == SYM.feodo, "FEODO_CC_IP -> FEODO_CC_IP")
check(route("FEODO_CC_IP_DEOBF") == SYM.feodo, "FEODO_CC_IP_DEOBF -> FEODO_CC_IP")
-- The regression these guards against: a feed hit landing on the generic tier.
check(route("THREATFOX_IOC_URL") ~= SYM.default, "ThreatFox must NOT fall through to generic YARA")
check(route("FEODO_CC_IP") ~= SYM.default, "Feodo must NOT fall through to generic YARA")
-- Neighbouring prefixes must not be mis-routed.
check(route("Cobalt_Strike") == SYM.default, "a normal rule still routes to the default tier")
check(route("URLHAUS_MALWARE_URL") == SYM.urlhaus, "URLhaus still routes to its own symbol")
check(route("MALWAREBAZAAR_MALWARE") == SYM.mbazaar, "MalwareBazaar still routes to its own symbol")

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
  check(plugin:find('"FEODO_"', 1, true) ~= nil, "plugin has a FEODO_ routing branch")
  check(plugin:find("threatfox_symbol", 1, true) ~= nil, "plugin defines threatfox_symbol")
  check(plugin:find("feodo_symbol", 1, true) ~= nil, "plugin defines feodo_symbol")
  -- The symbols must be registered (virtual children) so rspamd scores them.
  check(plugin:find("settings.threatfox_symbol,", 1, true) ~= nil, "threatfox_symbol registered")
  check(plugin:find("settings.feodo_symbol,", 1, true) ~= nil, "feodo_symbol registered")
end

local groups = slurp(here .. "/../local.d/groups.conf")
check(groups ~= nil, "groups.conf readable")
if groups then
  -- Assert each feed symbol has a weight line within its block.
  local function has_weighted_symbol(name)
    local block = groups:match('"' .. name .. '"%s*{(.-)}')
    return block ~= nil and block:find("weight%s*=") ~= nil
  end
  check(has_weighted_symbol("THREATFOX_IOC"), "groups.conf defines a weight for THREATFOX_IOC")
  check(has_weighted_symbol("FEODO_CC_IP"), "groups.conf defines a weight for FEODO_CC_IP")
end

if failures > 0 then
  io.stderr:write(failures .. " assertion(s) failed\n")
  os.exit(1)
end
print("mailstrix_feed_routing_spec: all assertions passed")
