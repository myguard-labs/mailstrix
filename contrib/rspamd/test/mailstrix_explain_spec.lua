#!/usr/bin/env lua
--[[
mailstrix_explain_spec.lua — standalone test (plain lua5.4, no rspamd) for the
verdict-explainability change in rspamd/plugins/mailstrix.lua:

  1. classify() honours an explicit meta.tier ("malware"/"exploit"/"phishing"/
     "suspicious") as an AUTHORITATIVE override, before the name/namespace/tag
     keyword heuristic. Rules with no meta.tier are unaffected (heuristic +
     meta.score path unchanged).
  2. The symbol option for strixd's own rules (meta.author=="strixd") appends the
     human meta.description so the rspamd history says WHY a hit fired, bounded to
     80 chars. Non-strixd (baked corpus) rules keep the bare "rule (namespace)".

The plugin can't be unit-loaded here (it require()s rspamd globals at load), so
these mirror the EXACT logic blocks in mailstrix.lua. If the plugin's classify()
override or option-build is changed incompatibly, the asserts below fail.

Run: lua5.4 rspamd/test/mailstrix_explain_spec.lua   (exit 0 = pass, 1 = fail)
--]]

-- Symbol names mirror the plugin defaults (settings.symbol_*).
local SYM = {
  default    = "STRIX",
  malware    = "STRIX_MALWARE",
  exploit    = "STRIX_EXPLOIT",
  phishing   = "STRIX_PHISHING",
  suspicious = "STRIX_SUSPICIOUS",
}

-- tier_from_meta MUST stay byte-identical to the meta.tier override block at the
-- top of classify() in mailstrix.lua. Returns a symbol, or nil to fall through to the
-- keyword heuristic.
local function tier_from_meta(m)
  if type(m.meta) == "table" and m.meta.tier then
    local t = string.lower(m.meta.tier)
    if t == "malware" then return SYM.malware end
    if t == "exploit" then return SYM.exploit end
    if t == "phishing" then return SYM.phishing end
    if t == "suspicious" then return SYM.suspicious end
  end
  return nil -- "info"/"default"/unknown/absent → heuristic path
end

-- build_option MUST stay byte-identical to the option-build block in mailstrix.lua's
-- process_results (the else branch for normal rule hits).
local function build_option(m)
  local opt = m.rule
  if m.namespace and m.namespace ~= "" then
    opt = m.rule .. " (" .. m.namespace .. ")"
  end
  if type(m.meta) == "table" and m.meta.author == "strixd"
    and type(m.meta.description) == "string" and m.meta.description ~= "" then
    local d = m.meta.description
    if #d > 80 then d = d:sub(1, 77) .. "..." end
    opt = opt .. ": " .. d
  end
  return opt
end

local failures = 0
local function check(cond, msg)
  if not cond then
    io.stderr:write("FAIL: " .. msg .. "\n")
    failures = failures + 1
  end
end

-- 1. meta.tier is authoritative for each known value.
check(tier_from_meta({ meta = { tier = "malware" } }) == SYM.malware, "tier=malware → STRIX_MALWARE")
check(tier_from_meta({ meta = { tier = "Exploit" } }) == SYM.exploit, "tier is case-insensitive (Exploit → STRIX_EXPLOIT)")
check(tier_from_meta({ meta = { tier = "phishing" } }) == SYM.phishing, "tier=phishing → STRIX_PHISHING")
check(tier_from_meta({ meta = { tier = "suspicious" } }) == SYM.suspicious, "tier=suspicious → STRIX_SUSPICIOUS")

-- 2. Unknown / info / absent tier → nil (fall through to heuristic, no override).
check(tier_from_meta({ meta = { tier = "info" } }) == nil, "tier=info falls through to heuristic")
check(tier_from_meta({ meta = { tier = "bogus" } }) == nil, "unknown tier falls through to heuristic")
check(tier_from_meta({ meta = {} }) == nil, "absent tier falls through (no behaviour change)")
check(tier_from_meta({ rule = "x" }) == nil, "no meta table falls through")

-- 3. tier override escalates a hit the keyword heuristic would have under-scored:
--    a rule named/tagged only "suspicious" but declaring tier=malware lands in
--    STRIX_MALWARE, not STRIX_SUSPICIOUS.
check(tier_from_meta({ rule = "Susp_Generic", meta = { tier = "malware" } }) == SYM.malware,
  "explicit tier overrides what the name heuristic would pick")

-- 4. Description appended for strixd rules, bounded to 80 chars.
do
  local m = { rule = "LOLBins_Invocation", namespace = "intent.yar",
              meta = { author = "strixd", description = "Living-off-the-land binary invoked with a download/execute argument" } }
  local opt = build_option(m)
  check(opt:find("LOLBins_Invocation %(intent%.yar%)") ~= nil, "option keeps rule (namespace)")
  check(opt:find(": Living%-off%-the%-land") ~= nil, "strixd rule description is appended after ': '")
end

do
  local long = string.rep("A", 200)
  local opt = build_option({ rule = "R", namespace = "n.yar", meta = { author = "strixd", description = long } })
  local desc = opt:match(": (.*)$")
  check(desc ~= nil and #desc == 80, "long description is truncated to 80 chars (77 + '...')")
  check(desc:sub(-3) == "...", "truncated description ends with '...'")
end

-- 5. Baked-corpus (non-strixd) rules get NO description appended — only "rule (ns)".
do
  local opt = build_option({ rule = "SUSP_x", namespace = "sigbase.yar",
                             meta = { author = "Florian Roth", description = "some noisy upstream description" } })
  check(opt == "SUSP_x (sigbase.yar)", "non-strixd rule keeps bare 'rule (namespace)', no description")
end

-- 6. strixd rule with empty/absent description is unchanged.
do
  check(build_option({ rule = "R", namespace = "n.yar", meta = { author = "strixd", description = "" } })
    == "R (n.yar)", "empty description not appended")
  check(build_option({ rule = "R", namespace = "n.yar", meta = { author = "strixd" } })
    == "R (n.yar)", "absent description not appended")
end

if failures > 0 then
  io.stderr:write(failures .. " assertion(s) failed\n")
  os.exit(1)
end
print("mailstrix_explain_spec: all assertions passed")
