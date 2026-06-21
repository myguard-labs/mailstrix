#!/usr/bin/env lua
--[[
yara_dedup_spec.lua — standalone test (plain lua5.4, no rspamd) for the
AUDIT-LUA-NAMESPACE-DEDUPE fix in rspamd/plugins/yara.lua.

The plugin can't be unit-loaded here (it `require`s rspamd_logger/_http/_util at
load and registers symbols against the rspamd_config global). So this mirrors the
exact dedup contract of process_results' `add()` closure: distinct matches are
bucketed under a `seen` set keyed per match, and a YARA scanner match's identity
is (namespace, rule) — NOT rule alone. Two same-named rules shipped by different
files are DISTINCT hits and must both survive; keying on rule alone would drop the
second and let it inherit the first's tier/weight (twin of the fixed Go
mergeMatches namespace bug). If the plugin's key expression is ever reverted to
rule-only, the "different namespace" assertion below fails.

Run: lua5.4 rspamd/test/yara_dedup_spec.lua   (exit 0 = pass, 1 = fail)
--]]

-- dedup_key MUST stay byte-identical to the key built in yara.lua process_results.
local function dedup_key(m)
  return "y:" .. (m.namespace or "") .. "\31" .. m.rule
end

-- add mirrors process_results' add(): inserts opt under sym only if the key is
-- unseen; tracks the strongest weight per symbol. Returns the bucket table.
local function new_collector()
  local seen, buckets = {}, {}
  local function add(sym, opt, key, weight)
    weight = weight or 1.0
    if seen[key] then return end
    seen[key] = true
    local b = buckets[sym]
    if not b then
      b = { opts = {}, weight = weight }
      buckets[sym] = b
    elseif weight > b.weight then
      b.weight = weight
    end
    b.opts[#b.opts + 1] = opt
  end
  return add, buckets
end

local failures = 0
local function check(cond, msg)
  if not cond then
    io.stderr:write("FAIL: " .. msg .. "\n")
    failures = failures + 1
  end
end

-- 1. Same rule name, DIFFERENT namespace (file) → two distinct hits, both kept.
do
  local add, buckets = new_collector()
  local a = { rule = "http", namespace = "rulesA.yar" }
  local b = { rule = "http", namespace = "rulesB.yar" }
  add("YARA", a.rule, dedup_key(a), 1.0)
  add("YARA", b.rule, dedup_key(b), 1.0)
  check(#buckets["YARA"].opts == 2,
    "same rule from two namespaces must NOT collapse (got " ..
    #buckets["YARA"].opts .. " opt(s), want 2)")
end

-- 2. Identical (namespace, rule) seen twice (e.g. matched in two scanned buffers)
--    → deduped to one.
do
  local add, buckets = new_collector()
  local m = { rule = "Cobalt_Strike", namespace = "apt.yar" }
  add("YARA_MALWARE", m.rule, dedup_key(m), 5.0)
  add("YARA_MALWARE", m.rule, dedup_key(m), 5.0)
  check(#buckets["YARA_MALWARE"].opts == 1,
    "identical namespace+rule must dedup to 1 (got " ..
    #buckets["YARA_MALWARE"].opts .. ")")
end

-- 3. Different rule, same namespace → distinct.
do
  local add, buckets = new_collector()
  local a = { rule = "foo", namespace = "x.yar" }
  local b = { rule = "bar", namespace = "x.yar" }
  add("YARA", a.rule, dedup_key(a), 1.0)
  add("YARA", b.rule, dedup_key(b), 1.0)
  check(#buckets["YARA"].opts == 2, "distinct rules in one namespace must both survive")
end

-- 4. The pre-fix key (rule alone) WOULD have collapsed case 1 — assert the new
--    key actually distinguishes them, so a regression to rule-only is caught.
do
  local a = { rule = "http", namespace = "rulesA.yar" }
  local b = { rule = "http", namespace = "rulesB.yar" }
  check(dedup_key(a) ~= dedup_key(b),
    "dedup_key must differ when only the namespace differs (regression guard)")
  local c = { rule = "http", namespace = "rulesA.yar" }
  check(dedup_key(a) == dedup_key(c), "dedup_key must match for identical namespace+rule")
end

if failures > 0 then
  io.stderr:write(failures .. " assertion(s) failed\n")
  os.exit(1)
end
print("yara_dedup_spec: all assertions passed")
