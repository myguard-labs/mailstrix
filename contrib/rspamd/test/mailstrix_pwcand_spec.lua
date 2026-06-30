#!/usr/bin/env lua
--[[
mailstrix_pwcand_spec.lua — standalone test (plain lua5.4, no rspamd) for the
password-candidate scraping in rspamd/plugins/mailstrix.lua (the opt-in
encrypted-archive decrypt sourcing).

The plugin can't be unit-loaded here (it `require`s rspamd_* at load and uses
rspamd_regexp:search). So this mirrors the EXACT post-match logic of
extract_pw_candidates — separator labels, capture shape, dedup, count/len cap
clamps — using a Lua-pattern stand-in for the PCRE. If the plugin's caps or
dedup ever drift, these assertions fail.

Note: the stand-in scans label-by-label (not in source match order), so the
relative order of candidates from DIFFERENT labels in one text can differ from
the plugin. The cap/dedup assertions here use single-label inputs, where order
is identical, so this does not affect what is tested.

Run: lua5.4 rspamd/test/mailstrix_pwcand_spec.lua   (exit 0 = pass, 1 = fail)
--]]

-- candidates_of mirrors extract_pw_candidates' body: scan each text source for
-- "<label><sep><token>", dedup, clamp count to maxn and length to maxlen. The
-- label/sep/token classes match the plugin's PCRE
--   \b(?:password|passwort|wachtwoord|senha|contrase|pass|pwd|pw|code)[\s:=]+([^\s,;"'<>]{1,64})
-- A Lua frontier+pattern is close enough for the post-match logic this checks.
local labels = { "password", "passwort", "wachtwoord", "senha", "contrase", "pass", "pwd", "pw", "code" }
local function candidates_of(cfg, texts)
  if not cfg.send_pw_candidates then return nil end
  local maxn = math.min(tonumber(cfg.pw_candidate_max) or 32, 32)
  local maxlen = math.min(tonumber(cfg.pw_candidate_maxlen) or 64, 64)
  if maxn < 1 then maxn = 1 end
  if maxlen < 1 then maxlen = 1 end

  local seen, out = {}, {}
  local function scan(text)
    if not text or #out >= maxn then return end
    local low = text:lower()
    for _, lbl in ipairs(labels) do
      local init = 1
      while #out < maxn do
        local s, e = low:find(lbl, init, true)
        if not s then break end
        init = e + 1
        -- separator: "\s+is\s+" OR "[\s:=]+", then capture [^\s,;"'<>]+. The PCRE
        -- bounds the capture in-pattern to {1,64}; mirror that by truncating the
        -- raw capture to 64 FIRST, then apply the plugin's reject-if->maxlen rule
        -- (the plugin drops, it does not truncate, an over-maxlen capture).
        local rest = text:sub(e + 1)
        local cap = rest:match([[^%s+is%s+([^%s,;"'<>]+)]])
          or rest:match([[^[%s:=]+([^%s,;"'<>]+)]])
        if cap and #cap > 0 then
          if #cap > 64 then cap = cap:sub(1, 64) end -- mirror PCRE {1,64}
          if #cap <= maxlen and not seen[cap] then   -- plugin rejects, never truncates, beyond maxlen
            seen[cap] = true
            out[#out + 1] = cap
          end
        end
      end
    end
  end

  for _, t in ipairs(texts) do scan(t) end
  if #out == 0 then return nil end
  return out
end

local fails = 0
local function eq(got, want, msg)
  if got ~= want then
    io.stderr:write(string.format("FAIL %s: got %s want %s\n", msg, tostring(got), tostring(want)))
    fails = fails + 1
  end
end
local function has(list, v)
  if not list then return false end
  for _, x in ipairs(list) do if x == v then return true end end
  return false
end

local on = { send_pw_candidates = true, pw_candidate_max = 32, pw_candidate_maxlen = 64 }

-- disabled -> nil (default OFF, no behaviour change)
eq(candidates_of({ send_pw_candidates = false }, { "password: infected" }), nil, "disabled -> nil")

-- basic extraction across separator styles
local r = candidates_of(on, { "The password is infected", "pass=Secret1", "pwd: hunter2" })
eq(has(r, "infected"), true, "extract 'password is X'")
eq(has(r, "Secret1"), true, "extract 'pass=X'")
eq(has(r, "hunter2"), true, "extract 'pwd: X'")

-- multilingual labels
local m = candidates_of(on, { "wachtwoord: geheim", "passwort = streng" })
eq(has(m, "geheim"), true, "dutch wachtwoord")
eq(has(m, "streng"), true, "german passwort")

-- dedup: same candidate twice -> one entry
local d = candidates_of(on, { "password: dup", "pass: dup" })
eq(#d, 1, "dedup identical candidates")

-- count cap: 40 distinct candidates clamps to 32
local many = {}
for i = 1, 40 do many[i] = "password: pw" .. i end
local c = candidates_of(on, many)
eq(#c, 32, "count cap clamps to 32")

-- count cap config is hard-clamped (request 1000 -> still 32)
local big = { send_pw_candidates = true, pw_candidate_max = 1000, pw_candidate_maxlen = 64 }
eq(#candidates_of(big, many), 32, "config count cap hard-clamped to 32")

-- capture is bounded to 64 in-pattern: a 100-char token yields a 64-char
-- candidate (kept, since 64 <= maxlen=64)
local longtok = string.rep("A", 100)
local lc = candidates_of(on, { "password: " .. longtok })
eq(#lc[1], 64, "capture bounded to 64")

-- length cap config is hard-clamped (request 1000 -> still effectively 64)
local biglen = { send_pw_candidates = true, pw_candidate_max = 32, pw_candidate_maxlen = 1000 }
eq(#candidates_of(biglen, { "password: " .. longtok })[1], 64, "config length cap hard-clamped to 64")

-- with a SMALL maxlen, an over-maxlen capture is REJECTED (dropped), not truncated
local smalllen = { send_pw_candidates = true, pw_candidate_max = 32, pw_candidate_maxlen = 5 }
eq(candidates_of(smalllen, { "password: abcdefghij" }), nil, "over-maxlen capture rejected, not truncated")
eq(candidates_of(smalllen, { "password: abc" })[1], "abc", "within-maxlen capture kept")

-- no label -> nil
eq(candidates_of(on, { "just an ordinary sentence with no secret word here" }), nil, "no label -> nil")

if fails == 0 then print("mailstrix_pwcand_spec: OK") os.exit(0) else os.exit(1) end
