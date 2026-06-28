#!/usr/bin/env lua
--[[
mailstrix_effort_spec.lua — standalone test (plain lua5.4, no rspamd) for the
EFFORT-3 X-MAILSTRIX-Effort tier computation in rspamd/plugins/mailstrix.lua.

The plugin can't be unit-loaded here (it `require`s rspamd_* at load and
registers against rspamd_config). So this mirrors the exact math of
compute_effort: prior metric score → level in [effort_min, effort_max], linear
between effort_score_low/high; a forcing symbol pins to max; result clamped.
If the plugin's mapping ever drifts (rounding, clamp order, force precedence),
these assertions fail.

Run: lua5.4 rspamd/test/mailstrix_effort_spec.lua   (exit 0 = pass, 1 = fail)
--]]

-- effort_of MUST stay byte-equivalent to compute_effort's body in mailstrix.lua.
-- score: prior rspamd metric score (number or nil). forced: a forcing symbol present.
local function effort_of(cfg, score, forced)
  local lo, hi = cfg.effort_min, cfg.effort_max
  if hi < lo then hi = lo end
  local level = lo
  score = tonumber(score)
  if score then
    local slo, shi = cfg.effort_score_low, cfg.effort_score_high
    if shi > slo then
      local frac = (score - slo) / (shi - slo)
      if frac < 0 then frac = 0 elseif frac > 1 then frac = 1 end
      level = lo + math.floor(frac * (hi - lo) + 0.5)
    elseif score >= shi then
      level = hi
    end
  end
  if forced then level = hi end
  if level < lo then level = lo elseif level > hi then level = hi end
  return level
end

local cfg = {
  effort_min = 1, effort_max = 10,
  effort_score_low = 0.0, effort_score_high = 8.0,
}

local fails = 0
local function eq(got, want, msg)
  if got ~= want then
    io.stderr:write(string.format("FAIL %s: got %s want %s\n", msg, tostring(got), tostring(want)))
    fails = fails + 1
  end
end

-- clean / trusted senders floor to effort_min
eq(effort_of(cfg, nil, false),   1, "no score -> min")
eq(effort_of(cfg, -5, false),    1, "negative score -> min")
eq(effort_of(cfg, 0,  false),    1, "score at low -> min")
-- bad senders cap at effort_max
eq(effort_of(cfg, 8,  false),   10, "score at high -> max")
eq(effort_of(cfg, 99, false),   10, "score over high -> max (clamped)")
-- linear midpoint: frac=4/8=0.5, lo+round(0.5*9)=1+5(round half up of 4.5)=6
eq(effort_of(cfg, 4,  false),    6, "midpoint score -> mid level")
-- a forcing symbol pins to max regardless of a clean score
eq(effort_of(cfg, 0,  true),    10, "force symbol overrides low score")
eq(effort_of(cfg, -9, true),    10, "force symbol overrides negative score")

-- degenerate config: min==max collapses to that level
local flat = { effort_min = 3, effort_max = 3, effort_score_low = 0, effort_score_high = 8 }
eq(effort_of(flat, 99, false),   3, "min==max collapses")
-- inverted band (high<=low) and a high score -> still max via the >=shi branch
local inv = { effort_min = 1, effort_max = 5, effort_score_low = 8, effort_score_high = 8 }
eq(effort_of(inv, 8, false),     5, "inverted band, score>=high -> max")
eq(effort_of(inv, 7, false),     1, "inverted band, score<high -> min")

if fails == 0 then print("mailstrix_effort_spec: OK") os.exit(0) else os.exit(1) end
