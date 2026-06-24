--[[
yara.lua — rspamd plugin that scans a message (and optionally each MIME part)
against a set of YARA rules through the yarad HTTP backend.

Project:  https://github.com/eilandert/rspamd-yarad
Write-up: https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/

Why a backend instead of a native module:
  * rspamd has no native YARA module (as of 4.1.0; upstream feature is still an
    open request). libyara is a CGO dependency that would block the worker event
    loop if run in-process.
  * yarad scans out-of-process and answers over HTTP, so this plugin stays fully
    async (rspamd_http) and libyara never enters the rspamd image.

yarad returns JSON:
  { "matches": [ { "rule": "<name>", "namespace": "<file>", "tags": [..], "meta": {..} }, ... ] }

Each matched rule is classified (see classify()) into one scoring-tier symbol —
YARA_MALWARE / YARA_EXPLOIT / YARA_PHISHING / YARA_SUSPICIOUS, or YARA for an
uncategorized hit — with the matched rules as that symbol's options, shown as
"rule (source-file.yar)" (traceable, and actionable by force_actions/multimap).
URLhaus malware-URL hits go to URLHAUS_MALWARE_URL; MalwareBazaar exact
attachment-hash hits go to MALWAREBAZAAR_MALWARE. Per-tier weights live in
groups.conf (group "YARA").

Scope is configurable (scan_message / scan_parts): the full rfc822 message,
each attachment part, or both.
--]]

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local N = "yara"

-- Defaults; overridden by the matching section in local.d/yara.conf.
local settings = {
  url = "http://127.0.0.1:8079/scan",
  token = "",                  -- shared secret; must equal yarad's YARAD_TOKEN
  token_file = "",             -- path to a file holding the token (preferred over
                               -- inline `token`; keeps the secret out of config)
  -- This must cover yarad's worst-case response: the time to acquire a scan slot
  -- (YARAD_BACKEND_TIMEOUT) PLUS the scan itself (YARAD_SCAN_TIMEOUT). yarad's
  -- defaults are intentionally aligned to fit this: 1s queue + 8s scan = 9s,
  -- leaving a little HTTP/JSON overhead before this 10s client timeout expires.
  -- A plugin timeout below that sum just abandons scans that are still running.
  timeout = 10.0,
  max_size = 8 * 1024 * 1024,  -- don't ship bodies larger than this to yarad
  -- Scoring tiers. Each matched rule is classified (see classify()) into ONE of
  -- these symbols by its name/source-file/tags/meta.score, so different kinds of
  -- hit score differently in groups.conf instead of one flat weight for every
  -- rule. `symbol` is the default/uncategorized bucket (and the callback symbol).
  symbol            = "YARA",             -- uncategorized rule match (default)
  symbol_malware    = "YARA_MALWARE",     -- malware family / webshell / RAT / APT
  symbol_exploit    = "YARA_EXPLOIT",     -- exploit / CVE / maldoc exploit
  symbol_phishing   = "YARA_PHISHING",    -- phishing kit / phishing document
  symbol_suspicious = "YARA_SUSPICIOUS",  -- heuristic / suspicious / anomaly
  -- Separate symbol for yarad's URLhaus malware-URL hits (rule names start
  -- "URLHAUS_"), so they score independently of YARA rule matches.
  urlhaus_symbol = "URLHAUS_MALWARE_URL",
  -- Separate symbol for yarad's MalwareBazaar attachment-hash hits (rule name
  -- "MALWAREBAZAAR_MALWARE"): an exact SHA256 match of the attachment against a
  -- known malware sample — a strong, standalone verdict.
  mbazaar_symbol = "MALWAREBAZAAR_MALWARE",
  -- Log-only symbol for rules yarad has allowlisted (meta.yarad_allow="1", set
  -- by YARAD_RULE_ALLOWLIST): the match is still surfaced (visible in history)
  -- but routed here so groups.conf can score it 0 — a known-FP rule demoted
  -- without dropping it or patching the source.
  allow_symbol = "YARA_ALLOWLISTED",
  -- What to scan. At least one must be true or the plugin does nothing.
  scan_message = true,         -- the whole rfc822 message in one scan
  scan_parts = true,          -- each MIME part (attachment) separately
  -- Only scan parts at/above this many bytes individually (tiny text parts are
  -- already covered by scan_message; skipping them saves round-trips).
  min_part_size = 64,
  -- meta.score → per-hit weight band. A rule's meta.score (0..100) is mapped
  -- linearly onto [score_weight_min, score_weight_max] and used as the symbol
  -- weight for that hit (the max over all hits in a bucket wins). Rules without
  -- a numeric meta.score keep weight 1.0. Set min=max=1.0 to disable and fall
  -- back to the old flat-1.0 behaviour.
  score_weight_min = 0.5,
  score_weight_max = 1.5,
  -- Cap on /scan requests per message (whole-message job + part jobs). A mail
  -- with dozens of parts can't fan out unbounded into yarad. Identical parts
  -- (same attachment twice) are also deduped by their digest before this cap.
  max_jobs = 32,
  -- Per-request effort tier (EFFORT-3). When enabled, the plugin sets the
  -- X-YARAD-Effort header from this message's signals so yarad spends deeper
  -- (slower, more decode passes) on suspicious senders and stays shallow/cheap on
  -- trusted ones. yarad clamps the header to its YARAD_EFFORT_MAX, so this can
  -- only ever LOWER effort below the operator's ceiling, never raise it past the
  -- DoS bound. Disabled by default (no header sent → yarad uses its own
  -- env/auto default, today's behaviour).
  effort_enabled = false,
  effort_max = 10,           -- the dial's top (mirror yarad's YARAD_EFFORT_MAX)
  effort_min = 1,            -- floor for the most-trusted senders
  -- Prior rspamd metric score → effort. At/below effort_score_low the sender
  -- looks clean (→ effort_min); at/above effort_score_high it looks bad
  -- (→ effort_max); linear in between. A negative score (whitelisted/authed)
  -- stays at effort_min.
  effort_score_low  = 0.0,
  effort_score_high = 8.0,
  -- Symbols that, if already present on the message, force full effort
  -- regardless of score (e.g. SPF/DKIM failures, known bad-sender lists). The
  -- max over score-derived and symbol-forced effort wins.
  effort_force_symbols = { "R_SPF_FAIL", "R_SPF_SOFTFAIL", "DMARC_POLICY_REJECT", "R_DKIM_REJECT" },
}

-- post sends buf to yarad and invokes cb(matches) with the decoded rule list
-- (possibly empty). Errors are logged and treated as "no match" (fail-open):
-- a scanner problem must never block mail. fname (optional) is the attachment
-- filename; it is passed to yarad so the YARA filename/extension external vars
-- get set and name-keyed rules (THOR/Loki) fire.
-- compute_effort derives the X-YARAD-Effort value (1..effort_max) for this
-- message, or nil when the feature is disabled (so no header is sent and yarad
-- falls back to its own default/auto). Cheap, signal-driven: clean/trusted
-- senders get the minimum, suspicious ones the maximum. Computed once per
-- message (not per part) — the sender's reputation is a message property.
local function compute_effort(task)
  if not settings.effort_enabled then return nil end
  local lo, hi = settings.effort_min, settings.effort_max
  if hi < lo then hi = lo end

  -- Score-derived level: map the prior metric score onto [lo, hi].
  local level = lo
  local score = nil
  local ok, res = pcall(function() return task:get_metric_score("default") end)
  if ok then
    if type(res) == "table" then res = res[1] end -- some bindings return {score, required}
    score = tonumber(res)
  end
  if score then
    local slo, shi = settings.effort_score_low, settings.effort_score_high
    if shi > slo then
      local frac = (score - slo) / (shi - slo)
      if frac < 0 then frac = 0 elseif frac > 1 then frac = 1 end
      level = lo + math.floor(frac * (hi - lo) + 0.5)
    elseif score >= shi then
      level = hi
    end
  end

  -- A forcing symbol (auth failure etc.) pins to full effort.
  for _, sym in ipairs(settings.effort_force_symbols or {}) do
    if task:has_symbol(sym) then level = hi break end
  end

  if level < lo then level = lo elseif level > hi then level = hi end
  return level
end

local function post(task, buf, what, fname, effort, cb)
  local function http_cb(err, code, body)
    if err then
      rspamd_logger.errx(task, "yarad request failed (%s): %s", what, err)
      return cb({})
    end
    if code ~= 200 then
      rspamd_logger.errx(task, "yarad returned HTTP %s (%s)", code, what)
      return cb({})
    end
    local ucl = require "ucl"
    local parser = ucl.parser()
    local ok, perr = parser:parse_string(body)
    if not ok then
      rspamd_logger.errx(task, "cannot parse yarad response: %s", perr)
      return cb({})
    end
    local res = parser:get_object()
    if type(res) ~= "table" or type(res.matches) ~= "table" then
      return cb({})
    end
    return cb(res.matches)
  end

  local headers = { ["Content-Type"] = "application/octet-stream" }
  if settings.token and settings.token ~= "" then
    headers["X-YARAD-Token"] = settings.token
  end
  -- The attachment filename comes from the (attacker-controlled) email, so it is
  -- base64-encoded: that keeps an embedded newline / control byte from injecting
  -- an HTTP header. yarad decodes it and sets the YARA filename/extension vars.
  if fname and fname ~= "" then
    headers["X-YARAD-Filename"] = rspamd_util.encode_base64(fname)
  end
  -- Per-request effort tier (EFFORT-3). Integer only; yarad clamps it to its
  -- configured ceiling, so a stale/oversized value can never raise effort past
  -- the DoS bound. nil → no header → yarad uses its own default.
  if effort then
    headers["X-YARAD-Effort"] = tostring(effort)
  end

  -- rspamd_http.request returns false when it could not even schedule the
  -- request (e.g. bad URL, no resolver). In that case http_cb will NEVER fire, so
  -- without this the per-job callback never runs, `pending` never reaches 0, and
  -- the whole message's collected matches are silently dropped. Fail open here.
  local scheduled = rspamd_http.request({
    task = task,
    url = settings.url,
    body = buf,
    callback = http_cb,
    timeout = settings.timeout,
    method = "POST",
    headers = headers,
  })
  if not scheduled then
    rspamd_logger.errx(task, "yarad request could not be scheduled (%s)", what)
    return cb({})
  end
end

-- score_weight turns a YARA rule's meta.score (0..100, as shipped by YARA-Forge
-- and signature-base) into a per-hit weight multiplier in [min..max], so a high-
-- confidence rule contributes more than a borderline one *within the same tier*
-- instead of every rule landing on a flat 1.0. The tier (group weight) is still
-- the dominant factor; this only modulates inside it. Rules without a numeric
-- meta.score (most of YARA-Forge core, ANY.RUN, …) keep weight 1.0 — unchanged
-- behaviour. Tunable here; retuning needs only an rspamd reload.
local function score_weight(m)
  local sc = tonumber(m.meta and m.meta.score)
  if not sc then return 1.0 end
  if sc < 0 then sc = 0 elseif sc > 100 then sc = 100 end
  -- Map 0..100 linearly onto the configured weight band.
  local lo, hi = settings.score_weight_min, settings.score_weight_max
  return lo + (hi - lo) * (sc / 100.0)
end

-- classify maps a matched YARA rule to a scoring-tier symbol from its name,
-- source file (namespace), tags and any meta.score. Heuristic and intentionally
-- tunable here (retuning needs only an rspamd reload, no yarad rebuild). The
-- strongest signal wins; anything unrecognised falls back to the default symbol.
local function classify(m)
  -- Authoritative override: a rule may self-declare its scoring tier via
  -- meta.tier ("malware"/"exploit"/"phishing"/"suspicious"). Honour it first so
  -- yarad's own marker/heuristic rules classify deterministically instead of
  -- being keyword-guessed from the rule name below (a LOLBin download-execute
  -- hit, for example, otherwise falls through to the generic YARA symbol).
  -- Read settings.symbol_* at call time so config overrides are respected.
  -- Rules with no meta.tier are unaffected: behaviour is identical for them.
  if type(m.meta) == "table" and m.meta.tier then
    local t = string.lower(m.meta.tier)
    if t == "malware" then return settings.symbol_malware end
    if t == "exploit" then return settings.symbol_exploit end
    if t == "phishing" then return settings.symbol_phishing end
    if t == "suspicious" then return settings.symbol_suspicious end
    -- "info"/"default"/unknown → fall through to the heuristic + meta.score.
  end
  local hay = string.lower((m.rule or "") .. " " .. (m.namespace or ""))
  if type(m.tags) == "table" then
    hay = hay .. " " .. string.lower(table.concat(m.tags, " "))
  end
  local function has(...)
    for _, p in ipairs({ ... }) do
      if hay:find(p, 1, true) then return true end
    end
    return false
  end
  -- Exploit / CVE / maldoc exploit (Equation Editor, shellcode, …).
  if has("expl", "cve", "exploit", "equation", "shellcode") then
    return settings.symbol_exploit
  end
  -- Malware family / webshell / hacktool / APT / ransomware / loader / stealer.
  if has("malw", "webshell", "ransom", "backdoor", "trojan", "apt_", "apt-",
         "hktl", "hacktool", "loader", "stealer", "botnet", "dropper", "keylog") then
    return settings.symbol_malware
  end
  -- Phishing kits / phishing documents.
  if has("phish", "_pk_", "phishingkit", "credential") then
    return settings.symbol_phishing
  end
  -- Heuristic / suspicious / anomaly / obfuscation.
  if has("susp", "anomaly", "heuristic", "obfusc") then
    return settings.symbol_suspicious
  end
  -- Fall back to a numeric meta.score where the ruleset provides one (YARA-Forge,
  -- signature-base): high = malware-grade, low = suspicious, else generic.
  local sc = tonumber(m.meta and m.meta.score)
  if sc then
    if sc >= 75 then return settings.symbol_malware end
    if sc < 40 then return settings.symbol_suspicious end
  end
  return settings.symbol
end

local function check_cb(task)
  -- Skip authenticated / outbound mail.
  if task:get_user() then return end

  -- Collect the buffers to scan: the whole message and/or each sizeable part.
  local jobs = {}
  if settings.scan_message then
    local content = task:get_content()
    if content and #content > 0 and #content <= settings.max_size then
      jobs[#jobs + 1] = { buf = content, what = "message" }
    end
  end
  if settings.scan_parts then
    local seen_parts = {}
    for _, part in ipairs(task:get_parts() or {}) do
      if #jobs >= settings.max_jobs then break end -- bound fan-out per message
      local content = part:get_content()
      if content and #content >= settings.min_part_size and #content <= settings.max_size then
        -- Dedup identical parts (same attachment included twice) by the digest
        -- rspamd already computed — saves a redundant /scan round-trip with no
        -- coverage loss. Parts without a digest are kept (never dropped).
        local dg = part:get_digest()
        if not (dg and seen_parts[dg]) then
          if dg then seen_parts[dg] = true end
          -- Pass the attachment filename so yarad sets the YARA filename/extension
          -- external vars (nil for an unnamed part — yarad then leaves them empty).
          jobs[#jobs + 1] = { buf = content, what = "part", fname = part:get_filename() }
        end
      end
    end
  end
  if #jobs == 0 then return end

  -- Fan out the scans; bucket distinct matches per scoring-tier symbol across all
  -- buffers. Each YARA rule is classified into a tier (malware/exploit/phishing/
  -- suspicious/default) so different hits score differently; URLHAUS_* hits go to
  -- their own symbol. One insert_result per non-empty symbol, after the last
  -- response, with the rule names (or URLs) as that symbol's options.
  local seen = {}
  local buckets = {} -- symbol name -> { opts = {..}, weight = number }
  local pending = #jobs

  -- add records a distinct option under a symbol and tracks the strongest weight
  -- seen for that symbol (the max over all its hits) as the value to insert.
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

  local function finish()
    pending = pending - 1
    if pending > 0 then return end
    for sym, b in pairs(buckets) do
      if #b.opts > 0 then
        task:insert_result(sym, b.weight, b.opts)
      end
    end
  end

  -- Effort tier is a per-message (sender) property: compute once, send on every
  -- per-part /scan for this message.
  local effort = compute_effort(task)

  for _, job in ipairs(jobs) do
    post(task, job.buf, job.what, job.fname, effort, function(matches)
      for _, m in ipairs(matches) do
        if m.rule then
          if m.rule:sub(1, 8) == "URLHAUS_" then
            -- For URLhaus hits the interesting thing is the malicious URL, not
            -- the (constant) rule name, so show the URL itself as the option;
            -- dedup on the URL so several distinct bad links don't collapse into
            -- one. Append a short tag for the host/deobfuscated variants.
            local url = (type(m.meta) == "table" and m.meta.url) or m.rule
            local tag = ""
            if m.rule:find("_HOST") then tag = tag .. " (host)" end
            if m.rule:find("_DEOBF") then tag = tag .. " (deobf)" end
            add(settings.urlhaus_symbol, url .. tag, "u:" .. url)
          elseif m.rule:sub(1, 14) == "MALWAREBAZAAR_" then
            -- Exact attachment-hash hit: show the SHA256 (from meta) as the
            -- option, deduped on the hash, so the history names the bad file.
            local sha = (type(m.meta) == "table" and m.meta.sha256) or m.rule
            add(settings.mbazaar_symbol, sha, "mb:" .. sha)
          else
            -- Classify into a scoring tier, and show "rule (source-file)" so a
            -- generic rule name (e.g. "http") is traceable to the ruleset that
            -- shipped it. m.namespace is the compiled rule file.
            local opt = m.rule
            if m.namespace and m.namespace ~= "" then
              opt = m.rule .. " (" .. m.namespace .. ")"
            end
            -- Explainability: for yarad's own marker/heuristic rules
            -- (meta.author=="yarad"), append the human description so the symbol
            -- option in rspamd history says WHY it fired ("Living-off-the-land
            -- binary invoked with a download/execute argument") instead of only a
            -- rule name. Bounded so a long description can't bloat the option.
            -- Restricted to yarad rules: baked-corpus descriptions are noisy/huge.
            if type(m.meta) == "table" and m.meta.author == "yarad"
              and type(m.meta.description) == "string" and m.meta.description ~= "" then
              local d = m.meta.description
              if #d > 80 then d = d:sub(1, 77) .. "..." end
              opt = opt .. ": " .. d
            end
            -- Dedup key is namespace+rule, NOT rule alone: a scanner match's
            -- identity is (namespace, rule), so two same-named rules shipped by
            -- different files (e.g. a generic "http" in two rulesets) are distinct
            -- hits. Keying on m.rule alone would drop the second and let it inherit
            -- the first's tier/weight (twin of the fixed Go mergeMatches bug). The
            -- \31 (unit separator) can't appear in a rule/namespace token.
            local key = "y:" .. (m.namespace or "") .. "\31" .. m.rule
            -- yarad allowlist: a known-FP rule demoted to log-only. Keep it
            -- visible but route to the 0-weight symbol instead of a scoring tier.
            if type(m.meta) == "table" and m.meta.yarad_allow == "1" then
              add(settings.allow_symbol, opt, key, 1.0)
            else
              -- Modulate within the tier by the rule's meta.score (1.0 if absent).
              add(classify(m), opt, key, score_weight(m))
            end
          end
        end
      end
      finish()
    end)
  end
end

-- Merge user config over defaults.
local opts = rspamd_config:get_all_opt(N)
if opts then
  settings = lua_util.override_defaults(settings, opts)
end

-- Resolve the shared secret. A token_file (Docker secret / 0444 file) wins over
-- an inline token so the secret never has to live in the config. Read at config
-- time only; trailing whitespace/newline is trimmed.
if settings.token_file and settings.token_file ~= "" then
  local f = io.open(settings.token_file, "r")
  if f then
    local t = f:read("*a") or ""
    f:close()
    settings.token = t:gsub("%s+$", "")
  else
    rspamd_logger.errx(rspamd_config, "%s: cannot read token_file %s", N, settings.token_file)
  end
end
if settings.token == "" then
  rspamd_logger.warnx(rspamd_config, "%s: no token set (token/token_file); yarad will refuse all scans", N)
elseif settings.token == "change-me" then
  rspamd_logger.warnx(rspamd_config, "%s: token is the placeholder 'change-me'; set a real shared secret", N)
end

if not settings.scan_message and not settings.scan_parts then
  rspamd_logger.warnx(rspamd_config, "%s: both scan_message and scan_parts are false; plugin disabled", N)
  return
end

local id = rspamd_config:register_symbol({
  name = settings.symbol,
  type = "callback",
  callback = check_cb,
  flags = "empty",
})

-- The tier symbols and the URLhaus symbol are all inserted from the same
-- callback, so register each as a virtual child of the callback symbol: rspamd
-- then knows them (no "unknown symbol" warnings) and they can be scored
-- independently in groups.conf.
for _, s in ipairs({
  settings.symbol_malware,
  settings.symbol_exploit,
  settings.symbol_phishing,
  settings.symbol_suspicious,
  settings.urlhaus_symbol,
  settings.mbazaar_symbol,
  settings.allow_symbol,
}) do
  rspamd_config:register_symbol({ name = s, type = "virtual", parent = id })
end

-- EFFORT-3: when the per-request effort tier is enabled it reads the message's
-- prior metric score and auth-failure symbols (compute_effort). The callback has
-- no inherent ordering, so without an explicit dependency YARA can run before
-- SPF/DKIM/DMARC and see a partial score / missing force symbol. Register the
-- callback as depending on each force symbol so those filters run first. (The
-- metric score is still best-effort — get_metric_score reflects whatever has run
-- — but the auth-failure pins, the strongest signal, are now reliable.) Only
-- wired when enabled, so the default-off path adds no scheduling constraint.
if settings.effort_enabled then
  for _, s in ipairs(settings.effort_force_symbols or {}) do
    rspamd_config:register_dependency(id, s)
  end
end

rspamd_logger.infox(rspamd_config, "%s: registered, backend=%s scan_message=%s scan_parts=%s urlhaus_symbol=%s",
  N, settings.url, settings.scan_message, settings.scan_parts, settings.urlhaus_symbol)
