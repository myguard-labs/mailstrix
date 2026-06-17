--[[
yara.lua — rspamd plugin that scans a message (and optionally each MIME part)
against a set of YARA rules through the yarad HTTP backend.

Why a backend instead of a native module:
  * rspamd has no native YARA module (as of 4.1.0; upstream feature is still an
    open request). libyara is a CGO dependency that would block the worker event
    loop if run in-process.
  * yarad scans out-of-process and answers over HTTP, so this plugin stays fully
    async (rspamd_http) and libyara never enters the rspamd image.

yarad returns JSON:
  { "matches": [ { "rule": "<name>", "tags": [..], "meta": {..} }, ... ] }

Each matched rule becomes a result on the single symbol YARA_MATCH, with the
matched rule names as the option list (so they show in the history / can be
acted on by force_actions/multimap without a symbol per rule). Scoring is done
in groups.conf — shipped at weight 0 (log-only) until false positives are
cleared, then raised.

Scope is configurable (scan_message / scan_parts): the full rfc822 message,
each attachment part, or both.
--]]

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local lua_util = require "lua_util"
local N = "yara"

-- Defaults; overridden by the matching section in local.d/yara.conf.
local settings = {
  url = "http://127.0.0.1:8079/scan",
  token = "",                  -- shared secret; must equal yarad's YARAD_TOKEN
  token_file = "",             -- path to a file holding the token (preferred over
                               -- inline `token`; keeps the secret out of config)
  -- This must cover yarad's worst-case response: the time to acquire a scan slot
  -- (YARAD_BACKEND_TIMEOUT) PLUS the scan itself (YARAD_SCAN_TIMEOUT). With yarad
  -- defaults (6s + 10s) that is up to 16s; for mail, lower yarad's two timeouts
  -- so their sum fits THIS budget (e.g. BACKEND_TIMEOUT=2 + SCAN_TIMEOUT=8 = 10s).
  -- A plugin timeout below that sum just abandons scans that are still running.
  timeout = 10.0,
  max_size = 8 * 1024 * 1024,  -- don't ship bodies larger than this to yarad
  symbol = "YARA_MATCH",
  -- What to scan. At least one must be true or the plugin does nothing.
  scan_message = true,         -- the whole rfc822 message in one scan
  scan_parts = true,          -- each MIME part (attachment) separately
  -- Only scan parts at/above this many bytes individually (tiny text parts are
  -- already covered by scan_message; skipping them saves round-trips).
  min_part_size = 64,
}

-- post sends buf to yarad and invokes cb(matches) with the decoded rule list
-- (possibly empty). Errors are logged and treated as "no match" (fail-open):
-- a scanner problem must never block mail.
local function post(task, buf, what, cb)
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
    for _, part in ipairs(task:get_parts() or {}) do
      local content = part:get_content()
      if content and #content >= settings.min_part_size and #content <= settings.max_size then
        jobs[#jobs + 1] = { buf = content, what = "part" }
      end
    end
  end
  if #jobs == 0 then return end

  -- Fan out the scans; collect distinct matched rule names across all buffers,
  -- then insert one result with the rule names as options. We track outstanding
  -- jobs so the symbol is inserted once, after the last response.
  local seen = {}
  local rules = {}
  local pending = #jobs

  local function finish()
    pending = pending - 1
    if pending > 0 then return end
    if #rules > 0 then
      task:insert_result(settings.symbol, 1.0, rules)
    end
  end

  for _, job in ipairs(jobs) do
    post(task, job.buf, job.what, function(matches)
      for _, m in ipairs(matches) do
        if m.rule and not seen[m.rule] then
          seen[m.rule] = true
          rules[#rules + 1] = m.rule
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

rspamd_config:register_symbol({
  name = settings.symbol,
  type = "callback",
  callback = check_cb,
  flags = "empty",
})

rspamd_logger.infox(rspamd_config, "%s: registered, backend=%s scan_message=%s scan_parts=%s",
  N, settings.url, settings.scan_message, settings.scan_parts)
