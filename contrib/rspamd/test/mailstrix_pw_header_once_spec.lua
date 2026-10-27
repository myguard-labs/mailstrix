#!/usr/bin/env lua
--[[
mailstrix_pw_header_once_spec.lua — real-plugin mock test for OPT-PERF-O2.

It proves password candidates are extracted once per message after jobs exist,
then the same header (or nil) is used by every unchanged /scan request.

Run: lua5.1 contrib/rspamd/test/mailstrix_pw_header_once_spec.lua
Benchmark: lua5.1 contrib/rspamd/test/mailstrix_pw_header_once_spec.lua \
  contrib/rspamd/plugins/mailstrix.lua --benchmark 2000 16
--]]

local here = arg[0]:match("^(.*)/[^/]*$") or "."
local plugin = arg[1] or here .. "/../plugins/mailstrix.lua"
local noop = function() end

package.loaded.rspamd_logger = { errx = noop, warnx = noop, infox = noop }
package.loaded.lua_cfg_utils = { push_config_error = noop }
package.loaded.lua_util = {
  override_defaults = function(defaults, opts)
    for k, v in pairs(opts) do
      if type(v) == type(defaults[k]) then defaults[k] = v end
    end
    return defaults
  end,
}
package.loaded.rspamd_util = {
  encode_base64 = function(value) return "b64:" .. value end,
}

local regex_searches = 0
package.loaded.rspamd_regexp = {
  create_cached = function()
    return {
      search = function(_, text)
        regex_searches = regex_searches + 1
        local candidate = text:match("password:%s*([^%s]+)")
        if candidate then return { { "password: " .. candidate, candidate } } end
        return nil
      end,
    }
  end,
}

local failures = 0
local function check(condition, message)
  if not condition then
    io.stderr:write("FAIL: " .. message .. "\n")
    failures = failures + 1
  end
end

local function load_callback(opts, requests)
  package.loaded.rspamd_http = {
    request = function(req)
      requests[#requests + 1] = req
      return true
    end,
  }
  local registered = {}
  rspamd_config = {
    get_all_opt = function() return opts end,
    register_symbol = function(_, symbol)
      registered[#registered + 1] = symbol
      return #registered
    end,
    register_dependency = noop,
  }
  assert(pcall(assert(loadfile(plugin))))
  for _, symbol in ipairs(registered) do
    if symbol.callback then return symbol.callback end
  end
  error("mailstrix callback was not registered")
end

local function make_task(part_count, subject, text_sources)
  local calls = { subject = 0, text_parts = 0 }
  local parts = {}
  for i = 1, part_count do
    parts[i] = {
      get_content = function() return string.rep(string.char(64 + i), 80) end,
      get_digest = function() return "digest-" .. i end,
      get_filename = function() return "part-" .. i .. ".bin" end,
    }
  end
  local text_parts = {}
  for i, text in ipairs(text_sources or {}) do
    text_parts[i] = { get_content = function() return text end }
  end
  local task = {
    get_user = noop,
    get_content = function() return "whole message" end,
    get_parts = function() return parts end,
    get_subject = function()
      calls.subject = calls.subject + 1
      return subject
    end,
    get_text_parts = function()
      calls.text_parts = calls.text_parts + 1
      return text_parts
    end,
    insert_result = noop,
  }
  return task, calls
end

local function run_case(opts, part_count, subject, text_sources)
  local requests = {}
  local callback = load_callback(opts, requests)
  local task, calls = make_task(part_count, subject, text_sources)
  local searches_before = regex_searches
  callback(task)
  return task, calls, requests, regex_searches - searches_before
end

local function benchmark()
  local iterations = tonumber(arg[3]) or 2000
  local part_count = tonumber(arg[4]) or 16
  local requests = {}
  local callback = load_callback({ send_pw_candidates = true }, requests)
  local subject = string.rep("x", 65500) .. " password: infected"
  local task, calls = make_task(part_count, subject, {})
  local started = os.clock()
  for _ = 1, iterations do callback(task) end
  local elapsed = os.clock() - started
  io.write(string.format(
    "mailstrix_pw_header_once_bench iterations=%d jobs=%d elapsed=%.6f subject_reads=%d searches=%d requests=%d\n",
    iterations, part_count + 1, elapsed, calls.subject, regex_searches, #requests))
end

if arg[2] == "--benchmark" then
  benchmark()
  os.exit(0)
end

-- Positive semantic control: one message plus two distinct parts still creates
-- all three requests, with their original buffers, filenames and task object.
local task, calls, requests, searches = run_case(
  { send_pw_candidates = true }, 2, "password: infected", {})
check(#requests == 3, "message and both part requests are scheduled")
check(calls.subject == 1, "candidate subject is read once per message")
check(calls.text_parts == 1, "candidate text parts are read once per message")
check(searches == 1, "candidate regex runs once for the single text source")
check(requests[1].body == "whole message", "whole-message request body is preserved")
check(requests[1].headers["X-MAILSTRIX-Filename"] == nil,
  "whole-message request keeps no filename header")
for i, request in ipairs(requests) do
  check(request.task == task, "request " .. i .. " retains the original task")
  check(request.headers["X-MAILSTRIX-PWCandidates"] == "b64:infected",
    "request " .. i .. " receives the same candidate header")
end
check(requests[2].body == string.rep("A", 80), "first part body is preserved")
check(requests[3].body == string.rep("B", 80), "second part body is preserved")
check(requests[2].headers["X-MAILSTRIX-Filename"] == "b64:part-1.bin",
  "first part filename is preserved")
check(requests[3].headers["X-MAILSTRIX-Filename"] == "b64:part-2.bin",
  "second part filename is preserved")

-- Nil-header control: no candidate still scans subject/text sources once and
-- schedules every job without the header.
task, calls, requests, searches = run_case(
  { send_pw_candidates = true }, 2, "ordinary subject", { "ordinary body" })
check(#requests == 3, "nil-header case preserves every request")
check(calls.subject == 1 and calls.text_parts == 1,
  "nil-header candidate sources are read once")
check(searches == 2, "nil-header sources are each searched once")
for i, request in ipairs(requests) do
  check(request.task == task, "nil-header request " .. i .. " retains task")
  check(request.headers["X-MAILSTRIX-PWCandidates"] == nil,
    "nil-header request " .. i .. " omits candidate header")
end

-- Disabled negative control: no password source is touched, but job scheduling
-- and task retention remain unchanged.
task, calls, requests, searches = run_case(
  { send_pw_candidates = false }, 2, "password: ignored", { "password: ignored" })
check(#requests == 3, "disabled case preserves every request")
check(calls.subject == 0 and calls.text_parts == 0 and searches == 0,
  "disabled case does not touch candidate sources")
for i, request in ipairs(requests) do
  check(request.task == task, "disabled request " .. i .. " retains task")
  check(request.headers["X-MAILSTRIX-PWCandidates"] == nil,
    "disabled request " .. i .. " omits candidate header")
end

-- Zero-job boundary: extraction remains behind the existing jobs guard.
local zero_requests = {}
local zero_callback = load_callback({
  send_pw_candidates = true,
  scan_message = false,
  scan_parts = true,
}, zero_requests)
local zero_task, zero_calls = make_task(0, "password: must-not-read", {})
local searches_before = regex_searches
zero_callback(zero_task)
check(#zero_requests == 0, "zero-job case schedules no request")
check(zero_calls.subject == 0 and zero_calls.text_parts == 0,
  "zero-job case does not extract candidates")
check(regex_searches == searches_before, "zero-job case runs no candidate regex")

if failures > 0 then os.exit(1) end
print("mailstrix_pw_header_once_spec: OK")
