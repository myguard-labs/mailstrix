-- luacheck configuration for rspamd-yarad Lua plugin
-- rspamd injects these as globals at load time; declaring them here suppresses
-- "accessing undefined global" warnings without needing rspamd installed.
std = "max"

globals = {
    "rspamd_config",   -- main rspamd config object (used at module level)
}

read_globals = {
    "rspamd_logger",   -- require "rspamd_logger"
    "rspamd_http",     -- require "rspamd_http"
    "rspamd_util",     -- require "rspamd_util"
    "lua_util",        -- require "lua_util"
    "ucl",             -- require "ucl"  (JSON/UCL parser)
}

-- rspamd Lua files tend to have longer lines in config tables
max_line_length = 150
