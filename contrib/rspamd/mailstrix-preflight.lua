-- Explicit lua include for deployments that auto-load mailstrix.lua.
-- Keep this file outside plugins.d: auto-loader errors do not stop Rspamd.
-- Validation only: no token reads, symbol registration, or network activity.
-- The shared policy test matrix checks this predicate and the plugin together.
local opts = rspamd_config:get_all_opt("mailstrix")
local cape_policy
if type(opts) == "table" then cape_policy = opts.cape_policy end
if cape_policy ~= nil and
    (type(cape_policy) ~= "string" or (cape_policy ~= "" and cape_policy ~= "static-only")) then
  require("lua_cfg_utils").push_config_error("mailstrix",
      "unsupported cape_policy: adapter requires static-only")
  error("unsupported cape_policy: adapter requires static-only")
end
