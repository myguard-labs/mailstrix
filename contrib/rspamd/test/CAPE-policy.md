# Adapter policy checks

`strix-milter -cape-policy` overrides `MAILSTRIX_CAPE_POLICY`; empty, omitted and
`static-only` preserve report-only operation. Any other value fails startup before
the listener or token file is opened. ICAP uses strixd's existing
`MAILSTRIX_CAPE_POLICY` / `-cape-policy` and checks it before binding its listener.
The daemon also validates this policy before starting its other listeners.
These checks never submit CAPE jobs, poll for results or associate manual jobs
with messages; existing static decisions and deadlines still apply.

Rspamd's `cape_policy` belongs in the inline `mailstrix { }` block in
`rspamd.conf.local`, alongside the explicit Lua include, as in the supplied
example. Omitted, empty and `static-only` preserve static scanning. Unsupported
strings (including `quarantine-pending` and `tempfail`) and non-string values
record a `lua_cfg_utils.push_config_error` and raise a Lua error before token
reads or registration, including when both scan toggles are false. An explicit
Lua include propagates that error to configuration loading and refuses startup.
No quarantine ownership is provided.

For module auto-loaders, including Mailcow, explicitly include the standalone
`mailstrix-preflight.lua` outside `plugins.d/`, following the
[integration recipe](../../integrations/README.md#mailcow). The preflight only
validates configuration; the plugin continues to register once through the
auto-loader. Auto-loader errors alone do not prevent Rspamd startup.

The mock test runs one policy matrix against both validators, and checks a
static scan through the plugin:

```sh
lua contrib/rspamd/test/mailstrix_cape_policy_spec.lua
go test ./cmd/strix-milter ./internal/mailstrix \
  -run '^TestCAPE((Milter|ICAP)StartupPolicy|ICAPPolicyBeforeListen)$' \
  -count=1 -timeout=60s
```

The real-process test requires Python 3 and Rspamd (CI uses Debian trixie).
It creates private configurations and Unix sockets under `/tmp`, sends no mail,
and retains diagnostic logs at the printed artifact path:

```sh
python3 contrib/rspamd/test/cape_startup_test.py
```

It checks actual UCL conversion, strict configtest and direct daemon startup for
the explicit plugin include and the auto-loader with explicit preflight. Valid
cases must start and register exactly once; invalid policies must report the
policy error and exit nonzero without a worker socket. An extracted installation
can be selected with `--prefix /path/to/root`.

These controls mutate isolated copies and must fail the same startup assertion:

```sh
python3 contrib/rspamd/test/cape_startup_test.py --mode inline --mutation return
python3 contrib/rspamd/test/cape_startup_test.py --mode autoload --mutation remove-preflight
```

Rspamd 3.12.1 has been exercised locally; this is cold-start evidence, not a
claim about every Rspamd release or a deployed Mailcow installation. Run
configtest on the actual deployment configuration before restarting it.
