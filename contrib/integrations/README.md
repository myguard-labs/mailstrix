# Mail server integration recipes

These recipes connect an existing mail filter to [Mailstrix](../../README.md)
using the shipped [Rspamd plugin](../rspamd/) or
[SpamAssassin plugin](../spamassassin/). They were checked against upstream
documentation and source on 2026-09-06; they have not been deployment-tested.
Recheck the paths against your installed release before applying them.

- [Mailcow](#mailcow)
- [docker-mailserver](#docker-mailserver)
- [Mailu](#mailu)
- [Proxmox Mail Gateway](#proxmox-mail-gateway)

## Shared prerequisites

Deploy `strixd serve` separately using the [server instructions](../../README.md).
Keep its HTTP endpoint on a trusted private network: requests contain message
bodies and the authentication token. For a remote network, use an authenticated,
encrypted transport. A token authenticates a request; it does not encrypt HTTP.

Choose an address reachable **from the filtering process**. `127.0.0.1` inside a
container refers to that container, not the host or a sibling container. For
Rspamd, use a reserved scanner IP on the shared private network, or a hostname
resolvable by Rspamd's configured DNS resolver; Docker's service-name resolution
is not sufficient evidence that Rspamd can resolve the name. The address below,
`192.0.2.10`, is a documentation placeholder and must be replaced.

Provision a token file outside Git and mount it read-only where needed. Its
contents must match the scanner's token. Use ownership and mode such as `0440`
that let the actual filter worker read it; verify directory traversal permissions
and container UID/GID mappings too. Do not make the token world-readable.
Plugin and configuration files can be root-owned `0644`.

Back up the affected configuration and Compose files first. Use a staging copy
of the mail stack and scanner for the checks below. Start with the staging
scanner's `MAILSTRIX_CANARY=1` and retain zero weights for canary/allowlisted
symbols. These plugins contribute scores; the mail stack still decides delivery,
quarantine and rejection. An absent match does not prove a scan happened: size
limits, timeouts and backend failures can leave a message unscanned.

## Rspamd configuration used below

The plugin uses Rspamd's bundled Lua modules (`rspamd_http`, `lua_util`, `ucl`,
among others); libyara belongs on the scanner, not in the Rspamd image.
Copy [mailstrix.lua](../rspamd/plugins/mailstrix.lua) and
[groups.conf](../rspamd/local.d/groups.conf) from the same Mailstrix release.

Merge this block into the platform's `rspamd.conf.local`, preserving existing
settings. Adjust or omit the Lua loader per recipe. Keep the configuration inline:
`local.d/mailstrix.conf` alone does not load this custom module. The explicit
`symbol = "STRIX"` agrees with the shipped scoring group.

```ucl
lua = "/opt/mailstrix-rspamd/mailstrix.lua";
mailstrix {
  url = "http://192.0.2.10:8079/scan";
  token_file = "/run/secrets/mailstrix_token";
  timeout = 10.0;
  max_size = 8388608;
  symbol = "STRIX";
  scan_message = true;
  scan_parts = true;
  min_part_size = 64;
}
```

Before using this block with **any of the three Rspamd recipes**, check the
whole scan deadline chain. The plugin's 10-second HTTP timeout must exceed the
scanner's queue plus scan timeout (defaults total 9 seconds), but must also fit
inside the effective Rspamd task deadline with time left for other filters and
overhead. Upstream documents an 8-second `task_timeout` default for both the
[normal worker](https://docs.rspamd.com/workers/normal/) and
[controller scan requests](https://docs.rspamd.com/workers/controller/).
That default is too short for this example's full scan budget. A worker's
`timeout` is its protocol I/O timeout; increasing it alone does not extend
`task_timeout`.

Inspect `rspamadm configdump worker options` locally in the filtering container
and compare the effective settings with your installed release's defaults; keep
configuration dumps private. Trace the MTA's actual scan route: the
[proxy worker](https://docs.rspamd.com/workers/rspamd_proxy/) can forward to a
normal scanner or scan itself with `self_scan`. Adjust the task deadline for
the worker that actually scans, including applicable
[global task options](https://docs.rspamd.com/configuration/options/), through
the platform's persistent configuration. Changing an unused normal worker
does not change a self-scan proxy's deadline. Check the controller separately
for WebUI/`rspamc` scans, and allow the complete task budget plus transport
overhead in the upstream proxy and MTA response timeouts.

If those outer deadlines must stay fixed, reduce the scanner's
`MAILSTRIX_BACKEND_TIMEOUT` and `MAILSTRIX_SCAN_TIMEOUT` and the plugin timeout
together so that the entire budget fits. A shorter budget can leave more scans
unfinished; confirm the resulting timeout policy in staging rather than treating
an interrupted scan as clean. Align size limits with your mail policy; the
example caps each request at 8 MiB. Rspamd transport errors do not add a malware
score.

### Mailcow

Mailcow documents custom modules in
[`data/conf/rspamd/plugins.d/`](https://docs.mailcow.email/manual-guides/Rspamd/u-e-rspamd-add-additional-modules/)
and their inline configuration in `data/conf/rspamd/rspamd.conf.local`.
This recipe follows that layout, not a fixed Mailcow release number.

1. Copy `mailstrix.lua` into `data/conf/rspamd/plugins.d/`. Merge only the
   `mailstrix { ... }` block above into `data/conf/rspamd/rspamd.conf.local`.
   Omit the `lua =` line: Mailcow loads `plugins.d/` modules automatically,
   as shown in its upstream module-loading instructions. An additional explicit
   loader would risk loading the plugin twice.
   Also copy `contrib/rspamd/mailstrix-preflight.lua` to
   `data/conf/rspamd/mailstrix-preflight.lua` (outside `plugins.d/`) and add:

   ```ucl
   lua = "/etc/rspamd/mailstrix-preflight.lua";
   ```

   This validation-only include rejects unsupported `cape_policy` values before
   workers start. Rspamd's module auto-loader logs plugin errors but can still
   start the daemon; the explicit preflight is required even with both scan
   toggles disabled. It does not register the plugin a second time.
2. Merge the shipped `group "STRIX"` into
   `data/conf/rspamd/local.d/groups.conf`, preserving other groups.
3. Add a read-only token-file bind mount to the `rspamd-mailcow` service at
   `/run/secrets/mailstrix_token` in your Compose override. Pre-create the host
   file and check its readability as the Rspamd worker. Keep scanner addressing
   within a network reachable by `rspamd-mailcow`.
4. In staging, apply any mount changes by recreating the affected service using
   your Mailcow release's Compose procedure, then run
   `docker compose exec rspamd-mailcow rspamadm configtest`. Confirm a single
   Mailstrix module initialization in its logs and perform the scan checks below.

Rollback: restore the prior `rspamd.conf.local` and groups file, remove only the
added plugin and token mount, and recreate `rspamd-mailcow` if mounts changed.
Run `configtest` again. Keep unrelated modules and scoring groups intact.

### docker-mailserver

Scope: [v16.0.1](https://github.com/docker-mailserver/docker-mailserver/releases/tag/v16.0.1),
with Rspamd already configured (`ENABLE_RSPAMD=1`). Follow the upstream
[Rspamd setup](https://docker-mailserver.github.io/docker-mailserver/latest/config/security/rspamd/)
first if the installation currently uses Amavis/SpamAssassin; switching filters
is a separate migration.

DMS copies `rspamd/override.d/*` from its config volume during startup.
That mechanism alone does not load a new Lua module. Use explicit file mounts
for the top-level configuration and plugin:

1. Create a host directory `mailstrix-rspamd/` beside your Compose file. Place
   `mailstrix.lua` and a working copy of `rspamd.conf.local` there. Preserve any
   existing top-level local settings and merge the shared block above.
2. Add these read-only mounts to the existing `mailserver` service (substitute
   your service name and token source). Pre-create every source file.

   ```yaml
   volumes:
     - ./mailstrix-rspamd:/opt/mailstrix-rspamd:ro
     - ./mailstrix-rspamd/rspamd.conf.local:/etc/rspamd/rspamd.conf.local:ro
     - ./secrets/mailstrix_token:/run/secrets/mailstrix_token:ro
   ```

3. Merge the shipped scoring group into
   `docker-data/dms/config/rspamd/override.d/groups.conf`. This path is relative
   to DMS's default config-volume location; preserve any existing groups file.
4. Recreate `mailserver` in staging to apply the mounts and startup copies.
   Run `docker compose exec mailserver rspamadm configtest`, then check logs
   and scan results. The Rspamd worker is `_rspamd` in this release; the token
   must be readable by its container UID/GID.

Rollback: restore the previous groups file and Compose mounts, recreate
`mailserver`, and rerun `configtest`. If a prior `rspamd.conf.local` mount existed,
restore that source as well. DMS's
[startup source](https://github.com/docker-mailserver/docker-mailserver/blob/v16.0.1/target/scripts/startup/setup.d/security/rspamd.sh)
documents the config-copy order; recheck it when upgrading.

### Mailu

Scope: Mailu's stable **2024.06** branch. Its
[antispam documentation](https://mailu.io/2024.06/antispam.html) maps the host
`overrides/rspamd/` directory to `/overrides` in `antispam`. The
[startup script](https://github.com/Mailu/Mailu/blob/2024.06/core/rspamd/start.py)
renders/copies those files into `/etc/rspamd/local.d/`. A file named
`overrides/rspamd/rspamd.conf.local` would therefore land at the wrong level.

Use the same `mailstrix-rspamd/` directory and three explicit mounts from the
DMS recipe, added to Mailu's **`antispam`** service instead. Keep this directory
outside `overrides/rspamd/`. Merge the shared Rspamd block into the mounted
`rspamd.conf.local`. Merge the scoring group into the host
`overrides/rspamd/groups.conf`, preserving any existing groups.

Mailu starts Rspamd as user/group `rspamd`; set token ownership for that
container's numeric IDs. Recreate `antispam` in staging to apply mounts and
startup copies, then run `docker compose exec antispam rspamadm configtest`
and the scan checks below. Recheck the mapping for other Mailu branches.

Rollback: restore the prior Compose configuration and groups override, then
recreate `antispam` and rerun `configtest`. Restore a pre-existing top-level
configuration mount rather than removing it.

## Proxmox Mail Gateway

Use the SpamAssassin **HTTP** mode. The current
[PMG administration guide, Custom SpamAssassin configuration](https://pmg.proxmox.com/pmg-docs/pmg-admin-guide.html#_custom_spamassassin_configuration)
reserves `/etc/mail/spamassassin/custom.cf` for local rules. Check the equivalent
section for your installed PMG version; do not edit generated `local.cf` or
`init.pre`.

1. Install [Mailstrix.pm](../spamassassin/Mailstrix.pm) at
   `/etc/mail/spamassassin/Mailstrix.pm`, root-owned and readable by the filter.
   HTTP mode needs Perl `HTTP::Tiny` and `JSON::PP`, alongside SpamAssassin.
   Check availability with `perl -MHTTP::Tiny -MJSON::PP -e 1`.
2. In `custom.cf`, add this absolute-path loader **before** the contents of the
   shipped [mailstrix.cf](../spamassassin/mailstrix.cf). Preserve existing rules.

   ```text
   loadplugin Mail::SpamAssassin::Plugin::Mailstrix /etc/mail/spamassassin/Mailstrix.pm
   ```

3. In the copied settings, set `mailstrix_mode http`, replace `mailstrix_url`
   with your reachable scanner base URL (for example `http://192.0.2.10:8079`,
   **without `/scan`**), and set
   `mailstrix_token_file /etc/mailstrix/strixd.token`. Keep the token readable
   by the actual `pmg-smtp-filter` worker identity; do not assume a standalone
   SpamAssassin service user. Retain `mailstrix_fail_open 1` for the initial
   trial and check the timeout/size settings in the plugin README.
4. Run `spamassassin --lint` in staging. After a successful lint, PMG requires
   a `pmg-smtp-filter` restart to load the configuration; plan that restart in
   your normal maintenance procedure. Test a harmless message with
   `spamassassin -t < harmless.eml` and inspect the report plus scanner logs.

In a PMG cluster, `custom.cf` is synchronized and can trigger filter restarts
on members. Distribute `Mailstrix.pm` and the token securely to **every node
before** changing `custom.cf`; the documented sync does not establish that
these extra files are copied. Check lint and file permissions on every node.

Rollback: restore `custom.cf`, lint it, and restart the filter through the same
maintenance procedure. Remove the extra plugin/token only after every node has
stopped referencing them. PMG's spam rules decide what the resulting score does;
a Mailstrix hit is not automatically a PMG virus-detector event.

## Scan checks in staging

After a successful syntax check, submit a harmless RFC 5322 message through the
staging filter and correlate its scan with the scanner logs. For Rspamd, use its
WebUI scan facility or `rspamc` against the staging worker; check that Mailstrix
initializes once and that no token-read, HTTP or timeout errors appear.

To check the positive path, use an inert marker message and an operator-owned
test YARA rule matching only that marker on the staging scanner. In canary mode,
Rspamd should report `STRIX_CANARY` at zero weight; SpamAssassin should leave
`MAILSTRIX`/`MAILSTRIX_HIGH` absent while the scanner records the canary match.
A harmless message without the marker is the negative case. Do not use live
malware or production mail for this check.

Finally, point only the staging configuration at an unavailable test endpoint
and confirm the logged error and unchanged malware score. Restore the endpoint
and repeat the harmless scan. Syntax success alone cannot validate authentication,
network reachability, score policy or rollback. Review staging observations before
changing canary mode or enabling nonzero production scores.
