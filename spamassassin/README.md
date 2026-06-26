# Scan mail with the remote yarad from SpamAssassin

This directory wires **SpamAssassin** to a central
[`yarad serve`](../README.md): every message SpamAssassin filters is handed to
yarad, and a YARA malware match becomes a SpamAssassin rule hit that lands in the
spam score next to everything else. It is the SpamAssassin sibling of the rspamd
[`yara.lua`](../rspamd/) plugin and the Dovecot/Sieve [`yarad-scan`](../sieve/)
client.

```
   message ─▶ SpamAssassin ─▶ Yarad.pm plugin ──┐
                                                 │  http: POST /scan   ┌────────────┐
                                                 ├────────────────────▶│ yarad serve│
                                                 │  shellout: pipe ───▶ │ (rules +   │
                                                 │           yarad-scan │  libyara)  │
              YARAD / YARAD_HIGH hits ◀──────────┘ ◀─────── {matches} ──└────────────┘
```

Like the Sieve path it **fails open** by default: a yarad outage, timeout, or
transport error is treated as *clean*, so a down backend never tags every
message. (Set `yarad_fail_open 0` to fire `YARAD_ERROR` instead.)

## Two modes

| `yarad_mode` | How | What it sees |
|--------------|-----|--------------|
| `http` (default) | the plugin POSTs the message to `<yarad_url>/scan` itself using core `HTTP::Tiny` — no extra binary | every matched rule's name, namespace, tags **and `meta.score`** → graduated `YARAD` + `YARAD_HIGH` symbols |
| `shellout` | the plugin pipes the message to the lean CGO-free [`yarad-scan`](../sieve/) client and reads its exit code | hit / no-hit only (matched rule names from stdout) — reuses one audited transport |

Use **http** unless you already deploy `yarad-scan` on the box and want a single
transport for both Sieve and SpamAssassin.

## Files here

| File | Goes to | What it is |
|------|---------|------------|
| `Yarad.pm` | a path SpamAssassin can read (e.g. `/etc/spamassassin/`) | the plugin |
| `yarad.pre` | SpamAssassin config dir (e.g. `/etc/spamassassin/`) | the `loadplugin` line |
| `yarad.cf` | SpamAssassin config dir | rule definitions, scores, and connection config |

## Setup

1. **Run the scanner** somewhere central (see the [main README](../README.md)):

   ```sh
   docker run -d --name yarad -e YARAD_TOKEN_FILE=/run/secrets/yarad_token \
       -p 8079:8079 eilandert/rspamd-yarad
   ```

2. **Install the plugin.** Drop `Yarad.pm`, `yarad.pre` and `yarad.cf` into your
   SpamAssassin config dir (`/etc/spamassassin/` or `/etc/mail/spamassassin/`).
   Make sure the `loadplugin` path in `yarad.pre` points at `Yarad.pm`.

3. **Configure** `yarad.cf` — at minimum set `yarad_url`, and `yarad_token_file`
   if your yarad requires a token (chmod `0440`, owned by the SpamAssassin /
   amavis user). For shellout mode set `yarad_mode shellout` and install the
   [`yarad-scan`](../sieve/) binary.

4. **Test the config and lint the rules:**

   ```sh
   spamassassin --lint -D yarad        # plugin loads, rules parse
   # feed a known-malware EML through and check for the hit:
   spamassassin -t < sample.eml | grep -i YARAD
   ```

   On a match you'll see `YARAD` (and `YARAD_HIGH` on a confident hit in http
   mode) in the report, and an `X-Spam-Yara:` header listing the fired YARA rule
   names.

## Scoring

A YARA malware match is high-confidence, so the shipped scores (`YARAD 5.0`,
`YARAD_HIGH 5.0`, stacking to 10) push a confident hit well over the default
spam threshold on their own. Tune in `yarad.cf`; per-rule scoring via the
`X-Spam-Yara` header is shown there too.

## See also

- **[Main README](../README.md)** — the `yarad serve` scanner this talks to.
- **[rspamd plugin](../rspamd/)** — the async `yara.lua` scorer for rspamd.
- **[Dovecot/Sieve example](../sieve/)** — quarantine a match at delivery with
  the `yarad-scan` client (the binary the shellout mode reuses).
- **Article:** [YARA malware scanning in rspamd](https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/).
