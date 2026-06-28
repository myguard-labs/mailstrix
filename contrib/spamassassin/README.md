# Scan mail with the remote strixd from SpamAssassin

This directory wires **SpamAssassin** to a central
[`strixd serve`](../../README.md): every message SpamAssassin filters is handed to
strixd, and a YARA malware match becomes a SpamAssassin rule hit that lands in the
spam score next to everything else. It is the SpamAssassin sibling of the rspamd
[`mailstrix.lua`](../rspamd/) plugin and the Dovecot/Sieve [`strix-scan`](../sieve/)
client.

```
   message ─▶ SpamAssassin ─▶ Mailstrix.pm plugin ──┐
                                                 │  http: POST /scan   ┌────────────┐
                                                 ├────────────────────▶│ strixd serve│
                                                 │  shellout: pipe ───▶ │ (rules +   │
                                                 │           strix-scan │  libyara)  │
              MAILSTRIX / MAILSTRIX_HIGH hits ◀──────────┘ ◀─────── {matches} ──└────────────┘
```

Like the Sieve path it **fails open** by default: a strixd outage, timeout, or
transport error is treated as *clean*, so a down backend never tags every
message. (Set `mailstrix_fail_open 0` to fire `MAILSTRIX_ERROR` instead.)

## Two modes

| `mailstrix_mode` | How | What it sees |
|--------------|-----|--------------|
| `http` (default) | the plugin POSTs the message to `<mailstrix_url>/scan` itself using core `HTTP::Tiny` — no extra binary | every matched rule's name, namespace, tags **and `meta.score`** → graduated `MAILSTRIX` + `MAILSTRIX_HIGH` symbols |
| `shellout` | the plugin pipes the message to the lean CGO-free [`strix-scan`](../sieve/) client and reads its exit code | hit / no-hit only (matched rule names from stdout) — reuses one audited transport |

Use **http** unless you already deploy `strix-scan` on the box and want a single
transport for both Sieve and SpamAssassin.

## Files here

| File | Goes to | What it is |
|------|---------|------------|
| `Mailstrix.pm` | a path SpamAssassin can read (e.g. `/etc/spamassassin/`) | the plugin |
| `strixd.pre` | SpamAssassin config dir (e.g. `/etc/spamassassin/`) | the `loadplugin` line |
| `strixd.cf` | SpamAssassin config dir | rule definitions, scores, and connection config |

## Setup

1. **Run the scanner** somewhere central (see the [main README](../../README.md)):

   ```sh
   docker run -d --name strixd -e MAILSTRIX_TOKEN_FILE=/run/secrets/mailstrix_token \
       -p 8079:8079 eilandert/mailstrix
   ```

2. **Install the plugin.** Drop `Mailstrix.pm`, `strixd.pre` and `strixd.cf` into your
   SpamAssassin config dir (`/etc/spamassassin/` or `/etc/mail/spamassassin/`).
   Make sure the `loadplugin` path in `strixd.pre` points at `Mailstrix.pm`.

3. **Configure** `strixd.cf` — at minimum set `mailstrix_url`, and `mailstrix_token_file`
   if your strixd requires a token (chmod `0440`, owned by the SpamAssassin /
   amavis user). For shellout mode set `mailstrix_mode shellout` and install the
   [`strix-scan`](../sieve/) binary.

   **Optional — part mode.** Set `mailstrix_part_mode 1` to scan each leaf MIME
   part's *decoded* body as its own request instead of the whole pristine
   message once. This sends an attachment as its real bytes (base64/QP undone)
   and keeps each request under `mailstrix_max_size`, at the cost of one backend
   round-trip per part. The strixd backend already does its own container/MIME
   extraction, so whole-message mode (`0`, default) is the right choice for most
   deployments — reach for part mode only when large attachments push the whole
   message past `mailstrix_max_size`, or you want the smaller per-part payloads. An
   oversized individual part is skipped (the rest still scan); a part that
   errors is treated under the same `mailstrix_fail_open` policy as a whole-message
   error.

4. **Test the config and lint the rules:**

   ```sh
   spamassassin --lint -D strixd        # plugin loads, rules parse
   # feed a known-malware EML through and check for the hit:
   spamassassin -t < sample.eml | grep -i MAILSTRIX
   ```

   On a match you'll see `MAILSTRIX` (and `MAILSTRIX_HIGH` on a confident hit in http
   mode) in the report, and an `X-Spam-Yara:` header listing the fired YARA rule
   names.

   For development, hermetic unit tests (no running strixd — http mode mocks
   `HTTP::Tiny`, shellout mode uses fake `strix-scan` scripts) live in
   [`t/mailstrix.t`](t/mailstrix.t) and run in CI alongside `perl -c`:

   ```sh
   perl -I . -c Mailstrix.pm                 # syntax check against Mail::SpamAssassin
   prove -v -I . t/mailstrix.t               # verdict mapping + both transport modes
   ```

   To reproduce the CI **real-host `spamassassin --lint`** (loads the plugin via
   `strixd.pre` + the rules in `strixd.cf` into an installed SpamAssassin, in a
   throwaway `debian:trixie-slim` container — no host SA needed):

   ```sh
   t/sa-lint.sh                          # quiet lint (exit 0 = ok)
   t/sa-lint.sh -D strixd                 # debug plugin load
   ```

## Scoring

A YARA malware match is high-confidence, so the shipped scores (`MAILSTRIX 5.0`,
`MAILSTRIX_HIGH 5.0`, stacking to 10) push a confident hit well over the default
spam threshold on their own. Tune in `strixd.cf`; per-rule scoring via the
`X-Spam-Yara` header is shown there too.

## See also

- **[Main README](../../README.md)** — the `strixd serve` scanner this talks to.
- **[rspamd plugin](../rspamd/)** — the async `mailstrix.lua` scorer for rspamd.
- **[Dovecot/Sieve example](../sieve/)** — quarantine a match at delivery with
  the `strix-scan` client (the binary the shellout mode reuses).
- **Article:** [YARA malware scanning in rspamd](https://deb.myguard.nl/articles/yara-malware-scanning-mailstrix/).
