# Scan mail with the remote strixd from Dovecot / Sieve

This directory wires a **Dovecot Sieve** delivery rule to a central
[`strixd serve`](../../README.md) using the lean **`strix-scan`** client — for a
mail-delivery box (Dovecot LDA / LMTP) that should stay thin and carries **no
YARA rules and no libyara** of its own.

```
   incoming mail ─▶ Dovecot LDA/LMTP ─▶ Sieve (execute :pipe)
                                          │  message on stdin
                                          ▼
                                   strix-scan-wrapper ─▶ strix-scan ──HTTP /scan──▶  strixd serve
                                          │                                          (rules + libyara)
                          exit 0 clean/log-only / 1 actionable match ◀───────────── {matches}
                                          │
                              actionable match ─▶ flag + fileinto Junk/Yara
                              clean/log-only ─▶ deliver normally
```

`strix-scan` **fails open**: any transport error, timeout, or non-200 is treated
as *clean* (exit 0), so a scanner outage never blocks or bounces delivery. Canary
and allowlisted hits are also log-only (exit 0).

## Files here

| File | Goes to | What it is |
|------|---------|------------|
| `strix-scan.sieve` | `/etc/dovecot/sieve/` | the Sieve rule (quarantine on match) |
| `strix-scan-wrapper` | `sieve_execute_bin_dir` (e.g. `/usr/lib/dovecot/sieve-execute/`), `0755` | shell bridge: pipes stdin to `strix-scan`, returns its exit code |
| `strix-scan.conf.example` | `/etc/dovecot/strix-scan.conf` | URL + token-file for the wrapper |
| `dovecot-sieve-extprograms.conf.example` | `/etc/dovecot/conf.d/` | enables the `execute` Sieve extension |

## Setup

1. **Run the scanner** somewhere central (see the [main README](../../README.md)):

   ```sh
   docker run -d --name strixd -e MAILSTRIX_TOKEN_FILE=/run/secrets/mailstrix_token \
       -p 8079:8079 eilandert/mailstrix
   ```

2. **Install the client** on the mail host — grab `strix-scan-linux-<arch>` from
   the [GitHub release](https://github.com/myguard-labs/mailstrix/releases):

   ```sh
   install -m0755 strix-scan-linux-amd64 /usr/local/bin/strix-scan
   strix-scan -version
   ```

3. **Drop the token** (same secret as the server's `MAILSTRIX_TOKEN`):

   ```sh
   printf '%s' 'the-shared-secret' > /etc/dovecot/strixd.token
   chown vmail:vmail /etc/dovecot/strixd.token && chmod 0440 /etc/dovecot/strixd.token
   ```

   The token is **optional** — if your strixd runs open (no `MAILSTRIX_TOKEN`), skip
   this step. The wrapper only passes `-token-file` when the file exists, so it
   works either way.

4. **Install the wrapper + config:**

   ```sh
   install -m0755 strix-scan-wrapper /usr/lib/dovecot/sieve-execute/strix-scan-wrapper
   install -m0644 strix-scan.conf.example /etc/dovecot/strix-scan.conf   # then edit MAILSTRIX_URL
   install -m0644 strix-scan.sieve        /etc/dovecot/sieve/strix-scan.sieve
   ```

5. **Enable the Sieve `execute` extension** — merge
   `dovecot-sieve-extprograms.conf.example` into your Dovecot config
   (it sets `sieve_plugins = sieve_extprograms`, `sieve_global_extensions =
   +vnd.dovecot.execute`, `sieve_execute_bin_dir`, and `sieve_before =
   …/strix-scan.sieve`), then `doveadm reload`.

## Test it

```sh
# the wrapper alone — pipe a message, check the exit code:
strix-scan-wrapper < /var/mail/some-message ; echo "exit=$?"   # 0 clean, 1 match

# end to end — deliver the EICAR test file and confirm it lands in Junk/Yara
# (build EICAR at runtime; don't store the literal signature):
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf 'Subject: test\n\n%s\n' "$EICAR" | strix-scan-wrapper ; echo "exit=$?"   # expect 1
```

(The baked rules include an EICAR rule, so a real match should fire.) Watch
delivery in the Dovecot log; a match adds the `X-Yara-Scan: MATCH` header and
files into `Junk/Yara`.

## Notes / tuning

- **Fail-open is deliberate.** To make a scanner outage *visible* instead
  (e.g. hold for retry), drop `-fail-open` in the wrapper — but then a down
  scanner causes exit 2 → the `execute` test is false → the message is treated
  like a match. Prefer the default unless you have a retry path.
- **Header-only mode:** to tag but not move, delete the `fileinto`/`setflag`
  lines from `strix-scan.sieve` and keep just `addheader`.
- **Filename hint:** the LDA has the message, not a single attachment, so the
  wrapper sends no `-filename`. Per-attachment naming is the rspamd plugin's job
  ([`../rspamd/`](../rspamd/)); use this Sieve path for whole-message scanning at
  delivery, the rspamd plugin for per-part scanning at SMTP time. They compose.
- **Performance:** the server-side verdict cache means repeated/bulk messages are
  near-free; the client just does one POST per delivery.

See also: the [main README](../../README.md) · the [rspamd plugin](../rspamd/).
