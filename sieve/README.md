# Scan mail with the remote yarad from Dovecot / Sieve

This directory wires a **Dovecot Sieve** delivery rule to a central
[`yarad serve`](../README.md) using the lean **`yarad-scan`** client — for a
mail-delivery box (Dovecot LDA / LMTP) that should stay thin and carries **no
YARA rules and no libyara** of its own.

```
   incoming mail ─▶ Dovecot LDA/LMTP ─▶ Sieve (execute :pipe)
                                          │  message on stdin
                                          ▼
                                   yarad-scan-wrapper ─▶ yarad-scan ──HTTP /scan──▶  yarad serve
                                          │                                          (rules + libyara)
                          exit 0 clean / 1 match ◀───────────────────────────────── {matches}
                                          │
                              match ─▶ flag + fileinto Junk/Yara
                              clean ─▶ deliver normally
```

`yarad-scan` **fails open**: any transport error, timeout, or non-200 is treated
as *clean* (exit 0), so a scanner outage never blocks or bounces delivery.

## Files here

| File | Goes to | What it is |
|------|---------|------------|
| `yarad-scan.sieve` | `/etc/dovecot/sieve/` | the Sieve rule (quarantine on match) |
| `yarad-scan-wrapper` | `sieve_execute_bin_dir` (e.g. `/usr/lib/dovecot/sieve-execute/`), `0755` | shell bridge: pipes stdin to `yarad-scan`, returns its exit code |
| `yarad-scan.conf.example` | `/etc/dovecot/yarad-scan.conf` | URL + token-file for the wrapper |
| `dovecot-sieve-extprograms.conf.example` | `/etc/dovecot/conf.d/` | enables the `execute` Sieve extension |

## Setup

1. **Run the scanner** somewhere central (see the [main README](../README.md)):

   ```sh
   docker run -d --name yarad -e YARAD_TOKEN_FILE=/run/secrets/yarad_token \
       -p 8079:8079 eilandert/rspamd-yarad
   ```

2. **Install the client** on the mail host — grab `yarad-scan-linux-<arch>` from
   the [GitHub release](https://github.com/eilandert/rspamd-yarad/releases):

   ```sh
   install -m0755 yarad-scan-linux-amd64 /usr/local/bin/yarad-scan
   yarad-scan -version
   ```

3. **Drop the token** (same secret as the server's `YARAD_TOKEN`):

   ```sh
   printf '%s' 'the-shared-secret' > /etc/dovecot/yarad.token
   chown vmail:vmail /etc/dovecot/yarad.token && chmod 0440 /etc/dovecot/yarad.token
   ```

   The token is **optional** — if your yarad runs open (no `YARAD_TOKEN`), skip
   this step. The wrapper only passes `-token-file` when the file exists, so it
   works either way.

4. **Install the wrapper + config:**

   ```sh
   install -m0755 yarad-scan-wrapper /usr/lib/dovecot/sieve-execute/yarad-scan-wrapper
   install -m0644 yarad-scan.conf.example /etc/dovecot/yarad-scan.conf   # then edit YARAD_URL
   install -m0644 yarad-scan.sieve        /etc/dovecot/sieve/yarad-scan.sieve
   ```

5. **Enable the Sieve `execute` extension** — merge
   `dovecot-sieve-extprograms.conf.example` into your Dovecot config
   (it sets `sieve_plugins = sieve_extprograms`, `sieve_global_extensions =
   +vnd.dovecot.execute`, `sieve_execute_bin_dir`, and `sieve_before =
   …/yarad-scan.sieve`), then `doveadm reload`.

## Test it

```sh
# the wrapper alone — pipe a message, check the exit code:
yarad-scan-wrapper < /var/mail/some-message ; echo "exit=$?"   # 0 clean, 1 match

# end to end — deliver the EICAR test file and confirm it lands in Junk/Yara
# (build EICAR at runtime; don't store the literal signature):
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf 'Subject: test\n\n%s\n' "$EICAR" | yarad-scan-wrapper ; echo "exit=$?"   # expect 1
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
  lines from `yarad-scan.sieve` and keep just `addheader`.
- **Filename hint:** the LDA has the message, not a single attachment, so the
  wrapper sends no `-filename`. Per-attachment naming is the rspamd plugin's job
  ([`../rspamd/`](../rspamd/)); use this Sieve path for whole-message scanning at
  delivery, the rspamd plugin for per-part scanning at SMTP time. They compose.
- **Performance:** the server-side verdict cache means repeated/bulk messages are
  near-free; the client just does one POST per delivery.

See also: the [main README](../README.md) · the [rspamd plugin](../rspamd/).
