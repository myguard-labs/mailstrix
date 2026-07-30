# Scan mail with the remote strixd from Postfix / Sendmail

This directory wires an **MTA** to a central [`strixd serve`](../../README.md)
using the lean **`strix-milter`** front-end — for a mail gateway that should stay
thin and carries **no YARA rules and no libyara** of its own.

```
   incoming SMTP ─▶ Postfix / Sendmail ─▶ strix-milter ──HTTP /scan──▶  strixd serve
                          ▲                    │                       (rules + libyara)
                          │        X-Mailstrix-Status: ... ◀───────────── {matches}
                          │                    │
                    header_checks ◀────────────┘
                          │
              infected ─▶ HOLD / REJECT      clean, unknown ─▶ deliver
```

`strix-milter` **always accepts**. It never rejects, defers, discards or
quarantines — it only stamps `X-Mailstrix-*` headers. A scanner outage, timeout or
oversized message is just an `unknown` stamp, so a bug here can never eat mail.
Turning the verdict into policy is `header_checks`' job, where you already express
mail policy and can change it without restarting the filter.

This is the **SMTP-time, whole-message** path. For per-attachment scanning at SMTP
time use the [rspamd plugin](../rspamd/); for delivery-time scanning on a Dovecot
box use [Sieve](../sieve/). They compose.

## Files here

| File | Goes to | What it is |
|------|---------|------------|
| `main.cf.example` | merge into `/etc/postfix/main.cf` | milter socket + `milter_default_action` + timeouts |
| `header_checks.example` | `/etc/postfix/header_checks` | turns `X-Mailstrix-Status: infected` into HOLD (or REJECT) |
| `sendmail.mc.example` | merge into `/etc/mail/sendmail.mc` | the Sendmail equivalent (`INPUT_MAIL_FILTER`) |

## Setup

1. **Run the scanner** somewhere central (see the [main README](../../README.md)):

   ```sh
   docker run -d --name strixd -e MAILSTRIX_TOKEN_FILE=/run/secrets/mailstrix_token \
       -p 8079:8079 myguard-labs/mailstrix
   ```

2. **Install the milter** on the MTA host — the `.deb` ships a hardened systemd
   unit, its own unprivileged user, and `/etc/mailstrix/strix-milter.env`:

   ```sh
   sudo apt install ./strix-milter_<ver>_<arch>.deb
   strix-milter -version
   ```

   Or take the static `strix-milter-linux-<arch>` binary from the
   [GitHub release](https://github.com/myguard-labs/mailstrix/releases).

3. **Point it at strixd** — set `MAILSTRIX_URL` (and `MAILSTRIX_TOKEN`, if your
   strixd requires one; prefer `-token-file` in `ExecStart` to keep the secret out
   of a world-readable env file):

   ```sh
   sudoedit /etc/mailstrix/strix-milter.env
   sudo systemctl enable --now strix-milter
   ```

4. **Wire the MTA:**

   ```sh
   # Postfix
   sudo install -m0644 header_checks.example /etc/postfix/header_checks
   # then merge main.cf.example into /etc/postfix/main.cf
   sudo postfix check && sudo systemctl reload postfix
   ```

   For Sendmail, merge `sendmail.mc.example` instead, rebuild `sendmail.cf` with
   `m4`, and restart.

Keep the listener on **loopback or a unix socket**: anyone who can reach it can
have messages scanned.

## Test it

```sh
# 1. the milter is up and strixd is reachable
systemctl status strix-milter
journalctl -u strix-milter -f &

# 2. end to end — send the EICAR test file through the MTA and confirm it is held
# (build EICAR at runtime; don't store the literal signature):
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf 'Subject: milter test\n\n%s\n' "$EICAR" | sendmail -i you@example.org

mailq                    # expect the message in the hold queue
postsuper -r <queue_id>  # release that one message, or
postsuper -d <queue_id>  # delete it
```

`postsuper -d ALL hold` empties the whole hold queue. On a live gateway that
throws away every held message, not only your test one, so prefer the queue id.

(The baked rules include an EICAR rule, so a real match should fire.) On a clean
message, check the stamp survived:

```sh
printf 'Subject: clean test\n\nhello\n' | sendmail -i you@example.org
# then in the delivered message: X-Mailstrix-Status: clean
```

If no `X-Mailstrix-*` header appears **at all**, the milter was not consulted —
check `smtpd_milters` and that the socket in `main.cf` matches
`MAILSTRIX_MILTER_LISTEN`. That is distinct from
`X-Mailstrix-Status: unknown`, which means the milter *did* run but could not get
a verdict; `X-Mailstrix-Info` carries the reason (strixd unreachable, message over
`-max-body`, empty body).

## Notes / tuning

- **`milter_default_action = accept` is required, not a preference.** With the
  Postfix default (`tempfail`), a milter outage defers your entire mailflow. The
  Sendmail equivalent is `F=` (empty) rather than `F=T`.
- **`unknown` is not a clean bill of health** — it means *not scanned* (outage,
  oversized, empty). Decide explicitly what to do with it; the shipped
  `header_checks` delivers it and lets the rest of the stack judge.
- **Forged headers are deleted, not just logged.** A sender shipping their own
  `X-Mailstrix-Status: clean` would otherwise win a first-match header lookup, so
  the milter removes every inbound `X-Mailstrix-*` header before stamping its own,
  and never feeds it to the scanner.
- **Sizing:** memory is bounded at roughly `-max-conns × -max-body`
  (64 × 8 MiB by default). Raise `-max-body` only with `-max-conns` in mind — the
  systemd unit's `MemoryMax=512M` is the backstop, and an OOM restart would, with
  `milter_default_action = accept`, let mail through unscanned.
- **Timeouts:** keep the MTA's content timeout above the milter's `-timeout`
  (default `20s`) so the milter returns its own `unknown` verdict instead of the
  MTA giving up on it first.
- **Performance:** the server-side verdict cache makes repeated/bulk messages
  near-free; the milter does one POST per message.

See also: the [main README](../../README.md) · the
[rspamd plugin](../rspamd/) · [Dovecot/Sieve](../sieve/) ·
[SpamAssassin](../spamassassin/).
