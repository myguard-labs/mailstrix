# yarad-scan.sieve — quarantine a message when yarad's YARA rules match it.
#
# Project:  https://github.com/eilandert/rspamd-yarad
# Write-up: https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/
#
# This runs at delivery (Dovecot LDA / LMTP) and pipes the message to the
# `yarad-scan-wrapper` program (a thin shell wrapper around the CGO-free
# `yarad-scan` client, which POSTs the message to a central `yarad serve`).
#
# The `execute` TEST succeeds when the program exits 0. yarad-scan exits:
#   0  clean  — no rule matched (ALSO on a scanner outage: it fails open)
#   1  match  — at least one YARA rule fired
# so:  execute true  => clean     => deliver normally
#      execute false => MATCH     => flag + quarantine
# A scanner being down therefore delivers normally — mail is never lost.
#
# Requires the Dovecot `sieve_extprograms` plugin (the `vnd.dovecot.execute`
# extension) — see README.md in this directory for the dovecot config.

require ["vnd.dovecot.execute", "fileinto", "mailbox", "imap4flags", "editheader"];

if not execute :pipe "yarad-scan-wrapper" {
    # A YARA rule matched. Tag the message and drop it in a quarantine folder
    # instead of the inbox. Adjust to taste (reject, discard, header-only, …).
    addheader "X-Yara-Scan" "MATCH";
    setflag "\\Flagged";
    fileinto :create "Junk/Yara";
    stop;
}

# Clean (or scanner unreachable): fall through to normal delivery.
addheader "X-Yara-Scan" "clean";
