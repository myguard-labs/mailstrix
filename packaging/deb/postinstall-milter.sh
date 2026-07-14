#!/bin/sh
set -e

# Create the strix-milter service account (sysusers if available, else useradd).
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/strix-milter.conf >/dev/null 2>&1 || true
elif ! getent passwd strix-milter >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --no-create-home \
            --shell /usr/sbin/nologin --comment "strix-milter mail filter" strix-milter || true
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # On an upgrade ($1 = configure <oldver>), restart the unit so the new binary
    # takes over — but only if it was already active, so a fresh install stays
    # stopped until the operator points it at a strixd and enables it.
    # try-restart is a no-op when the unit is not running.
    if [ "$1" = configure ] && [ -n "$2" ]; then
        systemctl try-restart strix-milter >/dev/null 2>&1 || true
    fi
fi

# First-time install ($2 empty) prints setup hints; an upgrade stays quiet.
if [ -z "$2" ]; then
    echo "strix-milter installed. Point it at your strixd in /etc/mailstrix/strix-milter.env, then:"
    echo "  systemctl enable --now strix-milter"
    echo "Then tell the MTA to use it, e.g. Postfix main.cf:"
    echo "  smtpd_milters = inet:127.0.0.1:8081"
    echo "  milter_default_action = accept"
    echo "It always ACCEPTS and stamps X-Mailstrix-Status; use header_checks to act on it."
fi
