#!/bin/sh
set -e

# dpkg calls prerm with "upgrade <newver>" before unpacking a replacement and
# with "remove" (or "remove in-favour ...") on an actual removal. Only stop and
# disable the service when the package is really going away — on an upgrade the
# old unit must keep running until postinst restarts it with the new binary,
# otherwise a routine `apt upgrade` would silently leave the milter down. With
# milter_default_action=accept that means unscanned mail; with =tempfail it
# means a mail outage. Neither is acceptable from an upgrade.
case "$1" in
    remove|deconfigure)
        if [ -d /run/systemd/system ]; then
            systemctl stop strix-milter >/dev/null 2>&1 || true
            systemctl disable strix-milter >/dev/null 2>&1 || true
        fi
        ;;
    upgrade|failed-upgrade)
        # keep the running service; postinst restarts it after the new unpack
        ;;
esac
