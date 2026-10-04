#!/bin/sh
# Packaged defaults must enable daily polling without changing the Go default.
set -eu
cd "$(dirname "$0")/.."
for file in docker/Dockerfile docker/Dockerfile.release packaging/deb/strixd.env; do
	count=$(grep -cE '^[[:space:]]*MAILSTRIX_RULES_POLL_INTERVAL=86400( \\)?$' "$file" || true)
	if [ "$count" != 1 ]; then
		echo "FAIL: $file must set the daily polling default exactly once" >&2
		exit 1
	fi
done
grep -qE '^[[:space:]]*MAILSTRIX_RULES_POLL_INTERVAL: "86400"' docker/docker-compose.yml
if ! grep -qE '^[[:space:]]*-[[:space:]]+/var/cache/mailstrix:uid=65532,gid=65532,mode=0755[[:space:]]*$' docker/docker-compose.yml; then
	echo 'FAIL: Compose must mount an active writable nonroot rules cache tmpfs' >&2
	exit 1
fi
# The existing packaging key gate must see the active key, not only a comment.
grep -qx 'MAILSTRIX_RULES_POLL_INTERVAL=86400' packaging/deb/strixd.env
echo 'PASS: Docker, Compose and Debian daily polling defaults'
