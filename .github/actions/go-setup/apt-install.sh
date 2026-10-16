#!/usr/bin/env bash
# Install apt packages on a self-hosted runner, tolerating a brief mirror/proxy
# outage. Usage: apt-install.sh pkg [pkg...]
#
#  - every package already installed (dpkg-query)  -> no apt call at all
#  - otherwise `apt-get update` + `install` are retried, bounded, with backoff
#  - a persistent failure still fails (last apt exit status is returned)
#  - no apt source is added or changed
#
# Tunables (tests set them; defaults suit CI): APT_ATTEMPTS (4), APT_BACKOFF
# (base seconds, doubled per retry, 5 -> 5+10+20s worst case = 35s of sleep).
set -uo pipefail

attempts="${APT_ATTEMPTS:-4}"
backoff="${APT_BACKOFF:-5}"

case "$attempts" in '' | *[!0-9]* | 0) echo "apt-install: bad APT_ATTEMPTS=$attempts" >&2; exit 2 ;; esac
case "$backoff" in '' | *[!0-9]*) echo "apt-install: bad APT_BACKOFF=$backoff" >&2; exit 2 ;; esac

if [ "$#" -eq 0 ]; then
  echo "apt-install: no packages requested" >&2
  exit 2
fi

missing=()
for pkg in "$@"; do
  # Debian package names: lowercase alnum start, then alnum + . - (optional :arch).
  if ! [[ "$pkg" =~ ^[a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?$ ]]; then
    echo "apt-install: invalid package name: $pkg" >&2
    exit 2
  fi
  status="$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)"
  if [ "$status" != "install ok installed" ]; then
    missing+=("$pkg")
  fi
done

if [ "${#missing[@]}" -eq 0 ]; then
  echo "apt-install: already installed: $*"
  exit 0
fi

rc=0
delay="$backoff"
for ((i = 1; i <= attempts; i++)); do
  sudo apt-get -o Acquire::Retries=3 update \
    && sudo apt-get -o Acquire::Retries=3 install -y --no-install-recommends "${missing[@]}"
  rc=$?
  [ "$rc" -eq 0 ] && exit 0
  if [ "$i" -lt "$attempts" ]; then
    echo "apt-install: attempt $i/$attempts failed (rc=$rc); retrying in ${delay}s" >&2
    sleep "$delay"
    delay=$((delay * 2))
  fi
done
echo "apt-install: giving up after $attempts attempts (rc=$rc)" >&2
exit "$rc"
