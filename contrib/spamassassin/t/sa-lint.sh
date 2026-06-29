#!/bin/sh
# sa-lint.sh — run `spamassassin --lint` against the real plugin in a throwaway
# debian:trixie-slim container. Mirrors the "spamassassin --lint" CI step so a
# dev can reproduce the real-host lint without a GitHub run or a host SA install.
#
# Loads Mailstrix.pm + mailstrix.pre (loadplugin) + mailstrix.cf (rules/meta) into the
# installed Mail::SpamAssassin and fails on any plugin-load, eval-rule, or
# config error. perl -c / prove only cover plugin syntax + mocked units; this
# covers the registration + config path they cannot.
#
#   contrib/spamassassin/t/sa-lint.sh           # quiet lint (exit 0 = ok)
#   contrib/spamassassin/t/sa-lint.sh -D strixd  # debug plugin load
set -eu

# Repo root = two levels up from this script (contrib/spamassassin/t/).
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)

exec docker run --rm -v "$root:/src" -w /src debian:trixie-slim sh -c '
  apt-get update >/dev/null 2>&1
  apt-get install -y --no-install-recommends spamassassin libhttp-tiny-perl perl >/dev/null 2>&1
  d=/etc/spamassassin
  install -m644 contrib/spamassassin/Mailstrix.pm "$d/Mailstrix.pm"
  install -m644 contrib/spamassassin/mailstrix.pre "$d/mailstrix.pre"
  install -m644 contrib/spamassassin/mailstrix.cf  "$d/mailstrix.cf"
  spamassassin --lint '"$*"'
'
