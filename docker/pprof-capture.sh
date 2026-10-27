#!/bin/sh
# pprof-capture.sh — capture a baseline set of pprof profiles from a running
# strixd under load, for PERF-* work (alloc/CPU hot-path tuning). strixd must be
# started with MAILSTRIX_PPROF=1; if it also runs MAILSTRIX_METRICS_AUTH=1, pass the
# token in MAILSTRIX_TOKEN so the /debug/pprof gate lets us in.
#
# Usage:
#   MAILSTRIX_TOKEN=secret ./pprof-capture.sh [base-url] [cpu-seconds] [out-dir]
# Defaults: base-url=http://127.0.0.1:8079  cpu-seconds=30  out-dir=./pprof-<ts>
#
# Output: cpu.pb.gz, heap.pb.gz, allocs.pb.gz, goroutine.pb.gz + a profiles.txt
# top listing for each, so a profile can be diffed across builds. Inspect with:
#   go tool pprof -http=: <out-dir>/cpu.pb.gz
set -eu

BASE="${1:-http://127.0.0.1:8079}"
SECS="${2:-30}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${3:-./pprof-$TS}"

case "$SECS" in
'' | *[!0-9]*)
	echo '[pprof-capture] cpu-seconds must be a positive integer' >&2
	exit 1
	;;
esac

# Strip leading zeroes only for bounded arithmetic; retain the operator's value
# in the pprof query itself. The upper bound keeps POSIX shell arithmetic safe.
TIMEOUT_SECS="$SECS"
while [ "${TIMEOUT_SECS#0}" != "$TIMEOUT_SECS" ]; do
	TIMEOUT_SECS="${TIMEOUT_SECS#0}"
done
if [ -z "$TIMEOUT_SECS" ] || [ "${#TIMEOUT_SECS}" -gt 9 ] || [ "$TIMEOUT_SECS" -gt 999999984 ]; then
	echo '[pprof-capture] cpu-seconds must be between 1 and 999999984' >&2
	exit 1
fi

CONNECT_TIMEOUT=5
SNAPSHOT_MAX_TIME=15
CPU_MAX_TIME=$((TIMEOUT_SECS + 15))

# Auth header only when a token is supplied (matches MAILSTRIX_METRICS_AUTH=1).
AUTH=""
if [ -n "${MAILSTRIX_TOKEN:-}" ]; then
	# A bearer value cannot contain line breaks: curl's header input format
	# treats them as separate headers. Reject them before starting any child.
	case "$MAILSTRIX_TOKEN" in
	*'
'* | *"$(printf '\r')"*)
		echo '[pprof-capture] token contains a line break' >&2
		exit 1
		;;
	esac
	AUTH="Authorization: Bearer ${MAILSTRIX_TOKEN}"
fi

mkdir -p "$OUT"
echo "[pprof-capture] base=$BASE cpu=${SECS}s out=$OUT"

fetch() {
	# fetch <path> <outfile> <max-seconds>
	_tmp="$OUT/.$2.part"
	rm -f "$_tmp"
	if [ -n "$AUTH" ]; then
		# printf is a shell builtin; only the pipe carries the credential.
		if printf '%s\n' "$AUTH" | curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$3" -H @- "$BASE$1" -o "$_tmp"; then
			mv "$_tmp" "$OUT/$2"
		else
			_status=$?
			rm -f "$_tmp"
			return "$_status"
		fi
	else
		if curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$3" "$BASE$1" -o "$_tmp"; then
			mv "$_tmp" "$OUT/$2"
		else
			_status=$?
			rm -f "$_tmp"
			return "$_status"
		fi
	fi
}

# CPU profile spans SECS of live load — run traffic against /scan during this.
echo "[pprof-capture] cpu profile (${SECS}s; drive /scan load now)…"
fetch "/debug/pprof/profile?seconds=${SECS}" cpu.pb.gz "$CPU_MAX_TIME"
echo "[pprof-capture] heap / allocs / goroutine snapshots…"
fetch "/debug/pprof/heap" heap.pb.gz "$SNAPSHOT_MAX_TIME"
fetch "/debug/pprof/allocs" allocs.pb.gz "$SNAPSHOT_MAX_TIME"
fetch "/debug/pprof/goroutine" goroutine.pb.gz "$SNAPSHOT_MAX_TIME"

# Top listings (best-effort: needs `go` on the capturing host; skipped if absent).
if command -v go >/dev/null 2>&1; then
	{
		for p in cpu heap allocs goroutine; do
			echo "===== top: $p ====="
			go tool pprof -top -nodecount=25 "$OUT/$p.pb.gz" 2>/dev/null || echo "(pprof top failed for $p)"
			echo
		done
	} >"$OUT/profiles.txt"
	echo "[pprof-capture] wrote $OUT/profiles.txt"
else
	echo "[pprof-capture] 'go' not found — raw .pb.gz only; analyse with: go tool pprof -http=: $OUT/cpu.pb.gz"
fi

echo "[pprof-capture] done -> $OUT"
