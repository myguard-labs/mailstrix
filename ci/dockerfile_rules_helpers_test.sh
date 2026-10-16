#!/bin/sh
# Every helper that docker/compile-rules.sh or docker/fetch-rules.sh resolves via
# $(dirname "$0")/<name> must be COPY'd into /usr/local/bin/ by the `rules` stage
# of BOTH docker/Dockerfile and docker/Dockerfile.release (#525 regression: the
# release rules stage lacked capture-compiler-inputs.py).
# Usage: dockerfile_rules_helpers_test.sh            (real files + self-controls)
#        dockerfile_rules_helpers_test.sh --check ROOT   (check one tree only)
set -eu

# helpers ROOT -> sorted helper names referenced by the stage scripts.
helpers() {
	for s in "$1/docker/compile-rules.sh" "$1/docker/fetch-rules.sh"; do
		[ -f "$s" ] || { echo "FAIL: missing $s" >&2; return 2; }
		# shellcheck disable=SC2016 # literal $(dirname "$0") is the pattern
		sed -n 's/.*\$(dirname "\$0")\/\([A-Za-z0-9_.-]*\).*/\1/p' "$s"
	done | sort -u
}

# copied DOCKERFILE -> basenames COPY'd into /usr/local/bin/ inside the rules stage.
copied() {
	awk '
		/^[[:space:]]*FROM[[:space:]]/ { in_rules = ($0 ~ /[[:space:]][Aa][Ss][[:space:]]+rules[[:space:]]*$/) ; next }
		in_rules && /^[[:space:]]*COPY[[:space:]]/ {
			n = split($0, f, /[[:space:]]+/)
			if (f[n] != "/usr/local/bin/") next
			for (i = 1; i <= n; i++) if (f[i] ~ /^docker\//) { sub(/^docker\//, "", f[i]); print f[i] }
		}' "$1" | sort -u
}

# check ROOT -> 0 when every referenced helper is COPY'd in both Dockerfiles.
check() {
	root=$1
	need=$(helpers "$root") || return 2
	[ -n "$need" ] || { echo "FAIL: no dirname helper references found (parser drift?)" >&2; return 2; }
	rc=0
	for df in docker/Dockerfile docker/Dockerfile.release; do
		[ -f "$root/$df" ] || { echo "FAIL: missing $root/$df" >&2; return 2; }
		have=$(copied "$root/$df")
		for h in $need; do
			if ! printf '%s\n' "$have" | grep -qx -- "$h"; then
				echo "FAIL: $df rules stage does not COPY $h into /usr/local/bin/" >&2
				rc=1
			fi
		done
	done
	return "$rc"
}

here=$(cd "$(dirname "$0")/.." && pwd)
if [ "${1:-}" = "--check" ]; then
	check "$2"
	exit $?
fi

# Positive: the real tree.
check "$here"
echo "PASS: real Dockerfiles copy every dirname helper: $(helpers "$here" | tr '\n' ' ')"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mk() { # mk DIR : copy the real inputs
	mkdir -p "$1/docker"
	cp "$here/docker/compile-rules.sh" "$here/docker/fetch-rules.sh" \
		"$here/docker/Dockerfile" "$here/docker/Dockerfile.release" "$1/docker/"
}

# Negative control: drop the helper from the release COPY line -> must fail.
mk "$tmp/neg"
sed -i '/AS rules/,/^FROM .* AS final/ s# docker/capture-compiler-inputs\.py##' "$tmp/neg/docker/Dockerfile.release"
if copied "$tmp/neg/docker/Dockerfile.release" | grep -qx capture-compiler-inputs.py; then
	echo "FAIL: negative fixture was not mutated" >&2; exit 1
fi
if check "$tmp/neg" 2>"$tmp/neg.err"; then
	echo "FAIL: negative control (helper removed from release) passed" >&2; exit 1
fi
grep -q 'Dockerfile.release rules stage does not COPY capture-compiler-inputs.py' "$tmp/neg.err"
echo "PASS: negative control red: $(cat "$tmp/neg.err")"

# Negative control 2: a COPY in a non-rules stage does not count.
mk "$tmp/stage"
sed -i 's#^COPY docker/fetch-rules.sh docker/compile-rules.sh docker/capture-compiler-inputs.py docker/filter-rules.py /usr/local/bin/#COPY docker/fetch-rules.sh docker/compile-rules.sh docker/capture-compiler-inputs.py /usr/local/bin/#' "$tmp/stage/docker/Dockerfile.release"
printf 'FROM scratch AS other\nCOPY docker/filter-rules.py /usr/local/bin/\n' >>"$tmp/stage/docker/Dockerfile.release"
if check "$tmp/stage" 2>/dev/null; then
	echo "FAIL: COPY outside rules stage was accepted" >&2; exit 1
fi
echo "PASS: COPY outside the rules stage rejected"

# Boundary: helpers split over several COPY lines still pass.
mk "$tmp/split"
sed -i 's#^COPY docker/fetch-rules.sh docker/compile-rules.sh docker/capture-compiler-inputs.py docker/build-marker-artifact.py docker/filter-rules.py /usr/local/bin/#COPY docker/fetch-rules.sh docker/compile-rules.sh /usr/local/bin/\nCOPY docker/capture-compiler-inputs.py /usr/local/bin/\nCOPY docker/filter-rules.py /usr/local/bin/#' "$tmp/split/docker/Dockerfile"
[ "$(grep -c '^COPY docker/.*/usr/local/bin/$' "$tmp/split/docker/Dockerfile")" -ge 3 ]
check "$tmp/split"
echo "PASS: split COPY lines accepted"

# Malformed: missing Dockerfile -> nonzero with a clear message.
mk "$tmp/miss"
rm "$tmp/miss/docker/Dockerfile.release"
if check "$tmp/miss" 2>"$tmp/miss.err"; then
	echo "FAIL: missing Dockerfile.release passed" >&2; exit 1
fi
grep -q 'FAIL: missing .*Dockerfile.release' "$tmp/miss.err"
echo "PASS: missing Dockerfile reported"

# Malformed: script with no helper references -> parser-drift failure, not a pass.
mk "$tmp/nohelp"
: >"$tmp/nohelp/docker/compile-rules.sh"; : >"$tmp/nohelp/docker/fetch-rules.sh"
if check "$tmp/nohelp" 2>"$tmp/nohelp.err"; then
	echo "FAIL: empty helper set passed" >&2; exit 1
fi
grep -q 'parser drift' "$tmp/nohelp.err"
echo "PASS: empty helper set rejected"
