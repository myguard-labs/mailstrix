#!/bin/sh
# Every helper that docker/fetch-rules.sh or docker/compile-rules.sh resolves via
# $(dirname "$0")/<name> must be COPY'd into /usr/local/bin/ by the stage that
# runs that script, in docker/Dockerfile, docker/Dockerfile.release, and the
# native profiling Dockerfile:
# fetch-rules.sh runs in `rules-src`, compile-rules.sh in `rules` (#525
# regression: the release rules stage lacked capture-compiler-inputs.py).
# Usage: dockerfile_rules_helpers_test.sh            (real files + self-controls)
#        dockerfile_rules_helpers_test.sh --check ROOT   (check one tree only)
set -eu

# helpers SCRIPT -> sorted helper names that stage script references.
helpers() {
	# Existence guard runs outside the pipeline: a pipeline's status is sort's.
	[ -f "$1" ] || {
		echo "FAIL: missing $1" >&2
		return 2
	}
	# shellcheck disable=SC2016 # literal $(dirname "$0") is the pattern
	sed -n 's/.*\$(dirname "\$0")\/\([A-Za-z0-9_.-]*\).*/\1/p' "$1" | sort -u
}

# copied DOCKERFILE STAGE -> basenames COPY'd into /usr/local/bin/ inside STAGE.
copied() {
	awk -v stage="$2" '
		/^[[:space:]]*FROM[[:space:]]/ {
			n = split($0, f, /[[:space:]]+/)
			in_stage = (n >= 2 && tolower(f[n - 1]) == "as" && f[n] == stage)
			next
		}
		in_stage && /^[[:space:]]*COPY[[:space:]]/ {
			n = split($0, f, /[[:space:]]+/)
			if (f[n] != "/usr/local/bin/") next
			for (i = 1; i <= n; i++) if (f[i] ~ /^docker\//) { sub(/^docker\//, "", f[i]); print f[i] }
		}' "$1" | sort -u
}

has_word() { # has_word "SPACE-SEPARATED WORDS" NEEDLE
	case " $1 " in
	*" $2 "*) return 0 ;;
	*) return 1 ;;
	esac
}

# check ROOT -> 0 when each script's helpers are COPY'd into its owning stage.
check() {
	root=$1
	fetch=$(helpers "$root/docker/fetch-rules.sh") || return 2
	compile=$(helpers "$root/docker/compile-rules.sh") || return 2
	[ -n "$fetch$compile" ] || {
		echo "FAIL: no dirname helper references found (parser drift?)" >&2
		return 2
	}
	rc=0
	for df in docker/Dockerfile docker/Dockerfile.release; do
		[ -f "$root/$df" ] || {
			echo "FAIL: missing $root/$df" >&2
			return 2
		}
		for pair in "rules-src:$fetch" "rules:$compile"; do
			stage=${pair%%:*}
			have=$(copied "$root/$df" "$stage" | tr '\n' ' ')
			for h in ${pair#*:}; do
				if ! has_word "$have" "$h"; then
					echo "FAIL: $df $stage stage does not COPY $h into /usr/local/bin/" >&2
					rc=1
				fi
			done
		done
	done
	profile=docker/profile/Dockerfile.profile
	[ -f "$root/$profile" ] || {
		echo "FAIL: missing $root/$profile" >&2
		return 2
	}
	have=$(copied "$root/$profile" yarap | tr '\n' ' ')
	while IFS= read -r h; do
		[ -n "$h" ] || continue
		if ! has_word "$have" "$h"; then
			echo "FAIL: $profile yarap stage does not COPY $h into /usr/local/bin/" >&2
			rc=1
		fi
	done <<EOF
$fetch
$compile
EOF
	return "$rc"
}

here=$(cd "$(dirname "$0")/.." && pwd)
if [ "${1:-}" = "--check" ]; then
	check "$2"
	exit $?
fi

# Positive: the real tree.
check "$here"
echo "PASS: real Dockerfiles copy every dirname helper: $(helpers "$here/docker/fetch-rules.sh" | tr '\n' ' ')$(helpers "$here/docker/compile-rules.sh" | tr '\n' ' ')"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mk() { # mk DIR : copy the real inputs
	mkdir -p "$1/docker/profile"
	cp "$here/docker/compile-rules.sh" "$here/docker/fetch-rules.sh" \
		"$here/docker/Dockerfile" "$here/docker/Dockerfile.release" "$1/docker/"
	cp "$here/docker/profile/Dockerfile.profile" "$1/docker/profile/"
}

# Negative control: drop the helper from the release COPY line -> must fail.
mk "$tmp/neg"
sed -i '/AS rules$/,/^FROM .* AS final/ s# docker/capture-compiler-inputs\.py##' "$tmp/neg/docker/Dockerfile.release"
if has_word "$(copied "$tmp/neg/docker/Dockerfile.release" rules | tr '\n' ' ')" capture-compiler-inputs.py; then
	echo "FAIL: negative fixture was not mutated" >&2
	exit 1
fi
if check "$tmp/neg" 2>"$tmp/neg.err"; then
	echo "FAIL: negative control (helper removed from release) passed" >&2
	exit 1
fi
grep -q 'Dockerfile.release rules stage does not COPY capture-compiler-inputs.py' "$tmp/neg.err"
echo "PASS: negative control red: $(cat "$tmp/neg.err")"

# Negative control 2: a COPY in an unrelated stage does not count.
mk "$tmp/stage"
sed -i 's#^COPY docker/fetch-rules.sh docker/filter-rules.py /usr/local/bin/#COPY docker/fetch-rules.sh /usr/local/bin/#' "$tmp/stage/docker/Dockerfile.release"
if has_word "$(copied "$tmp/stage/docker/Dockerfile.release" rules-src | tr '\n' ' ')" filter-rules.py; then
	echo "FAIL: stage fixture was not mutated" >&2
	exit 1
fi
printf 'FROM scratch AS other\nCOPY docker/filter-rules.py /usr/local/bin/\n' >>"$tmp/stage/docker/Dockerfile.release"
if check "$tmp/stage" 2>/dev/null; then
	echo "FAIL: COPY outside the rules-src stage was accepted" >&2
	exit 1
fi
echo "PASS: COPY outside the owning stage rejected"

# Negative control 3: a fetch helper in the compile stage is the wrong stage.
mk "$tmp/wrong"
sed -i 's#^COPY docker/fetch-rules.sh docker/filter-rules.py /usr/local/bin/#COPY docker/fetch-rules.sh /usr/local/bin/#' "$tmp/wrong/docker/Dockerfile"
sed -i 's#^COPY docker/compile-rules.sh docker/capture-compiler-inputs.py docker/build-marker-artifact.py /usr/local/bin/#&\nCOPY docker/filter-rules.py /usr/local/bin/#' "$tmp/wrong/docker/Dockerfile"
if ! has_word "$(copied "$tmp/wrong/docker/Dockerfile" rules | tr '\n' ' ')" filter-rules.py; then
	echo "FAIL: wrong-stage fixture was not mutated" >&2
	exit 1
fi
if check "$tmp/wrong" 2>"$tmp/wrong.err"; then
	echo "FAIL: fetch helper copied only into the rules stage was accepted" >&2
	exit 1
fi
grep -q 'docker/Dockerfile rules-src stage does not COPY filter-rules.py' "$tmp/wrong.err"
echo "PASS: helper in the wrong stage rejected"

# Negative control 4: the profiling stage owns both pipeline scripts and all
# helpers they resolve. A helper copied only by production stages is missing.
mk "$tmp/profile"
sed -i 's# docker/capture-compiler-inputs\.py##' "$tmp/profile/docker/profile/Dockerfile.profile"
if has_word "$(copied "$tmp/profile/docker/profile/Dockerfile.profile" yarap | tr '\n' ' ')" capture-compiler-inputs.py; then
	echo "FAIL: profile fixture was not mutated" >&2
	exit 1
fi
if check "$tmp/profile" 2>"$tmp/profile.err"; then
	echo "FAIL: missing profiling helper was accepted" >&2
	exit 1
fi
grep -q 'docker/profile/Dockerfile.profile yarap stage does not COPY capture-compiler-inputs.py' "$tmp/profile.err"
echo "PASS: missing profiling helper rejected"

# Boundary: helpers split over several COPY lines still pass.
mk "$tmp/split"
sed -i 's#^COPY docker/compile-rules.sh docker/capture-compiler-inputs.py docker/build-marker-artifact.py /usr/local/bin/#COPY docker/compile-rules.sh /usr/local/bin/\nCOPY docker/capture-compiler-inputs.py /usr/local/bin/\nCOPY docker/build-marker-artifact.py /usr/local/bin/#' "$tmp/split/docker/Dockerfile"
if [ "$(copied "$tmp/split/docker/Dockerfile" rules | wc -l)" -ne 3 ] ||
	[ "$(grep -c '^COPY docker/[^ ]* /usr/local/bin/$' "$tmp/split/docker/Dockerfile")" -lt 3 ]; then
	echo "FAIL: split fixture was not mutated" >&2
	exit 1
fi
check "$tmp/split"
echo "PASS: split COPY lines accepted"

# Malformed: missing Dockerfile -> nonzero with a clear message.
mk "$tmp/miss"
rm "$tmp/miss/docker/Dockerfile.release"
if check "$tmp/miss" 2>"$tmp/miss.err"; then
	echo "FAIL: missing Dockerfile.release passed" >&2
	exit 1
fi
grep -q 'FAIL: missing .*Dockerfile.release' "$tmp/miss.err"
echo "PASS: missing Dockerfile reported"

# Malformed: missing stage script -> helper resolution fails, not masked by sort.
mk "$tmp/nostage"
rm "$tmp/nostage/docker/fetch-rules.sh"
if check "$tmp/nostage" 2>"$tmp/nostage.err"; then
	echo "FAIL: missing fetch-rules.sh passed" >&2
	exit 1
fi
grep -q 'FAIL: missing' "$tmp/nostage.err"
echo "PASS: missing stage script reported"

# Malformed: script with no helper references -> parser-drift failure, not a pass.
mk "$tmp/nohelp"
: >"$tmp/nohelp/docker/compile-rules.sh"
: >"$tmp/nohelp/docker/fetch-rules.sh"
if check "$tmp/nohelp" 2>"$tmp/nohelp.err"; then
	echo "FAIL: empty helper set passed" >&2
	exit 1
fi
grep -q 'parser drift' "$tmp/nohelp.err"
echo "PASS: empty helper set rejected"
