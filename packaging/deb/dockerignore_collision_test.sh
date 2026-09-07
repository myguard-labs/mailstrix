#!/bin/sh
# Verify the dockerignore test names collisions and never removes paths it did
# not create. Docker is stubbed because collision rejection precedes any daemon
# call.
set -eu

source_root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/mailstrix-dockerignore-collision.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

mkdir -p "$tmp/bin"
cat >"$tmp/bin/docker" <<'EOF'
#!/bin/sh
exit 99
EOF
chmod +x "$tmp/bin/docker"

run_control() {
	kind="$1"
	sentinel="$2"
	case_root="$tmp/$kind"
	mkdir -p "$case_root/packaging/deb" "$(dirname "$case_root/$sentinel")"
	cp "$source_root/packaging/deb/dockerignore_test.sh" "$case_root/packaging/deb/"
	: >"$case_root/.dockerignore"
	if [ "$kind" = file ]; then
		printf '%s\n' keep >"$case_root/$sentinel"
	else
		ln -s preserved-target "$case_root/$sentinel"
	fi

	set +e
	PATH="$tmp/bin:$PATH" sh "$case_root/packaging/deb/dockerignore_test.sh" \
		>"$case_root/output.log" 2>&1
	status=$?
	set -e
	[ "$status" -eq 1 ] || {
		cat "$case_root/output.log" >&2
		echo "FAIL - $kind collision returned $status, want 1" >&2
		exit 1
	}
	expected="FAIL - private-corpus sentinel path already exists: $sentinel"
	grep -Fx "$expected" "$case_root/output.log" >/dev/null || {
		cat "$case_root/output.log" >&2
		echo "FAIL - $kind collision diagnostic did not identify $sentinel" >&2
		exit 1
	}
	if [ "$kind" = file ]; then
		[ "$(cat "$case_root/$sentinel")" = keep ]
	else
		[ -L "$case_root/$sentinel" ]
		[ "$(readlink "$case_root/$sentinel")" = preserved-target ]
	fi
}

run_control file tools/private-corpus.sentinel.json
run_control symlink tools/parity/private-corpus.sentinel.json
echo "ok - fixed collision names reported; pre-existing file and symlink preserved"
