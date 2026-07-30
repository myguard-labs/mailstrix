#!/bin/sh
# Guard against .dockerignore rotting: build-context hygiene (A5). Every
# Dockerfile in this repo builds with the repo root as its context (`docker
# build .`), so a missing/loosened .dockerignore leaks secrets, the .git
# history, local tooling, logs, transient rule dirs and compiled test/release
# binaries into whatever the daemon streams up — and, for docker/Dockerfile's
# `build`/`test` stages specifically, straight into `COPY . .` at /src.
#
# This is a REAL negative control, not a static grep of the .dockerignore
# text: it creates sentinel files matching each denied category directly in
# the working tree, builds a tiny throwaway `FROM scratch` stage that does
# `COPY . /ctx` (repo root as context, exactly like the real Dockerfiles), and
# asserts none of the sentinels reach /ctx. Mutation-tested: deleting the `*`
# deny-all line from .dockerignore makes every absence assertion fail (the
# context grows from ~300 to ~420 entries and all five sentinels appear). The
# sentinels are denied by that one line, not by per-category deny rules —
# there are none — so `*` is the assertion these tests actually bind to.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cd "$root"

command -v docker >/dev/null 2>&1 || { echo "SKIP - docker not available"; exit 0; }

[ -e "$root/.dockerignore" ] || { echo "FAIL - .dockerignore missing at repo root"; exit 1; }

tmpdir="$(mktemp -d)"
cleanup() {
    rc=$?
    rm -f "$root/extract.test.sentinel" \
          "$root/.env.sentinel" \
          "$root/secrets-sentinel/sentinel.token" \
          "$root/rules-sentinel/sentinel.yara" \
          "$root/build.log.sentinel" 2>/dev/null || true
    rmdir "$root/secrets-sentinel" 2>/dev/null || true
    rmdir "$root/rules-sentinel" 2>/dev/null || true
    docker image rm -f dockerignore-ctx-probe >/dev/null 2>&1 || true
    rm -rf "$tmpdir"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# Sentinels for the categories A5 calls out: .git, secrets/tokens/env, live
# rule corpora, logs, compiled test binaries, transient rule dirs.
mkdir -p "$root/secrets-sentinel" "$root/rules-sentinel"
echo "sentinel" > "$root/extract.test.sentinel"      # compiled test binary lookalike
echo "SECRET=x" > "$root/.env.sentinel"               # env/secret file
echo "shh" > "$root/secrets-sentinel/sentinel.token"           # token under a secrets-style dir
echo "rule sentinel" > "$root/rules-sentinel/sentinel.yara"  # transient rule dir
echo "log line" > "$root/build.log.sentinel"          # build/test log

probe_dockerfile="$tmpdir/Dockerfile.probe"
cat > "$probe_dockerfile" <<'EOF'
FROM scratch AS probe
COPY . /ctx
CMD ["/nonexistent"]
EOF

# Build a scratch stage from the SAME context (repo root) the real Dockerfiles
# use, then export it and list what actually made it into /ctx — this is what
# the daemon received, not what .dockerignore merely claims.
DOCKER_BUILDKIT=1 docker build -q -f "$probe_dockerfile" -t dockerignore-ctx-probe "$root" >/dev/null

# `FROM scratch` has no shell, so inspect via `docker create` + `docker export`
# instead of trying to run a command inside it.
cid="$(docker create dockerignore-ctx-probe)"
docker export "$cid" > "$tmpdir/ctx.tar"
docker rm "$cid" >/dev/null

fail=0
check_absent() {
    path="$1"
    label="$2"
    if tar tf "$tmpdir/ctx.tar" | grep -qE "^ctx/${path}(/|\$)"; then
        echo "FAIL - $label ($path) present in build context"; fail=1
    else
        echo "ok   - $label ($path) excluded from build context"
    fi
}

check_absent '\.git' '.git VCS metadata'
check_absent 'extract\.test\.sentinel' 'compiled test binary sentinel'
check_absent '\.env\.sentinel' 'env/secret file sentinel'
check_absent 'secrets-sentinel/sentinel\.token' 'token under a secrets-style dir'
check_absent 'rules-sentinel/sentinel\.yara' 'transient rule-dir sentinel'
check_absent 'build\.log\.sentinel' 'log file sentinel'

# Real files docker/Dockerfile's `build`/`test` stage COPY . . actually needs
# must still be present, so a deny-by-default .dockerignore can't silently
# break the build.
check_present() {
    path="$1"
    label="$2"
    if tar tf "$tmpdir/ctx.tar" | grep -qE "^ctx/${path}(/|\$)"; then
        echo "ok   - $label ($path) present in build context"
    else
        echo "FAIL - $label ($path) missing from build context"; fail=1
    fi
}
check_present 'go\.mod' 'go.mod'
check_present 'go\.sum' 'go.sum'
check_present 'cmd' 'cmd/'
check_present 'internal' 'internal/'
check_present 'docker/Dockerfile' 'docker/Dockerfile'
check_present 'docker/fetch-rules\.sh' 'docker/fetch-rules.sh'
check_present 'scripts/smoke\.sh' 'scripts/smoke.sh'

if [ "$fail" -eq 0 ]; then
    echo "ALL OK"
else
    echo "FAILURES"; exit 1
fi
