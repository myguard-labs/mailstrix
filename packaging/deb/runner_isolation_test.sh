#!/bin/sh
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
python3 - "$root/.github/workflows" <<'PY'
import pathlib
import sys

import yaml

workflows = pathlib.Path(sys.argv[1])
canary_routes = {
    "leave-lxc-state": ["self-hosted", "b02lxc", "lxc"],
    "prove-lxc-restore": ["self-hosted", "b02lxc", "lxc"],
    "leave-docker-state": ["self-hosted", "builder02", "docker"],
    "prove-docker-restore": ["self-hosted", "builder02", "docker"],
}

for path in workflows.glob("*.y*ml"):
    workflow = yaml.safe_load(path.read_text()) or {}
    for name, job in workflow.get("jobs", {}).items():
        runs_on = job.get("runs-on")
        if runs_on is None:
            continue
        if isinstance(runs_on, str):
            assert runs_on == "ubuntu-24.04-arm", f"{path}:{name}: unexpected hosted runner"
            continue
        assert isinstance(runs_on, list), f"{path}:{name}: runner group is forbidden"
        if path.name == "runner-isolation.yml":
            assert runs_on == canary_routes[name], f"{path}:{name}: slot affinity lost"
        else:
            assert runs_on in (
                ["self-hosted", "builder02", "docker"],
                ["self-hosted", "builder02", "lxc"],
            ), f"{path}:{name}: wrong shared builder route"
        assert not ({"mailstrix", "ephemeral", "canary-leave", "canary-prove"} & set(runs_on))

canary = yaml.safe_load((workflows / "runner-isolation.yml").read_text())["jobs"]
assert set(canary) == set(canary_routes)
for name, job in canary.items():
    assert job["steps"][0]["uses"].startswith("actions/checkout@"), f"{name}: probe unavailable"
assert canary["prove-lxc-restore"]["needs"] == "leave-lxc-state"
assert canary["prove-docker-restore"]["needs"] == "leave-docker-state"
PY

probe="$root/.github/runner/isolation-canary.sh"
grep -F "if [ \"\$RUNNER_NAME\" = \"\$previous\" ]" "$probe" >/dev/null
grep -F 'runner state from the previous job survived pristine restore' "$probe" >/dev/null
if grep -R -F 'mailstrix-jit' "$root/.github" >/dev/null; then
	echo "repository-local runner group/dispatcher contract survived" >&2
	exit 1
fi

test_tmp_root="${RUNNER_ISOLATION_TEST_TMPDIR:-/tmp}"
tmp="$(mktemp -d "$test_tmp_root/mailstrix-runner-isolation.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
GITHUB_RUN_ID=10
GITHUB_RUN_ATTEMPT=1
RUNNER_NAME=jit-lxc-first
export GITHUB_RUN_ID GITHUB_RUN_ATTEMPT RUNNER_NAME

# The harness itself must prove the production guard still rejects a checkout-
# relative fixture when Actions places that checkout beneath `_work`.
RUNNER_TEMP="$tmp/fake/_work/mailstrix/mailstrix/state/_work/_temp"
export RUNNER_TEMP
mkdir -p "$RUNNER_TEMP"
if "$probe" leave lxc >"$tmp/inside-work.log" 2>&1; then
	echo "inside-_work negative control unexpectedly passed" >&2
	exit 1
fi
grep -F 'runner state root resolves inside _work:' "$tmp/inside-work.log" >/dev/null

RUNNER_TEMP="$tmp/state/_work/_temp"
export RUNNER_TEMP
mkdir -p "$RUNNER_TEMP"
"$probe" leave lxc
canary="$tmp/state/.mailstrix-runner-isolation-10-1-lxc"
test -e "$canary/probe"
mkdir -p "$RUNNER_TEMP/predecessor"
cp "$RUNNER_TEMP/runner-identity" "$RUNNER_TEMP/predecessor/runner-identity"
rm -rf "$canary"
RUNNER_NAME=jit-lxc-second
export RUNNER_NAME
"$probe" prove lxc

RUNNER_NAME=jit-docker-first
GITHUB_RUN_ID=11
export RUNNER_NAME GITHUB_RUN_ID
"$probe" leave docker
mkdir -p "$RUNNER_TEMP/predecessor"
cp "$RUNNER_TEMP/runner-identity" "$RUNNER_TEMP/predecessor/runner-identity"
if "$probe" prove docker 2>/dev/null; then
	echo "identity-reuse negative control unexpectedly passed" >&2
	exit 1
fi
RUNNER_NAME=jit-docker-second
export RUNNER_NAME
if "$probe" prove docker 2>/dev/null; then
	echo "surviving-state negative control unexpectedly passed" >&2
	exit 1
fi
echo "ok - shared disposable singleton slots and both-profile canary"
