#!/bin/sh
# Guard the maintenance benchmark's Docker test-command contract. The benchmark
# must use the same build tags as the Dockerfile test stage, and a failed Docker
# invocation must remain fatal even though its output is piped through tee.
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/mailstrix-benchmark-command.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

python3 - \
	"$root/.github/workflows/maintenance.yml" \
	"$root/.github/workflows/ci.yml" \
	"$root/docker/Dockerfile" \
	"$tmp/benchmark.sh" <<'PY'
import pathlib
import re
import shlex
import sys

import yaml

maintenance_path, ci_path, dockerfile_path, output_path = map(pathlib.Path, sys.argv[1:])
workflow = yaml.safe_load(maintenance_path.read_text())
ci_workflow = yaml.safe_load(ci_path.read_text())
steps = workflow["jobs"]["perf-regression"]["steps"]
benchmark = next(step for step in steps if step.get("name") == "run benchmarks")["run"]
arm_job = workflow["jobs"]["race-arm64"]
arm_build = next(
    step for step in arm_job["steps"] if step.get("name") == "build test image (arm64 native)"
)["run"]

assert re.search(r"\|\s*tee\s+bench-results\.txt(?:\s|$)", benchmark), \
    "maintenance benchmark must retain its benchmark artifact"

stage_match = re.search(
    r"(?ms)^FROM\s+build\s+AS\s+test\s*$\n(.*?)(?=^FROM\s)",
    dockerfile_path.read_text(),
)
assert stage_match, "Dockerfile test stage not found"


def go_test_args(command):
    tokens = shlex.split(command.replace("\\\n", " "))
    for index in range(len(tokens) - 1):
        if tokens[index:index + 2] == ["go", "test"]:
            return tokens[index + 2:]
    raise AssertionError("go test command not found")


def build_tags(args):
    for index, arg in enumerate(args):
        if arg == "-tags":
            assert index + 1 < len(args), "-tags has no value"
            return set(args[index + 1].split(","))
        if arg.startswith("-tags="):
            return set(arg.removeprefix("-tags=").split(","))
    return set()


docker_args = go_test_args(stage_match.group(1))
benchmark_args = go_test_args(benchmark)
docker_tags = build_tags(docker_args)
benchmark_tags = build_tags(benchmark_args)
assert docker_tags, "Dockerfile test command has no build tags to compare"
assert benchmark_tags == docker_tags, \
    f"benchmark tags {sorted(benchmark_tags)} != Docker test tags {sorted(docker_tags)}"
assert "-race" in docker_args, "Docker test stage no longer runs the race detector"
assert "./..." in docker_args, "Docker test stage no longer covers every Go package"
assert "-bench=." in benchmark_args, "maintenance command no longer runs benchmarks"
arm_tokens = shlex.split(arm_build.replace("\\\n", " "))
assert arm_job["runs-on"] == "ubuntu-24.04-arm", "race-arm64 no longer runs natively"
assert "--target" in arm_tokens and arm_tokens[arm_tokens.index("--target") + 1] == "test", \
    "native arm64 build no longer executes the Docker test stage"
assert any(
    step.get("run") == "sh packaging/deb/benchmark_command_test.sh"
    for step in ci_workflow["jobs"]["scanners"]["steps"]
), "benchmark command contract test is not wired into ordinary CI"

output_path.write_text(benchmark.rstrip() + "\n")
PY

mkdir "$tmp/bin" "$tmp/run"
cat >"$tmp/bin/docker" <<'STUB'
#!/bin/sh
echo "stub docker failure"
exit 42
STUB
chmod +x "$tmp/bin/docker"

set +e
(
	cd "$tmp/run"
	PATH="$tmp/bin:$PATH" bash "$tmp/benchmark.sh"
) >"$tmp/output.log" 2>&1
status=$?
set -e

if [ "$status" -ne 42 ]; then
	cat "$tmp/output.log" >&2
	echo "FAIL - extracted benchmark returned $status; want docker failure 42 through tee" >&2
	exit 1
fi
grep -F "stub docker failure" "$tmp/output.log" >/dev/null
test -f "$tmp/run/bench-results.txt"

echo "ok - benchmark tags match Docker test stage and pipefail preserves docker status"
