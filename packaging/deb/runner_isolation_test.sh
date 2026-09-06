#!/bin/sh
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
python3 - "$root/.github/workflows" <<'PY'
import pathlib
import sys

import yaml

workflows = pathlib.Path(sys.argv[1])
canary_routes = {
    "leave-lxc-state": ["self-hosted", "b02lxc", "lxc", "ci-slot-builder02-runner-01"],
    "prove-lxc-restore": ["self-hosted", "b02lxc", "lxc", "ci-slot-builder02-runner-01"],
    "leave-docker-state": ["self-hosted", "builder02", "docker", "ci-slot-builder02-docker-01"],
    "prove-docker-restore": ["self-hosted", "builder02", "docker", "ci-slot-builder02-docker-01"],
    "cross-slot-negative-control": ["self-hosted", "b02lxc", "lxc", "ci-slot-builder02-runner-02"],
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

workflow = yaml.safe_load((workflows / "runner-isolation.yml").read_text())
assert workflow["concurrency"] == {
    "group": "mailstrix-runner-isolation-physical-slots", "cancel-in-progress": False,
}
assert workflow["on"]["workflow_dispatch"]["inputs"]["cross_slot_control"]["default"] is False
canary = workflow["jobs"]
assert set(canary) == set(canary_routes)
for name, job in canary.items():
    assert job["steps"][0]["uses"].startswith("actions/checkout@"), f"{name}: probe unavailable"
assert canary["prove-lxc-restore"]["needs"] == "leave-lxc-state"
assert canary["prove-docker-restore"]["needs"] == "leave-docker-state"
for profile in ("lxc", "docker"):
    leave = canary[f"leave-{profile}-state"]
    prove = canary[f"prove-{profile}-restore"]
    assert leave["outputs"] == {"tuple": "${{ steps.leave.outputs.tuple }}"}
    assert leave["steps"][-1]["id"] == "leave"
    assert prove["steps"][-1]["env"]["LEAVE_TUPLE"] == (
        "${{ needs.leave-" + profile + "-state.outputs.tuple }}"
    )
    slot = "builder02-runner-01" if profile == "lxc" else "builder02-docker-01"
    for mode, job in (("leave", leave), ("prove", prove)):
        assert job["steps"][-1]["run"] == f".github/runner/isolation-canary.sh {mode} {profile} {slot}"
        assert "if" not in job
        assert "concurrency" not in job
        assert not job.get("continue-on-error", False)
        assert not job["steps"][-1].get("continue-on-error", False)
control = canary["cross-slot-negative-control"]
assert control["needs"] == "leave-lxc-state"
assert control["if"] == "${{ github.event_name == 'workflow_dispatch' && inputs.cross_slot_control }}"
assert control["steps"][-1]["run"] == ".github/runner/isolation-canary.sh prove lxc builder02-runner-01"
assert control["steps"][-1]["env"]["LEAVE_TUPLE"] == "${{ needs.leave-lxc-state.outputs.tuple }}"
assert not control.get("continue-on-error", False)
assert not control["steps"][-1].get("continue-on-error", False)
PY

probe="$root/.github/runner/isolation-canary.sh"
grep -F 'runner state from the previous job survived pristine restore' "$probe" >/dev/null
if grep -F 'RUNNER_NAME' "$probe" >/dev/null; then
	echo "RUNNER_NAME must not be treated as JIT registration identity" >&2
	exit 1
fi
if grep -R -F 'mailstrix-jit' "$root/.github" >/dev/null; then
	echo "repository-local runner group/dispatcher contract survived" >&2
	exit 1
fi

python3 - "$probe" <<'PY'
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

probe = sys.argv[1]
with tempfile.TemporaryDirectory(prefix="mailstrix-runner-isolation-",
                                 dir=os.environ.get("RUNNER_ISOLATION_TEST_TMPDIR")) as temporary:
    fixture = Path(temporary)
    metadata = fixture / "run/myguard-ci-slot"
    metadata.parent.mkdir()
    state = fixture / "opt/actions-runner"
    state.mkdir(parents=True)
    output = fixture / "output"
    environment = dict(os.environ, GITHUB_RUN_ID="10", GITHUB_RUN_ATTEMPT="1",
                       GITHUB_OUTPUT=str(output))
    # Fixture mode is explicit and cannot be enabled by production Actions.
    # Only fixture subprocesses clear the marker, after testing its guard.
    environment.pop("GITHUB_ACTIONS", None)
    environment.pop("LEAVE_TUPLE", None)

    def run(name, mode="prove", profile="lxc", slot="builder02-runner-01",
            error=None, extra=None):
        result = subprocess.run(
            [probe, mode, profile, slot, "--test-root", temporary],
            env=environment | (extra or {}), capture_output=True, text=True, timeout=10,
            check=False,
        )
        if error is None:
            assert result.returncode == 0, f"{name}: {result.stderr}"
        else:
            assert result.returncode != 0, f"{name}: unexpectedly passed"
            assert error in result.stderr, f"{name}: wrong failure: {result.stderr}"
        print(f"ok - {name}")

    run("production rejects fixture override", mode="leave",
        extra={"GITHUB_ACTIONS": "true"}, error="test root is forbidden on Actions")
    for profile, slot in (("lxc", "builder02-runner-01"), ("docker", "builder02-docker-01")):
        metadata.write_text(f"{slot}\n/opt/actions-runner\n")
        output.write_text("")
        run(f"{profile} leave", "leave", profile, slot)
        lines = output.read_text().splitlines()
        assert len(lines) == 1
        assert lines[0].startswith("tuple=")
        tuple_text = lines[0].removeprefix("tuple=")
        expected = {"slot": slot, "profile": profile, "run_id": "10", "leave_attempt": "1",
                    "namespace": "/opt/actions-runner",
                    "canary_key": f".mailstrix-runner-isolation-10-1-{profile}"}
        assert json.loads(tuple_text) == expected
        environment["LEAVE_TUPLE"] = tuple_text
        canary = state / expected["canary_key"]
        assert (canary / "probe").read_text() == "must disappear before the next job\n"
        run(f"{profile} present canary", profile=profile, slot=slot,
            error="runner state from the previous job survived pristine restore")
        run(f"{profile} duplicate leave", "leave", profile, slot, error="File exists")
        assert output.read_text().splitlines() == lines
        shutil.rmtree(canary)
        run(f"{profile} same-slot absence", profile=profile, slot=slot)
        canary.symlink_to("missing-probe")
        run(f"{profile} dangling canary", profile=profile, slot=slot,
            error="runner state from the previous job survived pristine restore")
        canary.unlink()

    # Pin a valid LXC producer tuple while the canary is absent.
    environment["LEAVE_TUPLE"] = json.dumps({
        "slot": "builder02-runner-01", "profile": "lxc", "run_id": "10",
        "leave_attempt": "1", "namespace": "/opt/actions-runner",
        "canary_key": ".mailstrix-runner-isolation-10-1-lxc",
    })
    metadata.write_text("builder02-runner-02\n/opt/actions-runner\n")
    run("cross-slot absent canary", error="slot identity mismatch")
    state.rmdir()
    run("identity rejected before namespace lookup", error="slot identity mismatch")
    metadata.write_text("builder02-runner-01\n/opt/actions-runner\n")
    run("missing namespace", error="No such file or directory")
    state.write_text("not a directory")
    run("invalid namespace", error="Not a directory")
    state.unlink()
    state.symlink_to(fixture / "run", target_is_directory=True)
    run("symlink namespace", error="Not a directory")
    state.unlink()
    state.mkdir()
    run("stale producer attempt", extra={"GITHUB_RUN_ATTEMPT": "2"}, error="producer tuple mismatch")
    run("stale producer run", extra={"GITHUB_RUN_ID": "11"}, error="producer tuple mismatch")
    for value in ("", "{}", "null", "not-json", "x" * 1025):
        run(f"invalid producer {value[:12]!r}", extra={"LEAVE_TUPLE": value}, error="producer tuple")
    for field in ("slot", "profile", "namespace", "canary_key"):
        producer = json.loads(environment["LEAVE_TUPLE"])
        producer[field] = "wrong"
        run(f"producer {field} mismatch", extra={"LEAVE_TUPLE": json.dumps(producer)},
            error="producer tuple mismatch")
    for value in ("", "0", "1\nother=1", "1" * 21):
        run(f"invalid attempt {value!r}", extra={"GITHUB_RUN_ATTEMPT": value}, error="invalid run/attempt")
    run("expected profile mismatch", profile="docker", error="slot/profile mismatch")
    run("invalid expected slot", slot="../slot", error="invalid expected slot")
    for data in (b"", b"builder02-runner-01\n/opt/actions-runner",
                 b"builder02-runner-01\n/opt/actions-runner\nextra\n",
                 b"builder02-runner-01\n/opt/actions-runner/_work\n",
                 b"builder02-runner-01\x00\n/opt/actions-runner\n", b"x" * 300):
        metadata.write_bytes(data)
        run(f"malformed metadata {data[:32]!r}", error="malformed slot metadata")
    metadata.unlink()
    run("missing metadata", error="No such file or directory")
    metadata.symlink_to(output)
    run("symlink metadata", error="slot metadata must be a regular file")
    metadata.unlink()
    metadata.write_text("builder02-runner-01\n/opt/actions-runner\n")
    run("missing output", "leave", extra={"GITHUB_OUTPUT": ""}, error="missing GITHUB_OUTPUT")
    assert not (state / ".mailstrix-runner-isolation-10-1-lxc").exists()
    run("same-slot final proof")
print("ok - physical-slot binding, retry binding and both-profile restoration controls")
PY
