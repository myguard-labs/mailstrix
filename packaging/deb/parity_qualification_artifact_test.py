#!/usr/bin/env python3
"""Guard bounded failure artifacts for the optional parity qualification."""

import shlex
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
steps = workflow["jobs"]["parity-isolation"]["steps"]
qualification_step = next(step for step in steps
                          if "scripts/qualify-parity-isolation.sh" in step.get("run", ""))
assert not qualification_step.get("continue-on-error", False), (
    "cleanup failures must fail the step and trigger failure artifact upload"
)
qualification = qualification_step["run"]
qualification_tokens = shlex.split(qualification.replace("\\\n", ""))
script_index = qualification_tokens.index("scripts/qualify-parity-isolation.sh")
assert qualification_tokens[script_index + 1:].count("--cleanup-images") == 1, (
    "CI qualification must opt into invocation-owned image cleanup"
)
upload = next(
    step for step in steps if step.get("name") == "retain failed isolation qualification logs"
)

assert upload["if"] == "${{ failure() }}", "qualification artifacts must be failure-only"
assert upload["uses"] == (
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
), "qualification upload action must match the repository's pinned v4.6.2 action"
assert upload["with"]["retention-days"] == 7, "qualification artifact retention must stay bounded"
assert upload["with"]["if-no-files-found"] == "warn"

paths = set(upload["with"]["path"].splitlines())
expected = {
    "${{ runner.temp }}/parity-isolation/parity-runtime.log",
    "${{ runner.temp }}/parity-isolation/parity-probe-runtime.log",
    "${{ runner.temp }}/parity-isolation/parity-qualification-bin.log",
    "${{ runner.temp }}/parity-isolation/qualification.log",
    "${{ runner.temp }}/parity-isolation/parity-runtime.id",
    "${{ runner.temp }}/parity-isolation/parity-probe-runtime.id",
    "${{ runner.temp }}/parity-isolation/image-cleanup.log",
}
assert paths == expected, f"qualification artifact paths changed: {sorted(paths)}"
assert all("*" not in path and not path.endswith("/") for path in paths), (
    "qualification artifacts must name exact logs and immutable IDs"
)
print("ok - failure-only qualification artifacts are pinned, bounded and exact")
