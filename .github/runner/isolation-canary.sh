#!/usr/bin/env bash
# Verify host-published slot identity before leaving/checking restore state.
# Usage: isolation-canary.sh leave|prove lxc|docker EXPECTED_CT [--test-root DIR]
# Inputs: GITHUB_RUN_ID/ATTEMPT/OUTPUT; prove also requires LEAVE_TUPLE.
# Requires Python 3. Leave creates a canary and emits a JSON tuple; prove only
# reads. No dry-run. Local fixtures use --test-root, forbidden on Actions.
# This checks controlled jobs, not deliberate tampering by root-capable jobs.
set -euo pipefail
exec python3 - "$@" <<'PY'
import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path


def fail(message):
    raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description="Check physical-slot pristine restoration")
    parser.add_argument("mode", choices=("leave", "prove"))
    parser.add_argument("profile", choices=("lxc", "docker"))
    parser.add_argument("expected_slot")
    parser.add_argument("--test-root", type=Path)
    args = parser.parse_args()
    if args.test_root is not None and os.environ.get("GITHUB_ACTIONS") == "true":
        fail("test root is forbidden on Actions")
    prefix = args.test_root or Path("/")
    if not prefix.is_absolute():
        fail("test root must be absolute")
    if not re.fullmatch(r"builder0[23]-(runner|docker)-[0-9]{2}", args.expected_slot):
        fail("invalid expected slot")
    slot_profile = "docker" if "-docker-" in args.expected_slot else "lxc"
    if args.profile != slot_profile:
        fail("slot/profile mismatch")
    run = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt)):
        fail("invalid run/attempt")

    namespace = "/opt/actions-runner"
    metadata = prefix / "run/myguard-ci-slot"
    if not stat.S_ISREG(metadata.lstat().st_mode):
        fail("slot metadata must be a regular file")
    with metadata.open("rb") as stream:
        data = stream.read(257)
    if not re.fullmatch(rb"builder0[23]-(?:runner|docker)-[0-9]{2}\n/opt/actions-runner\n", data):
        fail("malformed slot metadata")
    slot = data.split(b"\n")[0].decode("ascii")
    if slot != args.expected_slot:
        fail(f"slot identity mismatch: expected {args.expected_slot}, observed {slot}")

    key = f".mailstrix-runner-isolation-{run}-{attempt}-{args.profile}"
    expected = {"slot": slot, "profile": args.profile, "run_id": run,
                "leave_attempt": attempt, "namespace": namespace, "canary_key": key}
    if args.mode == "prove":
        raw = os.environ.get("LEAVE_TUPLE", "")
        if len(raw) > 1024:
            fail("invalid producer tuple")
        try:
            producer = json.loads(raw)
        except (ValueError, TypeError):
            fail("invalid producer tuple")
        if producer != expected:
            fail("producer tuple mismatch: rerun the complete leave/prove pair")

    state = prefix / namespace.lstrip("/")
    # Missing parents and lookup errors cannot masquerade as canary absence.
    directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if args.mode == "leave":
            output = os.environ.get("GITHUB_OUTPUT", "")
            if not output:
                fail("missing GITHUB_OUTPUT")
            os.mkdir(key, mode=0o700, dir_fd=directory)
            with (state / key / "probe").open("x") as stream:
                stream.write("must disappear before the next job\n")
            with open(output, "a", encoding="utf-8") as stream:
                stream.write("tuple=" + json.dumps(expected, separators=(",", ":")) + "\n")
            print(f"leave complete: slot={slot} namespace={namespace} run={run} attempt={attempt}")
        else:
            try:
                os.stat(key, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                print(f"prove complete: slot={slot} namespace={namespace} run={run} attempt={attempt}")
            else:
                fail("runner state from the previous job survived pristine restore")
    finally:
        os.close(directory)


try:
    main()
except (OSError, ValueError) as error:
    print(f"runner isolation: {error}", file=sys.stderr)
    sys.exit(1)
PY
