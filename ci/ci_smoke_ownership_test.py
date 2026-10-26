"""Execute the real smoke scripts against a stateful, socket-free Docker fixture."""

import concurrent.futures
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(
    os.environ.get("MAILSTRIX_SMOKE_TEST_ROOT", Path(__file__).resolve().parents[1])
)
FOREIGN_ID = "f" * 64


# HTTP answers preserve each original positive/negative assertion and request
# order. These tests exercise ownership; the real-image matrix exercises rules.
SCAN_RULES = {
    18079: ["EICAR_Test_File", ""],
    18081: [
        "Maldoc_AutoExec_Write_Execute",
        "",
        "Maldoc_AutoExec_Write_Execute",
        "Maldoc_AutoExec_Write_Execute",
    ],
    18082: ["Maldoc_Suspicious_VBA_Keywords", "Maldoc_VBA_Shellcode_API", ""],
    18083: ["OOXML_Remote_Template", ""],
    18084: ["Maldoc_DDE_Field", ""],
    18087: ["XLM_Hidden_Macrosheet", ""],
    18094: ["XLM_Dangerous_Function", "XLM_Hidden_Macrosheet", ""],
    18088: ["VBA_Stomped", ""],
    18089: ["Exploit_EquationEditor", ""],
    18090: ["", ""],
    18091: ["Maldoc_DocProps_Payload", "", ""],
    18086: [
        "LOLBins_Invocation",
        "WMI_Process_Spawn",
        "PowerShell_Abuse_Flags",
        "Maldoc_AntiAnalysis_Evasion",
        "VBA_Environ_Probe",
        "",
    ],
}


def option(args, flag, default=None):
    return args[args.index(flag) + 1] if flag in args else default


def create_fixture(state, args, mode, fail_at):
    state["creates"] += 1
    name = option(args, "--name")
    label = option(args, "--label", "").removeprefix("myguard.run=")
    cidfile = option(args, "--cidfile")
    if not (name and label and cidfile):
        raise AssertionError("every create needs name, ownership label and cidfile")
    selected = state["creates"] == fail_at
    if selected and mode in (
        "create-fail",
        "name-collision",
        "foreign-cid",
        "malformed-cid",
        "malformed-success",
    ):
        if mode == "name-collision":
            state["containers"][FOREIGN_ID]["name"] = name
        if mode == "foreign-cid":
            Path(cidfile).write_text(FOREIGN_ID, encoding="utf-8")
        if mode in ("malformed-cid", "malformed-success"):
            Path(cidfile).write_text("--all\n", encoding="utf-8")
        return "", 0 if mode == "malformed-success" else 125
    identifier = f"{state['creates']:064x}"
    state["containers"][identifier] = {
        "name": name,
        "label": label,
        "env": [args[i + 1] for i, arg in enumerate(args) if arg == "-e"],
        "mounts": [args[i + 1] for i, arg in enumerate(args) if arg == "-v"],
        "starts": 0,
        "running": False,
    }
    state["created"].append(identifier)
    Path(cidfile).write_text(identifier, encoding="utf-8")
    # A daemon create can succeed before the client reports an error.
    return identifier, 125 if selected and mode == "partial-create" else 0


def inspect_fixture(container, args, mode):
    template = option(args, "-f")
    if "Labels" in template:
        return container["label"]
    if "Health" in template:
        return "unhealthy" if mode == "unhealthy" else "healthy"
    return str(container["running"]).lower()


def start_fixture(state, identifier, container, mode, fail_at):
    container["starts"] += 1
    container["running"] = True
    if identifier == f"{fail_at:064x}" and mode in ("start-fail", "replaced-name"):
        if mode == "replaced-name":
            state["containers"][FOREIGN_ID]["name"] = container["name"]
            del state["containers"][identifier]
        return identifier, 125
    return identifier, 0


def docker_fixture(state, args, mode, fail_at):
    command = args[0]
    if command == "create":
        return create_fixture(state, args, mode, fail_at)
    if command in ("run", "volume", "ps"):
        raise AssertionError(
            "smoke must not adopt reusable volume names or unrecorded run containers"
        )
    identifier = args[-2] if command == "port" else args[-1]
    container = state["containers"].get(identifier)
    if command == "rm":
        state["removed"].append(identifier)
        state["containers"].pop(identifier, None)
        return "", 0
    if container is None:
        return "", 1
    if command == "inspect":
        return inspect_fixture(container, args, mode), 0
    if command == "start":
        return start_fixture(state, identifier, container, mode, fail_at)
    if command == "stop":
        container["running"] = False
        return "", 0
    if command == "logs":
        return "seeded rules cache\n" * container["starts"], 0
    if command == "wait":
        return "7" if mode == "wipe-fail" else "0", 0
    if command == "port":
        state["polling_env"] = container["env"]
        return "127.0.0.1:18100", 0
    raise AssertionError(f"unexpected Docker command: {args}")


def curl_fixture(state, args, mode):
    url = urlsplit(args[-1])
    source = option(args, "--data-binary", "")
    if source == "@-":
        sys.stdin.buffer.read()
    elif source:
        with zipfile.ZipFile(
            io.BytesIO(Path(source.removeprefix("@")).read_bytes())
        ) as document:
            if b"evil.example/c2" not in document.read("docProps/core.xml"):
                raise AssertionError("real OOXML fixture must retain its hidden URL")
    if url.path == "/metrics":
        return "mailstrix_rules 1\n"
    if url.path == "/ready":
        return "ready"
    if url.path == "/version" and url.port == 18100:
        disabled = "MAILSTRIX_RULES_POLL_INTERVAL=0" in state["polling_env"]
        return json.dumps(
            {
                "rules_update": {
                    "enabled": not disabled,
                    "last_check_unix": int(not disabled),
                    "last_failure_unix": int(not disabled),
                    "failures": int(not disabled),
                }
            }
        )
    if url.path == "/version":
        return '{"extractor_version":"fixture"}'
    if "X-MAILSTRIX-Token: wrong" in args:
        return "401"
    state["scans"] += 1
    offsets = state.setdefault("scan_offsets", {})
    index = offsets.get(str(url.port), 0)
    offsets[str(url.port)] = index + 1
    rule = SCAN_RULES[url.port][index]
    return json.dumps(
        {"matches": [rule] if rule and mode != "assertion-fail" else []},
        separators=(",", ":"),
    )


def fixture(tool, args):
    """Model create/cidfile/start separately; names remain reusable aliases."""
    path = Path(os.environ["SMOKE_FIXTURE_STATE"])
    state = json.loads(path.read_text(encoding="utf-8"))
    state["calls"].append([tool, *args])
    mode = os.environ.get("SMOKE_FIXTURE_MODE", "")
    if tool == "docker":
        output, status = docker_fixture(
            state, args, mode, int(os.environ["SMOKE_FIXTURE_FAIL_AT"])
        )
    elif tool == "curl":
        output, status = curl_fixture(state, args, mode), 0
    elif tool == "sleep":
        output, status = "", 0  # keep every readiness iteration without a delay
    else:
        raise AssertionError(tool)
    path.write_text(json.dumps(state), encoding="utf-8")
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    return status


class SmokeOwnershipTests(unittest.TestCase):
    def invoke(self, mode="", fail_at=1, *, polling=False, body=None):
        with tempfile.TemporaryDirectory(prefix="smoke-ownership-test-") as temporary:
            root = Path(temporary)
            for relative in ("scripts/smoke.sh", "ci/rules_polling_test.sh"):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            shutil.copytree(ROOT / "docker/local-rules", root / "docker/local-rules")
            for relative in ("rules/eicar.yar", "rules-ym/preserved", "s.docx"):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"preexisting operator data\n")
            before = {
                p.relative_to(root): p.read_bytes()
                for p in root.rglob("*")
                if p.is_file()
            }
            bindir = root / "bin"
            bindir.mkdir()
            for tool in ("docker", "curl", "sleep"):
                wrapper = bindir / tool
                wrapper.write_text(
                    f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
                    f'{shlex.quote(str(Path(__file__).resolve()))} --fixture {tool} "$@"\n'
                )
                wrapper.chmod(0o755)
            statepath = root / "state.json"
            bashenv = root / "bash-env"
            bashenv.write_text(
                "PS4='+${BASH_SOURCE:-command}:${LINENO}: '; set -x\n", encoding="utf-8"
            )
            statepath.write_text(
                json.dumps(
                    {
                        "containers": {FOREIGN_ID: {"name": "yc", "label": "foreign"}},
                        "volumes": {"yc-cache": "foreign"},
                        "calls": [],
                        "creates": 0,
                        "created": [],
                        "removed": [],
                        "scans": 0,
                    }
                )
            )
            env = dict(
                os.environ,
                PATH=f"{bindir}:{os.environ['PATH']}",
                TMPDIR=str(root),
                SMOKE_FIXTURE_STATE=str(statepath),
                SMOKE_FIXTURE_MODE=mode,
                SMOKE_FIXTURE_FAIL_AT=str(fail_at),
                BASH_ENV=str(bashenv),
            )
            script = "ci/rules_polling_test.sh" if polling else "scripts/smoke.sh"
            command = ["bash", "-x", script, "fixture-image"]
            if body is not None:
                command = [
                    "bash",
                    "-xc",
                    "source scripts/smoke.sh; smoke_resources_init; " + body,
                ]
            result = subprocess.run(
                command, cwd=root, env=env, capture_output=True, check=False
            )
            state = json.loads(statepath.read_text())
            self.assertNotIn(
                b"Traceback", result.stderr, "fixture crashed, not a script failure"
            )
            self.assertIn(
                FOREIGN_ID, state["containers"], "cleanup deleted an unowned container"
            )
            self.assertNotIn(
                FOREIGN_ID, state["removed"], "cleanup attempted to delete a foreign ID"
            )
            self.assertEqual(state["volumes"], {"yc-cache": "foreign"})
            self.assertEqual(
                set(state["containers"]), {FOREIGN_ID}, "owned container leaked"
            )
            for relative, contents in before.items():
                self.assertEqual(
                    (root / relative).read_bytes(),
                    contents,
                    f"changed preexisting file: {relative}",
                )
            self.assertEqual(
                list(root.glob("mailstrix-smoke.*")), [], "owned workspace leaked"
            )
            trace_dir = os.environ.get("SMOKE_OWNERSHIP_EVIDENCE")
            if trace_dir:
                directory = Path(trace_dir)
                directory.mkdir(parents=True, exist_ok=True)
                prefix = (
                    directory
                    / f"{self._testMethodName}-{mode}-{fail_at}-{'polling' if polling else 'main'}"
                )
                prefix.with_suffix(".stdout").write_bytes(result.stdout)
                prefix.with_suffix(".stderr").write_bytes(result.stderr)
                prefix.with_suffix(".json").write_text(json.dumps(state, indent=2))
            return result, state

    def test_complete_real_script_keeps_all_smoke_cases(self):
        result, state = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"=== smoke: ALL OK ===", result.stdout)
        self.assertEqual(
            state["creates"], 16
        )  # 12 isolated + seed + wipe + two polling modes
        self.assertEqual(state["scans"], 33)
        self.assertEqual(set(state["created"]), set(state["removed"]))

    def test_create_start_partial_and_collision_errors_at_every_boundary(self):
        modes = (
            "create-fail",
            "partial-create",
            "start-fail",
            "name-collision",
            "replaced-name",
        )
        cases = tuple((mode, fail_at) for mode in modes for fail_at in range(1, 17))
        self.assertEqual(len(cases), 80)
        # Each invocation owns a private root and state file. Bound concurrency
        # removes repeated process-startup wall time while retaining every case.
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = {
                case: executor.submit(self.invoke, *case) for case in cases
            }
            for (mode, fail_at), future in results.items():
                with self.subTest(mode=mode, fail_at=fail_at):
                    result, state = future.result()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertGreaterEqual(
                        state["creates"], fail_at, "fault boundary never reached"
                    )

    def test_foreign_cidfile_is_never_cleanup_authority(self):
        result, _ = self.invoke("foreign-cid")
        self.assertNotEqual(result.returncode, 0)

    def test_malformed_cidfile_is_rejected(self):
        for mode in ("malformed-cid", "malformed-success"):
            with self.subTest(mode=mode):
                result, _ = self.invoke(mode)
                self.assertNotEqual(result.returncode, 0)

    def test_http_assertion_failure_still_cleans(self):
        result, _ = self.invoke("assertion-fail")
        self.assertNotEqual(result.returncode, 0)

    def test_unhealthy_container_still_cleans(self):
        result, _ = self.invoke("unhealthy")
        self.assertNotEqual(result.returncode, 0)

    def test_failed_wipe_exit_is_not_success(self):
        result, _ = self.invoke("wipe-fail")
        self.assertNotEqual(result.returncode, 0)

    def test_standalone_polling_failure_and_success(self):
        for mode in (
            "",
            "create-fail",
            "partial-create",
            "start-fail",
            "replaced-name",
        ):
            with self.subTest(mode=mode):
                result, _ = self.invoke(mode, polling=True)
                self.assertEqual(
                    result.returncode == 0, mode == "", result.stderr.decode()
                )

    def test_empty_and_repeated_cleanup(self):
        result, _ = self.invoke(body="cleanup; cleanup")
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_repeated_cleanup_after_partial_execution(self):
        result, _ = self.invoke(
            body="create_container example fixture-image; cleanup; cleanup"
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture":
        sys.exit(fixture(sys.argv[2], sys.argv[3:]))
    unittest.main()
