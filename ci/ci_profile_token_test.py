#!/usr/bin/env python3
"""Exercise the real profiling shell script with a hermetic curl recorder."""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class ProfileTokenTest(unittest.TestCase):
    def capture(self, token, fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder = (
                "import json,os,sys\n"
                "name=os.path.basename(sys.argv[1])\n"
                "args=sys.argv[2:]\n"
                'header=sys.stdin.read() if name=="curl" and "@-" in args else ""\n'
                'with open(os.environ["CAPTURE"],"a") as f:\n'
                ' f.write(json.dumps({"command":name,"argv":args,"header":header})+"\\n")\n'
                'if name=="date": print("fixture")\n'
                'if name=="mkdir": os.makedirs(args[-1],exist_ok=True)\n'
                'sys.exit(int(os.environ["CURL_EXIT"]) if name=="curl" else 0)\n'
            )
            # Keep all children hermetic, including optional pprof and timestamp.
            for name in ["curl", "date", "go", "mkdir"]:
                path = root / name
                # A quoted shell launcher also supports interpreter paths with spaces.
                path.write_text(
                    f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
                    f'-c {shlex.quote(recorder)} "$0" "$@"\n'
                )
                path.chmod(0o755)
            capture = root / "calls"
            env = dict(
                os.environ,
                PATH=tmp,
                CAPTURE=str(capture),
                CURL_EXIT="22" if fail else "0",
                MAILSTRIX_TOKEN=token,
            )
            result = subprocess.run(
                [
                    "/bin/sh",
                    str(ROOT / "docker/pprof-capture.sh"),
                    "http://fixture.invalid:8079",
                    "2",
                    str(root / "out"),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            calls = (
                [json.loads(line) for line in capture.read_text().splitlines()]
                if capture.exists()
                else []
            )
            if token:
                self.assertNotIn(token, result.stdout + result.stderr)
            for call in calls:
                if token:
                    self.assertTrue(
                        all(token not in arg for arg in call["argv"]),
                        "profiling credential leaked into child argv",
                    )
            return result, [call for call in calls if call["command"] == "curl"]

    def test_header_and_all_profiles(self):
        for token in [
            "",
            "synthetic-fixture-only",
            'synthetic "quote" \\ slash; $value',
        ]:
            with self.subTest(token_shape="empty" if not token else "nonempty"):
                result, calls = self.capture(token)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 4)
                for call, profile in zip(
                    calls, ["profile?seconds=2", "heap", "allocs", "goroutine"]
                ):
                    self.assertIn(
                        "http://fixture.invalid:8079/debug/pprof/" + profile,
                        call["argv"],
                    )
                    self.assertEqual(
                        call["header"],
                        "Authorization: Bearer " + token + "\n" if token else "",
                    )
                    self.assertEqual("@-" in call["argv"], bool(token))

    def test_curl_failure_stops_capture(self):
        result, calls = self.capture("synthetic-failure-fixture", fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)

    def test_reject_header_line_breaks(self):
        for token in ["synthetic\nInjected: value", "synthetic\rInjected: value"]:
            result, calls = self.capture(token)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])

    def test_helpers_use_selected_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "interpreter-calls"
            interpreter = root / "selected python"
            interpreter.write_text(
                "#!/bin/sh\nset -eu\n"
                'printf \'%s\\n\' "$3" >> "$PROFILE_INTERPRETER_TRACE"\n'
                f'exec {shlex.quote(sys.executable)} "$@"\n'
            )
            interpreter.chmod(0o755)
            with (
                mock.patch.object(sys, "executable", str(interpreter)),
                mock.patch.dict(os.environ, PROFILE_INTERPRETER_TRACE=str(trace)),
            ):
                result, calls = self.capture("synthetic-interpreter-fixture")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls), 4)
            self.assertTrue(
                trace.exists(), "helpers bypassed the selected Python interpreter"
            )
            self.assertCountEqual(
                [Path(line).name for line in trace.read_text().splitlines()],
                ["date", "mkdir", *(["curl", "go"] * 4)],
            )


if __name__ == "__main__":
    unittest.main()
