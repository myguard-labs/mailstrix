"""Local/monthly fixture bootstrap and Docker delivery contracts."""

import importlib.util
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "prepare", ROOT / "ci/prepare_marker_runtime.py"
)
assert SPEC is not None and SPEC.loader is not None
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class FixturePreparationTests(unittest.TestCase):
    def assert_asan_contract(self, source):
        # The maintenance contract uses literal fields and single-line commands;
        # reject unsupported/duplicate forms. actionlint validates the full YAML.
        jobs = re.findall(
            r"^  asan:\n(.*?)(?=^  [\w-]+:|\Z)", source, re.MULTILINE | re.DOTALL
        )
        self.assertEqual(len(jobs), 1, "ASAN job must exist exactly once")
        job = jobs[0]
        runners = re.findall(r"^    runs-on: \[([^\n]+)\]$", job, re.MULTILINE)
        self.assertEqual(len(runners), 1, "ASAN literal runner contract missing")
        labels = [label.strip().strip("\"'") for label in runners[0].split(",")]
        self.assertEqual(
            sorted(labels),
            ["builder02", "docker", "self-hosted"],
            "ASAN must select the canonical Docker daemon profile",
        )
        guards = re.findall(r"^    timeout-minutes: (\d+)$", job, re.MULTILINE)
        self.assertEqual(len(guards), 1, "ASAN job guard must be explicit")
        self.assertEqual(
            int(guards[0]), 60, "ASAN must permit the measured complete runtime"
        )
        commands = [
            shlex.split(command)
            for command in re.findall(r"^        run: (.+)$", job, re.MULTILINE)
        ]
        self.assertEqual(
            commands,
            [
                ["python3", "ci/prepare_marker_runtime.py"],
                ["go", "test", "-asan", "-p", "1", "-timeout", "30m", "./..."],
            ],
            "ASAN must prepare the genuine fixture then run every package with safe runtime bounds",
        )
        self.assertEqual(
            re.findall(r"^          CC: (.+)$", job, re.MULTILINE), ["clang"]
        )
        self.assertEqual(
            re.findall(r"^          ASAN_OPTIONS: (.+)$", job, re.MULTILINE),
            ["detect_leaks=0:detect_odr_violation=0"],
        )

    def test_monthly_asan_preserves_complete_native_caller(self):
        self.assert_asan_contract(
            (ROOT / ".github/workflows/maintenance.yml").read_text()
        )

    def test_monthly_asan_wrong_runner_guard_and_command_rejected(self):
        source = (ROOT / ".github/workflows/maintenance.yml").read_text()
        for original, broken, assertion in (
            (
                "runs-on: [self-hosted, builder02, docker]",
                "runs-on: [self-hosted, builder02, lxc]",
                "canonical Docker",
            ),
            ("timeout-minutes: 60", "timeout-minutes: 20", "measured complete runtime"),
            (
                "go test -asan -p 1 -timeout 30m ./...",
                "go test -asan ./...",
                "safe runtime bounds",
            ),
            (
                "        run: python3 ci/prepare_marker_runtime.py\n",
                "",
                "genuine fixture",
            ),
        ):
            with (
                self.subTest(broken=broken),
                self.assertRaisesRegex(AssertionError, assertion),
            ):
                self.assert_asan_contract(source.replace(original, broken, 1))

    def test_success_and_output_guards(self):
        for state in ("regular", "missing", "empty", "directory", "symlink"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                destination = root / "ci/testdata/marker-runtime.zip"
                destination.parent.mkdir(parents=True)
                destination.write_bytes(b"old output")

                def build(argv, *, check, root=root, state=state):
                    self.assertTrue(check)
                    self.assertEqual(
                        argv[:5], ["docker", "buildx", "build", "--builder", "default"]
                    )
                    self.assertEqual(
                        argv[argv.index("--target") + 1], "marker-fixture-export"
                    )
                    self.assertEqual(argv[-1], str(root))
                    output = Path(argv[argv.index("--output") + 1].split("dest=", 1)[1])
                    output.mkdir()
                    path = output / "marker-runtime.zip"
                    if state == "regular":
                        path.write_bytes(b"generated output")
                    elif state == "empty":
                        path.touch()
                    elif state == "directory":
                        path.mkdir()
                    elif state == "symlink":
                        source = output / "elsewhere"
                        source.write_bytes(b"generated output")
                        path.symlink_to(source)

                with patch.object(prepare.subprocess, "run", side_effect=build):
                    if state == "regular":
                        self.assertEqual(prepare.prepare(root), destination)
                        self.assertEqual(destination.read_bytes(), b"generated output")
                    else:
                        with self.assertRaisesRegex(
                            RuntimeError, "no regular nonempty output"
                        ):
                            prepare.prepare(root)
                        self.assertFalse(
                            destination.exists(),
                            "failed bootstrap retained stale fixture",
                        )

    def test_generator_and_missing_tool_failure_propagate(self):
        for error in (
            subprocess.CalledProcessError(17, ["docker"]),
            FileNotFoundError("docker"),
        ):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                destination = root / "ci/testdata/marker-runtime.zip"
                destination.parent.mkdir(parents=True)
                destination.write_bytes(b"old output")
                with (
                    patch.object(prepare.subprocess, "run", side_effect=error),
                    self.assertRaises(type(error)),
                ):
                    prepare.prepare(root)
                self.assertFalse(destination.exists())

    def test_every_native_caller_has_fail_closed_preparation(self):
        dockerfile = (ROOT / "docker/Dockerfile").read_text()
        self.assertIn("FROM yara AS marker-fixture", dockerfile)
        self.assertIn("python3 /src/ci/marker_runtime_fixture.py", dockerfile)
        self.assertIn("test -s /fixture/marker-runtime.zip", dockerfile)
        self.assertIn(
            "COPY --from=marker-fixture /fixture/marker-runtime.zip /src/ci/testdata/marker-runtime.zip",
            dockerfile,
        )
        maintenance = (ROOT / ".github/workflows/maintenance.yml").read_text()
        self.assertLess(
            maintenance.index("run: python3 ci/prepare_marker_runtime.py"),
            maintenance.index("run: go test -asan -p 1 -timeout 30m ./..."),
        )
        fixture_test = (ROOT / "internal/mailstrix/marker_artifact_test.go").read_text()
        self.assertIn(
            "run python3 ci/prepare_marker_runtime.py before local Go tests",
            fixture_test,
        )
        self.assertNotIn(
            "!ci/testdata/marker-runtime.zip", (ROOT / ".dockerignore").read_text()
        )
        self.assertIn(
            "/ci/testdata/marker-runtime.zip", (ROOT / ".gitignore").read_text()
        )


if __name__ == "__main__":
    unittest.main()
