"""Execute the Docker test-stage shell against inert affected-package fixtures."""

import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_stage_command():
    text = (ROOT / "docker/Dockerfile").read_text()
    stage = text.split("FROM build AS test\n", 1)[1].split("\nFROM ", 1)[0]
    lines = iter(stage.splitlines())
    command = next(line[4:] for line in lines if line.startswith("RUN "))
    while command.endswith("\\"):
        command = command[:-1] + next(lines)
    return re.sub(r"--mount=\S+\s*", "", command)


class VetWiringTests(unittest.TestCase):
    def invoke(
        self,
        scope,
        violation=False,
        selector_failure=False,
        test_failure=False,
        full=False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory)
            (fixture / "go.mod").write_text("module example.com/fixture\n\ngo 1.26\n")
            for name in ["affected", "unaffected"]:
                package = fixture / name
                package.mkdir()
                # The unselected package is always invalid for vet, but compiles.
                argument = '"wrong type"' if violation or name == "unaffected" else "1"
                (package / "fixture.go").write_text(
                    f'package {name}\nimport "fmt"\n'
                    f'func Check() {{ fmt.Printf("%d", {argument}) }}\n'
                )
            test_body = (
                't.Fatal("selected test failure")' if test_failure else "Check()"
            )
            (fixture / "affected/fixture_test.go").write_text(
                'package affected\nimport "testing"\n'
                f"func TestSelected(t *testing.T) {{ {test_body} }}\n"
            )
            binary = fixture / "bin"
            binary.mkdir()
            if full:
                (fixture / "ci").mkdir()
                # Inert stand-in: records that the combined-coverage check ran.
                gate = fixture / "ci/go_coverage.sh"
                gate.write_text('#!/bin/sh\necho "gate $*" >> "$TRACE"\n')
                gate.chmod(0o755)
            shim = binary / "go"
            shim.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$TRACE"
if [ "$1" = run ]; then
    [ "$SELECTOR_FAILURE" = 0 ] || exit 42
    printf '%s\\n' "$SCOPE"
    exit 0
fi
# Disable go test's implicit vet so this oracle detects removal of explicit vet.
if [ "$1" = test ]; then
    shift
    exec "$REAL_GO" test -vet=off "$@"
fi
exec "$REAL_GO" "$@"
""")
            shim.chmod(0o755)
            trace = fixture / "trace"
            result = subprocess.run(
                ["sh", "-c", test_stage_command()],
                cwd=fixture,
                env=dict(
                    os.environ,
                    PATH=f"{binary}:{os.environ['PATH']}",
                    REAL_GO=shutil.which("go"),
                    TRACE=str(trace),
                    SCOPE=scope,
                    SELECTOR_FAILURE=str(int(selector_failure)),
                    CHANGED_FILES="" if full else "--changed -- affected/fixture.go",
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            return result, trace.read_text() if trace.exists() else ""

    def test_affected_static_vet_passes_and_excludes_unaffected_violation(self):
        result, trace = self.invoke("./affected")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vet -tags yara_static ./affected\n", trace)
        self.assertIn(
            "test -race -p 1 -timeout 30m -tags yara_static ./affected\n", trace
        )
        self.assertNotIn("./unaffected", trace)
        self.assertNotIn("cover", trace)

    def test_full_run_reuses_test_run_for_combined_coverage(self):
        result, trace = self.invoke("./affected", full=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "test -race -p 1 -timeout 30m -tags yara_static "
            "-coverpkg=./... -coverprofile=/tmp/cover.out ./affected\n",
            trace,
        )
        self.assertEqual(trace.count("test -race"), 1)
        self.assertIn("gate /tmp/cover.out\n", trace)

    def test_full_run_test_failure_skips_coverage_gate(self):
        result, trace = self.invoke("./affected", full=True, test_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("gate", trace)

    def test_selected_test_failure_is_fatal(self):
        result, trace = self.invoke("./affected", test_failure=True)
        self.assertNotEqual(result.returncode, 0, "selected test failure must fail")
        self.assertIn("selected test failure", result.stdout)
        self.assertIn(
            "test -race -p 1 -timeout 30m -tags yara_static ./affected\n", trace
        )

    def test_affected_vet_violation_is_fatal_before_tests(self):
        result, trace = self.invoke("./affected", violation=True)
        self.assertNotEqual(result.returncode, 0, "affected vet violation must fail")
        self.assertIn("fmt.Printf format %d has arg", result.stderr)
        self.assertNotIn("test -race", trace)

    def test_empty_selection_skips_vet_and_tests(self):
        result, trace = self.invoke("")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("vet ", trace)
        self.assertNotIn("test ", trace)

    def test_selector_failure_is_fatal(self):
        result, trace = self.invoke("./affected", selector_failure=True)
        self.assertEqual(result.returncode, 42)
        self.assertNotIn("vet ", trace)
        self.assertNotIn("test ", trace)

    def test_failure_before_trace_creation_is_reported(self):
        with mock.patch(__name__ + ".test_stage_command", return_value="exit 42"):
            result, trace = self.invoke("./affected")
        self.assertEqual(result.returncode, 42)
        self.assertEqual(trace, "")

    def test_workflow_builds_vet_stage_with_affected_selection(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("- name: build test stage", 1)[1].split("\n      - ", 1)[
            0
        ]
        self.assertIn("needs.changes.outputs.go == 'true'", step)
        self.assertIn("--target test -f docker/Dockerfile", step)
        self.assertIn('--build-arg CHANGED_FILES="$CHANGED_FILES"', step)
        self.assertIn("CHANGED_FILES: ${{ needs.changes.outputs.changed_files }}", step)

    def test_wiring_contract_runs_after_go_setup(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        lint = workflow.split("  lint:\n", 1)[1].split("\n  scanners:", 1)[0]
        self.assertLess(
            lint.index("- uses: ./.github/actions/go-setup"),
            lint.index("run: python3 -B ci/vet_wiring_test.py"),
        )
        step = lint.split("- name: Docker vet wiring contract", 1)[1].split(
            "\n      - ", 1
        )[0]
        self.assertIn(
            "needs.changes.outputs.go == 'true' || needs.changes.outputs.scope == 'true'",
            lint.split("    steps:", 1)[0],
        )
        self.assertNotRegex(step, r"(?m)^\s*if:")


if __name__ == "__main__":
    unittest.main()
