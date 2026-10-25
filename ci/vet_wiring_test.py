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


def test_stage_command(text=None):
    if text is None:
        text = (ROOT / "docker/Dockerfile").read_text()
    stage = text.split("FROM build AS test\n", 1)[1].split("\nFROM ", 1)[0]
    commands = [
        line[4:]
        for line in stage.replace("\\\n", " ").splitlines()
        if line.startswith("RUN ") and re.search(r"\bgo\s+vet\b", line)
    ]
    assert len(commands) == 1, "expected exactly one Docker vet/test RUN"
    command = commands[0]
    assert re.search(r"\bgo\s+test\b", command), "Docker vet RUN has no go test"
    return re.sub(r"--mount=\S+\s*", "", command)


def fixture_stage_command(text=None):
    if text is None:
        text = (ROOT / "docker/Dockerfile").read_text()
    stage = text.split("FROM build AS test\n", 1)[1].split("\nFROM ", 1)[0]
    commands = [
        line[4:]
        for line in stage.replace("\\\n", " ").splitlines()
        if line.startswith("RUN ") and "go run ./tools/testscope" in line
    ]
    assert len(commands) == 1, "expected exactly one test-stage selector RUN"
    return re.sub(r"--mount=\S+\s*", "", commands[0])


class VetWiringTests(unittest.TestCase):
    def test_extracts_vet_run_after_count_gate(self):
        command = test_stage_command()
        self.assertIn("go vet -tags yara_static", command)
        self.assertIn("go test -race", command)
        self.assertNotIn("--native-ci", command)
        self.assertNotIn("--mount=", command)
        self.assertIn("cat .testscope-packages", command)

    def test_selector_plan_is_single_and_shared_by_both_runs(self):
        source = (ROOT / "docker/Dockerfile").read_text()
        stage = source.split("FROM build AS test\n", 1)[1].split("\nFROM ", 1)[0]
        self.assertEqual(stage.count("go run ./tools/testscope"), 1)
        self.assertIn("printf '%s\\n' \"$pkgs\" > .testscope-packages", stage)
        self.assertIn("cat .testscope-packages", test_stage_command(source))

    def test_duplicate_selector_mutation_is_rejected(self):
        source = (ROOT / "docker/Dockerfile").read_text()
        duplicate = source.replace(
            'pkgs="$(cat .testscope-packages)"',
            'pkgs="$(go run ./tools/testscope ${CHANGED_FILES})"',
            1,
        )
        self.assertNotEqual(duplicate, source)
        with self.assertRaisesRegex(AssertionError, "exactly one test-stage selector"):
            fixture_stage_command(duplicate)

    def test_missing_ambiguous_and_incomplete_vet_run_are_rejected(self):
        source = (ROOT / "docker/Dockerfile").read_text()
        for text, message in (
            (source.replace("go vet", "go version"), "exactly one"),
            (
                source.replace(
                    "FROM build AS test\n", "FROM build AS test\nRUN go vet ./...\n"
                ),
                "exactly one",
            ),
            (source.replace("go test", "go version"), "has no go test"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(AssertionError, message),
            ):
                test_stage_command(text)

    def invoke(
        self,
        scope,
        violation=False,
        selector_failure=False,
        test_failure=False,
        full=False,
        ci_pkg=False,
        ci_failure=False,
        changed="--changed -- affected/fixture.go",
        remove_plan=False,
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
            if full or ci_pkg:
                (fixture / "ci").mkdir()
                if ci_pkg:
                    body = 't.Fatal("ci test failure")' if ci_failure else ""
                    (fixture / "ci/ci_test.go").write_text(
                        'package ci\nimport "testing"\n'
                        f"func TestCI(t *testing.T) {{ {body} }}\n"
                    )
            if full:
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
            environment = dict(
                os.environ,
                PATH=f"{binary}:{os.environ['PATH']}",
                REAL_GO=shutil.which("go"),
                TRACE=str(trace),
                SCOPE=scope,
                SELECTOR_FAILURE=str(int(selector_failure)),
                CHANGED_FILES="" if full else changed,
            )
            preparation = subprocess.run(
                ["sh", "-c", fixture_stage_command()],
                cwd=fixture,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            if preparation.returncode:
                return preparation, trace.read_text() if trace.exists() else ""
            if remove_plan:
                (fixture / ".testscope-packages").unlink()
            result = subprocess.run(
                ["sh", "-c", test_stage_command()],
                cwd=fixture,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            return result, trace.read_text() if trace.exists() else ""

    def test_affected_static_vet_passes_and_excludes_unaffected_violation(self):
        result, trace = self.invoke("./affected")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(trace.count("run ./tools/testscope"), 1)
        self.assertIn("vet -tags yara_static ./affected\n", trace)
        self.assertIn(
            "test -race -p 1 -timeout 30m -tags yara_static ./affected\n", trace
        )
        self.assertNotIn("./unaffected", trace)
        self.assertNotIn("cover", trace)

    COVER = (
        "test -race -p 1 -timeout 30m -tags yara_static "
        "-coverpkg=./... -coverprofile=/tmp/cover.out "
    )
    PLAIN = "test -race -p 1 -timeout 30m -tags yara_static "

    def test_full_run_reuses_test_run_for_combined_coverage(self):
        result, trace = self.invoke("./affected", full=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.COVER + "example.com/fixture/affected\n", trace)
        self.assertEqual(trace.count("test -race"), 1)
        self.assertEqual(trace.count("vet -tags"), 1)
        self.assertEqual(trace.count("gate /tmp/cover.out\n"), 1)

    def test_full_run_tests_ci_outside_coverage_run(self):
        result, trace = self.invoke("./affected ./ci", full=True, ci_pkg=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.COVER + "example.com/fixture/affected\n", trace)
        self.assertIn(self.PLAIN + "example.com/fixture/ci\n", trace)
        self.assertEqual(trace.count("test -race"), 2)
        self.assertEqual(trace.count("example.com/fixture/ci"), 1)
        self.assertEqual(trace.count("vet -tags yara_static ./affected ./ci\n"), 1)
        self.assertEqual(trace.count("gate /tmp/cover.out\n"), 1)
        self.assertLess(trace.index("test -race"), trace.index("gate"))
        self.assertLess(trace.rindex("test -race"), trace.index("gate"))

    def test_full_run_only_ci_skips_coverage_gate(self):
        result, trace = self.invoke("./ci", full=True, ci_pkg=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.PLAIN + "example.com/fixture/ci\n", trace)
        self.assertEqual(trace.count("test -race"), 1)
        self.assertNotIn("cover", trace)
        self.assertNotIn("gate", trace)

    def test_full_run_ci_failure_fails_and_skips_gate(self):
        result, trace = self.invoke(
            "./affected ./ci", full=True, ci_pkg=True, ci_failure=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ci test failure", result.stdout)
        self.assertEqual(trace.count("test -race"), 2)
        self.assertNotIn("gate", trace)

    def test_full_run_covered_failure_fails_and_skips_gate(self):
        result, trace = self.invoke(
            "./affected ./ci", full=True, ci_pkg=True, test_failure=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected test failure", result.stdout)
        self.assertNotIn("gate", trace)

    def test_full_run_empty_selection_runs_nothing(self):
        result, trace = self.invoke("", full=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("test ", trace)
        self.assertNotIn("gate", trace)

    def test_scoped_run_with_ci_has_no_cover_and_single_test_run(self):
        result, trace = self.invoke(
            "./affected ./ci",
            ci_pkg=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.PLAIN + "./affected ./ci\n", trace)
        self.assertEqual(trace.count("test -race"), 1)
        self.assertNotIn("cover", trace)
        self.assertNotIn("gate", trace)

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

    def test_missing_shared_plan_fails_before_vet(self):
        result, trace = self.invoke("./affected", remove_plan=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("vet ", trace)

    def test_failure_before_trace_creation_is_reported(self):
        with mock.patch(__name__ + ".test_stage_command", return_value="exit 42"):
            result, trace = self.invoke("./affected")
        self.assertEqual(result.returncode, 42)
        self.assertEqual(trace.count("run ./tools/testscope"), 1)
        self.assertNotIn("vet ", trace)
        self.assertNotIn("test -race", trace)

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
