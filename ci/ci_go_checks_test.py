"""Prove Go analysis executes only selector outputs and fails on tool errors."""

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class GoChecksTests(unittest.TestCase):
    def invoke(self, scope, changed, failed="", directories=("",), script=None):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            trace = root / "trace"
            tool = root / "tool"
            tool.write_text("""#!/bin/bash
set -eu
name=${0##*/}
printf '%s' "$name" >> "$TRACE"
printf ' <%s>' "$@" >> "$TRACE"
printf '\\n' >> "$TRACE"
if [[ $name == "$FAIL_TOOL" ]]; then exit 42; fi
if [[ $name == go && $1 == run ]]; then printf '%s\\n' "$SCOPE"; fi
if [[ $name == go && $1 == list ]]; then printf '%s\\n' "$FIXTURE"; fi
""")
            tool.chmod(0o755)
            selected_dirs = []
            for name in directories:
                selected = root / name
                selected.mkdir(parents=True, exist_ok=True)
                (selected / "fixture.go").write_text("package fixture\n")
                selected_dirs.append(str(selected))
            for name in ["go", "gofmt", "staticcheck", "govulncheck", "gosec"]:
                (root / name).symlink_to(tool)
            environment = dict(
                os.environ,
                PATH=f"{temp}:{os.environ['PATH']}",
                TRACE=str(trace),
                SCOPE=scope,
                FAIL_TOOL=failed,
                FIXTURE="\n".join(selected_dirs),
                CHANGED_FILES=changed,
            )
            result = subprocess.run(
                ["bash", str(script or ROOT / "scripts/ci-go-checks.sh")],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            return result, trace.read_text() if trace.exists() else ""

    def test_multiple_selected_directories_share_one_gofmt_process(self):
        result, trace = self.invoke(
            "example/one example/two",
            "--changed -- internal/one/file.go",
            directories=("one", "two with space"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        formatted = [line for line in trace.splitlines() if line.startswith("gofmt ")]
        self.assertEqual(len(formatted), 1, trace)
        self.assertIn("/one/fixture.go>", formatted[0])
        self.assertIn("/two with space/fixture.go>", formatted[0])
        self.assertEqual(trace.count("go <list>"), 1)
        for name in ("staticcheck", "govulncheck", "gosec"):
            self.assertEqual(trace.count(name + " "), 1, trace)

    def test_affected_packages_reach_every_analyzer(self):
        result, trace = self.invoke(
            "example/extract example/server", "--changed -- internal/extract/pdf.go"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "go <run> <./tools/testscope> <--changed> <--> <internal/extract/pdf.go>",
            trace,
        )
        for name in ["staticcheck", "govulncheck"]:
            self.assertIn(f"{name} <example/extract> <example/server>", trace)
        self.assertNotIn("go <vet>", trace)
        gosec_line = next(
            line for line in trace.splitlines() if line.startswith("gosec ")
        )
        self.assertRegex(gosec_line, r"^gosec </[^>]+>$")
        self.assertNotIn("example/", gosec_line)
        self.assertNotIn("<./...>", trace)

    def test_empty_explicit_scope_runs_no_analyzers(self):
        result, trace = self.invoke("", "--changed --")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(trace.splitlines()), 1)
        self.assertIn("No affected", result.stdout)

    def test_failure_is_fatal(self):
        for failed in ["go", "gofmt", "staticcheck", "govulncheck", "gosec"]:
            with self.subTest(failed=failed):
                result, _ = self.invoke(
                    "example/pkg", "--changed -- internal/pkg/file.go", failed
                )
                self.assertEqual(result.returncode, 42)

    def test_release_preserves_full_selection(self):
        result, trace = self.invoke("./...", "")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("go <run> <./tools/testscope>\n", trace)
        self.assertIn("go <test> <-race> <./...>", trace)


if __name__ == "__main__":
    unittest.main()
