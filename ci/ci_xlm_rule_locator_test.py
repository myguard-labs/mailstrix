#!/usr/bin/env python3
"""Run the owning Go file-content contract in its normal package layout."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class XLMRuleLocatorTest(unittest.TestCase):
    def run_contract(self, rule):
        source = (ROOT / "internal/extract/xlm_emul_d8_test.go").read_text()
        # Copy the exact standalone owning test, rather than duplicating its locator.
        function = source[source.index("func TestYARARule_FileExists(") :]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "internal/extract"
            package.mkdir(parents=True)
            (root / "go.mod").write_text("module fixture\n\ngo 1.20\n")
            (package / "rule_test.go").write_text(
                'package extract\nimport ("bytes"; "os"; "testing")\n' + function
            )
            if rule is not None:
                target = root / "docker/local-rules/xlm_macrosheet.yara"
                target.parent.mkdir(parents=True)
                target.write_bytes(rule)
            result = subprocess.run(
                [
                    "go",
                    "test",
                    "-count=1",
                    "-race",
                    "-json",
                    "-run",
                    "^TestYARARule_FileExists$",
                    ".",
                ],
                cwd=package,
                text=True,
                capture_output=True,
                check=False,
            )
            events = [
                json.loads(line)
                for line in result.stdout.splitlines()
                if line.startswith("{")
            ]
            actions = [
                e["Action"]
                for e in events
                if e.get("Test") == "TestYARARule_FileExists"
            ]
            self.assertIn("run", actions, result.stdout + result.stderr)
            self.assertNotIn(
                "skip", actions, "XLM owning contract silently skipped its tracked rule"
            )
            return result

    def test_tracked_rule(self):
        result = self.run_contract(
            (ROOT / "docker/local-rules/xlm_macrosheet.yara").read_bytes()
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_rule(self):
        result = self.run_contract(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("read tracked XLM rule", result.stdout)

    def test_corrupt_rule(self):
        result = self.run_contract(b"rule corrupt { condition: true }")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not contain XLM-EMUL-DEPTH", result.stdout)


if __name__ == "__main__":
    unittest.main()
