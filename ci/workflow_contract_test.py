"""Exercise the required CI check against the shipped workflow script."""

import itertools
import os
import subprocess
import textwrap
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
OPTIONAL = ("PARITY", "LINT", "RSPAMD", "SPAMASSASSIN")


def required_check():
    workflow = WORKFLOW.read_text()
    job = workflow.split("  ci-ok:\n", 1)[1]
    block = job.split("        run: |\n", 1)[1]
    script = []
    for line in block.splitlines(keepends=True):
        if line.strip() and len(line) - len(line.lstrip()) <= 8:
            break
        script.append(line)
    return job, textwrap.dedent("".join(script))


def verdict(selected, results, *, changes="success", docker="success", scanners="success"):
    env = dict(os.environ)
    env.update(
        CHANGES_RESULT=changes,
        DOCKER_RESULT=docker,
        SCANNERS_RESULT=scanners,
        PARITY_SELECTED=selected[0],
        GO_SELECTED=selected[1],
        SCOPE_SELECTED=selected[2],
        RSPAMD_SELECTED=selected[3],
        SPAMASSASSIN_SELECTED=selected[4],
    )
    env.update(zip((f"{name}_RESULT" for name in OPTIONAL), results, strict=True))
    return subprocess.run(
        ["bash", "-e", "-c", required_check()[1]],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    ).returncode == 0


class RequiredCheck(unittest.TestCase):
    def test_wiring(self):
        job, script = required_check()
        self.assertIn("if: ${{ always() }}", job)
        self.assertIn(
            "needs: [changes, docker, parity-isolation, lint, scanners, rspamd, spamassassin]",
            job,
        )
        for name in (
            "changes", "docker", "parity-isolation", "lint", "scanners", "rspamd",
            "spamassassin",
        ):
            self.assertIn(f"needs.{name}.result", job)
        for name in ("parity", "go", "scope", "rspamd", "spamassassin"):
            self.assertIn(f"needs.changes.outputs.{name}", job)
        self.assertIn("require_selected", script)

    def test_selected_and_skipped_jobs(self):
        # Every selection combination succeeds only with its corresponding
        # success/skipped result; any other state must fail the stable check.
        states = ("success", "skipped", "failure", "cancelled", "")
        for bits in itertools.product(("true", "false"), repeat=5):
            expected = (
                bits[0] == "true",
                bits[1] == "true" or bits[2] == "true",
                bits[3] == "true",
                bits[4] == "true",
            )
            good = tuple("success" if value else "skipped" for value in expected)
            with self.subTest(selected=bits):
                self.assertTrue(verdict(bits, good))
                for index, state in itertools.product(range(4), states):
                    if state == good[index]:
                        continue
                    actual = list(good)
                    actual[index] = state
                    self.assertFalse(verdict(bits, actual), (index, state))

    def test_planner_and_required_gate_fail_closed(self):
        skipped = ("false",) * 5
        results = ("skipped",) * 4
        for job in ("changes", "docker", "scanners"):
            for state in ("failure", "cancelled", "skipped", ""):
                with self.subTest(job=job, state=state):
                    self.assertFalse(verdict(skipped, results, **{job: state}))
        for index in range(5):
            selected = list(skipped)
            selected[index] = ""
            self.assertFalse(verdict(selected, results))


if __name__ == "__main__":
    unittest.main()
