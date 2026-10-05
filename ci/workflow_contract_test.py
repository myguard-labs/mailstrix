"""Exercise the required CI check against the shipped workflow script."""

import itertools
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
OPTIONAL = ("PARITY", "LINT", "RSPAMD", "SPAMASSASSIN")


def workflow_step(name):
    workflow = WORKFLOW.read_text()
    step = workflow.split(f"      - name: {name}\n", 1)[1].split("      - name: ", 1)[0]
    script = step.split("        run: |\n", 1)[1]
    return step, textwrap.dedent(script)


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
    def test_shellcheck_discovers_tracked_scripts_and_reports_failures(self):
        step, script = workflow_step("shellcheck (all tracked shell scripts)")
        self.assertIn("needs.changes.outputs.shell == 'true'", step)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in (
                "packaging/deb/postinstall-milter.sh",
                "packaging/deb/preremove-milter.sh",
                "ci/example_test.sh",
                "contrib/sieve/strix-scan-wrapper",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\nexit 0\n")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                "shift 5\n"
                "for file do\n"
                "  printf '%s\\n' \"$file\" >> \"$CALLS\"\n"
                "  test -f \"$file\" || exit 3\n"
                "done\n"
                'test "${FAIL_LINT:-0}" = 0\n'
            )
            docker.chmod(0o755)
            calls = root / "calls"
            env = dict(
                os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}", CALLS=str(calls)
            )

            def run(**extra):
                return subprocess.run(
                    ["bash", "-e", "-c", script],
                    cwd=root,
                    env=dict(env, **extra),
                    capture_output=True,
                    text=True,
                    check=False,
                )

            self.assertEqual(run().returncode, 0)
            self.assertEqual(
                set(calls.read_text().splitlines()),
                {
                    "ci/example_test.sh",
                    "contrib/sieve/strix-scan-wrapper",
                    "packaging/deb/postinstall-milter.sh",
                    "packaging/deb/preremove-milter.sh",
                },
            )
            self.assertNotEqual(
                run(FAIL_LINT="1").returncode, 0, "a lint failure must fail the step"
            )
            (root / "ci/example_test.sh").unlink()
            self.assertNotEqual(
                run().returncode, 0, "a missing tracked test must fail the step"
            )

    def test_milter_script_changes_select_behavior_contract(self):
        workflow = WORKFLOW.read_text()
        step = workflow.split("      - name: deb maintainer-script behaviour", 1)[
            1
        ].split("      - name: ", 1)[0]
        self.assertIn("needs.changes.outputs.maintscript == 'true'", step)
        command = step.split("        run: ", 1)[1].strip()
        self.assertEqual(command, "sh packaging/deb/maintscript_test.sh")
        with tempfile.TemporaryDirectory() as temp:
            fake_sh = Path(temp) / "sh"
            fake_sh.write_text("#!/bin/sh\nexit 7\n")
            fake_sh.chmod(0o755)
            result = subprocess.run(
                ["bash", "-e", "-c", command],
                env=dict(os.environ, PATH=f"{temp}:{os.environ['PATH']}"),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 7, "a failing contract must fail CI")

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
