"""Contract: every `ensure gh CLI` workflow step retries apt boundedly."""

import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("nightly.yml", "release.yml")
STEP = "ensure gh CLI"
BASH = "/bin/bash"


def steps():
    """Yield (workflow, job, script) for every ensure-gh-CLI step."""
    for name in WORKFLOWS:
        doc = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
        for job, spec in doc["jobs"].items():
            for step in spec.get("steps", []):
                if step.get("name") == STEP:
                    yield name, job, step["run"]


def run_script(script, update=(0,), install=(0,), gh=False):
    """Run the step under fake sudo/apt-get/sleep; PATH holds only the stubs."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        bindir = tmp / "bin"
        bindir.mkdir()
        log = tmp / "calls.log"
        log.touch()

        def stub(name, body):
            path = bindir / name
            path.write_text("#!/bin/bash\n" + body + "\n")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

        def seq(name, codes):
            arms = "".join(f"{i}) rc={c};; " for i, c in enumerate(codes[:-1]))
            return (
                f'cnt="{tmp}/{name}.n"; n=0; [ -f "$cnt" ] && read -r n < "$cnt"; '
                f'echo $((n+1)) > "$cnt"; case $n in {arms}*) rc={codes[-1]};; esac; '
                "exit $rc"
            )

        stub("sudo", 'exec "$@"')
        stub("sleep", f'echo "sleep $1" >> "{log}"')
        stub(
            "apt-get",
            f'echo "apt-get $*" >> "{log}"\n'
            'for a in "$@"; do case "$a" in\n'
            f"  update) {seq('update', update)} ;;\n"
            f"  install) {seq('install', install)} ;;\n"
            "esac; done\nexit 0",
        )
        if gh:
            stub("gh", "exit 0")
        proc = subprocess.run(
            [BASH, "-e", "-c", script],
            env={"PATH": str(bindir)},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return proc, log.read_text().splitlines()


def count(calls, word):
    return len([c for c in calls if c.startswith("apt-get") and f" {word}" in c])


class EnsureGhCli(unittest.TestCase):
    def test_all_expected_steps_present(self):
        found = sorted((w, j) for w, j, _ in steps())
        # nightly runs on GitHub-hosted images, which ship gh.
        self.assertEqual(found, [("release.yml", "release")])

    def test_gh_present_skips_apt(self):
        for w, j, script in steps():
            with self.subTest(w=w, job=j):
                p, calls = run_script(script, update=(100,), gh=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(calls, [])

    def test_clean_install_runs_once_without_sleep(self):
        for w, j, script in steps():
            with self.subTest(w=w, job=j):
                p, calls = run_script(script)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(
                    (count(calls, "update"), count(calls, "install")), (1, 1)
                )
                self.assertFalse([c for c in calls if c.startswith("sleep")])

    def test_transient_failures_are_retried(self):
        for w, j, script in steps():
            with self.subTest(w=w, job=j, kind="update"):
                p, calls = run_script(script, update=(100, 100, 0))
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(count(calls, "update"), 3)
            with self.subTest(w=w, job=j, kind="install"):
                p, calls = run_script(script, install=(100, 0))
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(count(calls, "install"), 2)

    def test_persistent_failure_is_bounded_and_fails(self):
        for w, j, script in steps():
            with self.subTest(w=w, job=j):
                p, calls = run_script(script, update=(100,))
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(count(calls, "update"), 4)
                self.assertEqual(count(calls, "install"), 0)
                self.assertEqual(len([c for c in calls if c.startswith("sleep")]), 3)
                self.assertIn("giving up", p.stderr)

    def test_unretried_step_is_caught_negative_control(self):
        legacy = (
            "command -v gh >/dev/null || {\n"
            "  sudo apt-get update\n  sudo apt-get install -y gh\n}\n"
        )
        p, calls = run_script(legacy, update=(100, 0))
        self.assertNotEqual(p.returncode, 0)  # one blip fails the legacy step
        self.assertEqual(count(calls, "update"), 1)  # never retried
        # the shipped steps survive the same single blip
        for w, j, script in steps():
            with self.subTest(w=w, job=j):
                self.assertEqual(run_script(script, update=(100, 0))[0].returncode, 0)

    def test_shipped_steps_are_not_unbounded(self):
        for w, j, script in steps():
            with self.subTest(w=w, job=j):
                self.assertNotIn("while", script)
                self.assertIn("for attempt in", script)


if __name__ == "__main__":
    unittest.main()
