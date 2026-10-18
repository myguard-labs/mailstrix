"""Behavior of scripts/ci-preflight.sh in a throwaway git repo (fake go)."""

import importlib.util
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]


class Preflight(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name) / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        for name in ("ci-preflight.sh", "ci-impact.py"):
            shutil.copy(ROOT / "scripts" / name, self.repo / "scripts" / name)
        self.bin = Path(tmp.name) / "bin"
        self.bin.mkdir()
        self.trace = Path(tmp.name) / "trace"
        self.fake_go(0)
        self.git("init", "-q", "-b", "main")
        self.write("ci/status_log_test.go", "package ci\n")
        self.write("ci/old_unmapped_test.go", "package ci\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def fake_go(self, rc):
        path = self.bin / "go"
        path.write_text(f'#!/bin/bash\necho "go $*" >> "{self.trace}"\nexit {rc}\n')
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def git(self, *args):
        return subprocess.run(
            [*GIT, *args], cwd=self.repo, capture_output=True, text=True, check=True
        )

    def write(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def preflight(self, *args):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        proc = subprocess.run(
            ["bash", "scripts/ci-preflight.sh", *args],
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        trace = self.trace.read_text() if self.trace.exists() else ""
        return proc, trace

    def commit(self, message="change"):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def test_mapped_input_passes_and_reaches_testscope(self):
        self.write("ci/status_log_test.go", "package ci // edit\n")
        self.commit()
        proc, trace = self.preflight(self.base)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "go run ./tools/testscope --changed -- ci/status_log_test.go", trace
        )

    def test_unmapped_new_ci_input_fails_before_go(self):
        self.write("ci/brand_new_test.go", "package ci\n")
        self.commit()
        proc, trace = self.preflight(self.base)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unmapped changed path: ci/brand_new_test.go", proc.stderr)
        self.assertEqual(trace, "")

    def test_removal_of_mapped_input_passes(self):
        self.git("rm", "-q", "ci/status_log_test.go")
        self.commit()
        proc, trace = self.preflight(self.base)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("ci/status_log_test.go", trace)

    def test_removal_of_unmapped_input_stays_fail_closed(self):
        self.git("rm", "-q", "ci/old_unmapped_test.go")
        self.commit()
        proc, _ = self.preflight(self.base)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unmapped changed path: ci/old_unmapped_test.go", proc.stderr)

    def test_one_unmapped_path_among_mapped_ones_fails(self):
        self.write("ci/status_log_test.go", "package ci // edit\n")
        self.write("ci/another_new_test.go", "package ci\n")
        self.commit()
        proc, _ = self.preflight(self.base)
        self.assertNotEqual(proc.returncode, 0)

    def test_default_base_is_merge_base_with_origin_main(self):
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        self.write("ci/brand_new_test.go", "package ci\n")
        self.commit()
        proc, _ = self.preflight()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("brand_new_test.go", proc.stderr)

    def test_scope_selector_failure_propagates(self):
        self.write("ci/status_log_test.go", "package ci // edit\n")
        self.commit()
        self.fake_go(42)
        proc, _ = self.preflight(self.base)
        self.assertNotEqual(proc.returncode, 0)

    def test_malformed_base_fails(self):
        proc, _ = self.preflight("not-a-revision")
        self.assertNotEqual(proc.returncode, 0)

    def test_shipped_repo_maps_its_own_ci_inputs(self):
        # Every tracked ci/ input must be known to the planner (no silent gaps).
        spec = importlib.util.spec_from_file_location(
            "impact", ROOT / "scripts/ci-impact.py"
        )
        impact = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(impact)
        listed = subprocess.run(
            ["git", "ls-files", "-z", "ci"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout.decode()
        unmapped = []
        for path in filter(None, listed.split("\0")):
            try:
                impact.plan([path])
            except ValueError:
                unmapped.append(path)
        self.assertEqual(unmapped, [])


if __name__ == "__main__":
    unittest.main()
