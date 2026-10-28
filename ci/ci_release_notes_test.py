"""Exercise scripts/release-notes.py and its release.yml wiring."""

import importlib.util
import io
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/release-notes.py"
WORKFLOW = ROOT / ".github/workflows/release.yml"

spec = importlib.util.spec_from_file_location("release_notes", SCRIPT)
assert spec is not None and spec.loader is not None
rn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rn)

CHANGELOG = """# Changelog

## [Unreleased]

Unreleased text.

## [1.3.0] - 2026-11-01

### Security

- Fixed a thing (#1).

More text.

## [v1.2.1]

Prefixed body.

## [1.2.0-rc.1]

RC body.

[Unreleased]: https://example.invalid/compare
[1.3.0]: https://example.invalid/1.3.0
"""


class ExtractTest(unittest.TestCase):
    def test_section_with_date_stops_at_next_heading(self):
        self.assertEqual(
            rn.extract(CHANGELOG, "v1.3.0"),
            "### Security\n\n- Fixed a thing (#1).\n\nMore text.\n",
        )

    def test_v_prefixed_heading_without_date(self):
        self.assertEqual(rn.extract(CHANGELOG, "v1.2.1"), "Prefixed body.\n")

    def test_prerelease_tag(self):
        self.assertEqual(rn.extract(CHANGELOG, "v1.2.0-rc.1"), "RC body.\n")

    def test_last_section_stops_at_link_reference_footer(self):
        text = "## [2.0.0]\n\nBody.\n\n[2.0.0]: https://example.invalid\n"
        self.assertEqual(rn.extract(text, "v2.0.0"), "Body.\n")

    def test_last_section_stops_at_eof(self):
        self.assertEqual(rn.extract("## [2.0.0]\n\nBody.", "v2.0.0"), "Body.\n")

    def test_unreleased_never_selected(self):
        for tag in ("vUnreleased", "v0.0.0"):
            with self.assertRaises(rn.NotesError):
                rn.extract(CHANGELOG, tag)
        only = "## [Unreleased]\n\nText.\n"
        with self.assertRaises(rn.NotesError):
            rn.extract(only, "v1.0.0")

    def test_missing_section(self):
        with self.assertRaisesRegex(rn.NotesError, "no section"):
            rn.extract(CHANGELOG, "v9.9.9")

    def test_version_is_not_prefix_matched(self):
        with self.assertRaises(rn.NotesError):
            rn.extract(CHANGELOG, "v1.3")
        with self.assertRaises(rn.NotesError):
            rn.extract("## [1.3.01]\n\nx\n", "v1.3.0")

    def test_malformed_tags(self):
        for tag in ("", "1.3.0", "v1.3", "v1.3.0.4", "vx.y.z", "v01.3.0", "v1.3.0 "):
            with self.subTest(tag=tag), self.assertRaisesRegex(
                rn.NotesError, "malformed tag"
            ):
                rn.extract(CHANGELOG, tag)

    def test_empty_section(self):
        for text in ("## [1.0.0]\n\n## [0.9.0]\n\nx\n", "## [1.0.0]\n   \n"):
            with self.assertRaisesRegex(rn.NotesError, "empty"):
                rn.extract(text, "v1.0.0")

    def test_duplicate_heading(self):
        text = "## [1.0.0]\n\na\n\n## [v1.0.0] - 2026-01-01\n\nb\n"
        with self.assertRaisesRegex(rn.NotesError, "2 sections"):
            rn.extract(text, "v1.0.0")


class CliTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.log = self.dir / "CHANGELOG.md"
        self.log.write_text(CHANGELOG, encoding="utf-8")
        self.out = self.dir / "notes.md"

    def run_cli(self, tag, changelog=None):
        return subprocess.run(
            [
                sys.executable, "-B", str(SCRIPT), "--tag", tag,
                "--changelog", str(changelog or self.log),
                "--notes-file", str(self.out),
            ],
            capture_output=True, text=True, check=False,
        )

    def test_success_writes_exact_notes(self):
        res = self.run_cli("v1.3.0")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(
            self.out.read_text(encoding="utf-8"),
            "### Security\n\n- Fixed a thing (#1).\n\nMore text.\n",
        )

    def test_failures_exit_nonzero_and_write_nothing(self):
        for tag in ("v9.9.9", "bogus", "vUnreleased"):
            with self.subTest(tag=tag):
                res = self.run_cli(tag)
                self.assertEqual(res.returncode, 1)
                self.assertIn("release-notes:", res.stderr)
                self.assertFalse(self.out.exists())

    def test_missing_changelog_file(self):
        res = self.run_cli("v1.3.0", self.dir / "absent.md")
        self.assertEqual(res.returncode, 1)
        self.assertFalse(self.out.exists())

    def test_undecodable_changelog(self):
        bad = self.dir / "bad.md"
        bad.write_bytes(b"\xff\xfe\x00bad")
        res = self.run_cli("v1.3.0", bad)
        self.assertEqual(res.returncode, 1)
        self.assertFalse(self.out.exists())

    def test_main_in_process(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = rn.main(
                ["--tag", "v0.0.1", "--changelog", str(self.log),
                 "--notes-file", str(self.out)]
            )
        self.assertEqual(code, 1)
        self.assertIn("no section", buf.getvalue())
        self.assertEqual(
            rn.main(["--tag", "v1.2.1", "--changelog", str(self.log),
                     "--notes-file", str(self.out)]),
            0,
        )

    def test_real_changelog_unreleased_is_not_releasable(self):
        # The repo CHANGELOG must never serve [Unreleased] as notes.
        res = self.run_cli("v0.0.0", ROOT / "CHANGELOG.md")
        self.assertEqual(res.returncode, 1)


class WorkflowWiringTest(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_no_generated_notes(self):
        self.assertNotIn("--generate-notes", self.text)

    def test_notes_job_gates_everything(self):
        self.assertRegex(self.text, r"(?m)^  notes:\n")
        self.assertRegex(self.text, r"(?m)^  gate:\n    needs: notes\n")
        self.assertRegex(self.text, r"needs: \[notes, binaries,")
        job = self.text.split("\n  notes:\n", 1)[1].split("\n  # Re-run", 1)[0]
        self.assertIn("scripts/release-notes.py", job)
        self.assertNotIn("contents: write", job)

    def test_script_runs_before_any_gh_release_call(self):
        step = self.text.split("- name: create release", 1)[1]
        script = step.index("scripts/release-notes.py")
        for call in ("gh release view", "gh release upload",
                     "gh release edit", "gh release create"):
            self.assertLess(script, step.index(call), call)
        self.assertRegex(step, r"(?m)^\s*set -euo pipefail$")

    def test_both_paths_use_notes_file(self):
        step = self.text.split("- name: create release", 1)[1]
        self.assertRegex(
            step,
            r'gh release edit "\$\{GITHUB_REF_NAME\}" --notes-file "\$\{notes\}"',
        )
        create = step.split("gh release create", 1)[1]
        self.assertIn('--notes-file "${notes}"', create)
        edit = step.index("gh release edit")
        upload = step.index("gh release upload")
        self.assertLess(edit, upload)
        self.assertEqual(len(re.findall(r"--notes-file", step)), 3)


if __name__ == "__main__":
    unittest.main()
