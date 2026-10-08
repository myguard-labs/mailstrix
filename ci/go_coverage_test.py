"""Exercise ci/go_coverage.sh against tiny synthetic cover profiles."""

import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ci" / "go_coverage.sh"


def profile(covered, total):
    """Profile of `total` one-statement functions, `covered` of them hit."""
    lines = ["mode: atomic"]
    for index in range(total):
        count = 1 if index < covered else 0
        lines.append(f"example.com/m/p/f.go:{index + 2}.11,{index + 2}.14 1 {count}")
    return "\n".join(lines) + "\n"


def fixture_module(root, total=4):
    """Source the profile points at; `go tool cover -func` resolves it."""
    (root / "go.mod").write_text("module example.com/m\n\ngo 1.21\n")
    (root / "p").mkdir()
    body = "".join(f"func F{i}() {{ }}\n" for i in range(total))
    (root / "p" / "f.go").write_text("package p\n" + body)


class GoCoverageTests(unittest.TestCase):
    def run_script(self, content, floor=None):
        with tempfile.TemporaryDirectory() as directory:
            fixture_module(pathlib.Path(directory))
            path = pathlib.Path(directory) / "cover.out"
            if content is not None:
                path.write_text(content)
            args = ["bash", str(SCRIPT), str(path)]
            if floor is not None:
                args.append(floor)
            return subprocess.run(
                args, capture_output=True, text=True, cwd=directory, check=False
            )

    def test_above_floor_passes(self):
        result = self.run_script(profile(3, 4), "50.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("75.0%", result.stdout)

    def test_exactly_at_floor_passes(self):
        result = self.run_script(profile(1, 2), "50.0")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_below_floor_fails(self):
        result = self.run_script(profile(1, 4), "50.0")
        self.assertEqual(result.returncode, 1)
        self.assertIn("below floor", result.stderr)

    def test_just_below_floor_fails(self):
        result = self.run_script(profile(1, 3), "33.4")
        self.assertEqual(result.returncode, 1)

    def test_missing_profile_fails_cleanly(self):
        result = self.run_script(None, "1.0")
        self.assertEqual(result.returncode, 2)
        self.assertIn("missing or empty", result.stderr)

    def test_empty_profile_fails_cleanly(self):
        result = self.run_script("", "1.0")
        self.assertEqual(result.returncode, 2)

    def test_malformed_profile_fails_cleanly(self):
        result = self.run_script("not a profile\n", "1.0")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unreadable", result.stderr)

    def test_invalid_floor_fails_cleanly(self):
        result = self.run_script(profile(1, 1), "abc")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid floor", result.stderr)

    def test_no_argument_fails_cleanly(self):
        result = subprocess.run(
            ["bash", str(SCRIPT)], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 2)

    def test_help(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--help"], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage", result.stdout)


if __name__ == "__main__":
    unittest.main()
