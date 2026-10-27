"""Regression controls for the tracked contrib README link guard."""

import pathlib
import shutil
import subprocess
import unittest
from tempfile import mkdtemp

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUARD = ROOT / "packaging/deb/contrib_links_test.sh"


class ContribLinksGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        guard = self.root / "packaging/deb/contrib_links_test.sh"
        guard.parent.mkdir(parents=True)
        shutil.copy2(GUARD, guard)
        for path in (
            "README.md",
            "docker/.keep",
            ".github/.keep",
            "internal/.keep",
            "cmd/.keep",
            "third_party/.keep",
        ):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch()
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)

    def run_guard(self) -> subprocess.CompletedProcess[str]:
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        return subprocess.run(
            ["sh", "packaging/deb/contrib_links_test.sh"],
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def write_nested_readme(self, body: str) -> None:
        readme = self.root / "contrib/deploy/helm/mailstrix/README.md"
        readme.parent.mkdir(parents=True, exist_ok=True)
        readme.write_text(body, encoding="utf-8")

    def test_tracked_nested_readme_link_resolves(self) -> None:
        target = self.root / "contrib/deploy/prometheus/alerts.yml"
        target.parent.mkdir(parents=True)
        target.touch()
        self.write_nested_readme("[alerts](../../prometheus/alerts.yml)\n")

        result = self.run_guard()

        self.assertEqual(result.returncode, 0, result.stdout)

    def test_missing_target_in_tracked_nested_readme_fails(self) -> None:
        self.write_nested_readme("[missing](../../prometheus/missing.yml)\n")

        result = self.run_guard()

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("contrib/deploy/helm/mailstrix/README.md", result.stdout)
        self.assertIn("../../prometheus/missing.yml", result.stdout)

    def test_single_level_component_readme_is_checked(self) -> None:
        readme = self.root / "contrib/postfix/README.md"
        readme.parent.mkdir(parents=True)
        readme.write_text("[missing](../missing.md)\n", encoding="utf-8")

        result = self.run_guard()

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("contrib/postfix/README.md", result.stdout)

    def test_missing_git_checkout_fails_closed(self) -> None:
        self.write_nested_readme("[section](#install)\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        shutil.rmtree(self.root / ".git")

        result = subprocess.run(
            ["sh", "packaging/deb/contrib_links_test.sh"],
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("cannot enumerate tracked contrib README files", result.stdout)

    def test_external_and_anchor_links_are_excluded(self) -> None:
        self.write_nested_readme(
            "[web](https://example.invalid/file)\n"
            "[mail](mailto:security@example.invalid)\n"
            "[section](#install)\n"
        )

        result = self.run_guard()

        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
