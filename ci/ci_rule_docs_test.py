"""Keep rule documentation aligned with the shipped rule defaults."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def keyword_contract(readme, rule):
    condition = re.search(r"filesize < 16MB and (\d+) of them", rule)
    if condition is None:
        raise AssertionError("keyword rule condition is missing")
    threshold = int(condition.group(1))
    if threshold != 5:
        raise AssertionError(f"keyword rule threshold is {threshold}, want 5")

    expected = (
        f"fires on ≥{threshold} distinct",
        "one keyword\n  is noise, five together",
        f'The "{threshold} of them"\n      threshold',
        "reaches for five exec/persist/network/evasion/obfuscation",
    )
    for phrase in expected:
        if phrase not in readme + rule:
            raise AssertionError(f"keyword documentation is missing {phrase!r}")

    stale = re.search(
        r"≥6 distinct|six together|\"6 of them\"|half a dozen", readme + rule
    )
    if stale:
        raise AssertionError(f"stale six-keyword explanation remains: {stale.group(0)}")


def forge_default_contract(readme, fetch_script, dockerfiles):
    expected_readme = (
        "default tier `full` (`YARAFORGE_SET=core`/`extended` select smaller "
        "optional tiers)"
    )
    if expected_readme not in readme:
        raise AssertionError("README does not describe full as the YARA-Forge default")
    expected_header = (
        "YARA-Forge package: full (default), or the smaller optional\n"
        "#                    core and extended tiers"
    )
    if expected_header not in fetch_script:
        raise AssertionError("fetch-rules header does not describe the full default")
    if 'YARAFORGE_SET="${YARAFORGE_SET:-full}"' not in fetch_script:
        raise AssertionError("fetch-rules runtime default is not full")
    for name, dockerfile in dockerfiles.items():
        if "ARG YARAFORGE_SET=full" not in dockerfile:
            raise AssertionError(f"{name} does not default YARAFORGE_SET to full")


class RuleDocumentationContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.fetch_script = (ROOT / "docker/fetch-rules.sh").read_text(encoding="utf-8")
        cls.rule = (ROOT / "docker/local-rules/maldoc_suspicious.yara").read_text(
            encoding="utf-8"
        )
        cls.dockerfiles = {
            path.name: path.read_text(encoding="utf-8")
            for path in (ROOT / "docker/Dockerfile", ROOT / "docker/Dockerfile.release")
        }

    def test_keyword_explanation_matches_five_keyword_condition(self):
        keyword_contract(self.readme, self.rule)

    def test_keyword_contract_rejects_stale_and_removed_explanations(self):
        stale = self.readme.replace("≥5 distinct", "≥6 distinct", 1)
        self.assertNotEqual(stale, self.readme)
        with self.assertRaisesRegex(AssertionError, "missing|stale"):
            keyword_contract(stale, self.rule)

        removed = self.rule.replace(
            'The "5 of them"\n      threshold', "The threshold", 1
        )
        self.assertNotEqual(removed, self.rule)
        with self.assertRaisesRegex(AssertionError, "missing"):
            keyword_contract(self.readme, removed)

    def test_forge_full_default_matches_shell_and_dockerfiles(self):
        forge_default_contract(self.readme, self.fetch_script, self.dockerfiles)

    def test_forge_contract_rejects_stale_and_removed_defaults(self):
        stale = self.readme.replace("default tier `full`", "default tier `core`", 1)
        self.assertNotEqual(stale, self.readme)
        with self.assertRaisesRegex(AssertionError, "README"):
            forge_default_contract(stale, self.fetch_script, self.dockerfiles)

        removed = self.fetch_script.replace(
            'YARAFORGE_SET="${YARAFORGE_SET:-full}"',
            'YARAFORGE_SET="${YARAFORGE_SET}"',
            1,
        )
        self.assertNotEqual(removed, self.fetch_script)
        with self.assertRaisesRegex(AssertionError, "runtime default"):
            forge_default_contract(self.readme, removed, self.dockerfiles)


if __name__ == "__main__":
    unittest.main()
