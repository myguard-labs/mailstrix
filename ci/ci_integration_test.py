#!/usr/bin/env python3
"""Protect CI integration prerequisites without executing application code."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def jobs(text):
    """Read fixed two-space job blocks; reject absent or ambiguous definitions."""
    matches = list(re.finditer(r"(?m)^  ([a-zA-Z0-9_-]+):\s*$", text))
    result = {}
    for index, match in enumerate(matches):
        name = match.group(1)
        if name in result:
            raise AssertionError(f"duplicate job: {name}")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[name] = text[match.end() : end]
    return result


def postfix_contract(text):
    blocks = jobs(text)
    assert "postfix" not in blocks, (
        "Postfix cannot consume a local image in a fresh job"
    )
    docker = blocks["docker"]
    steps = re.split(r"(?m)^      - ", docker)
    producers = [
        index
        for index, step in enumerate(steps)
        if "--target test" in step and "-t strixd-test" in step
    ]
    consumers = [
        index
        for index, step in enumerate(steps)
        if "contrib/postfix/Dockerfile.integration" in step
    ]
    assert len(producers) == len(consumers) == 1, (
        "Postfix requires exactly one local image producer and consumer"
    )
    assert producers[0] < consumers[0], "Postfix must follow its test-image producer"
    producer = steps[producers[0]]
    condition = re.search(r"(?m)^        if:\s*(.+)$", producer)
    assert condition, "test-image producer must declare its impact condition"
    normalized = condition.group(1).replace("${{", "").replace("}}", "").strip()
    assert normalized == (
        "needs.changes.outputs.go == 'true' || needs.changes.outputs.postfix == 'true'"
    ), "Postfix-only changes must still build their local binary image"
    consumer = steps[consumers[0]]
    assert "if: needs.changes.outputs.postfix == 'true'" in consumer
    assert "docker run" in consumer and "--network none" in consumer


def spamassassin_contract(text):
    block = jobs(text)["spamassassin"]
    assert "sh -ec '" in block, "SpamAssassin setup and checks must fail fast"
    sources = re.findall(r"install\s+-m644\s+(contrib/spamassassin/\S+)\s+", block)
    expected = {
        "contrib/spamassassin/Mailstrix.pm",
        "contrib/spamassassin/mailstrix.pre",
        "contrib/spamassassin/mailstrix.cf",
    }
    assert set(sources) == expected, (
        "SpamAssassin must install the tracked plugin/config names"
    )
    for source in sources:
        assert (ROOT / source).is_file(), f"missing installed source: {source}"
    pre = (ROOT / "contrib/spamassassin/mailstrix.pre").read_text()
    assert re.search(
        r"(?m)^loadplugin\s+Mail::SpamAssassin::Plugin::Mailstrix\s+Mailstrix\.pm\s*$",
        pre,
    ), "installed pre config must load the installed plugin"
    assert re.search(r"(?m)^\s*perl .* -c .*Mailstrix\.pm\s*$", block)
    assert "prove -v" in block and "spamassassin --lint" in block


class CIIntegrationTest(unittest.TestCase):
    def test_postfix_local_image_prerequisite(self):
        postfix_contract(WORKFLOW.read_text())

    def test_missing_postfix_producer_is_rejected(self):
        text = WORKFLOW.read_text()
        mutated = text.replace("--target test", "--target final")
        self.assertNotEqual(mutated, text)
        with self.assertRaisesRegex(AssertionError, "local image producer"):
            postfix_contract(mutated)

    def test_spamassassin_tracked_config_and_fail_fast(self):
        spamassassin_contract(WORKFLOW.read_text())

    def test_stale_spamassassin_config_is_rejected(self):
        text = WORKFLOW.read_text()
        mutated = text.replace(
            "contrib/spamassassin/mailstrix.pre", "contrib/spamassassin/strixd.pre"
        )
        self.assertNotEqual(mutated, text)
        with self.assertRaisesRegex(AssertionError, "tracked plugin/config names"):
            spamassassin_contract(mutated)

    def test_nonfatal_spamassassin_setup_is_rejected(self):
        text = WORKFLOW.read_text()
        mutated = text.replace("sh -ec '", "sh -c '")
        self.assertNotEqual(mutated, text)
        with self.assertRaisesRegex(AssertionError, "fail fast"):
            spamassassin_contract(mutated)


if __name__ == "__main__":
    unittest.main()
