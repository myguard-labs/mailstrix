#!/usr/bin/env python3
"""Protect CI integration prerequisites without executing application code."""

import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
BAKE = ROOT / "docker/bake.ci.hcl"


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


def step_with(steps, marker):
    found = [step for step in steps if marker in step]
    assert len(found) == 1, f"expected one step containing {marker}"
    return found[0]


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
    assert re.search(
        r"(?m)^\s*docker build -f contrib/postfix/Dockerfile\.integration\s*\\\s*\n"
        r"\s*-t mailstrix-postfix-test contrib/postfix\s*$",
        consumer,
    ), "Postfix must use Engine build for the local strixd-test base"
    assert "docker buildx build" not in consumer
    assert "scope=postfix-integration" not in consumer
    assert (
        "FROM strixd-test AS binaries"
        in (ROOT / "contrib/postfix/Dockerfile.integration").read_text()
    )
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


def cache_runtime_contract(text):
    for name, build_marker in [
        ("docker", "--target test"),
        ("parity-isolation", "bash scripts/qualify-parity-isolation.sh"),
    ]:
        block = jobs(text)[name]
        marker = "uses: actions/github-script@"
        assert block.count(marker) == 1, "cache runtime must use an allowed action"
        assert block.index(marker) < block.index(build_marker)
        assert "core.setSecret(process.env.ACTIONS_RUNTIME_TOKEN)" in block
        assert "core.exportVariable(name, process.env[name])" in block
        assert 'throw new Error("BuildKit cache runtime is unavailable")' in block
        for variable in [
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_RESULTS_URL",
            "ACTIONS_CACHE_URL",
            "ACTIONS_CACHE_SERVICE_V2",
        ]:
            assert f'"{variable}"' in block, f"missing runtime export: {variable}"


def integration_cache_contract(text):
    docker = jobs(text)["docker"]
    assert "actions: write" in docker, "GHA cache export needs actions write"
    steps = re.split(r"(?m)^      - ", docker)
    date = step_with(steps, "name: Trivy DB cache date")
    cache = step_with(steps, "name: cache Trivy DB")
    scan = step_with(steps, "name: trivy image scan")
    assert steps.index(date) < steps.index(cache) < steps.index(scan)
    for step in (date, cache, scan):
        assert "if: needs.changes.outputs.image == 'true'" in step
    assert "date -u +%Y-%m-%d" in date
    assert "uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830" in cache
    assert "path: .trivy-cache" in cache
    image = re.search(r"aquasec/trivy:(\d+\.\d+\.\d+)", scan)
    assert image, "Trivy image must declare a numeric version"
    cache_prefix = f"trivy-{image.group(1)}-${{{{ runner.os }}}}"
    assert f"key: {cache_prefix}-${{{{ steps.trivy-date.outputs.day }}}}" in cache
    assert f"restore-keys: {cache_prefix}-" in cache
    assert '--user "$(id -u):$(id -g)"' in scan
    assert '--group-add "$(stat -c %g /var/run/docker.sock)"' in scan
    assert '-v "$PWD/.trivy-cache:/trivy-cache"' in scan
    assert "--cache-dir /trivy-cache" in scan
    for required in (
        "--severity HIGH,CRITICAL",
        "--exit-code 1",
        "--ignore-unfixed",
        "--timeout 5m",
        "strixd:ci",
    ):
        assert required in scan, f"missing Trivy gate: {required}"
    assert "postfix-integration" not in cache + scan


def bake_contract(bake):
    """Validate Bake's resolved targets instead of its HCL formatting."""
    parsed = subprocess.run(
        ["docker", "buildx", "bake", "-f", "-", "--print", "ci-images"],
        input=bake,
        text=True,
        capture_output=True,
        check=False,
    )
    assert parsed.returncode == 0, f"invalid bake definition: {parsed.stderr}"
    config = json.loads(parsed.stdout)
    assert config["group"]["ci-images"]["targets"] == ["rules-verifier", "final"]
    targets = config["target"]
    assert set(targets) == {"rules-verifier", "final"}
    common = {
        "context": ".",
        "dockerfile": "docker/Dockerfile",
        "cache-from": [{"type": "gha", "scope": "strixd-build"}],
        "output": [{"type": "docker"}],
    }
    for target in targets.values():
        for key, expected in common.items():
            assert target.get(key) == expected, f"bake {key} changed"
    rules = targets["rules-verifier"]
    final = targets["final"]
    assert rules["target"] == "rules-verifier"
    assert rules["tags"] == ["strixd-rules-verifier:ci"]
    assert "cache-to" not in rules
    assert final["target"] == "final"
    assert final["tags"] == ["strixd:ci"]
    assert final.get("args") == {"LOCAL_ONLY": "1"}
    assert final.get("cache-to") == [
        {"type": "gha", "mode": "max", "scope": "strixd-build"}
    ]


def image_bake_contract(workflow, bake):
    docker = jobs(workflow)["docker"]
    steps = re.split(r"(?m)^      - ", docker)
    build = step_with(steps, "name: build verifier and final images")
    verifier = step_with(steps, "name: smoke isolated rules verifier")
    trivy = step_with(steps, "name: trivy image scan")
    final_smoke = step_with(steps, "name: smoke matrix")
    assert steps.index(build) < steps.index(verifier) < steps.index(trivy)
    assert steps.index(trivy) < steps.index(final_smoke)
    assert docker.count("docker buildx bake") == 1
    assert "docker buildx bake -f docker/bake.ci.hcl" in build
    assert "RULES_CACHEBUST: >-" in build
    assert "rules-${{ hashFiles(" in build
    for path in (
        "docker/local-rules/**",
        "docker/fetch-rules.sh",
        "docker/compile-rules.sh",
        "docker/Dockerfile",
    ):
        assert f"'{path}'" in build
    assert "final.args.CACHEBUST=$RULES_CACHEBUST" in build
    assert "ci-images" in build
    assert "if: needs.changes.outputs.image == 'true'" in build
    assert "if: needs.changes.outputs.image == 'true'" in verifier
    for required in (
        "--read-only --network none",
        "strixd-rules-verifier:ci",
        "|| status=$?",
        'test "$status" -eq 2',
        "grep -F 'fetch manifest:' verifier-smoke.log",
    ):
        assert required in verifier, f"missing verifier smoke gate: {required}"
    assert "--exit-code 1" in trivy and "strixd:ci" in trivy
    assert "scripts/smoke.sh strixd:ci" in final_smoke

    bake_contract(bake)


class CIIntegrationTest(unittest.TestCase):
    def test_bake_tag_spacing_is_equivalent(self):
        bake = BAKE.read_text()
        wide = re.sub(r"(?m)^([ \t]*tags)[ \t]*=", r"\1     =", bake)
        compact = re.sub(r"(?m)^([ \t]*tags)[ \t]*=", r"\1 =", bake)
        self.assertNotEqual(wide, compact)
        image_bake_contract(WORKFLOW.read_text(), wide)
        image_bake_contract(WORKFLOW.read_text(), compact)

    def test_bake_comma_spacing_is_equivalent(self):
        bake = BAKE.read_text()
        compact = re.sub(
            r'"rules-verifier"[ \t]*,[ \t]*"final"', '"rules-verifier","final"', bake
        )
        spaced = re.sub(
            r'"rules-verifier"[ \t]*,[ \t]*"final"', '"rules-verifier", "final"', bake
        )
        self.assertNotEqual(compact, spaced)
        image_bake_contract(WORKFLOW.read_text(), compact)
        image_bake_contract(WORKFLOW.read_text(), spaced)

    def test_one_bake_loads_both_images_and_preserves_smoke_gates(self):
        image_bake_contract(WORKFLOW.read_text(), BAKE.read_text())

    def test_missing_image_or_smoke_gate_is_rejected(self):
        workflow = WORKFLOW.read_text()
        bake = BAKE.read_text()
        for pattern, replacement in [
            (
                r'(?m)^([ \t]*tags[ \t]*=[ \t]*)\["strixd-rules-verifier:ci"\][ \t]*$',
                r'\1["wrong:ci"]',
            ),
            (
                r'(?m)^([ \t]*tags[ \t]*=[ \t]*)\["strixd:ci"\][ \t]*$',
                r'\1["wrong:ci"]',
            ),
            (
                (
                    r'(?m)^([ \t]*targets[ \t]*=[ \t]*)\[[ \t]*"rules-verifier"'
                    r'[ \t]*,[ \t]*"final"[ \t]*\][ \t]*$'
                ),
                r'\1["final"]',
            ),
            (
                r'(?m)^[ \t]*args[ \t]*=[ \t]*\{[ \t]*LOCAL_ONLY[ \t]*=[ \t]*"1"[ \t]*\}[ \t]*\n?',
                "",
            ),
            (
                (
                    r'(?m)^[ \t]*cache-to[ \t]*=[ \t]*'
                    r'\["type=gha,mode=max,scope=strixd-build"\][ \t]*\n?'
                ),
                "",
            ),
        ]:
            with self.subTest(pattern=pattern):
                changed, count = re.subn(pattern, replacement, bake, count=1)
                self.assertEqual(count, 1)
                with self.assertRaises(AssertionError):
                    image_bake_contract(workflow, changed)
        with self.assertRaises(AssertionError):
            image_bake_contract(workflow, bake + '\ntarget "broken" {\n')
        for old, new in [
            ('test "$status" -eq 2', 'test "$status" -eq 0'),
            ("grep -F 'fetch manifest:' verifier-smoke.log", "true"),
            ("scripts/smoke.sh strixd:ci", "true"),
            ("--exit-code 1", "--exit-code 0"),
        ]:
            with self.subTest(old=old):
                changed = workflow.replace(old, new)
                self.assertNotEqual(changed, workflow)
                with self.assertRaises(AssertionError):
                    image_bake_contract(changed, bake)

    def test_trivy_cache_and_scan_keep_failure_gate(self):
        integration_cache_contract(WORKFLOW.read_text())

    def test_missing_or_misrouted_integration_cache_is_rejected(self):
        text = WORKFLOW.read_text()
        for old, new in [
            ("path: .trivy-cache", "path: .other-cache"),
            ('--user "$(id -u):$(id -g)"', ""),
            ('--group-add "$(stat -c %g /var/run/docker.sock)"', ""),
            ('-v "$PWD/.trivy-cache:/trivy-cache"', ""),
            ("--cache-dir /trivy-cache", ""),
            ("--exit-code 1", "--exit-code 0"),
            ("aquasec/trivy:0.62.1", "aquasec/trivy:0.63.0"),
        ]:
            with self.subTest(old=old):
                mutated = text.replace(old, new)
                self.assertNotEqual(mutated, text)
                with self.assertRaises(AssertionError):
                    integration_cache_contract(mutated)

    def test_cache_runtime_is_exposed_before_manual_builds(self):
        cache_runtime_contract(WORKFLOW.read_text())

    def test_missing_or_disallowed_cache_runtime_is_rejected(self):
        text = WORKFLOW.read_text()
        for old, new in [
            ("uses: actions/github-script@", "uses: unapproved/runtime@"),
            ('"ACTIONS_RUNTIME_TOKEN",', '"OTHER_RUNTIME_TOKEN",'),
            ("core.exportVariable(name, process.env[name])", "core.info(name)"),
            (
                'throw new Error("BuildKit cache runtime is unavailable")',
                'core.info("missing")',
            ),
        ]:
            with self.subTest(old=old):
                mutated = text.replace(old, new)
                self.assertNotEqual(mutated, text)
                with self.assertRaises(AssertionError):
                    cache_runtime_contract(mutated)

    def test_postfix_local_image_prerequisite(self):
        postfix_contract(WORKFLOW.read_text())

    def test_container_builder_postfix_is_rejected(self):
        text = WORKFLOW.read_text()
        mutated = text.replace(
            "docker build -f contrib/postfix/Dockerfile.integration",
            "docker buildx build -f contrib/postfix/Dockerfile.integration",
        )
        self.assertNotEqual(mutated, text)
        with self.assertRaisesRegex(AssertionError, "Engine build"):
            postfix_contract(mutated)

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
