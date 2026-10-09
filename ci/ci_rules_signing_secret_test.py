"""Keep the rules-signing secret out of every pull-request-reachable CI job.

MAILSTRIX_RULES_SIGNING_KEY signs the rules manifest that strixd installs and
executes. A fork PR that could read it would be able to sign its own bundle, so
the secret must never be referenced from a workflow reachable by
``pull_request`` or ``pull_request_target`` -- directly, or indirectly through a
``workflow_call`` that such a workflow invokes.
"""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github/workflows"
SECRET = "MAILSTRIX_RULES_SIGNING_KEY"
PR_EVENTS = ("pull_request", "pull_request_target")


def workflows():
    """Return {filename: (raw text, parsed document)} for every workflow."""
    found = {}
    for path in sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(
        WORKFLOW_DIR.glob("*.yaml")
    ):
        text = path.read_text(encoding="utf-8")
        found[path.name] = (text, yaml.safe_load(text))
    return found


def triggers(document):
    """Normalise a workflow's ``on:`` block to a set of event names.

    PyYAML resolves the bare key ``on`` to the boolean True (YAML 1.1), so both
    spellings are accepted.
    """
    block = document.get("on", document.get(True))
    if block is None:
        return set()
    if isinstance(block, str):
        return {block}
    if isinstance(block, list):
        return set(block)
    if isinstance(block, dict):
        return set(block)
    raise AssertionError(f"unsupported on: block {block!r}")


def called_workflows(document):
    """Local workflow files invoked through a job-level ``uses:``.

    Read from the PARSED document, not the raw text: YAML lets ``uses`` be
    quoted, folded, or written with an anchor, and a text regex silently misses
    those, which would make this guard under-report PR-reachable workflows.
    """
    called = set()
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return called
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        uses = job.get("uses")
        if not isinstance(uses, str):
            continue
        match = re.fullmatch(
            r"\./\.github/workflows/([^@\s]+\.ya?ml)(?:@\S+)?", uses.strip()
        )
        if match:
            called.add(match.group(1))
    return called


def pr_reachable(found):
    """Names of workflows reachable from a pull-request event, transitively."""
    reachable = {
        name
        for name, (_text, doc) in found.items()
        if triggers(doc) & set(PR_EVENTS)
    }
    # Follow reusable-workflow calls until the set stops growing.
    while True:
        grown = set(reachable)
        for name in reachable:
            grown |= called_workflows(found[name][1]) & set(found)
        if grown == reachable:
            return reachable
        reachable = grown


class RulesSigningSecretTest(unittest.TestCase):
    def setUp(self):
        self.found = workflows()
        self.assertTrue(self.found, "no workflows were discovered")

    def test_pull_request_workflows_are_detected(self):
        """Guard the guard: the detector must actually find PR workflows.

        Without this, a broken ``on:`` parser would make the real assertion
        below vacuously pass over an empty set.
        """
        reachable = pr_reachable(self.found)
        self.assertIn("ci.yml", reachable, "ci.yml is the PR gate and must be detected")

    def test_secret_absent_from_pull_request_reachable_workflows(self):
        for name in sorted(pr_reachable(self.found)):
            with self.subTest(workflow=name):
                # assertTrue on a boolean, not assertNotIn on the file body:
                # a failure must name the offending lines, not dump the
                # whole workflow.
                hits = [
                    f"{number}: {line.strip()}"
                    for number, line in enumerate(
                        self.found[name][0].splitlines(), start=1
                    )
                    if SECRET in line
                ]
                self.assertEqual(
                    hits,
                    [],
                    f"{name} is reachable from a pull_request event and must "
                    f"not reference {SECRET}",
                )

    def test_secret_never_reaches_pull_request_target(self):
        """pull_request_target runs with repository secrets available."""
        for name, (text, doc) in sorted(self.found.items()):
            if "pull_request_target" in triggers(doc):
                with self.subTest(workflow=name):
                    self.assertFalse(
                        SECRET in text, f"{name} exposes {SECRET}"
                    )

    def test_signing_key_is_read_from_the_environment_only(self):
        """Any workflow that does use the secret must not put it in argv."""
        for name, (text, _doc) in sorted(self.found.items()):
            if SECRET not in text:
                continue
            with self.subTest(workflow=name):
                for line in text.splitlines():
                    if f"secrets.{SECRET}" not in line:
                        continue
                    stripped = line.strip()
                    self.assertFalse(
                        stripped.startswith("run:") or " rulessign" in stripped,
                        f"{name} passes {SECRET} on a command line: {stripped}",
                    )

    def test_publisher_signs_and_reads_the_key_from_the_environment(self):
        """The real publisher must sign, and must not take the key via argv."""
        script = (ROOT / "docker/generate-rules.sh").read_text(encoding="utf-8")
        self.assertIn(
            "cmd/rulessign",
            script,
            "generate-rules.sh must sign the manifest it publishes",
        )
        self.assertIn(
            "compiled.yac.manifest.json.sig",
            script.replace("${MANIFEST}.sig", "compiled.yac.manifest.json.sig"),
            "generate-rules.sh must publish the detached signature",
        )
        for line in script.splitlines():
            if "rulessign" in line:
                self.assertNotIn(
                    f"${SECRET}",
                    line,
                    f"the signing key must not be interpolated into argv: {line.strip()}",
                )



class CalledWorkflowsTest(unittest.TestCase):
    """Reusable-workflow detection must survive every valid YAML spelling.

    If this under-reports, a workflow called by the PR gate escapes the secret
    check, which is the whole point of the guard.
    """

    def parse(self, text):
        return called_workflows(yaml.safe_load(text))

    def test_detects_plain_quoted_and_folded_uses(self):
        for name, body in {
            "plain": "jobs:\n  a:\n    uses: ./.github/workflows/ci.yml\n",
            "double quoted": 'jobs:\n  a:\n    uses: "./.github/workflows/ci.yml"\n',
            "single quoted": "jobs:\n  a:\n    uses: './.github/workflows/ci.yml'\n",
            "extra spaces": "jobs:\n  a:\n    uses:    ./.github/workflows/ci.yml   \n",
            "folded scalar": "jobs:\n  a:\n    uses: >-\n      ./.github/workflows/ci.yml\n",
            "with ref": "jobs:\n  a:\n    uses: ./.github/workflows/ci.yml@main\n",
        }.items():
            with self.subTest(form=name):
                self.assertEqual(
                    self.parse(body), {"ci.yml"}, f"{name} spelling was missed"
                )

    def test_ignores_remote_and_malformed_uses(self):
        for name, body in {
            "remote action": "jobs:\n  a:\n    uses: actions/checkout@v4\n",
            "remote workflow": "jobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@v1\n",
            "not a workflow": "jobs:\n  a:\n    uses: ./.github/workflows/notes.txt\n",
            "no jobs": "on: push\n",
            "jobs is a list": "jobs:\n  - a\n",
            "job is a string": "jobs:\n  a: nope\n",
            "uses is a mapping": "jobs:\n  a:\n    uses:\n      x: y\n",
        }.items():
            with self.subTest(form=name):
                self.assertEqual(self.parse(body), set(), f"{name} was wrongly matched")

    def test_detects_every_called_workflow(self):
        body = (
            "jobs:\n"
            "  a:\n    uses: ./.github/workflows/ci.yml\n"
            "  b:\n    uses: ./.github/workflows/build-binaries.yaml\n"
            "  c:\n    runs-on: ubuntu-latest\n"
        )
        self.assertEqual(self.parse(body), {"ci.yml", "build-binaries.yaml"})


if __name__ == "__main__":
    unittest.main()
