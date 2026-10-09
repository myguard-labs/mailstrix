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


def mentions_secret(text):
    """Whether ``text`` names the signing secret, in any letter case.

    GitHub matches secret names case-insensitively, so
    ``secrets.mailstrix_rules_signing_key`` resolves to the same value as the
    uppercase spelling. A case-sensitive ``SECRET in text`` search would let a
    lowercase reference slip past the pull-request exclusion checks.
    """
    return SECRET.casefold() in text.casefold()


# Every valid GitHub spelling of the signing-key secret expression. GitHub
# accepts the dotted and the bracket property form, tolerates arbitrary
# whitespace inside ``${{ }}``, and matches context names case-insensitively,
# so a narrow literal search for "${{ secrets.MAILSTRIX_RULES_SIGNING_KEY }}"
# would miss a workflow that leaks the key under any other spelling.
SECRET_EXPRESSION = re.compile(
    r"\$\{\{\s*secrets\s*"
    r"(?:\.\s*" + SECRET + r"\b"
    r"|\[\s*(?P<quote>['\"])" + SECRET + r"(?P=quote)\s*\])"
    r"\s*\}\}",
    re.IGNORECASE,
)


def run_bodies(document):
    """Every ``run:`` scalar in a workflow document, at any nesting depth.

    Read from the PARSED document rather than matching line prefixes: a
    ``run: |`` block's own lines do not start with ``run:``, so a prefix
    heuristic accepts the very thing this guard exists to forbid --
    ``go run ./cmd/rulessign ... "${{ secrets.<key> }}"`` indented inside a
    block scalar. Walking the document reaches ``run`` wherever it is legal:
    a job step, a composite action's ``steps``, or any nested mapping.
    """
    found = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "run" and isinstance(value, str):
                    found.append(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    return found


def argv_leaks(document):
    """``run:`` bodies that interpolate the signing-key secret into a command.

    Returns the offending lines, so a failure names them instead of dumping
    the workflow. An ``env:`` mapping value is the sanctioned route and is
    deliberately NOT reported: only a ``run`` body puts the key in argv.
    """
    leaks = []
    for body in run_bodies(document):
        if not SECRET_EXPRESSION.search(body):
            continue
        lines = [
            line.strip()
            for line in body.splitlines()
            if SECRET_EXPRESSION.search(line)
        ]
        # A ``${{ ... }}`` expression may itself be split across lines; fall
        # back to the collapsed body so such a leak is still reported.
        leaks.extend(lines or [" ".join(body.split())[:160]])
    return leaks


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
                    if mentions_secret(line)
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
                        mentions_secret(text), f"{name} exposes {SECRET}"
                    )

    def test_run_bodies_are_discovered(self):
        """Guard the guard: the ``run:`` walker must find real shell steps.

        Without this, a broken walker would make the argv assertion below
        pass vacuously over an empty list of run bodies.
        """
        bodies = [
            body
            for _name, (_text, doc) in self.found.items()
            for body in run_bodies(doc)
        ]
        self.assertTrue(bodies, "no run: bodies were discovered in any workflow")

    def test_signing_key_is_read_from_the_environment_only(self):
        """Any workflow that does use the secret must not put it in argv."""
        for name, (_text, doc) in sorted(self.found.items()):
            with self.subTest(workflow=name):
                self.assertEqual(
                    argv_leaks(doc),
                    [],
                    f"{name} passes {SECRET} on a command line; the signing "
                    f"key may only reach a step through an env: mapping",
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


class ArgvLeakTest(unittest.TestCase):
    """The argv guard must refuse every spelling that reaches a command line.

    The earlier version of this check tested ``line.strip().startswith("run:")``
    or ``" rulessign" in line``, which ACCEPTED
    ``go run ./cmd/rulessign -manifest m.json "${{ secrets.<key> }}"`` indented
    inside a ``run: |`` block: the line does not start with ``run:`` and
    ``./cmd/rulessign`` has no space before ``rulessign``. Each case below is a
    synthetic fixture; none of them edits a real workflow.
    """

    def leaks(self, body):
        return argv_leaks(yaml.safe_load(body))

    def workflow(self, command):
        """A minimal workflow whose single step runs ``command``."""
        return (
            "on: push\n"
            "jobs:\n"
            "  publish:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          set -euo pipefail\n"
            f"          {command}\n"
        )

    def test_refuses_the_exact_block_scalar_bypass(self):
        """The literal line the old prefix heuristic accepted."""
        command = (
            'go run ./cmd/rulessign -manifest m.json '
            '"${{ secrets.MAILSTRIX_RULES_SIGNING_KEY }}"'
        )
        self.assertEqual(
            self.leaks(self.workflow(command)),
            [command],
            "the block-scalar argv bypass must be refused",
        )

    def test_refuses_every_expression_spelling(self):
        for name, expression in {
            "dotted": "${{ secrets.MAILSTRIX_RULES_SIGNING_KEY }}",
            "no spaces": "${{secrets.MAILSTRIX_RULES_SIGNING_KEY}}",
            "wide spaces": "${{   secrets.MAILSTRIX_RULES_SIGNING_KEY   }}",
            "single-quoted bracket": (
                "${{ secrets['MAILSTRIX_RULES_SIGNING_KEY'] }}"
            ),
            "double-quoted bracket": (
                '${{ secrets["MAILSTRIX_RULES_SIGNING_KEY"] }}'
            ),
            "bracket no spaces": (
                "${{secrets['MAILSTRIX_RULES_SIGNING_KEY']}}"
            ),
            "lowercase context": "${{ secrets.mailstrix_rules_signing_key }}",
        }.items():
            with self.subTest(spelling=name):
                command = f'rulessign -key "{expression}"'
                self.assertEqual(
                    self.leaks(self.workflow(command)),
                    [command],
                    f"the {name} spelling escaped the argv guard",
                )

    def test_refuses_an_expression_split_across_lines(self):
        body = (
            "on: push\n"
            "jobs:\n"
            "  publish:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          rulessign -key \"${{\n"
            "            secrets.MAILSTRIX_RULES_SIGNING_KEY }}\"\n"
        )
        self.assertNotEqual(
            self.leaks(body), [], "a multi-line expression must still be caught"
        )

    def test_refuses_a_leak_in_a_composite_or_nested_step(self):
        for name, body in {
            "composite action": (
                "runs:\n"
                "  using: composite\n"
                "  steps:\n"
                "    - run: rulessign "
                '"${{ secrets.MAILSTRIX_RULES_SIGNING_KEY }}"\n'
                "      shell: bash\n"
            ),
            "matrix job step": (
                "on: push\n"
                "jobs:\n"
                "  a:\n"
                "    strategy:\n"
                "      matrix:\n"
                "        os: [ubuntu-latest]\n"
                "    steps:\n"
                "      - run: echo "
                '"${{ secrets.MAILSTRIX_RULES_SIGNING_KEY }}"\n'
            ),
        }.items():
            with self.subTest(shape=name):
                self.assertNotEqual(
                    self.leaks(body), [], f"a leak in a {name} escaped the guard"
                )

    def test_allows_the_secret_in_an_env_mapping(self):
        """The sanctioned route: the key reaches the tool through env:."""
        for name, body in {
            "step env": (
                "on: push\n"
                "jobs:\n"
                "  publish:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: rulessign -manifest m.json -out m.json.sig\n"
                "        env:\n"
                "          MAILSTRIX_RULES_SIGNING_KEY: "
                "${{ secrets.MAILSTRIX_RULES_SIGNING_KEY }}\n"
            ),
            "job env": (
                "on: push\n"
                "jobs:\n"
                "  publish:\n"
                "    runs-on: ubuntu-latest\n"
                "    env:\n"
                "      MAILSTRIX_RULES_SIGNING_KEY: "
                "${{ secrets.MAILSTRIX_RULES_SIGNING_KEY }}\n"
                "    steps:\n"
                "      - run: rulessign -manifest m.json -out m.json.sig\n"
            ),
            "bracket form in env": (
                "on: push\n"
                "jobs:\n"
                "  publish:\n"
                "    runs-on: ubuntu-latest\n"
                "    env:\n"
                "      MAILSTRIX_RULES_SIGNING_KEY: "
                "${{ secrets['MAILSTRIX_RULES_SIGNING_KEY'] }}\n"
                "    steps:\n"
                "      - run: rulessign -manifest m.json -out m.json.sig\n"
            ),
        }.items():
            with self.subTest(route=name):
                self.assertEqual(
                    self.leaks(body), [], f"the {name} route must stay legal"
                )

    def test_allows_unrelated_secrets_and_similar_names(self):
        for name, expression in {
            "other secret": "${{ secrets.GITHUB_TOKEN }}",
            "longer name": "${{ secrets.MAILSTRIX_RULES_SIGNING_KEY_OLD }}",
            "not a secret context": "${{ env.MAILSTRIX_RULES_SIGNING_KEY }}",
            "plain shell variable": "$MAILSTRIX_RULES_SIGNING_KEY",
        }.items():
            with self.subTest(expression=name):
                self.assertEqual(
                    self.leaks(self.workflow(f'rulessign -key "{expression}"')),
                    [],
                    f"{name} must not be reported as a signing-key leak",
                )

    def test_run_bodies_walks_every_nesting_shape(self):
        body = (
            "on: push\n"
            "jobs:\n"
            "  a:\n"
            "    steps:\n"
            "      - run: one\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: two\n"
            "  b:\n"
            "    steps:\n"
            "      - run: three\n"
        )
        self.assertEqual(
            sorted(run_bodies(yaml.safe_load(body))), ["one", "three", "two"]
        )

    def test_run_bodies_ignores_non_scalar_and_absent_run(self):
        for name, body in {
            "run is a mapping": "jobs:\n  a:\n    steps:\n      - run:\n          x: y\n",
            "run is a list": "jobs:\n  a:\n    steps:\n      - run:\n          - x\n",
            "no run anywhere": "on: push\njobs:\n  a:\n    uses: ./.github/workflows/ci.yml\n",
            "empty document": "{}\n",
        }.items():
            with self.subTest(shape=name):
                self.assertEqual(
                    run_bodies(yaml.safe_load(body)), [], f"{name} was wrongly collected"
                )


class MentionsSecretTest(unittest.TestCase):
    """The pull-request exclusion checks must be case-insensitive.

    GitHub resolves ``secrets.mailstrix_rules_signing_key`` to the same value
    as the uppercase spelling, so a case-sensitive substring search would let a
    pull_request_target workflow request the signing key undetected.
    """

    def test_matches_every_letter_case(self):
        for name, text in {
            "upper": "env:\n  K: ${{ secrets.MAILSTRIX_RULES_SIGNING_KEY }}\n",
            "lower": "env:\n  K: ${{ secrets.mailstrix_rules_signing_key }}\n",
            "mixed": "env:\n  K: ${{ secrets.Mailstrix_Rules_Signing_Key }}\n",
            "bracket lower": "env:\n  K: ${{ secrets['mailstrix_rules_signing_key'] }}\n",
        }.items():
            with self.subTest(case=name):
                self.assertTrue(
                    mentions_secret(text), f"the {name} spelling was missed"
                )

    def test_ignores_unrelated_text(self):
        for name, text in {
            "other secret": "env:\n  K: ${{ secrets.GITHUB_TOKEN }}\n",
            "empty": "",
            "partial name": "env:\n  K: ${{ secrets.MAILSTRIX_RULES }}\n",
        }.items():
            with self.subTest(case=name):
                self.assertFalse(
                    mentions_secret(text), f"{name} was wrongly matched"
                )


if __name__ == "__main__":
    unittest.main()
