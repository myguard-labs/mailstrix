"""Contracts for four logical CI groups folded into the stable required gate."""

import json
import os
import re
import subprocess
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
PLANNER = ROOT / "scripts/ci-plan.sh"
GROUPS = (
    "static-analysis",
    "go-correctness",
    "native-builds-artifacts",
    "contracts-integrations",
)
DIRECT_NEEDS = [
    "changes",
    "docker",
    "parity-isolation",
    "lint",
    "scanners",
    "publisher-concurrency",
    "publisher-ordering",
    "rspamd",
    "spamassassin",
    "compiler-inputs",
    "pr-binaries",
    "pr-marker-image",
]


def job_block(workflow, name):
    marker = f"  {name}:\n"
    if marker not in workflow:
        raise AssertionError(f"missing workflow job: {name}")
    tail = workflow.split(marker, 1)[1]
    return re.split(r"^  [a-zA-Z0-9_-]+:\n", tail, maxsplit=1, flags=re.MULTILINE)[
        0
    ]


def job_script(workflow, name):
    block = job_block(workflow, name)
    match = re.search(
        r"^        run: \|\n((?:(?:^          .*\n)|(?:^\s*$\n?))+)",
        block,
        re.MULTILINE,
    )
    if not match:
        raise AssertionError(f"missing run script: {name}")
    return textwrap.dedent(match.group(1))


def run_required_gate(workflow, env):
    return subprocess.run(
        ["bash", "-e", "-c", job_script(workflow, "ci-ok")],
        env=dict(os.environ, **env),
        check=False,
        capture_output=True,
        text=True,
    )


def manifest():
    source = PLANNER.read_text(encoding="utf-8")
    fragments = re.findall(
        r"^lane_manifest(?:\+)?='([^']*)'$", source, re.MULTILINE
    )
    if not fragments:
        raise AssertionError("planner has no lane manifest")
    return json.loads("".join(fragments))


def needs(workflow, name):
    block = job_block(workflow, name)
    multiline = re.search(
        r"^    needs:\n((?:      - [a-zA-Z0-9_-]+\n)+)", block, re.MULTILINE
    )
    if not multiline:
        raise AssertionError(f"missing needs list: {name}")
    return re.findall(r"^      - ([a-zA-Z0-9_-]+)$", multiline.group(1), re.MULTILINE)


class FourLaneContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    @staticmethod
    def docs_only_env():
        return {
            "CHANGES_RESULT": "success",
            "SCANNERS_RESULT": "success",
            "PUBLISHER_CONCURRENCY_SELECTED": "false",
            "PUBLISHER_CONCURRENCY_RESULT": "skipped",
            "PUBLISHER_ORDERING_SELECTED": "false",
            "PUBLISHER_ORDERING_RESULT": "skipped",
            "DOCKER_RESULT": "success",
            "GO_SELECTED": "false",
            "SCOPE_SELECTED": "false",
            "LINT_RESULT": "skipped",
            "EVENT_NAME": "workflow_call",
            "NATIVE_SELECTED": "false",
            "NATIVE_RESULT": "skipped",
            "RELEASE_IMAGE_SELECTED": "false",
            "PR_BINARIES_RESULT": "skipped",
            "PR_MARKER_IMAGE_RESULT": "skipped",
            "PARITY_SELECTED": "false",
            "PARITY_RESULT": "skipped",
            "RSPAMD_SELECTED": "false",
            "RSPAMD_RESULT": "skipped",
            "SPAMASSASSIN_SELECTED": "false",
            "SPAMASSASSIN_RESULT": "skipped",
        }

    def assert_direct_join_contract(self, workflow):
        self.assertEqual(needs(workflow, "ci-ok"), DIRECT_NEEDS)

    def test_manifest_has_four_groups_and_unique_job_owners(self):
        lane_manifest = manifest()
        self.assertEqual(lane_manifest["version"], 1)
        self.assertEqual(lane_manifest["logical_groups"], 4)
        self.assertEqual(lane_manifest["grouping_runner_start_delta"], 0)
        self.assertIs(lane_manifest["speed_claim"], False)
        self.assertEqual([lane["id"] for lane in lane_manifest["lanes"]], list(GROUPS))
        jobs = [job for lane in lane_manifest["lanes"] for job in lane["jobs"]]
        self.assertEqual(len(jobs), 37)
        self.assertEqual(len(jobs), len(set(jobs)))
        self.assertTrue(all(lane["mode"] for lane in lane_manifest["lanes"]))
        self.assertEqual(
            {item["lane"] for item in lane_manifest["step_overrides"]},
            {"static-analysis", "go-correctness"},
        )
        self.assertEqual(len(lane_manifest["check_aliases"]), 1)
        self.assertEqual(
            len(lane_manifest["check_aliases"][0]["baseline"]),
            2,
        )
        changes = job_block(self.workflow, "changes")
        self.assertIn("lane_manifest: ${{ steps.plan.outputs.lane_manifest }}", changes)

    def test_existing_gate_folds_groups_without_new_runner_jobs(self):
        self.assert_direct_join_contract(self.workflow)
        self.assertFalse(any(f"  lane-{group}:\n" in self.workflow for group in GROUPS))
        gate = job_block(self.workflow, "ci-ok")
        self.assertIn("runs-on: [self-hosted, builder02, docker]", gate)
        self.assertIn("timeout-minutes: 5", gate)
        script = job_script(self.workflow, "ci-ok")
        for group in GROUPS:
            self.assertIn(f"join_{group.replace('-', '_')}", script)

    def test_docs_only_safe_skips(self):
        result = run_required_gate(self.workflow, self.docs_only_env())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_selected_failure_cancel_timeout_and_unexpected_skip_fail(self):
        cases = (
            ("SCANNERS_RESULT", {}),
            (
                "PUBLISHER_CONCURRENCY_RESULT",
                {
                    "PUBLISHER_CONCURRENCY_SELECTED": "true",
                    "PUBLISHER_CONCURRENCY_RESULT": "success",
                },
            ),
            (
                "PUBLISHER_ORDERING_RESULT",
                {
                    "PUBLISHER_ORDERING_SELECTED": "true",
                    "PUBLISHER_ORDERING_RESULT": "success",
                },
            ),
            ("DOCKER_RESULT", {}),
            ("LINT_RESULT", {"GO_SELECTED": "true", "LINT_RESULT": "success"}),
            (
                "NATIVE_RESULT",
                {"NATIVE_SELECTED": "true", "NATIVE_RESULT": "success"},
            ),
            (
                "PR_BINARIES_RESULT",
                {
                    "EVENT_NAME": "pull_request",
                    "RELEASE_IMAGE_SELECTED": "true",
                    "PR_BINARIES_RESULT": "success",
                    "PR_MARKER_IMAGE_RESULT": "success",
                },
            ),
            (
                "PR_MARKER_IMAGE_RESULT",
                {
                    "EVENT_NAME": "pull_request",
                    "RELEASE_IMAGE_SELECTED": "true",
                    "PR_BINARIES_RESULT": "success",
                    "PR_MARKER_IMAGE_RESULT": "success",
                },
            ),
            (
                "PARITY_RESULT",
                {"PARITY_SELECTED": "true", "PARITY_RESULT": "success"},
            ),
            (
                "RSPAMD_RESULT",
                {"RSPAMD_SELECTED": "true", "RSPAMD_RESULT": "success"},
            ),
            (
                "SPAMASSASSIN_RESULT",
                {"SPAMASSASSIN_SELECTED": "true", "SPAMASSASSIN_RESULT": "success"},
            ),
        )
        for result_name, selected in cases:
            env = self.docs_only_env()
            env.update(selected)
            self.assertEqual(run_required_gate(self.workflow, env).returncode, 0)
            for state in ("failure", "cancelled", "timed_out", "skipped", "unknown", ""):
                with self.subTest(result=result_name, state=state):
                    broken = dict(env, **{result_name: state})
                    self.assertNotEqual(
                        run_required_gate(self.workflow, broken).returncode, 0
                    )

    def test_unselected_jobs_accept_only_explicit_skip(self):
        for result_name in (
            "LINT_RESULT",
            "PUBLISHER_CONCURRENCY_RESULT",
            "PUBLISHER_ORDERING_RESULT",
            "NATIVE_RESULT",
            "PR_BINARIES_RESULT",
            "PR_MARKER_IMAGE_RESULT",
            "PARITY_RESULT",
            "RSPAMD_RESULT",
            "SPAMASSASSIN_RESULT",
        ):
            for state in ("success", "failure", "cancelled", "timed_out", "unknown", ""):
                with self.subTest(result=result_name, state=state):
                    env = self.docs_only_env()
                    env[result_name] = state
                    self.assertNotEqual(
                        run_required_gate(self.workflow, env).returncode, 0
                    )

    def test_refusals_report_group_dependency_selection_and_result(self):
        cases = (
            (
                {"CHANGES_RESULT": "failure"},
                ("group=plan", "dependency=changes", "result=failure"),
            ),
            (
                {"SCANNERS_RESULT": "failure"},
                ("group=static-analysis", "dependency=scanners", "result=failure"),
            ),
            (
                {"DOCKER_RESULT": "cancelled"},
                ("group=static-analysis", "dependency=docker", "result=cancelled"),
            ),
            (
                {"GO_SELECTED": "true", "LINT_RESULT": "failure"},
                (
                    "group=go-correctness",
                    "dependency=lint",
                    "selected=true",
                    "result=failure",
                ),
            ),
            (
                {"GO_SELECTED": "invalid"},
                ("group=go-correctness", "go_selected=invalid", "scope_selected=false"),
            ),
            (
                {"SCOPE_SELECTED": ""},
                ("group=go-correctness", "go_selected=false", "scope_selected="),
            ),
            (
                {"NATIVE_SELECTED": "true", "NATIVE_RESULT": "failure"},
                (
                    "group=native-builds-artifacts",
                    "dependency=compiler-inputs",
                    "selected=true",
                    "result=failure",
                ),
            ),
            (
                {"NATIVE_SELECTED": "invalid"},
                (
                    "group=native-builds-artifacts",
                    "dependency=compiler-inputs",
                    "selected=invalid",
                    "result=skipped",
                ),
            ),
            (
                {"RELEASE_IMAGE_SELECTED": "invalid"},
                ("group=native-builds-artifacts", "release_image_selected=invalid"),
            ),
            (
                {"EVENT_NAME": "invalid"},
                ("group=native-builds-artifacts", "event=invalid"),
            ),
            (
                {
                    "EVENT_NAME": "pull_request",
                    "RELEASE_IMAGE_SELECTED": "true",
                    "PR_BINARIES_RESULT": "failure",
                },
                (
                    "group=native-builds-artifacts",
                    "dependency=pr-binaries",
                    "selected=true",
                    "result=failure",
                ),
            ),
            (
                {
                    "EVENT_NAME": "pull_request",
                    "RELEASE_IMAGE_SELECTED": "true",
                    "PR_BINARIES_RESULT": "success",
                    "PR_MARKER_IMAGE_RESULT": "failure",
                },
                (
                    "group=native-builds-artifacts",
                    "dependency=pr-marker-image",
                    "selected=true",
                    "result=failure",
                ),
            ),
            (
                {"PARITY_SELECTED": "true", "PARITY_RESULT": "failure"},
                (
                    "group=contracts-integrations",
                    "dependency=parity-isolation",
                    "selected=true",
                    "result=failure",
                ),
            ),
            (
                {"RSPAMD_SELECTED": "true", "RSPAMD_RESULT": "failure"},
                (
                    "group=contracts-integrations",
                    "dependency=rspamd",
                    "selected=true",
                    "result=failure",
                ),
            ),
            (
                {"SPAMASSASSIN_SELECTED": "true", "SPAMASSASSIN_RESULT": "failure"},
                (
                    "group=contracts-integrations",
                    "dependency=spamassassin",
                    "selected=true",
                    "result=failure",
                ),
            ),
            (
                {"LINT_RESULT": "success"},
                (
                    "group=go-correctness",
                    "dependency=lint",
                    "selected=false",
                    "result=success",
                ),
            ),
        )
        for update, expected in cases:
            with self.subTest(update=update):
                env = dict(self.docs_only_env(), **update)
                result = run_required_gate(self.workflow, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ci-ok:", result.stderr)
                self.assertIn(f"event={env['EVENT_NAME']}", result.stderr)
                for value in expected:
                    self.assertIn(value, result.stderr)
        success = run_required_gate(self.workflow, self.docs_only_env())
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(success.stderr, "")

    def test_each_group_reports_its_failed_docker_dependency(self):
        prefix, calls = self.workflow.rsplit("          join_static_analysis\n", 1)
        self.assertIn("join_contracts_integrations", calls)
        for group in ("static_analysis", "go_correctness", "contracts_integrations"):
            with self.subTest(group=group):
                workflow = prefix + f"          join_{group}\n"
                env = dict(self.docs_only_env(), DOCKER_RESULT="failure")
                result = run_required_gate(workflow, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"group={group.replace('_', '-')}", result.stderr)
                self.assertIn("dependency=docker result=failure", result.stderr)

    def test_valid_event_and_go_scope_combinations_stay_quiet(self):
        for event in (
            "pull_request",
            "push",
            "schedule",
            "workflow_dispatch",
            "workflow_call",
        ):
            for go in ("true", "false"):
                for scope in ("true", "false"):
                    with self.subTest(event=event, go=go, scope=scope):
                        env = dict(
                            self.docs_only_env(),
                            EVENT_NAME=event,
                            GO_SELECTED=go,
                            SCOPE_SELECTED=scope,
                            LINT_RESULT="success"
                            if "true" in (go, scope)
                            else "skipped",
                        )
                        result = run_required_gate(self.workflow, env)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr, "")

    def test_native_architecture_and_security_boundaries(self):
        self.assertIn("arches: '[\"amd64\",\"arm64\"]'", job_block(self.workflow, "pr-binaries"))
        marker = job_block(self.workflow, "pr-marker-image")
        self.assertIn("arch: [amd64, arm64]", marker)
        self.assertIn("fail-fast: false", marker)
        prefix = self.workflow.split("jobs:\n", 1)[0]
        self.assertIn("permissions:\n  contents: read", prefix)
        self.assertNotIn("pull_request_target", prefix)

    def test_removed_join_negative_control(self):
        self.assert_direct_join_contract(self.workflow)
        mutated = self.workflow.replace("      - docker\n", "", 1)
        with self.assertRaises(AssertionError):
            self.assert_direct_join_contract(mutated)


if __name__ == "__main__":
    unittest.main()
