"""Change-plan contracts, including real Git deletion/rename and failure controls."""

import importlib.util
import io
import json
import os
import pathlib
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("impact", ROOT / "scripts/ci-impact.py")
assert SPEC is not None and SPEC.loader is not None
impact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(impact)


class ImpactTests(unittest.TestCase):
    def test_batch_contract_selects_its_planner_job(self):
        selected = impact.plan(["ci/ci_batch_test.py"])
        self.assertTrue(selected["scope"])
        self.assertFalse(selected["go"])
        self.assertFalse(selected["image"])
        self.assertEqual(selected["changed_files"], "--changed -- ")

    def test_parity_batch_runner_selects_both_owning_controls(self):
        selected = impact.plan(["scripts/ci-test-batch.py"])
        self.assertTrue(selected["scope"])
        self.assertTrue(selected["qualification"])
        self.assertTrue(all(selected[key] for key in impact.RULES))

    def test_selection_table_for_actual_pr_lanes(self):
        cases = (
            (["README.md"], {"readme"}, {"go", "native", "image", "docker"}),
            (["internal/extract/pdf.go"], {"go", "image", "docker"}, {"native"}),
            (
                ["docker/compiler-input-capture.h"],
                {"go", "native", "image", "docker"},
                {"rspamd"},
            ),
            ([".github/workflows/ci.yml"], set(impact.RULES) | {"docker"}, set()),
            (["scripts/ci-go-checks.sh"], set(impact.RULES) | {"docker"}, set()),
        )
        for paths, selected, skipped in cases:
            with self.subTest(paths=paths):
                result = impact.plan(paths)
                self.assertTrue(all(result[key] for key in selected), result)
                self.assertTrue(all(not result[key] for key in skipped), result)

    def test_pr_release_image_selection(self):
        for path in (
            "cmd/strixd/main.go",
            "docker/Dockerfile",
            "docker/Dockerfile.release",
            "docker/release-marker-toolchain.sh",
            "ci/release_marker_image_test.sh",
            ".github/workflows/build-binaries.yml",
            ".github/workflows/nightly.yml",
            ".github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                self.assertTrue(impact.plan([path])["release_image"])
        for path in (
            "README.md",
            "internal/extract/pdf_test.go",
            ".github/workflows/maintenance.yml",
            "ci/ci_gh_install_test.py",
        ):
            with self.subTest(path=path):
                self.assertFalse(impact.plan([path])["release_image"])
        self.assertTrue(impact.plan([], full=True)["release_image"])

    def test_marker_runtime_fixture_real_consumers(self):
        for path in (
            "ci/testdata/marker-runtime.zip",
            "ci/marker_runtime_fixture.py",
            "ci/prepare_marker_runtime.py",
            "ci/ci_marker_runtime_fixture_test.py",
        ):
            result = impact.plan([path])
            self.assertTrue(result["go"])
            self.assertIn(
                "internal/mailstrix/marker_artifact_test.go", result["changed_files"]
            )
            self.assertIn("ci/marker_runtime_test.go", result["changed_files"])
        self.assertFalse(impact.plan(["README.md"])["go"])

    def test_marker_closure_exact_consumers(self):
        result = impact.plan(["ci/ci_marker_closure_test.py"])
        for key in ("native", "python", "scope", "go"):
            self.assertTrue(result[key], key)
        self.assertIn(
            "internal/mailstrix/marker_closure_test.go", result["changed_files"]
        )
        self.assertFalse(result["image"])
        for path in ("ci/unmapped_test.py", "ci/marker_closure_unmapped.py"):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([path])
        self.assertFalse(impact.plan(["README.md"])["go"])

    def test_memory_alert_fixture_selects_prometheus_only(self):
        result = impact.plan(["ci/mailstrix_memory_alerts_test.yml"])
        self.assertTrue(result["prometheus"])
        for key in ["go", "image", "parity", "postfix"]:
            self.assertFalse(result[key], key)
        self.assertFalse(impact.plan(["README.md"])["prometheus"])

    def test_native_compiler_proof_exact_scope(self):
        paths = (
            "docker/Dockerfile",
            "docker/compiler-input-capture.h",
            "docker/patch-compiler-input-capture.py",
            "docker/capture-compiler-inputs.py",
            "docker/export-compiler-inputs.py",
            "docker/build-marker-artifact.py",
            "docker/compile-rules.sh",
            "ci/compiler-input-check.sh",
            "ci/compiler_input_retention_test.py",
            "ci/compiler_input_export_test.py",
            "ci/marker_artifact_test.py",
            "ci/compiler-input/io-faults.c",
            "ci/compiler-input/seek.c",
            ".github/workflows/ci.yml",
            "ci/workflow_contract_test.py",
            "scripts/ci-impact.py",
        )
        for path in paths:
            self.assertTrue(impact.plan([path])["native"], path)
        for path in (
            "README.md",
            "internal/extract/pdf.go",
            "tools/parity/compare.py",
            "contrib/rspamd/README.md",
        ):
            self.assertFalse(impact.plan([path])["native"], path)
        self.assertTrue(impact.plan([], full=True)["native"])
        for path in ("docker/unmapped.py", "ci/compiler-input/unmapped.c"):
            with self.assertRaisesRegex(ValueError, "unmapped changed path"):
                impact.plan(["docker/Dockerfile", path])

    def test_export_exact_consumers(self):
        helper = impact.plan(["docker/export-compiler-inputs.py"])
        for key in ("native", "image", "python", "docker", "generate"):
            self.assertTrue(helper[key], key)
        test = impact.plan(["ci/compiler_input_export_test.py"])
        for key in ("native", "scope", "python"):
            self.assertTrue(test[key], key)
        self.assertFalse(helper["go"])
        self.assertFalse(test["image"])
        self.assertFalse(test["generate"])
        self.assertFalse(impact.plan(["README.md"])["generate"])
        for path in ("docker/export-unmapped.py", "ci/compiler_input_unmapped_test.py"):
            with self.assertRaisesRegex(ValueError, "unmapped changed path"):
                impact.plan([path])
        self.assertFalse(impact.plan(["README.md"])["native"])

    def test_exact_compiler_input_consumers_and_unmapped_controls(self):
        native = [
            "docker/compiler-input-capture.h",
            "docker/patch-compiler-input-capture.py",
        ]
        for path in native:
            result = impact.plan([path])
            for key in ("go", "image", "parity", "docker"):
                self.assertTrue(result[key], (path, key))
            self.assertIn(path, result["changed_files"])
        retained = impact.plan(["docker/capture-compiler-inputs.py"])
        self.assertTrue(retained["image"])
        self.assertTrue(retained["docker"])
        self.assertFalse(retained["go"])
        for path in (
            "ci/compiler-input-check.sh",
            "ci/compiler_input_retention_test.py",
            "ci/compiler_input_export_test.py",
            "ci/marker_artifact_test.py",
            "ci/compiler-input/io-faults.c",
            "ci/compiler-input/seek.c",
        ):
            self.assertTrue(impact.plan([path])["scope"], path)
        for path in (
            "docker/unmapped.py",
            "docker/unmapped.h",
            "ci/compiler-input/unmapped.c",
        ):
            with self.assertRaisesRegex(ValueError, "unmapped changed path"):
                impact.plan([path])
            with self.assertRaisesRegex(ValueError, "unmapped changed path"):
                impact.plan(["docker/Dockerfile", path])

    def test_docs_and_empty_skip_expensive_domains(self):
        for paths in [[], ["README.md"], ["tools/parity/README.md"]]:
            with self.subTest(paths=paths):
                result = impact.plan(paths)
                for key in [
                    "go",
                    "image",
                    "parity",
                    "postfix",
                    "rspamd",
                    "spamassassin",
                ]:
                    self.assertFalse(result[key], key)
                self.assertTrue(result["changed_files"].startswith("--changed --"))
        self.assertTrue(impact.plan(["README.md"])["readme"])

    def test_named_consumers_and_unrelated_controls(self):
        for path, selected, unrelated in [
            (
                "ci/rules_polling_defaults_test.sh",
                ["envkeys", "shell"],
                ["go", "image"],
            ),
            ("ci/rules_polling_test.sh", ["image", "shell", "smoke"], ["go", "parity"]),
            ("docker/docker-compose.yml", ["envkeys"], ["go", "image"]),
            (
                "packaging/deb/stop_timeout_test.sh",
                ["envkeys", "shell"],
                ["go", "image"],
            ),
            ("ci/rules_polling_config_test.go", ["go"], ["image", "parity"]),
            ("ci/rules_update_run_test.go", ["go"], ["image", "parity"]),
            ("ci/config_auto_derive_test.go", ["go"], ["image", "parity"]),
            ("ci/clamd_cache_test.go", ["go"], ["image", "parity", "postfix"]),
            ("ci/cache_distribution/main.go", ["go"], ["image", "parity", "postfix"]),
            (
                "ci/docker_context_selector_test.sh",
                ["dockerignore", "shell"],
                ["go", "image", "parity", "postfix"],
            ),
            ("ci/go_coverage_test.py", ["go"], ["image", "parity", "postfix"]),
            ("ci/go_coverage.sh", ["go", "shell"], ["image", "parity", "postfix"]),
            ("ci/streamdedupkey_test.go", ["go"], ["image", "parity", "postfix"]),
            ("ci/status_log_test.go", ["go"], ["image", "parity", "postfix"]),
            (
                "ci/release_marker_loader_text_test.go",
                ["go"],
                ["image", "parity", "postfix"],
            ),
            (
                "docker/release-marker-toolchain.sh",
                ["dockerfiles", "go", "shell"],
                ["parity", "postfix"],
            ),
            (
                "ci/icap_admission_ordering_test.go",
                ["go"],
                ["image", "parity", "postfix"],
            ),
            (
                "ci/testdata/icap_admission_ordering_test.go",
                ["go"],
                ["image", "parity", "postfix"],
            ),
            (
                "ci/generate_rules_count_test.sh",
                ["generate", "shell"],
                ["go", "image", "parity", "postfix"],
            ),
            (
                "ci/generate_rules_cron_signer_test.sh",
                ["generate", "shell", "scope"],
                ["go", "image", "parity", "postfix"],
            ),
            ("internal/verdict/verdict.go", ["go", "image", "postfix"], ["rspamd"]),
            ("internal/extract/pdf_test.go", ["go"], ["image", "parity", "postfix"]),
            (
                "internal/extract/testdata/document.doc",
                ["go"],
                ["image", "parity", "postfix"],
            ),
            ("internal/mailstrix/CAPE.md", ["go"], ["image", "parity", "postfix"]),
            (
                "docker/fetch-rules.sh",
                ["go", "image", "ruleargs"],
                ["rspamd", "postfix"],
            ),
            (
                "docker/compile-rules.sh",
                ["envkeys", "image", "native"],
                ["go", "rspamd", "postfix"],
            ),
            ("docker/local-rules/mail.yar", ["go", "image", "parity"], ["rspamd"]),
            ("docker/bake.ci.hcl", ["image", "docker"], ["go", "postfix"]),
            ("contrib/clamd/test_clients.py", ["go"], ["rspamd", "image"]),
            (
                "contrib/rspamd/mailstrix.lua",
                ["rspamd"],
                ["go", "image", "spamassassin"],
            ),
            (
                "contrib/spamassassin/Mailstrix.pm",
                ["spamassassin"],
                ["rspamd", "image"],
            ),
            (
                "contrib/postfix/Dockerfile.integration",
                ["postfix", "dockerfiles", "docker"],
                ["image", "go"],
            ),
            (
                "cmd/strix-milter/main.go",
                ["go", "image", "postfix", "docker"],
                ["rspamd"],
            ),
            (
                "go.sum",
                ["go", "image", "parity", "dependencies", "postfix"],
                ["rspamd"],
            ),
            ("ci/parity_cache_test.py", ["qualification", "scope"], ["image", "go"]),
            ("ci/vet_wiring_test.py", ["scope"], ["image", "go"]),
            ("ci/ci_release_tag_test.py", ["dockerfiles"], ["image", "go", "scope"]),
            ("ci/decode_runs_test.go", ["go"], ["image", "parity", "postfix"]),
        ]:
            with self.subTest(path=path):
                result = impact.plan([path])
                for key in selected:
                    self.assertTrue(result[key], key)
                for key in unrelated:
                    self.assertFalse(result[key], key)

    def test_cron_signer_test_reaches_its_generate_job(self):
        lint_predicate = (
            "if: ${{ needs.changes.outputs.go == 'true' || "
            "needs.changes.outputs.scope == 'true' }}"
        )
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count(lint_predicate), 1)
        result = impact.plan(["ci/generate_rules_cron_signer_test.sh"])
        self.assertTrue(result["generate"])
        self.assertTrue(result["shell"])
        self.assertFalse(result["go"])
        self.assertTrue(
            result["go"] or result["scope"],
            "the lint job containing the generate step must be selected",
        )

    def test_apt_install_test_and_subject_select_the_planner_job(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("-m unittest discover -s ci -p 'ci_*_test.py'", workflow)
        test = impact.plan(["ci/ci_apt_install_test.py"])
        self.assertEqual(
            {key for key, value in test.items() if value is True}, {"scope"}
        )
        self.assertEqual(test["changed_files"], "--changed -- ")
        subject = impact.plan([".github/actions/go-setup/apt-install.sh"])
        self.assertTrue(subject["scope"])
        self.assertTrue(subject["go"])
        for unrelated in ["ci/apt_install_test.py", "ci/ci_apt_install_test.txt"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_gh_install_contract_test_selects_the_planner_job(self):
        result = impact.plan(["ci/ci_gh_install_test.py"])
        self.assertEqual(
            {key for key, value in result.items() if value is True}, {"scope"}
        )
        with self.assertRaises(ValueError):
            impact.plan(["ci/gh_install_test.py"])

    def test_preflight_script_and_test_select_the_planner_job(self):
        for path in ("ci/ci_preflight_test.py", "scripts/ci-preflight.sh"):
            with self.subTest(path=path):
                self.assertTrue(impact.plan([path])["scope"])

    def test_helm_chart_files_are_passive_and_select_no_go(self):
        paths = [
            "contrib/deploy/helm/mailstrix/values.yaml",
            "contrib/deploy/helm/mailstrix/templates/deployment.yaml",
        ]
        result = impact.plan(paths)
        self.assertFalse(result["go"])
        self.assertEqual(result["changed_files"], "--changed -- ")
        # A removal is the same path set; the planner never reads file contents.
        self.assertFalse(impact.plan(paths[:1])["go"])
        for bad in ("/contrib/deploy/helm/x.yaml", "contrib/../x.yaml"):
            with self.subTest(path=bad), self.assertRaises(ValueError):
                impact.plan([bad])
        with self.assertRaises(ValueError):
            impact.plan(["contrib/deploy/helm/mailstrix/values.yaml", "unmapped.txt"])

    def test_decode_scalar_native_go_consumer(self):
        path = "ci/decode_scalar_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/decode_scalar_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_icap_admission_fixture_has_exact_go_consumers(self):
        for path in [
            "ci/icap_admission_ordering_test.go",
            "ci/testdata/icap_admission_ordering_test.go",
        ]:
            with self.subTest(path=path):
                result = impact.plan([path])
                self.assertEqual(
                    {key for key, value in result.items() if value is True},
                    {"go", "docker"},
                )
                self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in [
            "ci/icap_admission_ordering_test.py",
            "ci/testdata/icap_admission_ordering.txt",
        ]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_clamd_admission_fixture_has_exact_go_consumers(self):
        for path in [
            "ci/clamd_admission_ordering_test.go",
            "ci/testdata/clamd_admission_ordering_test.go",
        ]:
            with self.subTest(path=path):
                result = impact.plan([path])
                self.assertEqual(
                    {key for key, value in result.items() if value is True},
                    {"go", "docker"},
                )
                self.assertEqual(result["changed_files"], "--changed -- " + path)

    def test_release_tag_contract_is_a_named_dockerfile_consumer(self):
        path = "ci/ci_release_tag_test.py"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"dockerfiles", "release_image"},
        )
        self.assertEqual(result["changed_files"], "--changed -- ")
        for unrelated in ["ci/unmapped_test.py", "ci/release_tag_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_cape_response_native_go_consumer(self):
        path = "ci/cape_response_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/cape_response_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])
        without_path = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_path),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])

    def test_cape_store_seam_native_go_consumer(self):
        path = "ci/cape_store_seam_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/cape_store_seam_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_path = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_path),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])

    def test_scanner_budget_native_go_consumer(self):
        path = "ci/scanner_budget_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        # A named native test must not turn unrelated new CI files into inputs.
        for unrelated in ["ci/unmapped_test.go", "ci/scanner_budget_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_rule_generations_native_go_consumer(self):
        path = "ci/rule_generations_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/rule_generations_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_generations = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_generations),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])
        self.assertEqual(impact.plan([path]), result)

    def test_p7_lifetime_has_no_nested_go_test(self):
        source = (ROOT / "ci/p7_main_retirement_test.go").read_text()
        self.assertNotRegex(
            source,
            r'exec\.Command(?:Context)?\([\s\S]*?"go"\s*,\s*"test"',
            "native lifetime tests must run directly in their owning package",
        )
        self.assertIn("func TestP7PublicCloseAndFailedReload", source)

    def test_p7_main_retirement_native_go_consumer(self):
        path = "ci/p7_main_retirement_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/p7_main_retirement_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_retirement = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_retirement),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])
        self.assertEqual(impact.plan([path]), result)

    def test_extraction_native_go_consumers(self):
        path = "ci/extraction_memory_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/extraction_memory_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_extraction = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_extraction),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])
        self.assertEqual(impact.plan([path]), result)

        pattern = "ci/extraction-budget/*_test.go"
        for path in (
            "ci/extraction-budget/p16a_test.go",
            "ci/extraction-budget/p16b_test.go",
            "ci/extraction-budget/future_boundary_test.go",
        ):
            with self.subTest(path=path):
                result = impact.plan([path])
                self.assertEqual(
                    {key for key, value in result.items() if value is True},
                    {"go", "docker"},
                )
                self.assertEqual(result["changed_files"], "--changed -- " + path)

                without_directory = [
                    name for name in impact.GO_INPUTS if name != pattern
                ]
                with (
                    mock.patch.object(impact, "GO_INPUTS", without_directory),
                    self.assertRaisesRegex(ValueError, "unmapped changed path"),
                ):
                    impact.plan([path])

        for unrelated in (
            "ci/extraction-budget/helper.py",
            "ci/extraction-budget/fixture.json",
            "ci/extraction-budget/helper.go",
            "ci/extraction-budgetary/p16a_test.go",
            "ci/extraction-budget_test.go",
            "ci/unmapped_test.go",
        ):
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])

    def test_memory_metrics_native_go_consumer(self):
        path = "ci/memory_metrics_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/memory_metrics_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_memory = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_memory),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])
        self.assertEqual(impact.plan([path]), result)

    def test_cache_byte_bound_native_go_consumer(self):
        path = "ci/cache_byte_bound_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/cache_byte_bound_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_path = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_path),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])
        self.assertEqual(impact.plan([path]), result)

    def test_feed_set_bytes_native_go_consumer(self):
        path = "ci/feed_set_bytes_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/feed_set_bytes_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_path = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_path),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])
        self.assertEqual(impact.plan([path]), result)

    def test_startup_memory_go_consumer(self):
        path = "ci/startup_memory_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/startup_memory_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_memory = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_memory),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])
        self.assertEqual(impact.plan([path]), result)

    def test_reload_generation_native_go_consumer(self):
        path = "ci/reload_generation_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/reload_generation_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])
        without_reload = [name for name in impact.GO_INPUTS if name != path]
        with (
            mock.patch.object(impact, "GO_INPUTS", without_reload),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])
        self.assertEqual(impact.plan([path]), result)

    def test_marker_reload_native_go_consumer(self):
        path = "ci/marker_reload_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/marker_reload_test.py"]:
            with (
                self.subTest(path=unrelated),
                self.assertRaisesRegex(ValueError, "unmapped changed path"),
            ):
                impact.plan([unrelated])

    def test_mbazaar_lifecycle_native_go_consumer(self):
        path = "ci/mbazaar_lifecycle_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/mbazaar_lifecycle_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_threatfox_urlhaus_lifecycle_native_go_consumers(self):
        for name in ["threatfox", "urlhaus"]:
            path = f"ci/{name}_lifecycle_test.go"
            with self.subTest(path=path):
                result = impact.plan([path])
                self.assertEqual(
                    {key for key, value in result.items() if value is True},
                    {"go", "docker"},
                )
                self.assertEqual(result["changed_files"], "--changed -- " + path)
            for unrelated in [f"ci/{name}_lifecycle_test.py", "ci/unmapped_test.go"]:
                with self.subTest(path=unrelated), self.assertRaises(ValueError):
                    impact.plan([unrelated])

    def test_feed_lifecycle_helpers_and_feedrefresh_native_go_consumers(self):
        for path in [
            "ci/feed_lifecycle_helpers_test.go",
            "internal/feedrefresh/feedrefresh.go",
            "internal/feedrefresh/feedrefresh_test.go",
        ]:
            with self.subTest(path=path):
                result = impact.plan([path])
                self.assertTrue(result["go"])
                self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/feed_lifecycle_helpers_test.py", "ci/unmapped_test.go"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_mime_attachment_native_go_consumer(self):
        path = "ci/mime_attachment_hash_test.go"
        result = impact.plan([path], False)
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/mime_attachment_hash_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated], False)

    def test_encrypted_rar_native_go_consumer(self):
        path = "ci/rar_password_extract_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/rar_password_extract_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_extract_cap_stops_go_consumer(self):
        path = "ci/extract_cap_stops_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/extract_cap_stops_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_extract_verify_first_member_go_consumer(self):
        path = "ci/extract_verify_first_member_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in [
            "ci/unmapped_test.go",
            "ci/extract_verify_first_member_test.py",
        ]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_extract_lzma_dict_cap_go_consumer(self):
        path = "ci/extract_lzma_dict_cap_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/extract_lzma_dict_cap_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_extract_lzma2_dict_cap_go_consumer(self):
        path = "ci/extract_lzma2_dict_cap_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in [
            "ci/extract_lzma3_dict_cap_test.go",
            "ci/extract_lzma2_dict_cap_test.py",
        ]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_rc4md5_go_mapping_negative_control(self):
        cases = {
            "ci/rc4md5_extract_test.go": "--changed -- ci/rc4md5_extract_test.go",
            "ci/testdata/rc4md5-biff.xls": (
                "--changed -- ci/testdata/rc4md5-biff.xls internal/extract/rc4md5_fixture_test.go"
            ),
        }
        for path, changed_files in cases.items():
            with self.subTest(path=path):
                result = impact.plan([path])
                self.assertEqual(
                    {key for key, value in result.items() if value is True},
                    {"go", "docker"},
                )
                self.assertEqual(result["changed_files"], changed_files)

                # The same named test must fail if this mapping is removed.
                without_path = [name for name in impact.GO_INPUTS if name != path]
                with (
                    mock.patch.object(impact, "GO_INPUTS", without_path),
                    self.assertRaisesRegex(ValueError, "unmapped changed path"),
                ):
                    impact.plan([path])

        for unrelated in ["ci/unmapped_test.go", "ci/testdata/unmapped.xls"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_hdrenc_7z_fixture_go_mapping_negative_control(self):
        paths = [
            "ci/testdata/hdrenc-dir.7z",
            "ci/testdata/hdrenc-oversize.7z",
            "ci/testdata/hdrenc-small.7z",
            "ci/testdata/vfm-nonsolid.7z",
            "ci/testdata/vfm-solid.7z",
            "ci/testdata/vfm-onlybig.7z",
            "ci/testdata/lzmadict-enc-in.7z",
            "ci/testdata/lzmadict-enc-over.7z",
            "ci/testdata/lzmadict-hdrenc-over.7z",
        ]
        for path in paths:
            with self.subTest(path=path):
                result = impact.plan([path])
                self.assertEqual(
                    {key for key, value in result.items() if value is True},
                    {"go", "docker"},
                )
                self.assertEqual(result["changed_files"], f"--changed -- {path}")

                # The same named test must fail if this mapping is removed.
                without_path = [name for name in impact.GO_INPUTS if name != path]
                with (
                    mock.patch.object(impact, "GO_INPUTS", without_path),
                    self.assertRaisesRegex(ValueError, "unmapped changed path"),
                ):
                    impact.plan([path])

    def test_urlhaus_shared_host_native_go_consumer(self):
        path = "ci/urlhaus_shared_host_test.go"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"go", "docker"},
        )
        self.assertEqual(result["changed_files"], "--changed -- " + path)
        for unrelated in ["ci/unmapped_test.go", "ci/urlhaus_shared_host_test.py"]:
            with self.subTest(path=unrelated), self.assertRaises(ValueError):
                impact.plan([unrelated])

    def test_milter_maintainer_consumers(self):
        for path in [
            "packaging/deb/postinstall-milter.sh",
            "packaging/deb/preremove-milter.sh",
        ]:
            result = impact.plan([path])
            self.assertTrue(result["maintscript"])
            self.assertTrue(result["shell"])
            self.assertFalse(result["go"])

    def test_full_and_orchestration_scope(self):
        for result in [
            impact.plan([], full=True),
            impact.plan([".github/workflows/ci.yml"]),
            impact.plan(["scripts/ci-impact.py"]),
            impact.plan(["ci/workflow_contract_test.py"]),
        ]:
            self.assertTrue(
                all(value for key, value in result.items() if key != "changed_files")
            )
        self.assertEqual(impact.plan([], full=True)["changed_files"], "")
        self.assertEqual(
            impact.plan([".github/workflows/ci.yml"])["changed_files"],
            "--changed -- tools/testscope/main.go",
        )
        self.assertIn(
            "go.mod",
            impact.plan([".github/actions/go-setup/action.yml"])["changed_files"],
        )

    def test_order_and_duplicate_inputs_are_deterministic(self):
        paths = ["internal/extract/pdf_test.go", "internal/verdict/verdict.go"]
        self.assertEqual(impact.plan(paths), impact.plan(reversed(paths)))
        self.assertEqual(impact.plan(paths), impact.plan(paths * 2))
        self.assertTrue(impact.plan(paths)["image"])

    def test_dockerfile_only_selects_go_without_scope(self):
        result = impact.plan(["docker/Dockerfile"])
        self.assertTrue(result["go"])
        self.assertFalse(result["scope"])

    def test_bake_only_change_selects_images_and_missing_mapping_fails(self):
        path = "docker/bake.ci.hcl"
        result = impact.plan([path])
        self.assertTrue(result["image"])
        self.assertTrue(result["docker"])
        self.assertFalse(result["go"])
        without_bake = [name for name in impact.RULES["image"] if name != path]
        with (
            mock.patch.dict(impact.RULES, image=without_bake),
            self.assertRaisesRegex(ValueError, "unmapped changed path"),
        ):
            impact.plan([path])

    def test_extensionless_sieve_wrapper_alone_selects_shellcheck(self):
        path = "contrib/sieve/strix-scan-wrapper"
        result = impact.plan([path])
        self.assertTrue(result["shell"])
        self.assertFalse(result["image"])
        self.assertFalse(result["go"])

    def test_unknown_and_unsafe_fail(self):
        for path in [
            "ci/ci_vet_wiring_test.py",
            "new-surface/config.json",
            "../go.mod",
            "/go.mod",
            "internal/a bad.go",
            "file\nkey=true",
            "",
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                impact.plan([path])

    def test_unregistered_packaging_executables_fail(self):
        for path in [
            "packaging/deb/new-maintainer.sh",
            "packaging/deb/new-helper.py",
            "packaging/deb/new-config.json",
            "packaging/deb/workflow_pins_unused.py",
            "packaging/deb/parity_unused_test.py",
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                impact.plan([path])
        self.assertTrue(impact.plan(["packaging/deb/immutable_inputs_test.py"])["pins"])
        self.assertFalse(impact.plan(["packaging/deb/nfpm-strixd.yaml"])["go"])

    def test_graph_transport_errors_propagate(self):
        with mock.patch.object(
            impact.subprocess,
            "run",
            side_effect=subprocess.CalledProcessError(128, "git"),
        ):
            self.assertRaises(
                subprocess.CalledProcessError, impact.changed_paths, "missing", "HEAD"
            )

    def test_authoritative_check_rejects_failed_planner(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        docker = workflow.split("  docker:\n", 1)[1].split("  parity-isolation:", 1)[0]
        self.assertIn("if: ${{ always() }}", docker)
        self.assertIn("PLAN_RESULT: ${{ needs.changes.result }}", docker)
        command = re.search(r'run: (test "\$PLAN_RESULT" = success)', docker).group(1)
        for status in ["success", "failure", "cancelled", "skipped", "", "unknown"]:
            result = subprocess.run(
                ["bash", "-c", command],
                env=dict(os.environ, PLAN_RESULT=status),
                check=False,
            )
            self.assertEqual(result.returncode == 0, status == "success")

    def test_cli_full_output_and_required_base(self):
        with tempfile.TemporaryDirectory() as temp:
            output = pathlib.Path(temp) / "outputs"
            with (
                mock.patch.object(
                    sys, "argv", ["ci-impact", "--full", "--output", str(output)]
                ),
                mock.patch.object(sys, "stdout", io.StringIO()) as stdout,
            ):
                runpy.run_path(str(ROOT / "scripts/ci-impact.py"), run_name="__main__")
            self.assertTrue(json.loads(stdout.getvalue())["go"])
            self.assertIn("go=true\n", output.read_text())
        with (
            mock.patch.object(sys, "argv", ["ci-impact"]),
            mock.patch.object(sys, "stderr", io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            impact.main()
        self.assertEqual(error.exception.code, 2)

    def test_lanes_contract_selects_its_planner_job(self):
        result = impact.plan(["ci/ci_lanes_test.py"])
        self.assertTrue(result["scope"])
        self.assertFalse(result["go"])
        self.assertFalse(result["image"])
        self.assertEqual(result["changed_files"], "--changed -- ")

    def test_strict_cli_mapped_input_succeeds(self):
        with tempfile.TemporaryDirectory() as temp:
            output = pathlib.Path(temp) / "outputs"
            with (
                mock.patch.object(impact, "changed_paths", return_value=["README.md"]),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "ci-impact",
                        "--strict",
                        "--base",
                        "base",
                        "--output",
                        str(output),
                    ],
                ),
                mock.patch.object(sys, "stdout", io.StringIO()) as stdout,
            ):
                impact.main()
            self.assertEqual(json.loads(stdout.getvalue()), impact.plan(["README.md"]))
            self.assertIn("go=false\n", output.read_text())

    def test_strict_cli_refusals_preserve_outputs(self):
        for value in (
            ["ci/new_unregistered_test.py"],
            subprocess.CalledProcessError(128, "git"),
            FileNotFoundError("git"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
        ):
            for existing in (False, True):
                with (
                    self.subTest(value=value, existing=existing),
                    tempfile.TemporaryDirectory() as temp,
                ):
                    output = pathlib.Path(temp) / "outputs"
                    if existing:
                        output.write_text("sentinel\n")
                    with (
                        mock.patch.object(
                            impact,
                            "changed_paths",
                            side_effect=value if isinstance(value, Exception) else None,
                            return_value=value if isinstance(value, list) else None,
                        ),
                        mock.patch.object(
                            sys,
                            "argv",
                            [
                                "ci-impact",
                                "--strict",
                                "--base",
                                "missing",
                                "--output",
                                str(output),
                            ],
                        ),
                        mock.patch.object(sys, "stdout", io.StringIO()) as stdout,
                        self.assertRaises(
                            type(value)
                            if isinstance(value, Exception)
                            else impact.UnmappedPathError
                        ),
                    ):
                        impact.main()
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertEqual(output.exists(), existing)
                    if existing:
                        self.assertEqual(output.read_text(), "sentinel\n")

    def test_strict_cli_requires_base_unless_full(self):
        with (
            mock.patch.object(sys, "argv", ["ci-impact", "--strict"]),
            mock.patch.object(sys, "stderr", io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            impact.main()
        self.assertEqual(error.exception.code, 2)
        with (
            mock.patch.object(sys, "argv", ["ci-impact", "--strict", "--full"]),
            mock.patch.object(impact, "changed_paths") as changed,
            mock.patch.object(sys, "stdout", io.StringIO()) as stdout,
        ):
            impact.main()
        changed.assert_not_called()
        self.assertEqual(json.loads(stdout.getvalue()), impact.plan([], full=True))

    def test_strict_cli_hard_errors_precede_unknown_in_both_orders(self):
        for hard_path, error in (
            ("unsafe name.go", "unsafe changed path"),
            ("packaging/deb/new-helper.sh", "unmapped executable packaging path"),
        ):
            for paths in (["a/new.surface", hard_path], [hard_path, "a/new.surface"]):
                with self.subTest(paths=paths), tempfile.TemporaryDirectory() as temp:
                    output = pathlib.Path(temp) / "outputs"
                    with (
                        mock.patch.object(impact, "changed_paths", return_value=paths),
                        mock.patch.object(
                            sys,
                            "argv",
                            [
                                "ci-impact",
                                "--strict",
                                "--base",
                                "base",
                                "--output",
                                str(output),
                            ],
                        ),
                        mock.patch.object(sys, "stdout", io.StringIO()) as stdout,
                        self.assertRaisesRegex(ValueError, error),
                    ):
                        impact.main()
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertFalse(output.exists())

    def test_cli_unavailable_diff_selects_full_without_partial_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            output = pathlib.Path(temp) / "outputs"
            for error in (
                subprocess.CalledProcessError(128, "git"),
                FileNotFoundError("git"),
                UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
            ):
                with (
                    self.subTest(error=type(error).__name__),
                    mock.patch.object(impact, "changed_paths", side_effect=error),
                    mock.patch.object(
                        sys,
                        "argv",
                        ["ci-impact", "--base", "missing", "--output", str(output)],
                    ),
                    mock.patch.object(sys, "stdout", io.StringIO()) as stdout,
                    mock.patch.object(sys, "stderr", io.StringIO()) as stderr,
                ):
                    impact.main()
                    result = json.loads(stdout.getvalue())
                    self.assertTrue(all(result[key] for key in impact.RULES))
                    self.assertEqual(result["changed_files"], "")
                    self.assertIn("selecting full CI", stderr.getvalue())
                    self.assertIn("go=true\n", output.read_text())

    def test_cli_unsafe_path_and_program_error_still_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            output = pathlib.Path(temp) / "outputs"
            for value in (
                ["file\nkey=true"],
                ["packaging/deb/new-maintainer.sh"],
                ValueError("program defect"),
            ):
                with (
                    self.subTest(value=value),
                    mock.patch.object(
                        impact,
                        "changed_paths",
                        side_effect=value if isinstance(value, Exception) else None,
                        return_value=value if isinstance(value, list) else None,
                    ),
                    mock.patch.object(
                        sys,
                        "argv",
                        ["ci-impact", "--base", "base", "--output", str(output)],
                    ),
                    self.assertRaises(ValueError),
                ):
                    impact.main()
                self.assertFalse(output.exists())

    def test_hard_path_errors_precede_unmapped_fallback_in_both_orders(self):
        for hard_path, error in (
            ("unsafe name.go", "unsafe changed path"),
            ("packaging/deb/new-helper.sh", "unmapped executable packaging path"),
        ):
            for paths in (
                ["a/new.surface", hard_path],
                [hard_path, "a/new.surface"],
                ["a/another.surface", "a/new.surface", hard_path],
            ):
                with self.subTest(paths=paths):
                    with self.assertRaisesRegex(ValueError, error):
                        impact.plan(paths)
                    with tempfile.TemporaryDirectory() as temp:
                        output = pathlib.Path(temp) / "outputs"
                        with (
                            mock.patch.object(
                                impact, "changed_paths", return_value=paths
                            ),
                            mock.patch.object(
                                sys,
                                "argv",
                                [
                                    "ci-impact",
                                    "--base",
                                    "test",
                                    "--output",
                                    str(output),
                                ],
                            ),
                            self.assertRaisesRegex(ValueError, error),
                        ):
                            impact.main()
                        self.assertFalse(output.exists())

    def test_ci_plan_actual_pr_and_reusable_callers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / "scripts").mkdir()
            for name in ("ci-plan.sh", "ci-impact.py"):
                shutil.copy2(ROOT / "scripts" / name, root / "scripts" / name)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", temp, *args], text=True
                ).strip()

            git("init", "-q")
            git("config", "user.name", "CI Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            (root / "README.md").write_text("first\n")
            git("add", ".")
            git("commit", "-qm", "base")
            missing_base_output = root / "output-missing-base"
            missing_base = subprocess.run(
                ["bash", "scripts/ci-plan.sh"],
                cwd=root,
                env=dict(
                    os.environ,
                    EVENT_NAME="pull_request",
                    GITHUB_OUTPUT=str(missing_base_output),
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(missing_base.returncode, 0, missing_base.stderr)
            self.assertTrue(json.loads(missing_base.stdout)["native"])
            self.assertIn("release_image=true\n", missing_base_output.read_text())
            missing_base_output.unlink()
            (root / "README.md").write_text("second\n")
            git("add", ".")
            git("commit", "-qm", "docs")
            for event, full in (("pull_request", False), ("workflow_call", True)):
                with self.subTest(event=event):
                    output = root / f"output-{event}"
                    completed = subprocess.run(
                        ["bash", "scripts/ci-plan.sh"],
                        cwd=root,
                        env=dict(
                            os.environ, EVENT_NAME=event, GITHUB_OUTPUT=str(output)
                        ),
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    result = json.loads(completed.stdout)
                    self.assertEqual(result["go"], full, completed.stderr)
                    self.assertEqual(result["native"], full)
                    self.assertEqual(result["readme"], True)
                    self.assertIn(f"go={str(full).lower()}\n", output.read_text())

    def test_cli_empty_diff_without_output(self):
        empty = subprocess.CompletedProcess(["git"], 0, stdout=b"")
        with (
            mock.patch.object(impact.subprocess, "run", return_value=empty),
            mock.patch.object(sys, "argv", ["ci-impact", "--base", "base"]),
            mock.patch.object(sys, "stdout", io.StringIO()) as stdout,
        ):
            impact.main()
        self.assertFalse(json.loads(stdout.getvalue())["go"])

    def test_git_rename_delete_and_cli_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", temp, *args], text=True
                ).strip()

            git("init", "-q")
            git("config", "user.name", "CI Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            (root / "contrib/rspamd").mkdir(parents=True)
            old = root / "contrib/rspamd/old.lua"
            old.write_text("fixture")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (root / "contrib/spamassassin").mkdir(parents=True)
            old.rename(root / "contrib/spamassassin/new.pm")
            git("add", ".")
            git("commit", "-qm", "rename")
            output = root / "outputs"
            command = [
                sys.executable,
                str(ROOT / "scripts/ci-impact.py"),
                "--base",
                base,
                "--output",
                str(output),
            ]
            result = subprocess.run(
                command, cwd=temp, check=True, capture_output=True, text=True
            )
            plan = json.loads(result.stdout)
            self.assertTrue(plan["rspamd"])
            self.assertTrue(plan["spamassassin"])
            self.assertIn("rspamd=true\n", output.read_text())
            (root / "unknown.bin").write_bytes(b"unknown")
            git("add", "unknown.bin")
            git("commit", "-qm", "unknown")
            recovered = subprocess.run(
                command, cwd=temp, check=False, capture_output=True, text=True
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertIn("unmapped changed path", recovered.stderr)
            self.assertIn("selecting full CI", recovered.stderr)
            fallback = json.loads(recovered.stdout)
            self.assertTrue(all(fallback[key] for key in impact.RULES))
            self.assertEqual(fallback["changed_files"], "")
            self.assertTrue(output.read_text().endswith("docker=true\n"))
            (root / "a").mkdir()
            (root / "a/new.surface").write_text("unknown")
            (root / "packaging/deb").mkdir(parents=True)
            (root / "packaging/deb/new-helper.sh").write_text("#!/bin/sh\n")
            git("add", "a/new.surface", "packaging/deb/new-helper.sh")
            git("commit", "-qm", "unknown before required contract")
            before = output.read_text()
            blocked = subprocess.run(
                command, cwd=temp, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("unmapped executable packaging path", blocked.stderr)
            self.assertEqual(output.read_text(), before)
            packaging_base = git("rev-parse", "HEAD")
            (root / "a/new.surface").write_text("still unknown")
            (root / "b unsafe.go").write_text("unsafe")
            git("add", "a/new.surface", "b unsafe.go")
            git("commit", "-qm", "unknown before unsafe")
            unsafe_command = command.copy()
            unsafe_command[3] = packaging_base
            blocked = subprocess.run(
                unsafe_command, cwd=temp, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("unsafe changed path", blocked.stderr)
            self.assertEqual(output.read_text(), before)


if __name__ == "__main__":
    unittest.main()
