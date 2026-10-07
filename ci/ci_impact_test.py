"""Change-plan contracts, including real Git deletion/rename and failure controls."""

import importlib.util
import io
import json
import os
import pathlib
import re
import runpy
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
            ("ci/rules_polling_defaults_test.sh", ["envkeys", "shell"], ["go", "image"]),
            ("ci/rules_polling_test.sh", ["image", "shell", "smoke"], ["go", "parity"]),
            ("docker/docker-compose.yml", ["envkeys"], ["go", "image"]),
            ("packaging/deb/stop_timeout_test.sh", ["envkeys", "shell"], ["go", "image"]),
            ("ci/rules_polling_config_test.go", ["go"], ["image", "parity"]),
            ("ci/config_auto_derive_test.go", ["go"], ["image", "parity"]),
            ("ci/clamd_cache_test.go", ["go"], ["image", "parity", "postfix"]),
            (
                "ci/generate_rules_count_test.sh",
                ["generate", "shell"],
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

    def test_release_tag_contract_is_a_named_dockerfile_consumer(self):
        path = "ci/ci_release_tag_test.py"
        result = impact.plan([path])
        self.assertEqual(
            {key for key, value in result.items() if value is True},
            {"dockerfiles"},
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

    def test_rc4md5_go_mapping_negative_control(self):
        cases = {
            "ci/rc4md5_extract_test.go": "--changed -- ci/rc4md5_extract_test.go",
            "ci/testdata/rc4md5-biff.xls": (
                "--changed -- ci/testdata/rc4md5-biff.xls "
                "internal/extract/rc4md5_fixture_test.go"
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
            git("add", ".")
            git("commit", "-qm", "unknown")
            before = output.read_text()
            failed = subprocess.run(
                command, cwd=temp, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("unmapped changed path", failed.stderr)
            self.assertEqual(output.read_text(), before)


if __name__ == "__main__":
    unittest.main()
