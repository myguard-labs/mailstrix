"""Execute shipped batched workflow commands and required suite selection."""

import ast
import importlib.util
import io
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
RUNNER = ROOT / "scripts/ci-test-batch.py"


def named_step(job, prefix):
    block = job_block(job)
    steps = list(re.finditer(r"(?m)^      - name: (.+)$", block))
    found = [step for step in steps if step.group(1).startswith(prefix)]
    assert len(found) == 1, (job, prefix)
    start = found[0].start()
    following = re.search(r"(?m)^      - ", block[found[0].end() :])
    end = found[0].end() + following.start() if following else len(block)
    step = block[start:end]
    assert step.count("        run: |\n") == 1, (job, prefix)
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


def job_block(name):
    source = WORKFLOW.read_text()
    found = list(
        re.finditer(
            rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            source,
        )
    )
    assert len(found) == 1, name
    return found[0].group("body")


class BatchWorkflowTests(unittest.TestCase):
    def shellcheck(
        self,
        paths,
        *,
        fail_git=False,
        fail_input="",
        missing_docker=False,
        real_git=False,
        cwd=None,
        script=None,
    ):
        with tempfile.TemporaryDirectory() as temp:
            fixture = pathlib.Path(temp)
            binary = fixture / "bin"
            binary.mkdir()
            listing = fixture / "listing"
            listing.write_bytes(
                b"\0".join(path.encode() for path in paths) + (b"\0" if paths else b"")
            )
            trace = fixture / "trace"
            git = binary / "git"
            git.write_text(
                "#!/bin/sh\n"
                'if [ "$GIT_REAL" = 1 ]; then exec /usr/bin/git "$@"; fi\n'
                '/bin/cat "$LISTING"\n'
                'if [ "$GIT_FAIL" = 1 ]; then exit 42; fi\n'
            )
            git.chmod(0o755)
            if not missing_docker:
                docker = binary / "docker"
                docker.write_text(
                    "#!/bin/sh\n"
                    'printf "docker" >> "$TRACE"\n'
                    'for arg do printf " <%s>" "$arg" >> "$TRACE"; done\n'
                    'printf "\\n" >> "$TRACE"\n'
                    'for arg do if [ "$arg" = "$FAIL_INPUT" ]; then exit 42; fi; done\n'
                )
                docker.chmod(0o755)
            for name in ("mktemp", "rm"):
                (binary / name).symlink_to(shutil.which(name))
            result = subprocess.run(
                [
                    shutil.which("bash"),
                    "-e",
                    "-o",
                    "pipefail",
                    "-c",
                    script or named_step("scanners", "shellcheck"),
                ],
                cwd=cwd or ROOT,
                env=dict(
                    os.environ,
                    PATH=str(binary),
                    LISTING=str(listing),
                    TRACE=str(trace),
                    GIT_REAL="1" if real_git else "0",
                    GIT_FAIL="1" if fail_git else "0",
                    FAIL_INPUT=fail_input,
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            return result, trace.read_text() if trace.exists() else ""

    def test_shellcheck_batches_literal_tracked_paths(self):
        paths = [
            "scripts/one.sh",
            "scripts/middle space.sh",
            "scripts/end;touch marker.sh",
        ]
        result, trace = self.shellcheck(paths)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(trace.count("docker "), 1, trace)
        self.assertIn("<koalaman/shellcheck:v0.10.0>", trace)
        for path in paths:
            self.assertIn(f" <{path}>", trace)
        self.assertFalse((ROOT / "marker.sh").exists())

    def test_shellcheck_omitted_input_and_disabled_scanner_mutants(self):
        paths = ["scripts/first.sh", "scripts/middle.sh", "scripts/last.sh"]
        source = named_step("scanners", "shellcheck")
        omitted = source.replace('"${shell_scripts[@]}"', '"${shell_scripts[0]}"', 1)
        disabled = source.replace("docker run --rm", "true --rm", 1)
        self.assertNotEqual(omitted, source)
        self.assertNotEqual(disabled, source)
        for script, expected in ((omitted, False), (disabled, False), (source, True)):
            with self.subTest(restored=expected):
                result, trace = self.shellcheck(paths, script=script)
                self.assertEqual(result.returncode, 0, result.stderr)
                covered = trace.count("docker ") == 1 and all(
                    f" <{path}>" in trace for path in paths
                )
                self.assertEqual(covered, expected)

    def test_shellcheck_empty_or_partial_producer_is_fatal(self):
        for paths, fail_git in (([], False), (["scripts/one.sh"], True)):
            with self.subTest(paths=paths, fail_git=fail_git):
                result, trace = self.shellcheck(paths, fail_git=fail_git)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(trace, "")

    def test_shellcheck_missing_tool_and_failing_middle_input(self):
        paths = ["scripts/one.sh", "scripts/middle.sh", "scripts/last.sh"]
        missing, trace = self.shellcheck(paths, missing_docker=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertEqual(trace, "")
        failed, trace = self.shellcheck(paths, fail_input="scripts/middle.sh")
        self.assertEqual(failed.returncode, 42)
        self.assertIn("<scripts/last.sh>", trace)

    def test_shellcheck_committed_deletion_is_not_a_missing_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / "scripts").mkdir()
            for name in ("old.sh", "keep.sh"):
                (root / "scripts" / name).write_text("#!/bin/sh\n")
            git = lambda *args: subprocess.run(
                ["/usr/bin/git", "-C", temp, *args], check=True, capture_output=True
            )
            git("init", "-q")
            git("config", "user.name", "CI Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            git("add", ".")
            git("commit", "-qm", "base")
            (root / "scripts/old.sh").unlink()
            git("add", "-u")
            git("commit", "-qm", "delete")
            result, trace = self.shellcheck([], real_git=True, cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("<scripts/keep.sh>", trace)
            self.assertNotIn("old.sh", trace)

    def lua(self, *, fail_tool="", fail_input="", missing_tool="", script=None):
        with tempfile.TemporaryDirectory() as temp:
            fixture = pathlib.Path(temp)
            binary = fixture / "bin"
            binary.mkdir()
            trace = fixture / "trace"
            docker = binary / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                'printf "docker\\n" >> "$TRACE"\n'
                'while [ "$#" -gt 2 ]; do\n'
                '  if [ "$1" = sh ] && [ "$2" = -ec ]; then exec /bin/sh -ec "$3"; fi\n'
                "  shift\n"
                "done\n"
                "exit 90\n"
            )
            docker.chmod(0o755)
            tool = binary / "tool"
            tool.write_text(
                "#!/bin/sh\n"
                "name=${0##*/}\n"
                'printf "%s" "$name" >> "$TRACE"\n'
                'for arg do printf " <%s>" "$arg" >> "$TRACE"; done\n'
                'printf "\\n" >> "$TRACE"\n'
                'if [ "$name" = "$FAIL_TOOL" ] && [ "${1-}" = "$FAIL_INPUT" ]; then exit 42; fi\n'
            )
            tool.chmod(0o755)
            for name in ("apk", "luarocks-5.4", "luacheck", "lua5.4", "lua5.1"):
                if name != missing_tool:
                    (binary / name).symlink_to(tool)
            script = script or named_step("rspamd", "Lua lint and unit")
            result = subprocess.run(
                [shutil.which("bash"), "-e", "-o", "pipefail", "-c", script],
                cwd=ROOT,
                env=dict(
                    os.environ,
                    PATH=str(binary),
                    TRACE=str(trace),
                    FAIL_TOOL=fail_tool,
                    FAIL_INPUT=fail_input,
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            return result, trace.read_text() if trace.exists() else ""

    def test_lua_preparation_is_shared_without_losing_checks(self):
        rspamd = job_block("rspamd")
        self.assertEqual(rspamd.count("alpine:3.21"), 1)
        self.assertEqual(rspamd.count("debian:trixie-slim"), 1)
        result, trace = self.lua()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(trace.count("docker\n"), 1)
        self.assertEqual(trace.count("apk <add>"), 1)
        for package in (
            "luarocks5.4",
            "lua5.4-dev",
            "gcc",
            "musl-dev",
            "lua5.1",
            "lua5.4",
        ):
            self.assertIn(f"<{package}>", trace)
        self.assertEqual(trace.count("luarocks-5.4 <install> <luacheck>"), 1)
        self.assertEqual(trace.count("luacheck <contrib/rspamd/>"), 1)
        self.assertEqual(trace.count("lua5.4 <contrib/rspamd/test/"), 6)
        self.assertEqual(trace.count("lua5.1 <contrib/rspamd/test/"), 2)

    def test_lua_missing_tool_and_middle_failure_propagate(self):
        missing, trace = self.lua(missing_tool="luacheck")
        self.assertNotEqual(missing.returncode, 0)
        self.assertNotIn("lua5.4 <contrib/rspamd/test/", trace)
        failed, trace = self.lua(
            fail_tool="lua5.4",
            fail_input="contrib/rspamd/test/mailstrix_effort_spec.lua",
        )
        self.assertEqual(failed.returncode, 42)
        self.assertIn("mailstrix_dedup_spec.lua", trace)
        self.assertIn("mailstrix_effort_spec.lua", trace)
        self.assertNotIn("mailstrix_explain_spec.lua", trace)

    def test_lua_omitted_unit_mutant_loses_one_case(self):
        source = named_step("rspamd", "Lua lint and unit")
        omitted = source.replace(
            "lua5.4 contrib/rspamd/test/mailstrix_effort_spec.lua\n", "", 1
        )
        self.assertNotEqual(omitted, source)
        for script, expected in ((omitted, False), (source, True)):
            with self.subTest(restored=expected):
                result, trace = self.lua(script=script)
                self.assertEqual(result.returncode, 0, result.stderr)
                covered = trace.count("lua5.4 <contrib/rspamd/test/") == 6
                self.assertEqual(covered, expected)

    def test_lua_disabled_linter_mutant_is_detected(self):
        source = named_step("rspamd", "Lua lint and unit")
        disabled = source.replace("luacheck contrib/rspamd/\n", "", 1)
        self.assertNotEqual(disabled, source)
        for script, expected in ((disabled, False), (source, True)):
            with self.subTest(restored=expected):
                result, trace = self.lua(script=script)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("luacheck <contrib/rspamd/>" in trace, expected)


class BatchRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("mailstrix_ci_test_batch", RUNNER)
        assert spec is not None and spec.loader is not None
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def test_exact_qualification_route_and_selected_suite_identities(self):
        step = named_step("scanners", "parity qualification failure artifacts")
        expected_commands = [
            "python3 -B packaging/deb/parity_qualification_artifact_test.py",
            "python3 -B scripts/ci-test-batch.py",
        ]
        self.assertEqual(step.strip().splitlines(), expected_commands)
        expected_paths = (
            "packaging/deb/parity_image_cleanup_test.py",
            "ci/parity_cache_test.py",
        )
        self.assertEqual(tuple(path for path, _ in self.runner.SUITES), expected_paths)
        expected = []
        for path in expected_paths:
            tree = ast.parse((ROOT / path).read_text())
            expected.extend(
                f"{path}::{node.name}.{method.name}"
                for node in tree.body
                if isinstance(node, ast.ClassDef)
                for method in node.body
                if isinstance(method, ast.FunctionDef)
                and method.name.startswith("test_")
            )
        self.assertEqual(len(expected), 36)
        self.assertEqual(len(expected), len(set(expected)))
        self.assertEqual(len(self.runner.SUITES), 2)
        loaded = []
        module_paths = {name: path for path, name in self.runner.SUITES}

        def collect(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    collect(item)
                else:
                    module, identity = item.id().split(".", 1)
                    loaded.append(f"{module_paths[module]}::{identity}")
            return unittest.TestResult()

        with mock.patch.object(self.runner.unittest, "TextTestRunner") as runner:
            runner.return_value.run.side_effect = collect
            self.assertEqual(self.runner.main(), 0)
        self.assertEqual(len(loaded), 36)
        self.assertCountEqual(loaded, expected)

    def test_same_count_loader_drop_duplicate_is_detected(self):
        original = unittest.TestLoader.loadTestsFromModule

        def flatten(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from flatten(item)
                else:
                    yield item

        def wrong_ids(loader, module, *args, **kwargs):
            suite = original(loader, module, *args, **kwargs)
            if module.__name__ == self.runner.SUITES[0][1]:
                cases = list(flatten(suite))
                self.assertGreater(len(cases), 1)
                return unittest.TestSuite(cases[1:] + [cases[1]])
            return suite

        with mock.patch.object(unittest.TestLoader, "loadTestsFromModule", wrong_ids):
            red = unittest.TestResult()
            self.__class__(
                "test_exact_qualification_route_and_selected_suite_identities"
            ).run(red)
        self.assertEqual(len(red.failures), 1, red.errors)
        self.assertIn("Element counts were not equal", red.failures[0][1])

    def test_removed_group_or_omitted_suite_mutants_are_detected(self):
        step = named_step("scanners", "parity qualification failure artifacts")
        disabled = step.replace("python3 -B scripts/ci-test-batch.py", "true")
        self.assertNotEqual(disabled, step)
        with tempfile.TemporaryDirectory() as temp:
            mutated = pathlib.Path(temp) / "ci.yml"
            mutated.write_text(
                WORKFLOW.read_text().replace(
                    "          python3 -B scripts/ci-test-batch.py\n",
                    "          true\n",
                    1,
                )
            )
            with mock.patch.object(sys.modules[__name__], "WORKFLOW", mutated):
                red = unittest.TestResult()
                self.__class__(
                    "test_exact_qualification_route_and_selected_suite_identities"
                ).run(red)
                self.assertFalse(red.wasSuccessful())
                self.assertEqual(len(red.failures), 1)
        restored = unittest.TestResult()
        self.__class__(
            "test_exact_qualification_route_and_selected_suite_identities"
        ).run(restored)
        self.assertTrue(restored.wasSuccessful(), restored.failures)
        with mock.patch.object(self.runner, "SUITES", self.runner.SUITES[:1]):
            self.assertEqual(self.runner.main(), 1)
        self.assertEqual(len(self.runner.SUITES), 2)

    def test_zero_suite_import_error_and_duplicate_module_are_fatal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            empty = root / "empty.py"
            empty.write_text("VALUE = 1\n")
            malformed = root / "malformed.py"
            malformed.write_text("raise ImportError('fixture import failure')\n")
            exits = root / "exits.py"
            exits.write_text("raise SystemExit(0)\n")
            stream = io.StringIO()
            self.assertFalse(
                self.runner.run_suite(empty, "ci_batch_empty", stream=stream)
            )
            self.assertIn(str(empty), stream.getvalue())
            self.assertNotIn("ci_batch_empty", sys.modules)
            with self.assertRaisesRegex(ImportError, "fixture import failure"):
                self.runner.run_suite(
                    malformed, "ci_batch_malformed", stream=io.StringIO()
                )
            self.assertNotIn("ci_batch_malformed", sys.modules)
            self.assertFalse(
                self.runner.run_suite(exits, "ci_batch_exits", stream=io.StringIO())
            )
            self.assertNotIn("ci_batch_exits", sys.modules)
            with mock.patch.dict("sys.modules", {"ci_batch_duplicate": object()}):
                self.assertFalse(
                    self.runner.run_suite(
                        empty, "ci_batch_duplicate", stream=io.StringIO()
                    )
                )

    def test_first_middle_last_failures_keep_case_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            source = pathlib.Path(temp) / "cases.py"
            source.write_text(
                "import os, unittest\n"
                "class Cases(unittest.TestCase):\n"
                " def test_a(self): self.assertNotEqual(os.getenv('FAIL_CASE'), 'a')\n"
                " def test_b(self): self.assertNotEqual(os.getenv('FAIL_CASE'), 'b')\n"
                " def test_c(self): self.assertNotEqual(os.getenv('FAIL_CASE'), 'c')\n"
            )
            for failing in ("a", "b", "c"):
                with (
                    self.subTest(failing=failing),
                    mock.patch.dict(os.environ, FAIL_CASE=failing),
                ):
                    stream = io.StringIO()
                    self.assertFalse(
                        self.runner.run_suite(
                            source, f"ci_batch_failure_{failing}", stream=stream
                        )
                    )
                    self.assertIn(f"test_{failing}", stream.getvalue())
                    self.assertIn("Ran 3 tests", stream.getvalue())
            stream = io.StringIO()
            self.assertTrue(
                self.runner.run_suite(source, "ci_batch_restored", stream=stream)
            )
            self.assertIn("Ran 3 tests", stream.getvalue())

    def test_fixture_environment_and_module_state_are_isolated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            first = root / "first.py"
            first.write_text(
                "import os, unittest\n"
                "class Cases(unittest.TestCase):\n"
                " def test_set(self): os.environ['CI_BATCH_FIXTURE'] = 'set'\n"
            )
            second = root / "second.py"
            second.write_text(
                "import os, unittest\n"
                "class Cases(unittest.TestCase):\n"
                " def test_clean(self): self.assertNotIn('CI_BATCH_FIXTURE', os.environ)\n"
            )
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CI_BATCH_FIXTURE", None)
                self.assertTrue(
                    self.runner.run_suite(first, "ci_batch_first", stream=io.StringIO())
                )
                self.assertNotIn("CI_BATCH_FIXTURE", os.environ)
                self.assertTrue(
                    self.runner.run_suite(
                        second, "ci_batch_second", stream=io.StringIO()
                    )
                )


if __name__ == "__main__":
    unittest.main()
