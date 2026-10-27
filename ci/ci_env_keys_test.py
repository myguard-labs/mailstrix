"""Regression controls for the packaged environment-consumer guard."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUARD = ROOT / "packaging/deb/env_keys_test.sh"

# Test names state their contract; method docstrings would duplicate them.
# unittest owns TemporaryDirectory cleanup through enterContext.
# pylint: disable=missing-function-docstring,consider-using-with


class PackagedEnvironmentConsumersTest(unittest.TestCase):
    """Exercise the real shell guard against isolated source fixtures."""

    def setUp(self) -> None:
        temporary = self.enterContext(
            tempfile.TemporaryDirectory(prefix="mailstrix-env-consumers-")
        )
        self.root = pathlib.Path(temporary)
        guard = self.root / "packaging/deb/env_keys_test.sh"
        guard.parent.mkdir(parents=True)
        shutil.copy2(GUARD, guard)
        (self.root / "internal").mkdir()
        (self.root / "cmd").mkdir()
        self.write("packaging/deb/fixture.service", "[Service]\n")

    def write(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def run_guard(
        self, *, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", "packaging/deb/env_keys_test.sh"],
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=30,
            env=env,
        )

    def set_packaged_keys(self, *keys: str) -> None:
        self.write(
            "packaging/deb/fixture.env",
            "".join(f"#{key}=fixture\n" for key in keys),
        )

    def test_direct_named_and_file_readers_are_accepted(self) -> None:
        self.set_packaged_keys(
            "MAILSTRIX_DIRECT",
            "MAILSTRIX_NAMED",
            "MAILSTRIX_SECRET",
            "MAILSTRIX_SECRET_FILE",
            "MAILSTRIX_UNIT",
        )
        self.write(
            "packaging/deb/fixture.service",
            "[Service]\nExecStart=/bin/fixture $MAILSTRIX_UNIT\n",
        )
        self.write(
            "internal/config.go",
            """package internal

import "os"

const namedEnv = "MAILSTRIX_NAMED"

func load() {
    _ = os.Getenv("MAILSTRIX_DIRECT")
    _ = envDur(namedEnv, 1)
    _ = envOrFile("MAILSTRIX_SECRET")
}
""",
        )

        result = self.run_guard()

        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("ALL OK", result.stdout)

    def test_comments_tests_and_inert_strings_are_rejected(self) -> None:
        keys = (
            "MAILSTRIX_COMMENT_ONLY",
            "MAILSTRIX_TEST_ONLY",
            "MAILSTRIX_INERT_ONLY",
            "MAILSTRIX_UNIT_COMMENT_ONLY",
        )
        self.set_packaged_keys(*keys)
        self.write(
            "packaging/deb/fixture.service",
            "# ExecStart=/bin/fixture $MAILSTRIX_UNIT_COMMENT_ONLY\n",
        )
        self.write(
            "internal/config.go",
            """package internal

// os.Getenv("MAILSTRIX_COMMENT_ONLY")
const inert = "MAILSTRIX_INERT_ONLY"
""",
        )
        self.write(
            "internal/config_test.go",
            """package internal

import "os"

func testOnly() { _ = os.Getenv("MAILSTRIX_TEST_ONLY") }
""",
        )

        result = self.run_guard()

        self.assertNotEqual(0, result.returncode, result.stdout)
        for key in keys:
            self.assertIn(key, result.stdout)

    def test_function_local_constant_does_not_shadow_package_constant(self) -> None:
        self.set_packaged_keys("MAILSTRIX_PACKAGE", "MAILSTRIX_LOCAL_SHADOW")
        self.write(
            "internal/config.go",
            """package internal

import "os"

const envKey = "MAILSTRIX_PACKAGE"

func load() { _ = os.Getenv(envKey) }

func unrelated() {
    const envKey = "MAILSTRIX_LOCAL_SHADOW"
    _ = envKey
}
""",
        )

        result = self.run_guard()

        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("ok   - fixture.env: MAILSTRIX_PACKAGE", result.stdout)
        self.assertIn("FAIL - MAILSTRIX_LOCAL_SHADOW", result.stdout)

    def test_reader_with_local_shadow_is_not_misattributed(self) -> None:
        self.set_packaged_keys("MAILSTRIX_PACKAGE")
        self.write(
            "internal/config.go",
            """package internal

import "os"

const envKey = "MAILSTRIX_PACKAGE"

func load() {
    const envKey = "MAILSTRIX_OTHER"
    _ = os.Getenv(envKey)
}
""",
        )

        result = self.run_guard()

        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("FAIL - MAILSTRIX_PACKAGE", result.stdout)

    def test_parameters_and_variables_shadow_package_constants(self) -> None:
        self.set_packaged_keys("MAILSTRIX_PARAM", "MAILSTRIX_VAR")
        self.write(
            "internal/config.go",
            """package internal

import "os"

const paramKey = "MAILSTRIX_PARAM"
const varKey = "MAILSTRIX_VAR"

func byParam(paramKey string) { _ = os.Getenv(paramKey) }

func byVar() {
    var varKey = "MAILSTRIX_OTHER"
    _ = os.Getenv(varKey)
}
""",
        )

        result = self.run_guard()

        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("FAIL - MAILSTRIX_PARAM", result.stdout)
        self.assertIn("FAIL - MAILSTRIX_VAR", result.stdout)

    def test_nested_shadow_does_not_hide_earlier_package_read(self) -> None:
        self.set_packaged_keys("MAILSTRIX_PACKAGE")
        self.write(
            "internal/config.go",
            """package internal

import "os"

const envKey = "MAILSTRIX_PACKAGE"

func load(condition bool) {
    _ = os.Getenv(envKey)
    if condition {
        envKey := "MAILSTRIX_OTHER"
        _ = envKey
    }
}
""",
        )

        result = self.run_guard()

        self.assertEqual(0, result.returncode, result.stdout)

    def test_range_binding_does_not_resolve_to_package_constant(self) -> None:
        self.set_packaged_keys("MAILSTRIX_PACKAGE")
        self.write(
            "internal/config.go",
            """package internal

import "os"

const envKey = "MAILSTRIX_PACKAGE"

func load(keys []string) {
    for _, envKey := range keys {
        _ = os.Getenv(envKey)
    }
}
""",
        )

        result = self.run_guard()

        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("FAIL - MAILSTRIX_PACKAGE", result.stdout)

    def test_named_reader_removal_turns_green_red_then_green(self) -> None:
        self.set_packaged_keys("MAILSTRIX_CACHE_TTL")
        source = """package internal

const cacheTTLEnv = "MAILSTRIX_CACHE_TTL"

func load() { _ = envDur(cacheTTLEnv, 3600) }
"""
        path = self.root / "internal/config.go"
        self.write("internal/config.go", source)
        before = self.run_guard()
        self.assertEqual(0, before.returncode, before.stdout)

        path.write_text(
            source.replace(
                "func load() { _ = envDur(cacheTTLEnv, 3600) }",
                "func load() {}",
            ),
            encoding="utf-8",
        )
        removed = self.run_guard()
        self.assertNotEqual(0, removed.returncode, removed.stdout)
        self.assertIn("MAILSTRIX_CACHE_TTL", removed.stdout)

        path.write_text(source, encoding="utf-8")
        restored = self.run_guard()
        self.assertEqual(0, restored.returncode, restored.stdout)

    def test_go_parser_failure_is_not_hidden_by_sort(self) -> None:
        self.set_packaged_keys("MAILSTRIX_DIRECT")
        self.write(
            "internal/config.go",
            'package internal\nimport "os"\nfunc load() { _ = os.Getenv("MAILSTRIX_DIRECT") }\n',
        )
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_go = fake_bin / "go"
        fake_go.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
        fake_go.chmod(0o755)
        env = {"PATH": f"{fake_bin}:/usr/bin:/bin"}

        result = self.run_guard(env=env)

        self.assertNotEqual(0, result.returncode, result.stdout)

    def test_bodyless_function_declaration_is_ignored(self) -> None:
        self.set_packaged_keys("MAILSTRIX_DIRECT")
        self.write(
            "internal/config.go",
            'package internal\nimport "os"\nfunc assemblyBacked()\nfunc load() { _ = os.Getenv("MAILSTRIX_DIRECT") }\n',
        )

        result = self.run_guard()

        self.assertEqual(0, result.returncode, result.stdout)

    def test_repository_go_flags_do_not_affect_helper(self) -> None:
        self.set_packaged_keys("MAILSTRIX_DIRECT")
        self.write(
            "internal/config.go",
            'package internal\nimport "os"\nfunc load() { _ = os.Getenv("MAILSTRIX_DIRECT") }\n',
        )
        env = os.environ | {
            "GOFLAGS": "-mod=vendor",
            "GOWORK": "/does/not/exist",
        }

        result = self.run_guard(env=env)

        self.assertEqual(0, result.returncode, result.stdout)


if __name__ == "__main__":
    unittest.main()
