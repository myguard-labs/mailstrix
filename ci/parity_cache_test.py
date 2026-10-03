#!/usr/bin/env python3
"""Verify optional parity cache arguments using a failing Docker stub only."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qualify-parity-isolation.sh"


class ParityCacheTest(unittest.TestCase):
    def probe(self, mode):
        with tempfile.TemporaryDirectory(prefix="mailstrix-parity-cache-") as temp:
            base = Path(temp)
            binaries = base / "bin"
            binaries.mkdir()
            log = base / "docker-args.json"
            docker = binaries / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['CACHE_PROBE_LOG']).write_text("
                "json.dumps(sys.argv[1:]))\n"
                "print('stub parity build failure', file=sys.stderr)\n"
                "sys.exit(43)\n"
            )
            docker.chmod(0o755)
            # The build fails before image execution or qualification. No daemon,
            # process signal exercise, or real image exists in these controls.
            env = dict(os.environ)
            env.pop("CI_PARITY_CACHE", None)
            env.update(
                PATH=str(binaries) + os.pathsep + env["PATH"],
                CACHE_PROBE_LOG=str(log),
            )
            if mode is not None:
                env["CI_PARITY_CACHE"] = mode
            output = base / "output"
            result = subprocess.run(
                ["bash", str(SCRIPT), str(output)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            args = json.loads(log.read_text()) if log.exists() else None
            retained = output / "parity-runtime.log"
            build_log = retained.read_text() if retained.exists() else None
            return result, args, build_log

    def assert_failed_build(self, result, args, build_log):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIsNotNone(args)
        self.assertEqual(args[:3], ["--host", "unix:///var/run/docker.sock", "buildx"])
        self.assertIn("stub parity build failure", result.stderr)
        self.assertIn("stub parity build failure", build_log)

    def test_default_and_explicit_disable_do_not_use_remote_cache(self):
        for mode in (None, "0"):
            with self.subTest(mode=mode):
                result, args, build_log = self.probe(mode)
                self.assert_failed_build(result, args, build_log)
                self.assertNotIn("--cache-from", args)
                self.assertNotIn("--cache-to", args)

    def test_opt_in_has_both_read_scopes_and_separate_write_scope(self):
        result, args, build_log = self.probe("1")
        self.assert_failed_build(result, args, build_log)
        reads = [args[i + 1] for i, arg in enumerate(args) if arg == "--cache-from"]
        writes = [args[i + 1] for i, arg in enumerate(args) if arg == "--cache-to"]
        self.assertEqual(
            reads,
            [
                "type=gha,scope=strixd-build",
                "type=gha,scope=mailstrix-parity-parity-runtime",
            ],
        )
        self.assertEqual(
            writes, ["type=gha,mode=max,scope=mailstrix-parity-parity-runtime"]
        )

    def test_malformed_mode_rejects_before_any_docker_invocation(self):
        for mode in ("invalid", "2", "true", " "):
            with self.subTest(mode=mode):
                result, args, build_log = self.probe(mode)
                self.assertEqual(result.returncode, 2)
                self.assertIn("CI_PARITY_CACHE must be 0 or 1", result.stderr)
                self.assertIsNone(args)
                self.assertIsNone(build_log)


if __name__ == "__main__":
    unittest.main()
