"""Controls for Dockerfile.release's local candidate input (RELEASE_SOURCE=local).

A dry run must be able to build the release image from candidate binaries plus
their matching marker toolchain, while the default path still downloads and
verifies the published release. docker/release-local-artifacts.sh is exercised
directly; the stage selection is exercised with `docker buildx build --target
fetch` (no network is needed: the local path reads a build context and the
default path fails on its first guard). RELEASE_LOCALBIN_TEST_DOCKERFILE swaps
the Dockerfile under test so the selection control can be watched red.
"""

import os
import platform
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = Path(
    os.environ.get(
        "RELEASE_LOCAL_ARTIFACTS_TEST_PATH", ROOT / "docker/release-local-artifacts.sh"
    )
)
RELEASE = Path(
    os.environ.get("RELEASE_LOCALBIN_TEST_DOCKERFILE", ROOT / "docker/Dockerfile.release")
)
ARCH = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
    platform.machine(), "amd64"
)
NAMES = (
    "strixd-linux-{a}",
    "strix-scan-linux-{a}",
    "strix-milter-linux-{a}",
    "yarac-linux-{a}",
    "libyara-linux-{a}.a",
)


def docker_ready():
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(
            ["docker", "buildx", "version"], capture_output=True, check=False
        ).returncode
        == 0
        and subprocess.run(["docker", "info"], capture_output=True, check=False).returncode
        == 0
    )


def candidate(directory, skip=(), empty=()):
    directory.mkdir(parents=True, exist_ok=True)
    for tmpl in NAMES:
        name = tmpl.format(a=ARCH)
        if name in skip:
            continue
        (directory / name).write_bytes(b"" if name in empty else f"cand:{name}".encode())
    return directory


def stage(name):
    source = RELEASE.read_text(encoding="utf-8")
    return source.split(f" AS {name}\n", 1)[1].split("\nFROM ", 1)[0]


class HelperTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def run_helper(self, *args):
        return subprocess.run(
            ["sh", str(HELPER), *args], capture_output=True, text=True, check=False
        )

    def test_positive_lays_out_download_stage_shape(self):
        src = candidate(self.tmp / "in")
        res = self.run_helper(ARCH, str(src), str(self.tmp / "out"))
        self.assertEqual(res.returncode, 0, res.stderr)
        out = self.tmp / "out"
        for b in ("strixd", "strix-scan", "strix-milter"):
            path = out / "bin" / b
            self.assertEqual(path.read_text(), f"cand:{b}-linux-{ARCH}")
            self.assertTrue(os.access(path, os.X_OK))
        self.assertEqual((out / "marker/yarac").read_text(), f"cand:yarac-linux-{ARCH}")
        self.assertEqual(
            (out / "marker/libyara.a").read_text(), f"cand:libyara-linux-{ARCH}.a"
        )

    def test_each_missing_asset_fails_closed_and_is_named(self):
        for tmpl in NAMES:
            name = tmpl.format(a=ARCH)
            with self.subTest(name=name):
                src = candidate(self.tmp / f"in-{name}", skip=(name,))
                out = self.tmp / f"out-{name}"
                res = self.run_helper(ARCH, str(src), str(out))
                self.assertEqual(res.returncode, 1)
                self.assertIn("incomplete local artifacts", res.stderr)
                self.assertIn(name, res.stderr)
                self.assertFalse(out.exists(), "no partial layout on failure")

    def test_empty_asset_is_rejected(self):
        name = f"yarac-linux-{ARCH}"
        src = candidate(self.tmp / "in", empty=(name,))
        res = self.run_helper(ARCH, str(src), str(self.tmp / "out"))
        self.assertEqual(res.returncode, 1)
        self.assertIn(name, res.stderr)

    def test_other_architecture_assets_do_not_satisfy(self):
        other = "arm64" if ARCH == "amd64" else "amd64"
        src = self.tmp / "in"
        src.mkdir()
        for tmpl in NAMES:
            (src / tmpl.format(a=other)).write_bytes(b"x")
        res = self.run_helper(ARCH, str(src), str(self.tmp / "out"))
        self.assertEqual(res.returncode, 1)
        self.assertIn(f"strixd-linux-{ARCH}", res.stderr)

    def test_malformed_invocation(self):
        self.assertEqual(self.run_helper().returncode, 2)
        self.assertEqual(self.run_helper(ARCH, "a").returncode, 2)
        for bad in ("", "../x", "amd64;id", "AMD64"):
            with self.subTest(arch=bad):
                res = self.run_helper(bad, str(self.tmp), str(self.tmp / "o"))
                self.assertEqual(res.returncode, 2)
                self.assertIn("invalid ARCH", res.stderr)
        res = self.run_helper(ARCH, str(self.tmp / "absent"), str(self.tmp / "o"))
        self.assertEqual(res.returncode, 1)
        self.assertIn("input directory not found", res.stderr)

    def test_helper_never_downloads(self):
        text = HELPER.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\b(curl|wget)\b|https?://", text))


class DockerfileTest(unittest.TestCase):
    def test_default_source_is_the_verified_download(self):
        source = RELEASE.read_text(encoding="utf-8")
        head = source.split("\nFROM ", 1)[0]
        self.assertRegex(head, r"(?m)^ARG RELEASE_SOURCE=download$")
        self.assertRegex(source, r"(?m)^FROM fetch-\$\{RELEASE_SOURCE\} AS fetch$")
        download = stage("fetch-download")
        self.assertIn("sha256sum -c SHA256SUMS.arch", download)
        self.assertIn("releases/download/", download)

    def test_local_stage_downloads_nothing_and_uses_the_named_context(self):
        local = stage("fetch-local")
        self.assertIn("COPY --from=local-artifacts / /in/", local)
        self.assertIn("release-local-artifacts.sh", local)
        self.assertIsNone(re.search(r"\b(curl|wget)\b|https?://", local))
        self.assertNotIn("--from=local-artifacts", stage("fetch-download"))

    def test_later_stages_still_consume_fetch(self):
        rules = stage("rules")
        self.assertIn("COPY --from=fetch /out/bin/strixd /tmp/release/strixd", rules)
        self.assertIn("release-marker-toolchain.sh /tmp/release/strixd", rules)
        self.assertIn("COPY --from=fetch /out/bin/ /usr/local/bin/", stage("final"))


class SelectionTest(unittest.TestCase):
    def setUp(self):
        if not docker_ready():
            # CI must exercise the controls; a local run may opt out explicitly.
            required = os.environ.get(
                "RELEASE_LOCALBIN_REQUIRE_DOCKER", "1" if os.environ.get("CI") else "0"
            )
            if required != "0":
                self.fail("docker buildx and its daemon are required for the selection controls")
            self.skipTest("docker buildx daemon unavailable (RELEASE_LOCALBIN_REQUIRE_DOCKER=0)")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def build_fetch(self, *extra):
        out = self.tmp / "export"
        shutil.rmtree(out, ignore_errors=True)
        res = subprocess.run(
            [
                "docker", "buildx", "build", "--platform", f"linux/{ARCH}",
                "--target", "fetch", "--output", f"type=local,dest={out}",
                "-f", str(RELEASE), *extra, str(ROOT),
            ],
            capture_output=True, text=True, check=False,
        )
        return res, out

    def test_local_source_selects_candidate_binaries(self):
        ctx = candidate(self.tmp / "ctx")
        res, out = self.build_fetch(
            "--build-arg", "RELEASE_SOURCE=local", "--build-context", f"local-artifacts={ctx}"
        )
        self.assertEqual(res.returncode, 0, res.stderr[-2000:])
        self.assertEqual(
            (out / "out/bin/strixd").read_text(), f"cand:strixd-linux-{ARCH}"
        )
        self.assertEqual(
            (out / "out/marker/libyara.a").read_text(), f"cand:libyara-linux-{ARCH}.a"
        )
        self.assertTrue((out / "out/NOTICE").is_file())

    def test_local_source_incomplete_fails_without_download(self):
        ctx = candidate(self.tmp / "ctx", skip=(f"libyara-linux-{ARCH}.a",))
        res, _ = self.build_fetch(
            "--build-arg", "RELEASE_SOURCE=local", "--build-context", f"local-artifacts={ctx}"
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("incomplete local artifacts", res.stderr)
        self.assertNotIn("releases/download", res.stderr)

    def test_local_source_without_context_fails_closed(self):
        res, _ = self.build_fetch("--build-arg", "RELEASE_SOURCE=local")
        self.assertNotEqual(res.returncode, 0)
        # Not the helper's message: an omitted context is never bound, so the
        # build dies resolving it. Assert it names the context and never
        # falls back to a published release.
        self.assertIn("local-artifacts", res.stderr)
        self.assertNotIn("releases/download", res.stderr)

    def test_default_source_still_requires_a_published_release(self):
        # The download stage's first guard fires; a supplied local context is ignored.
        ctx = candidate(self.tmp / "ctx")
        res, out = self.build_fetch("--build-context", f"local-artifacts={ctx}")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("VERSION or RELEASE_TAG build-arg is required", res.stderr)
        self.assertFalse((out / "out/bin/strixd").exists())

    def test_default_source_needs_no_local_context(self):
        # The daily bake never supplies `local-artifacts`; the default path must
        # reach its first guard without resolving that context.
        res, out = self.build_fetch()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("VERSION or RELEASE_TAG build-arg is required", res.stderr)
        self.assertNotIn("local-artifacts", res.stderr)
        self.assertFalse((out / "out/bin/strixd").exists())

    def test_unknown_source_fails_closed(self):
        res, _ = self.build_fetch("--build-arg", "RELEASE_SOURCE=bogus")
        self.assertNotEqual(res.returncode, 0)


if __name__ == "__main__":
    unittest.main()
