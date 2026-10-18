"""Controls for the release image's marker toolchain binding.

docker/release-marker-toolchain.sh decides whether Dockerfile.release can bake
a marker artifact strixd will load: the release's yarac and libyara.a must be
the exact bytes whose SHA-256 values are linked into strixd. The Docker-backed
end-to-end proof is ci/release_marker_image_test.sh (release.yml marker-image).
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = Path(
    os.environ.get(
        "RELEASE_MARKER_TOOLCHAIN_TEST_PATH",
        ROOT / "docker/release-marker-toolchain.sh",
    )
)
RELEASE = ROOT / "docker/Dockerfile.release"
DOCKERFILE = ROOT / "docker/Dockerfile"
LOADER = b"PERF-18: marker artifact unavailable; full ruleset fallback: %v"
YARAC = b"\x7fELF fake yarac"
LIBYARA = b"!<arch>\nfake libyara"


def digest(data):
    return hashlib.sha256(data).hexdigest().encode()


def stage(sections):
    source = RELEASE.read_text(encoding="utf-8")
    return source.split(f" AS {sections}\n", 1)[1].split("\nFROM ", 1)[0]


class Fixture:
    def __init__(self, root):
        self.root = root
        self.strixd = root / "strixd"
        self.toolchain = root / "toolchain"
        self.toolchain.mkdir()
        self.yarac_dest = root / "dest-yarac"
        self.libyara_dest = root / "dest-libyara.a"

    def binary(self, *parts):
        self.strixd.write_bytes(b"\0go rodata\0" + b"".join(parts) + b"\0tail")

    def tools(self, yarac=YARAC, libyara=LIBYARA):
        if yarac is not None:
            (self.toolchain / "yarac").write_bytes(yarac)
        if libyara is not None:
            (self.toolchain / "libyara.a").write_bytes(libyara)

    def run(self, *args):
        argv = args or (
            str(self.strixd),
            str(self.toolchain),
            str(self.yarac_dest),
            str(self.libyara_dest),
        )
        return subprocess.run(
            ["sh", str(HELPER), *argv],
            capture_output=True,
            text=True,
            check=False,
        )


class ReleaseMarkerToolchain(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="mailstrix-marker-tool-"))
        self.addCleanup(shutil.rmtree, root)
        self.f = Fixture(root)

    def assert_nothing_installed(self):
        self.assertFalse(self.f.yarac_dest.exists())
        self.assertFalse(self.f.libyara_dest.exists())

    def test_linked_toolchain_is_installed_and_selects_marker_build(self):
        # Hashes adjacent to other rodata, as Go packs -X strings.
        self.f.binary(LOADER, digest(LIBYARA) + digest(YARAC))
        self.f.tools()
        result = self.f.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "marker\n")
        self.assertEqual(self.f.yarac_dest.read_bytes(), YARAC)
        self.assertEqual(self.f.libyara_dest.read_bytes(), LIBYARA)
        self.assertEqual(self.f.yarac_dest.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.f.libyara_dest.stat().st_mode & 0o777, 0o644)

    def test_pre_marker_release_without_toolchain_is_legacy(self):
        self.f.binary(b"strixd v1.2.0 without marker support")
        result = self.f.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "legacy\n")
        self.assert_nothing_installed()

    def test_marker_capable_release_without_toolchain_fails(self):
        self.f.binary(LOADER, digest(LIBYARA), digest(YARAC))
        result = self.f.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release has no yarac/libyara assets", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assert_nothing_installed()

    def test_half_toolchain_fails(self):
        self.f.binary(LOADER, digest(LIBYARA), digest(YARAC))
        for yarac, libyara, missing in (
            (YARAC, None, "libyara.a"),
            (None, LIBYARA, "yarac"),
        ):
            with self.subTest(missing=missing):
                for path in self.f.toolchain.iterdir():
                    path.unlink()
                self.f.tools(yarac, libyara)
                result = self.f.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"incomplete release toolchain: {missing} missing", result.stderr
                )
                self.assert_nothing_installed()

    def test_unlinked_compiler_or_library_fails(self):
        for name, yarac, libyara in (
            ("yarac", YARAC + b"x", LIBYARA),
            ("libyara.a", YARAC, LIBYARA + b"x"),
        ):
            with self.subTest(mismatch=name):
                self.f.binary(LOADER, digest(LIBYARA), digest(YARAC))
                self.f.tools(yarac, libyara)
                result = self.f.run()
                self.assertNotEqual(result.returncode, 0)
                bad = yarac if name == "yarac" else libyara
                self.assertIn(
                    f"release {name} sha256 {digest(bad).decode()} "
                    "is not linked into strixd",
                    result.stderr,
                )
                self.assertEqual(result.stdout, "")
                self.assert_nothing_installed()

    def test_truncated_hash_is_not_a_match(self):
        self.f.binary(LOADER, digest(LIBYARA), digest(YARAC)[:63])
        self.f.tools()
        result = self.f.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release yarac sha256", result.stderr)
        self.assert_nothing_installed()

    def test_usage_and_missing_strixd(self):
        result = self.f.run("only", "three", "args")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.f.tools()
        result = self.f.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("strixd not found", result.stderr)
        self.assert_nothing_installed()


class ReleaseDockerfileWiring(unittest.TestCase):
    def test_bin_target_exports_the_hashed_toolchain(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        link = re.search(
            r"marker_library=\$\(sha256sum (\S+) .*?"
            r"marker_compiler=\$\(sha256sum (\S+) ",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(link)
        library, compiler = link.groups()
        bin_stage = source.split(" AS bin\n", 1)[1].split("\nFROM ", 1)[0]
        self.assertIn(f"COPY --from=build {compiler} /yarac\n", bin_stage)
        self.assertIn(f"COPY --from=build {library} /libyara.a\n", bin_stage)

    def test_toolchain_installed_before_any_rule_compiles(self):
        rules = stage("rules")
        install = rules.index("release-marker-toolchain.sh /tmp/release/strixd")
        self.assertIn("COPY --from=fetch /out/bin/strixd /tmp/release/strixd", rules)
        self.assertIn("COPY --from=fetch /out/marker/ /tmp/release/marker/", rules)
        self.assertIn(
            '/usr/local/bin/yarac "$(pkg-config --variable=libdir yara)/libyara.a"',
            rules,
        )
        self.assertLess(install, rules.index("compile-rules.sh /rules/src"))
        build = rules.index("build-marker-artifact.py /rules")
        self.assertLess(rules.index("compile-rules.sh /rules/local-src"), build)
        self.assertIn('if [ "$(cat /tmp/release/mode)" = marker ]', rules)

    def test_final_ships_the_verified_export(self):
        export = stage("rules-export-inputs")
        self.assertIn('cmd="export-marker"', export)
        self.assertIn('export-compiler-inputs.py "${cmd}" /rules /rules-export', export)
        final = stage("final")
        self.assertIn(
            "COPY --from=rules-export-inputs /rules-export/ /usr/share/mailstrix/",
            final,
        )
        self.assertNotIn("COPY --from=rules /rules/compiled.yac", final)


if __name__ == "__main__":
    unittest.main()
