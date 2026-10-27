"""Behavioral contract for the profile wrapper's embedded sample extractor."""

import importlib
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "docker/profile/run-profile.sh"


def embedded_extractor():
    source = WRAPPER.read_text()
    match = re.search(
        r"python3 - \"\$SAMPLES\" <<'PY'\n(?P<code>.*?)\nPY\n",
        source,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError("profile sample extractor heredoc is missing")
    return match.group("code") + "\n"


def write_zip(path, members):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for member, contents in members:
            archive.writestr(member, contents)


def run_extractor(root, output, source=None, *, use_real_pyzipper=False):
    extractor = root / "extractor.py"
    extractor.write_text(source or embedded_extractor())
    if not use_real_pyzipper:
        (root / "pyzipper.py").write_text(
            "from zipfile import ZipFile\nAESZipFile = ZipFile\n"
        )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        path for path in (str(root), env.get("PYTHONPATH")) if path
    )
    return subprocess.run(
        [sys.executable, str(extractor), str(output)],
        cwd=root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


class ProfileSamplesTest(unittest.TestCase):
    def make_hostile_archives(self, root):
        live = root / "testdata/live-samples"
        directory = zipfile.ZipInfo("nested/")
        directory.external_attr = (stat.S_IFDIR | 0o755) << 16
        symlink = zipfile.ZipInfo("nested/link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        write_zip(
            live / "a.zip",
            [
                (directory, b""),
                ("../escape.bin", b"traversal"),
                ("/absolute.bin", b"absolute"),
                (symlink, b"../../outside"),
                ("nested/duplicate.bin", b"first duplicate"),
            ],
        )
        write_zip(live / "b.zip", [("other/duplicate.bin", b"second duplicate")])

    def test_regular_members_get_unique_flat_owned_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_hostile_archives(root)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()

            result = run_extractor(root, first)
            repeated = run_extractor(root, second)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            expected = {
                "archive-0000-member-0001.sample": b"traversal",
                "archive-0000-member-0002.sample": b"absolute",
                "archive-0000-member-0004.sample": b"first duplicate",
                "archive-0001-member-0000.sample": b"second duplicate",
            }
            observed = {path.name: path.read_bytes() for path in first.iterdir()}
            repeated_observed = {
                path.name: path.read_bytes() for path in second.iterdir()
            }
            self.assertEqual(observed, expected)
            self.assertEqual(repeated_observed, expected)
            self.assertEqual(result.stderr, "extracted 4 samples\n")
            self.assertEqual(len(observed), 4)
            self.assertFalse((root / "escape.bin").exists())
            self.assertFalse((root / "outside").exists())
            self.assertTrue(all("/" not in name for name in observed))

    def test_empty_archive_reports_zero_successful_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_zip(root / "testdata/live-samples/empty.zip", [])
            output = root / "output"
            output.mkdir()

            result = run_extractor(root, output)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "extracted 0 samples\n")
            self.assertEqual(list(output.iterdir()), [])

    def test_aes_archive_uses_infected_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            pyzipper = importlib.import_module("pyzipper")
            root = Path(tmp)
            archive_path = root / "testdata/live-samples/encrypted.zip"
            archive_path.parent.mkdir(parents=True)
            with pyzipper.AESZipFile(
                archive_path,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as archive:
                archive.setpassword(b"infected")
                archive.writestr("../encrypted.bin", b"encrypted payload")
            output = root / "output"
            output.mkdir()

            result = run_extractor(root, output, use_real_pyzipper=True)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "extracted 1 samples\n")
            self.assertEqual(
                (output / "archive-0000-member-0000.sample").read_bytes(),
                b"encrypted payload",
            )

    def test_malformed_archive_fails_without_reporting_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "testdata/live-samples"
            live.mkdir(parents=True)
            (live / "broken.zip").write_bytes(b"not a zip")
            output = root / "output"
            output.mkdir()

            result = run_extractor(root, output)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("BadZipFile", result.stderr)
            self.assertNotIn("extracted ", result.stderr)
            self.assertEqual(list(output.iterdir()), [])

    def test_output_error_is_not_counted_as_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_zip(root / "testdata/live-samples/a.zip", [("sample", b"data")])
            output = root / "not-a-directory"
            output.write_bytes(b"owned")

            result = run_extractor(root, output)

            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("extracted 1 samples", result.stderr)
            self.assertEqual(output.read_bytes(), b"owned")

    def test_directory_skip_repair_removal_changes_count_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_hostile_archives(root)
            output = root / "output"
            output.mkdir()
            source = embedded_extractor()
            mutant = source.replace(
                "if info.is_dir() or member_type not in (0, stat.S_IFREG):",
                "if False:",
            )
            self.assertNotEqual(mutant, source)

            result = run_extractor(root, output, mutant)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "extracted 6 samples\n")
            self.assertEqual(len(list(output.iterdir())), 6)


if __name__ == "__main__":
    unittest.main()
