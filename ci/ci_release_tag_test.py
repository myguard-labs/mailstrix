"""Exercise the release image's asset URL selection without building an image."""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

DOCKERFILE = Path(
    os.environ.get(
        "DOCKERFILE_RELEASE_TEST_PATH",
        Path(__file__).resolve().parents[1] / "docker/Dockerfile.release",
    )
)
ASSETS = ("strix-milter", "strix-scan", "strixd")
RELEASE_URL = "https://github.com/myguard-labs/mailstrix/releases/download"


def docker_commands():
    source = DOCKERFILE.read_text(encoding="utf-8")
    guard = re.search(r"^RUN test -n .*", source, re.MULTILINE)
    lines = source.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.startswith("RUN VER=")), None
    )
    if guard is None or start is None:
        raise AssertionError("release guard or fetch command is missing")
    end = start
    while lines[end].endswith("\\"):
        end += 1
    fetch = "\n".join(lines[start : end + 1])
    return guard.group()[4:] + "\n" + fetch[4:]


def write_fake_curl(bin_dir):
    curl = bin_dir / "curl"
    curl.write_text(
        """#!/usr/bin/env python3
import hashlib
import os
import pathlib
import sys

values = iter(sys.argv[1:])
urls = []
target = None
for value in values:
    if value == '-o':
        target = pathlib.Path(next(values))
    elif not value.startswith('-'):
        urls.append(value)
if len(urls) != 1 or target is None:
    sys.exit(23)
url = urls[0]
with open(os.environ['URL_LOG'], 'a', encoding='utf-8') as log:
    print(url, file=log)
prefix = os.environ['EXPECTED_RELEASE_URL'] + '/'
if not url.startswith(prefix) or url.rsplit('/', 1)[-1] != target.name:
    sys.exit(23)
if os.environ.get('FAIL_DOWNLOAD') == '1':
    sys.exit(22)
arch = os.environ['TARGETARCH']
names = ['strixd', 'strix-scan']
if os.environ.get('HAS_MILTER') == '1':
    names.append('strix-milter')
if target.name == 'SHA256SUMS':
    target.write_text(''.join(
        hashlib.sha256(name.encode()).hexdigest() + '  ' + name + '-linux-' + arch + '\\n'
        for name in names
    ))
else:
    target.write_bytes(target.name.split('-linux-', 1)[0].encode())
""",
        encoding="utf-8",
    )
    curl.chmod(0o755)


def run_commands(
    version, release_tag=None, *, arch="arm64", milter=True, fail_download=False
):
    command = docker_commands()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        write_fake_curl(bin_dir)
        env = dict(os.environ)
        env.update(
            VERSION=version,
            TARGETARCH=arch,
            HAS_MILTER="1" if milter else "0",
            FAIL_DOWNLOAD="1" if fail_download else "0",
            URL_LOG=str(root / "urls"),
            EXPECTED_RELEASE_URL=RELEASE_URL,
            PATH=f"{bin_dir}:{env['PATH']}",
        )
        if release_tag is None:
            env.pop("RELEASE_TAG", None)
        else:
            env["RELEASE_TAG"] = release_tag
        result = subprocess.run(
            ["sh", "-ec", command],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        url_log = root / "urls"
        urls = (
            url_log.read_text(encoding="utf-8").splitlines() if url_log.exists() else []
        )
        binaries = sorted(
            path.name for path in bin_dir.iterdir() if path.name != "curl"
        )
        # The Docker command moves verified assets into /out/bin, represented by
        # this temporary directory's bin/ after the fake curl has finished.
        return result, urls, binaries


class ReleaseTagContract(unittest.TestCase):
    def test_release_tag_is_a_fetch_stage_build_arg(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        fetch = source.split(" AS fetch\n", 1)[1].split("\nFROM ", 1)[0]
        self.assertRegex(fetch, r"(?m)^ARG RELEASE_TAG$")
        self.assertLess(fetch.index("ARG RELEASE_TAG"), fetch.index("RUN test -n"))

    def test_release_default_uses_version_and_keeps_arch_assets(self):
        result, urls, binaries = run_commands("v1.2.0", milter=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            urls,
            [
                f"{RELEASE_URL}/v1.2.0/SHA256SUMS",
                f"{RELEASE_URL}/v1.2.0/strixd-linux-arm64",
                f"{RELEASE_URL}/v1.2.0/strix-scan-linux-arm64",
            ],
        )
        self.assertEqual(binaries, ["strix-scan", "strixd"])

    def test_future_release_with_milter_asset(self):
        result, urls, binaries = run_commands("1.3.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            urls,
            [
                f"{RELEASE_URL}/v1.3.0/SHA256SUMS",
                f"{RELEASE_URL}/v1.3.0/strixd-linux-arm64",
                f"{RELEASE_URL}/v1.3.0/strix-scan-linux-arm64",
                f"{RELEASE_URL}/v1.3.0/strix-milter-linux-arm64",
            ],
        )
        self.assertEqual(binaries, list(ASSETS))

    def test_amd64_release_asset_paths(self):
        result, urls, binaries = run_commands("1.2.0", arch="amd64", milter=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            urls,
            [
                f"{RELEASE_URL}/v1.2.0/SHA256SUMS",
                f"{RELEASE_URL}/v1.2.0/strixd-linux-amd64",
                f"{RELEASE_URL}/v1.2.0/strix-scan-linux-amd64",
            ],
        )
        self.assertEqual(binaries, ["strix-scan", "strixd"])

    def test_future_milter_asset_on_amd64(self):
        result, urls, binaries = run_commands("1.3.0", arch="amd64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            urls,
            [
                f"{RELEASE_URL}/v1.3.0/SHA256SUMS",
                f"{RELEASE_URL}/v1.3.0/strixd-linux-amd64",
                f"{RELEASE_URL}/v1.3.0/strix-scan-linux-amd64",
                f"{RELEASE_URL}/v1.3.0/strix-milter-linux-amd64",
            ],
        )
        self.assertEqual(binaries, list(ASSETS))

    def test_nightly_tag_override(self):
        result, urls, binaries = run_commands("1.2.0", "nightly", milter=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            urls,
            [
                f"{RELEASE_URL}/nightly/SHA256SUMS",
                f"{RELEASE_URL}/nightly/strixd-linux-arm64",
                f"{RELEASE_URL}/nightly/strix-scan-linux-arm64",
            ],
        )
        self.assertEqual(binaries, ["strix-scan", "strixd"])

    def test_empty_override_falls_back_and_explicit_tag_needs_no_version(self):
        result, urls, _ = run_commands("1.2.0", "")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(urls[0], f"{RELEASE_URL}/v1.2.0/SHA256SUMS")
        result, urls, binaries = run_commands("", "nightly", milter=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            urls,
            [
                f"{RELEASE_URL}/nightly/SHA256SUMS",
                f"{RELEASE_URL}/nightly/strixd-linux-arm64",
                f"{RELEASE_URL}/nightly/strix-scan-linux-arm64",
            ],
        )
        self.assertEqual(binaries, ["strix-scan", "strixd"])

    def test_missing_selection_and_download_error_fail(self):
        result, urls, _ = run_commands("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VERSION or RELEASE_TAG build-arg is required", result.stderr)
        self.assertEqual(urls, [])
        result, urls, _ = run_commands("1.2.0", fail_download=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(urls), 1)

    def test_build_version_oci_label(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        final = source.split(" AS final\n", 1)[1]
        self.assertRegex(source.split("\nFROM ", 1)[0], r"(?m)^ARG VERSION$")
        self.assertRegex(source.split("\nFROM ", 1)[0], r"(?m)^ARG RELEASE_TAG$")
        self.assertRegex(final, r"(?m)^ARG VERSION$")
        self.assertRegex(final, r"(?m)^ARG RELEASE_TAG$")
        self.assertRegex(
            final, r"(?m)^ARG BUILD_VERSION=\$\{RELEASE_TAG:-v\$\{VERSION#v\}\}$"
        )
        self.assertRegex(
            final,
            r'(?m)^LABEL org\.opencontainers\.image\.version="\$\{BUILD_VERSION\}"$',
        )
        self.assertEqual(
            len(re.findall(r"org\.opencontainers\.image\.version\s*=", final)), 1
        )


if __name__ == "__main__":
    unittest.main()
