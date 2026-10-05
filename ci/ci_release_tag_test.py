"""Exercise the release image's asset URL selection without building an image."""

import os
import re
import shutil
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
    checksums = ''.join(
        hashlib.sha256(name.encode()).hexdigest() + '  ' + name + '-linux-' + arch + '\\n'
        for name in names
    )
    mode = os.environ.get('CHECKSUM_MODE', '')
    if mode == 'corrupt':
        checksums = checksums.replace(checksums[:64], '0' * 64, 1)
    elif mode == 'missing':
        checksums = ''.join(checksums.splitlines(keepends=True)[1:])
    elif mode == 'duplicate':
        checksums += checksums.splitlines(keepends=True)[0]
    target.write_text(checksums)
else:
    target.write_bytes(target.name.split('-linux-', 1)[0].encode())
""",
        encoding="utf-8",
    )
    curl.chmod(0o755)


def run_commands(
    version,
    release_tag=None,
    *,
    arch="arm64",
    milter=True,
    fail_download=False,
    cachebust=None,
    trace=False,
    checksum_mode="",
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
            CHECKSUM_MODE=checksum_mode,
            URL_LOG=str(root / "urls"),
            EXPECTED_RELEASE_URL=RELEASE_URL,
            PATH=f"{bin_dir}:{env['PATH']}",
        )
        if release_tag is None:
            env.pop("RELEASE_TAG", None)
        else:
            env["RELEASE_TAG"] = release_tag
        if cachebust is None:
            env.pop("CACHEBUST", None)
        else:
            env["CACHEBUST"] = cachebust
        result = subprocess.run(
            ["sh", "-exc" if trace else "-ec", command],
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
        result, urls, binaries = run_commands(
            "1.2.0", "nightly", milter=False, cachebust="build-sha"
        )
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
        result, urls, binaries = run_commands(
            "", "nightly", milter=False, cachebust="build-sha"
        )
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

    def test_nightly_requires_nonempty_cachebust_before_download(self):
        for cachebust in (None, ""):
            with self.subTest(cachebust=cachebust):
                result, urls, _ = run_commands("1.2.0", "nightly", cachebust=cachebust)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "CACHEBUST build-arg is required for nightly", result.stderr
                )
                self.assertEqual(urls, [])

    def test_nightly_cachebust_is_consumed_by_fetch_run(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        fetch = source.split(" AS fetch\n", 1)[1].split("\nFROM ", 1)[0]
        self.assertRegex(fetch, r"(?m)^ARG CACHEBUST$")
        self.assertLess(fetch.index("ARG CACHEBUST"), fetch.index("RUN VER="))
        for token in ("build-sha-a", "build-sha-b"):
            with self.subTest(token=token):
                result, urls, _ = run_commands(
                    "", "nightly", cachebust=token, trace=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"+ test -n {token}", result.stderr)
                self.assertEqual(urls[0], f"{RELEASE_URL}/nightly/SHA256SUMS")

    def test_stable_release_override_needs_no_cachebust(self):
        result, urls, _ = run_commands("1.2.0", "v2.0.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(urls[0], f"{RELEASE_URL}/v2.0.0/SHA256SUMS")

    def test_bad_checksums_never_install_binaries(self):
        for mode in ("corrupt", "missing", "duplicate"):
            with self.subTest(mode=mode):
                result, _, binaries = run_commands("1.3.0", checksum_mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(binaries, [])

    def test_build_version_oci_label(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        final = source.split(" AS final\n", 1)[1]
        self.assertRegex(source.split("\nFROM ", 1)[0], r"(?m)^ARG VERSION$")
        self.assertRegex(source.split("\nFROM ", 1)[0], r"(?m)^ARG RELEASE_TAG$")
        self.assertRegex(final, r"(?m)^ARG VERSION$")
        self.assertRegex(final, r"(?m)^ARG RELEASE_TAG$")
        self.assertRegex(
            final, r"(?m)^ARG BUILD_VERSION=\$\{RELEASE_TAG:-\$\{VERSION\}\}$"
        )
        self.assertRegex(
            final,
            r'(?m)^LABEL org\.opencontainers\.image\.version="\$\{BUILD_VERSION\}"$',
        )
        self.assertEqual(
            len(re.findall(r"org\.opencontainers\.image\.version\s*=", final)), 1
        )

    def test_build_version_label_with_docker_frontend(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        final = source.split(" AS final\n", 1)[1]
        label_lines = [
            line
            for line in final.splitlines()
            if line.startswith(
                (
                    "ARG VERSION",
                    "ARG RELEASE_TAG",
                    "ARG BUILD_VERSION",
                    "LABEL org.opencontainers.image.version",
                )
            )
        ]
        self.assertEqual(len(label_lines), 4)
        dockerfile = "FROM scratch\n" + "\n".join(label_lines) + "\n"
        self.assertIsNotNone(
            shutil.which("docker"), "Docker is required for the frontend contract"
        )
        for index, (version, tag, build_version, expected) in enumerate(
            (
                ("1.2.0", None, None, "1.2.0"),
                ("v1.2.0", "", None, "v1.2.0"),
                ("1.2.0", "v2.0.0", None, "v2.0.0"),
                ("", "nightly", None, "nightly"),
                ("1.2.0", None, "v1.2.0", "v1.2.0"),
            )
        ):
            with self.subTest(version=version, tag=tag, build_version=build_version):
                image_tag = f"mailstrix-label-test:{os.getpid()}-{index}"
                args = [
                    "docker",
                    "build",
                    "--load",
                    "--quiet",
                    "--tag",
                    image_tag,
                    "--build-arg",
                    f"VERSION={version}",
                ]
                if tag is not None:
                    args += ["--build-arg", f"RELEASE_TAG={tag}"]
                if build_version is not None:
                    args += ["--build-arg", f"BUILD_VERSION={build_version}"]
                args += ["-f", "-", "."]
                built = subprocess.run(
                    args, input=dockerfile, text=True, capture_output=True, check=False
                )
                self.assertEqual(built.returncode, 0, built.stderr)
                try:
                    inspect = subprocess.run(
                        [
                            "docker",
                            "image",
                            "inspect",
                            image_tag,
                            "--format",
                            '{{index .Config.Labels "org.opencontainers.image.version"}}',
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(inspect.returncode, 0, inspect.stderr)
                    self.assertEqual(inspect.stdout.strip(), expected)
                finally:
                    subprocess.run(
                        ["docker", "image", "rm", image_tag],
                        capture_output=True,
                        check=False,
                    )


if __name__ == "__main__":
    unittest.main()
