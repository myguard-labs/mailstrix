"""Exercise the real pin gate against harmless temporary repository fixtures."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from immutable_inputs_test import PinFixtures


class WorkflowControls(unittest.TestCase):
    """Each fixture changes a single dependency class; nothing is downloaded."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mailstrix-pin-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write(".github/workflows/ci.yml", "steps:\n  - uses: ./local\n")
        self.write(
            ".github/actions/nested/action.yml",
            "steps:\n  - uses: example/test@" + "a" * 40 + "\n",
        )
        self.write(
            "docker/Dockerfile",
            "FROM example.test/base:1@sha256:"
            + "1" * 64
            + "\n"
            + PinFixtures.yara
            + "\n",
        )
        self.write(".github/workflows/release.yml", PinFixtures.nfpm)

    def write(self, name: str, content: str) -> None:
        """Create only static fixture text below the temporary root."""
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def gate(self) -> subprocess.CompletedProcess[str]:
        """Run the same shell entry point as CI with a fixture root."""
        return subprocess.run(
            [
                "sh",
                str(Path(__file__).with_name("workflow_pins_test.sh")),
                str(self.root),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    def reject(self, marker: str) -> None:
        """Require an observed failure from the expected policy arm."""
        result = self.gate()
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(marker, result.stdout)
        print(result.stdout.strip())

    def test_valid_fixture(self) -> None:
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("ALL OK", result.stdout)

    def test_nested_action_tag(self) -> None:
        self.write(
            ".github/actions/nested/action.yml", "steps:\n  - uses: example/test@v5\n"
        )
        self.reject("third-party action(s) not pinned")

    def test_nested_action_inconsistent_sha(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: example/test@" + "b" * 40 + "\n",
        )
        self.reject("inconsistent pinned action SHAs")

    def test_nested_docker_base_tag(self) -> None:
        self.write("docker/nested/Dockerfile.test", "FROM example.test/base:1\n")
        self.reject("Docker external base must have a sha256 digest")

    def test_contrib_docker_base_tag(self) -> None:
        self.write(
            "contrib/postfix/Dockerfile.integration", "FROM example.test/base:1\n"
        )
        self.reject("Docker external base must have a sha256 digest")

    def test_local_integration_image(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "      run: |\n        docker buildx build --target test -f docker/Dockerfile -t strixd-test --load --progress=plain .\n",
        )
        self.write(
            "contrib/postfix/Dockerfile.integration",
            "ARG BUILD_IMAGE=strixd-test\nFROM ${BUILD_IMAGE} AS binaries\n",
        )
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.write(
            "contrib/postfix/Dockerfile.integration",
            "ARG BUILD_IMAGE=example.test/external:1\nFROM ${BUILD_IMAGE} AS binaries\n",
        )
        self.reject("Docker external base must have a sha256 digest")

    def test_local_image_requires_ci_producer(self) -> None:
        self.write(
            "contrib/postfix/Dockerfile.integration",
            "ARG BUILD_IMAGE=strixd-test\nFROM ${BUILD_IMAGE} AS binaries\n",
        )
        self.reject("Docker external base must have a sha256 digest")

    def test_yara_without_checksum(self) -> None:
        path = self.root / "docker/Dockerfile"
        self.write(
            "docker/Dockerfile",
            path.read_text(encoding="utf-8").replace("sha256sum -c -", "true"),
        )
        self.reject("YARA download must verify")

    def test_nfpm_without_checksum(self) -> None:
        self.write(
            ".github/workflows/release.yml",
            PinFixtures.nfpm.replace("sha256sum -c -", "true"),
        )
        self.reject("nfpm download must verify")


if __name__ == "__main__":
    unittest.main(verbosity=2)
