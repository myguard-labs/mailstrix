"""Exercise the real pin gate against harmless temporary repository fixtures."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import immutable_inputs_test as immutable_inputs

# Test names state their contract; method docstrings would only duplicate them.
# unittest owns TemporaryDirectory cleanup through enterContext.
# pylint: disable=missing-function-docstring,consider-using-with,too-many-public-methods


class TestWorkflowControls(unittest.TestCase):
    """Each fixture changes a single dependency class; nothing is downloaded."""

    def setUp(self) -> None:
        # enterContext owns cleanup for the full unittest case lifetime.
        temporary = self.enterContext(
            tempfile.TemporaryDirectory(prefix="mailstrix-pin-fixture-")
        )
        self.root = Path(temporary)
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: ./.github/actions/nested\n",
        )
        self.write(
            ".github/actions/nested/action.yml",
            "steps:\n  - uses: example/test@" + "a" * 40 + "\n",
        )
        self.write(
            "docker/Dockerfile",
            "FROM example.test/base:1@sha256:"
            + "1" * 64
            + "\n"
            + f"ARG YARA_VERSION={immutable_inputs.PinFixtures.yara_version}\n"
            + immutable_inputs.PinFixtures.yara
            + "\n",
        )
        for name in (
            "docker/Dockerfile.release",
            "docker/profile/Dockerfile.profile",
        ):
            self.write(
                name,
                f"ARG YARA_VERSION={immutable_inputs.PinFixtures.yara_version}\n"
                + immutable_inputs.PinFixtures.yara
                + "\n",
            )
        self.write(".github/workflows/release.yml", immutable_inputs.PinFixtures.nfpm)

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

    def test_flow_style_action_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "jobs:\n  test:\n    steps: [{ uses: example/test@v5 }]\n",
        )
        self.reject("flow-style uses")

    def test_quoted_uses_key_is_scanned(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            'steps:\n  - "uses": example/test@v5\n',
        )
        self.reject("third-party action(s) not pinned")

    def test_go_install_variable_version_is_rejected(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - run: go install example.test/tool@${TOOL_VERSION}\n",
        )
        self.reject("go install without an exact pinned version")

    def test_go_install_output_version_is_exact(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n"
            "  - id: pins\n"
            "    run: |\n"
            '      echo "tool=v1.2.3" >> "$GITHUB_OUTPUT"\n'
            "  - env:\n"
            "      TOOL_VERSION: ${{ steps.pins.outputs.tool }}\n"
            '    run: go install "example.test/tool@${TOOL_VERSION}"\n',
        )
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_local_action_outside_dot_github_is_scanned(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: ./ci/actions/nested\n",
        )
        self.write(
            "ci/actions/nested/action.yml",
            "runs:\n  steps:\n    - uses: example/test@v5\n",
        )
        self.reject("third-party action(s) not pinned")

    def test_local_action_path_with_spaces_is_scanned(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: ./ci/actions/space dir\n",
        )
        self.write(
            "ci/actions/space dir/action.yml",
            "runs:\n  steps:\n    - uses: example/test@v5\n",
        )
        self.reject("third-party action(s) not pinned")

    def test_missing_dot_github_actions_is_valid(self) -> None:
        shutil.rmtree(self.root / ".github/actions")
        self.write(
            ".github/workflows/ci.yml",
            "steps:\n  - uses: example/test@" + "a" * 40 + "\n",
        )
        result = self.gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

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
            "      run: |\n"
            "        docker buildx build --target test -f docker/Dockerfile "
            "-t strixd-test --load .\n",
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

    def test_missing_ci_workflow_fails_without_traceback(self) -> None:
        (self.root / ".github/workflows/ci.yml").unlink()
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

    def test_yara_recipes_must_change_together(self) -> None:
        path = self.root / "docker/profile/Dockerfile.profile"
        self.write(
            "docker/profile/Dockerfile.profile",
            path.read_text(encoding="utf-8").replace(
                immutable_inputs.PinFixtures.yara_digest, "2" * 64
            ),
        )
        self.reject("YARA build recipes must use the same version and checksum")

    def test_added_yara_recipe_uses_reviewed_pin(self) -> None:
        self.write(
            "contrib/new/Dockerfile",
            f"ARG YARA_VERSION={immutable_inputs.PinFixtures.yara_version}\n"
            + immutable_inputs.PinFixtures.yara.replace(
                immutable_inputs.PinFixtures.yara_digest, "2" * 64
            )
            + "\n",
        )
        self.reject("YARA build recipes must use the same version and checksum")

    def test_consistent_unreviewed_yara_pin_is_rejected(self) -> None:
        for name in immutable_inputs.YARA_RECIPE_PATHS:
            path = self.root / name
            self.write(
                name,
                path.read_text(encoding="utf-8").replace(
                    immutable_inputs.PinFixtures.yara_digest, "2" * 64
                ),
            )
        self.reject("YARA version/checksum pair does not match the reviewed pin")

    def test_nfpm_version_checksum_pair_is_reviewed(self) -> None:
        self.write(
            ".github/workflows/release.yml",
            immutable_inputs.PinFixtures.nfpm.replace(
                immutable_inputs.PinFixtures.nfpm_version, "9.99.99"
            ),
        )
        self.reject("nfpm version/checksum pair does not match the reviewed pin")

    def test_nfpm_without_checksum(self) -> None:
        self.write(
            ".github/workflows/release.yml",
            immutable_inputs.PinFixtures.nfpm.replace("sha256sum -c -", "true"),
        )
        self.reject("nfpm download must verify")


if __name__ == "__main__":
    unittest.main(verbosity=2)
