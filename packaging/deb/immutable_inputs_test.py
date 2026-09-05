"""Check repository Docker pins and the reviewed YARA/nfpm download recipes.

This is a static repository policy, not a general shell or Dockerfile analyzer.
The download recipes deliberately accept one fail-fast command shape; changes to
that shape require updating its positive and negative fixtures together.
"""

import re
import sys
import unittest
from pathlib import Path

HEX64 = r"[0-9a-f]{64}"
YARA_URL = (
    '"https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"'
)
YARA_RECIPE = (
    "RUN curl -fsSL "
    + re.escape(YARA_URL)
    + r' -o /tmp/yara\.tar\.gz && echo "'
    + HEX64
    + r'  /tmp/yara\.tar\.gz" \| sha256sum -c -'
    + r" && tar -xzf /tmp/yara\.tar\.gz -C /tmp && rm /tmp/yara\.tar\.gz"
)
NFPM_URL = (
    '"https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/'
    'nfpm_${NFPM_VERSION}_amd64.deb"'
)
NFPM_RECIPE = (
    r"curl -fsSL "
    + re.escape(NFPM_URL)
    + r" -o /tmp/nfpm\.deb\n"
    + r'echo "'
    + HEX64
    + r'  /tmp/nfpm\.deb" \| sha256sum -c -\n'
    + r"sudo dpkg -i /tmp/nfpm\.deb"
)


def docker_errors(text: str, local_images: frozenset[str] = frozenset()) -> list[str]:
    """Require immutable external images and checked YARA extraction."""
    errors = []
    stages = {"scratch"}
    yara_recipes = 0
    # Join only Docker continuation lines; command chaining remains significant.
    logical = re.sub(r"[ \t]*\\\n\s*", " ", text)
    for line in logical.splitlines():
        line = line.strip()
        yara_recipes += bool(re.fullmatch(YARA_RECIPE, line))
        if line.lower().startswith("# syntax=") and not re.fullmatch(
            r"# syntax=\S+@sha256:" + HEX64, line
        ):
            errors.append("Docker frontend must have a sha256 digest")
        if re.match(r"FROM\s", line, re.IGNORECASE):
            fields = line.split()
            if fields[1].startswith("--platform="):
                fields.pop(1)
            image = fields[1]
            if (
                image.lower() not in stages
                and image not in local_images
                and not re.fullmatch(r"\S+@sha256:" + HEX64, image)
            ):
                errors.append(
                    "Docker external base must have a sha256 digest: " + image
                )
            if len(fields) == 4 and fields[2].lower() == "as":
                stages.add(fields[3].lower())
        if (
            "github.com/VirusTotal/yara/" in line
            and not line.startswith("#")
            and not re.fullmatch(YARA_RECIPE, line)
        ):
            errors.append(
                "YARA download must verify a pinned checksum before extraction"
            )
    if re.search(r"(?m)^ARG YARA_VERSION(?:=|$)", text) and yara_recipes != 1:
        errors.append("YARA build must contain exactly one checked source download")
    return errors


def release_errors(text: str) -> list[str]:
    """Require the nfpm download/check/install sequence in a strict shell step."""
    errors = []
    # Inspect each workflow literal run block without treating comments or other
    # steps as evidence that this download was checked.
    blocks = re.findall(r"(?m)^( +)run: \|\s*\n((?:\1 +[^\n]*\n|\s*\n)*)", text + "\n")
    downloads = 0
    checked = 0
    for _, block in blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        downloads += sum("github.com/goreleaser/nfpm/" in line for line in lines)
        for index, line in enumerate(lines):
            if "github.com/goreleaser/nfpm/" not in line:
                continue
            recipe = "\n".join(lines[index : index + 3])
            if lines[0] == "set -euo pipefail" and re.fullmatch(NFPM_RECIPE, recipe):
                checked += 1
    # Count across the whole document as well, so an unsupported run style fails
    # closed instead of disappearing from the parsed block set.
    total = sum(
        "github.com/goreleaser/nfpm/" in line
        for line in text.splitlines()
        if not line.lstrip().startswith("#")
    )
    installs = len(re.findall(r"(?m)^\s*sudo dpkg -i /tmp/nfpm\.deb\s*$", text))
    if total != checked or downloads != checked or installs != checked:
        errors.append("nfpm download must verify a pinned checksum before sudo install")
    return errors


class PinFixtures(unittest.TestCase):
    """Benign static fixtures exercise each new policy arm and its boundary."""

    digest = "1" * 64
    yara = (
        f"RUN curl -fsSL {YARA_URL} -o /tmp/yara.tar.gz "
        f'&& echo "{"1" * 64}  /tmp/yara.tar.gz" | sha256sum -c - '
        "&& tar -xzf /tmp/yara.tar.gz -C /tmp && rm /tmp/yara.tar.gz"
    )
    nfpm = (
        "      run: |\n        set -euo pipefail\n"
        f"        curl -fsSL {NFPM_URL} -o /tmp/nfpm.deb\n"
        f'        echo "{"1" * 64}  /tmp/nfpm.deb" | sha256sum -c -\n'
        "        sudo dpkg -i /tmp/nfpm.deb\n"
    )

    def test_external_and_local_stages(self) -> None:
        self.assertEqual(
            [],
            docker_errors(
                f"FROM example.test/base:1@sha256:{self.digest} AS builder\n"
                "FROM builder AS test\nFROM scratch AS output\n"
            ),
        )
        self.assertIn(
            "Docker external base", docker_errors("FROM example.test/base:1")[0]
        )
        self.assertIn("Docker external base", docker_errors("FROM unknown_stage")[0])

    def test_frontend(self) -> None:
        self.assertEqual(
            [], docker_errors(f"# syntax=example.test/frontend:1@sha256:{self.digest}")
        )
        self.assertIn(
            "Docker frontend", docker_errors("# syntax=example.test/frontend:1")[0]
        )

    def test_yara_checksum_before_extract(self) -> None:
        self.assertEqual([], docker_errors(self.yara))
        self.assertIn(
            "YARA download", docker_errors(f"RUN curl -fsSL {YARA_URL} | tar -xz")[0]
        )
        self.assertIn(
            "YARA download",
            docker_errors(self.yara.replace("sha256sum -c -", "true"))[0],
        )
        self.assertIn(
            "YARA download", docker_errors(self.yara.replace("&& tar", "; tar"))[0]
        )
        self.assertIn(
            "YARA download", docker_errors(self.yara.replace(self.digest, "bad"))[0]
        )

    def test_nfpm_checksum_before_install(self) -> None:
        self.assertEqual([], release_errors(self.nfpm))
        self.assertIn(
            "nfpm download",
            release_errors(self.nfpm.replace("sha256sum -c -", "true"))[0],
        )
        self.assertIn(
            "nfpm download",
            release_errors(self.nfpm.replace("set -euo pipefail", "set -u"))[0],
        )
        self.assertIn(
            "nfpm download", release_errors(self.nfpm.replace(self.digest, "bad"))[0]
        )
        self.assertIn(
            "nfpm download",
            release_errors(self.nfpm.replace("github.com", "example.test"))[0],
        )
        lines = self.nfpm.splitlines()
        lines[-1], lines[-2] = lines[-2], lines[-1]
        self.assertIn("nfpm download", release_errors("\n".join(lines))[0])


def check_tree(root: Path) -> list[str]:
    """Scan root/docker/contrib Dockerfiles and recursive GitHub YAML files."""
    errors = []
    dockerfiles = sorted(
        [
            *root.glob("Dockerfile*"),
            *root.glob("docker/**/Dockerfile*"),
            *root.glob("contrib/**/Dockerfile*"),
        ]
    )
    if not dockerfiles:
        errors.append("no Dockerfiles found")
    for path in dockerfiles:
        text = path.read_text(encoding="utf-8")
        local_images: frozenset[str] = frozenset()
        # The Postfix integration image consumes binaries built from this
        # checkout by CI. Only that exact producer/consumer pair is exempt;
        # other ARG-based FROM references must carry literal digest pins.
        if (
            path.relative_to(root).as_posix()
            == "contrib/postfix/Dockerfile.integration"
        ):
            workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
            workflow = re.sub(r"[ \t]*\\\n\s*", " ", workflow)
            producer = re.search(
                r"(?m)^\s*docker buildx build --target test -f docker/Dockerfile -t strixd-test --load [^\n]* \.$",
                workflow,
            )
            if producer and re.search(r"(?m)^ARG BUILD_IMAGE=strixd-test$", text):
                local_images = frozenset({"${BUILD_IMAGE}"})
        errors.extend(
            f"{path.relative_to(root)}: {error}"
            for error in docker_errors(
                text,
                local_images,
            )
        )
    for path in sorted((root / ".github").rglob("*")):
        if path.suffix in {".yml", ".yaml"} and path.is_file():
            errors.extend(
                f"{path.relative_to(root)}: {error}"
                for error in release_errors(path.read_text(encoding="utf-8"))
            )
    return errors


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PinFixtures)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
    problems = check_tree(Path(sys.argv[1]))
    for problem in problems:
        print("FAIL - " + problem)
    if problems:
        sys.exit(1)
    print("ok   - Docker images and YARA/nfpm downloads have immutable pins")
