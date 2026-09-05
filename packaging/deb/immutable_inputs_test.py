"""Check repository Docker pins and the reviewed YARA/nfpm download recipes.

This is a static repository policy, not a general shell or Dockerfile analyzer.
The download recipes deliberately accept one fail-fast command shape; changes to
that shape require updating its positive and negative fixtures together.
"""

import re
import sys
import unittest
from pathlib import Path

# Test names state their contract; method docstrings would only duplicate them.
# pylint: disable=missing-function-docstring

HEX64 = r"[0-9a-f]{64}"
IMAGE_PINS = {
    "debian:bookworm-slim": (
        "88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
    ),
    "docker/dockerfile:1": (
        "ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32"
    ),
    "gcr.io/distroless/base-debian12:nonroot": (
        "7f0c72cd138b442ae0deeb69c08b1acf5525439ba251a49ad93c320a061567e5"
    ),
    "golang:1.25.13-bookworm": (
        "e401dae1bf814e29204a8cb7915682e1780951e609ca0dd8865ee1937f510c48"
    ),
}
PINNED_IMAGE_REPOSITORIES = {image.rsplit(":", 1)[0] for image in IMAGE_PINS}
YARA_PINS = {
    "4.5.2": "1f87056fcb10ee361936ee7b0548444f7974612ebb0e681734d8de7df055d1ec"
}
NFPM_PINS = {
    "2.43.0": "4a4402f8f9ea87c669d6a62b333f8e268439974754dd886a01731ecaf9fa6d66"
}
YARA_RECIPE_PATHS = (
    "docker/Dockerfile",
    "docker/Dockerfile.release",
    "docker/profile/Dockerfile.profile",
)
BLOCK_USES = re.compile(
    r"""^\s*(?:-\s*)?(?:uses|"uses"|'uses')\s*:\s*(?:"([^"]+)"|'([^']+)'|([^#]+?))\s*(?:#.*)?$"""
)
FLOW_USES = re.compile(r"""[{,]\s*(?:uses|"uses"|'uses')\s*:""")
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


def _image_repository(image: str) -> str:
    """Return an image repository without its final tag."""
    slash = image.rfind("/")
    colon = image.rfind(":")
    return image[:colon] if colon > slash else image


def _pin_association_errors(image: str) -> list[str]:
    """Bind reviewed readable image labels to their verified index digests."""
    label, separator, digest = image.partition("@sha256:")
    if not separator or _image_repository(label) not in PINNED_IMAGE_REPOSITORIES:
        return []
    expected = IMAGE_PINS.get(label)
    if expected is None:
        return ["Docker image label has no reviewed digest: " + label]
    if digest != expected:
        return [
            "Docker image label/digest pair does not match the reviewed pin: " + label
        ]
    return []


def _expand_args(value: str, args: dict[str, str]) -> str:
    """Expand Docker ARG defaults used by FROM labels for static comparison."""
    return re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda match: args.get(match.group(1), match.group(0)),
        value,
    )


def _docker_image_errors(
    image: str,
    raw_image: str,
    stages: set[str],
    local_images: frozenset[str],
) -> list[str]:
    """Validate one FROM image after Docker ARG expansion."""
    if image.lower() in stages or raw_image in local_images:
        return []
    if not re.fullmatch(r"\S+@sha256:" + HEX64, image):
        return ["Docker external base must have a sha256 digest: " + image]
    return _pin_association_errors(image)


def _frontend_errors(frontend: str) -> list[str]:
    """Validate one Dockerfile frontend reference."""
    if not re.fullmatch(r"\S+@sha256:" + HEX64, frontend):
        return ["Docker frontend must have a sha256 digest"]
    return _pin_association_errors(frontend)


def _yaml_uses(text: str) -> tuple[list[tuple[int, str]], list[str]]:
    """Extract supported block-style uses values and reject flow-style steps."""
    uses = []
    errors = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if FLOW_USES.search(line):
            errors.append(
                f"line {lineno}: flow-style uses mappings are unsupported; use block style"
            )
            continue
        match = BLOCK_USES.fullmatch(line)
        if match:
            value = next(value for value in match.groups() if value is not None)
            uses.append((lineno, value.strip()))
    return uses, errors


def _local_uses_file(root: Path, value: str) -> Path | None:
    """Resolve a local action or reusable workflow without permitting escape."""
    relative = Path(value[2:])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    target = root / relative
    if target.is_file() and target.suffix in {".yml", ".yaml"}:
        return target
    for name in ("action.yml", "action.yaml"):
        candidate = target / name
        if candidate.is_file():
            return candidate
    return None


def _resolved_go_version(text: str, variable: str) -> str | None:
    """Resolve one workflow output-backed tool version without shell overrides."""
    env_pattern = (
        rf"(?m)^\s*{re.escape(variable)}:\s*\$\{{\{{\s*steps\."
        r"[A-Za-z0-9_-]+\.outputs\.([A-Za-z0-9_-]+)\s*\}\}\s*$"
    )
    outputs = set(re.findall(env_pattern, text))
    if len(outputs) != 1:
        return None
    output = next(iter(outputs))
    version_pattern = (
        rf'(?m)^\s*echo\s+"{re.escape(output)}='
        r'(v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)"(?:\s*>>.*)?$'
    )
    versions = set(re.findall(version_pattern, text))
    overridden = re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(variable)}=", text)
    return next(iter(versions)) if len(versions) == 1 and not overridden else None


def _go_install_errors(root: Path, path: Path, text: str) -> list[str]:
    """Reject mutable Go tool versions in workflow shell blocks."""
    errors = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for match in re.finditer(r'go install\s+"?([^"\s]+)', line):
            ref = match.group(1)
            exact = re.search(r"@v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$", ref)
            variable = re.search(r"@\$\{([A-Za-z_][A-Za-z0-9_]*)\}$", ref)
            if exact or (variable and _resolved_go_version(text, variable.group(1))):
                continue
            relative = path.relative_to(root)
            errors.append(
                f"{relative}:{lineno}: "
                f"go install without an exact pinned version: {ref}"
            )
    return errors


def _uses_errors(
    root: Path, path: Path, text: str
) -> tuple[list[str], list[Path], list[tuple[str, str]]]:
    """Validate uses entries and return local manifests plus immutable pins."""
    errors: list[str] = []
    local_files: list[Path] = []
    pins: list[tuple[str, str]] = []
    uses, parse_errors = _yaml_uses(text)
    relative = path.relative_to(root)
    errors.extend(f"{relative}: {error}" for error in parse_errors)
    for lineno, value in uses:
        if value.startswith("./"):
            manifest = _local_uses_file(root, value)
            if manifest is None:
                errors.append(
                    f"{relative}:{lineno}: local action manifest not found: {value}"
                )
            else:
                local_files.append(manifest)
            continue
        match = re.fullmatch(r"([A-Za-z0-9._/-]+)@([0-9a-f]{40})", value)
        if match is None:
            errors.append(
                f"{relative}:{lineno}: third-party action(s) not pinned "
                f"to a full commit SHA: {value}"
            )
        else:
            pins.append((match.group(1), match.group(2)))
    return errors, local_files, pins


def workflow_errors(root: Path) -> list[str]:
    """Recursively enforce action and Go-tool pins from every workflow entry."""
    errors: list[str] = []
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    workflows += sorted((root / ".github/workflows").glob("*.yaml"))
    if not workflows:
        return [f"no workflows found under {root / '.github/workflows'}"]

    actions_root = root / ".github/actions"
    queued = list(workflows)
    if actions_root.is_dir():
        queued.extend(sorted(actions_root.rglob("*.yml")))
        queued.extend(sorted(actions_root.rglob("*.yaml")))

    seen = set()
    action_pins: dict[str, set[str]] = {}
    while queued:
        path = queued.pop(0)
        if path in seen:
            continue
        seen.add(path)
        text = path.read_text(encoding="utf-8")
        uses_errors, local_files, pins = _uses_errors(root, path, text)
        errors.extend(uses_errors)
        queued.extend(local_files)
        for action, sha in pins:
            action_pins.setdefault(action, set()).add(sha)
        errors.extend(_go_install_errors(root, path, text))

    for action, shas in sorted(action_pins.items()):
        if len(shas) > 1:
            errors.append(
                "inconsistent pinned action SHAs: "
                f"{action} pinned to multiple SHAs: {' '.join(sorted(shas))}"
            )
    return errors


def docker_errors(text: str, local_images: frozenset[str] = frozenset()) -> list[str]:
    """Require immutable external images and checked YARA extraction."""
    errors = []
    stages = {"scratch"}
    args = {}
    yara_recipes = 0
    # Join only Docker continuation lines; command chaining remains significant.
    logical = re.sub(r"[ \t]*\\\n\s*", " ", text)
    for line in logical.splitlines():
        line = line.strip()
        yara_recipes += bool(re.fullmatch(YARA_RECIPE, line))
        arg = re.fullmatch(r"ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line)
        if arg:
            args[arg.group(1)] = arg.group(2)
        directive = re.fullmatch(r"#\s*syntax\s*=\s*(\S+)", line, re.IGNORECASE)
        if directive:
            errors.extend(_frontend_errors(directive.group(1)))
        if re.match(r"FROM\s", line, re.IGNORECASE):
            fields = line.split()
            if fields[1].startswith("--platform="):
                fields.pop(1)
            raw_image = fields[1]
            image = _expand_args(raw_image, args)
            errors.extend(_docker_image_errors(image, raw_image, stages, local_images))
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


def yara_pin(text: str) -> tuple[str, str] | None:
    """Return the single checked YARA version/checksum tuple from a recipe."""
    version = re.search(r"(?m)^ARG YARA_VERSION=([^\s]+)$", text)
    logical = re.sub(r"[ \t]*\\\n\s*", " ", text)
    checksums = []
    for line in logical.splitlines():
        line = line.strip()
        if re.fullmatch(YARA_RECIPE, line):
            match = re.search(r'echo "(' + HEX64 + r')  /tmp/yara\.tar\.gz"', line)
            if match:
                checksums.append(match.group(1))
    if version is None or len(checksums) != 1:
        return None
    return version.group(1), checksums[0]


def _nfpm_pin_error(lines: list[str], recipe: str) -> str | None:
    """Validate the reviewed nfpm version/checksum pair in one recipe."""
    version = re.search(r"(?m)^NFPM_VERSION=([^\s]+)$", "\n".join(lines))
    checksum = re.search(r'echo "(' + HEX64 + r')  /tmp/nfpm\.deb"', recipe)
    if (
        version is None
        or checksum is None
        or NFPM_PINS.get(version.group(1)) != checksum.group(1)
    ):
        return "nfpm version/checksum pair does not match the reviewed pin"
    return None


def release_errors(text: str) -> list[str]:
    """Require the nfpm download/check/install sequence in a strict shell step."""
    errors = []
    # Inspect each workflow literal run block without treating comments or other
    # steps as evidence that this download was checked.
    blocks = re.findall(r"(?m)^( +)run: \|\s*\n((?:\1 +[^\n]*\n|\s*\n)*)", text + "\n")
    downloads = 0
    checked = 0
    pin_errors = []
    for _, block in blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        downloads += sum("github.com/goreleaser/nfpm/" in line for line in lines)
        for index, line in enumerate(lines):
            if "github.com/goreleaser/nfpm/" not in line:
                continue
            recipe = "\n".join(lines[index : index + 3])
            if lines[0] == "set -euo pipefail" and re.fullmatch(NFPM_RECIPE, recipe):
                checked += 1
                pin_error = _nfpm_pin_error(lines, recipe)
                if pin_error:
                    pin_errors.append(pin_error)
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
    errors.extend(pin_errors)
    return errors


class PinFixtures(unittest.TestCase):
    """Benign static fixtures exercise each new policy arm and its boundary."""

    digest = "1" * 64
    yara_version, yara_digest = next(iter(YARA_PINS.items()))
    nfpm_version, nfpm_digest = next(iter(NFPM_PINS.items()))
    yara = (
        f"RUN curl -fsSL {YARA_URL} -o /tmp/yara.tar.gz "
        f'&& echo "{yara_digest}  /tmp/yara.tar.gz" | sha256sum -c - '
        "&& tar -xzf /tmp/yara.tar.gz -C /tmp && rm /tmp/yara.tar.gz"
    )
    nfpm = (
        "      run: |\n        set -euo pipefail\n"
        f"        NFPM_VERSION={nfpm_version}\n"
        f"        curl -fsSL {NFPM_URL} -o /tmp/nfpm.deb\n"
        f'        echo "{nfpm_digest}  /tmp/nfpm.deb" | sha256sum -c -\n'
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
        self.assertEqual(
            [], docker_errors(f"#syntax=example.test/frontend:1@sha256:{self.digest}")
        )
        self.assertIn(
            "Docker frontend", docker_errors("# syntax=example.test/frontend:1")[0]
        )
        self.assertIn(
            "Docker frontend", docker_errors("#syntax=example.test/frontend:1")[0]
        )

    def test_known_image_label_matches_reviewed_digest(self) -> None:
        digest = IMAGE_PINS["golang:1.25.13-bookworm"]
        recipe = (
            "ARG GO_VERSION=1.25.13\n"
            f"FROM golang:${{GO_VERSION}}-bookworm@sha256:{digest}\n"
        )
        self.assertEqual([], docker_errors(recipe))
        self.assertIn(
            "label has no reviewed digest",
            docker_errors(recipe.replace("1.25.13", "9.99.99"))[0],
        )
        self.assertIn(
            "label/digest pair",
            docker_errors(recipe.replace(digest, "2" * 64))[0],
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
            "YARA download",
            docker_errors(self.yara.replace(self.yara_digest, "bad"))[0],
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
            "nfpm download",
            release_errors(self.nfpm.replace(self.nfpm_digest, "bad"))[0],
        )
        self.assertIn(
            "reviewed pin",
            release_errors(self.nfpm.replace(self.nfpm_version, "9.99.99"))[0],
        )
        self.assertIn(
            "reviewed pin",
            release_errors(self.nfpm.replace(self.nfpm_digest, "2" * 64))[0],
        )
        self.assertIn(
            "nfpm download",
            release_errors(self.nfpm.replace("github.com", "example.test"))[0],
        )
        lines = self.nfpm.splitlines()
        lines[-1], lines[-2] = lines[-2], lines[-1]
        self.assertIn("nfpm download", release_errors("\n".join(lines))[0])


def _local_images_for(root: Path, path: Path, text: str) -> frozenset[str]:
    """Return the one repository-produced image allowed by the integration test."""
    if path.relative_to(root).as_posix() != "contrib/postfix/Dockerfile.integration":
        return frozenset()
    ci_workflow = root / ".github/workflows/ci.yml"
    if not ci_workflow.is_file():
        return frozenset()
    workflow = ci_workflow.read_text(encoding="utf-8")
    workflow = re.sub(r"[ \t]*\\\n\s*", " ", workflow)
    producer = re.search(
        r"(?m)^\s*docker buildx build --target test -f docker/Dockerfile "
        r"-t strixd-test --load(?: [^\n]*?)? \.$",
        workflow,
    )
    if producer and re.search(r"(?m)^ARG BUILD_IMAGE=strixd-test$", text):
        return frozenset({"${BUILD_IMAGE}"})
    return frozenset()


def _yara_tree_errors(root: Path, dockerfiles: list[Path]) -> list[str]:
    """Require every YARA recipe to share one reviewed version/checksum."""
    required = [root / relative for relative in YARA_RECIPE_PATHS]
    missing = [path for path in required if not path.is_file()]
    errors = [
        f"missing required YARA build recipe: {path.relative_to(root)}"
        for path in missing
    ]
    paths = {
        path
        for path in dockerfiles
        if re.search(r"(?m)^ARG YARA_VERSION(?:=|$)", path.read_text(encoding="utf-8"))
    }
    pins = {}
    for path in sorted(paths):
        pin = yara_pin(path.read_text(encoding="utf-8"))
        if pin is None:
            errors.append(f"unreadable YARA build pin: {path.relative_to(root)}")
        else:
            pins[path] = pin
    if errors:
        return errors
    if not pins or len(set(pins.values())) != 1:
        return ["YARA build recipes must use the same version and checksum"]
    version, checksum = next(iter(pins.values()))
    if YARA_PINS.get(version) != checksum:
        return ["YARA version/checksum pair does not match the reviewed pin"]
    return []


def check_tree(root: Path) -> list[str]:
    """Scan root/docker/contrib Dockerfiles and recursive GitHub YAML files."""
    errors = workflow_errors(root)
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
        # The Postfix integration image consumes binaries built from this
        # checkout by CI. Only that exact producer/consumer pair is exempt;
        # other ARG-based FROM references must carry literal digest pins.
        local_images = _local_images_for(root, path, text)
        errors.extend(
            f"{path.relative_to(root)}: {error}"
            for error in docker_errors(
                text,
                local_images,
            )
        )
    errors.extend(_yara_tree_errors(root, dockerfiles))
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
    print("ok   - every third-party action is pinned to a full commit SHA")
    print("ok   - every go install pins an exact version")
    print("ok   - every SHA-pinned action is consistent across all workflows")
    print("ok   - Docker images and YARA/nfpm downloads have immutable pins")
