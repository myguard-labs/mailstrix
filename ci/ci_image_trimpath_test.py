"""Guards: release go builds use -trimpath; image repo names stay consistent."""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker/Dockerfile"
VALUES = ROOT / "contrib/deploy/helm/mailstrix/values.yaml"
README = ROOT / "README.md"
COMPOSE = ROOT / "docker/docker-compose.yml"
CONTRIB = ROOT / "contrib"

DOCKER_COMMAND = re.compile(
    r"^[ \t]*(?:\$ )?(?:sudo )?(?:timeout \S+ )?docker (?:run|build|buildx build)\b"
    r"(?:.*\\\n)*.*$",
    re.MULTILINE,
)
# Optional registry/owner path segments, so ghcr.io/x/mailstrix is reported, not skipped.
# A ref starts with a word character and cannot follow $ or :, so bind-mount
# paths such as ./x/mailstrix, $PWD/mailstrix or :/etc/mailstrix are not images.
# A registry segment may carry a port (localhost:5000/...).
IMAGE_REF = re.compile(
    r"(?<![\w./$:-])((?:\w[\w.-]*(?::\d+)?/)+mailstrix)(?::[\w.-]+)?(?![\w/-])"
)


def build_stage(text: str) -> str:
    match = re.search(r"^FROM [^\n]* AS build\b.*?(?=^FROM |\Z)", text, re.DOTALL | re.MULTILINE)
    if not match:
        raise AssertionError("no build stage in Dockerfile")
    return match.group(0)


def untrimmed_builds(text: str) -> list[str]:
    """Return go build commands writing /out/* binaries without -trimpath."""
    stage = build_stage(text).replace("\\\n", " ")
    cmds = [c for c in re.split(r"&&", stage) if re.search(r"\bgo build\b", c)]
    shipped = [c for c in cmds if re.search(r"-o\s+/out/", c)]
    if not shipped:
        raise AssertionError("no shipped go build found")
    return [c.strip()[:80] for c in shipped if "-trimpath" not in c]


def chart_repo(values: str) -> str:
    match = re.search(r"^image:\s*\n\s+repository:\s*(\S+)", values, re.MULTILINE)
    if not match:
        raise AssertionError("no image.repository in values.yaml")
    return match.group(1)


def readme_run_images(readme: str) -> list[str]:
    """Return the image (last token) of every `docker run` command."""
    commands = re.findall(r"^docker run\b(?:.*\\\n)*.*$", readme, re.MULTILINE)
    if not commands:
        raise AssertionError("no docker run command in README")
    return [command.split()[-1] for command in commands]


def doc_command_images(text: str) -> list[str]:
    """Return every <owner>/mailstrix image named inside a docker run/build command."""
    return [
        ref
        for command in DOCKER_COMMAND.findall(text)
        for ref in IMAGE_REF.findall(command)
    ]


def doc_files() -> list[pathlib.Path]:
    return [README, *sorted(CONTRIB.glob("**/README.md"))]


def compose_repo(compose: str) -> str:
    match = re.search(r"^\s*image:\s*([^\s:]+)", compose, re.MULTILINE)
    if not match:
        raise AssertionError("no image in compose file")
    return match.group(1)


class TrimpathTest(unittest.TestCase):
    def test_every_shipped_build_is_trimpath(self) -> None:
        self.assertEqual(untrimmed_builds(DOCKERFILE.read_text()), [])

    def test_three_binaries_checked(self) -> None:
        stage = build_stage(DOCKERFILE.read_text()).replace("\\\n", " ")
        outs = re.findall(r"-o\s+(/out/\S+)", stage)
        self.assertEqual(
            sorted(outs), ["/out/strix-milter", "/out/strix-scan", "/out/strixd"]
        )

    def test_negative_control_missing_trimpath_detected(self) -> None:
        mutated = DOCKERFILE.read_text().replace(
            "CGO_ENABLED=0 go build -trimpath", "CGO_ENABLED=0 go build", 1
        )
        self.assertNotEqual(mutated, DOCKERFILE.read_text())
        found = untrimmed_builds(mutated)
        self.assertEqual(len(found), 1)
        self.assertIn("go build", found[0])

    def test_negative_control_no_build_stage(self) -> None:
        with self.assertRaises(AssertionError):
            untrimmed_builds("FROM alpine AS final\nRUN true\n")


class ImageRepoTest(unittest.TestCase):
    def test_chart_matches_readme_and_compose(self) -> None:
        repo = chart_repo(VALUES.read_text())
        self.assertEqual(repo, "eilandert/mailstrix")
        self.assertEqual(repo, compose_repo(COMPOSE.read_text()))
        images = readme_run_images(README.read_text())
        self.assertEqual(len(images), 3)
        self.assertEqual(set(images), {repo})
        self.assertIn(f"hub.docker.com/r/{repo}", README.read_text())

    def test_negative_control_migrated_repo_detected(self) -> None:
        mutated = VALUES.read_text().replace("eilandert/", "myguard-labs/", 1)
        self.assertNotEqual(chart_repo(mutated), compose_repo(COMPOSE.read_text()))

    def test_negative_control_one_stale_readme_run_detected(self) -> None:
        text = README.read_text()
        needle = "    eilandert/mailstrix\n"
        last = text.rindex(needle)
        mutated = text[:last] + "    myguard-labs/mailstrix\n" + text[last + len(needle) :]
        self.assertNotEqual(mutated, text)
        self.assertEqual(
            set(readme_run_images(mutated)),
            {"eilandert/mailstrix", "myguard-labs/mailstrix"},
        )

    def test_malformed_readme(self) -> None:
        with self.assertRaises(AssertionError):
            readme_run_images("no commands here\n")

    def test_docs_docker_commands_use_chart_image(self) -> None:
        repo = chart_repo(VALUES.read_text())
        found = {
            str(path.relative_to(ROOT)): doc_command_images(path.read_text())
            for path in doc_files()
        }
        drift = {name: refs for name, refs in found.items() if set(refs) - {repo}}
        self.assertEqual(drift, {})
        # README: three runs and one build; contrib: clamd, postfix, sieve and
        # spamassassin runs (the last two indented inside list items).
        self.assertEqual(sum(len(refs) for refs in found.values()), 8)
        for name in (
            "contrib/clamd/README.md",
            "contrib/postfix/README.md",
            "contrib/sieve/README.md",
            "contrib/spamassassin/README.md",
        ):
            self.assertEqual(found[name], [repo], name)

    def test_negative_control_contrib_drift_detected(self) -> None:
        text = (CONTRIB / "clamd/README.md").read_text()
        mutated = text.replace("  eilandert/mailstrix\n", "  myguard-labs/mailstrix\n", 1)
        self.assertNotEqual(mutated, text)
        self.assertEqual(doc_command_images(mutated), ["myguard-labs/mailstrix"])

    def test_negative_control_build_tag_drift_detected(self) -> None:
        text = "docker build --target final -t myguard-labs/mailstrix:debian \\\n    .\n"
        self.assertEqual(doc_command_images(text), ["myguard-labs/mailstrix"])

    def test_negative_control_registry_prefixed_drift_detected(self) -> None:
        text = "docker run --rm \\\n    ghcr.io/myguard-labs/mailstrix:latest\n"
        self.assertEqual(doc_command_images(text), ["ghcr.io/myguard-labs/mailstrix"])

    def test_negative_control_registry_port_drift_detected(self) -> None:
        text = "docker run --rm localhost:5000/myguard-labs/mailstrix:latest\n"
        self.assertEqual(
            doc_command_images(text), ["localhost:5000/myguard-labs/mailstrix"]
        )

    def test_prefixed_command_forms_checked(self) -> None:
        text = (
            "$ docker run --rm myguard-labs/mailstrix\n"
            "sudo docker run --rm myguard-labs/mailstrix\n"
            "docker buildx build -t myguard-labs/mailstrix .\n"
        )
        self.assertEqual(doc_command_images(text), ["myguard-labs/mailstrix"] * 3)

    def test_bind_mount_paths_ignored(self) -> None:
        text = (
            "docker run -v ./myguard-labs/mailstrix:/work \\\n"
            '    -v "$PWD/mailstrix:/etc/mailstrix:ro" eilandert/mailstrix\n'
        )
        self.assertEqual(doc_command_images(text), ["eilandert/mailstrix"])

    def test_non_image_mentions_ignored(self) -> None:
        text = (
            "See https://github.com/myguard-labs/mailstrix/releases and\n"
            "an interim default of `myguard-labs/mailstrix` in prose.\n"
            "docker run -v /run/secrets/mailstrix_token:/t:ro \\\n"
            "    -t strixd-test eilandert/mailstrix\n"
        )
        self.assertEqual(doc_command_images(text), ["eilandert/mailstrix"])

    def test_malformed_values(self) -> None:
        with self.assertRaises(AssertionError):
            chart_repo("replicaCount: 1\n")


if __name__ == "__main__":
    unittest.main()
