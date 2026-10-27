"""Guards: release go builds use -trimpath; image repo names stay consistent."""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker/Dockerfile"
VALUES = ROOT / "contrib/deploy/helm/mailstrix/values.yaml"
README = ROOT / "README.md"
COMPOSE = ROOT / "docker/docker-compose.yml"


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

    def test_malformed_values(self) -> None:
        with self.assertRaises(AssertionError):
            chart_repo("replicaCount: 1\n")


if __name__ == "__main__":
    unittest.main()
