"""Deterministic traversal-work oracle for the private Go package bridge.

Collect a count-mode profile for exactly TestP12eNativeClosure/<depth> and pass
its compiler invocation plus the exact runtime source to this script. Timings
are supplemental; visited Go statements prove the work bound, excluding
native/manifest validation and other work outside the helper.
"""

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import ClassVar


def traversal_work(profile, source, graph):
    lines = source.splitlines()
    start = next(
        i + 1
        for i, line in enumerate(lines)
        if line.startswith("func markerRuleClosure(")
    )
    end = next(
        i + start + 1
        for i, line in enumerate(lines[start:])
        if line.startswith("func ")
    )
    rows = profile.splitlines()
    if rows[0] != "mode: count":
        raise ValueError("closure scaling requires count-mode statement evidence")
    visits = 0
    found = False
    for row in rows[1:]:
        match = re.fullmatch(r"(.+):(\d+)\.\d+,\d+\.\d+ (\d+) (\d+)", row)
        if not match:
            raise ValueError("malformed coverage row")
        if match[1].endswith("/marker_artifact.go") and start <= int(match[2]) < end:
            visits += int(match[3]) * int(match[4])
            found = True
    if not found or visits == 0:
        raise ValueError("closure helper was not exercised")
    # Index construction, queue insertion/visits, once-per-namespace globals,
    # ordered result projection and tag scanning each visit a constant number
    # of statements per inventory row/reference/tag. 32 leaves explicit headroom
    # above the implementation's maximum, rather than depending on machine time.
    bound = 32 * (
        len(graph["inventory"])
        + len(graph["references"])
        + sum(len(row.get("tags", [])) for row in graph["inventory"])
        + 1
    )
    return visits, bound


def assert_linear(profile, source, graph):
    visits, bound = traversal_work(profile, source, graph)
    print(
        json.dumps(
            {
                "visited_go_statements": visits,
                "linear_bound": bound,
                "inventory": len(graph["inventory"]),
                "references": len(graph["references"]),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    if visits > bound:
        raise AssertionError("indexed closure traversal exceeds linear statement bound")


def native_ci():
    repo = Path(__file__).resolve().parents[1]
    fixture = repo / "ci/testdata/marker-runtime.zip"
    source = repo / "internal/mailstrix/marker_artifact.go"
    with tempfile.TemporaryDirectory(prefix="mailstrix-closure-ci-") as directory:
        binary = Path(directory) / "marker-closure.test"
        build = [
            "go",
            "test",
            "-c",
            "-tags",
            "yara_static",
            "-covermode=count",
            "-coverpkg=./internal/mailstrix",
            "-o",
            str(binary),
            "./internal/mailstrix",
        ]
        subprocess.run(build, cwd=repo, check=True)
        print(
            json.dumps(
                {
                    "build_argv": build,
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "binary_mtime_ns": binary.stat().st_mtime_ns,
                    "binary_size": binary.stat().st_size,
                    "inputs": {
                        name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                        for name in (
                            "internal/mailstrix/marker_artifact.go",
                            "internal/mailstrix/marker_closure_test.go",
                            "ci/marker_runtime_fixture.py",
                            "ci/ci_marker_closure_test.py",
                            "ci/testdata/marker-runtime.zip",
                        )
                    },
                },
                sort_keys=True,
            ),
            flush=True,
        )
        failed = []
        with zipfile.ZipFile(fixture) as archive:
            for depth in (512, 2048):
                profile = Path(directory) / f"closure-{depth}.coverage"
                command = [
                    str(binary),
                    "-test.v",
                    f"-test.run=^TestP12eNativeClosure/{depth}$",
                    "-test.coverprofile=" + str(profile),
                ]
                print(
                    json.dumps({"run_argv": command, "cwd": "internal/mailstrix"}),
                    flush=True,
                )
                subprocess.run(command, cwd=repo / "internal/mailstrix", check=True)
                graph = json.loads(
                    archive.read(f"native-closure/{depth}/invocation.json")
                )["rule_graph"]
                try:
                    assert_linear(profile.read_text(), source.read_text(), graph)
                except AssertionError:
                    failed.append(depth)
        if failed:
            raise AssertionError(
                "indexed closure traversal exceeds linear statement bound: "
                + ", ".join(map(str, failed))
            )


class ClosureScalingTests(unittest.TestCase):
    source = "func markerRuleClosure(g G) {\n return\n}\nfunc next() {}\n"
    graph: ClassVar[dict] = {"inventory": [{}] * 8, "references": [[0, 1]] * 4}

    def test_indexed_work_and_legacy_negative_control(self):
        profile = "mode: count\nexample/marker_artifact.go:2.1,2.2 2 16\n"
        assert_linear(profile, self.source, self.graph)
        legacy = profile.replace("2 16", "2 1000")
        with self.assertRaisesRegex(
            AssertionError, "indexed closure traversal exceeds linear statement bound"
        ):
            assert_linear(legacy, self.source, self.graph)

    def test_native_ci_lane_is_wired_before_race(self):
        repo = Path(__file__).resolve().parents[1]
        docker = (repo / "docker/Dockerfile").read_text()
        ignore = (repo / ".dockerignore").read_text()
        self.assertIn("!ci/ci_marker_closure_test.py", ignore.splitlines())
        self.assertIn(
            "COPY ci/ci_marker_closure_test.py /src/ci/ci_marker_closure_test.py",
            docker,
        )
        self.assertIn(
            '*" $(go list -m)/internal/mailstrix "*) python3 ci/ci_marker_closure_test.py --native-ci ;;',
            docker,
        )
        self.assertLess(
            docker.index("--native-ci"),
            docker.index("go test -race"),
            "genuine count gate must precede expensive race traversal",
        )

    def test_missing_malformed_and_wrong_mode_profiles(self):
        for profile in (
            "mode: atomic\n",
            "mode: count\n",
            "mode: count\nmalformed\n",
            "mode: count\nexample/other.go:2.1,2.2 1 5\n",
        ):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                traversal_work(profile, self.source, self.graph)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-ci", action="store_true")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--invocation", type=Path)
    args = parser.parse_args()
    if args.native_ci:
        if args.profile or args.source or args.invocation:
            parser.error("--native-ci cannot use an external profile/source/invocation")
        native_ci()
    else:
        if not all((args.profile, args.source, args.invocation)):
            parser.error("--profile, --source and --invocation are required together")
        graph = json.loads(args.invocation.read_text())["rule_graph"]
        assert_linear(args.profile.read_text(), args.source.read_text(), graph)


if __name__ == "__main__":
    main()
