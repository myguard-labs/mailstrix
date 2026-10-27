#!/usr/bin/env python3
"""Mandatory static production compiler proof; no missing-prerequisite skips.

Run in the yara stage via compiler-input-check.sh. Original paths are replaced
only inside this disposable container, after all hashes have been verified.
"""

import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from itertools import pairwise, permutations
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "docker/capture-compiler-inputs.py"
ORIGINAL = Path(
    os.environ.get("MX_ORIGINAL_YARAC", "/opt/compiler-input-proof/yarac-original")
)
COMPILER = Path(os.environ.get("MX_CAPTURE_YARAC", "/usr/local/bin/yarac"))
spec = importlib.util.spec_from_file_location("capture_inputs", HELPER)
if spec is None or spec.loader is None:
    raise RuntimeError("capture helper loader unavailable")
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class TestCompilerArgumentAssembly(unittest.TestCase):
    def test_final_argv_preserves_records_verbatim_and_in_order(self):
        with tempfile.TemporaryDirectory(prefix="compiler-argv-") as temporary:
            root = Path(temporary)
            good = root / "accepted"
            records = [
                "first rule.yar:/rules/first rule.yar",
                "second.yara:/rules/[literal]*;$dollar\tsecond.yara",
            ]
            good.write_bytes(
                b"\n".join(os.fsencode(record) for record in records) + b"\n"
            )
            prefix = ["yarac", "-d", "filepath="]
            output = str(root / "compiled output.yac")
            with mock.patch.object(capture, "run", return_value=17) as run:
                self.assertEqual(capture.run_final(root, good, output, prefix), 17)
            run.assert_called_once_with(
                root, "final", "", "", prefix + records + [output]
            )

    def test_final_argv_rejects_malformed_records_without_running_compiler(self):
        malformed = {
            "empty": b"",
            "unterminated": b"one.yar:/rules/one.yar",
            "blank": b"one.yar:/rules/one.yar\n\n",
            "no namespace": b":/rules/one.yar\n",
            "no separator": b"one.yar-/rules/one.yar\n",
            "no path": b"one.yar:\n",
        }
        with tempfile.TemporaryDirectory(prefix="compiler-argv-") as temporary:
            root = Path(temporary)
            good = root / "accepted"
            for name, content in malformed.items():
                with self.subTest(name=name):
                    good.write_bytes(content)
                    with (
                        mock.patch.object(capture, "run") as run,
                        self.assertRaisesRegex(
                            capture.RetentionError, "malformed accepted-root records"
                        ),
                    ):
                        capture.run_final(root, good, "compiled.yac", ["yarac"])
                    run.assert_not_called()


class CompilerInputRetention(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for executable in (ORIGINAL, COMPILER):
            if not executable.is_file():
                raise RuntimeError(f"required static compiler missing: {executable}")
            result = subprocess.run(
                [str(executable), "--version"], capture_output=True, check=True
            )
            if result.stdout != b"4.5.2\n":
                raise RuntimeError("proof must use the production pinned YARA version")
            result = subprocess.run(
                ["ldd", str(executable)], capture_output=True, check=True
            )
            if b"libyara.so" in result.stdout:
                raise RuntimeError("proof must use static libyara")
        cls.build = tempfile.TemporaryDirectory(prefix="native-contract-")
        cls.faults = Path(cls.build.name) / "faults.so"
        subprocess.run(
            [
                "cc",
                "-O2",
                "-shared",
                "-fPIC",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(REPO / "ci/compiler-input/io-faults.c"),
                "-ldl",
                "-o",
                str(cls.faults),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="compiler-input-")
        self.root = Path(self.temporary.name)
        self.src = self.root / "src"
        self.src.mkdir()
        self.out = self.root / "compiled.yac"
        self.env = os.environ.copy()
        self.env["PATH"] = str(COMPILER.parent) + os.pathsep + self.env["PATH"]

    def tearDown(self):
        self.temporary.cleanup()

    def execute(self, argv, env=None):
        return subprocess.run(
            list(map(str, argv)),
            cwd=self.root,
            env=env or self.env,
            capture_output=True,
            check=False,
        )

    def compile_bundle(self):
        return self.execute(
            ["sh", REPO / "docker/compile-rules.sh", self.src, self.out]
        )

    def state(self):
        root = Path(str(self.out) + ".inputs")
        return root, json.loads((root / "manifest.json").read_text())

    def fixture(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.src / "inner.inc").write_text("private rule Nested { condition: true }\n")
        (self.src / "relative.inc").write_text(
            'include "inner.inc"\nrule Relative { condition: Nested }\n'
        )
        (outside / "nested.inc").write_text(
            "private rule AbsoluteNested { condition: true }\n"
        )
        (outside / "absolute.inc").write_text(
            'include "nested.inc"\nrule Absolute { condition: AbsoluteNested }\n'
        )
        (self.src / "a.yar").write_text(
            'import "hash"\nimport "math"\nimport "pe"\ninclude "relative.inc"\ninclude "'
            + str(outside / "absolute.inc")
            + (
                '"\nrule Same { condition: filepath == "" and filena'
                'me == "" and extension == "" and filetype == "" an'
                'd file_type == "" and owner == "" and VBA == 0 }\n'
            )
        )
        (self.src / "b.yara").write_text("rule Same { condition: true }\n")
        (self.src / "malformed.yara").write_bytes(b"\x01\n" + b"/*padding*/\n" * 3000)
        (self.src / "missing.yara").write_text(
            'include "absent.inc"\nrule Missing { condition: true }\n'
        )
        (self.src / "module.yara").write_text(
            'import "magic"\nrule Unsupported { condition: true }\n'
        )
        (self.src / "sources.json").write_text('{"fixture":"post-filter"}\n')
        return outside

    def test_lexical_malformed_include_skips_and_preserves_independent_root(self):
        (self.src / "a.yar").write_text("rule Good { condition: true }\n")
        (self.src / "broken.inc").write_text(
            'rule Broken { strings: $a = "unterminated\n'
        )
        bad = self.src / "b.yar"
        bad.write_text('include "broken.inc"\n')
        original = self.execute([ORIGINAL, bad, self.root / "rejected.yac"])
        self.assertEqual(original.returncode, 1)
        self.assertIn(b"unterminated string", original.stderr)
        result = self.compile_bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"skip b.yar (uncompilable)", result.stderr)
        root, state = self.state()
        self.assertEqual([v["accepted"] for v in state["validations"]], [True, False])
        rejected = state["validations"][1]
        self.assertIn(b"unterminated string", capture.get(root, rejected["stderr"]))
        self.assertEqual(rejected["sources"][0]["path"], str(bad))
        self.assertGreater(rejected["sources"][0]["errors"], 0)
        self.assertEqual(
            [s["path"] for s in state["final"]["sources"]], [str(self.src / "a.yar")]
        )
        oracle = self.root / "oracle.yac"
        self.assertEqual(
            self.execute([ORIGINAL, *state["final"]["argv"][1:-1], oracle]).returncode,
            0,
        )
        self.assertEqual(self.out.read_bytes(), oracle.read_bytes())

    def test_compile_rules_preserves_literal_accepted_root_argv_order(self):
        first = self.src / "z first rule.yar"
        second = self.src / "a [literal]*;$dollar.yara"
        first.write_text("rule First { condition: true }\n")
        second.write_text("rule Second { condition: true }\n")
        result = self.compile_bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        _, state = self.state()
        expected = [f"{path.name}:{path}" for path in (first, second)]
        roots = state["final"]["argv"][1 + 2 * len(capture.EXTERNALS) : -1]
        self.assertEqual(roots, expected)
        self.assertEqual(
            [validation["candidate"]["path"] for validation in state["validations"]],
            [str(first), str(second)],
        )

    def test_compile_rules_honors_capture_compiler_override(self):
        candidate = self.src / "override.yar"
        candidate.write_text("rule Override { condition: true }\n")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        decoy = bin_dir / "yarac"
        decoy.write_text("#!/bin/sh\nexit 125\n")
        decoy.chmod(0o755)
        env = dict(
            self.env,
            PATH=str(bin_dir) + os.pathsep + self.env["PATH"],
            MX_CAPTURE_YARAC=str(COMPILER),
        )
        result = self.execute(
            ["sh", REPO / "docker/compile-rules.sh", self.src, self.out], env=env
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, state = self.state()
        self.assertEqual(state["final"]["argv"][0], str(COMPILER))
        self.assertEqual(
            state["final"]["argv"][1 + 2 * len(capture.EXTERNALS) : -1],
            [f"{candidate.name}:{candidate}"],
        )

    def test_relative_output_verifies_and_restores_from_another_cwd(self):
        (self.src / "a.yar").write_text("rule Good { condition: true }\n")
        result = self.execute(
            ["sh", REPO / "docker/compile-rules.sh", self.src, "compiled.yac"]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        root, state = self.state()
        self.assertEqual(state["final"]["argv"][-1], "compiled.yac")
        other = self.root / "other"
        other.mkdir()
        for operation in (["verify", root], ["restore", root, other / "projected"]):
            result = subprocess.run(
                ["python3", "-B", HELPER, *map(str, operation)],
                cwd=other,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        replay = json.loads((other / "projected/replay.json").read_text())
        self.assertEqual(replay["cwd"], str(self.root))
        self.assertEqual(replay["argv"], state["final"]["argv"])
        corrupted = copy.deepcopy(state)
        corrupted["final"]["cwd"] = str(other)
        with self.assertRaisesRegex(capture.RetentionError, "contract mismatch"):
            capture.verify_contract(corrupted)

    def test_native_output_identity_preserves_lexical_filesystem_paths(self):
        (self.src / "a.yar").write_text("rule OutputPath { condition: true }\n")
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "target").mkdir()
        bridge = self.root / "bridge"
        bridge.symlink_to(elsewhere / "target", target_is_directory=True)
        cases = [
            ("absolute", str(self.root / "absolute.yac")),
            ("relative", "relative.yac"),
            ("absolute-dotdot", str(self.src) + "/../absolute-dotdot.yac"),
            ("relative-dotdot", "src/../relative-dotdot.yac"),
            ("repeated-dot", "./src/./../src/../repeated-dot.yac"),
            ("symlink-dotdot", str(bridge) + "/../symlink-dotdot.yac"),
        ]
        for mode, spelled in cases:
            with self.subTest(mode=mode):
                lexical = Path(self.root / spelled)
                normalized = Path(os.path.abspath(lexical))
                if mode == "symlink-dotdot":
                    normalized.write_bytes(b"normalized location must remain untouched")
                result = self.execute(
                    ["sh", REPO / "docker/compile-rules.sh", self.src, spelled]
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                retained = Path(str(lexical) + ".inputs")
                state = capture.verify(
                    retained, capture.load_json(retained / "manifest.json")
                )
                self.assertTrue(retained.is_symlink())
                self.assertEqual(state["output"], str(lexical.absolute()))
                self.assertEqual(state["final"]["argv"][-1], spelled)
                self.assertEqual(state["final"]["cwd"], str(self.root))
                self.assertEqual(state["final"]["exit"], 0)
                self.assertTrue(lexical.read_bytes())
                self.assertEqual(
                    lexical.read_bytes(), capture.get(retained, state["compiled"])
                )
                self.assertEqual(
                    state["compiled"]["sha256"],
                    hashlib.sha256(lexical.read_bytes()).hexdigest(),
                )
                oracle = self.root / (mode + "-oracle.yac")
                original = self.execute(
                    [ORIGINAL, *state["final"]["argv"][1:-1], oracle]
                )
                self.assertEqual(original.returncode, 0, original.stderr)
                self.assertEqual(lexical.read_bytes(), oracle.read_bytes())
                self.assertEqual(retained.resolve().parent, lexical.resolve().parent)
                if mode == "symlink-dotdot":
                    self.assertFalse(lexical.samefile(normalized))
                    self.assertEqual(
                        normalized.read_bytes(),
                        b"normalized location must remain untouched",
                    )
                    self.assertFalse(Path(str(normalized) + ".inputs").exists())
                for field in ("output", "argv"):
                    corrupted = copy.deepcopy(state)
                    if field == "output":
                        corrupted["output"] += ".wrong"
                    else:
                        corrupted["final"]["argv"][-1] += ".wrong"
                    with self.assertRaisesRegex(
                        capture.RetentionError, "contract mismatch"
                    ):
                        capture.verify_contract(corrupted)

    def assert_replay_projection(self, retained, state, projection):
        capture.restore(retained, projection)
        for original_path, item in state["final_inputs"].items():
            projected = projection / "inputs" / Path(original_path).relative_to("/")
            self.assertEqual(projected.read_bytes(), capture.get(retained, item))
        replay = json.loads((projection / "replay.json").read_text())
        self.assertEqual(replay["argv"], state["final"]["argv"])
        self.assertEqual(replay["cwd"], state["final"]["cwd"])

    def restore_original_paths(self, projection, state):
        # Empty traversal directories must come from the verified projection.
        for original_path in state["final_directories"]:
            projected = projection / "inputs" / Path(original_path).relative_to("/")
            self.assertTrue(projected.is_dir(), original_path)
            Path(original_path).mkdir(parents=True, exist_ok=True)
        for original_path in state["final_inputs"]:
            path = Path(original_path)
            shutil.copyfile(projection / "inputs" / path.relative_to("/"), path)

    def test_native_lexical_traversal_replay_original_argv(self):
        for mode in ("absolute", "relative", "repeated", "ordinary", "symlink"):
            with self.subTest(mode=mode):
                area = self.root / mode
                area.mkdir()
                source = area / "src"
                source.mkdir()
                bridge = area / "bridge"
                bridge.mkdir()
                if mode == "symlink":
                    actual = area / "elsewhere"
                    actual.mkdir()
                    (actual / "target").mkdir()
                    (actual / "src").mkdir()
                    bridge.rmdir()
                    bridge.symlink_to(actual / "target", target_is_directory=True)
                    actual_source = actual / "src"
                else:
                    actual_source = source
                (actual_source / "inner-bridge").mkdir()
                (actual_source / "nested-bridge").mkdir()
                (actual_source / "nested.inc").write_text(
                    "private rule Nested { condition: true }\n"
                )
                (actual_source / "inner.inc").write_text(
                    'include "nested-bridge/../nested.inc"\n'
                    "private rule Included { condition: Nested }\n"
                )
                (actual_source / "a.yar").write_text(
                    'include "inner-bridge/../inner.inc"\n'
                    "rule Traversal { condition: Included }\n"
                )
                spelling = str(area) + "/bridge/../src"
                if mode == "relative":
                    spelling = mode + "/bridge/../src"
                elif mode == "repeated":
                    spelling = str(area) + "/bridge/.././bridge/../../" + mode + "/src"
                elif mode == "ordinary":
                    spelling = str(source)
                built = self.execute(
                    ["sh", REPO / "docker/compile-rules.sh", spelling, self.out]
                )
                self.assertEqual(built.returncode, 0, built.stderr)
                retained, state = self.state()
                expected_sha = hashlib.sha256(self.out.read_bytes()).hexdigest()
                argv = state["final"]["argv"].copy()
                if mode != "ordinary":
                    self.assertIn("/bridge/../", argv[-2])
                shutil.rmtree(actual_source)
                if mode == "symlink":
                    bridge.unlink()
                    shutil.rmtree(actual)
                else:
                    bridge.rmdir()
                projection = self.root / ("projected-" + mode)
                self.assert_replay_projection(retained, state, projection)
                self.restore_original_paths(projection, state)
                self.assertFalse(bridge.is_symlink())
                self.assertEqual(bridge.exists(), mode != "ordinary")
                binpath = self.root / ("oracle-bin-" + mode)
                binpath.mkdir()
                (binpath / "yarac").symlink_to(ORIGINAL)
                env = self.env.copy()
                env["PATH"] = str(binpath) + os.pathsep + env["PATH"]
                self.out.unlink()
                replayed = self.execute(argv, env)
                self.assertEqual(replayed.returncode, 0, replayed.stderr)
                self.assertEqual(
                    hashlib.sha256(self.out.read_bytes()).hexdigest(), expected_sha
                )
                proof = {
                    "mode": mode,
                    "argv": argv,
                    "cwd": state["final"]["cwd"],
                    "sources": state["final"]["sources"],
                    "includes": state["final"]["includes"],
                    "directories": state["final_directories"],
                    "output_sha256": expected_sha,
                    "native_replay_exit": replayed.returncode,
                }
                if "MX_PROOF_EVIDENCE" in os.environ:
                    capture.save_json(
                        Path(os.environ["MX_PROOF_EVIDENCE"])
                        / (mode + "-traversal.json"),
                        proof,
                    )

    def test_lexical_directory_conflict_verification_and_cleanup(self):
        state = {
            "final": {
                "exit": 0,
                "cwd": "/cwd",
                "argv": ["yarac", "out"],
                "sources": [
                    {"path": "/bridge", "observed": {"sha256": "a", "size": 1}}
                ],
                "includes": [
                    {
                        "path": "/bridge/../src/a.yar",
                        "observed": {"sha256": "b", "size": 1},
                    }
                ],
            }
        }
        with self.assertRaisesRegex(capture.RetentionError, "cannot be projected"):
            capture.final_directories(state)
        state["final"]["sources"] = []
        state["final"]["includes"] = [
            {"path": "../../../../root.inc", "observed": {"sha256": "b", "size": 1}}
        ]
        self.assertIn("/", capture.final_directories(state))
        (self.src / "a.yar").write_text("rule Good { condition: true }\n")
        self.assertEqual(self.compile_bundle().returncode, 0)
        retained, state = self.state()
        conflict = copy.deepcopy(state)
        conflict["final"]["includes"].append(
            {
                "path": str(self.src / "a.yar") + "/../other.inc",
                "observed": state["final"]["sources"][0]["observed"],
            }
        )
        before_manifest = (retained / "manifest.json").read_bytes()
        before_pointer = retained.readlink()
        with (
            mock.patch.object(capture, "assemble", return_value=conflict),
            self.assertRaisesRegex(capture.RetentionError, "cannot be projected"),
        ):
            capture.finish(retained)
        self.assertEqual((retained / "manifest.json").read_bytes(), before_manifest)
        self.assertEqual(retained.readlink(), before_pointer)
        changed = copy.deepcopy(state)
        changed["final_directories"] = []
        with self.assertRaisesRegex(capture.RetentionError, "directory mapping"):
            capture.verify(retained, changed)
        destination = self.root / "failed-directory-projection"
        real_mkdir = Path.mkdir

        def mkdir(path, *args, **kwargs):
            if path == destination / "inputs":
                raise OSError("directory disk full")
            return real_mkdir(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "mkdir", mkdir),
            self.assertRaisesRegex(OSError, "directory disk full"),
        ):
            capture.restore(retained, destination)
        self.assertFalse(destination.exists())

    def test_native_replay_metadata_include_collision(self):
        include = Path("/replay.json")
        self.assertFalse(include.exists())
        self.addCleanup(include.unlink, missing_ok=True)
        include.write_bytes(b"private rule Included { condition: true }\n")
        (self.src / "a.yar").write_text(
            'include "/replay.json"\nrule Root { condition: Included }\n'
        )
        result = self.compile_bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        retained, state = self.state()
        projection = self.root / "projected-collision"
        self.assert_replay_projection(retained, state, projection)
        projected_include = projection / "inputs/replay.json"
        self.assertEqual(projected_include.read_bytes(), include.read_bytes())
        include.write_bytes(projected_include.read_bytes())
        argv = state["final"]["argv"].copy()
        argv[0], argv[-1] = str(ORIGINAL), str(self.root / "replayed.yac")
        replayed = self.execute(argv)
        self.assertEqual(replayed.returncode, 0, replayed.stderr)
        self.assertEqual(
            self.out.read_bytes(), (self.root / "replayed.yac").read_bytes()
        )

    def test_native_replay_metadata_directory_boundary(self):
        hierarchy = Path("/replay.json")
        self.assertFalse(hierarchy.exists())
        hierarchy.mkdir()
        self.addCleanup(shutil.rmtree, hierarchy)
        source = hierarchy / "source.yar"
        source.write_bytes(b"rule Hierarchy { condition: true }\n")
        result = self.execute(
            ["sh", REPO / "docker/compile-rules.sh", hierarchy, self.out]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        retained, state = self.state()
        self.assert_replay_projection(retained, state, self.root / "projected-boundary")

    def test_restore_input_write_failure_removes_destination(self):
        (self.src / "a.yar").write_text("rule Good { condition: true }\n")
        self.assertEqual(self.compile_bundle().returncode, 0)
        retained, _state = self.state()
        destination = self.root / "failed-input-projection"
        with (
            mock.patch.object(
                Path, "write_bytes", side_effect=OSError("input disk full")
            ),
            self.assertRaisesRegex(OSError, "input disk full"),
        ):
            capture.restore(retained, destination)
        self.assertFalse(destination.exists())

    def test_metadata_serialized_bytes_and_work_scale_linearly(self):
        measurements = []
        for count in (50, 100, 200):
            runroot = self.root / str(count)
            runroot.mkdir()
            with mock.patch.object(capture, "print", create=True) as printed:
                capture.begin(str(runroot / "compiled.yac"), str(self.src))
            retained = Path(printed.call_args.args[0])
            candidate = self.src / "representative.yar"
            candidate.write_text("rule Representative { condition: true }\n")
            writes = []
            reads = []
            real_save, real_load = capture.save_json, capture.load_json

            def saved(path, value, real_save=real_save, writes=writes):
                real_save(path, value)
                writes.append(path.stat().st_size)

            def loaded(path, real_load=real_load, reads=reads):
                reads.append(path.stat().st_size)
                return real_load(path)

            def compiler(argv, **kwargs):
                Path(kwargs["env"]["MAILSTRIX_COMPILER_INPUT_LOG"]).write_bytes(
                    b"trace"
                )
                return mock.Mock(returncode=0)

            observed = {
                "sources": [
                    {
                        "path": str(candidate),
                        "namespace": "representative.yar",
                        "errors": 0,
                        "observed": {"size": 4, "sha256": "a" * 64},
                    }
                ],
                "includes": [],
                "yarac_version": "4.5.2",
                "libyara_version": "4.5.2",
            }
            with (
                mock.patch.object(capture, "save_json", side_effect=saved),
                mock.patch.object(capture, "load_json", side_effect=loaded),
                mock.patch.object(capture.subprocess, "run", side_effect=compiler),
                mock.patch.object(capture, "parse_trace", return_value=observed),
                mock.patch.object(capture, "verify"),
            ):
                # A cursor must not rediscover its index by scanning prior files.
                with (
                    mock.patch.object(
                        Path,
                        "iterdir",
                        side_effect=AssertionError("per-invocation inventory scan"),
                    ),
                    mock.patch.object(
                        os,
                        "listdir",
                        side_effect=AssertionError("per-invocation inventory scan"),
                    ),
                    mock.patch.object(
                        os,
                        "scandir",
                        side_effect=AssertionError("per-invocation inventory scan"),
                    ),
                ):
                    for _ in range(count):
                        self.assertEqual(
                            capture.run(
                                retained,
                                "validation",
                                "representative.yar",
                                str(candidate),
                                [
                                    "yarac",
                                    "representative.yar:" + str(candidate),
                                    "out",
                                ],
                            ),
                            0,
                        )
                    final_observed = dict(observed, sources=observed["sources"] * count)
                    with mock.patch.object(
                        capture, "parse_trace", return_value=final_observed
                    ):
                        self.assertEqual(
                            capture.run(retained, "final", "", "", ["yarac", "out"]), 0
                        )
                (runroot / "compiled.yac").write_bytes(b"compiled")
                capture.finish(retained)
            measurements.append((sum(writes), sum(reads), len(writes) + len(reads)))
        evidence = os.environ.get("MX_PROOF_EVIDENCE")
        if evidence:
            capture.save_json(
                Path(evidence) / "metadata-scaling.json",
                {
                    "counts": [50, 100, 200],
                    "measurements": measurements,
                    "fields": [
                        "serialized_json_bytes",
                        "loaded_json_bytes",
                        "json_read_write_calls",
                    ],
                    "cursor_bytes_per_update": capture.CURSOR.size,
                },
            )
        for previous, current in pairwise(measurements):
            for old, new in zip(previous, current):
                self.assertLess(
                    new,
                    old * 2.2,
                    (measurements, "aggregate metadata bytes/work must be linear"),
                )

    def test_static_equivalence_and_offline_reproduction(self):
        outside = self.fixture()
        before = (self.src / "sources.json").read_bytes()
        result = self.compile_bundle()
        self.assertEqual(
            result.returncode,
            0,
            "expected retained compiler inputs for successful native compilation: "
            + result.stderr.decode(),
        )
        self.assertIn(b"bundled 2 files (3 skipped)", result.stdout)
        self.assertEqual((self.root / "sources.json").read_bytes(), before)
        retained, state = self.state()
        self.assertEqual(
            [v["candidate"]["namespace"] for v in state["validations"]],
            ["a.yar", "b.yara", "malformed.yara", "missing.yara", "module.yara"],
        )
        self.assertEqual(
            [v["accepted"] for v in state["validations"]],
            [True, True, False, False, False],
        )
        self.assertEqual(state["external_definitions"], capture.EXTERNALS)
        self.assertEqual(state["versions"], {"yarac": "4.5.2", "libyara": "4.5.2"})
        self.assertEqual(len(state["final"]["includes"]), 4)
        malformed = state["validations"][2]
        self.assertGreater(
            malformed["candidate"]["snapshot"]["size"],
            malformed["sources"][0]["observed"]["size"],
        )
        # Independent original compiler validates each candidate, preserving skips.
        for validation in state["validations"]:
            argv = validation["argv"].copy()
            argv[0], argv[-1] = str(ORIGINAL), str(self.root / "validation.yac")
            original = self.execute(argv)
            self.assertEqual(original.returncode, validation["exit"])
            self.assertEqual(
                original.stderr, capture.get(retained, validation["stderr"])
            )
        argv = state["final"]["argv"].copy()
        argv[0], argv[-1] = str(ORIGINAL), str(self.root / "original.yac")
        original = self.execute(argv)
        self.assertEqual(original.returncode, 0, original.stderr)
        self.assertEqual(
            self.out.read_bytes(), (self.root / "original.yac").read_bytes()
        )
        # Originals really become unavailable; only hash-checked captured buffers
        # are restored, at their original names in this disposable container.
        self.src.rename(self.root / "unavailable-src")
        outside.rename(self.root / "unavailable-outside")
        projection = self.root / "projected"
        capture.restore(retained, projection)
        self.restore_original_paths(projection, state)
        for original_path, item in state["final_inputs"].items():
            self.assertEqual(
                Path(original_path).read_bytes(), capture.get(retained, item)
            )
        replay = self.execute(argv)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(
            self.out.read_bytes(), (self.root / "original.yac").read_bytes()
        )
        nested = self.src / "inner.inc"
        good = nested.read_bytes()
        nested.unlink()
        absent = self.execute(argv)
        self.assertNotEqual(absent.returncode, 0)
        self.assertIn(b"can't open include file", absent.stderr)
        nested.write_bytes(good.replace(b"true", b"false"))
        tampered = self.execute(argv)
        self.assertEqual(tampered.returncode, 0)
        self.assertNotEqual(
            self.out.read_bytes(), (self.root / "original.yac").read_bytes()
        )
        nested.write_bytes(good)
        self.assertEqual(self.execute(argv).returncode, 0)
        self.assertEqual(
            self.out.read_bytes(), (self.root / "original.yac").read_bytes()
        )

    def test_native_rejected_observed_object_integrity(self):
        (self.src / "broken.inc").write_text(
            'rule Broken { strings: $a = "unterminated\n'
        )
        (self.src / "a-bad.yar").write_text(
            'include "broken.inc"\nrule Root { condition: true }\n'
            + "// unread suffix\n" * 10000
        )
        (self.src / "z-good.yar").write_text("rule Independent { condition: true }\n")
        built = self.compile_bundle()
        self.assertEqual(built.returncode, 0, built.stderr)
        root, state = self.state()
        self.assertEqual(capture.verify(root, state), state)
        protected = {i["sha256"] for i in state["final_inputs"].values()}
        protected.update(
            v["candidate"]["snapshot"]["sha256"] for v in state["validations"]
        )
        rejected = [v for v in state["validations"] if not v["accepted"]]
        self.assertTrue(rejected)
        references = [
            item["observed"]
            for invocation in rejected
            for item in invocation["sources"] + invocation["includes"]
            if item["observed"]["sha256"] not in protected
        ]
        self.assertEqual(
            len(references), 2, "rejected source prefix and include must be unique"
        )
        for ref in references:
            obj = root / "objects" / ref["sha256"]
            good = obj.read_bytes()
            self.assertEqual(hashlib.sha256(good).hexdigest(), ref["sha256"])
            self.assertEqual(len(good), ref["size"])
            for changed in (good + b"corruption", b"!" * len(good)):
                with self.subTest(ref=ref, corruption=changed):
                    obj.write_bytes(changed)
                    with self.assertRaisesRegex(
                        capture.RetentionError, "hash mismatch"
                    ):
                        capture.verify(root, state)
            obj.unlink()
            with self.assertRaises(FileNotFoundError):
                capture.verify(root, state)
            obj.write_bytes(good)
            self.assertEqual(capture.verify(root, state), state)
        # Every invocation and source/include reference must reach the same get
        # predicate, including rejected source prefixes that equal snapshots.
        original_get = capture.get
        for invocation in state["validations"] + [state["final"]]:
            for item in invocation["sources"] + invocation["includes"]:
                ref = item["observed"]
                for malformed in (
                    {"sha256": "../invalid", "size": ref["size"]},
                    {"sha256": ref["sha256"], "size": ref["size"] + 1},
                    {"sha256": "0" * 64, "size": ref["size"]},
                ):

                    def damaged_get(storage, reference, target=ref, bad=malformed):
                        return original_get(
                            storage, bad if reference is target else reference
                        )

                    with (
                        self.subTest(
                            invocation=invocation["exit"], reference=ref, bad=malformed
                        ),
                        mock.patch.object(capture, "get", side_effect=damaged_get),
                        self.assertRaises((capture.RetentionError, FileNotFoundError)),
                    ):
                        capture.verify(root, state)
        self.assertEqual(capture.verify(root, state), state)

    def test_hash_absence_and_manifest_contract_controls(self):
        (self.src / "one.yar").write_text("rule One { condition: true }\n")
        self.assertEqual(self.compile_bundle().returncode, 0)
        root, state = self.state()
        capture.verify(root, state)
        self.assertEqual(
            self.execute(["python3", "-B", HELPER, "verify", root]).returncode, 0
        )
        projection = self.root / "restore-cli"
        self.assertEqual(
            self.execute(
                ["python3", "-B", HELPER, "restore", root, projection]
            ).returncode,
            0,
        )
        rejected = self.execute(["python3", "-B", HELPER, "restore", root, projection])
        self.assertEqual(rejected.returncode, 125)
        self.assertIn(b"restore requires a new destination", rejected.stderr)
        data_ref = state["final"]["sources"][0]["observed"]
        obj = root / "objects" / data_ref["sha256"]
        good = obj.read_bytes()
        obj.write_bytes(good + b"tamper")
        with self.assertRaisesRegex(capture.RetentionError, "hash mismatch"):
            capture.verify(root, state)
        obj.unlink()
        with self.assertRaises(FileNotFoundError):
            capture.verify(root, state)
        obj.write_bytes(good)
        mutations = [
            lambda s: s["final"]["argv"].__setitem__(2, "VBA=1"),
            lambda s: s["external_definitions"][0].__setitem__("type", "integer"),
            lambda s: s["final"]["sources"][0].__setitem__("namespace", "wrong"),
            lambda s: s["versions"].__setitem__("libyara", "wrong"),
            lambda s: s["validations"][0].__setitem__("accepted", False),
        ]
        for mutate in mutations:
            bad = json.loads(json.dumps(state))
            mutate(bad)
            with self.assertRaises(capture.RetentionError):
                capture.verify(root, bad)
        capture.verify(root, state)
        # Repeated bundle builds preserve artifact bytes and publish a fresh pointer.
        previous_target = root.readlink()
        self.assertEqual(self.compile_bundle().returncode, 0)
        self.assertNotEqual(root.readlink(), previous_target)
        self.assertEqual(self.out.read_bytes(), capture.get(root, state["compiled"]))

    def direct_capture(self, mode, source, include=None):
        path = self.src / "fault.yar"
        path.write_bytes(source)
        if include is not None:
            (self.src / "fault.inc").write_bytes(include)
        log = self.root / "direct.native"
        log.unlink(missing_ok=True)
        env = self.env | {
            "LD_PRELOAD": str(self.faults),
            "MX_IO_MODE": mode,
            "MX_IO_ROOT": str(path),
            "MX_IO_INCLUDE": str(self.src / "fault.inc"),
            "MAILSTRIX_COMPILER_INPUT_LOG": str(log),
        }
        result = self.execute([COMPILER, "ns:" + str(path), self.out], env)
        native = log.read_bytes() if log.exists() else b""
        instrumented_bytes = self.out.read_bytes() if result.returncode == 0 else None
        path.write_bytes(source)
        if include is not None:
            (self.src / "fault.inc").write_bytes(include)
        original = self.execute(
            [ORIGINAL, "ns:" + str(path), self.root / "original.yac"], env
        )
        self.assertEqual(result.returncode, original.returncode, result.stderr)
        self.assertEqual(result.stderr, original.stderr)
        if result.returncode == 0:
            self.assertEqual(
                instrumented_bytes, (self.root / "original.yac").read_bytes()
            )
        storage = self.root / "capture"
        storage.mkdir(exist_ok=True)
        (storage / "objects").mkdir(exist_ok=True)
        observed = capture.parse_trace(storage, native, result.returncode, schema=2)
        evidence = os.environ.get("MX_PROOF_EVIDENCE")
        if evidence:
            capture.save_json(
                Path(evidence) / (mode + "-read-contract.json"),
                {
                    "mode": mode,
                    "original_exit": original.returncode,
                    "observed_exit": result.returncode,
                    "root_chunk_sizes": [
                        len(p) for k, _, p in capture.events(native) if k == 2
                    ],
                    "observed": observed,
                    "root_disk_sha256": capture.digest(path.read_bytes()),
                    "include_disk_sha256": capture.digest(
                        (self.src / "fault.inc").read_bytes()
                    )
                    if include is not None
                    else None,
                },
            )
        return observed, storage

    def test_read_short_error_and_transient_buffers(self):
        source = b"rule Root { condition: true }\n"
        for mode in (
            "root_short",
            "root_error",
            "root_transient",
            "capture_eintr",
            "capture_short",
        ):
            with self.subTest(mode=mode):
                state, storage = self.direct_capture(mode, source)
                observed = capture.get(storage, state["sources"][0]["observed"])
                if mode != "root_error":
                    # The rewrite is one byte longer. The original FILE cursor
                    # reads that trailing newline on its next unchanged fread.
                    expected = source + b"\n" if mode == "root_transient" else source
                    self.assertEqual(observed, expected)
                if mode == "root_transient":
                    self.assertNotEqual(observed, (self.src / "fault.yar").read_bytes())
        include = b"rule Fault { condition: true }\n"
        source = b'include "fault.inc"\nrule Root { condition: Fault }\n'
        for mode in ("include_short", "include_error", "include_transient"):
            with self.subTest(mode=mode):
                state, storage = self.direct_capture(mode, source, include)
                if mode == "include_transient":
                    observed = capture.get(storage, state["includes"][0]["observed"])
                    self.assertEqual(observed, include)
                    self.assertNotEqual(observed, (self.src / "fault.inc").read_bytes())
                else:
                    self.assertEqual(state["includes"], [])

    def test_retention_errors_are_not_malformed_skips(self):
        (self.src / "fault.yar").write_text("rule Root { condition: true }\n")
        for mode in ("capture_zero", "capture_error", "capture_close_error"):
            with self.subTest(mode=mode):
                self.env.update(LD_PRELOAD=str(self.faults), MX_IO_MODE=mode)
                result = self.compile_bundle()
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertIn(b"input retention failed", result.stderr)
                self.assertNotIn(b"skip", result.stderr)
                self.assertFalse(Path(str(self.out) + ".inputs").exists())
        env = self.env | {
            "MX_IO_MODE": "",
            "MAILSTRIX_COMPILER_INPUT_LOG": str(self.root / "missing/log.native"),
        }
        result = self.execute([COMPILER, self.src / "fault.yar", self.out], env)
        self.assertEqual(result.returncode, 125)
        self.assertIn(b"retention write failed", result.stderr)

    def test_empty_all_skipped_and_include_boundaries(self):
        result = self.compile_bundle()
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"nothing compiled", result.stderr)
        (self.src / "bad.yar").write_text("bad syntax")
        result = self.compile_bundle()
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"skip bad.yar", result.stderr)
        self.assertFalse(Path(str(self.out) + ".inputs").exists())
        source = b'include "fault.inc"\nrule Root { condition: true }\n'
        for include in (
            b"",
            b"\0rule Ignored { condition: false }\n",
            b"// padding\n" * 10000,
        ):
            with self.subTest(size=len(include)):
                state, storage = self.direct_capture("", source, include)
                self.assertEqual(
                    capture.get(storage, state["includes"][0]["observed"]), include
                )

    def test_seek_position_and_original_stream_contract(self):
        path = self.src / "seek.yar"
        path.write_text("ignored\nrule Seek { condition: true }\n")
        libraries = subprocess.check_output(
            ["pkg-config", "--static", "--libs", "yara"], text=True
        ).split()
        stdout, artifact = [], []
        for name, lib in (
            ("original", "/opt/compiler-input-proof/libyara-original.a"),
            ("observed", "/usr/local/lib/libyara.a"),
        ):
            binary = self.root / name
            flags = [v for v in libraries if v != "-lyara"]
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-flto",
                    "-DNDEBUG",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(REPO / "ci/compiler-input/seek.c"),
                    lib,
                    *flags,
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            env = self.env | {
                "MAILSTRIX_COMPILER_INPUT_LOG": str(self.root / "seek.native")
            }
            result = self.execute([binary, path, self.root / f"{name}.yac"], env)
            self.assertEqual(result.returncode, 0, result.stderr)
            stdout.append(result.stdout)
            artifact.append((self.root / f"{name}.yac").read_bytes())
        self.assertEqual(stdout[0], stdout[1])
        self.assertEqual(artifact[0], artifact[1])
        self.assertIn(b"error=0 eof=1", stdout[0])
        frames = list(capture.events((self.root / "seek.native").read_bytes()))
        self.assertEqual(
            b"".join(payload for kind, _, payload in frames if kind == 2),
            path.read_bytes()[8:],
        )

    def test_manifest_exit_status_requires_exact_supported_integer(self):
        self.fixture()
        result = self.compile_bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        root, state = self.state()
        self.assertEqual(capture.verify(root, state), state)
        capture.authoritative_rule_graph(root, state)
        successful = next(
            i for i, v in enumerate(state["validations"]) if v["exit"] == 0
        )
        failed = next(i for i, v in enumerate(state["validations"]) if v["exit"] == 1)
        for position, index in (
            ("final", None),
            ("validation", successful),
            ("validation", failed),
        ):
            for value in (0.0, False, 1.0, True, -1, 2, "0", "1", None):
                malformed = copy.deepcopy(state)
                invocation = (
                    malformed["final"]
                    if index is None
                    else malformed["validations"][index]
                )
                invocation["exit"] = value
                for verifier in (capture.verify, capture.authoritative_rule_graph):
                    with (
                        self.subTest(
                            position=position,
                            index=index,
                            value=value,
                            kind=type(value).__name__,
                            verifier=verifier.__name__,
                        ),
                        self.assertRaises(capture.RetentionError),
                    ):
                        verifier(root, malformed)
        self.assertEqual(capture.verify(root, state), state)
        capture.authoritative_rule_graph(root, state)

    def test_authoritative_native_resolved_reference_inventory(self):
        (self.src / "helpers.inc").write_text(
            "private rule Leaf { condition: VBA == 0 }\n"
            "rule Bridge { condition: Leaf }\n"
            "rule wildA { condition: Bridge }\nrule wildB { condition: false }\n"
        )
        (self.src / "a.yar").write_text(
            'include "helpers.inc"\nglobal rule Gate { condition: true }\n'
            "rule Marker : marker deny { condition: any of (wild*) }\n"
            'rule Literal { strings: $s="Bridge wildA Leaf" condition: $s }\n'
        )
        (self.src / "b.yar").write_text(
            "global rule Gate { condition: false }\nrule Marker : marker { condition: true }\n"
        )
        result = self.compile_bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        root, state = self.state()
        self.assertEqual(state["schema"], 2)
        capture.verify(root, state)
        graph = capture.authoritative_rule_graph(root, state)
        inventory = graph["inventory"]
        self.assertEqual(len(inventory), 9)
        self.assertEqual(graph["completions"], list(range(9)))
        identities = {(r["namespace"], r["identifier"]): r for r in inventory}
        self.assertEqual(identities["a.yar", "Leaf"]["flags"], 1)
        self.assertEqual(identities["a.yar", "Gate"]["flags"], 2)
        self.assertEqual(identities["a.yar", "Marker"]["tags"], ["marker", "deny"])
        edges = {tuple(edge) for edge in graph["references"]}

        def targets(namespace, identifier):
            index = identities[namespace, identifier]["native_index"]
            return {inventory[t]["identifier"] for s, t in edges if s == index}

        # This assertion uniquely belongs to the edge observer, independent of
        # completion coverage. The observer-off rebuilt compiler must fail here.
        self.assertEqual(targets("a.yar", "Marker"), {"wildA", "wildB"})
        self.assertEqual(targets("a.yar", "Bridge"), {"Leaf"})
        self.assertEqual(targets("a.yar", "wildA"), {"Bridge"})
        self.assertEqual(targets("a.yar", "Literal"), set())
        self.assertEqual(targets("b.yar", "Marker"), set())
        self.assertEqual(graph["summary"], [9, 4, 9, 3])
        empty_ns = self.root / "empty-namespace.yar"
        empty_ns.write_text("rule EmptyNamespace { condition: true }\n")
        log = self.root / "empty-namespace.native"
        observed = self.execute(
            [COMPILER, ":" + str(empty_ns), self.root / "empty.yac"],
            self.env | {"MAILSTRIX_COMPILER_INPUT_LOG": str(log)},
        )
        self.assertEqual(observed.returncode, 0, observed.stderr)
        parsed = capture.parse_trace(root, log.read_bytes(), 0, persist=False, schema=2)
        self.assertEqual(parsed["rule_graph"]["inventory"][0]["namespace"], "")

        legacy = copy.deepcopy(state)
        legacy["schema"] = 1
        for invocation in legacy["validations"] + [legacy["final"]]:
            invocation.pop("rule_graph")
            frames = capture.events(capture.get(root, invocation["native_trace"]))
            old = b"".join(
                capture.HEADER.pack(k, len(os.fsencode(n)), len(p)) + os.fsencode(n) + p
                for k, n, p in frames
                if not 10 <= k <= 15
            )
            invocation["native_trace"] = capture.store(root, old)
        legacy_root = self.root / "schema1-retained"
        shutil.copytree(root, legacy_root)
        capture.save_json(legacy_root / "manifest.json", legacy)
        capture.verify(legacy_root, legacy)
        legacy_projection = self.root / "schema1-restored"
        capture.restore(legacy_root, legacy_projection)
        for original_path, item in legacy["final_inputs"].items():
            projected = (
                legacy_projection / "inputs" / Path(original_path).relative_to("/")
            )
            self.assertEqual(projected.read_bytes(), capture.get(legacy_root, item))
        replay = capture.load_json(legacy_projection / "replay.json")
        self.assertEqual(replay["argv"], legacy["final"]["argv"])
        self.assertEqual(replay["cwd"], legacy["final"]["cwd"])
        with self.assertRaisesRegex(capture.RetentionError, "authoritative"):
            capture.authoritative_rule_graph(root, legacy)
        tampered = copy.deepcopy(state)
        tampered["final"]["rule_graph"]["inventory"][0]["identifier"] = "wrong"
        with self.assertRaisesRegex(capture.RetentionError, "native observation"):
            capture.verify(root, tampered)
        mutations = (
            lambda g: g.update(schema=True),
            lambda g: g.update(complete=1),
            lambda g: g["inventory"][0].update(native_index=False),
            lambda g: g["inventory"][0].update(flags=True),
            lambda g: g["completions"].__setitem__(0, 0.0),
            lambda g: g["summary"].__setitem__(0, 9.0),
            lambda g: g.update(unexpected=None),
        )
        for mutate in mutations:
            malformed = copy.deepcopy(state)
            mutate(malformed["final"]["rule_graph"])
            with self.assertRaisesRegex(capture.RetentionError, "native observation"):
                capture.verify(root, malformed)
        del tampered["final"]["rule_graph"]
        with self.assertRaises(capture.RetentionError):
            capture.verify(root, tampered)
        for legacy in (
            [],
            {},
            {"schema": 1},
            {"schema": True},
            {"schema": 3},
            {"schema": 2},
            {"schema": 2, "final": {"exit": 0}},
            {"schema": 2, "final": {"exit": 0, "rule_graph": {}}},
        ):
            with self.assertRaisesRegex(capture.RetentionError, "authoritative"):
                capture.authoritative_rule_graph(root, legacy)
        failed = copy.deepcopy(state)
        failed["final"]["exit"] = 1
        with self.assertRaisesRegex(capture.RetentionError, "authoritative"):
            capture.authoritative_rule_graph(root, failed)
        failed = copy.deepcopy(state)
        failed["final"]["rule_graph"]["complete"] = False
        with self.assertRaisesRegex(capture.RetentionError, "authoritative"):
            capture.authoritative_rule_graph(root, failed)

    def test_rule_graph_frame_contract_boundaries_and_negative_controls(self):

        def frame(kind, name="", payload=b""):
            name = name.encode()
            return capture.HEADER.pack(kind, len(name), len(payload)) + name + payload

        def pair(source, target):
            return struct.pack("<QQ", source, target)

        version = frame(10, "mailstrix-rule-graph/1")
        inventory = frame(13, "ns", struct.pack("<QI", 0, 3) + b"X")
        complete = frame(12, payload=pair(0, 0))
        tag = frame(14, "marker", struct.pack("<Q", 0))
        summary = frame(15, payload=struct.pack("<QQQQ", 1, 1, 1, 1))
        reference = frame(11, payload=pair(0, 0))
        source = (
            frame(8, "4.5.2")
            + frame(1, "root", b"ns")
            + frame(2, "root")
            + frame(3, "root", b"\0" * 4)
        )
        status = frame(9, "4.5.2", b"\0" * 4)
        valid = (
            version + source + reference + complete + inventory + tag + summary + status
        )
        graph = capture.parse_trace(self.root, valid, 0, persist=False, schema=2)[
            "rule_graph"
        ]
        self.assertEqual(graph["inventory"][0]["tags"], ["marker"])
        self.assertTrue(graph["complete"])
        for schema in (0, 3, True, "2"):
            with self.assertRaisesRegex(capture.RetentionError, "schema"):
                capture.parse_trace(self.root, valid, 0, persist=False, schema=schema)
        cases = [
            version + source + reference + complete + inventory + summary + status,
            source + complete + inventory + summary + status,
            source + status,
            version + version + source + status,
            frame(10, "wrong") + source + status,
            frame(10, "mailstrix-rule-graph/1", b"x") + source + status,
            version + source + frame(11, "name", pair(0, 0)) + status,
            version + source + frame(12, payload=b"short") + status,
            version + source + frame(12, payload=pair(0, 1)) + status,
            version + source + inventory + reference + status,
            version + source + frame(13, "ns", b"short") + status,
            version
            + source
            + frame(13, "n\0s", struct.pack("<QI", 0, 0) + b"X")
            + status,
            version
            + source
            + frame(13, "ns", struct.pack("<QI", 1, 0) + b"X")
            + status,
            version
            + source
            + frame(13, "ns", struct.pack("<QI", 0, 4) + b"X")
            + status,
            version
            + source
            + frame(13, "ns", struct.pack("<QI", 0, 0) + b"X\0")
            + status,
            version
            + source
            + inventory
            + frame(13, "ns", struct.pack("<QI", 1, 0) + b"X")
            + status,
            version + source + tag + status,
            version + source + inventory + frame(14, "", struct.pack("<Q", 0)) + status,
            version
            + source
            + inventory
            + frame(14, "n\0s", struct.pack("<Q", 0))
            + status,
            version + source + inventory + frame(14, "marker", b"short") + status,
            version
            + source
            + inventory
            + frame(14, "marker", struct.pack("<Q", 1))
            + status,
            version + source + inventory + tag + tag + status,
            version + source + frame(15, "bad", b"\0" * 32) + status,
            version + source + frame(15, payload=b"short") + status,
            version + source + complete + inventory + tag + status,
            version
            + source
            + complete
            + inventory
            + frame(15, payload=struct.pack("<QQQQ", 1, 0, 1, 0))
            + tag
            + status,
            version
            + source
            + inventory
            + frame(15, payload=struct.pack("<QQQQ", 1, 0, 0, 0))
            + status,
            version
            + source
            + reference
            + complete
            + inventory
            + frame(15, payload=struct.pack("<QQQQ", 2, 1, 1, 0))
            + status,
            version
            + source
            + frame(11, payload=pair(1, 0))
            + complete
            + inventory
            + tag
            + summary
            + status,
            version
            + source
            + frame(11, payload=pair(0, 1))
            + complete
            + inventory
            + tag
            + summary
            + status,
            version
            + source
            + frame(11, payload=pair(0, 1))
            + complete
            + frame(12, payload=pair(1, 1))
            + inventory
            + frame(13, "other", struct.pack("<QI", 1, 0) + b"Y")
            + frame(15, payload=struct.pack("<QQQQ", 2, 1, 2, 0))
            + status,
            version + frame(1, "root", b"ns") + inventory + status,
            valid[:-1],
        ]
        for index, data in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(capture.RetentionError):
                capture.parse_trace(self.root, data, 0, persist=False, schema=2)
        # Failed inputs preserve partial native observations without certifying
        # incomplete indices or invented inventory as successful closure.
        failed = (
            version
            + frame(1, "root", b"ns")
            + frame(11, payload=pair(5, 9))
            + frame(9, "4.5.2", b"\1\0\0\0")
        )
        graph = capture.parse_trace(self.root, failed, 1, persist=False, schema=2)[
            "rule_graph"
        ]
        self.assertFalse(graph["complete"])
        self.assertEqual(graph["references"], [[5, 9]])
        empty = version + source + frame(15, payload=b"\0" * 32) + status
        graph = capture.parse_trace(self.root, empty, 0, persist=False, schema=2)[
            "rule_graph"
        ]
        self.assertEqual(graph["inventory"], [])
        with self.assertRaisesRegex(capture.RetentionError, "outside graph"):
            capture._RuleGraph().observe(16, "", b"")
        graph = capture._RuleGraph()
        graph.observe(10, "mailstrix-rule-graph/1", b"")
        with self.assertRaisesRegex(capture.RetentionError, "unknown native graph"):
            graph.observe(16, "", b"")

    def test_native_header_complete_statement_and_branch_controls(self):

        harness = self.root / "header.c"
        harness.write_text(
            r"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static jmp_buf failure;
static int fault, writes, allocations;
static int fake_open(const char *path, int flags, ...) {
  (void)path; (void)flags;
  return fault == 1 ? -1 : 42;
}
static int fake_close(int fd) { (void)fd; return fault == 2 ? -1 : 0; }
static ssize_t fake_write(int fd, const void *bytes, size_t size) {
  (void)bytes;
  if (fd == STDERR_FILENO) return (ssize_t)size;
  ++writes;
  if (fault == 3) { errno = EIO; return -1; }
  if (fault == 4) return 0;
  if (fault == 5 && writes == 1) { errno = EINTR; return -1; }
  if (fault == 6 && writes == 1) return 1;
  return (ssize_t)size;
}
static void *fake_malloc(size_t size) {
  ++allocations;
  errno = ENOMEM;
  return fault == 7 ? NULL : malloc(size);
}
static _Noreturn void fake_exit(int code) { assert(code == 125); longjmp(failure, 1); }
#define open fake_open
#define close fake_close
#define write fake_write
#define malloc fake_malloc
#define _exit fake_exit
#define MAILSTRIX_CAPTURE_IMPLEMENTATION
#include "compiler-input-capture.h"
int main(void) {
  unsetenv("MAILSTRIX_COMPILER_INPUT_LOG");
  mailstrix_rule_capture(11, 0, 0);
  mailstrix_input_capture(1, NULL, NULL, 0);
  mailstrix_rule_inventory(0, 0, "ns", "X");
  setenv("MAILSTRIX_COMPILER_INPUT_LOG", "", 1);
  mailstrix_input_capture(1, NULL, NULL, 0);
  mailstrix_rule_inventory(0, 0, "ns", "X");
  assert(allocations == 0);
  setenv("MAILSTRIX_COMPILER_INPUT_LOG", "capture", 1);
  mailstrix_rule_begin();
  mailstrix_rule_capture(11, 0, UINT64_MAX);
  mailstrix_rule_capture(12, 0, 0);
  mailstrix_rule_tag(UINT64_MAX, "marker");
  mailstrix_rule_summary(1);
  errno = EDOM;
  mailstrix_rule_inventory(UINT64_MAX, UINT32_MAX, "ns", "X");
  assert(errno == EDOM && allocations == 1);
  mailstrix_input_capture(2, NULL, NULL, 0);
  for (int mode = 5; mode <= 6; ++mode) {
    fault = mode; writes = 0; errno = EDOM;
    mailstrix_input_capture(2, "root", "bytes", 5);
    assert(errno == EDOM);
  }
  for (int mode = 1; mode <= 4; ++mode) {
    fault = mode; writes = 0;
    if (setjmp(failure) == 0) {
      mailstrix_input_capture(2, "root", "bytes", 5);
      abort();
    }
  }
  fault = 7;
  if (setjmp(failure) == 0) {
    mailstrix_rule_inventory(0, 0, "ns", "X");
    abort();
  }
  return 0;
}
"""
        )
        binary = self.root / "header"
        subprocess.run(
            [
                "cc",
                "-std=c11",
                "-O0",
                "--coverage",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(REPO / "docker"),
                str(harness),
                "-o",
                str(binary),
            ],
            cwd=self.root,
            check=True,
            capture_output=True,
        )
        subprocess.run([str(binary)], cwd=self.root, check=True, capture_output=True)
        subprocess.run(
            [
                "gcov",
                "--json-format",
                "--branch-counts",
                "--branch-probabilities",
                "header.c",
            ],
            cwd=self.root,
            check=True,
            capture_output=True,
        )
        with gzip.open(self.root / "header.gcov.json.gz", "rt") as report:
            data = json.load(report)
        header = next(
            f for f in data["files"] if f["file"].endswith("compiler-input-capture.h")
        )
        self.assertTrue(header["lines"])
        self.assertEqual(
            [line["line_number"] for line in header["lines"] if not line["count"]], []
        )
        self.assertEqual(
            [
                (line["line_number"], index)
                for line in header["lines"]
                for index, branch in enumerate(line["branches"])
                if not branch["count"]
            ],
            [],
        )
        evidence = os.environ.get("MX_PROOF_EVIDENCE")
        if evidence:
            capture.save_json(Path(evidence) / "native-header-coverage.json", header)

    def test_native_reference_rejections_retain_partial_proof(self):
        (self.src / "accepted.yar").write_text("rule Accepted { condition: true }\n")
        rejected = {
            "external.yar": "rule X { condition: missing_external }\n",
            "wildcard.yar": "rule X { condition: any of (missing*) }\n",
            "forward.yar": "rule X { condition: Later } rule Later { condition: true }\n",
            "partial.yar": "private rule Leaf { condition: true } "
            "rule Bad { condition: Leaf and missing_external }\n",
        }
        for name, content in rejected.items():
            (self.src / name).write_text(content)
        result = self.compile_bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        root, state = self.state()
        capture.verify(root, state)
        failed = {
            Path(v["candidate"]["path"]).name: v
            for v in state["validations"]
            if not v["accepted"]
        }
        self.assertEqual(set(failed), set(rejected))
        for name, invocation in failed.items():
            graph = invocation["rule_graph"]
            self.assertEqual(invocation["exit"], 1)
            self.assertFalse(graph["complete"])
            self.assertEqual(graph["inventory"], [])
            self.assertIsNone(graph["summary"])
            self.assertTrue(capture.get(root, invocation["stderr"]))
            self.assertEqual(
                capture.get(root, invocation["candidate"]["snapshot"]),
                rejected[name].encode(),
            )
        self.assertEqual(failed["partial.yar"]["rule_graph"]["completions"], [0])
        self.assertEqual(failed["partial.yar"]["rule_graph"]["references"], [[1, 0]])
        self.assertEqual(
            capture.authoritative_rule_graph(root, state)["inventory"][0]["identifier"],
            "Accepted",
        )

    def test_versioned_capture_command_dispatch_and_failure(self):

        output = self.root / "dispatch.yac"
        candidate = self.src / "dispatch.yar"
        candidate.write_text("rule Dispatch { condition: true }\n")
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.assertEqual(capture.main(["begin", str(output), str(self.src)]), 0)
        root = Path(printed.getvalue().strip())
        ext = [
            v
            for e in capture.EXTERNALS
            for v in ("-d", e["name"] + "=" + str(e["value"]))
        ]
        self.assertEqual(
            capture.main(
                [
                    "run",
                    str(root),
                    "validation",
                    "dispatch.yar",
                    str(candidate),
                    str(COMPILER),
                    *ext,
                    "dispatch.yar:" + str(candidate),
                    str(output),
                ]
            ),
            0,
        )
        accepted = self.root / "dispatch-accepted"
        accepted.write_text("dispatch.yar:" + str(candidate) + "\n")
        self.assertEqual(
            capture.main(
                [
                    "final",
                    str(root),
                    str(accepted),
                    str(output),
                    str(COMPILER),
                    *ext,
                ]
            ),
            0,
        )
        self.assertEqual(capture.main(["finish", str(root)]), 0)
        self.assertEqual(capture.main(["verify", str(root)]), 0)
        self.assertEqual(
            capture.main(["restore", str(root), str(self.root / "dispatch-restored")]),
            0,
        )
        with self.assertRaisesRegex(capture.RetentionError, "new destination"):
            capture.restore(root, self.root)
        for command, code in ((["verify", str(root)], 0), (["unknown"], 125)):
            with (
                mock.patch.object(sys, "argv", [str(HELPER), *command]),
                self.assertRaises(SystemExit) as caught,
            ):
                runpy.run_path(str(HELPER), run_name="__main__")
            self.assertEqual(caught.exception.code, code)
        abnormal = self.root / "abnormal"
        abnormal.mkdir()
        capture.write_cursor(abnormal, 0, False)
        for code, message in (
            (2, "complete normally"),
            (125, "native retention failed"),
        ):
            with (
                mock.patch.object(
                    capture.subprocess, "run", return_value=mock.Mock(returncode=code)
                ),
                self.assertRaisesRegex(capture.RetentionError, message),
            ):
                capture.run(abnormal, "final", "", "", ["yarac", "out"])

    def test_pinned_capture_patch_is_fail_closed(self):
        archive = Path("/opt/compiler-input-proof/yara.tar.gz")
        self.assertTrue(
            archive.is_file(), "required original pinned source archive missing"
        )
        subprocess.run(["tar", "-xzf", str(archive), "-C", str(self.root)], check=True)
        source = self.root / "yara-4.5.2"
        result = self.execute(
            ["python3", "-B", REPO / "docker/patch-compiler-input-capture.py", source]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        before = {
            name: (source / name).read_bytes()
            for name in (
                "libyara/compiler.c",
                "libyara/lexer.c",
                "libyara/parser.c",
                "cli/yarac.c",
            )
        }
        repeat = self.execute(
            ["python3", "-B", REPO / "docker/patch-compiler-input-capture.py", source]
        )
        self.assertNotEqual(repeat.returncode, 0)
        self.assertIn(b"unsupported YARA capture source", repeat.stderr)
        # The source pins are checked as a whole before any patch writes.
        for name, original in before.items():
            self.assertEqual((source / name).read_bytes(), original)
        patch_spec = importlib.util.spec_from_file_location(
            "capture_patch", REPO / "docker/patch-compiler-input-capture.py"
        )
        self.assertIsNotNone(patch_spec)
        assert patch_spec is not None and patch_spec.loader is not None
        patch_module = importlib.util.module_from_spec(patch_spec)
        patch_spec.loader.exec_module(patch_module)
        direct = self.root / "direct-patch"
        direct.mkdir()
        subprocess.run(["tar", "-xzf", str(archive), "-C", str(direct)], check=True)
        patch_module.patch(direct / "yara-4.5.2")
        with self.assertRaisesRegex(ValueError, "unsupported YARA capture source"):
            patch_module.patch(direct / "yara-4.5.2")
        cli = self.root / "cli-patch"
        cli.mkdir()
        subprocess.run(["tar", "-xzf", str(archive), "-C", str(cli)], check=True)

        with mock.patch.object(sys, "argv", ["patch", str(cli / "yara-4.5.2")]):
            runpy.run_path(
                str(REPO / "docker/patch-compiler-input-capture.py"),
                run_name="__main__",
            )
        compiler_source = source / "libyara/compiler.c"
        compiler_source.write_text(
            compiler_source.read_text().replace(
                "#include <yara/compiler.h>", "/* missing anchor */"
            )
        )
        altered = {name: (source / name).read_bytes() for name in before}
        for name in before:
            patch_module.HASHES[name] = capture.digest(altered[name])
        with self.assertRaisesRegex(ValueError, "anchor mismatch"):
            patch_module.patch(source)
        for name, original in altered.items():
            self.assertEqual((source / name).read_bytes(), original)

    def test_native_frame_protocol_error_and_boundary_controls(self):
        def frame(kind, name="", payload=b""):
            name = name.encode()
            return capture.HEADER.pack(kind, len(name), len(payload)) + name + payload

        zero = (0).to_bytes(4, sys.byteorder, signed=True)
        one = (1).to_bytes(4, sys.byteorder, signed=True)
        begin = frame(1, "root", b"ns")
        read = frame(2, "root", b"bytes")
        eof = frame(2, "root")
        end = frame(3, "root", zero)
        status = frame(9, "4.5.2", zero)
        failed = frame(9, "4.5.2", one)
        valid = frame(8, "4.5.2") + begin + read + eof + end + status
        result = capture.parse_trace(self.root, valid, 0, persist=False)
        self.assertEqual(result["sources"][0]["observed"]["size"], 5)
        cases = [
            (begin + begin, 1),
            (read, 1),
            (begin + frame(2, "wrong"), 1),
            (begin + eof + read, 1),
            (end, 1),
            (begin + frame(3, "wrong", zero), 1),
            (begin + frame(3, "root", b"x"), 1),
            (begin + end, 0),
            (frame(4, "include", b"bytes"), 1),
            (frame(8, "4.5.2", b"x"), 1),
            (frame(8, "4.5.2") + frame(8, "wrong"), 1),
            (frame(9, "4.5.2", b"x"), 1),
            (begin + status, 0),
            (failed, 0),
            (failed + frame(8, "4.5.2"), 1),
            (begin, 1),
            (status, 0),
            (begin + frame(3, "root", one) + status, 0),
        ]
        for data, code in cases:
            with (
                self.subTest(data=data, code=code),
                self.assertRaises(capture.RetentionError),
            ):
                capture.parse_trace(self.root, data, code, persist=False)
        partial = capture.parse_trace(
            self.root, begin + read + failed, 1, persist=False
        )
        self.assertIsNone(partial["sources"][0]["errors"])
        self.assertFalse(partial["sources"][0]["eof"])
        self.assertEqual(
            capture.parse_trace(self.root, failed, 1, persist=False)["sources"], []
        )
        for sha in ("short", "x" * 64):
            with self.assertRaises(capture.RetentionError):
                capture.get(self.root, {"sha256": sha, "size": 0})
        with self.assertRaises(capture.RetentionError):
            capture.main(["unknown"])
        with self.assertRaises(capture.RetentionError):
            capture.final_inputs({"final": {"exit": 1}})
        with self.assertRaisesRegex(capture.RetentionError, "one tree"):
            capture.final_inputs(
                {
                    "final": {
                        "exit": 0,
                        "cwd": str(self.root),
                        "sources": [
                            {"path": "same", "observed": {"sha256": "a", "size": 1}}
                        ],
                        "includes": [
                            {
                                "path": "same/child",
                                "observed": {"sha256": "b", "size": 1},
                            }
                        ],
                    }
                }
            )

    def stage_state(self, root, state):
        """Seed a staging fixture through the current per-invocation format."""
        pending = dict(state, validations=[], final=None)
        capture.save_json(root / "pending.json", pending)
        for index, invocation in enumerate(state["validations"]):
            capture.save_json(
                root / "invocations" / f"validation-{index}.json",
                {"phase": "validation", "index": index, "invocation": invocation},
            )
        count = len(state["validations"])
        if state["final"] is not None:
            capture.save_json(
                root / "invocations/final.json",
                {"phase": "final", "index": count, "invocation": state["final"]},
            )
        else:
            (root / "invocations/final.json").unlink(missing_ok=True)
        capture.write_cursor(root, count, state["final"] is not None)

    def test_invocation_cursor_inventory_and_order_corruption(self):
        (self.src / "one.yar").write_text("rule One { condition: true }\n")
        self.assertEqual(self.compile_bundle().returncode, 0)
        root, state = self.state()
        root = root.resolve()
        self.stage_state(root, state)
        self.assertEqual(capture.assemble(root)["validations"], state["validations"])
        cursor = (root / "cursor").read_bytes()
        for corrupt in (b"", b"extra" + cursor, capture.CURSOR.pack(1, 2)):
            (root / "cursor").write_bytes(corrupt)
            with self.assertRaisesRegex(capture.RetentionError, "cursor"):
                capture.assemble(root)
        for count, complete in ((-1, False), (2**64, False), (0, 2)):
            with self.assertRaisesRegex(capture.RetentionError, "cursor"):
                capture.write_cursor(root, count, complete)
        capture.write_cursor(root, 0, False)
        self.assertEqual(capture.read_cursor(root), (0, False))
        capture.write_cursor(root, 2**64 - 1, False)
        self.assertEqual(capture.read_cursor(root), (2**64 - 1, False))
        with self.assertRaisesRegex(capture.RetentionError, "overflow"):
            capture.run(root, "validation", "", "", [])
        capture.write_cursor(root, 2**64 - 1, True)
        with self.assertRaisesRegex(capture.RetentionError, "inventory"):
            capture.assemble(root)
        capture.write_cursor(root, 1, False)
        with self.assertRaisesRegex(capture.RetentionError, "no completed final"):
            capture.assemble(root)
        capture.write_cursor(root, 2, True)
        with self.assertRaisesRegex(capture.RetentionError, "inventory"):
            capture.assemble(root)
        self.stage_state(root, state)
        record = root / "invocations/validation-0.json"
        original = record.read_bytes()
        value = capture.load_json(record)
        for field, invalid in (("index", 1), ("phase", "final")):
            altered = dict(value, **{field: invalid})
            capture.save_json(record, altered)
            with self.assertRaisesRegex(capture.RetentionError, "order mismatch"):
                capture.assemble(root)
        record.write_bytes(original)
        renamed = root / "invocations/validation-1.json"
        record.rename(renamed)
        with self.assertRaisesRegex(capture.RetentionError, "inventory"):
            capture.assemble(root)
        renamed.rename(record)
        extra = root / "invocations/unexpected.json"
        extra.write_text("{}")
        with self.assertRaisesRegex(capture.RetentionError, "inventory"):
            capture.assemble(root)
        extra.unlink()
        pending = copy.deepcopy(state)
        pending["final"] = None
        self.stage_state(root, pending)
        (root / "invocations/validation-1.json").write_text("{}")
        with (
            mock.patch.object(
                capture.subprocess,
                "run",
                side_effect=lambda argv, **kw: (
                    Path(kw["env"]["MAILSTRIX_COMPILER_INPUT_LOG"]).write_bytes(
                        b"trace"
                    ),
                    mock.Mock(returncode=0),
                )[1],
            ),
            mock.patch.object(capture, "parse_trace", return_value=state["final"]),
            self.assertRaisesRegex(capture.RetentionError, "already exists"),
        ):
            capture.run(
                root, "validation", "one.yar", str(self.src / "one.yar"), ["yarac"]
            )

    def test_retention_publication_and_cleanup_failures(self):
        (self.src / "one.yar").write_text("rule One { condition: true }\n")
        self.assertEqual(self.compile_bundle().returncode, 0)
        root, state = self.state()
        root = root.resolve()
        ref = state["compiled"]
        obj = root / "objects" / ref["sha256"]
        original = obj.read_bytes()
        obj.write_bytes(b"collision")
        with self.assertRaisesRegex(capture.RetentionError, "collision"):
            capture.store(root, original)
        obj.write_bytes(original)
        self.stage_state(root, state)
        with self.assertRaisesRegex(capture.RetentionError, "phase"):
            capture.run(root, "invalid", "", "", [])
        pending = copy.deepcopy(state)
        pending["final"] = None
        self.stage_state(root, pending)
        with (
            mock.patch.object(
                capture.subprocess, "run", return_value=mock.Mock(returncode=2)
            ),
            self.assertRaisesRegex(capture.RetentionError, "normally"),
        ):
            capture.run(root, "final", "", "", ["yarac"])
        changed = copy.deepcopy(state)
        changed["validations"][0]["argv"][2] = "VBA=1"
        with self.assertRaisesRegex(capture.RetentionError, "validation compiler"):
            capture.verify(root, changed)
        changed = copy.deepcopy(state)
        changed["final_inputs"] = {}
        with self.assertRaisesRegex(capture.RetentionError, "mapping"):
            capture.verify(root, changed)
        changed = copy.deepcopy(state)
        changed["validations"][0]["accepted"] = False
        self.stage_state(root, changed)
        with self.assertRaisesRegex(capture.RetentionError, "accepted candidate order"):
            capture.finish(root)
        self.stage_state(root, state)
        pointer = Path(state["output"] + ".inputs")
        pointer.unlink()
        pointer.mkdir()
        with self.assertRaisesRegex(capture.RetentionError, "managed pointer"):
            capture.finish(root)
        destination = self.root / "failed-projection"
        with (
            mock.patch.object(capture, "save_json", side_effect=OSError("disk full")),
            self.assertRaisesRegex(OSError, "disk full"),
        ):
            capture.restore(root, destination)
        self.assertFalse(destination.exists())

    def test_final_input_ancestor_paths_and_safe_near_misses(self):
        def observed_paths(paths):
            items = [
                {"path": path, "observed": {"sha256": "a", "size": 1}} for path in paths
            ]
            return capture.final_inputs(
                {
                    "final": {
                        "exit": 0,
                        "cwd": "/rules",
                        "sources": items[:1],
                        "includes": items[1:],
                    }
                }
            )

        collisions = (
            ("/rules/a", "/rules/a-extra", "/rules/a/nested.inc"),
            ("/rules/a", "/rules/a-extra", "/rules/a/deep/nested.inc"),
            ("/rules/a/deep", "/rules/a/deep-extra", "/rules/a/deep/nested.inc"),
            ("/", "/rules/a"),
            ("a/", "a-extra", "./a/deep/../nested.inc"),
        )
        for paths in collisions:
            for ordered in permutations(paths):
                with (
                    self.subTest(paths=ordered),
                    self.assertRaisesRegex(
                        capture.RetentionError, "cannot be projected into one tree"
                    ),
                ):
                    observed_paths(ordered)
        safe = (
            ("/rules/a", "/rules/a-extra/nested.inc"),
            ("/rules/a/deep", "/rules/a/deep-extra/nested.inc"),
            ("/rules/a/nested.inc", "/rules/a/other.inc"),
            ("/rules/a", "/rules/ab"),
            ("a", "./a", "/rules/a"),
            (),
        )
        for paths in safe:
            for ordered in permutations(paths):
                with self.subTest(paths=ordered):
                    result = observed_paths(ordered)
                    expected = {
                        os.path.abspath(os.path.join("/rules", path)) for path in paths
                    }
                    self.assertEqual(set(result), expected)
                    self.assertTrue(
                        all(
                            item == {"sha256": "a", "size": 1}
                            for item in result.values()
                        )
                    )

    def test_malformed_capture_frames_and_conflicting_paths(self):
        for data in (
            b"x",
            capture.HEADER.pack(1, 100, 0),
            capture.HEADER.pack(99, 0, 0),
        ):
            with self.assertRaises(capture.RetentionError):
                capture.parse_trace(self.root, data, 0)
        with self.assertRaisesRegex(capture.RetentionError, "different observed bytes"):
            capture.final_inputs(
                {
                    "final": {
                        "exit": 0,
                        "cwd": str(self.root),
                        "sources": [
                            {"path": "same", "observed": {"sha256": "a", "size": 1}}
                        ],
                        "includes": [
                            {"path": "same", "observed": {"sha256": "b", "size": 1}}
                        ],
                    }
                }
            )
        with self.assertRaises(capture.RetentionError):
            capture.final_inputs({"final": None})

    def serial_records(self, files):
        """The pre-batch loop: one `run ... validation` per file, in order."""
        out = self.root / "serial.yac"
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            capture.begin(str(out), str(self.src))
        root = Path(printed.getvalue().strip())
        prefix = [str(COMPILER)] + [
            v for e in capture.EXTERNALS for v in ("-d", f"{e['name']}={e['value']}")
        ]
        with mock.patch.dict(os.environ, {"PATH": self.env["PATH"]}):
            for f in files:
                ns = os.path.basename(f)
                with contextlib.redirect_stderr(io.TextIOWrapper(io.BytesIO())):
                    capture.run(
                        root,
                        "validation",
                        ns,
                        f,
                        prefix + [f"{ns}:{f}", str(self.root / "serial-one.yac")],
                    )
        return root, prefix

    def test_parallel_validation_matches_serial_records(self):
        self.fixture()
        files = sorted(
            str(p) for p in self.src.iterdir() if p.suffix in (".yar", ".yara")
        )
        serial, prefix = self.serial_records(files)
        out = self.root / "batch.yac"
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            capture.begin(str(out), str(self.src))
        batch = Path(printed.getvalue().strip())
        listing = self.root / "list"
        listing.write_text("".join(f + "\n" for f in files))
        good = self.root / "good"
        errors = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"PATH": self.env["PATH"]}),
            contextlib.redirect_stderr(errors),
        ):
            self.assertEqual(
                capture.validate_files(batch, str(good), str(listing), prefix), 0
            )
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            capture.begin(str(self.root / "parallel.yac"), str(self.src))
        parallel = Path(printed.getvalue().strip())
        with mock.patch.dict(os.environ, {"PATH": self.env["PATH"]}):
            capture.validate(
                parallel, prefix, [(os.path.basename(f), f) for f in files], jobs=3
            )
        self.assertEqual(capture.read_cursor(batch), (len(files), False))
        self.assertEqual(capture.read_cursor(serial), (len(files), False))
        accepted = []
        for i, f in enumerate(files):
            one = capture.invocation_record(serial, "validation", i)
            two = capture.invocation_record(batch, "validation", i)
            three = capture.invocation_record(parallel, "validation", i)
            # Only the scratch output path differs; verify ignores argv[-1].
            self.assertEqual(one["argv"][:-1], two["argv"][:-1])
            for record in (one, two, three):
                del record["argv"]
            self.assertEqual(one, two)
            self.assertEqual(one, three)
            if two["accepted"]:
                accepted.append(f"{os.path.basename(f)}:{f}")
        self.assertEqual(good.read_text().splitlines(), accepted)
        self.assertEqual(len(accepted), 2)
        for f in files:
            ns = os.path.basename(f)
            skipped = f"compile-rules: skip {ns} (uncompilable)" in errors.getvalue()
            self.assertEqual(skipped, f"{ns}:{f}" not in accepted)
        self.assertEqual([p.name for p in batch.glob(".validation-*")], [])

    def test_production_validation_default_bounds_actual_processes(self):
        """The real default entrypoint starts one compiler child at a time."""
        files = [str(self.src / f"bound-{i}.yar") for i in range(12)]
        for name in files:
            Path(name).write_text("rule Bound { condition: true }\n")
        listing, good = self.root / "list", self.root / "good"
        listing.write_text("".join(name + "\n" for name in files))
        lock, children, peak = threading.Lock(), [], [0]

        def compiler(argv, **kwargs):
            # Real finite children expose fanout without allocating a ruleset.
            kwargs.pop("check")
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(0.1)"], **kwargs
            )
            with lock:
                children.append(child)
                peak[0] = max(peak[0], sum(p.poll() is None for p in children))
            code = child.wait()
            Path(kwargs["env"]["MAILSTRIX_COMPILER_INPUT_LOG"]).write_bytes(b"t")
            return subprocess.CompletedProcess(argv, code)

        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            capture.begin(str(self.out), str(self.src))
        root = Path(printed.getvalue().strip())
        with (
            mock.patch.object(capture.os, "cpu_count", return_value=128),
            mock.patch.object(capture.subprocess, "run", side_effect=compiler),
            mock.patch.object(
                capture, "parse_trace", return_value={"sources": [], "includes": []}
            ),
        ):
            self.assertEqual(
                capture.main(["validate", str(root), str(good), str(listing)]), 0
            )
        self.assertEqual(peak[0], 1, "production validation spawned parallel compilers")
        self.assertEqual(capture.read_cursor(root), (len(files), False))
        self.assertEqual(len(list((root / "invocations").iterdir())), len(files))
        self.assertEqual([p.name for p in root.glob(".validation-*")], [])
        self.assertEqual(len(good.read_text().splitlines()), len(files))

    def test_parallel_validation_records_input_order_not_completion_order(self):
        files = [str(self.src / f"r{i}.yar") for i in range(6)]
        for f in files:
            Path(f).write_text("rule R { condition: true }\n")
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            capture.begin(str(self.out), str(self.src))
        root = Path(printed.getvalue().strip())
        capture.write_cursor(root, 3, False)
        finished = []

        def compiler(argv, **kwargs):
            # Later inputs finish first; odd inputs are rejected.
            i = int(Path(argv[-2].split(":", 1)[1]).stem[1:])
            time.sleep(0.05 * (len(files) - i))
            Path(kwargs["env"]["MAILSTRIX_COMPILER_INPUT_LOG"]).write_bytes(b"t")
            finished.append(i)
            return mock.Mock(returncode=i % 2)

        def observed(_root, data, code, **_kw):
            return {"sources": [], "includes": [], "code": code}

        with (
            mock.patch.object(capture.subprocess, "run", side_effect=compiler),
            mock.patch.object(capture, "parse_trace", side_effect=observed),
        ):
            codes = capture.validate(
                root, ["yarac"], [(os.path.basename(f), f) for f in files], jobs=6
            )
        self.assertNotEqual(finished, sorted(finished))
        self.assertEqual(codes, [0, 1, 0, 1, 0, 1])
        self.assertEqual(capture.read_cursor(root), (9, False))
        for i, f in enumerate(files):
            record = capture.invocation_record(root, "validation", 3 + i)
            self.assertEqual(record["candidate"]["path"], f)
            self.assertEqual(record["accepted"], i % 2 == 0)
        self.assertFalse((root / "invocations/validation-2.json").exists())
        self.assertFalse((root / "invocations/validation-9.json").exists())

    def test_parallel_validation_boundaries_and_failures(self):
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            capture.begin(str(self.out), str(self.src))
        root = Path(printed.getvalue().strip())
        # Empty input: no records, cursor untouched, empty accepted list.
        listing = self.root / "list"
        listing.write_text("")
        good = self.root / "good"
        self.assertEqual(
            capture.main(["validate", str(root), str(good), str(listing)]), 0
        )
        self.assertEqual(good.read_text(), "")
        self.assertEqual(capture.read_cursor(root), (0, False))
        self.assertEqual(list((root / "invocations").iterdir()), [])
        f = self.src / "one.yar"
        f.write_text("rule One { condition: true }\n")
        # A retention failure (exit 125) aborts the batch; the cursor stays put.
        with (
            mock.patch.object(
                capture.subprocess, "run", return_value=mock.Mock(returncode=125)
            ),
            self.assertRaisesRegex(capture.RetentionError, "exit 125"),
        ):
            capture.validate(root, ["yarac"], [("one.yar", str(f))])
        self.assertEqual(capture.read_cursor(root), (0, False))
        self.assertEqual([p.name for p in root.glob(".validation-*")], [])
        # A completed (final) cursor or an overflowing batch is refused.
        capture.write_cursor(root, 0, True)
        with self.assertRaisesRegex(capture.RetentionError, "phase"):
            capture.validate(root, ["yarac"], [("one.yar", str(f))])
        capture.write_cursor(root, 2**64 - 1, False)
        with self.assertRaisesRegex(capture.RetentionError, "phase"):
            capture.validate(root, ["yarac"], [("one.yar", str(f))])

    def test_compile_rules_retention_failure_exits_125(self):
        (self.src / "one.yar").write_text("rule One { condition: true }\n")
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "yarac"
        fake.write_text("#!/bin/sh\nexit 125\n")
        fake.chmod(0o755)
        env = dict(self.env, PATH=str(bin_dir) + os.pathsep + self.env["PATH"])
        env.pop("MX_CAPTURE_YARAC", None)
        result = self.execute(
            ["sh", REPO / "docker/compile-rules.sh", self.src, self.out], env=env
        )
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertIn(b"input retention failed", result.stderr)
        self.assertFalse(self.out.exists())

    def test_store_concurrent_identical_objects(self):
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            capture.begin(str(self.out), str(self.src))
        root = Path(printed.getvalue().strip())
        data = os.urandom(1 << 20)
        with capture.ThreadPoolExecutor(max_workers=16) as pool:
            refs = list(pool.map(lambda _: capture.store(root, data), range(64)))
        self.assertEqual(
            {r["sha256"] for r in refs}, {hashlib.sha256(data).hexdigest()}
        )
        self.assertEqual(capture.get(root, refs[0]), data)
        self.assertEqual(
            sorted(p.name for p in (root / "objects").iterdir()), [refs[0]["sha256"]]
        )


if __name__ == "__main__":
    unittest.main()
