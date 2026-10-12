#!/usr/bin/env python3
"""Fixed export and real-native transfer controls, including offline replay.

Invoked by compiler-input-check.sh in the exact production static YARA stage.
The command interface also prepares and verifies the BuildKit local transfer.
"""

import copy
import errno
import importlib.util
import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("test module loader unavailable")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


export = module("export_inputs", REPO / "docker/export-compiler-inputs.py")
retention = module("native_fixture", REPO / "ci/compiler_input_retention_test.py")


def prepare(root, source=None, with_marker=False):
    root.mkdir()
    source = source or root / "source"
    source.mkdir()
    fixture = retention.CompilerInputRetention()
    fixture.root, fixture.src = source, source / "src"
    fixture.src.mkdir()
    fixture.fixture()
    # Use the actual ordinary producer's metadata, not the historical proof's
    # arbitrary fixture object. LOCAL_ONLY performs no rule downloads.
    subprocess.run(
        ["sh", str(REPO / "docker/fetch-rules.sh"), str(fixture.src)],
        cwd=source,
        env={**os.environ, "LOCAL_ONLY": "1"},
        check=True,
    )
    local = source / "local-src"
    local.mkdir()
    (local / "local.yar").write_text("rule LocalOnly { condition: false }\n")
    for src, name in ((fixture.src, "compiled.yac"), (local, "local.yac")):
        subprocess.run(
            ["sh", str(REPO / "docker/compile-rules.sh"), str(src), str(source / name)],
            cwd=source,
            check=True,
        )
    (source / "libyara.version").write_text("4.5.2\n")
    if with_marker:
        before = Path.cwd()
        export.marker.build(source)
        if Path.cwd() != before:
            raise AssertionError("marker builder changed caller cwd")
    export.produce(source, root / "export", require_marker=with_marker)
    return source, root / "export"


def replay(root, results):
    index = export.verify(root)
    rows = {}
    for slot, name in export.SLOTS.items():
        graph = root / "compiler-inputs" / slot
        state = export.graph_state(graph)
        projection = Path("/replay-" + slot)
        export.capture.restore(graph, projection)
        for directory in state["final_directories"]:
            Path(directory).mkdir(parents=True, exist_ok=True)
        for path in state["final_inputs"]:
            target = Path(path)
            if target.exists():
                raise RuntimeError("original source unexpectedly exists in replay")
            shutil.copyfile(projection / "inputs" / target.relative_to("/"), target)
        argv = state["final"]["argv"].copy()
        argv[0], argv[-1] = str(retention.ORIGINAL), "/offline-" + slot + ".yac"
        subprocess.run(argv, cwd=state["final"]["cwd"], check=True)
        digest = export.fingerprint(Path(argv[-1]).read_bytes())["sha256"]
        if digest != index["artifacts"][slot]["compiled_sha256"]:
            raise RuntimeError("offline compiled bytes mismatch: " + name)
        rows[slot] = {
            "sha256": digest,
            "argv": argv,
            "original_argv": state["final"]["argv"],
            "cwd": state["final"]["cwd"],
            "network": "none",
        }
    if rows["main"]["sha256"] == rows["local"]["sha256"]:
        raise RuntimeError("native fixture must have distinct main/local artifacts")
    results.write_text(json.dumps(rows, indent=2) + "\n")


class CompilerInputExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Native prerequisites are mandatory, never skipped.
        for executable in (retention.ORIGINAL, retention.COMPILER):
            subprocess.run(
                [str(executable), "--version"], check=True, capture_output=True
            )
        cls.base = tempfile.TemporaryDirectory(prefix="compiler-export-fixture-")
        cls.source, cls.exported = prepare(Path(cls.base.name) / "fixture")

    @classmethod
    def tearDownClass(cls):
        cls.base.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="compiler-export-test-")
        self.root = Path(self.temp.name)
        self.out = self.root / "export"
        shutil.copytree(self.exported, self.out)

    def tearDown(self):
        self.temp.cleanup()

    def rejected(self):
        with self.assertRaises(
            (
                export.ExportError,
                export.capture.RetentionError,
                OSError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
            )
        ):
            export.verify(self.out)

    def save_index(self, index):
        (self.out / "compiler-inputs/index.json").write_text(json.dumps(index))

    def test_loader_and_cli_entry(self):
        with mock.patch.object(sys, "argv", ["export", "verify", str(self.out)]):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(
                    str(REPO / "docker/export-compiler-inputs.py"), run_name="__main__"
                )
            self.assertEqual(result.exception.code, 0)
        with (
            mock.patch.object(
                importlib.util, "spec_from_file_location", return_value=None
            ),
            self.assertRaisesRegex(RuntimeError, "loader unavailable"),
        ):
            runpy.run_path(str(REPO / "docker/export-compiler-inputs.py"))

    def test_positive_complete_and_root_bytes(self):
        index = export.verify(self.out)
        for name in (*export.SLOTS.values(), *export.METADATA):
            self.assertEqual(
                (self.source / name).read_bytes(), (self.out / name).read_bytes()
            )
        self.assertNotEqual(
            index["artifacts"]["main"]["compiled_sha256"],
            index["artifacts"]["local"]["compiled_sha256"],
        )
        for slot, name in export.SLOTS.items():
            graph = (self.source / (name + ".inputs")).resolve()
            self.assertEqual(
                export.inventory(graph),
                export.inventory(self.out / "compiler-inputs" / slot),
            )
        self.assertEqual(export.main(["verify", str(self.out)]), 0)
        self.assertEqual(
            export.main(["export", str(self.source), str(self.root / "cli")]), 0
        )

    def test_all_rejected_objects_traces_and_metadata(self):
        graph = self.out / "compiler-inputs/main"
        state = export.graph_state(graph)
        paths = {"manifest.json", "cursor", "invocations/final.json"}
        rejected = [v for v in state["validations"] if not v["accepted"]]
        self.assertEqual(len(rejected), 3)
        for invocation in rejected:
            for item in (
                invocation["candidate"]["snapshot"],
                invocation["native_trace"],
                invocation["stderr"],
                *[
                    v["observed"]
                    for v in invocation["sources"] + invocation["includes"]
                ],
            ):
                paths.add("objects/" + item["sha256"])
        for path in sorted(paths):
            target = graph / path
            saved = target.read_bytes()
            for action in ("tamper", "omit", "same-size"):
                if action == "same-size" and not saved:
                    continue
                with self.subTest(path=path, action=action):
                    if action == "omit":
                        target.unlink()
                    elif action == "same-size":
                        target.write_bytes(bytes([saved[0] ^ 1]) + saved[1:])
                    else:
                        target.write_bytes(saved + b"tampered")
                    self.rejected()
                    target.write_bytes(saved)
                    export.verify(self.out)

    def test_fixed_strict_index_matrix(self):
        original = export.verify(self.out)
        mutations = []
        for field in original:
            value = copy.deepcopy(original)
            del value[field]
            mutations.append(value)
        for schema in (True, 0, 2, "1", None):
            value = copy.deepcopy(original)
            value["schema"] = schema
            mutations.append(value)
        for field in ("metadata", "artifacts"):
            for slot in original[field]:
                value = copy.deepcopy(original)
                del value[field][slot]
                mutations.append(value)
            value = copy.deepcopy(original)
            value[field]["extra"] = {}
            mutations.append(value)
        for field in original["artifacts"]["main"]:
            value = copy.deepcopy(original)
            del value["artifacts"]["main"][field]
            mutations.append(value)
        for field, replacement in (
            ("compiled", "../compiled.yac"),
            ("graph", "../main"),
            ("versions", {"yarac": "0", "libyara": "0"}),
            ("compiled_sha256", "0" * 64),
            ("files", {}),
        ):
            value = copy.deepcopy(original)
            value["artifacts"]["main"][field] = replacement
            mutations.append(value)
        value = copy.deepcopy(original)
        value["extra"] = True
        mutations.append(value)
        for value in mutations:
            with self.subTest(index=value):
                self.save_index(value)
                self.rejected()
        for text in ("{}", "[]", "{", '{"schema":1,"schema":1}', '{"schema":NaN}'):
            (self.out / "compiler-inputs/index.json").write_text(text)
            self.rejected()
        self.save_index(original)
        export.verify(self.out)

    def test_root_metadata_slots_and_inventory(self):
        for name in (
            *export.SLOTS.values(),
            *export.METADATA,
            "compiler-inputs/index.json",
        ):
            target = self.out / name
            data = target.read_bytes()
            target.unlink()
            self.rejected()
            target.write_bytes(data)
            target.write_bytes(b"wrong")
            self.rejected()
            target.write_bytes(data)
        for name in ("extra", "compiler-inputs/main/extra", "compiler-inputs/extra"):
            target = self.out / name
            target.write_bytes(b"extra")
            self.rejected()
            target.unlink()
        for name in ("empty-extra", "compiler-inputs/empty-extra"):
            target = self.out / name
            target.mkdir()
            self.rejected()
            target.rmdir()
        index = export.verify(self.out)
        (self.out / "sources.json").write_text("{}")
        index["metadata"]["sources.json"] = export.fingerprint(b"{}")
        self.save_index(index)
        self.rejected()

    def test_optimized_cli_stays_fail_closed_and_source_symlink(self):
        helper = REPO / "docker/export-compiler-inputs.py"
        good = subprocess.run(
            [sys.executable, "-O", str(helper), "verify", str(self.out)],
            capture_output=True,
            check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        (self.out / "compiler-inputs/index.json").unlink()
        bad = subprocess.run(
            [sys.executable, "-O", str(helper), "verify", str(self.out)],
            capture_output=True,
            check=False,
        )
        self.assertEqual(bad.returncode, 125)
        self.assertIn(b"rejected", bad.stderr)
        alias = self.root / "source-link"
        alias.symlink_to(self.source, target_is_directory=True)
        self.assertEqual(
            export.main(["export", str(alias), str(self.root / "absent")]), 125
        )
        self.assertFalse((self.root / "absent").exists())

    def test_actual_source_metadata_shapes(self):
        original = export.verify(self.out)
        target = self.out / "sources.json"
        valid = target.read_bytes()
        for value in ({}, None, 1, "wrong", [1], [{"name": 1}], [{"set": False}]):
            data = json.dumps(value).encode()
            target.write_bytes(data)
            index = copy.deepcopy(original)
            index["metadata"]["sources.json"] = export.fingerprint(data)
            self.save_index(index)
            self.rejected()
        for value in (
            [],
            [{"name": "profile", "value": "mail", "filter": "mail-relevance+license"}],
            [
                {
                    "name": None,
                    "repo": "repo",
                    "license": "license",
                    "ref": "ref",
                    "set": "full",
                }
            ],
        ):
            data = json.dumps(value).encode()
            target.write_bytes(data)
            index = copy.deepcopy(original)
            index["metadata"]["sources.json"] = export.fingerprint(data)
            self.save_index(index)
            export.verify(self.out)
        target.write_bytes(valid)
        self.save_index(original)
        export.verify(self.out)

    def test_fingerprint_types_and_rejected_raw_evidence(self):
        original = export.verify(self.out)
        for entry in (
            {"sha256": "0" * 64, "size": False},
            {"sha256": 0, "size": 1},
            {"sha256": "bad", "size": -1},
            {"sha256": "g" * 64, "size": 0},
            {"sha256": "0" * 64, "size": 0, "extra": 1},
        ):
            index = copy.deepcopy(original)
            index["metadata"]["sources.json"] = entry
            self.save_index(index)
            self.rejected()
        self.save_index(original)
        graph = self.out / "compiler-inputs/main"
        state = export.graph_state(graph)
        for i, invocation in enumerate(state["validations"]):
            if invocation["accepted"]:
                continue
            for relative in (
                f"validation-{i}.native",
                f"validation-{i}.stderr",
                f"invocations/validation-{i}.json",
            ):
                target = graph / relative
                data = target.read_bytes()
                target.unlink()
                self.rejected()
                target.write_bytes(data)
                target.write_bytes(data + b"tampered")
                self.rejected()
                target.write_bytes(data)
        export.verify(self.out)

    def test_symlinks_special_files_and_identity_swaps(self):
        for relative in (
            "compiled.yac",
            "compiler-inputs/main/manifest.json",
            "compiler-inputs/main",
        ):
            target = self.out / relative
            saved = self.root / "saved"
            target.rename(saved)
            target.symlink_to(saved)
            self.rejected()
            target.unlink()
            saved.rename(target)
        fifo = self.out / "compiler-inputs/main/fifo"
        os.mkfifo(fifo)
        self.rejected()
        fifo.unlink()
        main, local = self.out / "compiled.yac", self.out / "local.yac"
        a, b = main.read_bytes(), local.read_bytes()
        main.write_bytes(b)
        local.write_bytes(a)
        self.rejected()
        main.write_bytes(a)
        local.write_bytes(b)
        a, b = self.out / "compiler-inputs/main", self.out / "compiler-inputs/local"
        a.rename(self.root / "swap")
        b.rename(a)
        (self.root / "swap").rename(b)
        self.rejected()

    def test_native_predicate_even_with_rewritten_inventory(self):
        graph = self.out / "compiler-inputs/main"
        state = export.graph_state(graph)
        state["versions"]["libyara"] = "0"
        (graph / "manifest.json").write_text(json.dumps(state))
        index = export.load(self.out / "compiler-inputs/index.json")
        index["artifacts"]["main"]["files"] = export.inventory(graph)
        self.save_index(index)
        self.rejected()

    def test_produce_errors_atomicity_and_snapshot_preservation(self):
        source = self.root / "source"
        shutil.copytree(self.source, source, symlinks=True)
        # Update only fixture output identity for this copied source.
        for name in export.SLOTS.values():
            graph = (source / (name + ".inputs")).resolve()
            state = export.load(graph / "manifest.json")
            state["output"] = str(source / name)
            state["final"]["argv"][-1] = str(source / name)
            state["final_directories"] = export.capture.final_directories(state)
            (graph / "manifest.json").write_text(json.dumps(state))
            count = len(state["validations"])
            (graph / "invocations/final.json").write_text(
                json.dumps(
                    {"phase": "final", "index": count, "invocation": state["final"]}
                )
            )
        before = export.inventory(source / os.readlink(source / "compiled.yac.inputs"))
        dest = self.root / "new"
        for name in ("libyara.version", "sources.json"):
            target = source / name
            saved = target.read_bytes()
            target.write_bytes(b"bad")
            self.assertEqual(export.main(["export", str(source), str(dest)]), 125)
            self.assertFalse(dest.exists())
            target.write_bytes(saved)
        self.assertEqual(
            export.inventory(source / os.readlink(source / "compiled.yac.inputs")),
            before,
        )
        self.assertTrue(list(self.root.glob(".compiler-export-*")))
        for target in ("../escape", "/absolute", "missing", ".compiler-inputs-missing"):
            pointer = source / "compiled.yac.inputs"
            original = os.readlink(pointer)
            pointer.unlink()
            pointer.symlink_to(target)
            self.assertEqual(export.main(["export", str(source), str(dest)]), 125)
            pointer.unlink()
            pointer.symlink_to(original)
        with mock.patch.object(
            export, "publish", side_effect=OSError("publication failure")
        ):
            self.assertEqual(export.main(["export", str(source), str(dest)]), 125)
        self.assertFalse(dest.exists())
        export.produce(source, dest)
        with self.assertRaisesRegex(export.ExportError, "already exists"):
            export.produce(source, dest)
        with mock.patch.object(export, "regular", side_effect=TypeError("malformed")):
            self.assertEqual(export.main(["verify", str(dest)]), 125)
        self.assertEqual(export.main([]), 125)

    def test_publication_success_and_existing_entries(self):
        stage = self.root / "stage"
        destination = self.root / "published"
        stage.mkdir()
        (stage / "verified").write_bytes(b"complete")
        inode = stage.stat().st_ino
        export.publish(stage, destination)
        self.assertFalse(stage.exists())
        self.assertEqual(destination.stat().st_ino, inode)
        self.assertEqual((destination / "verified").read_bytes(), b"complete")
        for kind in ("empty", "nonempty", "file", "symlink"):
            with self.subTest(kind=kind):
                stage.mkdir()
                (stage / "verified").write_bytes(b"complete")
                foreign = self.root / kind
                if kind in ("empty", "nonempty"):
                    foreign.mkdir()
                    if kind == "nonempty":
                        (foreign / "owner").write_bytes(b"foreign")
                elif kind == "file":
                    foreign.write_bytes(b"foreign")
                else:
                    foreign.symlink_to(self.root / "absent")
                before = foreign.lstat()
                with self.assertRaises(OSError) as result:
                    export.publish(stage, foreign)
                self.assertEqual(result.exception.errno, errno.EEXIST)
                self.assertEqual(foreign.lstat().st_ino, before.st_ino)
                self.assertEqual(foreign.lstat().st_mode, before.st_mode)
                self.assertEqual((stage / "verified").read_bytes(), b"complete")
                if kind == "nonempty":
                    self.assertEqual((foreign / "owner").read_bytes(), b"foreign")
                elif kind == "file":
                    self.assertEqual(foreign.read_bytes(), b"foreign")
                elif kind == "symlink":
                    self.assertEqual(os.readlink(foreign), str(self.root / "absent"))
                shutil.rmtree(stage)

    def source_identity(self):
        return {
            "files": {
                name: export.fingerprint(export.regular(self.source / name))
                for name in (*export.SLOTS.values(), *export.METADATA)
            },
            "graphs": {
                name: export.inventory((self.source / (name + ".inputs")).resolve())
                for name in export.SLOTS.values()
            },
            "pointers": {
                name: os.readlink(self.source / (name + ".inputs"))
                for name in export.SLOTS.values()
            },
        }

    def publication_race(self, nonempty):
        destination = self.root / "raced"
        before = self.source_identity()
        real = export.publish
        owned = []

        def compete(stage, target):
            self.assertEqual(target, destination)
            self.assertFalse(target.exists())
            # Verify the full envelope before its only publication boundary.
            export.verify(stage)
            destination.mkdir()
            if nonempty:
                (destination / "owner").write_bytes(b"foreign")
            owned.append((destination.stat().st_ino, stage))
            return real(stage, target)

        with mock.patch.object(export, "publish", side_effect=compete):
            self.assertEqual(
                export.main(["export", str(self.source), str(destination)]), 125
            )
        inode, stage = owned[0]
        self.assertEqual(destination.stat().st_ino, inode)
        self.assertEqual(
            sorted(p.name for p in destination.iterdir()),
            ["owner"] if nonempty else [],
        )
        if nonempty:
            self.assertEqual((destination / "owner").read_bytes(), b"foreign")
        export.verify(stage)
        self.assertEqual(self.source_identity(), before)

    def test_concurrent_empty_publication_preserves_owner(self):
        self.publication_race(False)

    def test_concurrent_nonempty_publication_preserves_owner(self):
        self.publication_race(True)

    def test_publication_unavailable_and_errno_fail_closed(self):
        destination = self.root / "unsupported"
        before = self.source_identity()
        with mock.patch.object(export.ctypes, "CDLL", return_value=object()):
            self.assertEqual(
                export.main(["export", str(self.source), str(destination)]), 125
            )
        for number in (
            errno.ENOSYS,
            errno.EOPNOTSUPP,
            errno.EINVAL,
            errno.EACCES,
            errno.EXDEV,
            errno.EIO,
        ):
            with self.subTest(errno=number):
                call = mock.Mock(return_value=-1)
                with (
                    mock.patch.object(export.ctypes, "CDLL") as library,
                    mock.patch.object(export.ctypes, "get_errno", return_value=number),
                ):
                    library.return_value.renameat2 = call
                    self.assertEqual(
                        export.main(["export", str(self.source), str(destination)]), 125
                    )
                    call.assert_called_once()
                    self.assertEqual(call.call_args.args[-1], 1)
                self.assertFalse(destination.exists())
        stages = list(self.root.glob(".compiler-export-*"))
        self.assertEqual(len(stages), 7)
        for stage in stages:
            export.verify(stage)
        self.assertEqual(self.source_identity(), before)

    def test_source_output_and_version_binding(self):
        with mock.patch.object(
            export, "graph_state", wraps=export.graph_state
        ) as predicate:
            export.produce(self.source, self.root / "valid")
            self.assertGreaterEqual(predicate.call_count, 4)
        with mock.patch.object(
            export, "fingerprint", return_value={"sha256": "bad", "size": 0}
        ):
            self.assertEqual(
                export.main(["export", str(self.source), str(self.root / "bad")]), 125
            )


def command(argv):
    if argv[0] in ("prepare", "prepare-marker"):
        prepare(
            Path(argv[1]),
            Path(argv[2]) if len(argv) == 3 else None,
            argv[0] == "prepare-marker",
        )
    elif argv[0] == "verify":
        export.verify(Path(argv[1]))
    elif argv[0] == "replay":
        replay(Path(argv[1]), Path(argv[2]))
    else:
        raise RuntimeError("unknown export fixture operation")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in (
        "prepare",
        "prepare-marker",
        "verify",
        "replay",
    ):
        command(sys.argv[1:])
    else:
        unittest.main()
