"""Inert frozen-inventory and private bridge protocol controls; no Docker use."""

import copy
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import clamav_adapter as adapter
import clamav_bridge as bridge
import qualify_clamav

IMAGE = "sha256:" + "a" * 64
IDENTITY = {
    "image_id": IMAGE,
    "rootfs_sha256": "b" * 64,
    "engine_assets_sha256": "c" * 64,
    "database_sha256": "d" * 64,
    "version": "ClamAV 1.5.3/28048/Thu Jul  2 06:25:04 2026",
}


def request(data=b"inert"):
    return {
        "version": 1,
        "operation": "scan",
        "name": "mailstrix-clamav-" + "a" * 32,
        "qualification_dir": "",
        "variant": "",
        "identity": dict(IDENTITY),
        "manifest_sha256": "e" * 64,
        "sample_sha256": adapter.digest(data),
        "size": len(data),
        "input_unit": "file",
        "scan_args": adapter.SCAN_ARGS,
    }


class FrozenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        binary, db = self.root / "binary", self.root / "db"
        binary.write_bytes(b"inert nonexecutable scanner inventory")
        db.write_bytes(b"inert database inventory")
        self.snapshot = adapter.snapshot(
            [(str(binary), "/usr/bin/clamscan"), (str(db), "/db/test.ndb")],
            self.root / "engine",
        )
        self.claimed = dict(self.snapshot, image=IMAGE)
        (self.root / "qualification.json").write_bytes(
            adapter.canonical(
                {
                    "schema_version": 1,
                    "qualified": True,
                    "engine": self.claimed,
                }
            )
        )
        self.image = {
            "Id": IMAGE,
            "Os": "linux",
            "Architecture": "amd64",
            "RootFS": {
                "Type": "layers",
                "Layers": ["sha256:" + self.snapshot["rootfs_sha256"]],
            },
            "Config": {},
        }
        self.runtime = {
            "CgroupVersion": "2",
            "SecurityOptions": ["name=seccomp,profile=builtin"],
            "MemoryLimit": True,
            "SwapLimit": True,
            "CpuCfsQuota": True,
            "PidsLimit": True,
        }

    def inspect(self):
        with patch.object(
            adapter,
            "call",
            side_effect=[
                adapter.Call(out=adapter.canonical(self.image)),
                adapter.Call(out=adapter.canonical(self.runtime)),
            ],
        ):
            return bridge.frozen_identity(self.root, "engine")

    def test_streamed_inventory_and_actual_single_layer(self):
        actual = self.inspect()
        self.assertEqual(actual["image_id"], IMAGE)
        for key in ("rootfs_sha256", "engine_assets_sha256", "database_sha256"):
            self.assertEqual(actual[key], self.snapshot[key])

    def test_actual_image_and_runtime_must_match(self):
        for key, value in (
            ("Id", "sha256:" + "f" * 64),
            ("Architecture", "arm64"),
            ("Os", "windows"),
            ("Config", {"Volumes": {"/db": {}}}),
            ("RootFS", {"Type": "layers", "Layers": ["sha256:" + "f" * 64]}),
            (
                "RootFS",
                {
                    "Type": "layers",
                    "Layers": [
                        "sha256:" + self.snapshot["rootfs_sha256"],
                        "sha256:" + "f" * 64,
                    ],
                },
            ),
        ):
            with self.subTest(key=key, value=value):
                original = self.image
                self.image = dict(original, **{key: value})
                with self.assertRaisesRegex(ValueError, "image does not match"):
                    self.inspect()
                self.image = original
        for key in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"):
            with self.subTest(key=key):
                self.runtime[key] = False
                with self.assertRaisesRegex(ValueError, "containment"):
                    self.inspect()
                self.runtime[key] = True

    def test_tar_and_inventory_corruption_before_any_docker_call(self):
        tarpath = self.root / "engine/rootfs.tar"
        original = tarpath.read_bytes()
        tarpath.write_bytes(original[:-1] + b"x")
        with (
            patch.object(adapter, "call") as execute,
            self.assertRaisesRegex(ValueError, "content hash"),
        ):
            bridge.frozen_identity(self.root, "engine")
        execute.assert_not_called()
        tarpath.write_bytes(original)
        for change in ("assets", "database_sha256", "engine_assets_sha256"):
            snapshot = copy.deepcopy(self.snapshot)
            if change == "assets":
                snapshot["assets"][0]["sha256"] = "f" * 64
            else:
                snapshot[change] = "f" * 64
            (self.root / "engine/snapshot.json").write_bytes(
                adapter.canonical(snapshot)
            )
            with (
                patch.object(adapter, "call") as execute,
                self.assertRaisesRegex(ValueError, "inventory"),
            ):
                bridge.frozen_identity(self.root, "engine")
            execute.assert_not_called()

    def test_corrupt_tar_structure_before_any_docker_call(self):
        tarpath = self.root / "engine/rootfs.tar"
        tarpath.write_bytes(b"not a tar archive")
        snapshot = dict(
            self.snapshot, rootfs_sha256=adapter.digest(tarpath.read_bytes())
        )
        (self.root / "engine/snapshot.json").write_bytes(adapter.canonical(snapshot))
        with (
            patch.object(adapter, "call") as execute,
            self.assertRaises(tarfile.TarError),
        ):
            bridge.frozen_identity(self.root, "engine")
        execute.assert_not_called()

    def test_duplicate_and_oversized_inventory_json_before_docker(self):
        snapshot_path = self.root / "engine/snapshot.json"
        for raw in (
            b'{"schema_version":1,"schema_version":1}',
            b" " * (bridge.MAX_JSON + 1),
        ):
            with self.subTest(raw=raw[:40]):
                snapshot_path.write_bytes(raw)
                with (
                    patch.object(adapter, "call") as execute,
                    self.assertRaises(ValueError),
                ):
                    bridge.frozen_identity(self.root, "engine")
                execute.assert_not_called()


class ProtocolTests(unittest.TestCase):
    def test_bound_json_duplicates_and_regular_files(self):
        for raw in (
            b"",
            b"{}{}",
            b'{"version":1,"version":1}',
            b"x" * (bridge.MAX_JSON + 1),
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                bridge.decode(raw)
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular file"):
                bridge.open_regular(fifo, 128)
            with self.assertRaisesRegex(ValueError, "regular file"):
                bridge.open_regular("/dev/zero", 128)

    def test_exact_input_and_identity_before_launch(self):
        for key, value in (
            ("version", True),
            ("operation", "other"),
            ("name", "wrong"),
            ("size", 99),
            ("sample_sha256", "f" * 64),
            ("manifest_sha256", "wrong"),
            ("input_unit", "unknown"),
            ("scan_args", []),
            ("identity", dict(IDENTITY, database_sha256="wrong")),
        ):
            with self.subTest(key=key), patch.object(adapter, "Adapter") as backend:
                req = dict(request(), **{key: value})
                with self.assertRaises(ValueError):
                    bridge.exchange(req, b"inert")
                backend.assert_not_called()

    def test_receipt_joins_and_named_lifecycle(self):
        with patch.object(adapter, "Adapter") as factory:
            factory.return_value.launch.return_value = {
                "status": "no_detection",
                "detections": [],
                "diagnostics": [
                    {
                        "code": "historical_database_age",
                        "text": adapter.AGE_WARNING_153.decode(),
                    }
                ],
                "database_stale": True,
            }
            factory.return_value.poisoned = False
            req = request()
            reply = bridge.exchange(req, b"inert")
            factory.return_value.launch.assert_called_once_with(
                b"inert", name=req["name"]
            )
            for key in (
                "name",
                "manifest_sha256",
                "sample_sha256",
                "size",
                "input_unit",
                "identity",
            ):
                self.assertEqual(reply[key], req[key])
            self.assertTrue(reply["database_stale"])
            self.assertFalse(reply["terminal"])

    def test_identity_operation_maps_only_exact_version_success(self):
        req = request(b"")
        req.update(
            operation="identity",
            qualification_dir="/inert",
            variant="engine",
            input_unit="",
        )
        frozen = {key: value for key, value in IDENTITY.items() if key != "version"}
        for observed, expected in (
            (
                {
                    "status": "version",
                    "detections": [],
                    "engine_version": IDENTITY["version"],
                },
                "ok",
            ),
            (
                {
                    "status": "version",
                    "detections": [],
                    "engine_version": "ClamAV 2.0.0/inert",
                },
                "identity_error",
            ),
            ({"status": "timeout", "detections": []}, "identity_error"),
        ):
            with self.subTest(observed=observed):
                with (
                    patch.object(bridge, "frozen_identity", return_value=dict(frozen)),
                    patch.object(adapter, "Adapter") as factory,
                ):
                    factory.return_value.launch.return_value = observed
                    factory.return_value.poisoned = False
                    reply = bridge.exchange(req, b"")
                self.assertEqual(reply["status"], expected)
                factory.return_value.launch.assert_called_once_with(
                    b"", version_probe=True, name=req["name"]
                )

    def test_main_contains_subprocess_errors_in_short_protocol_failure(self):
        raw = adapter.canonical(request()) + b"\n"
        for failure in (
            subprocess.SubprocessError("private transport detail"),
            subprocess.TimeoutExpired(["private", "argv"], 5),
        ):
            with self.subTest(failure=failure):
                stdin = SimpleNamespace(buffer=io.BytesIO(raw))
                stdout = SimpleNamespace(buffer=io.BytesIO())
                stderr = io.StringIO()
                with (
                    patch.object(sys, "stdin", stdin),
                    patch.object(sys, "stdout", stdout),
                    patch.object(sys, "stderr", stderr),
                    patch.object(bridge, "exchange", side_effect=failure),
                ):
                    self.assertEqual(bridge.main(), 2)
                self.assertEqual(stdout.buffer.getvalue(), b"")
                self.assertEqual(stderr.getvalue(), "ClamAV bridge failed\n")

    def test_null_host_memory_is_clear_qualification_failure(self):
        with self.assertRaisesRegex(ValueError, "Docker MemTotal must report"):
            qualify_clamav.require_host_memory({"MemTotal": None})

    def test_main_rejects_truncated_payload_and_header_without_private_output(self):
        script = str(Path(bridge.__file__).resolve())
        for raw in (
            adapter.canonical(request()) + b"\nshort",
            b"{}",
            b"x" * (bridge.MAX_JSON + 1),
        ):
            result = subprocess.run(
                [sys.executable, "-B", script],
                input=raw,
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"ClamAV bridge failed\n")


class SharedGroupTests(unittest.TestCase):
    def test_bridge_client_timeout_reaps_only_client_and_bridge_survives(self):
        # The harness starts its own session, just like Go's private group.
        # The client inherits it; a mistaken killpg(client.pid) cannot reap it,
        # and killing the bridge's group prevents the completion marker.
        module = str(Path(adapter.__file__).resolve().parent)
        code = """import os,sys
sys.path.insert(0,sys.argv[1])
import clamav_adapter as a
a.CALL_NEW_SESSION=False
child='import os,time;print(str(os.getpid())+":"+str(os.getpgrp()),flush=True);time.sleep(60)'
r=a.call([sys.executable,'-I','-c',child],seconds=0.1)
pid,group=map(int,r.out.decode().strip().split(':'))
assert group==os.getpgrp(), 'client escaped Go group'
assert r.status=='timeout' and r.code==-9, repr(r)
try: os.kill(pid,0)
except ProcessLookupError: pass
else: raise AssertionError('client not reaped')
print('bridge-survived-client-reaped')
"""
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", code, module],
            capture_output=True,
            start_new_session=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"bridge-survived-client-reaped\n")


if __name__ == "__main__":
    unittest.main()
