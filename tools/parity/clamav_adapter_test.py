"""Inert, stdlib-only controls for the optional offline ClamAV adapter."""

import ctypes
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import clamav_adapter as adapter

IMAGE = "sha256:" + "a" * 64
STATE = {"OOMKilled": False, "Running": False, "Error": "", "ExitCode": 0}
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37


class ClassifyTests(unittest.TestCase):
    def classify(self, code=0, out=b"stdin: OK\n", err=b"", status="ok", **state):
        return adapter.classify(
            adapter.Call(code, out, err, status), dict(STATE, ExitCode=code, **state)
        )

    def test_complete_native_invocations(self):
        self.assertEqual(self.classify(), ("no_detection", []))
        self.assertEqual(
            self.classify(1, b"stdin: Inert.Test.UNOFFICIAL FOUND\n"),
            ("detection", ["Inert.Test.UNOFFICIAL"]),
        )

    def test_failures_cannot_be_no_detection(self):
        self.assertEqual(
            self.classify(err=b"WARNING: scan incomplete"), ("execution_error", [])
        )
        self.assertEqual(self.classify(2), ("execution_error", []))
        self.assertEqual(self.classify(status="timeout"), ("timeout", []))
        self.assertEqual(self.classify(status="output_limit"), ("output_limit", []))
        self.assertEqual(self.classify(OOMKilled=True), ("resource_limit", []))
        self.assertEqual(self.classify(Running=True), ("execution_error", []))
        self.assertEqual(self.classify(Error="inert"), ("execution_error", []))

    def test_limit_and_heuristic_are_unknown(self):
        self.assertEqual(
            self.classify(1, b"stdin: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n"),
            ("scan_limit", []),
        )
        self.assertEqual(
            self.classify(1, b"stdin: Heuristics.Encrypted.Zip FOUND\n"),
            ("heuristic_unknown", []),
        )
        self.assertEqual(
            self.classify(
                2,
                b"stdin: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n"
                b"stdin: Virus(es) detected ERROR\n",
            ),
            ("scan_limit", []),
        )

    def test_exact_protocol(self):
        for code, raw in [
            (0, b""),
            (0, b"stdin: OK\nwarning\n"),
            (0, b"stdin: OK"),
            (1, b"stdin: OK\n"),
            (0, b"stdin: A FOUND\n"),
            (1, b"stdin: A FOUND"),
            (1, b"stdin: \xff FOUND\n"),
        ]:
            with self.subTest(code=code, raw=raw):
                self.assertEqual(self.classify(code, raw), ("malformed_output", []))

    def test_only_explicit_exact_historical_database_warning(self):
        result = adapter.Call(out=b"stdin: OK\n", err=adapter.AGE_WARNING_153)
        self.assertEqual(adapter.classify(result, STATE), ("execution_error", []))
        self.assertEqual(adapter.classify(result, STATE, True), ("no_detection", []))
        for diagnostic in [
            b" " + adapter.AGE_WARNING_153,
            adapter.AGE_WARNING_153 + b"warning\n",
            adapter.AGE_WARNING_153[:-1],
            adapter.AGE_WARNING_153.replace(b"7 days", b"8 days"),
        ]:
            with self.subTest(diagnostic=diagnostic):
                self.assertEqual(
                    adapter.classify(
                        adapter.Call(out=b"stdin: OK\n", err=diagnostic), STATE, True
                    ),
                    ("execution_error", []),
                )


class CallTests(unittest.TestCase):
    def test_stdin_and_both_pipes(self):
        result = adapter.call(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.write('e')",
            ],
            b"inert",
        )
        self.assertEqual(result, adapter.Call(0, b"inert", b"e"))

    def test_output_bound(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                result = adapter.call(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        f"import sys;sys.{stream}.write('x'*1000000)",
                    ],
                    seconds=3,
                )
                self.assertEqual(result.status, "output_limit")
                self.assertLessEqual(len(result.out), adapter.MAX_OUTPUT)
                self.assertLessEqual(len(result.err), adapter.MAX_OUTPUT)

    def test_timeout_reaps_process(self):
        result = adapter.call(
            [sys.executable, "-I", "-c", "import time;time.sleep(10)"], seconds=0.1
        )
        self.assertEqual(result.status, "timeout")
        self.assertLess(result.code, 0)

    def test_early_leader_exit_kills_private_group_before_reap(self):
        child = (
            "import subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-I','-c',"
            "'import time;time.sleep(60)']);"
            "print(p.pid,flush=True)"
        )
        libc = ctypes.CDLL(None, use_errno=True)
        old_subreaper = ctypes.c_int()
        self.assertEqual(
            libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(old_subreaper), 0, 0, 0),
            0,
            f"PR_GET_CHILD_SUBREAPER errno={ctypes.get_errno()}",
        )
        self.assertEqual(
            libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0),
            0,
            f"PR_SET_CHILD_SUBREAPER errno={ctypes.get_errno()}",
        )
        descendant = None
        failure = None
        cleanup_error = None
        descendant_absent = False
        try:
            result = adapter.call([sys.executable, "-I", "-c", child], seconds=1)
            self.assertTrue(
                result.out.strip(), "leader did not report its descendant PID"
            )
            descendant = int(result.out.strip())
            try:
                self.assertEqual(result.status, "timeout")
                self.assertEqual(result.code, 0)
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    try:
                        raw = Path(f"/proc/{descendant}/stat").read_text(
                            encoding="ascii"
                        )
                    except FileNotFoundError:
                        descendant_absent = True
                        break
                    if raw[raw.rfind(")") + 2 :].startswith("Z "):
                        break
                    time.sleep(0.01)
                else:
                    self.fail(f"early-exit leader left descendant {descendant} live")
            except AssertionError as error:
                failure = error
            finally:
                if not descendant_absent:
                    try:
                        os.kill(descendant, signal.SIGKILL)
                        waited, _ = os.waitpid(descendant, 0)
                        if waited != descendant:
                            cleanup_error = AssertionError(
                                f"reaped {waited}, want descendant {descendant}"
                            )
                    except (ProcessLookupError, ChildProcessError) as error:
                        cleanup_error = error
        finally:
            if (
                libc.prctl(PR_SET_CHILD_SUBREAPER, old_subreaper.value, 0, 0, 0) != 0
                and cleanup_error is None
            ):
                cleanup_error = OSError(
                    ctypes.get_errno(), "restore PR_SET_CHILD_SUBREAPER"
                )
        if failure is not None:
            if cleanup_error is not None:
                failure.add_note(f"secondary descendant cleanup error: {cleanup_error}")
            raise failure
        if cleanup_error is not None:
            raise AssertionError("descendant cleanup failed") from cleanup_error
        self.assertFalse(Path(f"/proc/{descendant}").exists())

    def test_truncated_stdin_is_not_success(self):
        result = adapter.call(
            [sys.executable, "-I", "-c", "import os;os.close(0);print('stdin: OK')"],
            b"x" * (1 << 20),
        )
        self.assertEqual(result.status, "input_error")


class SnapshotTests(unittest.TestCase):
    def test_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / "inert-fifo"
            os.mkfifo(fifo)
            code = (
                "import sys;sys.path.insert(0,sys.argv[1]);"
                "import clamav_adapter;"
                "clamav_adapter.snapshot([(sys.argv[2],'/usr/bin/clamscan')],sys.argv[3])"
            )
            # External deadline also bounds a regression in the blocking open.
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    code,
                    str(Path(__file__).parent),
                    str(fifo),
                    str(root / "out"),
                ],
                timeout=2,
                check=False,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"asset must be a bounded regular file", result.stderr)

    def test_regular_asset_symlink_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"inert installation asset")
            link = root / "link"
            link.symlink_to(source)
            receipt = adapter.snapshot(
                [(str(link), "/usr/bin/clamscan"), (str(source), "/db/inert.ndb")],
                root / "out",
            )
            self.assertEqual(
                receipt["assets"][1]["sha256"], adapter.digest(source.read_bytes())
            )

    def test_snapshot_reproducibility_and_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, db = root / "binary", root / "db"
            binary.write_bytes(b"inert binary")
            db.write_bytes(b"inert database")
            assets = [(str(binary), "/usr/bin/clamscan"), (str(db), "/db/test.ndb")]
            first = adapter.snapshot(assets, root / "first")
            second = adapter.snapshot(list(reversed(assets)), root / "second")
            self.assertEqual(first, second)
            self.assertEqual(
                (root / "first/rootfs.tar").read_bytes(),
                (root / "second/rootfs.tar").read_bytes(),
            )
            (root / "first/rootfs.tar").write_bytes(b"changed")
            with (
                self.assertRaisesRegex(ValueError, "integrity mismatch"),
                patch.object(adapter, "call") as execute,
            ):
                adapter.import_snapshot(root / "first")
            execute.assert_not_called()

    def test_missing_and_escaping_assets(self):
        for destinations in [
            ["/usr/bin/clamscan"],
            ["/db/a.ndb"],
            ["/usr/bin/clamscan", "/db/../a"],
            ["/usr/bin/clamscan", "/db/a.ndb", "/db/a.ndb"],
        ]:
            with (
                self.subTest(destinations=destinations),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                source = root / "source"
                source.write_bytes(b"inert")
                with self.assertRaises(ValueError):
                    adapter.snapshot(
                        [(str(source), dest) for dest in destinations], root / "out"
                    )


def container():
    return {
        "Image": IMAGE,
        "Mounts": [],
        "State": STATE.copy(),
        "Config": {
            "User": "65534:65534",
            "Entrypoint": ["/usr/bin/clamscan"],
            "Cmd": adapter.SCAN_ARGS,
            "OpenStdin": True,
            "Env": ["LC_ALL=C", "TZ=UTC"],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidMode": "",
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "PidsLimit": 64,
            "NanoCpus": 1000000000,
            "Memory": adapter.MEMORY,
            "MemorySwap": adapter.MEMORY,
            "Tmpfs": {"/tmp": adapter.TMPFS},
            "Binds": None,
            "VolumesFrom": None,
            "CapAdd": None,
            "LogConfig": {"Type": "none", "Config": {}},
            "Ulimits": [{"Name": "core", "Soft": 0, "Hard": 0}],
        },
    }


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.record = container()
        self.fail_create = False
        self.create_reply = adapter.Call(out=b"b" * 64 + b"\n")
        self.fail_cleanup = False
        self.result = adapter.Call(out=b"stdin: OK\n")

    def execute(self, args, **kwargs):
        command = args[len(adapter.DOCKER) :]
        self.events.append((command, kwargs))
        if command[0] == "create":
            if self.fail_create:
                return adapter.Call(status="timeout")
            return self.create_reply
        if command[0] == "inspect":
            return adapter.Call(out=json.dumps([self.record]).encode())
        if command[0] == "start":
            return self.result
        if command[0] == "ps" and self.fail_cleanup:
            return adapter.Call(out=b"id\n")
        return adapter.Call()

    def test_success_sequence_and_stdin(self):
        backend = adapter.Adapter(IMAGE, self.execute)
        self.assertEqual(
            backend.launch(b"inert"), {"status": "no_detection", "detections": []}
        )
        self.assertEqual(
            [args[0] for args, _ in self.events],
            ["create", "inspect", "start", "inspect", "rm", "ps"],
        )
        self.assertEqual(self.events[2][1]["data"], b"inert")
        self.assertIn("--pull=never", self.events[0][0])
        self.assertIn("--database=/db", self.events[0][0])

    def test_version_probe_uses_exact_argv_and_status(self):
        version_args = ["--database=/db", "--version"]
        self.record["Config"]["Cmd"] = version_args
        self.result = adapter.Call(out=b"ClamAV 1.5.3/28048/inert\n")
        observed = adapter.Adapter(IMAGE, self.execute).launch(b"", version_probe=True)
        self.assertEqual(
            observed,
            {
                "status": "version",
                "detections": [],
                "engine_version": "ClamAV 1.5.3/28048/inert",
            },
        )
        self.assertEqual(self.events[0][0][-2:], version_args)
        self.assertEqual(self.events[2][1]["data"], b"")

    def test_version_probe_rejects_nonexact_results(self):
        version_args = ["--database=/db", "--version"]
        for result, expected in (
            (adapter.Call(out=b"ClamAV 1.5.3/28048/inert"), "malformed_output"),
            (
                adapter.Call(out=b"ClamAV 1.5.3/28048/inert\nextra\n"),
                "malformed_output",
            ),
            (
                adapter.Call(out=b"ClamAV 1.5.3/28048/inert\n", status="timeout"),
                "timeout",
            ),
            (
                adapter.Call(code=1, out=b"ClamAV 1.5.3/28048/inert\n"),
                "execution_error",
            ),
        ):
            with self.subTest(result=result):
                self.events.clear()
                self.record = container()
                self.record["Config"]["Cmd"] = version_args
                self.result = result
                observed = adapter.Adapter(IMAGE, self.execute).launch(
                    b"", version_probe=True
                )
                self.assertEqual(observed["status"], expected)
                self.assertNotIn("engine_version", observed)

    def test_every_envelope_field_rejects_before_stdin(self):
        mutations = [("Image", None), ("Mounts", ["inert"])]
        for section in ("Config", "HostConfig"):
            mutations += [(section, key) for key in self.record[section]]
        for section, key in mutations:
            with self.subTest(section=section, key=key):
                self.events.clear()
                self.record = container()
                if key is None or section == "Mounts":
                    self.record[section] = "inert"
                else:
                    self.record[section][key] = "inert"
                observed = adapter.Adapter(IMAGE, self.execute).launch(b"inert")
                self.assertIn(observed["status"], ("envelope_error", "execution_error"))
                self.assertNotIn("start", [args[0] for args, _ in self.events])

    def test_memory_drift_blocks_input(self):
        self.record["HostConfig"]["Memory"] = 0
        observed = adapter.Adapter(IMAGE, self.execute).launch(b"inert")
        self.assertEqual(observed["status"], "envelope_error")
        self.assertNotIn("start", [args[0] for args, _ in self.events])

    def test_inconclusive_create_poisoned(self):
        self.fail_create = True
        backend = adapter.Adapter(IMAGE, self.execute)
        self.assertEqual(backend.launch(b"inert")["status"], "setup_error")
        self.assertEqual(backend.launch(b"inert")["status"], "backend_unavailable")
        self.assertEqual([args[0] for args, _ in self.events], ["create", "rm", "ps"])

    def test_invalid_create_acknowledgement_is_terminal(self):
        for raw in [b"", b"id\n", b"b" * 64, b"b" * 64 + b"\nextra"]:
            with self.subTest(raw=raw):
                self.events.clear()
                self.create_reply = adapter.Call(out=raw)
                backend = adapter.Adapter(IMAGE, self.execute)
                observed = backend.launch(b"inert")
                self.assertEqual(observed["status"], "setup_error")
                self.assertEqual(
                    observed["uncertain_container_name"], self.events[0][0][2]
                )
                self.assertEqual(
                    [args[0] for args, _ in self.events], ["create", "rm", "ps"]
                )
                self.assertEqual(
                    backend.launch(b"second")["status"], "backend_unavailable"
                )

    def test_cleanup_failure_overrides_success(self):
        self.fail_cleanup = True
        backend = adapter.Adapter(IMAGE, self.execute)
        observed = backend.launch(b"inert")
        self.assertEqual(observed["status"], "cleanup_error")
        self.assertEqual(observed["detections"], [])
        self.assertEqual(observed["uncertain_container_name"], self.events[0][0][2])
        self.assertEqual(backend.launch(b"inert")["status"], "backend_unavailable")

    def test_failed_removal_with_absence_is_terminal(self):
        failures = [
            adapter.Call(code=1),
            adapter.Call(status="timeout"),
            adapter.Call(err=b"inert removal diagnostic"),
            OSError("lost rm reply"),
            subprocess.SubprocessError("inert rm transport error"),
        ]
        for failure in failures:
            with self.subTest(failure=failure):
                self.events.clear()

                def execute(args, failure=failure, **kwargs):
                    result = self.execute(args, **kwargs)
                    if args[len(adapter.DOCKER)] == "rm":
                        if isinstance(failure, Exception):
                            raise failure
                        return failure
                    return result

                backend = adapter.Adapter(IMAGE, execute)
                observed = backend.launch(b"inert")
                self.assertEqual(observed["status"], "cleanup_error")
                self.assertTrue(backend.poisoned)
                self.assertEqual(
                    [args[0] for args, _ in self.events][-2:], ["rm", "ps"]
                )
                count = len(self.events)
                self.assertEqual(
                    backend.launch(b"second")["status"], "backend_unavailable"
                )
                self.assertEqual(len(self.events), count)

    def test_create_exception_with_absence_is_terminal_and_named(self):
        for failure in [
            OSError("lost create reply"),
            subprocess.SubprocessError("inert create transport error"),
        ]:
            with self.subTest(failure=failure):
                self.events.clear()

                def execute(args, failure=failure, **kwargs):
                    result = self.execute(args, **kwargs)
                    if args[len(adapter.DOCKER)] == "create":
                        raise failure
                    return result

                backend = adapter.Adapter(IMAGE, execute)
                observed = backend.launch(b"inert")
                self.assertEqual(observed["status"], "execution_error")
                self.assertTrue(backend.poisoned)
                name = self.events[0][0][2]
                self.assertEqual(observed["uncertain_container_name"], name)
                self.assertEqual(
                    [args[0] for args, _ in self.events], ["create", "rm", "ps"]
                )
                count = len(self.events)
                self.assertEqual(
                    backend.launch(b"second")["status"], "backend_unavailable"
                )
                self.assertEqual(len(self.events), count)

    def test_timeout_still_removed(self):
        self.result = adapter.Call(status="timeout")
        self.assertEqual(
            adapter.Adapter(IMAGE, self.execute).launch(b"inert")["status"], "timeout"
        )
        self.assertEqual([args[0] for args, _ in self.events][-2:], ["rm", "ps"])

    def test_input_limit_before_create(self):
        with patch.object(adapter, "MAX_INPUT", 3):
            self.assertEqual(
                adapter.Adapter(IMAGE, self.execute).launch(b"four")["status"],
                "input_limit",
            )
        self.assertEqual(self.events, [])

    def test_age_warning_is_retained_metadata(self):
        self.result.err = adapter.AGE_WARNING_153
        observed = adapter.Adapter(
            IMAGE, self.execute, allow_stale_database=True
        ).launch(b"inert")
        self.assertEqual(observed["status"], "no_detection")
        self.assertIs(observed["database_stale"], True)
        self.assertEqual(
            observed["diagnostics"],
            [
                {
                    "code": "historical_database_age",
                    "text": adapter.AGE_WARNING_153.decode("ascii"),
                }
            ],
        )

    def test_daemon_environment_order_has_no_meaning(self):
        self.record["Config"]["Env"].reverse()
        self.assertEqual(
            adapter.Adapter(IMAGE, self.execute).launch(b"inert")["status"],
            "no_detection",
        )


if __name__ == "__main__":
    unittest.main()
