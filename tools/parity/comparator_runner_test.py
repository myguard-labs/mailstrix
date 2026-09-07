"""Hermetic runner boundary tests; standard library only, no container or corpus."""

import hashlib
import io
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, mock_open, patch

import comparator_runner as runner


class DirectTests(unittest.TestCase):
    def observe(self, raw=b"[]", diagnostic=b"", code=0):
        def execute(_args, **kwargs):
            self.assertEqual(kwargs["timeout"], runner.SCAN_SECONDS)
            kwargs["stdout"].write(raw)
            kwargs["stderr"].write(diagnostic)
            return SimpleNamespace(returncode=code)

        with patch("builtins.open", mock_open()) as opened, \
                patch.object(runner.subprocess, "run", side_effect=execute):
            result = runner.direct(b"inert")
        opened().write.assert_called_once_with(b"inert")
        return result

    def test_success(self):
        self.assertEqual(self.observe(), ("ok", "[]"))

    def test_nonzero_and_diagnostics_with_valid_output(self):
        self.assertEqual(self.observe(code=9), ("tool_error", ""))
        self.assertEqual(self.observe(diagnostic=b"inert error"), ("tool_error", ""))

    def test_output_limit(self):
        with patch.object(runner, "MAX_OUTPUT", 2):
            self.assertEqual(self.observe(b"[]"), ("ok", "[]"))
            self.assertEqual(self.observe(b"[]x"), ("output_limit", ""))


class OlefyTests(unittest.TestCase):
    def setUp(self):
        self.server = Mock()
        self.server.poll.return_value = None
        self.connection = Mock()
        self.connection.__enter__ = Mock(return_value=self.connection)
        self.connection.__exit__ = Mock(return_value=False)
        self.connection.recv.side_effect = [b"[]\t\n\n\t", b""]

    def observe(self, diagnostic=b"", clock=None):
        def start(_args, **kwargs):
            self.assertEqual(kwargs["env"]["OLEFY_BINDADDRESS"], "127.0.0.1")
            self.assertEqual(kwargs["env"]["OLEFY_LOGLVL"], "40")
            kwargs["stdout"].write(diagnostic)
            return self.server

        with patch.object(runner.subprocess, "Popen", side_effect=start), \
                patch.object(runner.socket, "create_connection",
                             return_value=self.connection) as connect, \
                patch.object(runner.time, "monotonic", side_effect=clock, return_value=0):
            try:
                result = runner.olefy(b"inert")
                if connect.called:
                    self.assertEqual(connect.call_args.args[0], ("127.0.0.1", 10050))
                return result
            finally:
                self.server.kill.assert_called_once_with()
                self.server.wait.assert_called_once_with(timeout=1)

    def test_protocol_success_and_lifetime(self):
        self.assertEqual(self.observe(), ("ok", "[]"))
        self.connection.sendall.assert_called_once_with(
            b"OLEFY/1.0\nMethod: oletools\nRspamd-ID: parity\n\ninert")
        self.connection.shutdown.assert_called_once_with(runner.socket.SHUT_WR)
        self.connection.__exit__.assert_called_once()

    def test_diagnostics_reject_valid_response(self):
        self.assertEqual(self.observe(diagnostic=b"olevba exited with code 9"), ("tool_error", ""))

    def test_truncated_framing(self):
        self.connection.recv.side_effect = [b"[]\t\n", b""]
        self.assertEqual(self.observe(), ("malformed_output", ""))

    def test_output_bound(self):
        with patch.object(runner, "MAX_OUTPUT", 5):
            self.assertEqual(self.observe(), ("output_limit", ""))

    def test_socket_timeout_still_kills_and_waits(self):
        self.connection.recv.side_effect = TimeoutError("inert timeout")
        with self.assertRaises(TimeoutError):
            self.observe()

    def test_deadline_and_startup_failure(self):
        self.assertEqual(self.observe(clock=[0, 9]), ("timeout", ""))
        self.server.reset_mock()
        self.server.poll.return_value = 1
        self.assertEqual(self.observe(), ("tool_error", ""))


class EnvelopeBudgetTests(unittest.TestCase):
    def setUp(self):
        self.identity = {"oletools_version": "pinned", "olefy_sha256": "a" * 64}

    def emit(self, output, status="ok", identity=None):
        stream = io.BytesIO()
        with patch.object(runner.sys, "stdout", SimpleNamespace(buffer=stream)):
            runner.emit_envelope(self.identity if identity is None else identity,
                                 status, output)
        raw = stream.getvalue()
        self.assertLessEqual(len(raw), runner.MAX_ENVELOPE)
        self.assertTrue(raw.endswith(b"\n"))
        return raw, json.loads(raw)

    def test_unicode_raw_response_fits_without_ascii_expansion(self):
        output = json.dumps(["é" * 500000], ensure_ascii=False)
        self.assertLessEqual(len(output.encode("utf-8")), runner.MAX_OUTPUT)
        raw, envelope = self.emit(output)
        self.assertEqual(envelope["status"], "ok")
        self.assertEqual(envelope["output"], output)
        self.assertIn("é".encode(), raw)

    def test_ascii_escaping_overflow_discards_output(self):
        output = json.dumps("\\" * ((runner.MAX_OUTPUT - 2) // 2))
        self.assertEqual(len(output.encode("utf-8")), runner.MAX_OUTPUT)
        raw, envelope = self.emit(output)
        self.assertEqual(envelope, {"identity": self.identity,
                                    "status": "output_limit", "output": ""})
        self.assertLess(len(raw), 256)

    def test_exact_byte_boundary_includes_newline(self):
        output = json.dumps(["é" * 100], ensure_ascii=False)
        raw, _ = self.emit(output)
        for budget, status in ((len(raw), "ok"), (len(raw) - 1, "output_limit")):
            with self.subTest(budget=budget), patch.object(runner, "MAX_ENVELOPE", budget):
                _, envelope = self.emit(output)
                self.assertEqual(envelope["status"], status)
                self.assertEqual(envelope["output"], output if status == "ok" else "")

    def test_error_and_identity_envelopes_are_bounded(self):
        for status in ("identity_error", "pin_mismatch", "tool_error", "timeout",
                       "input_error", "output_limit"):
            with self.subTest(status=status):
                _, envelope = self.emit("", status=status)
                self.assertEqual(envelope["status"], status)
        for version in ("é" * runner.MAX_ENVELOPE, "\ud800"):
            with self.subTest(oversized=len(version) > 1):
                raw, envelope = self.emit("", status="identity_error",
                                          identity={"oletools_version": version,
                                                    "olefy_sha256": "a" * 64})
                self.assertEqual(envelope, {"identity": {"oletools_version": "",
                                                         "olefy_sha256": ""},
                                            "status": "identity_error", "output": ""})
                self.assertLess(len(raw), 128)


class IdentityAndEnvelopeTests(unittest.TestCase):
    def invoke(self, data=b"inert", probe=None, error=None):
        probe = probe or {}
        source = b"inert source identity"
        source_hash = hashlib.sha256(source).hexdigest()
        stream = Mock()
        stream.read.return_value = data
        output = io.BytesIO()
        argv = ["runner", "oletools", "pinned", probe.get("expected_hash", source_hash)]
        opened = mock_open(read_data=source)
        if "read_error" in probe:
            opened.return_value.read.side_effect = probe["read_error"]
        if "source_error" in probe:
            opened.side_effect = probe["source_error"]
        with patch.object(runner.resource, "setrlimit") as limit, \
                patch.object(runner.importlib.metadata, "version",
                             return_value=probe.get("version", "pinned"),
                             side_effect=probe.get("version_error")), \
                patch("builtins.open", opened), \
                patch.object(runner.sys, "argv", argv), \
                patch.object(runner.sys, "stdin", SimpleNamespace(buffer=stream)), \
                patch.object(runner, "direct", return_value=("ok", "[]"),
                             side_effect=error) as direct, \
                patch.object(runner.sys, "stdout", SimpleNamespace(buffer=output)):
            runner.main()
        limit.assert_called_once_with(runner.resource.RLIMIT_FSIZE,
                                      (runner.MAX_INPUT + 1, runner.MAX_INPUT + 1))
        return json.loads(output.getvalue()), stream, direct

    def test_identity_before_input(self):
        for kwargs in ({"version": "wrong"}, {"expected_hash": "wrong"}):
            with self.subTest(kwargs=kwargs):
                envelope, stream, direct = self.invoke(probe=kwargs)
                self.assertEqual(envelope["status"], "pin_mismatch")
                stream.read.assert_not_called()
                direct.assert_not_called()

    def test_probe_failure_before_input(self):
        for kwargs in (
                {"version_error": runner.importlib.metadata.PackageNotFoundError("oletools")},
                {"source_error": PermissionError("inert denied source")},
                {"read_error": OSError("inert failed read")}):
            with self.subTest(kwargs=kwargs):
                envelope, stream, direct = self.invoke(probe=kwargs)
                self.assertEqual(envelope["status"], "identity_error")
                self.assertEqual(envelope["output"], "")
                stream.read.assert_not_called()
                direct.assert_not_called()

    def test_success_and_input_bounds(self):
        with patch.object(runner, "MAX_INPUT", 5):
            envelope, stream, direct = self.invoke(data=b"inert")
            self.assertEqual(envelope["status"], "ok")
            stream.read.assert_called_once_with(6)
            direct.assert_called_once_with(b"inert")
            for data in (b"", b"inert!"):
                envelope, _, direct = self.invoke(data=data)
                self.assertEqual(envelope["status"], "input_error")
                direct.assert_not_called()

    def test_exception_statuses_never_clean(self):
        for error, status in ((TimeoutError(), "timeout"),
                              (subprocess.TimeoutExpired("inert", 8), "timeout"),
                              (OSError(), "tool_error"), (UnicodeError(), "tool_error")):
            with self.subTest(error=error):
                envelope, _, _ = self.invoke(error=error)
                self.assertEqual(envelope["status"], status)
                self.assertEqual(envelope["output"], "")


if __name__ == "__main__":
    unittest.main()
