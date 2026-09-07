"""Embedded, test-only entrypoint for one sample in an isolated container.

The host supplies no paths, credentials or network access. Raw tool responses
remain in the bounded pipe to the host normalizer, never in the public report.
"""

import hashlib
import importlib.metadata
import json
import os
import resource
import socket
import subprocess
import sys
import tempfile
import time

MAX_INPUT = 16 << 20
MAX_OUTPUT = 1 << 20
SCAN_SECONDS = 8
OLEVBA = os.path.join(os.path.dirname(sys.executable), "olevba")


def direct(data):
    with open("/tmp/sample", "wb") as sample:
        sample.write(data)
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostic:
        result = subprocess.run(
            [sys.executable, OLEVBA, "-a", "-j", "-l", "error", "/tmp/sample"],
            stdin=subprocess.DEVNULL, stdout=output, stderr=diagnostic,
            timeout=SCAN_SECONDS, check=False,
        )
        output.seek(0)
        raw = output.read(MAX_OUTPUT + 1)
        diagnostic.seek(0)
        if diagnostic.read(1) or result.returncode != 0:
            return "tool_error", ""
        if len(raw) > MAX_OUTPUT:
            return "output_limit", ""
        return "ok", raw.decode("utf-8")


def olefy(data):
    env = {
        "PATH": os.path.dirname(sys.executable) + ":/usr/local/bin:/usr/bin:/bin",
        "OLEFY_BINDADDRESS": "127.0.0.1",
        "OLEFY_BINDPORT": "10050",
        "OLEFY_PYTHON_PATH": sys.executable,
        "OLEFY_OLEVBA_PATH": OLEVBA,
        "OLEFY_LOGLVL": "40",
        "OLEFY_MINLENGTH": "500",
        "OLEFY_DEL_TMP": "1",
        "OLEFY_DEL_TMP_FAILED": "1",
        "OLEFY_TMPDIR": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    deadline = time.monotonic() + SCAN_SECONDS
    with tempfile.TemporaryFile() as diagnostic:
        server = subprocess.Popen(
            # The pinned source's address regex emits this compile-time
            # warning on Python 3.13. No runtime/logging errors are suppressed.
            [sys.executable, "-W", "ignore:invalid escape sequence:SyntaxWarning",
             "/usr/local/bin/olefy.py"],
            stdin=subprocess.DEVNULL, stdout=diagnostic, stderr=diagnostic, env=env,
        )
        try:
            while True:
                if server.poll() is not None:
                    return "tool_error", ""
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "timeout", ""
                try:
                    connection = socket.create_connection(("127.0.0.1", 10050), min(remaining, 0.2))
                    break
                except ConnectionRefusedError:
                    time.sleep(0.02)
            raw = bytearray()
            with connection:
                connection.settimeout(max(0.001, deadline - time.monotonic()))
                connection.sendall(b"OLEFY/1.0\nMethod: oletools\nRspamd-ID: parity\n\n" + data)
                connection.shutdown(socket.SHUT_WR)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return "timeout", ""
                    connection.settimeout(remaining)
                    chunk = connection.recv(min(65536, MAX_OUTPUT + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > MAX_OUTPUT:
                        return "output_limit", ""
        finally:
            server.kill()
            server.wait(timeout=1)
        # olefy can return valid-looking JSON despite a nonzero olevba exit.
        # Its ERROR log is load-bearing: any daemon diagnostic withholds success.
        diagnostic.seek(0)
        if diagnostic.read(1):
            return "tool_error", ""
        if not raw.endswith(b"\t\n\n\t"):
            return "malformed_output", ""
        return "ok", raw[:-4].decode("utf-8")


def main():
    # Enforced on the children too. /tmp and cgroup limits additionally bound
    # aggregate file space, memory and processes; the host enforces wall time.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_INPUT + 1, MAX_INPUT + 1))
    identity = {"oletools_version": "", "olefy_sha256": ""}
    status, output = "identity_error", ""
    try:
        try:
            identity["oletools_version"] = importlib.metadata.version("oletools")
            with open("/usr/local/bin/olefy.py", "rb") as source:
                identity["olefy_sha256"] = hashlib.sha256(source.read()).hexdigest()
        except (importlib.metadata.PackageNotFoundError, OSError):
            print(json.dumps({"identity": identity, "status": "identity_error", "output": ""}))
            return
        if identity["oletools_version"] != sys.argv[2] or identity["olefy_sha256"] != sys.argv[3]:
            status = "pin_mismatch"
        else:
            # Probe before reading or parsing any document bytes.
            data = sys.stdin.buffer.read(MAX_INPUT + 1)
            if not data or len(data) > MAX_INPUT:
                status = "input_error"
            elif sys.argv[1] == "oletools":
                status, output = direct(data)
            elif sys.argv[1] == "olefy":
                status, output = olefy(data)
            else:
                status = "input_error"
    except (subprocess.TimeoutExpired, TimeoutError):
        status = "timeout"
    except (OSError, UnicodeError, ValueError):
        status = "tool_error"
    print(json.dumps({"identity": identity, "status": status, "output": output}))


if __name__ == "__main__":
    main()
