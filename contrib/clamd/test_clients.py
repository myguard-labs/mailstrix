"""Qualify two installed clamd clients against isolated Mailstrix listeners.

Requires clamd==1.0.2 in the selected Python environment and clamdscan on PATH.
The test server uses a 4096-byte limit and matches the exact MATCH bytes below.
The Go fixture injects this result; native qualification uses a local rule.
--scanner-error also checks ERROR using the Go fixture's injected engine error.
No sample downloads, path scans, quarantine actions, or external listeners.
"""

import argparse
import importlib.metadata
import io
import pathlib
import subprocess
import tempfile

import clamd

CLEAN = b"An ordinary inert mail attachment.\n"
MATCH = b"MAILSTRIX-CLAMD-MATCH"
ERROR = b"MAILSTRIX-CLAMD-ERROR"


def check_python(client, scanner_error):
    """Assert the installed Python client's parsed results and reconnection."""
    assert client.ping() == "PONG"
    assert client.version().startswith("Mailstrix ")
    assert client.instream(io.BytesIO(CLEAN)) == {"stream": ("OK", None)}
    assert client.instream(io.BytesIO(MATCH)) == {
        "stream": ("FOUND", "Mailstrix.Match")
    }
    if scanner_error:
        assert client.instream(io.BytesIO(ERROR)) == {
            "stream": ("ERROR", "scan failed")
        }
    try:
        client.instream(io.BytesIO(b"x" * 4097))
    except (clamd.BufferTooLongError, clamd.ConnectionError, OSError):
        # A daemon can reject while the client is still uploading.
        pass
    else:
        raise AssertionError("oversized stream was accepted")
    assert client.ping() == "PONG"
    # PATH commands are unsupported; probe recognition without opening a path.
    assert client._basic_command("SCAN /not-opened") == "UNKNOWN COMMAND"
    assert client.ping() == "PONG"


def check_clamdscan(binary, config, root, scanner_error):
    """Assert exit status and terminal result from the actual clamdscan binary."""
    cases = [("clean", CLEAN, 0, "OK"), ("match", MATCH, 1, "Mailstrix.Match FOUND")]
    if scanner_error:
        cases.append(("error", ERROR, 2, "scan failed ERROR"))
    cases.append(("oversize", b"x" * 4097, 2, None))
    cases.append(("reconnect", CLEAN, 0, "OK"))
    for name, body, status, marker in cases:
        sample = root / name
        sample.write_bytes(body)
        result = subprocess.run(
            [binary, "--stream", "--no-summary", f"--config-file={config}", str(sample)],
            capture_output=True, text=True, timeout=10, check=False,
        )
        output = result.stdout + result.stderr
        assert result.returncode == status, (name, result.returncode, output)
        if marker is not None:
            assert marker in output, (name, output)
        else:
            assert "ERROR" in output, (name, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unix", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--clamdscan", default="clamdscan")
    parser.add_argument("--scanner-error", action="store_true")
    args = parser.parse_args()
    version = importlib.metadata.version("clamd")
    assert version == "1.0.2", f"qualification pins clamd1.0.2, got {version}"
    print(f"python-clamd={version}")
    identity = subprocess.run(
        [args.clamdscan, "--version"], capture_output=True, text=True,
        timeout=10, check=False,
    )
    print(f"clamdscan identity: {identity.stdout.strip()}")
    with tempfile.TemporaryDirectory(prefix="mailstrix-clients-") as directory:
        root = pathlib.Path(directory)
        for transport in ("unix", "tcp"):
            config = root / "clamd.conf"
            if transport == "unix":
                config.write_text(f"LocalSocket {args.unix}\n", encoding="utf-8")
                client = clamd.ClamdUnixSocket(path=args.unix, timeout=5)
            else:
                config.write_text(
                    f"TCPAddr {args.host}\nTCPSocket {args.port}\n", encoding="utf-8"
                )
                client = clamd.ClamdNetworkSocket(host=args.host, port=args.port, timeout=5)
            check_python(client, args.scanner_error)
            print(f"PASS python-clamd {transport}: clean/match/oversize/reconnect"
                  + ("/scanner-error" if args.scanner_error else ""))
            check_clamdscan(args.clamdscan, config, root, args.scanner_error)
            print(f"PASS clamdscan {transport}: clean/match/oversize/reconnect"
                  + ("/scanner-error" if args.scanner_error else ""))


if __name__ == "__main__":
    main()
