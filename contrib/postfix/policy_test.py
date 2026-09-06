"""Exercise the shipped policy with real Postfix, strix-milter and strixd.

Run only in Dockerfile.integration with --network none: no host queues or SMTP ports.
All messages are harmless and remain in the container's isolated queue.
"""

import json
import re
import smtplib
import socket
import subprocess
import time
from pathlib import Path


def run(*args):
    """Run a fixed local test command with bounded execution."""
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15).stdout


def wait_port(port):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"service on port {port} did not become ready")


def submit(subject, body, verdict, held):
    message = (
        "From: sender@example.test\r\nTo: recipient@example.test\r\n"
        f"Subject: {subject}\r\n\r\n{body}\r\n"
    )
    with smtplib.SMTP("127.0.0.1", 25, timeout=10) as smtp:
        smtp.ehlo()
        if smtp.mail("sender@example.test")[0] != 250:
            raise AssertionError("MAIL was not accepted")
        if smtp.rcpt("recipient@example.test")[0] != 250:
            raise AssertionError("RCPT was not accepted")
        code, reply = smtp.data(message)
    if code != 250:
        raise AssertionError(f"message was not accepted: {code} {reply!r}")
    match = re.search(rb"queued as ([A-Z0-9]+)", reply)
    if match is None:
        raise AssertionError(f"missing queue ID: {reply!r}")
    queue_id = match[1].decode("ascii")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        entries = [json.loads(line) for line in run("postqueue", "-j").splitlines()]
        entry = next((item for item in entries if item["queue_id"] == queue_id), None)
        if entry is not None:
            break
        time.sleep(0.1)
    else:
        raise AssertionError(f"{subject}: message missing from isolated queue")
    content = run("postcat", "-qh", queue_id)
    if verdict is None and "X-Mailstrix-Status:" in content:
        raise AssertionError(f"{subject}: unexpected verdict while milter is unavailable")
    if verdict is not None and f"X-Mailstrix-Status: {verdict}" not in content:
        raise AssertionError(f"{subject}: expected actual milter verdict {verdict}")
    if (entry["queue_name"] == "hold") != held:
        raise AssertionError(f"{subject}: expected held={held}, got queue={entry['queue_name']}")
    print(f"PASS {subject}: verdict={verdict}, queue={entry['queue_name']}", flush=True)


def main():
    if not Path("/.dockerenv").exists():
        raise RuntimeError("this test must run in its disposable Docker container")
    rules = Path("/fixture/rules")
    rules.mkdir()
    # Require both RFC5322 headers and the harmless antivirus marker.
    (rules / "test.yar").write_text(
        'rule Postfix_EICAR { strings: $h = "Subject: eicar" '
        '$e = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" condition: all of them }\n',
        encoding="utf-8",
    )
    config = Path("/etc/postfix/main.cf")
    config.write_text(
        config.read_text(encoding="utf-8") + "\n"
        + Path("/fixture/main.cf.example").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    Path("/etc/postfix/milter_header_checks").write_text(
        Path("/fixture/milter_header_checks.example").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    run("postconf", "-e", "myhostname = policy.example.test", "inet_interfaces = loopback-only",
        "inet_protocols = ipv4", "mynetworks = 127.0.0.0/8", "mydestination =",
        "defer_transports = smtp", "maillog_file = /dev/stdout")
    scanner = subprocess.Popen(["/usr/local/bin/strixd", "serve", "-rules-dir", str(rules)])
    milter = None
    try:
        wait_port(8079)
        milter = subprocess.Popen(["/usr/local/bin/strix-milter", "-url", "http://127.0.0.1:8079"])
        wait_port(8081)
        run("postfix", "start")
        wait_port(25)
        eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!' + '$H+H*'
        submit("eicar", eicar, "infected", True)
        submit("clean", "hello from the isolated integration test", "clean", False)
        scanner.terminate()
        scanner.wait(timeout=10)
        submit("scanner unavailable", "harmless message", "unknown", False)
        milter.terminate()
        milter.wait(timeout=10)
        submit("milter unavailable", "harmless message", None, False)
        print("ALL OK: real Postfix milter policy", flush=True)
    finally:
        if milter is not None and milter.poll() is None:
            milter.terminate()
            milter.wait(timeout=10)
        if scanner.poll() is None:
            scanner.terminate()
            scanner.wait(timeout=10)


if __name__ == "__main__":
    main()
