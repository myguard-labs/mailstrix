#!/usr/bin/env python3
"""Exercise the real profiling shell script with a hermetic curl recorder."""

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = "contrib/deploy/helm/mailstrix"
HELM_IMAGE = (
    "alpine/helm@sha256:"
    "aef9b56f64e866207d9591d0abd8f6d767b36aadd12edf68f8a719716d9d29c9"
)

CURL_RECORDER = (
    "import json,os,sys\n"
    "name=os.path.basename(sys.argv[1])\n"
    "args=sys.argv[2:]\n"
    'header=sys.stdin.read() if name=="curl" and "@-" in args else ""\n'
    'with open(os.environ["CAPTURE"],"a") as f:\n'
    ' f.write(json.dumps({"command":name,"argv":args,"header":header})+"\\n")\n'
    'if name=="date": print("fixture")\n'
    'if name=="mkdir": os.makedirs(args[-1],exist_ok=True)\n'
    'if name=="curl":\n'
    ' mode=os.environ["CURL_MODE"]\n'
    ' bounded="--connect-timeout" in args and "--max-time" in args\n'
    ' if mode=="require-deadlines" and not bounded: sys.exit(97)\n'
    ' out=args[args.index("-o")+1]\n'
    ' if mode in {"body-stall","partial"}: open(out,"wb").write(b"partial")\n'
    ' if mode in {"connect-stall","header-stall","body-stall"}: sys.exit(28)\n'
    ' if mode=="partial": sys.exit(18)\n'
    ' if mode=="http-error": sys.exit(22)\n'
    ' open(out,"wb").write(b"profile")\n'
    "sys.exit(0)\n"
)


def captured_outputs(output_dir):
    if not output_dir.exists():
        return {}
    return {path.name: path.read_bytes() for path in output_dir.iterdir()}


def render_chart(*set_values):
    """Render the real chart with a pinned Helm image and no network."""
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{ROOT}:/repo:ro",
        "-w",
        "/repo",
        HELM_IMAGE,
        "template",
        "strixd",
        CHART,
        "--namespace",
        "mailscreen",
    ]
    for value in set_values:
        command.extend(["--set-string", value])
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=60
    )
    if result.returncode != 0:
        raise AssertionError(f"helm template failed: {result.stderr}")
    return result.stdout


def rendered_objects(*set_values):
    return [
        document
        for document in yaml.safe_load_all(render_chart(*set_values))
        if document
    ]


def object_of_kind(objects, kind):
    found = [document for document in objects if document.get("kind") == kind]
    if len(found) != 1:
        raise AssertionError(f"expected one {kind}, found {len(found)}")
    return found[0]


class ProfileTokenTest(unittest.TestCase):
    def capture(self, token, duration="2", curl_mode="success", script=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Keep all children hermetic, including optional pprof and timestamp.
            for name in ["curl", "date", "go", "mkdir"]:
                path = root / name
                # A quoted shell launcher also supports interpreter paths with spaces.
                path.write_text(
                    f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
                    f'-c {shlex.quote(CURL_RECORDER)} "$0" "$@"\n'
                )
                path.chmod(0o755)
            capture = root / "calls"
            env = dict(
                os.environ,
                PATH=os.pathsep.join([tmp, os.defpath]),
                CAPTURE=str(capture),
                CURL_MODE=curl_mode,
                MAILSTRIX_TOKEN=token,
            )
            result = subprocess.run(
                [
                    "/bin/sh",
                    str(script or ROOT / "docker/pprof-capture.sh"),
                    "http://fixture.invalid:8079",
                    duration,
                    str(root / "out"),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            calls = (
                [json.loads(line) for line in capture.read_text().splitlines()]
                if capture.exists()
                else []
            )
            if token:
                self.assertNotIn(token, result.stdout + result.stderr)
            for call in calls:
                if token:
                    self.assertTrue(
                        all(token not in arg for arg in call["argv"]),
                        "profiling credential leaked into child argv",
                    )
            return (
                result,
                [call for call in calls if call["command"] == "curl"],
                captured_outputs(root / "out"),
            )

    def test_header_and_all_profiles(self):
        for token in [
            "",
            "synthetic-fixture-only",
            'synthetic "quote" \\ slash; $value',
        ]:
            with self.subTest(token_shape="empty" if not token else "nonempty"):
                result, calls, outputs = self.capture(token)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 4)
                self.assertEqual(
                    {name for name in outputs if name.endswith(".pb.gz")},
                    {"cpu.pb.gz", "heap.pb.gz", "allocs.pb.gz", "goroutine.pb.gz"},
                )
                for call, profile in zip(
                    calls,
                    ["profile?seconds=2", "heap", "allocs", "goroutine"],
                    strict=True,
                ):
                    self.assertIn(
                        "http://fixture.invalid:8079/debug/pprof/" + profile,
                        call["argv"],
                    )
                    self.assertEqual(
                        call["header"],
                        "Authorization: Bearer " + token + "\n" if token else "",
                    )
                    self.assertEqual("@-" in call["argv"], bool(token))
                    self.assertEqual(
                        call["argv"][call["argv"].index("--connect-timeout") + 1],
                        "5",
                    )

    def test_http_error_stops_capture(self):
        result, calls, outputs = self.capture(
            "synthetic-failure-fixture", curl_mode="http-error"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(outputs, {})

    def test_reject_header_line_breaks(self):
        for token in ["synthetic\nInjected: value", "synthetic\rInjected: value"]:
            result, calls, outputs = self.capture(token)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])
            self.assertEqual(outputs, {})

    def test_duration_boundary_and_malformed_inputs(self):
        result, calls, _outputs = self.capture("", duration="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("profile?seconds=1", calls[0]["argv"][-3])
        self.assertEqual(
            calls[0]["argv"][calls[0]["argv"].index("--max-time") + 1], "16"
        )

        result, calls, _outputs = self.capture("", duration="0002")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("profile?seconds=0002", calls[0]["argv"][-3])
        self.assertEqual(
            calls[0]["argv"][calls[0]["argv"].index("--max-time") + 1], "17"
        )

        result, calls, _outputs = self.capture("", duration="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("profile?seconds=30", calls[0]["argv"][-3])

        for duration in ["0", "-1", "1.5", "value", "999999985"]:
            with self.subTest(duration=duration):
                result, calls, outputs = self.capture("", duration=duration)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertEqual(outputs, {})

    def test_connection_header_and_body_stalls_fail_without_profiles(self):
        for mode in ["connect-stall", "header-stall", "body-stall", "partial"]:
            with self.subTest(mode=mode):
                result, calls, outputs = self.capture("", curl_mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)
                self.assertEqual(outputs, {})
                self.assertIn("--connect-timeout", calls[0]["argv"])
                self.assertIn("--max-time", calls[0]["argv"])

    def test_cpu_profile_allows_requested_duration_plus_grace(self):
        result, calls, _outputs = self.capture("", duration="61")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [call["argv"][call["argv"].index("--max-time") + 1] for call in calls],
            ["76", "15", "15", "15"],
        )

    def test_removed_deadlines_negative_control(self):
        source = (ROOT / "docker/pprof-capture.sh").read_text(encoding="utf-8")
        removed = re.sub(
            r' --connect-timeout "\$CONNECT_TIMEOUT" --max-time "\$3"', "", source
        )
        self.assertNotEqual(removed, source)
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "pprof-capture.sh"
            script.write_text(removed, encoding="utf-8")
            script.chmod(0o755)
            result, calls, _outputs = self.capture(
                "", curl_mode="require-deadlines", script=script
            )
        self.assertEqual(result.returncode, 97)
        self.assertEqual(len(calls), 1)

        result, calls, _outputs = self.capture("", curl_mode="require-deadlines")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 4)

    def test_helpers_use_selected_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "interpreter-calls"
            interpreter = root / "selected python"
            interpreter.write_text(
                "#!/bin/sh\nset -eu\n"
                'printf \'%s\\n\' "$3" >> "$PROFILE_INTERPRETER_TRACE"\n'
                f'exec {shlex.quote(sys.executable)} "$@"\n'
            )
            interpreter.chmod(0o755)
            with (
                mock.patch.object(sys, "executable", str(interpreter)),
                mock.patch.dict(os.environ, PROFILE_INTERPRETER_TRACE=str(trace)),
            ):
                result, calls, _outputs = self.capture("synthetic-interpreter-fixture")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls), 4)
            self.assertTrue(
                trace.exists(), "helpers bypassed the selected Python interpreter"
            )
            self.assertCountEqual(
                [Path(line).name for line in trace.read_text().splitlines()],
                ["date", "mkdir", *(["curl", "go"] * 4)],
            )


class DeploymentAuthContractTest(unittest.TestCase):
    def deployment_auth(self, *set_values):
        objects = rendered_objects(*set_values)
        deployment = object_of_kind(objects, "Deployment")
        pod = deployment["spec"]["template"]["spec"]
        container = pod["containers"][0]
        environment = {item["name"]: item for item in container["env"]}
        volumes = {item["name"]: item for item in pod["volumes"]}
        return objects, environment, volumes

    def test_render_errors_and_object_cardinality_are_explicit(self):
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="synthetic")
        with (
            mock.patch("subprocess.run", return_value=failed),
            self.assertRaisesRegex(AssertionError, "helm template failed: synthetic"),
        ):
            render_chart()
        with self.assertRaisesRegex(AssertionError, "expected one Secret, found 0"):
            object_of_kind([], "Secret")
        with self.assertRaisesRegex(AssertionError, "expected one Secret, found 2"):
            object_of_kind([{"kind": "Secret"}, {"kind": "Secret"}], "Secret")

    def test_no_token_renders_intentional_open_mode(self):
        objects, environment, volumes = self.deployment_auth()
        self.assertNotIn("MAILSTRIX_TOKEN_FILE", environment)
        self.assertNotIn("token", volumes)
        self.assertFalse(any(item.get("kind") == "Secret" for item in objects))
        notes = (ROOT / CHART / "templates/NOTES.txt").read_text(encoding="utf-8")
        self.assertIn(
            "if not (or .Values.token.value .Values.token.existingSecret)", notes
        )
        self.assertIn("HTTP 200", notes)
        self.assertIn("OPEN", notes)
        self.assertNotIn("HTTP 503", notes)

    def test_inline_token_renders_auth_and_owned_secret(self):
        token = "fixture-inline-token-with-128-bits-00000001"
        objects, environment, volumes = self.deployment_auth(f"token.value={token}")
        self.assertEqual(
            environment["MAILSTRIX_TOKEN_FILE"]["value"],
            "/run/secrets/strixd/token",
        )
        self.assertEqual(
            volumes["token"]["secret"]["secretName"], "strixd-mailstrix-token"
        )
        secret = object_of_kind(objects, "Secret")
        self.assertEqual(secret["stringData"], {"token": token})
        notes = (ROOT / CHART / "templates/NOTES.txt").read_text(encoding="utf-8")
        self.assertIn("HTTP 401", notes)
        self.assertNotIn("HTTP 503", notes)

    def test_existing_secret_renders_auth_without_copying_token(self):
        objects, environment, volumes = self.deployment_auth(
            "token.existingSecret=operator-token", "token.secretKey=credential"
        )
        self.assertEqual(
            environment["MAILSTRIX_TOKEN_FILE"]["value"],
            "/run/secrets/strixd/token",
        )
        self.assertEqual(
            volumes["token"]["secret"],
            {
                "secretName": "operator-token",
                "items": [{"key": "credential", "path": "token"}],
            },
        )
        self.assertFalse(any(item.get("kind") == "Secret" for item in objects))

    def test_existing_secret_takes_precedence_over_inline_boundary(self):
        objects, _environment, volumes = self.deployment_auth(
            "token.value=fixture-inline-token",
            "token.existingSecret=operator-token",
        )
        self.assertEqual(volumes["token"]["secret"]["secretName"], "operator-token")
        self.assertFalse(any(item.get("kind") == "Secret" for item in objects))

    def test_compose_enables_file_auth_without_false_503_promise(self):
        path = ROOT / "docker/docker-compose.yml"
        text = path.read_text(encoding="utf-8")
        compose = yaml.safe_load(text)
        service = compose["services"]["strixd"]
        self.assertEqual(
            service["environment"]["MAILSTRIX_TOKEN_FILE"],
            "/run/secrets/mailstrix_token",
        )
        self.assertEqual(
            compose["secrets"]["mailstrix_token"]["file"],
            "./secrets/mailstrix_token.txt",
        )
        self.assertNotIn("ports", service)
        self.assertIn("returns 401", text)
        self.assertIn("chmod 0444 secrets/mailstrix_token.txt", text)
        self.assertIn("container runs as uid 65532", text)
        self.assertNotIn("refuses every /scan (503)", text)

    def test_public_quick_start_uses_generated_file_secret_on_loopback(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("changeme", readme.casefold())
        self.assertIn("openssl rand -hex 32", readme)
        self.assertIn("MAILSTRIX_TOKEN_FILE=/run/secrets/token", readme)
        self.assertIn("127.0.0.1:8079:8079", readme)
        self.assertIn("--header @.mailstrix-secrets/curl-header", readme)
        self.assertNotRegex(readme, r"(?m)^\s*-p\s+8079:8079(?:\s|\\|$)")
        self.assertNotRegex(readme, r"(?m)^\s*-e\s+MAILSTRIX_TOKEN=")

    def test_helm_fresh_install_creates_namespace_before_secret(self):
        readme = (ROOT / CHART / "README.md").read_text(encoding="utf-8")
        install = (
            readme.split("## Install", 1)[1].split("```bash", 1)[1].split("```", 1)[0]
        )
        commands = [
            line.strip()
            for line in install.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        namespace = "kubectl create namespace mailscreen"
        secret = "kubectl -n mailscreen create secret generic strixd-token"
        self.assertIn(namespace, commands)
        self.assertTrue(any(line.startswith(secret) for line in commands))
        self.assertLess(
            commands.index(namespace),
            next(i for i, line in enumerate(commands) if line.startswith(secret)),
        )

    def test_helm_feed_install_uses_precreated_secret_namespace(self):
        readme = (ROOT / CHART / "README.md").read_text(encoding="utf-8")
        bash_blocks = re.findall(r"```bash\n(.*?)```", readme, flags=re.DOTALL)
        feed_blocks = [block for block in bash_blocks if "abuseChKey.value" in block]
        self.assertEqual(len(feed_blocks), 1, "expected one feed-enabled install block")
        secret_blocks = [
            block
            for block in bash_blocks
            if re.search(r"(?m)^\s*kubectl -n \S+ create secret generic \S+", block)
        ]
        self.assertEqual(len(secret_blocks), 1, "expected one Secret creation block")
        feed_command = " ".join(
            line.strip().removesuffix("\\").strip()
            for line in feed_blocks[0].splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        secret_command = " ".join(
            line.strip().removesuffix("\\").strip()
            for line in secret_blocks[0].splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        secret = re.search(
            r"kubectl -n (\S+) create secret generic (\S+)", secret_command
        )
        self.assertIsNotNone(secret, "pre-created Secret command is missing")
        namespace = re.search(r"(?:^| )--namespace (\S+)(?: |$)", feed_command)
        existing_secret = re.search(
            r"(?:^| )--set token\.existingSecret=(\S+)(?: |$)", feed_command
        )
        self.assertIsNotNone(namespace, "feed install namespace is missing")
        self.assertIsNotNone(existing_secret, "feed install Secret is missing")
        self.assertEqual(namespace.group(1), secret.group(1))
        self.assertEqual(existing_secret.group(1), secret.group(2))

    def test_no_runnable_placeholder_is_wildcard_published(self):
        paths = [ROOT / "README.md", ROOT / "docker/docker-compose.yml"]
        paths.extend((ROOT / "contrib/deploy").rglob("*"))
        placeholders = re.compile(r"(?i)(changeme|replace[-_ ]?me|your_secret)")
        wildcard = re.compile(
            r"(?m)(?:-p|--publish(?:=|\s+))\s*(?:0\.0\.0\.0:|\[?::\]?:)?8079:8079"
        )
        offenders = []
        scanned = 0
        for path in paths:
            if not path.is_file() or path.suffix not in {
                ".md",
                ".txt",
                ".yaml",
                ".yml",
            }:
                continue
            scanned += 1
            text = path.read_text(encoding="utf-8")
            if placeholders.search(text) and wildcard.search(text):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertGreater(scanned, 5, "deployment documentation scan was vacuous")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
