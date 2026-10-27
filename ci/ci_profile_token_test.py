#!/usr/bin/env python3
"""Exercise the real profiling shell script with a hermetic curl recorder."""

import json
import os
import re
import shlex
import shutil
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


def render_chart(*set_values):
    """Render the real chart with a pinned Helm image and no network."""
    helm = os.environ.get("MAILSTRIX_HELM")
    if helm:
        command = [helm, "template", "strixd", str(ROOT / CHART)]
    else:
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
        ]
    command.extend(["--namespace", "mailscreen"])
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


def render_notes(*set_values, template=None):
    """Render NOTES through Helm, exposing its special template as test YAML."""
    source_chart = ROOT / CHART
    with tempfile.TemporaryDirectory() as tmp:
        chart = Path(tmp) / "chart"
        shutil.copytree(source_chart, chart)
        notes_path = chart / "templates/NOTES.txt"
        notes = template or notes_path.read_text(encoding="utf-8")
        notes_path.unlink()
        (chart / "templates/notes-contract.yaml").write_text(
            '{{- define "mailstrix.notesContract" -}}\n'
            + notes
            + "\n{{- end }}\n"
            + "apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
            + "  name: notes-contract\ndata:\n  notes: |-\n"
            + '{{ include "mailstrix.notesContract" . | nindent 4 }}\n',
            encoding="utf-8",
        )
        helm = os.environ.get("MAILSTRIX_HELM")
        if helm:
            command = [helm, "template", "strixd", str(chart)]
        else:
            command = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{chart}:/chart:ro",
                HELM_IMAGE,
                "template",
                "strixd",
                "/chart",
            ]
        command.extend(["--namespace", "mailscreen"])
        for value in set_values:
            command.extend(["--set-string", value])
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=60
        )
        if result.returncode != 0:
            raise AssertionError(f"Helm NOTES render failed: {result.stderr}")
        objects = [item for item in yaml.safe_load_all(result.stdout) if item]
        notes_object = next(
            item
            for item in objects
            if item.get("kind") == "ConfigMap"
            and item.get("metadata", {}).get("name") == "notes-contract"
        )
        return notes_object["data"]["notes"]


def credentialed_redis_url(userinfo, target, scheme="redis"):
    """Build synthetic credential-bearing URLs without storing secret-like URIs."""
    return f"{scheme}://{userinfo}@{target}"


def assert_postfix_scanner_example(readme):
    """Validate the documented host token file and matching read-only mount."""
    setup = readme.split("1. **Run the scanner**", 1)[1].split(
        "2. **Install the milter**", 1
    )[0]
    mount = re.search(
        r'-v\s+"\$PWD/(?P<source>[^:"]+):(?P<destination>[^:"]+):ro"', setup
    )
    token_file = re.search(r"MAILSTRIX_TOKEN_FILE=(?P<path>/\S+)", setup)
    if mount is None or token_file is None:
        raise AssertionError(
            "scanner example needs a read-only token bind and file env"
        )
    if mount.group("destination") != token_file.group("path"):
        raise AssertionError("token bind destination must match MAILSTRIX_TOKEN_FILE")
    source = mount.group("source")
    if f"openssl rand -hex 32 > {source}" not in setup:
        raise AssertionError("scanner example must provision the mounted token file")
    if f"rm -f {source}" not in setup:
        raise AssertionError("scanner example must support safe token rotation")
    if f"chmod 0444 {source}" not in setup:
        raise AssertionError(
            "mounted token must be readable by the unprivileged container"
        )
    if "../../README.md#quick-start" not in setup:
        raise AssertionError("scanner example must link the maintained prerequisites")
    if "MAILSTRIX_TOKEN=" in setup or "changeme" in setup.casefold():
        raise AssertionError("scanner example must not contain an inline token value")
    if re.search(r"myguard-labs/mailstrix:[^\s]+", setup):
        raise AssertionError("scanner example must not invent an image version")


class ProfileTokenTest(unittest.TestCase):
    def capture(self, token, fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder = (
                "import json,os,sys\n"
                "name=os.path.basename(sys.argv[1])\n"
                "args=sys.argv[2:]\n"
                'header=sys.stdin.read() if name=="curl" and "@-" in args else ""\n'
                'with open(os.environ["CAPTURE"],"a") as f:\n'
                ' f.write(json.dumps({"command":name,"argv":args,"header":header})+"\\n")\n'
                'if name=="date": print("fixture")\n'
                'if name=="mkdir": os.makedirs(args[-1],exist_ok=True)\n'
                'sys.exit(int(os.environ["CURL_EXIT"]) if name=="curl" else 0)\n'
            )
            # Keep all children hermetic, including optional pprof and timestamp.
            for name in ["curl", "date", "go", "mkdir"]:
                path = root / name
                # A quoted shell launcher also supports interpreter paths with spaces.
                path.write_text(
                    f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
                    f'-c {shlex.quote(recorder)} "$0" "$@"\n'
                )
                path.chmod(0o755)
            capture = root / "calls"
            env = dict(
                os.environ,
                PATH=tmp,
                CAPTURE=str(capture),
                CURL_EXIT="22" if fail else "0",
                MAILSTRIX_TOKEN=token,
            )
            result = subprocess.run(
                [
                    "/bin/sh",
                    str(ROOT / "docker/pprof-capture.sh"),
                    "http://fixture.invalid:8079",
                    "2",
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
            return result, [call for call in calls if call["command"] == "curl"]

    def test_header_and_all_profiles(self):
        for token in [
            "",
            "synthetic-fixture-only",
            'synthetic "quote" \\ slash; $value',
        ]:
            with self.subTest(token_shape="empty" if not token else "nonempty"):
                result, calls = self.capture(token)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 4)
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

    def test_curl_failure_stops_capture(self):
        result, calls = self.capture("synthetic-failure-fixture", fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)

    def test_reject_header_line_breaks(self):
        for token in ["synthetic\nInjected: value", "synthetic\rInjected: value"]:
            result, calls = self.capture(token)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])

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
                result, calls = self.capture("synthetic-interpreter-fixture")
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

    def test_postfix_scanner_example_mounts_operator_token_read_only(self):
        readme = (ROOT / "contrib/postfix/README.md").read_text(encoding="utf-8")
        assert_postfix_scanner_example(readme)

    def test_postfix_scanner_example_removal_controls(self):
        readme = (ROOT / "contrib/postfix/README.md").read_text(encoding="utf-8")
        for broken in [
            readme.replace(
                ":/run/secrets/mailstrix_token:ro", ":/run/secrets/mailstrix_token"
            ),
            readme.replace(
                "MAILSTRIX_TOKEN_FILE=/run/secrets/mailstrix_token",
                "MAILSTRIX_TOKEN_FILE=/run/secrets/other-token",
            ),
            readme.replace("rm -f .mailstrix-secrets/token\n", ""),
            readme.replace("chmod 0444 .mailstrix-secrets/token\n", ""),
        ]:
            with self.subTest(), self.assertRaises(AssertionError):
                assert_postfix_scanner_example(broken)

    def test_multi_replica_notes_redact_redis_userinfo(self):
        credentials = [
            credentialed_redis_url("user:synthetic-pass", "valkey:6379/6"),
            credentialed_redis_url(
                "user%40domain:p%40ss%2Fword", "valkey:6380/0", scheme="rediss"
            ),
            credentialed_redis_url("user:p@ss", "valkey:6379/6"),
            credentialed_redis_url("user:synthetic-pass", "valkey:6379/6", "REDIS"),
            credentialed_redis_url(
                "user:synthetic-pass", "sentinel:26379/mymaster", "redis+sentinel"
            ),
            credentialed_redis_url(":synthetic-pass", "valkey:6379/6"),
        ]
        for redis_url in credentials:
            with self.subTest(redis_url=redis_url):
                notes = render_notes("replicaCount=2", f"redis.url={redis_url}")
                self.assertIn("Shared verdict cache is configured", notes)
                self.assertIn("credentials redacted", notes)
                self.assertNotIn(redis_url, notes)
                self.assertNotIn(redis_url.rsplit("@", 1)[1], notes)

    def test_multi_replica_notes_preserve_safe_and_missing_redis_guidance(self):
        safe_url = "redis://valkey:6379/6"
        configured = render_notes("replicaCount=2", f"redis.url={safe_url}")
        self.assertIn(f"Shared verdict cache via {safe_url}.", configured)
        missing = render_notes("replicaCount=2")
        self.assertIn("WARNING: redis.url is NOT set", missing)
        self.assertNotIn("Shared verdict cache via", missing)

    def test_one_replica_notes_omit_redis_section(self):
        redis_url = credentialed_redis_url("user:synthetic-pass", "valkey:6379/6")
        notes = render_notes("replicaCount=1", f"redis.url={redis_url}")
        self.assertNotIn("Shared verdict cache via", notes)
        self.assertNotIn("WARNING: redis.url is NOT set", notes)
        self.assertNotIn(redis_url, notes)

    def test_notes_redaction_removal_control_leaks_fixture(self):
        path = ROOT / CHART / "templates/NOTES.txt"
        template = path.read_text(encoding="utf-8")
        broken = template.replace('contains "@" .Values.redis.url', "false", 1)
        self.assertNotEqual(broken, template)
        fixture = credentialed_redis_url("user:synthetic-pass", "valkey:6379/6")
        leaked = render_notes("replicaCount=2", f"redis.url={fixture}", template=broken)
        self.assertIn(fixture, leaked)

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
