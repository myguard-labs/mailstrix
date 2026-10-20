"""Exercise the required CI check against the shipped workflow script."""

import hashlib
import itertools
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
OPTIONAL = ("PARITY", "LINT", "RSPAMD", "SPAMASSASSIN")
ROOT = Path(__file__).resolve().parents[1]


class DockerGateTimeoutContract(unittest.TestCase):
    """The authoritative docker job must keep headroom over measured runtimes."""

    SLOWEST_MEASURED_SUCCESS_MINUTES = 42.04  # ci + nightly runs, 2026-10
    MIN_HEADROOM = 1.4

    def assert_headroom(self, source):
        job = yaml.safe_load(source)["jobs"]["docker"]
        self.assertGreaterEqual(
            job["timeout-minutes"],
            self.SLOWEST_MEASURED_SUCCESS_MINUTES * self.MIN_HEADROOM,
        )

    def test_shipped_docker_timeout_has_headroom(self):
        self.assert_headroom(WORKFLOW.read_text())

    def test_old_cap_and_malformed_values_fail(self):
        for value in (45, 30, 0):
            with self.subTest(value=value):
                workflow = yaml.safe_load(WORKFLOW.read_text())
                workflow["jobs"]["docker"]["timeout-minutes"] = value
                with self.assertRaises(AssertionError):
                    self.assert_headroom(yaml.safe_dump(workflow))
        workflow = yaml.safe_load(WORKFLOW.read_text())
        del workflow["jobs"]["docker"]["timeout-minutes"]
        with self.assertRaises(KeyError):
            self.assert_headroom(yaml.safe_dump(workflow))


class CheckoutCredentialContract(unittest.TestCase):
    """Reject persisted checkout credentials before repository container mounts."""

    def assert_safe_checkouts(self, source):
        workflow = yaml.safe_load(source)
        self.assertEqual(workflow["permissions"]["contents"], "read")
        for name in ("changes", "compiler-inputs"):
            job = workflow["jobs"][name]
            self.assertEqual(
                job.get("permissions", workflow["permissions"])["contents"], "read"
            )
            checkouts = [
                step
                for step in job["steps"]
                if step.get("uses", "").startswith("actions/checkout@")
            ]
            self.assertTrue(checkouts, name + " requires a checkout")
            for checkout in checkouts:
                self.assertIs(
                    checkout.get("with", {}).get("persist-credentials"),
                    False,
                    name + " checkout must explicitly disable persisted credentials",
                )

    def test_shipped_checkout_credentials_are_disabled(self):
        self.assert_safe_checkouts(WORKFLOW.read_text())

    def test_unsafe_checkout_controls(self):
        for name in ("changes", "compiler-inputs"):
            for value in (None, True, "false", "true", 0, [], {}):
                with self.subTest(job=name, value=value):
                    workflow = yaml.safe_load(WORKFLOW.read_text())
                    checkout = workflow["jobs"][name]["steps"][0]
                    if value is None:
                        del checkout["with"]["persist-credentials"]
                    else:
                        checkout["with"]["persist-credentials"] = value
                    with self.assertRaises(AssertionError):
                        self.assert_safe_checkouts(yaml.safe_dump(workflow))
            for mutation in ("missing-job", "missing-checkout", "unsafe-extra"):
                with self.subTest(job=name, mutation=mutation):
                    workflow = yaml.safe_load(WORKFLOW.read_text())
                    if mutation == "missing-job":
                        del workflow["jobs"][name]
                    elif mutation == "missing-checkout":
                        workflow["jobs"][name]["steps"].pop(0)
                    else:
                        workflow["jobs"][name]["steps"].append(
                            {"uses": "actions/checkout@unsafe"}
                        )
                    with self.assertRaises((AssertionError, KeyError)):
                        self.assert_safe_checkouts(yaml.safe_dump(workflow))

    def test_broadened_contents_permissions_controls(self):
        for scope in ("workflow", "changes", "compiler-inputs"):
            with self.subTest(scope=scope):
                workflow = yaml.safe_load(WORKFLOW.read_text())
                target = workflow if scope == "workflow" else workflow["jobs"][scope]
                target["permissions"] = {"contents": "write"}
                with self.assertRaises(AssertionError):
                    self.assert_safe_checkouts(yaml.safe_dump(workflow))


class NativePrerequisiteTests(unittest.TestCase):
    """Exercise the real shell entrypoint with isolated daemon and key controls."""

    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temporary)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.root / "ci").mkdir()
        (self.root / "docker").mkdir()
        self.script = self.root / "ci/compiler-input-check.sh"
        self.source = (ROOT / "ci/compiler-input-check.sh").read_text()
        self.script.write_text(self.source)
        for name in (
            "compiler-input-capture.h",
            "patch-compiler-input-capture.py",
            "capture-compiler-inputs.py",
            "export-compiler-inputs.py",
            "build-marker-artifact.py",
            "Dockerfile",
        ):
            shutil.copyfile(ROOT / "docker" / name, self.root / "docker" / name)
        self.env = os.environ | {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "NATIVE_FIXTURE": str(self.root),
            "MX_INPUT_STAGE_MODE": "callable",
        }
        self.command(
            "docker",
            """#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$NATIVE_FIXTURE/docker.log"
case "$1" in
    info) exit "${NATIVE_DAEMON_EXIT:-0}" ;;
    build)
        [ "$2" = --builder ] && [ "$3" = default ] || exit 9
        for context do :; done
        cp "$context/deb.myguard.nl.gpg" "$NATIVE_FIXTURE/public-key.gpg"
        cp "$context/Dockerfile" "$NATIVE_FIXTURE/production-stage"
        exit "${NATIVE_BUILD_EXIT:-0}"
        ;;
    image)
        if [ "$2" = save ]; then
            printf native-image > "$5"
        fi
        ;;
    run)
        [ "${NATIVE_RUN_EXIT:-0}" = 0 ] || exit "$NATIVE_RUN_EXIT"
        case "$*" in
            *"coverage report"*)
                if [ -n "${NATIVE_COVERAGE_FILE:-}" ]; then
                    for argument do :; done
                    report="${argument##* && }"
                    report="${report#COVERAGE_FILE=/evidence/export.coverage }"
                    COVERAGE_FILE="$NATIVE_COVERAGE_FILE" sh -c "$report"
                fi
                ;;
            *"prepare-marker /proof/fixture /rules"*)
                for argument do
                    case "$argument" in *:/proof) context="${argument%:/proof}" ;; esac
                done
                mkdir "$context/rules"
                printf main > "$context/rules/compiled.yac"
                printf local > "$context/rules/local.yac"
                printf '4.5.2\\n' > "$context/rules/libyara.version"
                printf '[]\\n' > "$context/rules/sources.json"
                ;;
            *"verify /export"*)
                [ "${NATIVE_VERIFY_BYPASS:-0}" = 0 ] || exit 0
                for argument do
                    case "$argument" in *:/export:ro) exported="${argument%:/export:ro}" ;; esac
                done
                if [ ! -f "$exported/compiler-inputs/index.json" ]; then
                    echo 'missing compiler-inputs/index.json' >&2
                    exit 1
                fi
                ;;
        esac
        ;;
    buildx)
        if [ "$2" = inspect ]; then
            [ "$#" = 3 ] && [ "$3" = default ] || exit 9
            [ "${NATIVE_BUILDER_EXIT:-0}" = 0 ] || exit "$NATIVE_BUILDER_EXIT"
            printf 'Driver:  %s\\n' "${NATIVE_BUILDER_DRIVER-docker}"
            exit 0
        fi
        [ "$2" = build ] && [ "$3" = --builder ] && [ "$4" = default ] || exit 9
        [ "${NATIVE_TRANSFER_EXIT:-0}" = 0 ] || exit "$NATIVE_TRANSFER_EXIT"
        for argument do
            case "$argument" in
                type=local,dest=*) destination="${argument#type=local,dest=}" ;;
            esac
            context="$argument"
        done
        mkdir -p "$destination"
        cp "$context/rules/compiled.yac" "$context/rules/local.yac" \
            "$context/rules/libyara.version" "$context/rules/sources.json" "$destination/"
        case "$*" in
            *Dockerfile.omission*) ;;
            *)
                mkdir "$destination/compiler-inputs"
                printf '{}' > "$destination/compiler-inputs/index.json"
                ;;
        esac
        ;;
esac
""",
        )

    def command(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)

    def run_script(self, *arguments):
        return subprocess.run(
            ["/bin/sh", str(self.script), *arguments],
            env=self.env,
            capture_output=True,
            check=False,
        )

    def test_pinned_public_key_bootstrap_and_cleanup(self):
        # A missing host key is supported: the only trust input is the pinned
        # public key embedded in the checked entrypoint, with no host copy.
        self.assertNotIn("cp /etc/apt/keyrings", self.source)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            hashlib.sha256((self.root / "public-key.gpg").read_bytes()).hexdigest(),
            "9744a10c48237234dcb762b5f7326ed21b6944a6f079cc3624169edf90118bdc",
        )
        stage = (self.root / "production-stage").read_text()
        self.assertIn("signed-by=/etc/apt/keyrings/deb.myguard.nl.gpg", stage)
        self.assertIn("http://deb.myguard.nl:8888 bookworm main", stage)
        self.assertNotIn("trusted=yes", stage)
        self.assertNotIn("# ---- go build", stage)
        calls = (self.root / "docker.log").read_text().splitlines()
        context = Path(
            next(line for line in calls if line.startswith("build ")).split()[-1]
        )
        self.assertFalse(context.exists())
        self.assertTrue(any(line.startswith("run --rm ") for line in calls))
        self.assertTrue(any(line.startswith("container rm -f ") for line in calls))
        self.assertTrue(any(line.startswith("image rm ") for line in calls))
        transfers = [line for line in calls if line.startswith("buildx build ")]
        self.assertEqual(len(transfers), 3)
        self.assertEqual(sum("Dockerfile.omission" in line for line in transfers), 1)
        self.assertTrue(
            any("--network none" in line and "replay /export" in line for line in calls)
        )

    def test_callable_fixture_has_no_git_dependency(self):
        self.command("git", "#!/bin/sh\necho unexpected-git >&2\nexit 99\n")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"unexpected-git", result.stderr)

    def test_native_stage_copy_inputs_fit_minimal_context(self):
        # Validate the local COPY sources while the real entrypoint's context
        # exists. Consume the shipped fixture stages rather than restating
        # their source names: including any of them requires a larger context.
        validator = self.root / "context_contract.py"
        validator.write_text(
            """from pathlib import Path
import shlex
import sys

context = Path(sys.argv[1])
source = (context / 'Dockerfile').read_text().replace('\\\\\\n', ' ')
for line in source.splitlines():
    tokens = shlex.split(line, comments=True)
    if not tokens or tokens[0].upper() != 'COPY':
        continue
    if any(token.startswith('--from=') for token in tokens[1:]):
        continue
    for name in tokens[1:-1]:
        if not list(context.glob(name)):
            raise SystemExit('COPY input missing from native context: ' + name)
"""
        )
        docker = self.bin / "docker"
        original_command = docker.read_text()
        docker.write_text(
            original_command.replace(
                '        cp "$context/deb.myguard.nl.gpg"',
                '        python3 "$NATIVE_FIXTURE/context_contract.py" "$context"\n'
                '        cp "$context/deb.myguard.nl.gpg"',
                1,
            )
        )
        dockerfile = self.root / "docker/Dockerfile"
        production = dockerfile.read_text()
        stages = list(re.finditer(r"^FROM .+", production, re.MULTILINE))
        fixture_stage = production[stages[1].start() : stages[2].start()]
        inserted = fixture_stage.replace("AS marker-fixture", "AS inserted-fixture", 1)
        for source in (
            production,
            production[: stages[1].start()]
            + inserted
            + production[stages[1].start() :],
        ):
            with self.subTest(inserted=source != production):
                dockerfile.write_text(source)
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_evidence_skips_image_save(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root / "docker.log").read_text().splitlines()
        self.assertFalse(any(line.startswith("image save ") for line in calls))
        self.assertTrue(any("coverage report" in line for line in calls))
        self.assertTrue(any("replay /export" in line for line in calls))

    def test_explicit_empty_or_new_evidence_retains_image(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                evidence = self.root / str(existing)
                if existing:
                    evidence.mkdir()
                self.env["MX_INPUT_EVIDENCE_DIR"] = str(evidence)
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    (evidence / "native-image.tar").read_bytes(), b"native-image"
                )
                self.assertTrue((evidence / "native-source/Dockerfile").is_file())
                calls = (self.root / "docker.log").read_text()
                self.assertIn("coverage report", calls)
                self.assertIn("replay /export", calls)
                before = (evidence / "native-image.tar").read_bytes()
                repeat = self.run_script()
                self.assertNotEqual(repeat.returncode, 0)
                self.assertIn(b"invalid evidence directory", repeat.stderr)
                self.assertEqual(
                    (self.root / "docker.log").read_text(),
                    calls + "info\nbuildx inspect default\n",
                )
                self.assertEqual((evidence / "native-image.tar").read_bytes(), before)

    def test_invalid_evidence_rejects_before_owned_resources(self):
        self.command(
            "mktemp", '#!/bin/sh\ntouch "$NATIVE_FIXTURE/scratch-created"\nexit 99\n'
        )
        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / ".keep").write_text("preserve")
        file = self.root / "file"
        file.write_text("preserve")
        for evidence in (occupied, file, file / "child"):
            with self.subTest(evidence=evidence):
                self.env["MX_INPUT_EVIDENCE_DIR"] = str(evidence)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"invalid evidence directory", result.stderr)
                calls = (self.root / "docker.log").read_text().splitlines()
                self.assertFalse(
                    any(
                        line.startswith(
                            ("build ", "run ", "container rm ", "image rm ")
                        )
                        for line in calls
                    )
                )
                self.assertEqual((occupied / ".keep").read_text(), "preserve")
                self.assertEqual(file.read_text(), "preserve")
                self.assertFalse((self.root / "scratch-created").exists())

    def test_explicit_daemon_builder_ignores_selection_and_environment(self):
        for selected in ("default", "mailstrix-multi", "unavailable-builder"):
            with self.subTest(selected=selected):
                self.env["BUILDX_BUILDER"] = selected
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root / "docker.log").read_text().splitlines()
        native = [line for line in calls if line.startswith("build ")]
        transfers = [line for line in calls if line.startswith("buildx build ")]
        self.assertEqual(len(native), 3)
        self.assertEqual(len(transfers), 9)
        self.assertTrue(
            all(line.startswith("build --builder default ") for line in native)
        )
        self.assertTrue(
            all(
                line.startswith("buildx build --builder default ") for line in transfers
            )
        )
        self.assertFalse(any(line.startswith("buildx use ") for line in calls))

    def test_required_builder_errors_are_explicit(self):
        for variable, value, message in (
            (
                "NATIVE_BUILDER_EXIT",
                "7",
                b"required default Docker builder unavailable",
            ),
            (
                "NATIVE_BUILDER_DRIVER",
                "docker-container",
                b"must use the Docker driver",
            ),
            ("NATIVE_BUILDER_DRIVER", "", b"must use the Docker driver"),
        ):
            with self.subTest(variable=variable, value=value):
                self.env[variable] = value
                result = self.run_script("--prerequisites-only")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(message, result.stderr)
                self.env.pop(variable)
        self.assertFalse((self.root / "public-key.gpg").exists())

    def test_transfer_error_propagates_and_cleans_up(self):
        self.env["NATIVE_TRANSFER_EXIT"] = "7"
        result = self.run_script()
        self.assertEqual(result.returncode, 7, result.stderr)
        calls = (self.root / "docker.log").read_text().splitlines()
        context = Path(
            next(line for line in calls if line.startswith("build ")).split()[-1]
        )
        self.assertFalse(context.exists())
        self.assertTrue(any(line.startswith("container rm -f ") for line in calls))
        self.assertTrue(any(line.startswith("image rm ") for line in calls))

    def test_workflow_contract_dependencies_are_disposable_and_pinned(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["changes"]["steps"]
        command = next(
            step["run"]
            for step in steps
            if step.get("name") == "required check contract fixtures"
        )
        self.assertIn('docker run --rm -v "$PWD:/repo:ro" -w /repo', command)
        self.assertIn(
            "eilandert/goldenimage:ci@sha256:27b404ef4099fc1b9893d5843e0adf603c82b0c451bb89d3af88474147536d32",
            command,
        )
        self.assertIn("sh -ec", command)
        self.assertIn("python3 -m venv /tmp/workflow-contract", command)
        self.assertIn("coverage==7.6.0 PyYAML==6.0.2", command)
        self.assertIn('export PATH="/tmp/workflow-contract/bin:$PATH"', command)
        self.assertIn("python3 -B ci/workflow_contract_test.py", command)

    def test_real_committed_pr_base_stage_guard(self):
        repository = self.root / "stage-repository"
        (repository / "docker").mkdir(parents=True)
        dockerfile = repository / "docker/Dockerfile"
        original = (ROOT / "docker/Dockerfile").read_text()
        dockerfile.write_text(original)
        git = shutil.which("git", path=os.environ["PATH"])

        def commit():
            subprocess.run(
                [git, "-C", str(repository), "add", "docker/Dockerfile"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    git,
                    "-C",
                    str(repository),
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-m",
                    "fixture",
                ],
                check=True,
                capture_output=True,
            )
            return subprocess.check_output(
                [git, "-C", str(repository), "rev-parse", "HEAD"], text=True
            ).strip()

        subprocess.run([git, "init", str(repository)], check=True, capture_output=True)
        for key, value in (
            ("user.name", "Fixture"),
            ("user.email", "fixture@example.invalid"),
        ):
            subprocess.run(
                [git, "-C", str(repository), "config", key, value],
                check=True,
                capture_output=True,
            )
        base = commit()
        guard = self.source.split("<<'STAGES'\n", 1)[1].split("\nSTAGES\n", 1)[0]

        def check(mode="pr-export", reference=base):
            return subprocess.run(
                ["python3", "-c", guard, str(repository), mode, reference],
                capture_output=True,
                check=False,
            )

        additive = original.replace(
            "# ---- rules export", "# ---- rules export\n# fixture additive change", 1
        )
        dockerfile.write_text(
            additive.replace(
                "# ---- final", "# ---- final\n# fixture ordinary drift", 1
            )
        )
        drift = commit()
        result = check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            b"ordinary rules/runtime stage changed with export slice", result.stderr
        )
        dockerfile.write_text(additive)
        commit()
        self.assertEqual(check().returncode, 0)
        dockerfile.write_text(
            original.replace(
                "# ---- final", "# ---- final\n# legitimate ordinary-only change", 1
            )
        )
        commit()
        self.assertEqual(check().returncode, 0)
        self.assertEqual(check("callable", "").returncode, 0)
        head = subprocess.check_output(
            [git, "-C", str(repository), "rev-parse", "HEAD"], text=True
        ).strip()
        for mode, reference, message in (
            ("", base, b"explicit stage guard mode required"),
            ("wrong", base, b"explicit stage guard mode required"),
            ("pr-export", "", b"valid PR base SHA required"),
            ("pr-export", "wrong", b"valid PR base SHA required"),
            ("pr-export", "0" * 40, b"PR base unavailable"),
            ("pr-export", head, b"PR base must differ from HEAD"),
        ):
            with self.subTest(mode=mode, reference=reference):
                result = check(mode, reference)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        # The marker mode grants only the two explicit construction additions;
        # both legacy and already-integrated baselines retain ordinary guards.
        marker_copy = "docker/capture-compiler-inputs.py docker/build-marker-artifact.py docker/filter-rules.py"
        marker_run = (
            "    && python3 /usr/local/bin/build-marker-artifact.py /rules "
            + chr(92)
            + chr(10)
        )
        dockerfile.write_text(additive)
        commit()
        self.assertEqual(check("pr-marker").returncode, 0)
        for boundary in ("FROM yara AS rules\n", "# ---- final"):
            dockerfile.write_text(
                additive.replace(boundary, boundary + "\n# unrelated drift\n", 1)
            )
            result = check("pr-marker")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                b"ordinary rules/runtime stage changed with export slice", result.stderr
            )
        for added in (marker_copy, marker_run):
            dockerfile.write_text(additive.replace(added, "", 1))
            result = check("pr-marker")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"marker stage addition missing or duplicated", result.stderr)
        dockerfile.write_text(additive)
        self.assertNotEqual(drift, base)
        dockerfile.write_text(additive.replace("# ---- final", "# removed boundary", 1))
        result = check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"stage boundary changed", result.stderr)

    def test_helper_coverage_floor_rejects_actual_partial_coverage(self):
        source = self.root / "coverage-fixture.py"
        source.write_text(
            "import os\nif os.environ.get('COVER_BOTH'):\n    value = 1\nelse:\n    value = 2\n"
        )
        data = self.root / "fixture.coverage"
        coverage_env = self.env | {"COVERAGE_FILE": str(data)}
        coverage_env.pop("COVER_BOTH", None)
        command = ["python3", "-m", "coverage", "run", "--branch", str(source)]
        subprocess.run(command, env=coverage_env, check=True, capture_output=True)
        self.env["NATIVE_COVERAGE_FILE"] = str(data)
        partial = self.run_script()
        self.assertEqual(partial.returncode, 2, partial.stdout + partial.stderr)
        self.assertIn(b"Coverage failure", partial.stdout + partial.stderr)
        subprocess.run(
            command[:4] + ["--append"] + command[4:],
            env=coverage_env | {"COVER_BOTH": "1"},
            check=True,
            capture_output=True,
        )
        complete = self.run_script()
        self.assertEqual(complete.returncode, 0, complete.stdout + complete.stderr)
        self.assertIn(b"100%", complete.stdout)

    def test_export_omission_cannot_pass_with_disabled_verifier(self):
        self.env["NATIVE_VERIFY_BYPASS"] = "1"
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compiler export omission control survived", result.stderr)
        calls = (self.root / "docker.log").read_text().splitlines()
        self.assertTrue(any("Dockerfile.omission" in line for line in calls))
        context = Path(
            next(line for line in calls if line.startswith("build ")).split()[-1]
        )
        self.assertFalse(context.exists())

    def test_prerequisite_only_and_daemon_failure(self):
        result = self.run_script("--prerequisites-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.root / "docker.log").read_text(), "info\nbuildx inspect default\n"
        )
        self.env["NATIVE_DAEMON_EXIT"] = "1"
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Docker daemon unavailable", result.stderr)
        self.assertFalse((self.root / "public-key.gpg").exists())

    def test_missing_executable_errors(self):
        for missing in ("docker", "python3"):
            with self.subTest(missing=missing):
                isolated = self.root / ("missing-" + missing)
                isolated.mkdir()
                present = "python3" if missing == "docker" else "docker"
                (isolated / present).symlink_to(
                    shutil.which(present, path=self.env["PATH"])
                )
                self.env["PATH"] = str(isolated)
                result = self.run_script("--prerequisites-only")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    ("required executable unavailable: " + missing).encode(),
                    result.stderr,
                )
                self.env["PATH"] = str(self.bin) + os.pathsep + os.environ["PATH"]

    def test_malformed_and_unpinned_public_key_rejected(self):
        for encoded, marker in (
            ("!", b"malformed pinned public archive key"),
            ("AAAA", b"pinned public archive key checksum mismatch"),
        ):
            with self.subTest(marker=marker):
                self.script.write_text(
                    re.sub(
                        r'encoded = """.*?"""',
                        'encoded = """' + encoded + '"""',
                        self.source,
                        count=1,
                        flags=re.DOTALL,
                    )
                )
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(marker, result.stderr)
                self.assertFalse((self.root / "public-key.gpg").exists())
                self.assertNotIn("build ", (self.root / "docker.log").read_text())

    def test_key_provision_error_is_explicit(self):
        scratch = self.root / "scratch"
        (scratch / "deb.myguard.nl.gpg").mkdir(parents=True)
        self.command("mktemp", '#!/bin/sh\nprintf "%s\\n" "$NATIVE_FIXTURE/scratch"\n')
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"cannot provision disposable public archive key", result.stderr)
        self.assertFalse(scratch.exists())
        self.assertNotIn("build ", (self.root / "docker.log").read_text())

    def test_build_and_proof_errors_propagate(self):
        for variable in ("NATIVE_BUILD_EXIT", "NATIVE_RUN_EXIT"):
            with self.subTest(variable=variable):
                self.env[variable] = "7"
                result = self.run_script()
                self.assertEqual(result.returncode, 7)
                self.env.pop(variable)

    def test_production_stage_boundary_errors(self):
        dockerfile = self.root / "docker/Dockerfile"
        production = dockerfile.read_text()
        for old, marker in (
            (" AS yara\n", b"production yara-stage boundary changed"),
            ("RUN apt-get update", b"production yara-stage apt prerequisite changed"),
        ):
            with self.subTest(marker=marker):
                dockerfile.write_text(production.replace(old, "changed"))
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(marker, result.stderr)
                self.assertNotIn("build ", (self.root / "docker.log").read_text())

        stages = list(re.finditer(r"^FROM .+", production, re.MULTILINE))
        dockerfile.write_text(production[: stages[1].start()])
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"production yara-stage boundary changed", result.stderr)
        self.assertNotIn("build ", (self.root / "docker.log").read_text())


def workflow_document(path_variable, filename):
    """Load a workflow or its fixture through PyYAML's safe loader."""
    path = Path(os.environ.get(path_variable, ROOT / ".github/workflows" / filename))
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def workflow_step(name):
    workflow = WORKFLOW.read_text()
    step = workflow.split(f"      - name: {name}\n", 1)[1].split("      - name: ", 1)[0]
    script = step.split("        run: |\n", 1)[1]
    return step, textwrap.dedent(script)


def required_check():
    workflow = WORKFLOW.read_text()
    job = workflow.split("  ci-ok:\n", 1)[1]
    block = job.split("        run: |\n", 1)[1]
    script = []
    for line in block.splitlines(keepends=True):
        if line.strip() and len(line) - len(line.lstrip()) <= 8:
            break
        script.append(line)
    return job, textwrap.dedent("".join(script))


def verdict(
    selected,
    results,
    *,
    changes="success",
    docker="success",
    scanners="success",
    native_selected="false",
    native_result="skipped",
):
    env = dict(os.environ)
    env.update(
        CHANGES_RESULT=changes,
        DOCKER_RESULT=docker,
        SCANNERS_RESULT=scanners,
        NATIVE_SELECTED=native_selected,
        NATIVE_RESULT=native_result,
        PARITY_SELECTED=selected[0],
        GO_SELECTED=selected[1],
        SCOPE_SELECTED=selected[2],
        RSPAMD_SELECTED=selected[3],
        SPAMASSASSIN_SELECTED=selected[4],
    )
    env.update(zip((f"{name}_RESULT" for name in OPTIONAL), results, strict=True))
    return (
        subprocess.run(
            ["bash", "-e", "-c", required_check()[1]],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        ).returncode
        == 0
    )


class RequiredCheck(unittest.TestCase):
    def test_shellcheck_discovers_tracked_scripts_and_reports_failures(self):
        step, script = workflow_step("shellcheck (all tracked shell scripts)")
        self.assertIn("needs.changes.outputs.shell == 'true'", step)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in (
                "packaging/deb/postinstall-milter.sh",
                "packaging/deb/preremove-milter.sh",
                "ci/example_test.sh",
                "contrib/sieve/strix-scan-wrapper",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\nexit 0\n")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                "shift 5\n"
                "for file do\n"
                '  printf \'%s\\n\' "$file" >> "$CALLS"\n'
                '  test -f "$file" || exit 3\n'
                "done\n"
                'test "${FAIL_LINT:-0}" = 0\n'
            )
            docker.chmod(0o755)
            calls = root / "calls"
            env = dict(
                os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}", CALLS=str(calls)
            )

            def run(**extra):
                return subprocess.run(
                    ["bash", "-e", "-c", script],
                    cwd=root,
                    env=dict(env, **extra),
                    capture_output=True,
                    text=True,
                    check=False,
                )

            self.assertEqual(run().returncode, 0)
            self.assertEqual(
                set(calls.read_text().splitlines()),
                {
                    "ci/example_test.sh",
                    "contrib/sieve/strix-scan-wrapper",
                    "packaging/deb/postinstall-milter.sh",
                    "packaging/deb/preremove-milter.sh",
                },
            )
            self.assertNotEqual(
                run(FAIL_LINT="1").returncode, 0, "a lint failure must fail the step"
            )
            (root / "ci/example_test.sh").unlink()
            self.assertNotEqual(
                run().returncode, 0, "a missing tracked test must fail the step"
            )

    def test_milter_script_changes_select_behavior_contract(self):
        workflow = WORKFLOW.read_text()
        step = workflow.split("      - name: deb maintainer-script behaviour", 1)[
            1
        ].split("      - name: ", 1)[0]
        self.assertIn("needs.changes.outputs.maintscript == 'true'", step)
        command = step.split("        run: ", 1)[1].strip()
        self.assertEqual(command, "sh packaging/deb/maintscript_test.sh")
        with tempfile.TemporaryDirectory() as temp:
            fake_sh = Path(temp) / "sh"
            fake_sh.write_text("#!/bin/sh\nexit 7\n")
            fake_sh.chmod(0o755)
            result = subprocess.run(
                ["bash", "-e", "-c", command],
                env=dict(os.environ, PATH=f"{temp}:{os.environ['PATH']}"),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 7, "a failing contract must fail CI")

    def test_native_compiler_required_scope_and_prerequisites(self):
        document = yaml.safe_load(WORKFLOW.read_text())
        jobs = document["jobs"]
        self.assertFalse(
            any(
                "compiler-input-check.sh" in step.get("run", "")
                for step in jobs["changes"]["steps"]
            ),
            "planner must not build YARA",
        )
        job = jobs["compiler-inputs"]
        self.assertEqual(job["needs"], "changes")
        self.assertEqual(job["if"], "${{ needs.changes.outputs.native == 'true' }}")
        self.assertGreater(job["timeout-minutes"], jobs["changes"]["timeout-minutes"])
        steps = job["steps"]
        self.assertTrue(
            any(step.get("uses", "").startswith("actions/checkout@") for step in steps)
        )
        prereq = next(
            step
            for step in steps
            if step.get("name") == "require native compiler proof prerequisites"
        )
        self.assertEqual(
            prereq["run"], "ci/compiler-input-check.sh --prerequisites-only"
        )
        self.assertEqual(steps[-1]["run"], "ci/compiler-input-check.sh")
        self.assertEqual(steps[0]["with"]["fetch-depth"], 0)
        self.assertEqual(
            steps[-1]["env"],
            {
                "MX_INPUT_STAGE_MODE": (
                    "${{ github.event_name == 'pull_request' "
                    "&& 'pr-marker' || 'callable' }}"
                ),
                "MX_INPUT_STAGE_BASE": "${{ github.event.pull_request.base.sha }}",
            },
        )
        self.assertIn("compiler-inputs", jobs["ci-ok"]["needs"])
        env = jobs["ci-ok"]["steps"][0]["env"]
        self.assertEqual(env["NATIVE_SELECTED"], "${{ needs.changes.outputs.native }}")
        self.assertEqual(env["NATIVE_RESULT"], "${{ needs.compiler-inputs.result }}")

    def test_native_required_gate_failure_and_legitimate_skip(self):
        for selected in ("true", "false", "", "unexpected"):
            for result in ("success", "skipped", "failure", "cancelled", ""):
                with self.subTest(selected=selected, result=result):
                    self.assertEqual(
                        verdict(
                            ("false",) * 5,
                            ("skipped",) * 4,
                            native_selected=selected,
                            native_result=result,
                        ),
                        (selected, result)
                        in (("true", "success"), ("false", "skipped")),
                    )

    def test_wiring(self):
        job, script = required_check()
        self.assertIn("if: ${{ always() }}", job)
        self.assertIn(
            "needs: [changes, docker, parity-isolation, lint, scanners, rspamd, spamassassin, compiler-inputs]",
            job,
        )
        for name in (
            "changes",
            "docker",
            "parity-isolation",
            "lint",
            "scanners",
            "rspamd",
            "spamassassin",
            "compiler-inputs",
        ):
            self.assertIn(f"needs.{name}.result", job)
        for name in ("parity", "go", "scope", "rspamd", "spamassassin"):
            self.assertIn(f"needs.changes.outputs.{name}", job)
        self.assertIn("require_selected", script)

    def test_selected_and_skipped_jobs(self):
        # Every selection combination succeeds only with its corresponding
        # success/skipped result; any other state must fail the stable check.
        states = ("success", "skipped", "failure", "cancelled", "")
        for bits in itertools.product(("true", "false"), repeat=5):
            expected = (
                bits[0] == "true",
                bits[1] == "true" or bits[2] == "true",
                bits[3] == "true",
                bits[4] == "true",
            )
            good = tuple("success" if value else "skipped" for value in expected)
            with self.subTest(selected=bits):
                self.assertTrue(verdict(bits, good))
                for index, state in itertools.product(range(4), states):
                    if state == good[index]:
                        continue
                    actual = list(good)
                    actual[index] = state
                    self.assertFalse(verdict(bits, actual), (index, state))

    def test_planner_and_required_gate_fail_closed(self):
        skipped = ("false",) * 5
        results = ("skipped",) * 4
        for job in ("changes", "docker", "scanners"):
            for state in ("failure", "cancelled", "skipped", ""):
                with self.subTest(job=job, state=state):
                    self.assertFalse(verdict(skipped, results, **{job: state}))
        for index in range(5):
            selected = list(skipped)
            selected[index] = ""
            self.assertFalse(verdict(selected, results))


class NightlyMarkerImageContract(unittest.TestCase):
    """The nightly must prove its own binaries load markers before publishing."""

    def check(self, nightly):
        jobs = nightly["jobs"]
        marker = jobs["marker-image"]
        self.assertIn("binaries", marker["needs"])
        self.assertEqual(marker["permissions"], {"contents": "read"})
        download = next(
            s for s in marker["steps"] if s.get("name") == "download amd64 binaries"
        )
        # Its own just-built artifact, never a downloaded published release.
        self.assertEqual(download["with"], {"name": "bin-amd64", "path": "out/"})
        run = marker["steps"][-1]["run"]
        self.assertIn("bash ci/release_marker_image_test.sh amd64 out", run)
        self.assertNotIn("gh release", run)
        self.assertNotIn("releases/download", run)
        for step in marker["steps"]:
            self.assertNotIn("gh release", step.get("run", ""))
        publish = jobs["publish"]
        self.assertIn("marker-image", publish["needs"])
        self.assertIn("needs.marker-image.result == 'success'", publish["if"])

    def test_shipped_nightly_proves_markers(self):
        self.check(workflow_document("NIGHTLY_WORKFLOW_TEST_PATH", "nightly.yml"))

    def test_removed_or_miswired_proof_fails(self):
        base = workflow_document("NIGHTLY_WORKFLOW_TEST_PATH", "nightly.yml")

        def mutate(fn):
            doc = json.loads(json.dumps(base))
            fn(doc)
            return doc

        def drop_job(d):
            del d["jobs"]["marker-image"]

        def drop_need(d):
            d["jobs"]["publish"]["needs"].remove("marker-image")

        def downloaded(d):
            d["jobs"]["marker-image"]["steps"][-1]["run"] = (
                "gh release download nightly\nbash ci/release_marker_image_test.sh amd64 out"
            )

        def wrong_artifact(d):
            for s in d["jobs"]["marker-image"]["steps"]:
                if s.get("name") == "download amd64 binaries":
                    s["with"]["name"] = "bin-arm64"

        for fn in (drop_job, drop_need, downloaded, wrong_artifact):
            with (
                self.subTest(case=fn.__name__),
                self.assertRaises((AssertionError, KeyError)),
            ):
                self.check(mutate(fn))


class BinaryWorkflowContract(unittest.TestCase):
    """Keep the tag release wired to the reusable, pinned binary build."""

    def test_release_binary_contract(self):
        """The tag caller, inputs, artifacts and reviewed action pins agree."""
        release = workflow_document("RELEASE_WORKFLOW_TEST_PATH", "release.yml")
        binaries = workflow_document("BINARY_WORKFLOW_TEST_PATH", "build-binaries.yml")

        self.assertEqual(release[True]["push"]["tags"], ["v*"])
        jobs = release["jobs"]
        self.assertEqual(jobs["gate"]["uses"], "./.github/workflows/ci.yml")
        caller = jobs["binaries"]
        self.assertEqual(caller["needs"], "gate")
        self.assertEqual(caller["uses"], "./.github/workflows/build-binaries.yml")
        self.assertEqual(caller["with"]["version"], "${{ github.ref_name }}")
        self.assertEqual(caller["permissions"]["contents"], "read")
        self.assertEqual(jobs["debs"]["needs"], "binaries")
        self.assertEqual(jobs["release"]["needs"], ["binaries", "debs", "marker-image"])
        marker = jobs["marker-image"]
        self.assertEqual(marker["needs"], "binaries")
        self.assertEqual(marker["permissions"], {"contents": "read"})
        self.assertEqual(marker["strategy"]["matrix"]["arch"], ["amd64", "arm64"])
        self.assertIs(marker["strategy"]["fail-fast"], False)
        marker_download = next(
            step
            for step in marker["steps"]
            if step.get("name") == "download arch binaries"
        )
        self.assertEqual(
            marker_download["with"],
            {"name": "bin-${{ matrix.arch }}", "path": "out/"},
        )
        marker_check = marker["steps"][-1]
        self.assertEqual(marker_check["env"]["ARCH"], "${{ matrix.arch }}")
        self.assertIn(
            'bash ci/release_marker_image_test.sh "${ARCH}" out', marker_check["run"]
        )

        inputs = binaries[True]["workflow_call"]["inputs"]
        self.assertEqual(inputs["version"]["type"], "string")
        self.assertIs(inputs["version"]["required"], True)
        self.assertEqual(inputs["arches"]["type"], "string")
        self.assertEqual(json.loads(inputs["arches"]["default"]), ["amd64", "arm64"])
        build = binaries["jobs"]["binaries"]
        self.assertEqual(
            build["strategy"]["matrix"]["arch"], "${{ fromJSON(inputs.arches) }}"
        )
        steps = build["steps"]
        self.assertEqual(steps[3]["env"]["VERSION"], "${{ inputs.version }}")
        self.assertEqual(steps[3]["env"]["ARCH"], "${{ matrix.arch }}")
        script = steps[3]["run"]
        self.assertIn('arch="${ARCH}"', script)
        self.assertIn('--build-arg "VERSION=${VERSION}"', script)
        for asset in ("strixd", "strix-scan", "strix-milter", "yarac"):
            self.assertIn(f'"out/{asset}-linux-${{arch}}"', script)
        self.assertIn('"dist/${arch}/yarac" "out/yarac-linux-${arch}"', script)
        self.assertIn('"dist/${arch}/libyara.a" "out/libyara-linux-${arch}.a"', script)
        self.assertEqual(steps[4]["with"]["name"], "bin-${{ matrix.arch }}")
        self.assertEqual(steps[4]["with"]["if-no-files-found"], "error")
        for job in ("debs", "release"):
            download = next(
                step
                for step in jobs[job]["steps"]
                if step.get("name") == "download arch binaries"
            )
            self.assertEqual(download["with"]["pattern"], "bin-*")
            self.assertIs(download["with"]["merge-multiple"], True)
        deb_script = next(
            step["run"]
            for step in jobs["debs"]["steps"]
            if step.get("name") == "build .deb packages"
        )
        self.assertIn('export VERSION="${GITHUB_REF_NAME#v}"', deb_script)
        self.assertIn("for arch in amd64 arm64; do", deb_script)
        publish_script = next(
            step["run"]
            for step in jobs["release"]["steps"]
            if step.get("name") == "create release"
        )
        self.assertIn(
            "out/strixd-linux-* out/strix-scan-linux-* "
            "out/strix-milter-linux-* out/yarac-linux-* out/libyara-linux-* "
            "out/*.deb out/SHA256SUMS",
            publish_script,
        )
        checksum_script = next(
            step["run"]
            for step in jobs["release"]["steps"]
            if step.get("name") == "checksums"
        )
        self.assertIn("yarac-linux-* libyara-linux-* ./*.deb", checksum_script)
        self.assertIn('gh release create "${GITHUB_REF_NAME}"', publish_script)

        expected_pins = (
            "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
            "docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130",
            "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        )
        self.assertEqual(
            tuple(step["uses"] for step in steps if "uses" in step), expected_pins
        )


class NightlyWorkflowContract(unittest.TestCase):
    """Exercise the shipped nightly decision with an isolated gh fixture."""

    def nightly(self):
        """Load the candidate workflow or a mutated fixture."""
        return workflow_document("NIGHTLY_WORKFLOW_TEST_PATH", "nightly.yml")

    def decision(self, release, *, ref="refs/heads/main", sha="a" * 40):
        """Execute the real plan script while a fake gh supplies release state."""
        plan = self.nightly()["jobs"]["plan"]
        step = next(step for step in plan["steps"] if step.get("id") == "release")
        with tempfile.TemporaryDirectory(prefix="mailstrix-nightly-fixture-") as temp:
            root = Path(temp)
            fake_gh = root / "gh"
            fake_gh.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" > "$GH_CALLS"\n'
                'case "$FAKE_RELEASE" in\n'
                '  equal) printf "%s\\n" "$GITHUB_SHA";;\n'
                '  different) printf "%040d\\n" 0;;\n'
                '  missing) echo "release not found" >&2; exit 1;;\n'
                '  denied) echo "HTTP 403" >&2; exit 1;;\n'
                "esac\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            output = root / "output"
            calls = root / "calls"
            env = dict(
                os.environ,
                PATH=f"{root}:{os.environ['PATH']}",
                GITHUB_REF=ref,
                GITHUB_SHA=sha,
                GITHUB_REPOSITORY="myguard-labs/mailstrix",
                GITHUB_OUTPUT=str(output),
                GH_CALLS=str(calls),
                FAKE_RELEASE=release,
            )
            result = subprocess.run(
                ["bash", "-e", "-c", step["run"]],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            return (
                result,
                output.read_text() if output.exists() else "",
                (calls.read_text() if calls.exists() else ""),
            )

    def test_schedule_gate_and_amd64_build(self):
        """Only a fresh main commit may reach the reusable binary workflow."""
        workflow = self.nightly()
        self.assertEqual(workflow[True]["schedule"], [{"cron": "0 9 * * *"}])
        self.assertIn("workflow_dispatch", workflow[True])
        jobs = workflow["jobs"]
        self.assertEqual(
            jobs["plan"]["outputs"]["skip"], "${{ steps.release.outputs.skip }}"
        )
        self.assertEqual(
            jobs["plan"]["outputs"]["version"], "${{ steps.release.outputs.version }}"
        )
        self.assertEqual(jobs["gate"]["needs"], "plan")
        self.assertEqual(jobs["gate"]["uses"], "./.github/workflows/ci.yml")
        self.assertEqual(jobs["gate"]["if"], "needs.plan.outputs.skip == 'false'")
        self.assertEqual(jobs["binaries"]["needs"], ["plan", "gate"])
        self.assertEqual(
            jobs["binaries"]["uses"], "./.github/workflows/build-binaries.yml"
        )
        self.assertEqual(
            jobs["binaries"]["with"],
            {"version": "${{ needs.plan.outputs.version }}", "arches": '["amd64"]'},
        )
        condition = jobs["binaries"]["if"]
        predicate = re.fullmatch(
            r"needs\.plan\.outputs\.skip == '([^']+)' && "
            r"needs\.gate\.result == '([^']+)'",
            condition,
        )
        self.assertIsNotNone(predicate, condition)
        required_skip, required_gate = predicate.groups()
        self.assertEqual((required_skip, required_gate), ("false", "success"))
        for skip, gate, expected in (
            ("false", "success", True),
            ("false", "failure", False),
            ("false", "cancelled", False),
            ("true", "success", False),
        ):
            with self.subTest(skip=skip, gate=gate):
                self.assertEqual(
                    skip == required_skip and gate == required_gate, expected
                )

    def test_equal_nightly_target_skips(self):
        """An already published main SHA must suppress the gate and build."""
        result, output, calls = self.decision("equal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skip=true\n", output)
        self.assertIn("version=nightly-aaaaaaaaaaaa\n", output)
        self.assertIn("release view nightly --repo myguard-labs/mailstrix", calls)

    def test_different_nightly_target_builds(self):
        """A changed main SHA must run the CI gate and amd64 build."""
        result, output, _ = self.decision("different")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skip=false\n", output)

    def test_missing_nightly_release_builds(self):
        """The first nightly run must build when no release exists."""
        result, output, _ = self.decision("missing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skip=false\n", output)

    def test_release_lookup_error_fails_closed(self):
        """An API failure must not be mistaken for an absent release."""
        result, output, _ = self.decision("denied")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 403", result.stderr)
        self.assertEqual(output, "")

    def test_non_main_and_malformed_sha_fail_closed(self):
        """The build must never use a branch or malformed commit identity."""
        for ref, sha in (("refs/heads/dev", "a" * 40), ("refs/heads/main", "bad")):
            with self.subTest(ref=ref, sha=sha):
                result, output, calls = self.decision("different", ref=ref, sha=sha)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")
                self.assertEqual(calls, "")

    def test_publication_permissions_and_order(self):
        """Only a completed amd64 build can publish under a write token."""
        workflow = self.nightly()
        self.assertEqual(workflow["concurrency"]["cancel-in-progress"], False)
        self.assertEqual(
            workflow["concurrency"]["group"], "nightly-release-${{ github.repository }}"
        )
        self.assertEqual(workflow["permissions"]["contents"], "read")
        jobs = workflow["jobs"]
        self.assertEqual(
            jobs["publish"]["needs"], ["plan", "gate", "binaries", "marker-image"]
        )
        self.assertEqual(
            jobs["publish"]["if"],
            "needs.binaries.result == 'success' && needs.marker-image.result == 'success'",
        )
        self.assertEqual(jobs["publish"]["permissions"]["contents"], "write")
        for name, job in jobs.items():
            if name != "publish":
                self.assertNotEqual(job.get("permissions", {}).get("contents"), "write")
        download = next(
            step
            for step in jobs["publish"]["steps"]
            if step.get("name") == "download amd64 binaries"
        )
        self.assertEqual(
            download["uses"],
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        )
        self.assertEqual(download["with"], {"name": "bin-amd64", "path": "out/"})

    def test_amd64_checksums_cover_exact_assets(self):
        """All three downloaded binaries must be hashed before publication."""
        step = next(
            step
            for step in self.nightly()["jobs"]["publish"]["steps"]
            if step.get("name") == "checksums"
        )
        with tempfile.TemporaryDirectory(prefix="mailstrix-nightly-assets-") as temp:
            root = Path(temp)
            output = root / "out"
            output.mkdir()
            names = (
                "strixd-linux-amd64",
                "strix-scan-linux-amd64",
                "strix-milter-linux-amd64",
                "yarac-linux-amd64",
                "libyara-linux-amd64.a",
            )
            for name in names:
                (output / name).write_bytes(name.encode())
            result = subprocess.run(
                ["bash", "-e", "-c", step["run"]],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            sums = (output / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertEqual(
                [line.split("  ", 1)[1] for line in sums.splitlines()], list(names)
            )
            self.assertIn("sha256sum -c SHA256SUMS", step["run"])
            (output / names[1]).unlink()
            missing = subprocess.run(
                ["bash", "-e", "-c", step["run"]],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(missing.returncode, 0)

    def publication(self, release):
        """Run the real publish script against a harmless fake gh CLI."""
        step = next(
            step
            for step in self.nightly()["jobs"]["publish"]["steps"]
            if step.get("name") == "publish rolling nightly"
        )
        with tempfile.TemporaryDirectory(prefix="mailstrix-nightly-publish-") as temp:
            root = Path(temp)
            fake_gh = root / "gh"
            fake_gh.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" >> "$GH_CALLS"\n'
                'case "$1 $2" in\n'
                '  "release view")\n'
                '    case "$FAKE_RELEASE" in\n'
                "      existing) echo existing;;\n"
                '      missing) echo "release not found" >&2; exit 1;;\n'
                '      denied) echo "HTTP 403" >&2; exit 1;;\n'
                "    esac;;\n"
                '  "release delete")\n'
                '    if [ "$FAKE_RELEASE" = delete_fail ]; then exit 1; fi;;\n'
                "esac\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            calls = root / "calls"
            env = dict(
                os.environ,
                PATH=f"{root}:{os.environ['PATH']}",
                GH_CALLS=str(calls),
                FAKE_RELEASE=release,
                GITHUB_REPOSITORY="myguard-labs/mailstrix",
                GITHUB_SHA="a" * 40,
            )
            result = subprocess.run(
                ["bash", "-e", "-c", step["run"]],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_first_publication_is_prerelease_and_never_latest(self):
        """A missing nightly must be created with SHA target and six assets."""
        result, calls = self.publication("missing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2, calls)
        create = calls[-1]
        create_args = create.split()
        self.assertIn("release create nightly", create)
        self.assertIn("--target " + "a" * 40, create)
        self.assertIn("--prerelease", create_args)
        self.assertIn("--latest=false", create_args)
        for asset in (
            "strixd-linux-amd64",
            "strix-scan-linux-amd64",
            "strix-milter-linux-amd64",
            "yarac-linux-amd64",
            "libyara-linux-amd64.a",
            "SHA256SUMS",
        ):
            self.assertIn("out/" + asset, create)
        self.assertNotIn("arm64", create)

    def test_existing_publication_replaces_release_and_tag(self):
        """An old tag must be removed before the new SHA is recorded."""
        result, calls = self.publication("existing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3, calls)
        self.assertIn("release view nightly", calls[0])
        self.assertIn("release delete nightly", calls[1])
        self.assertIn("--cleanup-tag --yes", calls[1])
        self.assertIn("release create nightly", calls[2])

    def test_publication_lookup_error_fails_closed(self):
        """An authorization error must never delete or create a release."""
        result, calls = self.publication("denied")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 403", result.stderr)
        self.assertEqual(len(calls), 1, calls)


class LibyaraReproducibilityContract(unittest.TestCase):
    """libyara.a must stay byte-reproducible and be checked twice in CI."""

    FLAGS = ("-frandom-seed=mailstrix-yara", "-ffile-prefix-map=/tmp/yara-${YARA_VERSION}=.")

    def test_both_dockerfiles_carry_reproducibility_flags(self):
        for name in ("Dockerfile", "Dockerfile.release"):
            text = (ROOT / "docker" / name).read_text()
            for flag in self.FLAGS:
                with self.subTest(dockerfile=name, flag=flag):
                    self.assertGreaterEqual(text.count(flag), 1)

    def test_ci_runs_the_two_build_comparison(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["compiler-inputs"]["steps"]
        self.assertIn("ci/libyara-repro-check.sh", [step.get("run") for step in steps])

    def run_script(self, hashes, script=None, args=()):
        """Run the real script with a fake docker that emits the given libyara.a bytes."""
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (tmp / "bin").mkdir()
        counter = tmp / "count"
        counter.write_text("0")
        argv_log = tmp / "argv.log"
        self.argv_log = argv_log
        fake = tmp / "bin/docker"
        fake.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            echo "$*" >> {argv_log}
            case "$1" in
              cp)
                n=$(( $(cat {counter}) + 1 )); echo $n > {counter}
                contents=({" ".join(repr(h) for h in hashes)})
                # A cp past the provided archives fails like a missing file.
                [ "$n" -le "${{#contents[@]}}" ] || {{ echo "no such file" >&2; exit 1; }}
                printf '%s' "${{contents[$((n-1))]}}" > "$3" ;;
              *) : ;;
            esac
            """))
        fake.chmod(0o755)
        env = dict(os.environ, PATH=f"{tmp / 'bin'}:{os.environ['PATH']}")
        return subprocess.run(
            ["bash", str(script or ROOT / "ci/libyara-repro-check.sh"), *args],
            env=env, capture_output=True, text=True, check=False,
        )

    def run_script_args(self, hashes, script=None, args=()):
        """Like run_script but with a script override and argv; returns docker argv lines."""
        script = script or ROOT / "ci/libyara-repro-check.sh"
        result = self.run_script(hashes, script=script, args=args)
        return result, self.argv_log.read_text().splitlines()

    def test_identical_archives_pass(self):
        result = self.run_script(["same", "same"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reproducible", result.stdout)

    def assert_two_no_cache_builds(self, lines):
        builds = [i for i, l in enumerate(lines) if l.startswith("build ")]
        self.assertEqual(len(builds), 2, lines)
        for i in builds:
            self.assertIn("--no-cache", lines[i].split())
            self.assertIn("--target yara", lines[i])
        for i in builds:
            nxt = [l for l in lines[i + 1:] if l.startswith(("build ", "cp "))]
            self.assertTrue(nxt and nxt[0].startswith("cp "), lines)
            self.assertIn("/usr/local/lib/libyara.a", nxt[0])

    def test_docker_argv_two_no_cache_yara_builds_each_extracted(self):
        result, lines = self.run_script_args(["same", "same"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_two_no_cache_builds(lines)

    def mutated_script(self, old, new):
        text = (ROOT / "ci/libyara-repro-check.sh").read_text()
        self.assertIn(old, text)
        copy = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (copy / "ci").mkdir()
        script = copy / "ci/libyara-repro-check.sh"
        script.write_text(text.replace(old, new))
        return script

    def test_dropping_no_cache_is_detected(self):
        script = self.mutated_script("build --no-cache --target", "build --target")
        _, lines = self.run_script_args(["same", "same"], script=script)
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_single_build_is_detected(self):
        script = self.mutated_script("for n in 1 2; do", "for n in 1; do")
        _, lines = self.run_script_args(["same", "same"], script=script)
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_release_dockerfile_arg_is_passed_to_build(self):
        _, lines = self.run_script_args(
            ["same", "same"], args=("docker/Dockerfile.release",))
        self.assertTrue(all("-f docker/Dockerfile.release" in l
                            for l in lines if l.startswith("build ")), lines)

    def test_maintenance_runs_release_dockerfile_check(self):
        doc = yaml.safe_load((ROOT / ".github/workflows/maintenance.yml").read_text())
        runs = [s.get("run", "") for j in doc["jobs"].values() for s in j["steps"]]
        self.assertTrue(any(
            r.startswith("ci/libyara-repro-check.sh docker/Dockerfile.release")
            for r in runs), runs)

    def test_per_pr_ci_does_not_run_release_check(self):
        self.assertNotIn("Dockerfile.release --", WORKFLOW.read_text())
        self.assertNotIn("libyara-repro-check.sh docker/Dockerfile.release",
                         WORKFLOW.read_text())

    def test_differing_archives_fail(self):
        result = self.run_script(["one", "two"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not byte-reproducible", result.stderr)

    def test_missing_archive_fails(self):
        result = self.run_script(["same"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no such file", result.stderr)
        self.assertNotIn("not byte-reproducible", result.stderr)


if __name__ == "__main__":
    unittest.main()
