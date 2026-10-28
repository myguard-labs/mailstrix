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
# arm64 jobs build natively on GitHub's hosted arm runner; amd64 stays on the
# self-hosted Docker profile. No arm64 job may fall back to QEMU emulation.
NATIVE_RUNS_ON = (
    "${{ matrix.arch == 'arm64' && 'ubuntu-24.04-arm' || "
    'fromJSON(\'["self-hosted","builder02","docker"]\') }}'
)


# The reusable binary build and the nightly's own marker proof run every arch
# on GitHub-hosted runners.
HOSTED_RUNS_ON = "${{ matrix.arch == 'arm64' && 'ubuntu-24.04-arm' || 'ubuntu-24.04' }}"


def assert_native_arch_job(case, job, runs_on=NATIVE_RUNS_ON):
    case.assertEqual(job["runs-on"], runs_on)
    case.assertFalse(
        any(
            s.get("uses", "").startswith("docker/setup-qemu-action@")
            for s in job["steps"]
        ),
        "arm64 must build natively, not under QEMU",
    )


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


class ChangesJobTimeoutContract(unittest.TestCase):
    """The planner and containerized contract fixtures must both reach completion."""

    MINIMUM_MINUTES = 10

    def assert_headroom(self, source):
        job = yaml.safe_load(source)["jobs"]["changes"]
        self.assertGreaterEqual(job["timeout-minutes"], self.MINIMUM_MINUTES)

    def test_shipped_changes_timeout_covers_both_required_gates(self):
        self.assert_headroom(WORKFLOW.read_text())

    def test_old_cap_and_missing_timeout_fail(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        workflow["jobs"]["changes"]["timeout-minutes"] = 5
        with self.assertRaises(AssertionError):
            self.assert_headroom(yaml.safe_dump(workflow))
        del workflow["jobs"]["changes"]["timeout-minutes"]
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
        marker_copy = "docker/capture-compiler-inputs.py docker/build-marker-artifact.py /usr/local/bin/"
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
            (
                "RUN --mount=type=cache,target=/var/cache/apt,",
                b"production yara-stage apt prerequisite changed",
            ),
            ("apt-get update", b"production yara-stage apt prerequisite changed"),
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


def job_script(name):
    workflow = WORKFLOW.read_text()
    job = workflow.split(f"  {name}:\n", 1)[1]
    job = re.split(r"^  [a-zA-Z0-9_-]+:\n", job, maxsplit=1, flags=re.MULTILINE)[0]
    block = job.split("        run: |\n", 1)[1]
    script = []
    for line in block.splitlines(keepends=True):
        if line.strip() and len(line) - len(line.lstrip()) <= 8:
            break
        script.append(line)
    return job, textwrap.dedent("".join(script))


def required_check():
    return job_script("ci-ok")


def parsed_lane_manifest():
    planner = (ROOT / "scripts/ci-plan.sh").read_text(encoding="utf-8")
    fragments = re.findall(r"^lane_manifest(?:\+)?='([^']*)'$", planner, re.MULTILINE)
    return json.loads("".join(fragments))


def lane_job_owners(lane_manifest):
    owners = {}
    for lane in lane_manifest["lanes"]:
        for identity in lane["jobs"]:
            if identity in owners:
                raise AssertionError(f"duplicate lane job owner: {identity}")
            owners[identity] = lane["id"]
    return owners


def workflow_check_owners(job_owners, overrides):
    owners = {}
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        relative = path.relative_to(ROOT).as_posix()
        for job_name, job in document["jobs"].items():
            job_identity = f"{relative}#{job_name}"
            if job_identity not in job_owners:
                raise AssertionError(f"missing lane job owner: {job_identity}")
            for index, step in enumerate(job.get("steps", ()), start=1):
                step_name = step.get("name", f"step-{index}")
                identity = f"{job_identity}#{index}:{step_name}"
                if identity in owners:
                    raise AssertionError(f"duplicate check identity: {identity}")
                override_identity = f"{job_identity}#{step_name}"
                owners[identity] = overrides.get(
                    override_identity, (job_owners[job_identity], "job-default")
                )
    return owners


def verdict(
    selected,
    results,
    *,
    changes="success",
    docker="success",
    scanners="success",
    publisher_selected="false",
    publisher_result="skipped",
    ordering_selected="false",
    ordering_result="skipped",
    native_selected="false",
    native_result="skipped",
    event_name="workflow_call",
    release_image_selected="false",
    pr_binaries_result="skipped",
    pr_marker_image_result="skipped",
):
    env = dict(os.environ)
    env.update(
        CHANGES_RESULT=changes,
        DOCKER_RESULT=docker,
        SCANNERS_RESULT=scanners,
        PUBLISHER_CONCURRENCY_SELECTED=publisher_selected,
        PUBLISHER_CONCURRENCY_RESULT=publisher_result,
        PUBLISHER_ORDERING_SELECTED=ordering_selected,
        PUBLISHER_ORDERING_RESULT=ordering_result,
        NATIVE_SELECTED=native_selected,
        NATIVE_RESULT=native_result,
        EVENT_NAME=event_name,
        RELEASE_IMAGE_SELECTED=release_image_selected,
        PR_BINARIES_RESULT=pr_binaries_result,
        PR_MARKER_IMAGE_RESULT=pr_marker_image_result,
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
            for result in (
                "success",
                "skipped",
                "failure",
                "cancelled",
                "timed_out",
                "unknown",
                "",
            ):
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
        self.assertEqual(
            yaml.safe_load(WORKFLOW.read_text())["jobs"]["ci-ok"]["needs"],
            [
                "changes",
                "docker",
                "parity-isolation",
                "lint",
                "scanners",
                "publisher-concurrency",
                "publisher-ordering",
                "rspamd",
                "spamassassin",
                "compiler-inputs",
                "pr-binaries",
                "pr-marker-image",
            ],
        )
        for name in (
            "changes",
            "docker",
            "parity-isolation",
            "lint",
            "scanners",
            "publisher-concurrency",
            "publisher-ordering",
            "rspamd",
            "spamassassin",
            "compiler-inputs",
            "pr-binaries",
            "pr-marker-image",
        ):
            self.assertIn(f"needs.{name}.result", job)
        for group in (
            "static_analysis",
            "go_correctness",
            "native_builds_artifacts",
            "contracts_integrations",
        ):
            self.assertIn(f"join_{group}", script)

    def test_selected_and_skipped_jobs(self):
        # Every selection combination succeeds only with its corresponding
        # success/skipped result; any other state must fail the stable check.
        states = (
            "success",
            "skipped",
            "failure",
            "cancelled",
            "timed_out",
            "unknown",
            "",
        )
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

    def test_publisher_concurrency_selected_never_passes_unless_success(self):
        skipped = ("false",) * 5
        results = ("skipped",) * 4
        self.assertTrue(
            verdict(skipped, results, publisher_selected="true", publisher_result="success")
        )
        self.assertTrue(verdict(skipped, results))
        for state in ("failure", "cancelled", "timed_out", "skipped", "unknown", ""):
            with self.subTest(selected="true", state=state):
                self.assertFalse(
                    verdict(skipped, results, publisher_selected="true", publisher_result=state)
                )
        for state in ("success", "failure", "cancelled", "unknown", ""):
            with self.subTest(selected="false", state=state):
                self.assertFalse(verdict(skipped, results, publisher_result=state))
        self.assertFalse(
            verdict(skipped, results, publisher_selected="", publisher_result="success")
        )

    def test_publisher_ordering_selected_never_passes_unless_success(self):
        skipped = ("false",) * 5
        results = ("skipped",) * 4
        self.assertTrue(
            verdict(skipped, results, ordering_selected="true", ordering_result="success")
        )
        self.assertTrue(verdict(skipped, results))
        for state in ("failure", "cancelled", "timed_out", "skipped", "unknown", ""):
            with self.subTest(selected="true", state=state):
                self.assertFalse(
                    verdict(skipped, results, ordering_selected="true", ordering_result=state)
                )
        for state in ("success", "failure", "cancelled", "unknown", ""):
            with self.subTest(selected="false", state=state):
                self.assertFalse(verdict(skipped, results, ordering_result=state))
        self.assertFalse(
            verdict(skipped, results, ordering_selected="", ordering_result="success")
        )

    def test_planner_and_required_gate_fail_closed(self):
        skipped = ("false",) * 5
        results = ("skipped",) * 4
        for job in ("changes", "docker", "scanners"):
            for state in (
                "failure",
                "cancelled",
                "timed_out",
                "unknown",
                "skipped",
                "",
            ):
                with self.subTest(job=job, state=state):
                    self.assertFalse(verdict(skipped, results, **{job: state}))
        for index in range(5):
            selected = list(skipped)
            selected[index] = ""
            self.assertFalse(verdict(selected, results))

    def test_actual_caller_and_lane_predicate_table(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        jobs = workflow["jobs"]
        events = workflow[True]
        self.assertEqual(events["pull_request"]["branches"], ["main", "master"])
        self.assertIn("workflow_call", events)
        self.assertNotIn("pull_request_target", events)
        for caller in ("nightly.yml", "release.yml"):
            source = yaml.safe_load((ROOT / ".github/workflows" / caller).read_text())
            self.assertEqual(
                source["jobs"]["gate"]["uses"], "./.github/workflows/ci.yml"
            )
        self.assertNotIn(
            "./.github/workflows/ci.yml",
            (ROOT / ".github/workflows/maintenance.yml").read_text(),
        )
        for job, predicate in (
            ("compiler-inputs", "needs.changes.outputs.native == 'true'"),
            ("parity-isolation", "needs.changes.outputs.parity == 'true'"),
            (
                "lint",
                "needs.changes.outputs.go == 'true' || needs.changes.outputs.scope == 'true'",
            ),
            ("rspamd", "needs.changes.outputs.rspamd == 'true'"),
            ("spamassassin", "needs.changes.outputs.spamassassin == 'true'"),
        ):
            with self.subTest(job=job):
                self.assertIn(predicate, jobs[job]["if"])
        self.assertEqual(jobs["docker"]["if"], "${{ always() }}")
        self.assertEqual(jobs["ci-ok"]["if"], "${{ always() }}")

    def test_lane_manifest_owns_all_baseline_jobs_and_check_modes_once(self):
        lane_manifest = parsed_lane_manifest()
        job_owners = lane_job_owners(lane_manifest)
        overrides = {
            item["identity"]: (item["lane"], item["mode"])
            for item in lane_manifest["step_overrides"]
        }
        self.assertEqual(len(overrides), len(lane_manifest["step_overrides"]))
        check_owners = workflow_check_owners(job_owners, overrides)
        aliases = lane_manifest["check_aliases"]
        for alias in aliases:
            current_suffix = f"#{alias['current'].rsplit('#', 1)[1]}"
            self.assertTrue(
                any(
                    identity.split(":", 1)[1] == current_suffix.removeprefix("#")
                    for identity in check_owners
                    if identity.startswith(alias["current"].rsplit("#", 1)[0] + "#")
                )
            )
            self.assertEqual(len(alias["baseline"]), len(set(alias["baseline"])))
            self.assertEqual(
                alias["lane"], job_owners[alias["current"].rsplit("#", 1)[0]]
            )
        baseline_check_count = len(check_owners) + sum(
            len(alias["baseline"]) - 1 for alias in aliases
        )
        self.assertEqual(len(job_owners), 38)
        self.assertEqual(len(check_owners), 160)
        self.assertEqual(baseline_check_count, 161)
        observed_overrides = {
            f"{identity.rsplit('#', 1)[0]}#{identity.rsplit(':', 1)[1]}"
            for identity in check_owners
            if identity.rsplit(":", 1)[1]
            in {item.rsplit("#", 1)[1] for item in overrides}
        }
        self.assertEqual(set(overrides), observed_overrides)
        self.assertEqual(
            next(
                owner
                for identity, owner in check_owners.items()
                if identity.endswith(
                    ":build test stage (affected vet + race tests in-image)"
                )
            ),
            ("go-correctness", "production-yara-static-race-coverage"),
        )


class PRArtifactImageContract(unittest.TestCase):
    """A selected PR must prove both native binaries in the same run."""

    def test_shipped_route(self):
        jobs = workflow_document("PR_WORKFLOW_TEST_PATH", "ci.yml")["jobs"]
        self.assertEqual(
            jobs["changes"]["outputs"]["release_image"],
            "${{ steps.plan.outputs.release_image }}",
        )
        binaries = jobs["pr-binaries"]
        self.assertEqual(binaries["needs"], "changes")
        self.assertEqual(
            binaries["if"],
            "${{ github.event_name == 'pull_request' && needs.changes.outputs.release_image == 'true' }}",
        )
        self.assertEqual(binaries["permissions"], {"contents": "read"})
        self.assertEqual(binaries["uses"], "./.github/workflows/build-binaries.yml")
        self.assertEqual(
            binaries["with"],
            {
                "version": "pr-${{ github.sha }}",
                "arches": '["amd64","arm64"]',
                "gha-cache": False,
            },
        )

        marker = jobs["pr-marker-image"]
        self.assertEqual(marker["needs"], ["changes", "pr-binaries"])
        self.assertEqual(
            marker["if"],
            "${{ github.event_name == 'pull_request' && needs.changes.outputs.release_image == 'true' && needs.pr-binaries.result == 'success' }}",
        )
        self.assertEqual(marker["permissions"], {"contents": "read"})
        self.assertEqual(marker["strategy"]["matrix"]["arch"], ["amd64", "arm64"])
        self.assertIs(marker["strategy"]["fail-fast"], False)
        assert_native_arch_job(self, marker, HOSTED_RUNS_ON)
        download = next(
            step
            for step in marker["steps"]
            if step.get("name") == "download PR arch binaries"
        )
        self.assertEqual(
            download["with"], {"name": "bin-${{ matrix.arch }}", "path": "out/"}
        )
        build = marker["steps"][-1]
        self.assertEqual(build["env"]["ARCH"], "${{ matrix.arch }}")
        self.assertIn(
            'bash ci/release_marker_image_test.sh "${ARCH}" out', build["run"]
        )
        self.assertIn("${RUN_ATTEMPT}", build["run"])
        self.assertTrue(
            all("gh release" not in step.get("run", "") for step in marker["steps"])
        )
        check = jobs["ci-ok"]
        self.assertIn("pr-binaries", check["needs"])
        self.assertIn("pr-marker-image", check["needs"])
        env = check["steps"][0]["env"]
        self.assertEqual(
            env["RELEASE_IMAGE_SELECTED"],
            "${{ needs.changes.outputs.release_image }}",
        )
        self.assertEqual(env["PR_BINARIES_RESULT"], "${{ needs.pr-binaries.result }}")
        self.assertEqual(
            env["PR_MARKER_IMAGE_RESULT"],
            "${{ needs.pr-marker-image.result }}",
        )
        script = check["steps"][0]["run"]
        self.assertIn(
            'require_selected "$pr_image_selected" "$PR_BINARIES_RESULT"', script
        )
        self.assertIn(
            'require_selected "$pr_image_selected" "$PR_MARKER_IMAGE_RESULT"', script
        )

    def test_selected_failure_and_reusable_skip(self):
        skipped = ("false",) * 5
        results = ("skipped",) * 4
        cases = (
            ("pull_request", "true", "success", "success", True),
            ("pull_request", "true", "skipped", "success", False),
            ("pull_request", "true", "success", "skipped", False),
            ("pull_request", "true", "failure", "skipped", False),
            ("pull_request", "true", "timed_out", "skipped", False),
            ("pull_request", "true", "success", "unknown", False),
            ("pull_request", "false", "skipped", "skipped", True),
            ("pull_request", "false", "success", "success", False),
            ("workflow_call", "true", "skipped", "skipped", True),
            ("workflow_call", "true", "success", "success", False),
            ("pull_request", "", "skipped", "skipped", False),
            ("", "true", "skipped", "skipped", False),
            ("other", "false", "skipped", "skipped", False),
        )
        for event, selected, binary, marker, expected in cases:
            with self.subTest(
                event=event, selected=selected, binary=binary, marker=marker
            ):
                self.assertEqual(
                    verdict(
                        skipped,
                        results,
                        event_name=event,
                        release_image_selected=selected,
                        pr_binaries_result=binary,
                        pr_marker_image_result=marker,
                    ),
                    expected,
                )


class NightlyMarkerImageContract(unittest.TestCase):
    """The nightly must prove its own binaries load markers before publishing."""

    def check(self, nightly):
        jobs = nightly["jobs"]
        marker = jobs["marker-image"]
        self.assertIn("binaries", marker["needs"])
        self.assertEqual(marker["permissions"], {"contents": "read"})
        self.assertEqual(marker["strategy"]["matrix"]["arch"], ["amd64", "arm64"])
        self.assertIs(marker["strategy"]["fail-fast"], False)
        assert_native_arch_job(self, marker, HOSTED_RUNS_ON)
        download = next(
            s for s in marker["steps"] if s.get("name") == "download arch binaries"
        )
        # Its own just-built artifact, never a downloaded published release.
        self.assertEqual(
            download["with"], {"name": "bin-${{ matrix.arch }}", "path": "out/"}
        )
        self.assertEqual(marker["steps"][-1]["env"]["ARCH"], "${{ matrix.arch }}")
        run = marker["steps"][-1]["run"]
        self.assertIn('bash ci/release_marker_image_test.sh "${ARCH}" out', run)
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
                'gh release download nightly\nbash ci/release_marker_image_test.sh "${ARCH}" out'
            )

        def wrong_artifact(d):
            for s in d["jobs"]["marker-image"]["steps"]:
                if s.get("name") == "download arch binaries":
                    s["with"]["name"] = "bin-amd64"

        def amd64_only(d):
            d["jobs"]["marker-image"]["strategy"]["matrix"]["arch"] = ["amd64"]

        def emulated(d):
            d["jobs"]["marker-image"]["runs-on"] = [
                "self-hosted",
                "builder02",
                "docker",
            ]

        def self_hosted_amd64(d):
            d["jobs"]["marker-image"]["runs-on"] = NATIVE_RUNS_ON

        for fn in (
            drop_job,
            drop_need,
            downloaded,
            wrong_artifact,
            amd64_only,
            emulated,
            self_hosted_amd64,
        ):
            with (
                self.subTest(case=fn.__name__),
                self.assertRaises((AssertionError, KeyError)),
            ):
                self.check(mutate(fn))


class BinaryWorkflowContract(unittest.TestCase):
    """Keep the tag release wired to the reusable, pinned binary build."""

    def test_release_packaging_and_publication_have_finite_timeouts(self):
        """Keep both jobs within the release pipeline's maintained one-hour bound."""
        jobs = workflow_document("RELEASE_WORKFLOW_TEST_PATH", "release.yml")["jobs"]
        for name in ("debs", "release"):
            with self.subTest(job=name):
                minutes = jobs[name].get("timeout-minutes")
                self.assertIs(type(minutes), int)
                self.assertEqual(minutes, 60)

    def test_selected_pr_binary_job_has_native_build_timeout(self):
        """The selected PR route must call a bounded native binary matrix."""
        ci_jobs = workflow_document("PR_WORKFLOW_TEST_PATH", "ci.yml")["jobs"]
        self.assertEqual(
            ci_jobs["pr-binaries"]["uses"],
            "./.github/workflows/build-binaries.yml",
        )
        binaries = workflow_document("BINARY_WORKFLOW_TEST_PATH", "build-binaries.yml")
        build = binaries["jobs"]["binaries"]
        assert_native_arch_job(self, build, HOSTED_RUNS_ON)
        self.assertGreaterEqual(build["timeout-minutes"], 60)

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
        # A tag release never reads a layer cache another run could have written.
        self.assertNotIn("gha-cache", caller["with"])
        self.assertNotIn("actions", caller["permissions"])
        self.assertEqual(jobs["debs"]["needs"], "binaries")
        self.assertEqual(
            jobs["release"]["needs"],
            ["binaries", "debs", "marker-image", "libyara-repro"],
        )
        marker = jobs["marker-image"]
        self.assertEqual(marker["needs"], "binaries")
        self.assertEqual(marker["permissions"], {"contents": "read"})
        assert_native_arch_job(self, marker)
        assert_native_arch_job(self, jobs["libyara-repro"])
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
        self.assertEqual(inputs["gha-cache"]["type"], "boolean")
        self.assertIs(inputs["gha-cache"]["default"], False)
        build = binaries["jobs"]["binaries"]
        self.assertEqual(
            build["strategy"]["matrix"]["arch"], "${{ fromJSON(inputs.arches) }}"
        )
        assert_native_arch_job(self, build, HOSTED_RUNS_ON)
        steps = build["steps"]
        runtime = next(
            s for s in steps if s.get("name") == "expose buildx cache runtime"
        )
        self.assertEqual(runtime["if"], "inputs.gha-cache")
        compile_step = next(
            s for s in steps if s.get("name", "").startswith("build binaries")
        )
        self.assertEqual(compile_step["env"]["VERSION"], "${{ inputs.version }}")
        self.assertEqual(compile_step["env"]["ARCH"], "${{ matrix.arch }}")
        self.assertEqual(compile_step["env"]["GHA_CACHE"], "${{ inputs.gha-cache }}")
        script = compile_step["run"]
        self.assertIn('if [[ "${GHA_CACHE}" == true ]]; then', script)
        self.assertIn('--cache-from "type=gha,scope=bin-${arch}"', script)
        self.assertIn('--cache-to "type=gha,mode=max,scope=bin-${arch}"', script)
        self.assertIn('arch="${ARCH}"', script)
        self.assertIn('--build-arg "VERSION=${VERSION}"', script)
        for asset in ("strixd", "strix-scan", "strix-milter", "yarac"):
            self.assertIn(f'"out/{asset}-linux-${{arch}}"', script)
        self.assertIn('"dist/${arch}/yarac" "out/yarac-linux-${arch}"', script)
        self.assertIn('"dist/${arch}/libyara.a" "out/libyara-linux-${arch}.a"', script)
        upload = next(s for s in steps if s.get("name") == "upload arch binaries")
        self.assertEqual(upload["with"]["name"], "bin-${{ matrix.arch }}")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
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
            "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
            "actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd",
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

    def decision(
        self,
        release,
        *,
        ref="refs/heads/main",
        sha="a" * 40,
        cwd=None,
        target="",
        force="false",
    ):
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
                '  target) printf "%s\\n" "$FAKE_TARGET";;\n'
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
                FAKE_TARGET=target,
                FORCE=force,
            )
            result = subprocess.run(
                ["bash", "-e", "-c", step["run"]],
                env=env,
                cwd=cwd,
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
        # Two hours before dockerized's 12:00 UTC daily builds :testing from it.
        self.assertEqual(workflow[True]["schedule"], [{"cron": "0 10 * * *"}])
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
        # The binaries build alongside the gate; publish requires both.
        self.assertEqual(jobs["binaries"]["needs"], "plan")
        self.assertEqual(
            jobs["binaries"]["uses"], "./.github/workflows/build-binaries.yml"
        )
        self.assertEqual(
            jobs["binaries"]["with"],
            {
                "version": "${{ needs.plan.outputs.version }}",
                "arches": '["amd64","arm64"]',
                "gha-cache": True,
            },
        )
        self.assertEqual(
            jobs["binaries"]["permissions"], {"contents": "read", "actions": "write"}
        )
        self.assertEqual(jobs["binaries"]["if"], "needs.plan.outputs.skip == 'false'")
        self.assertIn("needs.gate.result == 'success'", jobs["publish"]["if"])

    def test_equal_nightly_target_skips(self):
        """An already published main SHA must suppress the gate and build."""
        result, output, calls = self.decision("equal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skip=true\n", output)
        self.assertIn("version=nightly-aaaaaaaaaaaa\n", output)
        self.assertIn("release view nightly --repo myguard-labs/mailstrix", calls)

    def test_force_equal_nightly_target_builds(self):
        """An explicit force request must rebuild an already published SHA."""
        result, output, _ = self.decision("equal", force="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skip=false\n", output)

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

    def git_history(self, root, *changes):
        """Commit a baseline, then one commit per change; return every SHA."""

        def git(*args):
            return subprocess.run(
                ["git", "-C", str(root), *args],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        git("init", "-q")
        git("config", "user.email", "ci@example.invalid")
        git("config", "user.name", "ci")
        git("config", "commit.gpgsign", "false")
        shas = []
        for change in ({"internal/x.go": "package x\n"}, *changes):
            for name, body in change.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            git("add", "-A")
            git("commit", "-q", "-m", "c")
            shas.append(git("rev-parse", "HEAD"))
        return shas

    def test_skips_unless_a_shipped_input_changed(self):
        """Docs, CI and test-only commits keep the published nightly."""
        cases = (
            ({"README.md": "docs\n"}, "true"),
            ({".github/workflows/x.yml": "on: push\n"}, "true"),
            ({"internal/x_test.go": "package x\n"}, "true"),
            ({"internal/testdata/f.bin": "x"}, "true"),
            ({"ci/x.py": "x = 1\n"}, "true"),
            ({"docker/generate-rules_test.sh": "#!/bin/sh\n"}, "true"),
            ({"docker/INPUTS.md": "inputs\n"}, "true"),
            ({"internal/x.go": "package x // changed\n"}, "false"),
            ({"cmd/strixd/main.go": "package main\n"}, "false"),
            ({"third_party/oleparse/a.go": "package a\n"}, "false"),
            ({"go.mod": "module m\n"}, "false"),
            ({"go.sum": "x\n"}, "false"),
            ({"NOTICE": "updated attribution\n"}, "false"),
            ({".dockerignore": "*\n!go.mod\n"}, "false"),
            ({"docker/Dockerfile.release": "FROM scratch\n"}, "false"),
            ({"docker/generate-rules.sh": "#!/bin/sh\n"}, "false"),
            ({"docker/check-input.py": "print('ok')\n"}, "false"),
            ({"docker/VERSION": "1\n"}, "false"),
        )
        for change, skip in cases:
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory(prefix="mailstrix-nightly-git-") as temp,
            ):
                base, head = self.git_history(Path(temp), change)
                result, output, _ = self.decision(
                    "target", sha=head, cwd=temp, target=base
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"skip={skip}\n", output)

    def test_every_explicit_release_context_copy_selects_a_build(self):
        """Every literal release COPY input is covered by the real Git plan."""
        sources = set()
        for line in (ROOT / "docker/Dockerfile.release").read_text().splitlines():
            if line.startswith("COPY ") and "--from=" not in line:
                sources.update(line.split()[1:-1])
        self.assertIn("NOTICE", sources)
        for source in sorted(sources):
            path = source + "fixture.yara" if source.endswith("/") else source
            with (
                self.subTest(source=source),
                tempfile.TemporaryDirectory(prefix="mailstrix-nightly-copy-") as temp,
            ):
                base, head = self.git_history(Path(temp), {path: "changed input\n"})
                result, output, _ = self.decision(
                    "target", sha=head, cwd=temp, target=base
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("skip=false\n", output)

    def test_force_unknown_target_and_missing_release_build(self):
        """Force, an unreachable target or no release all rebuild."""
        with tempfile.TemporaryDirectory(prefix="mailstrix-nightly-git-") as temp:
            base, head = self.git_history(Path(temp), {"README.md": "docs\n"})
            for kwargs in (
                {"release": "target", "target": base, "force": "true"},
                {"release": "target", "target": "f" * 40},
                {"release": "missing"},
            ):
                with self.subTest(**kwargs):
                    release = kwargs.pop("release")
                    result, output, _ = self.decision(
                        release, sha=head, cwd=temp, **kwargs
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("skip=false\n", output)
            # Negative control: the same docs-only history without force skips.
            result, output, _ = self.decision("target", sha=head, cwd=temp, target=base)
            self.assertIn("skip=true\n", output)

    def test_plan_checks_out_full_history(self):
        """The shipped-input diff needs the nightly target commit locally."""
        steps = self.nightly()["jobs"]["plan"]["steps"]
        checkout = steps[0]
        self.assertEqual(
            checkout["uses"],
            "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
        )
        self.assertEqual(
            checkout["with"], {"persist-credentials": False, "fetch-depth": 0}
        )
        dispatch = self.nightly()[True]["workflow_dispatch"]
        self.assertEqual(dispatch["inputs"]["force"]["type"], "boolean")
        self.assertIs(dispatch["inputs"]["force"]["default"], False)

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
            "needs.gate.result == 'success' && needs.binaries.result == 'success'"
            " && needs.marker-image.result == 'success'",
        )
        for name in ("plan", "publish"):
            self.assertEqual(jobs[name]["runs-on"], "ubuntu-24.04")
        self.assertEqual(jobs["publish"]["permissions"]["contents"], "write")
        for name, job in jobs.items():
            if name != "publish":
                self.assertNotEqual(job.get("permissions", {}).get("contents"), "write")
        download = next(
            step
            for step in jobs["publish"]["steps"]
            if step.get("name") == "download arch binaries"
        )
        self.assertEqual(
            download["uses"],
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        )
        self.assertEqual(
            download["with"],
            {"pattern": "bin-*", "merge-multiple": True, "path": "out/"},
        )

    def test_checksums_cover_exact_assets_for_both_arches(self):
        """Every downloaded binary of both arches is hashed before publication."""
        step = next(
            step
            for step in self.nightly()["jobs"]["publish"]["steps"]
            if step.get("name") == "checksums"
        )
        with tempfile.TemporaryDirectory(prefix="mailstrix-nightly-assets-") as temp:
            root = Path(temp)
            output = root / "out"
            output.mkdir()
            names = tuple(
                name
                for arch in ("amd64", "arm64")
                for name in (
                    f"strixd-linux-{arch}",
                    f"strix-scan-linux-{arch}",
                    f"strix-milter-linux-{arch}",
                    f"yarac-linux-{arch}",
                    f"libyara-linux-{arch}.a",
                )
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
            (output / names[-1]).unlink()
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
        """A missing nightly is created with SHA target and both arches' assets."""
        result, calls = self.publication("missing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2, calls)
        create = calls[-1]
        create_args = create.split()
        self.assertIn("release create nightly", create)
        self.assertIn("--target " + "a" * 40, create)
        self.assertIn("--prerelease", create_args)
        self.assertIn("--latest=false", create_args)
        assets = ["SHA256SUMS"] + [
            name
            for arch in ("amd64", "arm64")
            for name in (
                f"strixd-linux-{arch}",
                f"strix-scan-linux-{arch}",
                f"strix-milter-linux-{arch}",
                f"yarac-linux-{arch}",
                f"libyara-linux-{arch}.a",
            )
        ]
        self.assertEqual(
            [a for a in create_args if a.startswith("out/")],
            ["out/" + asset for asset in assets],
        )

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

    FLAGS = (
        "-frandom-seed=mailstrix-yara",
        "-ffile-prefix-map=/tmp/yara-${YARA_VERSION}=.",
    )

    def test_both_dockerfiles_carry_reproducibility_flags(self):
        for name in ("Dockerfile", "Dockerfile.release"):
            text = (ROOT / "docker" / name).read_text()
            for flag in self.FLAGS:
                with self.subTest(dockerfile=name, flag=flag):
                    self.assertGreaterEqual(text.count(flag), 1)

    def test_ci_runs_the_two_build_comparison(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["compiler-inputs"]["steps"]
        self.assertIn("ci/libyara-repro-check.sh", [step.get("run") for step in steps])

    def run_script(self, hashes, script=None, args=(), cache_log=None):
        """Run the real script with a fake docker that emits the given libyara.a bytes."""
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (tmp / "bin").mkdir()
        counter = tmp / "count"
        counter.write_text("0")
        argv_log = tmp / "argv.log"
        argv_log.touch()
        compiler_log = tmp / "ccache.log"
        compiler_log.write_text(
            cache_log
            if cache_log is not None
            else "Executing /usr/bin/gcc -c fixture.c\nResult: disabled\n"
        )
        fake = tmp / "bin/docker"
        fake.write_text(
            textwrap.dedent(f"""\
            #!/usr/bin/env bash
            echo "$*" >> {argv_log}
            case "$1" in
              cp)
                if [[ "$2" == *:/tmp/ccache-repro.log ]]; then
                  cat {compiler_log} > "$3"; exit 0
                fi
                n=$(( $(cat {counter}) + 1 )); echo $n > {counter}
                contents=({" ".join(repr(h) for h in hashes)})
                # A cp past the provided archives fails like a missing file.
                [ "$n" -le "${{#contents[@]}}" ] || {{ echo "no such file" >&2; exit 1; }}
                printf '%s' "${{contents[$((n-1))]}}" > "$3" ;;
              *) : ;;
            esac
            """)
        )
        fake.chmod(0o755)
        env = dict(os.environ, PATH=f"{tmp / 'bin'}:{os.environ['PATH']}")
        result = subprocess.run(
            ["bash", str(script or ROOT / "ci/libyara-repro-check.sh"), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return result, argv_log.read_text().splitlines()

    def test_identical_archives_pass(self):
        result, _ = self.run_script(["same", "same"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reproducible", result.stdout)

    def assert_two_no_cache_builds(self, lines):
        builds = [i for i, l in enumerate(lines) if l.startswith("buildx build ")]
        self.assertEqual(len(builds), 2, lines)
        for i in builds:
            self.assertIn("--no-cache", lines[i].split())
            tokens = lines[i].split()
            self.assertEqual(tokens.count("--load"), 1, lines[i])
            self.assertEqual(tokens.count("--target"), 1, lines[i])
            self.assertEqual(tokens[tokens.index("--target") + 1], "yara", lines[i])
            self.assertIn("--build-arg", tokens)
            self.assertEqual(tokens.count("CCACHE_DISABLE=1"), 1, lines[i])
        for i in builds:
            nxt = [l for l in lines[i + 1 :] if l.startswith(("buildx build ", "cp "))]
            self.assertTrue(nxt and nxt[0].startswith("cp "), lines)
            source = nxt[0].split()[1]
            self.assertTrue(source.endswith(":/usr/local/lib/libyara.a"), nxt[0])
            self.assertGreater(len(source), len(":/usr/local/lib/libyara.a"), nxt[0])

    def test_docker_argv_two_no_cache_yara_builds_each_extracted(self):
        result, lines = self.run_script(["same", "same"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_two_no_cache_builds(lines)

    def test_missing_compiler_cache_disable_is_detected(self):
        script = self.mutated_script("--build-arg CCACHE_DISABLE=1 ", "")
        result, lines = self.run_script(["same", "same"], script=script)
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_cache_hits_or_absent_compiler_execution_fail_the_proof(self):
        for log in (
            "",
            "Result: disabled\n",
            "Executing /usr/bin/gcc --version\nResult: disabled\n",
            "Executing /usr/bin/gcc -c x.c\nResult: direct_cache_hit\n",
            "Executing /usr/bin/gcc -c x.c\nResult: disabled\nResult: cache_miss\n",
        ):
            with self.subTest(log=log):
                result, _ = self.run_script(["same", "same"], cache_log=log)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("did not prove compiler-cache bypass", result.stderr)

    def assert_cache_disable_transport(self, source):
        """Execute both real Yara RUN commands with inert build-tool witnesses."""
        stage = source.split(" AS yara\n", 1)[1].split("\nFROM ", 1)[0]
        instructions = re.findall(r"(?m)^RUN .*?(?<!\\)$", stage, re.DOTALL)
        commands = [
            re.sub(r"^RUN --mount=\S+\s+", "", value).replace("\\\n", " ")
            for value in instructions
            if value.startswith("RUN --mount=type=cache,target=/root/.cache/ccache")
        ]
        self.assertEqual(len(commands), 2)
        declaration = re.search(r"(?m)^ARG CCACHE_DISABLE(?:=(.*))?$", stage)
        for command, proof in itertools.product(commands, (False, True)):
            with tempfile.TemporaryDirectory(prefix="mailstrix-repro-env-") as temp:
                fixture = Path(temp)
                tools = fixture / "bin"
                tools.mkdir()
                trace = fixture / "trace"
                witness = (
                    '#!/bin/sh\nprintf "%s %s\\n" "$0" '
                    '"${CCACHE_DISABLE-unset}" >> "$TRACE"\n'
                )
                for name in ("mkdir", "cp", "python3", "make", "ldconfig"):
                    path = tools / name
                    path.write_text(witness)
                    path.chmod(0o755)
                for name in ("bootstrap.sh", "configure"):
                    path = fixture / name
                    path.write_text(witness)
                    path.chmod(0o755)
                env = dict(
                    os.environ, PATH=str(tools) + ":/usr/bin:/bin", TRACE=str(trace)
                )
                env.pop("CCACHE_DISABLE", None)
                if declaration:
                    env["CCACHE_DISABLE"] = "1" if proof else (declaration[1] or "")
                result = subprocess.run(
                    ["sh", "-ec", command],
                    cwd=fixture,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                observations = trace.read_text().splitlines()
                self.assertTrue(any("/make " in line for line in observations))
                self.assertEqual(
                    {line.rsplit(" ", 1)[1] for line in observations},
                    {"1" if proof else "unset"},
                    "proof disablement or ordinary caching transport changed",
                )

    def test_both_yara_recipes_transport_disable_and_unset_default(self):
        for name in ("Dockerfile", "Dockerfile.release"):
            with self.subTest(recipe=name):
                self.assert_cache_disable_transport(
                    (ROOT / "docker" / name).read_text()
                )

    def test_removed_recipe_propagation_is_detected(self):
        for name in ("Dockerfile", "Dockerfile.release"):
            source = (ROOT / "docker" / name).read_text()
            with self.subTest(recipe=name), self.assertRaises(AssertionError):
                self.assert_cache_disable_transport(
                    source.replace("ARG CCACHE_DISABLE\n", "")
                )

    def mutated_script(self, old, new):
        text = (ROOT / "ci/libyara-repro-check.sh").read_text()
        self.assertIn(old, text)
        copy = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (copy / "ci").mkdir()
        script = copy / "ci/libyara-repro-check.sh"
        script.write_text(text.replace(old, new))
        return script

    def test_dropping_no_cache_is_detected(self):
        script = self.mutated_script(
            'buildx build --no-cache --load "${platform_args[@]}" --target',
            'buildx build --load "${platform_args[@]}" --target',
        )
        _, lines = self.run_script(["same", "same"], script=script)
        builds = [l for l in lines if l.startswith("buildx build ")]
        # The mutant still builds twice; only the missing flag must trip the check.
        self.assertEqual(len(builds), 2, lines)
        self.assertTrue(all("--no-cache" not in b.split() for b in builds), lines)
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_wrong_archive_source_is_detected(self):
        script = self.mutated_script(
            '"$extract:/usr/local/lib/libyara.a"',
            '"$extract:/usr/local/lib/libyara.a.bak"',
        )
        _, lines = self.run_script(["same", "same"], script=script)
        self.assertEqual(len([l for l in lines if l.startswith("cp ")]), 4, lines)
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_plain_docker_build_is_detected(self):
        script = self.mutated_script(
            "docker buildx build --no-cache", "docker build --no-cache"
        )
        _, lines = self.run_script(["same", "same"], script=script)
        self.assertEqual(len([l for l in lines if l.startswith("build ")]), 2, lines)
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_dropping_load_is_detected(self):
        script = self.mutated_script("--no-cache --load", "--no-cache")
        _, lines = self.run_script(["same", "same"], script=script)
        self.assertEqual(
            len([l for l in lines if l.startswith("buildx build ")]), 2, lines
        )
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_wrong_target_stage_is_detected(self):
        script = self.mutated_script("--target yara", "--target yara-debug")
        _, lines = self.run_script(["same", "same"], script=script)
        builds = [l for l in lines if l.startswith("buildx build ")]
        # The mutant still builds twice with --no-cache; only the stage must trip the check.
        self.assertEqual(len(builds), 2, lines)
        for b in builds:
            self.assertIn("--no-cache", b.split(), b)
            self.assertIn("yara-debug", b.split(), b)
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_single_build_is_detected(self):
        script = self.mutated_script("for n in 1 2; do", "for n in 1; do")
        _, lines = self.run_script(["same", "same"], script=script)
        builds = [l for l in lines if l.startswith("buildx build ")]
        # The mutant builds once with the right flags; only the count must trip it.
        self.assertEqual(len(builds), 1, lines)
        self.assertIn("--no-cache", builds[0].split())
        with self.assertRaises(AssertionError):
            self.assert_two_no_cache_builds(lines)

    def test_release_dockerfile_arg_is_passed_to_build(self):
        result, lines = self.run_script(
            ["same", "same"],
            args=("docker/Dockerfile.release", "mailstrix-repro-release"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        builds = [l for l in lines if l.startswith("buildx build ")]
        self.assertEqual(len(builds), 2, lines)
        for b in builds:
            tokens = b.split()
            self.assertIn("-f", tokens, b)
            self.assertEqual(
                tokens[tokens.index("-f") + 1], "docker/Dockerfile.release", b
            )

    RELEASE_RUN = (
        "ci/libyara-repro-check.sh docker/Dockerfile.release "
        '"mailstrix-repro-release-${RUN_ID}-${ARCH}" "linux/${ARCH}"'
    )
    MAINT_RUN = (
        "ci/libyara-repro-check.sh docker/Dockerfile.release "
        '"mailstrix-repro-maint-${RUN_ID}-${ARCH}" "linux/${ARCH}"'
    )
    REPRO_CHECK = "ci/libyara-repro-check.sh"

    def repro_step(self, job):
        return next(
            s for s in job["steps"] if s.get("run", "").startswith(self.REPRO_CHECK)
        )

    def assert_repro_job_covers_both_arches(self, job, expected_run):
        self.assertEqual(sorted(job["strategy"]["matrix"]["arch"]), ["amd64", "arm64"])
        self.assertIs(job["strategy"].get("fail-fast"), False)
        self.assertGreaterEqual(job["timeout-minutes"], 60)
        steps = job["steps"]
        runs = [
            s for s in steps if s.get("run", "").startswith("ci/libyara-repro-check.sh")
        ]
        self.assertEqual(len(runs), 1, steps)
        self.assertEqual(runs[0]["run"], expected_run)
        self.assertEqual(
            runs[0]["env"],
            {"ARCH": "${{ matrix.arch }}", "RUN_ID": "${{ github.run_id }}"},
        )
        uses = [s.get("uses", "") for s in steps]
        assert_native_arch_job(self, job)
        self.assertTrue(
            any(u.startswith("docker/setup-buildx-action@") for u in uses), uses
        )

    def test_maintenance_runs_release_dockerfile_check_for_every_arch(self):
        doc = yaml.safe_load((ROOT / ".github/workflows/maintenance.yml").read_text())
        job = doc["jobs"]["release-libyara-repro"]
        self.assert_repro_job_covers_both_arches(job, self.MAINT_RUN)

    def test_repro_prefixes_differ_and_are_run_scoped(self):
        def repro_run(path, job):
            doc = yaml.safe_load((ROOT / path).read_text())
            steps = doc["jobs"][job]["steps"]
            runs = [
                s["run"] for s in steps if s.get("run", "").startswith(self.REPRO_CHECK)
            ]
            self.assertEqual(len(runs), 1, path)
            return runs[0]

        release = repro_run(".github/workflows/release.yml", "libyara-repro")
        maint = repro_run(".github/workflows/maintenance.yml", "release-libyara-repro")
        self.assertIn('"mailstrix-repro-release-${RUN_ID}-${ARCH}"', release)
        self.assertIn('"mailstrix-repro-maint-${RUN_ID}-${ARCH}"', maint)
        self.assertNotEqual(release, maint)
        for run in (release, maint):
            self.assertIn("${RUN_ID}", run)

    def test_maintenance_prefix_without_run_id_is_detected(self):
        doc = yaml.safe_load((ROOT / ".github/workflows/maintenance.yml").read_text())
        job = doc["jobs"]["release-libyara-repro"]
        step = self.repro_step(job)
        old = "mailstrix-repro-maint-${RUN_ID}-"
        step["run"] = step["run"].replace(old, "mailstrix-repro-maint-")
        with self.assertRaises(AssertionError):
            self.assert_repro_job_covers_both_arches(job, self.MAINT_RUN)

    def test_repro_step_without_run_id_env_is_detected(self):
        doc = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        job = doc["jobs"]["libyara-repro"]
        del self.repro_step(job)["env"]["RUN_ID"]
        with self.assertRaises(AssertionError):
            self.assert_repro_job_covers_both_arches(job, self.RELEASE_RUN)

    def test_release_workflow_runs_release_check_before_publish(self):
        doc = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        jobs = doc["jobs"]
        gate = [
            n
            for n, j in jobs.items()
            if any(
                s.get("run", "").startswith(
                    "ci/libyara-repro-check.sh docker/Dockerfile.release"
                )
                for s in j.get("steps", [])
            )
        ]
        self.assertEqual(gate, ["libyara-repro"], gate)
        self.assert_repro_job_covers_both_arches(
            jobs["libyara-repro"], self.RELEASE_RUN
        )
        self.assertIn("libyara-repro", jobs["release"]["needs"])

    def test_release_matrix_without_arm64_is_detected(self):
        doc = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        job = doc["jobs"]["libyara-repro"]
        job["strategy"]["matrix"]["arch"] = ["amd64"]
        with self.assertRaises(AssertionError):
            self.assert_repro_job_covers_both_arches(job, self.RELEASE_RUN)

    def test_platform_arg_is_passed_to_both_builds_and_creates(self):
        result, lines = self.run_script(
            ["same", "same"],
            args=(
                "docker/Dockerfile.release",
                "mailstrix-repro-release-arm64",
                "linux/arm64",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_platform_passed(lines)

    def assert_platform_passed(self, lines):
        for verb in ("buildx build", "create"):
            cmds = [l.split() for l in lines if l.startswith(verb + " ")]
            self.assertEqual(len(cmds), 2, lines)
            for t in cmds:
                self.assertIn("--platform", t, lines)
                self.assertEqual(t[t.index("--platform") + 1], "linux/arm64", t)

    def test_no_platform_arg_adds_no_platform_token(self):
        result, lines = self.run_script(["same", "same"])
        self.assertEqual(result.returncode, 0, result.stderr)
        for l in lines:
            self.assertNotIn("--platform", l.split(), l)
            if l.startswith("buildx build "):
                self.assertEqual(l.split().count("--load"), 1, l)
            else:
                self.assertNotIn("--load", l.split(), l)

    def test_dropping_platform_passing_is_detected(self):
        script = self.mutated_script('"${platform_args[@]}" ', "")
        _, lines = self.run_script(
            ["same", "same"],
            script=script,
            args=("docker/Dockerfile.release", "p", "linux/arm64"),
        )
        with self.assertRaises(AssertionError):
            self.assert_platform_passed(lines)

    def test_per_pr_ci_does_not_run_release_check(self):
        self.assertNotIn("Dockerfile.release --", WORKFLOW.read_text())
        self.assertNotIn(
            "libyara-repro-check.sh docker/Dockerfile.release", WORKFLOW.read_text()
        )

    def test_differing_archives_fail(self):
        result, _ = self.run_script(["one", "two"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not byte-reproducible", result.stderr)

    def test_missing_archive_fails(self):
        result, _ = self.run_script(["same"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no such file", result.stderr)
        self.assertNotIn("not byte-reproducible", result.stderr)


if __name__ == "__main__":
    unittest.main()
