#!/usr/bin/env python3
"""Exercise qualification image lifetimes without touching a Docker daemon."""

import errno
import json
import os
import select
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualify-parity-isolation.sh"
WORKER = "sha256:" + "a" * 64
PROBE = "sha256:" + "b" * 64
PRE_EXISTING = "sha256:" + "c" * 64
SIGNAL_READY_TIMEOUT = 15
SIGNAL_PARENT_DELAY = 2.2
SIGNAL_WAIT_TIMEOUT = 8
SIGNAL_CLEANUP_TIMEOUT = 5
SIGNAL_CHILD_WATCHDOG = 45
FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
p = pathlib.Path(os.environ["DOCKER_STATE"])
s = json.loads(p.read_text())
a = sys.argv[1:]
assert a[:2] == ["--host", "unix:///var/run/docker.sock"], a
a = a[2:]
s["calls"].append(a)
code = 0
if a[:2] == ["buildx", "build"]:
    assert "--target" in a, "build requires --target"
    target = a[a.index("--target") + 1]
    if s["mode"] == "build-before-load-failure":
        p.write_text(json.dumps(s))
        sys.exit(9)
    if target == "parity-qualification-bin":
        assert "--output" in a, "qualification binary requires --output"
        dest = pathlib.Path(a[a.index("--output") + 1].split("dest=")[1])
        dest.mkdir()
        if s["mode"] in ("cleanup-log-failure", "cleanup-log-success"):
            (dest.parent / "image-cleanup.log").mkdir()
        exe = dest / "parity.test"
        exe.write_text("#!/bin/sh\necho qualification-ran\nexit " +
                       ("7" if s["mode"] in ("test-failure", "cleanup-log-failure",
                                             "inspect-timeout-original", "mktemp-original") else "0") + "\n")
        if s["mode"].startswith("signal-"):
            exe.write_text("#!/usr/bin/env python3\nimport os, signal\n"
                           "signal.alarm(int(os.environ['PARITY_TEST_WATCHDOG']))\n"
                           "print('qualification-ready', flush=True)\n"
                           "os.read(int(os.environ['PARITY_TEST_RELEASE_FD']), 1)\n")
        exe.chmod(0o755)
    else:
        assert "--iidfile" in a, "runtime build requires --iidfile"
        if s["cleanup"]:
            assert "--tag" in a, "cleanup runtime build requires --tag"
            assert "--label" in a, "cleanup runtime build requires --label"
        ident = "sha256:" + ("a" if target == "parity-runtime" else "b") * 64
        if ident not in s["images"]:
            s["images"].append(ident)
        if "--tag" in a:
            tag = a[a.index("--tag") + 1]
            owner = a[a.index("--label") + 1].split("=", 1)[1]
            s["tags"][tag] = [ident, "foreign-owner-fixture" if s["mode"] == "foreign-owner" else owner]
        if s["mode"] == "shared" and target == "parity-runtime":
            s["tags"]["other:consumer"] = [ident, "other"]
        pathlib.Path(a[a.index("--iidfile") + 1]).write_text(ident)
        if s["mode"] == "build-failure" and target == "parity-probe-runtime":
            pathlib.Path(a[a.index("--iidfile") + 1]).unlink()
            code = 9  # Load completed but build/iidfile publication failed.
elif a[:2] == ["image", "inspect"]:
    value = s["tags"].get(a[-1])
    if s["mode"] == "already-absent" and value:
        s["images"].remove(value[0])
        del s["tags"][a[-1]]
        value = None
    if s["mode"] == "inspect-failure":
        print("fixture: daemon unavailable", file=sys.stderr)
        code = 1
    elif value:
        if s["mode"] == "inspect-warning":
            print("fixture: Docker inspect warning", file=sys.stderr)
        if s["mode"] == "malformed-id":
            value = ["invalid-id", value[1]]
        print(" ".join(value))
        if s["mode"] == "extra-stdout":
            print("unexpected output")
    else:
        print("Error response from daemon: No such image: " + a[-1], file=sys.stderr)
        code = 1
elif a[:2] == ["image", "rm"]:
    assert a[2] == "--no-prune" and len(a) == 4, a
    tag = a[-1]
    assert tag.startswith("mailstrix-qualification:image-owner."), a
    ident = s["tags"][tag][0]
    if s["mode"] == "container-user" and ident.endswith("a" * 64):
        code = 1
    else:
        del s["tags"][tag]
        if not any(v[0] == ident for v in s["tags"].values()):
            s["images"].remove(ident)
else:
    raise AssertionError(a)
p.write_text(json.dumps(s))
sys.exit(code)
'''
FAKE_TIMEOUT = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
a = sys.argv[1:]
docker_args = a[a.index("docker"):] if "docker" in a else []
if docker_args[3:5] in (["image", "inspect"], ["image", "rm"]):
    expected = ["--kill-after=1s", "5s"] if docker_args[4] == "inspect" else ["--kill-after=2s", "15s"]
    assert a[:2] == expected, "cleanup must use its operation-specific timeout budget"
    p = pathlib.Path(os.environ["DOCKER_STATE"])
    s = json.loads(p.read_text())
    s.setdefault("cleanup_timeouts", []).append(a[:2])
    p.write_text(json.dumps(s))
    if docker_args[4] == "inspect" and s["mode"] in (
        "timeout-missing-tag", "killed-missing-tag", "missing-distinct-tag"
    ):
        tag = "other:tag" if s["mode"] == "missing-distinct-tag" else docker_args[-1]
        print("No such image: " + tag, file=sys.stderr)
        sys.exit({"timeout-missing-tag": 124, "killed-missing-tag": 137,
                  "missing-distinct-tag": 1}[s["mode"]])
    if docker_args[4] == "inspect" and (
        s["mode"].startswith("missing-warnings-") or s["mode"] in ("missing-prefix", "missing-suffix")
    ):
        tag = docker_args[-1]
        kind = "object" if s["mode"].endswith("object") else "image"
        prefix = "Error response from daemon: " if "prefixed" in s["mode"] else ""
        if "cli-error" in s["mode"]:
            prefix = "Error: "
        message = prefix + "No such " + kind + ": " + tag
        if s["mode"] == "missing-prefix":
            message = "unexpected: " + message
        elif s["mode"] == "missing-suffix":
            message += "-different"
        else:
            s["images"].remove(s["tags"][tag][0])
            del s["tags"][tag]
            p.write_text(json.dumps(s))
        print("fixture warning before", file=sys.stderr)
        print(message, file=sys.stderr)
        if s["mode"].startswith("missing-warnings-"):
            print("fixture warning after", file=sys.stderr)
        sys.exit(1)
    inspect_timeout = s["mode"] in ("inspect-timeout", "inspect-timeout-original")
    remove_timeout = s["mode"] == "remove-timeout"
    if (inspect_timeout and docker_args[4] == "inspect") or (
        remove_timeout and docker_args[4] == "rm"
    ):
        print("fixture: simulated Docker timeout", file=sys.stderr)
        sys.exit(124)
os.execv(os.environ["REAL_TIMEOUT"], [os.environ["REAL_TIMEOUT"], *a])
'''
FAKE_MKTEMP = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
a = sys.argv[1:]
p = pathlib.Path(os.environ["DOCKER_STATE"])
s = json.loads(p.read_text())
if a[:2] == ["-t", "mailstrix-parity-inspect.XXXXXXXX"] and s["mode"] in (
    "mktemp-failure", "mktemp-original"
):
    s["temp_allocations"] = s.get("temp_allocations", 0) + 1
    p.write_text(json.dumps(s))
    sys.exit(1)  # Deliberately silent: the caller must supply a diagnostic.
os.execv(os.environ["REAL_MKTEMP"], [os.environ["REAL_MKTEMP"], *a])
'''


class ImageCleanup(unittest.TestCase):
    def test_child_watchdog_exceeds_full_parent_budget(self):
        self.assertGreater(SIGNAL_CHILD_WATCHDOG, SIGNAL_READY_TIMEOUT + SIGNAL_PARENT_DELAY +
                           SIGNAL_WAIT_TIMEOUT + SIGNAL_CLEANUP_TIMEOUT)

    def test_popen_failure_closes_signal_pipe(self):
        # Popen is mocked before construction, so synthetic descriptors avoid
        # both real resource leaks and numeric FD reuse during tempfile cleanup.
        descriptors = (-101, -102)
        closed = []
        real_close = os.close

        def tracked_close(descriptor):
            if descriptor in descriptors:
                closed.append(descriptor)
            else:
                real_close(descriptor)

        with (
            mock.patch("os.pipe", return_value=descriptors),
            mock.patch("os.close", side_effect=tracked_close),
            mock.patch("subprocess.Popen",
                       side_effect=OSError(errno.EAGAIN, "injected spawn failure")),
            self.assertRaises(OSError) as raised,
        ):
            self.run_case("signal-term")
        self.assertEqual(raised.exception.errno, errno.EAGAIN)
        self.assertCountEqual(closed, descriptors,
                              "Popen failure must close each signal-pipe descriptor exactly once")

    def test_help_in_either_flag_order_does_no_work(self):
        for args in (["--help"], ["--help", "--cleanup-images"],
                     ["--cleanup-images", "--help"], ["output", "--help", "--cleanup-images"]):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                docker = root / "docker"
                docker.write_text("#!/bin/sh\nprintf 'unexpected Docker invocation' >&2\nexit 91\n")
                docker.chmod(0o755)
                env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}")
                result = subprocess.run(["bash", str(SCRIPT), *args], cwd=root, env=env,
                                        capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.startswith("Usage:"), result.stdout)
                self.assertEqual(result.stderr, "")
                self.assertEqual(set(root.iterdir()), {docker}, "help must not create output")

    def test_invalid_arguments_do_no_work(self):
        cases = (
            (["--cleanup-images", "--cleanup-images", "output"],
             "Duplicate option: --cleanup-images.\n"),
            (["--unknown"], "Unknown option: --unknown.\n"),
            ([], "One new output directory is required.\n"),
            (["--cleanup-images"], "One new output directory is required.\n"),
            (["one", "two"], "Only one output directory is allowed.\n"),
            ([""], "Output directory must not be empty.\n"),
            (["--"], "One new output directory is required.\n"),
            (["output", "--"], "One new output directory is required.\n"),
            (["--cleanup-images", "--"], "One new output directory is required.\n"),
            (["--", "one", "two"], "Only one output directory is allowed.\n"),
            (["--", "--help", "extra"], "Only one output directory is allowed.\n"),
            (["--", "--cleanup-images", "extra"], "Only one output directory is allowed.\n"),
            (["--", ""], "Output directory must not be empty.\n"),
        )
        for args, message in cases:
            with self.subTest(args=args), tempfile.TemporaryDirectory() as directory:
                docker = Path(directory) / "docker"
                docker.write_text("#!/bin/sh\nprintf 'unexpected Docker invocation' >&2\nexit 91\n")
                docker.chmod(0o755)
                env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}")
                result = subprocess.run(["bash", str(SCRIPT), *args], cwd=directory,
                                        env=env, capture_output=True, text=True,
                                        timeout=5, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stderr, message)
                self.assertEqual(result.stdout, "")
                self.assertEqual(set(Path(directory).iterdir()), {docker})

    def run_case(self, mode="new", cleanup=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_name = {"literal-dash": "-out", "literal-help": "--help",
                           "literal-cleanup": "--cleanup-images"}.get(mode, "output")
            output = root / output_name
            self.assertNotIn(ROOT, root.parents,
                             "fixture scratch must stay outside the build context")
            docker = root / "docker"
            docker.write_text(FAKE_DOCKER)
            docker.chmod(0o755)
            timeout = root / "timeout"
            timeout.write_text(FAKE_TIMEOUT)
            timeout.chmod(0o755)
            mktemp = root / "mktemp"
            mktemp.write_text(FAKE_MKTEMP)
            mktemp.chmod(0o755)
            state = root / "state.json"
            initial_images = [PRE_EXISTING] if mode == "pre-existing" else []
            state.write_text(json.dumps({"mode": mode, "cleanup": cleanup, "images": initial_images,
                                         "tags": {}, "calls": []}))
            real_timeout = shutil.which("timeout")
            self.assertIsNotNone(real_timeout)
            real_mktemp = shutil.which("mktemp")
            self.assertIsNotNone(real_mktemp)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", DOCKER_STATE=str(state),
                       REAL_TIMEOUT=real_timeout, REAL_MKTEMP=real_mktemp, TMPDIR=str(root))
            command = ["bash", str(SCRIPT)] + (["--cleanup-images"] if cleanup else [])
            command += [str(output)]
            if mode == "cleanup-last":
                command = ["bash", str(SCRIPT), str(output), "--cleanup-images"]
            if mode.startswith("literal-"):
                command = ["bash", str(SCRIPT)] + (["--cleanup-images"] if cleanup else [])
                command += ["--", output_name]
            if mode.startswith("signal-"):
                sent_signal = signal.SIGINT if mode == "signal-int" else signal.SIGTERM
                release_reader, release_writer = os.pipe()
                try:
                    env["PARITY_TEST_RELEASE_FD"] = str(release_reader)
                    env["PARITY_TEST_WATCHDOG"] = str(SIGNAL_CHILD_WATCHDOG)
                    with subprocess.Popen(command, env=env, cwd=root, start_new_session=True,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          text=True, pass_fds=(release_reader,)) as process:
                        os.close(release_reader)
                        release_reader = -1
                        try:
                            self.assertTrue(select.select(
                                [process.stdout], [], [], SIGNAL_READY_TIMEOUT
                            )[0],
                                            "qualification must become ready before signaling")
                            self.assertEqual(process.stdout.readline(), "qualification-ready\n")
                            if mode == "signal-term-delayed":
                                time.sleep(SIGNAL_PARENT_DELAY)
                                self.assertIsNone(process.poll(),
                                                  "qualification must wait for parent release")
                            if mode == "signal-leader":
                                os.kill(process.pid, sent_signal)
                                process.wait(timeout=SIGNAL_WAIT_TIMEOUT)
                                self.assertEqual(json.loads(state.read_text())["images"], [],
                                                 "leader exit must clean before child release")
                                with self.assertRaises(subprocess.TimeoutExpired):
                                    process.communicate(timeout=0.1)
                            else:
                                os.killpg(process.pid, sent_signal)
                            os.close(release_writer)
                            release_writer = -1
                            _, stderr = process.communicate(timeout=SIGNAL_WAIT_TIMEOUT)
                            self.assertIn(process.returncode,
                                          (-sent_signal, 128 + sent_signal), stderr)
                        finally:
                            if release_writer != -1:
                                os.close(release_writer)
                                release_writer = -1
                            if process.poll() is None:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.communicate(timeout=SIGNAL_CLEANUP_TIMEOUT)
                finally:
                    for descriptor in (release_reader, release_writer):
                        if descriptor != -1:
                            os.close(descriptor)
            else:
                result = subprocess.run(command, env=env, cwd=root, capture_output=True,
                                        text=True, timeout=15, check=False)
                self.assertEqual(result.returncode, {"build-failure": 1, "test-failure": 7,
                                                "cleanup-log-failure": 7,
                                                "cleanup-log-success": 1,
                                                "inspect-timeout-original": 7,
                                                "inspect-timeout": 1, "remove-timeout": 1,
                                                "inspect-failure": 1, "container-user": 1,
                                                "malformed-id": 1, "foreign-owner": 1,
                                                "timeout-missing-tag": 1, "killed-missing-tag": 1,
                                                "missing-distinct-tag": 1,
                                                "extra-stdout": 1,
                                                "missing-prefix": 1, "missing-suffix": 1,
                                                "mktemp-failure": 1, "mktemp-original": 7,
                                                "build-before-load-failure": 1}.get(mode, 0),
                                 result.stderr)
            self.assertTrue(output.is_dir(),
                            "qualification must create the requested output directory")
            artifacts = {p.name for p in output.iterdir()}
            self.assertFalse(any(name.startswith("image-owner.") for name in artifacts))
            if mode != "build-before-load-failure":
                self.assertIn("parity-runtime.log", artifacts)
                self.assertIn("parity-runtime.id", artifacts)
                if cleanup:
                    self.assertIn("image-cleanup.log", artifacts)
                if mode == "inspect-failure":
                    log = (output / "image-cleanup.log").read_text()
                    self.assertIn("fixture: daemon unavailable", log)
                    self.assertIn(
                        "Image inspection failed:", log
                    )
                if mode in ("malformed-id", "foreign-owner"):
                    log = (output / "image-cleanup.log").read_text()
                    reason = "invalid image ID" if mode == "malformed-id" else "owner mismatch"
                    self.assertIn(f"Skipping cleanup ({reason}): mailstrix-qualification:", log)
                    self.assertNotIn("foreign-owner-fixture", log)
            else:
                log = (output / "image-cleanup.log").read_text()
                self.assertIn("Error response from daemon: No such image:", log)
                self.assertIn("Tag already absent:", log)
                self.assertNotIn("Retaining unavailable or shared image", log)
            final_state = json.loads(state.read_text())
            if mode in ("mktemp-failure", "mktemp-original"):
                self.assertEqual((output / "image-cleanup.log").read_text(),
                                 "Cannot allocate Docker inspection diagnostic file.\n")
            if mode.startswith("missing-warnings-"):
                log = (output / "image-cleanup.log").read_text()
                self.assertIn("fixture warning before", log)
                self.assertIn("fixture warning after", log)
                self.assertIn("Tag already absent:", log)
            self.assertEqual(set(root.iterdir()), {docker, timeout, mktemp, state, output},
                             "temporary diagnostic files must be removed")
            if mode == "inspect-warning":
                self.assertIn("fixture: Docker inspect warning",
                              (output / "image-cleanup.log").read_text())
            if mode in ("timeout-missing-tag", "killed-missing-tag", "missing-distinct-tag",
                        "missing-prefix", "missing-suffix"):
                log = (output / "image-cleanup.log").read_text()
                self.assertIn("Image inspection failed:", log)
                self.assertNotIn("Tag already absent:", log)
            if mode in ("inspect-timeout", "inspect-timeout-original", "remove-timeout"):
                log = (output / "image-cleanup.log").read_text()
                self.assertIn("fixture: simulated Docker timeout", log)
                self.assertNotIn("Tag already absent:", log)
                expected_calls = 4 if mode == "remove-timeout" else 2
                self.assertEqual(len(final_state["cleanup_timeouts"]), expected_calls,
                                 "failed cleanup must not be retried by log fallback")
            if mode.startswith("signal-"):
                final_state["signal_returncode"] = process.returncode
            return final_state

    def test_new_images_removed(self):
        state = self.run_case()
        self.assertEqual(state["images"], [], "invocation-owned images must be removed")
        self.assertEqual(state["tags"], {})

    def test_cleanup_flag_after_output_removes_owned_images(self):
        self.assertEqual(self.run_case("cleanup-last")["images"], [])

    def test_terminator_allows_literal_option_like_directories(self):
        for mode in ("literal-dash", "literal-help", "literal-cleanup"):
            with self.subTest(mode=mode):
                cleanup = mode != "literal-cleanup"
                expected = [] if cleanup else [WORKER, PROBE]
                self.assertEqual(self.run_case(mode, cleanup=cleanup)["images"], expected)

    def test_cleanup_timeout_budgets_are_operation_specific(self):
        state = self.run_case()
        self.assertEqual(state["cleanup_timeouts"],
                         [["--kill-after=1s", "5s"], ["--kill-after=2s", "15s"]] * 2)

    def test_healthy_inspection_with_stderr_warning_succeeds(self):
        self.assertEqual(self.run_case("inspect-warning")["images"], [])

    def test_inspection_rejects_extra_stdout(self):
        self.assertEqual(self.run_case("extra-stdout")["images"], [WORKER, PROBE])

    def test_already_absent_tags_are_successful_cleanup(self):
        state = self.run_case("already-absent")
        self.assertEqual(state["images"], [])
        self.assertFalse(any(call[:2] == ["image", "rm"] for call in state["calls"]))

    def test_missing_tag_requires_normal_status_and_exact_tag(self):
        for mode in ("timeout-missing-tag", "killed-missing-tag", "missing-distinct-tag",
                     "missing-prefix", "missing-suffix"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_case(mode)["images"], [WORKER, PROBE])

    def test_exact_missing_diagnostic_among_warnings(self):
        for kind in ("image", "object", "prefixed-image", "prefixed-object",
                     "cli-error-image", "cli-error-object"):
            with self.subTest(kind=kind):
                self.assertEqual(self.run_case("missing-warnings-" + kind)["images"], [])

    def test_inspect_timeout_fails_successful_qualification(self):
        self.assertEqual(self.run_case("inspect-timeout")["images"], [WORKER, PROBE])

    def test_removal_timeout_fails_successful_qualification(self):
        self.assertEqual(self.run_case("remove-timeout")["images"], [WORKER, PROBE])

    def test_inspect_timeout_preserves_original_failure(self):
        self.assertEqual(self.run_case("inspect-timeout-original")["images"], [WORKER, PROBE])

    def test_log_open_failure_fails_success_but_still_cleans(self):
        self.assertEqual(self.run_case("cleanup-log-success")["images"], [])

    def test_diagnostic_temp_failure_is_visible_and_preserves_prior_status(self):
        for mode in ("mktemp-failure", "mktemp-original"):
            with self.subTest(mode=mode):
                state = self.run_case(mode)
                self.assertEqual(state["images"], [WORKER, PROBE])
                self.assertEqual(state["temp_allocations"], 1)
                self.assertFalse(any(call[:1] == ["image"] for call in state["calls"]))

    def test_process_group_sigterm_cleans_once_and_preserves_signal_status(self):
        self.assert_signal_cleanup("signal-term")

    def test_leader_only_sigterm(self):
        self.assert_signal_cleanup("signal-leader")

    def test_process_group_sigint_cleans_once_and_preserves_signal_status(self):
        self.assert_signal_cleanup("signal-int")

    def test_delayed_parent_signals_before_qualification_can_finish(self):
        self.assert_signal_cleanup("signal-term-delayed")

    def assert_signal_cleanup(self, mode):
        state = self.run_case(mode)
        self.assertEqual(state["images"], [], "signal exit must clean owned images")
        self.assertEqual(state["tags"], {})
        removals = [call for call in state["calls"] if call[:2] == ["image", "rm"]]
        self.assertEqual(len(removals), 2, "each owned tag must be removed exactly once")

    def test_pre_existing_retained(self):
        self.assertEqual(self.run_case("pre-existing")["images"], [PRE_EXISTING])

    def test_shared_content_retained(self):
        state = self.run_case("shared")
        self.assertEqual(state["images"], [WORKER])
        self.assertEqual(set(state["tags"]), {"other:consumer"})

    def test_container_user_retained(self):
        self.assertEqual(self.run_case("container-user")["images"], [WORKER])

    def test_foreign_owner_retained(self):
        self.assertEqual(self.run_case("foreign-owner")["images"], [WORKER, PROBE])

    def test_malformed_inspected_id_logged_and_retained(self):
        self.assertEqual(self.run_case("malformed-id")["images"], [WORKER, PROBE])

    def test_build_failure_without_iid_cleans_loaded_images(self):
        self.assertEqual(self.run_case("build-failure")["images"], [])

    def test_test_failure_cleans_images_and_preserves_status(self):
        self.assertEqual(self.run_case("test-failure")["images"], [])

    def test_unopenable_cleanup_log_preserves_status_and_cleans_images(self):
        self.assertEqual(self.run_case("cleanup-log-failure")["images"], [])

    def test_inspect_failure_logged_and_images_retained(self):
        self.assertEqual(self.run_case("inspect-failure")["images"], [WORKER, PROBE])

    def test_build_failure_before_load_reports_absent_tag(self):
        state = self.run_case("build-before-load-failure")
        self.assertEqual(state["images"], [])
        self.assertEqual([call[:2] for call in state["calls"]],
                         [["buildx", "build"], ["image", "inspect"]])

    def test_manual_retention_default(self):
        state = self.run_case(cleanup=False)
        self.assertEqual(state["images"], [WORKER, PROBE])
        self.assertTrue(all(call[:1] == ["buildx"] for call in state["calls"]))


if __name__ == "__main__":
    unittest.main()
