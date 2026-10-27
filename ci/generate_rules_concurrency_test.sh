#!/usr/bin/env bash
# Exercise the actual rolling publisher with inert release/build boundaries.
# Git itself is real: a shared bare remote provides the authoritative CAS lease.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$repo" <<'PY'
import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

repo = Path(sys.argv[1])
maximum = (1 << 63) - 1

ci_workflow_prefix = (repo / ".github/workflows/ci.yml").read_text(encoding="utf-8").split("\nconcurrency:", 1)[0]
if "refs/heads/mailstrix-publisher-leases/*" not in ci_workflow_prefix:
    raise AssertionError("CI workflow does not document the excluded publisher lease refs")
for workflow_path in sorted((repo / ".github/workflows").glob("*.yml")):
    trigger_prefix = workflow_path.read_text(encoding="utf-8").split("\npermissions:", 1)[0]
    if "\n  push:" in trigger_prefix:
        if 'tags: ["v*"]' not in trigger_prefix or "branches:" in trigger_prefix:
            raise AssertionError(f"{workflow_path.name} push filters admit publisher lease branches")


def fail(message):
    raise AssertionError(message)


with tempfile.TemporaryDirectory(prefix="mailstrix-publisher-lease-") as raw_root:
    root = Path(raw_root)
    project = root / "project"
    docker_dir = project / "docker"
    command_dir = root / "bin"
    release = root / "release"
    lease_remote = root / "lease.git"
    docker_dir.mkdir(parents=True)
    command_dir.mkdir()
    release.mkdir()
    shutil.copy2(repo / "docker/generate-rules.sh", docker_dir / "generate-rules.sh")
    publisher_source = (docker_dir / "generate-rules.sh").read_text(encoding="utf-8")
    lock_wait_formula = '''PUBLISH_LEASE_LOCAL_LOCK_WAIT_SECONDS=$((
    4 * PUBLISH_LEASE_GIT_TIMEOUT_SECONDS
    + PUBLISH_LEASE_CLOCK_TIMEOUT_SECONDS
    + PUBLISH_LEASE_LOCAL_LOCK_MARGIN_SECONDS
))'''
    for contract in (
        'PUBLISH_LEASE_REF="refs/heads/mailstrix-publisher-leases/${PUBLISH_LEASE_SCOPE}"',
        'PUBLISH_LEASE_REPO_IDENTITY="$(printf \'%s\' "$REPO" | LC_ALL=C tr \'[:upper:]\' \'[:lower:]\')"',
        'git init --bare --quiet --object-format=sha1 "$PUBLISH_LEASE_REPO"',
        'GIT_ASKPASS="$PUBLISH_LEASE_ASKPASS"',
        '*Username*) printf \'%s\\n\' x-access-token',
        'GH_TOKEN contents:write',
        lock_wait_formula,
        'exec {heartbeat_stop_fd}<"$PUBLISH_LEASE_STOP"',
        'exec {PUBLISH_LEASE_STOP_FD}>&-',
        '[ "$heartbeat_read_status" -gt 128 ] || break',
        'PUBLISH_LEASE_FOREGROUND_START="$(publisher_lease_process_start "$PUBLISH_LEASE_FOREGROUND_PID")"',
        '[ "$observed" = "$PUBLISH_LEASE_FOREGROUND_START" ]',
        'exec {PUBLISH_LEASE_ACTIVE_LOCK_FD}>&-',
    ):
        if contract not in publisher_source:
            fail(f"publisher branch-ref/token contract is missing: {contract}")
    publication_guards = (
        ("publisher lease was lost before release creation", 'gh release create "$TAG"'),
        ("publisher lease was lost before version reservation", 'gh release upload "$TAG" --repo "$REPO" --clobber "$VERSION_HIGH_WATER_RECOVERY_CANDIDATE"'),
        ("publisher lease was lost before canonical version reservation", 'gh release upload "$TAG" --repo "$REPO" --clobber "$VERSION_HIGH_WATER_CANDIDATE"'),
        ("publisher lease was lost before bundle upload", 'gh release upload "$TAG" --repo "$REPO" --clobber "$YAC"'),
        ("publisher lease was lost before marker upload", 'gh release upload "$TAG" --repo "$REPO" --clobber "$MARKER_FILE"'),
        ("publisher lease was lost before manifest signature upload", 'gh release upload "$TAG" --repo "$REPO" --clobber "$MANIFEST_SIG"'),
        ("publisher lease was lost before manifest activation", 'gh release upload "$TAG" --repo "$REPO" --clobber "$MANIFEST"'),
    )
    for guard, mutation in publication_guards:
        guard_at = publisher_source.find(guard)
        mutation_at = publisher_source.find(mutation, guard_at)
        if guard_at < 0 or mutation_at < 0 or guard_at > mutation_at:
            fail(f"release mutation lost its preceding ownership assertion: {mutation}")
    verifier_section = publisher_source.split(
        "# An independent download through the actual consumer", 1,
    )[1].split("# Prepare the success notification", 1)[0]
    if "publisher_lease_assert_owned" in verifier_section:
        fail("read-only post-publish verifier still depends on publisher lease I/O")
    (docker_dir / "Dockerfile").write_text("ARG YARA_VERSION=4.5.2\n", encoding="utf-8")
    subprocess.run(["git", "init", "--bare", "--quiet", lease_remote], check=True)

    stub = r"""#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

name = Path(sys.argv[0]).name
args = sys.argv[1:]
release = Path(os.environ["PUBLISH_TEST_RELEASE"])
events = Path(os.environ["PUBLISH_TEST_EVENTS"])
who = os.environ["PUBLISH_TEST_ID"]

def event(kind, **fields):
    with events.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"kind": kind, **fields}, sort_keys=True) + "\n")

if name == "curl":
    sys.stdin.read()
    if "-D" in args:
        failed_marker = events.with_suffix(events.suffix + ".failed-clock")
        if (os.environ.get("PUBLISH_TEST_FAIL_HEARTBEAT_CLOCK_ONCE") == "1"
                and (release / f"{who}.building").exists()
                and not failed_marker.exists()):
            failed_marker.touch()
            event("clock-failure")
            raise SystemExit(28)
        headers = Path(args[args.index("-D") + 1])
        server_date = os.environ.get("PUBLISH_TEST_SERVER_DATE", "Mon, 26 Oct 2026 12:00:00 GMT")
        headers.write_text(f"HTTP/2 200\r\ndate: {server_date}\r\n\r\n", encoding="ascii")
        print("200", end="")
    else:
        exists = os.environ.get("PUBLISH_TEST_RELEASE_EXISTS")
        if exists is None:
            exists = "1" if (release / "compiled.yac.manifest.json").is_file() else "0"
        print("200" if exists == "1" else "404", end="")
    raise SystemExit(0)

if name == "git":
    force = next((arg for arg in args if arg.startswith("--force-with-lease=")), "")
    building = (release / f"{who}.building").exists()
    if (os.environ.get("PUBLISH_TEST_LOSE_ACQUIRE_PUSH_RESPONSE_ONCE") == "1"
            and "push" in args and force.endswith(":")):
        failed_marker = events.with_suffix(events.suffix + ".acquire-push-response-loss")
        if not failed_marker.exists():
            failed_marker.touch()
            result = subprocess.run([os.environ["PUBLISH_TEST_REAL_GIT"], *args])
            if result.returncode != 0:
                raise SystemExit(result.returncode)
            event("acquire-push-response-loss")
            raise SystemExit(42)
    failure = None
    if (os.environ.get("PUBLISH_TEST_REJECT_ACQUIRE_PUSH_ONCE") == "1"
            and "push" in args and force.endswith(":")):
        failure = "acquire-push-rejection"
    elif (os.environ.get("PUBLISH_TEST_FAIL_HEARTBEAT_LS_REMOTE_ONCE") == "1"
            and building and "ls-remote" in args):
        failure = "heartbeat-ls-remote-failure"
    elif (os.environ.get("PUBLISH_TEST_FAIL_HEARTBEAT_PUSH_ONCE") == "1"
            and building and "push" in args and force and not force.endswith(":")):
        failure = "heartbeat-push-failure"
    elif (os.environ.get("PUBLISH_TEST_FAIL_LEASE_AFTER_MANIFEST") == "1"
            and (release / f"{who}.published.json").exists()
            and ("ls-remote" in args or "push" in args)):
        failure = "post-manifest-lease-failure"
    if failure is not None:
        failed_marker = events.with_suffix(events.suffix + f".{failure}")
        if not failed_marker.exists():
            failed_marker.touch()
            event(failure)
            raise SystemExit(42)
    if (os.environ.get("PUBLISH_TEST_OBSERVE_LEASE_CONTENTION") == "1"
            and "ls-remote" in args):
        result = subprocess.run(
            [os.environ["PUBLISH_TEST_REAL_GIT"], *args],
            text=True,
            stdout=subprocess.PIPE,
        )
        sys.stdout.write(result.stdout)
        if result.returncode == 0 and result.stdout.strip():
            (release / f"{who}.contending").touch()
            event("lease-contention-observed")
        raise SystemExit(result.returncode)
    os.execv(os.environ["PUBLISH_TEST_REAL_GIT"], [os.environ["PUBLISH_TEST_REAL_GIT"], *args])

if name == "go":
    output = Path(args[args.index("-o") + 1])
    event("go-build")
    output.write_text(r'''#!/usr/bin/env python3
import base64
import hashlib
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
manifest = Path(args[args.index("-manifest") + 1])
body = manifest.read_bytes()
if "-verify-signature" in args:
    signature = Path(args[args.index("-verify-signature") + 1]).read_bytes()
    if len(body) == 0 or len(body) > (64 << 10) or len(signature) == 0 or len(signature) > (1 << 10):
        raise SystemExit(2)
    expected = ("VALID:" + hashlib.sha256(body).hexdigest() + "\n").encode()
    raise SystemExit(0 if signature == expected else 2)
with open(os.environ["PUBLISH_TEST_EVENTS"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"kind": "sign"}, sort_keys=True) + "\n")
output = Path(args[args.index("-out") + 1])
output.write_text("VALID:" + hashlib.sha256(body).hexdigest() + "\n", encoding="ascii")
''', encoding="utf-8")
    output.chmod(0o755)
    raise SystemExit(0)

if name == "gh":
    if args[:2] == ["release", "view"]:
        for asset in sorted(item.name for item in release.iterdir() if item.is_file()):
            print(asset)
        event("release-view")
        raise SystemExit(0)
    if args[:2] == ["release", "download"]:
        destination = Path(args[args.index("--dir") + 1])
        assets = [args[index + 1] for index, arg in enumerate(args) if arg == "--pattern"]
        for asset in assets:
            fail_asset = os.environ.get("PUBLISH_TEST_FAIL_DOWNLOAD_ASSET_ONCE")
            failed_marker = events.with_suffix(events.suffix + ".failed-download")
            if asset == fail_asset and not failed_marker.exists():
                failed_marker.touch()
                event("download-failure", asset=asset)
                raise SystemExit(42)
            source = release / asset
            if not source.is_file():
                raise SystemExit(1)
            shutil.copy2(source, destination / asset)
        event("download", assets=assets)
        raise SystemExit(0)
    if args[:2] == ["release", "create"]:
        event("release-create")
        lost_marker = events.with_suffix(events.suffix + ".lost-release-create-response")
        if (os.environ.get("PUBLISH_TEST_LOSE_RELEASE_CREATE_RESPONSE_ONCE") == "1"
                and not lost_marker.exists()):
            lost_marker.touch()
            event("release-create-response-loss")
            raise SystemExit(42)
        raise SystemExit(0)
    if args[:2] == ["release", "upload"]:
        source = Path(args[-1])
        target = release / source.name
        block_asset = os.environ.get("PUBLISH_TEST_BLOCK_UPLOAD_ASSET")
        if source.name == block_asset:
            (release / f"{who}.uploading").touch()
            deadline = time.monotonic() + 30
            while not (release / f"{who}.resume").exists():
                if time.monotonic() > deadline:
                    raise SystemExit(97)
                time.sleep(0.02)
        fail_asset = os.environ.get("PUBLISH_TEST_FAIL_UPLOAD_ASSET_ONCE")
        failed_marker = events.with_suffix(events.suffix + ".failed-upload")
        if source.name == fail_asset and not failed_marker.exists():
            target.unlink(missing_ok=True)
            failed_marker.touch()
            event("upload-delete-failure", asset=source.name)
            raise SystemExit(42)
        lose_asset = os.environ.get("PUBLISH_TEST_LOSE_UPLOAD_RESPONSE_ASSET_ONCE")
        lost_marker = events.with_suffix(events.suffix + ".lost-upload-response")
        if source.name == lose_asset and not lost_marker.exists():
            shutil.copy2(source, target)
            lost_marker.touch()
            event("upload-response-loss", asset=source.name)
            raise SystemExit(42)
        shutil.copy2(source, target)
        event("upload", asset=source.name, sha256=hashlib.sha256(source.read_bytes()).hexdigest())
        if source.name == "compiled.yac.manifest.json":
            (release / f"{who}.published.json").write_bytes(source.read_bytes())
            if os.environ.get("PUBLISH_TEST_REMOVE_LEASE_AFTER_MANIFEST") == "1":
                refs = subprocess.check_output([
                    "git", f"--git-dir={os.environ['PUBLISH_LEASE_REMOTE']}",
                    "for-each-ref", "--format=%(refname)", "refs/heads/mailstrix-publisher-leases/",
                ], text=True).splitlines()
                for ref in refs:
                    subprocess.run([
                        "git", f"--git-dir={os.environ['PUBLISH_LEASE_REMOTE']}",
                        "update-ref", "-d", ref,
                    ], check=True)
                event("lease-removed-after-manifest")
        raise SystemExit(0)
    raise SystemExit(98)

if name == "docker":
    if args[:2] == ["buildx", "build"]:
        event("docker-build")
        if "--output" in args:
            destination = Path(args[args.index("--output") + 1].split("dest=", 1)[1])
            (destination / "compiled.yac").write_bytes(who.encode("ascii") * 4096)
            (destination / "libyara.version").write_text("4.5.2\n", encoding="ascii")
            if os.environ.get("PUBLISH_TEST_BLOCK_BUILD") == "1":
                (release / f"{who}.building").touch()
                deadline = time.monotonic() + 30
                while not (release / f"{who}.resume-build").exists():
                    if time.monotonic() > deadline:
                        raise SystemExit(97)
                    time.sleep(0.02)
            elif os.environ.get("PUBLISH_TEST_DELAY_BUILD") == "1":
                (release / f"{who}.building").touch()
                time.sleep(int(os.environ.get("PUBLISH_TEST_DELAY_SECONDS", "2")))
        if "--iidfile" in args:
            Path(args[args.index("--iidfile") + 1]).write_text("sha256:fixture\n", encoding="ascii")
            if os.environ.get("PUBLISH_TEST_LOSE_LEASE") == "1":
                refs = subprocess.check_output([
                    "git", f"--git-dir={os.environ['PUBLISH_LEASE_REMOTE']}",
                    "for-each-ref", "--format=%(refname)", "refs/heads/mailstrix-publisher-leases/",
                ], text=True).splitlines()
                for ref in refs:
                    subprocess.run(["git", f"--git-dir={os.environ['PUBLISH_LEASE_REMOTE']}", "update-ref", "-d", ref], check=True)
                event("lease-stolen")
        raise SystemExit(0)
    if args and args[0] == "run" and "check-rules" in args:
        print("check-rules: OK — 1 rules loaded (fingerprint fixture)")
        raise SystemExit(0)
    if args and args[0] == "run" and "-expected-version" in args:
        attempts_file = events.with_suffix(events.suffix + ".verify-attempts")
        attempts = int(attempts_file.read_text()) if attempts_file.exists() else 0
        attempts += 1
        attempts_file.write_text(str(attempts), encoding="ascii")
        expected = int(args[args.index("-expected-version") + 1])
        manifest = json.loads((release / "compiled.yac.manifest.json").read_text())
        bundle = (release / "compiled.yac").read_bytes()
        good = (
            manifest["version"] == expected
            and manifest["checksum"] == "sha256:" + hashlib.sha256(bundle).hexdigest()
            and manifest["size"] == len(bundle)
            and (release / "compiled.yac.manifest.json.sig").is_file()
        )
        if attempts <= int(os.environ.get("PUBLISH_TEST_FAIL_VERIFY_UNTIL", "0")):
            good = False
        event("verify", attempt=attempts, expected=expected, good=good)
        raise SystemExit(0 if good else 1)
    raise SystemExit(99)

raise SystemExit(100)
"""
    (command_dir / "stub.py").write_text(stub, encoding="utf-8")
    (command_dir / "stub.py").chmod(0o755)
    for command in ("curl", "docker", "gh", "go", "git"):
        (command_dir / command).symlink_to("stub.py")

    real_git = shutil.which("git")
    if real_git is None:
        fail("real git is unavailable")

    def sign(body):
        return b"VALID:" + hashlib.sha256(body).hexdigest().encode("ascii") + b"\n"

    def clear_release():
        for child in release.iterdir():
            if child.is_file():
                child.unlink()

    def set_previous(version, signature_mode="valid", manifest_bytes=None, marker=False):
        clear_release()
        bundle = (f"previous-{version}".encode("ascii") * 4096)
        (release / "compiled.yac").write_bytes(bundle)
        manifest = {
            "version": version,
            "checksum": "sha256:" + hashlib.sha256(bundle).hexdigest(),
            "size": len(bundle),
        }
        if marker:
            marker_body = (f"marker-{version}".encode("ascii") * 257)
            (release / "marker-tree.tar.gz").write_bytes(marker_body)
            manifest["marker"] = {
                "asset": "marker-tree.tar.gz",
                "sha256": hashlib.sha256(marker_body).hexdigest(),
                "size": len(marker_body),
            }
        body = manifest_bytes if manifest_bytes is not None else json.dumps(manifest, separators=(",", ":")).encode()
        (release / "compiled.yac.manifest.json").write_bytes(body)
        if signature_mode == "missing":
            return
        signature = sign(body)
        if signature_mode == "tampered":
            signature = sign(b'{"version":40}')
        elif signature_mode == "malformed":
            signature = b"not-a-signature\n"
        elif signature_mode == "untrusted":
            signature = b"VALID:" + b"0" * 64 + b"\n"
        elif signature_mode == "oversized":
            signature = b"A" * ((1 << 10) + 1)
        (release / "compiled.yac.manifest.json.sig").write_bytes(signature)

    def run_publisher(identifier, *, publisher=None, extra=None):
        events = root / f"{identifier}.events.jsonl"
        events.write_text("", encoding="utf-8")
        tmp = root / f"tmp-{identifier}"
        tmp.mkdir(exist_ok=True)
        env = os.environ.copy()
        env.update({
            "PATH": f"{command_dir}:/usr/bin:/bin",
            "GH_TOKEN": "inert-fixture",
            "MAILSTRIX_RULES_SIGNING_KEY": "inert-fixture",
            "MARKER_RELEASE_TAG": "off",
            "PUBLISH_LEASE_REMOTE": str(lease_remote),
            "PUBLISH_LEASE_HEARTBEAT_SECONDS": "10",
            "PUBLISH_LEASE_POLL_SECONDS": "1",
            "PUBLISH_LEASE_WAIT_SECONDS": "30",
            "PUBLISH_TEST_RELEASE": str(release),
            "PUBLISH_TEST_RELEASE_EXISTS": "1",
            "PUBLISH_TEST_EVENTS": str(events),
            "PUBLISH_TEST_ID": identifier,
            "PUBLISH_TEST_REAL_GIT": real_git,
            "TMPDIR": str(tmp),
        })
        if extra:
            env.update(extra)
        process = subprocess.Popen(
            ["bash", str(publisher or docker_dir / "generate-rules.sh")],
            cwd=project,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        return process, events

    def finish(started, timeout=40):
        process, events = started
        stdout, stderr = process.communicate(timeout=timeout)
        rows = [json.loads(line) for line in events.read_text(encoding="utf-8").splitlines()]
        return process.returncode, stdout, stderr, rows

    def assert_no_candidate_work(rows, name):
        forbidden = {"docker-build", "sign", "upload"}
        seen = {row["kind"] for row in rows}
        if seen & forbidden:
            fail(f"{name}: prior-state failure reached candidate work: {rows}")

    lease_scope = hashlib.sha256(b"myguard-labs/mailstrix\0rules-current").hexdigest()
    lease_ref_name = f"refs/heads/mailstrix-publisher-leases/{lease_scope}"

    def current_lease_oid():
        return subprocess.check_output(
            ["git", f"--git-dir={lease_remote}", "rev-parse", "--verify", "--quiet", lease_ref_name],
            text=True,
        ).strip()

    def seed_lease(owner, expires):
        tree = subprocess.check_output(
            ["git", f"--git-dir={lease_remote}", "mktree"], input="", text=True,
        ).strip()
        message = (
            "schema=mailstrix-publisher-lease-v1\n"
            f"owner={owner}\n"
            f"scope={lease_scope}\n"
            f"expires={expires:010d}\n"
        )
        identity = os.environ.copy()
        identity.update({
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@invalid",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@invalid",
        })
        oid = subprocess.check_output(
            ["git", f"--git-dir={lease_remote}", "commit-tree", tree],
            input=message,
            text=True,
            env=identity,
        ).strip()
        subprocess.run(
            ["git", f"--git-dir={lease_remote}", "update-ref", lease_ref_name, oid],
            check=True,
        )
        return oid

    # First publication has no prior pair and starts at one.
    print("PASS: CI excludes push triggers and publisher branch-ref/token assumptions are explicit")
    set_previous(1)
    (release / "compiled.yac.manifest.json").unlink()
    (release / "compiled.yac.manifest.json.sig").unlink()
    code, _, stderr, rows = finish(run_publisher("first", extra={"PUBLISH_TEST_RELEASE_EXISTS": "0"}))
    if code != 0 or json.loads((release / "first.published.json").read_text())["version"] != 1:
        fail(f"first publication failed: {code} {stderr} {rows}")
    print("PASS: first publication starts at version 1 under the shared lease")

    recovery_journal_assets = {
        "compiled.yac.recovery",
        "compiled.yac.manifest.json.recovery.sig",
        "compiled.yac.manifest.json.recovery",
        "marker-tree.tar.gz.recovery",
    }

    # GitHub can create the release while losing the response. The next run
    # sees an empty release and must resume the first publication at version 1.
    clear_release()
    code, _, _, rows = finish(run_publisher(
        "initial-create-response-lost",
        extra={
            "PUBLISH_TEST_RELEASE_EXISTS": "0",
            "PUBLISH_TEST_LOSE_RELEASE_CREATE_RESPONSE_ONCE": "1",
        },
    ))
    if code == 0 or sum(row["kind"] == "release-create-response-loss" for row in rows) != 1:
        fail(f"initial release create response loss was not exercised: {rows}")
    if any(row["kind"] == "upload" for row in rows) or any(release.iterdir()):
        fail(f"failed initial release creation mutated release assets: {rows}")
    code, _, stderr, rows = finish(run_publisher(
        "initial-create-restart",
        extra={"PUBLISH_TEST_RELEASE_EXISTS": "1"},
    ))
    if (code != 0
            or json.loads((release / "initial-create-restart.published.json").read_text())["version"] != 1
            or any(row["kind"] == "release-create" for row in rows)):
        fail(f"empty existing release did not resume at version 1: {stderr} {rows}")
    print("PASS: lost initial release-create response restarts from an empty release at version 1")

    # Failure before the first reservation is durable also leaves an empty
    # release. With no prior journal, restart still begins at version 1.
    clear_release()
    code, _, _, rows = finish(run_publisher(
        "initial-recovery-reservation-failed",
        extra={
            "PUBLISH_TEST_RELEASE_EXISTS": "0",
            "PUBLISH_TEST_FAIL_UPLOAD_ASSET_ONCE": "compiled.yac.version-high-water.recovery.json",
        },
    ))
    if code == 0 or any(release.iterdir()) or recovery_journal_assets & {item.name for item in release.iterdir()}:
        fail(f"failed first recovery reservation did not leave an empty release: {rows}")
    code, _, stderr, rows = finish(run_publisher(
        "initial-recovery-reservation-restart",
        extra={"PUBLISH_TEST_RELEASE_EXISTS": "1"},
    ))
    if code != 0 or json.loads((release / "initial-recovery-reservation-restart.published.json").read_text())["version"] != 1:
        fail(f"restart after failed first reservation did not publish version 1: {stderr} {rows}")

    # If the recovery reservation succeeded but the canonical reservation did
    # not, the authenticated maximum survives. Restart must skip the reserved
    # version even though no canonical manifest or recovery journal exists.
    clear_release()
    code, _, _, rows = finish(run_publisher(
        "initial-canonical-reservation-failed",
        extra={
            "PUBLISH_TEST_RELEASE_EXISTS": "0",
            "PUBLISH_TEST_FAIL_UPLOAD_ASSET_ONCE": "compiled.yac.version-high-water.json",
        },
    ))
    assets = {item.name for item in release.iterdir() if item.is_file()}
    if (code == 0
            or "compiled.yac.version-high-water.recovery.json" not in assets
            or "compiled.yac.version-high-water.json" in assets
            or recovery_journal_assets & assets):
        fail(f"failed canonical first reservation did not preserve only its authenticated maximum: {rows} {assets}")
    code, _, stderr, rows = finish(run_publisher(
        "initial-canonical-reservation-restart",
        extra={"PUBLISH_TEST_RELEASE_EXISTS": "1"},
    ))
    if code != 0 or json.loads((release / "initial-canonical-reservation-restart.published.json").read_text())["version"] != 2:
        fail(f"restart after partial first reservation reused version 1: {stderr} {rows}")
    print("PASS: initial reservation failures restart without a journal and never reuse a durable reservation")

    # Canonical decimal timing values at both sides of every public bound remain
    # accepted. No value reaches Bash arithmetic until its lexical form is safe.
    timing_boundaries = (
        ("timing-lower-bounds", {
            "PUBLISH_LEASE_TTL_SECONDS": "300",
            "PUBLISH_LEASE_HEARTBEAT_SECONDS": "299",
            "PUBLISH_LEASE_POLL_SECONDS": "1",
            "PUBLISH_LEASE_WAIT_SECONDS": "86400",
        }),
        ("timing-upper-bounds", {
            "PUBLISH_LEASE_TTL_SECONDS": "86400",
            "PUBLISH_LEASE_HEARTBEAT_SECONDS": "10",
            "PUBLISH_LEASE_POLL_SECONDS": "60",
            "PUBLISH_LEASE_WAIT_SECONDS": "0",
        }),
    )
    for name, timing in timing_boundaries:
        set_previous(4)
        code, _, stderr, rows = finish(run_publisher(name, extra=timing))
        if code != 0 or json.loads((release / f"{name}.published.json").read_text())["version"] != 5:
            fail(f"{name}: canonical boundary timing was rejected: {stderr} {rows}")
    print("PASS: canonical decimal lease timing accepts lower and upper boundaries")

    # Leading zeros and over-wide values are rejected lexically, before Bash can
    # interpret them as octal or overflow, and before any candidate work.
    timing_errors = (
        ("timing-zero-ttl", {"PUBLISH_LEASE_TTL_SECONDS": "0308"}),
        ("timing-zero-heartbeat", {"PUBLISH_LEASE_HEARTBEAT_SECONDS": "010"}),
        ("timing-zero-poll", {"PUBLISH_LEASE_POLL_SECONDS": "01"}),
        ("timing-zero-wait", {"PUBLISH_LEASE_WAIT_SECONDS": "00"}),
        ("timing-wide", {"PUBLISH_LEASE_TTL_SECONDS": "123456"}),
    )
    for name, timing in timing_errors:
        set_previous(4)
        code, _, stderr, rows = finish(run_publisher(name, extra=timing))
        if code == 0 or "canonical decimal integers of at most five digits" not in stderr:
            fail(f"{name}: unsafe timing spelling was not rejected lexically: {stderr} {rows}")
        assert_no_candidate_work(rows, name)
    print("PASS: zero-padded and over-wide lease timing fails before arithmetic or candidate work")

    # A denied/unavailable create push that leaves the mutex ref absent is not a
    # contention race. It must fail closed after one rejection, without a hot
    # loop or candidate work.
    set_previous(4)
    code, _, stderr, rows = finish(run_publisher(
        "acquire-push-rejected",
        extra={"PUBLISH_TEST_REJECT_ACQUIRE_PUSH_ONCE": "1"},
    ))
    if code == 0 or sum(row["kind"] == "acquire-push-rejection" for row in rows) != 1:
        fail(f"absent-ref acquire rejection did not fail closed once: {stderr} {rows}")
    assert_no_candidate_work(rows, "acquire-push-rejected")
    print("PASS: absent-ref acquire push rejection fails closed without spinning")

    # The create push may succeed server-side while its response is lost. The
    # exact locally-created OID observed remotely proves ownership and must be
    # adopted; cleanup then removes it rather than leaving an orphan mutex.
    set_previous(4)
    code, _, stderr, rows = finish(run_publisher(
        "acquire-push-response-lost",
        extra={"PUBLISH_TEST_LOSE_ACQUIRE_PUSH_RESPONSE_ONCE": "1"},
    ))
    remaining_refs = subprocess.check_output([
        "git", f"--git-dir={lease_remote}", "for-each-ref", "--format=%(refname)",
        "refs/heads/mailstrix-publisher-leases/",
    ], text=True).splitlines()
    if (code != 0
            or json.loads((release / "acquire-push-response-lost.published.json").read_text())["version"] != 5
            or sum(row["kind"] == "acquire-push-response-loss" for row in rows) != 1
            or remaining_refs):
        fail(f"lost successful acquire response was not adopted and released: {stderr} {rows} {remaining_refs}")
    print("PASS: an exact own OID adopts a successful acquire whose response was lost")

    # The isolated lease repository is always SHA-1 because GitHub refs expose
    # 40-hex object IDs. Inherited process defaults must not silently create a
    # SHA-256 lease object that the authoritative remote cannot accept.
    set_previous(4)
    sha1_run = run_publisher("sha1-forced", extra={
        "GIT_DEFAULT_HASH": "sha256",
        "PUBLISH_TEST_BLOCK_BUILD": "1",
    })
    deadline = time.monotonic() + 15
    while not (release / "sha1-forced.building").exists():
        if time.monotonic() > deadline:
            fail("forced-SHA-1 fixture never reached its build barrier")
        time.sleep(0.02)
    lease_oid = current_lease_oid()
    if len(lease_oid) != 40 or any(character not in "0123456789abcdef" for character in lease_oid):
        fail(f"inherited GIT_DEFAULT_HASH changed the lease object format: {lease_oid!r}")
    (release / "sha1-forced.resume-build").touch()
    code, _, stderr, rows = finish(sha1_run)
    if code != 0 or json.loads((release / "sha1-forced.published.json").read_text())["version"] != 5:
        fail(f"forced SHA-1 lease publication failed: {stderr} {rows}")
    print("PASS: inherited GIT_DEFAULT_HASH=sha256 still produces an exact 40-hex lease OID")

    # A valid exact-byte pair advances once; MaxInt-1 advances to MaxInt.
    for name, previous, expected in (("valid", 41, 42), ("max-minus-one", maximum - 1, maximum)):
        set_previous(previous)
        code, _, stderr, rows = finish(run_publisher(name))
        published = json.loads((release / f"{name}.published.json").read_text()) if code == 0 else None
        if code != 0 or published["version"] != expected:
            fail(f"{name}: {code} {stderr} {rows}")
    print("PASS: authenticated prior state advances exactly once through MaxInt-1")

    max_envelope = json.loads((release / "compiled.yac.version-high-water.json").read_text())
    max_record = json.loads(base64.b64decode(max_envelope["record"]))
    if max_record.get("version") != str(maximum):
        fail(f"installed jq did not preserve MaxInt as an exact decimal string: {max_record}")
    print("PASS: installed jq encodes MaxInt high-water as an exact decimal string")

    # The successful MaxInt activation above left a complete MaxInt-1 journal.
    # Exhaustion is authenticated state, not partial damage: a restart must not
    # restore that journal and publish different bytes under MaxInt again.
    code, _, _, rows = finish(run_publisher("max-exhausted-restart"))
    if code == 0 or any(row["kind"] == "upload" for row in rows):
        fail(f"MaxInt exhaustion restored or republished the prior journal: {rows}")
    print("PASS: authenticated MaxInt exhaustion refuses journal recovery and version reuse")

    # Damage after reserving/activating MaxInt must still restore the intact
    # MaxInt-1 journal. Restoration does not require allocating MaxInt+1; only
    # after exact canonical repair does the run stop because the range is spent.
    max_journal_hashes = {
        "compiled.yac": hashlib.sha256((release / "compiled.yac.recovery").read_bytes()).hexdigest(),
        "compiled.yac.manifest.json.sig": hashlib.sha256((release / "compiled.yac.manifest.json.recovery.sig").read_bytes()).hexdigest(),
        "compiled.yac.manifest.json": hashlib.sha256((release / "compiled.yac.manifest.json.recovery").read_bytes()).hexdigest(),
    }
    (release / "compiled.yac.manifest.json").unlink()
    code, _, stderr, rows = finish(run_publisher("max-damaged-restart"))
    restored_hashes = {
        asset: hashlib.sha256((release / asset).read_bytes()).hexdigest()
        for asset in max_journal_hashes
    }
    restored_manifest = json.loads((release / "compiled.yac.manifest.json").read_text())
    if (code == 0 or restored_hashes != max_journal_hashes
            or restored_manifest["version"] != maximum - 1
            or any(row["kind"] == "docker-build" for row in rows)
            or "prior canonical state was restored" not in stderr):
        fail(f"MaxInt damage was not restored before exhaustion: {stderr} {rows}")
    print("PASS: damaged MaxInt publication restores the exact prior journal, then fails exhausted")

    # Once version 42 has activated, a transient failure downloading its
    # complete canonical state must not restore the old version-41 journal and
    # publish different bytes under version 42 again.
    set_previous(41)
    code, _, stderr, rows = finish(run_publisher("activated-42"))
    if code != 0:
        fail(f"activated-42 setup failed: {stderr} {rows}")
    code, _, _, rows = finish(run_publisher(
        "transient-after-activation",
        extra={"PUBLISH_TEST_FAIL_DOWNLOAD_ASSET_ONCE": "compiled.yac.manifest.json"},
    ))
    if code == 0 or any(row["kind"] == "upload" for row in rows):
        fail(f"transient canonical download rewound an activated version: {rows}")
    print("PASS: transient canonical download failure cannot restore or reuse an activated version")

    # Release-asset write authority cannot forge a higher reservation: the
    # envelope record is independently authenticated by the client-pinned key.
    high_water_path = release / "compiled.yac.version-high-water.json"
    high_water_original = high_water_path.read_bytes()
    high_water_envelope = json.loads(high_water_original)
    high_water_record = json.loads(base64.b64decode(high_water_envelope["record"]))
    high_water_record["version"] = str(int(high_water_record["version"]) + 1)
    high_water_envelope["record"] = base64.b64encode(
        json.dumps(high_water_record, separators=(",", ":")).encode()
    ).decode("ascii")
    high_water_path.write_text(json.dumps(high_water_envelope, separators=(",", ":")) + "\n")
    code, _, _, rows = finish(run_publisher("tampered-high-water"))
    if code == 0 or any(row["kind"] == "upload" for row in rows):
        fail(f"tampered version high-water reached publication: {rows}")
    high_water_path.write_bytes(high_water_original)
    print("PASS: tampered version high-water is rejected before recovery or publication")

    # Both slots are equal before advancing. A canonical reservation failure
    # leaves the recovery maximum; repair of the missing slot is itself safe
    # across a lost response, and the following run skips both reserved values.
    set_previous(41)
    code, _, stderr, rows = finish(run_publisher("high-water-response-setup"))
    if code != 0:
        fail(f"high-water response-loss setup failed: {stderr} {rows}")
    code, _, _, rows = finish(run_publisher(
        "high-water-response-delete",
        extra={"PUBLISH_TEST_FAIL_UPLOAD_ASSET_ONCE": "compiled.yac.version-high-water.json"},
    ))
    if (code == 0
            or not any(row["kind"] == "upload" and row["asset"] == "compiled.yac.version-high-water.recovery.json" for row in rows)
            or not any(row["kind"] == "upload-delete-failure" and row["asset"] == "compiled.yac.version-high-water.json" for row in rows)):
        fail(f"canonical high-water clobber failure was not exercised after recovery reservation: {rows}")
    code, _, _, rows = finish(run_publisher(
        "high-water-repair-response-lost",
        extra={"PUBLISH_TEST_LOSE_UPLOAD_RESPONSE_ASSET_ONCE": "compiled.yac.version-high-water.json"},
    ))
    if code == 0 or not any(row["kind"] == "upload-response-loss" for row in rows):
        fail(f"high-water repair response loss was not exercised: {rows}")
    code, _, stderr, rows = finish(run_publisher("high-water-response-restart"))
    if (code != 0
            or json.loads((release / "high-water-response-restart.published.json").read_text())["version"] != 44):
        fail(f"response-loss restart reused a reserved version: {stderr} {rows}")
    print("PASS: lost repair response preserves the authenticated maximum and skips reserved versions")

    # Repeated alternating delete-before-upload failures cannot walk across and
    # erase both slots: every run repairs the sole maximum before advancing.
    set_previous(41)
    code, _, stderr, rows = finish(run_publisher("high-water-consecutive-setup"))
    if code != 0:
        fail(f"high-water consecutive setup failed: {stderr} {rows}")
    for name, asset in (
        ("high-water-consecutive-canonical", "compiled.yac.version-high-water.json"),
        ("high-water-consecutive-repair", "compiled.yac.version-high-water.json"),
        ("high-water-consecutive-recovery", "compiled.yac.version-high-water.recovery.json"),
    ):
        code, _, _, rows = finish(run_publisher(
            name,
            extra={"PUBLISH_TEST_FAIL_UPLOAD_ASSET_ONCE": asset},
        ))
        if code == 0 or not any(row["kind"] == "upload-delete-failure" and row["asset"] == asset for row in rows):
            fail(f"{name}: consecutive clobber failure was not exercised: {rows}")
    code, _, stderr, rows = finish(run_publisher("high-water-consecutive-restart"))
    if (code != 0
            or json.loads((release / "high-water-consecutive-restart.published.json").read_text())["version"] != 44):
        fail(f"consecutive clobber failures erased the maximum or reused version 43: {stderr} {rows}")
    print("PASS: alternating consecutive clobber failures retain one maximum and restart at version 44")

    # `gh release upload --clobber` deletes the old asset before uploading the
    # replacement. A restart must restore the exact signed prior bundle/pair
    # from the remote journal before it derives or publishes the replacement.
    for asset, name in (
        ("compiled.yac.manifest.json.sig", "signature-delete"),
        ("compiled.yac.manifest.json", "manifest-delete"),
    ):
        with_marker = name == "manifest-delete"
        set_previous(41, marker=with_marker)
        previous_assets = ["compiled.yac"]
        if with_marker:
            previous_assets.append("marker-tree.tar.gz")
        previous_assets.extend(["compiled.yac.manifest.json.sig", "compiled.yac.manifest.json"])
        old_hashes = {
            item: hashlib.sha256((release / item).read_bytes()).hexdigest()
            for item in previous_assets
        }
        code, _, _, rows = finish(run_publisher(
            f"{name}-fail",
            extra={"PUBLISH_TEST_FAIL_UPLOAD_ASSET_ONCE": asset},
        ))
        if code == 0 or not any(row["kind"] == "upload-delete-failure" and row["asset"] == asset for row in rows):
            fail(f"{name}: delete-before-upload failure was not exercised: {rows}")
        code, _, stderr, rows = finish(run_publisher(f"{name}-restart"))
        if code != 0:
            fail(f"{name}: restart did not recover and republish: {stderr} {rows}")
        build_index = next(index for index, row in enumerate(rows) if row["kind"] == "docker-build")
        canonical_before_build = [
            row for row in rows[:build_index]
            if row["kind"] == "upload" and row["asset"] in old_hashes
        ]
        if [row["asset"] for row in canonical_before_build] != previous_assets \
                or any(row["sha256"] != old_hashes[row["asset"]] for row in canonical_before_build):
            fail(f"{name}: restart did not restore the exact prior authenticated state first: {rows}")
        if json.loads((release / f"{name}-restart.published.json").read_text())["version"] != 43:
            fail(f"{name}: restart reused reserved version 42 instead of advancing to 43")
    print("PASS: true partial canonical damage restores exact prior state without reusing its reserved version")

    # A long transaction renews the same remote lease instead of silently
    # degrading to a one-shot lock that can expire during a build.
    set_previous(5)
    heartbeat = run_publisher(
        "heartbeat",
        extra={"PUBLISH_TEST_DELAY_BUILD": "1", "PUBLISH_TEST_DELAY_SECONDS": "12"},
    )
    deadline = time.monotonic() + 15
    while not (release / "heartbeat.building").exists():
        if time.monotonic() > deadline:
            fail("heartbeat fixture never reached build")
        time.sleep(0.02)
    lease_ref = subprocess.check_output(
        ["git", f"--git-dir={lease_remote}", "for-each-ref", "--format=%(objectname)", "refs/heads/mailstrix-publisher-leases/"],
        text=True,
    ).strip()
    time.sleep(10.5)
    renewed_ref = subprocess.check_output(
        ["git", f"--git-dir={lease_remote}", "for-each-ref", "--format=%(objectname)", "refs/heads/mailstrix-publisher-leases/"],
        text=True,
    ).strip()
    code, _, stderr, rows = finish(heartbeat)
    if not lease_ref or renewed_ref == lease_ref or code != 0:
        fail(f"lease heartbeat did not renew safely: {lease_ref}/{renewed_ref} {code} {stderr} {rows}")
    print("PASS: active publication renews its authoritative lease")

    # The heartbeat owns only a read descriptor. If SIGKILL removes the sole
    # foreground writer, FIFO EOF identifies that exact process lifetime and
    # stops renewal without a PID lookup that could alias a reused process.
    heartbeat_started = "PUBLISH_LEASE_HEARTBEAT_PID=$!\n"
    foreground_pause = '''PUBLISH_LEASE_HEARTBEAT_PID=$!
if [ "${PUBLISH_TEST_PAUSE_FOREGROUND_AFTER_HEARTBEAT:-0}" -eq 1 ]; then
    : >"${PUBLISH_TEST_RELEASE}/${PUBLISH_TEST_ID}.foreground-paused"
    while [ ! -e "${PUBLISH_TEST_RELEASE}/${PUBLISH_TEST_ID}.resume-foreground" ]; do
        publisher_lease_sleep
    done
fi
'''
    if publisher_source.count(heartbeat_started) != 1:
        fail("foreground-liveness fixture did not identify the heartbeat start")
    liveness_source = publisher_source.replace(heartbeat_started, foreground_pause)
    liveness_publisher = root / "generate-rules-foreground-liveness.sh"
    liveness_publisher.write_text(liveness_source, encoding="utf-8")

    set_previous(5)
    killed_foreground = run_publisher(
        "foreground-killed",
        publisher=liveness_publisher,
        extra={"PUBLISH_TEST_PAUSE_FOREGROUND_AFTER_HEARTBEAT": "1"},
    )
    deadline = time.monotonic() + 15
    while not (release / "foreground-killed.foreground-paused").exists():
        if time.monotonic() > deadline:
            fail("foreground-liveness fixture never paused after heartbeat start")
        time.sleep(0.02)
    killed_oid = current_lease_oid()
    os.kill(killed_foreground[0].pid, signal.SIGKILL)
    killed_code, _, _, _ = finish(killed_foreground, timeout=5)
    time.sleep(10.5)
    if killed_code != -signal.SIGKILL or current_lease_oid() != killed_oid:
        fail("heartbeat renewed after its exact foreground FIFO writer disappeared")
    subprocess.run(
        ["git", f"--git-dir={lease_remote}", "update-ref", "-d", lease_ref_name],
        check=True,
    )
    print("PASS: foreground SIGKILL closes the sole FIFO writer and stops heartbeat renewal")

    # Named repair-removal control: retain the inherited read/write descriptor,
    # read from it, and remove both exact-process checks. The orphan no longer
    # observes EOF or foreground death and renews after its publisher has died.
    child_fd_setup = '''    exec {heartbeat_stop_fd}<"$PUBLISH_LEASE_STOP" || exit 1
    exec {PUBLISH_LEASE_STOP_FD}>&-
'''
    inherited_fd_setup = '    exec {heartbeat_stop_fd}<"$PUBLISH_LEASE_STOP" || exit 1\n'
    heartbeat_read_fd = '-u "$heartbeat_stop_fd"'
    foreground_checks = (
        "        publisher_lease_foreground_alive || break\n",
        "            publisher_lease_foreground_alive || exit 0\n",
    )
    if (liveness_source.count(child_fd_setup) != 1
            or liveness_source.count(heartbeat_read_fd) != 1
            or any(liveness_source.count(check) != 1 for check in foreground_checks)):
        fail("orphan-heartbeat mutation did not identify the descriptor ownership points")
    orphan_source = liveness_source.replace(child_fd_setup, inherited_fd_setup)
    orphan_source = orphan_source.replace(heartbeat_read_fd, '-u "$PUBLISH_LEASE_STOP_FD"')
    for check in foreground_checks:
        orphan_source = orphan_source.replace(check, "")
    orphan_mutant = root / "generate-rules-orphan-heartbeat.sh"
    orphan_mutant.write_text(orphan_source, encoding="utf-8")
    set_previous(5)
    orphan = run_publisher(
        "orphan-mutant",
        publisher=orphan_mutant,
        extra={"PUBLISH_TEST_PAUSE_FOREGROUND_AFTER_HEARTBEAT": "1"},
    )
    deadline = time.monotonic() + 15
    while not (release / "orphan-mutant.foreground-paused").exists():
        if time.monotonic() > deadline:
            fail("orphan-heartbeat mutant never paused after heartbeat start")
        time.sleep(0.02)
    orphan_oid = current_lease_oid()
    os.kill(orphan[0].pid, signal.SIGKILL)
    renewed_orphan = ""
    deadline = time.monotonic() + 15
    while time.monotonic() <= deadline:
        observed = current_lease_oid()
        if observed != orphan_oid:
            renewed_orphan = observed
            break
        time.sleep(0.1)
    try:
        os.killpg(orphan[0].pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finish(orphan, timeout=5)
    subprocess.run(
        ["git", f"--git-dir={lease_remote}", "update-ref", "-d", lease_ref_name],
        check=True,
    )
    if not renewed_orphan:
        fail("inherited read/write descriptor mutant did not reproduce orphan renewal")
    print("PASS: heartbeat_liveness_removal observed RED (orphan renewed after foreground SIGKILL)")

    # TERM while the foreground owns the process-local flock enters EXIT cleanup
    # before Bash closes that function descriptor. The repaired cleanup releases
    # it first, stops the heartbeat, exact-OID deletes the remote ref, and returns
    # the conventional signal exit without waiting on its own lock.
    lock_acquired = '''    if "$operation"; then
'''
    lock_pause = '''    if [ "$foreground_lock" -eq 1 ] \
            && [ "${PUBLISH_TEST_PAUSE_WITH_FOREGROUND_LOCK:-0}" -eq 1 ] \
            && [ ! -e "${PUBLISH_TEST_RELEASE}/${PUBLISH_TEST_ID}.foreground-lock-held" ]; then
        printf '%s\n' "$PUBLISH_LEASE_ACTIVE_LOCK_FD" \
            >"${PUBLISH_TEST_RELEASE}/${PUBLISH_TEST_ID}.foreground-lock-held"
        while [ ! -e "${PUBLISH_TEST_RELEASE}/${PUBLISH_TEST_ID}.resume-foreground-lock" ]; do
            publisher_lease_sleep
        done
    fi
    if "$operation"; then
'''
    if publisher_source.count(lock_acquired) != 1:
        fail("foreground-lock signal hook did not identify one operation boundary")
    signal_lock_source = publisher_source.replace(lock_acquired, lock_pause)
    signal_lock_publisher = root / "generate-rules-signal-with-lock.sh"
    signal_lock_publisher.write_text(signal_lock_source, encoding="utf-8")

    set_previous(6)
    signalled = run_publisher(
        "signal-with-lock",
        publisher=signal_lock_publisher,
        extra={"PUBLISH_TEST_PAUSE_WITH_FOREGROUND_LOCK": "1"},
    )
    deadline = time.monotonic() + 15
    while not (release / "signal-with-lock.foreground-lock-held").exists():
        if time.monotonic() > deadline:
            fail("signal-with-lock fixture never acquired the foreground flock")
        time.sleep(0.02)
    tracked_fd = (release / "signal-with-lock.foreground-lock-held").read_text().strip()
    if not tracked_fd.isdecimal():
        fail(f"foreground flock was not tracked for cleanup: {tracked_fd!r}")
    signal_oid = current_lease_oid()
    signalled[0].send_signal(signal.SIGTERM)
    try:
        code, _, stderr, rows = finish(signalled, timeout=15)
    except subprocess.TimeoutExpired:
        status = signalled[0].poll()
        os.killpg(signalled[0].pid, signal.SIGKILL)
        finish(signalled, timeout=5)
        fail(f"signal-under-lock cleanup timed out with foreground status {status} and tracked fd {tracked_fd}")
    remaining_refs = subprocess.check_output([
        "git", f"--git-dir={lease_remote}", "for-each-ref", "--format=%(refname)",
        "refs/heads/mailstrix-publisher-leases/",
    ], text=True).splitlines()
    if code != 143 or remaining_refs or (release / "signal-with-lock.published.json").exists():
        fail(f"signal under foreground lock did not exit 143 and exact-OID release {signal_oid}: {code} {stderr} {rows} {remaining_refs}")
    print("PASS: TERM under foreground flock exits 143 promptly and exact-OID releases the mutex")

    # Named repair-removal control: remove only the cleanup-time descriptor
    # release. EXIT then remains alive waiting on the flock still held by the
    # interrupted foreground function until the fixture kills the process group.
    close_lock_block = '''    if [ -n "$PUBLISH_LEASE_ACTIVE_LOCK_FD" ]; then
        flock -u "$PUBLISH_LEASE_ACTIVE_LOCK_FD" 2>/dev/null || true
        exec {PUBLISH_LEASE_ACTIVE_LOCK_FD}>&- || true
        PUBLISH_LEASE_ACTIVE_LOCK_FD=""
    fi
'''
    if signal_lock_source.count(close_lock_block) != 1:
        fail("cleanup-lock release mutation did not identify one block")
    signal_lock_mutant = root / "generate-rules-no-cleanup-lock-release.sh"
    signal_lock_mutant.write_text(
        signal_lock_source.replace(close_lock_block, "    : # cleanup-lock-release-removal mutant\n"),
        encoding="utf-8",
    )
    set_previous(6)
    stuck = run_publisher(
        "signal-lock-mutant",
        publisher=signal_lock_mutant,
        extra={"PUBLISH_TEST_PAUSE_WITH_FOREGROUND_LOCK": "1"},
    )
    deadline = time.monotonic() + 15
    while not (release / "signal-lock-mutant.foreground-lock-held").exists():
        if time.monotonic() > deadline:
            fail("cleanup-lock removal fixture never acquired the foreground flock")
        time.sleep(0.02)
    stuck_oid = current_lease_oid()
    stuck[0].send_signal(signal.SIGTERM)
    time.sleep(3)
    if stuck[0].poll() is not None:
        fail("cleanup-lock release removal did not reproduce the self-lock wait")
    os.killpg(stuck[0].pid, signal.SIGKILL)
    finish(stuck, timeout=5)
    if current_lease_oid() != stuck_oid:
        fail("cleanup-lock removal unexpectedly released its stranded mutex")
    subprocess.run(
        ["git", f"--git-dir={lease_remote}", "update-ref", "-d", lease_ref_name, stuck_oid],
        check=True,
    )
    print("PASS: cleanup_lock_release_removal observed RED (EXIT waited on its own flock)")

    # Force the exact renewal interleaving that previously produced a false
    # ownership loss: the heartbeat has moved the remote ref but has not yet
    # replaced the foreground process's local OID. The foreground assertion
    # must wait for that atomic group to finish, then accept the renewed OID.
    renewal_write = '''        publisher_lease_write_state "$new" "$expires" "$now"
        return
'''
    renewal_pause = '''        if [ "${PUBLISH_TEST_PAUSE_RENEWAL_BEFORE_STATE:-0}" -eq 1 ]; then
            : >"${PUBLISH_TEST_RELEASE}/${PUBLISH_TEST_ID}.renewed-before-state"
            while [ ! -e "${PUBLISH_TEST_RELEASE}/${PUBLISH_TEST_ID}.resume-renewal-state" ]; do
                publisher_lease_sleep
            done
        fi
        publisher_lease_write_state "$new" "$expires" "$now"
        return
'''
    if publisher_source.count(renewal_write) != 1:
        fail("renewal interleaving hook did not identify one state transition")
    renewal_source = publisher_source.replace(renewal_write, renewal_pause)
    renewal_publisher = root / "generate-rules-renewal-interleaving.sh"
    renewal_publisher.write_text(renewal_source, encoding="utf-8")

    set_previous(8)
    renewal = run_publisher("renewal-race", publisher=renewal_publisher, extra={
        "PUBLISH_TEST_DELAY_BUILD": "1",
        "PUBLISH_TEST_DELAY_SECONDS": "12",
        "PUBLISH_TEST_PAUSE_RENEWAL_BEFORE_STATE": "1",
    })
    deadline = time.monotonic() + 20
    while not (release / "renewal-race.renewed-before-state").exists():
        if time.monotonic() > deadline:
            fail("renewal race fixture never paused between remote CAS and local state replacement")
        time.sleep(0.02)
    time.sleep(3)
    if renewal[0].poll() is not None or (release / "renewal-race.published.json").exists():
        fail("foreground publisher did not wait for the renewal state transition")
    (release / "renewal-race.resume-renewal-state").touch()
    code, _, stderr, rows = finish(renewal)
    published = json.loads((release / "renewal-race.published.json").read_text()) if code == 0 else None
    if code != 0 or published["version"] != 9:
        fail(f"coherent renewal interleaving did not publish: {code} {stderr} {rows}")
    print("PASS: ownership assertion waits for remote renewal and local OID replacement as one transition")

    # Named repair-removal control: bypass only the assertion-side local lock.
    # It then reads the old state while the paused heartbeat has already moved
    # the remote ref and reproduces the false ownership-loss verdict.
    assertion_lock = "    publisher_lease_with_local_lock publisher_lease_assert_owned_locked 1\n"
    if renewal_source.count(assertion_lock) != 1:
        fail("renewal assertion-lock mutation did not identify one wrapper")
    renewal_mutant = root / "generate-rules-renewal-assertion-unlocked.sh"
    renewal_mutant.write_text(
        renewal_source.replace(assertion_lock, "    publisher_lease_assert_owned_locked\n"),
        encoding="utf-8",
    )
    set_previous(8)
    mutant = run_publisher("renewal-unlocked", publisher=renewal_mutant, extra={
        "PUBLISH_TEST_DELAY_BUILD": "1",
        "PUBLISH_TEST_DELAY_SECONDS": "12",
        "PUBLISH_TEST_PAUSE_RENEWAL_BEFORE_STATE": "1",
    })
    deadline = time.monotonic() + 20
    while not (release / "renewal-unlocked.renewed-before-state").exists():
        if time.monotonic() > deadline:
            fail("renewal lock-removal fixture never reached the forced interleaving")
        time.sleep(0.02)
    # Reconciliation adds bounded pre-build work before the delayed build. Keep
    # the transition paused long enough for the unlocked foreground assertion
    # to reach and observe the deliberately incoherent state.
    time.sleep(6)
    (release / "renewal-unlocked.resume-renewal-state").touch()
    code, _, stderr, rows = finish(mutant)
    if (code == 0 or (release / "renewal-unlocked.published.json").exists()
            or "publisher lease was lost before version reservation" not in stderr):
        fail(f"assertion-lock removal did not reproduce false ownership loss: {code} {stderr} {rows}")
    print("PASS: renewal_assertion_lock_removal observed RED (old local OID mismatched renewed remote OID)")

    # A lock wait shorter than the bounded renewal critical section has the
    # same externally visible failure. Scale the production budget down to one
    # second while retaining the forced three-second interleaving.
    if renewal_source.count(lock_wait_formula) != 1:
        fail("short-lock-wait mutation did not identify the derived wait budget")
    short_wait_mutant = root / "generate-rules-short-local-lock-wait.sh"
    short_wait_mutant.write_text(
        renewal_source.replace(
            lock_wait_formula,
            "PUBLISH_LEASE_LOCAL_LOCK_WAIT_SECONDS=1",
        ),
        encoding="utf-8",
    )
    set_previous(8)
    short_wait = run_publisher("renewal-short-wait", publisher=short_wait_mutant, extra={
        "PUBLISH_TEST_DELAY_BUILD": "1",
        "PUBLISH_TEST_DELAY_SECONDS": "12",
        "PUBLISH_TEST_PAUSE_RENEWAL_BEFORE_STATE": "1",
    })
    deadline = time.monotonic() + 20
    while not (release / "renewal-short-wait.renewed-before-state").exists():
        if time.monotonic() > deadline:
            fail("short-lock-wait fixture never reached the forced interleaving")
        time.sleep(0.02)
    time.sleep(5)
    (release / "renewal-short-wait.resume-renewal-state").touch()
    code, _, stderr, rows = finish(short_wait)
    subprocess.run(
        ["git", f"--git-dir={lease_remote}", "update-ref", "-d", lease_ref_name],
        check=True,
    )
    if (code == 0 or (release / "renewal-short-wait.published.json").exists()
            or "publisher lease was lost before version reservation" not in stderr):
        fail(f"short lock wait did not reproduce false ownership loss: {code} {stderr} {rows}")
    print("PASS: short_local_lock_wait observed RED before the bounded renewal critical section completed")

    # A single transport/API fault does not prove ownership loss. Retry each
    # refresh boundary while the last confirmed monotonic deadline retains its
    # safety margin, and complete only after the exact ref is renewed.
    for name, fault, event_name in (
        ("transient-clock", "PUBLISH_TEST_FAIL_HEARTBEAT_CLOCK_ONCE", "clock-failure"),
        ("transient-ls-remote", "PUBLISH_TEST_FAIL_HEARTBEAT_LS_REMOTE_ONCE", "heartbeat-ls-remote-failure"),
        ("transient-push", "PUBLISH_TEST_FAIL_HEARTBEAT_PUSH_ONCE", "heartbeat-push-failure"),
    ):
        set_previous(7)
        code, _, stderr, rows = finish(run_publisher(name, extra={
            "PUBLISH_TEST_DELAY_BUILD": "1",
            "PUBLISH_TEST_DELAY_SECONDS": "12",
            fault: "1",
        }))
        published = json.loads((release / f"{name}.published.json").read_text()) if code == 0 else None
        if (code != 0 or published["version"] != 8
                or sum(row["kind"] == event_name for row in rows) != 1
                or "transient coordination error" not in stderr):
            fail(f"{name}: one transient refresh fault became terminal: {code} {stderr} {rows}")
    print("PASS: transient clock, ls-remote, and push faults retry within the confirmed lease margin")

    # Once the manifest is active, verification is read-only. A lease lookup at
    # this point adds no fencing and can only defeat the bounded CDN retry. The
    # old assertion is retained as a mutant to prove the network-failure case
    # reaches that exact false terminal path.
    verifier_loop = '''for attempt in 1 2 3 4 5; do
\tif docker run --rm --read-only'''
    asserted_verifier_loop = '''for attempt in 1 2 3 4 5; do
\tpublisher_lease_assert_owned \\
\t\t|| die "publisher lease was lost before post-publish verification"
\tif docker run --rm --read-only'''
    if publisher_source.count(verifier_loop) != 1:
        fail("post-publish verifier assertion mutant did not identify one retry loop")
    verifier_assertion_mutant = root / "generate-rules-post-publish-lease-assertion.sh"
    verifier_assertion_mutant.write_text(
        publisher_source.replace(verifier_loop, asserted_verifier_loop),
        encoding="utf-8",
    )
    set_previous(11)
    code, _, stderr, rows = finish(run_publisher(
        "post-activate-assertion-mutant",
        publisher=verifier_assertion_mutant,
        extra={"PUBLISH_TEST_FAIL_LEASE_AFTER_MANIFEST": "1"},
    ))
    if (code == 0 or any(row["kind"] == "verify" for row in rows)
            or sum(row["kind"] == "post-manifest-lease-failure" for row in rows) != 1
            or "publisher lease was lost before post-publish verification" not in stderr):
        fail(f"post-publish assertion mutant did not reproduce the false terminal failure: {code} {stderr} {rows}")
    subprocess.run(
        ["git", f"--git-dir={lease_remote}", "update-ref", "-d", lease_ref_name],
        check=True,
    )
    print("PASS: post_publish_lease_assertion_reenabled observed RED before CDN verification")

    # Both a transport failure and a changed/absent ref after activation are
    # irrelevant to the immutable verifier. The transport case also forces one
    # CDN miss so success proves the retry loop remains live.
    post_activation_cases = (
        (
            "post-activate-lease-network",
            {"PUBLISH_TEST_FAIL_LEASE_AFTER_MANIFEST": "1", "PUBLISH_TEST_FAIL_VERIFY_UNTIL": "1"},
            "post-manifest-lease-failure",
            2,
        ),
        (
            "post-activate-lease-changed",
            {"PUBLISH_TEST_REMOVE_LEASE_AFTER_MANIFEST": "1"},
            "lease-removed-after-manifest",
            1,
        ),
    )
    for name, extra, lease_event, expected_verifies in post_activation_cases:
        set_previous(11)
        code, _, stderr, rows = finish(run_publisher(name, extra=extra))
        verifies = [row for row in rows if row["kind"] == "verify"]
        published = json.loads((release / f"{name}.published.json").read_text()) if code == 0 else None
        if (code != 0 or published["version"] != 12
                or len(verifies) != expected_verifies or not verifies[-1]["good"]
                or sum(row["kind"] == lease_event for row in rows) != 1):
            fail(f"{name}: post-activation lease state defeated read-only verification: {code} {stderr} {rows}")
        subprocess.run(
            ["git", f"--git-dir={lease_remote}", "update-ref", "-d", lease_ref_name],
            check=True,
        )
    print("PASS: post-activation lease network failure/ref removal cannot defeat bounded CDN verification")

    # A failed heartbeat exits its reader before top-level cleanup runs. The
    # parent-held read/write descriptor keeps the stop notification bounded,
    # so cleanup cannot hang while opening an orphaned FIFO for writing.
    set_previous(6)
    failed_heartbeat = run_publisher(
        "failed-heartbeat",
        extra={"PUBLISH_TEST_DELAY_BUILD": "1", "PUBLISH_TEST_DELAY_SECONDS": "12"},
    )
    deadline = time.monotonic() + 15
    while not (release / "failed-heartbeat.building").exists():
        if time.monotonic() > deadline:
            fail("failed-heartbeat fixture never reached build")
        time.sleep(0.02)
    refs = subprocess.check_output(
        ["git", f"--git-dir={lease_remote}", "for-each-ref", "--format=%(refname)", "refs/heads/mailstrix-publisher-leases/"],
        text=True,
    ).splitlines()
    for ref in refs:
        subprocess.run(["git", f"--git-dir={lease_remote}", "update-ref", "-d", ref], check=True)
    code, _, stderr, rows = finish(failed_heartbeat, timeout=25)
    if code == 0 or any(
        row["kind"] == "upload" and row["asset"] in {
            "compiled.yac", "compiled.yac.manifest.json.sig", "compiled.yac.manifest.json"
        }
        for row in rows
    ):
        fail(f"failed heartbeat did not terminate before release mutation: {rows}")
    if "publisher mutex ownership changed" not in stderr:
        fail(f"proven OID loss was not distinguished from transient uncertainty: {stderr}")
    print("PASS: proven OID loss is terminal and cleanup avoids an orphaned-FIFO deadlock")

    # Every untrusted/malformed/boundary prior state stops before bundle work.
    negative = [
        ("missing-signature", 41, "missing", None),
        ("tampered", 41, "tampered", None),
        ("malformed-signature", 41, "malformed", None),
        ("untrusted-signature", 41, "untrusted", None),
        ("oversized-signature", 41, "oversized", None),
        ("oversized-manifest", 41, "valid", b"{" + b" " * (64 << 10) + b"}"),
        ("zero", 0, "valid", None),
        ("negative", -1, "valid", None),
        ("fractional", 1, "valid", b'{"version":1.5}'),
        ("nonnumeric", 1, "valid", b'{"version":"41"}'),
        ("boolean", 1, "valid", b'{"version":true}'),
        ("duplicate-version", 1, "valid", b'{"version":1,"version":2}'),
        ("non-object", 1, "valid", b'[41]'),
        ("malformed-manifest", 1, "valid", b'{"version":'),
        ("max", maximum, "valid", None),
        ("overflow", maximum + 1, "valid", None),
    ]
    for name, version, mode, body in negative:
        set_previous(version, mode, body)
        code, _, _, rows = finish(run_publisher(name))
        if code == 0:
            fail(f"{name}: invalid prior state was accepted")
        assert_no_candidate_work(rows, name)
    set_previous(41)
    (release / "compiled.yac.manifest.json").unlink()
    code, _, _, rows = finish(run_publisher("missing-manifest", extra={"PUBLISH_TEST_RELEASE_EXISTS": "1"}))
    if code == 0:
        fail("missing manifest was treated as a first publication")
    assert_no_candidate_work(rows, "missing-manifest")
    print("PASS: missing/tampered/untrusted/malformed/oversized and numeric boundaries fail before bundle work")

    # Two hosts overlap after A has acquired and read 118. B must wait, then
    # authenticate A's 119 and publish 120 rather than reusing 119.
    set_previous(118)
    a = run_publisher("A", extra={"PUBLISH_TEST_BLOCK_BUILD": "1"})
    deadline = time.monotonic() + 15
    while not (release / "A.building").exists():
        if time.monotonic() > deadline:
            fail("contention fixture never reached A build")
        time.sleep(0.02)
    b = run_publisher("B", extra={"PUBLISH_TEST_OBSERVE_LEASE_CONTENTION": "1"})
    deadline = time.monotonic() + 15
    while not (release / "B.contending").exists():
        if time.monotonic() > deadline:
            fail("contention fixture never proved B observed A's mutex")
        time.sleep(0.02)
    (release / "A.resume-build").touch()
    acode, _, astderr, arows = finish(a)
    bcode, _, bstderr, brows = finish(b)
    versions = [json.loads((release / f"{name}.published.json").read_text())["version"] for name in ("A", "B")]
    if acode != 0 or bcode != 0 or versions != [119, 120]:
        fail(f"contention: versions={versions}, A={acode}/{astderr}/{arows}, B={bcode}/{bstderr}/{brows}")
    print("PASS: authoritative CAS lease serializes overlapping hosts as versions 119 then 120")

    # GitHub treats owner/name spelling case-insensitively. Case variants must
    # therefore share one mutex scope and serialize the same rolling release.
    set_previous(218)
    a = run_publisher("case-A", extra={
        "REPO": "MyGuard-Labs/MailStrix",
        "PUBLISH_TEST_BLOCK_BUILD": "1",
    })
    deadline = time.monotonic() + 15
    while not (release / "case-A.building").exists():
        if time.monotonic() > deadline:
            fail("casefold fixture never reached A build")
        time.sleep(0.02)
    b = run_publisher("case-B", extra={"PUBLISH_TEST_OBSERVE_LEASE_CONTENTION": "1"})
    deadline = time.monotonic() + 15
    while not (release / "case-B.contending").exists():
        if time.monotonic() > deadline:
            fail("casefold fixture never proved B observed A's mutex")
        time.sleep(0.02)
    (release / "case-A.resume-build").touch()
    acode, _, astderr, arows = finish(a)
    bcode, _, bstderr, brows = finish(b)
    case_versions = [json.loads((release / f"case-{side}.published.json").read_text())["version"] for side in ("A", "B")]
    if acode != 0 or bcode != 0 or case_versions != [219, 220]:
        fail(f"casefold contention: versions={case_versions}, A={acode}/{astderr}/{arows}, B={bcode}/{bstderr}/{brows}")
    print("PASS: GitHub repository spelling variants share one publisher mutex")

    # Expiry is diagnostic, never authority to replace a publisher. A is
    # stalled inside an upload that already passed its ownership check. Even
    # after the server clock advances beyond A's expiry, B refuses. Once A has
    # been proven quiescent, B can remove only the exact observed OID and run.
    # A already reserved 119, so B must skip it and activate 120.
    set_previous(118)
    a = run_publisher("blocked-A", extra={
        "PUBLISH_TEST_BLOCK_UPLOAD_ASSET": "compiled.yac",
        "PUBLISH_TEST_SERVER_DATE": "Mon, 26 Oct 2026 12:00:00 GMT",
    })
    deadline = time.monotonic() + 15
    while not (release / "blocked-A.uploading").exists():
        if time.monotonic() > deadline:
            fail("blocked publisher never entered bundle upload")
        time.sleep(0.02)
    blocked_oid = current_lease_oid()
    code, _, stderr, rows = finish(run_publisher("expired-B", extra={
        "PUBLISH_TEST_SERVER_DATE": "Tue, 27 Oct 2026 12:00:00 GMT",
    }))
    if code == 0 or current_lease_oid() != blocked_oid:
        fail(f"expired foreign mutex was replaced: {rows}")
    if blocked_oid not in stderr or f"PUBLISH_LEASE_RECOVER_OID={blocked_oid}" not in stderr:
        fail(f"expired-holder diagnostic did not surface its exact recovery OID: {stderr}")
    assert_no_candidate_work(rows, "expired-B")
    os.killpg(a[0].pid, signal.SIGKILL)
    finish(a)
    if current_lease_oid() != blocked_oid:
        fail("quiescent blocked publisher did not leave its exact recovery OID")
    code, _, stderr, rows = finish(run_publisher("recovered-B", extra={
        "PUBLISH_TEST_SERVER_DATE": "Tue, 27 Oct 2026 12:00:00 GMT",
        "PUBLISH_LEASE_RECOVER_OID": blocked_oid,
    }))
    if code != 0 or json.loads((release / "recovered-B.published.json").read_text())["version"] != 120:
        fail(f"exact-OID recovery did not let B proceed after A ended: {stderr} {rows}")
    print("PASS: blocked upload remains fenced after expiry and proceeds only after quiescence plus exact-OID recovery")

    # Recovery rejects both an arbitrary OID and an OID that was current before
    # another actor changed the ref. Neither attempt reaches candidate work.
    set_previous(41)
    first_stale = seed_lease("1" * 64, 1)
    wrong = "f" * 40 if first_stale != "f" * 40 else "e" * 40
    code, _, _, rows = finish(run_publisher("wrong-recovery", extra={
        "PUBLISH_LEASE_RECOVER_OID": wrong,
    }))
    if code == 0 or current_lease_oid() != first_stale:
        fail("wrong recovery OID changed the mutex")
    assert_no_candidate_work(rows, "wrong-recovery")
    replacement = seed_lease("2" * 64, 1)
    code, _, _, rows = finish(run_publisher("stale-recovery", extra={
        "PUBLISH_LEASE_RECOVER_OID": first_stale,
    }))
    if code == 0 or current_lease_oid() != replacement:
        fail("stale recovery OID changed the replacement mutex")
    assert_no_candidate_work(rows, "stale-recovery")
    code, _, stderr, rows = finish(run_publisher("exact-recovery", extra={
        "PUBLISH_LEASE_RECOVER_OID": replacement,
    }))
    if code != 0:
        fail(f"exact recovery OID was rejected: {stderr} {rows}")
    print("PASS: wrong and stale recovery OIDs are rejected; exact expired OID succeeds")

    # Unavailable coordination and mid-transaction lease loss are terminal.
    set_previous(41)
    unavailable = root / "missing" / "lease.git"
    code, _, _, rows = finish(run_publisher("unavailable", extra={"PUBLISH_LEASE_REMOTE": str(unavailable)}))
    if code == 0:
        fail("unavailable coordination was accepted")
    assert_no_candidate_work(rows, "unavailable")
    set_previous(41)
    code, _, _, rows = finish(run_publisher("lease-loss", extra={"PUBLISH_TEST_LOSE_LEASE": "1"}))
    if code == 0 or any(
        row["kind"] == "upload" and row["asset"] in {
            "compiled.yac", "compiled.yac.manifest.json.sig", "compiled.yac.manifest.json"
        }
        for row in rows
    ):
        fail(f"lease loss did not stop before release mutation: {rows}")
    print("PASS: coordination failure and lease loss fail closed before release mutation")

    source = (docker_dir / "generate-rules.sh").read_text(encoding="utf-8")

    # Named repair-removal control: without the explicit object format, an
    # inherited SHA-256 default creates objects the SHA-1 remote cannot accept.
    object_format_mutant = root / "generate-rules-no-object-format.sh"
    object_format_guard = 'git init --bare --quiet --object-format=sha1 "$PUBLISH_LEASE_REPO"'
    mutated = source.replace(
        object_format_guard,
        'git init --bare --quiet "$PUBLISH_LEASE_REPO"',
        1,
    )
    if mutated == source or object_format_guard not in source:
        fail("lease object-format mutation did not apply")
    object_format_mutant.write_text(mutated, encoding="utf-8")
    set_previous(4)
    code, _, stderr, rows = finish(run_publisher(
        "object-format-mutant",
        publisher=object_format_mutant,
        extra={"GIT_DEFAULT_HASH": "sha256"},
    ))
    refs = subprocess.check_output([
        "git", f"--git-dir={lease_remote}", "for-each-ref", "--format=%(refname)",
        "refs/heads/mailstrix-publisher-leases/",
    ], text=True).splitlines()
    if code == 0 or refs:
        fail(f"object-format removal did not fail before acquiring a SHA-1 remote ref: {stderr} {rows} {refs}")
    assert_no_candidate_work(rows, "object-format-mutant")
    print("PASS: lease_object_format_removal observed RED under GIT_DEFAULT_HASH=sha256")

    # Named repair-removal control: the old digit-only check accepts decimal 360
    # at the bounds gate, then Bash arithmetic creates a 240-second octal lease.
    timing_mutant = root / "generate-rules-octal-timing.sh"
    timing_guard = '''        ''|*[!0-9]*|0[0-9]*|??????*)
            die "publisher lease timing values must be canonical decimal integers of at most five digits"
            ;;
'''
    mutated = source.replace(
        timing_guard,
        '''        ''|*[!0-9]*) die "publisher lease timing values must be decimal integers" ;;
''',
        1,
    )
    if mutated == source or timing_guard not in source:
        fail("lease-timing canonicalization mutation did not apply")
    timing_mutant.write_text(mutated, encoding="utf-8")
    set_previous(4)
    code, _, stderr, rows = finish(run_publisher(
        "timing-octal-mutant",
        publisher=timing_mutant,
        extra={"PUBLISH_LEASE_TTL_SECONDS": "0360"},
    ))
    if code != 0 or json.loads((release / "timing-octal-mutant.published.json").read_text())["version"] != 5:
        fail(f"lease timing removal did not admit decimal 360 as octal 240: {stderr} {rows}")
    print("PASS: lease_timing_canonicalization_removal observed RED (360 used as octal 240)")

    # Named repair-removal control: if an exact own OID after a failed create
    # response is not adopted, the run fails and leaves an orphan mutex.
    acquire_adopt_mutant = root / "generate-rules-no-acquire-adopt.sh"
    acquire_adopt_block = '''        if [ "$current" = "$new" ]; then
            publisher_lease_write_state "$new" "$expires" "$now" || return 1
            PUBLISH_LEASE_HELD=1
            return 0
        fi
'''
    mutated = source.replace(
        acquire_adopt_block,
        '''        if [ "$current" = "$new" ]; then
            return 1 # acquire-adoption-removal mutant
        fi
''',
    )
    if mutated == source or acquire_adopt_block not in source:
        fail("acquire-adoption mutation did not apply")
    acquire_adopt_mutant.write_text(mutated, encoding="utf-8")
    set_previous(4)
    code, _, _, rows = finish(run_publisher(
        "acquire-adopt-mutant",
        publisher=acquire_adopt_mutant,
        extra={"PUBLISH_TEST_LOSE_ACQUIRE_PUSH_RESPONSE_ONCE": "1"},
    ))
    orphan = current_lease_oid()
    if code == 0 or not orphan or sum(row["kind"] == "acquire-push-response-loss" for row in rows) != 1:
        fail(f"acquire-adoption removal did not strand the successful mutex: {rows}")
    subprocess.run(
        ["git", f"--git-dir={lease_remote}", "update-ref", "-d", lease_ref_name, orphan],
        check=True,
    )
    print("PASS: acquire_response_adoption_removal observed RED (successful mutex was orphaned)")

    # Named repair-removal control: hashing GitHub's case-preserving spelling
    # gives one case variant a different ref, so both publishers reuse 219.
    casefold_mutant = root / "generate-rules-no-repo-casefold.sh"
    casefold_scope = 'PUBLISH_LEASE_SCOPE="$(printf \'%s\\0%s\' "$PUBLISH_LEASE_REPO_IDENTITY" "$TAG" | sha256sum | awk \'{print $1}\')"'
    mutated = source.replace(
        casefold_scope,
        'PUBLISH_LEASE_SCOPE="$(printf \'%s\\0%s\' "$REPO" "$TAG" | sha256sum | awk \'{print $1}\')"',
    )
    if mutated == source or casefold_scope not in source:
        fail("repository-casefold mutation did not apply")
    casefold_mutant.write_text(mutated, encoding="utf-8")
    set_previous(218)
    a = run_publisher("case-mutant-A", publisher=casefold_mutant, extra={
        "REPO": "MyGuard-Labs/MailStrix",
        "PUBLISH_TEST_BLOCK_BUILD": "1",
    })
    deadline = time.monotonic() + 15
    while not (release / "case-mutant-A.building").exists():
        if time.monotonic() > deadline:
            fail("repository-casefold mutant never reached A build")
        time.sleep(0.02)
    b = run_publisher("case-mutant-B", publisher=casefold_mutant)
    bcode, _, _, _ = finish(b)
    (release / "case-mutant-A.resume-build").touch()
    acode, _, _, _ = finish(a)
    mutant_versions = [json.loads((release / f"case-mutant-{side}.published.json").read_text())["version"] for side in ("A", "B")]
    if acode != 0 or bcode != 0 or mutant_versions != [219, 219]:
        fail(f"repository-casefold removal did not reproduce duplicate versions: {mutant_versions}")
    print("PASS: repository_casefold_removal observed RED (case variants both published version 219)")

    # Named repair-removal control: without repair-before-advance, alternating
    # clobber failures erase the sole maximum and restart reuses version 43.
    high_water_mutant = root / "generate-rules-no-high-water-reconcile.sh"
    reconcile_call = '''        reconcile_version_high_water \\
            || die "could not preserve the authenticated version maximum in both reservation slots; canonical assets were not changed"
'''
    mutated = source.replace(reconcile_call, '        : # high-water-reconciliation-removal mutant\n', 1)
    if mutated == source or reconcile_call not in source:
        fail("high-water reconciliation mutation did not apply")
    high_water_mutant.write_text(mutated, encoding="utf-8")
    set_previous(41)
    code, _, stderr, rows = finish(run_publisher("high-water-mutant-setup"))
    if code != 0:
        fail(f"high-water reconciliation mutant setup failed: {stderr} {rows}")
    code, _, _, rows = finish(run_publisher(
        "high-water-mutant-canonical-fail",
        extra={"PUBLISH_TEST_FAIL_UPLOAD_ASSET_ONCE": "compiled.yac.version-high-water.json"},
    ))
    if code == 0:
        fail(f"high-water reconciliation mutant setup did not leave a sole maximum: {rows}")
    code, _, _, rows = finish(run_publisher(
        "high-water-mutant-recovery-fail",
        publisher=high_water_mutant,
        extra={"PUBLISH_TEST_FAIL_UPLOAD_ASSET_ONCE": "compiled.yac.version-high-water.recovery.json"},
    ))
    if code == 0 or not any(row["kind"] == "upload-delete-failure" for row in rows):
        fail(f"high-water reconciliation mutant did not erase the sole maximum: {rows}")
    code, _, stderr, rows = finish(run_publisher("high-water-mutant-restart"))
    if (code != 0
            or json.loads((release / "high-water-mutant-restart.published.json").read_text())["version"] != 43):
        fail(f"high-water recovery removal did not reproduce version reuse: {stderr} {rows}")
    print("PASS: high_water_reconciliation_removal observed RED (restart reused version 43)")

    # Named repair-removal control: restore automatic expired-ref takeover.
    # B publishes while A's already-authorized bundle upload is blocked; when A
    # resumes, that stale upload overwrites B's bundle and breaks B's manifest.
    takeover_mutant = root / "generate-rules-expired-takeover.sh"
    durable_block = '''        if [ -n "$current" ]; then
            read -r owner expires detail_extra <<<"$(publisher_lease_details "$current")" || return 1
            [ -n "$owner" ] && [ -z "${detail_extra:-}" ] || return 1
            if [ "$expires" -le "$now" ]; then
                note "publisher mutex ${current} is expired but remains authoritative; after proving the holder quiescent, rerun with PUBLISH_LEASE_RECOVER_OID=${current}"
                return 1
            fi
            publisher_lease_sleep
            continue
        fi
'''
    takeover_block = '''        if [ -n "$current" ]; then
            read -r owner expires detail_extra <<<"$(publisher_lease_details "$current")" || return 1
            [ -n "$owner" ] && [ -z "${detail_extra:-}" ] || return 1
            if [ "$expires" -gt "$now" ]; then
                publisher_lease_sleep
                continue
            fi
        fi
'''
    mutated = source.replace(durable_block, takeover_block)
    mutated = mutated.replace(
        '--force-with-lease="${PUBLISH_LEASE_REF}:"',
        '--force-with-lease="${PUBLISH_LEASE_REF}:${current}"',
        1,
    )
    if mutated == source or durable_block not in source:
        fail("expired-takeover mutation did not apply")
    takeover_mutant.write_text(mutated, encoding="utf-8")
    set_previous(118)
    a = run_publisher("takeover-A", extra={
        "PUBLISH_TEST_BLOCK_UPLOAD_ASSET": "compiled.yac",
        "PUBLISH_TEST_SERVER_DATE": "Mon, 26 Oct 2026 12:00:00 GMT",
    })
    deadline = time.monotonic() + 15
    while not (release / "takeover-A.uploading").exists():
        if time.monotonic() > deadline:
            fail("takeover mutant fixture never blocked A in upload")
        time.sleep(0.02)
    bcode, _, bstderr, brows = finish(run_publisher(
        "takeover-B",
        publisher=takeover_mutant,
        extra={"PUBLISH_TEST_SERVER_DATE": "Tue, 27 Oct 2026 12:00:00 GMT"},
    ))
    if bcode != 0:
        fail(f"expired-takeover mutant did not let B publish: {bstderr} {brows}")
    (release / "takeover-A.resume").touch()
    acode, _, _, arows = finish(a)
    manifest = json.loads((release / "compiled.yac.manifest.json").read_text())
    bundle = (release / "compiled.yac").read_bytes()
    if acode == 0 or manifest["checksum"] == "sha256:" + hashlib.sha256(bundle).hexdigest():
        fail(f"expired-takeover mutant did not reproduce stale upload overwrite: {arows}")
    print("PASS: expired_takeover_reenabled observed RED (A overwrote B after B published)")

    # Named repair-removal control: partition the lease by process. Both hosts
    # then read 118 and successfully reuse 119, reproducing D2.
    lease_mutant = root / "generate-rules-no-shared-lease.sh"
    needle = 'PUBLISH_LEASE_REF="refs/heads/mailstrix-publisher-leases/${PUBLISH_LEASE_SCOPE}"'
    mutated = source.replace(needle, needle[:-1] + '-$$"')
    if mutated == source:
        fail("lease-removal mutation did not apply")
    lease_mutant.write_text(mutated, encoding="utf-8")
    set_previous(118)
    a = run_publisher("mutant-A", publisher=lease_mutant, extra={"PUBLISH_TEST_BLOCK_BUILD": "1"})
    deadline = time.monotonic() + 15
    while not (release / "mutant-A.building").exists():
        if time.monotonic() > deadline:
            fail("lease mutant fixture never reached build")
        time.sleep(0.02)
    b = run_publisher("mutant-B", publisher=lease_mutant)
    bcode, _, _, _ = finish(b)
    (release / "mutant-A.resume-build").touch()
    acode, _, _, _ = finish(a)
    mutant_versions = [json.loads((release / f"mutant-{side}.published.json").read_text())["version"] for side in ("A", "B")]
    if acode != 0 or bcode != 0 or mutant_versions != [119, 119]:
        fail(f"lease repair-removal control did not reproduce duplicate versions: {mutant_versions}")
    print("PASS: D2_shared_lease_removal observed RED (two successful version-119 publications)")

    # Removing exact-byte verification admits a tampered prior manifest.
    verify_mutant = root / "generate-rules-no-prior-verify.sh"
    verify_block = '''    "$RULESIGN_BIN" -manifest "$manifest" -verify-signature "$signature" \\
        || return 1\n'''
    mutated = source.replace(verify_block, "    : # verification-removal mutant\n")
    if mutated == source:
        fail("verification-removal mutation did not apply")
    verify_mutant.write_text(mutated, encoding="utf-8")
    set_previous(41, "tampered")
    code, _, _, _ = finish(run_publisher("verify-mutant", publisher=verify_mutant))
    if code != 0:
        fail("verification-removal mutant did not admit tampered state")
    print("PASS: previous_signature_verification_removal observed RED")

    # Removing the ceiling admits MaxInt and produces an unrepresentable next
    # client version. The restored candidate rejected the same input above.
    increment_mutant = root / "generate-rules-no-checked-increment.sh"
    mutated = source.replace(
        "if current < 1 or current > maximum or high_water < current or high_water >= maximum:\n",
        "if current < 1 or current > maximum or high_water < current or high_water > maximum:\n",
    )
    if mutated == source:
        fail("checked-increment mutation did not apply")
    increment_mutant.write_text(mutated, encoding="utf-8")
    set_previous(maximum)
    code, _, _, _ = finish(run_publisher("increment-mutant", publisher=increment_mutant))
    published = json.loads((release / "increment-mutant.published.json").read_text()) if code == 0 else None
    if code != 0 or published["version"] != maximum + 1:
        fail("checked-increment-removal mutant did not cross MaxInt")
    print("PASS: previous_version_checked_increment_removal observed RED")

    print("PASS: candidate restored after all named repair-removal controls")
PY
