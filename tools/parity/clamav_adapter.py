"""Optional offline ClamAV qualification backend; not a Mailstrix CLI backend.

The caller supplies trusted local installation assets explicitly. Snapshot bytes,
not mutable host files, become an immutable scratch image. Only this parent talks
to Docker. A sequential launch owns create -> inspect -> start -> inspect ->
remove -> absence; input is sent only after inspecting the enforced envelope.
Inconclusive create or cleanup poisons the instance: no retry or later sample.
No daemon, mounts, pull, freshclam, host scanner fallback or network is used.
"""

import hashlib
import io
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
MAX_INPUT = 32 << 20
MAX_OUTPUT = 64 << 10
SECONDS = 45
MEMORY = 4 << 30
TMPFS = "rw,noexec,nosuid,nodev,size=512m"
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
CONTAINER_NAME = re.compile(r"mailstrix-clamav-[0-9a-f]{32}")
RUNTIME_LIMITS = ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit")
BUILTIN_SECCOMP = "name=seccomp,profile=builtin"
DEFERRED_REAPS: list[subprocess.Popen] = []
PROCESS_STATUS_ATTRIBUTE = "_mailstrix_clamav_process_status"


class QualificationFailure(ValueError):
    """Operator-facing verdict containing only bounded, non-sensitive fields."""


# The Go bridge puts Python and its Docker clients in one parent-owned process
# group. Standalone qualification owns/reaps each client's group itself.
CALL_NEW_SESSION = True
AGE_WARNING_153 = (
    b"LibClamAV Warning: **************************************************\n"
    b"LibClamAV Warning: ***  The virus database is older than 7 days!  ***\n"
    b"LibClamAV Warning: ***   Please update it as soon as possible.    ***\n"
    b"LibClamAV Warning: **************************************************\n"
)
# Explicit policy, including limits which the engine may not report as an error.
# Invocation completeness is not exhaustive extraction coverage.
SCAN_ARGS = [
    "--database=/db",
    "--no-summary",
    "--stdout",
    "--tempdir=/tmp",
    "--alert-exceeds-max=yes",
    "--max-scantime=0",
    "--max-filesize=32M",
    "--max-scansize=64M",
    "--max-files=1000",
    "--max-recursion=16",
    "--max-dir-recursion=16",
    "--max-embeddedpe=32M",
    "--max-htmlnormalize=32M",
    "--max-htmlnotags=32M",
    "--max-scriptnormalize=32M",
    "--max-ziptypercg=1M",
    "--max-partitions=50",
    "--max-iconspe=100",
    "--max-rechwp3=16",
    "--pcre-match-limit=100000",
    "--pcre-recmatch-limit=2000",
    "--pcre-max-filesize=32M",
    "--bytecode-timeout=1000",
    "--disable-cache",
    "-",
]


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def stream_digest(stream):
    value = hashlib.sha256()
    while chunk := stream.read(1 << 20):
        value.update(chunk)
    return value.hexdigest()


def require_runtime_containment(info):
    """Require every host capability used by the qualified Docker envelope."""
    if (
        not isinstance(info, dict)
        or info.get("CgroupVersion") != "2"
        or not isinstance(info.get("SecurityOptions"), list)
        or BUILTIN_SECCOMP not in info["SecurityOptions"]
        or any(info.get(key) is not True for key in RUNTIME_LIMITS)
    ):
        raise QualificationFailure("runtime containment unavailable")


@dataclass
class Call:
    code: int = 0
    out: bytes = b""
    err: bytes = b""
    status: str = "ok"
    failure_type: str = ""


def wait_unreaped(proc, deadline):
    """Observe direct-child exit without releasing its PID/PGID identity."""
    while True:
        try:
            exited = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except InterruptedError:
            continue
        if exited is not None:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def signal_before_reap(proc):
    """Terminate the owned target while its unreaped leader pins identity."""
    try:
        if CALL_NEW_SESSION:
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        # No signalable target remains; proc.wait below still reaps the leader.
        return


def reap_in_background(proc, thread_factory=threading.Thread):
    """Keep one killed direct child reachable until it eventually exits."""
    DEFERRED_REAPS.append(proc)

    def reap():
        try:
            proc.wait()
        except BaseException:  # noqa: BLE001
            return
        else:
            try:
                DEFERRED_REAPS.remove(proc)
            except ValueError:
                pass

    thread_factory(
        target=reap,
        name="mailstrix-clamav-reaper",
        daemon=True,
    ).start()


def retain_for_polling(proc):
    """Retain an unsignalled child without dedicating an unbounded thread."""
    DEFERRED_REAPS.append(proc)


def signal_and_reap(proc):
    """Kill the owned process family and bound direct-child reaping."""

    def defer(status):
        """Retain the unreaped child and return its terminal status."""
        if status != "ok":
            retain_for_polling(proc)
            return status
        try:
            reap_in_background(proc)
        except RuntimeError:
            # reap_in_background retains proc before starting its thread, so a
            # thread-start failure remains available to nonblocking polling.
            pass
        return "reap_timeout"

    signal_status = "ok"
    signal_failure = None
    wait_failure = None
    try:
        signal_before_reap(proc)
    except OSError:
        signal_status = "signal_error"
    except BaseException as error:  # noqa: BLE001
        signal_status = "signal_error"
        signal_failure = error
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        signal_status = defer(signal_status)
    except BaseException as error:  # noqa: BLE001
        wait_failure = error
        signal_status = defer(signal_status)
    if signal_failure is not None:
        setattr(signal_failure, PROCESS_STATUS_ATTRIBUTE, signal_status)
        if wait_failure is not None:
            signal_failure.add_note(
                "secondary wait error: " + type(wait_failure).__name__
            )
        raise signal_failure
    if wait_failure is not None:
        setattr(wait_failure, PROCESS_STATUS_ATTRIBUTE, signal_status)
        raise wait_failure
    return signal_status


def poll_deferred_reaps():
    """Non-blockingly reap retained children that lack a reaper thread."""
    for proc in tuple(DEFERRED_REAPS):
        if proc.poll() is not None:
            try:
                DEFERRED_REAPS.remove(proc)
            except ValueError:
                pass


def close_process_pipes(proc):
    """Close every parent pipe without one close masking the remaining closes."""
    for stream in (proc.stdout, proc.stderr, proc.stdin):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def call(args, data=b"", seconds=SECONDS, input_file=None):
    """Bound both pipes while streaming stdin; cancellation kills/reaps the CLI.

    The Docker-owned process is separately removed by Adapter.launch. Snapshot
    import can use a file descriptor instead of retaining the tar in memory.
    """
    poll_deferred_reaps()
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    # Docker consults the user's config even with a stripped environment. An
    # empty private config prevents implicit proxy/credential/context injection.
    with tempfile.TemporaryDirectory(
        prefix="mailstrix-clamav-docker-", ignore_cleanup_errors=True
    ) as config:
        # The explicit lifecycle below bounds reaping; Popen's context manager
        # performs an unbounded wait when its __exit__ path sees TimeoutExpired.
        # pylint: disable=consider-using-with
        proc = None
        streams = [bytearray(), bytearray()]
        status = "ok"
        offset = 0
        failure = None
        control_failure = None
        setup_failure = None
        cleanup_failure = None
        process_status = "ok"
        try:
            proc = subprocess.Popen(
                (
                    [args[0], "--config", config, *args[1:]]
                    if args[: len(DOCKER)] == DOCKER
                    else args
                ),
                stdin=input_file or subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=CALL_NEW_SESSION,
            )
            deadline = time.monotonic() + seconds
            try:
                with selectors.DefaultSelector() as selector:
                    for index, stream in enumerate((proc.stdout, proc.stderr)):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, index)
                    if input_file is None:
                        os.set_blocking(proc.stdin.fileno(), False)
                        if data:
                            selector.register(proc.stdin, selectors.EVENT_WRITE, 2)
                        else:
                            proc.stdin.close()
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            status = "timeout"
                            break
                        for event, _ in selector.select(remaining):
                            if event.data == 2:
                                try:
                                    offset += os.write(
                                        event.fd, data[offset : offset + 4096]
                                    )
                                except BrokenPipeError:
                                    status = "input_error"
                                    break
                                if offset == len(data):
                                    selector.unregister(event.fileobj)
                                    event.fileobj.close()
                                continue
                            chunk = os.read(event.fd, 4096)
                            if not chunk:
                                selector.unregister(event.fileobj)
                                continue
                            streams[event.data].extend(chunk)
                            if len(streams[event.data]) > MAX_OUTPUT:
                                status = "output_limit"
                                break
                        if status != "ok":
                            break
                    if status == "ok" and not wait_unreaped(proc, deadline):
                        status = "timeout"
            # Preserve arbitrary operational failures only when process ownership
            # is certain; terminal process cleanup must precede every body error.
            # Control-flow exceptions still propagate after the finally cleanup.
            except Exception as error:  # noqa: BLE001
                failure = error
            except BaseException as error:  # noqa: BLE001
                control_failure = error
        except BaseException as error:  # noqa: BLE001
            setup_failure = error
        finally:
            if proc is not None:
                # Keep the leader unreaped until its process family has been
                # signalled. Its PID therefore still pins the private PGID and
                # cannot name a recycled group after an early leader exit.
                try:
                    process_status = signal_and_reap(proc)
                except BaseException as error:  # noqa: BLE001
                    cleanup_failure = error
                    process_status = getattr(
                        error, PROCESS_STATUS_ATTRIBUTE, "reap_timeout"
                    )
                finally:
                    close_process_pipes(proc)
        if setup_failure is not None:
            if proc is not None and process_status != "ok":
                setattr(setup_failure, PROCESS_STATUS_ATTRIBUTE, process_status)
            if cleanup_failure is not None:
                setup_failure.add_note(
                    "secondary process cleanup error: " + type(cleanup_failure).__name__
                )
            raise setup_failure
        if control_failure is not None:
            if process_status != "ok":
                setattr(control_failure, PROCESS_STATUS_ATTRIBUTE, process_status)
            if cleanup_failure is not None:
                control_failure.add_note(
                    "secondary process cleanup error: " + type(cleanup_failure).__name__
                )
            raise control_failure
        if cleanup_failure is not None:
            setattr(cleanup_failure, PROCESS_STATUS_ATTRIBUTE, process_status)
            if failure is not None:
                cleanup_failure.add_note(
                    "preceding body error: " + type(failure).__name__
                )
            raise cleanup_failure
        if process_status != "ok":
            status = process_status
        elif failure is not None:
            raise failure
        return Call(
            proc.returncode if isinstance(proc.returncode, int) else -1,
            bytes(streams[0][:MAX_OUTPUT]),
            bytes(streams[1][:MAX_OUTPUT]),
            status,
            type(failure).__name__ if failure is not None else "",
        )


def require(result):
    if result.status != "ok" or result.code != 0 or result.err:
        raise QualificationFailure(
            "Docker operation failed: "
            f"status={result.status} code={result.code} stderr={bool(result.err)} "
            f"cause={result.failure_type or 'none'}"
        )
    return result.out


def read_asset(source):
    """Read one stable regular installation file; FIFOs must not block open.

    Symlinks from a trusted installation (for example libclamav.so.12) are
    supported. Validate the opened descriptor, not an earlier path lookup.
    """
    descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 256 << 20:
            raise ValueError("asset must be a bounded regular file")
        data = stream.read((256 << 20) + 1)
        after = os.fstat(stream.fileno())
    if (
        len(data) != before.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise ValueError("asset changed while freezing")
    return data


def snapshot(assets, output):
    """Freeze explicitly supplied source/destination pairs into a normalized tar.

    Sources are trusted installation files, never corpus files. Open regular
    files only, bounded to 256MiB each/1GiB total/128 entries. Digests cover the
    copied bytes. Source paths and host timestamps do not enter the inventory.
    The fresh output directory is retained even on failure, without a receipt.
    """
    output = Path(output)
    output.mkdir(mode=0o700)
    if not 1 <= len(assets) <= 128:
        raise ValueError("asset count")
    inventory = []
    destinations = set()
    total = 0
    with tarfile.open(output / "rootfs.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        # 1.5.3 requires this directory even for legacy CVD verification. Empty
        # means no detached-signature CA support, not disabled verification.
        certs = tarfile.TarInfo("etc/clamav/certs")
        certs.type, certs.mode = tarfile.DIRTYPE, 0o555
        tar.addfile(certs)
        for source, destination in sorted(assets, key=lambda item: item[1]):
            path = PurePosixPath(destination)
            if (
                not path.is_absolute()
                or ".." in path.parts
                or str(path) != destination
                or destination in destinations
                or not re.fullmatch(
                    r"/(?:usr/bin/clamscan|(?:lib|lib64|usr/lib)/[A-Za-z0-9_./+-]+"
                    r"|db/[A-Za-z0-9_.-]+)",
                    destination,
                )
            ):
                raise ValueError("invalid or duplicate asset destination")
            destinations.add(destination)
            data = read_asset(source)
            total += len(data)
            if total > 1 << 30:
                raise ValueError("total asset size")
            info = tarfile.TarInfo(destination.lstrip("/"))
            info.size = len(data)
            info.mode = (
                0o555
                if destination == "/usr/bin/clamscan"
                or not destination.startswith("/db/")
                else 0o444
            )
            tar.addfile(info, io.BytesIO(data))
            inventory.append(
                {"path": destination, "size": len(data), "sha256": digest(data)}
            )
    databases = [item for item in inventory if item["path"].startswith("/db/")]
    if "/usr/bin/clamscan" not in destinations or not databases:
        raise ValueError("explicit scanner and database assets required")
    result = {
        "schema_version": 1,
        "assets": inventory,
        "database_sha256": digest(canonical(databases)),
        "engine_assets_sha256": digest(
            canonical([item for item in inventory if item not in databases])
        ),
    }
    with (output / "rootfs.tar").open("rb") as source:
        result["rootfs_sha256"] = stream_digest(source)
    (output / "snapshot.json").write_bytes(canonical(result))
    return result


def import_snapshot(output):
    """Import a frozen rootfs only; scratch import has no pull/build/update path."""
    with (Path(output) / "rootfs.tar").open("rb") as source:
        receipt = json.loads((Path(output) / "snapshot.json").read_bytes())
        if stream_digest(source) != receipt["rootfs_sha256"]:
            raise ValueError("snapshot integrity mismatch")
        source.seek(0)
        raw = require(
            call(
                DOCKER + ["image", "import", "--platform=linux/amd64", "-"],
                seconds=60,
                input_file=source,
            )
        )
    image = raw.decode("ascii").strip()
    if not IMAGE.fullmatch(image):
        raise ValueError("import did not return immutable image ID")
    return image


def classify(result, state, allow_stale_database=False):
    """Parse exact stdin result lines. Any diagnostic/heuristic is uncertainty."""
    if state.get("OOMKilled") is True:
        return "resource_limit", []
    if result.status != "ok":
        return result.status, []
    if (
        state.get("OOMKilled") is not False
        or state.get("Running") is not False
        or state.get("Error") != ""
        or state.get("ExitCode") != result.code
    ):
        return "execution_error", []
    known_age = allow_stale_database and result.err == AGE_WARNING_153
    # 1.5.3 reports stdin MaxFileSize as a detection followed by ERROR/exit 2.
    # Preserve its limit status, without admitting any successful observation.
    if (
        (not result.err or known_age)
        and result.code == 2
        and re.fullmatch(
            rb"stdin: Heuristics\.Limits\.Exceeded\.[A-Za-z0-9_.]{1,100} FOUND\n"
            rb"stdin: Virus\(es\) detected ERROR\n",
            result.out,
        )
    ):
        return "scan_limit", []
    if (result.err and not known_age) or result.code not in (0, 1):
        return "execution_error", []
    if result.code == 0 and result.out == b"stdin: OK\n":
        return "no_detection", []
    names = []
    for line in result.out.splitlines():
        match = re.fullmatch(rb"stdin: ([A-Za-z0-9_.:+-]{1,200}) FOUND", line)
        if not match:
            return "malformed_output", []
        name = match[1].decode("ascii")
        if name.startswith("Heuristics.Limits.Exceeded"):
            return "scan_limit", []
        if name.startswith("Heuristics."):
            return "heuristic_unknown", []
        names.append(name)
    if result.code == 1 and names and result.out.endswith(b"\n"):
        return "detection", sorted(set(names))
    return "malformed_output", []


class Adapter:
    def __init__(self, image, execute=call, memory=MEMORY, allow_stale_database=False):
        if not IMAGE.fullmatch(image):
            raise ValueError("immutable image ID required")
        if not 0 < memory <= MEMORY:
            raise ValueError("memory must not exceed the qualification envelope")
        self.image = image
        self.execute = execute
        self.memory = memory  # Lower budgets are used only by the inert OOM control.
        self.allow_stale_database = allow_stale_database
        self.poisoned = False
        self.process_uncertain = False

    def command(self, args, **kwargs):
        if self.process_uncertain:
            return Call(status="backend_unavailable")
        try:
            result = self.execute(DOCKER + args, **kwargs)
        except BaseException as error:
            if getattr(error, PROCESS_STATUS_ATTRIBUTE, "") in (
                "reap_timeout",
                "signal_error",
            ):
                self.process_uncertain = True
                self.poisoned = True
            raise
        if result.status in ("reap_timeout", "signal_error"):
            self.process_uncertain = True
            self.poisoned = True
        return result

    def create_args(self, name, scan_args):
        return [
            "create",
            "--name",
            name,
            "--pull=never",
            "--platform=linux/amd64",
            "--network=none",
            "--read-only",
            "--tmpfs=/tmp:" + TMPFS,
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65534:65534",
            "--pids-limit=64",
            "--cpus=1",
            "--memory=" + str(self.memory),
            "--memory-swap=" + str(self.memory),
            "--cgroupns=private",
            "--ipc=private",
            "--ulimit=core=0:0",
            "--log-driver=none",
            "--no-healthcheck",
            "--interactive",
            "--env=LC_ALL=C",
            "--env=TZ=UTC",
            "--entrypoint=/usr/bin/clamscan",
            self.image,
            *scan_args,
        ]

    def verify(self, container, scan_args):
        config, host = container["Config"], container["HostConfig"]
        expected = {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidMode": "",
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "PidsLimit": 64,
            "NanoCpus": 1000000000,
            "Memory": self.memory,
            "MemorySwap": self.memory,
            "Tmpfs": {"/tmp": TMPFS},
        }
        return (
            container["Image"] == self.image
            and config["User"] == "65534:65534"
            and config["Entrypoint"] == ["/usr/bin/clamscan"]
            and config["Cmd"] == scan_args
            and config["OpenStdin"] is True
            and sorted(config["Env"]) == ["LC_ALL=C", "TZ=UTC"]
            and not container["Mounts"]
            and not host["Binds"]
            and not host["VolumesFrom"]
            and not host["CapAdd"]
            and host["LogConfig"] == {"Type": "none", "Config": {}}
            and {"Name": "core", "Soft": 0, "Hard": 0} in host["Ulimits"]
            and all(host.get(key) == value for key, value in expected.items())
        )

    def inspect(self, name):
        return json.loads(require(self.command(["inspect", name], seconds=5)))[0]

    def cleanup(self, name):
        """Require both acknowledged removal and independent current absence.

        After process cleanup becomes uncertain, make no further Docker call and
        leave the exact name uncertain. Otherwise always query absence, including
        after a removal exception; absence cannot resolve a lost acknowledgement.
        """
        if self.process_uncertain:
            return False
        try:
            require(self.command(["rm", "--force", name], seconds=5))
        except (OSError, ValueError, subprocess.SubprocessError):
            removed = False
        else:
            removed = True
        try:
            absent = require(
                self.command(
                    [
                        "ps",
                        "--all",
                        "--quiet",
                        "--filter",
                        "name=^/" + name + "$",
                    ],
                    seconds=5,
                )
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            return False
        return removed and not absent.strip()

    def launch(
        self, data, scan_args=None, seconds=SECONDS, version_probe=False, name=None
    ):
        """One bounded observation; scan_args overrides are qualification-only."""
        poll_deferred_reaps()
        if self.poisoned:
            return {"status": "backend_unavailable", "detections": []}
        if len(data) > MAX_INPUT:
            return {"status": "input_limit", "detections": []}
        scan_args = SCAN_ARGS if scan_args is None else scan_args
        if version_probe:
            scan_args = ["--database=/db", "--version"]
        if name is None:
            name = "mailstrix-clamav-" + secrets.token_hex(16)
        elif not CONTAINER_NAME.fullmatch(name):
            raise ValueError("invalid parent-owned container name")
        status, detections = "setup_error", []
        version = ""
        diagnostics = []
        try:
            # Set uncertainty before submitting create: even a raised transport
            # error can follow daemon acceptance. Only an exact ack clears it.
            self.poisoned = True
            created = self.command(self.create_args(name, scan_args), seconds=5)
            # Inconclusive create may register late, even after empty ps.
            if (
                created.status == "ok"
                and created.code == 0
                and not created.err
                and re.fullmatch(rb"[a-f0-9]{64}\n", created.out)
            ):
                self.poisoned = False
            if self.poisoned:
                status = "setup_error"
            elif not self.verify(self.inspect(name), scan_args):
                status = "envelope_error"
            else:
                result = self.command(
                    ["start", "--attach", "--interactive", name],
                    data=data,
                    seconds=seconds,
                )
                if self.allow_stale_database and result.err == AGE_WARNING_153:
                    diagnostics = [
                        {
                            "code": "historical_database_age",
                            "text": AGE_WARNING_153.decode("ascii"),
                        }
                    ]
                state = self.inspect(name)["State"]
                if version_probe and (
                    result.status == "ok"
                    and result.code == 0
                    and not result.err
                    and state.get("Running") is False
                    and state.get("OOMKilled") is False
                    and state.get("Error") == ""
                    and state.get("ExitCode") == 0
                    and re.fullmatch(
                        rb"ClamAV [0-9]+\.[0-9]+\.[0-9]+[^\r\n]{0,150}\n", result.out
                    )
                ):
                    status, version = "version", result.out.decode("ascii").strip()
                else:
                    status, detections = classify(
                        result, state, self.allow_stale_database
                    )
        except (
            OSError,
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            UnicodeError,
            subprocess.SubprocessError,
        ):
            status, detections = "execution_error", []
        finally:
            if not self.cleanup(name):
                self.poisoned = True
                status, detections = "cleanup_error", []
        observed = {"status": status, "detections": detections}
        if self.poisoned:
            observed["uncertain_container_name"] = name
        if version and status == "version":
            observed["engine_version"] = version
        if diagnostics:
            observed.update(diagnostics=diagnostics, database_stale=True)
        return observed
