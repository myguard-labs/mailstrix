"""Exercise real UCL/configtest/startup in private Unix sockets; send no mail.

Requires Rspamd and Python 3. Optional --prefix supports an extracted installation.
Mutation switches exercise the same startup oracle on isolated source copies.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ERROR = "unsupported cape_policy: adapter requires static-only"


@dataclass(frozen=True)
class StartupCase:
    mode: str
    name: str
    option: str
    valid: bool


@dataclass(frozen=True)
class CaseFiles:
    directory: Path
    config: Path
    socket: Path


CASES = (
    ("omitted", "", True),
    ("empty", 'cape_policy = "";', True),
    ("static-only", 'cape_policy = "static-only";', True),
    ("quarantine", 'cape_policy = "quarantine";', False),
    ("tempfail", 'cape_policy = "tempfail";', False),
    ("boolean", "cape_policy = true;", False),
    ("number", "cape_policy = 17;", False),
    ("table", "cape_policy = {};", False),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def stop(proc: subprocess.Popen) -> None:
    """Join the foreground parent; kill its private process group on timeout."""
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        raise RuntimeError("Rspamd failed to drain its workers") from None


def print_failure_logs(case: Path) -> None:
    """Keep bounded synthetic diagnostics in CI output after its container exits."""
    for name in ("configtest.log", "daemon.log"):
        path = case / name
        try:
            with path.open("rb") as log:
                log.seek(0, os.SEEK_END)
                log.seek(max(0, log.tell() - 8192))
                tail = log.read(8192).decode("utf-8", errors="replace")
        except OSError as error:
            tail = f"log unavailable: {error}"
        print(
            f"--- {case.name}/{name} (last 8192 bytes) ---\n{tail}",
            file=sys.stderr,
            flush=True,
        )


def config_test(prefix: Path, env: dict, case: StartupCase, files: CaseFiles) -> None:
    with (files.directory / "configtest.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(
            [
                str(prefix / "usr/bin/rspamadm"),
                "configtest",
                "-s",
                "-c",
                str(files.config),
            ],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
    diagnostic = (files.directory / "configtest.log").read_text(encoding="utf-8")
    require(
        (result.returncode == 0) == case.valid,
        f"{case.mode}/{case.name}: configtest validity mismatch; see {files.directory}",
    )
    if not case.valid:
        require(
            ERROR in diagnostic,
            f"{case.mode}/{case.name}: missing configtest policy error",
        )


def daemon_startup(
    prefix: Path, env: dict, case: StartupCase, files: CaseFiles
) -> None:
    command = [str(prefix / "usr/bin/rspamd"), "-f", "-c", str(files.config)]
    if os.geteuid() == 0:
        command.append("-i")  # Only this synthetic test configuration, inside CI.
    with (
        (files.directory / "daemon.log").open("w", encoding="utf-8") as log,
        subprocess.Popen(
            command,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        ) as proc,
    ):
        try:
            deadline = time.monotonic() + 15
            while proc.poll() is None and not files.socket.exists():
                remaining = deadline - time.monotonic()
                require(
                    remaining > 0,
                    f"{case.mode}/{case.name}: startup timed out; "
                    f"see {files.directory}",
                )
                time.sleep(min(0.05, remaining))
            if case.valid:
                require(
                    proc.poll() is None and files.socket.exists(),
                    f"{case.mode}/{case.name}: valid policy did not start "
                    f"worker; see {files.directory}",
                )
            else:
                require(
                    not files.socket.exists(),
                    f"{case.mode}/{case.name}: invalid policy started worker; "
                    f"see {files.directory}",
                )
                require(
                    proc.returncode is not None and proc.returncode > 0,
                    f"{case.mode}/{case.name}: invalid policy did not exit nonzero",
                )
        finally:
            stop(proc)
    diagnostic = (files.directory / "daemon.log").read_text(encoding="utf-8")
    if case.valid:
        require(proc.returncode == 0, f"{case.mode}/{case.name}: shutdown failed")
        require(
            diagnostic.count("mailstrix: registered, backend=") == 1,
            f"{case.mode}/{case.name}: plugin must register exactly once",
        )
    else:
        require(
            ERROR in diagnostic, f"{case.mode}/{case.name}: missing daemon policy error"
        )
        require(
            "mailstrix: registered, backend=" not in diagnostic,
            f"{case.mode}/{case.name}: invalid policy registered plugin",
        )


def run_case(
    base: Path, prefix: Path, env: dict, case: StartupCase, mutation: str
) -> None:
    directory = base / f"{case.mode}-{case.name}"
    directory.mkdir()
    sock = directory / "worker.sock"
    if case.mode == "inline":
        loader = f'lua = "{base}/mailstrix.lua";'
    else:
        loader = f'modules {{ path = "{base}/plugins"; }}'
        if mutation != "remove-preflight":
            loader += f'\nlua = "{base}/mailstrix-preflight.lua";'
    config = directory / "rspamd.conf"
    files = CaseFiles(directory, config, sock)
    config.write_text(
        f'''logging {{ type = console; level = info; }}
options {{ pidfile = "{directory}/rspamd.pid"; tempdir = "{directory}";
  hs_cache_dir = "{directory}"; maps_cache_dir = "{directory}";
  url_tld = "{base}/tlds"; filters = "";
  dns {{ nameserver = "127.0.0.1:9"; }} }}
lang_detection {{ languages = "{prefix}/usr/share/rspamd/languages"; }}
{loader}
mailstrix {{ {case.option} url = "http://127.0.0.1:9/scan"; }}
worker "normal" {{ bind_socket = "{sock}"; count = 1; }}
actions {{ reject = 15; add_header = 6; greylist = 4; }}
''',
        encoding="utf-8",
    )
    config_test(prefix, env, case, files)
    daemon_startup(prefix, env, case, files)
    print(f"PASS {case.mode}/{case.name}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path("/"))
    parser.add_argument("--mode", choices=("all", "inline", "autoload"), default="all")
    parser.add_argument(
        "--mutation", choices=("none", "return", "remove-preflight"), default="none"
    )
    args = parser.parse_args()
    prefix = args.prefix.resolve()
    base = Path(tempfile.mkdtemp(prefix="cape-start-", dir="/tmp"))
    print(f"Artifacts: {base}", flush=True)
    source = Path(__file__).resolve().parents[1]
    plugin = (source / "plugins/mailstrix.lua").read_text(encoding="utf-8")
    if args.mutation == "return":
        guard = f'error("{ERROR}")'
        require(
            plugin.count(guard) == 1, "return mutation must replace exactly one guard"
        )
        plugin = plugin.replace(guard, "return")
    (base / "mailstrix.lua").write_text(plugin, encoding="utf-8")
    (base / "plugins").mkdir()
    shutil.copyfile(base / "mailstrix.lua", base / "plugins/mailstrix.lua")
    shutil.copyfile(
        source / "mailstrix-preflight.lua", base / "mailstrix-preflight.lua"
    )
    (base / "tlds").write_text("com\ninvalid\n", encoding="utf-8")
    # Explicit nonsecret environment: no ambient credentials or host config.
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(base),
        "TMPDIR": str(base),
        "LD_LIBRARY_PATH": f"{prefix}/usr/lib/rspamd:{prefix}/usr/lib/x86_64-linux-gnu",
        "LUALIBDIR": f"{prefix}/usr/share/rspamd/lualib",
        "RSPAMD_LIBDIR": f"{prefix}/usr/lib/rspamd",
        "RULESDIR": f"{prefix}/usr/share/rspamd/rules",
        "SHAREDIR": f"{prefix}/usr/share/rspamd",
        **{
            key: str(base)
            for key in ("CONFDIR", "LOCAL_CONFDIR", "DBDIR", "RUNDIR", "LOGDIR")
        },
    }
    version = subprocess.check_output(
        [str(prefix / "usr/bin/rspamd"), "--version"],
        env=env,
        text=True,
        timeout=10,
    )
    print(version.splitlines()[0], flush=True)
    modes = ("inline", "autoload") if args.mode == "all" else (args.mode,)
    for mode in modes:
        for name, option, valid in CASES:
            case = StartupCase(mode, name, option, valid)
            try:
                run_case(base, prefix, env, case, args.mutation)
            except (RuntimeError, OSError, subprocess.SubprocessError):
                print_failure_logs(base / f"{case.mode}-{case.name}")
                raise
    print("PASS: real Rspamd policy startup checks", flush=True)


if __name__ == "__main__":
    main()
