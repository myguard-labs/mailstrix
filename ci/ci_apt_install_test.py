"""Behavior tests for .github/actions/go-setup/apt-install.sh (fake sudo/apt/dpkg)."""

import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/actions/go-setup/apt-install.sh"
ACTION = ROOT / ".github/actions/go-setup/action.yml"


class Fixture:
    """A PATH of stubs. `installed` is the dpkg view; apt behaviour is scripted
    as a per-call list of exit codes for `update` and `install` (last repeats)."""

    def __init__(self, installed=(), update=(0,), install=(0,)):
        self.tmp = tempfile.TemporaryDirectory()
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        self.log = Path(self.tmp.name) / "calls.log"
        self.log.touch()
        self.installed = installed
        self.update = update
        self.install = install
        self._stub(
            "sudo",
            'exec "$@"',
        )
        self._stub(
            "sleep",
            f'echo "sleep $1" >> {self.log}',
        )
        self._stub(
            "dpkg-query",
            "pkg=${@: -1}\n"
            + "".join(
                f'[ "$pkg" = "{p}" ] && {{ printf "install ok installed"; exit 0; }}\n'
                for p in installed
            )
            + "exit 1",
        )
        self._stub("apt-get", self._apt_body())

    def _apt_body(self):
        def seq(name, codes):
            cases = "\n".join(f"      {i}) rc={c} ;;" for i, c in enumerate(codes[:-1]))
            return textwrap.dedent(
                f"""\
                cnt={self.tmp.name}/{name}.count
                n=$(cat "$cnt" 2>/dev/null || echo 0)
                echo $((n+1)) > "$cnt"
                case $n in
                {cases}
                      *) rc={codes[-1]} ;;
                esac
                exit $rc"""
            )

        return (
            f'echo "apt-get $*" >> {self.log}\n'
            'for a in "$@"; do case "$a" in\n'
            f"  update) {seq('update', self.update)} ;;\n"
            f"  install) {seq('install', self.install)} ;;\n"
            "esac; done\nexit 0"
        )

    def _stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + body + "\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run(self, *pkgs, **env):
        e = dict(os.environ)
        e["PATH"] = f"{self.bin}:{e['PATH']}"
        e.update({"APT_BACKOFF": "1"}, **env)
        proc = subprocess.run(
            [str(SCRIPT), *pkgs],
            env=e,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return proc, self.log.read_text().splitlines()

    def close(self):
        self.tmp.cleanup()


class AptInstall(unittest.TestCase):
    def fixture(self, **kw):
        f = Fixture(**kw)
        self.addCleanup(f.close)
        return f

    def test_installs_missing_packages_once(self):
        f = self.fixture()
        p, calls = f.run("libyara-dev", "clang")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len([c for c in calls if " update" in c]), 1)
        installs = [c for c in calls if " install " in c]
        self.assertEqual(len(installs), 1)
        self.assertIn("--no-install-recommends libyara-dev clang", installs[0])
        self.assertIn("Acquire::Retries=3", installs[0])
        self.assertFalse([c for c in calls if c.startswith("sleep")])

    def test_already_installed_skips_apt_entirely(self):
        f = self.fixture(installed=("libyara-dev", "clang"), update=(100,))
        p, calls = f.run("libyara-dev", "clang")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(calls, [])
        self.assertIn("already installed", p.stdout)

    def test_partially_installed_installs_only_missing(self):
        f = self.fixture(installed=("libyara-dev",))
        p, calls = f.run("libyara-dev", "clang")
        self.assertEqual(p.returncode, 0, p.stderr)
        installs = [c for c in calls if " install " in c]
        self.assertTrue(installs[0].endswith("--no-install-recommends clang"))

    def test_transient_update_failure_then_success(self):
        f = self.fixture(update=(100, 100, 0))
        p, calls = f.run("libyara-dev")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len([c for c in calls if " update" in c]), 3)
        self.assertEqual(
            [c for c in calls if c.startswith("sleep")], ["sleep 1", "sleep 2"]
        )

    def test_transient_install_failure_then_success(self):
        f = self.fixture(install=(100, 0))
        p, calls = f.run("libyara-dev")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len([c for c in calls if " install " in c]), 2)

    def test_persistent_failure_still_fails_and_is_bounded(self):
        f = self.fixture(update=(100,))
        p, calls = f.run("libyara-dev", APT_ATTEMPTS="3")
        self.assertEqual(p.returncode, 100)
        self.assertEqual(len([c for c in calls if " update" in c]), 3)
        self.assertEqual(len([c for c in calls if c.startswith("sleep")]), 2)
        self.assertFalse([c for c in calls if " install " in c])
        self.assertIn("giving up after 3 attempts", p.stderr)

    def test_persistent_install_failure_propagates_exit_code(self):
        f = self.fixture(install=(7,))
        p, _ = f.run("libyara-dev", APT_ATTEMPTS="2")
        self.assertEqual(p.returncode, 7)

    def test_malformed_package_names_rejected_without_apt(self):
        for bad in ("Bad Name", "-oFoo=bar", "a;rm", "$(x)", "", "UPPER", "pkg/evil"):
            with self.subTest(pkg=bad):
                f = self.fixture()
                p, calls = f.run("libyara-dev", bad)
                self.assertEqual(p.returncode, 2)
                self.assertEqual(calls, [])

    def test_no_packages_and_bad_tunables_rejected(self):
        f = self.fixture()
        self.assertEqual(f.run()[0].returncode, 2)
        for var, val in (
            ("APT_ATTEMPTS", "0"),
            ("APT_ATTEMPTS", "x"),
            ("APT_BACKOFF", "-1"),
        ):
            with self.subTest(var=var, val=val):
                p, calls = f.run("libyara-dev", **{var: val})
                self.assertEqual(p.returncode, 2)
                self.assertEqual(calls, [])

    def test_action_delegates_to_script_without_adding_sources(self):
        text = ACTION.read_text()
        self.assertIn("apt-install.sh", text)
        self.assertIn("libyara-dev $EXTRA_PACKAGES", text)
        self.assertNotIn("sudo apt-get", text)
        self.assertNotIn("add-apt-repository", SCRIPT.read_text())
        self.assertNotIn("sources.list", SCRIPT.read_text())
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
