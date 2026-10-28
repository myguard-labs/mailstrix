"""Exercise scripts/elf-hardening.py, its workflow wiring and the build flags."""

import importlib.util
import io
import re
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/elf-hardening.py"
WORKFLOW = ROOT / ".github/workflows/build-binaries.yml"
DOCKERFILE = ROOT / "docker/Dockerfile"
RELEASE_DOCKERFILE = ROOT / "docker/Dockerfile.release"

spec = importlib.util.spec_from_file_location("elf_hardening", SCRIPT)
assert spec is not None and spec.loader is not None
eh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eh)

PT_INTERP = 3


def make_elf(
    *,
    e_type=eh.ET_DYN,
    relro=True,
    stack_flags=6,
    dyn=((eh.DT_FLAGS, eh.DF_BIND_NOW), (eh.DT_FLAGS_1, eh.DF_1_NOW | eh.DF_1_PIE)),
    imports=("__stack_chk_fail", "__memcpy_chk", "memcpy"),
    defined=("main",),
    dynamic=True,
    terminate=True,
    interp=True,
) -> bytes:
    """Build a minimal ELF64 LE image with program headers, .dynamic and .dynsym."""
    phdrs = [(PT_INTERP, 4)] if interp else []
    if stack_flags is not None:
        phdrs.append((eh.PT_GNU_STACK, stack_flags))
    if relro:
        phdrs.append((eh.PT_GNU_RELRO, 4))
    if dynamic:
        phdrs.append((eh.PT_DYNAMIC, 6))
    phoff = 64
    dyn_off = phoff + 56 * len(phdrs)
    tail = ((eh.DT_NULL, 0),) if terminate else ()
    dynamic = b"".join(struct.pack("<qQ", t, v) for t, v in (*dyn, *tail))
    names = [*imports, *defined]
    dynstr = b"\0"
    name_off = {}
    for name in names:
        name_off[name] = len(dynstr)
        dynstr += name.encode() + b"\0"
    str_off = dyn_off + len(dynamic)
    sym_off = str_off + len(dynstr)
    syms = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    for name in imports:
        syms += struct.pack("<IBBHQQ", name_off[name], 0x12, 0, 0, 0, 0)
    for name in defined:
        syms += struct.pack("<IBBHQQ", name_off[name], 0x12, 0, 14, 0x1000, 8)
    shoff = sym_off + len(syms)
    shdrs = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, str_off, len(dynstr), 0, 0, 1, 0)
    shdrs += struct.pack(
        "<IIQQQQIIQQ", 0, eh.SHT_DYNSYM, 0, 0, sym_off, len(syms), 1, 1, 8, 24
    )
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header += struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,
        62,
        1,
        0x1000,
        phoff,
        shoff,
        0,
        64,
        56,
        len(phdrs),
        64,
        3,
        0,
    )
    body = b""
    for p_type, p_flags in phdrs:
        offset, size = (dyn_off, len(dynamic)) if p_type == eh.PT_DYNAMIC else (0, 0)
        body += struct.pack("<IIQQQQQQ", p_type, p_flags, offset, 0, 0, size, size, 8)
    return header + body + dynamic + dynstr + syms + shdrs


class Workdir(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def run_main(self, *paths) -> tuple:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = eh.main([str(p) for p in paths])
        return status, out.getvalue(), err.getvalue()


class InspectTest(Workdir):
    def test_positive_hardened_fixture_passes_every_policy(self) -> None:
        for name in ("strixd", "yarac-linux-arm64"):
            with self.subTest(name=name):
                self.assertEqual(eh.check(self.write(name, make_elf())), [])

    def test_positive_static_fixture_passes_client_policy(self) -> None:
        # What a CGO_ENABLED=0 Go build looks like: no PT_INTERP, no .dynamic.
        static = make_elf(interp=False, dynamic=False, e_type=2, dyn=())
        for name in ("strix-scan", "strix-milter-linux-amd64"):
            with self.subTest(name=name):
                self.assertEqual(eh.check(self.write(name, static)), [])
        self.assertTrue(eh.inspect(static)["static"])
        self.assertFalse(eh.inspect(make_elf())["static"])

    def test_negative_dynamic_client_fails_static_policy(self) -> None:
        pie = make_elf()  # dynamic PIE: has PT_INTERP
        needed = make_elf(interp=False, dyn=((eh.DT_NEEDED, 1),))
        for label, data in {"interp": pie, "needed": needed}.items():
            for name in ("strix-scan", "strix-milter-linux-arm64"):
                with self.subTest(case=label, name=name):
                    self.assertEqual(eh.check(self.write(name, data)), ["static"])

    def test_negative_executable_stack_fails_client_policy(self) -> None:
        bad = make_elf(interp=False, dynamic=False, stack_flags=7)
        self.assertEqual(eh.check(self.write("strix-scan", bad)), ["nx"])
        none = make_elf(interp=False, dynamic=False, stack_flags=None)
        self.assertEqual(eh.check(self.write("strix-milter", none)), ["nx"])

    def test_client_policy_does_not_require_pie_or_relro(self) -> None:
        self.assertEqual(eh.STATIC_CHECKS, ("static", "nx"))
        plain = make_elf(
            interp=False, dynamic=False, relro=False, e_type=2, imports=("memcpy",)
        )
        self.assertEqual(eh.check(self.write("strix-scan", plain)), [])

    def test_facts_of_hardened_fixture(self) -> None:
        facts = eh.inspect(make_elf())
        self.assertTrue(
            facts["pie"] and facts["relro"] and facts["bindnow"] and facts["nx"]
        )
        self.assertTrue(facts["canary"])
        # memcpy is not fortified; __stack_chk_fail is the canary, not FORTIFY.
        self.assertEqual(facts["fortify"], ["__memcpy_chk"])

    def test_negative_unhardened_fixture_reports_every_gap(self) -> None:
        bad = make_elf(
            e_type=2,
            relro=False,
            stack_flags=7,
            dyn=(),
            imports=("memcpy",),
            defined=(),
        )
        self.assertEqual(eh.check(self.write("strixd", bad)), list(eh.C_CHECKS))
        # A dynamic non-PIE client with an executable stack fails both its checks.
        self.assertEqual(
            eh.check(self.write("strix-scan", bad)), list(eh.STATIC_CHECKS)
        )

    def test_each_check_fails_alone(self) -> None:
        cases = {
            "pie": make_elf(e_type=2),
            "relro": make_elf(relro=False),
            "bindnow": make_elf(dyn=((eh.DT_FLAGS_1, eh.DF_1_PIE),)),
            "canary": make_elf(imports=("__memcpy_chk",)),
            "fortify": make_elf(
                imports=("__stack_chk_fail", "__stack_chk_guard", "memcpy")
            ),
        }
        for expected, data in cases.items():
            with self.subTest(check=expected):
                self.assertEqual(eh.check(self.write("strixd", data)), [expected])

    def test_nx_needs_a_non_executable_gnu_stack(self) -> None:
        self.assertEqual(
            eh.check(self.write("strixd", make_elf(stack_flags=7))), ["nx"]
        )
        self.assertEqual(
            eh.check(self.write("strixd", make_elf(stack_flags=None))), ["nx"]
        )

    def test_shared_library_is_not_a_pie(self) -> None:
        lib = make_elf(dyn=((eh.DT_FLAGS, eh.DF_BIND_NOW),))
        self.assertEqual(eh.check(self.write("strixd", lib)), ["pie"])

    def test_every_bind_now_spelling_counts(self) -> None:
        for dyn in (
            ((eh.DT_BIND_NOW, 0), (eh.DT_FLAGS_1, eh.DF_1_PIE)),
            ((eh.DT_FLAGS, eh.DF_BIND_NOW), (eh.DT_FLAGS_1, eh.DF_1_PIE)),
            ((eh.DT_FLAGS_1, eh.DF_1_PIE | eh.DF_1_NOW),),
        ):
            with self.subTest(dyn=dyn):
                self.assertTrue(eh.inspect(make_elf(dyn=dyn))["bindnow"])

    def test_entries_after_dt_null_are_ignored(self) -> None:
        dyn = ((eh.DT_FLAGS_1, eh.DF_1_PIE), (eh.DT_NULL, 0), (eh.DT_BIND_NOW, 0))
        self.assertFalse(eh.inspect(make_elf(dyn=dyn))["bindnow"])

    def test_unterminated_dynamic_table_is_read_to_its_end(self) -> None:
        dyn = ((eh.DT_FLAGS_1, eh.DF_1_PIE), (eh.DT_BIND_NOW, 0))
        self.assertTrue(eh.inspect(make_elf(dyn=dyn, terminate=False))["bindnow"])

    def test_static_binary_without_dynamic_segment(self) -> None:
        facts = eh.inspect(make_elf(dynamic=False, interp=False))
        self.assertTrue(facts["static"])
        self.assertFalse(facts["pie"] or facts["bindnow"])
        self.assertTrue(facts["relro"] and facts["nx"])

    def test_sectionless_static_client_is_checked_not_crashed(self) -> None:
        # e_shoff, e_shentsize and e_shnum may all be 0 when there is no
        # section header table; the program-header checks must still run.
        image = bytearray(make_elf(interp=False, dynamic=False, e_type=2, dyn=()))
        struct.pack_into("<Q", image, 40, 0)
        struct.pack_into("<HH", image, 58, 0, 0)
        self.assertEqual(eh.check(self.write("strix-scan", bytes(image))), [])
        struct.pack_into("<I", image, 64 + 4, 7)  # PT_GNU_STACK now RWX
        self.assertEqual(eh.check(self.write("strix-milter", bytes(image))), ["nx"])

    def test_defined_chk_symbol_is_not_an_import(self) -> None:
        facts = eh.inspect(
            make_elf(imports=("__stack_chk_fail",), defined=("__memcpy_chk",))
        )
        self.assertEqual(facts["fortify"], [])


class MalformedTest(Workdir):
    def test_malformed_inputs_raise(self) -> None:
        good = make_elf()
        cases = {
            "empty": b"",
            "not elf": b"#!/bin/sh\necho hi\n" + bytes(64),
            "short header": good[:40],
            "32-bit": good[:4] + b"\x01" + good[5:],
            "big-endian": good[:5] + b"\x02" + good[6:],
            "phdrs past eof": good[:100],
            "sections past eof": good[:-10],
            "tiny phentsize": good[:54] + struct.pack("<H", 8) + good[56:],
        }
        for label, data in cases.items():
            with self.subTest(case=label), self.assertRaises(eh.ElfError):
                eh.inspect(data)

    def test_out_of_range_read_raises(self) -> None:
        with self.assertRaises(eh.ElfError):
            eh._unpack("<Q", b"1234", 0)
        with self.assertRaises(eh.ElfError):
            eh._unpack("<B", b"1234", -1)

    def string_table_header(self, data: bytearray) -> int:
        shoff = struct.unpack_from("<Q", data, 40)[0]
        return shoff + 64

    def test_string_table_past_eof_raises(self) -> None:
        data = bytearray(make_elf())
        struct.pack_into("<Q", data, self.string_table_header(data) + 32, len(data))
        with self.assertRaises(eh.ElfError):
            eh.inspect(bytes(data))

    def test_unterminated_symbol_name_raises(self) -> None:
        data = bytearray(make_elf(imports=("__stack_chk_fail",), defined=()))
        hdr = self.string_table_header(data)
        size = struct.unpack_from("<Q", data, hdr + 32)[0]
        struct.pack_into("<Q", data, hdr + 32, size - 1)
        with self.assertRaises(eh.ElfError):
            eh.inspect(bytes(data))

    def test_bad_symbol_name_offset_raises(self) -> None:
        data = bytearray(make_elf())
        shoff = struct.unpack_from("<Q", data, 40)[0]
        sym_off = struct.unpack_from("<Q", data, shoff + 2 * 64 + 24)[0]
        struct.pack_into("<I", data, sym_off + 24, 0xFFFF)
        with self.assertRaises(eh.ElfError):
            eh.inspect(bytes(data))

    def test_missing_string_table_link_raises(self) -> None:
        data = bytearray(make_elf())
        shoff = struct.unpack_from("<Q", data, 40)[0]
        struct.pack_into("<I", data, shoff + 2 * 64 + 40, 9)
        with self.assertRaises(eh.ElfError):
            eh.inspect(bytes(data))

    def test_main_reports_missing_unknown_and_malformed_as_errors(self) -> None:
        missing = self.dir / "strixd"
        unknown = self.write("other-tool", make_elf())
        broken = self.write("strix-scan", b"\x7fELF")
        for path in (missing, unknown, broken):
            with self.subTest(path=path.name):
                status, out, err = self.run_main(path)
                self.assertEqual(status, 2)
                self.assertEqual(out, "")
                self.assertIn("error:", err)

    def test_main_usage(self) -> None:
        for argv in ([], ["--help"]):
            with self.subTest(argv=argv):
                err = io.StringIO()
                with redirect_stderr(err):
                    self.assertEqual(eh.main(argv), 2)
                self.assertIn("Usage:", err.getvalue())

    def test_main_status_and_messages(self) -> None:
        good = self.write("strixd-linux-amd64", make_elf())
        bad = self.write("yarac", make_elf(relro=False))
        status, out, err = self.run_main(good)
        self.assertEqual((status, err), (0, ""))
        self.assertIn(
            "strixd-linux-amd64: ok (pie relro bindnow nx canary fortify)", out
        )
        status, out, err = self.run_main(good, bad)
        self.assertEqual(status, 1)
        self.assertIn("yarac: FAIL: missing relro", err)
        status, _, _ = self.run_main(bad, self.dir / "strix-milter")
        self.assertEqual(status, 2)

    def test_main_guard_exits_with_status(self) -> None:
        good = self.write("strixd", make_elf())
        argv = [str(SCRIPT), str(good)]
        with (
            mock.patch.object(sys, "argv", argv),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 0)

    def test_cli_entry_point(self) -> None:
        good = self.write("strix-milter", make_elf(interp=False, dynamic=False, dyn=()))
        proc = subprocess.run(
            ["python3", "-I", str(SCRIPT), str(good)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("ok (static nx)", proc.stdout)


@unittest.skipUnless(shutil.which("gcc"), "gcc not installed")
class RealToolchainTest(Workdir):
    """Cross-check the parser against binaries from the host C toolchain."""

    SOURCE = (
        "#include <stdio.h>\n#include <string.h>\n"
        "int main(int argc, char **argv) { char b[16];"
        ' strcpy(b, argc > 5 ? argv[1] : "x"); puts(b); return 0; }\n'
    )

    def build(self, name: str, *flags: str) -> Path:
        src = self.write("t.c", self.SOURCE.encode())
        out = self.dir / name
        subprocess.run(["gcc", "-O2", *flags, "-o", str(out), str(src)], check=True)
        return out

    def test_hardened_c_binary_passes(self) -> None:
        out = self.build(
            "yarac",
            "-fPIE",
            "-pie",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=2",
            "-Wl,-z,relro",
            "-Wl,-z,now",
        )
        self.assertEqual(eh.check(out), [])

    def test_unhardened_c_binary_fails(self) -> None:
        out = self.build(
            "yarac",
            "-fno-pie",
            "-no-pie",
            "-fno-stack-protector",
            "-U_FORTIFY_SOURCE",
            "-Wl,-z,norelro",
            "-Wl,-z,lazy",
        )
        self.assertEqual(
            eh.check(out), ["pie", "relro", "bindnow", "canary", "fortify"]
        )


def build_stage(text: str) -> str:
    match = re.search(
        r"^FROM [^\n]* AS build\b.*?(?=^FROM |\Z)", text, re.DOTALL | re.MULTILINE
    )
    if not match:
        raise AssertionError("no build stage in Dockerfile")
    return match.group(0).replace("\\\n", " ")


def shipped_builds(text: str) -> dict:
    """Map each /out/<binary> go build command in the build stage to its text."""
    cmds = [c for c in build_stage(text).split("&&") if re.search(r"\bgo build\b", c)]
    out = {}
    for cmd in cmds:
        match = re.search(r"-o\s+/out/(\S+)", cmd)
        if match:
            out[match.group(1)] = cmd
    return out


def unhardened_builds(text: str) -> list:
    builds = shipped_builds(text)
    if set(builds) != {"strixd", "strix-scan", "strix-milter"}:
        raise AssertionError(f"unexpected shipped go builds: {sorted(builds)}")
    bad = []
    for name, cmd in builds.items():
        if name == "strixd":
            need = [
                "-buildmode=pie",
                "-trimpath",
                "-Wl,-z,relro",
                "-Wl,-z,now",
                'CGO_CFLAGS="-O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2"',
            ]
            forbid = []
        else:
            # Clients stay static non-PIE: a dynamic PIE breaks musl/Alpine hosts.
            need = ["CGO_ENABLED=0", "-trimpath"]
            forbid = ["-buildmode", "-bindnow", "-linkmode"]
        bad += [f"{name}: {flag}" for flag in need if flag not in cmd]
        bad += [f"{name}: must not use {flag}" for flag in forbid if flag in cmd]
    return bad


YARA_CFLAGS = "-fstack-protector-strong -D_FORTIFY_SOURCE=2"
YARA_LDFLAGS = "-Wl,-z,relro -Wl,-z,now"


def unhardened_yara(text: str) -> list:
    cflags = re.findall(r'^\s*CFLAGS="([^"]*)"', text, re.MULTILINE)
    ldflags = re.findall(r'^\s*LDFLAGS="([^"]*)"', text, re.MULTILINE)
    if len(cflags) != 1 or len(ldflags) != 1:
        raise AssertionError("expected one libyara CFLAGS and LDFLAGS assignment")
    bad = [] if YARA_CFLAGS in cflags[0] else [f"CFLAGS lacks {YARA_CFLAGS}"]
    return bad + (
        [] if YARA_LDFLAGS in ldflags[0] else [f"LDFLAGS lacks {YARA_LDFLAGS}"]
    )


class BuildFlagsTest(unittest.TestCase):
    def test_release_go_builds_are_hardened(self) -> None:
        self.assertEqual(unhardened_builds(DOCKERFILE.read_text()), [])

    def test_both_libyara_builds_are_hardened(self) -> None:
        for path in (DOCKERFILE, RELEASE_DOCKERFILE):
            with self.subTest(path=path.name):
                self.assertEqual(unhardened_yara(path.read_text()), [])

    def test_negative_controls_detect_dropped_flags(self) -> None:
        text = DOCKERFILE.read_text()
        dropped = {
            "-buildmode=pie -tags": "-tags",
            "-Wl,-z,relro -Wl,-z,now'": "-Wl,-z,relro'",
            ' -D_FORTIFY_SOURCE=2" \\\n       go build': '" \\\n       go build',
        }
        for old, new in dropped.items():
            with self.subTest(old=old):
                self.assertIn(old, text)
                self.assertNotEqual(unhardened_builds(text.replace(old, new, 1)), [])
        for old, new in {
            "CGO_ENABLED=0 go build -trimpath \\": "CGO_ENABLED=0 go build -trimpath -buildmode=pie \\",
            '-s -w -X main.version=${VERSION}" \\\n        -o /out/strix-scan': '-s -w -bindnow -X main.version=${VERSION}" \\\n        -o /out/strix-scan',
        }.items():
            with self.subTest(client_drift=old):
                self.assertIn(old, text)
                self.assertNotEqual(unhardened_builds(text.replace(old, new, 1)), [])
        yara = text.replace(" -fstack-protector-strong", "", 1)
        self.assertEqual(unhardened_yara(yara), [f"CFLAGS lacks {YARA_CFLAGS}"])
        yara = text.replace(' -Wl,-z,now"', '"', 1)
        self.assertEqual(unhardened_yara(yara), [f"LDFLAGS lacks {YARA_LDFLAGS}"])

    def test_malformed_dockerfiles_are_rejected(self) -> None:
        with self.assertRaises(AssertionError):
            unhardened_builds("FROM x AS other\nRUN go build -o /out/strixd .\n")
        with self.assertRaises(AssertionError):
            unhardened_builds("FROM x AS build\nRUN go build -o /out/strixd .\n")
        with self.assertRaises(AssertionError):
            unhardened_yara("FROM x\n")


class WorkflowWiringTest(unittest.TestCase):
    def test_build_binaries_checks_every_shipped_binary_before_upload(self) -> None:
        text = WORKFLOW.read_text()
        check = text.index("python3 -B scripts/elf-hardening.py")
        self.assertLess(text.index("docker buildx build"), check)
        self.assertLess(check, text.index("upload-artifact"))
        step = text[check : text.index("upload-artifact")]
        for name in ("strixd", "strix-scan", "strix-milter", "yarac"):
            self.assertIn(f'"out/{name}-linux-${{ARCH}}"', step)
        self.assertNotIn("continue-on-error", step)

    def test_every_policy_matches_a_shipped_asset(self) -> None:
        self.assertEqual(
            set(eh.POLICIES), {"strixd", "yarac", "strix-scan", "strix-milter"}
        )


if __name__ == "__main__":
    unittest.main()
