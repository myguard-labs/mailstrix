#!/usr/bin/env python3
"""Fail when a shipped release binary loses its ELF hardening.

Usage: elf-hardening.py FILE...
Each FILE is named like a release asset (strixd, strixd-linux-amd64, ...); the
name selects the policy. Checks read the ELF structures directly (stdlib only),
so the guard needs no binutils or checksec on the runner:

  pie      ET_DYN with DF_1_PIE (an executable, not a shared library)
  relro    a PT_GNU_RELRO segment
  bindnow  DT_BIND_NOW, DF_BIND_NOW or DF_1_NOW (with relro: full RELRO)
  nx       a PT_GNU_STACK segment without PF_X
  static   no PT_INTERP and no DT_NEEDED (statically linked, runs on any libc)
  canary   __stack_chk_fail imported from libc (C code only)
  fortify  at least one fortified __*_chk import (C code only)

strixd and yarac contain C (libyara, cgo), so the pie/relro/bindnow/nx/canary/
fortify checks apply. strix-scan and strix-milter are pure Go and deliberately
static non-PIE, so the documented "static binary you can drop on any mail host"
contract holds (a dynamic PIE needs a glibc loader and breaks musl/Alpine
hosts). They are checked for static and nx only: pure Go has no C memory-safety
surface, and PIE/RELRO/BIND_NOW/canary/FORTIFY are not required of them.
Exit status: 0 all pass, 1 a hardening check failed, 2 usage error, unknown
binary name, missing file or malformed/unsupported ELF.
"""

import re
import struct
import sys
from pathlib import Path

C_CHECKS = ("pie", "relro", "bindnow", "nx", "canary", "fortify")
STATIC_CHECKS = ("static", "nx")
POLICIES = {
    "strixd": C_CHECKS,
    "yarac": C_CHECKS,
    "strix-scan": STATIC_CHECKS,
    "strix-milter": STATIC_CHECKS,
}
ASSET_SUFFIX = re.compile(r"-linux-(?:amd64|arm64)$")
FORTIFIED = re.compile(r"^__\w+_chk$")
NOT_FORTIFY = {"__stack_chk_fail", "__stack_chk_guard"}

ET_DYN = 3
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 1
DT_NULL = 0
DT_NEEDED = 1
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000
SHT_DYNSYM = 11
SHN_UNDEF = 0


class ElfError(Exception):
    """The file is not a readable 64-bit little-endian ELF image."""


def _unpack(fmt: str, data: bytes, offset: int) -> tuple:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ElfError(f"truncated at offset {offset:#x}")
    return struct.unpack_from(fmt, data, offset)


def _table(data: bytes, offset: int, entsize: int, count: int, minsize: int) -> range:
    if not count:  # an absent table may legally carry entsize 0
        return range(0)
    if entsize < minsize:
        raise ElfError(f"entry size {entsize} below {minsize}")
    if offset < 0 or offset + entsize * count > len(data):
        raise ElfError(f"table at {offset:#x} exceeds the file")
    return range(offset, offset + entsize * count, entsize)


def _cstr(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise ElfError(f"string offset {offset:#x} outside the table")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ElfError("unterminated string")
    return data[offset:end].decode("ascii", "replace")


def inspect(data: bytes) -> dict:
    """Return the hardening facts of an ELF64 little-endian image."""
    if data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    if len(data) < 64:
        raise ElfError("truncated ELF header")
    if data[4] != 2 or data[5] != 1:
        raise ElfError("unsupported ELF: only 64-bit little-endian is checked")
    (e_type,) = _unpack("<H", data, 16)
    e_phoff, e_shoff = _unpack("<QQ", data, 32)
    e_phentsize, e_phnum, e_shentsize, e_shnum = _unpack("<HHHH", data, 54)

    relro = nx = False
    gnu_stack = interp = False
    dynamic = None
    for off in _table(data, e_phoff, e_phentsize, e_phnum, 56):
        p_type, p_flags, p_offset = _unpack("<IIQ", data, off)
        (p_filesz,) = _unpack("<Q", data, off + 32)
        if p_type == PT_GNU_RELRO:
            relro = True
        elif p_type == PT_GNU_STACK:
            gnu_stack = True
            nx = not p_flags & PF_X
        elif p_type == PT_INTERP:
            interp = True
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)

    flags = flags_1 = 0
    bind_now = needed = False
    if dynamic is not None:
        offset, size = dynamic
        for off in _table(data, offset, 16, size // 16, 16):
            tag, val = _unpack("<qQ", data, off)
            if tag == DT_NULL:
                break
            if tag == DT_FLAGS:
                flags = val
            elif tag == DT_FLAGS_1:
                flags_1 = val
            elif tag == DT_BIND_NOW:
                bind_now = True
            elif tag == DT_NEEDED:
                needed = True

    imports = set()
    sections = list(_table(data, e_shoff, e_shentsize, e_shnum, 64))
    for off in sections:
        _, sh_type = _unpack("<II", data, off)
        if sh_type != SHT_DYNSYM:
            continue
        sh_offset, sh_size, sh_link = _unpack("<QQI", data, off + 24)
        (sh_entsize,) = _unpack("<Q", data, off + 56)
        if sh_link >= len(sections):
            raise ElfError("dynamic symbol table links a missing string table")
        str_off, str_size = _unpack("<QQ", data, sections[sh_link] + 24)
        if str_off + str_size > len(data):
            raise ElfError("dynamic string table exceeds the file")
        strtab = data[str_off : str_off + str_size]
        count = sh_size // sh_entsize if sh_entsize else 0
        for sym in _table(data, sh_offset, sh_entsize, count, 24):
            st_name, _, _, st_shndx = _unpack("<IBBH", data, sym)
            if st_name and st_shndx == SHN_UNDEF:
                imports.add(_cstr(strtab, st_name))

    return {
        "pie": e_type == ET_DYN and bool(flags_1 & DF_1_PIE),
        "relro": relro,
        "bindnow": bind_now or bool(flags & DF_BIND_NOW) or bool(flags_1 & DF_1_NOW),
        "nx": gnu_stack and nx,
        "static": not interp and not needed,
        "canary": "__stack_chk_fail" in imports,
        "fortify": sorted(
            name
            for name in imports
            if FORTIFIED.match(name) and name not in NOT_FORTIFY
        ),
    }


def policy_for(path: Path) -> tuple:
    name = ASSET_SUFFIX.sub("", path.name)
    if name not in POLICIES:
        raise KeyError(f"no hardening policy for {path.name}")
    return POLICIES[name]


def check(path: Path) -> list:
    """Return the failed checks for one binary; raise on unusable input."""
    checks = policy_for(path)
    facts = inspect(path.read_bytes())
    return [name for name in checks if not facts[name]]


def main(argv: list) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    status = 0
    for arg in argv:
        path = Path(arg)
        try:
            failed = check(path)
        except (KeyError, OSError, ElfError) as exc:
            reason = exc.args[0] if isinstance(exc, KeyError) else exc
            print(f"elf-hardening: {arg}: error: {reason}", file=sys.stderr)
            status = max(status, 2)
            continue
        if failed:
            print(
                f"elf-hardening: {arg}: FAIL: missing {' '.join(failed)}",
                file=sys.stderr,
            )
            status = max(status, 1)
        else:
            print(f"elf-hardening: {arg}: ok ({' '.join(policy_for(path))})")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
