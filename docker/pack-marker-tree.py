#!/usr/bin/env python3
"""Pack a verified rules export into the signed marker-tree archive.

usage: pack-marker-tree.py EXPORT_DIR OUTPUT.tar.gz

The archive contract is the client's extractor (extractMarkerTree and
markerTreeEntryName in internal/mailstrix/fetchrules_marker.go): a gzip tar that
contains only compiler-inputs/, marker-artifact/, libyara.version and
sources.json, directories and regular files only, within 1 GiB archive, 2 GiB
expanded tree and 131072 entries. This packer refuses anything the client would
refuse. The output is deterministic: entries sorted, mtime/uid/gid/mode fixed,
no gzip name or timestamp, so the same tree always yields the same bytes.
"""

import gzip
import os
import stat
import sys
import tarfile
from pathlib import Path

DIRS = ("compiler-inputs", "marker-artifact")
FILES = ("libyara.version", "sources.json")
REQUIRED = ("compiler-inputs", "marker-artifact", "libyara.version")
MAX_ARCHIVE = 1 << 30
MAX_TREE = 2 << 30
MAX_ENTRIES = 1 << 17


class PackError(Exception):
    pass


def walk(root):
    """Return sorted (relative name, is_dir, path) for the contract entries."""
    entries = []
    total = 0

    def add(path, name):
        nonlocal total
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            entries.append((name, True, path))
            for child in sorted(os.listdir(path)):
                add(path / child, name + "/" + child)
        elif stat.S_ISREG(mode):
            total += path.lstat().st_size
            entries.append((name, False, path))
        else:
            raise PackError(f"not a regular file or directory: {name}")
        if "\\" in name or "\x00" in name:
            raise PackError(f"invalid character in entry name: {name!r}")

    for name in REQUIRED:
        if not (root / name).exists() and not (root / name).is_symlink():
            raise PackError(f"missing required entry: {name}")
    for name in DIRS + FILES:
        path = root / name
        if not path.exists() and not path.is_symlink():
            continue
        is_dir = stat.S_ISDIR(path.lstat().st_mode)
        if is_dir != (name in DIRS):
            raise PackError(f"wrong type for entry: {name}")
        add(path, name)
    if len(entries) > MAX_ENTRIES:
        raise PackError(f"more than {MAX_ENTRIES} entries")
    if total > MAX_TREE:
        raise PackError(f"tree exceeds {MAX_TREE} bytes")
    return sorted(entries, key=lambda e: e[0])


def pack(root, output):
    entries = walk(root)
    tmp = output.with_name(output.name + ".tmp")
    with (
        open(tmp, "wb") as raw,
        gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
        ) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar,
    ):
        for name, is_dir, path in entries:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if is_dir:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.size = path.lstat().st_size
                with open(path, "rb") as handle:
                    tar.addfile(info, handle)
    if tmp.stat().st_size > MAX_ARCHIVE:
        tmp.unlink()
        raise PackError(f"archive exceeds {MAX_ARCHIVE} bytes")
    os.replace(tmp, output)


def main(argv):
    if len(argv) != 2:
        print(__doc__.split("\n\n", maxsplit=1)[0], file=sys.stderr)
        return 2
    try:
        pack(Path(argv[0]), Path(argv[1]))
    except (PackError, OSError) as error:
        print(f"pack-marker-tree: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
