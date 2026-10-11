#!/usr/bin/env python3
"""Materialize complete verified compiler graphs in a fixed export envelope.

Hashes bind transfer integrity; they do not authenticate a publisher. Source
snapshots and failed staging directories are retained. Only a fully verified
new destination is published, by a same-filesystem atomic no-replace rename.
"""

import ctypes
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "capture_inputs", Path(__file__).with_name("capture-compiler-inputs.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("capture helper loader unavailable")
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)
SLOTS = {"main": "compiled.yac", "local": "local.yac"}
METADATA = ("libyara.version", "sources.json")


class ExportError(Exception):
    """Absent, malformed or inconsistent export evidence."""


def publish(stage, destination):
    """Linux renameat2 rejects every competing entry atomically, without fallback.

    Failed publication retains our staging directory for diagnosis. Constants
    and signature follow Linux fs.h and glibc stdio.h/fcntl.h.
    """
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:
        raise ExportError("atomic no-replace publication unavailable") from error
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    # AT_FDCWD = -100; RENAME_NOREPLACE = 1. No check-and-rename emulation.
    if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(destination))


def require(condition, message):
    if not condition:
        raise ExportError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(value):
    raise ExportError("non-finite JSON number: " + value)


def load(path):
    return json.loads(
        path.read_text(), object_pairs_hook=pairs, parse_constant=invalid_constant
    )


def fingerprint(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), f"not a regular file: {path}")
    return path.read_bytes()


def inventory(root):
    require(stat.S_ISDIR(root.lstat().st_mode), f"not a directory: {root}")
    result = {}
    for path in sorted(root.iterdir()):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            for name, entry in inventory(path).items():
                result[path.name + "/" + name] = entry
        else:
            result[path.name] = fingerprint(regular(path))
    return result


def graph_state(root):
    inventory(root)  # Reject symlinks/special files before native predicate reads.
    state = load(root / "manifest.json")
    capture.verify(root, state)
    count, complete = capture.read_cursor(root)
    require(complete and count == len(state["validations"]), "graph cursor mismatch")
    expected = {f"validation-{i}.json" for i in range(count)} | {"final.json"}
    require(
        {p.name for p in (root / "invocations").iterdir()} == expected,
        "graph invocation inventory mismatch",
    )
    for item in (root / "objects").iterdir():
        require(
            item.name == fingerprint(regular(item))["sha256"],
            "graph object identity mismatch",
        )
    invocations = [("validation", i, v) for i, v in enumerate(state["validations"])]
    invocations.append(("final", count, state["final"]))
    for phase, i, invocation in invocations:
        for suffix, field in (("native", "native_trace"), ("stderr", "stderr")):
            require(
                fingerprint(regular(root / f"{phase}-{i}.{suffix}"))
                == invocation[field],
                "raw invocation evidence mismatch",
            )
    for i, invocation in enumerate(state["validations"]):
        record = load(root / "invocations" / f"validation-{i}.json")
        require(
            record == {"phase": "validation", "index": i, "invocation": invocation},
            "graph invocation metadata mismatch",
        )
    require(
        load(root / "invocations/final.json")
        == {"phase": "final", "index": count, "invocation": state["final"]},
        "graph final metadata mismatch",
    )
    return state


def keys(value, expected, message):
    require(isinstance(value, dict) and set(value) == set(expected), message)


def file_entries(entries):
    require(isinstance(entries, dict), "file inventory must be an object")
    for entry in entries.values():
        keys(entry, ("sha256", "size"), "file fingerprint fields mismatch")
        require(
            isinstance(entry["sha256"], str)
            and len(entry["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in entry["sha256"])
            and type(entry["size"]) is int
            and entry["size"] >= 0,
            "file fingerprint type mismatch",
        )


def verify(root):
    files = inventory(root)
    index = load(root / "compiler-inputs/index.json")
    keys(index, ("schema", "artifacts", "metadata"), "index fields mismatch")
    require(
        type(index["schema"]) is int and index["schema"] == 1, "index schema mismatch"
    )
    keys(index["artifacts"], SLOTS, "artifact slots mismatch")
    keys(index["metadata"], METADATA, "metadata slots mismatch")
    file_entries(index["metadata"])
    for name in METADATA:
        require(
            fingerprint(regular(root / name)) == index["metadata"][name],
            "export metadata hash mismatch: " + name,
        )
    version = regular(root / "libyara.version").decode().strip()
    sources = load(root / "sources.json")
    # fetch-rules.sh emits an array consumed as []RuleSource (fetchrules.go).
    # Unknown fields remain allowed, as in the existing JSON consumer.
    require(isinstance(sources, list), "sources metadata must be an array")
    for entry in sources:
        require(isinstance(entry, dict), "source entry must be an object")
        for field in ("name", "repo", "license", "ref", "set"):
            require(
                entry.get(field) is None or isinstance(entry[field], str),
                "source string field malformed: " + field,
            )
    expected = set(SLOTS.values()) | set(METADATA) | {"compiler-inputs/index.json"}
    for slot, name in SLOTS.items():
        binding = index["artifacts"][slot]
        keys(
            binding,
            ("compiled", "graph", "compiled_sha256", "versions", "files"),
            "artifact fields mismatch: " + slot,
        )
        require(
            binding["compiled"] == name
            and binding["graph"] == "compiler-inputs/" + slot,
            "artifact slot mismatch: " + slot,
        )
        graph = root / "compiler-inputs" / slot
        actual = inventory(graph)
        file_entries(binding["files"])
        require(actual == binding["files"], "graph inventory/hash mismatch: " + slot)
        state = graph_state(graph)
        require(
            Path(state["output"]).name == name, "graph output slot mismatch: " + slot
        )
        compiled = regular(root / name)
        require(
            fingerprint(compiled) == state["compiled"]
            and hashlib.sha256(compiled).hexdigest() == binding["compiled_sha256"],
            "compiled identity mismatch: " + slot,
        )
        require(
            binding["versions"] == state["versions"]
            and state["versions"] == {"yarac": version, "libyara": version}
            and bool(version),
            "version identity mismatch: " + slot,
        )
        expected.update("compiler-inputs/" + slot + "/" + path for path in actual)
    require(set(files) == expected, "export file inventory mismatch")
    require(
        {p.name for p in root.iterdir()}
        == set(SLOTS.values()) | set(METADATA) | {"compiler-inputs"},
        "export root inventory mismatch",
    )
    require(
        {p.name for p in (root / "compiler-inputs").iterdir()}
        == {"main", "local", "index.json"},
        "export graph slots mismatch",
    )
    return index


def produce(source, destination):
    require(stat.S_ISDIR(source.lstat().st_mode), "source must be a real directory")
    require(
        not destination.exists() and not destination.is_symlink(),
        "destination already exists",
    )
    # Disallow symlink parent components for the publication path.
    for parent in (destination.parent, *destination.parent.parents):
        require(
            stat.S_ISDIR(parent.lstat().st_mode),
            "destination parent must be a real directory",
        )
    stage = Path(tempfile.mkdtemp(prefix=".compiler-export-", dir=destination.parent))
    (stage / "compiler-inputs").mkdir()
    index = {"schema": 1, "artifacts": {}, "metadata": {}}
    for slot, name in SLOTS.items():
        compiled = regular(source / name)
        pointer = source / (name + ".inputs")
        require(pointer.is_symlink(), "retained graph pointer missing: " + name)
        target = os.readlink(pointer)
        require(
            target.startswith(".compiler-inputs-") and Path(target).name == target,
            "retained graph pointer escapes source directory",
        )
        graph = source / target
        state = graph_state(graph)
        require(
            fingerprint(compiled) == state["compiled"],
            "source compiled identity mismatch: " + slot,
        )
        require(
            Path(state["output"]).absolute() == (source / name).absolute(),
            "source output binding mismatch: " + slot,
        )
        (stage / name).write_bytes(compiled)
        transferred = stage / "compiler-inputs" / slot
        transferred.mkdir()
        before = inventory(graph)
        for relative, entry in before.items():
            data = regular(graph / relative)
            require(fingerprint(data) == entry, "source graph changed during export")
            output = transferred / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        require(inventory(graph) == before, "source graph changed during export")
        index["artifacts"][slot] = {
            "compiled": name,
            "graph": "compiler-inputs/" + slot,
            "compiled_sha256": hashlib.sha256(compiled).hexdigest(),
            "versions": state["versions"],
            "files": before,
        }
    for name in METADATA:
        data = regular(source / name)
        (stage / name).write_bytes(data)
        index["metadata"][name] = fingerprint(data)
    (stage / "compiler-inputs/index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n"
    )
    verify(stage)
    # A concurrent destination is rejected; callers must own the destination.
    require(
        not destination.exists() and not destination.is_symlink(),
        "destination already exists",
    )
    publish(stage, destination)
    return index


def main(argv):
    try:
        if len(argv) == 2 and argv[0] == "verify":
            verify(Path(argv[1]))
        elif len(argv) == 3 and argv[0] == "export":
            produce(Path(argv[1]).absolute(), Path(argv[2]).absolute())
        else:
            raise ExportError("usage: export SOURCE DESTINATION | verify EXPORT")
    except (
        ExportError,
        capture.RetentionError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        AttributeError,
    ) as error:
        print(f"compiler-input export: rejected: {error}", file=sys.stderr)
        return 125
    print("compiler-input export: verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
