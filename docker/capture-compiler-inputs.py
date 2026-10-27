#!/usr/bin/env python3
"""Retain native compiler observations beside each compiled bundle.

Candidate snapshots are inventory, not proof of consumed bytes. Every successful
invocation must contain complete native root/EOF/include/completion frames.
`restore ROOT` verifies every hash and projects final inputs into an empty tree;
run the retained final argv inside a disposable container with those original
paths. It never writes original source paths on the caller's filesystem.
"""

import hashlib
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

EXTERNALS = [
    {
        "name": name,
        "type": "integer" if name == "VBA" else "string",
        "value": 0 if name == "VBA" else "",
    }
    for name in (
        "filepath",
        "filename",
        "extension",
        "filetype",
        "file_type",
        "owner",
        "VBA",
    )
]
HEADER = struct.Struct("<BQQ")
CURSOR = struct.Struct("<QB")


class RetentionError(Exception):
    """Incomplete/unverifiable evidence, distinct from rejected YARA syntax."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def load_json(path):
    return json.loads(path.read_text())


def store(root, data):
    sha = digest(data)
    target = root / "objects" / sha
    if target.exists() and target.read_bytes() != data:
        raise RetentionError("retained object collision")
    # Parallel validations may store the same object: publish it atomically so
    # a concurrent reader never sees a partial write as a collision. The name is
    # joined to the lexical root (tempfile would normalize a `..` through a
    # symlinked parent into a different directory).
    tmp = target.with_name(f".object-{secrets.token_hex(8)}")
    with open(tmp, "xb") as handle:
        handle.write(data)
    os.replace(tmp, target)
    return {"sha256": sha, "size": len(data)}


def get(root, item):
    sha = item["sha256"]
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise RetentionError("invalid object digest")
    data = (root / "objects" / sha).read_bytes()
    if len(data) != item["size"] or digest(data) != sha:
        raise RetentionError("retained object hash mismatch")
    return data


def events(data):
    offset = 0
    while offset < len(data):
        if len(data) - offset < HEADER.size:
            raise RetentionError("truncated native frame header")
        kind, name_size, size = HEADER.unpack_from(data, offset)
        offset += HEADER.size
        if name_size + size > len(data) - offset:
            raise RetentionError("truncated native frame payload")
        name = os.fsdecode(data[offset : offset + name_size])
        offset += name_size
        payload = data[offset : offset + size]
        offset += size
        yield kind, name, payload


class _RuleGraph:
    """Versioned resolved native bytecode observations, bound to final inventory.

    Schema1 source graphs may still be replayed, but carry no rule-closure proof.
    Only a successful schema2 invocation with all frames can certify a graph.
    Failed compilations retain partial observations without claiming completeness.

    Frame v1: 10 starts mailstrix-rule-graph/1; 11/12 carry little-endian
    uint64 source/target indices (12 is completion); 13 carries namespace in
    the name and uint64 index/uint32 flags/identifier bytes in its payload;
    14 carries a tag name and uint64 rule index; 15 seals four uint64 counts
    (inventory, references, completions, tags). Raw repeated references remain
    intact. Flags 1/2 mean private/global: closure consumers must also include
    implicit global rules in each visited rule's namespace, even with no edges.
    """

    def __init__(self):
        self.started = self.sealed = False
        self.references, self.completions, self.inventory = [], [], []
        self.summary = None
        self.identities = set()

    def observe(self, kind, name, payload):
        if kind == 10:
            if self.started or name != "mailstrix-rule-graph/1" or payload:
                raise RetentionError("invalid native rule graph version")
            self.started = True
            return
        if not self.started or self.sealed:
            raise RetentionError("rule observation outside graph")
        handlers = {
            11: self.opcode,
            12: self.opcode,
            13: self.rule,
            14: self.tag,
            15: self.seal,
        }
        handler = handlers.get(kind)
        if handler is None:
            raise RetentionError("unknown native graph frame")
        handler(kind, name, payload)

    def opcode(self, kind, name, payload):
        if name or len(payload) != 16 or self.inventory:
            raise RetentionError("invalid native rule opcode frame")
        source, target = struct.unpack("<QQ", payload)
        if kind == 11:
            self.references.append([source, target])
        else:
            if source != target:
                raise RetentionError("native completion index mismatch")
            self.completions.append(source)

    def rule(self, _kind, name, payload):
        if len(payload) <= 12 or "\0" in name:
            raise RetentionError("invalid native rule inventory frame")
        index, flags = struct.unpack_from("<QI", payload)
        identifier = os.fsdecode(payload[12:])
        if index != len(self.inventory) or flags & ~3 or "\0" in identifier:
            raise RetentionError("native inventory index/flags/identifier mismatch")
        if (name, identifier) in self.identities:
            raise RetentionError("duplicate native rule identity")
        self.identities.add((name, identifier))
        self.inventory.append(
            {
                "native_index": index,
                "namespace": name,
                "identifier": identifier,
                "flags": flags,
                "tags": [],
            }
        )

    def tag(self, _kind, name, payload):
        if len(payload) != 8 or not name or "\0" in name or not self.inventory:
            raise RetentionError("invalid native rule tag frame")
        (index,) = struct.unpack("<Q", payload)
        tags = self.inventory[-1]["tags"]
        if index != self.inventory[-1]["native_index"] or name in tags:
            raise RetentionError("native tag inventory binding mismatch")
        tags.append(name)

    def seal(self, _kind, name, payload):
        if name or len(payload) != 32:
            raise RetentionError("invalid native graph summary")
        self.summary = list(struct.unpack("<QQQQ", payload))
        self.sealed = True

    def result(self, code):
        if not self.started:
            raise RetentionError("missing native rule graph proof")
        if code == 0:
            count = len(self.inventory)
            if not self.sealed or self.summary != [
                count,
                len(self.references),
                len(self.completions),
                sum(len(rule["tags"]) for rule in self.inventory),
            ]:
                raise RetentionError("missing/incomplete native rule graph summary")
            if self.completions != list(range(count)):
                raise RetentionError("native rule completion coverage mismatch")
            for source, target in self.references:
                if source >= count or target >= count:
                    raise RetentionError("reference index out of native inventory")
                if (
                    self.inventory[source]["namespace"]
                    != self.inventory[target]["namespace"]
                ):
                    raise RetentionError("native reference namespace mismatch")
        return {
            "schema": 1,
            "complete": code == 0,
            "inventory": self.inventory,
            "references": self.references,
            "completions": self.completions,
            "summary": self.summary,
        }


class _Trace:
    """Native framing state: one active root; completion closes the invocation."""

    def __init__(self, root, code, persist):
        self.root, self.code, self.persist = root, code, persist
        self.sources, self.includes = [], []
        self.active = {}
        self.complete = False
        self.compiler_version = self.library_version = None

    def retain(self, payload):
        if self.persist:
            return store(self.root, payload)
        return {"sha256": digest(payload), "size": len(payload)}

    def require_root(self, name=None):
        if not self.active or (name is not None and name != self.active["path"]):
            raise RetentionError("unmatched root observation")

    def begin(self, name, payload):
        if self.active:
            raise RetentionError("invalid root begin")
        self.active = {
            "path": name,
            "namespace": os.fsdecode(payload),
            "chunks": [],
            "eof": False,
        }

    def read(self, name, payload):
        self.require_root(name)
        if self.active["eof"]:
            raise RetentionError("read after root EOF")
        self.active["chunks"].append(payload)
        self.active["eof"] = not payload

    def finish_root(self, errors):
        self.active["errors"] = errors
        self.active["observed"] = self.retain(b"".join(self.active.pop("chunks")))
        self.sources.append(self.active)
        self.active = {}

    def end(self, name, payload):
        self.require_root(name)
        if len(payload) != 4:
            raise RetentionError("invalid root end status")
        errors = int.from_bytes(payload, sys.byteorder, signed=True)
        if errors == 0 and not self.active["eof"]:
            raise RetentionError("successful root lacks observed EOF")
        self.finish_root(errors)

    def include(self, name, payload):
        self.require_root()
        self.includes.append(
            {
                "path": name,
                "root": self.active["path"],
                "observed": self.retain(payload),
            }
        )

    def version(self, name, payload):
        if payload or (
            self.library_version is not None and self.library_version != name
        ):
            raise RetentionError("library version mismatch")
        self.library_version = name

    def status(self, name, payload):
        if len(payload) != 4 or (self.active and self.code == 0):
            raise RetentionError("incomplete compiler observation")
        if self.active:
            # YARA's fatal scanner recovery can leave a failed root unfinished.
            # Record the observed prefix without inventing EOF or acceptance.
            self.finish_root(None)
        if int.from_bytes(payload, sys.byteorder, signed=True) != self.code:
            raise RetentionError("compiler exit mismatch")
        self.compiler_version, self.complete = name, True

    def result(self):
        successful_roots = self.sources and all(s["errors"] == 0 for s in self.sources)
        if not self.complete or (self.code == 0 and not successful_roots):
            raise RetentionError("missing complete native compiler observation")
        return {
            "sources": self.sources,
            "includes": self.includes,
            "yarac_version": self.compiler_version,
            "libyara_version": self.library_version,
        }


def parse_trace(root, data, code, persist=True, schema=1):
    if type(schema) is not int or schema not in (1, 2):
        raise RetentionError("unsupported retained graph schema")
    graph = _RuleGraph() if schema == 2 else None
    trace = _Trace(root, code, persist)
    handlers = {
        1: trace.begin,
        2: trace.read,
        3: trace.end,
        4: trace.include,
        8: trace.version,
        9: trace.status,
    }
    for kind, name, payload in events(data):
        if trace.complete:
            raise RetentionError("native frames after compiler completion")
        if graph is not None and 10 <= kind <= 15:
            if kind != 10 and trace.active and kind >= 13:
                raise RetentionError("inventory before root completion")
            graph.observe(kind, name, payload)
            continue
        handler = handlers.get(kind)
        if handler is None:
            raise RetentionError("unknown native frame")
        handler(name, payload)
    result = trace.result()
    if graph is not None:
        result["rule_graph"] = graph.result(code)
    return result


def read_cursor(root):
    data = (root / "cursor").read_bytes()
    if len(data) != CURSOR.size:
        raise RetentionError("invalid invocation cursor")
    count, complete = CURSOR.unpack(data)
    if complete not in (0, 1):
        raise RetentionError("invalid invocation cursor")
    return count, bool(complete)


def write_cursor(root, count, complete):
    if not 0 <= count < 2**64 or complete not in (False, True):
        raise RetentionError("invalid invocation cursor")
    (root / "cursor").write_bytes(CURSOR.pack(count, complete))


def invocation_record(root, phase, index):
    path = (
        root
        / "invocations"
        / (f"validation-{index}.json" if phase == "validation" else "final.json")
    )
    record = load_json(path)
    if record["phase"] != phase or record["index"] != index:
        raise RetentionError("invocation record order mismatch")
    return record["invocation"]


def assemble(root):
    state = load_json(root / "pending.json")
    count, complete = read_cursor(root)
    if not complete:
        raise RetentionError("no completed final invocation")
    names = {p.name for p in (root / "invocations").iterdir()}
    if len(names) != count + 1:
        raise RetentionError("invocation record inventory mismatch")
    expected = {f"validation-{i}.json" for i in range(count)} | {"final.json"}
    if names != expected:
        raise RetentionError("invocation record inventory mismatch")
    state["validations"] = [
        invocation_record(root, "validation", i) for i in range(count)
    ]
    state["final"] = invocation_record(root, "final", count)
    return state


def begin(out, src):
    parent = Path(out).absolute().parent
    root = Path(tempfile.mkdtemp(prefix=".compiler-inputs-", dir=parent))
    (root / "objects").mkdir()
    (root / "invocations").mkdir()
    write_cursor(root, 0, False)
    save_json(
        root / "pending.json",
        {
            "schema": 2,
            "source_directory": src,
            "output": str(Path(out).absolute()),
            "cwd": os.getcwd(),
            "external_definitions": EXTERNALS,
            "validations": [],
            "final": None,
        },
    )
    print(root)


def run(root, phase, namespace, filename, argv):
    index, complete = read_cursor(root)
    if phase not in ("validation", "final") or complete:
        raise RetentionError("invalid capture invocation phase")
    if phase == "validation" and index == 2**64 - 1:
        raise RetentionError("invocation cursor overflow")
    code = run_at(root, phase, index, namespace, filename, argv)
    write_cursor(root, index + (phase == "validation"), phase == "final")
    return code


def run_at(root, phase, index, namespace, filename, argv, quiet=False):
    """Record one invocation at a fixed index; the caller owns the cursor."""
    candidate = None
    if phase == "validation":
        candidate = {
            "path": filename,
            "namespace": namespace,
            "snapshot": store(root, Path(filename).read_bytes()),
        }
    trace = root / f"{phase}-{index}.native"
    error_log = root / f"{phase}-{index}.stderr"
    env = os.environ.copy()
    env["MAILSTRIX_COMPILER_INPUT_LOG"] = str(trace)
    # Preserve compiler argv, cwd, stdout and diagnostics. Validation's caller
    # redirects output exactly as before; retained stderr is also forwarded.
    with error_log.open("wb") as errors:
        result = subprocess.run(
            argv,
            env=env,
            stderr=errors,
            stdout=subprocess.DEVNULL if quiet else None,
            check=False,
        )
    if not quiet:
        sys.stderr.buffer.write(error_log.read_bytes())
    if result.returncode == 125:
        raise RetentionError("native retention failed (exit 125)")
    if result.returncode not in (0, 1):
        raise RetentionError(f"compiler did not complete normally: {result.returncode}")
    native = trace.read_bytes()
    observed = parse_trace(root, native, result.returncode, schema=2)
    invocation = {
        "argv": argv,
        "exit": result.returncode,
        "cwd": os.getcwd(),
        "stderr": store(root, error_log.read_bytes()),
        "native_trace": store(root, native),
        **observed,
    }
    if candidate is not None:
        invocation["candidate"] = candidate
        invocation["accepted"] = result.returncode == 0
    record = (
        root
        / "invocations"
        / (f"validation-{index}.json" if phase == "validation" else "final.json")
    )
    if record.exists():
        raise RetentionError("invocation record already exists")
    save_json(record, {"phase": phase, "index": index, "invocation": invocation})
    return result.returncode


def validate(root, prefix, roots, jobs=None):
    """Validate roots serially by default; explicit jobs bound parallel work.

    Same records as one `run ... validation` per root in order: indexes follow
    the list, each run writes its own scratch output, and the cursor moves once,
    after every record exists. Compiler stdout/stderr stay out of the caller's
    streams (still retained), as the serial loop's redirect did. Any retention
    failure aborts the batch. Returns the compiler exit codes in input order.
    """
    start, complete = read_cursor(root)
    if complete or start + len(roots) >= 2**64:
        raise RetentionError("invalid capture invocation phase")
    scratch = root / f".validation-{secrets.token_hex(8)}"
    scratch.mkdir()

    def one(i):
        ns, path = roots[i]
        argv = prefix + [f"{ns}:{path}", str(scratch / f"{i}.yac")]
        return run_at(root, "validation", start + i, ns, path, argv, quiet=True)

    try:
        with ThreadPoolExecutor(max_workers=jobs or 1) as pool:
            codes = list(pool.map(one, range(len(roots))))
    finally:
        shutil.rmtree(scratch)
    write_cursor(root, start + len(roots), False)
    return codes


def validate_files(root, good, filelist, prefix):
    """compile-rules.sh entry: namespace = basename; accepted roots -> good."""
    files = Path(filelist).read_text().splitlines()
    roots = [(os.path.basename(f), f) for f in files]
    accepted = []
    for (ns, path), code in zip(roots, validate(root, prefix, roots)):
        if code == 0:
            accepted.append(f"{ns}:{path}\n")
        else:
            print(f"compile-rules: skip {ns} (uncompilable)", file=sys.stderr)
    Path(good).write_text("".join(accepted))
    return 0


def run_final(root, good, output, prefix):
    """Run the final compiler with each accepted record as one argument."""
    serialized = Path(good).read_bytes()
    if not serialized.endswith(b"\n"):
        raise RetentionError("malformed accepted-root records")
    records = serialized[:-1].split(b"\n")
    if any(
        not namespace or not separator or not path
        for record in records
        for namespace, separator, path in (record.partition(b":"),)
    ):
        raise RetentionError("malformed accepted-root records")
    return run(
        root,
        "final",
        "",
        "",
        prefix + [os.fsdecode(record) for record in records] + [output],
    )


def final_inputs(state):
    final = state["final"]
    if final is None or final["exit"] != 0:
        raise RetentionError("no successful final compilation")
    result = {}
    for item in final["sources"] + final["includes"]:
        path = os.path.abspath(os.path.join(final["cwd"], item["path"]))
        observed = item["observed"]
        if path in result and result[path] != observed:
            raise RetentionError("different observed bytes at one final source path")
        result[path] = observed
    for path in result:
        if any(str(parent) in result for parent in Path(path).parents):
            raise RetentionError("final input paths cannot be projected into one tree")
    return result


def final_directories(state):
    """Project directories traversed lexically, independently of file keys.

    Native observations bind the bytes at each spelling. No original filesystem
    lookup (including symlink resolution) is needed or permitted here.
    """
    final = state["final"]
    paths = [item["path"] for item in final["sources"] + final["includes"]]
    paths.extend([final["cwd"] + "/", final["argv"][0], final["argv"][-1]])
    directories = {"/"}
    for path in paths:
        absolute = path if path.startswith("/") else final["cwd"] + "/" + path
        components = absolute.split("/")[:-1]
        current = []
        for component in components:
            if component == "..":
                if current:
                    current.pop()
            elif component and component != ".":
                current.append(component)
            directories.add("/" + "/".join(current))
    if directories.intersection(final_inputs(state)):
        raise RetentionError("final input paths cannot be projected into one tree")
    return sorted(directories)


def finish(root):
    state = assemble(root)
    accepted = [v["candidate"]["path"] for v in state["validations"] if v["accepted"]]
    if not accepted or [s["path"] for s in state["final"]["sources"]] != accepted:
        raise RetentionError("final roots differ from accepted candidate order")
    state["final_inputs"] = final_inputs(state)
    state["final_directories"] = final_directories(state)
    state["compiled"] = store(root, Path(state["output"]).read_bytes())
    state["versions"] = {
        "yarac": state["final"]["yarac_version"],
        "libyara": state["final"]["libyara_version"],
    }
    save_json(root / "manifest.json", state)
    # Re-verify before publication. An incomplete staging directory is never
    # an accepted snapshot; the bound manifest is the publication boundary.
    verify(root, state)
    destination = Path(state["output"] + ".inputs")
    if destination.exists() and not destination.is_symlink():
        raise RetentionError(
            f"retention destination is not a managed pointer: {destination}"
        )
    (root / "pending.json").unlink()
    pointer = root.with_name(root.name + ".pointer")
    pointer.symlink_to(root.name)
    os.replace(pointer, destination)


def verify_contract(state):
    final = state["final"]
    accepted = [v["candidate"] for v in state["validations"] if v["accepted"]]
    ext_argv = [
        value for e in EXTERNALS for value in ("-d", e["name"] + "=" + str(e["value"]))
    ]
    expected = {
        "args": ext_argv + [c["namespace"] + ":" + c["path"] for c in accepted],
        "output": os.path.abspath(state["output"]),
        "roots": [(c["path"], c["namespace"]) for c in accepted],
        "versions": {
            "yarac": final["yarac_version"],
            "libyara": final["libyara_version"],
        },
    }
    actual = {
        "args": final["argv"][1:-1],
        "output": os.path.abspath(os.path.join(final["cwd"], final["argv"][-1])),
        "roots": [(s["path"], s["namespace"]) for s in final["sources"]],
        "versions": state["versions"],
    }
    if actual != expected or not all(state["versions"].values()):
        raise RetentionError("final compiler contract mismatch")
    for invocation in state["validations"]:
        c = invocation["candidate"]
        actual = {"accepted": invocation["accepted"], "args": invocation["argv"][1:-1]}
        expected = {
            "accepted": invocation["exit"] == 0,
            "args": ext_argv + [c["namespace"] + ":" + c["path"]],
        }
        if actual != expected:
            raise RetentionError("validation compiler contract mismatch")


def verify(root, state):
    if (
        type(state["schema"]) is not int
        or state["schema"] not in (1, 2)
        or state["external_definitions"] != EXTERNALS
    ):
        raise RetentionError("retained input contract mismatch")
    for invocation in state["validations"] + [state["final"]]:
        if type(invocation["exit"]) is not int or invocation["exit"] not in (0, 1):
            raise RetentionError("invalid compiler exit status")
        native = get(root, invocation["native_trace"])
        observed = parse_trace(
            root, native, invocation["exit"], persist=False, schema=state["schema"]
        )
        for field, value in observed.items():
            if field not in invocation:
                raise RetentionError("manifest disagrees with native observation")
            actual = invocation[field]
            if field == "rule_graph":
                # JSON type identity matters: bool/float indices cannot be
                # accepted merely because Python compares them equal to ints.
                actual = json.dumps(actual, sort_keys=True, allow_nan=False)
                value = json.dumps(value, sort_keys=True, allow_nan=False)
            if actual != value:
                raise RetentionError("manifest disagrees with native observation")
        for item in invocation["sources"] + invocation["includes"]:
            get(root, item["observed"])
        get(root, invocation["stderr"])
        if "candidate" in invocation:
            get(root, invocation["candidate"]["snapshot"])
    verify_contract(state)
    if state["final_inputs"] != final_inputs(state):
        raise RetentionError("final input mapping mismatch")
    if state["final_directories"] != final_directories(state):
        raise RetentionError("final directory mapping mismatch")
    get(root, state["compiled"])
    for item in state["final_inputs"].values():
        get(root, item)
    return state


def authoritative_rule_graph(root, state):
    """Verify new complete proof; legacy source replay never permits narrowing."""
    if (
        not isinstance(state, dict)
        or type(state.get("schema")) is not int
        or state["schema"] != 2
    ):
        raise RetentionError("no authoritative native rule graph")
    final = state.get("final")
    if (
        not isinstance(final, dict)
        or final.get("exit") != 0
        or not isinstance(final.get("rule_graph"), dict)
        or final["rule_graph"].get("complete") is not True
    ):
        raise RetentionError("no authoritative native rule graph")
    verify(root, state)
    return final["rule_graph"]


def restore(root, destination):
    state = verify(root, load_json(root / "manifest.json"))
    if destination.exists():
        raise RetentionError("restore requires a new destination")
    destination.mkdir()
    try:
        for path in state["final_directories"]:
            target = destination / "inputs" / Path(path).relative_to("/")
            target.mkdir(parents=True, exist_ok=True)
        for path, item in state["final_inputs"].items():
            relative = Path(path).relative_to("/")
            target = destination / "inputs" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(get(root, item))
        save_json(
            destination / "replay.json",
            {
                "cwd": state["final"]["cwd"],
                "argv": state["final"]["argv"],
                "compiled": state["compiled"],
                "versions": state["versions"],
                ("instruction"): (
                    "Run argv at the original paths inside a disposable"
                    " container; compare output SHA256."
                ),
            },
        )
    except (OSError, ValueError, RetentionError):
        shutil.rmtree(destination)
        raise


def main(argv):
    command = argv[0]
    if command == "begin":
        begin(argv[1], argv[2])
    elif command == "run":
        return run(Path(argv[1]), argv[2], argv[3], argv[4], argv[5:])
    elif command == "validate":
        # validate ROOT GOOD FILELIST COMPILER-ARGV...: FILELIST holds one
        # source path per line; COMPILER-ARGV excludes the root and output.
        return validate_files(Path(argv[1]), argv[2], argv[3], argv[4:])
    elif command == "final":
        # final ROOT GOOD OUTPUT COMPILER-ARGV...: GOOD holds one complete
        # namespace:path compiler argument per newline-terminated record.
        return run_final(Path(argv[1]), argv[2], argv[3], argv[4:])
    elif command == "finish":
        finish(Path(argv[1]))
    elif command == "verify":
        root = Path(argv[1])
        verify(root, load_json(root / "manifest.json"))
    elif command == "restore":
        restore(Path(argv[1]), Path(argv[2]))
    else:
        raise RetentionError("unknown retention operation")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, RetentionError) as exc:
        print(f"compile-rules: input retention failed: {exc}", file=sys.stderr)
        sys.exit(125)
