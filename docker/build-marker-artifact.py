#!/usr/bin/env python3
"""Build a native-proved marker namespace bundle before source removal.

The marker directory is a single publication unit. Schema1 source retention is
replayable but never grants permission to narrow. No source-text dependency
inference is used: only the complete resolved native rule graph selects roots.
"""

import contextlib
import ctypes
import hashlib
import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "marker_capture", Path(__file__).with_name("capture-compiler-inputs.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("capture helper loader unavailable")
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)

# Descriptors come from the actual serialized rules, not a source parser.
# Hex encoding makes native strings unambiguous, including tabs/newlines.
INSPECTOR = r"""
#include <stdio.h>
#include <string.h>
#include <yara.h>
static void hex(const char *p, size_t n) {
  for (size_t i=0; i<n; i++) printf("%02x", (unsigned char)p[i]);
}
static void text(const char *p) { hex(p, strlen(p)); }
int main(int n, char **v) {
  if (n != 2) return 2;
  int e = yr_initialize(); if (e) return e;
  YR_RULES *r; e = yr_rules_load(v[1], &r); if (e) return e;
  YR_RULE *x; YR_META *m; YR_STRING *s; const char *t;
  yr_rules_foreach(r, x) {
    printf("R\t"); text(x->ns->name); printf("\t"); text(x->identifier);
    printf("\t%d\n", x->flags);
    yr_rule_tags_foreach(x, t) { printf("T\t"); text(t); puts(""); }
    yr_rule_metas_foreach(x, m) {
      printf("M\t"); text(m->identifier);
      printf("\t%d\t%lld\t", m->type, (long long)m->integer);
      if (m->type == META_TYPE_STRING) text(m->string);
      puts("");
    }
    yr_rule_strings_foreach(x, s) {
      printf("S\t"); text(s->identifier);
      printf("\t%u\t%d\t", s->flags, s->length);
      hex((const char *)s->string, s->length); puts("");
    }
  }
  YR_EXTERNAL_VARIABLE *ev = r->ext_vars_table;
  for (; !EXTERNAL_VARIABLE_IS_NULL(ev); ev++) {
    printf("X\t"); text(ev->identifier); printf("\t%d\t", ev->type);
    if (ev->type == EXTERNAL_VARIABLE_TYPE_STRING) text(ev->value.s);
    else printf("%lld", (long long)ev->value.i);
    puts("");
  }
  yr_rules_destroy(r); yr_finalize(); return 0;
}
"""


class MarkerError(Exception):
    """Marker artifact proof does not match its main bundle."""


def require(condition, message):
    if not condition:
        raise MarkerError(message)


def fingerprint(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def identity(rule):
    return [rule["namespace"], rule["identifier"]]


def closure_index(graph):
    rows = graph["inventory"]
    edges = [[] for _ in rows]
    globals_by_ns = {}
    markers = []
    for row in rows:
        if row["flags"] & 2:
            globals_by_ns.setdefault(row["namespace"], []).append(row["native_index"])
        if "marker" in row["tags"]:
            markers.append(row["native_index"])
    for source, target in graph["references"]:
        # The native graph deliberately retains repeated references. Keep them
        # here too: every explicit edge of a retained rule must be visited.
        edges[source].append(target)
    return rows, edges, globals_by_ns, markers


def closure(graph, *, operations=None):
    rows, edges, globals_by_ns, markers = closure_index(graph)
    retained = set(markers)
    todo = list(markers)
    expanded_namespaces = set()
    counts = {
        "rule_visits": 0,
        "explicit_edge_visits": 0,
        "namespace_expansions": 0,
        "namespace_global_visits": 0,
    }

    def enqueue(dep):
        if dep not in retained:
            retained.add(dep)
            todo.append(dep)

    for current in todo:
        counts["rule_visits"] += 1
        for dep in edges[current]:
            counts["explicit_edge_visits"] += 1
            enqueue(dep)
        namespace = rows[current]["namespace"]
        if namespace not in expanded_namespaces:
            # Removing this add must trip the named operation-bound mutation:
            # globals are expanded once per reachable namespace, not per rule.
            expanded_namespaces.add(namespace)
            counts["namespace_expansions"] += 1
            for dep in globals_by_ns.get(namespace, ()):
                counts["namespace_global_visits"] += 1
                enqueue(dep)
    if operations is not None:
        operations.clear()
        operations.update(counts)
    return {"markers": markers, "retained": sorted(retained)}


def selection(state, graph):
    proof = closure(graph)
    namespaces = {graph["inventory"][i]["namespace"] for i in proof["retained"]}
    accepted = [v["candidate"] for v in state["validations"] if v["accepted"]]
    # A no-marker corpus keeps all accepted namespaces (full-size fallback),
    # rather than inventing a synthetic source or invoking yarac with no roots.
    selected = [
        c for c in accepted if not proof["markers"] or c["namespace"] in namespaces
    ]
    require(
        namespaces <= {c["namespace"] for c in selected},
        "closure namespace has no accepted source",
    )
    return proof, selected


def descriptor(data):
    rules, externals = [], []
    for line in data.decode("ascii").splitlines():
        fields = line.split("\t")
        if fields[0] == "R":
            rules.append(
                {
                    "identity": [bytes.fromhex(s).decode() for s in fields[1:3]],
                    "lines": [line],
                }
            )
        elif fields[0] == "X":
            externals.append(line)
        else:
            require(
                bool(rules) and fields[0] in ("T", "M", "S"),
                "invalid native descriptor",
            )
            rules[-1]["lines"].append(line)
    return {"rules": rules, "externals": externals}


def binding(
    main_root, main, marker_root, marker, main_descriptors, marker_descriptors, abi
):
    graph = capture.authoritative_rule_graph(main_root, main)
    narrow = capture.authoritative_rule_graph(marker_root, marker)
    proof, selected = selection(main, graph)
    selected_ns = {c["namespace"] for c in selected}
    expected = [r for r in graph["inventory"] if r["namespace"] in selected_ns]
    # Native indices change in a narrow compilation; every other rule field is
    # required to remain equal, including order, private/global flags and tags.
    projected = [{**r, "native_index": i} for i, r in enumerate(expected)]
    require(narrow["inventory"] == projected, "marker native inventory mismatch")
    mapping = {r["native_index"]: i for i, r in enumerate(expected)}
    references = [
        [mapping[s], mapping[t]] for s, t in graph["references"] if s in mapping
    ]
    require(narrow["references"] == references, "marker native reference mismatch")
    require(
        marker["external_definitions"] == main["external_definitions"]
        and marker["versions"] == main["versions"],
        "marker compiler/external identity mismatch",
    )
    require(
        marker["final"]["cwd"] == main["final"]["cwd"]
        and marker["final"]["argv"][:15] == main["final"]["argv"][:15],
        "marker compiler invocation mismatch",
    )
    require(
        marker["final"]["sources"]
        == [s for s in main["final"]["sources"] if s["namespace"] in selected_ns],
        "marker source identity mismatch",
    )
    require(
        all(
            main["final_inputs"].get(p) == v for p, v in marker["final_inputs"].items()
        ),
        "marker include identity mismatch",
    )
    ids = {tuple(identity(r)) for r in expected}
    require(
        [r["identity"] for r in main_descriptors["rules"]]
        == [identity(r) for r in graph["inventory"]],
        "main descriptor inventory mismatch",
    )
    require(
        marker_descriptors
        == {
            "rules": [
                r for r in main_descriptors["rules"] if tuple(r["identity"]) in ids
            ],
            "externals": main_descriptors["externals"],
        },
        "marker native descriptor mismatch",
    )
    return {
        "schema": 1,
        "construction": "complete-native-namespace-closure/1",
        "main": main["compiled"],
        "marker": marker["compiled"],
        "main_manifest": fingerprint((main_root / "manifest.json").read_bytes()),
        "marker_manifest": fingerprint((marker_root / "manifest.json").read_bytes()),
        "versions": main["versions"],
        "abi": abi,
        "module_identity": {"static_libyara": abi["libyara"]},
        "external_definitions": main["external_definitions"],
        "namespace_order": [c["namespace"] for c in selected],
        "sources": [c for c in selected],
        "includes": marker["final"]["includes"],
        "closure": proof,
        "main_inventory": graph["inventory"],
        "marker_inventory": narrow["inventory"],
        "main_descriptors": main_descriptors,
        "marker_descriptors": marker_descriptors,
    }


@contextlib.contextmanager
def compiler_cwd(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def build(source):
    require(stat.S_ISDIR(source.lstat().st_mode), "source must be a real directory")
    destination = source / "marker-artifact"
    require(
        not destination.exists() and not destination.is_symlink(),
        "marker destination already exists",
    )
    pointer = source / "compiled.yac.inputs"
    require(pointer.is_symlink(), "main retained graph pointer missing")
    target = os.readlink(pointer)
    require(
        target.startswith(".compiler-inputs-") and Path(target).name == target,
        "main graph pointer escapes source",
    )
    root = source / target
    state = capture.load_json(root / "manifest.json")
    graph = capture.authoritative_rule_graph(root, state)
    require(
        fingerprint((source / "compiled.yac").read_bytes()) == state["compiled"],
        "main compiled identity mismatch",
    )
    _, selected = selection(state, graph)
    for path, item in state["final_inputs"].items():
        require(
            fingerprint(Path(path).read_bytes()) == item,
            "main source changed before marker build",
        )
    stage = Path(tempfile.mkdtemp(prefix=".marker-artifact-", dir=source))
    compiler = Path(
        shutil.which(state["final"]["argv"][0]) or state["final"]["argv"][0]
    )
    library = (
        Path(
            subprocess.check_output(
                ["pkg-config", "--variable=libdir", "yara"], text=True
            ).strip()
        )
        / "libyara.a"
    )
    abi = {
        "compiler": fingerprint(compiler.read_bytes()),
        "libyara": fingerprint(library.read_bytes()),
        "descriptor_source": fingerprint(INSPECTOR.encode()),
    }
    (stage / "abi").mkdir()
    (stage / "abi/yarac").write_bytes(compiler.read_bytes())
    (stage / "abi/libyara.a").write_bytes(library.read_bytes())
    inspector_source = stage / "inspect.c"
    inspector_source.write_text(INSPECTOR)
    flags = subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "--static", "yara"], text=True
    ).split()
    subprocess.run(
        ["cc", str(inspector_source), "-O2", "-o", str(stage / "inspect"), *flags],
        check=True,
    )
    main_data = subprocess.check_output(
        [str(stage / "inspect"), str(source / "compiled.yac")]
    )
    (stage / "main.descriptors").write_bytes(main_data)
    main_descriptors = descriptor(main_data)
    out = stage / "markers.yac"
    with compiler_cwd(state["final"]["cwd"]):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            capture.begin(str(out), state["source_directory"])
        marker_root = Path(output.getvalue().strip())
        prefix = state["final"]["argv"][: 1 + 2 * len(capture.EXTERNALS)]
        codes = capture.validate(
            marker_root, prefix, [(c["namespace"], c["path"]) for c in selected]
        )
        require(all(code == 0 for code in codes), "marker source validation failed")
        require(
            capture.run(
                marker_root,
                "final",
                "",
                "",
                prefix
                + [c["namespace"] + ":" + c["path"] for c in selected]
                + [str(out)],
            )
            == 0,
            "marker compilation failed",
        )
        capture.finish(marker_root)
    marker = capture.load_json(marker_root / "manifest.json")
    marker_data = subprocess.check_output([str(stage / "inspect"), str(out)])
    (stage / "marker.descriptors").write_bytes(marker_data)
    marker_descriptors = descriptor(marker_data)
    metadata = binding(
        root, state, marker_root, marker, main_descriptors, marker_descriptors, abi
    )
    capture.save_json(stage / "binding.json", metadata)
    # Keep only the fixed verified envelope; compiler intermediates cannot be
    # mistaken for published evidence. Source graphs survive failed builds.
    (stage / "markers.yac.inputs").unlink()
    marker_root.rename(stage / "graph")
    for name in ("inspect", "inspect.c"):
        (stage / name).unlink()
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(destination))
    return metadata


def main(argv):
    try:
        require(len(argv) == 1, "usage: build-marker-artifact.py SOURCE")
        build(Path(argv[0]).absolute())
    except (
        MarkerError,
        capture.RetentionError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        AttributeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"marker artifact: rejected: {error}", file=sys.stderr)
        return 125
    print("marker artifact: verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
