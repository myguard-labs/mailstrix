#!/usr/bin/env python3
"""Regenerate the native fixture in the Dockerfile's pinned yara stage.

Run from /src mounted read-only, with an empty writable /fixture:
 docker run --rm -v "$PWD:/src:ro" -v "$out:/fixture" \
   mailstrix-p12c-yara:local python3 /src/ci/marker_runtime_fixture.py
Ordinary local native Go tests: python3 ci/prepare_marker_runtime.py first.
Docker's test stage copies the generated export without a nested daemon.
The fixed native paths and ZIP metadata make repeated regeneration byte exact.
"""

import importlib.util
import json
import os
import subprocess
import zipfile
from pathlib import Path
from unittest.mock import patch

REPO = Path("/src")
ROOT = Path("/fixture")
SOURCE = ROOT / "source"
SOURCES = {
    "broken.yar": "rule Broken {",
    "a.yar": """global rule Gate { condition: true }
include "dependency.inc"
rule Marker : marker { condition: true }
rule PublicDependency { condition: true }
rule MarkerPrivate : marker { strings: $a="EXT-MISMATCH" condition: $a and PrivateDependency }
rule MarkerPublic : marker { strings: $a="EXT-MISMATCH" condition: $a and PublicDependency }
rule MarkerVBA : marker { condition: VBA == 1 }
rule MarkerFilename : marker { condition: extension == ".jpg" and file_type == "" }
rule PlainCompanion { strings: $a="harmless" condition: $a }
""",
    "dependency.inc": "private rule PrivateDependency { condition: true }\n",
    "b.yar": """import "hash"
rule RawOnly { strings: $a="harmless" condition: $a }
""",
}
# The production shell records validation argv, including mktemp output names.
# Fix only those test paths; compiler/capture/build/export code stays unchanged.
(ROOT / "bin").mkdir()
mktemp = ROOT / "bin/mktemp"
mktemp.write_text(
    '#!/bin/sh\nset -eu\n[ $# -eq 0 ]\ncounter=/fixture/temp-counter\nn=0\n[ ! -f "$counter" ] || n=$(cat "$counter")\nn=$((n + 1))\necho "$n" > "$counter"\np=/fixture/compile-temp-$n\n: > "$p"\necho "$p"\n'
)
mktemp.chmod(0o755)
os.environ["PATH"] = str(ROOT / "bin") + os.pathsep + os.environ["PATH"]
SOURCE.mkdir()
(SOURCE / "src").mkdir()
(SOURCE / "local-src").mkdir()
for name, value in SOURCES.items():
    (SOURCE / "src" / name).write_text(value)
(SOURCE / "src/sources.json").write_text("[]\n")
(SOURCE / "local-src/local.yar").write_text("rule Local { condition: false }\n")
for name, directory in [("compiled.yac", "src"), ("local.yac", "local-src")]:
    subprocess.run(
        [
            "sh",
            str(REPO / "docker/compile-rules.sh"),
            str(SOURCE / directory),
            str(SOURCE / name),
        ],
        check=True,
    )
(SOURCE / "libyara.version").write_text("4.5.2\n")
spec = importlib.util.spec_from_file_location(
    "export", REPO / "docker/export-compiler-inputs.py"
)
assert spec is not None and spec.loader is not None
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)
# Only the artifact/export stages use temporary paths in bound compiler argv.
# Fix those paths while retaining the actual production builder and validator.


def deterministic_stage(*, prefix, dir):
    path = Path(dir) / (prefix + "fixture")
    path.mkdir()
    return str(path)


with patch("tempfile.mkdtemp", new=deterministic_stage):
    export.marker.build(SOURCE)
    export.produce(SOURCE, ROOT / "envelope", require_marker=True)
export.verify(ROOT / "envelope")
# Genuine compiler observations for scaling and late-duplicate controls. Each
# namespace deliberately repeats identifiers from the other namespace.
inventory = ROOT / "native-inventory"
inventory.mkdir()
for count in (2048, 16384):
    inputs = ROOT / ("inventory-src-" + str(count))
    inputs.mkdir()
    for namespace in ("a", "b"):
        (inputs / (namespace + ".yar")).write_text(
            "".join(
                f"rule Inventory_{index} {{ condition: true }}\n"
                for index in range(count // 2)
            )
        )
    output = ROOT / ("inventory-" + str(count) + ".yac")
    subprocess.run(
        ["sh", str(REPO / "docker/compile-rules.sh"), str(inputs), str(output)],
        check=True,
    )
    retained = Path(str(output) + ".inputs")
    manifest = json.loads((retained / "manifest.json").read_text())
    final = manifest["final"]
    assert len(final["rule_graph"]["inventory"]) == count
    destination = inventory / str(count)
    destination.mkdir()
    (destination / "native").write_bytes(
        (retained / "objects" / final["native_trace"]["sha256"]).read_bytes()
    )
    (destination / "invocation.json").write_text(json.dumps(final, sort_keys=True))
with zipfile.ZipFile(
    ROOT / "marker-runtime.zip", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
) as archive:
    for path in sorted([*(ROOT / "envelope").rglob("*"), *inventory.rglob("*")]):
        if path.is_file():
            base = ROOT / "envelope" if path.is_relative_to(ROOT / "envelope") else ROOT
            info = zipfile.ZipInfo(
                path.relative_to(base).as_posix(), (1980, 1, 1, 0, 0, 0)
            )
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
(ROOT / "fixture-summary.json").write_text(
    json.dumps(export.verify(ROOT / "envelope"), sort_keys=True, indent=2) + "\n"
)
