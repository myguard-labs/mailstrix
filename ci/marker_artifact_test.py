#!/usr/bin/env python3
"""Real native marker construction, envelope and publication controls."""

import copy
import importlib.util
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "marker_export", REPO / "docker/export-compiler-inputs.py"
)
if spec is None or spec.loader is None:
    raise RuntimeError("export helper loader unavailable")
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)
marker = export.marker


def prepare(source, markers=True):
    source.mkdir()
    src = source / "src"
    src.mkdir()
    (src / "dependency.inc").write_text(
        'private rule Dependency { condition: filename == "enabled" }\nrule wildA { condition: Dependency }\nrule wildB { condition: false }\n'
    )
    (src / "a.yar").write_text(
        'include "dependency.inc"\n'
        + (
            'rule Marker : marker deny { meta: note="text" rank=4 good=true strings: $a="needle" condition: any of (wild*) or $a }\n'
            if markers
            else "rule Companion { condition: wildA }\n"
        )
    )
    (src / "b.yar").write_text(
        "global rule Gate { condition: VBA == 1 }\nprivate rule Private { condition: true }\n"
        + (
            "rule Marker : marker { condition: Private }\n"
            if markers
            else "rule Companion { condition: Private }\n"
        )
    )
    (src / "c.yar").write_text('import "hash"\nrule Unused { condition: false }\n')
    (src / "sources.json").write_text("[]\n")
    local = source / "local-src"
    local.mkdir()
    (local / "local.yar").write_text("rule Local { condition: false }\n")
    for inputs, name in ((src, "compiled.yac"), (local, "local.yac")):
        subprocess.run(
            [
                "sh",
                str(REPO / "docker/compile-rules.sh"),
                str(inputs),
                str(source / name),
            ],
            check=True,
        )
    (source / "libyara.version").write_text("4.5.2\n")
    return source


EQUIVALENCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>
static int marker(YR_RULE*r){const char*t;yr_rule_tags_foreach(r,t){if(!strcmp(t,"marker"))return 1;}return 0;}
struct hits{char lines[200][512];int n;};
static int cb(YR_SCAN_CONTEXT*c,int m,void*d,void*u){(void)c;struct hits*h=u;YR_RULE*r=d;if(m==CALLBACK_MSG_RULE_MATCHING&&marker(r)){if(h->n>=200)abort();snprintf(h->lines[h->n++],512,"%s\t%s",r->ns->name,r->identifier);}return CALLBACK_CONTINUE;}
static int cmp(const void*a,const void*b){return strcmp(a,b);}
static int expected_hits=-1;
static int check(YR_RULES*a,YR_RULES*b,const uint8_t*p,size_t n){struct hits x={0},y={0};int e=yr_rules_scan_mem(a,p,n,0,cb,&x,60);if(e)return e;e=yr_rules_scan_mem(b,p,n,0,cb,&y,60);if(e)return e;if(expected_hits>=0 && x.n!=expected_hits){fprintf(stderr,"fixture expected marker hits=%d actual=%d\n",expected_hits,x.n);return 126;}qsort(x.lines,x.n,512,cmp);qsort(y.lines,y.n,512,cmp);if(x.n!=y.n||memcmp(x.lines,y.lines,x.n*512)){fprintf(stderr,"marker output mismatch size=%zu full=%d narrow=%d\n",n,x.n,y.n);return 125;}return 0;}
int main(int n,char**v){if(n!=3)return 2;yr_initialize();YR_RULES*a=NULL,*b=NULL;int e=yr_rules_load(v[1],&a);if(e)return e;e=yr_rules_load(v[2],&b);if(e)return e;int count=0;
for(int mode=0;mode<4;mode++){
  yr_rules_define_string_variable(a,"filename",(mode&1)?"enabled":"");
  yr_rules_define_string_variable(b,"filename",(mode&1)?"enabled":"");
  yr_rules_define_integer_variable(a,"VBA",(mode&2)?1:0);
  yr_rules_define_integer_variable(b,"VBA",(mode&2)?1:0);
  const char *fixtures[]={"","needle","enabled","other","needle enabled","\xff\x01"};
  for(int j=0;j<6;j++){expected_hits=((mode&1)||j==1||j==4)+!!(mode&2);e=check(a,b,(const uint8_t*)fixtures[j],strlen(fixtures[j]));if(e)return e;count++;}
}
YR_RULE *denied;
yr_rules_foreach(a,denied){if(!(denied->flags&(RULE_FLAGS_PRIVATE|RULE_FLAGS_GLOBAL))&&!strcmp(denied->identifier,"wildA"))yr_rule_disable(denied);}
yr_rules_foreach(b,denied){if(!(denied->flags&(RULE_FLAGS_PRIVATE|RULE_FLAGS_GLOBAL))&&!strcmp(denied->identifier,"wildA"))yr_rule_disable(denied);}
expected_hits=2;e=check(a,b,(const uint8_t*)"needle",6);if(e)return e;count++;
expected_hits=1;e=check(a,b,(const uint8_t*)"",0);if(e)return e;count++;expected_hits=-1;
uint8_t*all=malloc(1000000);size_t len=0;YR_RULE*r;YR_STRING*s;yr_rules_foreach(a,r){if(!marker(r))continue;yr_rule_strings_foreach(r,s){if(s->length>0){e=check(a,b,s->string,s->length);if(e)return e;count++;if(len+s->length+1>1000000)return 3;memcpy(all+len,s->string,s->length);len+=s->length;all[len++]='\n';}}}e=check(a,b,all,len);if(e)return e;count++;for(size_t i=0;i<4096;i++)all[i]=(uint8_t)((i*73+11)%256);for(size_t i=0;i<=4096;i=i?i*2:1){e=check(a,b,all,i);if(e)return e;count++;}printf("{\"native_detection_cases\":%d,\"full_set_filtered_equivalent\":true}\n",count);free(all);yr_rules_destroy(a);yr_rules_destroy(b);yr_finalize();return 0;}
"""


class MarkerArtifact(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="marker-artifact-test-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def build(self, markers=True):
        source = prepare(self.root / "rules", markers)
        before = {name: (source / name).read_bytes() for name in export.SLOTS.values()}
        metadata = marker.build(source)
        for name, data in before.items():
            self.assertEqual((source / name).read_bytes(), data)
        return source, metadata

    def test_complete_native_namespace_closure_companions_and_descriptors(self):
        source, metadata = self.build()
        self.assertEqual(metadata["namespace_order"], ["a.yar", "b.yar"])
        self.assertEqual(metadata["closure"]["markers"], [3, 6])
        self.assertEqual(metadata["closure"]["retained"], list(range(7)))
        self.assertEqual(len(metadata["marker_inventory"]), 7)
        self.assertEqual(metadata["main_inventory"][-1]["identifier"], "Unused")
        self.assertEqual(metadata["marker_inventory"][0]["flags"], 1)
        self.assertEqual(metadata["marker_inventory"][4]["flags"], 2)
        self.assertTrue(metadata["includes"])
        self.assertTrue(metadata["marker_descriptors"]["externals"])
        for field in ("compiler", "libyara", "descriptor_source"):
            self.assertGreater(metadata["abi"][field]["size"], 0)
        out = self.root / "export"
        index = export.produce(source, out, require_marker=True)
        self.assertEqual(index["schema"], 2)
        self.assertEqual(export.verify(out), index)
        self.assertEqual(
            (out / "marker-artifact/markers.yac").read_bytes(),
            (source / "marker-artifact/markers.yac").read_bytes(),
        )

    def test_filtered_equivalence_externals_global_private_include_wildcard_and_deny(
        self,
    ):
        source, _ = self.build()
        c = self.root / "equivalence.c"
        c.write_text(EQUIVALENCE)
        flags = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "--static", "yara"], text=True
        ).split()
        binary = self.root / "equivalence"
        subprocess.run(["cc", "-O2", str(c), "-o", str(binary), *flags], check=True)
        output = subprocess.check_output(
            [
                str(binary),
                str(source / "compiled.yac"),
                str(source / "marker-artifact/markers.yac"),
            ],
            text=True,
        )
        result = json.loads(output)
        self.assertTrue(result["full_set_filtered_equivalent"])
        self.assertEqual(result["native_detection_cases"], 42)

    def test_no_markers_keeps_complete_accepted_sources(self):
        source, metadata = self.build(False)
        self.assertEqual(metadata["closure"], {"markers": [], "retained": []})
        self.assertEqual(metadata["namespace_order"], ["a.yar", "b.yar", "c.yar"])
        self.assertEqual(metadata["main_inventory"], metadata["marker_inventory"])
        export.produce(source, self.root / "export", require_marker=True)

    def test_binding_mutation_controls(self):
        source, _ = self.build()
        main_root = source / os.readlink(source / "compiled.yac.inputs")
        root = source / "marker-artifact"
        path = root / "binding.json"
        original = path.read_bytes()
        metadata = json.loads(original)
        mutations = [
            lambda m: m.update(schema=True),
            lambda m: m.update(schema=2),
            lambda m: m.update(extra=1),
            lambda m: m["main"].update(sha256="0" * 64),
            lambda m: m["marker"].update(size=0),
            lambda m: m["abi"]["descriptor_source"].update(size=0),
            lambda m: m["abi"].update(extra={}),
            lambda m: m["abi"]["compiler"].update(size=True),
            lambda m: m["versions"].update(yarac="0"),
            lambda m: m["external_definitions"][0].update(type="integer"),
            lambda m: m["namespace_order"].reverse(),
            lambda m: m["closure"]["retained"].clear(),
            lambda m: m["sources"][0].update(namespace="foreign"),
            lambda m: m["includes"].clear(),
            lambda m: m["main_inventory"][0].update(identifier="bad"),
            lambda m: m["marker_inventory"].pop(),
            lambda m: m["main_descriptors"]["rules"].pop(),
            lambda m: m["marker_descriptors"]["rules"].pop(),
            lambda m: m["marker_descriptors"]["externals"].clear(),
        ]
        for mutate in mutations:
            candidate = copy.deepcopy(metadata)
            mutate(candidate)
            path.write_text(json.dumps(candidate))
            with (
                self.subTest(mutation=mutate),
                self.assertRaises((export.ExportError, marker.MarkerError)),
            ):
                export.verify_marker(main_root, root)
        path.write_bytes(original)
        export.verify_marker(main_root, root)
        artifact = root / "markers.yac"
        original = artifact.read_bytes()
        artifact.write_bytes(original + b"tamper")
        with self.assertRaisesRegex(export.ExportError, "compiled identity"):
            export.verify_marker(main_root, root)
        artifact.write_bytes(original)
        export.verify_marker(main_root, root)

    def test_omission_extra_symlink_traversal_atomic_export(self):
        source, _ = self.build()
        root = source / "marker-artifact"
        for name in ("markers.yac", "binding.json", "graph"):
            target = root / name
            saved = self.root / "saved"
            target.rename(saved)
            self.assertEqual(
                export.main(
                    ["export-marker", str(source), str(self.root / "rejected")]
                ),
                125,
            )
            self.assertFalse((self.root / "rejected").exists())
            target.symlink_to(saved)
            self.assertEqual(
                export.main(
                    ["export-marker", str(source), str(self.root / "rejected")]
                ),
                125,
            )
            target.unlink()
            saved.rename(target)
        (root / "extra").write_bytes(b"extra")
        self.assertEqual(
            export.main(["export-marker", str(source), str(self.root / "rejected")]),
            125,
        )
        (root / "extra").unlink()
        root.rename(self.root / "missing")
        self.assertEqual(
            export.main(["export-marker", str(source), str(self.root / "rejected")]),
            125,
        )
        (self.root / "missing").rename(root)
        with mock.patch.object(
            export, "publish", side_effect=OSError("partial publication")
        ):
            self.assertEqual(
                export.main(
                    ["export-marker", str(source), str(self.root / "rejected")]
                ),
                125,
            )
        self.assertFalse((self.root / "rejected").exists())
        self.assertEqual(
            export.main(["export-marker", str(source), str(self.root / "restored")]), 0
        )
        index_path = self.root / "restored/compiler-inputs/index.json"
        index = json.loads(index_path.read_bytes())
        index["marker"]["files"]["../escape"] = export.fingerprint(b"escape")
        index_path.write_text(json.dumps(index))
        self.assertEqual(export.main(["verify", str(self.root / "restored")]), 125)

    def test_builder_failure_and_legacy_graph_rejection(self):
        source = prepare(self.root / "rules")
        root = source / os.readlink(source / "compiled.yac.inputs")
        manifest = root / "manifest.json"
        state = json.loads(manifest.read_bytes())
        original = manifest.read_bytes()
        state["schema"] = 1
        manifest.write_text(json.dumps(state))
        self.assertEqual(marker.main([str(source)]), 125)
        self.assertFalse((source / "marker-artifact").exists())
        manifest.write_bytes(original)
        main = source / "compiled.yac"
        original_main = main.read_bytes()
        main.write_bytes(b"bad")
        self.assertEqual(marker.main([str(source)]), 125)
        main.write_bytes(original_main)
        inputs = source / "src/a.yar"
        saved = inputs.read_bytes()
        inputs.write_bytes(b"bad")
        self.assertEqual(marker.main([str(source)]), 125)
        inputs.write_bytes(saved)
        pointer = source / "compiled.yac.inputs"
        saved = os.readlink(pointer)
        for target in ("../escape", "/absolute", "missing"):
            pointer.unlink()
            pointer.symlink_to(target)
            self.assertEqual(marker.main([str(source)]), 125)
        pointer.unlink()
        self.assertEqual(marker.main([str(source)]), 125)
        pointer.symlink_to(saved)
        alias = self.root / "alias"
        alias.symlink_to(source)
        self.assertEqual(marker.main([str(alias)]), 125)
        self.assertEqual(marker.main([]), 125)
        with mock.patch.object(marker.capture, "run", return_value=1):
            self.assertEqual(marker.main([str(source)]), 125)
        original_run = marker.capture.run
        with mock.patch.object(
            marker.capture,
            "run",
            side_effect=lambda root, phase, *args: (
                1 if phase == "final" else original_run(root, phase, *args)
            ),
        ):
            self.assertEqual(marker.main([str(source)]), 125)
        call = mock.Mock(return_value=-1)
        with (
            mock.patch.object(marker.ctypes, "CDLL") as lib,
            mock.patch.object(marker.ctypes, "get_errno", return_value=17),
        ):
            lib.return_value.renameat2 = call
            self.assertEqual(marker.main([str(source)]), 125)
        self.assertFalse((source / "marker-artifact").exists())
        self.assertEqual(marker.main([str(source)]), 0)
        self.assertEqual(marker.main([str(source)]), 125)

    def test_descriptor_invalid_and_graph_selection_boundaries(self):
        with self.assertRaisesRegex(marker.MarkerError, "descriptor"):
            marker.descriptor(b"T\t00\n")
        graph = {
            "inventory": [
                {
                    "native_index": 0,
                    "namespace": "missing",
                    "identifier": "M",
                    "flags": 0,
                    "tags": ["marker"],
                }
            ],
            "references": [],
        }
        with self.assertRaisesRegex(marker.MarkerError, "namespace"):
            marker.selection({"validations": []}, graph)

    def test_import_and_script_entry(self):
        with (
            mock.patch("importlib.util.spec_from_file_location", return_value=None),
            self.assertRaisesRegex(RuntimeError, "loader"),
        ):
            runpy.run_path(
                str(REPO / "docker/build-marker-artifact.py"), run_name="test_import"
            )
        original_spec = importlib.util.spec_from_file_location
        with (
            mock.patch(
                "importlib.util.spec_from_file_location",
                side_effect=lambda name, path: (
                    None if name == "marker_artifact" else original_spec(name, path)
                ),
            ),
            self.assertRaisesRegex(RuntimeError, "marker helper loader"),
        ):
            runpy.run_path(
                str(REPO / "docker/export-compiler-inputs.py"), run_name="test_import"
            )
        with (
            mock.patch.object(sys, "argv", ["build-marker-artifact.py"]),
            self.assertRaises(SystemExit) as result,
        ):
            runpy.run_path(
                str(REPO / "docker/build-marker-artifact.py"), run_name="__main__"
            )
        self.assertEqual(result.exception.code, 125)


if __name__ == "__main__":
    unittest.main()
