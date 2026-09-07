package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const nativeCleanFixture = `[
{"script_name":"olevba","version":"0.60.2","type":"MetaInformation","python_version":[3,13,15]},
{"container":null,"file":"/tmp/private-path","json_conversion_successful":true,"analysis":null,"code_deobfuscated":null,"do_deobfuscate":false,"show_pcode":false,"type":"OpenXML","macros":[]}
]`

func testPins(t *testing.T) comparatorPins {
	t.Helper()
	pins, err := pinnedComparators()
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

func fixtureEnvelope(t *testing.T, status, output string, identity comparatorIdentity) []byte {
	t.Helper()
	b, err := json.Marshal(comparatorEnvelope{Identity: identity, Status: status, Output: output})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestComparatorIdentityAndNormalization(t *testing.T) {
	pins := testPins(t)
	id := comparatorIdentity{OletoolsVersion: pins.OletoolsVersion, OlefySHA256: pins.OlefySHA256}
	clean := normalizeComparator(fixtureEnvelope(t, "ok", nativeCleanFixture, id), pins)
	if clean.Status != "ok" || clean.HasMacros || clean.Format != "OpenXML" || len(clean.Categories) != 0 || clean.Identity != id {
		t.Fatalf("complete native no-macro observation lost: %+v", clean)
	}
	positive := strings.Replace(nativeCleanFixture, `"macros":[]`, `"macros":[{"code":null,"vba_filename":"inert","subfilename":"inert","ole_stream":"inert"}]`, 1)
	positive = strings.Replace(positive, `"analysis":null`, `"analysis":[{"type":"Suspicious","keyword":"private-string"},{"type":"AutoExec"},{"type":"Suspicious"}]`, 1)
	o := normalizeComparator(fixtureEnvelope(t, "ok", positive, id), pins)
	if o.Status != "ok" || !o.HasMacros || !slices.Equal(o.Categories, []string{"AutoExec", "Suspicious"}) {
		t.Fatalf("native category normalization: %+v", o)
	}
	for _, bad := range []comparatorIdentity{{}, {OletoolsVersion: "0.60.3", OlefySHA256: id.OlefySHA256}, {OletoolsVersion: id.OletoolsVersion, OlefySHA256: strings.Repeat("0", 64)}} {
		o := normalizeComparator(fixtureEnvelope(t, "ok", nativeCleanFixture, bad), pins)
		if o.Status != "pin_mismatch" || o.HasMacros || o.Format != "" {
			t.Fatalf("mismatched identity yielded an observation: %+v", o)
		}
	}
}

func TestComparatorFailuresNeverBecomeClean(t *testing.T) {
	pins := testPins(t)
	id := comparatorIdentity{OletoolsVersion: pins.OletoolsVersion, OlefySHA256: pins.OlefySHA256}
	for _, missing := range []comparatorIdentity{{}, {OletoolsVersion: pins.OletoolsVersion}} {
		o := normalizeComparator(fixtureEnvelope(t, "identity_error", nativeCleanFixture, missing), pins)
		if o.Status != "identity_error" || o.Format != "" || o.HasMacros {
			t.Fatalf("failed identity probe lost failure or yielded observation: %+v", o)
		}
		o = normalizeComparator(fixtureEnvelope(t, "ok", nativeCleanFixture, missing), pins)
		if o.Status != "pin_mismatch" {
			t.Fatalf("unqualified success accepted: %+v", o)
		}
	}
	for _, status := range []string{"timeout", "tool_error", "output_limit", "identity_error", "input_error", "malformed_output", "unexpected"} {
		t.Run(status, func(t *testing.T) {
			o := normalizeComparator(fixtureEnvelope(t, status, nativeCleanFixture, id), pins)
			if o.Status == "ok" || o.Format != "" || len(o.Categories) != 0 {
				t.Fatalf("failed transport yielded clean observation: %+v", o)
			}
		})
	}
	cases := map[string]string{
		"empty": "", "null": "null", "empty array": "[]", "truncated": nativeCleanFixture[:len(nativeCleanFixture)-1],
		"trailing": nativeCleanFixture + `{}`, "wrapper error": `[{"error":"File too small"}]`,
		"conversion failed":   strings.Replace(nativeCleanFixture, `"json_conversion_successful":true`, `"json_conversion_successful":false`, 1),
		"conversion absent":   strings.Replace(nativeCleanFixture, `"json_conversion_successful":true,`, "", 1),
		"macros absent":       strings.Replace(nativeCleanFixture, `,"macros":[]`, "", 1),
		"macros null":         strings.Replace(nativeCleanFixture, `"macros":[]`, `"macros":null`, 1),
		"analysis absent":     strings.Replace(nativeCleanFixture, `"analysis":null,`, "", 1),
		"wrong engine header": strings.Replace(nativeCleanFixture, `"version":"0.60.2"`, `"version":"0.60.3"`, 1),
		"unsupported text":    strings.Replace(nativeCleanFixture, `"type":"OpenXML"`, `"type":"Text"`, 1),
		"nested unit":         strings.Replace(nativeCleanFixture, `"container":null`, `"container":"decrypted"`, 1),
		"missing container":   strings.Replace(nativeCleanFixture, `"container":null,`, "", 1),
		"duplicate":           strings.Replace(nativeCleanFixture, `"macros":[]`, `"macros":[],"macros":[]`, 1),
		"extra error":         strings.Replace(nativeCleanFixture, `"macros":[]`, `"macros":[],"error":"partial parse"`, 1),
		"partial macro":       strings.Replace(nativeCleanFixture, `"macros":[]`, `"macros":[{}]`, 1),
		"contradiction":       strings.Replace(nativeCleanFixture, `"analysis":null`, `"analysis":[{"type":"AutoExec"}]`, 1),
		"log entry":           strings.TrimSuffix(nativeCleanFixture, "]") + `,{"type":"msg","level":"ERROR","message":"private diagnostic"}]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			o := normalizeComparator(fixtureEnvelope(t, "ok", raw, id), pins)
			if o.Status == "ok" || o.Format != "" || len(o.Categories) != 0 {
				t.Fatalf("invalid output yielded observation: %+v", o)
			}
		})
	}
}

func TestComparatorCorpusCompletenessAndPrivacy(t *testing.T) {
	m, hash, root := generated(t)
	pins := testPins(t)
	id := comparatorIdentity{OletoolsVersion: pins.OletoolsVersion, OlefySHA256: pins.OlefySHA256}
	called := 0
	observe := func(adapter string, data []byte) nativeObservation {
		called++
		if len(data) == 0 {
			t.Fatal("empty sample forwarded")
		}
		return normalizeComparator(fixtureEnvelope(t, "ok", nativeCleanFixture, id), pins)
	}
	r := compareCorpus(root, m, hash, pins, selectedAdapters("both"), observe)
	if r.Complete || r.UniqueSamples != 6 || r.Agreement["equal"] != 1 || r.Agreement["excluded"] != 5 || called != 2 {
		t.Fatalf("unsupported formats must withhold completeness: %+v; called %d", r, called)
	}
	for _, a := range r.Adapters {
		if a.Statuses["unsupported"] != 5 || a.WithoutMacros != 1 || a.WithMacros != 0 {
			t.Fatalf("failed sample counted clean: %+v", a)
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private-path", root.Name(), m.Samples[0].SHA256, m.Samples[0].Locator} {
		if bytes.Contains(b, []byte(private)) {
			t.Fatalf("report leaked sample data %q", private)
		}
	}
	// A caller-owned local Office manifest is accepted by compare independently
	// of the generator allowlist that still guards Mailstrix's run command.
	for _, s := range m.Samples {
		if s.Format == "office" {
			m.Samples = []sample{s}
			break
		}
	}
	m.Samples[0].Partition = "external-unlabelled"
	r = compareCorpus(root, m, hash, pins, selectedAdapters("both"), observe)
	if !r.Complete || r.Agreement["equal"] != 1 {
		t.Fatalf("local Office comparison incomplete: %+v", r)
	}
	for _, failure := range []string{"timeout", "pin_mismatch", "tool_error", "malformed_output", "cleanup_error"} {
		r = compareCorpus(root, m, hash, pins, selectedAdapters("both"), func(string, []byte) nativeObservation { return nativeObservation{Status: failure} })
		if r.Complete || r.Agreement["excluded"] != 1 || r.Adapters["oletools"].WithoutMacros != 0 {
			t.Fatalf("failure became clean: %+v", r)
		}
	}
	alias := m.Samples[0]
	alias.ID, alias.Locator = "alias", "missing-private-file"
	m.Samples = append(m.Samples, alias)
	called = 0
	r = compareCorpus(root, m, hash, pins, selectedAdapters("both"), observe)
	if called != 0 || r.Complete || r.Duplicates != 1 || r.Adapters["olefy"].Statuses["integrity_error"] != 1 {
		t.Fatalf("bad alias bypassed integrity: %+v", r)
	}
}

func TestComparatorCommandIsolationAndOutputBound(t *testing.T) {
	pins := testPins(t)
	d := dockerComparator{pins: pins}
	args := d.args("mailstrix-parity-test", "olefy")
	for _, required := range []string{"--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534", "--pids-limit=32", "--cpus=1", "--memory=256m", "--memory-swap=256m", "--log-driver=none", pins.Image + "@" + pins.IndexDigest, pins.Platform} {
		if !slices.Contains(args, required) {
			t.Fatalf("missing confinement flag %s", required)
		}
	}
	for _, arg := range args {
		if arg == "--volume" || arg == "--mount" || arg == "-v" || arg == "--publish" || arg == "-p" || strings.Contains(arg, ":latest") {
			t.Fatalf("unconfined comparator argument %q", arg)
		}
	}
	t.Setenv("DOCKER_HOST", "tcp://private.example.invalid:2375")
	t.Setenv("DOCKER_CONTEXT", "remote")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := dockerCommand(ctx, "version")
	if !slices.Equal(cmd.Args[1:3], []string{"--host", dockerSocket}) || len(cmd.Env) != 1 || !strings.HasPrefix(cmd.Env[0], "PATH=") {
		t.Fatalf("remote context or environment leaked: %v %v", cmd.Args, cmd.Env)
	}
	output := &boundedComparatorOutput{limit: 4, cancel: cancel}
	if n, err := output.Write([]byte("1234")); n != 4 || err != nil {
		t.Fatalf("boundary write: %d %v", n, err)
	}
	if _, err := output.Write([]byte("5")); err == nil || !output.overflow || output.Len() != 4 || ctx.Err() != context.Canceled {
		t.Fatal("oversized comparator output did not cancel execution")
	}
}

func TestCompareCLIRejectsInvalidAdapterWithoutDocker(t *testing.T) {
	_, _, root := generated(t)
	var stdout, stderr bytes.Buffer
	args := []string{"compare", "-manifest", filepath.Join(root.Name(), "manifest.json"), "-corpus-root", root.Name(), "-adapter", "moving-tag"}
	if code := cli(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatalf("invalid adapter exit=%d output=%s", code, stdout.String())
	}
}
