package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func clamIdentityFixture() clamIdentity {
	return clamIdentity{"sha256:" + digest([]byte("image")), digest([]byte("rootfs")), digest([]byte("engine")), digest([]byte("database")), "ClamAV 1.5.3/28048/Thu Jul  2 06:25:04 2026"}
}

func clamRequestFixture() clamBridgeRequest {
	return clamBridgeRequest{Version: 1, Operation: "scan", Name: "mailstrix-clamav-" + strings.Repeat("a", 32), Identity: clamIdentityFixture(), ManifestSHA256: digest([]byte("manifest")), SampleSHA256: digest(nil), InputUnit: "file", ScanArgs: []string{"--stdin"}}
}

func clamReplyFixture(req clamBridgeRequest) clamBridgeReply {
	return clamBridgeReply{Version: 1, Name: req.Name, ManifestSHA256: req.ManifestSHA256, SampleSHA256: req.SampleSHA256, Size: req.Size, InputUnit: req.InputUnit, Identity: req.Identity, ScanArgs: req.ScanArgs,
		clamObservation: clamObservation{Status: "no_detection", Detections: []string{}, Diagnostics: []clamDiagnostic{}}}
}

func TestClamReplyBindingsAndUnknowns(t *testing.T) {
	req := clamRequestFixture()
	raw, _ := json.Marshal(clamReplyFixture(req))
	if _, err := decodeClamReply(raw, req); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*clamBridgeReply)
	}{
		{"container", func(r *clamBridgeReply) { r.Name += "b" }},
		{"manifest", func(r *clamBridgeReply) { r.ManifestSHA256 = digest(nil) }},
		{"sample", func(r *clamBridgeReply) { r.SampleSHA256 = digest([]byte("wrong")) }},
		{"size", func(r *clamBridgeReply) { r.Size++ }},
		{"unit", func(r *clamBridgeReply) { r.InputUnit = "message" }},
		{"database", func(r *clamBridgeReply) { r.Identity.DatabaseSHA256 = digest(nil) }},
		{"policy", func(r *clamBridgeReply) { r.ScanArgs = []string{"--different"} }},
		{"terminal success", func(r *clamBridgeReply) { r.Terminal = true }},
		{"empty detection", func(r *clamBridgeReply) { r.Status = "detection" }},
		{"heuristic", func(r *clamBridgeReply) { r.Status = "detection"; r.Detections = []string{"Heuristics.Inert"} }},
		{"failure detection", func(r *clamBridgeReply) { r.Status = "timeout"; r.Detections = []string{"Inert.Test"} }},
		{"duplicate detection", func(r *clamBridgeReply) { r.Status = "detection"; r.Detections = []string{"Inert.Test", "Inert.Test"} }},
		{"unknown status", func(r *clamBridgeReply) { r.Status = "new-success" }},
		{"missing detections", func(r *clamBridgeReply) { r.Detections = nil }},
		{"missing diagnostics", func(r *clamBridgeReply) { r.Diagnostics = nil }},
		{"undeclared warning", func(r *clamBridgeReply) {
			r.Diagnostics = []clamDiagnostic{{"historical_database_age", clamAgeWarning}}
		}},
		{"altered warning", func(r *clamBridgeReply) {
			r.DatabaseStale = true
			r.Diagnostics = []clamDiagnostic{{"historical_database_age", clamAgeWarning + "x"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := clamReplyFixture(req)
			tc.edit(&r)
			raw, _ := json.Marshal(r)
			if _, err := decodeClamReply(raw, req); err == nil {
				t.Fatal("invalid reply accepted")
			}
		})
	}
	for _, bad := range [][]byte{append(raw, []byte(`{}`)...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"Version":1`), 1), raw[:len(raw)-1], bytes.Repeat([]byte(" "), clamBridgeLimit+1)} {
		if _, err := decodeClamReply(bad, req); err == nil {
			t.Fatal("invalid framing accepted")
		}
	}
}

// Real isolated subprocesses exercise stdin framing, bounds, deadlines, direct
// child reaping and exact-name cleanup. They never launch Docker or a scanner.
func TestClamBridgeProcessFailures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process groups")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, script string
		budget       time.Duration
		wantError    bool
	}{
		{"success", `import json,sys
r=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read()
out={k:r[k] for k in ('version','name','manifest_sha256','sample_sha256','size','input_unit','identity','scan_args')}
out.update(status='no_detection',detections=[],diagnostics=[],database_stale=False,terminal=False)
print(json.dumps(out))`, time.Second, false},
		{"death before create", `import sys;sys.exit(7)`, time.Second, true},
		{"death after request", `import json,sys;r=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read();sys.exit(7)`, time.Second, true},
		{"timeout", `import time;time.sleep(60)`, 100 * time.Millisecond, true},
		{"stdout bound", `import sys;sys.stdout.write('x'*70000)`, time.Second, true},
		{"stderr bound", `import sys;sys.stderr.write('x'*70000)`, time.Second, true},
		{"malformed", `print('{}')`, time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cleanupOK := range []bool{true, false} {
				var diagnostic bytes.Buffer
				var cmd *exec.Cmd
				name, cleaned := "", ""
				b := clamBridge{budget: tc.budget, diagnostics: &diagnostic,
					command: func(ctx context.Context, chosen string) *exec.Cmd {
						name = chosen
						cmd = exec.CommandContext(ctx, python, "-I", "-c", tc.script)
						return cmd
					},
					cleanup: func(chosen string) bool {
						cleaned = chosen
						if cmd.ProcessState == nil {
							t.Fatal("cleanup before direct child reaped")
						}
						return cleanupOK
					},
				}
				_, err := b.invoke(clamRequestFixture(), nil)
				if (err != nil) != tc.wantError || b.stopped != tc.wantError {
					t.Fatalf("error=%v stopped=%t", err, b.stopped)
				}
				if cmd.ProcessState == nil {
					t.Fatal("bridge child not reaped")
				}
				if tc.wantError {
					if name == "" || cleaned != name || !strings.Contains(diagnostic.String(), name) {
						t.Fatal("exact uncertainty identity lost")
					}
					if _, err := b.invoke(clamRequestFixture(), nil); err == nil {
						t.Fatal("terminal backend reused")
					}
				} else if cleaned != "" || diagnostic.Len() != 0 {
					t.Fatal("normal bridge duplicated lifecycle ownership")
				}
			}
		})
	}
}
