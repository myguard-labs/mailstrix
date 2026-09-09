package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
	raw, err := json.Marshal(clamReplyFixture(req))
	if err != nil {
		t.Fatal(err)
	}
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
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
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
		name, script, cause string
		budget              time.Duration
		wantError           bool
	}{
		{"success", `import json,sys
r=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read()
out={k:r[k] for k in ('version','name','manifest_sha256','sample_sha256','size','input_unit','identity','scan_args')}
out.update(status='no_detection',detections=[],diagnostics=[],database_stale=False,terminal=False)
print(json.dumps(out))`, "", 30 * time.Second, false},
		{"death before create", `import sys;sys.exit(7)`, "process", 30 * time.Second, true},
		{"death after create", `import json,sys;r=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read();sys.exit(7)`, "process", 30 * time.Second, true},
		{"timeout", `import time;time.sleep(60)`, "timeout", 100 * time.Millisecond, true},
		{"stdout bound", `import sys;sys.stdout.write('x'*70000)`, "output_limit", 30 * time.Second, true},
		{"stderr bound", `import sys;sys.stderr.write('x'*70000)`, "output_limit", 30 * time.Second, true},
		{"stderr diagnostic", `import sys;sys.stderr.write('PRIVATE_SENTINEL')`, "unexpected_diagnostics", 30 * time.Second, true},
		{"truncated reply", `import sys;sys.stdout.write('{"version":')`, "invalid_reply", 30 * time.Second, true},
		{"identity mismatch", `import json,sys
r=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read()
out={k:r[k] for k in ('version','name','manifest_sha256','sample_sha256','size','input_unit','identity','scan_args')}
out.update(name=r['name']+'x',status='no_detection',detections=[],diagnostics=[],database_stale=False,terminal=False)
print(json.dumps(out))`, "invalid_reply", 30 * time.Second, true},
		{"malformed", `print('{}')`, "invalid_reply", 30 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cleanupOK := range []bool{true, false} {
				var diagnostic bytes.Buffer
				var cmd *exec.Cmd
				name, cleaned := "", ""
				commands := 0
				b := clamBridge{budget: tc.budget, diagnostics: &diagnostic,
					command: func(ctx context.Context, chosen string) *exec.Cmd {
						commands++
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
					wantDiagnostic := "container=" + name + " cause=" + tc.cause + " cleanup_confirmed=" + strconv.FormatBool(cleanupOK) + "; backend stopped"
					if name == "" || cleaned != name || !strings.Contains(diagnostic.String(), wantDiagnostic) {
						t.Fatal("exact uncertainty identity lost")
					}
					if strings.Contains(diagnostic.String(), "PRIVATE_SENTINEL") {
						t.Fatal("private bridge diagnostic leaked")
					}
					if _, err := b.invoke(clamRequestFixture(), nil); err == nil {
						t.Fatal("terminal backend reused")
					}
					if commands != 1 {
						t.Fatalf("terminal backend started %d bridge processes", commands)
					}
				} else if cleaned != "" || diagnostic.Len() != 0 {
					t.Fatal("normal bridge duplicated lifecycle ownership")
				}
			}
		})
	}
}

func TestClamBridgeFailureCausePrecedence(t *testing.T) {
	deadline := context.DeadlineExceeded
	if got := clamBridgeFailureCause(clamBridgeOutcome{groupAbsent: false, runErr: deadline, groupErr: errors.New("quiescence"), contextErr: deadline, outputOverflow: true, diagnosticOverflow: true, diagnosticBytes: 1}); got != "group_cleanup" {
		t.Fatalf("group cleanup did not take precedence: %s", got)
	}
	if got := clamBridgeFailureCause(clamBridgeOutcome{groupAbsent: true, runErr: context.Canceled, contextErr: context.Canceled, outputOverflow: true}); got != "output_limit" {
		t.Fatalf("output limit did not take precedence over cancellation: %s", got)
	}
}

func TestClamBridgeStartFailureDoesNotInventContainerCleanup(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("Linux process groups")
	}
	var diagnostic bytes.Buffer
	cleanupCalls := 0
	b := clamBridge{
		diagnostics: &diagnostic,
		command: func(ctx context.Context, _ string) *exec.Cmd {
			return exec.CommandContext(ctx, "/inert/missing-clamav-bridge")
		},
		cleanup: func(string) bool {
			cleanupCalls++
			return false
		},
	}
	if _, err := b.invoke(clamRequestFixture(), nil); err == nil {
		t.Fatal("missing bridge executable accepted")
	}
	if cleanupCalls != 0 || !strings.Contains(diagnostic.String(), "cause=process cleanup_confirmed=true") {
		t.Fatalf("start failure invented container cleanup: calls=%d diagnostic=%q", cleanupCalls, diagnostic.String())
	}
}

func TestClamBridgeInterpreterIgnoresCallerPath(t *testing.T) {
	pathDir := t.TempDir()
	t.Setenv("PATH", pathDir)
	interpreter := filepath.Join(pathDir, "python3")
	if err := os.WriteFile(interpreter, []byte("inert"), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(interpreter)
	if err != nil {
		t.Fatal(err)
	}
	originalStat := statClamBridgePython
	defer func() { statClamBridgePython = originalStat }()
	originalAccess := accessClamBridgePython
	defer func() { accessClamBridgePython = originalAccess }()
	statClamBridgePython = func(string) (os.FileInfo, error) {
		return info, nil
	}
	accessClamBridgePython = func(string) bool { return true }
	cmd := clamBridgeCommand(context.Background(), "/inert-bridge")
	if cmd.Err != nil || cmd.Path != "/usr/bin/python3" || len(cmd.Args) < 4 || cmd.Args[1] != "-I" || cmd.Args[2] != "-B" || cmd.Args[3] != "-c" {
		t.Fatalf("bridge interpreter not pinned and isolated: path=%q args=%q command_err=%v", cmd.Path, cmd.Args, cmd.Err)
	}
	statClamBridgePython = func(string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	err = (&clamBridge{}).setup("/inert", "engine", digest([]byte("manifest")))
	statClamBridgePython = originalStat
	if err == nil || err.Error() != "ClamAV bridge requires executable /usr/bin/python3" {
		t.Fatalf("command missing-interpreter diagnosis=%v", err)
	}
	statClamBridgePython = func(string) (os.FileInfo, error) { return info, nil }
	accessClamBridgePython = func(string) bool { return false }
	err = (&clamBridge{}).setup("/inert", "engine", digest([]byte("manifest")))
	if err == nil || err.Error() != "ClamAV bridge requires executable /usr/bin/python3" {
		t.Fatalf("inaccessible interpreter diagnosis=%v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing-python")
	statClamBridgePython = originalStat
	accessClamBridgePython = originalAccess
	if err := requireClamBridgePython(missing); err == nil || err.Error() != "ClamAV bridge requires executable /usr/bin/python3" {
		t.Fatalf("missing interpreter diagnosis=%v", err)
	}
	nonExecutable := filepath.Join(t.TempDir(), "python3")
	if err := os.WriteFile(nonExecutable, []byte("inert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireClamBridgePython(nonExecutable); err == nil || err.Error() != "ClamAV bridge requires executable /usr/bin/python3" {
		t.Fatalf("non-executable interpreter diagnosis=%v", err)
	}
}

func TestClamBridgeInterpreterRemovalStopsLaterInvocation(t *testing.T) {
	originalStat := statClamBridgePython
	defer func() { statClamBridgePython = originalStat }()
	statClamBridgePython = func(string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	var diagnostic bytes.Buffer
	b := clamBridge{diagnostics: &diagnostic}
	if _, err := b.invoke(clamRequestFixture(), nil); !errors.Is(err, errClamBridgePython) || !b.stopped {
		t.Fatalf("removed interpreter did not stop bridge: stopped=%t err=%v", b.stopped, err)
	}
	if got := diagnostic.String(); got != errClamBridgePython.Error()+"\n" {
		t.Fatalf("removed interpreter diagnostic=%q", got)
	}
}

func TestClamBridgeTerminalReplyRetainsExactName(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process groups")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	name := ""
	commands := 0
	b := clamBridge{budget: time.Second, diagnostics: &diagnostic,
		command: func(ctx context.Context, chosen string) *exec.Cmd {
			commands++
			name = chosen
			return exec.CommandContext(ctx, python, "-I", "-c", `import json,sys
r=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read()
out={k:r[k] for k in ('version','name','manifest_sha256','sample_sha256','size','input_unit','identity','scan_args')}
out.update(status='cleanup_error',detections=[],diagnostics=[],database_stale=False,terminal=True)
print(json.dumps(out))`)
		},
		cleanup: func(string) bool {
			t.Fatal("terminal reply duplicated Python-owned cleanup")
			return false
		},
	}
	reply, err := b.invoke(clamRequestFixture(), nil)
	if err != nil || reply.Status != "cleanup_error" || !reply.Terminal || !b.stopped {
		t.Fatalf("terminal reply=%+v error=%v stopped=%t", reply, err, b.stopped)
	}
	if name == "" || !strings.Contains(diagnostic.String(), "container="+name) {
		t.Fatalf("terminal name not retained: %q", diagnostic.String())
	}
	if _, err := b.invoke(clamRequestFixture(), nil); err == nil || commands != 1 {
		t.Fatalf("terminal backend reused: error=%v commands=%d", err, commands)
	}
}
