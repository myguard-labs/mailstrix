package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func isolatedTestIdentity() isolatedIdentity {
	return isolatedIdentity{digest([]byte("test binary")), "4.5.2", "go1.26.8", "linux/amd64", digest([]byte("test rules"))}
}

func isolatedTestResponse(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(isolatedResponse{1, "ok", isolatedTestIdentity(), []symbol{}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIsolatedFraming(t *testing.T) {
	data := []byte("inert content")
	r := isolatedRequest{1, "scan", "html", "file", int64(len(data)), digest(data)}
	good, err := encodeIsolatedRequest(r, data)
	if err != nil {
		t.Fatal(err)
	}
	decoded, payload, err := decodeIsolatedRequest(bytes.NewReader(good))
	if headerSize := binary.BigEndian.Uint32(good[:4]); headerSize == 0 || headerSize > isolatedHeaderLimit {
		t.Fatalf("outgoing header violates decoder bound: %d", headerSize)
	}
	if err != nil || decoded != r || !bytes.Equal(payload, data) {
		t.Fatalf("roundtrip: %v", err)
	}
	for name, b := range map[string][]byte{
		"truncated prefix": good[:2], "empty header": {0, 0, 0, 0}, "oversized header": {0, 0, 32, 0},
		"truncated header": good[:12], "truncated payload": good[:len(good)-1],
		"trailing byte": append(slices.Clone(good), 'x'), "wrong hash": append(slices.Clone(good[:len(good)-1]), 'X'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeIsolatedRequest(bytes.NewReader(b)); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
	header, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"duplicate":        bytes.Replace(header, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"case":             bytes.Replace(header, []byte(`"version"`), []byte(`"Version"`), 1),
		"missing":          bytes.Replace(header, []byte(`"version":1,`), nil, 1),
		"unknown":          bytes.Replace(header, []byte(`"version":1`), []byte(`"version":1,"other":1`), 1),
		"version":          bytes.Replace(header, []byte(`"version":1`), []byte(`"version":2`), 1),
		"format":           bytes.Replace(header, []byte(`"html"`), []byte(`"unknown"`), 1),
		"unit":             bytes.Replace(header, []byte(`"file"`), []byte(`"unknown"`), 1),
		"oversize":         bytes.Replace(header, []byte(`"size":13`), []byte(`"size":16777217`), 1),
		"negative size":    bytes.Replace(header, []byte(`"size":13`), []byte(`"size":-1`), 1),
		"trailing message": append(slices.Clone(header), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			var frame bytes.Buffer
			if err := binary.Write(&frame, binary.BigEndian, uint32(len(b))); err != nil {
				t.Fatal(err)
			}
			frame.Write(b)
			frame.Write(data)
			if _, _, err := decodeIsolatedRequest(&frame); err == nil {
				t.Fatal("accepted invalid header")
			}
		})
	}
	identity, err := encodeIsolatedRequest(isolatedRequest{Version: 1, Operation: "identity"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeIsolatedRequest(bytes.NewReader(identity)); err != nil {
		t.Fatal(err)
	}
	r.Size = maxSample + 1
	if _, err := encodeIsolatedRequest(r, data); err == nil {
		t.Fatal("accepted oversized outgoing frame")
	}
}

func TestIsolatedResponseBoundary(t *testing.T) {
	good := isolatedTestResponse(t)
	if _, err := decodeIsolatedResponse(good); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"duplicate":      bytes.Replace(good, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"unknown":        bytes.Replace(good, []byte(`"version":1`), []byte(`"version":1,"other":0`), 1),
		"case":           bytes.Replace(good, []byte(`"status"`), []byte(`"STATUS"`), 1),
		"missing":        bytes.Replace(good, []byte(`"version":1,`), nil, 1),
		"null symbols":   bytes.Replace(good, []byte(`"symbols":[]`), []byte(`"symbols":null`), 1),
		"unknown status": bytes.Replace(good, []byte(`"ok"`), []byte(`"clean"`), 1),
		"bad identity":   bytes.Replace(good, []byte(`"4.5.2"`), []byte(`"unknown"`), 1),
		"trailing":       append(slices.Clone(good), []byte(`{}`)...), "truncated": good[:len(good)-1],
		"oversize": bytes.Repeat([]byte(" "), isolatedOutputLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeIsolatedResponse(b); err == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
	for _, symbols := range [][]symbol{{{"namespace", "valid"}, {"namespace", "valid"}}, {{"namespace", "bad\nname"}}, make([]symbol, isolatedSymbolLimit+1)} {
		b, err := json.Marshal(isolatedResponse{1, "ok", isolatedTestIdentity(), symbols})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeIsolatedResponse(b); err == nil {
			t.Fatal("accepted invalid symbols")
		}
	}
	for _, status := range []string{"error", "timeout", "indeterminate"} {
		b, err := json.Marshal(isolatedResponse{1, status, isolatedTestIdentity(), []symbol{{"ns", "rule"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeIsolatedResponse(b); err == nil {
			t.Fatal("failure carried symbols")
		}
	}
}

const isolatedEffectiveFixture = `{"Image":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Config":{"User":"65534:65534","Entrypoint":["/usr/local/bin/parity"],"Cmd":["isolated-worker-v1"],"OpenStdin":true},"Mounts":[],"HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"Privileged":false,"Binds":[],"VolumesFrom":[],"CapAdd":[],"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"PidMode":"","IpcMode":"private","CgroupnsMode":"private","PidsLimit":64,"NanoCpus":1000000000,"Memory":536870912,"MemorySwap":536870912,"Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,size=64m"},"LogConfig":{"Type":"none"},"Ulimits":[{"Name":"core","Soft":0,"Hard":0}]}}`

func isolatedTestDocker() isolatedDocker {
	return isolatedDocker{image: "sha256:" + strings.Repeat("a", 64), identity: isolatedTestIdentity()}
}

func TestIsolatedEffectiveControls(t *testing.T) {
	d := isolatedTestDocker()
	if !d.effective([]byte(isolatedEffectiveFixture)) {
		t.Fatal("valid controls rejected")
	}
	for _, pair := range [][2]string{
		{`"NetworkMode":"none"`, `"NetworkMode":"host"`}, {`"ReadonlyRootfs":true`, `"ReadonlyRootfs":false`},
		{`"Privileged":false`, `"Privileged":true`}, {`"Mounts":[]`, `"Mounts":[{}]`}, {`"Binds":[]`, `"Binds":["/tmp:/tmp"]`},
		{`"PidsLimit":64`, `"PidsLimit":0`}, {`"Memory":536870912`, `"Memory":0`}, {`"MemorySwap":536870912`, `"MemorySwap":-1`},
		{`"NanoCpus":1000000000`, `"NanoCpus":0`}, {`"CapDrop":["ALL"]`, `"CapDrop":[]`}, {`"CapAdd":[]`, `"CapAdd":["SYS_ADMIN"]`},
		{`"SecurityOpt":["no-new-privileges"]`, `"SecurityOpt":[]`}, {`"PidMode":""`, `"PidMode":"host"`},
		{`"IpcMode":"private"`, `"IpcMode":"host"`}, {`"CgroupnsMode":"private"`, `"CgroupnsMode":"host"`},
		{`"User":"65534:65534"`, `"User":"0"`}, {`"OpenStdin":true`, `"OpenStdin":false`},
		{`size=64m`, `size=128m`}, {`"Type":"none"`, `"Type":"json-file"`}, {`"Soft":0`, `"Soft":1`},
	} {
		t.Run(pair[0], func(t *testing.T) {
			if d.effective([]byte(strings.Replace(isolatedEffectiveFixture, pair[0], pair[1], 1))) {
				t.Fatal("accepted weakened effective control")
			}
		})
	}
	args := d.args("test-name")
	for _, flag := range []string{"--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--pids-limit=64", "--memory=512m", "--memory-swap=512m", "--cpus=1"} {
		if !slices.Contains(args, flag) {
			t.Fatalf("missing %s", flag)
		}
	}
	t.Setenv("DOCKER_HOST", "tcp://invalid.example:1234")
	t.Setenv("MAILSTRIX_SECRET_TEST", "inert")
	cmd := dockerCommand(context.Background(), "version")
	if !slices.Contains(cmd.Args, dockerSocket) || len(cmd.Env) != 1 || !strings.HasPrefix(cmd.Env[0], "PATH=") {
		t.Fatalf("inherited caller context: %v", cmd.Env)
	}
}

// The helper echoes only controlled fixtures; real pipes exercise cancellation,
// bounded stream writers and process exit status without a Docker daemon.
func TestIsolatedProcessHelper(t *testing.T) {
	i := slices.Index(os.Args, "--isolated-helper")
	if i < 0 {
		return
	}
	switch os.Args[i+1] {
	case "json":
		if _, err := os.Stdout.Write([]byte(os.Args[i+2])); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "wait":
		time.Sleep(10 * time.Second)
		os.Exit(1)
	case "error":
		os.Exit(7)
	case "stderr":
		if _, err := os.Stderr.Write([]byte("inert diagnostic")); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "overflow":
		if _, err := os.Stdout.Write(bytes.Repeat([]byte("x"), isolatedOutputLimit+1)); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "stderr-overflow":
		if _, err := os.Stderr.Write(bytes.Repeat([]byte("x"), isolatedOutputLimit+1)); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "empty":
		os.Exit(0)
	default:
		os.Exit(8)
	}
}

func fakeIsolatedDocker(t *testing.T, failOp, mode, cleanup string) (isolatedDocker, *[]processCall) {
	t.Helper()
	d := isolatedTestDocker()
	d.budget = 2 * time.Second
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	calls := []processCall{}
	coverDir := t.TempDir()
	d.command = func(ctx context.Context, args ...string) *exec.Cmd {
		operation := args[0]
		m, b := "empty", ""
		switch operation {
		case "info":
			m, b = "json", `{"OSType":"linux","Architecture":"x86_64","CgroupVersion":"2","ServerVersion":"29.6.2","KernelVersion":"test-kernel","MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"PidsLimit":true,"SecurityOptions":["name=seccomp,profile=builtin"]}`
		case "image":
			m, b = "json", `{"Id":"`+d.image+`","Os":"linux","Architecture":"amd64","Config":{"Volumes":{}}}`
		case "inspect":
			m, b = "json", isolatedEffectiveFixture
		case "start":
			m, b = "json", string(isolatedTestResponse(t))
		case "ps":
			m = cleanup
		}
		if operation == failOp {
			m = mode
		}
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestIsolatedProcessHelper$", "--", "--isolated-helper", m, b)
		cmd.Env = []string{"GORACE=atexit_sleep_ms=0", "GOCOVERDIR=" + coverDir}
		cmd.WaitDelay = time.Second
		calls = append(calls, processCall{slices.Clone(args), cmd})
		return cmd
	}
	return d, &calls
}

func TestIsolatedExecutionFailures(t *testing.T) {
	for _, tc := range []struct{ op, mode, cleanup, want string }{
		{"", "", "empty", "ok"}, {"create", "error", "empty", "create_uncertain"}, {"inspect", "empty", "empty", "setup_error"},
		{"start", "error", "empty", "execution_error"}, {"start", "stderr", "empty", "execution_error"},
		{"start", "overflow", "empty", "output_limit"}, {"start", "stderr-overflow", "empty", "output_limit"},
		{"start", "wait", "empty", "timeout"}, {"start", "empty", "empty", "malformed_output"},
		{"", "", "error", "cleanup_error"}, {"rm", "error", "empty", "ok"},
	} {
		t.Run(tc.op+tc.mode+tc.cleanup, func(t *testing.T) {
			d, calls := fakeIsolatedDocker(t, tc.op, tc.mode, tc.cleanup)
			if tc.mode == "wait" {
				d.budget = 150 * time.Millisecond
			}
			data := []byte("inert")
			o := d.observe(sample{Format: "html", InputUnit: "file", Size: int64(len(data)), SHA256: digest(data)}, data)
			if o.Status != tc.want {
				t.Fatalf("status=%s want=%s", o.Status, tc.want)
			}
			name := (*calls)[0].args[2]
			n := len(*calls)
			if !slices.Equal((*calls)[n-2].args, []string{"rm", "--force", name}) || !slices.Equal((*calls)[n-1].args, []string{"ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"}) {
				t.Fatal("cleanup lost exact owned name")
			}
			for _, c := range *calls {
				if c.cmd.ProcessState == nil {
					t.Fatal("client not waited")
				}
			}
		})
	}
}

func TestIsolatedAliasesAndStopAfterUncertainty(t *testing.T) {
	m, hash, root := generated(t)
	for _, status := range []string{"cleanup_error", "create_uncertain", "identity_error", "setup_error"} {
		calls := 0
		r := isolatedCorpus(root, m, hash, isolatedTestDocker(), func(sample, []byte) observation { calls++; return observation{Status: status} })
		if calls != 1 || r.Complete || r.Summary.Pass || r.Summary.Statuses["not_run"] != len(m.Samples)-1 {
			t.Fatalf("continued after %s: calls=%d summary=%+v", status, calls, r.Summary)
		}
	}
	alias := m.Samples[0]
	alias.ID = "alias"
	alias.Locator = "missing-alias"
	m.Samples = append(m.Samples, alias)
	calls := 0
	r := isolatedCorpus(root, m, hash, isolatedTestDocker(), func(s sample, _ []byte) observation {
		calls++
		if s.SHA256 == alias.SHA256 {
			t.Fatal("invalid alias reached scanner")
		}
		return observation{Status: "ok"}
	})
	if calls != len(m.Samples)-2 || r.Complete || r.Summary.Statuses["integrity_error"] != 1 || r.Summary.Duplicates != 1 {
		t.Fatalf("alias accounting: %+v", r)
	}
}

func TestIsolatedCleanupFailureStopsCorpus(t *testing.T) {
	m, hash, root := generated(t)
	d, calls := fakeIsolatedDocker(t, "", "", "error")
	r := isolatedCorpus(root, m, hash, d, d.observe)
	starts := 0
	for _, c := range *calls {
		if c.args[0] == "start" {
			starts++
		}
	}
	if starts != 1 || r.Complete || r.Summary.Statuses["cleanup_error"] != 1 || r.Summary.Statuses["not_run"] != 5 {
		t.Fatalf("cleanup confirmation failure did not stop corpus: starts=%d statuses=%v", starts, r.Summary.Statuses)
	}
}

func TestIsolatedUncertainCreateStopsCorpus(t *testing.T) {
	m, hash, root := generated(t)
	for _, mode := range []string{"wait", "error", "stderr"} {
		t.Run(mode, func(t *testing.T) {
			d, calls := fakeIsolatedDocker(t, "create", mode, "empty")
			if mode == "wait" {
				d.budget = 150 * time.Millisecond
			}
			var diagnostic bytes.Buffer
			d.diagnostics = &diagnostic
			r := isolatedCorpus(root, m, hash, d, d.observe)
			if len(*calls) != 3 || (*calls)[0].args[0] != "create" || (*calls)[1].args[0] != "rm" || (*calls)[2].args[0] != "ps" || r.Complete || r.Summary.Statuses["create_uncertain"] != 1 || r.Summary.Statuses["not_run"] != 5 {
				t.Fatalf("inconclusive create continued despite current absence: calls=%d statuses=%v", len(*calls), r.Summary.Statuses)
			}
			name := (*calls)[0].args[2]
			if diagnostic.String() != "container creation uncertain: "+name+"; no sample sent; reconcile this exact owned name before retrying\n" {
				t.Fatal("exact owned reconciliation name missing from bounded local diagnostic")
			}
		})
	}
}

func TestIsolatedSetup(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		d, calls := fakeIsolatedDocker(t, "", "", "empty")
		if d.setup() == nil || len(*calls) != 0 {
			t.Fatal("unsupported platform reached daemon or was accepted")
		}
		return
	}
	for _, tc := range []struct {
		op, mode  string
		wantError bool
	}{
		{"", "", false}, {"info", "error", true}, {"info", "empty", true}, {"image", "error", true}, {"image", "empty", true}, {"start", "empty", true}, {"start", "error", true},
	} {
		t.Run(tc.op+tc.mode, func(t *testing.T) {
			d, _ := fakeIsolatedDocker(t, tc.op, tc.mode, "empty")
			err := d.setup()
			if (err != nil) != tc.wantError {
				t.Fatalf("setup error=%v", err)
			}
			if err == nil && (d.identity != isolatedTestIdentity() || d.runtime.DockerVersion != "29.6.2") {
				t.Fatal("setup lost qualified identity")
			}
		})
	}
	for _, image := range []string{"image:latest", "registry.example/image@sha256:" + strings.Repeat("a", 64), "sha256:short", "sha256:" + strings.Repeat("A", 64)} {
		d, calls := fakeIsolatedDocker(t, "", "", "empty")
		d.image = image
		if d.setup() == nil || len(*calls) != 0 {
			t.Fatal("invalid image reached daemon")
		}
	}
}

func TestIsolatedIdentityAndInputFailure(t *testing.T) {
	d, calls := fakeIsolatedDocker(t, "", "", "empty")
	data := []byte("inert")
	s := sample{Format: "html", InputUnit: "file", Size: 5, SHA256: digest(data)}
	bad := s
	bad.SHA256 = digest([]byte("other"))
	if o := d.observe(bad, data); o.Status != "integrity_error" || len(*calls) != 0 {
		t.Fatal("invalid outgoing sample launched")
	}
	d.identity.BinarySHA256 = digest([]byte("another binary"))
	if o := d.observe(s, data); o.Status != "identity_error" || len(o.Matches) != 0 {
		t.Fatal("response identity drift accepted")
	}
}

func TestIsolatedCLIUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"-rules", "host-rules"}, {"unexpected"}, {"-manifest", "missing", "-corpus-root", "missing", "-engine-image", "latest"}} {
		var stdout, stderr bytes.Buffer
		if code := cli(append([]string{"run-isolated"}, args...), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("invalid isolated CLI args accepted: %v", args)
		}
	}
}

func TestIsolatedReportAndSummaryOutput(t *testing.T) {
	for _, tc := range []struct {
		complete, pass bool
		want           int
	}{{true, true, 0}, {false, true, 1}, {true, false, 1}} {
		r := isolatedReport{Schema: "mailstrix-isolated-v1", Complete: tc.complete, Summary: summary{UniqueSamples: 2, Duplicates: 1, Pass: tc.pass}}
		var stdout, stderr bytes.Buffer
		if code := writeIsolatedReport(r, &stdout, &stderr); code != tc.want {
			t.Fatalf("exit=%d want=%d", code, tc.want)
		}
		var parsed isolatedReport
		if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil || parsed.Schema != r.Schema {
			t.Fatal("versioned JSON report missing")
		}
		want := fmt.Sprintf("isolated Mailstrix: 2 unique samples, 1 duplicates; complete=%t; labelled gate=%t; real-world precision unmeasured\n", tc.complete, tc.pass)
		if stderr.String() != want {
			t.Fatalf("human summary=%q want=%q", stderr.String(), want)
		}
	}
	for _, stream := range []string{"stdout", "stderr"} {
		var buffer bytes.Buffer
		var stdout, stderr io.Writer = &buffer, &buffer
		if stream == "stdout" {
			stdout = brokenWriter{}
		} else {
			stderr = brokenWriter{}
		}
		if code := writeIsolatedReport(isolatedReport{}, stdout, stderr); code != 2 {
			t.Fatalf("%s failure did not fail report", stream)
		}
	}
}

func TestIsolatedSummaryReproducible(t *testing.T) {
	m, hash, root := generated(t)
	observe := func(sample, []byte) observation {
		return observation{Status: "ok", Matches: []symbol{{"ns", "z"}, {"ns", "a"}}}
	}
	a := isolatedCorpus(root, m, hash, isolatedTestDocker(), observe)
	slices.Reverse(m.Samples)
	b := isolatedCorpus(root, m, hash, isolatedTestDocker(), observe)
	a.ElapsedMS = 0
	b.ElapsedMS = 0
	if !reflect.DeepEqual(a, b) {
		t.Fatal("input order changed isolated report")
	}
	if a.RealWorldPrecision != nil || a.Schema != "mailstrix-isolated-v1" {
		t.Fatal("report conflates contracts")
	}
}

func TestIsolatedReportBudgets(t *testing.T) {
	m, hash, root := generated(t)
	for _, tc := range []struct {
		name string
		d    isolatedDocker
		want time.Duration
	}{
		{"default", isolatedTestDocker(), isolatedBudget},
		{"test override", func() isolatedDocker {
			d := isolatedTestDocker()
			d.budget = 275 * time.Millisecond
			return d
		}(), 275 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := isolatedCorpus(root, m, hash, tc.d, func(sample, []byte) observation {
				return observation{Status: "ok"}
			})
			if r.ScanBudgetMS != isolatedScanBudget.Milliseconds() {
				t.Fatalf("scan budget=%d, want %d", r.ScanBudgetMS, isolatedScanBudget.Milliseconds())
			}
			if r.HostBudgetMS != tc.want.Milliseconds() {
				t.Fatalf("host budget=%d, want %d", r.HostBudgetMS, tc.want.Milliseconds())
			}
		})
	}
}
