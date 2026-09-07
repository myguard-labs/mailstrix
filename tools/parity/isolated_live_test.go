//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Only the separate parity-probe-runtime test image uses these entrypoints.
// Each probe is finite even if an isolation control is deliberately mutated.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "isolated-worker-v1" {
		os.Exit(inertIsolationProbe())
	}
	if len(os.Args) == 2 && os.Args[1] == "inert-child" {
		time.Sleep(8 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type inertProbeRequest struct{ Mode, Sentinel, Address string }
type inertProbeResult struct {
	UID                                                                          int
	HostInaccessible, NetworkInaccessible, RootReadOnly                          bool
	CapEff, NoNewPrivs, Seccomp, MemoryMax, SwapMax, PidsMax, CPUmax, PidsEvents string
}

func probeRead(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(b))
}

func inertIsolationProbe() int {
	r, data, err := decodeIsolatedRequest(os.Stdin)
	if err != nil {
		return 2
	}
	if r.Operation == "identity" {
		if json.NewEncoder(os.Stdout).Encode(isolatedResponse{1, "ok", isolatedTestIdentity(), []symbol{}}) != nil {
			return 2
		}
		return 0
	}
	var request inertProbeRequest
	if json.Unmarshal(data, &request) != nil {
		return 2
	}
	switch request.Mode {
	case "timeout":
		if _, err := io.WriteString(os.Stdout, "probe-ready"); err != nil {
			return 2
		}
		time.Sleep(8 * time.Second) // intentionally no cooperative cancellation
		return 0
	case "memory":
		if _, err := io.WriteString(os.Stdout, "probe-ready"); err != nil {
			return 2
		}
		// Finite 640 MiB ceiling; touching each page crosses the fixed 512 MiB
		// cgroup budget. This never accepts attacker-supplied allocation sizes.
		chunks := make([][]byte, 0, 640)
		for range 640 {
			b := make([]byte, 1<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			chunks = append(chunks, b)
		}
		runtime.KeepAlive(chunks)
		return 0
	case "controls", "pids":
	default:
		return 2
	}
	result := inertProbeResult{UID: os.Getuid(), MemoryMax: probeRead("/sys/fs/cgroup/memory.max"), SwapMax: probeRead("/sys/fs/cgroup/memory.swap.max"), PidsMax: probeRead("/sys/fs/cgroup/pids.max"), CPUmax: probeRead("/sys/fs/cgroup/cpu.max")}
	for line := range strings.SplitSeq(probeRead("/proc/self/status"), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "CapEff":
			result.CapEff = value
		case "NoNewPrivs":
			result.NoNewPrivs = value
		case "Seccomp":
			result.Seccomp = value
		}
	}
	if request.Mode == "controls" {
		_, err := os.Stat(request.Sentinel)
		result.HostInaccessible = errors.Is(err, os.ErrNotExist)
		conn, err := net.DialTimeout("tcp", request.Address, 200*time.Millisecond)
		result.NetworkInaccessible = err != nil
		if err == nil {
			_ = conn.Close()
		}
		err = os.WriteFile("/probe-writable/inert", []byte("inert"), 0600)
		result.RootReadOnly = errors.Is(err, syscall.EROFS)
	} else {
		children := make([]*exec.Cmd, 0, 80)
		defer func() {
			for _, cmd := range children {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		for range 80 {
			cmd := exec.CommandContext(ctx, "/usr/local/bin/parity", "inert-child")
			cmd.Env = []string{"GOMAXPROCS=1"}
			cmd.WaitDelay = time.Second
			if cmd.Start() != nil {
				break
			}
			children = append(children, cmd)
		}
		result.PidsEvents = probeRead("/sys/fs/cgroup/pids.events")
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 2
	}
	return 0
}

func liveIsolatedDocker(t *testing.T, variable string) (isolatedDocker, *[]string) {
	t.Helper()
	image := os.Getenv(variable)
	if image == "" {
		if os.Getenv("PARITY_ISOLATION_REQUIRED") == "1" {
			t.Fatalf("required qualification image missing: %s", variable)
		}
		t.Skip("explicit local qualification image not supplied")
	}
	d := isolatedDocker{image: image}
	names := []string{}
	d.command = func(ctx context.Context, args ...string) *exec.Cmd {
		if args[0] == "create" {
			names = append(names, args[2])
		}
		return dockerCommand(ctx, args...)
	}
	t.Cleanup(func() {
		for _, name := range names {
			if !d.cleanup(name) {
				t.Errorf("qualification could not remove owned container %s", name)
			}
		}
	})
	if err := d.setup(); err != nil {
		t.Fatal(err)
	}
	return d, &names
}

func liveProbeInput(t *testing.T, r inertProbeRequest) []byte {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encodeIsolatedRequest(isolatedRequest{1, "scan", "html", "file", int64(len(data)), digest(data)}, data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertLiveAbsent(t *testing.T, d isolatedDocker, names []string) {
	t.Helper()
	for _, name := range slices.Backward(names) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		b, status := d.call(ctx, nil, "ps", "--all", "--quiet", "--filter", "name=^/"+name+"$")
		cancel()
		if status != "ok" || len(bytes.TrimSpace(b)) != 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			running, _ := d.call(ctx, nil, "inspect", "--format={{.State.Running}}", name)
			cancel()
			t.Fatalf("owned container remains after launch: %s (%s; running=%s)", name, status, bytes.TrimSpace(running))
		}
	}
}

func TestIsolatedLiveControls(t *testing.T) {
	d, names := liveIsolatedDocker(t, "PARITY_PROBE_IMAGE")
	sentinel := filepath.Join(t.TempDir(), "host-sentinel")
	if err := os.WriteFile(sentinel, []byte("inert sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	// A successful host-side connection establishes the positive network arm.
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	b, status := d.launch(liveProbeInput(t, inertProbeRequest{"controls", sentinel, listener.Addr().String()}))
	if status != "ok" {
		t.Fatalf("controls probe: %s", status)
	}
	var r inertProbeResult
	if json.Unmarshal(b, &r) != nil {
		t.Fatal("malformed controls probe")
	}
	if !r.NetworkInaccessible {
		t.Fatal("network isolation failed: inert host listener reachable")
	}
	if !r.HostInaccessible || !r.RootReadOnly || r.UID != 65534 || r.CapEff != "0000000000000000" || r.NoNewPrivs != "1" || r.Seccomp != "2" {
		t.Fatalf("namespace/privilege controls not enforced: %+v", r)
	}
	if r.MemoryMax != "536870912" || r.SwapMax != "0" || r.PidsMax != "64" || r.CPUmax != "100000 100000" {
		t.Fatalf("effective cgroup budget: %+v", r)
	}
	assertLiveAbsent(t, d, *names)
	t.Logf("effective controls and namespace denials: %+v", r)
}

func TestIsolatedLiveTimeoutNoncooperative(t *testing.T) {
	d, names := liveIsolatedDocker(t, "PARITY_PROBE_IMAGE")
	d.budget = 2 * time.Second
	started := time.Now()
	b, status := d.launch(liveProbeInput(t, inertProbeRequest{Mode: "timeout"}))
	if status != "timeout" || string(b) != "probe-ready" {
		t.Fatalf("noncooperative probe did not reach timeout: status=%s output=%q", status, b)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("noncooperative worker exceeded enforced deadline and cleanup allowance")
	}
	assertLiveAbsent(t, d, *names)
	t.Log("ready noncooperative worker killed; parent alive; owned containers absent")
}

func TestIsolatedLiveResourceBounds(t *testing.T) {
	d, names := liveIsolatedDocker(t, "PARITY_PROBE_IMAGE")
	for _, mode := range []string{"memory", "pids"} {
		t.Run(mode, func(t *testing.T) {
			b, status := d.launch(liveProbeInput(t, inertProbeRequest{Mode: mode}))
			if mode == "memory" {
				if status != "memory_limit" || string(b) != "probe-ready" {
					t.Fatalf("memory budget did not terminate finite probe: %s", status)
				}
			} else {
				if status != "ok" {
					t.Fatalf("process limit probe: %s", status)
				}
				var r inertProbeResult
				if json.Unmarshal(b, &r) != nil || r.PidsMax != "64" || !strings.HasPrefix(r.PidsEvents, "max ") || r.PidsEvents == "max 0" {
					t.Fatalf("pids controller did not deny process creation: %s", b)
				}
				t.Logf("process limit enforced: %s", r.PidsEvents)
			}
			assertLiveAbsent(t, d, *names)
		})
	}
}

func TestIsolatedLiveGeneratedParity(t *testing.T) {
	d, names := liveIsolatedDocker(t, "PARITY_WORKER_IMAGE")
	m, hash, root := generated(t)
	rules := os.Getenv("PARITY_RULES_DIR")
	if rules == "" {
		rules = "../../docker/local-rules"
	}
	baseline, err := run(root, m, hash, rules)
	if err != nil {
		t.Fatal(err)
	}
	if d.identity.RulesFingerprintSHA256 != digest([]byte(baseline.RulesFingerprint)) {
		t.Fatal("host/image effective rules differ")
	}
	r := isolatedCorpus(root, m, hash, d, d.observe)
	if !r.Complete || !r.Summary.Pass || !reflect.DeepEqual(r.Summary, baseline.Summary) {
		t.Fatalf("isolated generated observations differ: %+v baseline=%+v", r.Summary, baseline.Summary)
	}
	// Explicit external metadata around the same inert bytes exercises the new
	// contract without fetching, acquiring or scanning any external sample.
	for i := range m.Samples {
		m.Samples[i].Partition = "external-clean"
		m.Samples[i].Truth.Basis = "independent"
	}
	for i := range m.Sources {
		m.Sources[i].Kind = "external"
	}
	if err := m.validate(); err != nil {
		t.Fatalf("external test metadata must pass real manifest validation: %v", err)
	}
	if requireSynthetic(m) == nil {
		t.Fatal("synthetic run accepted external metadata")
	}
	manifestBytes, err := encodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("external-manifest.json", manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := isolatedCLI([]string{"-manifest", filepath.Join(root.Name(), "external-manifest.json"), "-corpus-root", root.Name(), "-engine-image", d.image}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stderr.String(), "isolated Mailstrix: 6 unique samples, 0 duplicates; complete=true; labelled gate=true") {
		t.Fatalf("external CLI failed: code=%d summary=%s", code, stderr.String())
	}
	var external isolatedReport
	if err := json.Unmarshal(stdout.Bytes(), &external); err != nil {
		t.Fatal(err)
	}
	if !external.Complete || !external.Summary.Pass || !reflect.DeepEqual(external.Summary.Statuses, r.Summary.Statuses) {
		t.Fatal("external-metadata inert execution incomplete")
	}
	if external.Schema != "mailstrix-isolated-v1" {
		t.Fatal("wrong report contract")
	}
	assertLiveAbsent(t, d, *names)
	t.Logf("six generated observations and external-metadata counterparts agree; worker=%+v", d.identity)
}
