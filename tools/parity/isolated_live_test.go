//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if err := liveAbsenceError(d, names); err != nil {
		t.Fatal(err)
	}
}

func liveAbsenceError(d isolatedDocker, names []string) error {
	for _, name := range slices.Backward(names) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		b, status := d.call(ctx, nil, "ps", "--all", "--quiet", "--filter", "name=^/"+name+"$")
		cancel()
		if status != "ok" || len(bytes.TrimSpace(b)) != 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			running, inspectStatus := d.call(ctx, nil, "inspect", "--format={{.State.Running}}", name)
			cancel()
			return fmt.Errorf("owned container remains after launch: %s (%s; inspect=%s; running=%s)", name, status, inspectStatus, bytes.TrimSpace(running))
		}
	}
	return nil
}

func shellLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func recordCLIDockerNames(t *testing.T, lieAboutCleanup bool) (string, func()) {
	t.Helper()
	realDocker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	realDocker, err = filepath.Abs(realDocker)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "created-names")
	cleanup := "0"
	if lieAboutCleanup {
		cleanup = "1"
	}
	script := "#!/bin/sh\nset -eu\n" +
		"if [ \"$#\" -ge 5 ] && [ \"$3\" = create ] && [ \"$4\" = --name ]; then\n" +
		"\tprintf '%s\\n' \"$5\" >> " + shellLiteral(record) + "\n" +
		"fi\n" +
		"if [ " + cleanup + " = 1 ] && [ \"$#\" -ge 3 ] && { [ \"$3\" = rm ] || [ \"$3\" = ps ]; }; then\n" +
		"\texit 0\n" +
		"fi\nexec " + shellLiteral(realDocker) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	originalPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+originalPath); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if err := os.Setenv("PATH", originalPath); err != nil {
			t.Errorf("restore PATH: %v", err)
		}
	}
	t.Cleanup(func() {
		restore()
		b, err := os.ReadFile(record)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Errorf("read CLI-owned container names for teardown: %v", err)
			return
		}
		d := isolatedDocker{}
		for _, name := range strings.Fields(string(b)) {
			if !d.cleanup(name) {
				t.Errorf("qualification could not remove CLI-owned container %s", name)
			}
		}
	})
	return record, restore
}

func recordedCLINames(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	names := strings.Fields(string(b))
	for _, name := range names {
		if !strings.HasPrefix(name, "mailstrix-isolated-") {
			t.Fatalf("unexpected recorded container name %q", name)
		}
	}
	return names
}

// waitLiveOwnedVisible waits for each CLI-owned name in an independent Docker
// name-filter query. The CLI shim records a create request before Docker
// answers it, so a recorded name alone is not a visibility signal.
func waitLiveOwnedVisible(d isolatedDocker, names []string, timeout time.Duration) error {
	for _, name := range names {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		for {
			b, status := d.call(ctx, nil, "ps", "--all", "--quiet", "--filter", "name=^/"+name+"$")
			if status == "ok" && len(bytes.TrimSpace(b)) != 0 {
				break
			}
			select {
			case <-ctx.Done():
				cancel()
				return fmt.Errorf("CLI-owned container %s not visible within %s (last status=%s)", name, timeout, status)
			case <-time.After(50 * time.Millisecond):
			}
		}
		cancel()
	}
	return nil
}

func TestWaitLiveOwnedVisible(t *testing.T) {
	names := []string{"mailstrix-isolated-inert-a", "mailstrix-isolated-inert-b"}
	queries := map[string]int{}
	d := isolatedDocker{command: func(ctx context.Context, args ...string) *exec.Cmd {
		var name string
		for _, owned := range names {
			if slices.Equal(args, []string{"ps", "--all", "--quiet", "--filter", "name=^/" + owned + "$"}) {
				name = owned
				break
			}
		}
		if name == "" {
			t.Fatalf("unexpected Docker query: %q", args)
		}
		queries[name]++
		if queries[name] == 1 {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0")
		}
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'inert-id\\n'")
	}}
	if err := waitLiveOwnedVisible(d, names, time.Second); err != nil || queries[names[0]] != 2 || queries[names[1]] != 2 {
		t.Fatalf("both owned names must survive transient absence: queries=%v err=%v", queries, err)
	}
	d.command = func(ctx context.Context, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0")
	}
	if err := waitLiveOwnedVisible(d, names[:1], 20*time.Millisecond); err == nil || !strings.Contains(err.Error(), names[0]) || !strings.Contains(err.Error(), "not visible") {
		t.Fatalf("missing owned name escaped deadline: %v", err)
	}
	d.command = func(ctx context.Context, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'inert-id\\n'; exit 1")
	}
	if err := waitLiveOwnedVisible(d, names[:1], 20*time.Millisecond); err == nil || !strings.Contains(err.Error(), "last status=execution_error") {
		t.Fatalf("nonempty output from a failed Docker query was accepted: %v", err)
	}
}

func TestWaitLiveOwnedVisiblePerNameDeadline(t *testing.T) {
	names := []string{"mailstrix-isolated-inert-a", "mailstrix-isolated-inert-b"}
	const visibleTimeout = 5 * time.Second
	queries := map[string]int{}
	contexts := map[string]context.Context{}
	missingSecond := false
	d := isolatedDocker{command: func(ctx context.Context, args ...string) *exec.Cmd {
		for _, name := range names {
			if slices.Equal(args, []string{"ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"}) {
				queries[name]++
				if missingSecond && name == names[1] {
					return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0")
				}
				contexts[name] = ctx
				return exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'inert-id\\n'")
			}
		}
		t.Fatalf("unexpected Docker query: %q", args)
		return nil
	}}
	if err := waitLiveOwnedVisible(d, names, visibleTimeout); err != nil {
		t.Fatalf("each visible name should receive its own deadline: queries=%v err=%v", queries, err)
	}
	if queries[names[0]] != 1 || queries[names[1]] != 1 {
		t.Fatalf("each owned name needs a visibility query: %v", queries)
	}
	// isolatedDocker.call wraps each parent with context.WithCancel, so the
	// command contexts have distinct identities even with one shared deadline.
	firstDeadline, firstOK := contexts[names[0]].Deadline()
	secondDeadline, secondOK := contexts[names[1]].Deadline()
	if !firstOK || !secondOK || firstDeadline.Equal(secondDeadline) {
		t.Fatalf("each owned name needs a distinct timeout deadline: first=%v second=%v", firstDeadline, secondDeadline)
	}
	missingSecond = true
	if err := waitLiveOwnedVisible(d, names[1:], 20*time.Millisecond); err == nil || !strings.Contains(err.Error(), names[1]) || !strings.Contains(err.Error(), "not visible") {
		t.Fatalf("missing second name must fail its own deadline: queries=%v err=%v", queries, err)
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
	// The budget starts at "probe-ready", so a slow container start on a loaded
	// runner cannot expire it before the probe is running (C4 flake).
	d.readyBudget = 2 * time.Second
	started := time.Now()
	b, status := d.launch(liveProbeInput(t, inertProbeRequest{Mode: "timeout"}))
	if status != "timeout" || string(b) != "probe-ready" {
		t.Fatalf("noncooperative probe did not reach timeout: status=%s output=%q", status, b)
	}
	// Host budget plus the two 5s cleanup calls is the enforced ceiling.
	if limit := d.effectiveBudget() + 10*time.Second; time.Since(started) > limit {
		t.Fatalf("noncooperative worker exceeded enforced deadline and cleanup allowance %s", limit)
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

func TestIsolatedLiveAbsenceOracleRejectsOwnedContainer(t *testing.T) {
	d, lifecycleNames := liveIsolatedDocker(t, "PARITY_PROBE_IMAGE")
	name := fmt.Sprintf("mailstrix-isolated-oracle-%d", os.Getpid())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	containerID, status := d.call(ctx, nil, d.args(name)...)
	cancel()
	if status != "ok" || len(bytes.TrimSpace(containerID)) == 0 {
		t.Fatalf("create stopped oracle control: status=%s id=%q", status, containerID)
	}
	err := liveAbsenceError(isolatedDocker{}, []string{name})
	if err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("absence oracle accepted its owned stopped container: %v", err)
	}
	assertLiveAbsent(t, d, (*lifecycleNames)[:len(*lifecycleNames)-1])
	t.Logf("absence oracle rejected owned stopped container: %v", err)
}

func TestIsolatedLiveCLIAbsenceOracleControl(t *testing.T) {
	d, lifecycleNames := liveIsolatedDocker(t, "PARITY_WORKER_IMAGE")
	m, hash, root := generated(t)
	cliRecord, restorePath := recordCLIDockerNames(t, true)
	var stdout, stderr bytes.Buffer
	code := isolatedCLI([]string{"-manifest", filepath.Join(root.Name(), "manifest.json"), "-corpus-root", root.Name(), "-engine-image", d.image}, &stdout, &stderr)
	restorePath()
	var report isolatedReport
	if code != 0 || json.Unmarshal(stdout.Bytes(), &report) != nil || report.ManifestSHA256 != hash {
		t.Fatalf("lying-cleanup CLI control did not complete: code=%d summary=%s", code, stderr.String())
	}
	names := recordedCLINames(t, cliRecord)
	if len(names) != len(m.Samples)+1 {
		t.Fatalf("lying-cleanup CLI created %d containers, want identity plus %d samples", len(names), len(m.Samples))
	}
	cliDocker := isolatedDocker{}
	if err := waitLiveOwnedVisible(cliDocker, names, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	err := liveAbsenceError(cliDocker, names)
	if err == nil || !strings.Contains(err.Error(), names[len(names)-1]) {
		t.Fatalf("independent daemon oracle accepted CLI-owned stopped containers: %v", err)
	}
	assertLiveAbsent(t, d, *lifecycleNames)
	t.Logf("independent daemon oracle rejected CLI-owned stopped container: %v", err)
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
	cliRecord, restorePath := recordCLIDockerNames(t, false)
	code := isolatedCLI([]string{"-manifest", filepath.Join(root.Name(), "external-manifest.json"), "-corpus-root", root.Name(), "-engine-image", d.image}, &stdout, &stderr)
	restorePath()
	if code != 0 || !strings.Contains(stderr.String(), "isolated Mailstrix: 6 unique samples, 0 duplicates; complete=true; labelled gate=true") {
		t.Fatalf("external CLI failed: code=%d summary=%s", code, stderr.String())
	}
	cliNames := recordedCLINames(t, cliRecord)
	cliDocker := isolatedDocker{}
	if len(cliNames) != len(m.Samples)+1 {
		t.Fatalf("isolated CLI created %d containers, want identity plus %d samples", len(cliNames), len(m.Samples))
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
	assertLiveAbsent(t, cliDocker, cliNames)
	t.Logf("six generated observations and external-metadata counterparts agree; worker=%+v", d.identity)
}
