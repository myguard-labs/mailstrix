package ci_test

import (
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func TestStartupMemoryWording(t *testing.T) {
	// Capture the public startup path. An invalid listen address ends serving
	// immediately after logging, without opening a socket or allocating bodies.
	capture, err := os.CreateTemp(t.TempDir(), "startup")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := capture.Close(); err != nil {
			t.Errorf("close startup capture: %v", err)
		}
	}()
	original := os.Stderr
	os.Stderr = capture
	defer func() { os.Stderr = original }()
	s := ms.NewServer(&ms.Config{Host: "invalid:host", Port: 1, MaxConcurrent: 1, MaxInflight: 1, MaxBody: 1 << 50, CacheSize: 1}, &memoryEngine{})
	if err := s.ListenAndServe(); err == nil {
		t.Fatal("invalid listen address unexpectedly succeeded")
	}
	output, err := os.ReadFile(capture.Name())
	if err != nil {
		t.Fatal(err)
	}
	logs := string(output)
	for _, text := range []string{"lower bound for peak memory", "extraction_retained", "ICAP pre-admission buffers", "RSS="} {
		if !strings.Contains(logs, text) {
			t.Fatalf("startup memory log missing %q:\n%s", text, logs)
		}
	}
	foundWarning := false
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, "WARNING:") || !strings.Contains(line, "memory") {
			continue
		}
		foundWarning = true
		for _, text := range []string{"lower bound", "extraction_retained", "ICAP pre-admission buffers", "MAILSTRIX_MAX_INFLIGHT", "MAILSTRIX_MAX_BODY"} {
			if !strings.Contains(line, text) {
				t.Fatalf("memory warning missing %q: %s", text, line)
			}
		}
		if strings.Contains(line, "MAILSTRIX_MAX_CONCURRENT") {
			t.Fatalf("memory warning recommends unrelated scan concurrency: %s", line)
		}
	}
	if !foundWarning {
		t.Fatalf("large buffer estimate did not emit memory warning:\n%s", logs)
	}
}

// The subprocess excludes other tests' forced collections and finalizers.
// GOGC=off makes NumGC an exact count of explicit startup collections.
func TestP10StartupReclaim(t *testing.T) {
	if os.Getenv("MAILSTRIX_P10_RECLAIM_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestP10StartupReclaim$", "-test.v")
		cmd.Env = append(os.Environ(), "MAILSTRIX_P10_RECLAIM_CHILD=1", "GOGC=off", "GOMEMLIMIT=off", "GODEBUG=madvdontneed=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("startup reclaim subprocess: %v\n%s", err, out)
		}
		return
	}
	debug.SetGCPercent(-1)
	dir := t.TempDir()
	path := filepath.Join(dir, "main.yar")
	p10WriteRule(t, path, "rule Startup { condition: false }")
	cfg := &ms.Config{RulesDir: dir, Host: "invalid:host", Port: 1, MaxConcurrent: 1, MaxInflight: 1, CacheSize: 1}
	scanner, err := ms.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	capture, err := os.CreateTemp(t.TempDir(), "startup")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := capture.Close(); err != nil {
			t.Error(err)
		}
	}()
	old := os.Stderr
	os.Stderr = capture
	defer func() { os.Stderr = old }()
	server := ms.NewServer(cfg, scanner)
	// Fault in dead Go pages after rule load. No collection can free them until
	// startup explicitly collects, so a sample taken first still includes them.
	p10DirtyStartupPages()
	beforeRSS := p10RSS(t)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := server.ListenAndServe(); err == nil {
		t.Fatal("invalid listen unexpectedly succeeded")
	}
	runtime.ReadMemStats(&after)
	if got := after.NumGC - before.NumGC; got != 1 {
		t.Fatalf("startup forced collections=%d want=1", got)
	}
	logs, err := os.ReadFile(capture.Name())
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`lower bound for peak memory ~\d+ MiB: RSS=(\d+) MiB`).FindSubmatch(logs)
	if len(match) != 2 {
		t.Fatalf("startup RSS banner missing: %s", logs)
	}
	banner, err := strconv.ParseInt(string(match[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if banner > beforeRSS-32 {
		t.Fatalf("startup RSS sampled before reclaim: banner=%d before=%d MiB; want >=32 MiB drop", banner, beforeRSS)
	}
	if after.HeapReleased < before.HeapReleased+32<<20 {
		t.Fatalf("startup released Go pages=%d want >=32 MiB", after.HeapReleased-before.HeapReleased)
	}
	// Real scanner operations cover successful and failed reloads and scans.
	p10WriteRule(t, path, "rule Reloaded { condition: false }")
	if err := scanner.Reload(); err != nil {
		t.Fatal(err)
	}
	p10WriteRule(t, path, "broken rules")
	if err := scanner.Reload(); err == nil {
		t.Fatal("malformed reload succeeded")
	}
	for i := 0; i < 3; i++ {
		if _, err := scanner.Scan([]byte("fixture"), ms.ScanMeta{}); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/scan", strings.NewReader("fixture"))
		req.Header.Set("Content-Length", "7")
		server.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("HTTP scan status=%d", w.Code)
		}
	}
	var end runtime.MemStats
	runtime.ReadMemStats(&end)
	if end.NumGC != after.NumGC {
		t.Fatalf("reload/scan forced collections=%d want=0", end.NumGC-after.NumGC)
	}
	t.Logf("startup: RSS %d -> banner %d MiB; collections=1, reload/scan=0", beforeRSS, banner)
}

//go:noinline
func p10DirtyStartupPages() {
	pages := make([]byte, 64<<20)
	for i := 0; i < len(pages); i += 4096 {
		pages[i] = 1
	}
	runtime.KeepAlive(pages)
}

func p10RSS(t *testing.T) int64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		t.Fatal(err)
	}
	var total, resident int64
	if _, err := fmt.Sscan(string(data), &total, &resident); err != nil {
		t.Fatal(err)
	}
	return resident * int64(os.Getpagesize()) >> 20
}

func p10WriteRule(t *testing.T, path, source string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
}
