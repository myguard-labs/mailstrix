package ci_test

import (
	"os"
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
	for _, text := range []string{"lower bound for peak memory", "extraction streams", "ICAP pre-admission buffers", "RSS="} {
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
		for _, text := range []string{"lower bound", "extraction streams", "ICAP pre-admission buffers", "MAILSTRIX_MAX_INFLIGHT", "MAILSTRIX_MAX_BODY"} {
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
