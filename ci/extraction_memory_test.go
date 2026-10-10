package ci_test

import (
	"archive/zip"
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func retainedZip(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, err := z.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestExtractionMemoryNested(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.yar"), []byte("rule Clean { condition: false }"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &ms.Config{RulesDir: dir, MaxConcurrent: 4, MaxInflight: 4, CacheSize: 1}
	scanner, err := ms.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	srv := ms.NewServer(cfg, scanner)
	// Outer retains the inner ZIP and its leaf, including both nested layers.
	leaf := []byte("nested retained leaf!")
	inner := retainedZip(t, "leaf.txt", leaf)
	outer := retainedZip(t, "inner.zip", inner)
	want := uint64(len(inner) + len(leaf))
	scrape := func() string {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		if w.Code != 200 {
			t.Errorf("metrics status=%d", w.Code)
		}
		return w.Body.String()
	}
	check := func(count, sum uint64) {
		t.Helper()
		got := scanner.ExtractionBytesRetained()
		if got.Count != count || got.Sum != sum {
			t.Fatalf("retained extraction snapshot count=%d sum=%d want count=%d sum=%d", got.Count, got.Sum, count, sum)
		}
		body := scrape()
		for _, line := range []string{"# TYPE mailstrix_extraction_bytes_retained histogram", "mailstrix_extraction_bytes_retained_count " + strconv.FormatUint(count, 10), "mailstrix_extraction_bytes_retained_sum " + strconv.FormatUint(sum, 10), "mailstrix_extraction_bytes_retained_bucket{le=\"+Inf\"} " + strconv.FormatUint(count, 10), "mailstrix_extraction_bytes_retained_bucket{le=\"1024\"} " + strconv.FormatUint(count, 10)} {
			if !strings.Contains(body, line+"\n") {
				t.Fatalf("missing histogram line %q", line)
			}
		}
	}
	check(0, 0)
	if matches, e := scanner.Scan(outer, ms.ScanMeta{}); e != nil || len(matches) != 0 {
		t.Fatalf("nested verdict matches=%v err=%v", matches, e)
	}
	check(1, want)
	if _, e := scanner.Scan(nil, ms.ScanMeta{}); e != nil {
		t.Fatal(e)
	}
	check(2, want)
	// Truncated ZIP preserves the existing best-effort verdict and observes zero streams.
	if _, e := scanner.Scan([]byte("PK\x03\x04truncated"), ms.ScanMeta{}); e != nil {
		t.Fatalf("malformed best-effort verdict changed: %v", e)
	}
	check(3, want)
	// Repeated collection does not itself add observations. Concurrent real scans
	// and scrapes exercise the provider and Prometheus serialization together.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if _, e := scanner.Scan(outer, ms.ScanMeta{}); e != nil {
					t.Error(e)
				}
				body := scrape()
				if !strings.Contains(body, "# TYPE mailstrix_extraction_bytes_retained histogram\n") {
					t.Error("missing histogram")
				}
			}
		}()
	}
	wg.Wait()
	check(43, want*41)
	check(43, want*41)
}
