package ci

import (
	"archive/zip"
	"bytes"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func TestScanExtractedBudgetBoundary(t *testing.T) {
	for _, tc := range []struct {
		name             string
		timeout, elapsed time.Duration
		incomplete       bool
	}{
		{"above_second", 2 * time.Second, 0, false},
		{"exact_second", 2 * time.Second, time.Second, false},
		{"subsecond", 2 * time.Second, time.Second + time.Nanosecond, true},
		{"expired", 2 * time.Second, 3 * time.Second, true},
		{"unlimited_zero", 0, 3 * time.Second, false},
		{"unlimited_negative", -time.Second, 3 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dir := t.TempDir()
				// Distinct rules prove the raw result survives and the extracted scan ran.
				rule := `rule Raw { condition: uint16(0) == 0x4b50 }
rule Child { strings: $a = "budget child payload" condition: $a }`
				if err := os.WriteFile(filepath.Join(dir, "budget.yar"), []byte(rule), 0600); err != nil {
					t.Fatal(err)
				}
				var body bytes.Buffer
				zw := zip.NewWriter(&body)
				w, err := zw.Create("child.txt")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write([]byte("budget child payload")); err != nil {
					t.Fatal(err)
				}
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				cfg := &mailstrix.Config{RulesDir: dir, ScanTimeout: tc.timeout, BigFileThreshold: 1, BigFileRules: dir, EffortMax: 10, Effort: 10, Token: "budget-test", CacheTTL: time.Hour, CacheSize: 10, MaxBody: 1 << 20}
				advanced := 0
				sc, err := mailstrix.NewScanner(cfg, func(format string, _ ...any) {
					if strings.HasPrefix(format, "oversized buffer (") {
						// Fake time advances after Scan sets its deadline, before the raw scan.
						// This avoids real sleeps and makes the 1ns boundary deterministic.
						advanced++
						time.Sleep(tc.elapsed)
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				defer sc.Close()
				matches, err := sc.Scan(body.Bytes(), mailstrix.ScanMeta{})
				if errors.Is(err, mailstrix.ErrScanIncomplete) != tc.incomplete {
					t.Fatalf("incomplete error = %v, want %v", err, tc.incomplete)
				}
				if err != nil && !tc.incomplete {
					t.Fatal(err)
				}
				found := map[string]bool{}
				for _, match := range matches {
					found[match.Rule] = true
				}
				if !found["Raw"] {
					t.Fatalf("prior raw match lost: %v", matches)
				}
				if found["MAILSTRIX_SCAN_INCOMPLETE"] != tc.incomplete {
					t.Fatalf("incomplete marker mismatch: %v", matches)
				}
				if tc.incomplete {
					if sc.StreamChannelScans() != 0 || sc.MarkerChannelScans() != 0 {
						t.Fatalf("native extracted scan started with insufficient budget: streams=%d markers=%d", sc.StreamChannelScans(), sc.MarkerChannelScans())
					}
				} else if sc.StreamChannelScans() == 0 || !found["Child"] {
					t.Fatalf("complete control missed child: %v", matches)
				}
				if advanced != 1 {
					t.Fatalf("clock hook ran %d times, want 1", advanced)
				}

				// Exercise the real native scanner through the HTTP cache consumer twice.
				server := mailstrix.NewServer(cfg, sc)
				before := sc.RawChannelScans()
				for range 2 {
					request := httptest.NewRequest("POST", "/scan", bytes.NewReader(body.Bytes()))
					request.Header.Set("X-MAILSTRIX-Token", "budget-test")
					request.Header.Set("Content-Length", strconv.Itoa(body.Len()))
					response := httptest.NewRecorder()
					server.ServeHTTP(response, request)
					if response.Code != 200 || !strings.Contains(response.Body.String(), `"Raw"`) {
						t.Fatalf("partial response lost match: %d %s", response.Code, response.Body.String())
					}
				}
				wantScans := uint64(1)
				if tc.incomplete {
					wantScans = 2
				}
				if got := sc.RawChannelScans() - before; got != wantScans {
					t.Fatalf("cache scans = %d, want %d", got, wantScans)
				}
			})
		})
	}
}
