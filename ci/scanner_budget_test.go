package ci

import (
	"archive/zip"
	"bytes"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/myguard-labs/mailstrix/internal/mailstrix"
	"github.com/myguard-labs/mailstrix/internal/urlcand"
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

// Keep the extraction budget contract at the public boundary: invalid and
// duplicate matches must consume exactly the same budget as before defanging
// was optimized. Raw matches always precede the defanged pass.
func TestURLCandidateExtractionContract(t *testing.T) {
	raw := func(s string) urlcand.Candidate { return urlcand.NewCandidate(s, false) }
	deobf := func(s string) urlcand.Candidate { return urlcand.NewCandidate(s, true) }
	for _, tc := range []struct {
		name, input string
		limit       int
		want        []urlcand.Candidate
	}{
		{"raw", "HTTP://A.example/x https://b.example/y", 2, []urlcand.Candidate{raw("HTTP://A.example/x"), raw("https://b.example/y")}},
		{"raw_before_defanged", "hxxps://obf[.]example/x http://raw.example/y", 2, []urlcand.Candidate{raw("http://raw.example/y"), deobf("https://obf.example/x")}},
		{"cross_pass_duplicate", "http://dup.example/x hxxp://dup[.]example/x hxxp://new[.]example/y", 2, []urlcand.Candidate{raw("http://dup.example/x"), deobf("http://new.example/y")}},
		{"defanged_duplicates", "hxxp://dup[.]example/x hxxp://dup[.]example/x hXXps[://]new[DOT]example/y", 2, []urlcand.Candidate{deobf("http://dup.example/x"), deobf("https://new.example/y")}},
		{"raw_budget_full", "hxxp://obf[.]example/x http://raw.example/y", 1, []urlcand.Candidate{raw("http://raw.example/y")}},
		{"defanged_budget_full", "hxxp://first[.]example/x hxxp://second[.]example/y", 1, []urlcand.Candidate{deobf("http://first.example/x")}},
		{"raw_scan_cap", strings.Repeat("http://pad.example/x ", 32) + "http://late.example/x hxxp://late[.]example/y", 2, []urlcand.Candidate{raw("http://pad.example/x")}},
		{"defanged_scan_cap", strings.Repeat("hxxp://pad[.]example/x ", 32) + "hxxp://late[.]example/y", 2, []urlcand.Candidate{deobf("http://pad.example/x")}},
		{"last_scanned_match", strings.Repeat("hxxp://pad[.]example/x ", 31) + "hxxp://last[.]example/y", 2, []urlcand.Candidate{deobf("http://pad.example/x"), deobf("http://last.example/y")}},
		{"invalid_spends_budget", "http://bad%zz/x hxxp://valid[.]example/y", 1, []urlcand.Candidate{raw("http://bad%zz/x")}},
		{"invalid_bytes", "hxxp://host[.]example/\xff\x00http://raw.example/x", 2, []urlcand.Candidate{raw("http://raw.example/x"), deobf("http://host.example/\xff")}},
		{"default_zero", "hxxp[:]//host{dot}example/x", 0, []urlcand.Candidate{deobf("http://host.example/x")}},
		{"default_negative", "hXXps://host(dot)example/x", -1, []urlcand.Candidate{deobf("https://host.example/x")}},
		{"unsupported_scheme", "ftp://host.example/x", 2, nil},
		{"no_urls", "hxxp and [.] and ://", 2, nil},
		{"clean", "ordinary prose", 2, nil},
		{"empty", "", 2, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.input)
			got := urlcand.Extract(data, tc.limit)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidates = %#v, want %#v", got, tc.want)
			}
			// Neither input mutation nor eager normalization is part of Extract.
			if string(data) != tc.input {
				t.Fatal("Extract modified input")
			}
			for i := range data {
				data[i] = '!'
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatal("candidates alias caller input")
			}
		})
	}
}

func TestURLCandidateDefangAllocations(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		maxAllocs   float64
	}{
		{"clean", strings.Repeat("ordinary prose ", 1024), 0},
		// A warm single URL needs only matches, replacement buffers and the
		// detached candidate. Leave room for regexp implementation changes,
		// while catching reconstruction of the replacement trie per call.
		{"defanged", "hxxp://obf[.]example/x", 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.input)
			allocs := testing.AllocsPerRun(100, func() { urlcand.Extract(data, 64) })
			if allocs > tc.maxAllocs {
				t.Fatalf("Extract allocations = %g, want <= %g", allocs, tc.maxAllocs)
			}
		})
	}
}

func TestURLCandidateDefaultBudget(t *testing.T) {
	var input strings.Builder
	want := make([]urlcand.Candidate, 0, 64)
	for i := 0; i < 65; i++ {
		raw := "http://host.example/" + strconv.Itoa(i)
		input.WriteString(raw + " ")
		if i < 64 {
			want = append(want, urlcand.NewCandidate(raw, false))
		}
	}
	for _, limit := range []int{0, -1} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			got := urlcand.Extract([]byte(input.String()), limit)
			if len(got) != 64 {
				t.Fatalf("default budget returned %d candidates, want exactly 64", len(got))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("default budget candidates = %#v, want first 64 in order %#v", got, want)
			}
		})
	}
}
