package mailstrix

// PF-03 filename-partition witnesses. The verdict cache key carries the
// attachment metadata (ScanMeta.cacheKey: filename, extension, file_type,
// effort). These tests pin that a real scanner behind the real verdict cache
// and coalescing path never lets one attachment name reuse the verdict computed
// for another name on identical bytes, in either order or concurrently.
//
// Two independent filename channels are exercised so a future partition design
// cannot pass by inspecting only one of them:
//   - YARA externals: test-compiled rules on `extension`, `filename` and
//     `file_type` (the THOR/Loki and InQuest conventions mailstrix defines).
//   - The shipped local rule Renamed_Container (docker/local-rules/
//     archive_indicators.yara), which references NO external variable: it fires
//     on the synthetic EXT-MISMATCH marker the scanner emits when the claimed
//     extension contradicts the extracted type. Ruleset introspection of
//     external usage alone would therefore miss it.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const pf03Token = "pf03-token"

// pf03Body is an RTF document: the extractor reports IsRTF, so a benign coat
// (.jpg/.txt) produces EXT-MISMATCH while .rtf or an unlisted extension does not.
// The backslash is the literal RTF control-word prefix, not an escape.
var pf03Body = []byte(`{\rtf1 harmless}`)

const pf03Rules = `
rule PF03_Ext_Scr { condition: extension == ".scr" }
rule PF03_Name_Case { condition: filename == "Report.txt" }
rule PF03_Outlook { condition: file_type contains "outlook" }
`

// pf03Watched restricts assertions to the witness rules; other rules in the
// shipped archive_indicators.yara file may legitimately fire on the body.
var pf03Watched = map[string]bool{
	"PF03_Ext_Scr": true, "PF03_Name_Case": true, "PF03_Outlook": true, "Renamed_Container": true,
}

type pf03Case struct {
	label  string
	name   string // raw attachment name; "-" means no filename header at all
	header string // explicit raw header value overriding base64(name) when set
	want   []string
}

func pf03Cases() []pf03Case {
	return []pf03Case{
		{label: "malicious-ext", name: "invoice.scr", want: []string{"PF03_Ext_Scr"}},
		{label: "benign-ext", name: "invoice.rtf", want: nil},
		{label: "renamed-jpg", name: "invoice.jpg", want: []string{"Renamed_Container"}},
		{label: "case-exact", name: "Report.txt", want: []string{"PF03_Name_Case", "Renamed_Container"}},
		{label: "case-lower", name: "report.txt", want: []string{"Renamed_Container"}},
		{label: "upper-ext", name: "INVOICE.SCR", want: []string{"PF03_Ext_Scr"}},
		{label: "no-header", name: "-", want: nil},
		{label: "blank-name", name: "   ", want: nil},
		{label: "undecodable-header", header: "!!!not base64!!!", want: nil},
		{label: "extension-only", name: ".scr", want: nil}, // leading dot: no extension
		{label: "outlook", name: "message.MSG", want: []string{"PF03_Outlook"}},
		{label: "long-255", name: strings.Repeat("a", 251) + ".scr", want: []string{"PF03_Ext_Scr"}},
		{label: "long-256-truncated", name: strings.Repeat("a", 252) + ".scr", want: nil}, // capped to ".sc"
		{label: "path-stripped", name: `D:\mailroom\inbox\Report.txt`, want: []string{"PF03_Name_Case", "Renamed_Container"}},
	}
}

func pf03RulesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	shipped, err := os.ReadFile(filepath.Join("..", "..", "docker", "local-rules", "archive_indicators.yara"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(shipped, []byte("rule Renamed_Container")) {
		t.Fatal("archive_indicators.yara no longer ships Renamed_Container; pick another filename-sensitive witness")
	}
	if err := os.WriteFile(filepath.Join(dir, "archive_indicators.yara"), shipped, 0o600); err != nil { // #nosec G703 -- dir is t.TempDir(), name constant
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pf03.yar"), []byte(pf03Rules), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func pf03Scanner(t *testing.T) *Scanner {
	t.Helper()
	sc, err := NewScanner(&Config{RulesDir: pf03RulesDir(t), ScanTimeout: time.Minute}, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	return sc
}

func pf03Server(sc *Scanner, maxConcurrent int) *Server {
	return NewServer(&Config{
		Token: pf03Token, MaxConcurrent: maxConcurrent, MaxInflight: 256, MaxBody: 4096,
		CacheTTL: time.Hour, CacheSize: 256, Effort: 5, EffortMax: 10,
		BackendTimeout: time.Minute, ScanTimeout: time.Minute,
	}, sc)
}

func pf03Watch(rules []string) []string {
	var out []string
	for _, r := range rules {
		if pf03Watched[r] {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func pf03MatchNames(m []Match) []string {
	names := make([]string, 0, len(m))
	for _, x := range m {
		names = append(names, x.Rule)
	}
	return pf03Watch(names)
}

// pf03Post scans pf03Body through the HTTP handler and returns the watched rule
// names plus the X-MAILSTRIX-Cache status ("" on a fresh scan).
func pf03Post(t *testing.T, s *Server, c pf03Case) ([]string, string, error) {
	req := httptest.NewRequest("POST", "/scan", bytes.NewReader(pf03Body))
	req.Header.Set("X-MAILSTRIX-Token", pf03Token)
	req.Header.Set("Content-Length", fmt.Sprint(len(pf03Body)))
	switch {
	case c.header != "":
		req.Header.Set("X-MAILSTRIX-Filename", c.header)
	case c.name != "-":
		req.Header.Set("X-MAILSTRIX-Filename", base64.StdEncoding.EncodeToString([]byte(c.name)))
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 200 {
		return nil, "", fmt.Errorf("%s: status %d body %s", c.label, w.Code, w.Body.String())
	}
	var resp struct {
		Matches []struct {
			Rule string `json:"rule"`
		} `json:"matches"`
		Degraded string `json:"degraded"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		return nil, "", fmt.Errorf("%s: decode %q: %w", c.label, w.Body.String(), err)
	}
	if resp.Degraded != "" {
		return nil, "", fmt.Errorf("%s: degraded verdict %q", c.label, resp.Degraded)
	}
	names := make([]string, 0, len(resp.Matches))
	for _, m := range resp.Matches {
		names = append(names, m.Rule)
	}
	return pf03Watch(names), w.Header().Get("X-MAILSTRIX-Cache"), nil
}

// Oracle: without any cache, the same bytes yield different verdicts per name.
// Every later witness relies on these fixtures being genuinely name-sensitive.
func TestPF03FilenameWitnessDirectScan(t *testing.T) {
	sc := pf03Scanner(t)
	distinct := map[string]bool{}
	for _, c := range pf03Cases() {
		if c.header != "" {
			continue // header decoding is an HTTP concern; covered below
		}
		name := c.name
		if name == "-" {
			name = ""
		}
		m, err := sc.Scan(pf03Body, NewScanMeta(name))
		if err != nil {
			t.Fatalf("%s: scan: %v", c.label, err)
		}
		if got := pf03MatchNames(m); !slices.Equal(got, c.want) {
			t.Errorf("%s: direct scan of %q = %v, want %v", c.label, c.name, got, c.want)
		}
		distinct[strings.Join(c.want, ",")] = true
	}
	if len(distinct) < 4 {
		t.Fatalf("witness set is not filename-sensitive enough: %d distinct verdicts", len(distinct))
	}
}

// Sequential: in forward and reverse order through one caching server, every
// name gets its own verdict on first sight, then the same verdict from cache.
func TestPF03FilenamePartitionSequential(t *testing.T) {
	for _, order := range []string{"forward", "reverse"} {
		t.Run(order, func(t *testing.T) {
			cases := pf03Cases()
			if order == "reverse" {
				slices.Reverse(cases)
			}
			sc := pf03Scanner(t)
			s := pf03Server(sc, 4)
			for pass := range 2 {
				for _, c := range cases {
					got, cache, err := pf03Post(t, s, c)
					if err != nil {
						t.Fatal(err)
					}
					if !slices.Equal(got, c.want) {
						t.Errorf("pass %d %s (%q): verdict %v (cache=%q), want %v", pass, c.label, c.name, got, cache, c.want)
					}
					if pass == 1 && cache != "hit" {
						t.Errorf("pass 1 %s: cache status %q, want hit (witness must exercise the cache)", c.label, cache)
					}
				}
			}
		})
	}
}

// Pairs: a malicious-named and a benign-named copy of the same bytes, in both
// orders, on a fresh cache each time (the first verdict must not leak).
func TestPF03FilenamePairBothOrders(t *testing.T) {
	byLabel := map[string]pf03Case{}
	for _, c := range pf03Cases() {
		byLabel[c.label] = c
	}
	pairs := [][2]string{
		{"malicious-ext", "benign-ext"},
		{"renamed-jpg", "benign-ext"},
		{"case-exact", "case-lower"},
		{"malicious-ext", "extension-only"},
		{"long-255", "long-256-truncated"},
		{"outlook", "no-header"},
	}
	for _, p := range pairs {
		for _, first := range []int{0, 1} {
			a, b := byLabel[p[first]], byLabel[p[1-first]]
			t.Run(a.label+"_then_"+b.label, func(t *testing.T) {
				s := pf03Server(pf03Scanner(t), 4)
				for _, c := range []pf03Case{a, b} {
					got, cache, err := pf03Post(t, s, c)
					if err != nil {
						t.Fatal(err)
					}
					if !slices.Equal(got, c.want) {
						t.Fatalf("%s after %s: verdict %v (cache=%q), want %v", c.label, a.label, got, cache, c.want)
					}
				}
			})
		}
	}
}

// Normalization equivalence: names that normalize to the same ScanMeta share a
// key, and the shared verdict equals the fresh one (no false split, no leak).
func TestPF03FilenameEquivalentNamesShareVerdict(t *testing.T) {
	s := pf03Server(pf03Scanner(t), 4)
	empty := []pf03Case{
		{label: "no-header", name: "-"},
		{label: "blank-name", name: "   "},
		{label: "control-only", name: "\r\n\t"},
		{label: "undecodable-header", header: "!!!not base64!!!"},
	}
	for i, c := range empty {
		got, cache, err := pf03Post(t, s, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("%s: verdict %v, want none", c.label, got)
		}
		if i > 0 && cache != "hit" {
			t.Errorf("%s: cache=%q, want hit (normalizes to the zero ScanMeta)", c.label, cache)
		}
	}
	long := strings.Repeat("a", 252)
	for i, suffix := range []string{".scr", ".scr-and-more-tail"} {
		c := pf03Case{label: "long-" + suffix, name: long + suffix}
		got, cache, err := pf03Post(t, s, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("%s: verdict %v, want none (capped name has extension .sc)", c.label, got)
		}
		if i > 0 && cache != "hit" {
			t.Errorf("%s: cache=%q, want hit (both cap to the same 255-byte name)", c.label, cache)
		}
	}
}

// Concurrent: many requests for differently named copies released together
// through the flight path with one scan slot. Each must receive its own verdict.
func TestPF03FilenamePartitionConcurrent(t *testing.T) {
	cases := pf03Cases()
	for round := range 8 {
		s := pf03Server(pf03Scanner(t), 1)
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, len(cases)*4)
		for rep := range 4 {
			for _, c := range cases {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					got, cache, err := pf03Post(t, s, c)
					if err != nil {
						errs <- err
						return
					}
					if !slices.Equal(got, c.want) {
						errs <- fmt.Errorf("round %d rep %d %s (%q): verdict %v (cache=%q), want %v", round, rep, c.label, c.name, got, cache, c.want)
					}
				}()
			}
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if t.Failed() {
			return
		}
	}
}
