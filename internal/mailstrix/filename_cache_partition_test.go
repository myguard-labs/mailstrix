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
	"sync/atomic"
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

func pf03Server(sc ScanEngine, maxConcurrent int) *Server {
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

// pf03Gate wraps a real scanner and holds the FIRST Scan call open until
// released. Embedding the ScanEngine interface (not *Scanner) hides
// acquireScanLease, so leaseScanEngine routes the scan through this Scan.
type pf03Gate struct {
	ScanEngine
	calls   atomic.Int32
	entered chan struct{} // closed when the gated (leader) Scan is running
	release chan struct{} // closed by the test to let the leader finish
}

func newPF03Gate(sc *Scanner) *pf03Gate {
	return &pf03Gate{ScanEngine: sc, entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *pf03Gate) Scan(buf []byte, meta ScanMeta) ([]Match, error) {
	if g.calls.Add(1) == 1 {
		close(g.entered)
		select {
		case <-g.release:
		case <-time.After(time.Minute):
			return nil, fmt.Errorf("pf03 gate never released")
		}
	}
	return g.ScanEngine.Scan(buf, meta)
}

// pf03Joiners reports how many followers are registered on in-flight scans.
func pf03Joiners(s *Server) int {
	s.flights.mu.Lock()
	defer s.flights.mu.Unlock()
	n := 0
	for _, fl := range s.flights.m {
		n += fl.joiners
	}
	return n
}

func pf03Ext(c pf03Case) string {
	if c.header != "" || c.name == "-" {
		return ""
	}
	return NewScanMeta(c.name).Extension
}

// pf03Neighbour picks a case whose verdict differs from cases[i], preferring one
// that shares the extension so only the filename component of the key separates
// it from the held flight. nil when no differently-verdicted case exists.
func pf03Neighbour(cases []pf03Case, i int) *pf03Case {
	c := cases[i]
	var other *pf03Case
	for j := range cases {
		if j == i || slices.Equal(cases[j].want, c.want) {
			continue
		}
		if other == nil || (pf03Ext(cases[j]) == pf03Ext(c) && pf03Ext(*other) != pf03Ext(c)) {
			other = &cases[j]
		}
	}
	return other
}

// pf03AwaitNeighbour posts the neighbour while the leader is held and returns its
// reply, failing at once if it registers as a second joiner on the held flight.
func pf03AwaitNeighbour(t *testing.T, s *Server, held, other pf03Case, deadline time.Time) pf03Reply {
	t.Helper()
	neighbour := pf03Async(t, s, other)
	for {
		select {
		case nr := <-neighbour:
			return nr
		default:
		}
		if pf03Joiners(s) > 1 {
			t.Fatalf("%s (%q) coalesced onto the held scan of %s (%q)", other.label, other.name, held.label, held.name)
		}
		if time.Now().After(deadline) {
			t.Fatalf("neighbour %s never completed while the leader was held", other.label)
		}
		time.Sleep(time.Millisecond)
	}
}

type pf03Reply struct {
	got   []string
	cache string
	err   error
}

// pf03Async runs pf03Post off the test goroutine, so pf03Post must never call
// t.Fatal/t.Error: it reports failures only through the returned pf03Reply.
func pf03Async(t *testing.T, s *Server, c pf03Case) <-chan pf03Reply {
	out := make(chan pf03Reply, 1)
	go func() {
		got, cache, err := pf03Post(t, s, c)
		out <- pf03Reply{got, cache, err}
	}()
	return out
}

func pf03Wait(t *testing.T, what string, ch <-chan pf03Reply) pf03Reply {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return pf03Reply{}
	}
}

// Coalesced follower: for every name, the leader's scan is held open inside the
// engine, a follower with the SAME name provably registers on that flight
// (observed via flightGroup.joiners, no sleeps), and a differently named request
// that needs a different verdict runs to completion meanwhile without joining the
// held flight. Only then is the leader released. The follower must report
// cache=coalesced and every response must carry its own name's verdict. The
// leader's cache status is not pinned: flightGroup reports it as shared when a
// follower was still waiting at finish, a metric approximation (flight.go), so
// either a fresh "" or "coalesced" is accepted for the leader.
func TestPF03FilenameCoalescedFollower(t *testing.T) {
	sc := pf03Scanner(t)
	cases := pf03Cases()
	for i, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			other := pf03Neighbour(cases, i)
			if other == nil {
				t.Fatal("no differently-verdicted neighbour name for " + c.label)
			}
			gate := newPF03Gate(sc)
			s := pf03Server(gate, 2)
			var once sync.Once
			free := func() { once.Do(func() { close(gate.release) }) }
			t.Cleanup(free)

			leader := pf03Async(t, s, c)
			select {
			case <-gate.entered:
			case <-time.After(30 * time.Second):
				t.Fatal("leader never reached the engine")
			}
			follower := pf03Async(t, s, c)
			deadline := time.Now().Add(30 * time.Second)
			for pf03Joiners(s) < 1 {
				if time.Now().After(deadline) {
					t.Fatal("follower never joined the in-flight scan")
				}
				time.Sleep(time.Millisecond) // polls the observable joiner count; not a synchronizer
			}
			nr := pf03AwaitNeighbour(t, s, c, *other, time.Now().Add(30*time.Second))
			if nr.err != nil || !slices.Equal(nr.got, other.want) || nr.cache != "" {
				t.Errorf("neighbour %s (%q): verdict %v cache=%q err=%v, want %v fresh", other.label, other.name, nr.got, nr.cache, nr.err, other.want)
			}

			free()
			lr := pf03Wait(t, "leader", leader)
			fr := pf03Wait(t, "follower", follower)
			for _, x := range []struct {
				role  string
				r     pf03Reply
				cache []string
			}{{"leader", lr, []string{"", "coalesced"}}, {"follower", fr, []string{"coalesced"}}} {
				if x.r.err != nil {
					t.Errorf("%s: %v", x.role, x.r.err)
					continue
				}
				if !slices.Equal(x.r.got, c.want) {
					t.Errorf("%s %s (%q): verdict %v, want %v", x.role, c.label, c.name, x.r.got, c.want)
				}
				if !slices.Contains(x.cache, x.r.cache) {
					t.Errorf("%s %s: cache=%q, want one of %q", x.role, c.label, x.r.cache, x.cache)
				}
			}
		})
	}
}
