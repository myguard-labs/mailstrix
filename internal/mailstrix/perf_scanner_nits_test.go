package mailstrix

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// capDedupRef is the pre-PERF-54 behaviour: dedup the concatenation, then cut.
func capDedupRef(lists ...[]string) []string {
	var all []string
	for _, l := range lists {
		all = append(all, l...)
	}
	out := dedupCandidates(all)
	if len(out) > maxEffectivePWCandidates {
		out = out[:maxEffectivePWCandidates]
	}
	return out
}

func words(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return out
}

func TestCapDedupCandidatesMatchesReference(t *testing.T) {
	cases := map[string][][]string{
		"empty":           nil,
		"empty lists":     {nil, {}, nil},
		"blank and space": {{"", "  ", "\t"}, {" a ", "a", "b"}},
		"exactly cap":     {words("w", maxEffectivePWCandidates)},
		"cap plus one":    {words("w", maxEffectivePWCandidates+1)},
		"dups across":     {{"x", "y"}, {"y", "x", "z"}, words("w", 10)},
		"big wordlist":    {{"body"}, {"name"}, words("d", 5), words("w", 4096)},
		"dups at cap":     {words("w", maxEffectivePWCandidates-1), {"w0", "w1", "tail", "after"}},
	}
	for name, lists := range cases {
		got, want := capDedupCandidates(lists...), capDedupRef(lists...)
		if strings.Join(got, "\n") != strings.Join(want, "\n") || len(got) != len(want) {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 500; i++ {
		lists := make([][]string, rng.Intn(5))
		for j := range lists {
			l := make([]string, rng.Intn(60))
			for k := range l {
				l[k] = []string{"", " ", "a", " b", "c "}[rng.Intn(5)] + fmt.Sprint(rng.Intn(80))
			}
			lists[j] = l
		}
		got, want := capDedupCandidates(lists...), capDedupRef(lists...)
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") || len(got) != len(want) {
			t.Fatalf("random case %d: got %q, want %q", i, got, want)
		}
	}
}

func TestCapDedupCandidatesStopsAtCap(t *testing.T) {
	// The tail behind the cap must not be visited: 64 unique heads plus a huge
	// wordlist allocates about as much as the heads alone.
	head := words("h", maxEffectivePWCandidates)
	tail := words("w", 4096)
	small := testing.AllocsPerRun(20, func() { _ = capDedupCandidates(head) })
	big := testing.AllocsPerRun(20, func() { _ = capDedupCandidates(head, tail) })
	if big > small+1 {
		t.Fatalf("tail behind the cap was processed: %v allocs vs %v", big, small)
	}
}

func TestFingerprintPolicyMemoised(t *testing.T) {
	dir := writeRules(t, eicarRule)
	cfg := &Config{RulesDir: dir, ArchivePW: true, ArchivePWords: words("w", 4096),
		RuleAllowlist: map[string]struct{}{"eicar_test_file": {}}}
	cfg.sanitize()
	s, err := NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	fp := s.Fingerprint()
	if !strings.HasSuffix(fp, ":"+s.scoringPolicyHash()) {
		t.Fatalf("fingerprint %q does not end in the policy hash", fp)
	}
	if allocs := testing.AllocsPerRun(50, func() { _ = s.Fingerprint() }); allocs > 4 {
		t.Fatalf("Fingerprint rehashes the policy: %v allocs", allocs)
	}
	// Different policy, different fingerprint (memoisation is per scanner).
	cfg2 := &Config{RulesDir: dir}
	cfg2.sanitize()
	s2, err := NewScanner(cfg2, func(string, ...any) {})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if s2.Fingerprint() == fp {
		t.Fatal("different scoring policy produced the same fingerprint")
	}
	// A zero Scanner (struct literal) still computes a policy hash.
	var z Scanner
	if z.policyFingerprint() == "" || z.policyFingerprint() != z.scoringPolicyHash() {
		t.Fatal("zero scanner policy fingerprint wrong")
	}
}

func TestFilterDeniedDoesNotTagAllow(t *testing.T) {
	s := &Scanner{allowlist: map[string]struct{}{"keep": {}}}
	in := []Match{{Rule: "Keep"}, {Rule: "other"}}
	out := s.filterDenied(in)
	if len(out) != 2 || out[0].Meta != nil {
		t.Fatalf("filterDenied must leave allow tagging to applyResponseTags: %+v", out)
	}
	tagged := s.applyResponseTags(out)
	if tagged[0].Meta["mailstrix_allow"] != "1" || tagged[1].Meta != nil {
		t.Fatalf("applyResponseTags allow tag wrong: %+v", tagged)
	}
	deny := map[string]struct{}{"other": {}}
	s.denylist.Store(&deny)
	if out := s.filterDenied([]Match{{Rule: "OTHER"}, {Rule: "keep"}}); len(out) != 1 || out[0].Rule != "keep" {
		t.Fatalf("denylisted rule kept: %+v", out)
	}
	if out := s.filterDenied(nil); out != nil {
		t.Fatalf("nil input: %+v", out)
	}
}

func TestGetScannerStaleRulesDoNotReplacePool(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	cur := s.rules.Load()
	sc, gen, err := s.getScanner(cur)
	if err != nil {
		t.Fatal(err)
	}
	s.putScanner(sc, gen)
	live := s.scanners.Load()
	if live == nil || live.rules != cur || len(live.free) != 1 {
		t.Fatalf("pool not installed for current rules: %+v", live)
	}
	stale, err := compileDir(writeRules(t, eicarRule), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Destroy()
	ssc, sgen, err := s.getScanner(stale)
	if err != nil {
		t.Fatal(err)
	}
	if s.scanners.Load() != live {
		t.Fatal("stale-rules scan replaced the live pool")
	}
	s.putScanner(ssc, sgen) // destroyed, not pooled
	if len(live.free) != 1 || len(sgen.free) != 0 {
		t.Fatalf("stale scanner pooled or live pool drained: live=%d stale=%d", len(live.free), len(sgen.free))
	}
}
