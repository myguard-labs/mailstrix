package urlcand_test

import (
	"strings"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/urlcand"
)

func TestExtractRawBeforeDeobf(t *testing.T) {
	// Buffer contains both a plain URL and a defanged one.
	data := []byte("see http://plain.example/a and hxxp://obfuscated[.]example/b")
	cands := urlcand.Extract(data, 64)
	if len(cands) < 2 {
		t.Fatalf("expected >=2 candidates, got %d: %+v", len(cands), cands)
	}
	// All raw candidates must precede all deobf candidates.
	seenDeobf := false
	for _, c := range cands {
		if c.Deobf {
			seenDeobf = true
		} else if seenDeobf {
			t.Errorf("raw candidate after deobf candidate: %+v", cands)
			break
		}
	}
	// First candidate must be the plain URL (Deobf=false).
	if cands[0].Deobf {
		t.Errorf("first candidate should be raw, got Deobf=true: %+v", cands[0])
	}
	// At least one deobf candidate.
	hasDeobf := false
	for _, c := range cands {
		if c.Deobf {
			hasDeobf = true
			break
		}
	}
	if !hasDeobf {
		t.Error("expected at least one deobf candidate")
	}
}

func TestExtractBudgetBoundsTotal(t *testing.T) {
	// Build a buffer with more URLs than the budget allows.
	var sb strings.Builder
	for i := 0; i < 10; i++ {
		sb.WriteString("http://host.example/path ")
	}
	// Add a defanged URL too.
	sb.WriteString("hxxp://obf[.]example/x ")
	data := []byte(sb.String())

	budget := 5
	cands := urlcand.Extract(data, budget)
	if len(cands) > budget {
		t.Errorf("got %d candidates with budget %d", len(cands), budget)
	}
}

func TestExtractNoDefangGate(t *testing.T) {
	// Buffer contains no defang trigger bytes ([, (, {, x, X) — only plain URLs.
	data := []byte("see http://plain.host/path and https://other.host/page")
	cands := urlcand.Extract(data, 64)
	for _, c := range cands {
		if c.Deobf {
			t.Errorf("got Deobf candidate from buffer with no defang triggers: %+v", c)
		}
	}
}

func TestExtractEmptyBuffer(t *testing.T) {
	if cands := urlcand.Extract([]byte{}, 64); cands != nil {
		t.Errorf("empty buffer should return nil, got %+v", cands)
	}
	if cands := urlcand.Extract(nil, 64); cands != nil {
		t.Errorf("nil buffer should return nil, got %+v", cands)
	}
}

func TestExtractNoURLs(t *testing.T) {
	if cands := urlcand.Extract([]byte("no urls here just text"), 64); cands != nil {
		t.Errorf("no-URL buffer should return nil, got %+v", cands)
	}
}

func TestExtractOrdering(t *testing.T) {
	// Multiple raw URLs + multiple defanged URLs: ordering must be raw-all then deobf-all.
	data := []byte("http://a.example/1 https://b.example/2 hxxp://c[.]example/3 hxxp://d[.]example/4")
	cands := urlcand.Extract(data, 64)

	rawCount := 0
	deobfCount := 0
	for _, c := range cands {
		if !c.Deobf {
			rawCount++
		}
	}
	for _, c := range cands {
		if c.Deobf {
			deobfCount++
		}
	}
	if rawCount < 2 {
		t.Errorf("expected >=2 raw candidates, got %d", rawCount)
	}
	if deobfCount < 2 {
		t.Errorf("expected >=2 deobf candidates, got %d", deobfCount)
	}

	// Verify ordering: all raw before any deobf.
	inDeobf := false
	for _, c := range cands {
		if c.Deobf {
			inDeobf = true
		} else if inDeobf {
			t.Errorf("raw candidate appeared after deobf section: %+v", cands)
			break
		}
	}
}

func TestExtractDefaultBudget(t *testing.T) {
	// maxURLs=0 should default to 64.
	data := []byte("http://a.example/x")
	cands := urlcand.Extract(data, 0)
	if len(cands) == 0 {
		t.Error("zero maxURLs should default to 64, not drop all candidates")
	}
}

func TestCandidateNormalizationFields(t *testing.T) {
	cands := urlcand.Extract([]byte("see HTTP://1.2.3.4:80/path?q=1#frag"), 64)
	if len(cands) != 1 {
		t.Fatalf("candidates = %+v, want one", cands)
	}
	norm, host, ip := cands[0].Normalize()
	if norm != cands[0].Norm || host != cands[0].Host || ip != cands[0].IP {
		t.Fatalf("Normalize did not cache fields on candidate: %+v", cands[0])
	}
	if cands[0].Norm != "http://1.2.3.4/path?q=1" {
		t.Errorf("Norm = %q", cands[0].Norm)
	}
	if cands[0].Host != "1.2.3.4" {
		t.Errorf("Host = %q", cands[0].Host)
	}
	if cands[0].IP != "1.2.3.4" {
		t.Errorf("IP = %q", cands[0].IP)
	}

	norm, host, ip = urlcand.NormalizeHTTPURL(` https://Example.COM:443/a/. `)
	if norm != "https://example.com/a/" || host != "example.com" || ip != "" {
		t.Errorf("NormalizeHTTPURL = (%q,%q,%q)", norm, host, ip)
	}
}

// TestExtractRepeatedURLPaddingDoesNotHideDistinct (COR-07): one URL repeated
// many times spends no budget, so a later distinct URL is still returned.
func TestExtractRepeatedURLPaddingDoesNotHideDistinct(t *testing.T) {
	data := strings.Repeat("http://pad.example/x ", 200) + "http://evil.example/drop.exe"
	got := urlcand.Extract([]byte(data), 64)
	if len(got) != 2 || got[0].Raw != "http://pad.example/x" || got[1].Raw != "http://evil.example/drop.exe" {
		t.Fatalf("got %+v", got)
	}
}

// TestExtractDistinctURLsStillCapped (negative/boundary): the cap still holds
// for distinct URLs, and a defanged copy of a raw URL is not repeated.
func TestExtractDistinctURLsStillCapped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("http://h" + strings.Repeat("a", i%26+1) + ".example/" + string(rune('a'+i%26)) + strings.Repeat("z", i/26) + " ")
	}
	if got := urlcand.Extract([]byte(b.String()), 64); len(got) != 64 {
		t.Fatalf("distinct cap: got %d, want 64", len(got))
	}
	got := urlcand.Extract([]byte("http://dup.example/a and hxxp://dup[.]example/a"), 64)
	if len(got) != 1 {
		t.Fatalf("defanged duplicate repeated: %+v", got)
	}
}

// TestNormalizeHTTPURLTrailingDotHost (COR-12): a root-dot FQDN normalizes to
// the same URL and host as the plain name, so feed lookups match.
func TestNormalizeHTTPURLTrailingDotHost(t *testing.T) {
	wantNorm, wantHost, _ := urlcand.NormalizeHTTPURL("http://evil.com/x.exe")
	for _, raw := range []string{
		"http://evil.com./x.exe",
		"http://EVIL.com../x.exe", // boundary: repeated dots
		"http://evil.com.:80/x.exe",
	} {
		norm, host, _ := urlcand.NormalizeHTTPURL(raw)
		if norm != wantNorm || host != wantHost {
			t.Errorf("%s -> (%q, %q), want (%q, %q)", raw, norm, host, wantNorm, wantHost)
		}
	}
	// Malformed: a host made only of dots is rejected, not normalized to "".
	if norm, host, _ := urlcand.NormalizeHTTPURL("http://./x.exe"); norm != "" || host != "" {
		t.Errorf("dot-only host -> (%q, %q), want rejection", norm, host)
	}
	// Negative: an inner dot is not touched.
	if _, host, _ := urlcand.NormalizeHTTPURL("http://a.evil.com/x"); host != "a.evil.com" {
		t.Errorf("inner dots changed: host %q", host)
	}
}
