package threatfox

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleCSV = `# Dump generated 2026-06-29
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
"2026-06-29 16:02:30", "1839890", "http://c2.evil.test/Payload.exe", "url", "botnet_cc", "agenttesla", "None", "AgentTesla", "", "90", "False", "None", "exe", "1", "tester"
"2026-06-29 16:02:28", "1839889", "malicious.domain.test", "domain", "botnet_cc", "emotet", "None", "Emotet", "", "90", "False", "None", "", "1", "tester"
"2026-06-29 16:02:27", "1839888", "10.20.30.40:4444", "ip:port", "botnet_cc", "trickbot", "None", "TrickBot", "", "80", "False", "None", "", "1", "tester"
`

const legacySampleCSV = `# id,ioc_type,ioc_value,threat_type,fk_threat_type,malware,fk_malware,malware_alias,malware_printable,first_seen_utc,last_seen_utc,confidence_level,anonymized,tags,credits,reference
"1","url","http://legacy.evil.test/payload.exe","botnet_cc","1","AgentTesla","1","AgentTesla","AgentTesla","2024-01-01 00:00:00 UTC","2024-01-02 00:00:00 UTC","75","","exe","anon","https://threatfox.abuse.ch/ioc/1/"
`

func testChecker(t *testing.T) *Checker {
	t.Helper()
	rs, err := parseFeed(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{logf: func(string, ...any) {}}
	c.rs.Store(rs)
	return c
}

func TestParseFeed(t *testing.T) {
	rs, err := parseFeed(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	// URL row: "http://c2.evil.test/payload.exe" → urls + domains
	if len(rs.urls) != 1 {
		t.Errorf("urls=%d want 1", len(rs.urls))
	}
	// domain row: "malicious.domain.test" + host from url row = 2 domains
	if len(rs.domains) != 2 {
		t.Errorf("domains=%d want 2 (url-host + domain-row)", len(rs.domains))
	}
	if _, ok := rs.domains["malicious.domain.test"]; !ok {
		t.Error("domain malicious.domain.test missing")
	}
	if _, ok := rs.domains["c2.evil.test"]; !ok {
		t.Error("url-derived host c2.evil.test missing from domains")
	}
}

func TestFeedHTTPClientRefusesRedirects(t *testing.T) {
	c := newFeedHTTPClient(time.Second)
	req, err := http.NewRequest(http.MethodGet, "https://example.test/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(req, []*http.Request{{}}); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

func TestReadFeedBodyRejectsOversized(t *testing.T) {
	_, err := readFeedBody(bytes.NewReader([]byte("123456")), 5)
	if !errors.Is(err, errFeedTooLarge) {
		t.Fatalf("readFeedBody err = %v, want errFeedTooLarge", err)
	}
}

func TestParseFeedLegacyCacheFormat(t *testing.T) {
	rs, err := parseFeed(strings.NewReader(legacySampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.urls["http://legacy.evil.test/payload.exe"]; !ok {
		t.Fatalf("legacy URL row missing; urls=%v", rs.urls)
	}
	if _, ok := rs.domains["legacy.evil.test"]; !ok {
		t.Fatalf("legacy URL host missing; domains=%v", rs.domains)
	}
}

func TestCheckExactURL(t *testing.T) {
	hits := testChecker(t).Check([]byte("click http://c2.evil.test/Payload.exe now"), 64)
	if len(hits) != 1 || hits[0].Host || hits[0].Deobf {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].Rule() != "THREATFOX_IOC_URL" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckDomainMatch(t *testing.T) {
	// Different path on known-bad domain → domain-level hit.
	hits := testChecker(t).Check([]byte("see https://malicious.domain.test/other/path"), 64)
	if len(hits) != 1 || !hits[0].Host {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].Rule() != "THREATFOX_IOC_DOMAIN" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckDeobf(t *testing.T) {
	hits := testChecker(t).Check([]byte("hxxp://c2.evil[.]test/Payload.exe"), 64)
	if len(hits) != 1 || !hits[0].Deobf {
		t.Fatalf("deobf hits=%+v", hits)
	}
	if hits[0].Rule() != "THREATFOX_IOC_URL_DEOBF" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckClean(t *testing.T) {
	hits := testChecker(t).Check([]byte("nothing bad here https://good.example/ok"), 64)
	if len(hits) != 0 {
		t.Errorf("clean buffer matched: %+v", hits)
	}
}

func TestCheckBudget(t *testing.T) {
	hits := testChecker(t).Check([]byte("https://good.example/a http://c2.evil.test/Payload.exe"), 1)
	if len(hits) != 0 {
		t.Errorf("budget not honoured: %+v", hits)
	}
}

func TestCheckCandidatesEmptyNoAlloc(t *testing.T) {
	c := testChecker(t)
	allocs := testing.AllocsPerRun(100, func() {
		if hits := c.CheckCandidates(nil, 64); hits != nil {
			t.Fatalf("empty candidates hit: %+v", hits)
		}
	})
	if allocs != 0 {
		t.Errorf("empty CheckCandidates allocs = %g, want 0", allocs)
	}
}

func TestNewDisabledNoKey(t *testing.T) {
	if New("", 0, "", func(string, ...any) {}) != nil {
		t.Error("empty key must disable the checker (nil)")
	}
}

func TestWarmStartFromCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "threatfox.csv"), []byte(sampleCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New("bogus-key", 0, dir, func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil with a key set")
	}
	hits := c.Check([]byte("click http://c2.evil.test/Payload.exe now"), 64)
	if len(hits) == 0 {
		t.Error("warm-started feed should match the cached URL before any network refresh")
	}
}

func TestCloseNilSafeAndIdempotent(t *testing.T) {
	var nilC *Checker
	nilC.Close()

	c := New("bogus-key", 0, "", func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil for a non-empty key")
	}
	c.Close()
	c.Close()
	select {
	case <-c.stop:
	default:
		t.Fatal("Close did not close the stop channel")
	}
}
