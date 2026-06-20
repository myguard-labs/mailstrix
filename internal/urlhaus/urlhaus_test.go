package urlhaus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWarmStartFromCache: a persisted feed snapshot in cacheDir is loaded into
// the set at New() time, so a lookup hits before any network refresh. (New's
// background refresh fires against the real feed with a bogus key and fails
// harmlessly; warmStart ran synchronously first.)
func TestWarmStartFromCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "urlhaus.csv"), []byte(sampleCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New("bogus-key", 0, dir, func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil with a key set")
	}
	hits := c.Check([]byte("click http://evil.example/malware.exe now"), 64)
	if len(hits) == 0 {
		t.Error("warm-started feed should match the cached URL before any refresh")
	}
}

// TestWarmStartBadCacheIgnored: a corrupt cache file is ignored (logged), New
// still returns a usable (empty) checker.
func TestWarmStartBadCacheIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "urlhaus.csv"), []byte("\x00\x01 not csv"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := New("bogus-key", 0, dir, func(string, ...any) {}); c == nil {
		t.Error("New should still return a checker despite a bad cache")
	}
}

const sampleCSV = `# Dump generated 2024-01-02
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2024-01-01 00:00:00","http://evil.example/malware.exe","online","2024-01-02","malware_download","exe,doc","https://urlhaus.abuse.ch/url/1/","anon"
"2","2024-01-02 00:00:00","https://bad.host.test/path?x=1","online","2024-01-02","malware_download","","https://urlhaus.abuse.ch/url/2/","anon"
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
	if len(rs.urls) != 2 {
		t.Errorf("urls=%d want 2", len(rs.urls))
	}
	if _, ok := rs.hosts["evil.example"]; !ok {
		t.Error("host evil.example missing")
	}
}

func TestCheckExactURL(t *testing.T) {
	hits := testChecker(t).Check([]byte("please click http://evil.example/malware.exe right now"), 64)
	if len(hits) != 1 || hits[0].Host || hits[0].Deobf {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].Rule() != "URLHAUS_MALWARE_URL" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckHostMatch(t *testing.T) {
	// A different path on a known-bad host -> host-level hit, not exact.
	hits := testChecker(t).Check([]byte("see http://bad.host.test/some/other/path"), 64)
	if len(hits) != 1 || !hits[0].Host {
		t.Fatalf("hits=%+v", hits)
	}
	if hits[0].Rule() != "URLHAUS_MALWARE_HOST" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckDeobf(t *testing.T) {
	// Defanged URL: only found after un-defanging -> Deobf hit.
	hits := testChecker(t).Check([]byte("dropper url: hxxp://evil[.]example/malware.exe"), 64)
	if len(hits) != 1 || !hits[0].Deobf {
		t.Fatalf("deobf hits=%+v", hits)
	}
	if hits[0].Rule() != "URLHAUS_MALWARE_URL_DEOBF" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
}

func TestCheckClean(t *testing.T) {
	if hits := testChecker(t).Check([]byte("nothing bad here https://good.example/ok"), 64); len(hits) != 0 {
		t.Errorf("clean buffer matched: %+v", hits)
	}
}

func TestCheckBudget(t *testing.T) {
	// maxURLs bounds how many URLs are examined; with budget 0 -> default 64, so
	// use 1 and a buffer whose first URL is clean to prove the bad one past the
	// budget is not examined.
	hits := testChecker(t).Check([]byte("https://good.example/a http://evil.example/malware.exe"), 1)
	if len(hits) != 0 {
		t.Errorf("budget not honoured: %+v", hits)
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"http://Evil.Example/":        "http://evil.example",
		"https://h.test:443/p":        "https://h.test/p",
		"http://h.test:80/p?q=1#frag": "http://h.test/p?q=1",
		"ftp://h.test/x":              "",
		"not a url":                   "",
	}
	for in, want := range cases {
		if got, _ := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNewDisabledNoKey(t *testing.T) {
	if New("", 0, "", func(string, ...any) {}) != nil {
		t.Error("empty key must disable the checker (nil)")
	}
}

// TestCloseNilSafeAndIdempotent: Close on a nil *Checker (disabled feature) and
// a double Close must not panic, so shutdown code can call it unconditionally.
// (STAB-7)
func TestCloseNilSafeAndIdempotent(t *testing.T) {
	var nilC *Checker
	nilC.Close() // must be a no-op, not a panic

	// A live checker (bogus key so the background fetch just fails) must close
	// cleanly, and a second Close must be a no-op rather than a double-close
	// panic on the stop channel.
	c := New("bogus-key", 0, "", func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil for a non-empty key")
	}
	c.Close()
	c.Close() // idempotent

	select {
	case <-c.stop:
		// closed as expected
	default:
		t.Fatal("Close did not close the stop channel")
	}
}
