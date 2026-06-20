package mbazaar

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// sampleCSV mirrors the MalwareBazaar dump layout:
// first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,…
const sampleCSV = `# MalwareBazaar export
# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature
"2024-01-01 00:00:00","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","d41d8cd98f00b204e9800998ecf8427e","da39a3ee5e6b4b0d3255bfef95601890afd80709","anon","evil.exe","exe","application/x-dosexec","AgentTesla"
"2024-01-02 00:00:00","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","d41d8cd98f00b204e9800998ecf8427e","da39a3ee5e6b4b0d3255bfef95601890afd80709","anon","doc.xlsm","xlsm","application/zip","Emotet"
`

// hashOf returns the lowercase hex SHA256 of s — what MalwareBazaar would list.
func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// csvFor builds a one-row dump whose sha256 column is the real SHA256 of body,
// so a Check of body must hit. Returned as plain CSV bytes.
func csvFor(body string) []byte {
	return []byte("# header\n\"2024-01-01\",\"" + hashOf(body) + "\",\"md5\",\"sha1\",\"anon\",\"x\"\n")
}

func zipOf(t *testing.T, csv []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("full.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(csv); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func checkerFrom(t *testing.T, body []byte) *Checker {
	t.Helper()
	hs, err := parseFeed(body)
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{logf: func(string, ...any) {}}
	c.set.Store(hs)
	return c
}

func TestParseFeedPlainCSV(t *testing.T) {
	hs, err := parseFeed([]byte(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.m) != 2 {
		t.Fatalf("hashes=%d want 2", len(hs.m))
	}
	var want [32]byte
	if _, err := hex.Decode(want[:], bytes.Repeat([]byte("a"), 64)); err != nil {
		t.Fatal(err)
	}
	if _, ok := hs.m[want]; !ok {
		t.Error("expected sha256 not in set")
	}
}

func TestParseFeedZip(t *testing.T) {
	// The full dump is a ZIP holding one CSV; parseFeed must unwrap it.
	hs, err := parseFeed(zipOf(t, []byte(sampleCSV)))
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.m) != 2 {
		t.Fatalf("zip hashes=%d want 2", len(hs.m))
	}
}

func TestCheckHit(t *testing.T) {
	body := "this exact attachment is known malware"
	c := checkerFrom(t, csvFor(body))
	hits := c.Check([]byte(body))
	if len(hits) != 1 {
		t.Fatalf("hits=%+v want 1", hits)
	}
	if hits[0].SHA256 != hashOf(body) {
		t.Errorf("hit sha256=%s want %s", hits[0].SHA256, hashOf(body))
	}
	if hits[0].Rule() != "MALWAREBAZAAR_MALWARE" {
		t.Errorf("rule=%s", hits[0].Rule())
	}
	if m := c.Metrics(); m.Lookups != 1 || m.Hits != 1 || m.FeedHashes != 1 {
		t.Errorf("metrics=%+v", m)
	}
}

func TestCheckMiss(t *testing.T) {
	c := checkerFrom(t, csvFor("known sample"))
	if hits := c.Check([]byte("a totally different, benign attachment")); len(hits) != 0 {
		t.Errorf("benign buffer matched: %+v", hits)
	}
}

func TestCheckEmptySet(t *testing.T) {
	c := &Checker{logf: func(string, ...any) {}}
	c.set.Store(&hashSet{m: map[[32]byte]struct{}{}})
	if hits := c.Check([]byte("anything")); hits != nil {
		t.Errorf("empty set must never hit: %+v", hits)
	}
}

func TestPickSHA256FallbackColumn(t *testing.T) {
	// sha256 not in the documented column 1 — must still be found by length.
	rec := []string{"date", "not-a-hash", "md5short", hashOf("x")}
	d, ok := pickSHA256(rec)
	if !ok {
		t.Fatal("sha256 in a non-standard column not found")
	}
	var want [32]byte
	hex.Decode(want[:], []byte(hashOf("x")))
	if d != want {
		t.Error("wrong digest picked")
	}
	// md5 (32) / sha1 (40) lengths must NOT be mistaken for sha256.
	if _, ok := pickSHA256([]string{"d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709"}); ok {
		t.Error("md5/sha1 wrongly accepted as sha256")
	}
}

func TestNewDisabledNoKey(t *testing.T) {
	if New("", 0, "", "", func(string, ...any) {}) != nil {
		t.Error("empty key must disable the checker (nil)")
	}
}

// TestCloseNilSafeAndIdempotent: Close on a nil *Checker (disabled feature) and
// a double Close must not panic, so shutdown code can call it unconditionally.
// (STAB-7)
func TestCloseNilSafeAndIdempotent(t *testing.T) {
	var nilC *Checker
	nilC.Close() // must be a no-op, not a panic

	c := New("bogus-key", 0, "", "", func(string, ...any) {})
	if c == nil {
		t.Fatal("New returned nil for a non-empty key")
	}
	c.Close()
	c.Close() // idempotent

	select {
	case <-c.stop:
	default:
		t.Fatal("Close did not close the stop channel")
	}
}
