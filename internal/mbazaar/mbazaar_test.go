package mbazaar

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	if len(hs.s) != 2 {
		t.Fatalf("hashes=%d want 2", len(hs.s))
	}
	var want [32]byte
	if _, err := hex.Decode(want[:], bytes.Repeat([]byte("a"), 64)); err != nil {
		t.Fatal(err)
	}
	if ok := hs.has(want); !ok {
		t.Error("expected sha256 not in set")
	}
}

func TestParseFeedZip(t *testing.T) {
	// The full dump is a ZIP holding one CSV; parseFeed must unwrap it.
	hs, err := parseFeed(zipOf(t, []byte(sampleCSV)))
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.s) != 2 {
		t.Fatalf("zip hashes=%d want 2", len(hs.s))
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
	c.set.Store(&hashSet{})
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
	if _, e := hex.Decode(want[:], []byte(hashOf("x"))); e != nil {
		t.Fatal(e)
	}
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

// TestParseFeedDecompressedCap verifies the DECOMPRESSED CSV stream is bounded
// (zip-bomb guard): a body over maxDecompressedBytes is rejected with
// errOverCeiling (never silently truncated into a partial set), a body under it
// loads fully.
func TestParseFeedDecompressedCap(t *testing.T) {
	orig := maxDecompressedBytes
	defer func() { maxDecompressedBytes = orig }()

	var b bytes.Buffer
	b.WriteString("# first_seen_utc,sha256_hash,md5_hash\n")
	const rows = 5000
	for i := 0; i < rows; i++ {
		sum := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		b.WriteString("\"2024-01-01 00:00:00\",\"" + hex.EncodeToString(sum[:]) + "\",\"x\"\n")
	}
	full := b.Bytes()

	hsFull, err := parseFeed(full)
	if err != nil {
		t.Fatalf("uncapped parseFeed: %v", err)
	}
	if len(hsFull.s) != rows {
		t.Fatalf("uncapped: got %d hashes, want %d", len(hsFull.s), rows)
	}

	maxDecompressedBytes = 512
	if hs, err := parseFeed(full); !errors.Is(err, errOverCeiling) || hs != nil {
		t.Fatalf("capped plain CSV: hs=%v err=%v, want errOverCeiling", hs, err)
	}
	if hs, err := parseFeed(zipOf(t, full)); !errors.Is(err, errOverCeiling) || hs != nil {
		t.Fatalf("capped zip: hs=%v err=%v, want errOverCeiling", hs, err)
	}
}

// TestParseFeedExactlyAtCeiling is the boundary: a CSV of exactly
// maxDecompressedBytes loads, one byte more is rejected (plain and zip).
func TestParseFeedExactlyAtCeiling(t *testing.T) {
	orig := maxDecompressedBytes
	defer func() { maxDecompressedBytes = orig }()
	csv := []byte(sampleCSV)

	maxDecompressedBytes = int64(len(csv))
	for name, body := range map[string][]byte{"plain": csv, "zip": zipOf(t, csv)} {
		hs, err := parseFeed(body)
		if err != nil || len(hs.s) != 2 {
			t.Fatalf("%s at bound: n=%v err=%v, want 2 hashes", name, hs, err)
		}
	}
	maxDecompressedBytes = int64(len(csv)) - 1
	for name, body := range map[string][]byte{"plain": csv, "zip": zipOf(t, csv)} {
		if _, err := parseFeed(body); !errors.Is(err, errOverCeiling) {
			t.Fatalf("%s one over bound: err=%v, want errOverCeiling", name, err)
		}
	}
}

// TestParseFeedLyingZipHeader: a zip whose header declares a small size but
// inflates past the ceiling is stopped by the streaming bound, not the header.
func TestParseFeedLyingZipHeader(t *testing.T) {
	orig := maxDecompressedBytes
	maxDecompressedBytes = 1024
	defer func() { maxDecompressedBytes = orig }()

	big := bytes.Repeat([]byte("# padding padding padding padding\n"), 200) // ~7 KB
	z := zipOf(t, big)
	// Forge the central-directory uncompressed size (offset 24 in the PK\x01\x02
	// record) to a small value so only the streaming bound can catch the bomb.
	i := bytes.LastIndex(z, []byte("PK\x01\x02"))
	if i < 0 {
		t.Fatal("no central directory")
	}
	copy(z[i+24:i+28], []byte{16, 0, 0, 0})
	zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		t.Fatal(err)
	}
	if zr.File[0].UncompressedSize64 > uint64(maxDecompressedBytes) {
		t.Fatal("forged header must claim a size under the ceiling")
	}
	if _, err := parseFeed(z); err == nil {
		t.Fatal("lying header inflating past the ceiling was accepted")
	}
}

// TestParseFeedMalformedRejected: a truncated zip, a corrupt deflate stream and
// a zip with no file entry are rejected (not an empty or partial set).
func TestParseFeedMalformedRejected(t *testing.T) {
	good := zipOf(t, []byte(sampleCSV))
	corrupt := append([]byte(nil), good...)
	for i := 40; i < 60 && i < len(corrupt); i++ { // inside the deflate payload
		corrupt[i] ^= 0xFF
	}
	cases := map[string][]byte{
		"truncated":  good[:len(good)/2],
		"corrupt":    corrupt,
		"magic-only": []byte("PK\x03\x04junk"),
	}
	for name, body := range cases {
		if hs, err := parseFeed(body); err == nil {
			t.Errorf("%s: accepted (hs=%v), want error", name, hs)
		}
	}
	// Malformed CSV rows alone are skipped, not fatal.
	hs, err := parseFeed([]byte("\"unterminated,\x00\n" + string(csvFor("ok"))))
	if err != nil || hs == nil {
		t.Fatalf("bad row must be skipped: %v", err)
	}
}

func TestParseFeedSpaceSeparatedRows(t *testing.T) {
	a, b := hashOf("a"), hashOf("b")
	feed := "# comment\n# \"first_seen_utc\", \"sha256_hash\", \"md5_hash\"\n" +
		"\"2026-10-14 10:00:00\", \"" + a + "\", \"md5\", \"x\"\n" +
		"\"2026-10-14 10:00:01\",\"" + b + "\",\"md5\"\n" + // no-space boundary
		"\"2026-10-14 10:00:02\", \"not-a-hash\", \"md5\"\n" // malformed
	hs, err := parseFeed([]byte(feed))
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.s) != 2 {
		t.Fatalf("entries=%d want 2", len(hs.s))
	}
	for _, h := range []string{a, b} {
		d, ok := parseSHA256(h)
		if hit := hs.has(d); !ok || !hit {
			t.Fatalf("missing %s", h)
		}
	}
}
