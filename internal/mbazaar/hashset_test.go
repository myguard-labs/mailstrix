package mbazaar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func hexRow(h [32]byte) string { return fmt.Sprintf("\"2024-01-01\",\"%x\",\"m\"\n", h[:]) }

func dig(b byte) (d [32]byte) {
	for i := range d {
		d[i] = b
	}
	return d
}

func parseDigs(t *testing.T, ds ...[32]byte) *hashSet {
	t.Helper()
	var buf bytes.Buffer
	for _, d := range ds {
		buf.WriteString(hexRow(d))
	}
	hs, err := parseFeed(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return hs
}

func TestHashSetSortedLookup(t *testing.T) {
	// unsorted input incl. duplicates; first/last boundaries are 0x01.. and 0xfe..
	hs := parseDigs(t, dig(0x80), dig(0xfe), dig(0x01), dig(0x80), dig(0x40), dig(0xfe))
	if len(hs.s) != 4 {
		t.Fatalf("len=%d want 4 (duplicates collapse)", len(hs.s))
	}
	for _, b := range []byte{0x01, 0x40, 0x80, 0xfe} { // first, middle, last
		if !hs.has(dig(b)) {
			t.Errorf("hit %#x missing", b)
		}
	}
	for _, b := range []byte{0x00, 0x02, 0x7f, 0x81, 0xff} { // below first, gaps, above last
		if hs.has(dig(b)) {
			t.Errorf("miss %#x reported present", b)
		}
	}
}

func TestHashSetEmptyAndSingle(t *testing.T) {
	if hs := parseDigs(t); len(hs.s) != 0 || hs.has(dig(1)) {
		t.Fatal("empty feed must be an empty set")
	}
	hs := parseDigs(t, dig(7))
	if len(hs.s) != 1 || !hs.has(dig(7)) || hs.has(dig(8)) || hs.has(dig(6)) {
		t.Fatal("single-entry set wrong")
	}
	if (&hashSet{}).has(dig(1)) {
		t.Fatal("zero hashSet must not match")
	}
}

func TestHashSetBytes(t *testing.T) {
	hs := parseDigs(t, dig(1), dig(2))
	if got, want := hs.bytes(), int64(cap(hs.s))*32+24; got != want || got < 2*32+24 {
		t.Fatalf("bytes=%d want %d", got, want)
	}
}

func TestHashSetDedupeBeforeGrowth(t *testing.T) {
	// More rows than compactMin, only 3 distinct digests, unsorted: the in-flight
	// dedupe must keep every digest and not blow the backing array up.
	var buf bytes.Buffer
	for i := 0; i < 3*compactMin; i++ {
		buf.WriteString(hexRow(dig(byte(3 - i%3))))
	}
	hs, err := parseFeed(buf.Bytes())
	if err != nil || len(hs.s) != 3 {
		t.Fatalf("len=%d err=%v want 3", len(hs.s), err)
	}
	if cap(hs.s) > 2*compactMin {
		t.Fatalf("cap=%d: duplicates were not collapsed before growth", cap(hs.s))
	}
	for b := byte(1); b <= 3; b++ {
		if !hs.has(dig(b)) {
			t.Errorf("%d missing", b)
		}
	}
}

func TestHashSetMaxHashesCapsDistinct(t *testing.T) {
	orig := maxHashes
	maxHashes = 80
	defer func() { maxHashes = orig }()

	var buf bytes.Buffer
	for i := 0; i < 500; i++ { // 500 distinct rows -> capped
		buf.WriteString(hexRow(sha256Of(i)))
	}
	hs, err := parseFeed(buf.Bytes())
	if err != nil || len(hs.s) != maxHashes {
		t.Fatalf("distinct overflow: len=%d err=%v want %d", len(hs.s), err, maxHashes)
	}

	buf.Reset()
	for i := 0; i < 5000; i++ { // 70 distinct, many duplicates -> not truncated
		buf.WriteString(hexRow(sha256Of(i % 70)))
	}
	hs, err = parseFeed(buf.Bytes())
	if err != nil || len(hs.s) != 70 {
		t.Fatalf("duplicates: len=%d err=%v want 70", len(hs.s), err)
	}
}

func sha256Of(i int) [32]byte { return sha256.Sum256([]byte{byte(i), byte(i >> 8)}) }
