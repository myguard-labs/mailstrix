package ci_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/zeebo/xxh3"

	"github.com/myguard-labs/mailstrix/internal/extract"
	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
)

// wantDedupKey is the pinned key layout: xxh3 Hash128 Lo||Hi, little-endian.
func wantDedupKey(b []byte) [16]byte {
	h := xxh3.Hash128(b)
	var k [16]byte
	binary.LittleEndian.PutUint64(k[0:8], h.Lo)
	binary.LittleEndian.PutUint64(k[8:16], h.Hi)
	return k
}

func TestStreamDedupKeyPinnedXXH3(t *testing.T) {
	big := bytes.Repeat([]byte("mailstrix-dedup-"), (1<<20)/16+1024) // > 1 MiB
	if len(big) <= 1<<20 {
		t.Fatalf("test buffer too small: %d", len(big))
	}
	inputs := map[string][]byte{
		"short": []byte("hello macro world"),
		"nul":   {0x00},
		"mid":   bytes.Repeat([]byte{0xAB}, 300),
		"big":   big,
	}
	for name, in := range inputs {
		if got, want := ms.StreamDedupKey(in), wantDedupKey(in); got != want {
			t.Errorf("%s: key %x, want %x", name, got, want)
		}
	}
}

func TestStreamDedupKeyBoundary(t *testing.T) {
	if ms.StreamDedupKey(nil) != ms.StreamDedupKey([]byte{}) {
		t.Fatal("nil and empty must hash identically")
	}
	if ms.StreamDedupKey(nil) != wantDedupKey(nil) {
		t.Fatal("empty key must match xxh3 of empty input")
	}
	one := []byte{0x7f}
	if ms.StreamDedupKey(one) != wantDedupKey(one) {
		t.Fatal("1-byte key mismatch")
	}
}

func TestStreamDedupKeyNegative(t *testing.T) {
	a := bytes.Repeat([]byte{'a'}, 4096)
	b := bytes.Clone(a)
	b[2048] ^= 0x01
	if ms.StreamDedupKey(a) == ms.StreamDedupKey(b) {
		t.Fatal("one-byte difference must change the key")
	}
}

func TestExtractVersionXXH3KeyToken(t *testing.T) {
	if !strings.HasSuffix(extract.Version, "+xxh3key") {
		t.Fatalf("extract.Version must end with +xxh3key to invalidate old-domain cache entries; got suffix %q",
			extract.Version[len(extract.Version)-20:])
	}
}

// dedupKeySink keeps the benchmarked call from being optimized away.
var dedupKeySink [16]byte

func BenchmarkStreamDedupKey(b *testing.B) {
	for _, c := range []struct {
		name string
		n    int
	}{{"64KiB", 64 << 10}, {"1MiB", 1 << 20}} {
		buf := bytes.Repeat([]byte{0x5a, 0xc3, 0x11, 0x99}, c.n/4)
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(c.n))
			for i := 0; i < b.N; i++ {
				dedupKeySink = ms.StreamDedupKey(buf)
			}
		})
	}
}
