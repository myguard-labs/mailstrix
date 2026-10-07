package mailstrix

import (
	"testing"
)

// TestStreamDedupKey verifies the basic contract of the streamDedupKey helper:
//   - same input → same key (deterministic)
//   - different inputs → different keys (no trivial collisions)
//   - empty input does not panic
//
// This test does not exercise any YARA / cgo code; it compiles as part of the
// package only because streamDedupKey lives in package mailstrix. Remote CI
// (docker build with libyara) is required to run it locally.
func TestStreamDedupKey(t *testing.T) {
	// empty and nil must hash to the same key (both are zero-length content) and
	// must not panic.
	t.Run("empty and nil hash identically", func(t *testing.T) {
		if streamDedupKey([]byte{}) != streamDedupKey(nil) {
			t.Fatal("empty and nil inputs must produce the same key")
		}
	})

	t.Run("same input returns same key", func(t *testing.T) {
		data := []byte("hello macro world")
		k1 := streamDedupKey(data)
		k2 := streamDedupKey(data)
		if k1 != k2 {
			t.Fatalf("expected identical keys for identical input, got %x vs %x", k1, k2)
		}
	})

	t.Run("different inputs return different keys", func(t *testing.T) {
		pairs := [][2][]byte{
			{[]byte("aaa"), []byte("bbb")},
			{[]byte("stream-1"), []byte("stream-2")},
			{[]byte{0x00}, []byte{0x01}},
			{[]byte(""), []byte("x")},
		}
		for _, p := range pairs {
			k1 := streamDedupKey(p[0])
			k2 := streamDedupKey(p[1])
			if k1 == k2 {
				t.Errorf("unexpected collision: streamDedupKey(%q) == streamDedupKey(%q) == %x", p[0], p[1], k1)
			}
		}
	})

	// the high and low 64-bit halves must differ for typical input (xxh3
	// Hash128 Lo and Hi are distinct words, not a doubled 64-bit hash).
	t.Run("halves are independent", func(t *testing.T) {
		k := streamDedupKey([]byte("test"))
		var lo, hi [8]byte
		copy(lo[:], k[0:8])
		copy(hi[:], k[8:16])
		if lo == hi {
			t.Fatalf("low and high halves identical (%x) — domain separation broken", k)
		}
	})
}
