package mailstrix

import (
	"strings"
	"testing"
)

func pwMeta(c ...string) ScanMeta {
	return ScanMeta{Filename: "f.zip", Extension: ".zip", FileType: "zip", Effort: 2, PWCandidates: c}
}

func TestCacheKeyPWCandidates(t *testing.T) {
	const hist = "f.zip\x00.zip\x00zip\x002"

	t.Run("no candidates is exactly the historical key", func(t *testing.T) {
		for name, m := range map[string]ScanMeta{"nil": pwMeta(), "empty": pwMeta([]string{}...)} {
			if got := m.cacheKey(); got != hist {
				t.Fatalf("%s: got %q, want %q", name, got, hist)
			}
			if strings.Contains(m.cacheKey(), "\x00pw:") {
				t.Fatalf("%s: unexpected pw suffix", name)
			}
		}
	})
	t.Run("candidates add the pw suffix on top of the historical key", func(t *testing.T) {
		got := pwMeta("a").cacheKey()
		if !strings.HasPrefix(got, hist+"\x00pw:") {
			t.Fatalf("got %q", got)
		}
		if got == hist {
			t.Fatal("candidates did not change the key")
		}
	})
	t.Run("same candidates same order is stable", func(t *testing.T) {
		a, b := pwMeta("x", "y", "z").cacheKey(), pwMeta("x", "y", "z").cacheKey()
		if a != b {
			t.Fatalf("unstable: %q vs %q", a, b)
		}
	})
	t.Run("same set different order differs", func(t *testing.T) {
		if pwMeta("x", "y", "z").cacheKey() == pwMeta("z", "y", "x").cacheKey() {
			t.Fatal("order is verdict-significant but keys are equal")
		}
		if pwMeta("pw", "f1", "f2").cacheKey() == pwMeta("f1", "f2", "pw").cacheKey() {
			t.Fatal("prefix-significant order shares a key")
		}
	})
	t.Run("different candidates differ", func(t *testing.T) {
		pairs := [][2]ScanMeta{
			{pwMeta("a"), pwMeta("b")},
			{pwMeta("a"), pwMeta("a", "b")},
			{pwMeta("a", "b"), pwMeta("a", "c")},
			{pwMeta("a"), pwMeta()},
		}
		for i, p := range pairs {
			if p[0].cacheKey() == p[1].cacheKey() {
				t.Fatalf("pair %d collides: %q", i, p[0].cacheKey())
			}
		}
	})
	t.Run("candidate boundaries guaranteed by the NUL terminator", func(t *testing.T) {
		pairs := [][2]ScanMeta{
			{pwMeta("a", "b"), pwMeta("ab")},
			{pwMeta("ab", ""), pwMeta("ab")},
			{pwMeta("", "ab"), pwMeta("ab")},
			{pwMeta(""), pwMeta()},
			{pwMeta("a", "", "b"), pwMeta("a", "b")},
		}
		for i, p := range pairs {
			if p[0].cacheKey() == p[1].cacheKey() {
				t.Fatalf("pair %d collides: %q", i, p[0].cacheKey())
			}
		}
	})
	t.Run("candidates do not mask other metadata", func(t *testing.T) {
		a, b := pwMeta("a"), pwMeta("a")
		b.Effort = 3
		if a.cacheKey() == b.cacheKey() {
			t.Fatal("effort ignored with candidates present")
		}
		b = pwMeta("a")
		b.Filename = "g.zip"
		if a.cacheKey() == b.cacheKey() {
			t.Fatal("filename ignored with candidates present")
		}
	})
	t.Run("key stays bounded regardless of candidate count and length", func(t *testing.T) {
		big := make([]string, 500)
		for i := range big {
			big[i] = strings.Repeat("p", 1000)
		}
		short, long := pwMeta("a").cacheKey(), pwMeta(big...).cacheKey()
		if len(long) > len(short)+16 { // 64-bit hash renders <=16 hex chars
			t.Fatalf("key grew with input: %d vs %d", len(long), len(short))
		}
	})
	t.Run("embedded NUL collision is not asserted", func(t *testing.T) {
		// The hash stream is c1,NUL,c2,NUL: a candidate containing NUL can alias a
		// split list. Not guaranteed either way by the implementation; the server
		// header parse strips control bytes so it is unreachable from the wire.
		if pwMeta("a", "b").cacheKey() == pwMeta("a\x00b").cacheKey() {
			t.Logf("observed: [a b] and [a\\x00b] share a cache key (internal callers only)")
		}
	})
}
