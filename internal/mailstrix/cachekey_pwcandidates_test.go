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
	t.Run("embedded NUL does not alias a split list (AUD-M2b)", func(t *testing.T) {
		pairs := [][2]ScanMeta{
			{pwMeta("a", "b"), pwMeta("a\x00b")},
			{pwMeta("a", ""), pwMeta("a\x00")},
			{pwMeta("", ""), pwMeta("\x00")},
			{pwMeta("a\x00", "b"), pwMeta("a", "\x00b")},
			{pwMeta("\x00"), pwMeta("", "")},
		}
		for i, p := range pairs {
			if p[0].cacheKey() == p[1].cacheKey() {
				t.Fatalf("pair %d collides: %q", i, p[0].cacheKey())
			}
		}
	})
	t.Run("positive distinct lists differ identical lists match", func(t *testing.T) {
		lists := [][]string{{"a"}, {"b"}, {"a", "b"}, {"b", "a"}, {"ab"}, {""}, {"", ""}, {"a\x00b"}}
		seen := map[string]int{}
		for i, l := range lists {
			k := pwMeta(l...).cacheKey()
			if j, dup := seen[k]; dup {
				t.Fatalf("lists %d and %d share key %q", j, i, k)
			}
			seen[k] = i
			if k != pwMeta(append([]string(nil), l...)...).cacheKey() {
				t.Fatalf("list %d unstable", i)
			}
		}
	})
	t.Run("boundary empty candidate versus none versus two", func(t *testing.T) {
		const hist = "f.zip\x00.zip\x00zip\x002"
		var nilList []string
		if got := pwMeta(nilList...).cacheKey(); got != hist {
			t.Fatalf("nil key changed: %q", got)
		}
		if got := pwMeta([]string{}...).cacheKey(); got != hist {
			t.Fatalf("empty key changed: %q", got)
		}
		one, two := pwMeta("").cacheKey(), pwMeta("", "").cacheKey()
		if one == hist || two == hist || one == two {
			t.Fatalf("empty-candidate keys not distinct: %q %q %q", hist, one, two)
		}
	})
	t.Run("malformed very long candidate and NUL-only candidates", func(t *testing.T) {
		long := strings.Repeat("\x00", 1<<20)
		a, b := pwMeta(long).cacheKey(), pwMeta(long+"\x00").cacheKey()
		if a == b {
			t.Fatal("long NUL candidates of different length collide")
		}
		if a != pwMeta(long).cacheKey() {
			t.Fatal("long candidate unstable")
		}
		if pwMeta(long[:10], long[:10]).cacheKey() == pwMeta(long[:20]).cacheKey() {
			t.Fatal("split NUL runs collide")
		}
	})
	t.Run("negative order remains significant with NUL candidates", func(t *testing.T) {
		if pwMeta("a\x00", "b").cacheKey() == pwMeta("b", "a\x00").cacheKey() {
			t.Fatal("order ignored")
		}
	})
}
