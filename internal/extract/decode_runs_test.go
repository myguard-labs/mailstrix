package extract

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Retained pre-scalar implementation: the regex engine is the independent
// oracle for match boundaries, padding, suppression and candidate truncation.
func referenceDecodeBase64Runs(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reBase64.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		// An all-hex run is handled by the hex pass; decoding it as base64 too
		// would emit a bogus blob and burn the blob cap, so skip it here.
		if !allHex(run) {
			if dec, ok := tryBase64(run); ok {
				if !emit(dec) {
					return false
				}
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

func referenceDecodeHexRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reHex.FindIndex(rest)
		if loc == nil {
			return true
		}
		// The match is an even number of hex digits by construction; cap the
		// candidate to an even prefix so a giant run can't allocate past the cap.
		run := rest[loc[0]:loc[1]]
		if len(run) > maxHexEncoded {
			run = run[:maxHexEncoded]
		}
		dec := make([]byte, hex.DecodedLen(len(run)))
		if n, err := hex.Decode(dec, run); err == nil {
			if !emit(dec[:n]) {
				return false
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

func TestDecodeRunsReferenceEquivalence(t *testing.T) {
	corpus := [][]byte{nil, []byte("plain words"), bytes.Repeat([]byte("!"), 8193)}
	for _, n := range []int{0, 1, 23, 24, 25, 26, 27, 31, 32, 33, 63, 64, 65} {
		for _, alphabet := range []string{"a", "G", "/", "+", "f0", "aZ09+/"} {
			run := strings.Repeat(alphabet, n)
			for _, pad := range []string{"", "=", "==", "===", "=G", "\x00", "\xff"} {
				corpus = append(corpus, []byte("!"+run+pad+"!"+run))
			}
		}
	}
	for delimiter := 0; delimiter < 256; delimiter++ {
		corpus = append(corpus, append(append([]byte(strings.Repeat("aG", 16)), byte(delimiter)), []byte(strings.Repeat("f0", 17))...))
	}
	// Long runs must emit once, not once per candidate cap. Classify the
	// entire base64 run, even when its first non-hex byte lies beyond the cap.
	for _, n := range []int{maxB64Encoded - 1, maxB64Encoded, maxB64Encoded + 1, maxHexEncoded + 1} {
		corpus = append(corpus, []byte(strings.Repeat("a", n)+"G!"+strings.Repeat("aG", 16)), []byte(strings.Repeat("a", n)+"=="))
	}
	for i, src := range corpus {
		for _, hexMode := range []bool{false, true} {
			re := reBase64
			if hexMode {
				re = reHex
			}
			for rest := src; len(rest) > 0; {
				want := re.FindIndex(rest)
				start, end, hexOnly := nextDecodeRun(rest, hexMode, time.Time{})
				if want == nil {
					if start >= 0 {
						t.Fatalf("corpus %d: unexpected scalar match", i)
					}
					break
				}
				if start != want[0] || end != want[1] || hexOnly != allHex(rest[want[0]:want[1]]) {
					t.Fatalf("corpus %d hex=%v: match [%d,%d] != %v or classification differs", i, hexMode, start, end, want)
				}
				rest = rest[end:]
			}
		}
	}
	for _, mode := range []struct {
		name               string
		current, reference func([]byte, time.Time, func([]byte) bool) bool
	}{
		{"base64", decodeBase64Runs, referenceDecodeBase64Runs}, {"hex", decodeHexRuns, referenceDecodeHexRuns},
	} {
		t.Run(mode.name, func(t *testing.T) {
			for i, src := range corpus {
				for _, limit := range []int{1, 2, 100} {
					collect := func(fn func([]byte, time.Time, func([]byte) bool) bool) ([][]byte, bool) {
						var output [][]byte
						ok := fn(src, time.Time{}, func(b []byte) bool { output = append(output, b); return len(output) < limit })
						return output, ok
					}
					got, ok := collect(mode.current)
					want, wok := collect(mode.reference)
					if ok != wok || !reflect.DeepEqual(got, want) {
						t.Fatalf("corpus %d len=%d limit=%d: result=%v/%v streams=%d/%d differ", i, len(src), limit, ok, wok, len(got), len(want))
					}
				}
			}
		})
	}
}

func TestDecodeRunsDeadline(t *testing.T) {
	for _, hexMode := range []bool{false, true} {
		for _, src := range [][]byte{bytes.Repeat([]byte("!"), 8193), bytes.Repeat([]byte("a"), 8193)} {
			start, end, hexOnly := nextDecodeRun(src, hexMode, time.Now().Add(-time.Second))
			if start != -1 || end != 0 || hexOnly {
				t.Fatal("expired scalar search returned a match")
			}
		}
	}
	for _, fn := range []func([]byte, time.Time, func([]byte) bool) bool{decodeBase64Runs, decodeHexRuns} {
		called := false
		if !fn([]byte(strings.Repeat("aG", 32)+"!"+strings.Repeat("ab", 32)), time.Now().Add(-time.Second), func([]byte) bool { called = true; return true }) || called {
			t.Fatal("expired decoder emitted or reported a global cap")
		}
	}
}

func BenchmarkDecodeRunsScalar(b *testing.B) {
	for _, mode := range []struct {
		name               string
		current, reference func([]byte, time.Time, func([]byte) bool) bool
	}{
		{"base64", decodeBase64Runs, referenceDecodeBase64Runs}, {"hex", decodeHexRuns, referenceDecodeHexRuns},
	} {
		for _, fixture := range []struct{ name, data string }{
			{"no-match", strings.Repeat("ordinary words! ", 16384)},
			{"long-run", strings.Repeat("aG", 131072)},
			{"hex-run", strings.Repeat("ab", 131072)},
		} {
			src := []byte(fixture.data)
			for _, scalar := range []bool{false, true} {
				b.Run(fmt.Sprintf("%s/%s/scalar=%t", mode.name, fixture.name, scalar), func(b *testing.B) {
					fn := mode.reference
					if scalar {
						fn = mode.current
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(src)))
					for b.Loop() {
						fn(src, time.Time{}, func([]byte) bool { return true })
					}
				})
			}
		}
	}
}
