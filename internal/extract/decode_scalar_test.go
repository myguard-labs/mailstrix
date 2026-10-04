package extract

// Retained pre-scalar decoders are independent oracles for match and output parity.

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// NETBIOS matching now needs a regex only as the retained test oracle.
var reNetbios = regexp.MustCompile(fmt.Sprintf(`[A-P]{%d,}`, minNetbiosRun))

func referenceDecodeDecSeqRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reDecSeq.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		if len(run) > maxDecSeqEncoded {
			run = run[:maxDecSeqEncoded]
			// Trim back to the last separator so the clamp never cuts a token in
			// half (e.g. "256" → "25", which Atoi would silently accept as a wrong
			// byte). Drop the trailing partial token entirely.
			if i := bytes.LastIndexAny(run, ",;"); i >= 0 {
				run = run[:i]
			}
		}
		// Determine the separator from the first separator character.
		sep := byte(',')
		for _, c := range run {
			if c == ',' || c == ';' {
				sep = c
				break
			}
		}
		// Split on the separator and validate all tokens.
		parts := bytes.Split(run, []byte{sep})
		dec := make([]byte, 0, len(parts))
		valid := true
		for _, p := range parts {
			p = bytes.TrimSpace(p)
			if len(p) == 0 {
				valid = false
				break
			}
			// Reject if any byte is the OTHER separator (mixed separators).
			otherSep := byte(';')
			if sep == ';' {
				otherSep = ','
			}
			if bytes.IndexByte(p, otherSep) >= 0 {
				valid = false
				break
			}
			n, err := strconv.Atoi(string(p))
			if err != nil || n < 0 || n > 255 {
				valid = false
				break
			}
			dec = append(dec, byte(n)) // #nosec G115 -- n bounded 0..255 above
		}
		if valid && len(dec) >= minDecSeqRun {
			if !emit(dec) {
				return false
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

func referenceDecodeNetbiosRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reNetbios.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		// Cap to maxNetbiosEncoded; further clamp to even length.
		if len(run) > maxNetbiosEncoded {
			run = run[:maxNetbiosEncoded]
		}
		if len(run)%2 != 0 {
			run = run[:len(run)-1]
		}
		dec := make([]byte, len(run)/2)
		for i := 0; i < len(run); i += 2 {
			hi := run[i] - 'A'
			lo := run[i+1] - 'A'
			// Both nibbles must be in range [0,15] (chars A-P map to 0-15).
			// The regex [A-P] already guarantees this, but clamp defensively.
			if hi > 15 || lo > 15 {
				dec = nil
				break
			}
			dec[i/2] = (hi << 4) | lo
		}
		if dec == nil {
			rest = rest[loc[1]:]
			continue
		}
		// Gate: only emit if decoded result is mostly printable text OR carries
		// a known container magic (PK zip, OLE, MZ exe, PDF). This prevents emitting
		// garbage from random uppercase text like variable names or acronyms.
		if mostlyText(dec) || hasContainerMagic(dec) {
			if !emit(dec) {
				return false
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

func referenceDecodeBase32Runs(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reBase32.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		if len(run) > maxBase32Encoded {
			// Trim to multiple of 8 (base32 groups).
			n := maxBase32Encoded - (maxBase32Encoded % 8)
			run = run[:n]
		}
		// Require at least one base32-distinctive digit (2-7). Pure [A-Z] runs are
		// ambiguous (could be base64, NETBIOS, or plain text); runs with 2-7 are
		// distinctively base32.
		hasDistinctive := false
		for _, c := range run {
			if c >= '2' && c <= '7' {
				hasDistinctive = true
				break
			}
		}
		if !hasDistinctive {
			rest = rest[loc[1]:]
			continue
		}
		dec, ok := tryBase32(run)
		if ok {
			if !emit(dec) {
				return false
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

func TestDecodeScalarReferenceEquivalence(t *testing.T) {
	corpus := [][]byte{nil, []byte("ordinary words"), bytes.Repeat([]byte("!"), 8193)}
	for _, n := range []int{0, 1, 11, 12, 13, 23, 31, 32, 33, 63, 64, 65} {
		for _, alphabet := range []string{"A", "GH", "Z2", "2", "123,", "1;", "256,", "001,", "1234,", "12345;", "1,2;", ",;"} {
			for _, pad := range []string{"", "=", "======", "=======", ",", ";", "12345", "\xff"} {
				corpus = append(corpus, []byte("!"+strings.Repeat(alphabet, n)+pad+"!"+strings.Repeat(alphabet, n)))
			}
		}
	}
	for c := 0; c < 256; c++ {
		for _, run := range []string{strings.Repeat("GH", 20), strings.Repeat("Z2", 20), strings.Repeat("123,", 13) + "1"} {
			corpus = append(corpus, []byte(run+string([]byte{byte(c)})+run))
		}
	}
	for _, n := range []int{maxNetbiosEncoded - 1, maxNetbiosEncoded + 1, maxBase32Encoded - 1, maxBase32Encoded, maxBase32Encoded + 1} {
		corpus = append(corpus, []byte(strings.Repeat("H", n)+"2!"+strings.Repeat("Z2", 20)))
	}
	for _, token := range []string{"1,", "255,", "256,", "1;2,"} {
		corpus = append(corpus, []byte(strings.Repeat(token, maxDecSeqEncoded/len(token)+2)+"12!"+strings.Repeat("97,", 13)+"97"))
	}
	for _, mode := range []struct {
		name               string
		re                 *regexp.Regexp
		scan               func([]byte) (int, int)
		current, reference func([]byte, time.Time, func([]byte) bool) bool
	}{
		{"netbios", reNetbios, func(b []byte) (int, int) {
			// Only match bounds are under test; the third result is digit metadata.
			s, e, _ := nextScalarRunUntil(b, false, func() bool { return false })
			return s, e
		}, decodeNetbiosRuns, referenceDecodeNetbiosRuns},
		{"base32", reBase32, func(b []byte) (int, int) {
			// Only match bounds are under test; the third result is digit metadata.
			s, e, _ := nextScalarRunUntil(b, true, func() bool { return false })
			return s, e
		}, decodeBase32Runs, referenceDecodeBase32Runs},
		{"decimal", reDecSeq, func(b []byte) (int, int) { return nextDecSeqRunUntil(b, func() bool { return false }) }, decodeDecSeqRuns, referenceDecodeDecSeqRuns},
	} {
		t.Run(mode.name, func(t *testing.T) {
			for i, src := range corpus {
				for rest := src; len(rest) > 0; {
					want := mode.re.FindIndex(rest)
					start, end := mode.scan(rest)
					if want == nil {
						if start >= 0 {
							t.Fatalf("corpus %d: unexpected match [%d,%d]", i, start, end)
						}
						break
					}
					if start != want[0] || end != want[1] {
						t.Fatalf("corpus %d: match [%d,%d] != %v", i, start, end, want)
					}
					rest = rest[end:]
				}
				for _, limit := range []int{1, 2, 100} {
					collect := func(fn func([]byte, time.Time, func([]byte) bool) bool) ([][]byte, bool) {
						var out [][]byte
						ok := fn(src, time.Time{}, func(b []byte) bool { out = append(out, b); return len(out) < limit })
						return out, ok
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

func TestDecodeScalarInFlightExpiry(t *testing.T) {
	for _, mode := range []struct {
		name string
		scan func([]byte, func() bool) (int, int)
		run  string
	}{
		{"netbios", func(b []byte, f func() bool) (int, int) { // Only match bounds are under test; the third result is digit metadata.
			s, e, _ := nextScalarRunUntil(b, false, f)
			return s, e
		}, strings.Repeat("H", 8193)},
		{"base32", func(b []byte, f func() bool) (int, int) { // Only match bounds are under test; the third result is digit metadata.
			s, e, _ := nextScalarRunUntil(b, true, f)
			return s, e
		}, strings.Repeat("Z2", 4097)},
		{"decimal", nextDecSeqRunUntil, strings.Repeat("12,", 2731) + "1"},
	} {
		for _, fixture := range []struct {
			name, src string
			start     int
		}{
			{"run", mode.run, 0}, {"late", strings.Repeat("!", 8192) + mode.run, 8192}, {"none", strings.Repeat("!", 8193), -1}, {"boundary", mode.run[:4096], 0},
		} {
			t.Run(mode.name+"/"+fixture.name, func(t *testing.T) {
				checks := 0
				start, end := mode.scan([]byte(fixture.src), func() bool { checks++; return checks == 2 })
				if checks != 2 || start != -1 || end != 0 {
					t.Fatalf("in-flight expiry: checkpoints=%d match=[%d,%d]; want two checkpoints and no match", checks, start, end)
				}
				checks = 0
				start, _ = mode.scan([]byte(fixture.src), func() bool { checks++; return false })
				if start != fixture.start || checks != len(fixture.src)/4096+1 {
					t.Fatalf("live scan: start=%d checks=%d", start, checks)
				}
			})
		}
	}
	for _, fn := range []func([]byte, time.Time, func([]byte) bool) bool{decodeNetbiosRuns, decodeBase32Runs, decodeDecSeqRuns} {
		called := false
		if !fn([]byte(strings.Repeat("H", 64)+"!"+strings.Repeat("Z2", 32)+"!"+strings.Repeat("97,", 20)+"97"), time.Now().Add(-time.Second), func([]byte) bool { called = true; return true }) || called {
			t.Fatal("expired decoder emitted or reported a global cap")
		}
	}
}

func TestDecodeScalarPaddingCheckpoint(t *testing.T) {
	checks := 0
	src := []byte(strings.Repeat("Z2", 2047) + "Z======")
	start, end, _ := nextScalarRunUntil(src, true, func() bool { checks++; return checks == 2 })
	if checks != 2 || start != -1 || end != 0 {
		t.Fatalf("padding expiry: checkpoints=%d match=[%d,%d]; want two checkpoints and no match", checks, start, end)
	}
}

// Keep the search live and expire only once conversion has been reached. The
// second case permits 4096 conversion bytes before cancellation; neither case
// may publish the partially converted candidate.
func TestDecodeScalarConversionExpiry(t *testing.T) {
	for _, mode := range []struct {
		name      string
		src, want []byte
		decode    func([]byte, func() bool, func([]byte) bool) bool
	}{
		{"decimal", []byte(strings.Repeat("97,", 2731) + "97"), bytes.Repeat([]byte("a"), 2732), decodeDecSeqRunsUntil},
		{"netbios", []byte(strings.Repeat("HH", 4097)), bytes.Repeat([]byte("w"), 4097), decodeNetbiosRunsUntil},
	} {
		t.Run(mode.name, func(t *testing.T) {
			// One outer precheck, then the scanner checks at 0, 4096 and 8192.
			beforeConversion := 1 + len(mode.src)/4096 + 1
			for _, conversionCheck := range []int{1, 2} {
				t.Run(fmt.Sprintf("checkpoint-%d", conversionCheck), func(t *testing.T) {
					calls, emitted := 0, false
					expireAt := beforeConversion + conversionCheck
					ok := mode.decode(mode.src, func() bool { calls++; return calls >= expireAt }, func([]byte) bool { emitted = true; return true })
					if !ok || emitted || calls != expireAt {
						t.Fatalf("conversion expiry: checks=%d want=%d emitted=%v completed=%v; want cancellation without partial emission", calls, expireAt, emitted, ok)
					}
				})
			}
			calls := 0
			var output [][]byte
			ok := mode.decode(mode.src, func() bool { calls++; return false }, func(b []byte) bool { output = append(output, b); return true })
			if !ok || len(output) != 1 || !bytes.Equal(output[0], mode.want) {
				t.Fatalf("live conversion: completed=%v streams=%d; want complete decoded candidate", ok, len(output))
			}
			if calls != beforeConversion+len(mode.src)/4096+1 {
				t.Fatalf("live conversion: checks=%d; want search and conversion checkpoints", calls)
			}
		})
	}
}
