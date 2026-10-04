package extract

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Preserve the original helper as the compatibility and allocation oracle.
func referenceTryBase32(run []byte) ([]byte, bool) {
	s := string(run)
	if dec, err := base32.StdEncoding.DecodeString(s); err == nil {
		return dec, true
	}
	s = strings.TrimRight(s, "=")
	if rem := len(s) % 8; rem != 0 {
		s += strings.Repeat("=", 8-rem)
	}
	if dec, err := base32.StdEncoding.DecodeString(s); err == nil {
		return dec, true
	}
	return nil, false
}

func TestTryBase32Reference(t *testing.T) {
	check := func(run []byte) {
		t.Helper()
		before := bytes.Clone(run)
		want, wantOK := referenceTryBase32(run)
		got, gotOK := tryBase32(run)
		if gotOK != wantOK || !bytes.Equal(got, want) || (got == nil) != (want == nil) {
			t.Fatalf("input %q: got %x/%t, want %x/%t", run, got, gotOK, want, wantOK)
		}
		if !bytes.Equal(run, before) {
			t.Fatal("decoder changed its input")
		}
	}
	for n := 0; n < 80; n++ {
		encoded := base32.StdEncoding.EncodeToString(bytes.Repeat([]byte{'z'}, n))
		raw := strings.TrimRight(encoded, "=")
		for padding := 0; padding <= 10; padding++ {
			run := raw + strings.Repeat("=", padding)
			check([]byte(run))
			for _, newline := range []string{"\n", "\r\n", strings.Repeat("\n", 8)} {
				check([]byte(newline + run))
				check([]byte(run + newline))
				check([]byte(run[:len(run)/2] + newline + run[len(run)/2:]))
			}
		}
	}
	for n := 0; n < 32; n++ {
		for _, suffix := range []string{"", "=", "==", "========", "!", "0", "1", "8", "a", "\x00", "\xff", "=A", "\n"} {
			check([]byte(strings.Repeat("Z", n) + suffix))
		}
	}
	rng := rand.New(rand.NewSource(60))
	alphabet := []byte("AZ27=01az!\r\n\x00\xff")
	for i := 0; i < 10000; i++ {
		run := make([]byte, rng.Intn(70))
		for j := range run {
			run[j] = alphabet[rng.Intn(len(alphabet))]
		}
		check(run)
	}
}

var base32AllocationSink []byte

func TestTryBase32Allocations(t *testing.T) {
	run := []byte(strings.TrimRight(base32.StdEncoding.EncodeToString(bytes.Repeat([]byte{'z'}, 4097)), "="))
	measure := func(decode func([]byte) ([]byte, bool)) float64 {
		return testing.AllocsPerRun(100, func() {
			var ok bool
			base32AllocationSink, ok = decode(run)
			if !ok || len(base32AllocationSink) != 4097 {
				panic("allocation fixture did not decode")
			}
		})
	}
	original, current := measure(referenceTryBase32), measure(tryBase32)
	t.Logf("raw allocations: original %.0f, current %.0f", original, current)
	if current >= original {
		t.Fatalf("raw decoding allocations did not decrease: current %.0f >= original %.0f", current, original)
	}
}

func BenchmarkTryBase32(b *testing.B) {
	for _, n := range []int{4095, 4097} {
		payload := bytes.Repeat([]byte{'z'}, n)
		padded := base32.StdEncoding.EncodeToString(payload)
		for _, mode := range []struct{ name, run string }{{"padded", padded}, {"raw", strings.TrimRight(padded, "=")}} {
			run := []byte(mode.run)
			for _, impl := range []struct {
				name   string
				decode func([]byte) ([]byte, bool)
			}{{"original", referenceTryBase32}, {"direct", tryBase32}} {
				b.Run(fmt.Sprintf("%d/%s/%s", n, mode.name, impl.name), func(b *testing.B) {
					decoded, ok := impl.decode(run)
					if !ok || !bytes.Equal(decoded, payload) {
						b.Fatal("benchmark fixture did not decode to the original payload")
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(run)))
					for b.Loop() {
						base32AllocationSink, _ = impl.decode(run)
					}
				})
			}
		}
	}
}
