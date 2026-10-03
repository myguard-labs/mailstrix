package extract

import (
	"bytes"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"
)

// gateCases pairs each PERF-51 literal gate with the regex it skips.
var gateCases = []struct {
	name string
	re   *regexp.Regexp
	gate func([]byte) bool
}{
	{"chrconcat", reChrConcat, func(b []byte) bool {
		return bytes.ContainsAny(b, "&+") && (bytes.ContainsRune(b, '"') || containsASCIIFold(b, vbaChrNeedle))
	}},
	{"arrayxor", reArrayXor, func(b []byte) bool { return containsASCIIFold(b, vbaArrayNeedle) }},
	{"strreverse", reStrReverse, func(b []byte) bool { return containsASCIIFold(b, vbaStrReverseNeedle) }},
	{"environ", reEnviron, func(b []byte) bool { return containsASCIIFold(b, vbaEnvironNeedle) }},
	{"hxxp", reHxxp, func(b []byte) bool { return containsASCIIFold(b, defangHxxpNeedle) }},
	{"fxp", reFxp, func(b []byte) bool { return containsASCIIFold(b, defangFxpNeedle) }},
}

// gateAlphabet is built from the regex tokens so random inputs hit near-misses.
var gateAlphabet = []string{
	`"`, `""`, "&", "+", " ", "Chr", "CHRW$", "chrb", "(", ")", "65", "1,2", ",",
	"Array", "aRRay(", "Xor", " xor ", "7", "StrReverse", "strreverse(", "Environ",
	"environ$(", "hxxp", "HXXPS", "fxp", ":", "[", "]", "[.]", "x", "\n",
}

func randomGateInput(r *rand.Rand) []byte {
	var b strings.Builder
	for n := r.Intn(24); n >= 0; n-- {
		b.WriteString(gateAlphabet[r.Intn(len(gateAlphabet))])
	}
	return []byte(b.String())
}

// TestLiteralGatesNeverHideAMatch (PERF-51): whenever a gate is closed, its
// regex finds nothing, so skipping the regex cannot change the output.
func TestLiteralGatesNeverHideAMatch(t *testing.T) {
	r := rand.New(rand.NewSource(51))
	opened := map[string]int{}
	for i := 0; i < 200000; i++ {
		in := randomGateInput(r)
		for _, c := range gateCases {
			if c.gate(in) {
				opened[c.name]++
				continue
			}
			if c.re.Match(in) {
				t.Fatalf("%s: gate closed but regex matched %q", c.name, in)
			}
		}
	}
	for _, c := range gateCases { // the generator must exercise both sides
		if opened[c.name] == 0 {
			t.Errorf("%s: gate never opened", c.name)
		}
	}
}

func FuzzLiteralGates(f *testing.F) {
	for _, s := range []string{`"a" & Chr(66)`, "Array(1,2) Xor 7", `StrReverse("ab")`, `Environ$("TEMP")`, "hxxps[:]//x", "fxp://y", "plain"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		for _, c := range gateCases {
			if !c.gate(in) && c.re.Match(in) {
				t.Fatalf("%s: gate closed but regex matched %q", c.name, in)
			}
		}
	})
}

// TestFoldVBAStringsGatedStillFolds (positive): each gated fold still fires.
func TestFoldVBAStringsGatedStillFolds(t *testing.T) {
	src := []byte(`x = "pow" & Chr(101) & "rshell"` + "\n" +
		`y = Array(97,98,99,100) Xor 0` + "\n" +
		`z = StrReverse("dlrowolleh")` + "\n" +
		`w = Environ("APPDATA")`)
	var got []string
	foldVBAStrings(src, time.Time{}, func(b []byte) bool { got = append(got, string(b)); return true })
	all := strings.Join(got, "|")
	for _, want := range []string{"powershell", "abcd", "helloworld", "VBA-ENVIRON %APPDATA%"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in %q", want, all)
		}
	}
}

// TestUndefangGates: prose with 'h'/'f' but no defang is left alone without
// work; hxxp, fxp and bracket defangs still fold; an empty input is a no-op.
func TestUndefangGates(t *testing.T) {
	prose := []byte("the fish had a fine home here")
	if out, ok := undefang(prose); ok || &out[0] != &prose[0] {
		t.Fatalf("prose changed: %q", out)
	}
	for in, want := range map[string]string{
		"hxxps[:]//evil[.]com": "https://evil.com",
		"FXP://host":           "ftp://host",
		"a(.)b":                "a.b",
	} {
		if out, ok := undefang([]byte(in)); !ok || string(out) != want {
			t.Errorf("undefang(%q) = %q, %v; want %q", in, out, ok, want)
		}
	}
	if _, ok := undefang(nil); ok {
		t.Fatal("empty input changed")
	}
}
