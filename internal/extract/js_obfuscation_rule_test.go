package extract

import (
	"bytes"
	"os"
	"testing"
)

// js_obfuscation.yara ships two heuristics that close live-corpus .js misses:
// JS_Obfusc_StringConcat_Accumulate (salmon-style self-concat builder) and
// JS_Dropper_CharCodeArray_ActiveX (additive-cipher WSH dropper). yarad's unit
// suite does not link libyara, so — like TestYARARule_FileExists in
// xlm_emul_d8_test.go — this asserts the rule SOURCE is present and well-formed.
// The actual compile + match is exercised by the Docker `full` CI stage
// (compile-rules.sh runs yarac over every local rule).
//
// The guards below catch the two ways this file has already gone wrong in
// authoring: a YARA backreference (\1, which yarac rejects — and which
// compile-rules.sh would then SILENTLY SKIP, shipping no rule at all), and a
// missing `wide` modifier (the 74c761 sample is UTF-16LE, so ASCII-only strings
// never match it).

func loadJSObfuscationRule(t *testing.T) []byte {
	t.Helper()
	paths := []string{
		"../../../../docker/local-rules/js_obfuscation.yara",
		"../../../docker/local-rules/js_obfuscation.yara",
		"../../docker/local-rules/js_obfuscation.yara",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("js_obfuscation.yara not found relative to test dir")
	return nil
}

func TestJSObfuscationRule_Present(t *testing.T) {
	data := loadJSObfuscationRule(t)
	for _, want := range []string{
		"rule JS_Obfusc_StringConcat_Accumulate",
		"rule JS_Dropper_CharCodeArray_ActiveX",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("js_obfuscation.yara missing %q", want)
		}
	}
}

func TestJSObfuscationRule_Anchors(t *testing.T) {
	data := loadJSObfuscationRule(t)
	// the specific mechanics each rule keys on — if these strings change the
	// rules no longer match the corpus samples they were written against.
	for _, anchor := range []string{
		"String.fromCharCode", // additive-decode mechanic (rule B)
		"ActiveXObject",       // WSH primitive (rule B)
		"this.",               // self-concat shape (rule A)
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("js_obfuscation.yara missing anchor %q", anchor)
		}
	}
}

func TestJSObfuscationRule_NoBackreference(t *testing.T) {
	// YARA's regex engine rejects backreferences; a rule using one fails to
	// compile and compile-rules.sh silently drops it. Catch it here at unit
	// speed instead of discovering a missing rule on the live host.
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(loadJSObfuscationRule(t), bad) {
			t.Errorf("js_obfuscation.yara contains backreference %q — yarac will reject it", bad)
		}
	}
}

func TestJSObfuscationRule_WideForUTF16(t *testing.T) {
	// The 74c761 live dropper is UTF-16LE; rule B must scan `wide` or it never
	// matches. Assert the dropper rule's region carries a `wide` modifier.
	data := loadJSObfuscationRule(t)
	idx := bytes.Index(data, []byte("rule JS_Dropper_CharCodeArray_ActiveX"))
	if idx < 0 {
		t.Skip("dropper rule not present (covered by TestJSObfuscationRule_Present)")
	}
	if !bytes.Contains(data[idx:], []byte("wide")) {
		t.Error("JS_Dropper_CharCodeArray_ActiveX must use `wide` (UTF-16LE samples) — none found")
	}
}
