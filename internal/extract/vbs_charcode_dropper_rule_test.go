package extract

import (
	"bytes"
	"os"
	"testing"
)

// vbs_charcode_dropper.yara ships VBS_CharCode_Split_Dropper, closing a live
// .vbs corpus miss (4c6c3fb4: Split -> ChrW(IsNumeric) -> Execute char-code
// dropper hidden under ~2000 decoy assignments). yarad's unit suite does not
// link libyara, so — like the js_obfuscation rule test — this asserts the rule
// SOURCE is present and well-formed; the real compile+match runs in the Docker
// `full` CI stage (compile-rules.sh runs yarac over every local rule, then the
// runtime scanners job scans fixtures).
//
// Guards the two ways a hand-authored YARA rule silently breaks: a backreference
// (\1, which yarac rejects and compile-rules.sh then SILENTLY SKIPS — shipping
// no rule), and a missing `wide` modifier (these droppers ship UTF-16LE as often
// as ASCII, so ASCII-only strings would never match them).

func loadVBSCharCodeRule(t *testing.T) []byte {
	t.Helper()
	paths := []string{
		"../../../../docker/local-rules/vbs_charcode_dropper.yara",
		"../../../docker/local-rules/vbs_charcode_dropper.yara",
		"../../docker/local-rules/vbs_charcode_dropper.yara",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("vbs_charcode_dropper.yara not found relative to test dir")
	return nil
}

func TestVBSCharCodeRule_Present(t *testing.T) {
	data := loadVBSCharCodeRule(t)
	if !bytes.Contains(data, []byte("rule VBS_CharCode_Split_Dropper")) {
		t.Errorf("vbs_charcode_dropper.yara missing rule VBS_CharCode_Split_Dropper")
	}
}

func TestVBSCharCodeRule_Anchors(t *testing.T) {
	data := loadVBSCharCodeRule(t)
	// the decode-loop primitives the rule keys on — if any string changes the
	// rule no longer matches the corpus sample it was written against.
	for _, anchor := range []string{
		"Split(",    // tokenize the delimited payload
		"ChrW(",     // per-token char-code decode
		"IsNumeric", // numeric gate
		"Execute",   // run the rebuilt payload
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("vbs_charcode_dropper.yara missing anchor %q", anchor)
		}
	}
}

func TestVBSCharCodeRule_HasWideModifier(t *testing.T) {
	// UTF-16LE droppers must match — every string in the rule must carry `wide`.
	// Cheap proxy: the file declares `ascii wide` and never an ascii-only string.
	data := loadVBSCharCodeRule(t)
	if !bytes.Contains(data, []byte("ascii wide")) {
		t.Errorf("vbs_charcode_dropper.yara: strings must be `ascii wide` (UTF-16LE samples)")
	}
}

func TestVBSCharCodeRule_NoBackreference(t *testing.T) {
	// yarac rejects backreferences; compile-rules.sh would then silently drop the
	// rule. Catch it at unit speed instead of as a missing rule on the live host.
	data := loadVBSCharCodeRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("vbs_charcode_dropper.yara contains backreference %q (yarac rejects, rule silently skipped)", bad)
		}
	}
}

func TestVBSCharCodeRule_NoNestedUnboundedQuantifier(t *testing.T) {
	// The catastrophic-backtracking class (#174/#177): a `){N,}` after an
	// unbounded inner quantifier blows scan_timeout and fail-opens the file.
	// This rule must stay linear.
	data := loadVBSCharCodeRule(t)
	if bytes.Contains(data, []byte("){")) {
		t.Errorf("vbs_charcode_dropper.yara has a `){...}` group-repeat — risks catastrophic backtracking; keep regexes linear")
	}
}
