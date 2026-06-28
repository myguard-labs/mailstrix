package extract

import (
	"bytes"
	"testing"
)

// TestSplitPureMarkers_Partition pins the Phase-1 invariant: every PURE marker
// leaves Streams for the Markers channel, every COMBINED marker and every real
// content entry stays in Streams, order is preserved, and decodeMoved counts the
// MSD markers removed (so DecodedStreams stays exact).
func TestSplitPureMarkers_Partition(t *testing.T) {
	in := [][]byte{
		[]byte("real macro source Sub Auto_Open()"),
		[]byte("USERFORM-STRINGS"),
		[]byte("DOCPROPS-STRINGS"),
		[]byte("carved docprop string value"),
		[]byte("MSD-DEEPDECODE depth=4"),
		[]byte("OLE-DOC-SECURITY-1"),
		[]byte("ENCRYPTION-AES"),
		[]byte("DIGITAL-SIGNATURE"),
		[]byte("XLM-AUTO-OPEN"),
		// COMBINED markers — must stay in content (carry attacker IOC).
		[]byte("SLK-DDE =cmd|'/c calc'!A1"),
		[]byte("RTF-DDE-FIELD DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe"),
		[]byte("XLM-HIDDEN-MACROSHEET hidden Macro1"),
		[]byte("XLM-DANGEROUS-FUNC EXEC"),
		[]byte("OOXML-DDE-FIELD DDE cmd"),
		[]byte("CSV-DDE =2+5+cmd|'/c calc'!A0"),
	}
	wantMarkers := map[string]bool{
		"USERFORM-STRINGS":       true,
		"DOCPROPS-STRINGS":       true,
		"MSD-DEEPDECODE depth=4": true,
		"OLE-DOC-SECURITY-1":     true,
		"ENCRYPTION-AES":         true,
		"DIGITAL-SIGNATURE":      true,
		"XLM-AUTO-OPEN":          true,
	}

	content, markers, decodeMoved := splitPureMarkers(in)

	// No PURE marker leaked into content.
	for _, c := range content {
		if isPureMarker(c) {
			t.Fatalf("pure marker leaked into content: %q", c)
		}
	}
	// Every Markers entry is a known PURE marker.
	for _, m := range markers {
		if !isPureMarker(m) {
			t.Fatalf("non-pure entry routed to markers: %q", m)
		}
		if !wantMarkers[string(m)] {
			t.Fatalf("unexpected markers entry: %q", m)
		}
		delete(wantMarkers, string(m))
	}
	if len(wantMarkers) != 0 {
		t.Fatalf("expected markers not routed: %v", wantMarkers)
	}
	// COMBINED markers and real content stay in Streams.
	for _, want := range []string{
		"real macro source Sub Auto_Open()", "carved docprop string value",
		"SLK-DDE =cmd|'/c calc'!A1", "XLM-HIDDEN-MACROSHEET hidden Macro1",
		"XLM-DANGEROUS-FUNC EXEC", "OOXML-DDE-FIELD DDE cmd", "CSV-DDE =2+5+cmd|'/c calc'!A0",
	} {
		found := false
		for _, c := range content {
			if bytes.Equal(c, []byte(want)) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("content entry missing after split: %q", want)
		}
	}
	if decodeMoved != 1 {
		t.Fatalf("decodeMoved = %d, want 1 (one MSD-DEEPDECODE marker)", decodeMoved)
	}
}

// TestJoinMarkerPayload_CoLocateAndRoute pins the Phase 2b fix: a combined
// "<marker>\n<carved...>" buffer co-locates the marker literal with each carved
// IOC (so a `$marker and $ioc` rule can match in ONE buffer) AND routes to the
// out-of-band Markers channel via the marker prefix, never staying in content.
func TestJoinMarkerPayload_CoLocateAndRoute(t *testing.T) {
	for _, marker := range []string{docPropsMarker, userFormMarker} {
		carved := [][]byte{
			[]byte("http://evil.example/c2"),
			[]byte("powershell -enc AAA"),
		}
		buf := joinMarkerPayload(marker, carved)

		if !bytes.HasPrefix(buf, []byte(marker)) {
			t.Fatalf("%s: buffer missing marker prefix: %q", marker, buf)
		}
		for _, c := range carved {
			if !bytes.Contains(buf, c) {
				t.Fatalf("%s: buffer missing carved IOC %q: %q", marker, c, buf)
			}
		}
		if !isPureMarker(buf) {
			t.Fatalf("%s: combined buffer not recognised as a marker", marker)
		}

		content, markers, _ := splitPureMarkers([][]byte{
			[]byte("real content no marker"), buf,
		})
		if len(markers) != 1 || !bytes.Equal(markers[0], buf) {
			t.Fatalf("%s: combined buffer not routed to Markers: %v", marker, markers)
		}
		for _, c := range content {
			if bytes.HasPrefix(c, []byte(marker)) {
				t.Fatalf("%s: combined buffer leaked into content: %q", marker, c)
			}
		}
	}
}

// TestJoinMarkerPayload_Empty: no carved strings → bare marker literal, still a
// pure marker (routes to the channel; just carries no IOC so the rule won't fire).
func TestJoinMarkerPayload_Empty(t *testing.T) {
	buf := joinMarkerPayload(docPropsMarker, nil)
	if !bytes.Equal(buf, []byte(docPropsMarker)) {
		t.Fatalf("empty carved: want bare %q, got %q", docPropsMarker, buf)
	}
	if !isPureMarker(buf) {
		t.Fatal("bare marker not recognised as pure marker")
	}
}

// TestSplitPureMarkers_Empty: nil/empty input yields nil slices, no panic.
func TestSplitPureMarkers_Empty(t *testing.T) {
	content, markers, n := splitPureMarkers(nil)
	if len(content) != 0 || len(markers) != 0 || n != 0 {
		t.Fatalf("empty input: content=%d markers=%d moved=%d", len(content), len(markers), n)
	}
}

// TestJoinXLMStackerMarkers_Colocates pins the Phase-2c fix: the scattered XLM
// markers (each emitted as its own Streams entry, scanned independently) are
// collected into ONE XLM-STACK-prefixed buffer so the multi-marker stacker rules
// (XLM_AutoOpen_Dropper etc.) can satisfy their conjunctions on the Markers
// channel. Confirmed dead-without-fix empirically via blacktop/yara.
func TestJoinXLMStackerMarkers_Colocates(t *testing.T) {
	streams := [][]byte{
		[]byte("real macro source"),
		[]byte("XLM-AUTO-OPEN"),
		[]byte("XLM-HIDDEN-MACROSHEET hidden Macro1"),
		[]byte("XLM-DANGEROUS-FUNC EXEC"),
		[]byte("XLM-EMUL-DEPTH branched"),
	}
	buf := joinXLMStackerMarkers(streams)
	if buf == nil {
		t.Fatal("expected combined buffer for >=2 stacker markers, got nil")
	}
	if !bytes.HasPrefix(buf, []byte(xlmStackerPrefix)) {
		t.Fatalf("combined buffer missing XLM-STACK prefix: %q", buf)
	}
	if !isPureMarker(buf) {
		t.Fatal("combined buffer not routed to Markers channel (isPureMarker=false)")
	}
	for _, want := range []string{"XLM-AUTO-OPEN", "XLM-HIDDEN-MACROSHEET hidden", "XLM-DANGEROUS-FUNC EXEC", "XLM-EMUL-DEPTH branched"} {
		if !bytes.Contains(buf, []byte(want)) {
			t.Fatalf("combined buffer missing co-located marker %q: %q", want, buf)
		}
	}
}

// TestJoinBehaviorScore_AggregatesAndRoutes pins the behavioral tier: when at
// least behaviorScoreMin DISTINCT weak-marker classes co-occur, one aggregate
// MALDOC-BEHAVIOR-SCORE buffer is emitted, carries the distinct count + each
// class co-located, and routes to the Markers channel. Source markers are NOT
// consumed (this only adds a stacking verdict).
func TestJoinBehaviorScore_AggregatesAndRoutes(t *testing.T) {
	streams := [][]byte{
		[]byte("real macro source"),
		[]byte("OLEID-VBA-PRESENT"),
		[]byte("OLEID-EXTREL"),
		[]byte("DIGITAL-SIGNATURE"),
		[]byte("OLE-DOC-SECURITY-1"), // value-carrying, collapses to its class
		[]byte("OLEID-VBA-PRESENT"),  // duplicate class — counted once
	}
	buf := joinBehaviorScore(streams)
	if buf == nil {
		t.Fatal("expected aggregate buffer for >=3 distinct weak markers, got nil")
	}
	if !bytes.HasPrefix(buf, []byte(behaviorScorePrefix)) {
		t.Fatalf("aggregate buffer missing prefix: %q", buf)
	}
	if !isPureMarker(buf) {
		t.Fatal("aggregate buffer not routed to Markers channel (isPureMarker=false)")
	}
	// 4 distinct classes (VBA-PRESENT, EXTREL, DIGITAL-SIGNATURE, DOC-SECURITY).
	if !bytes.Contains(buf, []byte("n=4\n")) {
		t.Fatalf("aggregate buffer wrong distinct count: %q", buf)
	}
	for _, want := range []string{"OLEID-VBA-PRESENT", "OLEID-EXTREL", "DIGITAL-SIGNATURE", "OLE-DOC-SECURITY-"} {
		if !bytes.Contains(buf, []byte(want)) {
			t.Fatalf("aggregate buffer missing co-located class %q: %q", want, buf)
		}
	}
}

// TestJoinBehaviorScore_BelowThreshold: fewer than behaviorScoreMin distinct
// classes -> nil (no aggregate signal; the individual marker rules still fire).
func TestJoinBehaviorScore_BelowThreshold(t *testing.T) {
	if buf := joinBehaviorScore([][]byte{
		[]byte("OLEID-VBA-PRESENT"), []byte("DIGITAL-SIGNATURE"), []byte("plain content"),
	}); buf != nil {
		t.Fatalf("2 distinct weak markers: want nil, got %q", buf)
	}
	if buf := joinBehaviorScore([][]byte{[]byte("no markers here")}); buf != nil {
		t.Fatalf("no weak markers: want nil, got %q", buf)
	}
}

// TestItoa exercises the small-int renderer used for the distinct count.
func TestItoa(t *testing.T) {
	for v, want := range map[int]string{0: "0", 3: "3", 9: "9", 10: "10", 16: "16"} {
		if got := itoa(v); got != want {
			t.Fatalf("itoa(%d) = %q, want %q", v, got, want)
		}
	}
}

// TestJoinXLMStackerMarkers_SingleNil: a single stacker marker can never satisfy
// a conjunction, so no buffer is built (nil).
func TestJoinXLMStackerMarkers_SingleNil(t *testing.T) {
	if buf := joinXLMStackerMarkers([][]byte{[]byte("XLM-AUTO-OPEN"), []byte("plain content")}); buf != nil {
		t.Fatalf("single stacker marker: want nil, got %q", buf)
	}
	if buf := joinXLMStackerMarkers([][]byte{[]byte("no markers here")}); buf != nil {
		t.Fatalf("no stacker markers: want nil, got %q", buf)
	}
}
