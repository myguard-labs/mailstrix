package yarad

import "testing"

// PLAN-marker-channel Phase 2: a PURE-marker rule (tagged `marker`) must fire
// ONLY on the out-of-band Result.Markers channel — never on raw bytes or real
// extracted content, so an attacker who plants a yarad marker literal in a body
// cannot trip it.

func TestMatchIsMarker(t *testing.T) {
	cases := []struct {
		tags []string
		want bool
	}{
		{nil, false},
		{[]string{"maldoc", "heuristic", "suspicious"}, false},
		{[]string{"marker"}, true},
		{[]string{"maldoc", "heuristic", "suspicious", "marker"}, true},
		{[]string{"markerish"}, false}, // exact-match only, no prefix slip
	}
	for _, c := range cases {
		if got := matchIsMarker(Match{Tags: c.tags}); got != c.want {
			t.Errorf("matchIsMarker(%v) = %v, want %v", c.tags, got, c.want)
		}
	}
}

func TestFilterMarkerChannel(t *testing.T) {
	in := []Match{
		{Rule: "Content_A"},                          // not marker
		{Rule: "Marker_B", Tags: []string{"marker"}}, // marker
		{Rule: "Content_C", Tags: []string{"maldoc"}},
		{Rule: "Marker_D", Tags: []string{"x", "marker"}},
	}

	// Raw / content channel: keep non-marker only.
	content := filterMarkerChannel(in, false)
	if len(content) != 2 || content[0].Rule != "Content_A" || content[1].Rule != "Content_C" {
		t.Errorf("content channel = %+v, want [Content_A Content_C]", content)
	}

	// Markers channel: keep marker-tagged only.
	markers := filterMarkerChannel(in, true)
	if len(markers) != 2 || markers[0].Rule != "Marker_B" || markers[1].Rule != "Marker_D" {
		t.Errorf("markers channel = %+v, want [Marker_B Marker_D]", markers)
	}

	// Nothing-to-filter returns the input slice unchanged (no alloc).
	allMarker := []Match{{Tags: []string{"marker"}}, {Tags: []string{"marker"}}}
	if got := filterMarkerChannel(allMarker, true); &got[0] != &allMarker[0] {
		t.Error("filterMarkerChannel should return input slice unchanged when nothing is filtered")
	}
}

// markerChannelRules: a marker-tagged rule keyed on a yarad PURE-marker literal,
// plus an untagged control rule, in one file.
const markerChannelRules = `
rule Marker_ObjectPool : maldoc heuristic suspicious marker
{
    strings:
        $m = "OLEID-OBJECTPOOL"
    condition:
        $m
}

rule Control_Benign : maldoc
{
    strings:
        $c = "BENIGN-CONTROL-LITERAL-XYZ"
    condition:
        $c
}
`

// TestMarkerRuleRejectedOnRaw is the adversarial/collision test: a raw buffer
// carrying the marker literal must NOT fire the marker rule (it would be a false
// positive — the literal is yarad-synthetic), while a normal content rule on the
// same buffer fires unaffected.
func TestMarkerRuleRejectedOnRaw(t *testing.T) {
	s := newScanner(t, writeRules(t, markerChannelRules))

	// Body contains BOTH literals, as an attacker-planted collision would.
	body := []byte("harmless text OLEID-OBJECTPOOL more text BENIGN-CONTROL-LITERAL-XYZ end")
	m, err := scanT(s, body, ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}

	var sawMarker, sawControl bool
	for _, hit := range m {
		switch hit.Rule {
		case "Marker_ObjectPool":
			sawMarker = true
		case "Control_Benign":
			sawControl = true
		}
	}
	if sawMarker {
		t.Error("marker-tagged rule fired on raw bytes — collision filter failed")
	}
	if !sawControl {
		t.Error("control rule did not fire — non-marker matching regressed")
	}
}
