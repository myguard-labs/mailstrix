package extract

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// PERF-63: depth-0 sources skip the mostlyText/mayBeEncoded re-check in the
// BFS because the prefilter already applied both. These cases pin that the
// skip changes nothing observable: encoded text still decodes (positive), a
// nested layer still decodes (depth > 0 keeps its gates), prose and binary
// sources still emit no decoded blob (negative), and empty input is harmless.
func TestFromEncodedDepth0GateBehaviour(t *testing.T) {
	payload := "MZ-this-is-the-hidden-dropper-payload-" + strings.Repeat("x", 64)
	one := base64.StdEncoding.EncodeToString([]byte(payload))
	two := base64.StdEncoding.EncodeToString([]byte(one))
	cases := []struct {
		name string
		in   []byte
		want bool // payload recovered
	}{
		{"single base64 layer", []byte("body: " + one + " end"), true},
		{"double base64 layer", []byte("body: " + two + " end"), true},
		{"plain prose", []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 40)), false},
		{"binary", bytes.Repeat([]byte{0, 1, 2, 0xff, 0xfe, 7}, 200), false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		res := &Result{}
		fromEncoded(c.in, res, FullOptions(time.Time{}))
		got := false
		for _, s := range res.Streams {
			if bytes.Contains(s, []byte(payload)) {
				got = true
			}
		}
		if !c.want && len(res.Streams) != 0 {
			t.Errorf("%s: got %d streams, want 0", c.name, len(res.Streams))
		}
		if got != c.want {
			t.Errorf("%s: payload recovered=%v, want %v (%d streams)", c.name, got, c.want, len(res.Streams))
		}
	}
}
