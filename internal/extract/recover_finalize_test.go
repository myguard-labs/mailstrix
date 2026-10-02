package extract

import (
	"bytes"
	"testing"
	"time"
)

func withAfterFormatHook(t *testing.T, h func(*Result)) {
	t.Helper()
	afterFormatHook = h
	t.Cleanup(func() { afterFormatHook = nil })
}

func hasStream(list [][]byte, want []byte) bool {
	for _, s := range list {
		if bytes.Equal(s, want) {
			return true
		}
	}
	return false
}

// TestPanicKeepsEmittedPureMarkers (COR-17): a PURE marker emitted before an
// extractor panic still lands in Markers (not Streams, where the scanner's
// marker filter would drop it), and content emitted before it stays content.
func TestPanicKeepsEmittedPureMarkers(t *testing.T) {
	marker := []byte(pureMarkerPrefixes[0] + " injected")
	content := []byte("plain member content before the panic")
	withAfterFormatHook(t, func(r *Result) {
		r.Streams = append(r.Streams, content, marker)
		panic("injected extractor panic")
	})
	res := ExtractWithOptions([]byte("hello"), FullOptions(time.Time{}))
	if !res.Panicked || !res.Failed {
		t.Fatalf("panic not recorded: %+v", res)
	}
	if !hasStream(res.Markers, marker) || hasStream(res.Streams, marker) {
		t.Fatalf("marker not routed to Markers: streams=%q markers=%q", res.Streams, res.Markers)
	}
	if !hasStream(res.Streams, content) || res.ContentStreams < 1 {
		t.Fatalf("content lost or uncounted: streams=%q content=%d", res.Streams, res.ContentStreams)
	}
}

// TestPanicWithNoStreamsBoundary: a panic before anything was emitted yields
// an empty, failed result rather than a second panic.
func TestPanicWithNoStreamsBoundary(t *testing.T) {
	withAfterFormatHook(t, func(*Result) { panic("early") })
	res := ExtractWithOptions([]byte("x"), FullOptions(time.Time{}))
	if !res.Panicked || len(res.Streams) != 0 || len(res.Markers) != 0 || res.ContentStreams != 0 {
		t.Fatalf("got %+v", res)
	}
}

// TestPanicDuringFinalizeIsContained (malformed): a stream that makes the
// finaliser itself misbehave cannot escape ExtractWithOptions.
func TestPanicDuringFinalizeIsContained(t *testing.T) {
	withAfterFormatHook(t, func(r *Result) {
		r.Streams = append(r.Streams, nil, []byte{})
		panic("with odd streams")
	})
	res := ExtractWithOptions([]byte("x"), FullOptions(time.Time{}))
	if !res.Panicked {
		t.Fatal("panic not recorded")
	}
}

// TestNoPanicNormalExitUnchanged (negative control): without a panic the hook
// path changes nothing; markers still split as before.
func TestNoPanicNormalExitUnchanged(t *testing.T) {
	marker := []byte(pureMarkerPrefixes[0] + " normal")
	withAfterFormatHook(t, func(r *Result) { r.Streams = append(r.Streams, marker) })
	res := ExtractWithOptions([]byte("hello"), FullOptions(time.Time{}))
	if res.Panicked || !hasStream(res.Markers, marker) || hasStream(res.Streams, marker) {
		t.Fatalf("normal exit changed: panicked=%v streams=%q markers=%q", res.Panicked, res.Streams, res.Markers)
	}
}
