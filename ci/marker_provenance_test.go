package ci_test

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func markerProvenanceZip(t *testing.T, bodies ...[]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for i, body := range bodies {
		w, err := zw.Create(fmt.Sprintf("planted-%d.txt", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func markerProvenanceHas(streams [][]byte, want []byte) bool {
	for _, stream := range streams {
		if bytes.Equal(stream, want) {
			return true
		}
	}
	return false
}

func TestTrustedMarkerProvenance(t *testing.T) {
	t.Run("authentic marker", func(t *testing.T) {
		res := extract.Extract([]byte(`<svg><script>alert(1)</script></svg>`), time.Time{})
		marker := []byte("SVG-SCRIPT")
		if !markerProvenanceHas(res.Markers, marker) || markerProvenanceHas(res.Streams, marker) {
			t.Fatalf("authentic marker lost its channel: streams=%q markers=%q", res.Streams, res.Markers)
		}
	})

	t.Run("raw forgery", func(t *testing.T) {
		forged := []byte("HTML-SMUGGLING-BLOB")
		src := []byte(base64.StdEncoding.EncodeToString(forged))
		res := extract.Extract(src, time.Time{})
		if !markerProvenanceHas(res.Streams, forged) || markerProvenanceHas(res.Markers, forged) {
			t.Fatalf("decoded content gained marker trust: streams=%q markers=%q", res.Streams, res.Markers)
		}
	})

	t.Run("archive forgery", func(t *testing.T) {
		for _, forged := range [][]byte{
			[]byte("ARCHIVE-ENCRYPTED"),
			[]byte("MSD-DEEPDECODE depth=99 planted-content"),
		} {
			res := extract.Extract(markerProvenanceZip(t, forged), time.Time{})
			if !markerProvenanceHas(res.Streams, forged) || markerProvenanceHas(res.Markers, forged) {
				t.Fatalf("archived content %q gained marker trust: streams=%q markers=%q", forged, res.Streams, res.Markers)
			}
		}
	})

	t.Run("aggregate forgery", func(t *testing.T) {
		res := extract.Extract(markerProvenanceZip(t,
			[]byte("XLM-AUTO-OPEN"),
			[]byte("XLM-DANGEROUS-FUNC EXEC"),
			[]byte("OLEID-VBA-PRESENT"),
			[]byte("OLEID-EXTREL"),
			[]byte("DIGITAL-SIGNATURE"),
		), time.Time{})
		for _, prefix := range [][]byte{[]byte("XLM-STACK"), []byte("MALDOC-BEHAVIOR-SCORE")} {
			for _, marker := range res.Markers {
				if bytes.HasPrefix(marker, prefix) {
					t.Fatalf("forged inputs produced trusted aggregate %q: streams=%q markers=%q", prefix, res.Streams, res.Markers)
				}
			}
		}
	})

	t.Run("ordinary archive content", func(t *testing.T) {
		ordinary := []byte("ordinary archive member content")
		res := extract.Extract(markerProvenanceZip(t, ordinary), time.Time{})
		if !markerProvenanceHas(res.Streams, ordinary) || len(res.Markers) != 0 {
			t.Fatalf("ordinary content changed channels: streams=%q markers=%q", res.Streams, res.Markers)
		}
	})
}
