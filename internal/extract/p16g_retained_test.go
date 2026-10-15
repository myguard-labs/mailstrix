package extract

import (
	"bytes"
	"testing"
	"time"
)

func p16gInternalFinalBytes(r *Result) uint64 {
	var total uint64
	for _, group := range [][][]byte{r.Streams, r.Markers} {
		for _, entry := range group {
			total += uint64(len(entry))
		}
	}
	return total
}

func TestP16gOLEIDMarkerAccountingBoundaries(t *testing.T) {
	r, ledger := p16bResult()
	seed := []byte("seed")
	out := [][]byte{seed}

	unchanged := appendOLEIDMarker(r, out, "OLEID-DDE", false)
	if len(unchanged) != 1 || !bytes.Equal(unchanged[0], seed) || ledger.snapshot().Bytes() != 0 {
		t.Fatalf("false condition changed output/accounting: out=%q bytes=%d", unchanged, ledger.snapshot().Bytes())
	}

	existing := []byte("OLEID-DDE")
	r.recordRetained(existing)
	out = append(out, existing)
	before := ledger.snapshot().Bytes()
	deduplicated := appendOLEIDMarker(r, out, "OLEID-DDE", true)
	if len(deduplicated) != len(out) || ledger.snapshot().Bytes() != before {
		t.Fatalf("existing marker was re-added/recharged: len=%d bytes=%d want len=%d bytes=%d", len(deduplicated), ledger.snapshot().Bytes(), len(out), before)
	}

	markers := []string{"OLEID-VBA-PRESENT", "OLEID-EXTREL", "OLEID-XLM-PRESENT"}
	wantBytes := before
	for _, marker := range markers {
		out = appendOLEIDMarker(r, out, marker, true)
		wantBytes += uint64(len(marker))
	}
	if got := ledger.snapshot().Bytes(); got != wantBytes {
		t.Fatalf("four-marker retained bytes=%d want=%d", got, wantBytes)
	}
	if len(out) != 2+len(markers) {
		t.Fatalf("four-marker output count=%d want=%d", len(out), 2+len(markers))
	}
	for i, marker := range markers {
		if got := string(out[i+2]); got != marker {
			t.Fatalf("marker %d=%q want=%q", i, got, marker)
		}
	}
}

func TestP16gPreviouslyUnregisteredSinkAccounting(t *testing.T) {
	t.Run("lnk", func(t *testing.T) {
		buf := (&lnkBuilder{
			flags:   lnkHasArguments | lnkIsUnicode,
			strings: [][2]string{{"arguments", "powershell.exe -nop"}},
			unicode: true,
		}).build()
		res := Extract(buf, time.Time{})
		if got, want := res.Retained.Bytes(), p16gInternalFinalBytes(&res); got != want || want == 0 {
			t.Fatalf("LNK retained closure=%d want=%d", got, want)
		}
	})

	t.Run("pdf_stream_and_markers", func(t *testing.T) {
		input := append(pdfWithStream(zlibDeflate([]byte("P16G PDF retained payload"))), []byte("\n/OpenAction /JavaScript /AA /Launch /EmbeddedFile /JBIG2Decode /ObjStm")...)
		res := Extract(input, time.Time{})
		if got, want := res.Retained.Bytes(), p16gInternalFinalBytes(&res); got != want || want == 0 {
			t.Fatalf("PDF retained closure=%d want=%d", got, want)
		}
	})

	t.Run("pdf_additional_raw_deflate", func(t *testing.T) {
		payload := []byte("P16G additional raw-deflate retained payload")
		body := ascii85Encode(rawDeflate(payload))
		res := Extract(pdfWithFilter("/ASCII85Decode", body), time.Time{})
		if len(res.Streams) < 2 {
			t.Fatalf("PDF additional raw-deflate path emitted %d streams want at least 2", len(res.Streams))
		}
		if got, want := res.Retained.Bytes(), p16gInternalFinalBytes(&res); got != want || want == 0 {
			t.Fatalf("PDF additional retained closure=%d want=%d", got, want)
		}
	})

	t.Run("ole2link", func(t *testing.T) {
		url := "https://p16g.example/payload"
		buf := buildCFB(t, []cfbEntry{
			{name: "Root Entry", mse: 5},
			{name: "Object", mse: 2, data: makeMoniker(url)},
		})
		r, ledger := p16bResult()
		fromOLE2Link(parseP16bOLE(t, buf), r, time.Time{})
		want := uint64(len("OLE2LINK-URL ") + len(url))
		if len(r.Streams) != 1 || !bytes.Equal(r.Streams[0], []byte("OLE2LINK-URL "+url)) {
			t.Fatalf("OLE2Link output changed: %q", r.Streams)
		}
		if got := ledger.snapshot().Bytes(); got != want {
			t.Fatalf("OLE2Link retained bytes=%d want=%d", got, want)
		}
	})
}
