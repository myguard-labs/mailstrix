package extractionbudget_test

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// TestCR534DecoyMemberDoesNotHideSiblingAtDefaultCeiling is the end-to-end
// CR534 regression at the shipped default ceiling with no override: a zip whose
// first member is larger than the whole retained budget must still publish the
// small member after it. The decoy is refused (never truncated) and the result
// is flagged truncated, which the scanner turns into MAILSTRIX_SCAN_INCOMPLETE.
func TestCR534DecoyMemberDoesNotHideSiblingAtDefaultCeiling(t *testing.T) {
	limit := extract.EffectiveDefaultRetainedBytesLimit()
	if limit != extract.DefaultRetainedBytesLimit {
		t.Fatalf("a test override leaked: effective=%d default=%d", limit, extract.DefaultRetainedBytesLimit)
	}
	sibling := []byte("CR534 sibling payload: AutoOpen Shell powershell -enc")
	decoy := bytes.Repeat([]byte{'D'}, int(limit+limit/25)) // about 2.6 MiB vs 2.5 MiB
	input := p16bZip(t,
		p16bZipEntry{name: "decoy.bin", data: decoy},
		p16bZipEntry{name: "sibling.txt", data: sibling},
	)

	res := extract.Extract(input, time.Time{})

	if !slices.ContainsFunc(res.Streams, func(s []byte) bool { return bytes.Equal(s, sibling) }) {
		t.Fatalf("sibling hidden by the refused decoy: %d streams", len(res.Streams))
	}
	for _, s := range res.Streams {
		if len(s) >= len(decoy)/2 {
			t.Fatalf("decoy (or a large prefix of it) was published: %d bytes", len(s))
		}
	}
	if !res.RetainedTruncated || !slices.Contains(res.CapHits, "retained-bytes") {
		t.Fatalf("decoy refusal not flagged: truncated=%v caps=%v", res.RetainedTruncated, res.CapHits)
	}
	got, _ := p16gIndependentBytes(res)
	if got > uint64(limit) || res.Retained.Bytes() != got {
		t.Fatalf("final=%d ledger=%d E=%d", got, res.Retained.Bytes(), limit)
	}

	// Control: without the decoy the same sibling is published and nothing is
	// truncated, so the assertion above is about the decoy, not the fixture.
	clean := extract.Extract(p16bZip(t, p16bZipEntry{name: "sibling.txt", data: sibling}), time.Time{})
	if !slices.ContainsFunc(clean.Streams, func(s []byte) bool { return bytes.Equal(s, sibling) }) || clean.RetainedTruncated {
		t.Fatalf("clean control: streams=%d truncated=%v", len(clean.Streams), clean.RetainedTruncated)
	}
}
