package extract

import (
	"bytes"
	"encoding/base64"
	"net/textproto"
	"testing"
	"time"
)

func p16fHeader(contentType, encoding, disposition string) textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", contentType)
	if encoding != "" {
		h.Set("Content-Transfer-Encoding", encoding)
	}
	if disposition != "" {
		h.Set("Content-Disposition", disposition)
	}
	return h
}

func p16fMessage(contentType string, body []byte) []byte {
	return append([]byte("From: p16f@example.test\r\nMIME-Version: 1.0\r\nContent-Type: "+contentType+"\r\n\r\n"), body...)
}

func p16fSameSlice(a, b []byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

func p16fHasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestP16fMIMEAttachmentAdmissionAlias(t *testing.T) {
	payload := []byte("P16F complete attachment")
	r, ledger := p16bResult()
	b := &archiveBudget{}
	walkMIMEEntity(
		p16fHeader("application/octet-stream; name=payload.bin", "", "attachment; filename=payload.bin"),
		bytes.NewReader(payload), r, b, 0, time.Time{}, new(int), true,
	)
	if len(r.Streams) != 1 || len(r.MIMEAttachments) != 1 {
		t.Fatalf("ordinary MIME outputs streams=%d attachments=%d", len(r.Streams), len(r.MIMEAttachments))
	}
	if !bytes.Equal(r.Streams[0], payload) || !p16fSameSlice(r.Streams[0], r.MIMEAttachments[0]) {
		t.Fatal("ordinary MIME stream and attachment lost bytes or shared identity")
	}
	if got := ledger.snapshot().Bytes(); got != uint64(len(payload)) {
		t.Fatalf("ordinary MIME retained bytes=%d want one admission=%d", got, len(payload))
	}
	if ledger.admissions != 1 || b.members != 1 || b.total != len(payload) || !r.IsMIME {
		t.Fatalf("ordinary MIME admission/flags changed: admissions=%d budget=%+v IsMIME=%v", ledger.admissions, b, r.IsMIME)
	}
}

func TestP16fMIMEAttachedMessageIndependentAdmission(t *testing.T) {
	payload := []byte("P16F nested attachment")
	leaf := p16fMessage("application/octet-stream; name=inner.bin", payload)
	inner := p16fMessage("message/rfc822; name=inner.eml", leaf)
	outer := p16fMessage("message/rfc822; name=forwarded.eml", inner)
	r, ledger := p16bResult()
	b := &archiveBudget{}
	fromMIME(outer, r, b, 0, time.Time{})
	if len(r.Streams) != 1 || len(r.MIMEAttachments) != 3 {
		t.Fatalf("nested MIME outputs streams=%d attachments=%d", len(r.Streams), len(r.MIMEAttachments))
	}
	if !bytes.Equal(r.MIMEAttachments[0], inner) || !bytes.Equal(r.MIMEAttachments[1], leaf) || !p16fSameSlice(r.MIMEAttachments[2], r.Streams[0]) {
		t.Fatal("nested wrapper bytes/order or descendant alias changed")
	}
	want := uint64(len(inner) + len(leaf) + len(payload))
	if got := ledger.snapshot().Bytes(); got != want {
		t.Fatalf("nested MIME retained bytes=%d want wrappers+descendant=%d", got, want)
	}
	if ledger.admissions != 3 || b.members != 3 || b.total != int(want) {
		t.Fatalf("nested MIME admission/budget changed: admissions=%d budget=%+v", ledger.admissions, b)
	}
}

func TestP16fMIMEEOFAtArchiveCap(t *testing.T) {
	payload := []byte("P16F cap boundary")
	r, ledger := p16bResult()
	b := &archiveBudget{total: maxTotalArchive - len(payload)}
	walkMIMEEntity(
		p16fHeader("application/octet-stream; name=cap.bin", "", "attachment"),
		bytes.NewReader(payload), r, b, 0, time.Time{}, new(int), true,
	)
	if len(r.Streams) != 1 || len(r.MIMEAttachments) != 1 || !p16fSameSlice(r.Streams[0], r.MIMEAttachments[0]) {
		t.Fatalf("EOF-at-cap outputs changed: streams=%d attachments=%d", len(r.Streams), len(r.MIMEAttachments))
	}
	if got := ledger.snapshot().Bytes(); got != uint64(len(payload)) || ledger.admissions != 1 {
		t.Fatalf("EOF-at-cap retained=%d admissions=%d want=%d/1", got, ledger.admissions, len(payload))
	}
	if !b.spent() || len(r.CapHits) != 1 || !p16fHasString(r.CapHits, "archive-budget") {
		t.Fatalf("EOF-at-cap stop semantics changed: spent=%v hits=%v", b.spent(), r.CapHits)
	}
}

func TestP16fMIMEIncompleteAndNonAttachmentAdmissions(t *testing.T) {
	tests := []struct {
		name             string
		header           textproto.MIMEHeader
		body             []byte
		completeAncestor bool
		remaining        int
		want             []byte
		wantCap          string
	}{
		{
			name:             "invalid_base64",
			header:           p16fHeader("application/octet-stream; name=bad.bin", "base64", "attachment"),
			body:             []byte(base64.StdEncoding.EncodeToString([]byte("P16F invalid base64")) + "!"),
			completeAncestor: true,
			want:             []byte("P16F invalid base64"),
		},
		{
			name:             "truncated",
			header:           p16fHeader("application/octet-stream; name=cut.bin", "", "attachment"),
			body:             []byte("P16F truncated body"),
			completeAncestor: true,
			remaining:        8,
			want:             []byte("P16F tru"),
			wantCap:          "archive-budget",
		},
		{
			name:   "incomplete_ancestor",
			header: p16fHeader("application/octet-stream; name=ancestor.bin", "", "attachment"),
			body:   []byte("P16F incomplete ancestor"),
			want:   []byte("P16F incomplete ancestor"),
		},
		{
			name:             "nonattachment",
			header:           p16fHeader("text/plain", "", ""),
			body:             []byte("P16F ordinary body"),
			completeAncestor: true,
			want:             []byte("P16F ordinary body"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, ledger := p16bResult()
			b := &archiveBudget{}
			if tc.remaining > 0 {
				b.total = maxTotalArchive - tc.remaining
			}
			walkMIMEEntity(tc.header, bytes.NewReader(tc.body), r, b, 0, time.Time{}, new(int), tc.completeAncestor)
			if len(r.MIMEAttachments) != 0 || len(r.Streams) != 1 || !bytes.Equal(r.Streams[0], tc.want) {
				t.Fatalf("incomplete/nonattachment bytes changed: streams=%q attachments=%q", r.Streams, r.MIMEAttachments)
			}
			if got := ledger.snapshot().Bytes(); got != uint64(len(tc.want)) || ledger.admissions != 1 {
				t.Fatalf("incomplete/nonattachment retained=%d admissions=%d want=%d/1", got, ledger.admissions, len(tc.want))
			}
			if tc.wantCap != "" && !p16fHasString(r.CapHits, tc.wantCap) {
				t.Fatalf("missing cap hit %q: %v", tc.wantCap, r.CapHits)
			}
		})
	}
}

func TestP16fMIMEDepthProbeUsesShadowLedger(t *testing.T) {
	payload := []byte("=cmd|'/c calc.exe'!A1,plain\n")
	r, ledger := p16bResult()
	b := &archiveBudget{}
	emitMIMEPart(payload, r, b, maxNestDepth, time.Time{}, retainedToken{})
	if len(r.Streams) != 1 || !bytes.Equal(r.Streams[0], payload) || !p16fHasString(r.CapHits, "depth") {
		t.Fatalf("depth probe changed parent output: streams=%q hits=%v", r.Streams, r.CapHits)
	}
	if got := ledger.snapshot().Bytes(); got != uint64(len(payload)) || ledger.admissions != 1 {
		t.Fatalf("depth probe consumed parent ledger: bytes=%d admissions=%d want=%d/1", got, ledger.admissions, len(payload))
	}
}
