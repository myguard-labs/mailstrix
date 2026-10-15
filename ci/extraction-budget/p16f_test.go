package extractionbudget_test

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

func p16fMessage(contentType, encoding string, body []byte) []byte {
	header := "From: p16f@example.test\r\nMIME-Version: 1.0\r\nContent-Type: " + contentType + "\r\n"
	if encoding != "" {
		header += "Content-Transfer-Encoding: " + encoding + "\r\n"
	}
	return append([]byte(header+"\r\n"), body...)
}

func p16fSameSlice(a, b []byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

func p16fIndependentBytes(res extract.Result) uint64 {
	total := p16dFinalBytes(res)
	for _, attachment := range res.MIMEAttachments {
		aliased := false
		for _, stream := range res.Streams {
			if p16fSameSlice(attachment, stream) {
				aliased = true
				break
			}
		}
		if !aliased {
			total += uint64(len(attachment))
		}
	}
	return total
}

func TestP16fMIMEAccountingAndResultParity(t *testing.T) {
	payload := []byte("P16F public attachment payload")
	leaf := p16fMessage("application/octet-stream; name=inner.bin", "", payload)
	inner := p16fMessage("message/rfc822; name=inner.eml", "", leaf)
	badAncestor := base64.StdEncoding.EncodeToString(leaf) + "!"
	tests := []struct {
		name            string
		input           []byte
		wantStreams     int
		wantAttachments int
		wantDigest      string
	}{
		{
			name:            "ordinary_alias",
			input:           p16fMessage("application/octet-stream; name=payload.bin", "", payload),
			wantStreams:     1,
			wantAttachments: 1,
			wantDigest:      "e5598e7b9c59b127c16e07c170bb85272b6e8f078148abfff781bef7c87b958a",
		},
		{
			name:            "nested_wrapper",
			input:           p16fMessage("message/rfc822; name=forwarded.eml", "", inner),
			wantStreams:     1,
			wantAttachments: 3,
			wantDigest:      "3452d612ae4d04002047c7244b2f0ee563db18aeb5a3cf9f42b6bf9daaa8106c",
		},
		{
			name:        "base64_ancestor_error",
			input:       p16fMessage("message/rfc822; name=broken.eml", "base64", []byte(badAncestor)),
			wantStreams: 2,
			wantDigest:  "12f1c9715834088165a5221384632c294af35ef6eac560a4e4d2574d84084fb6",
		},
		{
			name:        "nonattachment",
			input:       p16fMessage("text/plain", "", []byte("P16F public ordinary body")),
			wantStreams: 1,
			wantDigest:  "33f491941c06a7b3e67abd8d7f9103fcd5d09bf4e7a1eda37b9c8af159114141",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := extract.Extract(tc.input, time.Time{})
			if !res.IsMIME || res.TopType != extract.TopTypeMIME || res.Failed || res.Panicked {
				t.Fatalf("MIME identity/flags changed: %+v", res)
			}
			if len(res.Streams) != tc.wantStreams || res.ContentStreams != 1 || len(res.MIMEAttachments) != tc.wantAttachments {
				t.Fatalf("MIME ordering/provenance changed: streams=%d content=%d attachments=%d", len(res.Streams), res.ContentStreams, len(res.MIMEAttachments))
			}
			if got, want := res.Retained.Bytes(), p16fIndependentBytes(res); got != want {
				t.Fatalf("P16f retained closure=%d want independent output+attachment bytes=%d", got, want)
			}
			if tc.name == "ordinary_alias" && !p16fSameSlice(res.Streams[0], res.MIMEAttachments[0]) {
				t.Fatal("ordinary MIME attachment lost stream alias identity")
			}
			if tc.name == "nested_wrapper" && (!bytes.Equal(res.MIMEAttachments[0], inner) || !bytes.Equal(res.MIMEAttachments[1], leaf) || !p16fSameSlice(res.Streams[0], res.MIMEAttachments[2]) || p16fSameSlice(res.Streams[0], res.MIMEAttachments[0]) || p16fSameSlice(res.Streams[0], res.MIMEAttachments[1])) {
				t.Fatal("nested MIME wrapper order or descendant identity changed")
			}
			if got := p16dResultDigest(t, res); got != tc.wantDigest {
				t.Errorf("complete Result digest=%s want baseline=%s", got, tc.wantDigest)
			}
		})
	}
}
