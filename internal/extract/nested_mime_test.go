package extract

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func nestedMIMEFixture() []byte {
	return emlWithParts(b64Part("dropper.vbe", encodedVBEBlock))
}

func TestNestedMIMEDirectArchiveAndAttachedMessageParity(t *testing.T) {
	inner := nestedMIMEFixture()
	attached := emlWithParts("Content-Type: message/rfc822\r\n" +
		"Content-Disposition: attachment; filename=\"forwarded.eml\"\r\n\r\n" +
		string(inner) + "\r\n")
	cases := map[string][]byte{
		"direct":           inner,
		"archive-member":   buildZip(t, map[string][]byte{"forwarded.eml": inner}),
		"attached-message": attached,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			res := Extract(input, time.Time{})
			if !res.IsMIME || !res.EncodedScript || !streamsContain(res, "MsgBox") {
				t.Fatalf("nested MIME parity failed: IsMIME=%t EncodedScript=%t streams=%d", res.IsMIME, res.EncodedScript, len(res.Streams))
			}
		})
	}
}

func TestNestedMIMEMalformedBodyKeepsDecodedPrefix(t *testing.T) {
	encoded := b64Lines([]byte(mimeNeedle + "-NESTED-MALFORMED and trailing bytes"))
	malformed := emlWithParts("Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		encoded[:len(encoded)-12] + "!!\r\n")
	res := Extract(buildZip(t, map[string][]byte{"broken.eml": malformed}), time.Time{})
	if res.Panicked || !streamsContain(res, mimeNeedle+"-NESTED-MALFORMED") {
		t.Fatalf("malformed nested MIME lost its safe decoded prefix: panicked=%t streams=%d", res.Panicked, len(res.Streams))
	}
}

func TestNestedMIMEGuards(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		res := &Result{}
		extractChild(nestedMIMEFixture(), res, &archiveBudget{}, maxNestDepth+1, time.Time{})
		if !hasCapHit(*res, "depth") || res.EncodedScript {
			t.Fatalf("depth guard failed: caps=%v EncodedScript=%t", res.CapHits, res.EncodedScript)
		}
	})

	t.Run("parts", func(t *testing.T) {
		parts := make([]string, maxMIMEParts+1)
		for i := range parts {
			parts[i] = fmt.Sprintf("Content-Type: text/plain\r\n\r\npart-%03d\r\n", i)
		}
		res := &Result{}
		extractChild(emlWithParts(parts...), res, &archiveBudget{}, 0, time.Time{})
		if !hasCapHit(*res, "mime-parts") {
			t.Fatalf("part guard did not fire: caps=%v", res.CapHits)
		}
	})

	t.Run("bytes", func(t *testing.T) {
		body := bytes.Repeat([]byte{'A'}, 32)
		message := []byte("From: a@example.test\r\nMIME-Version: 1.0\r\n" +
			"Content-Type: application/octet-stream\r\n\r\n" + string(body))
		res := &Result{}
		budget := &archiveBudget{total: maxTotalArchive - 8}
		extractChild(message, res, budget, 0, time.Time{})
		if !hasCapHit(*res, "archive-budget") {
			t.Fatalf("byte guard did not fire: caps=%v", res.CapHits)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		res := &Result{}
		extractChild(nestedMIMEFixture(), res, &archiveBudget{}, 0, time.Now().Add(-time.Second))
		if res.IsMIME || res.EncodedScript || len(res.Streams) != 0 {
			t.Fatalf("expired nested MIME was processed: IsMIME=%t EncodedScript=%t streams=%d", res.IsMIME, res.EncodedScript, len(res.Streams))
		}
	})

	t.Run("incomplete-header", func(t *testing.T) {
		message := []byte("From: a@example.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"" +
			strings.Repeat("x", maxMIMEHeaderBytes))
		res := &Result{}
		extractChild(message, res, &archiveBudget{}, 0, time.Time{})
		if !hasCapHit(*res, mimeHeaderCapHitKind) {
			t.Fatalf("incomplete nested MIME header did not fail closed: caps=%v", res.CapHits)
		}
	})
}
