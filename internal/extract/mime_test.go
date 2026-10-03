package extract

import (
	"encoding/base64"
	"fmt"
	"mime/quotedprintable"
	"strings"
	"testing"
	"time"
)

const mimeNeedle = "COR01-MIME-DROPPER-PAYLOAD"

func b64Lines(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.String()
}

func qpEncode(s string) string {
	var b strings.Builder
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.String()
}

func emlWithParts(parts ...string) []byte {
	var b strings.Builder
	b.WriteString("From: a@example.com\r\nTo: b@example.com\r\nSubject: invoice\r\nMIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\npreamble\r\n")
	for _, p := range parts {
		b.WriteString("--BOUND\r\n" + p)
	}
	b.WriteString("--BOUND--\r\n")
	return []byte(b.String())
}

func b64Part(name string, data []byte) string {
	return "Content-Type: application/octet-stream; name=\"" + name + "\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64Lines(data)
}

// TestMIMEBase64ZipAttachment (COR-01): a base64 zip attachment in an .eml is
// decoded and unpacked, so the script member inside it is scanned.
func TestMIMEBase64ZipAttachment(t *testing.T) {
	zip := zipOfMembers(t, []string{"z.vbs"}, [][]byte{[]byte(`WScript.Echo "` + mimeNeedle + `"`)})
	eml := emlWithParts("Content-Type: text/plain\r\n\r\nsee attached\r\n", b64Part("invoice.zip", zip))
	res := Extract(eml, time.Time{})
	if !streamsContain(res, mimeNeedle) {
		t.Fatalf("payload in zipped attachment not reached; streams=%d", len(res.Streams))
	}
	if !res.IsMIME || res.TopType != TopTypeMIME || !res.IsArchive {
		t.Fatalf("flags: IsMIME=%v TopType=%q IsArchive=%v", res.IsMIME, res.TopType, res.IsArchive)
	}
}

// TestMIMEQuotedPrintableAndNested: a quoted-printable part is decoded, and a
// message/rfc822 part is walked recursively.
func TestMIMEQuotedPrintableAndNested(t *testing.T) {
	qp := "Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		qpEncode("<script>var x = \""+strings.Repeat("=", 3)+mimeNeedle+"-QP\";</script>") + "\r\n"
	inner := string(emlWithParts(b64Part("inner.bin", []byte(mimeNeedle+"-NESTED"))))
	nested := "Content-Type: message/rfc822\r\n\r\n" + inner + "\r\n"
	res := Extract(emlWithParts(qp, nested), time.Time{})
	for _, want := range []string{mimeNeedle + "-QP", mimeNeedle + "-NESTED"} {
		if !streamsContain(res, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// TestMIMESinglePartBase64: a non-multipart message with a base64 body.
func TestMIMESinglePartBase64(t *testing.T) {
	eml := "From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64Lines([]byte(mimeNeedle+"-SINGLE"))
	if res := Extract([]byte(eml), time.Time{}); !streamsContain(res, mimeNeedle+"-SINGLE") {
		t.Fatal("single-part base64 body not decoded")
	}
}

// TestMIMEPartCap (boundary): more than maxMIMEParts parts emit at most
// maxMIMEParts streams.
func TestMIMEPartCap(t *testing.T) {
	var parts []string
	for i := 0; i < maxMIMEParts+40; i++ {
		parts = append(parts, fmt.Sprintf("Content-Type: text/plain\r\n\r\npart body %04d\r\n", i))
	}
	res := Extract(emlWithParts(parts...), time.Time{})
	if n := len(res.Streams); n == 0 || n > maxMIMEParts {
		t.Fatalf("streams = %d, want 1..%d", n, maxMIMEParts)
	}
}

// TestMIMEMalformed: a truncated base64 part keeps its decoded prefix, base64
// with stray spaces still decodes, and a missing boundary or broken message
// neither panics nor emits garbage.
func TestMIMEMalformed(t *testing.T) {
	enc := b64Lines([]byte(mimeNeedle + "-TRUNCATED and some more trailing bytes"))
	truncated := emlWithParts("Content-Transfer-Encoding: base64\r\n\r\n" + enc[:len(enc)-12] + "!!\r\n")
	if res := Extract(truncated, time.Time{}); !streamsContain(res, mimeNeedle+"-TRUNCATED") {
		t.Error("truncated base64 part lost its prefix")
	}
	spaced := strings.ReplaceAll(b64Lines([]byte(mimeNeedle+"-SPACED")), "A", "A ")
	if res := Extract(emlWithParts("Content-Transfer-Encoding: base64\r\n\r\n"+spaced), time.Time{}); !streamsContain(res, mimeNeedle+"-SPACED") {
		t.Error("base64 with spaces not decoded")
	}
	noBoundary := "From: a@x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed\r\n\r\nbody\r\n"
	if res := Extract([]byte(noBoundary), time.Time{}); res.Panicked || len(res.Streams) != 0 {
		t.Errorf("no boundary: panicked=%v streams=%d", res.Panicked, len(res.Streams))
	}
	unterminated := emlWithParts(b64Part("a.bin", []byte(mimeNeedle+"-OPEN")))
	unterminated = unterminated[:len(unterminated)-len("--BOUND--\r\n")]
	if res := Extract(unterminated, time.Time{}); res.Panicked {
		t.Error("unterminated multipart panicked")
	}
}

// TestIsMIMEMessage: detection needs a header block with Content-Type plus
// another message header; prose and other formats are not messages.
func TestIsMIMEMessage(t *testing.T) {
	for in, want := range map[string]bool{
		"From: a@x\r\nContent-Type: text/plain\r\n\r\nhi":        true,
		"MIME-Version: 1.0\nContent-Type: text/plain\n\nhi":      true,
		"Content-Type: text/plain\r\n\r\nno other header":        false,
		"From: a@x\r\nSubject: s\r\n\r\nno content-type":         false,
		"Dear user,\nContent-Type: text/plain\nFrom: x\n\nprose": false,
		"From: a@x\r\nContent-Type: text/plain\r\nno blank line": false,
		"": false,
	} {
		if got := isMIMEMessage([]byte(in)); got != want {
			t.Errorf("isMIMEMessage(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestMIMENegativeControl: a raw zip still takes the zip path, and plain
// text is not treated as a message.
func TestMIMENegativeControl(t *testing.T) {
	zip := zipOfMembers(t, []string{"z.vbs"}, [][]byte{[]byte(mimeNeedle)})
	if res := Extract(zip, time.Time{}); res.IsMIME || !streamsContain(res, mimeNeedle) {
		t.Fatalf("raw zip: IsMIME=%v", res.IsMIME)
	}
	if res := Extract([]byte("just some text without headers"), time.Time{}); res.IsMIME {
		t.Fatal("plain text taken for a message")
	}
}
