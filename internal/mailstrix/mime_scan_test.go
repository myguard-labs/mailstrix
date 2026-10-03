package mailstrix

import (
	"encoding/base64"
	"testing"
)

const mimeDropperRule = `rule MIME_DROPPER { strings: $a = "COR01-SCAN-NEEDLE" condition: $a }`

// TestScanEMLZipAttachment (COR-01): a script inside a base64 zip attachment
// of a whole .eml now matches, as it does for the raw zip.
func TestScanEMLZipAttachment(t *testing.T) {
	s := newScanner(t, writeRules(t, mimeDropperRule))
	defer s.Close()
	zip := makePlainZIP(t, [][]byte{[]byte(`WScript.Echo "COR01-SCAN-NEEDLE"`)})
	eml := "From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n" +
		"--B\r\nContent-Type: application/zip\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(zip) + "\r\n--B--\r\n"
	m, err := s.Scan([]byte(eml), ScanMeta{})
	if err != nil || !hasRule(m, "MIME_DROPPER") {
		t.Fatalf("matches=%v err=%v", m, err)
	}
}

// TestScanEMLClean (negative control): a clean message does not match.
func TestScanEMLClean(t *testing.T) {
	s := newScanner(t, writeRules(t, mimeDropperRule))
	defer s.Close()
	eml := "From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
	if m, err := s.Scan([]byte(eml), ScanMeta{}); err != nil || hasRule(m, "MIME_DROPPER") {
		t.Fatalf("matches=%v err=%v", m, err)
	}
}
