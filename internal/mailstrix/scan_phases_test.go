package mailstrix

// AUD-M4a1/M4a2: direct tests for the helpers extracted from scanGeneration.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
	"github.com/myguard-labs/mailstrix/internal/mbazaar"
)

func TestRecordExtractMetricsFlags(t *testing.T) {
	type tc struct {
		name string
		res  extract.Result
		ctr  func(*Scanner) *atomic.Uint64
	}
	cases := []tc{
		{"doc", extract.Result{IsDoc: true}, func(s *Scanner) *atomic.Uint64 { return &s.exDocs }},
		{"encrypted", extract.Result{Encrypted: true}, func(s *Scanner) *atomic.Uint64 { return &s.exEncrypted }},
		{"failed", extract.Result{Failed: true}, func(s *Scanner) *atomic.Uint64 { return &s.exFailed }},
		{"panicked", extract.Result{Panicked: true}, func(s *Scanner) *atomic.Uint64 { return &s.exPanicked }},
		{"msi", extract.Result{IsMSI: true}, func(s *Scanner) *atomic.Uint64 { return &s.exMSI }},
		{"msg", extract.Result{IsMSG: true}, func(s *Scanner) *atomic.Uint64 { return &s.exMSG }},
		{"onenote", extract.Result{IsOneNote: true}, func(s *Scanner) *atomic.Uint64 { return &s.exOneNote }},
		{"archive", extract.Result{IsArchive: true}, func(s *Scanner) *atomic.Uint64 { return &s.exArchive }},
		{"archive-decrypted", extract.Result{DecryptedArchive: true}, func(s *Scanner) *atomic.Uint64 { return &s.exArchiveDecrypted }},
		{"ole-package", extract.Result{IsOLEPackage: true}, func(s *Scanner) *atomic.Uint64 { return &s.exOLEPackage }},
		{"lnk", extract.Result{IsLNK: true}, func(s *Scanner) *atomic.Uint64 { return &s.exLNK }},
		{"pdf", extract.Result{IsPDF: true}, func(s *Scanner) *atomic.Uint64 { return &s.exPDF }},
		{"rtf", extract.Result{IsRTF: true}, func(s *Scanner) *atomic.Uint64 { return &s.exRTF }},
		{"slk", extract.Result{IsSLK: true}, func(s *Scanner) *atomic.Uint64 { return &s.exSLK }},
		{"encoded-script", extract.Result{EncodedScript: true}, func(s *Scanner) *atomic.Uint64 { return &s.exEncodedScript }},
		{"docprops", extract.Result{HasDocProps: true}, func(s *Scanner) *atomic.Uint64 { return &s.exDocProps }},
		{"xlmfold", extract.Result{HasXLMFold: true}, func(s *Scanner) *atomic.Uint64 { return &s.exXLMFold }},
		{"decoded", extract.Result{DecodedStreams: 1}, func(s *Scanner) *atomic.Uint64 { return &s.exDecoded }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Scanner{}
			res := c.res
			s.recordExtractMetrics(&res)
			if got := c.ctr(s).Load(); got != 1 {
				t.Fatalf("counter = %d, want 1", got)
			}
			if s.exMacroDocs.Load() != 0 || s.exStreams.Load() != 0 {
				t.Fatalf("macro counters moved without streams")
			}
		})
	}
	// Negative control: an empty result moves nothing.
	s := &Scanner{}
	s.recordExtractMetrics(&extract.Result{})
	if s.exDocs.Load()+s.exArchive.Load()+s.exPDF.Load()+s.exDecoded.Load()+s.exMacroDocs.Load() != 0 {
		t.Fatal("empty result moved a counter")
	}
}

func TestRecordExtractMetricsStreams(t *testing.T) {
	s := &Scanner{}
	// 3 streams, 1 of them static-decode blobs: 2 macro streams.
	s.recordExtractMetrics(&extract.Result{Streams: [][]byte{{1}, {2}, {3}}, DecodedStreams: 1})
	if s.exMacroDocs.Load() != 1 || s.exStreams.Load() != 2 || s.exDecoded.Load() != 1 {
		t.Fatalf("macroDocs=%d streams=%d decoded=%d", s.exMacroDocs.Load(), s.exStreams.Load(), s.exDecoded.Load())
	}
	// Only decode blobs: not a macro document.
	s2 := &Scanner{}
	s2.recordExtractMetrics(&extract.Result{Streams: [][]byte{{1}}, DecodedStreams: 1})
	if s2.exMacroDocs.Load() != 0 || s2.exStreams.Load() != 0 {
		t.Fatal("decode-only streams counted as macro")
	}
}

func TestScanRecordsArchiveMetric(t *testing.T) {
	s := newScanner(t, writeRules(t, eicarRule))
	zipBytes := makePlainZIP(t, [][]byte{[]byte("hello")})
	if _, err := s.Scan(zipBytes, ScanMeta{}); err != nil {
		t.Fatal(err)
	}
	if s.exArchive.Load() != 1 {
		t.Fatalf("exArchive = %d, want 1 after scanning a zip", s.exArchive.Load())
	}
}

func newMBazaarScanner(t *testing.T, listed ...[]byte) *Scanner {
	t.Helper()
	dir := t.TempDir()
	csv := "# stub\n"
	for _, b := range listed {
		d := sha256.Sum256(b)
		csv += "x," + hex.EncodeToString(d[:]) + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "malwarebazaar.bin"), []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	c := mbazaar.New("k", 0, "http://127.0.0.1:1/", dir, func(string, ...any) {})
	t.Cleanup(c.Close)
	return &Scanner{mbazaar: c}
}

func TestMBazaarMatchesMIMEAttachments(t *testing.T) {
	att := []byte("attachment-bytes")
	whole := []byte("whole-envelope")
	s := newMBazaarScanner(t, att)
	// MIME: the attachments are hashed (duplicate attachment deduped), not buf.
	res := &extract.Result{TopType: extract.TopTypeMIME, MIMEAttachments: [][]byte{att, att}}
	ms, inc := s.mbazaarMatches(whole, res, time.Time{})
	if inc || len(ms) != 1 || ms[0].Rule != "MALWAREBAZAAR_MALWARE" || ms[0].Tags[0] != "malwarebazaar" {
		t.Fatalf("matches=%+v incomplete=%v", ms, inc)
	}
	d := sha256.Sum256(att)
	if ms[0].Meta["sha256"] != hex.EncodeToString(d[:]) {
		t.Fatalf("sha256 meta = %q", ms[0].Meta["sha256"])
	}
}

func TestMBazaarMatchesWholeBufAndNegative(t *testing.T) {
	whole := []byte("whole-file")
	s := newMBazaarScanner(t, whole)
	ms, inc := s.mbazaarMatches(whole, &extract.Result{}, time.Time{})
	if inc || len(ms) != 1 {
		t.Fatalf("non-MIME whole file: matches=%+v incomplete=%v", ms, inc)
	}
	// Non-MIME ignores attachments.
	ms, _ = s.mbazaarMatches([]byte("other"), &extract.Result{MIMEAttachments: [][]byte{whole}}, time.Time{})
	if len(ms) != 0 {
		t.Fatalf("attachments hashed for non-MIME: %+v", ms)
	}
	// Unlisted digest: no match.
	ms, inc = s.mbazaarMatches([]byte("clean"), &extract.Result{}, time.Time{})
	if inc || len(ms) != 0 {
		t.Fatalf("clean: %+v %v", ms, inc)
	}
}

func TestMBazaarMatchesDeadline(t *testing.T) {
	att := []byte("a")
	s := newMBazaarScanner(t, att)
	res := &extract.Result{TopType: extract.TopTypeMIME, MIMEAttachments: [][]byte{att}}
	ms, inc := s.mbazaarMatches(nil, res, time.Now().Add(-time.Second))
	if !inc || len(ms) != 0 {
		t.Fatalf("expired deadline: matches=%+v incomplete=%v", ms, inc)
	}
	// Future deadline is not incomplete.
	ms, inc = s.mbazaarMatches(nil, res, time.Now().Add(time.Hour))
	if inc || len(ms) != 1 {
		t.Fatalf("future deadline: matches=%+v incomplete=%v", ms, inc)
	}
}

func TestURLFeedMatchesBudgetExhausted(t *testing.T) {
	s := newURLhausScanner(t)
	defer s.Close()
	var logged int
	s.logf = func(string, ...any) { logged++ }
	buf := []byte(feedURLBody)
	streams := [][]byte{[]byte(feedURL2Body), []byte("third")}
	keys := [][16]byte{streamDedupKey(streams[0]), streamDedupKey(streams[1])}
	res := &extract.Result{Streams: streams}

	// Expired deadline: raw buf is still checked, streams are left unchecked.
	ms, inc := s.urlFeedMatches(buf, res, keys, streamDedupKey(buf), time.Now().Add(-time.Second))
	if !inc || len(ms) != 1 || ms[0].Meta["url"] != feedTestURL || logged != 1 {
		t.Fatalf("expired: matches=%+v incomplete=%v logged=%d", ms, inc, logged)
	}
	// No deadline: both buffers contribute, in order, and nothing is incomplete.
	ms, inc = s.urlFeedMatches(buf, res, keys, streamDedupKey(buf), time.Time{})
	if inc || len(ms) != 2 || ms[0].Meta["url"] != feedTestURL || ms[1].Meta["url"] != "http://other.example/payload.exe" {
		t.Fatalf("no deadline: matches=%+v incomplete=%v", ms, inc)
	}
}
