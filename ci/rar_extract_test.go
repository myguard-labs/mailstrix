package ci_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// TestEncryptedRARExtractWithOptions exercises the public scanner boundary,
// including the final split of payload streams and synthetic markers. The
// existing #384 fixture is reused unchanged; no RAR writer is needed.
func TestEncryptedRARExtractWithOptions(t *testing.T) {
	fixture, err := os.ReadFile("../internal/extract/testdata/fixture-encrypted.rar")
	if err != nil {
		t.Fatal(err)
	}
	// Pin the KDF candidate cap at the public boundary: the last allowed
	// candidate succeeds, while the first candidate beyond the cap cannot run.
	const kdfCap = 16
	boundary := make([]string, kdfCap)
	for i := range boundary {
		boundary[i] = "wrong-password"
	}
	beyond := append(append([]string(nil), boundary...), "fixture-password")
	boundary[kdfCap-1] = "fixture-password"

	cases := []struct {
		name       string
		buf        []byte
		candidates []string
		disabled   bool
		expired    bool
		decrypted  bool
		encrypted  bool
	}{
		{name: "correct", buf: fixture, candidates: []string{"fixture-password"}, decrypted: true},
		{name: "wrong-then-correct", buf: fixture, candidates: []string{"wrong-password", "fixture-password"}, decrypted: true},
		{name: "wrong", buf: fixture, candidates: []string{"wrong-password"}, encrypted: true},
		{name: "absent-candidates", buf: fixture, encrypted: true},
		{name: "disabled", buf: fixture, candidates: []string{"fixture-password"}, disabled: true, encrypted: true},
		{name: "kdf-last-allowed", buf: fixture, candidates: boundary, decrypted: true},
		{name: "kdf-exhausted", buf: fixture, candidates: beyond, encrypted: true},
		{name: "expired-deadline", buf: fixture, candidates: []string{"fixture-password"}, expired: true},
		{name: "truncated", buf: fixture[:100], candidates: []string{"fixture-password"}, encrypted: true},
		{name: "malformed", buf: append(append([]byte(nil), fixture[:8]...), []byte("malformed RAR header")...), candidates: []string{"fixture-password"}},
		{name: "nil", candidates: []string{"fixture-password"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := extract.FullOptions(time.Now().Add(time.Minute))
			opts.ArchivePWEnabled = !tc.disabled
			opts.PWCandidates = tc.candidates
			if tc.expired {
				opts.Deadline = time.Now().Add(-time.Minute)
			}
			res := extract.ExtractWithOptions(tc.buf, opts)
			if res.Panicked || res.Failed {
				t.Fatalf("public extraction failed: panicked=%v failed=%v", res.Panicked, res.Failed)
			}
			if res.DecryptedArchive != tc.decrypted || res.EncryptedArchive != tc.encrypted {
				t.Fatalf("archive flags: decrypted=%v encrypted=%v, want %v/%v", res.DecryptedArchive, res.EncryptedArchive, tc.decrypted, tc.encrypted)
			}
			wantMembers := [][]byte{
				[]byte("hello from mailstrix encrypted rar fixture\n"),
				[]byte("second plaintext member for listing\n"),
			}
			if tc.decrypted {
				if !res.IsArchive || res.TopType != extract.TopTypeArchive {
					t.Fatalf("decrypted RAR not recognised as archive: %+v", res)
				}
				if len(res.Streams) != len(wantMembers) {
					t.Fatalf("emitted %d members, want %d", len(res.Streams), len(wantMembers))
				}
				for i, want := range wantMembers {
					if !bytes.Equal(res.Streams[i], want) {
						t.Errorf("member %d: got %q, want %q", i, res.Streams[i], want)
					}
				}
			} else if len(res.Streams) != 0 {
				t.Fatalf("rejected RAR emitted payload streams: %q", res.Streams)
			}
			var wantMarkers [][]byte
			if tc.decrypted {
				wantMarkers = append(wantMarkers, []byte("ARCHIVE-DECRYPTED"))
			}
			if tc.encrypted {
				wantMarkers = append(wantMarkers, []byte("ARCHIVE-ENCRYPTED"))
			}
			if len(res.Markers) != len(wantMarkers) {
				t.Fatalf("markers: got %q, want %q", res.Markers, wantMarkers)
			}
			for i, want := range wantMarkers {
				if !bytes.Equal(res.Markers[i], want) {
					t.Errorf("marker %d: got %q, want %q", i, res.Markers[i], want)
				}
			}
		})
	}
}
