package mbazaar

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// fuzzMaxDecompressed is the cap used inside fuzz targets. It is much lower than
// the production 1 GiB so the CSV-parse loop terminates in finite time and the
// fuzz worker does not OOM on a crafted zip entry that claims a plausible but
// large UncompressedSize64.
const fuzzMaxDecompressed = 1 << 20 // 1 MiB

// FuzzParseFeed drives parseFeed (→ openCSV → CSV parse) with arbitrary bytes.
// parseFeed accepts fully attacker-influenced data (a downloaded feed file) and
// dispatches on magic: ZIP path or plain-CSV path. Invariants:
//   - never panic
//   - on success the returned set is non-nil and len ≤ maxHashes
func FuzzParseFeed(f *testing.F) {
	// Lower the decompression cap for fuzz workers. Must happen before f.Fuzz
	// so both the seed-corpus runs and the generated runs see the lowered value.
	orig := maxDecompressedBytes
	maxDecompressedBytes = fuzzMaxDecompressed
	f.Cleanup(func() { maxDecompressedBytes = orig })

	// Plain CSV seeds.
	f.Add([]byte(""))
	f.Add([]byte("# comment\n"))
	f.Add([]byte("first_seen,sha256,md5,sha1,reporter,file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh\n"))
	// Row with valid SHA256 in col 1.
	f.Add([]byte("2024-01-01," + strings.Repeat("a", 64) + ",md5,sha1,reporter,name,exe,app/exe,,,,,,\n"))
	// Row with valid SHA256 only in a fallback column.
	f.Add([]byte("garbage," + strings.Repeat("b", 64) + "\n"))
	// Many rows — exercises maxHashes break.
	var many bytes.Buffer
	for i := 0; i < 10; i++ {
		var h [32]byte
		h[0] = byte(i)
		many.WriteString("," + hex.EncodeToString(h[:]) + "\n")
	}
	f.Add(many.Bytes())
	// ZIP with a plain CSV inside (the real dump format).
	f.Add(buildZipCSV([]byte("," + strings.Repeat("c", 64) + "\n")))
	// ZIP magic + garbage.
	f.Add(append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0xAA}, 128)...))
	// ZIP with an entry whose UncompressedSize64 exceeds the fuzz cap (bomb guard).
	f.Add(buildOversizedZip(fuzzMaxDecompressed))
	// Binary junk.
	f.Add(bytes.Repeat([]byte{0xFF}, 256))
	f.Add([]byte("\x00\x01\x02\x03"))

	f.Fuzz(func(t *testing.T, body []byte) {
		hs, err := parseFeed(body)
		if err != nil {
			return // errors are expected; just must not panic
		}
		if hs == nil {
			t.Fatal("parseFeed returned nil hashSet with nil error")
		}
		if len(hs.m) > maxHashes {
			t.Fatalf("hashSet size %d > maxHashes %d", len(hs.m), maxHashes)
		}
	})
}

// FuzzOpenCSV drives the ZIP/plain-CSV dispatcher in isolation.
// Invariant: never panic; when successful, the returned ReadCloser must be
// readable without blocking (bounded by the LimitReader in parseFeed's caller;
// here we drain with a small local limit to avoid OOM on crafted zip entries).
func FuzzOpenCSV(f *testing.F) {
	orig := maxDecompressedBytes
	maxDecompressedBytes = fuzzMaxDecompressed
	f.Cleanup(func() { maxDecompressedBytes = orig })

	f.Add([]byte(""))
	f.Add([]byte("plain,csv,row\n"))
	f.Add(buildZipCSV([]byte("plain,csv,row\n")))
	f.Add(append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0xBB}, 64)...))
	f.Add([]byte("PK\x03\x04\x00\x00"))
	f.Add(buildOversizedZip(fuzzMaxDecompressed))

	f.Fuzz(func(t *testing.T, body []byte) {
		rc, err := openCSV(body)
		if err != nil {
			return
		}
		defer func() { _ = rc.Close() }()
		buf := make([]byte, 512)
		rc.Read(buf) //nolint:errcheck // just must not panic
	})
}

// buildZipCSV creates a minimal valid ZIP containing one file with the given
// CSV bytes — matches the real MalwareBazaar dump format.
func buildZipCSV(csv []byte) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create("full_sha256.csv")
	w.Write(csv) //nolint:errcheck
	zw.Close()   //nolint:errcheck
	return b.Bytes()
}

// buildOversizedZip creates a ZIP where the sole entry claims a decompressed
// size larger than cap to exercise the bomb-guard skip path in openCSV.
func buildOversizedZip(cap int64) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	fh := &zip.FileHeader{
		Name:               "bomb.csv",
		Method:             zip.Deflate,
		UncompressedSize64: uint64(cap) + 1,
	}
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("x")) //nolint:errcheck
	zw.Close()           //nolint:errcheck
	return b.Bytes()
}
