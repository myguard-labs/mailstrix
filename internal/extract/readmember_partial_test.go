package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// partialNeedle is the payload marker a corrupted member must still deliver.
const partialNeedle = "COR06-PARTIAL-MEMBER-PAYLOAD"

func partialPayload() []byte {
	return []byte("WScript.Echo \"" + partialNeedle + "\"\r\n" + strings.Repeat("x", 4096))
}

// storedZipBadCRC builds a one-member stored zip whose central-directory CRC
// is wrong, so archive/zip reads every byte and then returns ErrChecksum.
func storedZipBadCRC(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	cd := bytes.LastIndex(out, []byte{0x50, 0x4b, 0x01, 0x02})
	if cd < 0 {
		t.Fatal("no central directory")
	}
	crc := binary.LittleEndian.Uint32(out[cd+16:])
	binary.LittleEndian.PutUint32(out[cd+16:], crc^0xdeadbeef)
	return out
}

// TestReadMemberBadCRCZipDelivered (COR-06): a zip member whose CRC does not
// match is still scanned, as unzip would deliver it.
func TestReadMemberBadCRCZipDelivered(t *testing.T) {
	buf := storedZipBadCRC(t, "drop.vbs", partialPayload())
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("precondition: want ErrChecksum, got %v", err)
	}
	if res := Extract(buf, time.Time{}); !streamsContain(res, partialNeedle) {
		t.Fatalf("bad-CRC zip member dropped; streams=%d", len(res.Streams))
	}
}

// TestReadMemberTruncatedGzipDelivered: a gzip whose 8-byte trailer is cut
// off still yields its decompressed body.
func TestReadMemberTruncatedGzipDelivered(t *testing.T) {
	full := buildGzip(t, partialPayload())
	truncated := full[:len(full)-8]
	gr, err := gzip.NewReader(bytes.NewReader(truncated))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(gr); err == nil {
		t.Fatal("precondition: truncated gzip read without error")
	}
	if res := Extract(truncated, time.Time{}); !streamsContain(res, partialNeedle) {
		t.Fatalf("truncated gzip body dropped; streams=%d", len(res.Streams))
	}
}

// TestReadMemberTruncatedTarDelivered: a .tar.gz whose tar member is cut
// short mid-data still delivers the bytes present (tar is only walked inside
// gzip).
func TestReadMemberTruncatedTarDelivered(t *testing.T) {
	data := partialPayload()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "drop.vbs", Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	truncated := buildGzip(t, b.Bytes()[:512+len(data)/2]) // header + half the member
	if res := Extract(truncated, time.Time{}); !streamsContain(res, partialNeedle) {
		t.Fatalf("truncated tar member dropped; streams=%d", len(res.Streams))
	}
}

// TestReadZipEntryBadCRCDelivered: the OOXML/vbaProject.bin reader keeps the
// bytes of a CRC-mismatched entry too.
func TestReadZipEntryBadCRCDelivered(t *testing.T) {
	buf := storedZipBadCRC(t, "word/vbaProject.bin", partialPayload())
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	if got := readZipEntry(zr.File[0]); !bytes.Contains(got, []byte(partialNeedle)) {
		t.Fatalf("readZipEntry dropped bad-CRC entry: %d bytes", len(got))
	}
}

type failingReader struct{ data []byte }

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// TestReadMemberErrorBoundary: an error after output keeps the output; an
// error with no output (malformed member) stays nil; a clean empty member is
// still non-error empty; the size cap still holds.
func TestReadMemberErrorBoundary(t *testing.T) {
	if got := readMember(&failingReader{data: []byte("ab")}, 0); string(got) != "ab" {
		t.Fatalf("partial: got %q", got)
	}
	if got := readMember(&failingReader{}, 0); got != nil {
		t.Fatalf("error with no output: got %q, want nil", got)
	}
	if got := readMember(bytes.NewReader(nil), 0); len(got) != 0 {
		t.Fatalf("clean empty member: got %q", got)
	}
	big := &failingReader{data: bytes.Repeat([]byte("a"), maxBytesPerMember+10)}
	if got := readMember(big, 0); len(got) != maxBytesPerMember {
		t.Fatalf("cap: got %d bytes, want %d", len(got), maxBytesPerMember)
	}
}

// TestReadMemberIntactZipControl: an intact zip is unchanged (negative control).
func TestReadMemberIntactZipControl(t *testing.T) {
	res := Extract(buildZip(t, map[string][]byte{"drop.vbs": partialPayload()}), time.Time{})
	if !streamsContain(res, partialNeedle) {
		t.Fatal("intact zip member missing")
	}
}
