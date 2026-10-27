package ci_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// rarWalkOrderFixture is the committed mixed plaintext/encrypted RAR5 archive.
// buildRarWalkOrderFixture regenerates it byte for byte from
// fixture-encrypted-files.rar; set MAILSTRIX_WRITE_RAR_WALK_FIXTURE=1 to rewrite
// it after changing the builder.
const rarWalkOrderFixture = "../internal/extract/testdata/rar-walk-order-mixed.rar"

// rarWalkOrderPlain are the stored (method 0) plaintext members spliced around
// the encrypted members: one before the first, one between the first and the
// second, and one after the last.
var rarWalkOrderPlain = []struct{ name, body string }{
	{"before.txt", "mailstrix rar walk-order fixture: plaintext member BEFORE the encrypted members\n"},
	{"middle.txt", "mailstrix rar walk-order fixture: plaintext member BETWEEN encrypted members\n"},
	{"after.txt", "mailstrix rar walk-order fixture: plaintext member AFTER the encrypted members\n"},
}

func rar5Vint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func rar5ReadVint(b []byte, i int) (uint64, int) {
	var v uint64
	for shift := uint(0); i < len(b) && shift < 64; shift += 7 {
		c := b[i]
		i++
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i
		}
	}
	return 0, -1
}

type rar5Block struct {
	htype uint64
	data  uint64 // data-area size; zero for the fixture's directory entries
	raw   []byte
}

// rar5Blocks splits a RAR5 archive (signature excluded) into whole blocks:
// crc32, header-size vint, header, then the optional data area.
func rar5Blocks(t *testing.T, buf []byte) []rar5Block {
	t.Helper()
	var out []rar5Block
	for i := 8; i < len(buf); {
		start := i
		hsize, j := rar5ReadVint(buf, i+4)
		if j < 0 {
			t.Fatalf("bad header size at %d", i)
		}
		hdrEnd := j + int(hsize)
		htype, k := rar5ReadVint(buf, j)
		flags, k := rar5ReadVint(buf, k)
		if flags&0x01 != 0 {
			_, k = rar5ReadVint(buf, k)
		}
		var dsize uint64
		if flags&0x02 != 0 {
			dsize, k = rar5ReadVint(buf, k)
		}
		if k < 0 || hdrEnd > len(buf) || hdrEnd+int(dsize) > len(buf) {
			t.Fatalf("truncated block at %d", i)
		}
		i = hdrEnd + int(dsize)
		out = append(out, rar5Block{htype: htype, data: dsize, raw: buf[start:i]})
	}
	return out
}

// rar5StoredFile builds a deterministic RAR5 file block holding body uncompressed:
// file flags carry only the CRC32 (no mtime), method 0, Windows host, attrs 0x20.
func rar5StoredFile(name, body string) []byte {
	return rar5StoredFileFlags(name, body, 0)
}

// rar5StoredFileFlags is rar5StoredFile with explicit compression-info flags
// (0x40 is the per-file solid bit).
func rar5StoredFileFlags(name, body string, comp uint64) []byte {
	var hdr []byte
	hdr = append(hdr, rar5Vint(2)...)                 // htype: file
	hdr = append(hdr, rar5Vint(0x02)...)              // block flags: has data
	hdr = append(hdr, rar5Vint(uint64(len(body)))...) // data size
	hdr = append(hdr, rar5Vint(0x04)...)              // file flags: CRC32 present
	hdr = append(hdr, rar5Vint(uint64(len(body)))...) // unpacked size
	hdr = append(hdr, rar5Vint(0x20)...)              // attributes
	hdr = binary.LittleEndian.AppendUint32(hdr, crc32.ChecksumIEEE([]byte(body)))
	hdr = append(hdr, rar5Vint(comp)...) // compression info: method 0 (stored)
	hdr = append(hdr, rar5Vint(0)...)    // host OS: Windows
	hdr = append(hdr, rar5Vint(uint64(len(name)))...)
	hdr = append(hdr, name...)
	sized := append(rar5Vint(uint64(len(hdr))), hdr...)
	block := binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(sized))
	block = append(block, sized...)
	return append(block, body...)
}

// buildRarWalkOrderFixture splices the plaintext members around the three
// encrypted file blocks of fixture-encrypted-files.rar, keeping its signature,
// main header, directory entries, service block and end block. File order:
// before, enc1, middle, enc2, enc3, (directories), after.
func buildRarWalkOrderFixture(t *testing.T) []byte {
	t.Helper()
	enc := encryptedRARFixture(t)
	out := append([]byte(nil), enc[:8]...)
	files := 0
	for _, blk := range rar5Blocks(t, enc) {
		switch blk.htype {
		case 2:
			if blk.data == 0 {
				break // directory entry: not a member the walk scans
			}
			switch files {
			case 0:
				out = append(out, rar5StoredFile(rarWalkOrderPlain[0].name, rarWalkOrderPlain[0].body)...)
			case 1:
				out = append(out, rar5StoredFile(rarWalkOrderPlain[1].name, rarWalkOrderPlain[1].body)...)
			}
			files++
		case 5:
			out = append(out, rar5StoredFile(rarWalkOrderPlain[2].name, rarWalkOrderPlain[2].body)...)
		}
		out = append(out, blk.raw...)
	}
	if files != len(encryptedRARMembers) {
		t.Fatalf("encrypted fixture has %d file blocks, want %d", files, len(encryptedRARMembers))
	}
	return out
}

func rarWalkOrderFixtureBytes(t *testing.T) []byte {
	t.Helper()
	buf, err := os.ReadFile(rarWalkOrderFixture)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func countExactStream(streams [][]byte, want []byte) int {
	n := 0
	for _, s := range streams {
		if bytes.Equal(s, want) {
			n++
		}
	}
	return n
}

// TestRarWalkOrderFixtureIsReproducible pins the committed fixture to its builder.
func TestRarWalkOrderFixtureIsReproducible(t *testing.T) {
	built := buildRarWalkOrderFixture(t)
	if os.Getenv("MAILSTRIX_WRITE_RAR_WALK_FIXTURE") == "1" {
		if err := os.WriteFile(rarWalkOrderFixture, built, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := rarWalkOrderFixtureBytes(t); !bytes.Equal(got, built) {
		t.Fatalf("committed fixture (sha256 %x) differs from builder output (sha256 %x)",
			sha256.Sum256(got), sha256.Sum256(built))
	}
}

// TestRarWalkOrderPlaintextAfterEncryptedIsScanned (REL-RAR-WALK-ORDER): once the
// password is cracked at the first encrypted member, every plaintext member is
// still scanned exactly once: the ones before it by the first walk, the ones
// between and after the encrypted members by the password re-walk.
func TestRarWalkOrderPlaintextAfterEncryptedIsScanned(t *testing.T) {
	got := extract.ExtractWithOptions(rarWalkOrderFixtureBytes(t), rarOptions(time.Time{}, "wrong-password", "test"))
	for _, m := range rarWalkOrderPlain {
		if n := countExactStream(got.Streams, []byte(m.body)); n != 1 {
			t.Errorf("plaintext member %s emitted %d times, want once", m.name, n)
		}
	}
	assertRARMembers(t, got)
	if got.Failed || got.Panicked || len(got.CapHits) != 0 {
		t.Fatalf("mixed RAR walk: failed=%v panicked=%v caps=%v", got.Failed, got.Panicked, got.CapHits)
	}
}

// TestRarWalkOrderWithoutPasswordScansEveryPlaintext is the no-crack control: the
// single walk scans every plaintext member once and keeps the encrypted tell.
func TestRarWalkOrderWithoutPasswordScansEveryPlaintext(t *testing.T) {
	for name, opts := range map[string]*extract.Options{
		"no-candidates":  rarOptions(time.Time{}),
		"wrong-password": rarOptions(time.Time{}, "wrong-password"),
	} {
		t.Run(name, func(t *testing.T) {
			got := extract.ExtractWithOptions(rarWalkOrderFixtureBytes(t), opts)
			for _, m := range rarWalkOrderPlain {
				if n := countExactStream(got.Streams, []byte(m.body)); n != 1 {
					t.Errorf("plaintext member %s emitted %d times, want once", m.name, n)
				}
			}
			if len(got.Streams) != len(rarWalkOrderPlain) {
				t.Errorf("emitted %d streams, want only the %d plaintext members", len(got.Streams), len(rarWalkOrderPlain))
			}
			if !got.EncryptedArchive || got.DecryptedArchive || !hasRARMarker(got.Markers, "ARCHIVE-ENCRYPTED") {
				t.Fatalf("encrypted tell: encrypted=%v decrypted=%v markers=%q", got.EncryptedArchive, got.DecryptedArchive, got.Markers)
			}
		})
	}
}

// TestRarWalkOrderFixtureLayout guards the fixture itself: the plaintext members
// really sit before, between and after the encrypted file blocks.
func TestRarWalkOrderFixtureLayout(t *testing.T) {
	var order []string
	for _, blk := range rar5Blocks(t, rarWalkOrderFixtureBytes(t)) {
		if blk.htype != 2 || blk.data == 0 {
			continue
		}
		kind := "enc"
		for _, m := range rarWalkOrderPlain {
			if bytes.HasSuffix(blk.raw, []byte(m.body)) {
				kind = m.name
			}
		}
		order = append(order, kind)
	}
	if got := fmt.Sprint(order); got != "[before.txt enc middle.txt enc enc after.txt]" {
		t.Fatalf("file block order = %s", got)
	}
}

// rarWithFiles wraps file blocks in fixture-encrypted-files.rar's signature,
// non-solid main header and end block.
func rarWithFiles(t *testing.T, files ...[]byte) []byte {
	t.Helper()
	enc := encryptedRARFixture(t)
	out := append([]byte(nil), enc[:8]...)
	for _, blk := range rar5Blocks(t, enc) {
		switch blk.htype {
		case 1:
			out = append(out, blk.raw...)
		case 5:
			for _, f := range files {
				out = append(out, f...)
			}
			out = append(out, blk.raw...)
		}
	}
	return out
}

// TestRarPerMemberSolidIsIncomplete (REL-RAR-SOLID-INCOMPLETE): a member whose
// per-file solid flag is set in an archive whose main header is not solid is
// refused undecoded; the refusal must surface as the rar-solid cap hit and its
// PURE marker, while the plaintext member before it is still scanned.
func TestRarPerMemberSolidIsIncomplete(t *testing.T) {
	first := rarWalkOrderPlain[0]
	solidBody := "mailstrix per-member solid fixture body\n"
	for name, tc := range map[string]struct {
		comp uint64
		want bool
	}{
		"per-file-solid": {0x40, true},
		"control":        {0, false},
	} {
		t.Run(name, func(t *testing.T) {
			buf := rarWithFiles(t, rar5StoredFile(first.name, first.body), rar5StoredFileFlags("solid.txt", solidBody, tc.comp))
			got := extract.Extract(buf, time.Time{})
			if countExactStream(got.Streams, []byte(first.body)) != 1 {
				t.Fatalf("plaintext member before the solid one was not scanned once: %q", got.Streams)
			}
			hit := false
			for _, k := range got.CapHits {
				hit = hit || k == "rar-solid"
			}
			marker := hasRARMarker(got.Markers, "EXTRACT-CAP-HIT kind=rar-solid")
			scanned := countExactStream(got.Streams, []byte(solidBody)) == 1
			if hit != tc.want || marker != tc.want || scanned == tc.want {
				t.Fatalf("cap hit=%v marker=%v solid body scanned=%v; want refusal=%v (CapHits=%v)", hit, marker, scanned, tc.want, got.CapHits)
			}
		})
	}
}
