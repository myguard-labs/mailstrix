package extract

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FuzzExtract drives the OLE2/OOXML parsers with arbitrary bytes. Extract parses
// fully attacker-controlled binary (a mail attachment), so the invariant is
// strong: it must NEVER panic out, NEVER hang, and always return a self-
// consistent Result — Encrypted implies no streams, !IsDoc implies no streams,
// every stream non-empty. A crash here is a remote DoS on the scan path.
func FuzzExtract(f *testing.F) {
	// Seed with the real macro doc, the magics, and structurally interesting
	// near-misses so the fuzzer starts from valid-ish containers, not just noise.
	if buf, err := os.ReadFile(filepath.Join("testdata", "xlswithmacro.xlsm")); err == nil {
		f.Add(buf)
	}
	f.Add(append(append([]byte{}, oleMagic...), bytes.Repeat([]byte{0x00}, 512)...))
	f.Add(append(append([]byte{}, zipMagic...), bytes.Repeat([]byte{0xFF}, 64)...))
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	if w, err := zw.Create("xl/vbaProject.bin"); err == nil {
		_, _ = w.Write(append(append([]byte{}, oleMagic...), 0x01, 0x02, 0x03))
	}
	_ = zw.Close()
	f.Add(z.Bytes())
	// Archive magics (gz/7z/rar) followed by junk — exercise the nested-archive
	// decompressors' fail-open paths.
	f.Add(append(append([]byte{}, gzipMagic...), bytes.Repeat([]byte{0xFF}, 64)...))
	f.Add(append(append([]byte{}, sevenZMagic...), bytes.Repeat([]byte{0xAA}, 128)...))
	f.Add(append(append([]byte{}, rarMagic...), bytes.Repeat([]byte{0x55}, 128)...))
	// OLE2 magic + a truncated Ole10Native-shaped tail — fuzz the package field
	// walk's bounds checks on hostile/short input.
	f.Add(append(append([]byte{}, oleMagic...),
		[]byte{0x10, 0, 0, 0, 0x02, 0, 'a', 0, 'b', 0, 0, 0, 0, 0}...))
	// .lnk magic + flags claiming IDList/LinkInfo/Arguments then junk — fuzz the
	// SHLLINK section walk and StringData bounds checks.
	{
		h := make([]byte, lnkHeaderSize)
		copy(h, lnkMagic)
		h[lnkFlagsOff] = byte(lnkHasLinkTargetIDList | lnkHasLinkInfo | lnkHasArguments | lnkIsUnicode)
		f.Add(append(h, bytes.Repeat([]byte{0xFF}, 32)...))
	}
	// PDF magic + a stream keyword without endstream — fuzz the carve/inflate loop.
	f.Add([]byte("%PDF-1.7\nobj\nstream\n\x78\x9c\x00\x00 garbage no endstream"))
	// RTF with an \objdata group of odd-length/garbage hex — fuzz the hex decoder
	// and the fromRTF group-scan bounds (must terminate, never over-read).
	f.Add([]byte("{\\rtf1{\\object{\\*\\objdata d0cf11e0 a1b11ae1 zz}}}"))
	// A valid minimal ISO9660 image plus a truncated one (header only) — fuzz the
	// directory-extent walk's bounds/cycle guards on hostile LBAs.
	f.Add(buildISO("DROP.EXE;1", []byte("MZ iso member"), false))
	{
		iso := make([]byte, (isoSystemArea+1)*isoSectorSize)
		iso[isoSystemArea*isoSectorSize] = isoVDPrimary
		copy(iso[isoSystemArea*isoSectorSize+1:], isoMagic)
		f.Add(iso)
	}
	// A valid minimal UDF image (embedded + short_ad data) plus a truncated one —
	// fuzz the anchor/descriptor resolve and the FID/allocation-descriptor walk's
	// bounds guards on hostile logical blocks and extent lengths.
	f.Add(buildUDF("DROP.EXE", []byte("MZ udf member"), false))
	f.Add(buildUDF("RUN.JS", []byte("udf extent member"), true))
	{
		udf := make([]byte, 20*udfSectorSize)
		copy(udf[16*udfSectorSize+1:], "NSR02")
		f.Add(udf)
	}
	f.Add([]byte{})
	f.Add([]byte("plain text"))

	f.Fuzz(func(t *testing.T, buf []byte) {
		res := Extract(buf, time.Time{}) // must not panic, must terminate

		if !res.IsDoc && (len(res.Streams) > 0 || res.Failed || res.Encrypted) {
			t.Fatalf("non-doc with side effects: %+v (len=%d)", flags(res), len(buf))
		}
		if res.Encrypted && len(res.Streams) > 0 {
			t.Fatalf("encrypted doc also returned %d streams", len(res.Streams))
		}
		for i, s := range res.Streams {
			if len(s) == 0 {
				t.Fatalf("empty stream at %d", i)
			}
		}
		if len(res.Streams) > maxStreams {
			t.Fatalf("returned %d streams > cap %d", len(res.Streams), maxStreams)
		}
	})
}
