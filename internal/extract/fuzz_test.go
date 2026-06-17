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
