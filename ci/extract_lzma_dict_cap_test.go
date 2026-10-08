package ci_test

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"runtime"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/ulikunitz/xz/lzma"

	"github.com/myguard-labs/mailstrix/internal/extract"
)

// AUD-17: the 7z LZMA dictionary is bounded at 8 MiB (internal/extract/lzmacap.go).
// The archives are built in-process: 7-Zip cannot be told to declare a 1 GiB
// dictionary over a tiny payload, and the test must not depend on /usr/bin/7z.

const lzmaCeiling = 8 << 20

// sevenNum encodes v as a 7z NUMBER in its widest form (0xFF + 8 LE bytes).
func sevenNum(v uint64) []byte {
	return binary.LittleEndian.AppendUint64([]byte{0xFF}, v)
}

// lzmaRaw LZMA-encodes data (small real dictionary) and returns the raw stream
// without the 13-byte .lzma header plus the lc/lp/pb properties byte.
func lzmaRaw(t *testing.T, data []byte) (stream []byte, propsByte byte) {
	t.Helper()
	var b bytes.Buffer
	w, err := lzma.WriterConfig{DictCap: 4096, Size: int64(len(data)), SizeInHeader: true}.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()[13:], b.Bytes()[0]
}

// build7z returns a one-file 7z whose LZMA coder declares props verbatim and
// unpack size n, with stream as the packed data.
func build7z(stream, props []byte, n uint64) []byte {
	return wrap7z(stream, plain7zHeader(stream, props, n))
}

// plain7zHeader returns the (unencoded) Header block for build7z.
func plain7zHeader(stream, props []byte, n uint64) []byte {
	var h bytes.Buffer
	h.Write([]byte{0x01, 0x04})                   // Header, MainStreamsInfo
	h.Write([]byte{0x06, 0x00, 0x01, 0x09})       // PackInfo: pos 0, 1 stream, Size
	h.Write(sevenNum(uint64(len(stream))))        //
	h.Write([]byte{0x00})                         // end PackInfo
	h.Write([]byte{0x07, 0x0B, 0x01, 0x00})       // UnpackInfo, Folder, 1 folder, not external
	h.Write([]byte{0x01, 0x23, 0x03, 0x01, 0x01}) // 1 coder, id size 3 + props, LZMA
	h.Write(sevenNum(uint64(len(props))))         //
	h.Write(props)                                //
	h.Write([]byte{0x0C})                         // CodersUnpackSize
	h.Write(sevenNum(n))                          //
	h.Write([]byte{0x00, 0x00})                   // end UnpackInfo, end StreamsInfo
	name := utf16.Encode([]rune("a.txt\x00"))     //
	nb := []byte{0x00}                            // external = 0
	for _, u := range name {                      //
		nb = binary.LittleEndian.AppendUint16(nb, u) //
	} //
	h.Write([]byte{0x05, 0x01, 0x11})  // FilesInfo, 1 file, Names
	h.Write(sevenNum(uint64(len(nb)))) //
	h.Write(nb)                        //
	h.Write([]byte{0x00, 0x00})        // end FilesInfo, end Header
	return h.Bytes()
}

// wrap7z lays out signature header + packed streams + trailing header block.
func wrap7z(stream, hdr []byte) []byte {
	start := make([]byte, 20)
	binary.LittleEndian.PutUint64(start[0:], uint64(len(stream)))
	binary.LittleEndian.PutUint64(start[8:], uint64(len(hdr)))
	binary.LittleEndian.PutUint32(start[16:], crc32.ChecksumIEEE(hdr))
	var out bytes.Buffer
	out.Write([]byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4})
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], crc32.ChecksumIEEE(start))
	out.Write(c[:])
	out.Write(start)
	out.Write(stream)
	out.Write(hdr)
	return out.Bytes()
}

func lzmaProps(pb byte, dict uint32) []byte {
	p := make([]byte, 5)
	p[0] = pb
	binary.LittleEndian.PutUint32(p[1:], dict)
	return p
}

// lzma7z builds an archive for payload declaring dictionary dict.
func lzma7z(t *testing.T, payload []byte, dict uint32) []byte {
	t.Helper()
	stream, pb := lzmaRaw(t, payload)
	return build7z(stream, lzmaProps(pb, dict), uint64(len(payload)))
}

func hasStopKind(res extract.Result, kind string) bool { return capHasHit(res, kind) }

func hasStreamWith(res extract.Result, needle []byte) bool {
	for _, s := range res.Streams {
		if bytes.Contains(s, needle) {
			return true
		}
	}
	return false
}

func zerosWithMarker(n int, marker string) []byte {
	b := bytes.Repeat([]byte("A"), n)
	copy(b[n-len(marker):], marker)
	return b
}

func TestLZMADictCapPositive(t *testing.T) {
	t.Run("small dict small member extracts and scans", func(t *testing.T) {
		payload := []byte("LZMA-MARKER-small\n")
		res := extract.ExtractWithOptions(lzma7z(t, payload, 1<<16), extract.FullOptions(time.Time{}))
		if !hasStreamWith(res, []byte("LZMA-MARKER-small")) || hasStopKind(res, "lzma-dict") {
			t.Fatalf("streams=%d caps=%v", len(res.Streams), res.CapHits)
		}
	})
	t.Run("huge declared dict but unpack below ceiling is safe", func(t *testing.T) {
		// effective dictionary is min(declared, unpack): 64 KiB, so 1 GiB declared is harmless.
		payload := zerosWithMarker(64<<10, "LZMA-MARKER-clamp")
		res := extract.ExtractWithOptions(lzma7z(t, payload, 1<<30), extract.FullOptions(time.Time{}))
		if !hasStreamWith(res, []byte("LZMA-MARKER-clamp")) || hasStopKind(res, "lzma-dict") {
			t.Fatalf("streams=%d caps=%v", len(res.Streams), res.CapHits)
		}
	})
}

func TestLZMADictCapBoundary(t *testing.T) {
	defer extract.SetDecryptAttemptTimeForTest(time.Minute)()
	payload := zerosWithMarker(10<<20, "LZMA-MARKER-edge")
	t.Run("dict exactly at ceiling with larger unpack extracts", func(t *testing.T) {
		res := extract.ExtractWithOptions(lzma7z(t, payload, lzmaCeiling), extract.FullOptions(time.Time{}))
		if !hasStreamWith(res, []byte("LZMA-MARKER-edge")) || hasStopKind(res, "lzma-dict") {
			t.Fatalf("streams=%d caps=%v", len(res.Streams), res.CapHits)
		}
	})
	t.Run("one byte over ceiling with larger unpack is a cap stop", func(t *testing.T) {
		res := extract.ExtractWithOptions(lzma7z(t, payload, lzmaCeiling+1), extract.FullOptions(time.Time{}))
		if !hasStopKind(res, "lzma-dict") || hasStreamWith(res, []byte("LZMA-MARKER-edge")) {
			t.Fatalf("streams=%d caps=%v", len(res.Streams), res.CapHits)
		}
	})
	t.Run("one byte over ceiling but unpack at ceiling extracts", func(t *testing.T) {
		p := zerosWithMarker(lzmaCeiling, "LZMA-MARKER-eq")
		res := extract.ExtractWithOptions(lzma7z(t, p, lzmaCeiling+1), extract.FullOptions(time.Time{}))
		if !hasStreamWith(res, []byte("LZMA-MARKER-eq")) || hasStopKind(res, "lzma-dict") {
			t.Fatalf("streams=%d caps=%v", len(res.Streams), res.CapHits)
		}
	})
}

func TestLZMADictCapMalicious(t *testing.T) {
	defer extract.SetDecryptAttemptTimeForTest(time.Minute)()
	payload := zerosWithMarker(12<<20, "LZMA-MARKER-evil")
	arc := lzma7z(t, payload, 1<<30) // 1 GiB declared, ~100 byte payload
	if len(arc) > 4096 {
		t.Fatalf("fixture not tiny: %d", len(arc))
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	res := extract.ExtractWithOptions(arc, extract.FullOptions(time.Time{}))
	runtime.ReadMemStats(&m1)
	// TotalAlloc is cumulative, so any eager 1 GiB dictionary shows up even if freed.
	if d := m1.TotalAlloc - m0.TotalAlloc; d > 256<<20 {
		t.Fatalf("allocated %d MiB for a %d byte archive", d>>20, len(arc))
	}
	if !hasStopKind(res, "lzma-dict") {
		t.Fatalf("not reported as a cap stop: caps=%v", res.CapHits)
	}
	if hasStreamWith(res, []byte("LZMA-MARKER-evil")) {
		t.Fatal("refused member still produced a stream")
	}
}

func TestLZMADictCapMalformedProps(t *testing.T) {
	stream, pb := lzmaRaw(t, []byte("LZMA-MARKER-bad"))
	for name, props := range map[string][]byte{
		"empty":        {},
		"short":        {pb, 0, 0, 1},
		"long":         append(lzmaProps(pb, 1<<16), 0),
		"bad lc/lp/pb": lzmaProps(225, 1<<16),
		"zero dict":    lzmaProps(pb, 0),
	} {
		t.Run(name, func(t *testing.T) {
			res := extract.ExtractWithOptions(build7z(stream, props, 15), extract.FullOptions(time.Time{}))
			if name != "zero dict" && hasStreamWith(res, []byte("LZMA-MARKER-bad")) {
				t.Fatal("malformed props produced a stream")
			}
			if hasStopKind(res, "lzma-dict") {
				t.Fatalf("malformed props misreported as dict cap: %v", res.CapHits)
			}
		})
	}
}

// encoded7z builds a 7z whose Header is stored as a kEncodedHeader (id 0x17): the
// real header is LZMA-compressed into a second packed stream and the trailing block
// is a StreamsInfo declaring hdrProps and hdrUnpack for it. When hdrStream is nil the
// real header is compressed with a small dictionary (valid archive); otherwise
// hdrStream is used verbatim (the declared sizes need not match it).
func encoded7z(t *testing.T, payload []byte, hdrStream, hdrProps []byte, hdrUnpack uint64) []byte {
	t.Helper()
	stream, pb := lzmaRaw(t, payload)
	real := plain7zHeader(stream, lzmaProps(pb, 1<<16), uint64(len(payload)))
	if hdrStream == nil {
		var hpb byte
		hdrStream, hpb = lzmaRaw(t, real)
		hdrProps = lzmaProps(hpb, 1<<16)
		hdrUnpack = uint64(len(real))
	}
	var e bytes.Buffer
	e.Write([]byte{0x17, 0x06})               // EncodedHeader, PackInfo
	e.Write(sevenNum(uint64(len(stream))))    // pack position: after the member stream
	e.Write([]byte{0x01, 0x09})               // 1 stream, Size
	e.Write(sevenNum(uint64(len(hdrStream)))) //
	e.Write([]byte{0x00})                     // end PackInfo
	e.Write([]byte{0x07, 0x0B, 0x01, 0x00})   // UnpackInfo, Folder, 1 folder, not external
	e.Write([]byte{0x01, 0x23, 0x03, 0x01, 0x01})
	e.Write(sevenNum(uint64(len(hdrProps))))
	e.Write(hdrProps)
	e.Write([]byte{0x0C})
	e.Write(sevenNum(hdrUnpack))
	e.Write([]byte{0x00, 0x00}) // end UnpackInfo, end StreamsInfo
	return wrap7z(append(append([]byte{}, stream...), hdrStream...), e.Bytes())
}

// AUD-17a: an LZMA-encoded 7z header is decoded inside sevenzip.NewReader, where the
// ceiling refusal used to look like a header-encrypted/corrupt archive.
func TestLZMADictCapEncodedHeader(t *testing.T) {
	defer extract.SetDecryptAttemptTimeForTest(time.Minute)()
	t.Run("encoded header within ceiling opens and extracts", func(t *testing.T) {
		arc := encoded7z(t, []byte("LZMA-MARKER-enchdr\n"), nil, nil, 0)
		res := extract.ExtractWithOptions(arc, extract.FullOptions(time.Time{}))
		if !hasStreamWith(res, []byte("LZMA-MARKER-enchdr")) || hasStopKind(res, "lzma-dict") {
			t.Fatalf("streams=%d caps=%v", len(res.Streams), res.CapHits)
		}
	})
	t.Run("encoded header over ceiling is a cap stop, not clean", func(t *testing.T) {
		junk, pb := lzmaRaw(t, []byte("x"))
		arc := encoded7z(t, []byte("LZMA-MARKER-enchdr\n"), junk, lzmaProps(pb, lzmaCeiling+1), lzmaCeiling+1)
		res := extract.ExtractWithOptions(arc, extract.FullOptions(time.Time{}))
		if !hasStopKind(res, "lzma-dict") || !res.IsArchive || hasStreamWith(res, []byte("LZMA-MARKER-enchdr")) {
			t.Fatalf("isArchive=%v caps=%v streams=%d", res.IsArchive, res.CapHits, len(res.Streams))
		}
	})
	t.Run("encoded header at ceiling with large declared dict is not a cap stop", func(t *testing.T) {
		// min(declared, unpack) == ceiling: allowed; the bogus stream then just fails to decode.
		junk, pb := lzmaRaw(t, []byte("x"))
		arc := encoded7z(t, []byte("LZMA-MARKER-enchdr\n"), junk, lzmaProps(pb, 1<<30), lzmaCeiling)
		res := extract.ExtractWithOptions(arc, extract.FullOptions(time.Time{}))
		if hasStopKind(res, "lzma-dict") {
			t.Fatalf("at-ceiling header misreported: %v", res.CapHits)
		}
	})
}
