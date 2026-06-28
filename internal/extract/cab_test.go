package extract_test

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"testing"
	"time"

	"github.com/eilandert/rspamd-yarad/internal/extract"
)

// buildNoneCab builds a minimal CAB with NONE compression holding one file.
func buildNoneCab(filename string, content []byte) []byte {
	// Layout:
	//   CFHEADER  (36 bytes)
	//   CFFOLDER  (8 bytes)
	//   CFFILE    (16 + len(filename)+1 bytes)
	//   CFDATA    (8 + len(content) bytes)

	nameBytes := append([]byte(filename), 0)
	cffileSize := 16 + len(nameBytes)

	// Offsets.
	cfheaderSize := 36
	cffolderOffset := cfheaderSize            // 36
	cffileOffset := cffolderOffset + 8        // 44
	cfdataOffset := cffileOffset + cffileSize // 44 + cffileSize
	totalSize := cfdataOffset + 8 + len(content)

	buf := make([]byte, totalSize)

	// CFHEADER.
	copy(buf[0:4], "MSCF")
	// reserved1 = 0
	binary.LittleEndian.PutUint32(buf[8:12], uint32(totalSize)) // cbCabinet
	// reserved2 = 0
	binary.LittleEndian.PutUint32(buf[16:20], uint32(cffileOffset)) // coffFiles
	// reserved3 = 0
	buf[24] = 3                                  // versionMinor
	buf[25] = 1                                  // versionMajor
	binary.LittleEndian.PutUint16(buf[26:28], 1) // cFolders
	binary.LittleEndian.PutUint16(buf[28:30], 1) // cFiles
	// flags = 0, setID = 0, iCabinet = 0

	// CFFOLDER.
	binary.LittleEndian.PutUint32(buf[cffolderOffset:cffolderOffset+4], uint32(cfdataOffset)) // coffCabStart
	binary.LittleEndian.PutUint16(buf[cffolderOffset+4:cffolderOffset+6], 1)                  // cCFData
	binary.LittleEndian.PutUint16(buf[cffolderOffset+6:cffolderOffset+8], 0x0000)             // NONE

	// CFFILE.
	foff := cffileOffset
	binary.LittleEndian.PutUint32(buf[foff:foff+4], uint32(len(content))) // cbFile
	binary.LittleEndian.PutUint32(buf[foff+4:foff+8], 0)                  // uoffFolderStart
	binary.LittleEndian.PutUint16(buf[foff+8:foff+10], 0)                 // iFolder
	// date, time, attribs = 0
	copy(buf[foff+16:], nameBytes)

	// CFDATA.
	doff := cfdataOffset
	// checksum = 0
	binary.LittleEndian.PutUint16(buf[doff+4:doff+6], uint16(len(content))) // cbData
	binary.LittleEndian.PutUint16(buf[doff+6:doff+8], uint16(len(content))) // cbUncomp
	copy(buf[doff+8:], content)

	return buf
}

// buildMSZIPCab builds a minimal CAB with MSZIP compression holding one file.
func buildMSZIPCab(filename string, content []byte) []byte {
	// Compress content as CK+DEFLATE.
	var compressed bytes.Buffer
	compressed.WriteByte(0x43) // 'C'
	compressed.WriteByte(0x4B) // 'K'
	fw, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	_, _ = fw.Write(content)
	_ = fw.Close()
	compData := compressed.Bytes()

	nameBytes := append([]byte(filename), 0)
	cffileSize := 16 + len(nameBytes)

	cfheaderSize := 36
	cffolderOffset := cfheaderSize
	cffileOffset := cffolderOffset + 8
	cfdataOffset := cffileOffset + cffileSize
	totalSize := cfdataOffset + 8 + len(compData)

	buf := make([]byte, totalSize)

	copy(buf[0:4], "MSCF")
	binary.LittleEndian.PutUint32(buf[8:12], uint32(totalSize))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(cffileOffset))
	buf[24] = 3
	buf[25] = 1
	binary.LittleEndian.PutUint16(buf[26:28], 1)
	binary.LittleEndian.PutUint16(buf[28:30], 1)

	binary.LittleEndian.PutUint32(buf[cffolderOffset:cffolderOffset+4], uint32(cfdataOffset))
	binary.LittleEndian.PutUint16(buf[cffolderOffset+4:cffolderOffset+6], 1)
	binary.LittleEndian.PutUint16(buf[cffolderOffset+6:cffolderOffset+8], 0x0001) // MSZIP

	foff := cffileOffset
	binary.LittleEndian.PutUint32(buf[foff:foff+4], uint32(len(content)))
	binary.LittleEndian.PutUint32(buf[foff+4:foff+8], 0)
	binary.LittleEndian.PutUint16(buf[foff+8:foff+10], 0)
	copy(buf[foff+16:], nameBytes)

	doff := cfdataOffset
	binary.LittleEndian.PutUint16(buf[doff+4:doff+6], uint16(len(compData)))
	binary.LittleEndian.PutUint16(buf[doff+6:doff+8], uint16(len(content)))
	copy(buf[doff+8:], compData)

	return buf
}

func deadline() time.Time {
	return time.Now().Add(5 * time.Second)
}

func TestCabNoneCompression(t *testing.T) {
	content := []byte("hello world")
	cab := buildNoneCab("hello.txt", content)

	res := extract.Extract(cab, deadline())

	if !res.IsArchive {
		t.Fatal("expected IsArchive=true")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, content) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected stream containing %q; got %d streams", content, len(res.Streams))
	}
}

func TestCabMSZIPCompression(t *testing.T) {
	content := []byte("mszip compressed cabinet content for testing")
	cab := buildMSZIPCab("test.txt", content)

	res := extract.Extract(cab, deadline())

	if !res.IsArchive {
		t.Fatal("expected IsArchive=true")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Contains(s, content) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected decompressed stream containing %q; got %d streams", content, len(res.Streams))
	}
}

func TestCabUnsupportedCompression(t *testing.T) {
	// Build a minimal CAB with typeCompress=0x02 (QUANTUM).
	// We just need a structurally valid header pointing to a folder with QUANTUM.
	content := []byte("quantum data")
	nameBytes := append([]byte("file.bin"), 0)
	cffileSize := 16 + len(nameBytes)

	cfheaderSize := 36
	cffolderOffset := cfheaderSize
	cffileOffset := cffolderOffset + 8
	cfdataOffset := cffileOffset + cffileSize
	totalSize := cfdataOffset + 8 + len(content)

	buf := make([]byte, totalSize)
	copy(buf[0:4], "MSCF")
	binary.LittleEndian.PutUint32(buf[8:12], uint32(totalSize))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(cffileOffset))
	buf[24] = 3
	buf[25] = 1
	binary.LittleEndian.PutUint16(buf[26:28], 1)
	binary.LittleEndian.PutUint16(buf[28:30], 1)

	binary.LittleEndian.PutUint32(buf[cffolderOffset:cffolderOffset+4], uint32(cfdataOffset))
	binary.LittleEndian.PutUint16(buf[cffolderOffset+4:cffolderOffset+6], 1)
	binary.LittleEndian.PutUint16(buf[cffolderOffset+6:cffolderOffset+8], 0x0002) // QUANTUM

	foff := cffileOffset
	binary.LittleEndian.PutUint32(buf[foff:foff+4], uint32(len(content)))
	binary.LittleEndian.PutUint32(buf[foff+4:foff+8], 0)
	binary.LittleEndian.PutUint16(buf[foff+8:foff+10], 0)
	copy(buf[foff+16:], nameBytes)

	doff := cfdataOffset
	binary.LittleEndian.PutUint16(buf[doff+4:doff+6], uint16(len(content)))
	binary.LittleEndian.PutUint16(buf[doff+6:doff+8], uint16(len(content)))
	copy(buf[doff+8:], content)

	res := extract.Extract(buf, deadline())

	if res.Panicked {
		t.Fatal("panicked on QUANTUM cabinet")
	}
	if !res.IsArchive {
		t.Fatal("expected IsArchive=true")
	}
	found := false
	for _, s := range res.Streams {
		if bytes.Equal(s, []byte("CAB-COMPRESSION-UNSUPPORTED")) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected CAB-COMPRESSION-UNSUPPORTED marker; streams=%v", res.Streams)
	}
}

func TestCabAdversarial(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		res := extract.Extract([]byte{}, deadline())
		if res.Panicked {
			t.Fatal("panicked on empty input")
		}
	})

	t.Run("magic_only", func(t *testing.T) {
		res := extract.Extract([]byte("MSCF"), deadline())
		if res.Panicked {
			t.Fatal("panicked on truncated magic")
		}
	})

	t.Run("coffFiles_past_end", func(t *testing.T) {
		buf := make([]byte, 36)
		copy(buf[0:4], "MSCF")
		binary.LittleEndian.PutUint32(buf[8:12], 36)
		binary.LittleEndian.PutUint32(buf[16:20], 0xFFFFFFFF) // coffFiles way past end
		binary.LittleEndian.PutUint16(buf[26:28], 1)
		binary.LittleEndian.PutUint16(buf[28:30], 1)
		res := extract.Extract(buf, deadline())
		if res.Panicked {
			t.Fatal("panicked on coffFiles past end")
		}
	})

	t.Run("cbFile_oversize", func(t *testing.T) {
		content := []byte("small")
		cab := buildNoneCab("big.bin", content)
		// Overwrite cbFile with huge value.
		// CFFILE starts at offset 44.
		binary.LittleEndian.PutUint32(cab[44:48], 0xFFFFFFFF)
		res := extract.Extract(cab, deadline())
		if res.Panicked {
			t.Fatal("panicked on oversize cbFile")
		}
	})

	t.Run("cFiles_bomb", func(t *testing.T) {
		buf := make([]byte, 100)
		copy(buf[0:4], "MSCF")
		binary.LittleEndian.PutUint32(buf[8:12], 100)
		binary.LittleEndian.PutUint32(buf[16:20], 44) // coffFiles=44
		binary.LittleEndian.PutUint16(buf[26:28], 1)
		binary.LittleEndian.PutUint16(buf[28:30], 0xFFFF) // cFiles bomb
		// CFFOLDER at 36.
		binary.LittleEndian.PutUint32(buf[36:40], 60) // coffCabStart
		binary.LittleEndian.PutUint16(buf[40:42], 0)  // cCFData=0
		binary.LittleEndian.PutUint16(buf[42:44], 0)  // NONE
		res := extract.Extract(buf, deadline())
		if res.Panicked {
			t.Fatal("panicked on cFiles bomb")
		}
	})
}
