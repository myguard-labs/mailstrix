package extract

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildUDF assembles a minimal but valid UDF image with a single regular file in
// the root directory, exercising the resolve+walk path end to end. Layout
// (2048-byte sectors, partition base 0 so logical block == absolute sector):
//
//	0-15  system area
//	16    BEA01 / 17 NSR02 / 18 TEA01  (Volume Recognition Sequence)
//	32    Partition Descriptor (PartitionStartingLocation = 0)
//	33    Logical Volume Descriptor (FSD long_ad -> sector 40)
//	34    Terminating Descriptor (ends the MVDS)
//	40    File Set Descriptor (RootDirectoryICB -> sector 41)
//	41    root File Entry (directory, embedded FIDs)
//	42    child File Entry (regular file)
//	256   Anchor Volume Descriptor Pointer (MVDS extent -> sector 32, len 3*2048)
//
// When extent is true the child file's data is stored via a short_ad pointing at
// sector 43 (exercising gatherExtents); otherwise it is embedded in the FE.
func buildUDF(name string, data []byte, extent bool) []byte {
	const sec = udfSectorSize
	const (
		mvdsLoc  = 32
		pdLoc    = 32
		lvdLoc   = 33
		tdLoc    = 34
		fsdLoc   = 40
		rootLoc  = 41
		childLoc = 42
		dataLoc  = 43
	)
	img := make([]byte, (dataLoc+1)*sec)

	// VRS: BEA01 / NSR02 / TEA01, one per sector from sector 16.
	udfVRSDesc(img, 16, "BEA01")
	udfVRSDesc(img, 17, "NSR02")
	udfVRSDesc(img, 18, "TEA01")

	// Partition Descriptor: tag 5, PartitionStartingLocation (offset 188) = 0.
	pd := udfTag(udfTagPD, sec)
	binary.LittleEndian.PutUint32(pd[188:192], 0)
	copy(img[pdLoc*sec:], pd)

	// Logical Volume Descriptor: tag 6, LogicalVolumeContentsUse (offset 248) is a
	// long_ad pointing at the File Set Descriptor (logical block fsdLoc).
	lvd := udfTag(udfTagLVD, sec)
	binary.LittleEndian.PutUint32(lvd[248:252], sec) // ad length
	binary.LittleEndian.PutUint32(lvd[252:256], fsdLoc)
	binary.LittleEndian.PutUint16(lvd[256:258], 0) // partition ref
	copy(img[lvdLoc*sec:], lvd)

	// Terminating Descriptor ends the MVDS.
	copy(img[tdLoc*sec:], udfTag(udfTagTD, sec))

	// File Set Descriptor: tag 256, RootDirectoryICB (offset 400) -> rootLoc.
	fsd := udfTag(udfTagFSD, sec)
	binary.LittleEndian.PutUint32(fsd[400:404], sec)
	binary.LittleEndian.PutUint32(fsd[404:408], rootLoc)
	copy(img[fsdLoc*sec:], fsd)

	// Root directory File Entry: embedded FIDs (a "parent" entry + the child).
	fids := make([]byte, 0, 2*sec)
	fids = append(fids, udfFID(rootLoc, udfFIDParent, nil)...) // ".."
	fids = append(fids, udfFID(childLoc, 0, []byte(name))...)  // child file
	rootFE := udfFileEntry(udfFileTypeDir, fids, false, 0)
	copy(img[rootLoc*sec:], rootFE)

	// Child regular-file File Entry: embedded data, or a short_ad to dataLoc.
	if extent {
		childFE := udfFileEntry(udfFileTypeFile, nil, true, dataLoc)
		copy(img[childLoc*sec:], childFE)
		copy(img[dataLoc*sec:], data)
		// store the extent length in the FE's short_ad (already set below)
		_ = data
		// patch the short_ad length to len(data)
		patchShortADLen(img[childLoc*sec:], uint32(len(data)))
	} else {
		childFE := udfFileEntry(udfFileTypeFile, data, false, 0)
		copy(img[childLoc*sec:], childFE)
	}

	// Anchor Volume Descriptor Pointer at sector 256: MVDS extent_ad (len, loc).
	avdp := udfTag(udfTagAVDP, sec)
	binary.LittleEndian.PutUint32(avdp[16:20], 3*sec) // length: PD+LVD+TD
	binary.LittleEndian.PutUint32(avdp[20:24], mvdsLoc)
	// AVDP lives at sector 256, beyond dataLoc — grow the image to fit it.
	if (udfAnchorSector+1)*sec > len(img) {
		grown := make([]byte, (udfAnchorSector+1)*sec)
		copy(grown, img)
		img = grown
	}
	copy(img[udfAnchorSector*sec:], avdp)
	return img
}

// udfVRSDesc writes a Volume Recognition Sequence descriptor (structure type 0,
// identifier, version 1) at the given sector.
func udfVRSDesc(img []byte, sector int, id string) {
	off := sector * udfSectorSize
	copy(img[off+1:off+6], id)
	img[off+6] = 1
}

// udfTag returns a size-byte buffer whose first 2 bytes are the descriptor tag
// identifier (the only tag field the parser checks).
func udfTag(id uint16, size int) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:2], id)
	return b
}

// udfFID builds a File Identifier Descriptor: tag 257, FileCharacteristics
// (offset 18), ICB long_ad logical block (offset 24), and the file identifier
// appended after the 38-byte header. Padded to a 4-byte boundary.
func udfFID(childLBA uint32, chars byte, id []byte) []byte {
	idLen := len(id)
	total := 38 + idLen
	total = (total + 3) &^ 3
	b := make([]byte, total)
	binary.LittleEndian.PutUint16(b[0:2], udfTagFID)
	b[18] = chars
	binary.LittleEndian.PutUint32(b[24:28], childLBA) // ICB long_ad logical block
	b[19] = byte(idLen)                               // LengthOfFileIdentifier
	binary.LittleEndian.PutUint16(b[36:38], 0)        // ImplementationUse length
	copy(b[38:], id)
	return b
}

// udfFileEntry builds a File Entry (tag 261) with the given ICB file type. When
// shortAD is true the descriptor carries one short_ad (8 bytes) pointing at
// extentLBA (length patched later); otherwise the data is embedded inline.
func udfFileEntry(fileType byte, data []byte, shortAD bool, extentLBA uint32) []byte {
	const headerLen = 176
	var body []byte
	var icbFlags uint16
	if shortAD {
		icbFlags = 0 // short_ad list
		ad := make([]byte, 8)
		// length patched by patchShortADLen; position = extentLBA.
		binary.LittleEndian.PutUint32(ad[4:8], extentLBA)
		body = ad
	} else {
		icbFlags = 3 // embedded data
		body = data
	}
	b := make([]byte, headerLen+len(body))
	binary.LittleEndian.PutUint16(b[0:2], udfTagFE)
	// icbtag at offset 16: FileType at +11, Flags at +18.
	b[16+11] = fileType
	binary.LittleEndian.PutUint16(b[16+18:16+20], icbFlags)
	binary.LittleEndian.PutUint32(b[168:172], 0)                 // LengthOfExtendedAttributes
	binary.LittleEndian.PutUint32(b[172:176], uint32(len(body))) // LengthOfAllocationDescriptors
	copy(b[headerLen:], body)
	return b
}

// patchShortADLen sets the recorded length of the first short_ad in a File Entry
// built with shortAD=true (the AD sits at offset 176).
func patchShortADLen(fe []byte, n uint32) {
	binary.LittleEndian.PutUint32(fe[176:180], n&0x3FFFFFFF)
}

func TestExtractUDFMemberFile(t *testing.T) {
	payload := []byte("MZ\x90\x00 udf dropper member payload invoke calc.exe")
	buf := buildUDF("DROP.EXE", payload, false)
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Fatal("UDF not flagged IsDoc")
	}
	if !res.IsUDF {
		t.Fatal("UDF not flagged IsUDF")
	}
	if res.IsISO {
		t.Fatal("pure UDF wrongly flagged IsISO")
	}
	if !streamsContain(res, "udf dropper member payload") {
		t.Fatal("UDF member file not surfaced to streams")
	}
}

func TestExtractUDFShortAD(t *testing.T) {
	payload := []byte("udf short_ad extent member payload script body")
	buf := buildUDF("RUN.JS", payload, true)
	res := Extract(buf, time.Time{})
	if !res.IsUDF {
		t.Fatal("short_ad UDF not flagged IsUDF")
	}
	if !streamsContain(res, "udf short_ad extent member") {
		t.Fatal("short_ad UDF member not surfaced to streams")
	}
}

// A non-UDF buffer must not be flagged IsUDF.
func TestExtractUDFNegative(t *testing.T) {
	res := Extract([]byte("not a disc image, just plain text content here too"), time.Time{})
	if res.IsUDF {
		t.Fatal("plain text wrongly flagged IsUDF")
	}
}

// A truncated image (VRS present, anchor/descriptors missing) must fail open:
// flagged IsUDF, no panic, no streams.
func TestExtractUDFTruncated(t *testing.T) {
	full := buildUDF("X.EXE", []byte("payload"), false)
	buf := full[:20*udfSectorSize] // VRS present, AVDP at sector 256 gone
	res := Extract(buf, time.Time{})
	if !res.IsUDF {
		t.Fatal("truncated UDF should still be flagged IsUDF")
	}
	if len(res.Streams) != 0 {
		t.Fatal("truncated UDF should yield no streams")
	}
}
