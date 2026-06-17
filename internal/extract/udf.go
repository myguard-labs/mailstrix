package extract

import (
	"bytes"
	"encoding/binary"
	"time"
)

// UDF (Universal Disk Format, ECMA-167 / OSTA UDF) disc-image member carve.
// Like ISO9660, a .udf/.iso image is a MOTW-bypass dropper container: Windows
// mounts the image and the user runs the .lnk/.exe/.js inside, which never
// inherits the mark-of-the-web of the original download. Raw-byte scanning sees
// the on-disk filesystem layout (sparse, descriptor-tagged, allocation-extent
// based), not the member files as standalone buffers, so container/keyword
// rules over a dropped script never fire on the whole image.
//
// fromUDF resolves the volume structure (Anchor -> Main Volume Descriptor
// Sequence -> Partition + Logical Volume descriptors -> File Set Descriptor ->
// root File Entry) and walks the directory tree, surfacing each regular file's
// bytes to res.Streams. Only the embedded (in-ICB) and short/long allocation
// descriptor data layouts are read; extended-attribute streams, symlinks, and
// the rarely-seen extended (type-3) allocation indirection are skipped.
//
// Best-effort and fail-open: a malformed descriptor/record is skipped, never
// fatal (Extract's recover still covers a panic). A UDF feature we don't parse
// degrades to a raw-only scan.

const (
	// udfSectorSize is the standard UDF logical sector size (2048 bytes). Images
	// with a different physical block size are not handled (degrade to raw scan).
	udfSectorSize = 2048
	// udfVRSStart is the first sector of the Volume Recognition Sequence (the
	// 16-sector system area precedes it, same as ISO9660).
	udfVRSStart = 16
	// udfAnchorSector is the standard Anchor Volume Descriptor Pointer location.
	udfAnchorSector = 256

	// ECMA-167 descriptor tag identifiers (tag.TagIdentifier, offset 0 of a tag).
	udfTagPVD  = 1   // Primary Volume Descriptor
	udfTagAVDP = 2   // Anchor Volume Descriptor Pointer
	udfTagPD   = 5   // Partition Descriptor
	udfTagLVD  = 6   // Logical Volume Descriptor
	udfTagFSD  = 256 // File Set Descriptor
	udfTagFID  = 257 // File Identifier Descriptor
	udfTagFE   = 261 // File Entry
	udfTagTD   = 8   // Terminating Descriptor
	udfTagEFE  = 266 // Extended File Entry

	// ICB file types (icbtag.FileType): 4 = directory, 5 = regular file.
	udfFileTypeDir  = 4
	udfFileTypeFile = 5

	// FID flags bit 3 (0x08): the "deleted" flag — skip such entries.
	udfFIDDeleted = 0x08
	// FID flags bit 1 (0x02): "parent" entry (the ".." link) — skip it.
	udfFIDParent = 0x02

	// Bounds (mirror the ISO caps so one image can't exhaust time/memory).
	maxUDFFiles        = 256
	maxUDFDirs         = 4096
	maxUDFRecords      = 1 << 16
	maxBytesPerUDFFile = 8 << 20
	maxTotalUDF        = 48 << 20
)

// isUDF reports whether buf carries a UDF volume: an "NSR02" or "NSR03"
// structure identifier somewhere in the Volume Recognition Sequence (the
// descriptors "BEA01" / "NSR0x" / "TEA01" each occupy one 2048-byte sector
// starting at sector 16). The NSR tag is the UDF recogniser; "CD001" alone is
// plain ISO9660. Guards every index.
func isUDF(buf []byte) bool {
	for i := 0; i < 32; i++ { // bound the VRS scan
		off := (udfVRSStart + i) * udfSectorSize
		if off+7 > len(buf) {
			return false
		}
		id := buf[off+1 : off+6]
		if bytes.Equal(id, []byte("NSR02")) || bytes.Equal(id, []byte("NSR03")) {
			return true
		}
		if bytes.Equal(id, []byte("TEA01")) {
			return false // end of the VRS, no NSR seen
		}
	}
	return false
}

// udfState carries the per-image walk budget plus the resolved partition base so
// a deeply nested or cyclic directory structure can't exhaust time/memory.
type udfState struct {
	buf      []byte
	res      *Result
	deadline time.Time
	partBase uint32 // partition starting location (logical-block 0 maps here)
	total    int    // cumulative bytes emitted
	dirsSeen int    // directory File Entries visited (maxUDFDirs guard)
	recsSeen int    // FID records examined (maxUDFRecords guard)
}

// fromUDF resolves the volume structure and walks the directory tree, appending
// each regular file's bytes to res.Streams. Sets res.IsUDF whenever buf is a UDF
// image. Bounded by the maxUDF* caps.
func fromUDF(buf []byte, res *Result, deadline time.Time) {
	res.IsUDF = true
	mvdsLoc, mvdsLen, ok := udfAnchor(buf)
	if !ok {
		return
	}
	partBase, fsdLoc, fsdLBA, ok := udfVolumeDescriptors(buf, mvdsLoc, mvdsLen)
	if !ok {
		return
	}
	st := &udfState{buf: buf, res: res, deadline: deadline, partBase: partBase}
	// The FSD location is a long_ad whose extent is relative to the partition
	// referenced in the LVD's logical-volume-contents-use; fsdLBA carries it.
	rootLoc, ok := udfFileSetRoot(buf, st.lbaOffset(fsdLoc, fsdLBA))
	if !ok {
		return
	}
	st.walkDir(rootLoc, 0)
}

// udfTagOffset converts a sector number to a byte offset, doing the multiply in
// uint64 so a hostile 32-bit sector can't wrap a 32-bit int. Returns false when
// the offset is out of range.
func udfSectorOffset(sector uint32) (int, bool) {
	off := uint64(sector) * udfSectorSize
	if off > uint64(^uint(0)>>1) {
		return 0, false
	}
	return int(off), true
}

// lbaOffset maps a partition-relative logical block (with a partition reference
// number, which we treat as the single mapped partition) to a byte offset.
func (s *udfState) lbaOffset(lba uint32, _ uint16) int {
	off, ok := udfSectorOffset(s.partBase + lba)
	if !ok {
		return -1
	}
	return off
}

// udfTagValid checks the 16-byte descriptor tag at buf[off:]: the tag
// identifier matches want and the structure fits in buf. The tag checksum and
// CRC are not verified (a tampered image still gets best-effort carving); only
// the identifier and bounds gate the parse.
func udfTagValid(buf []byte, off int, want uint16) bool {
	if off < 0 || off+16 > len(buf) {
		return false
	}
	return binary.LittleEndian.Uint16(buf[off:off+2]) == want
}

// udfAnchor reads the Anchor Volume Descriptor Pointer at sector 256 and returns
// the location (sector) and length (bytes) of the Main Volume Descriptor
// Sequence extent it points to. The AVDP's MainVolumeDescriptorSequenceExtent is
// an extent_ad at offset 16: 4-byte length then 4-byte location.
func udfAnchor(buf []byte) (loc, length uint32, ok bool) {
	off, ok := udfSectorOffset(udfAnchorSector)
	if !ok || !udfTagValid(buf, off, udfTagAVDP) {
		return 0, 0, false
	}
	if off+24 > len(buf) {
		return 0, 0, false
	}
	length = binary.LittleEndian.Uint32(buf[off+16 : off+20])
	loc = binary.LittleEndian.Uint32(buf[off+20 : off+24])
	if length == 0 {
		return 0, 0, false
	}
	return loc, length, true
}

// udfVolumeDescriptors walks the Main Volume Descriptor Sequence (mvdsLoc,
// mvdsLen bytes) collecting the Partition Descriptor's starting location and the
// Logical Volume Descriptor's File Set Descriptor pointer (a long_ad inside the
// LVD's logical-volume-contents-use). Returns the partition base sector and the
// FSD long_ad (lba within partition + partition reference).
func udfVolumeDescriptors(buf []byte, mvdsLoc, mvdsLen uint32) (partBase, fsdLoc uint32, fsdLBA uint16, ok bool) {
	base, ok := udfSectorOffset(mvdsLoc)
	if !ok {
		return 0, 0, 0, false
	}
	nSectors := int(mvdsLen) / udfSectorSize
	if nSectors <= 0 {
		// An MVDS extent too small to hold even one descriptor is malformed; fail
		// open rather than parsing later sectors as PD/LVD.
		return 0, 0, 0, false
	}
	if nSectors > 256 {
		nSectors = 256 // cap the descriptor-sequence walk
	}
	var gotPart, gotFSD bool
	for i := 0; i < nSectors; i++ {
		off := base + i*udfSectorSize
		if off+16 > len(buf) {
			break
		}
		tag := binary.LittleEndian.Uint16(buf[off : off+2])
		switch tag {
		case udfTagPD:
			// Partition Descriptor: PartitionStartingLocation at offset 188 (uint32).
			if off+192 <= len(buf) {
				partBase = binary.LittleEndian.Uint32(buf[off+188 : off+192])
				gotPart = true
			}
		case udfTagLVD:
			// Logical Volume Descriptor: LogicalVolumeContentsUse (offset 248, a
			// 16-byte long_ad) points to the File Set Descriptor. long_ad layout:
			// 4-byte length, 4-byte logical-block, 2-byte partition reference.
			if off+258 <= len(buf) {
				fsdLBA = binary.LittleEndian.Uint16(buf[off+256 : off+258])
				fsdLoc = binary.LittleEndian.Uint32(buf[off+252 : off+256])
				gotFSD = true
			}
		case udfTagTD:
			i = nSectors // terminator ends the sequence
		}
		if gotPart && gotFSD {
			break
		}
	}
	return partBase, fsdLoc, fsdLBA, gotPart && gotFSD
}

// udfFileSetRoot parses the File Set Descriptor at byte offset fsdOff and returns
// the root directory ICB long_ad's logical block (partition-relative). The FSD's
// RootDirectoryICB is a 16-byte long_ad at offset 400.
func udfFileSetRoot(buf []byte, fsdOff int) (uint32, bool) {
	if !udfTagValid(buf, fsdOff, udfTagFSD) {
		return 0, false
	}
	if fsdOff+406 > len(buf) {
		return 0, false
	}
	rootLBA := binary.LittleEndian.Uint32(buf[fsdOff+404 : fsdOff+408])
	return rootLBA, fsdOff+408 <= len(buf)
}

// walkDir reads the directory File Entry at partition-relative logical block
// `lba`, iterating its File Identifier Descriptors and recursing into
// subdirectories / emitting regular files. depth/budget guards bound a hostile
// image with cyclic or deeply nested directories.
func (s *udfState) walkDir(lba uint32, depth int) {
	if depth > 64 || s.dirsSeen >= maxUDFDirs || s.recsSeen >= maxUDFRecords {
		return
	}
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		return
	}
	s.dirsSeen++
	data, isDir, ok := s.fileEntryData(lba)
	if !ok || !isDir {
		return
	}
	// The directory's data is a sequence of File Identifier Descriptors.
	for off := 0; off+38 <= len(data); {
		if s.recsSeen >= maxUDFRecords {
			return
		}
		s.recsSeen++
		// FID tag must be 257; otherwise the directory data is corrupt — stop.
		if binary.LittleEndian.Uint16(data[off:off+2]) != udfTagFID {
			return
		}
		liu := binary.LittleEndian.Uint16(data[off+36 : off+38]) // ImplementationUse length
		fileChars := data[off+18]                                // FileCharacteristics flags
		idLen := int(data[off+19])                               // LengthOfFileIdentifier
		// ICB long_ad of the referenced FE is at offset 20 (16 bytes): logical block.
		childLBA := binary.LittleEndian.Uint32(data[off+24 : off+28])
		// FID total length = 38 + liu + idLen, padded up to a 4-byte boundary.
		fidLen := 38 + int(liu) + idLen
		fidLen = (fidLen + 3) &^ 3
		if fidLen <= 0 || off+fidLen > len(data) {
			return
		}
		off += fidLen
		// Skip parent (".." link) and deleted entries.
		if fileChars&(udfFIDParent|udfFIDDeleted) != 0 {
			continue
		}
		s.walkChild(childLBA, depth)
		if len(s.res.Streams) >= maxUDFFiles || s.total >= maxTotalUDF {
			return
		}
	}
}

// walkChild resolves a child File Entry by logical block: recurse if it is a
// directory, emit its bytes if it is a regular file.
func (s *udfState) walkChild(lba uint32, depth int) {
	data, isDir, ok := s.fileEntryData(lba)
	if !ok {
		return
	}
	if isDir {
		s.walkDir(lba, depth+1)
		return
	}
	s.emit(data)
}

// fileEntryData reads the File Entry (tag 261) or Extended File Entry (tag 266)
// at partition-relative logical block `lba` and returns the file's data bytes,
// whether it is a directory, and ok. Only the embedded (ICB flags type 3) and
// short/long allocation-descriptor data layouts are followed; other layouts
// yield ok=false (degrade to raw scan for that member).
func (s *udfState) fileEntryData(lba uint32) (data []byte, isDir bool, ok bool) {
	off := s.lbaOffset(lba, 0)
	if off < 0 || off+16 > len(s.buf) {
		return nil, false, false
	}
	tag := binary.LittleEndian.Uint16(s.buf[off : off+2])
	var icbOff, eaLenOff, adLenOff, headerLen int
	switch tag {
	case udfTagFE:
		// File Entry: icbtag at offset 16; LengthOfExtendedAttributes at 168,
		// LengthOfAllocationDescriptors at 172; the AD/embedded data follows the EA.
		icbOff, eaLenOff, adLenOff, headerLen = 16, 168, 172, 176
	case udfTagEFE:
		// Extended File Entry: icbtag at 16; LengthOfExtendedAttributes at 208,
		// LengthOfAllocationDescriptors at 212; data follows at 216 + EA length.
		icbOff, eaLenOff, adLenOff, headerLen = 16, 208, 212, 216
	default:
		return nil, false, false
	}
	if off+headerLen > len(s.buf) {
		return nil, false, false
	}
	// icbtag.FileType is at icbtag offset 11; icbtag.Flags at offset 18 (2 bytes).
	fileType := s.buf[off+icbOff+11]
	icbFlags := binary.LittleEndian.Uint16(s.buf[off+icbOff+18 : off+icbOff+20])
	isDir = fileType == udfFileTypeDir
	if fileType != udfFileTypeDir && fileType != udfFileTypeFile {
		return nil, false, false
	}
	eaLen := binary.LittleEndian.Uint32(s.buf[off+eaLenOff : off+eaLenOff+4])
	adLen := binary.LittleEndian.Uint32(s.buf[off+adLenOff : off+adLenOff+4])
	dataStart := off + headerLen + int(eaLen)
	// icbFlags low 3 bits = allocation-descriptor type: 3 = data embedded inline.
	switch icbFlags & 0x07 {
	case 3: // embedded data
		if dataStart < 0 || dataStart+int(adLen) > len(s.buf) || int(adLen) < 0 {
			return nil, false, false
		}
		return s.buf[dataStart : dataStart+int(adLen)], isDir, true
	case 0: // short_ad list (8 bytes each: length, partition-relative position)
		return s.gatherExtents(dataStart, int(adLen), true), isDir, true
	case 1: // long_ad list (16 bytes each: length, position, partition ref)
		return s.gatherExtents(dataStart, int(adLen), false), isDir, true
	default:
		return nil, false, false
	}
}

// gatherExtents reads a short_ad (8-byte) or long_ad (16-byte) allocation
// descriptor list at byte offset start (adLen bytes total) and concatenates the
// referenced data extents into one buffer, bounded by the per-file cap. The high
// 2 bits of an extent's length field are the extent type; only type 0 (recorded
// and allocated) data is collected.
func (s *udfState) gatherExtents(start, adLen int, short bool) []byte {
	if start < 0 || adLen <= 0 || start+adLen > len(s.buf) {
		return nil
	}
	step := 16
	if short {
		step = 8
	}
	var out []byte
	for p := start; p+step <= start+adLen; p += step {
		raw := binary.LittleEndian.Uint32(s.buf[p : p+4])
		extType := raw >> 30
		extLen := raw & 0x3FFFFFFF
		if extType != 0 || extLen == 0 {
			continue
		}
		lba := binary.LittleEndian.Uint32(s.buf[p+4 : p+8])
		eo := s.lbaOffset(lba, 0)
		if eo < 0 || eo >= len(s.buf) {
			continue
		}
		n := int(extLen)
		if eo+n > len(s.buf) {
			n = len(s.buf) - eo
		}
		// Trim to the remaining per-file budget BEFORE the copy: a hostile extent
		// can advertise a length far above the cap, and appending the whole extent
		// first would force a large allocation/copy despite the cap.
		if remain := maxBytesPerUDFFile - len(out); n > remain {
			n = remain
		}
		if n <= 0 {
			continue
		}
		out = append(out, s.buf[eo:eo+n]...)
		if len(out) >= maxBytesPerUDFFile {
			return out
		}
	}
	return out
}

// emit appends a regular file's data to res.Streams, bounded by the per-file and
// cumulative caps.
func (s *udfState) emit(data []byte) {
	if len(s.res.Streams) >= maxUDFFiles || s.total >= maxTotalUDF || len(data) == 0 {
		return
	}
	n := len(data)
	if n > maxBytesPerUDFFile {
		n = maxBytesPerUDFFile
	}
	b := append([]byte(nil), data[:n]...)
	s.res.Streams = append(s.res.Streams, b)
	s.total += n
}
