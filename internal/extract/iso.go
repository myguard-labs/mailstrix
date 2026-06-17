package extract

import (
	"bytes"
	"encoding/binary"
	"time"
)

// ISO9660 (CD-ROM) member carve. Mailing a payload inside an .iso is a common
// MOTW-bypass dropper technique: Windows mounts the ISO and the user runs the
// .lnk/.exe/.js inside, which never inherits the mark-of-the-web the original
// download carried. Raw-byte scanning of the ISO sees the on-disk filesystem
// layout, not the member files as standalone buffers, so container/keyword
// rules over a dropped script or shortcut never fire on the whole image.
//
// fromISO walks the ISO9660 directory tree (plain ECMA-119 plus the Joliet
// supplementary descriptor for Unicode names) and surfaces each regular file's
// bytes to res.Streams so the rules match the dropped member, not the image.
// El Torito boot images and the volume metadata are skipped. UDF and FAT/IMG/
// VHD(X) images are not handled here (separate TODO items); a UDF-only image
// degrades to a raw-only scan.
//
// Best-effort and fail-open: a malformed descriptor/record is skipped, never
// fatal (Extract's recover still covers a panic).

const (
	// isoSectorSize is the ECMA-119 logical sector size (2048 bytes).
	isoSectorSize = 2048
	// isoSystemArea is the 16-sector reserved area before the volume descriptors.
	isoSystemArea = 16
	// isoMagic is the "CD001" standard identifier at offset 1 of every descriptor.
	isoMagic = "CD001"

	// Volume descriptor types.
	isoVDPrimary       = 1   // Primary Volume Descriptor (PVD)
	isoVDSupplementary = 2   // Supplementary VD (Joliet when escape seq is UCS-2)
	isoVDTerminator    = 255 // Volume Descriptor Set Terminator

	// Directory record file-flags bit 1 (0x02): entry is a subdirectory.
	isoFlagDir = 0x02

	// maxISOFiles bounds how many member files we emit from one image.
	maxISOFiles = 256
	// maxISODirs bounds directory extents walked (cycle/bomb guard).
	maxISODirs = 4096
	// maxISORecords bounds total directory records examined across the whole walk.
	// A large accepted image whose directory extents are full of zero-sized or
	// invalid records emits no files and burns no byte budget, so a record cap
	// (independent of streams emitted) is needed to keep the walk O(bounded).
	maxISORecords = 1 << 16
	// maxBytesPerISOFile caps one emitted member (raw scan covers the rest).
	maxBytesPerISOFile = 8 << 20
	// maxTotalISO caps cumulative member bytes emitted from one image.
	maxTotalISO = 48 << 20
)

// isISO reports whether buf is an ISO9660 image: the "CD001" standard
// identifier at offset 1 of the first volume descriptor (sector 16). The 16
// preceding sectors are an unstructured system area, so the magic is the
// recogniser. Guards the length before indexing.
func isISO(buf []byte) bool {
	off := isoSystemArea*isoSectorSize + 1
	if len(buf) < off+len(isoMagic) {
		return false
	}
	return string(buf[off:off+len(isoMagic)]) == isoMagic
}

// fromISO walks the ISO9660 directory tree and appends each regular file's bytes
// to res.Streams. It prefers the Joliet supplementary descriptor (Unicode names)
// when present but reads the same data extents either way, so the choice only
// affects which name table is walked, not the bytes emitted. Sets res.IsISO
// whenever buf is an ISO image. Bounded by the maxISO* caps.
func fromISO(buf []byte, res *Result, deadline time.Time) {
	res.IsISO = true
	root := isoRootRecord(buf)
	if root == nil {
		return
	}
	st := &isoState{buf: buf, res: res, deadline: deadline}
	st.walk(root.extent, root.size, 0)
}

// isoRecord is a parsed directory record: the location/length of a file or
// subdirectory's data extent, plus whether it is a directory.
type isoRecord struct {
	extent uint32 // starting logical block number (LBA)
	size   uint32 // data length in bytes
	isDir  bool
}

// isoState carries the per-image walk budget so a deeply nested or cyclic
// directory structure can't exhaust time/memory.
type isoState struct {
	buf      []byte
	res      *Result
	deadline time.Time // extraction deadline (zero = no limit)
	total    int       // cumulative bytes emitted
	dirsSeen int       // directory extents visited (maxISODirs guard)
	recsSeen int       // directory records examined (maxISORecords guard)
}

// isoRootRecord returns the root directory record from the best available volume
// descriptor: the Joliet supplementary descriptor if one is present (Unicode
// names), else the primary descriptor. Returns nil if no usable PVD is found.
func isoRootRecord(buf []byte) *isoRecord {
	var primary *isoRecord
	for i := 0; i < 64; i++ { // bound the descriptor scan
		off := (isoSystemArea + i) * isoSectorSize
		if off+isoSectorSize > len(buf) {
			break
		}
		sec := buf[off : off+isoSectorSize]
		if string(sec[1:6]) != isoMagic {
			break // not a descriptor; end of the set
		}
		switch sec[0] {
		case isoVDPrimary:
			primary = parseRootRecord(sec)
		case isoVDSupplementary:
			// A supplementary descriptor is Joliet when its escape sequences
			// (offset 88, 32 bytes) select a UCS-2 level (%/@, %/C, %/E). The
			// root record location is identical in layout to the PVD's; prefer
			// it for the Unicode name table.
			if isJoliet(sec) {
				if r := parseRootRecord(sec); r != nil {
					return r
				}
			}
		case isoVDTerminator:
			return primary
		}
	}
	return primary
}

// isJoliet reports whether a supplementary volume descriptor selects a Joliet
// UCS-2 escape sequence (ECMA-119 §8.5.6: "%/@", "%/C", "%/E").
func isJoliet(sec []byte) bool {
	esc := sec[88:120]
	for _, seq := range [][]byte{{'%', '/', '@'}, {'%', '/', 'C'}, {'%', '/', 'E'}} {
		if bytes.HasPrefix(esc, seq) {
			return true
		}
	}
	return false
}

// parseRootRecord extracts the 34-byte root directory record embedded at offset
// 156 of a (primary or supplementary) volume descriptor.
func parseRootRecord(sec []byte) *isoRecord {
	if len(sec) < 156+34 {
		return nil
	}
	return parseDirRecord(sec[156 : 156+34])
}

// parseDirRecord parses one ISO9660 directory record header (location, length,
// flags) from rec. Returns nil for a malformed/zero-length record. The name
// itself is not needed — we emit file bytes, not names — so only the extent,
// size, and dir flag are read. Both the extent (offset 2) and size (offset 10)
// are stored little-endian-then-big-endian; we read the little-endian copy.
func parseDirRecord(rec []byte) *isoRecord {
	if len(rec) < 33 {
		return nil
	}
	length := rec[0]
	if length < 33 || int(length) > len(rec) {
		return nil
	}
	return &isoRecord{
		extent: binary.LittleEndian.Uint32(rec[2:6]),
		size:   binary.LittleEndian.Uint32(rec[10:14]),
		isDir:  rec[25]&isoFlagDir != 0,
	}
}

// walk reads the directory extent at LBA `extent` (size bytes), emitting regular
// file members and recursing into subdirectories. depth/budget guards bound a
// hostile image with cyclic or deeply nested directories.
func (s *isoState) walk(extent, size uint32, depth int) {
	if depth > 64 || s.dirsSeen >= maxISODirs || s.recsSeen >= maxISORecords {
		return
	}
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		return
	}
	s.dirsSeen++
	start, ok := isoOffset(extent)
	if !ok {
		return
	}
	end := start + int(size)
	if end <= start || end > len(s.buf) {
		return
	}
	data := s.buf[start:end]
	for off := 0; off < len(data); {
		// A directory full of zero-sized/invalid records emits nothing and burns
		// no byte budget; cap the records examined so the walk stays bounded.
		if s.recsSeen >= maxISORecords {
			return
		}
		s.recsSeen++
		rec := data[off:]
		recLen := int(rec[0])
		if recLen == 0 {
			// A zero length pads to the end of the sector; jump to the next one.
			next := (off/isoSectorSize + 1) * isoSectorSize
			if next <= off {
				break
			}
			off = next
			continue
		}
		if recLen < 33 || off+recLen > len(data) {
			break
		}
		r := parseDirRecord(rec[:recLen])
		idLen := int(rec[32]) // file-identifier length (offset 32)
		off += recLen
		if r == nil {
			continue
		}
		// Skip the "." and ".." self/parent entries: both have a single-byte file
		// identifier (0x00 / 0x01). Gate on the identifier LENGTH, not the byte
		// value at offset 33 — under a Joliet SVD ordinary names are UCS-2BE and
		// start with 0x00, so a value check would skip real files.
		if idLen == 1 {
			continue
		}
		if r.isDir {
			s.walk(r.extent, r.size, depth+1)
			continue
		}
		s.emitFile(r)
		if len(s.res.Streams) >= maxISOFiles || s.total >= maxTotalISO {
			return
		}
	}
}

// isoOffset converts a logical block number (LBA) to a byte offset into the
// image, doing the multiply in uint64 so a hostile 32-bit LBA can't wrap a
// 32-bit int and map an out-of-range block back into the buffer. Returns false
// when the offset doesn't fit in a positive int (i.e. is out of range).
func isoOffset(lba uint32) (int, bool) {
	off := uint64(lba) * isoSectorSize
	if off > uint64(^uint(0)>>1) { // > maxInt
		return 0, false
	}
	return int(off), true
}

// emitFile reads a regular file's data extent and appends it to res.Streams,
// bounded by the per-file and cumulative caps.
func (s *isoState) emitFile(r *isoRecord) {
	if len(s.res.Streams) >= maxISOFiles || s.total >= maxTotalISO || r.size == 0 {
		return
	}
	start, ok := isoOffset(r.extent)
	if !ok || start >= len(s.buf) {
		return
	}
	n := int(r.size)
	if n > maxBytesPerISOFile {
		n = maxBytesPerISOFile
	}
	if start+n > len(s.buf) {
		n = len(s.buf) - start
	}
	if n <= 0 {
		return
	}
	b := append([]byte(nil), s.buf[start:start+n]...)
	s.res.Streams = append(s.res.Streams, b)
	s.total += n
}
