package extract

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// Windows Shell Link (.lnk) parsing. A .lnk is a prime mail-malware vector: the
// shortcut's COMMAND_LINE_ARGUMENTS field carries a full
// `powershell -enc …` / `cmd /c …` payload while the icon impersonates a PDF or
// document. The command line is buried in the binary SHLLINK structure, so
// raw-byte keyword rules miss it — and a .lnk is not a container the other
// extractors recognise.
//
// fromLNK parses the StringData blocks (name / relative-path / working-dir /
// arguments / icon-location) and surfaces them as cleartext (UTF-16 decoded to
// UTF-8) so the rules match the embedded command. We deliberately do NOT fully
// parse the LinkTargetIDList / LinkInfo binary blobs — only enough of the header
// and those two size-prefixed sections to reach StringData. Best-effort and
// fail-open: a truncated/crafted .lnk yields whatever decoded cleanly, never a
// panic (Extract's recover also covers it).
//
// Reference: [MS-SHLLINK] §2.1 ShellLinkHeader, §2.4 StringData.

// lnkMagic is the ShellLinkHeader: HeaderSize (0x4C, little-endian) followed by
// the LinkCLSID {00021401-0000-0000-C000-000000000046} in on-disk byte order.
var lnkMagic = []byte{
	0x4C, 0x00, 0x00, 0x00, // HeaderSize = 76
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // CLSID Data1/2/3
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, // CLSID Data4
}

const (
	lnkHeaderSize = 76 // ShellLinkHeader is exactly 76 bytes
	lnkFlagsOff   = 20 // LinkFlags is a uint32 at offset 20

	// LinkFlags bits we care about (MS-SHLLINK §2.1.1).
	lnkHasLinkTargetIDList = 1 << 0
	lnkHasLinkInfo         = 1 << 1
	lnkHasName             = 1 << 2
	lnkHasRelativePath     = 1 << 3
	lnkHasWorkingDir       = 1 << 4
	lnkHasArguments        = 1 << 5
	lnkHasIconLocation     = 1 << 6
	lnkIsUnicode           = 1 << 7

	// maxLNKStringChars bounds one StringData block's declared length so a hostile
	// CountChars can't drive a huge read; a real command line is far smaller.
	maxLNKStringChars = 1 << 16
)

// isLNK reports whether buf begins with the ShellLink header magic.
func isLNK(buf []byte) bool {
	return bytes.HasPrefix(buf, lnkMagic)
}

// fromLNK parses a .lnk and appends its StringData fields (decoded to UTF-8) to
// res.Streams. Sets IsLNK. Bounded and fail-open: parsing stops at the first
// malformed/truncated section, surfacing whatever was read so far.
func fromLNK(buf []byte, res *Result) {
	res.IsLNK = true
	if len(buf) < lnkHeaderSize {
		return
	}
	flags := binary.LittleEndian.Uint32(buf[lnkFlagsOff:])
	p := lnkHeaderSize

	// LinkTargetIDList: 2-byte IDListSize then that many bytes. Skip it.
	if flags&lnkHasLinkTargetIDList != 0 {
		if p+2 > len(buf) {
			return
		}
		n := int(binary.LittleEndian.Uint16(buf[p:]))
		p += 2 + n
		if p > len(buf) || p < lnkHeaderSize {
			return
		}
	}

	// LinkInfo: 4-byte LinkInfoSize (counts itself) then the rest of the block.
	if flags&lnkHasLinkInfo != 0 {
		if p+4 > len(buf) {
			return
		}
		// LinkInfoSize counts its own 4 bytes. int(uint32) is safe on 64-bit (max
		// ~4 GiB << maxint) and avail is non-negative (p <= len(buf) above), so the
		// comparison stays in the int domain — no int->uint64 conversion. n must be
		// >= 4 and fit within the bytes remaining.
		n := int(binary.LittleEndian.Uint32(buf[p:]))
		avail := len(buf) - p
		if n < 4 || n > avail {
			return
		}
		p += n
	}

	unicode := flags&lnkIsUnicode != 0
	// StringData blocks appear in this fixed order, each present only if its flag
	// is set (MS-SHLLINK §2.4). Surface them all; the command line / arguments and
	// relative path are where the payload hides.
	order := []uint32{
		lnkHasName, lnkHasRelativePath, lnkHasWorkingDir,
		lnkHasArguments, lnkHasIconLocation,
	}
	for _, bit := range order {
		if flags&bit == 0 {
			continue
		}
		var s []byte
		s, p = readLNKString(buf, p, unicode)
		if p < 0 {
			return // truncated/malformed: stop, keep what we have
		}
		if len(s) > 0 {
			res.appendStreamOwned(&s)
			if len(res.Streams) >= maxStreams {
				return
			}
		}
	}
}

// readLNKString reads one StringData block at off: a uint16 CountChars followed
// by CountChars characters (2 bytes each when unicode, else 1). It returns the
// decoded UTF-8 bytes and the offset just past the block, or (nil, -1) if the
// block is truncated or the declared length is implausibly large.
func readLNKString(buf []byte, off int, unicode bool) ([]byte, int) {
	if off < 0 || off+2 > len(buf) {
		return nil, -1
	}
	count := int(binary.LittleEndian.Uint16(buf[off:]))
	off += 2
	if count > maxLNKStringChars {
		return nil, -1
	}
	if count == 0 {
		return nil, off
	}
	if unicode {
		nbytes := count * 2
		if off+nbytes > len(buf) {
			return nil, -1
		}
		u16 := make([]uint16, count)
		for i := 0; i < count; i++ {
			u16[i] = binary.LittleEndian.Uint16(buf[off+i*2:])
		}
		off += nbytes
		return []byte(string(utf16.Decode(u16))), off
	}
	if off+count > len(buf) {
		return nil, -1
	}
	s := append([]byte(nil), buf[off:off+count]...)
	off += count
	return s, off
}
