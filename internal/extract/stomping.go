package extract

// VBA stomping detection.
//
// VBA stomping is an evasion technique where an attacker replaces the plaintext
// VBA source in an OLE2 VBA project with a harmless stub, while preserving the
// compiled p-code (the bytecode that Office actually executes). Static scanners
// that rely on source text (olevba, most YARA rules) see only the stub — they
// miss the real payload lurking in the p-code.
//
// How the MS-OVBA spec structures a module stream:
//
//	[p-code bytes 0 .. MODULEOFFSET-1][MS-OVBA compressed source MODULEOFFSET .. end]
//
// MODULEOFFSET is declared in the dir stream (record 0x0031). P-code occupies
// all bytes before that offset; source is everything from that offset onward
// (decompressed). A stomped module has substantial p-code (MODULEOFFSET >= 256)
// but trivial or empty source (empty, only whitespace, or only Attribute VB_*
// header lines).
//
// This detector re-walks the VBA dir stream (same logic as oleparse.ExtractMacros)
// to recover MODULEOFFSET for every module, then checks the source text.
// It emits a synthetic
//
//	"VBA-STOMPED <moduleName> pcode=<n> src=<n>"
//
// stream into Result.Streams for each stomped module, so the vba_stomping.yara
// rule can match it. Fail-open: any parse error is silently ignored.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"www.velocidex.com/golang/oleparse"
)

const (
	// stompPCodeThreshold is the minimum p-code bytes to consider substantial
	// (a real compiled module vs. an empty placeholder).
	stompPCodeThreshold = 256
	// stompSourceThreshold is the maximum effective source bytes before we
	// treat the source as trivial (stub or gutted).
	stompSourceThreshold = 32
)

var stompAttributePrefix = []byte("Attribute VB_")

// detectStompingModules inspects modules that were already parsed by oleparse.
// It avoids the old second pass over the "dir" stream and a second decompression
// of every module's source on the normal macro-extraction path.
func detectStompingModules(mods []*oleparse.VBAModule, result *Result, deadline time.Time) {
	if result == nil || expired(deadline) {
		return
	}
	for _, m := range mods {
		if expired(deadline) || len(result.Streams) >= maxStreams {
			break
		}
		if m == nil {
			continue
		}
		pcodeLen := int(m.TextOffset)
		if pcodeLen < stompPCodeThreshold {
			continue
		}

		srcEffective := 0
		if len(m.CodeBytes) > 0 {
			srcEffective = effectiveSourceLen(m.CodeBytes)
		} else if m.Code != "" {
			srcEffective = effectiveSourceLen([]byte(m.Code))
		}
		if srcEffective >= stompSourceThreshold {
			continue
		}

		name := m.ModuleName
		if name == "" {
			name = m.StreamName
		}
		marker := fmt.Sprintf("VBA-STOMPED %s pcode=%d src=%d",
			name, pcodeLen, srcEffective)
		result.Streams = append(result.Streams, []byte(marker))
	}
}

// effectiveSourceLen returns the byte count of meaningful source lines —
// excluding empty lines and Attribute VB_* header lines. A stomped module
// has zero or near-zero effective source.
func effectiveSourceLen(src []byte) int {
	if len(src) == 0 {
		return 0
	}
	var total int
	for len(src) > 0 {
		line := src
		if i := bytes.IndexByte(src, '\n'); i >= 0 {
			line = src[:i]
			src = src[i+1:]
		} else {
			src = nil
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || bytes.HasPrefix(trimmed, stompAttributePrefix) {
			continue
		}
		total += len(trimmed)
	}
	return total
}

// dirModRecord holds the fields we extract per module from the VBA dir stream.
type dirModRecord struct {
	name       string
	streamName string
	offset     uint32 // MODULEOFFSET = p-code size
}

// walkDirStream parses a decompressed VBA dir stream (MS-OVBA §2.3.4.2) and
// returns the per-module records. It mirrors the logic in oleparse.ExtractMacros
// but extracts only {name, streamName, MODULEOFFSET}. Fails open on truncation.
func walkDirStream(dir []byte) ([]dirModRecord, error) {
	const maxModules = 256
	const maxRecordSize = 1 << 20

	i := 0

	readU16 := func() (uint16, bool) {
		if i+2 > len(dir) {
			return 0, false
		}
		v := binary.LittleEndian.Uint16(dir[i:])
		i += 2
		return v, true
	}
	readU32 := func() (uint32, bool) {
		if i+4 > len(dir) {
			return 0, false
		}
		v := binary.LittleEndian.Uint32(dir[i:])
		i += 4
		return v, true
	}
	skipN := func(n int) bool {
		if i+n > len(dir) {
			return false
		}
		i += n
		return true
	}
	readN := func(n int) ([]byte, bool) {
		if i+n > len(dir) {
			return nil, false
		}
		b := dir[i : i+n]
		i += n
		return b, true
	}

	const idPROJECTMODULES = uint16(0x000F)
	const idPROJECTCOOKIE = uint16(0x0013)

	// Scan for PROJECTMODULES record.
	moduleCount := 0
	for {
		id, ok := readU16()
		if !ok {
			return nil, fmt.Errorf("truncated before PROJECTMODULES")
		}
		sz, ok := readU32()
		if !ok {
			return nil, fmt.Errorf("truncated at section size")
		}
		if id == idPROJECTMODULES {
			cnt, ok := readU16()
			if !ok {
				return nil, fmt.Errorf("truncated PROJECTMODULES count")
			}
			moduleCount = int(cnt)
			if moduleCount > maxModules {
				moduleCount = maxModules
			}
			break
		}
		if sz > uint32(maxRecordSize) {
			return nil, fmt.Errorf("dir record 0x%04x size %d exceeds cap", id, sz)
		}
		if !skipN(int(sz)) {
			return nil, fmt.Errorf("truncated inside section 0x%04x", id)
		}
	}

	// Skip PROJECTCOOKIE if present.
	if id, ok := readU16(); ok {
		if id == idPROJECTCOOKIE {
			if sz, ok := readU32(); ok {
				skipN(int(sz)) //nolint:errcheck
			}
		} else {
			i -= 2 // un-read
		}
	}

	const (
		idMODULENAME        = uint16(0x0019)
		idMODULENAMEUNICODE = uint16(0x0047)
		idMODULESTREAMNAME  = uint16(0x001A)
		idMODULESTREAMNAMEr = uint16(0x0032)
		idMODULEDOCSTRING   = uint16(0x001C)
		idMODULEDOCSTRINGr  = uint16(0x0048)
		idMODULEOFFSET      = uint16(0x0031)
		idMODULEHELPCTX     = uint16(0x001E)
		idMODULECOOKIE      = uint16(0x002C)
		idMODULETYPEPROC    = uint16(0x0021)
		idMODULETYPECLS     = uint16(0x0022)
		idMODULEREADONLY    = uint16(0x0025)
		idMODULEPRIVATE     = uint16(0x0028)
		idTERMINATOR        = uint16(0x002B)
	)

	if moduleCount == 0 {
		return nil, nil
	}

	var result []dirModRecord

moduleLoop:
	for mi := 0; mi < moduleCount; mi++ {
		var rec dirModRecord

		id, ok := readU16()
		if !ok || id != idMODULENAME {
			break
		}
		sz, ok := readU32()
		if !ok {
			break
		}
		if sz > uint32(maxRecordSize) {
			return nil, fmt.Errorf("dir record 0x%04x size %d exceeds cap", idMODULENAME, sz)
		}
		nameBytes, ok := readN(int(sz))
		if !ok {
			break
		}
		rec.name = string(nameBytes)

		for {
			sid, ok2 := readU16()
			if !ok2 {
				break moduleLoop
			}
			ssz, ok2 := readU32()
			if !ok2 {
				break moduleLoop
			}
			if ssz > uint32(maxRecordSize) {
				break moduleLoop
			}
			switch sid {
			case idMODULENAMEUNICODE:
				b, ok3 := readN(int(ssz))
				if !ok3 {
					break moduleLoop
				}
				if len(b) >= 2 {
					u16s := make([]uint16, len(b)/2)
					for k := 0; k+1 < len(b); k += 2 {
						u16s[k/2] = binary.LittleEndian.Uint16(b[k:])
					}
					if s := strings.TrimRight(string(utf16.Decode(u16s)), "\x00"); s != "" {
						rec.name = s
					}
				}
			case idMODULESTREAMNAME:
				b, ok3 := readN(int(ssz))
				if !ok3 {
					break moduleLoop
				}
				rec.streamName = string(b)
				// Consume the reserved record that follows.
				if rid, ok3 := readU16(); ok3 {
					if rid == idMODULESTREAMNAMEr {
						if rsz, ok4 := readU32(); ok4 {
							skipN(int(rsz)) //nolint:errcheck
						}
					} else {
						i -= 2 // un-read
					}
				}
			case idMODULEDOCSTRING:
				if !skipN(int(ssz)) {
					break moduleLoop
				}
				if rid, ok3 := readU16(); ok3 {
					if rid == idMODULEDOCSTRINGr {
						if rsz, ok4 := readU32(); ok4 {
							skipN(int(rsz)) //nolint:errcheck
						}
					} else {
						i -= 2
					}
				}
			case idMODULEOFFSET:
				v, ok3 := readU32()
				if !ok3 {
					break moduleLoop
				}
				rec.offset = v
			case idMODULEHELPCTX, idMODULECOOKIE:
				if !skipN(int(ssz)) {
					break moduleLoop
				}
			case idMODULETYPEPROC, idMODULETYPECLS:
				if !skipN(int(ssz)) {
					break moduleLoop
				}
			case idMODULEREADONLY, idMODULEPRIVATE:
				// ssz == 0 reserved; nothing to skip
			case idTERMINATOR:
				if rec.streamName != "" {
					result = append(result, rec)
				}
				continue moduleLoop
			default:
				if !skipN(int(ssz)) {
					break moduleLoop
				}
			}
		}
	}
	return result, nil
}

// decompressOVBA calls oleparse.DecompressStream and truncates the result to
// maxBytesPerModule. This prevents a crafted compressed stream (copy-token or
// chunk-size bomb) from expanding into unbounded heap allocation.
func decompressOVBA(raw []byte) []byte {
	out := oleparse.DecompressStream(raw)
	if len(out) > maxBytesPerModule {
		out = out[:maxBytesPerModule]
	}
	return out
}

// vbaCompressStream implements the MS-OVBA CompressStream algorithm using only
// raw (uncompressed) chunks. Valid per spec §2.4.1; used in tests to build
// synthetic module streams without needing real VBA tooling.
func vbaCompressStream(src []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(0x01) // signature byte
	for len(src) > 0 {
		chunk := src
		if len(chunk) > 4096 {
			chunk = chunk[:4096]
		}
		src = src[len(chunk):]
		// Raw chunk: header word bit15=0, bits0-11 = (size-1).
		padded := make([]byte, 4096)
		copy(padded, chunk)
		hdr := uint16(len(padded)-1) & 0x0FFF // #nosec G115 -- padded is always 4096
		var hdrBuf [2]byte
		binary.LittleEndian.PutUint16(hdrBuf[:], hdr)
		out.Write(hdrBuf[:])
		out.Write(padded)
	}
	return out.Bytes()
}
