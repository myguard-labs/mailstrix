package extract

import "bytes"

// Archive-solidity detection for RAR (audit A10).
//
// WHY THIS EXISTS. rardecode drains a solid member's body INLINE, on whatever
// goroutine calls Next(): decodeReader.nextFile() does `if d.solid { io.Copy(io.Discard, d) }`
// (decode_reader.go:345). That drain is an uncancellable, time-unbounded decode of
// attacker-authored bytes — exactly what A8/A9 exist to keep off the scan goroutine.
//
// The per-member guard in emitRarMembers (h.Solid) CANNOT stop it. h.Solid is the
// PER-FILE flag (file5CompSolid, archive50.go:373), but the drain fires on d.solid,
// which is the ARCHIVE-level flag (arc5Solid, archive50.go:469; arcSolid,
// archive15.go:350). In a solid archive the FIRST member has h.Solid == false —
// nothing precedes it — so it sails past the guard, gets read, and the NEXT Next()
// drains its body on the scan goroutine before any h.Solid == true header is ever
// seen. rardecode does not export archive-solidity over an in-memory reader, so the
// only way to learn it before handing bytes to the decoder is to read the flag out
// of the main archive header ourselves. That is all this file does.
//
// This is a pure header parse: fixed-width fields and varints, no decompression, no
// third-party call, no unbounded loop. It is safe to run inline on the scan goroutine.
//
// FAIL-SAFE, NOT FAIL-OPEN. Every "I can't parse this" path returns true (assume
// solid ⇒ refuse the archive). A malformed or truncated header must not be a way to
// talk us into running the decoder: if an attacker could make the parse fail and
// thereby get treated as non-solid, the whole guard would be bypassable by corrupting
// one byte. Refusing a corrupt archive costs us nothing — rardecode would have failed
// on it anyway.

const (
	// Main archive block flags. Same meaning in both formats, different bit and
	// different framing, hence two parsers.
	rar5ArcSolid = 0x0004 // arc5Solid,  archive50.go:39
	rar4ArcSolid = 0x0008 // arcSolid,   archive15.go:30

	rar5BlockArc      = 1      // block5Arc,      archive50.go:19
	rar5BlockHasExtra = 0x0001 // block5HasExtra, archive50.go:26
	rar5BlockHasData  = 0x0002 // block5HasData,  archive50.go:27

	rar4BlockArc = 0x73 // blockArc, archive15.go

	// Bound the walk to the archive-block search. The main block is the FIRST block
	// after the signature in both formats, so we never need to scan far; this is a
	// belt-and-braces cap against a crafted header chain, not a real limit.
	rarMaxBlockScan = 8
)

// rarSigPrefix and rarMaxSfxSize MUST match rardecode's findSig (bufio.go). rardecode
// does NOT require the signature at offset 0: to support self-extracting archives it
// scans the first maxSfxSize bytes for "Rar!\x1a\x07" and opens the archive at the first
// signature it finds. If our guard only checked offset 0 while rardecode scanned, an
// attacker could PREPEND a decoy — a valid sigPrefix with an invalid version byte, which
// rardecode skips — in front of a real solid archive: we would find no offset-0 match,
// call it non-solid, and hand the buffer to rardecode, which finds the real signature and
// drains the solid body on the scan goroutine. The whole DoS back, for a few bytes. So we
// locate the signature EXACTLY as rardecode does, and parse from THAT offset.
const (
	rarSigPrefix  = "Rar!\x1a\x07"
	rarMaxSfxSize = 0x100000 // maxSfxSize, bufio.go:11
)

// rarArchiveIsSolid reports whether buf is a RAR archive whose MAIN header carries
// the archive-level solid flag — i.e. whether rardecode's Next() will drain member
// bodies inline. It returns true for anything it cannot confidently parse as a
// non-solid RAR (see the fail-safe note above), so a true result means "refuse", not
// "definitely solid".
func rarArchiveIsSolid(buf []byte) bool {
	off, ver, found := rarFindSig(buf)
	if !found {
		// No signature rardecode would accept ⇒ rardecode's own findSig returns ErrNoSig
		// and never opens the archive, so its solid drain never runs. Safe as non-solid.
		return false
	}
	body := buf[off:]
	if ver == 0 {
		return rar4ArchiveIsSolid(body)
	}
	return rar5ArchiveIsSolid(body)
}

// rarFindSig mirrors rardecode's bufVolumeReader.findSig (bufio.go): it scans the first
// maxSfxSize bytes for "Rar!\x1a\x07" and, at each candidate, reads the version byte —
// ver==0 selects the RAR4 format (signature is 7 bytes) and a version of 1 followed by a
// 0 byte selects RAR5 (8 bytes). Any other version byte is skipped and the scan
// continues, EXACTLY as rardecode does, so we settle on the same archive rardecode would.
//
// It returns the offset of the first byte AFTER the accepted signature, the format
// version (0 for RAR4, 1 for RAR5), and whether one was found.
func rarFindSig(buf []byte) (off, ver int, found bool) {
	i := 0
	for i <= rarMaxSfxSize {
		rel := bytes.IndexByte(buf[i:], rarSigPrefix[0])
		if rel < 0 {
			return 0, 0, false
		}
		i += rel
		if i > rarMaxSfxSize {
			return 0, 0, false
		}
		// Need the prefix plus two more bytes (version + the RAR5 discriminator) to
		// classify, matching findSig's sigPrefixLen+2 requirement.
		if i+len(rarSigPrefix)+2 > len(buf) {
			return 0, 0, false
		}
		if !bytes.HasPrefix(buf[i:], []byte(rarSigPrefix)) {
			i++
			continue
		}
		v := int(buf[i+len(rarSigPrefix)])
		switch {
		case v == 0: // RAR 1.5–4.x
			return i + len(rarSigPrefix) + 1, 0, true
		case buf[i+len(rarSigPrefix)+1] == 0: // RAR5
			return i + len(rarSigPrefix) + 2, 1, true
		default:
			i++ // decoy signature (bad version byte): rardecode skips it, so do we
		}
	}
	return 0, 0, false
}

// rar5ArchiveIsSolid parses RAR5 block headers looking for the archive block.
//
// RAR5 block framing (archive50.go readBlockHeader): crc32 (4 bytes), then a varint
// header size counting the bytes AFTER the size field, then the header body —
// htype (varint), flags (varint), optional extra size (varint), optional data size
// (varint), then type-specific data. For the archive block that data begins with the
// archive flags varint (parseArcBlock, archive50.go:467).
//
// A block5Encrypt block means the headers themselves are encrypted; we cannot read
// the archive flags at all, so we refuse (true).
func rar5ArchiveIsSolid(b []byte) bool {
	for scan := 0; scan < rarMaxBlockScan; scan++ {
		if len(b) < 4 {
			return true // truncated: refuse
		}
		b = b[4:] // skip header crc32

		hdrSize, n := rar5Uvarint(b)
		hsz, ok := fitsWithin(hdrSize, len(b)-n)
		if n == 0 || hdrSize == 0 || !ok {
			return true // unparseable or overlong header: refuse
		}
		hdr := b[n : n+hsz]
		next := b[n+hsz:]

		htype, n := rar5Uvarint(hdr)
		if n == 0 {
			return true
		}
		hdr = hdr[n:]

		flags, n := rar5Uvarint(hdr)
		if n == 0 {
			return true
		}
		hdr = hdr[n:]

		// Encrypted headers: the archive flags are unreadable. Refuse.
		if htype == rar5BlockEncrypt {
			return true
		}

		if flags&rar5BlockHasExtra != 0 {
			if _, n = rar5Uvarint(hdr); n == 0 {
				return true
			}
			hdr = hdr[n:]
		}
		var dataSize uint64
		if flags&rar5BlockHasData != 0 {
			dataSize, n = rar5Uvarint(hdr)
			if n == 0 {
				return true
			}
			hdr = hdr[n:]
		}

		if htype == rar5BlockArc {
			arcFlags, n := rar5Uvarint(hdr)
			if n == 0 {
				return true // archive block we can't read: refuse
			}
			return arcFlags&rar5ArcSolid != 0
		}

		// Not the archive block. Step over it (header + its data payload) and retry.
		// The archive block is normally first, so this is near-unreachable in practice.
		dsz, ok := fitsWithin(dataSize, len(next))
		if !ok {
			return true
		}
		b = next[dsz:]
	}
	return true // never found an archive block: refuse
}

const rar5BlockEncrypt = 4 // block5Encrypt, archive50.go:21

// rar4ArchiveIsSolid parses RAR4 block headers looking for the archive block.
//
// RAR4 block framing (archive15.go readBlockHeader): crc16 (2 bytes), htype (1 byte),
// flags (uint16 LE), size (uint16 LE) — 7 bytes, with size counting the WHOLE header
// including those 7. The archive block's solid bit lives in that flags field
// (parseArcBlock, archive15.go:350), so unlike RAR5 there is nothing further to parse.
func rar4ArchiveIsSolid(b []byte) bool {
	for scan := 0; scan < rarMaxBlockScan; scan++ {
		if len(b) < 7 {
			return true // truncated: refuse
		}
		htype := b[2]
		flags := uint16(b[3]) | uint16(b[4])<<8
		size := int(uint16(b[5]) | uint16(b[6])<<8)

		if htype == rar4BlockArc {
			return flags&rar4ArcSolid != 0
		}
		if size < 7 || size > len(b) {
			return true // corrupt framing: refuse
		}
		b = b[size:]
	}
	return true // never found an archive block: refuse
}

// fitsWithin reports whether the attacker-supplied size v fits within a buffer of the
// given (non-negative) length, returning it as an int when it does. The comparison is
// done entirely in uint64 space, so the returned int() conversion only ever runs on a
// value already proven <= limit, i.e. bounded by a real in-memory slice length and
// therefore not subject to overflow (including on 32-bit builds).
func fitsWithin(v uint64, limit int) (int, bool) {
	if limit < 0 || v > uint64(limit) {
		return 0, false
	}
	// #nosec G115 -- v <= limit is proven above and limit is a slice length, so this
	// conversion cannot overflow (the whole point of this helper is to make that provable).
	return int(v), true
}

// rar5Uvarint decodes rardecode's little-endian base-128 varint (readBuf.uvarint).
// It returns the value and the number of bytes consumed, or n == 0 if the buffer is
// truncated or the value is overlong (>10 bytes, i.e. cannot fit a uint64).
func rar5Uvarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		v |= uint64(c&0x7f) << uint(7*i)
		if c&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}
