package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"time"

	"github.com/bodgit/sevenzip"
	rardecode "github.com/nwaples/rardecode/v2"
)

// Nested-archive unpacking. Mail malware routinely hides the payload one or more
// archive layers deep — a .zip holding a .7z holding the real .exe/.js/.lnk, or
// a .gz-wrapped script — specifically to get past scanners that only look at the
// outer bytes. yarad already special-cases an OOXML zip for VBA, but a plain
// archive (zip/7z/rar/gz/tar) whose members are droppers was previously scanned
// only as opaque outer bytes.
//
// fromArchive unpacks an archive in memory and surfaces each member's bytes as
// its own stream so the rules match the inner file. A member that is itself an
// archive (or an OLE2/OOXML/OneNote container) is recursed into, up to a bounded
// depth, so a zip-in-7z-in-gz still reaches the payload. Everything is bounded
// by a single shared budget (depth, cumulative decompressed bytes, member count)
// so a decompression bomb or a deeply nested "quine" archive can't exhaust CPU
// or memory — the budget is the whole point of doing this carefully.
//
// Best-effort and fail-open like the rest of the package: an unreadable archive,
// an encrypted member, or a truncated entry is skipped, never fatal (Extract's
// recover still covers a panic from any decompressor).

// Archive magic bytes. zip shares zipMagic from extract.go (OOXML is a zip too,
// so a zip is handled by BOTH the OOXML macro path and this member path).
var (
	gzipMagic = []byte{0x1F, 0x8B}
	// 7z signature: '7' 'z' 0xBC 0xAF 0x27 0x1C
	sevenZMagic = []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}
	// RAR4 ("Rar!\x1a\x07\x00") and RAR5 ("Rar!\x1a\x07\x01\x00") share this prefix.
	rarMagic = []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}
)

const (
	// maxArchiveDepth bounds nesting (zip-in-7z-in-gz…). Real mail droppers nest
	// 1–2 layers; this stops an archive quine from recursing without end.
	maxArchiveDepth = 6
	// maxArchiveMembers bounds the total members unpacked across ALL layers of one
	// input — a flat guard against a zip stuffed with a million tiny entries.
	maxArchiveMembers = 4096
	// maxBytesPerMember caps one decompressed member (zip-bomb guard); the raw
	// outer scan still covers anything larger.
	maxBytesPerMember = 16 << 20
	// maxTotalArchive caps cumulative decompressed bytes across all members/layers
	// of one input — the per-member cap alone doesn't bound the sum (1000 members
	// just under the per-member cap would still be huge).
	maxTotalArchive = 128 << 20
)

// archiveBudget is the single shared accounting passed down every recursion of
// fromArchive so the caps apply to the whole nested unpack, not per-layer.
type archiveBudget struct {
	members int // members unpacked so far (all layers)
	total   int // cumulative decompressed bytes emitted (all layers)
}

func (b *archiveBudget) spent() bool {
	return b.members >= maxArchiveMembers || b.total >= maxTotalArchive
}

// isOfficeZip reports whether a zip is an OOXML/ODF Office document rather than a
// plain archive. Such a zip is handled by the macro path only — surfacing its
// parts (document.xml, sheet XML, …) would scan ordinary body text and invite
// false positives, the same reason MSI stream-dumping is CLSID-gated. OOXML
// carries a root `[Content_Types].xml`; ODF carries a `mimetype` entry whose
// content begins `application/vnd.oasis.opendocument`.
func isOfficeZip(buf []byte) bool {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return false
	}
	for i, f := range zr.File {
		if i >= maxZipEntries {
			break
		}
		switch f.Name {
		case "[Content_Types].xml": // OOXML (.docx/.xlsx/.docm/…)
			return true
		case "mimetype": // ODF (.odt/.ods/…)
			return true
		}
		// OOXML part directories: a zip carrying these is an Office document even
		// if (in a hand-built test fixture) the [Content_Types].xml is absent.
		n := f.Name
		if strings.HasPrefix(n, "word/") || strings.HasPrefix(n, "xl/") ||
			strings.HasPrefix(n, "ppt/") || strings.HasPrefix(n, "visio/") ||
			strings.HasPrefix(n, "customXml/") || strings.HasPrefix(n, "_rels/") ||
			strings.HasPrefix(n, "docProps/") {
			return true
		}
	}
	return false
}

// markEncryptedArchive emits the ARCHIVE-ENCRYPTED PURE marker the first time a
// password-protected member is seen in one input, and no more than once per
// input (the flag is the signal — repeating it per member is just noise). A
// password-protected attachment whose password is in the mail body is a strong,
// FP-safe mail-malware tell on its own: the payload is deliberately hidden from
// the scanner, so the encryption itself is the indicator. yarad cannot decrypt
// (no password), so it surfaces the marker instead of silently skipping the
// member, which is what the unpackers did before.
func markEncryptedArchive(res *Result) {
	if res.EncryptedArchive {
		return
	}
	res.EncryptedArchive = true
	res.Streams = append(res.Streams, []byte("ARCHIVE-ENCRYPTED"))
}

// isArchive reports whether buf starts with a supported archive magic. zip is
// intentionally NOT included here: the dispatcher already routes a zip to the
// OOXML path, which then also calls fromArchive — testing zipMagic here would
// double-handle it.
func isArchive(buf []byte) bool {
	return bytes.HasPrefix(buf, gzipMagic) ||
		bytes.HasPrefix(buf, sevenZMagic) ||
		bytes.HasPrefix(buf, rarMagic)
}

// fromArchive recognises a supported archive and appends each member's bytes to
// res.Streams, recursing into members that are themselves containers. Returns
// true if buf was a recognised archive (whether or not any member was emitted).
// depth is the current nesting level (0 at the top); b is the shared budget.
func fromArchive(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) bool {
	if depth > maxArchiveDepth || b.spent() || expired(deadline) {
		return false
	}
	switch {
	case bytes.HasPrefix(buf, zipMagic):
		unpackZip(buf, res, b, depth, deadline)
		return true
	case bytes.HasPrefix(buf, gzipMagic):
		unpackGzip(buf, res, b, depth, deadline)
		return true
	case bytes.HasPrefix(buf, sevenZMagic):
		unpack7z(buf, res, b, depth, deadline)
		return true
	case bytes.HasPrefix(buf, rarMagic):
		unpackRar(buf, res, b, depth, deadline)
		return true
	default:
		return false
	}
}

// emitMember accounts one decompressed member against the shared budget, appends
// it as a stream, and recurses into it if it is itself a container. The bytes are
// clamped to maxBytesPerMember before this is called.
func emitMember(data []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	defer func() {
		if recover() != nil {
			res.Panicked = true
		}
	}()
	if len(data) == 0 || b.spent() || len(res.Streams) >= maxStreams {
		return
	}
	b.members++
	b.total += len(data)
	res.Streams = append(res.Streams, data)
	res.IsArchive = true
	// Recurse: a member may be a nested archive OR another carrier we know how to
	// crack (OLE2 macro doc / MSI / .msg, OOXML, OneNote, PDF, RTF, .lnk, encoded
	// script). extractChild dispatches by magic on the shared budget so a .docm,
	// a child PDF's FlateDecode JS, or a dropped .vbe inside a zip is fully
	// extracted too (depth+1: one carrier deeper than this archive).
	extractChild(data, res, b, depth+1, deadline)
}

// readMember reads one archive member from rc, bounded by maxBytesPerMember so a
// member that lies about its size can't exhaust memory. Returns nil on error.
func readMember(rc io.Reader) []byte {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(io.LimitReader(rc, maxBytesPerMember)); err != nil {
		return nil
	}
	return buf.Bytes()
}

// unpackZip walks a zip's entries and emits each file member. This is the
// general-archive counterpart to fromOOXML (which only reads *.bin for macros):
// here every regular file member is surfaced, so a dropper zip's .exe/.js/.lnk
// gets scanned. Directory entries and the size-cap-exceeding members are skipped.
func unpackZip(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return
	}
	res.IsArchive = true
	for i, f := range zr.File {
		if i >= maxZipEntries || b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/") {
			continue
		}
		// General-purpose bit 0 set => the member is encrypted (traditional zip
		// or AE-x AES). yarad has no password, so flag it and skip the member.
		if f.Flags&0x1 != 0 {
			markEncryptedArchive(res)
			continue
		}
		if f.UncompressedSize64 > maxBytesPerMember {
			continue // implausibly large member (zip-bomb guard)
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data := readMember(rc)
		_ = rc.Close()
		emitMember(data, res, b, depth, deadline)
	}
}

// unpackGzip decompresses a single-stream gzip (and, if that stream is a tar,
// walks the tar members too — .tar.gz being the common case). A bare gzip wraps
// exactly one logical file; emit it (and recurse, so a gz-wrapped zip works).
func unpackGzip(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	gr, err := gzip.NewReader(bytes.NewReader(buf))
	if err != nil {
		return
	}
	defer gr.Close()
	res.IsArchive = true
	data := readMember(gr)
	if len(data) == 0 {
		return
	}
	// A .tar.gz: the decompressed stream is itself a tar of many members. Detect
	// and walk it rather than emitting the whole tar blob as one stream.
	if looksLikeTar(data) {
		unpackTar(data, res, b, depth, deadline)
		return
	}
	emitMember(data, res, b, depth, deadline)
}

// unpackTar walks a (already-decompressed) tar and emits each regular-file member.
func unpackTar(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	tr := tar.NewReader(bytes.NewReader(buf))
	res.IsArchive = true
	for {
		if b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		h, err := tr.Next()
		if err != nil {
			break // EOF or a corrupt header: stop, keep what we have
		}
		if h.Typeflag != tar.TypeReg || h.Size == 0 {
			continue
		}
		if h.Size > maxBytesPerMember {
			continue
		}
		data := readMember(tr)
		emitMember(data, res, b, depth, deadline)
	}
}

// looksLikeTar checks the ustar magic at offset 257 of a candidate tar block.
// A POSIX/GNU tar header carries "ustar" there; a plain non-tar gzip member won't.
func looksLikeTar(data []byte) bool {
	return len(data) >= 262 && bytes.HasPrefix(data[257:], []byte("ustar"))
}

// unpack7z walks a 7-Zip archive and emits each file member. sevenzip is pure-Go.
// Encrypted entries (no password) error on Open and are skipped.
func unpack7z(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	zr, err := sevenzip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return
	}
	res.IsArchive = true
	for _, f := range zr.File {
		if b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize > maxBytesPerMember {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			// sevenzip surfaces a password/decrypt error for an AES-encrypted
			// member (we hold no password); flag those specifically rather than
			// lumping every member error in with plain corruption.
			if isEncryptedErr(err) {
				markEncryptedArchive(res)
			}
			continue // encrypted/corrupt member: skip, keep the rest
		}
		data := readMember(rc)
		_ = rc.Close()
		emitMember(data, res, b, depth, deadline)
	}
}

// isEncryptedErr reports whether a member Open error is an encryption/password
// failure rather than generic corruption. sevenzip's AES coder returns an error
// mentioning "password"; matching on that keeps a plain-corrupt 7z from being
// mislabelled as encrypted.
func isEncryptedErr(err error) bool {
	if err == nil {
		return false
	}
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "password") || strings.Contains(e, "decrypt")
}

// unpackRar walks a RAR archive (v4/v5, pure-Go rardecode) and emits each
// regular-file member. Encrypted/solid members that error are skipped.
func unpackRar(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	rr, err := rardecode.NewReader(bytes.NewReader(buf))
	if err != nil {
		return
	}
	res.IsArchive = true
	for {
		if b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		h, err := rr.Next()
		if err != nil {
			break // EOF, encrypted-header, or corrupt: stop, keep what we have
		}
		if h.IsDir {
			continue
		}
		// Encrypted file contents or an encrypted header (whole-archive password):
		// no password here, so flag and skip. HeaderEncrypted typically also fails
		// the rr.Next() above, but a per-file Encrypted member is reachable.
		if h.Encrypted || h.HeaderEncrypted {
			markEncryptedArchive(res)
			continue
		}
		if h.UnPackedSize > maxBytesPerMember {
			continue
		}
		data := readMember(rr)
		emitMember(data, res, b, depth, deadline)
	}
}
