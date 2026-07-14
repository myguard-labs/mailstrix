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
	// Microsoft Cabinet
	cabMagic = []byte("MSCF")
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
	// decryptAttempts counts ALL password-decrypt attempts (candidate × encrypted
	// member) across every layer of one input, checked against maxDecryptAttempts.
	// kdfAttempts counts ONLY the expensive KDF-format attempts (WinZip-AES, 7z,
	// rar), checked against the much lower maxKDFDecryptAttempts. They are separate
	// so cheap ZipCrypto attempts can't exhaust the KDF sub-cap (and vice versa).
	// The brute-force loop over attacker-influenced candidates is the feature's
	// primary DoS surface — see archivepw.go.
	decryptAttempts int
	kdfAttempts     int
	// decryptStalled latches once a decrypt attempt for THIS input overran its
	// watchdog. The decoder that did so is still running and cannot be cancelled, so
	// every further candidate would stack another uncancellable worker on the same
	// hostile member. One stall therefore ends all decryption for the input — see
	// archiveBudget.decryptExhausted and archiveworker.go.
	decryptStalled bool
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
		// if (in a hand-built test fixture) the [Content_Types].xml is absent. Use
		// the CLASSIFICATION predicate (no bare META-INF/) so a Java .jar / Android
		// .apk — which carry META-INF/MANIFEST.MF but NONE of the office roots — is
		// NOT mistaken for an Office doc and is left to fromArchive member-unpacking.
		if isOfficeClassPart(f.Name) {
			return true
		}
	}
	return false
}

// isOfficePartName reports whether a zip entry name is a structural OOXML/ODF part
// (a document body/metadata/relationship part), NOT an arbitrary attached file.
// Used by fromOfficeZipCarriers to decide which members of an ALREADY-classified
// Office zip are body parts (left to the macro path, never member-dumped → no
// body-text FP) versus sibling files that should still be carrier-unpacked. It
// includes META-INF/ (the ODF manifest / OOXML signature dir) — safe here because
// the zip is already known to be Office.
func isOfficePartName(n string) bool {
	return isOfficeClassPart(n) || strings.HasPrefix(n, "META-INF/")
}

// isOfficeClassPart is the office-document CLASSIFICATION predicate: the part
// names that, on their own, prove a zip is an OOXML/ODF document. It deliberately
// EXCLUDES bare META-INF/ — that directory is shared with Java .jar and Android
// .apk archives (META-INF/MANIFEST.MF), so classifying on it routed every JAR/APK
// (a real Java-RAT mail vector: Adwind/jRAT/STRRAT) to the macro path instead of
// archive member-unpacking, hiding its .class / nested-jar payloads. A genuine
// ODF/OOXML doc always also carries mimetype / [Content_Types].xml / word|xl|ppt/,
// so dropping META-INF/ here loses no real Office detection.
func isOfficeClassPart(n string) bool {
	return strings.HasPrefix(n, "word/") || strings.HasPrefix(n, "xl/") ||
		strings.HasPrefix(n, "ppt/") || strings.HasPrefix(n, "visio/") ||
		strings.HasPrefix(n, "customXml/") || strings.HasPrefix(n, "_rels/") ||
		strings.HasPrefix(n, "docProps/") || n == "[Content_Types].xml" ||
		n == "mimetype"
}

// fromOfficeZipCarriers closes the spoofed-container gap: an Office-classified zip
// is handled by the macro path only (its body XML is never member-dumped, to
// avoid body-text false positives), but an attacker can drop a real dropper as a
// SIBLING member of an otherwise-valid .docx/.xlsx — e.g. a PE, a nested zip, an
// OLE2 doc, an RTF, a PDF, a .lnk, or an encoded script. Those members are NOT
// office body parts, so unpacking only the ones that are themselves a recognised
// CARRIER (by magic) recovers the dropper with zero body-text FP risk: a plain
// text/XML body part matches no carrier magic and is left untouched. Bounded by
// the shared archive budget/depth/deadline and the per-member size cap, exactly
// like fromArchive.
func fromOfficeZipCarriers(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	if b == nil || depth > maxNestDepth || b.spent() || expired(deadline) {
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return
	}
	for i, f := range zr.File {
		if i >= maxZipEntries || b.spent() || expired(deadline) || len(res.Streams) >= maxStreams {
			break
		}
		// Skip office body/metadata/relationship parts — the macro path owns those.
		if isOfficePartName(f.Name) {
			continue
		}
		if f.UncompressedSize64 > maxBytesPerBin {
			continue // zip-bomb guard, mirrors the .bin cap
		}
		data := readZipEntry(f)
		if len(data) == 0 {
			continue
		}
		// Only route members that are themselves a recognised carrier; a non-carrier
		// (ordinary attached text/image) matches no magic in extractChild and would
		// just be appended as a raw stream — which for an Office sibling is exactly
		// the body-text FP we avoid, so gate on carrier magic here.
		if !isNestedCarrier(data) {
			continue
		}
		b.members++
		b.total += len(data)
		res.Streams = append(res.Streams, data)
		extractChild(data, res, b, depth+1, deadline)
	}
}

// isNestedCarrier reports whether data begins with the magic of a container yarad
// knows how to crack further (so routing it through extractChild adds signal).
// A buffer that is none of these is left to the raw scan, never member-dumped.
func isNestedCarrier(data []byte) bool {
	return bytes.HasPrefix(data, zipMagic) || isArchive(data) ||
		bytes.HasPrefix(data, oleMagic) || isPDF(data) || isRTF(data) ||
		isLNK(data) || isOneNote(data) || isTNEF(data) || isValidPEAt(data, 0) ||
		bytes.HasPrefix(data, cabMagic)
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
		bytes.HasPrefix(buf, rarMagic) ||
		bytes.HasPrefix(buf, cabMagic)
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
	case bytes.HasPrefix(buf, cabMagic):
		unpackCab(buf, res, b, depth, deadline)
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
// readMember reads one archive member, hard-capped at maxBytesPerMember. declared
// is the member's declared uncompressed size (0 when the format/stream does not
// expose one); PERF-40 uses it to pre-size the buffer via preallocHint, clamped to
// the hard cap and the anti-amplification ceiling, so an honest modest member
// avoids regrow churn while a lying header can force at most maxPreallocHint of
// speculative allocation.
func readMember(rc io.Reader, declared uint64) []byte {
	var buf bytes.Buffer
	if h := preallocHint(declared, maxBytesPerMember); h > 0 {
		buf.Grow(h)
	}
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
	// pwc is non-nil only when MAILSTRIX_ARCHIVE_PW is enabled and candidates were
	// sourced. zdec is a lazily-built yeka/zip reader over the same buffer, used to
	// decrypt encrypted members (std archive/zip cannot decrypt). zfound caches the
	// build so a second encrypted member reuses it (or skips after a build failure).
	pwc := pwCandidates(res)
	var zdec *zipDecryptReader
	for i, f := range zr.File {
		if i >= maxZipEntries || b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/") {
			continue
		}
		// General-purpose bit 0 set => the member is encrypted (traditional zip
		// or AE-x AES). With no candidates (feature off) we cannot decrypt, so flag
		// it and skip. With candidates, try a bounded decrypt and, on success, emit
		// the plaintext as a normal member; on failure keep the encrypted signal.
		if f.Flags&0x1 != 0 {
			if len(pwc) == 0 {
				markEncryptedArchive(res)
				continue
			}
			if zdec == nil {
				zdec = newZipDecryptReader(buf)
			}
			// AES (KDF-bound) vs ZipCrypto (cheap) is read straight off the std-zip
			// member's validated AE-x extra — no extra yeka parse, so a post-cap
			// member pays nothing.
			plain := zdec.decryptMember(i, hasAESExtra(f.Extra), f.UncompressedSize64, pwc, b, deadline)
			if plain == nil {
				markEncryptedArchive(res)
				continue
			}
			// Emit the payload BEFORE the marker so a maxStreams cap hit can never
			// drop the decrypted dropper in favour of the marker.
			emitMember(plain, res, b, depth, deadline)
			markDecryptedArchive(res)
			continue
		}
		if f.UncompressedSize64 > maxBytesPerMember {
			continue // implausibly large member (zip-bomb guard)
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data := readMember(rc, f.UncompressedSize64)
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
	data := readMember(gr, 0) // gzip stream exposes no reliable uncompressed size
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
		var decl uint64
		if h.Size > 0 {
			decl = uint64(h.Size)
		}
		data := readMember(tr, decl)
		emitMember(data, res, b, depth, deadline)
	}
}

// looksLikeTar checks the ustar magic at offset 257 of a candidate tar block.
// A POSIX/GNU tar header carries "ustar" there; a plain non-tar gzip member won't.
func looksLikeTar(data []byte) bool {
	return len(data) >= 262 && bytes.HasPrefix(data[257:], []byte("ustar"))
}

// unpack7z walks a 7-Zip archive and emits each file member. sevenzip is pure-Go.
//
// 7z gives NO reliable "this is encrypted" signal: a content-encrypted member
// Opens cleanly and only fails on Read (the decrypt garbage trips lzma), and a
// header-encrypted archive fails NewReader with a generic parse error — neither
// mentions "password". So encryption is detected EMPIRICALLY: when a member can't
// be read (or the whole reader won't open) and password candidates are available,
// attempt a bounded crack; a candidate that opens+reads the archive proves it was
// encrypted. One 7z password unlocks the whole archive, so the crack is done once.
func unpack7z(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	pwc := pwCandidates(res)
	zr, err := sevenzip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		// The reader won't open. This is either a header-encrypted 7z (the file
		// list itself is AES-wrapped) or plain corruption. With candidates, try to
		// crack — success means it was header-encrypted; otherwise classify via the
		// (best-effort) error text so a clearly-encrypted error still marks.
		res.IsArchive = true
		if len(pwc) > 0 {
			// Header-encrypted: no specific trigger member (the whole listing is
			// hidden), so verify against any member — targetIdx -1.
			if pw := crack7zPassword(buf, -1, pwc, b, deadline); pw != "" {
				if dr := open7zReader(buf, pw); dr != nil {
					// Emit members first; mark decrypted only if ≥1 payload landed, so
					// a maxStreams cap can't sacrifice the dropper for the marker.
					if emit7zMembers(dr, res, b, depth, deadline) {
						markDecryptedArchive(res)
					} else {
						markEncryptedArchive(res)
					}
					return
				}
			}
			// Candidates were tried and none worked. A NewReader failure on a valid 7z
			// (magic already matched by the dispatcher) is overwhelmingly a header-
			// encrypted archive whose listing we couldn't read — preserve the encrypted
			// signal even though the generic parse error doesn't say "password".
			markEncryptedArchive(res)
			return
		}
		if isEncryptedErr(err) {
			markEncryptedArchive(res)
		}
		return
	}
	res.IsArchive = true
	// dec is a lazily-cracked password reader, built the first time a member fails
	// to read and candidates are available; one password serves every member.
	var dec *sevenzip.Reader
	decTried := false
	tryCrackOnce := func(targetIdx int) {
		if !decTried {
			decTried = true // crack once; a failed crack is not retried per member
			// Validate the password against the member that actually failed the
			// plaintext read (the encrypted one), not a sibling plaintext member.
			if pw := crack7zPassword(buf, targetIdx, pwc, b, deadline); pw != "" {
				dec = open7zReader(buf, pw)
			}
		}
	}
	for i, f := range zr.File {
		if b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize > maxBytesPerMember {
			continue
		}
		// Attempt the plaintext read first. ok=false means Open/Read failed — for a
		// content-encrypted member the decrypt garbage trips the decompressor, which
		// is indistinguishable from corruption here, so on !ok with candidates we
		// fall through to a password crack. An empty member reads ok (empty plaintext)
		// and must NOT be mistaken for encryption.
		if data, ok := open7zMemberPlain(f); ok {
			emitMember(data, res, b, depth, deadline)
			continue
		}
		if len(pwc) == 0 {
			// No candidates: an unreadable member might be encrypted or corrupt. The
			// pre-feature behaviour marked encrypted only on an isEncryptedErr Open;
			// preserve that conservative signal by re-checking the Open error.
			if _, oerr := f.Open(); isEncryptedErr(oerr) {
				markEncryptedArchive(res)
			}
			continue
		}
		tryCrackOnce(i)
		if dec == nil {
			markEncryptedArchive(res)
			continue
		}
		if data, ok := boundedDecrypted7zMember(dec.File, i, b, deadline); ok {
			// Payload before marker so a maxStreams cap can't drop the dropper.
			emitMember(data, res, b, depth, deadline)
			markDecryptedArchive(res)
		} else {
			markEncryptedArchive(res)
		}
	}
}

// open7zMemberPlain opens and reads a 7z member with no password, bounded by
// maxBytesPerMember, under an unconditional recover. Returns (data, true) on a
// clean read (data may be empty for a legitimately empty member) and (nil, false)
// on any failure (encrypted member, corrupt stream) — the caller treats !ok as
// "try a password crack if candidates exist".
func open7zMemberPlain(f *sevenzip.File) (out []byte, ok bool) {
	defer func() {
		if recover() != nil {
			out, ok = nil, false
		}
	}()
	rc, err := f.Open()
	if err != nil {
		return nil, false
	}
	defer func() { _ = rc.Close() }()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(io.LimitReader(rc, maxBytesPerMember)); err != nil {
		return nil, false // decrypt-garbage tripped the decompressor, or truncation
	}
	return buf.Bytes(), true // clean read (possibly empty for an empty member)
}

// emit7zMembers walks an already-decrypted 7z reader (the header-encrypted case,
// where the whole listing was hidden) and emits each regular-file member. Bounded
// by the shared budget/deadline and the per-member size cap, like unpack7z.
func emit7zMembers(zr *sevenzip.Reader, res *Result, b *archiveBudget, depth int, deadline time.Time) (emitted bool) {
	for i, f := range zr.File {
		if b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		if f.FileInfo().IsDir() || f.UncompressedSize > maxBytesPerMember {
			continue
		}
		data, ok := boundedDecrypted7zMember(zr.File, i, b, deadline)
		if !ok || len(data) == 0 {
			if b.decryptExhausted() {
				break // stalled decoder: stop walking this archive entirely
			}
			continue
		}
		emitMember(data, res, b, depth, deadline)
		emitted = true
	}
	return emitted
}

// memberRead is openDecrypted7zMember's (data, ok) pair boxed into one value, so the
// read can be handed to the single-result runBounded.
type memberRead struct {
	data []byte
	ok   bool
}

// boundedDecrypted7zMember reads a member with the CRACKED password on a pooled
// worker. Cracking the password does not make the member safe: the decrypt+LZMA of
// attacker-authored plaintext is the same uncancellable third-party code the crack
// loop runs, and it can spin just as easily. Without the pool this read would escape
// the containment entirely — the crack would land inside a worker slot and then the
// (unbounded) extraction would run on the scan goroutine. A stall latches the budget,
// so the remaining members of a hostile archive are not fed to the decoder as well.
func boundedDecrypted7zMember(files []*sevenzip.File, idx int, b *archiveBudget, deadline time.Time) ([]byte, bool) {
	if b.decryptExhausted() {
		return nil, false // already stalled/capped: launch no more decoder work
	}
	r, stalled := runBounded(deadline, func() memberRead {
		data, ok := openDecrypted7zMember(files, idx)
		return memberRead{data: data, ok: ok}
	})
	if stalled {
		b.markDecryptStalled()
		return nil, false
	}
	return r.data, r.ok
}

// openDecrypted7zMember opens the member at index idx in files and reads it,
// bounded by maxBytesPerMember, under an unconditional recover (the decrypt +
// decompress runs on hostile input). Returns (data, true) on a clean read,
// (nil, false) on miss / error / oversize. Call it through
// boundedDecrypted7zMember — it must not run on the scan goroutine.
func openDecrypted7zMember(files []*sevenzip.File, idx int) (out []byte, ok bool) {
	defer func() {
		if recover() != nil {
			out, ok = nil, false
		}
	}()
	if idx < 0 || idx >= len(files) {
		return nil, false
	}
	f := files[idx]
	if f.FileInfo().IsDir() || f.UncompressedSize > maxBytesPerMember {
		return nil, false
	}
	rc, err := f.Open()
	if err != nil {
		return nil, false
	}
	defer func() { _ = rc.Close() }()
	data := readMember(rc, f.UncompressedSize)
	if data == nil {
		return nil, false // read/decompress failure: not a clean decrypt
	}
	return data, true
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
		if !isEncryptedErr(err) {
			return
		}
		res.IsArchive = true
		// A whole-archive header-encrypted RAR fails construction. With candidates,
		// crack the archive password and walk the now-readable listing; otherwise
		// emit ARCHIVE-ENCRYPTED.
		if pwc := pwCandidates(res); len(pwc) > 0 {
			if pw := crackRarPassword(buf, pwc, b, deadline); pw != "" {
				if dr := openRarReader(buf, pw); dr != nil {
					// Marker emitted per successfully-read member inside the walk; if
					// the walk landed nothing (cap/deadline), fall through to mark
					// encrypted so the signal isn't lost.
					if emitRarMembers(dr, buf, true, res, b, depth, deadline) {
						return
					}
				}
			}
		}
		markEncryptedArchive(res)
		return
	}
	res.IsArchive = true
	emitRarMembers(rr, buf, false, res, b, depth, deadline)
}

// emitRarMembers walks a rardecode reader and emits each regular-file member. buf
// is the original archive bytes (needed to re-open with a password); cracked marks
// rr as an already-password-unlocked reader. When a per-file-encrypted member is
// hit on a NON-cracked reader and candidates are available, it cracks the archive
// password once and re-walks via a fresh password reader (RAR applies one password
// per archive), decrypting this and the remaining encrypted members.
func emitRarMembers(rr *rardecode.Reader, buf []byte, cracked bool, res *Result, b *archiveBudget, depth int, deadline time.Time) (emitted bool) {
	for {
		if b.spent() || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		h, err := rr.Next()
		if err != nil {
			if isEncryptedErr(err) {
				// A header-encrypted RAR can surface its encryption HERE (at Next())
				// rather than at NewReader. On a non-cracked reader with candidates,
				// crack and re-walk via a password reader before giving up.
				if pwc := pwCandidates(res); !cracked && len(pwc) > 0 {
					if pw := crackRarPassword(buf, pwc, b, deadline); pw != "" {
						if dr := openRarReader(buf, pw); dr != nil {
							if emitRarMembers(dr, buf, true, res, b, depth, deadline) {
								return true
							}
						}
					}
				}
				markEncryptedArchive(res)
			}
			break // EOF, encrypted-header, or corrupt: stop, keep what we have
		}
		if h.IsDir {
			continue
		}
		// Encrypted file contents or an encrypted header (whole-archive password).
		if h.Encrypted || h.HeaderEncrypted {
			if cracked {
				// rr already carries the correct password — DON'T skip; read the
				// member (the reader decrypts it transparently). On an oversized
				// member or a read failure, keep the ARCHIVE-ENCRYPTED signal so the
				// hidden-payload tell isn't silently lost.
				if h.UnPackedSize > maxBytesPerMember {
					markEncryptedArchive(res)
					continue
				}
				var decl uint64
				if h.UnPackedSize > 0 {
					decl = uint64(h.UnPackedSize)
				}
				if data := readMember(rr, decl); data != nil {
					// Payload before marker so a maxStreams cap can't drop the dropper.
					emitMember(data, res, b, depth, deadline)
					markDecryptedArchive(res)
					emitted = true
				} else {
					markEncryptedArchive(res)
				}
				continue
			}
			// Non-cracked reader: crack once and re-walk through a password reader so
			// this and the remaining encrypted members decrypt. If the cracked re-walk
			// lands NO payload (cap/deadline stopped it before the dropper), keep the
			// ARCHIVE-ENCRYPTED signal so the hidden-payload tell isn't lost.
			if pwc := pwCandidates(res); len(pwc) > 0 {
				if pw := crackRarPassword(buf, pwc, b, deadline); pw != "" {
					if dr := openRarReader(buf, pw); dr != nil {
						if emitRarMembers(dr, buf, true, res, b, depth, deadline) {
							return true
						}
						markEncryptedArchive(res)
						return emitted
					}
				}
			}
			markEncryptedArchive(res)
			continue
		}
		// Plaintext member. On the cracked RE-WALK these were already emitted by the
		// first (non-cracked) pass, so DON'T re-emit — re-emitting would burn the
		// member/stream budget before the encrypted dropper is reached. Read-and-
		// discard to keep the rardecode stream positioned, but bound it: skip an
		// oversized sibling (past the per-member cap) outright so a hostile archive
		// can't force repeated 16MiB inflates during the replay.
		if cracked {
			if h.UnPackedSize > 0 && h.UnPackedSize <= maxBytesPerMember {
				_ = readMember(rr, uint64(h.UnPackedSize))
			}
			continue
		}
		if h.UnPackedSize > maxBytesPerMember {
			continue
		}
		var decl uint64
		if h.UnPackedSize > 0 {
			decl = uint64(h.UnPackedSize)
		}
		data := readMember(rr, decl)
		emitMember(data, res, b, depth, deadline)
		emitted = true
	}
	return emitted
}
