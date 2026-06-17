// Package extract is yarad's format-aware front-end. It pulls plaintext that is
// hidden inside structured container formats — primarily the run-length
// (MS-OVBA) compressed VBA macro source inside OLE2 and OOXML Office documents —
// so the YARA scanner's keyword rules can actually match it.
//
// Why it exists: ScanMem over a raw .docm sees the zip plus the MS-OVBA
// compressed macro stream, so VBA-keyword rules never fire. A scanner that only
// ever sees raw bytes is the weaker design; every real maldoc engine (ClamAV's
// unpackers, YARA's own pe/dotnet/macho modules) preprocesses structured
// formats before matching. This package is that preprocessing step, kept in its
// own package so the scanner core stays format-blind: it calls Extract and scans
// whatever extra blobs come back, knowing nothing about documents.
//
// Contract: extraction is best-effort enrichment, not a gate. Extract never
// returns an error and never panics out — for a non-container input, or on any
// parse failure (truncated, obfuscated, hostile), it reports no streams and the
// caller scans the raw bytes regardless (fail-open, matching yarad's gozer
// contract). The Result flags exist only for observability/metrics.
package extract

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// Version identifies the extraction logic. It is folded into the scanner's
// verdict-cache fingerprint, so a bump here (new extractor behaviour, an
// oleparse upgrade that changes output) invalidates cached verdicts the same
// way a rule-set change does — important for the shared Redis L2 that survives
// an image rebuild. Bump it whenever the bytes Extract emits could change.
const Version = "ole2"

// OLE2/CFB compound-document magic (legacy .doc/.xls, the vbaProject.bin
// embedded in OOXML, AND the encrypted-OOXML wrapper) and the local-file-header
// magic that starts every ZIP / OOXML (.docm/.xlsm/.pptm) archive.
var (
	oleMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	zipMagic = []byte{'P', 'K', 0x03, 0x04}
)

// Caps that bound the work a single hostile document can cause. VBA macro
// projects are small in practice; these only exist to stop a crafted
// decompression bomb or a zip stuffed with thousands of .bin entries from
// blowing the per-scan time/memory budget.
const (
	// maxStreams bounds distinct macro blobs returned per document.
	maxStreams = 256
	// maxBytesPerBin caps one vbaProject.bin read out of a zip (zip-bomb guard).
	maxBytesPerBin = 8 << 20
	// maxTotalCode caps total extracted cleartext per document.
	maxTotalCode = 16 << 20
	// maxZipEntries bounds zip directory entries walked before giving up.
	maxZipEntries = 4096
	// maxParseBins caps how many *.bin members we actually OLE-parse, so a zip
	// stuffed with thousands of tiny "macro" members can't trigger thousands of
	// oleparse runs (CPU) regardless of their individual sizes.
	maxParseBins = 64
	// maxTotalBin caps the cumulative decompressed bytes READ across all *.bin
	// members — the per-member cap alone doesn't bound the sum.
	maxTotalBin = 64 << 20
)

// Result reports what Extract found in one buffer. Streams is the only field the
// scanner needs to match rules; the booleans are for /metrics so the new code
// path is observable (how often docs arrive, yield macros, fail, or are
// encrypted) rather than invisible.
type Result struct {
	// Streams holds the decompressed VBA macro source, one cleartext blob per
	// module. The caller scans each in addition to the raw bytes.
	Streams [][]byte
	// IsDoc is true when buf was a recognised OLE2/OOXML container (magic hit),
	// whether or not any macro was found.
	IsDoc bool
	// Encrypted is true for an ECMA-376 encrypted OOXML (an OLE2 wrapper holding
	// EncryptionInfo/EncryptedPackage). The real document is AES-wrapped, so no
	// macros are extractable here — we flag it but do not decrypt (that needs a
	// full ECMA-376 implementation; see the package notes / TODO).
	Encrypted bool
	// Failed is true when extraction was attempted on a container (IsDoc) but the
	// parse errored. Distinct from "not a document" (IsDoc=false).
	Failed bool
	// Panicked is true when oleparse panicked on hostile input and was recovered.
	// Worth a separate counter: a spike points at a parser bug or a new evasion.
	Panicked bool
}

// Extract reports the plaintext hidden inside an OLE2/OOXML container — the
// decompressed VBA macro source — plus flags describing what the buffer was. For
// anything that is not a recognised container it returns the zero Result
// (IsDoc=false, no streams). It never returns an error and never panics out: a
// poison attachment degrades to a raw-only scan, never crashes the scan path.
//
// deadline bounds the OOXML extraction loop (decompression + oleparse runs are
// done before any libyara scan, so a small compressed bomb could otherwise burn
// CPU before the scan budget is ever consulted). A zero deadline means no time
// limit; the cumulative byte/count caps still apply regardless.
func Extract(buf []byte, deadline time.Time) (res Result) {
	// oleparse walks attacker-controlled binary offsets; a malformed document can
	// drive it to panic. Recover and mark it so the caller still scans raw bytes.
	defer func() {
		if recover() != nil {
			res.Failed = true
			res.Panicked = true
		}
	}()

	switch {
	case bytes.HasPrefix(buf, oleMagic):
		res.IsDoc = true
		fromOLE(buf, &res, deadline)
	case bytes.HasPrefix(buf, zipMagic):
		res.IsDoc = true
		fromOOXML(buf, &res, deadline)
	}
	return res
}

// fromOLE handles an OLE2/CFB buffer: a legacy .doc/.xls, a bare vbaProject.bin,
// or an encrypted-OOXML wrapper. It parses the compound file once, then either
// flags encryption or decompresses the VBA streams. Unlike the OOXML loop this
// is single-shot (one NewOLEFile + ExtractMacros) so it can't be interrupted
// mid-parse; instead it refuses to start when the budget is already spent or the
// legacy container is implausibly large — the raw scan still happens either way.
func fromOLE(buf []byte, res *Result, deadline time.Time) {
	if !deadline.IsZero() && time.Now().After(deadline) {
		res.Failed = true
		return
	}
	if len(buf) > maxTotalBin {
		// A multi-tens-of-MiB legacy OLE is not a normal mail macro doc; skip the
		// (uninterruptible) parse rather than risk a long stall. Raw scan stands.
		res.Failed = true
		return
	}
	ole, err := oleparse.NewOLEFile(buf)
	if err != nil {
		res.Failed = true
		return
	}
	// Encrypted OOXML stores the real (zip) document AES-wrapped in an
	// EncryptedPackage stream with key material in EncryptionInfo. oleparse finds
	// no VBA in that, so detect it explicitly: the encryption itself is the
	// signal (legit senders rarely default-password-encrypt). We do NOT decrypt.
	if ole.FindStreamByName("EncryptedPackage") != nil || ole.FindStreamByName("EncryptionInfo") != nil {
		res.Encrypted = true
		return
	}
	mods, err := oleparse.ExtractMacros(ole)
	if err != nil {
		res.Failed = true
		return
	}
	res.Streams = codes(mods, nil)
}

// fromOOXML handles a modern Office document: a ZIP whose vbaProject.bin entries
// are themselves OLE2 compound files. We read the zip in memory (no temp file)
// and decompress the VBA out of every *.bin member, mirroring oleparse.ParseFile
// but without touching disk. A zip we can't open at all is a parse failure; a
// single unparseable .bin is skipped without losing the rest.
func fromOOXML(buf []byte, res *Result, deadline time.Time) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		res.Failed = true
		return
	}
	var out [][]byte
	var totalCode, totalBin, attempted, failedBins int
	for i, f := range zr.File {
		if i >= maxZipEntries {
			break
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			res.Failed = true // ran out of time mid-extraction
			break
		}
		if !strings.HasSuffix(strings.ToLower(f.Name), ".bin") {
			continue
		}
		if attempted >= maxParseBins || totalBin >= maxTotalBin {
			break // cumulative work cap hit; stop before the next parse
		}
		if f.UncompressedSize64 > maxBytesPerBin {
			continue // skip an implausibly large "macro" container (zip bomb guard)
		}
		bin := readZipEntry(f)
		if bin == nil {
			continue
		}
		totalBin += len(bin)
		attempted++
		mods, err := oleparse.ParseBuffer(bin)
		if err != nil {
			failedBins++ // one unparseable .bin must not lose the others
			continue
		}
		out = codes(mods, out)
		if len(out) >= maxStreams {
			break
		}
		totalCode = 0
		for _, b := range out {
			totalCode += len(b)
		}
		if totalCode >= maxTotalCode {
			break
		}
	}
	res.Streams = out
	// Every .bin we tried failed to parse and nothing came out: a document that
	// looks macro-bearing but yields no usable VBA (obfuscated/corrupt/hostile).
	// Mark it failed so it shows up in extract_failed_total rather than silently
	// looking like a clean macro-free doc.
	if attempted > 0 && len(out) == 0 && failedBins == attempted {
		res.Failed = true
	}
}

// readZipEntry reads one zip member fully, bounded by maxBytesPerBin so a member
// that lies about its uncompressed size can't be used to exhaust memory.
func readZipEntry(f *zip.File) []byte {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	var b bytes.Buffer
	// Hard ceiling independent of the (untrusted) zip-header size field.
	if _, err := b.ReadFrom(io.LimitReader(rc, maxBytesPerBin)); err != nil {
		return nil
	}
	return b.Bytes()
}

// codes appends the non-empty decompressed source of each VBA module to out.
// The Code field is already cleartext (oleparse.ExtractMacros runs the MS-OVBA
// DecompressStream), which is exactly what the keyword rules need to see.
func codes(mods []*oleparse.VBAModule, out [][]byte) [][]byte {
	for _, m := range mods {
		if m == nil || m.Code == "" {
			continue
		}
		out = append(out, []byte(m.Code))
		if len(out) >= maxStreams {
			break
		}
	}
	return out
}
