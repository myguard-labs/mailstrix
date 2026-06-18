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
	"encoding/xml"
	"io"
	"regexp"
	"strings"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// Version identifies the extraction logic. It is folded into the scanner's
// verdict-cache fingerprint, so a bump here (new extractor behaviour, an
// oleparse upgrade that changes output) invalidates cached verdicts the same
// way a rule-set change does — important for the shared Redis L2 that survives
// an image rebuild. Bump it whenever the bytes Extract emits could change.
const Version = "ole2+msi+vbe+msg+onenote+archive+olepkg+lnk+pdf+rtf+decode+tmplinj"

// OLE2/CFB compound-document magic (legacy .doc/.xls, the vbaProject.bin
// embedded in OOXML, AND the encrypted-OOXML wrapper) and the local-file-header
// magic that starts every ZIP / OOXML (.docm/.xlsm/.pptm) archive.
var (
	oleMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	zipMagic = []byte{'P', 'K', 0x03, 0x04}

	// relsPathRe matches OOXML relationship part paths: */_rels/*.rels or
	// _rels/*.rels (root level). The anchored suffix avoids matching paths
	// where "_rels/" appears only as a directory component somewhere other than
	// the penultimate segment (e.g. foo/_rels_backup/x.rels would not match).
	relsPathRe = regexp.MustCompile(`(^|/)_rels/[^/]+\.rels$`)
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

	// --- OOXML relationship (.rels) extraction caps ---
	// maxRelsFiles bounds how many */_rels/*.rels parts we parse per zip.
	maxRelsFiles = 128
	// maxBytesPerRels caps one .rels file read (a .rels with thousands of
	// Relationship entries is anomalous; cap prevents a memory spike).
	maxBytesPerRels = 512 << 10
	// maxExternalRels bounds how many OOXML-EXTERNAL-REL synthetic streams we
	// emit per document (one entry per suspicious external relationship).
	maxExternalRels = 64

	// --- MSI (Windows Installer) stream extraction caps ---
	// An MSI is an OLE2 database; the interesting cleartext (CustomAction
	// VBScript/JScript/PowerShell bodies, embedded DLL/EXE names in the string
	// pool) lives in its streams. These bound a hostile MSI with thousands of
	// tiny streams or one giant stream.
	//
	// maxMSIStreams bounds how many streams we emit from one MSI.
	maxMSIStreams = 256
	// maxBytesPerMSIStream caps one emitted stream (a single CustomAction script
	// is small; a multi-MiB "stream" is an embedded blob we don't want to scan
	// whole — the raw-bytes scan still covers it).
	maxBytesPerMSIStream = 4 << 20
	// maxTotalMSI caps the cumulative bytes emitted across all MSI streams.
	maxTotalMSI = 32 << 20

	// --- Outlook .msg attachment extraction caps ---
	// A .msg is an OLE2 MAPI message; nested attachment files live in
	// `__attach_version1.0_#XXXXXXXX` storages, the bytes in a
	// `__substg1.0_3701000D` (PR_ATTACH_DATA_BIN) stream. These bound a hostile
	// .msg with thousands of attachment storages or one giant attachment.
	//
	// maxMSGAttachments bounds how many attachment-data streams we emit.
	maxMSGAttachments = 128
	// maxBytesPerMSGAttach caps one emitted attachment (raw scan covers the rest).
	maxBytesPerMSGAttach = 8 << 20
	// maxTotalMSG caps the cumulative attachment bytes emitted from one .msg.
	maxTotalMSG = 48 << 20
)

// msiRootCLSID is the OLE2 root-storage CLSID for a Windows Installer database
// ({000C1084-0000-0000-C000-000000000046}) in on-disk little-endian byte order.
// Used to recognise an MSI so its streams are dumped only for real installers,
// not for every macro-less legacy OLE document (that would scan body text and
// invite false positives).
var msiRootCLSID = [16]byte{
	0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

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
	// IsMSI is true when buf was recognised as a Windows Installer database (an
	// OLE2 with the MSI root CLSID) and its streams were dumped for scanning.
	IsMSI bool
	// IsMSG is true when buf was recognised as an Outlook .msg (an OLE2 MAPI
	// message store) and its nested attachment data streams were pulled out for
	// scanning.
	IsMSG bool
	// IsPDF is true when buf was a PDF whose FlateDecode object streams were
	// inflated and surfaced for scanning.
	IsPDF bool
	// IsLNK is true when buf was a Windows shell link (.lnk) whose StringData
	// fields (command-line arguments, paths) were surfaced for scanning.
	IsLNK bool
	// IsOLEPackage is true when an OLE2 document carried an embedded OLE Package
	// object (Ole10Native stream) whose native file data was carved out.
	IsOLEPackage bool
	// IsArchive is true when buf (or a nested member) was a recognised archive
	// (zip/gz/7z/rar/tar) whose members were unpacked and surfaced for scanning.
	IsArchive bool
	// IsRTF is true when buf was recognised as an RTF document whose \objdata
	// embedded-object groups were hex-decoded and carved for scanning.
	IsRTF bool
	// IsOneNote is true when buf was recognised as a OneNote section/TOC
	// (.one/.onetoc2) and its embedded FileDataStoreObject payloads were carved
	// out for scanning.
	IsOneNote bool
	// EncodedScript is true when >=1 MS Script Encoder block (#@~^...^#~@,
	// i.e. an encoded VBScript/JScript, as in .vbe/.jse or embedded in a
	// .wsf/.hta/.html/.sct) was found and decoded to cleartext for scanning.
	EncodedScript bool
	// DecodedStreams is how many blobs the single-layer static decode pass
	// (base64/hex/whole-buffer reverse; see decode.go) appended to Streams. These
	// are the trailing len-N entries of Streams; the caller subtracts them so the
	// macro/extracted-stream metrics aren't inflated by decode output. >0 means
	// the pass fired.
	DecodedStreams int
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
		res.IsDoc = true // zip magic matched — a container attempt (per Result.IsDoc)
		// A zip is either an OOXML/ODF Office document (handle via the macro path
		// only — dumping its parts would scan ordinary body XML and invite FPs) or
		// a plain archive whose members may be droppers (unpack them). The macro
		// path also flags Failed on an unopenable (corrupt) zip; never member-dump
		// an Office doc.
		fromOOXML(buf, &res, deadline)
		if !isOfficeZip(buf) {
			fromArchive(buf, &res, &archiveBudget{}, 0, deadline)
		}
	case isArchive(buf):
		// A non-zip archive (gz/7z/rar). Unpack members (recursing into nested
		// archives/containers) so a dropped payload is scanned, not just the
		// opaque outer bytes.
		res.IsDoc = true
		fromArchive(buf, &res, &archiveBudget{}, 0, deadline)
	case isPDF(buf):
		// A PDF: inflate its FlateDecode object streams so hidden JS / actions /
		// embedded files are scanned, not buried in compressed objects.
		res.IsDoc = true
		fromPDF(buf, &res, deadline)
	case isRTF(buf):
		// An RTF document: hex-decode its \objdata embedded-object groups so a
		// dropped OLE2 doc / package / OLENativeStream payload (CVE-2017-0199 /
		// -11882, OLE2Link) is scanned, not buried in the RTF hex.
		res.IsDoc = true
		fromRTF(buf, &res, deadline)
	case isLNK(buf):
		// A Windows shell link (.lnk): surface its StringData (command-line
		// arguments / paths) so the dropper command is matched, not buried in the
		// SHLLINK binary.
		res.IsDoc = true
		fromLNK(buf, &res)
	case isOneNote(buf):
		// A standalone OneNote section (.one) — neither OLE2 nor ZIP. Carve its
		// embedded FileDataStoreObject payloads (the maldoc delivery vector).
		res.IsDoc = true
		fromOneNote(buf, &res, deadline)
	default:
		// Not a container. The buffer may still hide an MS Script Encoder block
		// (#@~^...^#~@) — an encoded VBScript/JScript that raw-byte rules can't see
		// because the script source is substituted. Found in .vbe/.jse files and
		// embedded in .wsf/.hta/.html/.sct. Decode every block to cleartext so the
		// keyword rules match. Best-effort; non-script input yields nothing.
		fromEncodedScript(buf, &res, deadline)
	}

	// After the format-specific extraction, run the single-layer static decode
	// pass over the raw buffer AND every stream surfaced above, so a base64/hex/
	// reversed payload hidden in a script body or a decompressed macro is decoded
	// and re-scanned. Snapshotted internally so decoded blobs are not re-decoded
	// (depth cap 1). Best-effort; binary container bytes are skipped.
	fromEncoded(buf, &res, deadline)
	return res
}

// expired reports whether the extraction deadline has passed. A zero deadline
// (the caller disabled the time limit) never expires. All extractor loops that
// decompress or carve attacker-controlled members consult this between items so
// extraction — which runs inside the held scan-CPU slot — cannot overrun the
// per-request wall-clock budget the scanner sets (see scanner.Scan). The
// per-item/cumulative byte and count caps still apply regardless.
func expired(deadline time.Time) bool {
	return !deadline.IsZero() && time.Now().After(deadline)
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
		// A macro-extraction error on a real MSI/.msg is expected (no VBA project),
		// so don't fail outright — fall through to the MSG (Outlook) and MSI paths,
		// which decide whether this OLE2 is one of those worth dumping.
		if !fromMSG(ole, res, deadline) && !fromMSI(ole, res, deadline) && !fromOLEPackage(ole, res, deadline) {
			res.Failed = true
		}
		return
	}
	res.Streams = codes(mods, nil)
	// An embedded OLE Package object (dropped .exe/.bat in an Ole10Native stream)
	// can ride alongside macros, so always carve it regardless of whether VBA was
	// found — it's a no-op when the doc has no package stream.
	fromOLEPackage(ole, res, deadline)
	// No VBA found: the OLE2 may instead be an Outlook .msg (pull its nested
	// attachment files out and scan them) or an MSI (dump its payload streams).
	// Both helpers are no-ops for an OLE2 that isn't theirs. Try MSG first — a
	// .msg has no MSI CLSID so the order is safe.
	if len(res.Streams) == 0 {
		if !fromMSG(ole, res, deadline) {
			fromMSI(ole, res, deadline)
		}
	}
}

// fromMSI recognises a Windows Installer database (OLE2 root CLSID == MSI) and
// appends the bytes of its streams to res.Streams so YARA rules can match the
// CustomAction script bodies and the DLL/EXE/path strings MSI keeps in its
// string pool. It is deliberately gated on the MSI CLSID: dumping every stream
// of an arbitrary macro-less OLE2 would scan ordinary document body text and
// invite false positives. Returns true if buf was an MSI (whether or not any
// stream was emitted). Bounded by the maxMSI* caps; best-effort, never panics
// out (the caller's recover still covers it).
func fromMSI(ole *oleparse.OLEFile, res *Result, deadline time.Time) bool {
	if !isMSI(ole) {
		return false
	}
	res.IsMSI = true
	var total int
	for _, d := range ole.Directory {
		if d == nil {
			continue
		}
		// Mse: 2 = stream (stg/root are 1/5); only streams carry payload bytes.
		if d.Header.Mse != 2 || d.Header.Size == 0 {
			continue
		}
		if len(res.Streams) >= maxMSIStreams || total >= maxTotalMSI || expired(deadline) {
			break
		}
		b := ole.GetStream(d.Index)
		if len(b) == 0 {
			continue
		}
		if len(b) > maxBytesPerMSIStream {
			b = b[:maxBytesPerMSIStream]
		}
		res.Streams = append(res.Streams, b)
		total += len(b)
	}
	return true
}

// isMSI reports whether the OLE2 root storage carries the MSI CLSID. The root
// directory entry is index 0 (Mse==5); guard the slice and the type before
// comparing the CLSID bytes.
func isMSI(ole *oleparse.OLEFile) bool {
	if ole == nil || len(ole.Directory) == 0 {
		return false
	}
	root := ole.Directory[0]
	if root == nil || root.Header.Mse != 5 {
		return false
	}
	return root.Header.ClsId == msiRootCLSID
}

// MSG MAPI naming (ASCII inside the OLE2 directory): the message store has a
// `__properties_version1.0` stream; each attachment is a storage named
// `__attach_version1.0_#XXXXXXXX`; the attached file bytes live in that
// storage's `__substg1.0_3701000D` (PR_ATTACH_DATA_BIN) stream — or rarely the
// `...3701000C` variant. We can't cheaply scope a stream to its parent storage
// with this flat directory API, so we emit every PR_ATTACH_DATA_BIN-named stream
// (there is one per attachment); that is exactly the set we want.
const (
	msgPropsStream  = "__properties_version1.0"
	msgAttachPrefix = "__attach_version1.0_"
	msgAttachData1  = "__substg1.0_3701000d" // PR_ATTACH_DATA_BIN (lowercased)
	msgAttachData2  = "__substg1.0_3701000c"
)

// isMSG reports whether the OLE2 is an Outlook MAPI message (.msg): it carries
// the `__properties_version1.0` store stream AND at least one attachment storage.
// Both are required so an arbitrary OLE2 that merely has a similarly named stream
// isn't misread as a .msg.
func isMSG(ole *oleparse.OLEFile) bool {
	if ole == nil {
		return false
	}
	var hasProps, hasAttach bool
	for _, d := range ole.Directory {
		if d == nil {
			continue
		}
		n := strings.ToLower(d.Name)
		if n == msgPropsStream {
			hasProps = true
		} else if strings.HasPrefix(n, msgAttachPrefix) {
			hasAttach = true
		}
		if hasProps && hasAttach {
			return true
		}
	}
	return false
}

// fromMSG recognises an Outlook .msg and appends each nested attachment's data
// stream (PR_ATTACH_DATA_BIN) to res.Streams so the embedded file is scanned by
// the rules — the attachment is the dangerous part, and it's otherwise buried in
// the OLE2 binary. Returns true if buf was a .msg (whether or not any attachment
// was emitted). Bounded by the maxMSG* caps; best-effort, never panics out (the
// caller's recover covers it). Note: a nested attachment that is itself a doc/
// archive is not recursively re-extracted here — it is scanned as raw bytes,
// which still fires container/keyword rules; deep recursion is a separate item.
func fromMSG(ole *oleparse.OLEFile, res *Result, deadline time.Time) bool {
	if !isMSG(ole) {
		return false
	}
	res.IsMSG = true
	var total int
	for _, d := range ole.Directory {
		if d == nil || d.Header.Mse != 2 || d.Header.Size == 0 {
			continue
		}
		n := strings.ToLower(d.Name)
		if n != msgAttachData1 && n != msgAttachData2 {
			continue
		}
		if len(res.Streams) >= maxMSGAttachments || total >= maxTotalMSG || expired(deadline) {
			break
		}
		b := ole.GetStream(d.Index)
		if len(b) == 0 {
			continue
		}
		if len(b) > maxBytesPerMSGAttach {
			b = b[:maxBytesPerMSGAttach]
		}
		res.Streams = append(res.Streams, b)
		total += len(b)
	}
	return true
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
	// Scan every */_rels/*.rels part for external relationships (template
	// injection, OLE object, frame, externalLink). Each hit appends a synthetic
	// "OOXML-EXTERNAL-REL <Type> <Target>" stream so YARA rules can match it.
	// Fail-open: malformed .rels parts are silently skipped.
	fromOOXMLRels(zr, &out, deadline)
	res.Streams = out
	// Every .bin we tried failed to parse and nothing came out: a document that
	// looks macro-bearing but yields no usable VBA (obfuscated/corrupt/hostile).
	// Mark it failed so it shows up in extract_failed_total rather than silently
	// looking like a clean macro-free doc.
	if attempted > 0 && len(out) == 0 && failedBins == attempted {
		res.Failed = true
	}
}

// externalRelSchemes lists the URI schemes that indicate an attacker-controlled
// remote resource in an OOXML Relationship Target.
//   - http://, https://: plain remote fetch (template injection, CVE-2017-0199)
//   - smb://: explicit SMB (NTLM relay)
//   - file://\\: UNC path encoded as file URI (file://\\server\share) — NTLM relay
//   - \\\\: raw UNC path (\\server\share) — NTLM relay
//
// Local file:// paths (file:///C:/..., file:///tmp/...) are intentionally NOT
// included: a local-path template is low-threat and high-FP.
var externalRelSchemes = []string{"http://", "https://", "smb://", "file://\\\\", "\\\\"}

// fromOOXMLRels reads every */_rels/*.rels part inside the already-opened zip,
// parses the XML Relationship entries, and appends a synthetic
// "OOXML-EXTERNAL-REL <Type> <Target>" []byte stream to *out for each entry
// whose TargetMode is "External" and whose Target starts with a suspicious URI
// scheme. The caller scans these streams alongside the VBA blobs so YARA rules
// can detect remote-template injection and similar attacks.
//
// Fail-open contract: a .rels file that cannot be read or parsed is silently
// skipped — it must never cause the whole extract to fail. Bounded by
// maxRelsFiles + maxExternalRels + maxBytesPerRels.
func fromOOXMLRels(zr *zip.Reader, out *[][]byte, deadline time.Time) {
	// xmlRel is the schema for a single <Relationship> element.
	type xmlRel struct {
		Type       string `xml:"Type,attr"`
		Target     string `xml:"Target,attr"`
		TargetMode string `xml:"TargetMode,attr"`
	}
	type xmlRels struct {
		Rels []xmlRel `xml:"Relationship"`
	}

	relsSeen := 0
	for _, f := range zr.File {
		if expired(deadline) {
			break
		}
		name := f.Name
		// Match */_rels/*.rels or _rels/*.rels (root level).
		if !relsPathRe.MatchString(name) {
			continue
		}
		if relsSeen >= maxRelsFiles {
			break
		}
		relsSeen++

		if f.UncompressedSize64 > maxBytesPerRels {
			continue // anomalously large .rels — skip
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, maxBytesPerRels))
		rc.Close() // #nosec G104 -- zip entry close; error is unrecoverable here
		if err != nil || len(raw) == 0 {
			continue
		}

		var doc xmlRels
		if err := xml.Unmarshal(raw, &doc); err != nil {
			continue // malformed XML — fail-open
		}

		for _, rel := range doc.Rels {
			if expired(deadline) {
				break
			}
			if len(*out) >= maxStreams || countExternalRels(*out) >= maxExternalRels {
				break
			}
			if !strings.EqualFold(rel.TargetMode, "External") {
				continue
			}
			target := rel.Target
			if !hasSuspiciousScheme(target) {
				continue
			}
			// Build a short type label: use the last path segment of the Type URI.
			typLabel := rel.Type
			if idx := strings.LastIndex(typLabel, "/"); idx >= 0 {
				typLabel = typLabel[idx+1:]
			}
			stream := []byte("OOXML-EXTERNAL-REL " + typLabel + " " + target)
			*out = append(*out, stream)
		}
	}
}

// hasSuspiciousScheme reports whether target starts with one of the URI schemes
// that can reach a remote or local-UNC resource in an OOXML document.
func hasSuspiciousScheme(target string) bool {
	lower := strings.ToLower(target)
	for _, scheme := range externalRelSchemes {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return false
}

// countExternalRels counts how many entries in streams start with the
// OOXML-EXTERNAL-REL synthetic marker (used to enforce maxExternalRels).
func countExternalRels(streams [][]byte) int {
	n := 0
	for _, s := range streams {
		if bytes.HasPrefix(s, []byte("OOXML-EXTERNAL-REL ")) {
			n++
		}
	}
	return n
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
