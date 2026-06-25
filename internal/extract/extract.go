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
	"unicode"
	"unicode/utf8"

	"www.velocidex.com/golang/oleparse"
)

// Version identifies the extraction logic. It is folded into the scanner's
// verdict-cache fingerprint, so a bump here (new extractor behaviour, an
// oleparse upgrade that changes output) invalidates cached verdicts the same
// way a rule-set change does — important for the shared Redis L2 that survives
// an image rebuild. Bump it whenever the bytes Extract emits could change.
const Version = "ole2+msi+vbe+msg+onenote+archive+olepkg+lnk+pdf+rtf+decode+tmplinj+dde+xlm+stomp+userform+docprops+strfold+rtftricks+xlmfold+strrev+environ+dridex+oleid+bounds+ole2link+pdfdeepen+msd+pdflex+nested+pdfendstr+pdffilter+defang+msdenc+msddeep+xlmbiff+xlsb+slk+xlminterp+oledir+oletimes+enctype+digsig+pdfendstr2+rtfquote+csvdde+effort4+xlmbinop+xlmdde+xlmname+dsf+defaultpw+defaultpwrc4+pptvba+xlmemul+xlmemulbiff+xlmemuldepth+oleid2+ddews+docsec+dcufpayload+xlmstack+oleextra+htmlsmuggle+encarchive+polyglot+xll+htmlnested+encarchivehdr+onenoterec+rtfcfbole+fmtcaplocal+csvquote+nestedooxmlopts+ddeparts"

// Options carries the per-request extraction caps (EFFORT-4) plus the time
// budget. It is resolved once per scan from the effort level and threaded to the
// two cap-sink chains that honour a per-request bound: the MSD multi-layer decode
// (DecodeDepth/DecodeIterations) and the PDF structural-indicator pass
// (PDFDeepen). Every other extractor still consults Deadline directly; only these
// two read effort-scaled caps today. A higher effort level widens the caps; the
// scanner builds Options from EffortProfileFor (see yarad.EffortProfile).
//
// Deadline mirrors the old bare deadline argument (zero == no time limit). The
// cap fields are floored to sane minimums by their read-sites so a zero-value
// Options (e.g. a test passing &Options{}) degrades to the shallowest safe
// behaviour rather than an unbounded or zero-depth walk.
type Options struct {
	Deadline time.Time // zero == no wall-clock limit (mirrors the old deadline arg)

	// DecodeDepth caps the MSD multi-layer static-decode recursion (decodeSourceTree).
	// DecodeIterations caps worklist dequeues per source stream. Both are floored
	// to 1 at the read-site. Effort scales these: a low level unwraps fewer layers.
	DecodeDepth      int
	DecodeIterations int

	// PDFDeepen enables the pdfid-style structural-indicator pass over a PDF
	// (fromPDFIndicators). Disabled at low effort: only the inflated object streams
	// are scanned, not the action/JS/launch name markers.
	PDFDeepen bool

	// XLMFoldSheets caps the number of macrosheets scanned per document by the
	// XLM constant-fold pass. 0 means use the package default (maxXLMFoldSheets).
	XLMFoldSheets int
	// XLMFoldFormulas caps the number of formulas processed per macrosheet by the
	// XLM constant-fold pass. 0 means use the package default (maxXLMFoldFormulas).
	XLMFoldFormulas int
}

// FullOptions returns an Options at maximum depth for the given deadline — the
// historical always-on behaviour. Used by tests and any caller that wants no
// effort scaling. Values mirror the extract package's own ceilings.
func FullOptions(deadline time.Time) *Options {
	return &Options{
		Deadline:         deadline,
		DecodeDepth:      maxDecodeDepth,
		DecodeIterations: maxDecodeIterations,
		PDFDeepen:        true,
		XLMFoldSheets:    maxXLMFoldSheets,
		XLMFoldFormulas:  maxXLMFoldFormulas,
	}
}

// xlmFoldSheets returns the effective sheet cap for the XLM fold pass.
// Falls back to the package constant when the field is zero (unset), and
// clamps to the package ceiling: the effort dial may only SHED work, never
// raise the cap above the always-on bound (anti-amplifier defense).
func (o *Options) xlmFoldSheets() int {
	if o != nil && o.XLMFoldSheets > 0 && o.XLMFoldSheets < maxXLMFoldSheets {
		return o.XLMFoldSheets
	}
	return maxXLMFoldSheets
}

// xlmFoldFormulas returns the effective formula cap for the XLM fold pass.
// Falls back to the package constant when the field is zero (unset), and
// clamps to the package ceiling (see xlmFoldSheets — effort may only shed).
func (o *Options) xlmFoldFormulas() int {
	if o != nil && o.XLMFoldFormulas > 0 && o.XLMFoldFormulas < maxXLMFoldFormulas {
		return o.XLMFoldFormulas
	}
	return maxXLMFoldFormulas
}

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
	// maxBytesPerModule clamps one decompressed VBA module's cleartext. A crafted
	// vbaProject.bin can ask oleparse's MS-OVBA DecompressStream to expand a tiny
	// stream into hundreds of MiB (copy-token bomb); even though ExtractMacros has
	// already paid that cost, copying the whole blob into res.Streams is the OOM
	// amplifier yarad controls, so truncate per module before it lands.
	maxBytesPerModule = 4 << 20
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
	// Markers holds yarad's synthetic PURE marker entries (no attacker-controlled
	// data) split out of Streams at the end of extraction — the out-of-band
	// "marker channel" (PLAN-marker-channel Phase 1). The scanner scans these
	// against the full ruleset exactly like Streams, so Phase 1 changes nothing
	// observable beyond the separation; the split is the prerequisite for the
	// Phase 2 collision filter and Phase 3 compiled markers.yac partition.
	// COMBINED markers (marker tag + a real attacker IOC in one string) stay in
	// Streams. Populated by splitPureMarkers (see markers.go).
	Markers [][]byte
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
	// EncryptedArchive is true when a password-protected member was seen in the
	// archive (any layer). yarad holds no password so it cannot unpack the member;
	// the ARCHIVE-ENCRYPTED marker is emitted instead — a hidden-payload mail tell.
	EncryptedArchive bool
	// Polyglot is true when buf is simultaneously a valid PE image and a valid ZIP
	// (file-type confusion): the email gateway parses the ZIP while the endpoint
	// runs the PE. The POLYGLOT-PE-ZIP marker is emitted; extraction is not
	// re-routed.
	Polyglot bool
	// IsXLL is true when buf is a PE that exports the Excel XLL add-in callback
	// contract (xlAutoOpen): an Excel add-in DLL, which runs code on load without
	// a macro prompt. The XLL-ADDIN marker is emitted.
	IsXLL bool
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
	// HasDocProps is true when at least one string was extracted from document
	// properties (OOXML docProps/*, customXml/, word/settings.xml docVars, or
	// OLE2 \x05SummaryInformation / \x05DocumentSummaryInformation streams) and
	// emitted for YARA scanning. Drives the extract_docprops_total metric.
	HasDocProps bool
	// HasXLMFold is true when at least one XLM formula was constant-folded
	// and the folded cleartext was emitted for YARA scanning.
	HasXLMFold bool
	// IsSLK is true when buf was recognised as a SYLK (.slk) spreadsheet, whose
	// C-record E-field formulas were scanned for XLM/DDE droppers.
	IsSLK bool
	// DecodedStreams is how many blobs the single-layer static decode pass
	// (base64/hex/whole-buffer reverse; see decode.go) appended to Streams. These
	// are the trailing len-N entries of Streams; the caller subtracts them so the
	// macro/extracted-stream metrics aren't inflated by decode output. >0 means
	// the pass fired.
	DecodedStreams int

	// childOpts carries the request's effort Options down the nested-carrier walk
	// (extractChild) so a nested PDF honors the same PDFDeepen / DecodeDepth /
	// DecodeIterations caps as a top-level one. nil => FullOptions (top-level
	// Extract / tests that build Result directly).
	childOpts *Options
}

// Extract is the back-compat full-depth entry point: it runs every extractor at
// maximum depth, bounded only by deadline (zero == no limit). Used by tests and
// the -extract CLI tool. The server scan path calls ExtractWithOptions to apply
// per-request effort caps (EFFORT-4).
func Extract(buf []byte, deadline time.Time) Result {
	return ExtractWithOptions(buf, FullOptions(deadline))
}

// ExtractWithOptions reports the plaintext hidden inside an OLE2/OOXML container —
// the decompressed VBA macro source — plus flags describing what the buffer was.
// For anything that is not a recognised container it returns the zero Result
// (IsDoc=false, no streams). It never returns an error and never panics out: a
// poison attachment degrades to a raw-only scan, never crashes the scan path.
//
// opts carries the time budget (opts.Deadline; zero == no limit) plus the
// per-request effort caps (EFFORT-4). The deadline bounds the OOXML extraction
// loop (decompression + oleparse runs are done before any libyara scan, so a
// small compressed bomb could otherwise burn CPU before the scan budget is ever
// consulted); the effort caps scale the MSD decode depth and the PDF indicator
// pass. A nil opts degrades to FullOptions (no time limit, full depth). The
// cumulative byte/count caps still apply regardless.
func ExtractWithOptions(buf []byte, opts *Options) (res Result) {
	if opts == nil {
		opts = FullOptions(time.Time{})
	}
	deadline := opts.Deadline
	res.childOpts = opts
	// oleparse walks attacker-controlled binary offsets; a malformed document can
	// drive it to panic. Recover and mark it so the caller still scans raw bytes.
	defer func() {
		if recover() != nil {
			res.Failed = true
			res.Panicked = true
		}
	}()

	// One shared nested-carrier budget for the whole input: archive members,
	// .msg attachments, OLE Package payloads, and RTF objects all recurse through
	// extractChild against this budget so a fan-out / deeply nested carrier set is
	// bounded as a unit (see nested.go).
	b := &archiveBudget{}

	switch {
	case bytes.HasPrefix(buf, oleMagic):
		res.IsDoc = true
		fromOLE(buf, &res, b, 0, deadline)
	case bytes.HasPrefix(buf, zipMagic):
		res.IsDoc = true // zip magic matched — a container attempt (per Result.IsDoc)
		// A zip is either an OOXML/ODF Office document (handle via the macro path
		// only — dumping its parts would scan ordinary body XML and invite FPs) or
		// a plain archive whose members may be droppers (unpack them). The macro
		// path also flags Failed on an unopenable (corrupt) zip; never member-dump
		// an Office doc.
		fromOOXML(buf, &res, deadline, opts)
		if !isOfficeZip(buf) {
			fromArchive(buf, &res, b, 0, deadline)
		}
	case isArchive(buf):
		// A non-zip archive (gz/7z/rar). Unpack members (recursing into nested
		// archives/containers) so a dropped payload is scanned, not just the
		// opaque outer bytes.
		res.IsDoc = true
		fromArchive(buf, &res, b, 0, deadline)
	case isPDF(buf):
		// A PDF: inflate its FlateDecode object streams so hidden JS / actions /
		// embedded files are scanned, not buried in compressed objects.
		res.IsDoc = true
		fromPDF(buf, &res, opts)
	case isRTF(buf):
		// An RTF document: hex-decode its \objdata embedded-object groups so a
		// dropped OLE2 doc / package / OLENativeStream payload (CVE-2017-0199 /
		// -11882, OLE2Link) is scanned, not buried in the RTF hex.
		res.IsDoc = true
		fromRTF(buf, &res, b, 0, deadline)
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
		fromOneNote(buf, &res, b, 0, deadline)
	case isSLK(buf):
		// A SYLK (.slk) spreadsheet — plain text, but Excel executes its XLM/DDE
		// cell formulas, so it's a macro-dropper carrier. Fold the C-record
		// E-field formulas through the shared XLM sink.
		res.IsDoc = true
		fromSLK(buf, &res, deadline)
	case isSpreadsheetML(buf):
		// An Excel-2003-XML ("XML Spreadsheet 2003") document — plain XML, but
		// Excel executes its cell formulas, so a DDE command formula in an
		// ss:Formula / <Data> cell is a macro-less command-execution carrier.
		// Surface CSV-DDE markers for the DDE command form.
		fromSpreadsheetML(buf, &res, deadline)
	default:
		// Not a container. The buffer may still hide an MS Script Encoder block
		// (#@~^...^#~@) — an encoded VBScript/JScript that raw-byte rules can't see
		// because the script source is substituted. Found in .vbe/.jse files and
		// embedded in .wsf/.hta/.html/.sct. Decode every block to cleartext so the
		// keyword rules match. Best-effort; non-script input yields nothing.
		fromEncodedScript(buf, &res, deadline)
		// The buffer may also be a plain CSV/TSV whose cells carry the DDE
		// command-injection form (=cmd|'/c calc'!A1) — a macro-less, container-
		// less command-execution carrier. Self-gating: emits a CSV-DDE marker only
		// on a real DDE-form cell, so it's safe to run on arbitrary text.
		fromCSVDDE(buf, &res, deadline)
		// The buffer may be an HTML/SVG part smuggling a payload (atob→Blob→
		// download, or a force-downloaded base64 data: URI). Self-gating: emits a
		// marker only on the dangerous combo and carves a force-downloaded data:
		// URI back through extractChild. Safe on arbitrary text.
		fromHTMLSmuggling(buf, &res, b, 0, deadline)
	}

	// Polyglot / file-type confusion: the dispatch above routes on the FIRST magic
	// only, so a file that is simultaneously two types (a PE with a zip appended, a
	// zip with a PE appended) reaches just one path and its second, executable half
	// is never examined. This is a top-level structural check on the original
	// buffer — it does not re-route extraction, it emits a POLYGLOT marker so the
	// contradiction itself is scored. Self-gating (requires two valid structures),
	// so it is safe on arbitrary input.
	fromPolyglot(buf, &res)

	// Excel XLL add-in: a PE DLL that Excel loads as an add-in, running attacker
	// code via the xlAutoOpen entry point with no macro prompt. Top-level check on
	// the original buffer (the .xll attachment is the PE itself). Self-gating on a
	// valid PE header AND the mandatory XLL export name, so it is safe to run on
	// any input.
	fromXLL(buf, &res)

	// After the format-specific extraction, run the single-layer static decode
	// pass over the raw buffer AND every stream surfaced above, so a base64/hex/
	// reversed payload hidden in a script body or a decompressed macro is decoded
	// and re-scanned. Snapshotted internally so decoded blobs are not re-decoded
	// (depth cap 1). Best-effort; binary container bytes are skipped.
	fromEncoded(buf, &res, opts)

	// Split the synthetic PURE markers out of Streams into the out-of-band Markers
	// channel (PLAN-marker-channel Phase 1). Done here at the single exit so every
	// emitter is covered regardless of format path, and AFTER the in-extraction
	// has*Marker / countXLMMarker helpers have run against Streams. decodeMoved
	// keeps DecodedStreams exact: an MSD-DEEPDECODE marker counted into that total
	// is no longer in Streams, so subtract it.
	// Co-locate the scattered XLM markers into one document-level buffer so the
	// multi-marker stacker rules can satisfy their conjunctions (markers are
	// emitted as separate Streams entries, each scanned independently — the same
	// cross-entry dead-rule class fixed for DocProps/UserForm in Phase 2b). The
	// buffer is XLM-STACK-prefixed so splitPureMarkers routes it to the Markers
	// channel; the individual entries stay in Streams for the self-contained rules.
	if xb := joinXLMStackerMarkers(res.Streams); xb != nil {
		res.Streams = append(res.Streams, xb)
	}

	content, markers, decodeMoved := splitPureMarkers(res.Streams)
	res.Streams = content
	res.Markers = markers
	res.DecodedStreams -= decodeMoved
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
func fromOLE(buf []byte, res *Result, bud *archiveBudget, depth int, deadline time.Time) {
	// Stream count at entry. On a NESTED OLE child (carried in a .msg/Ole10Native/
	// RTF object/archive member) res.Streams already holds parent + sibling output,
	// so "did THIS OLE yield anything" must be measured as a delta from here, not as
	// the global len(res.Streams) (else a no-VBA nested OLE's .msg/MSI fallback would
	// be wrongly skipped just because a parent stream exists).
	streamsBefore := len(res.Streams)
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
	// EncryptedPackage stream with key material in EncryptionInfo. Before marking
	// it as opaque, try default passwords (VelvetSweatshop etc.) via ECMA-376
	// Agile/Standard decryption — many malware samples use well-known passwords.
	if ole.FindStreamByName("EncryptedPackage") != nil || ole.FindStreamByName("EncryptionInfo") != nil {
		fromDefaultPWOOXML(ole, res, deadline)
		res.Encrypted = true
		fromOLEEncInfo(ole, res) // ENCRYPTION-AES type marker
		return
	}
	// Flag a payload stapled past the CFB's FAT coverage (a benign-looking
	// .doc/.xls with a second stage appended after its last allocated sector).
	// Runs on both the macro and no-macro paths below.
	fromOLEExtraData(ole, buf, res, deadline)
	mods, err := oleparse.ExtractMacros(ole)
	if err != nil {
		// A macro-extraction error on a real MSI/.msg is expected (no VBA project),
		// so don't fail outright — fall through to the MSG (Outlook) and MSI paths,
		// which decide whether this OLE2 is one of those worth dumping.
		if !fromMSG(ole, res, bud, depth, deadline) && !fromMSI(ole, res, deadline) && !fromOLEPackage(ole, res, bud, depth, deadline) {
			res.Failed = true
		}
		// Even when VBA extraction fails, a legacy spreadsheet may carry hidden
		// XLM macrosheets in its Workbook stream — scan for BOUNDSHEET8 records.
		fromBIFFXLM(ole, res, deadline)
		// Surface VBA macros embedded in legacy PowerPoint (.ppt/.pps) files.
		// oleparse.ExtractMacros finds no _VBA_PROJECT at the root level; the
		// project is nested inside ExternalObjectStorage records in the PPT stream.
		fromPPTVBA(ole, res, deadline)
		// Structural indicators (ObjectPool / Flash) are independent of VBA, so
		// surface them on a no-macro OLE2 too.
		fromOLEIndicators(ole, res, deadline)
		fromOLEOrphans(ole, res, deadline)
		fromOLETimes(ole, res, deadline)
		fromOLEEncType(ole, res, deadline)
		// Attempt to decrypt BIFF8 streams protected with default passwords
		// (XOR Method 1 and RC4) so hidden XLM macros are not missed.
		fromDefaultPWXOR(ole, res, deadline)
		fromDefaultPWRC4(ole, res, deadline)
		fromOLEDigSig(ole, res, deadline)
		// An OLE2Link object's URL moniker (CVE-2017-0199) is independent of VBA.
		fromOLE2Link(ole, res, deadline)
		return
	}
	// Append (not overwrite): when fromOLE runs on a NESTED child (an OLE2 carried
	// in a .msg attachment / Ole10Native payload / RTF object / archive member via
	// extractChild) res.Streams already holds the parent's and siblings' streams —
	// seeding codes() with the existing slice preserves them instead of erasing.
	res.Streams = codes(mods, res.Streams)
	// Detect VBA stomping: substantial p-code but trivial/missing source.
	// Emits "VBA-STOMPED <name> pcode=<n> src=<n>" markers for YARA matching.
	detectStomping(ole, res, deadline)
	// Extract strings hidden in VBA UserForm control data (captions, tags, text
	// values stored in "o"/"f"/"\x03VBFrame" streams). These are invisible to
	// source-text scanners. Emits "USERFORM-STRINGS" marker + carved strings.
	fromUserForms(ole, res, deadline)
	// Carve payload strings hidden in OLE2 SummaryInformation and
	// DocumentSummaryInformation property-set streams. Emits
	// "DOCPROPS-STRINGS" marker + carved strings.
	fromOLEDocProps(ole, res, deadline)
	// An embedded OLE Package object (dropped .exe/.bat in an Ole10Native stream)
	// can ride alongside macros, so always carve it regardless of whether VBA was
	// found — it's a no-op when the doc has no package stream.
	fromOLEPackage(ole, res, bud, depth, deadline)
	// oleid-style structural indicators: an ObjectPool storage (embedded OLE
	// objects) and embedded Flash/SWF objects. Emits OLEID-* markers.
	fromOLEIndicators(ole, res, deadline)
	fromOLEOrphans(ole, res, deadline)
	fromOLETimes(ole, res, deadline)
	fromOLEEncType(ole, res, deadline)
	// Attempt to decrypt BIFF8 streams protected with default passwords
	// (XOR Method 1 and RC4) so hidden XLM macros are not missed.
	fromDefaultPWXOR(ole, res, deadline)
	fromDefaultPWRC4(ole, res, deadline)
	fromOLEDigSig(ole, res, deadline)
	// An OLE2Link object's URL moniker (CVE-2017-0199) auto-fetches a remote
	// payload on open; surface it as an OLE2LINK-URL marker.
	fromOLE2Link(ole, res, deadline)
	// Detect hidden Excel-4.0 macrosheets in legacy .xls BIFF8 streams. This is
	// independent of VBA: XLM macro sheets use a different mechanism and their
	// BOUNDSHEET8 records are in the Workbook stream, not a VBA project.
	// fromBIFFXLM is a no-op when there is no Workbook/Book stream.
	fromBIFFXLM(ole, res, deadline)
	// Surface VBA macros embedded in legacy PowerPoint (.ppt/.pps) files.
	fromPPTVBA(ole, res, deadline)
	// No VBA found: the OLE2 may instead be an Outlook .msg (pull its nested
	// attachment files out and scan them) or an MSI (dump its payload streams).
	// Both helpers are no-ops for an OLE2 that isn't theirs. Try MSG first — a
	// .msg has no MSI CLSID so the order is safe.
	if len(res.Streams) == streamsBefore {
		if !fromMSG(ole, res, bud, depth, deadline) {
			fromMSI(ole, res, deadline)
		}
	}
}

// extraDataMinBytes is the smallest trailing blob worth flagging as data appended
// beyond a CFB's FAT coverage — below this it's just sub-sector padding.
const extraDataMinBytes = 512

// maxExtraDataCarve bounds how much trailing data is carved for scanning.
const maxExtraDataCarve = 4 << 20

// fromOLEExtraData flags bytes appended after the last FAT-allocated sector of a
// CFB compound file (oletools' "extra data after last sector"): a common way to
// staple a second-stage payload onto a benign-looking .doc/.xls without touching
// its directory or FAT. It emits an OLE2-EXTRA-DATA marker and carves the trailing
// blob so content rules scan it in isolation. buf is the original container bytes.
//
// Soundness: a sector is allocated iff its FAT entry is not FREESECT; the highest
// such index is the last meaningful sector, and anything past it is appended.
// Trailing free sectors (all-zero padding) are NOT flagged — only a non-zero blob
// is, which keeps benign over-allocated containers from tripping the marker.
func fromOLEExtraData(ole *oleparse.OLEFile, buf []byte, res *Result, deadline time.Time) {
	if ole == nil || expired(deadline) || ole.SectorSize <= 0 || len(res.Streams) >= maxStreams {
		return
	}
	last := -1
	for i, v := range ole.Fat {
		if v != oleparse.FREESECT {
			last = i
		}
	}
	if last < 0 {
		return
	}
	// Sector i spans bytes [SectorSize*(i+1), SectorSize*(i+2)) — the 512-byte
	// header is "sector -1" (see oleparse ReadSector). Coverage ends after `last`.
	covered := ole.SectorSize * (last + 2)
	if covered <= 0 || covered >= len(buf) {
		return
	}
	tail := buf[covered:]
	if len(tail) < extraDataMinBytes || allZero(tail) {
		return // sub-sector padding or free-sector zeros — not an appended payload
	}
	res.Streams = append(res.Streams, []byte("OLE2-EXTRA-DATA"))
	if len(tail) > maxExtraDataCarve {
		tail = tail[:maxExtraDataCarve]
	}
	if len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, append([]byte(nil), tail...))
	}
}

// allZero reports whether b is entirely zero bytes (CFB free-sector padding).
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
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
// caller's recover covers it). A nested attachment that is itself a carrier
// (PDF, Office doc, archive, .msg, RTF, .lnk, encoded script) is additionally
// routed through extractChild so its own format is cracked (a child PDF's
// FlateDecode JS / child Office macro is otherwise invisible one layer deep);
// the raw attachment bytes are still surfaced for the leaf scan. bud/depth are
// the shared nested-carrier budget (see nested.go).
func fromMSG(ole *oleparse.OLEFile, res *Result, bud *archiveBudget, depth int, deadline time.Time) bool {
	if !isMSG(ole) {
		return false
	}
	res.IsMSG = true
	var total int
	var emitted int // THIS .msg's attachment count, not the global len(res.Streams)
	// (a parent stream count must not pre-consume this .msg's per-format budget).
	for _, d := range ole.Directory {
		if d == nil || d.Header.Mse != 2 || d.Header.Size == 0 {
			continue
		}
		n := strings.ToLower(d.Name)
		if n != msgAttachData1 && n != msgAttachData2 {
			continue
		}
		if emitted >= maxMSGAttachments || len(res.Streams) >= maxStreams || total >= maxTotalMSG || expired(deadline) || bud.spent() {
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
		emitted++
		// Charge the shared nested-carrier budget so a .msg → carrier fan-out is
		// bounded together with archive members (see nested.go), then crack the
		// attachment's own carrier layer if it is one (depth+1: one carrier deeper
		// than this .msg). No-op for an ordinary file.
		bud.members++
		bud.total += len(b)
		extractChild(b, res, bud, depth+1, deadline)
	}
	return true
}

// fromOOXML handles a modern Office document: a ZIP whose vbaProject.bin entries
// are themselves OLE2 compound files. We read the zip in memory (no temp file)
// and decompress the VBA out of every *.bin member, mirroring oleparse.ParseFile
// but without touching disk. A zip we can't open at all is a parse failure; a
// single unparseable .bin is skipped without losing the rest.
// opts carries per-request caps (nil degrades to package defaults).
func fromOOXML(buf []byte, res *Result, deadline time.Time, opts *Options) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		res.Failed = true
		return
	}
	// Seed from the existing streams (not an empty slice): on a NESTED child (an
	// Office zip carried in a .msg/Ole10Native/RTF object/archive member via
	// extractChild) res.Streams already holds parent + sibling streams, and the
	// final `res.Streams = out` must extend them, not erase them. At top level
	// res.Streams is empty so this is a no-op. The macro/cap counters below then
	// also bound the cumulative (parent-inclusive) total, which is the intent.
	out := res.Streams
	parentStreams := len(out) // streams already present (nested child); excluded from the Failed delta
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
	lenBeforeRels := len(out)
	fromOOXMLRels(zr, &out, deadline)
	hasExtRel := len(out) > lenBeforeRels
	// Scan word/document.xml (and related parts) for DDE/DDEAUTO field
	// instructions. Each hit appends a synthetic "OOXML-DDE-FIELD <instr>" stream.
	// Fail-open: malformed XML is silently skipped.
	lenBeforeDDE := len(out)
	fromOOXMLDDE(zr, &out, deadline)
	hasDDE := len(out) > lenBeforeDDE
	// Detect hidden Excel-4.0 macrosheets in OOXML workbooks (xlsm/xlsb/xlam).
	// Each hidden/veryHidden sheet coinciding with an xl/macrosheets/ part appends
	// a synthetic "XLM-HIDDEN-MACROSHEET <state> <name>" stream.
	// Fail-open: any parse error is silently ignored.
	lenBeforeXLM := len(out)
	fromOOXMLXLM(zr, &out, deadline)
	// Constant-fold XLM formula strings from OOXML macrosheets. Reassembles
	// obfuscated CHAR()&CHAR()&"..." concatenations into cleartext so
	// keyword/URL/IOC YARA rules fire. Also emits XLM-DANGEROUS-FUNC markers.
	prevLen := len(out)
	fromOOXMLXLMFold(zr, &out, deadline, opts)
	// .xlsb stores macrosheets as BIFF12 binary parts (xl/macrosheets/sheet*.bin)
	// rather than XML <f> elements, so fromOOXMLXLMFold (which only reads .xml)
	// misses them. Fold the BIFF12 ptg token streams too (XLM-4).
	fromXLSBXLMFold(zr, &out, deadline, opts)
	if len(out) > prevLen {
		res.HasXLMFold = true
	}
	// Carve payload strings from OOXML document-property parts
	// (docProps/core.xml, docProps/app.xml, docProps/custom.xml,
	// customXml/item*.xml) and word/settings.xml docVars.
	// Emits "DOCPROPS-STRINGS" marker + extracted strings.
	fromOOXMLDocProps(zr, &out, deadline)
	if hasDocPropsMarker(out) {
		res.HasDocProps = true
	}
	// Emit OLEID-style synthetic marker streams for OOXML structural indicators.
	// These mirror oletools' oleid.py indicators for the OOXML path. Each marker
	// is only appended when not already present (dedup guard) and never causes
	// extraction failure (fail-open). The OLE path (oleid.go) emits OLEID-OBJECTPOOL
	// and OLEID-FLASH only; these four markers are OOXML-exclusive, no overlap.
	out = appendOLEIDMarker(out, "OLEID-VBA-PRESENT", attempted > 0 && len(out) > parentStreams)
	out = appendOLEIDMarker(out, "OLEID-EXTREL", hasExtRel)
	out = appendOLEIDMarker(out, "OLEID-DDE", hasDDE)
	out = appendOLEIDMarker(out, "OLEID-XLM-PRESENT", len(out) > lenBeforeXLM || res.HasXLMFold)
	res.Streams = out
	// Every .bin we tried failed to parse and nothing came out: a document that
	// looks macro-bearing but yields no usable VBA (obfuscated/corrupt/hostile).
	// Mark it failed so it shows up in extract_failed_total rather than silently
	// looking like a clean macro-free doc.
	if attempted > 0 && len(out) == parentStreams && failedBins == attempted {
		res.Failed = true
	}
}

// appendOLEIDMarker appends a []byte stream containing marker to out if cond is
// true and the marker is not already present. Fail-open: always returns out.
func appendOLEIDMarker(out [][]byte, marker string, cond bool) [][]byte {
	if !cond {
		return out
	}
	mb := []byte(marker)
	for _, s := range out {
		if bytes.Equal(s, mb) {
			return out
		}
	}
	return append(out, mb)
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

// maxDDEParts bounds how many isDDEDocPart-matched parts we scan for DDE fields,
// so a crafted document with thousands of headerN.xml parts cannot force
// unbounded work. Real documents have a handful.
const maxDDEParts = 64

// isDDEDocPart reports whether an OOXML part name is a word-processing part that
// may carry a field instruction (DDE/DDEAUTO). document.xml is the primary
// carrier, but Word also evaluates fields in headers, footers, footnotes,
// endnotes and comments — a DDE field planted in word/header2.xml or
// word/footnotes.xml was previously MISSED by the old fixed four-name list
// (document/document2/header1/footer1 only). Match the whole family by glob:
//
//	word/document*.xml  word/header*.xml  word/footer*.xml
//	word/footnotes.xml  word/endnotes.xml  word/comments*.xml
//
// Case-insensitive on the part name (zip names are normally lowercase, but a
// crafted container may vary case). Bounded by maxDDEParts at the call site.
func isDDEDocPart(name string) bool {
	n := strings.ToLower(name)
	if !strings.HasPrefix(n, "word/") || !strings.HasSuffix(n, ".xml") {
		return false
	}
	base := n[len("word/"):]
	switch {
	case strings.HasPrefix(base, "document"),
		strings.HasPrefix(base, "header"),
		strings.HasPrefix(base, "footer"),
		strings.HasPrefix(base, "comments"):
		return true
	case base == "footnotes.xml", base == "endnotes.xml":
		return true
	}
	return false
}

// maxDDEFields caps how many OOXML-DDE-FIELD synthetic streams we emit per
// document. A legitimate document with thousands of DDE fields is anomalous;
// the cap prevents a crafted document from flooding Streams.
const maxDDEFields = 64

// maxBytesPerDocXML caps one word/document.xml read (zip-bomb guard). A real
// Word document body is rarely > 4 MiB; beyond that we skip the part.
const maxBytesPerDocXML = 4 << 20

// fromOOXMLDDE reads every isDDEDocPart-matched word-processing part from the
// already-opened zip, parses their XML, and appends a synthetic
// "OOXML-DDE-FIELD <instr>" []byte stream to *out for each field instruction
// that begins with (or contains) "DDE" or "DDEAUTO". Two field instruction
// shapes are handled:
//
//   - w:fldSimple/@w:instr — the whole instruction is a single XML attribute.
//   - w:instrText runs     — the instruction may be split across multiple
//     consecutive <w:instrText> elements; the helper concatenates them before
//     testing, which is how Word itself assembles the instruction (and how
//     obfuscators split DDE tokens across runs).
//
// Fail-open contract: a part that cannot be read or parsed is silently skipped.
// Bounded by maxDDEFields + maxBytesPerDocXML; respects expired(deadline).
func fromOOXMLDDE(zr *zip.Reader, out *[][]byte, deadline time.Time) {
	// Walk the directory once, scanning every word-processing part that may carry
	// a DDE field (isDDEDocPart globs document*/header*/footer*/footnotes/endnotes/
	// comments*) — not a fixed four-name list that missed header2+, footnotes, etc.
	// Bounded by maxDDEParts (parts scanned), maxDDEFields/maxStreams (emitted),
	// the per-part size cap, and the deadline.
	parts := 0
	for _, f := range zr.File {
		if expired(deadline) {
			break
		}
		if countDDEFields(*out) >= maxDDEFields || len(*out) >= maxStreams || parts >= maxDDEParts {
			break
		}
		if !isDDEDocPart(f.Name) {
			continue
		}
		parts++
		if f.UncompressedSize64 > maxBytesPerDocXML {
			continue // anomalously large part — skip
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, maxBytesPerDocXML))
		rc.Close() // #nosec G104 -- zip entry close; error is unrecoverable here
		if err != nil || len(raw) == 0 {
			continue
		}
		parseDDEFields(raw, out, deadline)
	}
}

// parseDDEFields walks the XML of one OOXML word-processing part and appends
// OOXML-DDE-FIELD synthetic streams to *out for every DDE/DDEAUTO field it
// finds. It handles both w:fldSimple/@w:instr (single-attribute instructions)
// and concatenated w:instrText run text (split-run instructions). Malformed
// XML is silently ignored (fail-open).
func parseDDEFields(raw []byte, out *[][]byte, deadline time.Time) {
	// We stream-parse with encoding/xml to avoid loading the whole DOM.
	// State machine: inside a w:fldChar complex field, we accumulate
	// w:instrText content until w:fldChar w:fldCharType="end".
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	var instrBuf strings.Builder // accumulates w:instrText for one complex field
	inComplexField := false

	emitIfDDE := func(instr string) {
		// norm = collapse every run of Unicode whitespace to a single space
		// (handles tabs/newlines between runs); noWS = fully whitespace-free, used
		// to detect an inter-letter-spaced "D D E A U T O" directive.
		norm := strings.Join(strings.Fields(instr), " ")
		noWS := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, norm)
		upper := strings.ToUpper(noWS)
		if !strings.HasPrefix(upper, "DDE") {
			return
		}
		if countDDEFields(*out) >= maxDDEFields || len(*out) >= maxStreams {
			return
		}
		// Emit `<directive> <tail>`: the directive token (DDE/DDEAUTO) is made
		// contiguous so YARA `$ddeauto = "DDEAUTO "` fires even on the obfuscated
		// inter-letter-spaced form, while the tail keeps its single-space args
		// (legitimate field paths/commands have meaningful spaces — don't strip).
		dirLen := 3 // "DDE"
		if strings.HasPrefix(upper, "DDEAUTO") {
			dirLen = 7 // "DDEAUTO"
		}
		// Walk norm to the byte offset just past the directive's dirLen non-space
		// runes, so the readable tail starts after the (possibly spaced) directive.
		seen, cut := 0, len(norm)
		for i, r := range norm {
			if !unicode.IsSpace(r) {
				seen++
				if seen == dirLen {
					cut = i + utf8.RuneLen(r)
					break
				}
			}
		}
		emit := noWS[:dirLen]
		if tail := strings.TrimSpace(norm[cut:]); tail != "" {
			emit += " " + tail
		}
		*out = append(*out, []byte("OOXML-DDE-FIELD "+emit))
	}

	for {
		if expired(deadline) {
			break
		}
		tok, err := dec.Token()
		if err != nil {
			break // EOF or malformed — fail-open
		}
		switch t := tok.(type) {
		case xml.StartElement:
			localName := t.Name.Local
			switch localName {
			case "fldSimple":
				// w:fldSimple w:instr="..." — whole instruction in an attribute.
				for _, attr := range t.Attr {
					if attr.Name.Local == "instr" {
						emitIfDDE(attr.Value)
						break
					}
				}
			case "fldChar":
				// w:fldChar w:fldCharType="begin|separate|end"
				for _, attr := range t.Attr {
					if attr.Name.Local == "fldCharType" {
						switch strings.ToLower(attr.Value) {
						case "begin":
							inComplexField = true
							instrBuf.Reset()
						case "end":
							if inComplexField {
								emitIfDDE(instrBuf.String())
								inComplexField = false
								instrBuf.Reset()
							}
						}
						break
					}
				}
			case "instrText":
				// w:instrText — content is part of the field instruction.
				// CharData comes in the next token(s).
				if inComplexField {
					if inner, ierr := dec.Token(); ierr == nil {
						if cd, ok := inner.(xml.CharData); ok {
							instrBuf.Write(cd)
						}
					}
				}
			}
		}
	}
}

// countDDEFields counts how many entries in streams start with the
// OOXML-DDE-FIELD synthetic marker (used to enforce maxDDEFields).
func countDDEFields(streams [][]byte) int {
	n := 0
	for _, s := range streams {
		if bytes.HasPrefix(s, []byte("OOXML-DDE-FIELD ")) {
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
//
// Bounds (ROBUST-BOUNDS): the OLE2 path feeds the raw ExtractMacros output here
// with no module-count or byte budget of its own (unlike fromOOXML, which caps
// as it goes), so codes itself enforces all three caps: maxStreams (blob count),
// maxBytesPerModule (one bomb module can't dominate), and maxTotalCode (the sum
// across modules). A crafted vbaProject.bin with thousands of modules or a
// decompression bomb therefore cannot OOM the container through res.Streams.
func codes(mods []*oleparse.VBAModule, out [][]byte) [][]byte {
	total := 0
	for _, b := range out {
		total += len(b)
	}
	for _, m := range mods {
		if m == nil || m.Code == "" {
			continue
		}
		if len(out) >= maxStreams || total >= maxTotalCode {
			break
		}
		// Truncate the *string* before the []byte copy: m.Code may be hundreds of
		// MiB (decompression bomb), so converting it whole would itself be the OOM
		// allocation. Clamp to both the per-module cap and the remaining total
		// budget so neither maxTotalCode nor the copy can overshoot.
		n := len(m.Code)
		if n > maxBytesPerModule {
			n = maxBytesPerModule
		}
		if rem := maxTotalCode - total; n > rem {
			n = rem
		}
		out = append(out, []byte(m.Code[:n]))
		total += n
	}
	return out
}
