package yarad

import (
	"strings"

	"github.com/eilandert/rspamd-yarad/internal/extract"
)

// extMismatchMarker is the synthetic out-of-band marker emitted when the actual
// container type recovered by the extractor contradicts a benign-looking
// attachment extension (a renamed dropper: real OLE/OOXML/RTF/archive wearing a
// .txt/.jpg/.pdf coat). It is the yarad analog of SpamAssassin's OLEMACRO_RENAME
// / MIME_BAD_EXTENSION — but driven by the REAL parsed type, not a magic-byte
// grep. The marker body carries the claimed and actual type so a rule (and the
// log) can show WHY. Scanned only on the marker channel → zero-FP by
// construction (the literal is yarad-synthetic).
const extMismatchMarkerPrefix = "EXT-MISMATCH"

// benignExts are extensions a sender uses for a document/media/text file that a
// recipient opens without suspicion. A high-signal container (OLE2 doc, OOXML
// macro doc, RTF, archive, LNK, MSI, OneNote) arriving under one of these is a
// classic rename evasion. Office-document extensions are deliberately ABSENT:
// a .doc that is really an OLE2 doc is not renamed, and a .docx that is really
// a zip is correct — only a MISMATCH against the recovered type is flagged, and
// the per-type allowlists below encode what each type may legitimately wear.
var benignExts = map[string]struct{}{
	".txt": {}, ".text": {}, ".log": {}, ".csv": {}, ".rtf": {},
	".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".bmp": {}, ".webp": {},
	".pdf": {}, ".html": {}, ".htm": {}, ".xml": {}, ".json": {},
	".mp3": {}, ".mp4": {}, ".wav": {}, ".avi": {}, ".mov": {},
	".dat": {}, ".bin": {}, ".tmp": {},
}

// extMismatch returns a non-empty "<claimed>:<actual>" descriptor when meta's
// extension is a benign type but the extractor recovered a high-signal container
// that the extension cannot legitimately name. It is intentionally conservative:
//
//   - no extension, or an unrecognized extension → "" (cannot prove a rename).
//   - the extension is in the type's legitimate-extension allowlist → "".
//   - only the high-signal container types are considered (a plain encoded
//     script body is not "renamed").
//
// A miss here costs nothing (the stream rules still run); a false positive would
// score a legitimately-named file, so the gate stays tight.
func extMismatch(res extract.Result, ext string) string {
	if ext == "" {
		return ""
	}
	ext = strings.ToLower(ext)

	// actualType + its legitimate extensions. Picked in priority order: the most
	// specific recovered type wins. A type with no benign-coat risk (PDF, plain
	// archive named .zip) is omitted.
	switch {
	case res.IsRTF:
		// RTF is text-ish but a renamed .rtf dropper (objupdate/objdata) is common.
		if ext == ".rtf" || ext == ".doc" {
			return ""
		}
		if _, benign := benignExts[ext]; benign {
			return "rtf:" + claimed(ext)
		}
	case res.IsMSI:
		if ext == ".msi" || ext == ".msp" {
			return ""
		}
		if _, benign := benignExts[ext]; benign {
			return "msi:" + claimed(ext)
		}
	case res.IsLNK:
		if ext == ".lnk" {
			return ""
		}
		if _, benign := benignExts[ext]; benign {
			return "lnk:" + claimed(ext)
		}
	case res.IsOneNote:
		if ext == ".one" || ext == ".onepkg" {
			return ""
		}
		if _, benign := benignExts[ext]; benign {
			return "onenote:" + claimed(ext)
		}
	case res.IsOLEPackage:
		// Embedded OLE Package (often wraps an exe/script). Any benign coat is bad.
		if _, benign := benignExts[ext]; benign {
			return "ole-package:" + claimed(ext)
		}
	case res.IsDoc:
		// Recovered Office container (OLE2 .doc/.xls or OOXML). Legitimate Office
		// extensions are fine; a benign media/text coat over a macro-capable doc is
		// the renamed-maldoc case.
		if isOfficeExt(ext) {
			return ""
		}
		if _, benign := benignExts[ext]; benign {
			return "office-doc:" + claimed(ext)
		}
	}
	return ""
}

// claimed strips the leading dot for the marker body (".jpg" -> "jpg").
func claimed(ext string) string { return strings.TrimPrefix(ext, ".") }

// isOfficeExt reports whether ext is a legitimate Office-document extension. A
// recovered Office container wearing one of these is correctly named, not a
// rename. List mirrors SpamAssassin olemacro_exts ∪ olemacro_macro_exts ∪
// olemacro_skip_exts.
func isOfficeExt(ext string) bool {
	switch ext {
	case ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm",
		".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt", ".xltx", ".xltm", ".xla", ".xlam", ".xlm",
		".ppt", ".pptx", ".pptm", ".pps", ".ppsx", ".ppsm", ".ppa", ".ppam", ".pot", ".potx", ".potm",
		".sldm", ".sldx", ".xps":
		return true
	}
	return false
}
