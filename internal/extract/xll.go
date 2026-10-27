package extract

import "bytes"

// Excel XLL add-in detection. An .xll is an ordinary Windows PE DLL that Excel
// loads as an add-in: on load Excel calls the add-in's xlAutoOpen entry point,
// which runs attacker code with NO macro-security prompt and NO Protected View —
// a single "Enable" click, or none at all if the add-in is trusted. Phishing use
// of .xll surged sharply through 2025 (FIN7 and commodity campaigns) precisely
// because it sidesteps the macro hardening users were trained to distrust.
//
// yarad otherwise has no PE awareness, so an .xll attachment was scanned only as
// opaque bytes. This surfaces a marker when the buffer is a real PE that exports
// the XLL add-in callback contract, so the rules score it as the executable
// add-in it is.
//
// FP-safety: the marker requires BOTH a structurally valid PE header (validated
// through e_lfanew, see isValidPEAt) AND the presence of the xlAutoOpen export
// name — the mandatory XLL entry point. A non-XLL DLL does not export xlAutoOpen,
// and ordinary (non-PE) content cannot satisfy the PE check, so the conjunction
// does not fire on benign attachments.

// xllExportNames are the Excel-Add-in-Manager callback exports that identify a
// PE as an XLL. xlAutoOpen is the mandatory load entry point; the others
// corroborate. Each is an exact ASCII export-table name.
var xllExportNames = [][]byte{
	[]byte("xlAutoOpen"),
	[]byte("xlAutoClose"),
	[]byte("xlAddInManagerInfo"),
	[]byte("xlAddInManagerInfo12"),
}

// fromXLL emits the XLL-ADDIN marker when buf is a PE that carries the XLL
// add-in export contract. Called once on the top-level buffer (an .xll
// attachment is the PE itself, at offset 0). Best-effort; it does not parse the
// full export table — the export NAME strings live verbatim in the export-name
// table of the PE image, so a substring match over the (bounded) image is both
// sufficient and cheap, and the valid-PE gate is what keeps it specific.
func fromXLL(buf []byte, res *Result) {
	if !isValidPEAt(buf, 0) {
		return
	}
	// xlAutoOpen is mandatory for a loadable XLL — require it, then the marker is
	// effectively the (validPE AND xlAutoOpen) conjunction.
	scan := buf
	if len(scan) > peMaxScan {
		scan = scan[:peMaxScan]
	}
	if !bytes.Contains(scan, xllExportNames[0]) {
		return
	}
	res.IsXLL = true
	res.appendMarker(trustedMarker("XLL-ADDIN"))
}
