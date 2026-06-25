package extract

// CSV / Excel-2003-XML DDE command-injection extraction — CSV-DDE.
//
// Excel (and other spreadsheet apps) treat a cell whose text begins with one of
// '=', '+', '-' or '@' as a FORMULA, even when the file is a plain .csv or .tsv
// that never went through a macro. When that formula is the DDE command form —
//     =cmd|'/c calc.exe'!A1            (classic DDE)
//     @SUM(1+1)*cmd|'/c calc'!A0       (leading-@ formula-injection variant)
// — opening the file launches the named program. This is "CSV formula injection"
// / "DDE command execution" (MITRE T1559.002), delivered as innocuous-looking
// text with no OLE2/OOXML container at all, so none of yarad's container paths
// see it. msodde.py (oletools) carries the same detection for csv / xls-2003-xml.
//
// Two carriers are handled, both plain text:
//   - CSV / TSV — line-oriented; each ','- or '\t'-delimited cell is tested.
//   - Excel-2003-XML (SpreadsheetML) — the XML dialect Excel writes for
//     "XML Spreadsheet 2003". Formulas live in an ss:Formula="=..." attribute or
//     a <Data>=...</Data> element; the file is recognised by its mso-application
//     progid / office:spreadsheet namespace signature.
//
// Detection itself is the gate for the CSV path: we only emit a "CSV-DDE <cell>"
// marker when a cell both starts with a formula trigger AND contains the DDE
// command form (an app token, a '|' pipe, and a '!' cell-ref tail). A bare
// leading '=' (an ordinary "=SUM(A1:A9)") never carries that form, so plain
// spreadsheets exported to CSV do not false-positive. The marker prefix is
// literal yarad output, so the scoring rule is zero-FP by construction.
//
// Fail-open + bounded: cell/line counts, line length and emit count are all
// capped; malformed input is skipped. Never panics (Extract's recover covers it).

import (
	"bytes"
	"strings"
	"time"
)

const (
	// maxCSVLines caps records scanned per CSV/TSV file.
	maxCSVLines = 1 << 16
	// maxCSVLineLen caps a single record line length (bytes) inspected.
	maxCSVLineLen = 64 << 10
	// maxCSVCellsPerLine caps cells split out of one record (a line of millions of
	// commas must not force an unbounded split).
	maxCSVCellsPerLine = 4096
	// maxCSVDDEMarkers bounds how many CSV-DDE markers we emit per file.
	maxCSVDDEMarkers = 64
	// maxCSVDDECell caps one emitted cell/formula length.
	maxCSVDDECell = 4 << 10
	// csvSniffLen is how many leading bytes isSpreadsheetML inspects.
	csvSniffLen = 512
)

// formulaTriggers are the leading characters Excel treats as starting a formula.
var formulaTriggers = [256]bool{'=': true, '+': true, '-': true, '@': true}

// spreadsheetMLSigs are the leading-bytes signatures of an Excel-2003 "XML
// Spreadsheet" file. Either the processing-instruction progid or the office
// spreadsheet namespace is sufficient.
var spreadsheetMLSigs = [][]byte{
	[]byte("progid=\"Excel.Sheet\""),
	[]byte("urn:schemas-microsoft-com:office:spreadsheet"),
}

// isSpreadsheetML reports whether buf opens an Excel-2003-XML (SpreadsheetML)
// document. It must look like XML (start with '<', after an optional UTF-8 BOM)
// and carry the mso-application progid or the office:spreadsheet namespace in its
// leading bytes.
func isSpreadsheetML(buf []byte) bool {
	buf = bytes.TrimPrefix(buf, utf8BOM)
	head := buf
	if len(head) > csvSniffLen {
		head = head[:csvSniffLen]
	}
	if len(head) == 0 || head[0] != '<' {
		return false
	}
	for _, sig := range spreadsheetMLSigs {
		if bytes.Contains(head, sig) {
			return true
		}
	}
	return false
}

// fromCSVDDE scans plain-text CSV/TSV cells for the DDE command-injection form
// and emits a "CSV-DDE <cell>" marker for each. Self-gating: it only emits on a
// real DDE-form cell, so it is safe to run on any non-container text buffer.
// Fail-open; bounded; respects deadline. Does NOT set a Result flag for an empty
// scan (a buffer with no DDE cell is indistinguishable from non-CSV text).
func fromCSVDDE(buf []byte, res *Result, deadline time.Time) {
	if expired(deadline) {
		return
	}
	buf = bytes.TrimPrefix(buf, utf8BOM)

	// Fast-path guard: a CSV-DDE match requires a formula-trigger cell ('=+-@')
	// AND an unquoted '|' AND an unquoted '!' (see isFormulaInjectionDDE). If the
	// whole buffer lacks a '|' or a '!', no cell can ever match — skip the entire
	// per-line/per-cell walk. This is the common case for benign text buffers and
	// avoids the per-line string() alloc + cell split. O(n) single pass, far below
	// the cost it replaces. (The trigger char is implied by '|'+'!' being rare in
	// plain prose, so we gate on the two mandatory structural chars only.)
	if bytes.IndexByte(buf, '|') < 0 || bytes.IndexByte(buf, '!') < 0 {
		return
	}

	rest := buf
	lines := 0
	for len(rest) > 0 {
		if lines >= maxCSVLines || countCSVDDE(res.Streams) >= maxCSVDDEMarkers ||
			len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		lines++
		var raw []byte
		raw, rest, _ = bytes.Cut(rest, []byte("\n"))
		line := bytes.TrimRight(raw, "\r")
		if len(line) == 0 {
			continue
		}
		if len(line) > maxCSVLineLen {
			line = line[:maxCSVLineLen]
		}
		scanCSVLine(line, res, deadline)
	}
}

// scanCSVLine splits one record into cells (on ',' or '\t') and emits a CSV-DDE
// marker for each cell carrying the DDE command form.
func scanCSVLine(line []byte, res *Result, deadline time.Time) {
	// Delimiter: comma is the CSV default; fall back to tab only for a genuine TSV
	// (a line with tabs but no comma). Preferring comma avoids mis-splitting a
	// comma-CSV row that merely contains a tab inside a quoted field (which would
	// otherwise hide a comma-separated DDE cell).
	delim := byte(',')
	if bytes.IndexByte(line, ',') < 0 && bytes.IndexByte(line, '\t') >= 0 {
		delim = '\t'
	}
	cells := 0
	for len(line) > 0 {
		if cells >= maxCSVCellsPerLine || countCSVDDE(res.Streams) >= maxCSVDDEMarkers ||
			len(res.Streams) >= maxStreams || expired(deadline) {
			return
		}
		cells++
		// Quote-aware split (RFC4180): a delimiter inside a "..." field is literal,
		// not a cell boundary. A DDE payload whose command argument carries the
		// delimiter — e.g. `"=cmd|'/c calc,exe'!A1"` in a comma-CSV — would be cut
		// mid-payload by a quote-blind split, so neither half matches the DDE form
		// and the attack is MISSED. nextCSVDelim returns the index of the next
		// UNQUOTED delimiter (or -1), so a quoted field stays whole for normCSVCell.
		var cell []byte
		if idx := nextCSVDelim(line, delim); idx >= 0 {
			cell, line = line[:idx], line[idx+1:]
		} else {
			cell, line = line, nil
		}
		emitIfCSVDDE(cell, res)
	}
}

// nextCSVDelim returns the index of the first delim that lies OUTSIDE a CSV
// double-quoted field, or -1 if none. Quoting follows RFC4180: a '"' toggles
// quote state, and a doubled '""' inside a quoted field is an escaped quote (it
// stays quoted, so it must not toggle state). Leading whitespace before the
// opening quote (" =...") is tolerated — a field is treated as quoted once a '"'
// is seen with no preceding unquoted content, matching how normCSVCell trims then
// unquotes. Bytes outside any quote are scanned for the delimiter.
func nextCSVDelim(line []byte, delim byte) int {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			if inQuote && i+1 < len(line) && line[i+1] == '"' {
				i++ // skip the escaped "" pair, stay quoted
				continue
			}
			inQuote = !inQuote
		case delim:
			if !inQuote {
				return i
			}
		}
	}
	return -1
}

// emitIfCSVDDE tests one cell for the formula-injection DDE form and appends a
// "CSV-DDE <cell>" marker if it matches.
func emitIfCSVDDE(cell []byte, res *Result) {
	c := normCSVCell(cell)
	if len(c) == 0 || !formulaTriggers[c[0]] || !isFormulaInjectionDDE(string(c)) {
		return
	}
	if len(c) > maxCSVDDECell {
		c = c[:maxCSVDDECell]
	}
	res.Streams = append(res.Streams, append([]byte("CSV-DDE "), c...))
}

// normCSVCell strips surrounding whitespace and a single layer of CSV double
// quoting ("=..." → =...), unescaping the doubled-quote ("") escape, so a
// quoted formula cell is tested in its effective (unquoted) form. Excel applies
// the formula trigger to the unquoted text.
func normCSVCell(cell []byte) []byte {
	c := bytes.TrimSpace(cell)
	if len(c) >= 2 && c[0] == '"' && c[len(c)-1] == '"' {
		c = bytes.ReplaceAll(c[1:len(c)-1], []byte(`""`), []byte(`"`))
		c = bytes.TrimSpace(c)
	}
	return c
}

// isFormulaInjectionDDE reports whether a cell's text is a formula (starts with
// '=','+','-' or '@') that carries the DDE command-execution form: a bare app
// token, a '|' pipe, and a '!' cell-ref tail after the pipe (=cmd|'/c calc'!A1).
//
// The pipe AND the '!' must both be UNQUOTED: in the real DDE form the app token
// (cmd, MSEXCEL, mshta, …) and the '|' separator are bare, only the command
// ARGUMENT is quoted (=cmd|'/c calc'!A1). String-literal formulas that merely
// embed '|' and '!' inside a quoted argument — =HYPERLINK("x|y!"),
// ="a | b !" — are NOT DDE and must not match. We therefore scan with quote
// state and only accept a pipe seen outside any '…' / "…" literal, followed by
// an unquoted '!'. Mirrors the intent of isSLKDDE but quote-aware.
func isFormulaInjectionDDE(c string) bool {
	if c == "" || !formulaTriggers[c[0]] {
		return false
	}
	var quote byte // 0 = outside a literal, else the open-quote char
	bar := -1
	for i := 1; i < len(c); i++ { // start at 1: the trigger char is never the app token
		ch := c[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '|':
			// Require at least one bare app-token char between the trigger and the
			// pipe (cmd, MSEXCEL, …); a pipe at offset 1 has no app token.
			if i > 1 && bar == -1 {
				bar = i
			}
		case '!':
			if bar != -1 {
				return true // unquoted '|' earlier, now an unquoted '!' tail
			}
		}
	}
	return false
}

// countCSVDDE counts emitted CSV-DDE markers (enforces maxCSVDDEMarkers).
func countCSVDDE(streams [][]byte) int {
	n := 0
	for _, s := range streams {
		if bytes.HasPrefix(s, []byte("CSV-DDE ")) {
			n++
		}
	}
	return n
}

// skipToFormulaValue advances past the '=' and surrounding whitespace after
// 'Formula' in an attribute, returning the slice at the opening quote. Returns
// nil if no '=' is found or the next non-ws byte is not '='.
func skipToFormulaValue(b []byte) []byte {
	i := 0
	// Skip leading whitespace
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	// Check for '='
	if i >= len(b) || b[i] != '=' {
		return nil
	}
	i++
	// Skip trailing whitespace
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	return b[i:]
}

// ssFormulaAttr / ssDataOpen mark where SpreadsheetML carries cell formulas.
var (
	ssFormulaAttr = []byte("Formula")
	ssDataOpen    = []byte("<Data")
)

// fromSpreadsheetML scans an Excel-2003-XML document for DDE command-injection
// formulas in ss:Formula attributes and <Data> cell text, emitting a "CSV-DDE
// <formula>" marker for each. Sets res.IsDoc handled by the caller. Reuses the
// shared isFormulaInjectionDDE test so CSV and SpreadsheetML cannot drift.
// Fail-open; bounded; respects deadline. We deliberately use a lightweight byte
// scan (not a full XML parse): the file is attacker-controlled and may be
// malformed, the formula text is a flat attribute/element value, and the marker
// is self-gated so over-matching only adds (zero-FP) markers, never FPs.
func fromSpreadsheetML(buf []byte, res *Result, deadline time.Time) {
	res.IsDoc = true
	if expired(deadline) {
		return
	}
	if len(buf) > maxBytesPerDocXML {
		buf = buf[:maxBytesPerDocXML]
	}

	// 1) ss:Formula="..." attributes.
	rest := buf
	for {
		if countCSVDDE(res.Streams) >= maxCSVDDEMarkers || len(res.Streams) >= maxStreams || expired(deadline) {
			return
		}
		i := bytes.Index(rest, ssFormulaAttr)
		if i < 0 {
			break
		}
		rest = rest[i+len(ssFormulaAttr):]
		v := skipToFormulaValue(rest)
		if v == nil {
			continue
		}
		emitIfCSVDDE([]byte(attrValue(v)), res)
	}

	// 2) <Data ...>=...</Data> element text.
	rest = buf
	for {
		if countCSVDDE(res.Streams) >= maxCSVDDEMarkers || len(res.Streams) >= maxStreams || expired(deadline) {
			return
		}
		i := bytes.Index(rest, ssDataOpen)
		if i < 0 {
			break
		}
		rest = rest[i+len(ssDataOpen):]
		gt := bytes.IndexByte(rest, '>')
		if gt < 0 {
			break
		}
		body := rest[gt+1:]
		end := bytes.IndexByte(body, '<')
		if end < 0 {
			end = len(body)
		}
		emitIfCSVDDE([]byte(unescapeXMLText(string(body[:end]))), res)
		rest = body
	}
}

// attrValue returns the value of an XML attribute given the bytes immediately
// after `Name=` (i.e. starting at the opening quote). Returns "" if not quoted.
func attrValue(b []byte) string {
	if len(b) == 0 || (b[0] != '"' && b[0] != '\'') {
		return ""
	}
	q := b[0]
	end := bytes.IndexByte(b[1:], q)
	if end < 0 {
		return ""
	}
	return unescapeXMLText(string(b[1 : 1+end]))
}

// unescapeXMLText unescapes the five predefined XML entities so an entity-encoded
// formula (e.g. "&#61;cmd&#124;...") is tested in cleartext. Only the common
// cases are handled (full entity decoding is unnecessary for the trigger/pipe
// test and keeps this fail-open).
func unescapeXMLText(s string) string {
	if !strings.ContainsAny(s, "&") {
		return s
	}
	r := strings.NewReplacer(
		"&#61;", "=", "&#x3D;", "=", "&#x3d;", "=",
		"&#124;", "|", "&#x7C;", "|", "&#x7c;", "|",
		"&#33;", "!", "&#x21;", "!",
		"&#43;", "+", "&#64;", "@", "&#45;", "-",
		"&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&",
	)
	return r.Replace(s)
}
