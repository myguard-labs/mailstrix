package extract

// SYLK (.slk) XLM/DDE formula extraction — XLM-5.
//
// SYLK ("symbolic link") is a plain-text spreadsheet interchange format. It is a
// line-oriented record stream: each line starts with a single record-type letter
// followed by ';'-delimited fields. Excel opens .slk files and — critically —
// executes XLM macro formulas and DDE expressions stored in cell records, so
// .slk is a known macro-dropper carrier (=EXEC(...), =CALL(...), and the DDE
// =cmd|'/c calc'!A1 form) that arrives as innocuous-looking text.
//
// The only records we care about are cell records ("C;...") whose fields include
// an expression field — "E<formula>" (the active formula). We pull each E-field,
// constant-fold it through the SAME foldXLMFormula engine + emitFoldedFormula
// sink the OOXML/.xls/.xlsb XLM paths use (so dangerous-func markers and the
// minlen/output caps cannot drift across container forms), and also surface a
// DDE marker for the SLK DDE command form.
//
// Fail-open + bounded: line count, line length and folded-output budget are all
// capped; any malformed line is skipped. Never panics.

import (
	"bytes"
	"strings"
	"time"
)

// SLK fold caps.
const (
	// maxSLKLines caps records scanned per .slk file.
	maxSLKLines = 1 << 16
	// maxSLKLineLen caps a single record line length (bytes) fed to the folder.
	maxSLKLineLen = maxXLMFoldFormulaLen
	// slkSniffLen is how many leading bytes isSLK inspects for the ID signature.
	slkSniffLen = 16
)

// isSLK reports whether buf opens a SYLK document. SYLK has no binary magic; the
// recogniser is its mandatory leading record — the file MUST begin with an "ID"
// record ("ID;P..." in practice, "ID;" minimally), optionally after a UTF-8 BOM.
// Requiring the "ID;" record (not merely a leading 'C') keeps ordinary CSV/text
// from being misclassified as SLK.
func isSLK(buf []byte) bool {
	buf = bytes.TrimPrefix(buf, utf8BOM)
	if len(buf) > slkSniffLen {
		buf = buf[:slkSniffLen]
	}
	return bytes.HasPrefix(buf, []byte("ID;"))
}

// fromSLK scans a SYLK document's cell records for XLM/DDE formulas, folds them
// through the shared XLM sink, and emits folded cleartext + dangerous-func / DDE
// markers to res.Streams. Sets res.IsSLK and res.HasXLMFold (when anything
// folded). Fail-open; bounded; respects deadline.
func fromSLK(buf []byte, res *Result, deadline time.Time) {
	res.IsSLK = true
	if expired(deadline) {
		return
	}

	buf = bytes.TrimPrefix(buf, utf8BOM)
	totalOutput := 0
	lines := 0
	prevLen := len(res.Streams)

	// SYLK lines are CR, LF or CRLF separated. Iterate with bytes.Cut rather than
	// bytes.Split so the maxSLKLines cap bounds the work BEFORE any per-line
	// allocation — a crafted .slk with millions of '\n' bytes must not force a
	// full line-header slice for the whole input up front.
	rest := buf
	for len(rest) > 0 {
		if lines >= maxSLKLines || len(res.Streams) >= maxStreams || expired(deadline) {
			break
		}
		lines++
		var raw []byte
		raw, rest, _ = bytes.Cut(rest, []byte("\n"))
		line := bytes.TrimRight(raw, "\r")
		// Cell records carry formulas. A record is "<letter>;<field>;<field>...".
		if len(line) < 2 || line[0] != 'C' || line[1] != ';' {
			continue
		}
		if len(line) > maxSLKLineLen {
			line = line[:maxSLKLineLen]
		}
		formula := slkExpressionField(line)
		if formula == "" {
			continue
		}
		// DDE command form: =cmd|'/c calc'!A1 — surface a marker regardless of
		// whether the constant-folder recognises it as an XLM call.
		if isSLKDDE(formula) {
			res.Streams = append(res.Streams, []byte("SLK-DDE "+formula))
		}
		folded := foldXLMFormulaDepth(formula, 0, deadline)
		if folded == "" {
			folded = formula // emit the raw formula so keyword/URL rules still see it
		}
		if !emitFoldedFormula(folded, &res.Streams, &totalOutput, true) {
			break // per-document output cap reached
		}
	}

	if len(res.Streams) > prevLen {
		res.HasXLMFold = true
	}
}

// slkExpressionField returns the value of the "E" (expression/formula) field of
// a SYLK cell record, or "" if absent. Fields are ';'-delimited; the E-field is
// the one beginning with 'E'. A literal ";;" inside a SYLK field is an escaped
// semicolon, but the formula text we want stops at the first unescaped ';', so
// we walk fields honouring the ";;" escape.
func slkExpressionField(line []byte) string {
	s := string(line)
	// Split into fields on single ';' but keep ";;" (escaped) together.
	fields := splitSLKFields(s)
	for _, f := range fields {
		if len(f) >= 1 && (f[0] == 'E' || f[0] == 'e') {
			return strings.TrimSpace(f[1:])
		}
	}
	return ""
}

// splitSLKFields splits a SYLK record on ';' delimiters, treating ";;" as an
// escaped literal semicolon within a field (SYLK's documented escape).
func splitSLKFields(s string) []string {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			if i+1 < len(s) && s[i+1] == ';' {
				cur.WriteByte(';') // escaped literal ';'
				i++
				continue
			}
			fields = append(fields, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	fields = append(fields, cur.String())
	return fields
}

// isSLKDDE reports whether a SYLK formula is the DDE command-execution form,
// e.g. =cmd|'/c calc.exe'!A1 or =MSEXCEL|'\..\..\Windows\...'!A1. The signature
// is an '=' followed (after optional spaces) by an app token, a '|' pipe, a
// quoted command, and a '!' cell-ref tail.
func isSLKDDE(formula string) bool {
	f := strings.TrimSpace(formula)
	if len(f) == 0 || f[0] != '=' {
		return false
	}
	bar := strings.IndexByte(f, '|')
	if bar <= 1 {
		return false
	}
	return strings.IndexByte(f[bar:], '!') > 0
}
