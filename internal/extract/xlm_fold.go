package extract

// XLM constant-fold string reassembly. Parses Excel-4.0 macrosheet FORMULA
// cell text and applies bounded constant-folding to reassemble obfuscated
// strings (CHAR(n)&CHAR(m)&"literal"…). NO cell-graph execution, no GOTO/RUN,
// no cell-reference dereferencing, no variable dataflow. The folded cleartext
// is emitted as streams so keyword/URL/IOC YARA rules fire on it.
//
// Two container forms:
//   - OOXML (.xlsm): fromOOXMLXLMFold reads xl/macrosheets/sheet*.xml,
//     parses <f> formula elements, folds them, and emits results.
//   - BIFF8 (.xls): fromBIFFXLM (xlm.go) walks the Workbook stream's BIFF
//     records; inside a macrosheet substream (BOF dt 0x0040) it folds each
//     FORMULA (0x06) cell's ptg token stream via parseBIFF8Formula (biff_ptg.go)
//     and feeds the SAME emitFoldedFormula sink as the OOXML path (XLM-3).
//
// Fail-open: any parse error silently returns with no streams emitted.

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// XLM fold caps.
const (
	// maxXLMFoldFormulaLen caps individual formula text length (bytes).
	maxXLMFoldFormulaLen = 64 * 1024
	// maxXLMFoldOutputLen caps the total folded output (bytes) per document.
	maxXLMFoldOutputLen = 1 << 20
	// maxXLMFoldFormulas caps formulas processed per macrosheet.
	maxXLMFoldFormulas = 4096
	// maxXLMFoldSheets caps macrosheets scanned per document.
	maxXLMFoldSheets = 64
	// minXLMFoldResult is the minimum folded-string length to emit (avoids noise).
	minXLMFoldResult = 8
	// maxXLMFoldDepth bounds the foldXLMFormula↔foldFunctionCall mutual
	// recursion. A hostile formula nested deeper than the Go stack (e.g.
	// =EXEC(EXEC(EXEC(…)))) would otherwise overflow the stack — a fatal,
	// unrecoverable crash that recover() cannot trap. At the cap we stop
	// recursing and fold the remaining text flat, emitting a partial result.
	maxXLMFoldDepth = 16
)

// xlmDangerousFuncs are XLM function names whose presence in a folded result
// triggers a synthetic XLM-DANGEROUS-FUNC marker.
var xlmDangerousFuncs = []string{
	"EXEC",
	"EXECUTE",  // DDE command execution (ftab 178); distinct from =EXEC( above
	"INITIATE", // DDE conversation open (ftab 175) — VBA→DDE XLM bridge
	"CALL",
	"REGISTER",
	"FOPEN",
	"FWRITE",
	"HALT",
	"OPEN",      // opens a workbook/file; used in dropper chains (ftab 32769)
	"SEND.KEYS", // sends keystrokes to another app; shellcode trampoline (ftab 32899)
}

// fromOOXMLXLMFold reads xl/macrosheets/sheet*.xml from the already-opened
// OOXML zip, parses <f> (formula) elements, runs foldXLMFormula on each, and
// appends the non-trivial folded results to *out. Also emits XLM-DANGEROUS-FUNC
// markers for dangerous XLM function names found in the folded output.
// Fail-open: any read/parse error silently returns. Bounded; respects deadline.
// opts carries the per-request sheet/formula caps; nil uses package defaults.
func fromOOXMLXLMFold(zr *zip.Reader, out *[][]byte, deadline time.Time, opts *Options) {
	if expired(deadline) {
		return
	}

	sheetCap := opts.xlmFoldSheets()
	formulaCap := opts.xlmFoldFormulas()

	// Collect macrosheet zip entries.
	var sheets []*zip.File
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "xl/macrosheets/") && strings.HasSuffix(f.Name, ".xml") {
			sheets = append(sheets, f)
			if len(sheets) >= sheetCap {
				break
			}
		}
	}
	if len(sheets) == 0 {
		return
	}

	totalOutput := 0
	for _, sf := range sheets {
		if expired(deadline) || len(*out) >= maxStreams {
			return
		}
		processXLMFoldSheet(sf, out, &totalOutput, deadline, formulaCap)
	}
}

// processXLMFoldSheet parses one macrosheet XML, collects cell coordinates,
// formulas (<f>), and pre-computed values (<v>), then runs the two-pass
// XLM cell-reference interpreter (XLM-6) before emitting results.
// formulaCap limits how many cells are collected (effort-scaled).
func processXLMFoldSheet(sf *zip.File, out *[][]byte, totalOutput *int, deadline time.Time, formulaCap int) {
	if sf.UncompressedSize64 > maxBytesWorkbookXML {
		return
	}
	rc, err := sf.Open()
	if err != nil {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxBytesWorkbookXML))
	rc.Close() // #nosec G104 -- zip entry close
	if err != nil || len(raw) == 0 {
		return
	}

	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false

	var cells []xlmCell
	var currentCell xlmCell
	inCell := false

	for {
		if expired(deadline) || len(*out) >= maxStreams {
			break // stop collecting, but still interpret+emit what we have
		}
		if len(cells) >= formulaCap {
			break
		}

		tok, err := dec.Token()
		if err != nil {
			break // EOF or malformed
		}

		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "c":
				// Cell element — capture the "r" attribute (coordinate).
				inCell = true
				currentCell = xlmCell{}
				for _, attr := range t.Attr {
					if attr.Name.Local == "r" {
						currentCell.coord = attr.Value
						break
					}
				}

			case "f":
				// Formula element inside a cell.
				if !inCell {
					continue
				}
				var content string
				if err := dec.DecodeElement(&content, &t); err != nil {
					continue
				}
				if len(content) > 0 && len(content) <= maxXLMFoldFormulaLen {
					currentCell.formula = content
				}

			case "v":
				// Pre-computed value element inside a cell.
				if !inCell {
					continue
				}
				var content string
				if err := dec.DecodeElement(&content, &t); err != nil {
					continue
				}
				if len(content) <= maxXLMFoldFormulaLen {
					currentCell.value = content
				}
			}

		case xml.EndElement:
			if t.Name.Local == "c" && inCell {
				if currentCell.formula != "" || currentCell.value != "" {
					cells = append(cells, currentCell)
				}
				inCell = false
				currentCell = xlmCell{}
			}
		}
	}

	// Bounded XLM emulator (D6). Zero-output fallback to interpreter inside emulateXLMCells.
	emulateXLMCells(cells, out, totalOutput, deadline)
}

// emitFoldedFormula is the shared emit sink for folded/precomputed XLM strings.
// It enforces the minXLMFoldResult floor (skip-but-continue) and the
// maxXLMFoldOutputLen per-document cap (stop), appends the string to *out, and —
// when checkDangerous — emits XLM-DANGEROUS-FUNC markers. Both the OOXML path and
// the future BIFF8 ptg front-end (XLM-2/3) feed this sink so they cannot drift on
// the floor, the cap, or marker emission. Returns false when the output cap is
// reached, signalling the caller to stop emitting.
func emitFoldedFormula(s string, out *[][]byte, totalOutput *int, checkDangerous bool) bool {
	if len(s) < minXLMFoldResult {
		return true // below the noise floor — skip, but keep scanning
	}
	if *totalOutput+len(s) > maxXLMFoldOutputLen {
		return false // per-document output cap reached
	}
	*totalOutput += len(s)
	*out = append(*out, []byte(s))
	if checkDangerous {
		emitDangerousMarkers(s, out)
	}
	return true
}

// emitDangerousMarkers appends XLM-DANGEROUS-FUNC markers for any dangerous
// XLM functions found in the folded string.
func emitDangerousMarkers(folded string, out *[][]byte) {
	upper := strings.ToUpper(folded)
	for _, fn := range xlmDangerousFuncs {
		if strings.Contains(upper, "="+fn+"(") {
			*out = append(*out, []byte("XLM-DANGEROUS-FUNC "+fn))
		}
	}
}

// foldXLMFormula applies bounded constant-folding to an XLM formula string.
// It handles:
//   - CHAR(N) → single character (N 0-127 printable, else dropped)
//   - & concatenation of CHAR() results and string literals
//   - Quoted string literals "..."
//   - =PREFIX stripping
//
// Anything it cannot fold (cell refs, unknown functions) is skipped, and the
// successfully folded portions are concatenated. The goal is to reassemble
// obfuscated strings like =CHAR(104)&CHAR(116)&"tp://evil.com" → "http://evil.com".
// foldXLMFormula folds with no deadline (callers that aren't on the scan
// wall-clock path — unit/fuzz tests). expired() is false on a zero time, so this
// behaves exactly as before deadline plumbing was added.
func foldXLMFormula(formula string) string {
	return foldXLMFormulaDepth(formula, 0, time.Time{})
}

// foldXLMFormulaDepth is foldXLMFormula with an explicit recursion depth and a
// deadline. foldPart→foldFunctionCall recurse back here with depth+1; at
// maxXLMFoldDepth we stop descending into function arguments and fold the parts
// flat so a pathologically nested formula cannot overflow the stack (a fatal
// crash that recover() cannot trap). The deadline is checked at entry and inside
// the parts loop (STAB-2) so a single oversized/wide formula bails mid-fold
// rather than only at the per-formula boundary in processXLMFoldSheet; on expiry
// we return what we have folded so far.
func foldXLMFormulaDepth(formula string, depth int, deadline time.Time) string {
	if len(formula) == 0 || expired(deadline) {
		return ""
	}

	// Strip leading = if present.
	s := formula
	if s[0] == '=' {
		s = s[1:]
	}

	// Split on & (concatenation operator) respecting quoted strings.
	parts := splitOnConcat(s)

	var buf strings.Builder
	buf.Grow(min(len(s), 4096))

	for i, part := range parts {
		// Bail mid-formula on deadline: a formula split into thousands of parts
		// (each a CHAR()/function call) must not run the whole loop once the scan
		// budget is spent. Check every 64 parts to keep time.Now() off the hot path.
		if i&63 == 0 && expired(deadline) {
			break
		}
		part = strings.TrimSpace(part)
		if len(part) == 0 {
			continue
		}

		if folded, ok := foldPart(part, depth, deadline); ok {
			buf.WriteString(folded)
		}
		// If we can't fold a part, skip it — emit what we can.
	}
	return buf.String()
}

// splitOnConcat splits a formula on the & operator, respecting quoted strings
// and balanced parentheses (so EXEC(CHAR(65)&CHAR(66)) is not split inside
// the EXEC call).
func splitOnConcat(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	depth := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' {
			if inQuote {
				// Check for escaped quote ("").
				if i+1 < len(s) && s[i+1] == '"' {
					cur.WriteByte('"')
					cur.WriteByte('"')
					i++
					continue
				}
				inQuote = false
			} else {
				inQuote = true
			}
			cur.WriteByte(ch)
		} else if !inQuote && ch == '(' {
			depth++
			cur.WriteByte(ch)
		} else if !inQuote && ch == ')' {
			if depth > 0 {
				depth--
			}
			cur.WriteByte(ch)
		} else if ch == '&' && !inQuote && depth == 0 {
			parts = append(parts, cur.String())
			cur.Reset()
		} else {
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}

// foldPart tries to fold a single formula part (between & operators).
// Returns the folded string and true if successful. depth is the current
// recursion depth, propagated to foldFunctionCall to bound nesting; deadline is
// propagated so a nested function call bails with the rest of the fold.
func foldPart(part string, depth int, deadline time.Time) (string, bool) {
	trimmed := strings.TrimSpace(part)
	upper := strings.ToUpper(trimmed)

	// CHAR(N)
	if strings.HasPrefix(upper, "CHAR(") && strings.HasSuffix(upper, ")") {
		inner := trimmed[5 : len(trimmed)-1]
		inner = strings.TrimSpace(inner)
		n, err := strconv.Atoi(inner)
		if err != nil || n < 0 || n > 127 {
			return "", false
		}
		ch := rune(n)
		if !unicode.IsPrint(ch) && ch != '\t' && ch != '\n' && ch != '\r' {
			return "", false
		}
		return string(ch), true
	}

	// Quoted string literal "..."
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		inner := trimmed[1 : len(trimmed)-1]
		inner = strings.ReplaceAll(inner, `""`, `"`)
		return inner, true
	}

	// Function call with string arguments — preserve the function wrapper
	// and fold its inner arguments so dangerous-func detection works.
	if idx := strings.IndexByte(upper, '('); idx > 0 {
		fname := strings.TrimSpace(upper[:idx])
		if isXLMFunctionName(fname) {
			return foldFunctionCall(trimmed, depth, deadline), true
		}
	}

	return "", false
}

// foldFunctionCall preserves a function wrapper and folds its arguments.
// depth bounds the mutual recursion with foldXLMFormulaDepth: at the cap we
// keep the arguments verbatim instead of recursing, so dangerous-func markers
// still fire on the wrapper but the stack can't overflow.
func foldFunctionCall(call string, depth int, deadline time.Time) string {
	idx := strings.IndexByte(call, '(')
	if idx < 0 {
		return call
	}
	fname := strings.ToUpper(strings.TrimSpace(call[:idx]))
	rest := call[idx+1:]
	closeIdx := strings.LastIndexByte(rest, ')')
	if closeIdx < 0 {
		return call
	}
	args := rest[:closeIdx]
	if depth >= maxXLMFoldDepth || expired(deadline) {
		// Recursion cap reached (or deadline hit): emit the wrapper with un-folded
		// args so dangerous-func markers still fire but we stop descending.
		return "=" + fname + "(" + args + ")"
	}
	folded := foldXLMFormulaDepth(args, depth+1, deadline)
	if folded == "" {
		folded = args
	}
	return "=" + fname + "(" + folded + ")"
}

// isXLMFunctionName checks if a string looks like an XLM function name that
// wraps arguments we should try to fold.
func isXLMFunctionName(s string) bool {
	switch s {
	case "EXEC", "CALL", "REGISTER", "FOPEN", "FWRITE", "HALT",
		"FORMULA", "FORMULA.FILL", "SET.NAME", "SET.VALUE",
		"ALERT", "INPUT", "APP.MAXIMIZE", "WORKBOOK.HIDE",
		"RUN", "GOTO", "RETURN", "IF", "WHILE", "ERROR":
		return true
	}
	return false
}
