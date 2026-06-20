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
//   - BIFF8 (.xls): skipped — BIFF8 formula token parsing (ptg opcodes) is
//     substantially more complex than OOXML text formulas, and the OOXML path
//     covers .xlsm which is the dominant modern XLM vector. TODO: add BIFF8
//     folding if real-world samples demand it.
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
)

// xlmDangerousFuncs are XLM function names whose presence in a folded result
// triggers a synthetic XLM-DANGEROUS-FUNC marker.
var xlmDangerousFuncs = []string{
	"EXEC",
	"CALL",
	"REGISTER",
	"FOPEN",
	"FWRITE",
	"HALT",
}

// fromOOXMLXLMFold reads xl/macrosheets/sheet*.xml from the already-opened
// OOXML zip, parses <f> (formula) elements, runs foldXLMFormula on each, and
// appends the non-trivial folded results to *out. Also emits XLM-DANGEROUS-FUNC
// markers for dangerous XLM function names found in the folded output.
// Fail-open: any read/parse error silently returns. Bounded; respects deadline.
func fromOOXMLXLMFold(zr *zip.Reader, out *[][]byte, deadline time.Time) {
	if expired(deadline) {
		return
	}

	// Collect macrosheet zip entries.
	var sheets []*zip.File
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "xl/macrosheets/") && strings.HasSuffix(f.Name, ".xml") {
			sheets = append(sheets, f)
			if len(sheets) >= maxXLMFoldSheets {
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
		processXLMFoldSheet(sf, out, &totalOutput, deadline)
	}
}

// processXLMFoldSheet parses one macrosheet XML and folds its formulas.
func processXLMFoldSheet(sf *zip.File, out *[][]byte, totalOutput *int, deadline time.Time) {
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

	formulaCount := 0
	for {
		if expired(deadline) || len(*out) >= maxStreams {
			return
		}
		if formulaCount >= maxXLMFoldFormulas {
			return
		}

		tok, err := dec.Token()
		if err != nil {
			return // EOF or malformed
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		switch se.Name.Local {
		case "f":
			// Formula element — read its text content.
			var content string
			if err := dec.DecodeElement(&content, &se); err != nil {
				continue
			}
			formulaCount++
			if len(content) == 0 || len(content) > maxXLMFoldFormulaLen {
				continue
			}
			folded := foldXLMFormula(content)
			if len(folded) < minXLMFoldResult {
				continue
			}
			if *totalOutput+len(folded) > maxXLMFoldOutputLen {
				return
			}
			*totalOutput += len(folded)
			*out = append(*out, []byte(folded))

			// Check for dangerous functions.
			emitDangerousMarkers(folded, out)

		case "v":
			// Value element — may contain a pre-computed string result.
			var content string
			if err := dec.DecodeElement(&content, &se); err != nil {
				continue
			}
			formulaCount++
			if len(content) < minXLMFoldResult || len(content) > maxXLMFoldFormulaLen {
				continue
			}
			if *totalOutput+len(content) > maxXLMFoldOutputLen {
				return
			}
			*totalOutput += len(content)
			*out = append(*out, []byte(content))
		}
	}
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
func foldXLMFormula(formula string) string {
	if len(formula) == 0 {
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

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) == 0 {
			continue
		}

		if folded, ok := foldPart(part); ok {
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
// Returns the folded string and true if successful.
func foldPart(part string) (string, bool) {
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
			return foldFunctionCall(trimmed), true
		}
	}

	return "", false
}

// foldFunctionCall preserves a function wrapper and folds its arguments.
func foldFunctionCall(call string) string {
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
	folded := foldXLMFormula(args)
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
