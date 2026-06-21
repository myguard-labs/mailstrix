package extract

// xlm_interp.go — bounded 1-level XLM cell-reference interpreter for the
// OOXML (.xlsm) macrosheet path.
//
// Performs a two-pass resolution over the cells collected by
// processXLMFoldSheet:
//   PASS 1 — build a coord→value map from <v> elements and SET.VALUE formulas.
//   PASS 2 — for each formula cell, fold it and substitute one level of A1-style
//            cell references with the values from PASS 1, then emit.
//
// Design constraints:
//   - Bounded:    caps on cell count, substitutions per formula.
//   - Fail-open:  any parse or substitution error leaves the ref as-is.
//   - Never-panic: no out-of-bounds access; all index arithmetic is guarded.
//   - 1-level only: PASS 2 substitutes from the static vals map; it does not
//     re-evaluate the value it just substituted (no chained graph walk).

import (
	"regexp"
	"strings"
	"time"
)

// xlmCell holds a single macrosheet cell's coordinate, formula, and
// pre-computed value as decoded from the macrosheet XML.
type xlmCell struct {
	coord   string // e.g. "A1", "B3"
	formula string // raw <f> text (may be empty)
	value   string // raw <v> text (may be empty)
}

const (
	// maxXLMInterpCells caps the number of cells accepted for interpretation.
	maxXLMInterpCells = 4096
	// maxXLMInterpSubs caps substitutions applied per formula in PASS 2.
	maxXLMInterpSubs = 256
)

// reSetValue matches a SET.VALUE formula and captures the target coordinate
// and the value expression.
//
//	group 1: target coordinate (possibly with $ prefixes)
//	group 2: value expression (everything after the comma, trimmed)
var reSetValue = regexp.MustCompile(`(?i)^=?SET\.VALUE\(\s*(\$?[A-Z]{1,3}\$?[0-9]{1,7})\s*,\s*(.*?)\s*\)$`)

// reNormCoord matches the optional $ plus a column letter group and row digit
// group so normCoord can strip the sigils.
var reNormCoord = regexp.MustCompile(`^\$?([A-Z]{1,3})\$?([0-9]{1,7})$`)

// reValidCoord accepts a normalised (no-$) coord produced by normCoord.
var reValidCoord = regexp.MustCompile(`^[A-Z]{1,3}[0-9]{1,7}$`)

// normCoord strips leading $ from column and row parts and uppercases the
// result.  Accepts "$A$1", "A1", "$A1", "A$1" → always "A1" style.
// Returns "" for any input that does not look like a cell coordinate.
func normCoord(s string) string {
	upper := strings.ToUpper(strings.TrimSpace(s))
	m := reNormCoord.FindStringSubmatch(upper)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// stripOuterQuotes removes a single layer of double quotes from a quoted string
// literal, e.g. `"calc.exe"` → `calc.exe`.  Returns s unchanged if it is not
// a quoted literal.
func stripOuterQuotes(s string) string {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		inner := trimmed[1 : len(trimmed)-1]
		// Unescape doubled quotes ("" → ").
		return strings.ReplaceAll(inner, `""`, `"`)
	}
	return s
}

// interpretXLMCells performs the two-pass cell-reference resolution over the
// cells collected from one macrosheet and emits the resolved formulas via the
// shared emitFoldedFormula sink.
//
// PASS 1 builds a coord→string value map.
// PASS 2 folds each formula and substitutes one level of A1 refs.
func interpretXLMCells(cells []xlmCell, out *[][]byte, totalOutput *int, deadline time.Time) {
	if len(cells) == 0 {
		return
	}
	// Hard cap on input.
	if len(cells) > maxXLMInterpCells {
		cells = cells[:maxXLMInterpCells]
	}

	// ── PASS 1 ── build vals map ────────────────────────────────────────────

	vals := make(map[string]string, len(cells))

	for i, cell := range cells {
		if i&63 == 0 && expired(deadline) {
			return
		}
		if len(vals) >= maxXLMInterpCells {
			break
		}

		coord := normCoord(cell.coord)

		// Seed from pre-computed <v> values.
		if cell.value != "" && coord != "" && reValidCoord.MatchString(coord) {
			if _, exists := vals[coord]; !exists {
				vals[coord] = cell.value
			}
		}

		// Seed from SET.VALUE formulas.
		if cell.formula != "" && strings.Contains(strings.ToUpper(cell.formula), "SET.VALUE") {
			folded := foldXLMFormulaDepth(cell.formula, 0, deadline)
			if expired(deadline) {
				return
			}
			m := reSetValue.FindStringSubmatch(folded)
			if m == nil {
				// Also try on the raw formula in case folding didn't help.
				m = reSetValue.FindStringSubmatch(cell.formula)
			}
			if len(m) >= 3 {
				targetCoord := normCoord(m[1])
				if targetCoord != "" && reValidCoord.MatchString(targetCoord) {
					if len(vals) < maxXLMInterpCells {
						vals[targetCoord] = stripOuterQuotes(m[2])
					}
				}
			}
		}
	}

	// ── PASS 2 ── fold + substitute + emit ──────────────────────────────────

	for _, cell := range cells {
		if expired(deadline) || len(*out) >= maxStreams {
			return
		}

		if cell.formula != "" {
			folded := foldXLMFormulaDepth(cell.formula, 0, deadline)
			if expired(deadline) {
				return
			}
			resolved := substituteRefs(folded, vals)
			if !emitFoldedFormula(resolved, out, totalOutput, true) {
				return // per-document output cap reached
			}
		} else if cell.value != "" {
			// Pre-computed value with no formula — emit directly (no dangerous
			// marker scan; matches prior <v> behaviour).
			if !emitFoldedFormula(cell.value, out, totalOutput, false) {
				return
			}
		}
	}
}

// substituteRefs replaces unquoted, same-sheet A1-style cell references in s
// with their values from vals (one level only). It accepts case-insensitive and
// absolute references ($A$1). Sheet-qualified references remain untouched:
// this interpreter deliberately has no cross-sheet value graph. At most
// maxXLMInterpSubs substitutions are performed. Any error or unrecognised ref
// is left as-is (fail-open).
func substituteRefs(s string, vals map[string]string) string {
	if len(vals) == 0 || s == "" {
		return s
	}

	var buf strings.Builder
	buf.Grow(len(s))
	pos := 0
	subs := 0
	inString := false

	for i := 0; i < len(s); {
		if s[i] == '"' {
			if inString && i+1 < len(s) && s[i+1] == '"' {
				i += 2 // Excel escapes a quote in a string literal as "".
				continue
			}
			inString = !inString
			i++
			continue
		}
		if inString || subs >= maxXLMInterpSubs {
			i++
			continue
		}

		end, coord, ok := a1RefAt(s, i)
		if !ok {
			i++
			continue
		}

		val, found := vals[coord]
		if !found {
			i = end
			continue
		}
		buf.WriteString(s[pos:i])
		buf.WriteString(val)
		pos = end
		subs++
		i = end
	}
	buf.WriteString(s[pos:])
	return buf.String()
}

// a1RefAt recognises one standalone, unqualified A1 reference at start and
// returns its end offset plus uppercase, dollar-free coordinate. It rejects
// refs in identifiers and refs immediately following !, which are qualified by
// another sheet/workbook and cannot be resolved by this sheet-local interpreter.
func a1RefAt(s string, start int) (end int, coord string, ok bool) {
	if start >= len(s) || (start > 0 && (isA1Word(s[start-1]) || s[start-1] == '!')) {
		return 0, "", false
	}

	i := start
	if s[i] == '$' {
		i++
	}
	colStart := i
	for i < len(s) && isASCIIAlpha(s[i]) && i-colStart < 3 {
		i++
	}
	if i == colStart || (i < len(s) && isASCIIAlpha(s[i])) {
		return 0, "", false
	}
	col := strings.ToUpper(s[colStart:i])

	if i < len(s) && s[i] == '$' {
		i++
	}
	rowStart := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' && i-rowStart < 7 {
		i++
	}
	if i == rowStart || (i < len(s) && s[i] >= '0' && s[i] <= '9') {
		return 0, "", false
	}
	if i < len(s) && isA1Word(s[i]) {
		return 0, "", false
	}
	return i, col + s[rowStart:i], true
}

func isASCIIAlpha(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func isA1Word(c byte) bool {
	return isASCIIAlpha(c) || c >= '0' && c <= '9' || c == '_'
}
