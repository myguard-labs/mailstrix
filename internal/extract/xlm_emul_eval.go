package extract

// xlm_emul_eval.go — bounded iterative formula evaluator for the XLM emulator (Wave D, D2).
//
// evalExpr folds a formula string and resolves A1/R1C1 cell references
// iteratively (not recursively), with cycle-break via an evaluating set.
// Offline only (test-only caller until D4/D5 wire it in).

import (
	"regexp"
	"strconv"
	"strings"
)

// maxRefResolvePasses is the maximum number of A1-ref resolution passes
// evalExpr will attempt before returning a partial result.
const maxRefResolvePasses = 32

// reR1C1 matches R1C1-style references (Rrow Ccol) where row and col are each
// 1–7 decimal digits. The negative lookbehind is approximated by the caller
// checking the preceding byte.
var reR1C1 = regexp.MustCompile(`R(\d{1,7})C(\d{1,7})`)

// colNumToLetters converts a 1-based column number to Excel column letters.
// 1→"A", 26→"Z", 27→"AA", 702→"ZZ", 703→"AAA". Capped at 3 letters (max XFD=16384).
// Returns "" for out-of-range input (n<1 or n>16384).
func colNumToLetters(n int) string {
	if n < 1 || n > 16384 {
		return ""
	}
	result := make([]byte, 0, 3)
	for n > 0 {
		n-- // shift to 0-based
		result = append([]byte{byte('A' + n%26)}, result...)
		n /= 26
	}
	return string(result)
}

// r1c1ToA1 converts an R1C1-style reference string (e.g. "R1C1", "R12C34")
// to A1 notation. Returns "" if conversion is impossible.
func r1c1ToA1(r1c1 string) string {
	m := reR1C1.FindStringSubmatch(r1c1)
	if m == nil {
		return ""
	}
	row, err := strconv.Atoi(m[1])
	if err != nil || row < 1 {
		return ""
	}
	col, err := strconv.Atoi(m[2])
	if err != nil || col < 1 {
		return ""
	}
	letters := colNumToLetters(col)
	if letters == "" {
		return ""
	}
	return letters + strconv.Itoa(row)
}

// evalExpr iteratively resolves A1 and R1C1 cell references in formula
// against m (up to maxRefResolvePasses passes), then constant-folds the
// result. Cycle-break is enforced via the evaluating set: a ref already
// being evaluated is left in place. If evaluating is nil a fresh map is
// allocated internally.
func evalExpr(m *xlmMachine, sheetName, formula string, evaluating map[string]bool) string {
	if evaluating == nil {
		evaluating = make(map[string]bool)
	}

	// Work on the raw formula so that A1/R1C1 refs survive until substituted.
	s := formula

	// Step 1: iteratively resolve A1 and R1C1 refs.
	for pass := 0; pass < maxRefResolvePasses; pass++ {
		if expired(m.deadline) {
			break
		}

		// Convert any R1C1 refs to A1 first.
		s = replaceR1C1(s)
		s = resolveRefPlaceholdersQuoted(m, sheetName, s)

		// Resolve A1 refs.
		changed := false
		var b strings.Builder
		b.Grow(len(s))
		i := 0
		for i < len(s) {
			end, coord, ok := a1RefAt(s, i)
			if !ok {
				b.WriteByte(s[i])
				i++
				continue
			}
			key := sheetName + "!" + coord
			if evaluating[key] {
				// Cycle: leave ref as-is.
				b.WriteString(s[i:end])
				i = end
				continue
			}
			val, found := m.getCellValue(sheetName, coord)
			if !found {
				b.WriteString(s[i:end])
				i = end
				continue
			}
			// Resolve: substitute value (quote it so fold treats it as a string literal).
			evaluating[key] = true
			b.WriteString(quoteXLMStringLiteral(val))
			evaluating[key] = false
			i = end
			changed = true
		}
		s = b.String()
		if !changed {
			break // converged
		}
	}

	// Step 2: constant-fold the ref-resolved formula.
	folded := foldXLMFormulaDepth(s, 0, m.deadline)
	if folded != "" && !strings.Contains(strings.ToUpper(folded), "MID(") {
		return folded
	}
	if embedded, ok := foldEmbeddedMIDCalls(s, 0, m.deadline); ok {
		return strings.TrimPrefix(embedded, "=")
	}
	return folded
}

// replaceR1C1 replaces R1C1-style references in s with their A1 equivalents,
// skipping any match whose immediately preceding character is an A1 word char
// (letter, digit, or underscore) to avoid false-positives inside identifiers.
func replaceR1C1(s string) string {
	matches := reR1C1.FindAllStringIndex(s, -1)
	if len(matches) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, loc := range matches {
		start, end := loc[0], loc[1]
		// Check the byte before the match.
		if start > 0 && isA1Word(s[start-1]) {
			// Looks like it's part of an identifier — skip.
			b.WriteString(s[prev:end])
			prev = end
			continue
		}
		a1 := r1c1ToA1(s[start:end])
		if a1 == "" {
			b.WriteString(s[prev:end])
			prev = end
			continue
		}
		b.WriteString(s[prev:start])
		b.WriteString(a1)
		prev = end
	}
	b.WriteString(s[prev:])
	return b.String()
}
