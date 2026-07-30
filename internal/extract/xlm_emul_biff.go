package extract

// xlm_emul_biff.go — BIFF8/BIFF12 two-pass XLM emulator helpers (Wave D, D7).
//
// Provides WithRefs variants of parseBIFF8Formula and parseBIFF12Formula that
// emit [[REF:A1]] placeholder tokens for ptgRef cells (instead of "") so the
// caller can later resolve them against the live emulator grid.
//
// Also provides:
//   - biffCellToA1:          convert 0-based (row, col) to A1 notation
//   - reRefPlaceholder:      regexp matching [[REF:A1]] tokens
//   - resolveRefPlaceholders: substitute [[REF:...]] against the xlmMachine grid
//   - stripRefPlaceholders:   remove any remaining [[REF:...]] tokens

import (
	"regexp"
	"strconv"
	"strings"
)

// biffCellToA1 converts a 0-based (row, col) pair from a BIFF ptgRef payload
// to A1 notation. Bits 14-15 of col are relative-reference flags and are
// masked before conversion. Both row and col are made 1-based.
func biffCellToA1(row, col uint16) string {
	// Mask relative-reference bits (14 and 15).
	c := int(col&0x3FFF) + 1
	r := int(row) + 1
	letters := colNumToLetters(c)
	if letters == "" {
		return ""
	}
	return letters + strconv.Itoa(r)
}

// parseBIFF8FormulaWithRefs is like parseBIFF8Formula but overrides the ptgRef
// case: instead of pushing "" it pushes a "[[REF:A1]]" placeholder that the
// caller can resolve against the live emulator grid. ptgRef3d still pushes "".
//
// Shares the dispatch loop with the other three folders via biff8RefsDialect;
// see biffPtgDialect (biff_ptg.go) for exactly what the WithRefs variant changes.
func parseBIFF8FormulaWithRefs(data []byte) string {
	return foldBIFFPtgStream(data, biff8RefsDialect)
}

// parseBIFF12FormulaWithRefs is like parseBIFF12Formula but overrides the
// ptgRef case to emit "[[REF:A1]]" placeholders. ptgStr uses BIFF12 encoding
// (uint16 cch + UTF-16LE, no fHighByte). ptgRef3d still pushes "".
//
// Shares the dispatch loop with the other three folders via biff12RefsDialect.
func parseBIFF12FormulaWithRefs(data []byte) string {
	return foldBIFFPtgStream(data, biff12RefsDialect)
}

// reRefPlaceholder matches [[REF:A1]]-style tokens emitted by the WithRefs
// parsers. The inner part is the A1 coordinate (letters then digits).
var reRefPlaceholder = regexp.MustCompile(`\[\[REF:([A-Z]+[0-9]+)\]\]`)

// resolveRefPlaceholders replaces every [[REF:coord]] token in s with the
// live value of that cell in the named sheet (via m.getCellValue). Tokens
// whose cell has no value (empty or absent) are left unchanged.
func resolveRefPlaceholders(m *xlmMachine, sheetName, s string) string {
	return reRefPlaceholder.ReplaceAllStringFunc(s, func(match string) string {
		sub := reRefPlaceholder.FindStringSubmatch(match)
		if sub == nil {
			return match
		}
		coord := sub[1]
		if val, ok := m.getCellValue(sheetName, coord); ok {
			return val
		}
		return match
	})
}

func resolveRefPlaceholdersQuoted(m *xlmMachine, sheetName, s string) string {
	return reRefPlaceholder.ReplaceAllStringFunc(s, func(match string) string {
		sub := reRefPlaceholder.FindStringSubmatch(match)
		if sub == nil {
			return match
		}
		coord := sub[1]
		if val, ok := m.getCellValue(sheetName, coord); ok {
			return quoteXLMStringLiteral(val)
		}
		return match
	})
}

func quoteXLMStringLiteral(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// stripRefPlaceholders removes every [[REF:...]] token from s, leaving the
// surrounding text intact.
func stripRefPlaceholders(s string) string {
	return reRefPlaceholder.ReplaceAllString(s, "")
}
