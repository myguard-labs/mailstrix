package extract

// xlm_emul_flow.go — IF-branch exploration, WHILE/NEXT unroll, FOR.CELL cap,
// and SET.NAME/DEFINE.NAME for the XLM emulator (Wave D, D5).
//
// All control-flow handlers here are called from xlm_emul_pc.go's run() loop.
// COW fork frames are explored after the main loop exits.

import (
	"maps"
	"strings"
)

// forkFrame is a saved emulator state pushed onto m.forkQueue when an IF
// branch result is unknown and both paths must be explored.
type forkFrame struct {
	sheet  string
	coord  string
	sheets map[string]*xlmSheet // COW snapshot (shallow-cloned)
	names  map[string]string    // COW snapshot (shallow-cloned)
	steps  int                  // step count at fork point
}

// boolLiteral returns "TRUE" or "FALSE" when s is a bare boolean literal
// (case-insensitive, optional leading "="), and "" otherwise.
// Handles "TRUE", "FALSE", "1", "0" which Excel treats as boolean constants.
func boolLiteral(s string) string {
	t := strings.TrimSpace(s)
	if len(t) > 0 && t[0] == '=' {
		t = strings.TrimSpace(t[1:])
	}
	switch strings.ToUpper(t) {
	case "TRUE", "1":
		return "TRUE"
	case "FALSE", "0":
		return "FALSE"
	}
	return ""
}

// cowSheetsSnapshot creates a shallow copy of the sheets map suitable for
// COW fork exploration. The outer map is cloned via maps.Clone; each
// *xlmSheet pointer is replaced with a new xlmSheet whose cells map is also
// cloned. This means the snapshot is independent of the original for any
// insertions/deletions but shares the *emulCell values themselves (which
// D5 never mutates during exploration).
func cowSheetsSnapshot(src map[string]*xlmSheet) map[string]*xlmSheet {
	snap := maps.Clone(src) // outer map cloned
	for k, sh := range snap {
		shCopy := &xlmSheet{
			name:  sh.name,
			cells: maps.Clone(sh.cells),
		}
		snap[k] = shCopy
	}
	return snap
}

// parseIFArgs extracts the three arguments of an IF formula.
// Accepts forms like "=IF(cond,true,false)" or "IF(cond,true,false)".
// Splits on the first two top-level commas (not inside nested parens).
// Returns ("","","",false) on any parse failure.
func parseIFArgs(formula string) (cond, truePart, falsePart string, ok bool) {
	s := formula
	if len(s) > 0 && s[0] == '=' {
		s = s[1:]
	}
	upper := strings.ToUpper(s)
	idx := strings.Index(upper, "IF(")
	if idx < 0 {
		return "", "", "", false
	}
	inner := s[idx+3:]

	// Find matching close paren for the IF( open.
	depth := 1
	commas := []int{}
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				if len(commas) < 2 {
					return "", "", "", false
				}
				c1, c2 := commas[0], commas[1]
				cond = strings.TrimSpace(inner[:c1])
				truePart = strings.TrimSpace(inner[c1+1 : c2])
				falsePart = strings.TrimSpace(inner[c2+1 : i])
				if cond == "" {
					return "", "", "", false
				}
				return cond, truePart, falsePart, true
			}
		case ',':
			if depth == 1 && len(commas) < 2 {
				commas = append(commas, i)
			}
		}
	}
	return "", "", "", false
}

// parseNameArg extracts the (name, value) pair from a SET.NAME or DEFINE.NAME
// formula. Accepts "=SET.NAME(name,value)" and "=DEFINE.NAME(name,refers_to)".
// Both arguments are trimmed of surrounding whitespace and outer double-quotes.
// Returns ("","",false) on any parse failure.
func parseNameArg(formula string) (name, value string, ok bool) {
	s := formula
	if len(s) > 0 && s[0] == '=' {
		s = s[1:]
	}
	upper := strings.ToUpper(s)

	var innerStart int
	switch {
	case strings.HasPrefix(upper, "SET.NAME("):
		innerStart = len("SET.NAME(")
	case strings.HasPrefix(upper, "DEFINE.NAME("):
		innerStart = len("DEFINE.NAME(")
	default:
		return "", "", false
	}

	inner := s[innerStart:]
	// Find the closing paren at depth 1.
	depth := 1
	commaIdx := -1
	closeIdx := -1
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				closeIdx = i
			}
		case ',':
			if depth == 1 && commaIdx < 0 {
				commaIdx = i
			}
		}
		if closeIdx >= 0 {
			break
		}
	}
	if commaIdx < 0 || closeIdx < 0 || closeIdx <= commaIdx {
		return "", "", false
	}

	rawName := strings.TrimSpace(inner[:commaIdx])
	rawVal := strings.TrimSpace(inner[commaIdx+1 : closeIdx])

	// Strip outer double-quotes if present.
	rawName = stripOuterQuotes(rawName)
	rawVal = stripOuterQuotes(rawVal)

	if rawName == "" {
		return "", "", false
	}
	return rawName, rawVal, true
}

// handleIF processes an IF(cond,true,false) formula at the current PC.
// - If cond evaluates to "TRUE": redirect PC to truePart coord.
// - If cond evaluates to "FALSE": redirect PC to falsePart coord.
// - Otherwise (unknown): follow truePart immediately and push falsePart as a
//   fork frame (COW snapshot). If falsePart is empty, only the true branch
//   is followed.
//
// curSheet and curCoord are updated in-place to move the PC.
func (m *xlmMachine) handleIF(formula, sheetName, coord string, curSheet, curCoord *string) {
	cond, truePart, falsePart, ok := parseIFArgs(formula)
	if !ok {
		// Malformed IF: advance to next row.
		*curCoord = nextRow(coord)
		return
	}

	// Evaluate the condition. First try a direct boolean literal check on the
	// raw condition string (before evalExpr, which can't fold bare TRUE/FALSE).
	condResult := boolLiteral(cond)
	if condResult == "" {
		// Not a bare literal: try evalExpr (handles cell refs and functions).
		condResult = strings.ToUpper(strings.TrimSpace(evalExpr(m, sheetName, cond, nil)))
		// Retry bare boolean check on the evaluated result.
		if condResult == "" {
			condResult = boolLiteral(cond)
		}
	}

	// Resolve the branch targets. They can be plain coords or sheet!coord.
	trueSheet, trueCoord := resolveBranchTarget(truePart, sheetName)
	falseSheet, falseCoord := resolveBranchTarget(falsePart, sheetName)

	switch condResult {
	case "TRUE", "1":
		if trueCoord != "" {
			*curSheet = trueSheet
			*curCoord = trueCoord
		} else {
			*curCoord = nextRow(coord)
		}

	case "FALSE", "0":
		if falseCoord != "" {
			*curSheet = falseSheet
			*curCoord = falseCoord
		} else {
			*curCoord = nextRow(coord)
		}

	default:
		// Unknown condition: fork. Push false branch to queue, follow true branch.
		if falseCoord != "" && len(m.forkQueue) < maxEmulBranchStack {
			m.forkQueue = append(m.forkQueue, forkFrame{
				sheet:  falseSheet,
				coord:  falseCoord,
				sheets: cowSheetsSnapshot(m.sheets),
				names:  maps.Clone(m.names),
				steps:  m.steps,
			})
			m.ifForksPushed++
		}
		if trueCoord != "" {
			*curSheet = trueSheet
			*curCoord = trueCoord
		} else {
			*curCoord = nextRow(coord)
		}
	}
}

// resolveBranchTarget parses a branch target which may be "Sheet!A1", "A1",
// or any other expression. Returns (sheet, coord); sheet defaults to
// defaultSheet when no "!" is present. Returns (defaultSheet, "") when the
// target cannot be parsed as a cell reference.
func resolveBranchTarget(target, defaultSheet string) (sheet, coord string) {
	if target == "" {
		return defaultSheet, ""
	}
	if bang := strings.Index(target, "!"); bang >= 0 {
		sh := strings.TrimSpace(target[:bang])
		c := normCoord(strings.TrimSpace(target[bang+1:]))
		if c == "" {
			return defaultSheet, ""
		}
		return sh, c
	}
	c := normCoord(target)
	if c == "" {
		return defaultSheet, ""
	}
	return defaultSheet, c
}

// handleWHILE processes a WHILE(cond) formula.
// - Evaluates cond. If "FALSE"/falsy: scan forward past the matching NEXT and
//   set PC there.
// - If "TRUE"/unknown: push current coord onto m.whileStack and advance PC to
//   next row (enter loop body).
//
// curSheet and curCoord are updated in-place.
func (m *xlmMachine) handleWHILE(formula, sheetName, coord string, curSheet, curCoord *string) {
	// Extract raw condition expression from WHILE(cond).
	condStr := extractRawArg(formula, "WHILE")

	var condResult string
	if condStr != "" {
		// Try bare boolean literal first (evalExpr can't fold bare TRUE/FALSE).
		condResult = boolLiteral(condStr)
		if condResult == "" {
			condResult = strings.ToUpper(strings.TrimSpace(evalExpr(m, sheetName, condStr, nil)))
		}
	}

	switch condResult {
	case "FALSE", "0":
		// Skip to past the matching NEXT.
		next := m.findMatchingNext(sheetName, coord)
		*curCoord = next

	default:
		// TRUE or unknown: enter loop body.
		if len(m.whileStack) < maxEmulWhileUnroll {
			m.whileStack = append(m.whileStack, sheetName+"!"+coord)
		}
		next := nextRow(coord)
		if next == "" {
			return
		}
		*curSheet = sheetName
		*curCoord = next
	}
}

// extractRawArg extracts the raw inner text of a single-argument call like
// "=WHILE(expr)" without normalising it as a coord. Returns "" on failure.
func extractRawArg(formula, verb string) string {
	s := formula
	if len(s) > 0 && s[0] == '=' {
		s = s[1:]
	}
	upper := strings.ToUpper(s)
	prefix := strings.ToUpper(verb) + "("
	idx := strings.Index(upper, prefix)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(prefix):]
	// Find matching close paren.
	depth := 1
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return strings.TrimSpace(rest[:i])
			}
		}
	}
	return ""
}

// findMatchingNext searches forward from coord in sheetName for the cell
// immediately after the NEXT() that closes the current WHILE. It respects
// nested WHILE/NEXT pairs. Returns nextRow(coord) if nothing is found
// (safe fallback: advance past WHILE).
func (m *xlmMachine) findMatchingNext(sheetName, whileCoord string) string {
	sh, ok := m.sheets[sheetName]
	if !ok {
		return nextRow(whileCoord)
	}

	current := nextRow(whileCoord)
	depth := 1 // we are inside one WHILE
	for i := 0; i < maxEmulSteps && current != ""; i++ {
		cell := sh.cells[current]
		if cell == nil {
			break
		}
		f := strings.ToUpper(cell.formula)
		switch {
		case strings.Contains(f, "WHILE("):
			depth++
		case strings.Contains(f, "NEXT(") || strings.TrimSpace(strings.TrimPrefix(f, "=")) == "NEXT":
			depth--
			if depth == 0 {
				// Return the row after this NEXT.
				after := nextRow(current)
				if after == "" {
					return current
				}
				return after
			}
		}
		current = nextRow(current)
	}
	return nextRow(whileCoord)
}

// handleNEXT processes a NEXT() formula (closes a WHILE loop body).
// - If whileStack is non-empty: pop the WHILE address, check unroll counter.
//   If unroll count for this WHILE < maxEmulWhileUnroll, jump back to WHILE.
//   Otherwise advance past NEXT.
// - If whileStack is empty: advance to next row (standalone NEXT, no loop).
//
// curSheet and curCoord are updated in-place.
func (m *xlmMachine) handleNEXT(curSheet, curCoord *string) {
	if len(m.whileStack) == 0 {
		// Standalone NEXT with no matching WHILE: advance.
		*curCoord = nextRow(*curCoord)
		return
	}

	// Pop the innermost WHILE address.
	top := m.whileStack[len(m.whileStack)-1]
	m.whileStack = m.whileStack[:len(m.whileStack)-1]

	// Parse "sheet!coord" from the saved frame.
	whileSheet, whileCoord := *curSheet, top
	if bang := strings.Index(top, "!"); bang >= 0 {
		whileSheet = top[:bang]
		whileCoord = top[bang+1:]
	}

	// Count how many times we have visited this WHILE.
	visitKey := whileSheet + "!" + whileCoord
	// We reuse m.visited for tracking — but that could trip the revisit fuse.
	// Instead, track WHILE back-jumps separately via a dedicated check on steps.
	// We use a simpler approach: re-push the WHILE coord and keep going if
	// the revisit count is still under the while-unroll cap (not the revisit fuse).
	currentVisit := m.visited[visitKey]
	if currentVisit < maxEmulWhileUnroll {
		// Jump back to WHILE.
		*curSheet = whileSheet
		*curCoord = whileCoord
		// Re-push so the next NEXT can see it.
		m.whileStack = append(m.whileStack, top)
	} else {
		// Cap hit: advance past NEXT.
		*curCoord = nextRow(*curCoord)
	}
}

// handleFORCELL processes a FOR.CELL(...) formula.
// Cap at maxEmulWhileUnroll (16) iterations. When the cap is reached, skip
// the FOR.CELL cell (advance PC). Otherwise increment forCellCount and
// advance to next row.
func (m *xlmMachine) handleFORCELL(curCoord *string) {
	if m.forCellCount >= maxEmulWhileUnroll {
		// Skip: advance past FOR.CELL.
		*curCoord = nextRow(*curCoord)
		return
	}
	m.forCellCount++
	*curCoord = nextRow(*curCoord)
}

// handleSetName processes SET.NAME(name,value) and DEFINE.NAME(name,refers_to).
// Stores the (name→value) pair in m.names. No-op on parse failure.
func (m *xlmMachine) handleSetName(formula, sheetName string) {
	name, value, ok := parseNameArg(formula)
	if !ok {
		return
	}
	// Resolve value if it contains a cell reference.
	if value != "" {
		resolved := evalExpr(m, sheetName, value, nil)
		if resolved != "" {
			value = resolved
		}
	}
	m.names[name] = value
}

// handleSetValue processes SET.VALUE(coord, expr): evaluates expr and stores
// the result in the target cell's value field so that subsequent cells that
// reference coord (e.g. =EXEC(A2)) can resolve it via getCellValue.
// Uses the same reSetValue regex as the interpreter. No-op on parse failure.
func (m *xlmMachine) handleSetValue(formula, sheetName string) {
	matches := reSetValue.FindStringSubmatch(formula)
	if matches == nil {
		return
	}
	targetCoord := normCoord(matches[1])
	if targetCoord == "" {
		return
	}
	valExpr := strings.TrimSpace(matches[2])
	// Evaluate the value expression (fold + resolve refs).
	resolved := evalExpr(m, sheetName, valExpr, nil)
	if resolved == "" {
		// Fallback: strip outer quotes from a bare string literal.
		resolved = stripOuterQuotes(valExpr)
	}
	// Store/update the cell with the computed value.
	// Preserve any existing formula; only overwrite the value field.
	sh, ok := m.sheets[sheetName]
	if ok {
		if cell, exists := sh.cells[targetCoord]; exists {
			cell.value = resolved
			return
		}
	}
	// Cell doesn't exist yet: create it with an empty formula and the resolved value.
	m.setCell(sheetName, targetCoord, "", resolved)
}
