package extract

// xlm_emul_pc.go — bounded PC execution loop for the XLM emulator (Wave D, D4).
//
// Implements (m).run(sheetName, startCoord): a step-limited program-counter
// loop that handles GOTO/RUN/HALT/RETURN control flow. Offline only — not
// wired to the live extraction path until D6.
//
// Fuses enforced here:
//
//	m.steps >= maxEmulSteps   → stop (too many PC advances)
//	m.visited[addr] > maxEmulRevisit → stop (tight loop)
//	len(m.branchStack) >= maxEmulBranchStack → stop (call-stack overflow)
//	expired(m.deadline)       → stop (wall-clock deadline)

import (
	"strconv"
	"strings"
)

// nextRow increments the numeric row part of an A1 coordinate by one.
// "A1" → "A2", "ZZ9999998" → "ZZ9999999". Returns "" on parse failure or
// when the resulting row number would exceed 9999999.
func nextRow(coord string) string {
	if coord == "" {
		return ""
	}
	// Find where the column letters end and the row digits begin.
	i := 0
	for i < len(coord) && coord[i] >= 'A' && coord[i] <= 'Z' {
		i++
	}
	if i == 0 || i == len(coord) {
		return ""
	}
	col := coord[:i]
	rowStr := coord[i:]
	row, err := strconv.Atoi(rowStr)
	if err != nil || row < 1 {
		return ""
	}
	row++
	if row > 9999999 {
		return ""
	}
	return col + strconv.Itoa(row)
}

// parseControlFlowArg extracts the single argument from a control-flow call
// such as GOTO(A3), GOTO(Sheet1!A3), RUN(B1), etc.
//
// It strips a leading "=" if present, locates "verb(" case-insensitively,
// extracts the inner argument up to the matching ")", and splits on "!" to
// detect an optional sheet prefix. The coord part is normalised via normCoord.
//
// Returns ("", "", false) on any parse failure.
func parseControlFlowArg(verb, formula string) (sheet, coord string, ok bool) {
	s := formula
	// Strip optional leading "=".
	if len(s) > 0 && s[0] == '=' {
		s = s[1:]
	}

	upper := strings.ToUpper(s)
	verbUpper := strings.ToUpper(verb)

	// Find the verb followed immediately by "(".
	prefix := verbUpper + "("
	idx := strings.Index(upper, prefix)
	if idx < 0 {
		return "", "", false
	}
	// The argument starts right after "verb(";
	argStart := idx + len(prefix)
	// Find the closing ")".
	argEnd := strings.Index(s[argStart:], ")")
	if argEnd < 0 {
		return "", "", false
	}
	arg := strings.TrimSpace(s[argStart : argStart+argEnd])
	if arg == "" {
		return "", "", false
	}

	// Split on "!" to extract optional sheet name.
	if bang := strings.Index(arg, "!"); bang >= 0 {
		sheetPart := arg[:bang]
		coordPart := normCoord(arg[bang+1:])
		if coordPart == "" {
			return "", "", false
		}
		return sheetPart, coordPart, true
	}

	// No sheet prefix — normalise as coord.
	nc := normCoord(arg)
	if nc == "" {
		return "", "", false
	}
	return "", nc, true
}

// controlVerb detects a bare control-flow verb in a formula (case-insensitive).
// Returns the verb in uppercase if found, or "" if the formula is not a
// bare control-flow statement.
//
// Recognised bare forms (no arguments): HALT, HALT(), RETURN, RETURN().
// These are matched after stripping a leading "=".
func controlVerb(formula string) string {
	s := formula
	if len(s) > 0 && s[0] == '=' {
		s = s[1:]
	}
	upper := strings.ToUpper(strings.TrimSpace(s))
	for _, v := range []string{"HALT", "RETURN"} {
		if upper == v || upper == v+"()" {
			return v
		}
	}
	return ""
}

// hasControlVerb reports whether formula contains a call to verb (case-insensitive),
// e.g. "GOTO(" or "RUN(". Used to classify the control-flow type before
// extracting the argument.
func hasControlVerb(formula, verb string) bool {
	s := formula
	if len(s) > 0 && s[0] == '=' {
		s = s[1:]
	}
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(verb)+"(")
}

// run executes the bounded PC loop starting at (sheetName, startCoord).
//
// The loop emits folded formula results for non-control-flow cells and
// advances the PC row-by-row. HALT/RETURN stop execution; GOTO/RUN update
// the PC; fuses terminate runaway sequences.
func (m *xlmMachine) run(sheetName, startCoord string) {
	currentSheet := sheetName
	currentCoord := normCoord(startCoord)
	if currentCoord == "" {
		return
	}

	for {
		// Deadline fuse.
		if expired(m.deadline) {
			return
		}
		// Step fuse.
		if m.steps >= maxEmulSteps {
			return
		}

		addr := currentSheet + "!" + currentCoord

		// Revisit fuse.
		m.visited[addr]++
		if m.visited[addr] > maxEmulRevisit {
			return
		}

		m.steps++

		// Look up the current cell.
		sh, ok := m.sheets[currentSheet]
		if !ok {
			return
		}
		cell := sh.cells[currentCoord]
		if cell == nil {
			return
		}

		formula := cell.formula

		// Dispatch on control-flow verb.
		switch {
		case formula == "" ||
			(!hasControlVerb(formula, "GOTO") &&
				!hasControlVerb(formula, "RUN") &&
				controlVerb(formula) == ""):
			// Not a control-flow statement: eval and emit, then advance.
			if formula != "" {
				if s := evalExpr(m, currentSheet, formula, nil); s != "" {
					if !emitFoldedFormula(s, m.out, m.totalOutput, true) {
						return // output cap reached
					}
				}
			}
			next := nextRow(currentCoord)
			if next == "" {
				return
			}
			currentCoord = next

		case controlVerb(formula) == "HALT":
			return

		case controlVerb(formula) == "RETURN":
			if len(m.branchStack) == 0 {
				return
			}
			frame := m.branchStack[len(m.branchStack)-1]
			m.branchStack = m.branchStack[:len(m.branchStack)-1]
			currentSheet = frame.returnSheet
			currentCoord = frame.returnAddr

		case hasControlVerb(formula, "GOTO"):
			targetSheet, targetCoord, ok := parseControlFlowArg("GOTO", formula)
			if !ok || targetCoord == "" {
				return
			}
			if targetSheet == "" {
				targetSheet = currentSheet
			}
			currentSheet = targetSheet
			currentCoord = targetCoord

		case hasControlVerb(formula, "RUN"):
			if len(m.branchStack) >= maxEmulBranchStack {
				return
			}
			targetSheet, targetCoord, ok := parseControlFlowArg("RUN", formula)
			if !ok || targetCoord == "" {
				return
			}
			if targetSheet == "" {
				targetSheet = currentSheet
			}
			// Push return frame: resume at the NEXT row after the RUN cell.
			returnCoord := nextRow(currentCoord)
			if returnCoord == "" {
				return
			}
			m.branchStack = append(m.branchStack, branchFrame{
				returnSheet: currentSheet,
				returnAddr:  returnCoord,
			})
			currentSheet = targetSheet
			currentCoord = targetCoord

		default:
			// Unknown formula pattern — treat as non-control, emit and advance.
			if s := evalExpr(m, currentSheet, formula, nil); s != "" {
				if !emitFoldedFormula(s, m.out, m.totalOutput, true) {
					return
				}
			}
			next := nextRow(currentCoord)
			if next == "" {
				return
			}
			currentCoord = next
		}
	}
}
