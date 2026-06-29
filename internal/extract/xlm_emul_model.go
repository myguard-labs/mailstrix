package extract

// xlm_emul_model.go — mutable grid model for the bounded XLM emulator (Wave D).
//
// Defines the core data structures and accessors used by the emulator. Nothing
// is wired to the live extraction path yet; interpretXLMCells remains the active
// entry point. The adapter emulateXLMCells is a passthrough stub for D6.
//
// Five runaway fuses (any trips → stop + emit partial, fail-open):
//
//	maxEmulSteps       PC advances
//	visited[addr]      revisits per cell
//	len(branchStack)   call-stack depth
//	whileStack depth   back-jump unroll count (via len(whileStack) < maxEmulWhileUnroll)
//	evaluating set     per-formula cycle break
//
// Plus inherited bounds: deadline (threaded), maxXLMFoldOutputLen (sink),
// getFormulaCell scan cap maxEmulFormulaCell, cells ≤ maxEmulCells.

import (
	"strings"
	"time"
)

// Emulator fuse constants.
const (
	maxEmulSteps       = 2000 // max PC advances before forced stop
	maxEmulRevisit     = 8    // max revisits of a single cell coord
	maxEmulBranchStack = 64   // max call/branch stack depth
	maxEmulWhileUnroll = 16   // max back-jump unrolls (WHILE loops)
	maxEmulCells       = 8192 // total cell cap across all sheets
	maxEmulFormulaCell = 1000 // getFormulaCell iteration cap
)

// branchFrame holds a return address for RUN/CALL return stack (wired in D4).
type branchFrame struct {
	returnSheet string // sheet to resume after RETURN
	returnAddr  string // coord to resume after RETURN
}

// emulCell is a single macrosheet cell in the emulator grid.
// It mirrors xlmCell but adds a sheet field so a cell is self-contained.
type emulCell struct {
	coord   string // normalised A1 coordinate (no $ signs)
	sheet   string // owning sheet name
	formula string // raw formula text (may be empty)
	value   string // current computed/stored value (may be empty)
}

// xlmSheet is one macrosheet's cell store within the emulator.
type xlmSheet struct {
	name  string
	cells map[string]*emulCell // keyed by normalised A1 coord
}

// xlmMachine is the full emulator state for one document.
type xlmMachine struct {
	sheets        map[string]*xlmSheet
	names         map[string]string // defined names → value
	branchStack   []branchFrame     // GOTO/CALL return stack (D4)
	forkQueue     []forkFrame       // D5: IF-branch COW fork frames to explore after main loop
	whileStack    []string          // D5: active WHILE cell addresses ("sheet!coord"), one per nesting level
	forCellCount  int               // D5: FOR.CELL iteration counter (capped at maxEmulWhileUnroll)
	visited       map[string]int    // "sheet!coord" → revisit count (fuse)
	steps         int               // PC advance counter (fuse)
	ifForksPushed int               // D8: counts how many IF not-taken forks were pushed to forkQueue
	deadline      time.Time
	out           *[][]byte
	totalOutput   *int
}

// newMachine creates an empty xlmMachine ready for cell population.
func newMachine(out *[][]byte, totalOutput *int, deadline time.Time) *xlmMachine {
	return &xlmMachine{
		sheets:      make(map[string]*xlmSheet),
		names:       make(map[string]string),
		visited:     make(map[string]int),
		deadline:    deadline,
		out:         out,
		totalOutput: totalOutput,
	}
}

// totalCells counts all cells stored across every sheet.
func (m *xlmMachine) totalCells() int {
	n := 0
	for _, sh := range m.sheets {
		n += len(sh.cells)
	}
	return n
}

// setCell stores or updates a cell in the named sheet.
// coord is normalised via normCoord; if normalisation fails the call is a no-op.
// If the total cell count across all sheets is already at maxEmulCells the call
// is a no-op (capacity fuse).
func (m *xlmMachine) setCell(sheetName, coord, formula, value string) {
	nc := normCoord(coord)
	if nc == "" {
		return
	}
	sh, ok := m.sheets[sheetName]
	if !ok {
		if m.totalCells() >= maxEmulCells {
			return
		}
		sh = &xlmSheet{
			name:  sheetName,
			cells: make(map[string]*emulCell),
		}
		m.sheets[sheetName] = sh
	}

	if _, exists := sh.cells[nc]; !exists {
		// New cell: enforce aggregate cap across all sheets before inserting.
		if m.totalCells() >= maxEmulCells {
			return
		}
	}
	// Updating an existing cell is always allowed (no cap check needed).

	sh.cells[nc] = &emulCell{
		coord:   nc,
		sheet:   sheetName,
		formula: formula,
		value:   value,
	}
}

// getCellValue returns the stored value for a cell and true when the cell
// exists and has a non-empty value. Returns ("", false) for missing sheets,
// missing cells, or cells with an empty value field.
// This is a pure lookup — it does not evaluate formulas.
func (m *xlmMachine) getCellValue(sheetName, coord string) (string, bool) {
	nc := normCoord(coord)
	if nc == "" {
		return "", false
	}
	sh, ok := m.sheets[sheetName]
	if !ok {
		return "", false
	}
	cell, ok := sh.cells[nc]
	if !ok || cell.value == "" {
		return "", false
	}
	return cell.value, true
}

// getFormulaCell returns the first cell in the named sheet that has a non-empty
// formula, scanning at most maxEmulFormulaCell entries. Returns nil when the
// sheet is absent or no formula cell is found within the cap.
// Used in D6 as the fallback entry point when no explicit start address is known.
func (m *xlmMachine) getFormulaCell(sheetName string) *emulCell {
	sh, ok := m.sheets[sheetName]
	if !ok {
		return nil
	}
	scanned := 0
	for _, cell := range sh.cells {
		if scanned >= maxEmulFormulaCell {
			break
		}
		scanned++
		if cell.formula != "" {
			return cell
		}
	}
	return nil
}

// emulDepthClass returns the depth classification of this emulator run.
// "branched" wins over "looped" (branched is higher signal).
func emulDepthClass(m *xlmMachine) string {
	for _, count := range m.visited {
		if count > 1 {
			if m.ifForksPushed > 0 {
				return "branched"
			}
			return "looped"
		}
	}
	if m.ifForksPushed > 0 {
		return "branched"
	}
	return "shallow"
}

// emulateXLMCells is the live entry point for the bounded XLM emulator (D6).
// It populates a machine from cells, finds the Auto_Open entry coordinate via
// a three-tier name lookup, runs the emulator, and falls back to
// interpretXLMCells when the emulator produces no output (defense-in-depth).
// A top-level recover ensures the emulator never panics into the extraction
// pipeline; any partial *out accumulated before the panic is preserved.
func emulateXLMCells(cells []xlmCell, out *[][]byte, totalOutput *int, deadline time.Time) {
	if len(cells) == 0 {
		return
	}
	if len(cells) > maxEmulCells {
		cells = cells[:maxEmulCells]
	}

	// Top-level recover — emulator must never panic live.
	defer func() {
		if r := recover(); r != nil {
			// Partial *out is already accumulated; just stop.
		}
	}()

	m := newMachine(out, totalOutput, deadline)

	// Populate grid from cells. Use a fixed sheet name; OOXML path does not
	// carry the workbook-level sheet name at this call site.
	const sheetName = "Sheet1"
	for _, c := range cells {
		m.setCell(sheetName, c.coord, c.formula, c.value)
	}

	// Find start cell via Auto_Open lookup (strict→prefix→fuzzy-subseq→fallback).
	startCoord := findAutoOpenCoord(m, sheetName, cells)

	// Remember output length before emulator run.
	priorLen := len(*out)

	m.run(sheetName, startCoord)

	// Capture the emulator blob count before emitting the depth marker, so the
	// fallback decision is based on real emulator output only (not the marker).
	emulatorLen := len(*out)

	// Emit depth class marker so YARA rules can correlate emulation depth with
	// dangerous-func co-occurrence (e.g. CALL + branched = high signal).
	depthMarker := "XLM-EMUL-DEPTH " + emulDepthClass(m)
	emitFoldedFormula(depthMarker, m.out, m.totalOutput, false)

	// Zero-output fallback: if the emulator produced no real output (depth
	// marker is not counted), fall back to the old interpreter for
	// defense-in-depth coverage.
	if emulatorLen <= priorLen {
		interpretXLMCells(cells, out, totalOutput, deadline)
	} else {
		emitEvaluatedXLMCells(cells, out, totalOutput, deadline)
	}
}

func emitEvaluatedXLMCells(cells []xlmCell, out *[][]byte, totalOutput *int, deadline time.Time) {
	if len(cells) == 0 || expired(deadline) {
		return
	}
	m := newMachine(out, totalOutput, deadline)
	const sheetName = "Sheet1"
	for _, c := range cells {
		m.setCell(sheetName, c.coord, c.formula, c.value)
	}
	seen := make(map[string]struct{}, len(*out))
	for _, s := range *out {
		seen[string(s)] = struct{}{}
	}
	for _, c := range cells {
		if expired(deadline) || len(*out) >= maxStreams {
			return
		}
		if c.formula == "" {
			continue
		}
		s := evalExpr(m, sheetName, c.formula, nil)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		before := len(*out)
		if !emitFoldedFormula(s, out, totalOutput, true) {
			return
		}
		if len(*out) > before {
			seen[s] = struct{}{}
		}
	}
}

// findAutoOpenCoord finds the XLM entry-point coordinate using a three-tier lookup:
//  1. Strict:       m.names["AUTO_OPEN"] or m.names["Auto_Open"] exact match
//  2. Prefix:       any m.names key whose upper-case form starts with "AUTO_OPEN"
//  3. Fuzzy-subseq: any m.names key containing "AUTO" and "OPEN" (in that order)
//  4. Fallback:     getFormulaCell(sheetName) — first formula cell in sheet
//
// Returns the coord string (normalised) or "A1" when all lookups fail.
// For OOXML documents the workbook-level defined names are not parsed at this
// call site, so m.names is typically empty; the full lookup is implemented for
// correctness when SET.NAME/DEFINE.NAME cells have already populated m.names.
func findAutoOpenCoord(m *xlmMachine, sheetName string, _ []xlmCell) string {
	// Tier 1: strict exact match (case-insensitive on the canonical spellings).
	for _, key := range []string{"Auto_Open", "AUTO_OPEN", "auto_open"} {
		if v, ok := m.names[key]; ok && v != "" {
			return v
		}
	}

	// Tier 2: prefix — any name whose upper-case form starts with "AUTO_OPEN".
	for k, v := range m.names {
		if len(k) >= 9 && strings.ToUpper(k[:9]) == "AUTO_OPEN" && v != "" {
			return v
		}
	}

	// Tier 3: fuzzy subsequence — key contains both "AUTO" and "OPEN"
	// (the "AUTO" substring must appear before "OPEN").
	for k, v := range m.names {
		up := strings.ToUpper(k)
		ai := strings.Index(up, "AUTO")
		oi := strings.Index(up, "OPEN")
		if ai >= 0 && oi > ai && v != "" {
			return v
		}
	}

	// Tier 4: fallback — first formula cell in the sheet.
	cell := m.getFormulaCell(sheetName)
	if cell != nil {
		return cell.coord
	}
	return "A1"
}
