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
//	whileDepth         back-jump unroll count
//	evaluating set     per-formula cycle break
//
// Plus inherited bounds: deadline (threaded), maxXLMFoldOutputLen (sink),
// getFormulaCell scan cap maxEmulFormulaCell, cells ≤ maxEmulCells.

import "time"

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
	sheets      map[string]*xlmSheet
	names       map[string]string // defined names → value
	branchStack []branchFrame     // GOTO/CALL return stack (D4)
	whileDepth  int               // bounded unroll counter (D5)
	visited     map[string]int    // "sheet!coord" → revisit count (fuse)
	steps       int               // PC advance counter (fuse)
	deadline    time.Time
	out         *[][]byte
	totalOutput *int
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

// emulateXLMCells is the adapter entry point for the bounded emulator (D6).
// Until D6 is wired, this is a passthrough to interpretXLMCells so that
// goldens remain byte-identical and no live behaviour changes.
func emulateXLMCells(cells []xlmCell, out *[][]byte, totalOutput *int, deadline time.Time) {
	// TODO(D6): replace body with emulator execution; keep interpretXLMCells
	// call only as the fallback / pre-pass.
	interpretXLMCells(cells, out, totalOutput, deadline)
}
