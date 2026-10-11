package extract

import "testing"

func TestHandleSetValueSupport(t *testing.T) {
	for _, tc := range []struct {
		name, sheet, formula, want string
		existing                   bool
	}{
		{"absent cell", "Sheet1", `=SET.VALUE($B$2,"created")`, "created", false},
		{"absent sheet", "NewSheet", `=SET.VALUE(B2,"new sheet")`, "new sheet", false},
		{"existing cell", "Sheet1", `=SET.VALUE(B2,"updated")`, "updated", true},
		{"resolved reference", "Sheet1", `=SET.VALUE(B2,A1)`, "source value", false},
		{"empty literal", "Sheet1", `=SET.VALUE(B2,"")`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newFlowTestMachine()
			m.setCell("Sheet1", "A1", "", "source value")
			if tc.existing {
				m.setCell(tc.sheet, "B2", "=CHAR(65)", "old")
			}
			m.handleSetValue(tc.formula, tc.sheet)
			sh := m.sheets[tc.sheet]
			if sh == nil {
				t.Fatal("SET.VALUE did not create sheet")
			}
			cell := sh.cells["B2"]
			if cell == nil {
				t.Fatal("SET.VALUE did not create cell")
			}
			if cell.value != tc.want {
				t.Fatalf("value=%q want=%q", cell.value, tc.want)
			}
			wantFormula := ""
			if tc.existing {
				wantFormula = "=CHAR(65)"
			}
			if cell.formula != wantFormula {
				t.Fatalf("formula=%q want=%q", cell.formula, wantFormula)
			}
			if m.sheets["Sheet1"].cells["A1"].value != "source value" {
				t.Fatal("source cell changed")
			}
		})
	}
	for _, formula := range []string{"", "=SET.VALUE(B2)", `=SET.VALUE(!,"bad")`, `=SET.VALUE(A-1,"bad")`, `=OTHER(B2,"bad")`} {
		t.Run("malformed "+formula, func(t *testing.T) {
			m := newFlowTestMachine()
			m.handleSetValue(formula, "Absent")
			if len(m.sheets) != 0 {
				t.Fatal("malformed SET.VALUE created sheet")
			}
		})
	}
}
