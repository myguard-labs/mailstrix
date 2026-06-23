package extract

import (
	"strings"
	"testing"
	"time"
)

func TestIsFormulaInjectionDDE(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"=cmd|'/c calc.exe'!A1", true},
		{"@SUM(1+1)*cmd|'/c calc'!A0", true},
		{"+cmd|'/c calc'!A1", true},
		{"-2+3+cmd|'/c calc'!D2", true},
		{"=MSEXCEL|'\\..\\..\\x'!A1", true},
		{"=SUM(A1:A9)", false},      // formula, no DDE form
		{"=cmd!A1", false},          // no pipe
		{"=|'/c calc'!A1", false},   // empty app token before pipe
		{"cmd|'/c calc'!A1", false}, // no formula trigger
		{"plain text", false},
		{"", false},
		// quote-aware: pipe/bang inside a quoted literal are NOT the DDE form.
		{`=HYPERLINK("x|y!")`, false},
		{`="a | b !"`, false},
		{`="not DDE | !"`, false},
		// real form with the '!A1' tail after the closing quote still matches.
		{"=MSEXCEL|'\\..\\x'!A1", true},
	}
	for _, c := range cases {
		if got := isFormulaInjectionDDE(c.in); got != c.want {
			t.Errorf("isFormulaInjectionDDE(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormCSVCell(t *testing.T) {
	if got := string(normCSVCell([]byte(`  "=cmd|'/c calc'!A1"  `))); got != `=cmd|'/c calc'!A1` {
		t.Errorf("quote/space strip: got %q", got)
	}
	if got := string(normCSVCell([]byte(`"=a""b"`))); got != `=a"b` {
		t.Errorf("doubled-quote unescape: got %q", got)
	}
	if got := string(normCSVCell([]byte("=plain"))); got != "=plain" {
		t.Errorf("unquoted passthrough: got %q", got)
	}
}

func TestFromCSVDDE_CommaAndTab(t *testing.T) {
	for _, doc := range []string{
		"a,b,=cmd|'/c calc.exe'!A1,d\n",
		"a\tb\t=cmd|'/c calc.exe'!A1\td\n",
		"\"=cmd|'/c calc.exe'!A1\"\n", // quoted cell
	} {
		var res Result
		fromCSVDDE([]byte(doc), &res, time.Time{})
		var saw bool
		for _, s := range res.Streams {
			if strings.HasPrefix(string(s), "CSV-DDE ") && strings.Contains(string(s), "calc.exe") {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("CSV-DDE not emitted for %q; streams=%q", doc, res.Streams)
		}
	}
}

func TestFromCSVDDE_CommaPreferredOverTab(t *testing.T) {
	// A comma-CSV row whose quoted field contains a tab must still split on comma,
	// so the DDE cell is found (regression for the tab-if-any-tab evasion).
	doc := "\"a\tb\",y,=cmd|'/c calc.exe'!A1\n"
	var res Result
	fromCSVDDE([]byte(doc), &res, time.Time{})
	var saw bool
	for _, s := range res.Streams {
		if strings.HasPrefix(string(s), "CSV-DDE ") && strings.Contains(string(s), "calc.exe") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("comma-preferred split missed DDE cell; streams=%q", res.Streams)
	}
}

func TestFromCSVDDE_BenignNoMarker(t *testing.T) {
	doc := "name,total,formula\nfoo,3,=SUM(A1:A9)\nbar,4,plain\n" +
		"baz,5,\"=HYPERLINK(\"\"http://x|y!\"\")\"\n"
	var res Result
	fromCSVDDE([]byte(doc), &res, time.Time{})
	for _, s := range res.Streams {
		if strings.HasPrefix(string(s), "CSV-DDE ") {
			t.Fatalf("benign CSV produced a CSV-DDE marker: %q", s)
		}
	}
}

// TestFromCSVDDE_GuardSkip exercises the buffer-level fast-path guard: a DDE
// match requires both '|' and '!' in the buffer, so a buffer that has formula
// triggers ('=' cells) but lacks either char must early-return with no markers.
// This is the common benign case the guard short-circuits.
func TestFromCSVDDE_GuardSkip(t *testing.T) {
	cases := []string{
		"name,total\nfoo,=SUM(A1:A9)\nbar,=A1+B2\n", // triggers, no '|' and no '!'
		"=cmd '/c calc'A1\n",                        // trigger + no '|', no '!'
		"=cmd|'/c calc'A1\n",                        // has '|' but no '!' → guard skips
		"=cmd '/c calc'!A1\n",                       // has '!' but no '|' → guard skips
		"plain text, nothing here at all\n",         // no trigger, no '|', no '!'
	}
	for _, doc := range cases {
		var res Result
		fromCSVDDE([]byte(doc), &res, time.Time{})
		for _, s := range res.Streams {
			if strings.HasPrefix(string(s), "CSV-DDE ") {
				t.Fatalf("guard should skip %q but emitted %q", doc, s)
			}
		}
	}
	// Sanity: a buffer that DOES carry both '|' and '!' in a real DDE cell still
	// passes the guard and emits (guard must not over-reject).
	var res Result
	fromCSVDDE([]byte("a,=cmd|'/c calc.exe'!A1\n"), &res, time.Time{})
	saw := false
	for _, s := range res.Streams {
		if strings.HasPrefix(string(s), "CSV-DDE ") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("guard over-rejected a real DDE cell; streams=%q", res.Streams)
	}
}

func TestFromCSVDDE_MarkerCapBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxCSVDDEMarkers+50; i++ {
		b.WriteString("=cmd|'/c calc'!A1\n")
	}
	var res Result
	fromCSVDDE([]byte(b.String()), &res, time.Time{})
	if got := countCSVDDE(res.Streams); got > maxCSVDDEMarkers {
		t.Fatalf("marker cap not enforced: got %d > %d", got, maxCSVDDEMarkers)
	}
}

func TestIsSpreadsheetML(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`<?xml version="1.0"?>` + "\n" + `<?mso-application progid="Excel.Sheet"?>`, true},
		{`<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet">`, true},
		{`<html><body>hi</body></html>`, false},
		{"ID;PWXL;N;E\n", false},
		{"a,b,c\n", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isSpreadsheetML([]byte(c.in)); got != c.want {
			t.Errorf("isSpreadsheetML(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestFromSpreadsheetML_FormulaAttrAndData(t *testing.T) {
	doc := `<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet">
 <Worksheet ss:Name="S1"><Table>
  <Row><Cell ss:Formula="=cmd|'/c calc.exe'!A1"><Data ss:Type="String">x</Data></Cell></Row>
  <Row><Cell><Data ss:Type="String">=mshta|'/c evil'!A2</Data></Cell></Row>
 </Table></Worksheet>
</Workbook>`
	var res Result
	fromSpreadsheetML([]byte(doc), &res, time.Time{})
	if !res.IsDoc {
		t.Fatal("IsDoc not set")
	}
	var sawAttr, sawData bool
	for _, s := range res.Streams {
		str := string(s)
		if strings.HasPrefix(str, "CSV-DDE ") && strings.Contains(str, "calc.exe") {
			sawAttr = true
		}
		if strings.HasPrefix(str, "CSV-DDE ") && strings.Contains(str, "evil") {
			sawData = true
		}
	}
	if !sawAttr {
		t.Fatalf("ss:Formula DDE not surfaced; streams=%q", res.Streams)
	}
	if !sawData {
		t.Fatalf("<Data> DDE not surfaced; streams=%q", res.Streams)
	}
}

func TestFromSpreadsheetML_EntityEncodedFormula(t *testing.T) {
	// =cmd|'/c calc'!A1 with =, | entity-encoded.
	doc := `<?mso-application progid="Excel.Sheet"?>` +
		`<Cell ss:Formula="&#61;cmd&#124;'/c calc.exe'!A1"/>`
	var res Result
	fromSpreadsheetML([]byte(doc), &res, time.Time{})
	var saw bool
	for _, s := range res.Streams {
		if strings.HasPrefix(string(s), "CSV-DDE ") && strings.Contains(string(s), "calc.exe") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("entity-encoded DDE not surfaced; streams=%q", res.Streams)
	}
}

func TestFromSpreadsheetML_SpacedFormulaAttr(t *testing.T) {
	// CSV-DDE-FORMULA-WS: whitespace around the '=' must still match.
	cases := []string{
		`<Cell ss:Formula = "=cmd|'/c calc.exe'!A1"/>`,
		`<Cell ss:Formula ='=cmd|/c calc.exe!A1'/>`,
		`<Cell ss:Formula	=	"=cmd|'/c calc.exe'!A1"/>`,
	}
	for _, doc := range cases {
		var res Result
		fromSpreadsheetML([]byte(doc), &res, time.Time{})
		var saw bool
		for _, s := range res.Streams {
			if strings.HasPrefix(string(s), "CSV-DDE ") && strings.Contains(string(s), "calc.exe") {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("spaced ss:Formula DDE not surfaced for %q; streams=%q", doc, res.Streams)
		}
	}
}

func TestFromSpreadsheetML_FormulaSubstringNoEquals(t *testing.T) {
	// "Formula" appearing without a following '=' (e.g. attr name FormulaR1C1
	// used as a value, or a stray token) must not crash or false-match.
	doc := `<Cell ss:FormulaName="harmless"/><Note>Formula notes here</Note>`
	var res Result
	fromSpreadsheetML([]byte(doc), &res, time.Time{})
	for _, s := range res.Streams {
		if strings.HasPrefix(string(s), "CSV-DDE ") {
			t.Fatalf("unexpected CSV-DDE marker from non-formula text; streams=%q", res.Streams)
		}
	}
}

func TestExtract_CSVDDEDispatch(t *testing.T) {
	doc := "id,payload\n1,=cmd|'/c calc.exe'!A1\n"
	res := Extract([]byte(doc), time.Time{})
	var saw bool
	for _, s := range res.Streams {
		if strings.Contains(string(s), "CSV-DDE ") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("CSV-DDE not dispatched via Extract; streams=%q", res.Streams)
	}
}

func TestExtract_SpreadsheetMLDispatch(t *testing.T) {
	doc := `<?mso-application progid="Excel.Sheet"?>` +
		`<Cell ss:Formula="=cmd|'/c calc.exe'!A1"/>`
	res := Extract([]byte(doc), time.Time{})
	if !res.IsDoc {
		t.Fatal("SpreadsheetML not dispatched: IsDoc=false")
	}
	var saw bool
	for _, s := range res.Streams {
		if strings.Contains(string(s), "CSV-DDE ") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("CSV-DDE not surfaced; streams=%q", res.Streams)
	}
}
