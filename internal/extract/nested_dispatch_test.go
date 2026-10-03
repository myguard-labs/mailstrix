package extract

import (
	"strings"
	"testing"
	"time"
)

func anyStreamHas(res Result, prefix, sub string) bool {
	for _, set := range [][][]byte{res.Streams, res.Markers} {
		for _, s := range set {
			if strings.HasPrefix(string(s), prefix) && strings.Contains(string(s), sub) {
				return true
			}
		}
	}
	return false
}

// TestNestedSLKAndCSVAndSpreadsheetML (COR-09): SLK, SpreadsheetML and CSV
// DDE carriers inside a zip get the same markers as at top level.
func TestNestedSLKAndCSVAndSpreadsheetML(t *testing.T) {
	slk := "ID;PWXL;N;E\r\nC;Y1;X1;E=EXEC(CHAR(99)&CHAR(97)&CHAR(108)&CHAR(99))\r\nE\r\n"
	csv := "a,b,=cmd|'/c calc.exe'!A1,d\n"
	xml := `<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"><Worksheet><Table>
<Row><Cell ss:Formula="=cmd|'/c mshta.exe'!A1"><Data ss:Type="String">x</Data></Cell></Row>
</Table></Worksheet></Workbook>`
	for name, c := range map[string]struct {
		member, body, prefix, sub string
	}{
		"slk": {"a.slk", slk, "XLM-DANGEROUS-FUNC", "EXEC"},
		"csv": {"a.csv", csv, "CSV-DDE ", "calc.exe"},
		"xml": {"a.xml", xml, "CSV-DDE ", "mshta.exe"},
	} {
		top := Extract([]byte(c.body), time.Time{})
		if !anyStreamHas(top, c.prefix, c.sub) {
			t.Fatalf("%s: top-level control lost the marker", name)
		}
		res := Extract(zipOfMembers(t, []string{c.member}, [][]byte{[]byte(c.body)}), time.Time{})
		if !anyStreamHas(res, c.prefix, c.sub) {
			t.Errorf("%s: zipped carrier emitted no %q marker", name, c.prefix)
		}
	}
}

// TestNestedBenignTextNoDDE (negative control): an ordinary zipped text file
// gets no DDE or XLM marker.
func TestNestedBenignTextNoDDE(t *testing.T) {
	res := Extract(zipOfMembers(t, []string{"notes.csv"}, [][]byte{[]byte("name,total\nalice,=SUM(A1:A2)\n")}), time.Time{})
	if anyStreamHas(res, "CSV-DDE", "") || anyStreamHas(res, "XLM-DANGEROUS-FUNC", "") {
		t.Fatalf("benign member marked: %q %q", res.Streams, res.Markers)
	}
}
