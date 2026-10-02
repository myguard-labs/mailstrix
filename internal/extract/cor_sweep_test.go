package extract

import (
	"bytes"
	"testing"
	"time"
)

// foldAll collects everything foldVBAStrings emits for src.
func foldAll(src string) []byte {
	var out bytes.Buffer
	foldVBAStrings([]byte(src), time.Time{}, func(b []byte) bool {
		out.Write(b)
		out.WriteByte('\n')
		return true
	})
	return out.Bytes()
}

// TestFoldChrVariants (COR-11): Chr$, ChrW$, ChrB and "Chr (" fold like Chr.
func TestFoldChrVariants(t *testing.T) {
	for _, src := range []string{
		`x = Chr(112) & Chr(111) & Chr(119) & "ershell"`, // positive baseline
		`x = Chr$(112) & Chr$(111) & Chr$(119) & "ershell"`,
		`x = ChrW$(112) & ChrW$(111) & ChrW$(119) & "ershell"`,
		`x = ChrB(112) & ChrB(111) & ChrB(119) & "ershell"`,
		`x = Chr (112) & chr$ (111) & CHRW(119) & "ershell"`, // spacing and case boundary
	} {
		if got := foldAll(src); !bytes.Contains(got, []byte("powershell")) {
			t.Errorf("%s: folded %q, want powershell", src, got)
		}
	}
}

// TestFoldChrRejectsLookalikes: other calls named like Chr are not folded
// (negative), and malformed calls do not panic or fold.
func TestFoldChrRejectsLookalikes(t *testing.T) {
	for _, src := range []string{
		`x = ChrX(112) & ChrX(111) & ChrX(119) & "ershell"`,
		`x = Chr$$(112) & Chr$$(111) & "ershell"`,
		`x = Chr(112 & Chr(`,
	} {
		if got := foldAll(src); bytes.Contains(got, []byte("powershell")) {
			t.Errorf("%s: unexpectedly folded %q", src, got)
		}
	}
}

// TestStripEchoPrefixDelimiters (COR-10): every cmd.exe echo delimiter yields
// the text after it; bare forms yield an empty line; other words are rejected.
func TestStripEchoPrefixDelimiters(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"echo hello", "hello", true},
		{"ECHO.hello", "hello", true},
		{"echo(hello", "hello", true},
		{"echo:hello", "hello", true},
		{"echo\thello", "hello", true},
		{"echo;hello", "hello", true},
		{"echo,hello", "hello", true},
		{"echo=hello", "hello", true},
		{"echo/hello", "hello", true},
		{"echo+hello", "hello", true},
		{"echo[hello", "hello", true},
		{"echo]hello", "hello", true},
		{"echo.", "", true}, // boundary: blank-line idiom
		{"echo", "", true},  // boundary: bare echo
		{"echo ", "", true},
		{"echoed text", "", false}, // negative: different command word
		{"ech", "", false},         // malformed: too short
		{"", "", false},
		{"set x=1", "", false},
	}
	for _, tc := range cases {
		got, ok := stripEchoPrefix([]byte(tc.in))
		if ok != tc.ok || string(got) != tc.want {
			t.Errorf("stripEchoPrefix(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
