package mailstrix

import (
	"reflect"
	"strings"
	"testing"
)

func TestFilenameTokensTable(t *testing.T) {
	t32 := strings.Repeat("a", 32)
	t33 := strings.Repeat("b", 33)
	cases := []struct {
		name string
		in   string
		want []string // nil means want a nil slice
	}{
		{"empty is nil", "", nil},
		{"extension dropped", "invoice.zip", []string{"invoice"}},
		{"only last dot is the extension", "a.tar.gz", []string{"tar"}},
		{"only last dot long", "report.final.zip", []string{"report", "final"}},
		{"leading dot keeps name", ".hidden", []string{"hidden"}},
		{"no extension", "invoice", []string{"invoice"}},
		{"space sep", "foo bar baz.zip", []string{"foo", "bar", "baz"}},
		{"underscore sep", "foo_bar.zip", []string{"foo", "bar"}},
		{"dash sep", "foo-bar.zip", []string{"foo", "bar"}},
		{"parens sep", "foo(bar)baz.zip", []string{"foo", "bar", "baz"}},
		{"brackets sep", "foo[bar]baz.zip", []string{"foo", "bar", "baz"}},
		{"password in name", "invoice_2024.zip", []string{"invoice", "2024"}},
		{"len 2 dropped", "ab_abc.zip", []string{"abc"}},
		{"len 3 kept", "abc.zip", []string{"abc"}},
		{"len 32 kept", t32 + ".zip", []string{t32}},
		{"len 33 dropped", t33 + "_ok123.zip", []string{"ok123"}},
		{"len 1 dropped", "a_b_c.zip", []string{}},
		{"cap at six", "aaa_bbb_ccc_ddd_eee_fff_ggg_hhh.zip", []string{"aaa", "bbb", "ccc", "ddd", "eee", "fff"}},
		{"exactly six", "aaa_bbb_ccc_ddd_eee_fff.zip", []string{"aaa", "bbb", "ccc", "ddd", "eee", "fff"}},
		{"cap counts only valid tokens", "a_b_aaa_bbb_ccc_ddd_eee_fff_ggg.zip", []string{"aaa", "bbb", "ccc", "ddd", "eee", "fff"}},
		// Lengths are byte lengths: "é" is 2 bytes, so "éa" is 3 bytes and kept,
		// while a single "é" is 2 bytes and dropped.
		{"multibyte 3 bytes kept", "éa.zip", []string{"éa"}},
		{"multibyte 2 bytes dropped", "é.zip", []string{}},
		{"multibyte 32 bytes kept", strings.Repeat("é", 16) + ".zip", []string{strings.Repeat("é", 16)}},
		{"multibyte 34 bytes dropped", strings.Repeat("é", 17) + ".zip", []string{}},
		{"only separators", "_-_ ()[].zip", []string{}},
		{"only separators no ext", "_- ()[]", []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := filenameTokens(c.in)
			if c.want == nil {
				if got != nil {
					t.Fatalf("filenameTokens(%q) = %#v, want nil", c.in, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("filenameTokens(%q) = nil, want non-nil %#v", c.in, c.want)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("filenameTokens(%q) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}

func TestFilenameTokensNeverExceedsCap(t *testing.T) {
	in := strings.Repeat("abc_", 500) + "x.zip"
	if got := filenameTokens(in); len(got) != maxFilenameTokens {
		t.Fatalf("len = %d, want %d", len(got), maxFilenameTokens)
	}
}
