package mailstrix

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"github.com/myguard-labs/mailstrix/internal/extract"
)

// Scan the public extractor's individual streams with the shipped rules, as the
// scanner does. These cases distinguish field extraction from opaque raw text.
func TestLauncherRules(t *testing.T) {
	source, err := os.ReadFile("../../docker/local-rules/launcher_fields.yara")
	if err != nil {
		t.Fatal(err)
	}
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if err := c.AddString(string(source), ""); err != nil {
		t.Fatal(err)
	}
	rules, err := c.GetRules()
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	type ruleCase struct{ name, body, rule string }
	cases := []ruleCase{
		{"remote icon", "[InternetShortcut]\nIconFile=\\\\files.example\\icons\\a.ico", ""},
		{"encoded DeepLink", "<PCSettingsFile><DeepLink>power&#115;hell -enc QUFBQUFBQUFBQUFBQUFBQUFB</DeepLink></PCSettingsFile>", "SettingContent_DeepLink_EncodedPowerShell"},
		{"pwsh DeepLink", "<PCSettingsFile><DeepLink>pwsh -nop</DeepLink></PCSettingsFile>", "SettingContent_DeepLink_EncodedPowerShell"},
		{"benign URL", "[InternetShortcut]\nURL=https://example.com/", ""},
		{"executable URL alone", "[InternetShortcut]\nURL=https://example.com/app.exe", ""},
		{"local icon", "[InternetShortcut]\nIconFile=C:\\Windows\\icon.ico", ""},
		{"benign settings", "<PCSettingsFile><DeepLink>ms-settings:display</DeepLink></PCSettingsFile>", ""},
		{"plain PowerShell", "<PCSettingsFile><DeepLink>powershell Get-Date</DeepLink></PCSettingsFile>", ""},
		{"flags in other field", "<PCSettingsFile><DeepLink>powershell Get-Date</DeepLink><Icon>-nop</Icon></PCSettingsFile>", ""},
		{"comment only", "<PCSettingsFile><!-- <DeepLink>powershell -nop</DeepLink> --></PCSettingsFile>", ""},
	}
	for _, branch := range []struct{ name, arg string }{
		{"hidden-short", "-w hidden"},
		{"hidden-long", "-windowstyle hidden"},
		{"no-profile", "-nop"},
		{"bypass-short", "-ep bypass"},
		{"bypass-long", "-executionpolicy bypass"},
		{"base64-method", "FromBase64String"},
		{"download-method", "DownloadString"},
	} {
		cases = append(cases,
			ruleCase{branch.name, "<PCSettingsFile><DeepLink>powershell " + branch.arg + "</DeepLink></PCSettingsFile>", "SettingContent_DeepLink_EncodedPowerShell"},
			ruleCase{branch.name + "-other-field", "<PCSettingsFile><DeepLink>powershell Get-Date</DeepLink><Icon>" + branch.arg + "</Icon></PCSettingsFile>", ""},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var zipped bytes.Buffer
			w := zip.NewWriter(&zipped)
			member, err := w.Create("unrelated.bin")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := member.Write([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			for _, input := range [][]byte{[]byte(tc.body), zipped.Bytes()} {
				res := extract.Extract(input, time.Now().Add(time.Second))
				found := false
				for _, stream := range res.Streams {
					var matches yara.MatchRules
					if err := rules.ScanMem(stream, 0, time.Second, &matches); err != nil {
						t.Fatal(err)
					}
					for _, match := range matches {
						score50 := false
						for _, meta := range match.Metas {
							if meta.Identifier == "score" && meta.Value == "50" {
								score50 = true
							}
						}
						if !score50 {
							t.Fatal("DeepLink heuristic must retain score 50")
						}
						if match.Rule != tc.rule {
							t.Errorf("unexpected rule %s, want %q", match.Rule, tc.rule)
						}
						found = true
					}
				}
				if found != (tc.rule != "") {
					t.Fatalf("matched=%v, want rule %q", found, tc.rule)
				}
			}
		})
	}
}
