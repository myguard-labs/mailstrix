package extract

import (
	"bytes"
	"os"
	"testing"
)

// script_downloaders.yara ships tiny-stub downloader/executor heuristics: the
// original four (ten live MalwareBazaar .ps1/.vbs 0-hit misses, 55-152 byte
// first-stage stubs) plus the s31 second batch of four single-family ASCII
// PS/VBS misses (2c41d4f8 / 9f0a17d4 / 3ae711ab / f6438c51). yarad's unit suite
// does not link libyara, so — like the other rule
// tests — this asserts the rule SOURCE is present and well-formed; the real
// compile+match runs in the Docker `full` CI stage (compile-rules.sh runs yarac
// over every local rule, then the runtime scanners job scans fixtures).

func loadScriptDownloadersRule(t *testing.T) []byte {
	t.Helper()
	paths := []string{
		"../../../../docker/local-rules/script_downloaders.yara",
		"../../../docker/local-rules/script_downloaders.yara",
		"../../docker/local-rules/script_downloaders.yara",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("script_downloaders.yara not found relative to test dir")
	return nil
}

func TestScriptDownloadersRule_Present(t *testing.T) {
	data := loadScriptDownloadersRule(t)
	for _, want := range []string{
		"rule PS1_IEX_IRM_DownloadCradle",
		"rule VBS_GetObject_Scriptlet_SelfDelete",
		"rule Script_MSIExec_Remote_Package_Silent",
		"rule VBS_WScriptShell_Run_TempBat_Hidden",
		// s31 second batch: four single-family 0-hit misses.
		"rule PS1_Curl_Rundll32_PNG_Loader",          // 2c41d4f8
		"rule PS1_PSCredential_Password_Spray",       // 9f0a17d4
		"rule PS1_Defender_Exclusion_Cleanup_Loader", // 3ae711ab
		"rule VBS_CustomBase64_MSXML_ExecuteGlobal",  // f6438c51
		// s31 third batch: GitHub-raw random-name dropper family (was generic-only).
		"rule PS1_RandomName_Temp_Download_Exec_Delete", // 0f21d86b/2033921b/d3fd81d8
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("script_downloaders.yara missing %q", want)
		}
	}
}

func TestScriptDownloadersRule_Anchors(t *testing.T) {
	data := loadScriptDownloadersRule(t)
	// the specific malicious constructs each rule keys on
	for _, anchor := range []string{
		"irm",                               // PS cradle
		`GetObject\(\s*"script:`,            // VBS scriptlet loader
		"DeleteFile WScript.ScriptFullName", // self-delete
		"msiexec",                           // remote installer
		"WScript.Shell",                     // Run launcher
		`AppData\\Local\\Temp\\`,            // temp drop path
		// s31 batch construct anchors
		"curl.exe",       // 2c41d4f8
		`\.png["']?\s*,`, // 2c41d4f8 rundll32-on-png
		"System.Management.Automation.PSCredential", // 9f0a17d4
		"-AsPlainText",                 // 9f0a17d4
		"Remove-MpPreference",          // 3ae711ab
		"$MyInvocation.MyCommand.Path", // 3ae711ab self-delete
		"MSXML2.ServerXMLHTTP",         // f6438c51
		"ExecuteGlobal",                // f6438c51
		// s31 random-name dropper family anchors
		`Get-Random\s+-Min`, // forge random temp filename
		`\$env:TEMP`,        // temp drop path
		"-OutFile",          // download to file
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("script_downloaders.yara missing anchor %q", anchor)
		}
	}
}

func TestScriptDownloadersRule_HasWideModifier(t *testing.T) {
	// UTF-16LE stubs must match — every string carries `wide`.
	data := loadScriptDownloadersRule(t)
	if !bytes.Contains(data, []byte("ascii wide")) {
		t.Errorf("script_downloaders.yara: strings must be `ascii wide` (UTF-16LE samples)")
	}
}

func TestScriptDownloadersRule_HasFilesizeGuard(t *testing.T) {
	// every rule must bound filesize so the broad keyword conjunctions only fire
	// on the small stubs they target (not large benign scripts that mention them).
	data := loadScriptDownloadersRule(t)
	if !bytes.Contains(data, []byte("filesize <")) {
		t.Errorf("script_downloaders.yara: rules must carry a `filesize <` guard")
	}
}

func TestScriptDownloadersRule_NoBackreference(t *testing.T) {
	// yarac rejects backreferences; compile-rules.sh would then silently drop the
	// rule. Catch it at unit speed instead of as a missing rule on the live host.
	data := loadScriptDownloadersRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("script_downloaders.yara contains backreference %q (yarac rejects, rule silently skipped)", bad)
		}
	}
}

func TestScriptDownloadersRule_NoNestedUnboundedQuantifier(t *testing.T) {
	// The catastrophic-backtracking class (#174/#177): a `){N,}` after an
	// unbounded inner quantifier blows scan_timeout and fail-opens the file.
	data := loadScriptDownloadersRule(t)
	if bytes.Contains(data, []byte("){")) {
		t.Errorf("script_downloaders.yara has a `){...}` group-repeat — risks catastrophic backtracking; keep regexes linear")
	}
}
