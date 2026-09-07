package extract

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	yekazip "github.com/yeka/zip"
)

func msixFixture(body string) []byte {
	return []byte(`<Package xmlns="` + msixFoundationNS + `" xmlns:uap="` + msixUAPNS + `"><Identity Name="Example.App" Publisher="CN=Example" Version="1.0.0.0"/>` + body + `</Package>`)
}

const msixApplicationFixture = `<Applications><Application Id="Example" Executable="bin\example.exe" EntryPoint="Example.App" StartPage="index.html?a=1&amp;b=2"><Extensions><uap:Extension Category="windows.protocol"><uap:Protocol Name="example"/></uap:Extension></Extensions></Application></Applications>`

func TestMSIXPublicExtraction(t *testing.T) {
	manifest := msixFixture(msixApplicationFixture)
	for _, opc := range []bool{false, true} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("opc=%t/nested=%t", opc, nested), func(t *testing.T) {
				members := map[string][]byte{msixManifestName: manifest, "readme.txt": []byte("ordinary-package-body")}
				if opc {
					members["[Content_Types].xml"] = []byte(`<Types/>`)
				}
				buf := buildZip(t, members)
				if nested {
					buf = buildZip(t, map[string][]byte{"arbitrary.bin": buf})
				}
				res := Extract(buf, time.Time{})
				for _, want := range []string{"MSIX-IDENTITY name=Example.App", "MSIX-IDENTITY publisher=CN=Example", "MSIX-IDENTITY version=1.0.0.0", "MSIX-APPLICATION id=Example", `MSIX-APPLICATION executable=bin\example.exe`, "MSIX-APPLICATION entrypoint=Example.App", "MSIX-APPLICATION startpage=index.html?a=1&b=2", "MSIX-PROTOCOL name=example"} {
					if !streamsContain(res, want) {
						t.Errorf("missing %q", want)
					}
				}
				// Check exact emitted bodies: nested raw ZIP bytes may contain text.
				bodyFound := false
				for _, stream := range res.Streams {
					if bytes.Equal(stream, members["readme.txt"]) {
						bodyFound = true
					}
				}
				if bodyFound == opc {
					t.Errorf("existing body policy changed: OPC=%t body=%t", opc, bodyFound)
				}
			})
		}
	}
}

func TestMSIXRecognitionAndFallback(t *testing.T) {
	for _, name := range []string{"other.xml", "sub/AppxManifest.xml", "appxmanifest.xml"} {
		res := Extract(buildZip(t, map[string][]byte{name: msixFixture(msixApplicationFixture)}), time.Time{})
		if streamsContain(res, msixIdentityTag) {
			t.Errorf("recognized non-root name %q", name)
		}
	}
	bad := []byte(`<Package xmlns="urn:unrelated"><Identity Name="Example"/></Package>`)
	res := Extract(buildZip(t, map[string][]byte{msixManifestName: bad}), time.Time{})
	if streamsContain(res, msixIdentityTag) || !streamsContain(res, string(bad)) {
		t.Fatal("unrelated schema changed raw fallback")
	}
	pe := minimalPE()
	res = Extract(buildZip(t, map[string][]byte{"[Content_Types].xml": []byte(`<Types/>`), msixManifestName: pe}), time.Time{})
	found := false
	for _, stream := range res.Streams {
		if bytes.Equal(stream, pe) {
			found = true
		}
	}
	if !found {
		t.Fatal("manifest name suppressed existing PE carrier")
	}
}

func TestMSIXMalformedAndLimits(t *testing.T) {
	good := string(msixFixture(msixApplicationFixture))
	attrs := ""
	for i := 0; i <= maxMSIXAttrs; i++ {
		attrs += fmt.Sprintf(` a%d="x"`, i)
	}
	cases := map[string]string{
		"truncated": good[:len(good)-1], "leading-text": "text" + good, "trailing-text": good + "text", "two-roots": good + good,
		"wrong-namespace":     strings.ReplaceAll(good, msixFoundationNS, "urn:other"),
		"wrong-root":          strings.ReplaceAll(good, "Package", "Something"),
		"missing-identity":    `<Package xmlns="` + msixFoundationNS + `"/>`,
		"missing-required":    strings.Replace(good, ` Publisher="CN=Example"`, "", 1),
		"duplicate-attribute": strings.Replace(good, `Name="Example.App"`, `Name="Example.App" Name="Other"`, 1),
		"duplicate-identity":  string(msixFixture(`<Identity Name="Other" Publisher="CN=Other" Version="1.0.0.0"/>`)),
		"unknown-entity":      strings.Replace(good, "Example.App", "&unknown;", 1),
		"bytes":               good + strings.Repeat(" ", maxMSIXBytes),
		"tokens":              string(msixFixture(strings.Repeat(`<x/>`, maxMSIXTokens))),
		"depth":               string(msixFixture(strings.Repeat(`<x>`, maxMSIXDepth) + strings.Repeat(`</x>`, maxMSIXDepth))),
		"attributes":          string(msixFixture(`<x` + attrs + `/>`)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if got := msixManifestFields([]byte(input), maxStreams, time.Time{}); len(got) != 0 {
				t.Fatalf("published %d fields", len(got))
			}
		})
	}
	if got := msixManifestFields([]byte(good), maxStreams, time.Now().Add(-time.Second)); len(got) != 0 {
		t.Fatal("expired deadline emitted")
	}
	if got := msixManifestFields([]byte(good), 0, time.Time{}); len(got) != 0 {
		t.Fatal("zero stream allowance emitted")
	}
	if got := msixManifestFields([]byte(good), 2, time.Time{}); len(got) != 2 {
		t.Fatalf("stream cap: %d", len(got))
	}
	many := msixFixture(`<Applications>` + strings.Repeat(`<Application Id="Example"/>`, 40) + `</Applications>`)
	if got := msixManifestFields(many, maxStreams, time.Time{}); len(got) != maxMSIXFields {
		t.Fatalf("field cap: %d", len(got))
	}
	long := strings.Replace(good, "Example.App", strings.Repeat("x", maxMSIXValue+1), 1)
	got := msixManifestFields([]byte(long), maxStreams, time.Time{})
	if len(got) == 0 || len(got[0]) != len(msixIdentityTag+"name=")+maxMSIXValue {
		t.Fatal("value cap not applied")
	}
}

func TestMSIXPathsAndOrdering(t *testing.T) {
	for _, body := range []string{
		`<Application Executable="wrong.exe"/>`,
		`<Applications xmlns="urn:other"><Application Executable="wrong.exe"/></Applications>`,
		strings.Replace(msixApplicationFixture, "windows.protocol", "windows.other", 1),
		strings.ReplaceAll(msixApplicationFixture, "uap:Protocol", "Protocol"),
	} {
		fields := bytes.Join(msixManifestFields(msixFixture(body), maxStreams, time.Time{}), []byte("\n"))
		if bytes.Contains(fields, []byte("wrong.exe")) || bytes.Contains(fields, []byte(msixProtocolTag)) {
			t.Fatalf("wrong path/category emitted: %s", fields)
		}
	}
	a := msixFixture("")
	b := bytes.Replace(a, []byte(`Name="Example.App" Publisher="CN=Example" Version="1.0.0.0"`), []byte(`Version="1.0.0.0" Publisher="CN=Example" Name="Example.App"`), 1)
	if !bytes.Equal(bytes.Join(msixManifestFields(a, 32, time.Time{}), nil), bytes.Join(msixManifestFields(b, 32, time.Time{}), nil)) {
		t.Fatal("attribute order changed fields")
	}
}

func TestMSIXSharedBudgets(t *testing.T) {
	data := msixFixture("")
	for _, opc := range []bool{false, true} {
		members := map[string][]byte{msixManifestName: data}
		if opc {
			members["[Content_Types].xml"] = []byte(`<Types/>`)
		}
		buf := buildZip(t, members)
		run := func(res *Result, b *archiveBudget) {
			if opc {
				fromOfficeZipCarriers(buf, res, b, 0, time.Time{})
			} else {
				fromArchive(buf, res, b, 0, time.Time{})
			}
		}
		res, b := Result{}, archiveBudget{}
		run(&res, &b)
		if b.members != 1 || b.total != len(data) || !streamsContain(res, msixIdentityTag) {
			t.Fatalf("OPC=%t accounting=%+v", opc, b)
		}
		res, b = Result{}, archiveBudget{members: maxArchiveMembers}
		run(&res, &b)
		if len(res.Streams) != 0 {
			t.Fatal("spent budget emitted")
		}
		res, b = Result{Streams: make([][]byte, maxStreams)}, archiveBudget{}
		run(&res, &b)
		if len(res.Streams) != maxStreams || b.members != 0 {
			t.Fatal("full streams consumed member")
		}
	}
}

func TestMSIXEncryptedZIP(t *testing.T) {
	buf := buildYekaZip(t, msixManifestName, testPW, yekazip.StandardEncryption, msixFixture(msixApplicationFixture))
	res := ExtractWithOptions(buf, pwOpts(testPW))
	if !streamsContain(res, "MSIX-PROTOCOL name=example") {
		t.Fatal("decrypted manifest fields missing")
	}
}

func TestMSIXExactTokenBudget(t *testing.T) {
	// Package and Identity contribute four tokens, each empty x contributes two.
	atCap := msixFixture(strings.Repeat(`<x/>`, (maxMSIXTokens-4)/2))
	if fields := msixManifestFields(atCap, maxStreams, time.Time{}); len(fields) != 3 {
		t.Fatalf("exact token budget rejected: got %d fields, want 3", len(fields))
	}
	overCap := bytes.Replace(atCap, []byte(`</Package>`), []byte(`<!--one more token--></Package>`), 1)
	if fields := msixManifestFields(overCap, maxStreams, time.Time{}); len(fields) != 0 {
		t.Fatal("over token budget emitted fields")
	}
}
