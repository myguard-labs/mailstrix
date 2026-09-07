package extract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func launcherWide(text string, be bool) []byte {
	order := binary.ByteOrder(binary.LittleEndian)
	if be {
		order = binary.BigEndian
	}
	units := append([]uint16{0xfeff}, utf16.Encode([]rune(text))...)
	buf := make([]byte, len(units)*2)
	for i, unit := range units {
		order.PutUint16(buf[2*i:], unit)
	}
	return buf
}

func launcherFields(res Result) []string {
	var fields []string
	for _, stream := range res.Streams {
		if bytes.HasPrefix(stream, []byte(urlShortcutMarker)) ||
			bytes.HasPrefix(stream, []byte(settingsDeepMarker)) ||
			bytes.HasPrefix(stream, []byte(settingsIconMarker)) {
			fields = append(fields, string(stream))
		}
	}
	return fields
}

func TestLauncherUTF16Equivalence(t *testing.T) {
	for _, text := range []string{benignURL, strings.Replace(benignSettings, `encoding="UTF-8"`, `encoding="UTF-16"`, 1)} {
		base := strings.Replace(text, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)
		want := launcherFields(Extract([]byte(base), time.Time{}))
		if len(want) == 0 {
			t.Fatal("UTF-8 baseline emitted no launcher fields")
		}
		for _, be := range []bool{false, true} {
			for _, nested := range []bool{false, true} {
				t.Run(fmt.Sprintf("xml=%t/be=%t/nested=%t", strings.HasPrefix(text, "<?xml"), be, nested), func(t *testing.T) {
					wide := launcherWide(text, be)
					input := wide
					if nested {
						input = buildZip(t, map[string][]byte{"arbitrary.bin": input})
					}
					res := Extract(input, time.Time{})
					if got := launcherFields(res); !reflect.DeepEqual(got, want) {
						t.Fatalf("launcher fields = %q, want %q", got, want)
					}
					if !streamsContain(res, text) {
						t.Fatal("generic decoded text recovery was displaced")
					}
				})
			}
		}
	}
}

func TestLauncherUTF16Declarations(t *testing.T) {
	body := `<PCSettingsFile><DeepLink>ms-settings:display</DeepLink><Icon>https://example.com/图🙂.ico</Icon></PCSettingsFile>`
	for _, be := range []bool{false, true} {
		matching, wrong := "UTF-16LE", "UTF-16BE"
		if be {
			matching, wrong = wrong, matching
		}
		for _, declaration := range []string{
			"", `<?xml version="1.0"?>`, `<?xml version="1.0" encoding="UTF-16"?>`,
			`<?xml version='1.0' encoding='` + strings.ToLower(matching) + `' standalone='yes'?>`,
		} {
			var res Result
			fromLauncherFields(launcherWide(declaration+body, be), &res, time.Time{})
			want := []string{settingsDeepMarker + "ms-settings:display", settingsIconMarker + "https://example.com/图🙂.ico"}
			if got := launcherFields(res); !reflect.DeepEqual(got, want) {
				t.Errorf("be=%t declaration=%q fields=%q, want %q", be, declaration, got, want)
			}
		}
		for _, declaration := range []string{
			`<?xml version="1.0" encoding="` + wrong + `"?>`,
			`<?xml version="1.0" encoding="UTF-8"?>`,
			`<?xml version="1.0" encoding="windows-1252"?>`,
			`<?xml version="1.0" encoding="UTF-16" encoding="UTF-16"?>`,
			`<?xml version="1.0" encoding="UTF-16"`,
			`<?xml version="1.0" ` + strings.Repeat(" ", maxLauncherLineLen) + `?>`,
		} {
			var res Result
			fromLauncherFields(launcherWide(declaration+body, be), &res, time.Time{})
			if len(launcherFields(res)) != 0 {
				t.Errorf("be=%t unsupported declaration emitted fields", be)
			}
		}
	}
}

func TestLauncherUTF16InvalidUnits(t *testing.T) {
	for _, be := range []bool{false, true} {
		order := binary.ByteOrder(binary.LittleEndian)
		if be {
			order = binary.BigEndian
		}
		for _, units := range [][]uint16{{0xd800}, {0xdc00}, {0xd800, 'x'}, {0xd800, 0xd800}} {
			buf := launcherWide(benignURL, be)
			for _, unit := range units {
				buf = append(buf, 0, 0)
				order.PutUint16(buf[len(buf)-2:], unit)
			}
			var res Result
			fromLauncherFields(buf, &res, time.Time{})
			if len(launcherFields(res)) != 0 {
				t.Errorf("be=%t invalid units=%x emitted fields", be, units)
			}
		}
		var res Result
		fromLauncherFields(append(launcherWide(benignURL, be), 0), &res, time.Time{})
		if len(launcherFields(res)) != 0 {
			t.Fatal("odd byte count emitted fields")
		}
		// BOM-less input retains existing generic recovery, without new recognition.
		buf := launcherWide(benignURL, be)[2:]
		res = Extract(buf, time.Time{})
		if len(launcherFields(res)) != 0 || !streamsContain(res, benignURL) {
			t.Fatalf("be=%t BOM-less recovery changed", be)
		}
	}
}

func TestLauncherUTF16Budgets(t *testing.T) {
	deadline := time.Time{}
	exactOriginal := launcherWide(strings.Repeat("a", maxLauncherBytes/2-1), false)
	if got := launcherText(exactOriginal, deadline); len(got) != maxLauncherBytes/2-1 {
		t.Fatal("exact original-byte cap rejected")
	}
	if launcherText(append(exactOriginal, 'a', 0), deadline) != nil {
		t.Fatal("original-byte overrun accepted")
	}
	exactText := strings.Repeat("\u0800", maxLauncherBytes/3) + "a"
	if got := launcherText(launcherWide(exactText, true), deadline); string(got) != exactText {
		t.Fatal("exact decoded-byte cap rejected")
	}
	if launcherText(launcherWide(exactText+"a", true), deadline) != nil {
		t.Fatal("decoded-byte overrun accepted")
	}
	wide := launcherWide(benignURL, false)
	if launcherText(wide, time.Now().Add(-time.Second)) != nil {
		t.Fatal("expired normalization emitted text")
	}
	res := Result{Streams: make([][]byte, maxStreams)}
	fromLauncherFields(wide, &res, deadline)
	if len(res.Streams) != maxStreams {
		t.Fatal("full stream budget grew")
	}
	res.Streams = res.Streams[:maxStreams-1]
	fromLauncherFields(launcherWide(benignURL+"IconFile=example.ico\n", false), &res, deadline)
	if len(res.Streams) != maxStreams || string(res.Streams[maxStreams-1]) != urlShortcutMarker+"url=https://example.com/docs" {
		t.Fatal("last stream slot did not preserve first complete field")
	}
}
