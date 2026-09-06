package extract

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// fixtureCFB makes every supplied stream reachable from the root. Like buildCFB,
// this is a minimal parser fixture, not an Office application document writer.
func fixtureCFB(t *testing.T, streams []cfbEntry) []byte {
	t.Helper()
	entries := append([]cfbEntry{{name: "Root Entry", mse: 5}}, streams...)
	for i := range entries {
		entries[i].linksSet = true
		entries[i].left, entries[i].right, entries[i].child = cfbFree, cfbFree, cfbFree
		if i == 0 && len(streams) > 0 {
			entries[i].child = 1
		} else if i > 0 && i+1 < len(entries) {
			entries[i].right = uint32(i + 1)
		}
	}
	return buildCFB(t, entries)
}

func requireFixtureStream(t *testing.T, streams [][]byte, want string) {
	t.Helper()
	for _, stream := range streams {
		if bytes.Equal(stream, []byte(want)) {
			return
		}
	}
	t.Fatalf("missing exact plaintext stream %q", want)
}

func requireFixtureMarker(t *testing.T, res Result, marker, want string) {
	t.Helper()
	for _, stream := range res.Markers {
		if bytes.HasPrefix(stream, []byte(marker+"\n")) && bytes.Contains(stream, []byte(want)) {
			return
		}
	}
	t.Fatalf("missing %s marker containing plaintext %q", marker, want)
}

// Reuse the checked-in workbook's valid VBA PROJECT, dir and module streams so
// Extract reaches the post-VBA OLE walks. Metadata assertions below require
// their own plaintext, which the VBA source cannot supply.
func fixtureVBAStreams(t *testing.T) []cfbEntry {
	t.Helper()
	buf := readFixture(t, "xlswithmacro.xlsm")
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range zr.File {
		if entry.Name != "xl/vbaProject.bin" {
			continue
		}
		ole, err := oleparse.NewOLEFile(readZipEntry(entry))
		if err != nil {
			t.Fatal(err)
		}
		mods, err := oleparse.ExtractMacroBlobs(ole)
		if err != nil || len(mods) == 0 {
			t.Fatalf("fixture VBA modules: count=%d err=%v", len(mods), err)
		}
		names := []string{"PROJECT", "dir", "_VBA_PROJECT"}
		for _, mod := range mods {
			names = append(names, mod.StreamName)
		}
		var streams []cfbEntry
		for _, name := range names {
			stream := ole.FindStreamByName(name)
			if stream == nil {
				t.Fatalf("missing VBA fixture stream %q", name)
			}
			streams = append(streams, cfbEntry{name: name, mse: 2, data: bytes.Clone(ole.GetStreamView(stream.Index))})
		}
		return streams
	}
	t.Fatal("fixture has no xl/vbaProject.bin")
	return nil
}

func TestExtractOLEDocPropsFixture(t *testing.T) {
	const title = "Quarterly report fixture"
	streams := append(fixtureVBAStreams(t), cfbEntry{
		name: "\x05SummaryInformation", mse: 2,
		data: buildSummaryStream([]metaProp{lpstrProp(2, title)}),
	})
	res := Extract(fixtureCFB(t, streams), time.Time{})
	requireFixtureStream(t, res.Streams, title)
	if !res.IsDoc || res.Failed || res.Panicked || !res.HasDocProps {
		t.Fatalf("property fixture flags: IsDoc=%t Failed=%t Panicked=%t HasDocProps=%t", res.IsDoc, res.Failed, res.Panicked, res.HasDocProps)
	}
	requireFixtureMarker(t, res, "DOCPROPS-STRINGS", title)
}

func TestExtractUserFormFixture(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
	}{
		{"o", "\x01\x00Binary form caption fixture\x00", "Binary form caption fixture"},
		{"f", "Caption=Text form caption fixture\r\n", "Text form caption fixture"},
		{"\x03VBFrame", "Tag=Frame tag fixture\r\n", "Frame tag fixture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			streams := append(fixtureVBAStreams(t), cfbEntry{name: tc.name, mse: 2, data: []byte(tc.data)})
			res := Extract(fixtureCFB(t, streams), time.Time{})
			if !res.IsDoc || res.Failed || res.Panicked {
				t.Fatalf("form fixture flags: IsDoc=%t Failed=%t Panicked=%t", res.IsDoc, res.Failed, res.Panicked)
			}
			requireFixtureStream(t, res.Streams, tc.want)
			requireFixtureMarker(t, res, "USERFORM-STRINGS", tc.want)
		})
	}
}
