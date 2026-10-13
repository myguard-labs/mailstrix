package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"
	"www.velocidex.com/golang/oleparse"
)

func assertP16eClosure(t *testing.T, r *Result, b *retainedBudget) {
	t.Helper()
	want := p16dStreamBytes(r.Streams) + p16dStreamBytes(r.Markers)
	if want == 0 {
		t.Fatal("positive fixture emitted no output")
	}
	if got := b.snapshot().Bytes(); got != want {
		t.Fatalf("P16e retained closure=%d want complete output bytes=%d", got, want)
	}
}

type p16eOLECase struct {
	name    string
	entries []cfbEntry
	emit    func(*oleparse.OLEFile, *Result)
}

func p16eOLECases() []p16eOLECase {
	return []p16eOLECase{
		{"xor", []cfbEntry{{name: "Workbook", mse: 2, data: workbookWithFilepass(0)}}, func(o *oleparse.OLEFile, r *Result) { fromOLEEncType(o, r, time.Time{}) }},
		{"rc4", []cfbEntry{{name: "Workbook", mse: 2, data: workbookWithFilepass(1)}}, func(o *oleparse.OLEFile, r *Result) { fromOLEEncType(o, r, time.Time{}) }},
		{"aes", nil, fromOLEEncInfo},
		{"word", []cfbEntry{{name: "WordDocument", mse: 2, data: wordDocStream(0x100)}}, fromWordFibEncryption},
		{"ppt", []cfbEntry{{name: "EncryptedSummary", mse: 2, data: []byte("summary")}}, fromPPTEncryptedSummary},
		{"signature", []cfbEntry{{name: "_signatures", mse: 1}}, func(o *oleparse.OLEFile, r *Result) { fromOLEDigSig(o, r, time.Time{}) }},
		{"objectpool", []cfbEntry{{name: "ObjectPool", mse: 1}}, func(o *oleparse.OLEFile, r *Result) { fromOLEIndicators(o, r, time.Time{}) }},
		{"flash", []cfbEntry{{name: "Contents", mse: 2, data: []byte("CWS flash payload")}}, func(o *oleparse.OLEFile, r *Result) { fromOLEIndicators(o, r, time.Time{}) }},
		{"docsecurity", []cfbEntry{{name: "\x05SummaryInformation", mse: 2, data: buildSummaryInfoStream(4)}}, func(o *oleparse.OLEFile, r *Result) { fromOLEDocProps(o, r, time.Time{}) }},
		{"docprops", []cfbEntry{{name: "\x05DocumentSummaryInformation", mse: 2, data: []byte("\x00cmd.exe /c powershell -nop\x00")}}, func(o *oleparse.OLEFile, r *Result) { fromOLEDocProps(o, r, time.Time{}) }},
		{"metadata", []cfbEntry{{name: "\x05SummaryInformation", mse: 2, data: buildSummaryStream([]metaProp{lpstrProp(pidsiTemplate, "https://evil.example/template.dot")})}}, func(o *oleparse.OLEFile, r *Result) { fromOLEDocProps(o, r, time.Time{}) }},
		{"userform", []cfbEntry{{name: "o", mse: 2, data: []byte("\x00cmd.exe /c powershell -nop\x00")}}, func(o *oleparse.OLEFile, r *Result) { fromUserForms(o, r, time.Time{}) }},
	}
}

func TestP16eStructuralAdmissions(t *testing.T) {
	for _, tc := range p16eOLECases() {
		t.Run(tc.name, func(t *testing.T) {
			entries := append([]cfbEntry{{name: "Root Entry", mse: 5}}, tc.entries...)
			o := parseP16bOLE(t, buildCFB(t, entries))
			r, b := p16bResult()
			tc.emit(o, r)
			assertP16eClosure(t, r, b)
			before := b.snapshot().Bytes()
			finalizeStreams(r, len(r.Streams))
			assertP16eClosure(t, r, b)
			if tc.name == "docprops" || tc.name == "userform" || tc.name == "metadata" {
				if len(r.Markers) == 0 {
					t.Fatal("combined payload missing marker channel")
				}
			}
			if b.snapshot().Bytes() != before {
				t.Fatal("partition charged existing outputs again")
			}
			var private Result
			tc.emit(o, &private) // nil accounting preserves private callers
		})
	}
	t.Run("times", func(t *testing.T) {
		stamp := timeToFiletime(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
		entries := []cfbEntry{{name: "Root Entry", mse: 5, ctime: stamp, mtime: stamp}, {name: "A", mse: 1, ctime: stamp, mtime: stamp}, {name: "B", mse: 1, ctime: stamp, mtime: stamp}}
		r, b := p16bResult()
		fromOLETimes(parseP16bOLE(t, buildCFB(t, entries)), r, time.Time{})
		if len(r.Streams) != 2 {
			t.Fatalf("future+synthetic=%q", r.Streams)
		}
		assertP16eClosure(t, r, b)
	})
	t.Run("stomp", func(t *testing.T) {
		r, b := p16bResult()
		detectStompingModules([]*oleparse.VBAModule{{ModuleName: "M", TextOffset: 4096}}, r, time.Time{})
		assertP16eClosure(t, r, b)
	})
	t.Run("extra", func(t *testing.T) {
		for _, size := range []int{extraDataMinBytes, maxExtraDataCarve + 1} {
			r, b := p16bResult()
			buf := append(make([]byte, 1024), bytes.Repeat([]byte{'A'}, size)...)
			fromOLEExtraData(&oleparse.OLEFile{SectorSize: 512, Fat: []uint32{oleparse.ENDOFCHAIN}}, buf, r, time.Time{})
			assertP16eClosure(t, r, b)
		}
	})
	t.Run("binary_dedup", func(t *testing.T) {
		elf := make([]byte, 64)
		copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
		elf[16] = 2
		elf[18] = 62
		r, b := p16bResult()
		r.Streams = [][]byte{elf}
		r.recordRetained(elf)
		analyzeBinaries(elf, r)
		if len(r.Streams) != 2 {
			t.Fatalf("binary marker dedup failed=%q", r.Streams)
		}
		assertP16eClosure(t, r, b)
	})
}

func TestP16eFinalizerJoinedMarkerClosure(t *testing.T) {
	for _, panicExit := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "panic"}[panicExit], func(t *testing.T) {
			content := []byte("complete retained payload")
			seeds := [][]byte{content, []byte("XLM-AUTO-OPEN"), []byte("XLM-DANGEROUS-FUNC EXEC"), []byte("OLEID-OBJECTPOOL"), []byte("OLEID-FLASH"), []byte("DIGITAL-SIGNATURE")}
			withAfterFormatHook(t, func(r *Result) {
				for _, s := range seeds {
					r.recordRetained(s)
					r.Streams = append(r.Streams, s)
				}
				r.capHit("p16e-fixture")
				if panicExit {
					panic("P16e after accepted admissions")
				}
			})
			r := ExtractWithOptions([]byte("plain"), FullOptions(time.Time{}))
			assertP16eClosure(t, &r, r.childOpts.retained)
			wantContent := 2 // dangerous-function payload remains content; cap is outside normal pre-decode snapshot
			if panicExit {
				wantContent = 3
			} // panic fallback includes the existing cap marker
			if r.Panicked != panicExit || r.Failed != panicExit || r.ContentStreams != wantContent || r.DecodedStreams != 0 || !hasStream(r.Streams, content) {
				t.Fatalf("finalizer metadata changed: %+v", r)
			}
			if !hasStream(r.Streams, []byte(capHitMarkerPrefix+"p16e-fixture")) {
				t.Fatal("cap marker changed channel")
			}
			for _, prefix := range []string{xlmStackerPrefix, behaviorScorePrefix} {
				found := false
				for _, m := range r.Markers {
					found = found || bytes.HasPrefix(m, []byte(prefix))
				}
				if !found {
					t.Fatalf("missing joined/cap marker %q", prefix)
				}
			}
		})
	}
}

func TestP16eFinalizerBoundaries(t *testing.T) {
	for _, pre := range []int{-1, 0, 2} {
		r, b := p16bResult()
		payload := []byte("payload")
		r.recordRetained(payload)
		r.Streams = [][]byte{payload}
		finalizeStreams(r, pre)
		assertP16eClosure(t, r, b)
		want := 1
		if pre == 0 {
			want = 0
		}
		if r.ContentStreams != want {
			t.Fatalf("content provenance=%d want=%d", r.ContentStreams, want)
		}
	}
	r, b := p16bResult()
	fromOLEEncType(nil, r, time.Time{})
	fromOLEEncInfo(nil, r)
	fromWordFibEncryption(nil, r)
	fromPPTEncryptedSummary(nil, r)
	fromOLEDigSig(nil, r, time.Time{})
	fromOLEIndicators(nil, r, time.Time{})
	fromOLETimes(nil, r, time.Time{})
	fromOLEDocProps(nil, r, time.Time{})
	fromUserForms(nil, r, time.Time{})
	fromXLL([]byte("MZ"), r)
	fromPolyglot([]byte("MZ"), r)
	analyzeBinaries([]byte("text"), r)
	finalizeStreams(r, -1)
	if b.snapshot().Bytes() != 0 || len(r.Streams)+len(r.Markers) != 0 {
		t.Fatal("malformed inputs retained output")
	}
}

func TestP16eCompleteOLEParity(t *testing.T) {
	want := map[string]string{"xor": "8e47558149bbdc8697ed3977df098afe1cbad9b8daa01a54a49ab1d4dc6711c2", "rc4": "aca143bcc6aec0e49ecd8d628ef6b4bcfdc360223c40bfa55093129634e6049c", "aes": "5785205668cb2fbd6fa094becb087842f8564843279a77918c7b86f51b24847c", "word": "aca143bcc6aec0e49ecd8d628ef6b4bcfdc360223c40bfa55093129634e6049c", "ppt": "aca143bcc6aec0e49ecd8d628ef6b4bcfdc360223c40bfa55093129634e6049c", "signature": "a26569b53332b65a9fbf86b34debd2608337ca3f6618446f102ec41a22614008", "objectpool": "f033982267bb8c6829bc92404099225b1d96cd847b5d2cd60fca4b1635550362", "flash": "d055bd3b742f986ea76d46922774cbe14cc8633ca6ea04f6929b8f5b38f7009d", "docsecurity": "79b018f19fc5fb49a45c47fea50d392d389de20064977b6a0df351ad8f3d51ca", "docprops": "a5544d10e92c8839dc32da582900210022fb2c54a1c6ab21a28cf21d94242396", "metadata": "62863e0880946bace70e5ce98006f192afec2b2d06b34a68207644e7e2f310b9", "userform": "999ceaf1b1d5add982b8eb5ed2cee506f264061a01d96e025fb7c1c1ef8efd00"}
	for _, tc := range p16eOLECases() {
		t.Run(tc.name, func(t *testing.T) {
			entries := append([]cfbEntry{{name: "Root Entry", mse: 5}}, tc.entries...)
			o := parseP16bOLE(t, buildCFB(t, entries))
			var r Result
			tc.emit(o, &r)
			finalizeStreams(&r, len(r.Streams))
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			got := fmt.Sprintf("%x", sha256.Sum256(encoded))
			if got != want[tc.name] {
				t.Fatalf("complete OLE Result digest=%s want baseline=%s", got, want[tc.name])
			}
		})
	}
}

func TestP16eArchiveMarkersDedupAndLimits(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint(full), func(t *testing.T) {
			r, b := p16bResult()
			if full {
				r.Streams = make([][]byte, maxStreams)
			}
			markEncryptedArchive(r)
			markDecryptedArchive(r)
			markEncryptedArchive(r)
			markDecryptedArchive(r)
			wantCount := 2
			if full {
				wantCount += maxStreams
			}
			if len(r.Streams) != wantCount || !r.EncryptedArchive || !r.DecryptedArchive {
				t.Fatalf("archive marker flags/cap/dedup changed: %+v", r)
			}
			assertP16eClosure(t, r, b)
			if b.snapshot().Bytes() != 34 {
				t.Fatalf("archive marker bytes=%d want complete independent markers=34", b.snapshot().Bytes())
			}
			before := b.snapshot().Bytes()
			finalizeStreams(r, len(r.Streams))
			assertP16eClosure(t, r, b)
			if b.snapshot().Bytes() != before || len(r.Markers) != 2 {
				t.Fatal("archive marker transfer recharged or changed channel")
			}
		})
	}
	var private Result
	markEncryptedArchive(&private)
	markDecryptedArchive(&private)
	if len(private.Streams) != 2 {
		t.Fatal("nil accounting changed private caller")
	}
	r, b := p16bResult()
	r.EncryptedArchive = true
	r.DecryptedArchive = true
	markEncryptedArchive(r)
	markDecryptedArchive(r)
	if b.snapshot().Bytes() != 0 || len(r.Streams) != 0 {
		t.Fatal("already-set flags emitted or charged markers")
	}
	for _, emit := range []func(*Result){markEncryptedArchive, markDecryptedArchive} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("nil Result no longer preserves existing panic")
				}
			}()
			emit(nil)
		}()
	}
}
