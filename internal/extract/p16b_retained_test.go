package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"www.velocidex.com/golang/oleparse"
)

func p16bCab(content []byte, compression uint16) []byte {
	name := []byte("member.bin\x00")
	fileOffset := 44
	dataOffset := fileOffset + 16 + len(name)
	buf := make([]byte, dataOffset+8+len(content))
	copy(buf[:4], "MSCF")
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(buf)))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(fileOffset))
	buf[24], buf[25] = 3, 1
	binary.LittleEndian.PutUint16(buf[26:28], 1)
	binary.LittleEndian.PutUint16(buf[28:30], 1)
	binary.LittleEndian.PutUint32(buf[36:40], uint32(dataOffset))
	binary.LittleEndian.PutUint16(buf[40:42], 1)
	binary.LittleEndian.PutUint16(buf[42:44], compression)
	binary.LittleEndian.PutUint32(buf[fileOffset:fileOffset+4], uint32(len(content)))
	copy(buf[fileOffset+16:], name)
	binary.LittleEndian.PutUint16(buf[dataOffset+4:dataOffset+6], uint16(len(content)))
	binary.LittleEndian.PutUint16(buf[dataOffset+6:dataOffset+8], uint16(len(content)))
	copy(buf[dataOffset+8:], content)
	return buf
}

func p16bResult() (*Result, *retainedBudget) {
	ledger := &retainedBudget{}
	return &Result{childOpts: &Options{retained: ledger}}, ledger
}

func assertP16bAccounting(t *testing.T, res *Result, ledger *retainedBudget) {
	t.Helper()
	var want uint64
	for _, stream := range res.Streams {
		want += uint64(len(stream))
	}
	if got := ledger.snapshot().Bytes(); got != want {
		t.Fatalf("source-bound retained bytes=%d want emitted stream bytes=%d", got, want)
	}
}

func parseP16bOLE(t *testing.T, buf []byte) *oleparse.OLEFile {
	t.Helper()
	ole, err := oleparse.NewOLEFile(buf)
	if err != nil {
		t.Fatal(err)
	}
	return ole
}

func TestP16bDirectCarrierAccounting(t *testing.T) {
	t.Run("archive_member", func(t *testing.T) {
		res, ledger := p16bResult()
		emitMember([]byte("plain archive member"), res, &archiveBudget{}, 0, time.Time{})
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("office_sibling", func(t *testing.T) {
		sibling := []byte("{\\rtf1{\\field{\\*\\fldinst DDEAUTO cmd /c calc}}}")
		buf := buildZip(t, map[string][]byte{"word/document.xml": []byte("body"), "sibling.rtf": sibling})
		zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
		if err != nil {
			t.Fatal(err)
		}
		res, ledger := p16bResult()
		fromOfficeZipCarriersZip(zr, res, &archiveBudget{}, 0, time.Time{})
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("cab_member_and_marker", func(t *testing.T) {
		res, ledger := p16bResult()
		unpackCab(p16bCab([]byte("cab member"), 0), res, &archiveBudget{}, 0, time.Time{})
		unpackCab(p16bCab([]byte("cab member"), 2), res, &archiveBudget{}, 0, time.Time{})
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("msix_member_and_fields", func(t *testing.T) {
		manifest := msixFixture(`<Applications><Application Id="App" Executable="app.exe" EntryPoint="Windows.FullTrustApplication"><uap:Extension Category="windows.protocol"><uap:Protocol Name="sample"/></uap:Extension></Application></Applications>`)
		res, ledger := p16bResult()
		emitZipMember(msixManifestName, manifest, res, &archiveBudget{}, 0, time.Time{})
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("ole_msi", func(t *testing.T) {
		res, ledger := p16bResult()
		if !fromMSI(parseP16bOLE(t, buildMinimalMSI(t, []byte("msi payload"))), res, time.Time{}) {
			t.Fatal("MSI fixture not recognized")
		}
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("ole_msg", func(t *testing.T) {
		buf := buildCFB(t, []cfbEntry{
			{name: "Root Entry", mse: 5},
			{name: "__properties_version1.0", mse: 2, data: []byte("props")},
			{name: "__attach_version1.0_#00000000", mse: 1},
			{name: "__substg1.0_3701000D", mse: 2, data: []byte("msg attachment")},
		})
		res, ledger := p16bResult()
		if !fromMSG(parseP16bOLE(t, buf), res, &archiveBudget{}, 0, time.Time{}) {
			t.Fatal("MSG fixture not recognized")
		}
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("ole_package", func(t *testing.T) {
		stream := buildOle10Native("x", "x", "x", []byte("package payload"), 0)
		buf := buildCFB(t, []cfbEntry{{name: "Root Entry", mse: 5}, {name: "\x01Ole10Native", mse: 2, data: stream}})
		res, ledger := p16bResult()
		if !fromOLEPackage(parseP16bOLE(t, buf), res, &archiveBudget{}, 0, time.Time{}) {
			t.Fatal("package fixture not recognized")
		}
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("ole_orphan", func(t *testing.T) {
		buf := buildCFB(t, []cfbEntry{
			{name: "Root Entry", mse: 5, child: 1, left: cfbFree, right: cfbFree, linksSet: true},
			{name: "Reachable", mse: 2, data: []byte("reachable"), left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
			{name: "Orphan", mse: 2, data: []byte("orphan payload"), left: cfbFree, right: cfbFree, child: cfbFree, linksSet: true},
		})
		res, ledger := p16bResult()
		fromOLEOrphans(parseP16bOLE(t, buf), res, time.Time{})
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("onenote", func(t *testing.T) {
		res, ledger := p16bResult()
		fromOneNote(buildOneNote(buildFDSO([]byte("OneNote payload"), 0)), res, &archiveBudget{}, 0, time.Time{})
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("rtf", func(t *testing.T) {
		packageStream := buildOle10Native("x", "x", "x", []byte("RTF package payload"), 0)
		buf := append([]byte("{\\rtf1{\\field{\\*\\fldinst DDEAUTO cmd /c calc}}\\objupdate"), wrapRTFObjData(packageStream)...)
		res, ledger := p16bResult()
		fromRTF(buf, res, &archiveBudget{}, 0, time.Time{})
		assertP16bAccounting(t, res, ledger)
	})

	t.Run("tnef", func(t *testing.T) {
		res, ledger := p16bResult()
		fromTNEF(buildTNEF([]byte("TNEF attachment")), res, &archiveBudget{}, 0, time.Time{})
		assertP16bAccounting(t, res, ledger)
	})
}

func TestP16bMalformedCarriersRecordNothing(t *testing.T) {
	inputs := [][]byte{
		[]byte("PK\x03\x04truncated"),
		[]byte("MSCFtruncated"),
		[]byte("{\\rtf1{\\object{\\*\\objdata zzz}}}"),
		append([]byte(nil), oneSectionGUID...),
		{0x78, 0x9f, 0x3e, 0x22},
	}
	for _, input := range inputs {
		res := Extract(input, time.Time{})
		if got := res.Retained.Bytes(); got != 0 {
			t.Fatalf("malformed %x retained bytes=%d want=0", input[:min(len(input), 8)], got)
		}
	}
}
