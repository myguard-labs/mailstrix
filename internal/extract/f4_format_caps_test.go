package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"www.velocidex.com/golang/oleparse"
)

const f4FreeSector = 0xFFFFFFFF

func f4HasCap(res *Result, want string) bool {
	for _, got := range res.CapHits {
		if got == want {
			return true
		}
	}
	return false
}

func f4HasBytes(res *Result, want []byte) bool {
	for _, got := range res.Streams {
		if bytes.Contains(got, want) {
			return true
		}
	}
	return false
}

func TestVALF4FormatCapReachedBoundaries(t *testing.T) {
	clean := &Result{}
	if formatCapReached(clean, 0, 1, 0, 1, "fixture") || len(clean.CapHits) != 0 {
		t.Fatalf("below-cap request marked incomplete: %v", clean.CapHits)
	}
	formatBound := &Result{}
	if !formatCapReached(formatBound, 1, 1, 0, 1, "fixture") || !f4HasCap(formatBound, "fixture") {
		t.Fatalf("format cap not reported: %v", formatBound.CapHits)
	}
	streamBound := &Result{Streams: make([][]byte, maxStreams)}
	if !formatCapReached(streamBound, 0, 1, 0, 1, "fixture") || !f4HasCap(streamBound, "streams") {
		t.Fatalf("global stream cap not reported: %v", streamBound.CapHits)
	}
}

// buildF4CFB is a count-cap fixture builder. Unlike buildCFB, it emits as many
// FAT sectors as the fixture needs, so the 65/129/257-entry boundary cases pass
// through oleparse instead of relying on a mocked directory.
func buildF4CFB(t *testing.T, entries []cfbEntry, rootCLSID [16]byte) []byte {
	t.Helper()
	const (
		sectorSize = 512
		endOfChain = 0xFFFFFFFE
		fatSector  = 0xFFFFFFFD
		miniCutoff = 4096
		dirEntrySz = 128
	)

	entries = append([]cfbEntry(nil), entries...)
	streamSectors := 0
	for i := range entries {
		if entries[i].mse == 2 && len(entries[i].data) < miniCutoff {
			entries[i].data = append(entries[i].data, make([]byte, miniCutoff-len(entries[i].data))...)
		}
		if entries[i].mse == 2 {
			streamSectors += (len(entries[i].data) + sectorSize - 1) / sectorSize
		}
	}
	dirSectors := (len(entries)*dirEntrySz + sectorSize - 1) / sectorSize
	fatSectors := 1
	for {
		need := (fatSectors + dirSectors + streamSectors + sectorSize/4 - 1) / (sectorSize / 4)
		if need == fatSectors {
			break
		}
		fatSectors = need
	}
	if fatSectors > 109 {
		t.Fatalf("F4 fixture needs %d FAT sectors; header DIFAT holds 109", fatSectors)
	}

	firstDirSector := fatSectors
	nextSector := firstDirSector + dirSectors
	type placement struct {
		start   uint32
		sectors int
	}
	placements := make([]placement, len(entries))
	for i, entry := range entries {
		if entry.mse != 2 || len(entry.data) == 0 {
			placements[i].start = endOfChain
			continue
		}
		count := (len(entry.data) + sectorSize - 1) / sectorSize
		placements[i] = placement{start: uint32(nextSector), sectors: count}
		nextSector += count
	}

	header := make([]byte, sectorSize)
	copy(header[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(header[24:], 0x3E)
	binary.LittleEndian.PutUint16(header[26:], 3)
	binary.LittleEndian.PutUint16(header[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(header[30:], 9)
	binary.LittleEndian.PutUint16(header[32:], 6)
	binary.LittleEndian.PutUint32(header[44:], uint32(fatSectors))
	binary.LittleEndian.PutUint32(header[48:], uint32(firstDirSector))
	binary.LittleEndian.PutUint32(header[56:], miniCutoff)
	binary.LittleEndian.PutUint32(header[60:], endOfChain)
	binary.LittleEndian.PutUint32(header[68:], endOfChain)
	for i := 0; i < 109; i++ {
		value := uint32(f4FreeSector)
		if i < fatSectors {
			value = uint32(i)
		}
		binary.LittleEndian.PutUint32(header[76+i*4:], value)
	}

	fat := make([]byte, fatSectors*sectorSize)
	for i := 0; i < len(fat)/4; i++ {
		binary.LittleEndian.PutUint32(fat[i*4:], f4FreeSector)
	}
	putFAT := func(sector int, value uint32) { binary.LittleEndian.PutUint32(fat[sector*4:], value) }
	for i := 0; i < fatSectors; i++ {
		putFAT(i, fatSector)
	}
	for i := 0; i < dirSectors; i++ {
		sector := firstDirSector + i
		if i+1 == dirSectors {
			putFAT(sector, endOfChain)
		} else {
			putFAT(sector, uint32(sector+1))
		}
	}
	for _, placed := range placements {
		for i := 0; i < placed.sectors; i++ {
			sector := int(placed.start) + i
			if i+1 == placed.sectors {
				putFAT(sector, endOfChain)
			} else {
				putFAT(sector, uint32(sector+1))
			}
		}
	}

	directory := make([]byte, dirSectors*sectorSize)
	for i, entry := range entries {
		out := directory[i*dirEntrySz : (i+1)*dirEntrySz]
		name := utf16le(entry.name)
		copy(out[:64], name)
		binary.LittleEndian.PutUint16(out[64:], uint16(len(name)))
		out[66] = entry.mse
		binary.LittleEndian.PutUint32(out[68:], f4FreeSector)
		binary.LittleEndian.PutUint32(out[72:], f4FreeSector)
		binary.LittleEndian.PutUint32(out[76:], f4FreeSector)
		if i == 0 {
			copy(out[80:96], rootCLSID[:])
			if len(entries) > 1 {
				binary.LittleEndian.PutUint32(out[76:], 1)
			}
		}
		binary.LittleEndian.PutUint32(out[116:], placements[i].start)
		binary.LittleEndian.PutUint64(out[120:], uint64(len(entry.data)))
	}

	var fixture bytes.Buffer
	fixture.Write(header)
	fixture.Write(fat)
	fixture.Write(directory)
	for i, entry := range entries {
		if placements[i].sectors == 0 {
			continue
		}
		padded := make([]byte, placements[i].sectors*sectorSize)
		copy(padded, entry.data)
		fixture.Write(padded)
	}
	return fixture.Bytes()
}

func f4OLE(t *testing.T, fixture []byte) *oleparse.OLEFile {
	t.Helper()
	ole, err := oleparse.NewOLEFile(fixture)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	return ole
}

func TestVALF4MSIContentCap(t *testing.T) {
	marker := []byte("VAL-F4-MSI-TAIL")
	run := func(count int) *Result {
		entries := []cfbEntry{{name: "Root Entry", mse: 5}}
		for i := 0; i < count; i++ {
			payload := []byte(fmt.Sprintf("ordinary-msi-stream-%03d", i))
			if i+1 == count {
				payload = marker
			}
			entries = append(entries, cfbEntry{name: fmt.Sprintf("stream-%03d", i), mse: 2, data: payload})
		}
		res := &Result{}
		if !fromMSI(f4OLE(t, buildF4CFB(t, entries, msiRootCLSID)), res, time.Time{}) {
			t.Fatal("MSI fixture not recognized")
		}
		return res
	}
	boundary := run(maxMSIStreams)
	if !f4HasBytes(boundary, marker) || f4HasCap(boundary, "msi-streams") {
		t.Fatalf("exact cap: tail=%v caps=%v", f4HasBytes(boundary, marker), boundary.CapHits)
	}
	over := run(maxMSIStreams + 1)
	if f4HasBytes(over, marker) || !f4HasCap(over, "msi-streams") {
		t.Fatalf("one over: tail=%v caps=%v", f4HasBytes(over, marker), over.CapHits)
	}
	nonMSI := &Result{}
	if fromMSI(f4OLE(t, buildF4CFB(t, []cfbEntry{{name: "Root Entry", mse: 5}, {name: "payload", mse: 2, data: marker}}, [16]byte{})), nonMSI, time.Time{}) || len(nonMSI.CapHits) != 0 {
		t.Fatalf("non-MSI input accepted or marked incomplete: caps=%v", nonMSI.CapHits)
	}
	fresh := run(1)
	if !f4HasBytes(fresh, marker) || len(fresh.CapHits) != 0 {
		t.Fatalf("fresh request inherited incompleteness: tail=%v caps=%v", f4HasBytes(fresh, marker), fresh.CapHits)
	}
}

func TestVALF4MSGContentCap(t *testing.T) {
	marker := []byte("VAL-F4-MSG-TAIL")
	run := func(count int, eligible bool) *Result {
		entries := []cfbEntry{{name: "Root Entry", mse: 5}, {name: msgPropsStream, mse: 2, data: []byte("props")}, {name: msgAttachPrefix + "00000000", mse: 1}}
		for i := 0; i < count; i++ {
			name := msgAttachData1
			if !eligible {
				name = "malformed-attachment-data"
			}
			payload := []byte(fmt.Sprintf("ordinary-msg-attachment-%03d", i))
			if i+1 == count {
				payload = marker
			}
			entries = append(entries, cfbEntry{name: name, mse: 2, data: payload})
		}
		res := &Result{}
		if !fromMSG(f4OLE(t, buildF4CFB(t, entries, [16]byte{})), res, &archiveBudget{}, 0, time.Time{}) {
			t.Fatal("MSG fixture not recognized")
		}
		return res
	}
	boundary := run(maxMSGAttachments, true)
	if !f4HasBytes(boundary, marker) || f4HasCap(boundary, "msg-attachments") {
		t.Fatalf("exact cap: tail=%v caps=%v", f4HasBytes(boundary, marker), boundary.CapHits)
	}
	over := run(maxMSGAttachments+1, true)
	if f4HasBytes(over, marker) || !f4HasCap(over, "msg-attachments") {
		t.Fatalf("one over: tail=%v caps=%v", f4HasBytes(over, marker), over.CapHits)
	}
	malformed := run(maxMSGAttachments+1, false)
	if len(malformed.Streams) != 0 || len(malformed.CapHits) != 0 {
		t.Fatalf("ineligible streams marked incomplete: streams=%d caps=%v", len(malformed.Streams), malformed.CapHits)
	}
	if fresh := run(1, true); !f4HasBytes(fresh, marker) || len(fresh.CapHits) != 0 {
		t.Fatalf("fresh request inherited incompleteness: tail=%v caps=%v", f4HasBytes(fresh, marker), fresh.CapHits)
	}
}

func TestVALF4OLEPackageContentCap(t *testing.T) {
	marker := []byte("VAL-F4-OLEPACKAGE-TAIL")
	run := func(count int, valid bool) *Result {
		entries := []cfbEntry{{name: "Root Entry", mse: 5}}
		for i := 0; i < count; i++ {
			payload := []byte(fmt.Sprintf("ordinary-package-%03d", i))
			if i+1 == count {
				payload = marker
			}
			stream := buildOle10Native("x", "x", "x", payload, 0)
			if !valid {
				stream = []byte{0, 0, 0, 0, 2, 0}
			}
			entries = append(entries, cfbEntry{name: fmt.Sprintf("%03d-%s", i, ole10NativeSuffix), mse: 2, data: stream})
		}
		res := &Result{}
		if !fromOLEPackage(f4OLE(t, buildF4CFB(t, entries, [16]byte{})), res, &archiveBudget{}, 0, time.Time{}) {
			t.Fatal("OLE Package fixture not recognized")
		}
		return res
	}
	boundary := run(maxPackageObjects, true)
	if !f4HasBytes(boundary, marker) || f4HasCap(boundary, "ole-package-objects") {
		t.Fatalf("exact cap: tail=%v caps=%v", f4HasBytes(boundary, marker), boundary.CapHits)
	}
	over := run(maxPackageObjects+1, true)
	if f4HasBytes(over, marker) || !f4HasCap(over, "ole-package-objects") {
		t.Fatalf("one over: tail=%v caps=%v", f4HasBytes(over, marker), over.CapHits)
	}
	malformed := run(maxPackageObjects+1, false)
	if len(malformed.Streams) != 0 || len(malformed.CapHits) != 0 {
		t.Fatalf("malformed objects marked incomplete: streams=%d caps=%v", len(malformed.Streams), malformed.CapHits)
	}
	if fresh := run(1, true); !f4HasBytes(fresh, marker) || len(fresh.CapHits) != 0 {
		t.Fatalf("fresh request inherited incompleteness: tail=%v caps=%v", f4HasBytes(fresh, marker), fresh.CapHits)
	}
}

func f4VBAProject(t *testing.T) []byte {
	t.Helper()
	fixture := readFixture(t, "xlswithmacro.xlsm")
	zr, err := zip.NewReader(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range zr.File {
		if entry.Name == "xl/vbaProject.bin" {
			return readZipEntry(entry)
		}
	}
	t.Fatal("fixture has no VBA project")
	return nil
}

func TestVALF4PPTContentCap(t *testing.T) {
	valid := pptRecord(0, 0, pptRecTypeExternalObjectStorage, f4VBAProject(t))
	invalid := pptRecord(0, 0, pptRecTypeExternalObjectStorage, []byte("not-an-ole"))
	runBlobs := func(invalidCount int) *Result {
		data := bytes.Repeat(invalid, invalidCount)
		data = append(data, valid...)
		fixture := buildF4CFB(t, []cfbEntry{{name: "Root Entry", mse: 5}, {name: "PowerPoint Document", mse: 2, data: data}}, [16]byte{})
		res := &Result{}
		fromPPTVBA(f4OLE(t, fixture), res, time.Now().Add(time.Minute))
		return res
	}
	boundary := runBlobs(maxPPTVBABlobs - 1)
	if !f4HasBytes(boundary, []byte("PPT-VBA-EXTRACTED")) || f4HasCap(boundary, "ppt-vba") {
		t.Fatalf("exact blob cap: marker=%v caps=%v", f4HasBytes(boundary, []byte("PPT-VBA-EXTRACTED")), boundary.CapHits)
	}
	over := runBlobs(maxPPTVBABlobs)
	if f4HasBytes(over, []byte("PPT-VBA-EXTRACTED")) || !f4HasCap(over, "ppt-vba") {
		t.Fatalf("one over blob cap: marker=%v caps=%v", f4HasBytes(over, []byte("PPT-VBA-EXTRACTED")), over.CapHits)
	}
	malformedFixture := buildF4CFB(t, []cfbEntry{{name: "Root Entry", mse: 5}, {name: "PowerPoint Document", mse: 2, data: invalid}}, [16]byte{})
	malformed := &Result{}
	fromPPTVBA(f4OLE(t, malformedFixture), malformed, time.Now().Add(time.Minute))
	if f4HasBytes(malformed, []byte("PPT-VBA-EXTRACTED")) || len(malformed.CapHits) != 0 {
		t.Fatalf("malformed EOS marked incomplete: marker=%v caps=%v", f4HasBytes(malformed, []byte("PPT-VBA-EXTRACTED")), malformed.CapHits)
	}
	ordinary := pptRecord(0, 0, 0x1000, []byte("ordinary"))
	recordData := bytes.Repeat(ordinary, maxPPTRecords)
	recordData = append(recordData, valid...)
	recordFixture := buildF4CFB(t, []cfbEntry{{name: "Root Entry", mse: 5}, {name: "PowerPoint Document", mse: 2, data: recordData}}, [16]byte{})
	records := &Result{}
	fromPPTVBA(f4OLE(t, recordFixture), records, time.Now().Add(time.Minute))
	if f4HasBytes(records, []byte("PPT-VBA-EXTRACTED")) || !f4HasCap(records, "ppt-vba") {
		t.Fatalf("record tail: marker=%v caps=%v", f4HasBytes(records, []byte("PPT-VBA-EXTRACTED")), records.CapHits)
	}
	fresh := runBlobs(0)
	if !f4HasBytes(fresh, []byte("PPT-VBA-EXTRACTED")) || len(fresh.CapHits) != 0 {
		t.Fatalf("fresh request inherited incompleteness: marker=%v caps=%v", f4HasBytes(fresh, []byte("PPT-VBA-EXTRACTED")), fresh.CapHits)
	}
}

func buildF4TNEF(parts int, marker []byte) []byte {
	const (
		levelAttachment = 0x02
		attachRendData  = 0x9002
		attachData      = 0x800f
	)
	blob := []byte{0x78, 0x9F, 0x3E, 0x22, 0, 0}
	for i := 0; i < parts; i++ {
		payload := []byte(fmt.Sprintf("ordinary-tnef-part-%03d", i))
		if i+1 == parts {
			payload = marker
		}
		blob = append(blob, tnefObj(levelAttachment, attachRendData, []byte{0})...)
		blob = append(blob, tnefObj(levelAttachment, attachData, payload)...)
	}
	return blob
}

func TestVALF4TNEFContentCap(t *testing.T) {
	marker := []byte("VAL-F4-TNEF-TAIL")
	run := func(parts int) *Result {
		res := &Result{}
		fromTNEF(buildF4TNEF(parts, marker), res, nil, 0, time.Time{})
		return res
	}
	boundary := run(maxTNEFParts)
	if !f4HasBytes(boundary, marker) || f4HasCap(boundary, "tnef-parts") {
		t.Fatalf("exact cap: tail=%v caps=%v", f4HasBytes(boundary, marker), boundary.CapHits)
	}
	over := run(maxTNEFParts + 1)
	if f4HasBytes(over, marker) || !f4HasCap(over, "tnef-parts") {
		t.Fatalf("one over: tail=%v caps=%v", f4HasBytes(over, marker), over.CapHits)
	}
	malformed := &Result{}
	fromTNEF([]byte{0x78, 0x9F, 0x3E, 0x22, 0, 0, 2}, malformed, nil, 0, time.Time{})
	if len(malformed.Streams) != 0 || len(malformed.CapHits) != 0 {
		t.Fatalf("malformed TNEF marked incomplete: streams=%d caps=%v", len(malformed.Streams), malformed.CapHits)
	}
	if fresh := run(1); !f4HasBytes(fresh, marker) || len(fresh.CapHits) != 0 {
		t.Fatalf("fresh request inherited incompleteness: tail=%v caps=%v", f4HasBytes(fresh, marker), fresh.CapHits)
	}
}

func TestVALF4OneNoteContentCap(t *testing.T) {
	marker := []byte("VAL-F4-ONENOTE-COMPRESSED-TAIL")
	tail := buildZip(t, map[string][]byte{"sole-detection.txt": marker})
	if bytes.Contains(tail, marker) {
		t.Fatal("compressed tail exposes the detection marker without recursion")
	}
	run := func(count int) *Result {
		var body bytes.Buffer
		for i := 0; i < count; i++ {
			payload := []byte(fmt.Sprintf("ordinary-onenote-object-%03d", i))
			if i+1 == count {
				payload = tail
			}
			body.Write(buildFDSO(payload, 0))
		}
		res := &Result{}
		fromOneNote(buildOneNote(body.Bytes()), res, &archiveBudget{}, 0, time.Time{})
		return res
	}
	for _, count := range []int{maxONEFiles - 1, maxONEFiles} {
		res := run(count)
		if !f4HasBytes(res, marker) || f4HasCap(res, "onenote-files") {
			t.Fatalf("%d objects: compressed tail=%v caps=%v", count, f4HasBytes(res, marker), res.CapHits)
		}
	}
	over := run(maxONEFiles + 1)
	if f4HasBytes(over, marker) || !f4HasCap(over, "onenote-files") {
		t.Fatalf("one over: compressed tail=%v caps=%v", f4HasBytes(over, marker), over.CapHits)
	}
}
