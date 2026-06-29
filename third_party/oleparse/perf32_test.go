package oleparse

// PERF-32: tests for name index (O(1) FindStreamByName) and bounded stream cache.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// utf16leEncode encodes a short ASCII string as UTF-16LE for the OLE directory.
func utf16leEncode(s string) []byte {
	out := make([]byte, len(s)*2)
	for i, c := range s {
		out[i*2] = byte(c)
		out[i*2+1] = 0
	}
	return out
}

// miniOLE builds a minimal valid OLE2 compound file in memory containing the
// given named streams.  Each stream's content is padded to ≥ miniCutoff bytes
// so it lives in the regular FAT (no mini-stream needed).
//
// Layout: header (512) | FAT sector (512) | dir sector(s) (512 each) | stream data
func miniOLE(t testing.TB, streams map[string][]byte) []byte {
	t.Helper()
	const (
		sz         = 512  // sector size (version 3)
		miniCutoff = 4096 // same as OLEHeader.MiniSectorCutoff default
		dirEntSz   = 128  // directory entry size
		endOfChain = uint32(0xFFFFFFFE)
		fatSect    = uint32(0xFFFFFFFD)
		freeSect   = uint32(0xFFFFFFFF)
	)

	// Build ordered list: root first, then streams.
	type entry struct {
		name string
		data []byte
		mse  byte // 5 = root, 2 = stream
	}
	entries := []entry{{name: "Root Entry", mse: 5}}
	for name, data := range streams {
		padded := make([]byte, len(data))
		copy(padded, data)
		if len(padded) < miniCutoff {
			padded = append(padded, make([]byte, miniCutoff-len(padded))...)
		}
		entries = append(entries, entry{name: name, data: padded, mse: 2})
	}

	// Directory sectors required (4 entries per 512-byte sector).
	dirSectors := (len(entries)*dirEntSz + sz - 1) / sz
	firstDirSect := 1 // sector 0 = FAT
	nextSect := firstDirSect + dirSectors

	type placed struct {
		start uint32
		secs  int
	}
	pl := make([]placed, len(entries))
	for i, e := range entries {
		if e.mse != 2 {
			pl[i] = placed{start: endOfChain}
			continue
		}
		n := (len(e.data) + sz - 1) / sz
		pl[i] = placed{start: uint32(nextSect), secs: n}
		nextSect += n
	}

	// --- header ---
	hdr := make([]byte, sz)
	copy(hdr[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(hdr[24:], 0x3E) // MinorVersion
	binary.LittleEndian.PutUint16(hdr[26:], 3)    // MajorVersion
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(hdr[30:], 9) // SectorShift → 512
	binary.LittleEndian.PutUint16(hdr[32:], 6) // MiniSectorShift → 64
	binary.LittleEndian.PutUint32(hdr[44:], 1) // CsectFat
	binary.LittleEndian.PutUint32(hdr[48:], uint32(firstDirSect))
	binary.LittleEndian.PutUint32(hdr[56:], miniCutoff)
	binary.LittleEndian.PutUint32(hdr[60:], endOfChain) // SectMiniFatStart (none)
	binary.LittleEndian.PutUint32(hdr[68:], endOfChain) // SectDifStart (none)
	binary.LittleEndian.PutUint32(hdr[76:], 0)          // SectFat[0] = sector 0

	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(hdr[76+i*4:], freeSect)
	}

	// --- FAT (sector 0) ---
	fat := make([]byte, sz)
	put := func(idx int, v uint32) { binary.LittleEndian.PutUint32(fat[idx*4:], v) }
	for i := 0; i < sz/4; i++ {
		put(i, freeSect)
	}
	put(0, fatSect) // sector 0 is the FAT sector itself
	for i := 0; i < dirSectors; i++ {
		s := firstDirSect + i
		if i == dirSectors-1 {
			put(s, endOfChain)
		} else {
			put(s, uint32(s+1))
		}
	}
	for _, p := range pl {
		if p.start == endOfChain {
			continue
		}
		for i := 0; i < p.secs; i++ {
			s := int(p.start) + i
			if i == p.secs-1 {
				put(s, endOfChain)
			} else {
				put(s, uint32(s+1))
			}
		}
	}

	// --- directory ---
	dir := make([]byte, dirSectors*sz)
	for i, e := range entries {
		b := dir[i*dirEntSz : (i+1)*dirEntSz]
		u := utf16leEncode(e.name)
		copy(b[0:64], u)
		binary.LittleEndian.PutUint16(b[64:], uint16(len(u)))
		b[66] = e.mse
		binary.LittleEndian.PutUint32(b[68:], freeSect) // SidLeftSib
		binary.LittleEndian.PutUint32(b[72:], freeSect) // SidRightSib
		if e.mse == 5 && len(entries) > 1 {
			binary.LittleEndian.PutUint32(b[76:], 1) // root's child = entry 1
		} else {
			binary.LittleEndian.PutUint32(b[76:], freeSect)
		}
		binary.LittleEndian.PutUint32(b[116:], pl[i].start)
		binary.LittleEndian.PutUint32(b[120:], uint32(len(e.data)))
	}

	// --- stream data ---
	var data bytes.Buffer
	for i, e := range entries {
		if e.mse != 2 {
			continue
		}
		padded := make([]byte, pl[i].secs*sz)
		copy(padded, e.data)
		data.Write(padded)
	}

	var out bytes.Buffer
	out.Write(hdr)
	out.Write(fat)
	out.Write(dir)
	out.Write(data.Bytes())
	return out.Bytes()
}

// --- Part 1: name index tests ---

// TestFindStreamByName_Hit verifies O(1) lookup returns the correct Directory.
func TestFindStreamByName_Hit(t *testing.T) {
	want := []byte("hello world content PERF32 test")
	buf := miniOLE(t, map[string][]byte{"Workbook": want})
	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	d := ole.FindStreamByName("Workbook")
	if d == nil {
		t.Fatal("FindStreamByName returned nil for existing stream")
	}
	// Confirm the stream data matches.
	data := ole.GetStream(d.Index)
	if !bytes.HasPrefix(data, want) {
		t.Errorf("stream content mismatch: got %q, want prefix %q", data[:min(len(data), len(want))], want)
	}
}

// TestFindStreamByName_Miss verifies nil is returned for absent names.
func TestFindStreamByName_Miss(t *testing.T) {
	buf := miniOLE(t, map[string][]byte{"Alpha": []byte("data")})
	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	if d := ole.FindStreamByName("NonExistent"); d != nil {
		t.Errorf("expected nil, got %+v", d)
	}
}

// TestFindStreamByName_KeepFirst checks that when the Directory contains two
// entries with the same Name (malformed OLE), FindStreamByName returns the
// FIRST one — identical to the pre-index linear scan behaviour.
//
// We synthesise this by directly manipulating the OLEFile after construction.
func TestFindStreamByName_KeepFirst(t *testing.T) {
	buf := miniOLE(t, map[string][]byte{"Alpha": []byte("first"), "Beta": []byte("second")})
	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	// Find the "Alpha" directory entry index so we can duplicate its name.
	alphaD := ole.FindStreamByName("Alpha")
	if alphaD == nil {
		t.Fatal("Alpha stream not found; cannot run keep-first test")
	}

	// Insert a second Directory entry with name "Alpha" at the end.
	duplicate := &Directory{
		Index: uint32(len(ole.Directory)),
		Name:  "Alpha",
	}
	duplicate.Header.Mse = 2
	ole.Directory = append(ole.Directory, duplicate)

	// Rebuild the name index as NewOLEFile would: keep-first.
	ole.nameIdx = make(map[string]*Directory, len(ole.Directory))
	for _, d := range ole.Directory {
		if d == nil {
			continue
		}
		if _, exists := ole.nameIdx[d.Name]; !exists {
			ole.nameIdx[d.Name] = d
		}
	}

	got := ole.FindStreamByName("Alpha")
	if got == nil {
		t.Fatal("FindStreamByName returned nil after duplicate injection")
	}
	if got.Index != alphaD.Index {
		t.Errorf("keep-first violated: got index %d, want %d (first entry)", got.Index, alphaD.Index)
	}
}

// --- Part 2: stream cache tests ---

// TestGetStream_CacheHit verifies repeated reads return byte-identical results.
func TestGetStream_CacheHit(t *testing.T) {
	content := []byte("stream cache test content PERF32")
	buf := miniOLE(t, map[string][]byte{"Workbook": content})
	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	d := ole.FindStreamByName("Workbook")
	if d == nil {
		t.Fatal("Workbook not found")
	}

	first := ole.GetStream(d.Index)
	second := ole.GetStream(d.Index)

	if !bytes.Equal(first, second) {
		t.Errorf("cache hit returned different bytes: first len=%d second len=%d", len(first), len(second))
	}
	if !bytes.HasPrefix(first, content) {
		t.Errorf("stream content mismatch: got prefix %q, want %q", first[:min(len(first), len(content))], content)
	}
}

// TestGetStream_TwoStreams verifies different indices return their own bytes.
func TestGetStream_TwoStreams(t *testing.T) {
	aData := []byte("stream-A data PERF32")
	bData := []byte("stream-B data PERF32 DIFFERENT")
	buf := miniOLE(t, map[string][]byte{"Alpha": aData, "Beta": bData})
	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	da := ole.FindStreamByName("Alpha")
	db := ole.FindStreamByName("Beta")
	if da == nil || db == nil {
		t.Fatal("Alpha or Beta not found")
	}
	gotA := ole.GetStream(da.Index)
	gotB := ole.GetStream(db.Index)

	if bytes.Equal(gotA, gotB) {
		t.Error("two distinct streams returned identical bytes — cache aliasing bug")
	}
	if !bytes.HasPrefix(gotA, aData) {
		t.Errorf("Alpha content wrong: got prefix %q, want %q", gotA[:min(len(gotA), len(aData))], aData)
	}
	if !bytes.HasPrefix(gotB, bData) {
		t.Errorf("Beta content wrong: got prefix %q, want %q", gotB[:min(len(gotB), len(bData))], bData)
	}
}

// TestGetStream_LargeStreamUncached verifies a stream > streamCacheMaxSize is
// returned correctly even though it bypasses the cache.
func TestGetStream_LargeStreamUncached(t *testing.T) {
	// Build a stream that is definitely larger than streamCacheMaxSize (4096).
	large := make([]byte, streamCacheMaxSize+1)
	for i := range large {
		large[i] = byte(i & 0xFF)
	}
	buf := miniOLE(t, map[string][]byte{"BigStream": large})
	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	d := ole.FindStreamByName("BigStream")
	if d == nil {
		t.Fatal("BigStream not found")
	}
	got := ole.GetStream(d.Index)
	if !bytes.HasPrefix(got, large) {
		t.Errorf("large stream content wrong: first bytes differ")
	}
	// Must NOT be in cache (size > cap).
	if _, cached := ole.streamCache[d.Index]; cached {
		t.Error("large stream was incorrectly stored in the cache")
	}
	// Second call also correct.
	got2 := ole.GetStream(d.Index)
	if !bytes.Equal(got, got2) {
		t.Error("second call to large-stream GetStream returned different bytes")
	}
}

func TestGetStreamPrefixDoesNotPoisonFullRead(t *testing.T) {
	content := bytes.Repeat([]byte("prefix-safe-"), 600)
	buf := miniOLE(t, map[string][]byte{"Workbook": content})
	ole, err := NewOLEFile(buf)
	if err != nil {
		t.Fatalf("NewOLEFile: %v", err)
	}
	d := ole.FindStreamByName("Workbook")
	if d == nil {
		t.Fatal("Workbook not found")
	}

	prefix := ole.GetStreamPrefix(d.Index, 32)
	if len(prefix) != 32 {
		t.Fatalf("prefix len = %d, want 32", len(prefix))
	}
	if !bytes.Equal(prefix, content[:32]) {
		t.Fatalf("prefix content = %q, want %q", prefix, content[:32])
	}
	if _, cached := ole.streamCache[d.Index]; cached {
		t.Fatal("prefix-only read populated the full-stream cache")
	}

	full := ole.GetStream(d.Index)
	if !bytes.HasPrefix(full, content) {
		t.Fatalf("full read after prefix lost data: got prefix %q, want %q", full[:min(len(full), len(content))], content)
	}
}

// --- Benchmarks ---

// BenchmarkFindStreamByName compares index lookup vs linear scan on an OLE with
// multiple streams.
func BenchmarkFindStreamByName(b *testing.B) {
	streams := map[string][]byte{
		"Workbook":         []byte("wb data"),
		"WordDocument":     []byte("wd data"),
		"EncryptionInfo":   []byte("ei data"),
		"EncryptedPackage": []byte("ep data"),
		"dir":              []byte("dir data"),
	}
	buf := miniOLE(b, streams)
	ole, err := NewOLEFile(buf)
	if err != nil {
		b.Fatalf("NewOLEFile: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ole.FindStreamByName("Workbook")
		_ = ole.FindStreamByName("dir")
		_ = ole.FindStreamByName("NonExistent")
	}
}

// BenchmarkGetStream_Cached measures the cost of a cache-hit GetStream call.
func BenchmarkGetStream_Cached(b *testing.B) {
	buf := miniOLE(b, map[string][]byte{"Workbook": []byte("wb content")})
	ole, err := NewOLEFile(buf)
	if err != nil {
		b.Fatalf("NewOLEFile: %v", err)
	}
	d := ole.FindStreamByName("Workbook")
	if d == nil {
		b.Fatal("Workbook not found")
	}
	// Warm the cache.
	_ = ole.GetStream(d.Index)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ole.GetStream(d.Index)
	}
}

func BenchmarkGetStreamView_Cached(b *testing.B) {
	buf := miniOLE(b, map[string][]byte{"Workbook": []byte("wb content")})
	ole, err := NewOLEFile(buf)
	if err != nil {
		b.Fatalf("NewOLEFile: %v", err)
	}
	d := ole.FindStreamByName("Workbook")
	if d == nil {
		b.Fatal("Workbook not found")
	}
	_ = ole.GetStream(d.Index)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ole.GetStreamView(d.Index)
	}
}
