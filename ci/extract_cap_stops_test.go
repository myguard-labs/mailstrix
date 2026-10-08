package ci_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nwaples/rardecode/v2"

	"github.com/myguard-labs/mailstrix/internal/extract"
	"github.com/myguard-labs/mailstrix/internal/mailstrix"
	yekazip "github.com/yeka/zip"
)

// Cap values mirrored from internal/extract; a drift shows up as a failing
// boundary control rather than a silent pass.
const (
	capMember = 16 << 20
	capBin    = 8 << 20
	// capStreams mirrors maxStreams (internal/extract/extract.go).
	capStreams = 256
)

func capHasHit(res extract.Result, kind string) bool {
	for _, k := range res.CapHits {
		if k == kind {
			return true
		}
	}
	return false
}

func capZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Sorted creation is not needed; each entry is independent.
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func capFill(n int) []byte {
	b := bytes.Repeat([]byte("A"), n)
	return b
}

func capExtract(buf []byte) extract.Result {
	return extract.Extract(buf, time.Time{})
}

func TestCapStopMemberSize(t *testing.T) {
	// A tar member's own size can only exceed the cap once its gzip wrapper was
	// truncated (header and trailer add 1.5 KiB), so the in-cap control sits
	// below the cap and the over-cap case at it.
	tarOf := func(size int) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		if err := tw.WriteHeader(&tar.Header{Name: "m.bin", Mode: 0o600, Size: int64(size), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(capFill(size)); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		var gz bytes.Buffer
		gw := gzip.NewWriter(&gz)
		_, _ = gw.Write(b.Bytes())
		_ = gw.Close()
		return gz.Bytes()
	}
	officeBin := func(size int) []byte {
		return capZip(t, map[string][]byte{
			"[Content_Types].xml": []byte("<Types/>"),
			"word/document.xml":   []byte("<w:document>body</w:document>"),
			"word/vbaProject.bin": capFill(size),
		})
	}
	officeSibling := func(size int) []byte {
		return capZip(t, map[string][]byte{
			"[Content_Types].xml": []byte("<Types/>"),
			"word/document.xml":   []byte("<w:document>body</w:document>"),
			"payload.dat":         append([]byte("PK\x03\x04"), capFill(size-4)...),
		})
	}
	officeNonCarrier := func(size int) []byte {
		return capZip(t, map[string][]byte{
			"[Content_Types].xml": []byte("<Types/>"),
			"word/document.xml":   []byte("<w:document>body</w:document>"),
			"payload.dat":         capFill(size),
		})
	}
	cases := []struct {
		name string
		buf  func(int) []byte
		cap  int
		off  int // added to cap for the in-cap control
	}{
		{"zip", func(n int) []byte { return capZip(t, map[string][]byte{"m.bin": capFill(n)}) }, capMember, 0},
		{"tar.gz", tarOf, capMember, -4096},
		{"office-bin", officeBin, capBin, 0},
		{"office-carrier", officeSibling, capBin, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/at-cap-no-hit", func(t *testing.T) {
			if res := capExtract(tc.buf(tc.cap + tc.off)); capHasHit(res, "member-size") {
				t.Fatalf("member exactly at cap flagged: %v", res.CapHits)
			}
		})
		t.Run(tc.name+"/over-cap-hit", func(t *testing.T) {
			over := tc.cap + 1
			if tc.off != 0 {
				over = tc.cap
			}
			if res := capExtract(tc.buf(over)); !capHasHit(res, "member-size") {
				t.Fatalf("oversize member not recorded: %v", res.CapHits)
			}
		})
	}
	// Negative control: an oversize NON-carrier Office sibling is ignored by
	// design (like a small one), so it must not make the document incomplete.
	if res := capExtract(officeNonCarrier(capBin + 1)); capHasHit(res, "member-size") {
		t.Fatalf("oversize non-carrier office sibling flagged: %v", res.CapHits)
	}
	// An at-cap zip member is still scanned (not skipped).
	res := capExtract(capZip(t, map[string][]byte{"m.bin": capFill(capMember)}))
	found := false
	for _, s := range res.Streams {
		found = found || len(s) == capMember
	}
	if !found {
		t.Fatal("member at the cap was not emitted")
	}
}

// The bomb forms never declare the size honestly: gzip exposes none and a zip
// can understate it in the central directory. Both must report truncation.
func TestCapStopTruncatedMember(t *testing.T) {
	gz := func(n int) []byte {
		var b bytes.Buffer
		gw := gzip.NewWriter(&b)
		_, _ = gw.Write(append(capFill(n-6), []byte("MARKER")...))
		_ = gw.Close()
		return b.Bytes()
	}
	understated := func(n int) []byte {
		z := capZip(t, map[string][]byte{"m.bin": append(capFill(n-6), []byte("MARKER")...)})
		i := bytes.Index(z, []byte("PK\x01\x02"))
		if i < 0 {
			t.Fatal("no central directory")
		}
		binary.LittleEndian.PutUint32(z[i+24:], 1024) // declared uncompressed size
		return z
	}
	for name, mk := range map[string]func(int) []byte{"gzip": gz, "understated-zip": understated} {
		t.Run(name+"/control-15MiB", func(t *testing.T) {
			if res := capExtract(mk(15 << 20)); capHasHit(res, "member-size") {
				t.Fatalf("in-cap stream flagged: %v", res.CapHits)
			}
		})
		t.Run(name+"/exact-cap", func(t *testing.T) {
			if res := capExtract(mk(capMember)); capHasHit(res, "member-size") {
				t.Fatalf("stream of exactly the cap flagged: %v", res.CapHits)
			}
		})
		t.Run(name+"/over-cap", func(t *testing.T) {
			res := capExtract(mk(capMember + 100))
			// archive/zip itself fails a read that outruns the central-directory
			// size, so the understated zip is bounded by the stdlib and surfaces
			// as a read error, not a cap stop; only the gzip form must record.
			if name == "gzip" && !capHasHit(res, "member-size") {
				t.Fatalf("truncated stream not recorded: %v", res.CapHits)
			}
			for _, s := range res.Streams {
				if len(s) > capMember {
					t.Fatalf("stream %d exceeds the cap", len(s))
				}
			}
		})
	}
}

func capNestedZips(t *testing.T, n int) []byte {
	t.Helper()
	cur := []byte("innermost payload text")
	for i := 0; i < n; i++ {
		cur = capZip(t, map[string][]byte{fmt.Sprintf("l%d.zip", i): cur})
	}
	return cur
}

func TestCapStopNestedDepth(t *testing.T) {
	if res := capExtract(capNestedZips(t, 7)); capHasHit(res, "depth") {
		t.Fatalf("7 nested zips (within depth) flagged: %v", res.CapHits)
	}
	if res := capExtract(capNestedZips(t, 8)); !capHasHit(res, "depth") {
		t.Fatalf("8 nested zips not recorded: %v", res.CapHits)
	}
	// Negative control: a deep chain ending in a non-container leaves nothing
	// unwalked, and empty / garbage buffers never panic or flag.
	for _, buf := range [][]byte{nil, {}, []byte("PK\x03\x04"), append([]byte("PK\x03\x04"), capFill(64)...)} {
		if res := capExtract(buf); capHasHit(res, "depth") {
			t.Fatalf("malformed input flagged depth: %v", res.CapHits)
		}
	}
}

func capMIME(parts int) []byte {
	var b strings.Builder
	b.WriteString("From: a@example.com\r\nTo: b@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n")
	for i := 0; i < parts; i++ {
		fmt.Fprintf(&b, "--BND\r\nContent-Type: text/plain\r\n\r\npart body number %d\r\n", i)
	}
	b.WriteString("--BND--\r\n")
	return []byte(b.String())
}

func capMIMENested(levels int) []byte {
	var b strings.Builder
	b.WriteString("From: a@example.com\r\nTo: b@example.com\r\nMIME-Version: 1.0\r\n")
	for i := 0; i < levels; i++ {
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"B%d\"\r\n\r\n--B%d\r\n", i, i)
	}
	b.WriteString("Content-Type: text/plain\r\n\r\nleaf text body\r\n")
	for i := levels - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--B%d--\r\n", i)
	}
	return []byte(b.String())
}

func TestCapStopMIMEParts(t *testing.T) {
	for _, n := range []int{1, 255, 256} {
		if res := capExtract(capMIME(n)); capHasHit(res, "mime-parts") {
			t.Fatalf("%d parts flagged: %v", n, res.CapHits)
		}
	}
	for _, n := range []int{257, 300} {
		if res := capExtract(capMIME(n)); !capHasHit(res, "mime-parts") {
			t.Fatalf("%d parts not recorded: %v", n, res.CapHits)
		}
	}
	// Malformed: missing boundary / truncated body must not panic or flag.
	for _, m := range []string{
		"From: a@b\r\nTo: c@d\r\nContent-Type: multipart/mixed\r\n\r\nbody",
		"From: a@b\r\nTo: c@d\r\nContent-Type: multipart/mixed; boundary=\"X\"\r\n\r\n--X\r\nContent-Type: text",
	} {
		if res := capExtract([]byte(m)); capHasHit(res, "mime-parts") || capHasHit(res, "mime-depth") {
			t.Fatalf("malformed MIME flagged: %v", res.CapHits)
		}
	}
}

func TestCapStopMIMEDepth(t *testing.T) {
	for _, n := range []int{1, 5, 6} {
		if res := capExtract(capMIMENested(n)); capHasHit(res, "mime-depth") {
			t.Fatalf("%d levels flagged: %v", n, res.CapHits)
		}
	}
	for _, n := range []int{7, 8} {
		if res := capExtract(capMIMENested(n)); !capHasHit(res, "mime-depth") {
			t.Fatalf("%d levels not recorded: %v", n, res.CapHits)
		}
	}
}

func TestCapStopMIMEMemberSize(t *testing.T) {
	msg := func(n int) []byte {
		return []byte("From: a@b\r\nTo: c@d\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a.bin\r\n\r\n" + string(capFill(n)) + "\r\n--B--\r\n")
	}
	if res := capExtract(msg(capMember - 2)); capHasHit(res, "member-size") {
		t.Fatalf("in-cap part flagged: %v", res.CapHits)
	}
	if res := capExtract(msg(capMember + 10)); !capHasHit(res, "member-size") {
		t.Fatalf("truncated part not recorded: %v", res.CapHits)
	}
}

// End to end: a scan that dropped an oversize member is incomplete and never
// cached; a small clean zip caches normally.
func TestCapStopScanIncompleteNotCached(t *testing.T) {
	dir := t.TempDir()
	rule := `rule Raw { condition: uint16(0) == 0x4b50 }`
	if err := os.WriteFile(filepath.Join(dir, "cap.yar"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &mailstrix.Config{RulesDir: dir, Effort: 10, EffortMax: 10, Token: "cap-test", CacheTTL: time.Hour, CacheSize: 10, MaxBody: 64 << 20}
	sc, err := mailstrix.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	server := mailstrix.NewServer(cfg, sc)
	post := func(body []byte) {
		r := httptest.NewRequest("POST", "/scan", bytes.NewReader(body))
		r.Header.Set("X-MAILSTRIX-Token", "cap-test")
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	}
	scansFor := func(body []byte) uint64 {
		before := sc.RawChannelScans()
		post(body)
		post(body)
		return sc.RawChannelScans() - before
	}
	big := capZip(t, map[string][]byte{"m.bin": capFill(capMember + 1)})
	small := capZip(t, map[string][]byte{"m.txt": []byte("small clean member")})
	if _, err := sc.Scan(big, mailstrix.ScanMeta{}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("oversize member zip: err = %v, want incomplete", err)
	}
	if _, err := sc.Scan(small, mailstrix.ScanMeta{}); err != nil {
		t.Fatalf("small zip: %v", err)
	}
	if got := scansFor(big); got != 2 {
		t.Fatalf("incomplete scan was cached: %d scans for 2 requests, want 2", got)
	}
	if got := scansFor(small); got != 1 {
		t.Fatalf("clean scan not cached: %d scans for 2 requests, want 1", got)
	}
}

// Content the default branch of extractChild would extract (batch dropper,
// HTML smuggling) is unexamined once the depth limit stops it.
func TestCapStopDepthDefaultContent(t *testing.T) {
	batch := []byte("@echo off\r\n>>\"x.vbs\" echo Set o=CreateObject(\"WScript.Shell\")\r\n>>\"x.vbs\" echo o.Run \"calc\"\r\ncscript x.vbs\r\n")
	html := []byte("<html><script>var b=new Blob([atob('QUJD')]);var a=document.createElement('a');a.download='x.exe';a.click();</script></html>")
	plain := []byte("just some ordinary attached text with nothing to extract in it at all")
	nest := func(payload []byte, n int) []byte {
		cur := payload
		for i := 0; i < n; i++ {
			cur = capZip(t, map[string][]byte{fmt.Sprintf("l%d.zip", i): cur})
		}
		return cur
	}
	for name, p := range map[string][]byte{"batch": batch, "html-smuggling": html} {
		if res := capExtract(nest(p, 6)); capHasHit(res, "depth") {
			t.Fatalf("%s within depth flagged: %v", name, res.CapHits)
		}
		if res := capExtract(nest(p, 7)); !capHasHit(res, "depth") {
			t.Fatalf("%s past depth not recorded: %v", name, res.CapHits)
		}
	}
	if res := capExtract(nest(plain, 7)); capHasHit(res, "depth") {
		t.Fatalf("plain text past depth flagged: %v", res.CapHits)
	}
	// Negative control: the cheap "@echo off" prefilter alone is not content.
	echoOnly := []byte("@echo off\r\nrem nothing is dropped here\r\nexit /b 0\r\n")
	for _, n := range []int{6, 7} {
		if res := capExtract(nest(echoOnly, n)); capHasHit(res, "depth") {
			t.Fatalf("@echo off only (%d nested) flagged depth: %v", n, res.CapHits)
		}
	}
}

// A batch dropper carving more files than the stream cap allows ends with a
// "streams" cap hit instead of a silent clean result.
func TestCapStopBatchDropperStreams(t *testing.T) {
	build := func(n int) []byte {
		var sb strings.Builder
		sb.WriteString("@echo off\r\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, ">>\"f%d.vbs\" echo Set o=CreateObject(\"WScript.Shell\")\r\n", i)
		}
		sb.WriteString("cscript f0.vbs\r\n")
		return []byte(sb.String())
	}
	// Reaching the cap exactly already records "streams": the batch walk fills the
	// stream budget and cannot prove nothing further was carved.
	for _, n := range []int{capStreams - 6, capStreams - 1} {
		if res := capExtract(build(n)); capHasHit(res, "streams") {
			t.Fatalf("%d carved files (below cap %d) flagged: %v", n, capStreams, res.CapHits)
		}
	}
	for _, n := range []int{capStreams, capStreams + 1, capStreams + 4} {
		res := capExtract(build(n))
		if !capHasHit(res, "streams") {
			t.Fatalf("%d carved files (cap %d) not recorded as streams: %v (streams=%d)", n, capStreams, res.CapHits, len(res.Streams))
		}
		if len(res.Streams) > capStreams {
			t.Fatalf("%d carved files emitted %d streams, over cap %d", n, len(res.Streams), capStreams)
		}
	}
}

// Header-encrypted 7z fixtures (password "test"), generated with /usr/bin/7z:
//
//	hdrenc-oversize.7z: 7z a -p'test' -mhe=on -mx=9 hdrenc-oversize.7z asmall.dat zbig.dat   (zbig.dat = 17000000 zero bytes, asmall.dat = "hello-in-cap\n"; the in-cap asmall.dat must sort first, because the crack step validates on the first regular member and skips an oversize one)
//	hdrenc-small.7z:    7z a -p'test' -mhe=on hdrenc-small.7z small.txt          (small.txt = "hello-in-cap\n")
//	hdrenc-dir.7z:      7z a -p'test' -mhe=on hdrenc-dir.7z emptydir             (empty directory only)
func capHdrEnc7z(t *testing.T, name string, cands ...string) extract.Result {
	t.Helper()
	buf, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	opts := extract.FullOptions(time.Time{})
	opts.ArchivePWEnabled = true
	opts.PWCandidates = cands
	return extract.ExtractWithOptions(buf, opts)
}

func TestCapStopHeaderEncrypted7zMemberSize(t *testing.T) {
	t.Run("oversize-records-member-size", func(t *testing.T) {
		res := capHdrEnc7z(t, "hdrenc-oversize.7z", "wrong", "test")
		// DecryptedArchive stays false here (nothing was emitted); the hit itself
		// proves the crack path, since the listing is hidden without the password.
		if !capHasHit(res, "member-size") {
			t.Fatalf("CapHits=%v, want member-size", res.CapHits)
		}
	})
	t.Run("in-cap-no-hit-and-extracted", func(t *testing.T) {
		res := capHdrEnc7z(t, "hdrenc-small.7z", "test")
		if !res.DecryptedArchive || capHasHit(res, "member-size") {
			t.Fatalf("decrypted=%v CapHits=%v", res.DecryptedArchive, res.CapHits)
		}
		if len(res.Streams) == 0 {
			t.Fatal("in-cap member not extracted")
		}
	})
	t.Run("directory-no-hit", func(t *testing.T) {
		res := capHdrEnc7z(t, "hdrenc-dir.7z", "test")
		if capHasHit(res, "member-size") {
			t.Fatalf("directory recorded member-size: %v", res.CapHits)
		}
	})
	t.Run("wrong-password-no-hit", func(t *testing.T) {
		res := capHdrEnc7z(t, "hdrenc-oversize.7z", "wrong")
		if capHasHit(res, "member-size") {
			t.Fatalf("uncracked archive recorded member-size: %v", res.CapHits)
		}
	})
}

// ---- RAR5 in-memory builder (AUD-04c3 / AUD-04c4) ----------------------------
//
// No rar CLI is available, so the tests assemble RAR5 archives by hand following
// rardecode v2.2.5 archive50.go (the parser the extractor uses). Members are
// STORED (compression method 0). The builder is verified against rardecode in
// TestCapRarBuilderSanity before any cap assertion relies on it.

type capRarMember struct {
	name        string
	data        []byte // bytes stored in the data area (already padded when encrypted)
	declared    uint64 // value of the unpacked-size field
	unknownSize bool   // set the "unpacked size unknown" file flag
	password    string // non-empty: AES-256-CBC file encryption record
	plainLen    int    // encrypted only: real length before zero padding
}

func capVint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

// capRarBlock frames a RAR5 block: CRC32 over (size vint + header body), the
// size vint, then the body.
func capRarBlock(body []byte) []byte {
	sized := append(capVint(uint64(len(body))), body...)
	return append(binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(sized)), sized...)
}

// capRarKeys mirrors rardecode calcKeys50: PBKDF2-HMAC-SHA256 split into the
// block key (0), hash key (1) and the 12-byte password check value (2).
func capRarKeys(pass, salt []byte, kdfExp int) (key, check []byte) {
	count := 1 << uint(kdfExp)
	prf := hmac.New(sha256.New, pass)
	prf.Write(salt)
	prf.Write([]byte{0, 0, 0, 1})
	t := prf.Sum(nil)
	u := append([]byte(nil), t...)
	count--
	var keys [3][]byte
	for i, iter := range []int{count, 16, 16} {
		for ; iter > 0; iter-- {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range u {
				t[j] ^= u[j]
			}
		}
		keys[i] = append([]byte(nil), t...)
	}
	pw := keys[2]
	for i, v := range pw[8:] {
		pw[i&7] ^= v
	}
	pw = pw[:8]
	sum := sha256.Sum256(pw)
	return keys[0], append(append([]byte(nil), pw...), sum[:4]...)
}

// capRarEncrypt zero-pads plain to the AES block size and encrypts it, returning
// the ciphertext and the file-encryption extra record (type 1) for it.
func capRarEncrypt(t *testing.T, password string, plain []byte) ([]byte, []byte) {
	t.Helper()
	salt := bytes.Repeat([]byte{0x5a}, 16)
	iv := bytes.Repeat([]byte{0xa5}, 16)
	key, check := capRarKeys([]byte(password), salt, 0)
	padded := append([]byte(nil), plain...)
	if r := len(padded) % 16; r != 0 || len(padded) == 0 {
		padded = append(padded, make([]byte, 16-r)...)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(padded, padded)
	rec := append(capVint(1), capVint(0)...) // record type 1, encryption version 0
	rec = append(rec, capVint(1)...)         // flags: password check present
	rec = append(rec, 0)                     // kdf count exponent
	rec = append(rec, salt...)
	rec = append(rec, iv...)
	rec = append(rec, check...)
	return padded, append(capVint(uint64(len(rec))), rec...)
}

func capRar5(t *testing.T, members ...capRarMember) []byte {
	t.Helper()
	out := []byte("Rar!\x1a\x07\x01\x00")
	out = append(out, capRarBlock(append(append(capVint(1), capVint(0)...), capVint(0)...))...) // main header
	for _, m := range members {
		data := m.data
		var extra []byte
		if m.password != "" {
			data, extra = capRarEncrypt(t, m.password, m.data[:m.plainLen])
		}
		hflags := uint64(0x0002) // has data
		if len(extra) > 0 {
			hflags |= 0x0001
		}
		body := capVint(2)
		body = append(body, capVint(hflags)...)
		if len(extra) > 0 {
			body = append(body, capVint(uint64(len(extra)))...)
		}
		body = append(body, capVint(uint64(len(data)))...)
		var fflags uint64
		if m.unknownSize {
			fflags = 0x0008
		}
		body = append(body, capVint(fflags)...)
		body = append(body, capVint(m.declared)...)
		body = append(body, capVint(0)...) // attributes
		body = append(body, capVint(0)...) // compression: stored, version 0
		body = append(body, capVint(1)...) // host OS: unix
		body = append(body, capVint(uint64(len(m.name)))...)
		body = append(body, m.name...)
		body = append(body, extra...)
		out = append(out, capRarBlock(body)...)
		out = append(out, data...)
	}
	end := append(capVint(5), capVint(0)...)
	end = append(end, capVint(0)...)
	return append(out, capRarBlock(end)...)
}

func capRarExtract(buf []byte, cands ...string) extract.Result {
	opts := extract.FullOptions(time.Time{})
	opts.ArchivePWEnabled = len(cands) > 0
	opts.PWCandidates = cands
	return extract.ExtractWithOptions(buf, opts)
}

// capUnknown is the unpacked-size field of an "unknown size" member: all ones,
// which rardecode reads back as UnPackedSize == -1.
const capUnknown = ^uint64(0)

func TestCapRarBuilderSanity(t *testing.T) {
	payload := []byte("hello-rar5-builder")
	t.Run("declared-size", func(t *testing.T) {
		rr, err := rardecode.NewReader(bytes.NewReader(capRar5(t,
			capRarMember{name: "a.txt", data: payload, declared: uint64(len(payload))})))
		if err != nil {
			t.Fatal(err)
		}
		h, err := rr.Next()
		if err != nil || h.Name != "a.txt" || h.UnPackedSize != int64(len(payload)) || h.UnKnownSize {
			t.Fatalf("hdr=%+v err=%v", h, err)
		}
		got, err := io.ReadAll(rr)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("got=%q err=%v", got, err)
		}
		if _, err := rr.Next(); !errors.Is(err, io.EOF) {
			t.Fatalf("second Next err=%v, want EOF", err)
		}
	})
	t.Run("unknown-size", func(t *testing.T) {
		rr, err := rardecode.NewReader(bytes.NewReader(capRar5(t,
			capRarMember{name: "u.bin", data: payload, declared: capUnknown, unknownSize: true})))
		if err != nil {
			t.Fatal(err)
		}
		h, err := rr.Next()
		if err != nil || !h.UnKnownSize || h.UnPackedSize != -1 {
			t.Fatalf("hdr=%+v err=%v", h, err)
		}
		got, err := io.ReadAll(rr)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("got=%q err=%v", got, err)
		}
	})
	t.Run("encrypted", func(t *testing.T) {
		buf := capRar5(t, capRarMember{name: "e.txt", data: payload, plainLen: len(payload),
			declared: uint64(len(payload)), password: "secret"})
		rr, err := rardecode.NewReader(bytes.NewReader(buf), rardecode.Password("secret"))
		if err != nil {
			t.Fatal(err)
		}
		h, err := rr.Next()
		if err != nil || !h.Encrypted {
			t.Fatalf("hdr=%+v err=%v", h, err)
		}
		got, err := io.ReadAll(rr)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("got=%q err=%v", got, err)
		}
		bad, err := rardecode.NewReader(bytes.NewReader(buf), rardecode.Password("wrong"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bad.Next(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(bad); err == nil {
			t.Fatal("wrong password read cleanly; check value not honoured")
		}
	})
}

// capRarUnknownBody returns n bytes of filler with the whole marker at index markAt.
func capRarUnknownBody(n, markAt int) []byte {
	const mark = "CAPMARK"
	if markAt < 0 || markAt+len(mark) > n {
		panic(fmt.Sprintf("capRarUnknownBody: marker at %d does not fit in %d bytes", markAt, n))
	}
	b := capFill(n)
	copy(b[markAt:], mark)
	return b
}

func TestCapStopRarUnknownSizeMember(t *testing.T) {
	t.Run("plain-over-cap-records-member-size", func(t *testing.T) {
		body := capRarUnknownBody(capMember+1, capMember-6) // marker straddles the cap: its last byte is the first past it
		res := capRarExtract(capRar5(t, capRarMember{name: "u.bin", data: body, declared: capUnknown, unknownSize: true}))
		if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
			t.Fatalf("CapHits=%v, want exactly [member-size]", res.CapHits)
		}
	})
	t.Run("plain-at-cap-no-hit", func(t *testing.T) {
		body := capRarUnknownBody(capMember, capMember-7) // marker is the last in-cap bytes
		res := capRarExtract(capRar5(t, capRarMember{name: "u.bin", data: body, declared: capUnknown, unknownSize: true}))
		if capHasHit(res, "member-size") {
			t.Fatalf("at-cap member recorded member-size: %v", res.CapHits)
		}
		if len(res.Streams) == 0 {
			t.Fatal("in-cap member not extracted")
		}
	})
	t.Run("cracked-encrypted-over-cap-records-member-size", func(t *testing.T) {
		// The small first member is what the cracker validates the password on; the
		// unknown-size member after it is read through the cracked fresh reader.
		small := []byte("hello-in-cap")
		body := capRarUnknownBody(capMember+1, capMember-6)
		res := capRarExtract(capRar5(t,
			capRarMember{name: "a.txt", data: small, plainLen: len(small), declared: uint64(len(small)), password: "test"},
			capRarMember{name: "u.bin", data: body, plainLen: len(body), declared: capUnknown, unknownSize: true, password: "test"},
		), "wrong", "test")
		if !res.DecryptedArchive {
			t.Fatalf("archive not decrypted (cracker failed?): %+v", res.CapHits)
		}
		if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
			t.Fatalf("CapHits=%v, want exactly [member-size]", res.CapHits)
		}
	})
}

func TestCapStopRarOversizeSkip(t *testing.T) {
	// The declared size lies about the data area on purpose: both skip branches
	// decide from the header alone and never read the body.
	stub := []byte("stub-bytes")
	t.Run("plain-declared-over-cap", func(t *testing.T) {
		res := capRarExtract(capRar5(t, capRarMember{name: "big.bin", data: stub, declared: capMember + 1}))
		if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
			t.Fatalf("CapHits=%v, want exactly [member-size]", res.CapHits)
		}
	})
	t.Run("plain-declared-at-cap-no-hit", func(t *testing.T) {
		res := capRarExtract(capRar5(t, capRarMember{name: "ok.bin", data: stub, declared: capMember}))
		if capHasHit(res, "member-size") {
			t.Fatalf("declared==cap recorded member-size: %v", res.CapHits)
		}
	})
	t.Run("plain-oversize-with-password-candidates-not-double-recorded", func(t *testing.T) {
		// A plaintext oversize member is also met by the cracked re-walk when a
		// sibling is encrypted; the `if cracked { continue }` guard precedes the
		// skip, so the hit is recorded once (CapHits is a deduplicated set).
		small := []byte("hello-in-cap")
		res := capRarExtract(capRar5(t,
			capRarMember{name: "big.bin", data: stub, declared: capMember + 1},
			capRarMember{name: "a.txt", data: small, plainLen: len(small), declared: uint64(len(small)), password: "test"},
		), "test")
		n := 0
		for _, k := range res.CapHits {
			if k == "member-size" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("member-size recorded %d times: %v", n, res.CapHits)
		}
	})
	t.Run("cracked-encrypted-declared-over-cap", func(t *testing.T) {
		small := []byte("hello-in-cap")
		res := capRarExtract(capRar5(t,
			capRarMember{name: "a.txt", data: small, plainLen: len(small), declared: uint64(len(small)), password: "test"},
			capRarMember{name: "big.bin", data: stub, plainLen: len(stub), declared: capMember + 1, password: "test"},
		), "wrong", "test")
		if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
			t.Fatalf("CapHits=%v, want exactly [member-size]", res.CapHits)
		}
		if !res.DecryptedArchive {
			t.Fatal("in-cap encrypted sibling not decrypted: cracker did not unlock the archive")
		}
	})
	t.Run("cracked-encrypted-declared-at-cap-no-hit", func(t *testing.T) {
		small := []byte("hello-in-cap")
		res := capRarExtract(capRar5(t,
			capRarMember{name: "a.txt", data: small, plainLen: len(small), declared: uint64(len(small)), password: "test"},
			capRarMember{name: "ok.bin", data: stub, plainLen: len(stub), declared: capMember, password: "test"},
		), "test")
		if capHasHit(res, "member-size") {
			t.Fatalf("declared==cap recorded member-size: %v", res.CapHits)
		}
	})
}

// capPWExtract runs the public API with archive-password candidates enabled.
func capPWExtract(buf []byte, cands ...string) extract.Result {
	opts := extract.FullOptions(time.Time{})
	opts.ArchivePWEnabled = true
	opts.PWCandidates = cands
	return extract.ExtractWithOptions(buf, opts)
}

// capRawEncryptedZip builds a zip whose single member has general-purpose bit 0
// set and the given declared uncompressed size, with junk (undecryptable) data.
func capRawEncryptedZip(t *testing.T, declared uint64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name:               "enc.bin",
		Method:             zip.Store,
		Flags:              0x1,
		CRC32:              1,
		CompressedSize64:   32,
		UncompressedSize64: declared,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte{0x5a}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestCapStopEncryptedZipDeclaredOversize covers AUD-04c5 (a): an encrypted zip
// member declaring more than the cap used to be dropped with no cap hit.
func TestCapStopEncryptedZipDeclaredOversize(t *testing.T) {
	t.Run("declared-over-cap-records-member-size", func(t *testing.T) {
		res := capPWExtract(capRawEncryptedZip(t, capMember+1), "secret")
		if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
			t.Fatalf("CapHits=%v, want [member-size]", res.CapHits)
		}
	})
	t.Run("declared-at-cap-no-hit", func(t *testing.T) {
		res := capPWExtract(capRawEncryptedZip(t, capMember), "secret")
		if capHasHit(res, "member-size") {
			t.Fatalf("at-cap member recorded member-size: %v", res.CapHits)
		}
	})
	t.Run("no-candidates-no-hit", func(t *testing.T) {
		res := capPWExtract(capRawEncryptedZip(t, capMember+1))
		if capHasHit(res, "member-size") {
			t.Fatalf("no-candidate path recorded member-size: %v", res.CapHits)
		}
	})
}

// capYekaZip builds a genuinely encrypted zip (yeka, stored) holding content, then
// patches the declared uncompressed size in every local and central header (and a
// data descriptor if present) to declared.
func capYekaZip(t *testing.T, enc yekazip.EncryptionMethod, pw string, content []byte, declared uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := yekazip.NewWriter(&buf)
	w, err := zw.Encrypt("m.bin", pw, enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	patched := 0
	for _, s := range []struct {
		sig []byte
		off int
	}{{[]byte("PK\x03\x04"), 22}, {[]byte("PK\x01\x02"), 24}} {
		if i := bytes.Index(b, s.sig); i >= 0 {
			binary.LittleEndian.PutUint32(b[i+s.off:], declared)
			patched++
		}
	}
	if patched != 2 {
		t.Fatalf("patched %d headers, want 2", patched)
	}
	return b
}

// TestCapStopEncryptedZipStreamOutrunsDeclared covers AUD-04c5 (b): the stream
// exceeds the cap while the headers declare <= cap, so the old bounded read cut it
// silently.
func TestCapStopEncryptedZipStreamOutrunsDeclared(t *testing.T) {
	// yeka's ZipCrypto checksumReader drops the final chunk (returns 0 bytes) when
	// the stream ends with a size mismatch, so a stream only 1 byte over the cap
	// errors out instead of reaching the probe; overshoot by a few KiB so the
	// cap read ends mid-stream.
	over := capFill(capMember + 4096)
	over[capMember] = 'Z' // marker in the byte past the cap
	// Decrypting a 16 MiB member under -race on a contended runner can overrun the
	// 750ms production per-attempt watchdog (AUD-04c8-zc); raise it for this test
	// only. A hard stall is still bounded by the minute-scale ceiling.
	t.Cleanup(extract.SetDecryptAttemptTimeForTest(time.Minute))
	for name, enc := range map[string]yekazip.EncryptionMethod{"zipcrypto": yekazip.StandardEncryption, "aes256": yekazip.AES256Encryption} {
		enc := enc
		t.Run(name, func(t *testing.T) {
			t.Run("stream-over-cap-records-member-size", func(t *testing.T) {
				res := capPWExtract(capYekaZip(t, enc, "secret", over, 1000), "wrong", "secret")
				if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
					t.Fatalf("CapHits=%v, want [member-size]", res.CapHits)
				}
				if !res.DecryptedArchive {
					t.Fatal("archive not reported decrypted")
				}
				for _, s := range res.Streams {
					if len(s) > capMember {
						t.Fatalf("stream of %d bytes exceeds cap", len(s))
					}
				}
			})
			t.Run("one-byte-over-cap-declared-mismatch-records-member-size", func(t *testing.T) {
				res := capPWExtract(capYekaZip(t, enc, "secret", capFill(capMember+1), 1000), "wrong", "secret")
				if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
					t.Fatalf("CapHits=%v, want [member-size] (enc=%v dec=%v)", res.CapHits, res.EncryptedArchive, res.DecryptedArchive)
				}
				if !res.DecryptedArchive {
					t.Fatal("archive not reported decrypted")
				}
				for _, s := range res.Streams {
					if len(s) > capMember {
						t.Fatalf("stream of %d bytes exceeds cap", len(s))
					}
				}
			})
			// yeka reports a declared-size mismatch as ErrUnexpectedEOF on the post-cap
			// probe for ZipCrypto, so exact-cap content cannot be told from cap+1 when
			// the declared size is smaller. A mismatch reaching the cap is a malformed
			// member, so the conservative member-size signal is accepted. AES-256's
			// probe returns io.EOF, so it records no hit.
			t.Run("exact-cap-declared-mismatch", func(t *testing.T) {
				res := capPWExtract(capYekaZip(t, enc, "secret", capFill(capMember), 1000), "wrong", "secret")
				if enc == yekazip.StandardEncryption {
					if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
						t.Fatalf("CapHits=%v, want [member-size]", res.CapHits)
					}
					if !res.DecryptedArchive {
						t.Fatal("archive not reported decrypted")
					}
				} else if capHasHit(res, "member-size") {
					t.Fatalf("CapHits=%v, want no member-size", res.CapHits)
				}
				for _, s := range res.Streams {
					if len(s) > capMember {
						t.Fatalf("stream of %d bytes exceeds cap", len(s))
					}
				}
			})
			t.Run("in-cap-control-no-hit", func(t *testing.T) {
				in := capFill(capMember)
				res := capPWExtract(capYekaZip(t, enc, "secret", in, capMember), "secret")
				if capHasHit(res, "member-size") || !res.DecryptedArchive {
					t.Fatalf("CapHits=%v decrypted=%v", res.CapHits, res.DecryptedArchive)
				}
			})
		})
	}
}

// TestCapStopEncryptedZipAESAuthFailureAtCap pins what happens when an AES-256
// member holds exactly the cap, declares an honest size, and one byte of its
// 10-byte HMAC authentication code is flipped. yeka authenticates before it
// releases any plaintext, so the cap-sized read itself fails; the candidate is
// treated as a wrong password, the archive stays encrypted, and no cap signal
// is recorded (the post-cap probe in yekaMoreFollow is never reached).
func TestCapStopEncryptedZipAESAuthFailureAtCap(t *testing.T) {
	// Decrypting a full maxBytesPerMember AES-256 member can exceed the 750ms
	// production per-attempt watchdog on a loaded -race runner (the untampered
	// control then reads as undecrypted). Same override as the sibling tests.
	t.Cleanup(extract.SetDecryptAttemptTimeForTest(time.Minute))
	good := capYekaZip(t, yekazip.AES256Encryption, "secret", capFill(capMember), capMember)
	t.Run("untampered-control-no-hit", func(t *testing.T) {
		res := capPWExtract(good, "wrong", "secret")
		if capHasHit(res, "member-size") || !res.DecryptedArchive {
			t.Fatalf("CapHits=%v decrypted=%v", res.CapHits, res.DecryptedArchive)
		}
	})
	t.Run("flipped-hmac-byte-fails-read-no-hit", func(t *testing.T) {
		b := append([]byte(nil), good...)
		ci := bytes.Index(b, []byte("PK\x01\x02"))
		if ci < 0 || bytes.Index(b, []byte("PK\x03\x04")) != 0 {
			t.Fatal("zip headers not found")
		}
		comp := int(binary.LittleEndian.Uint32(b[ci+20:]))
		start := 30 + int(binary.LittleEndian.Uint16(b[26:])) + int(binary.LittleEndian.Uint16(b[28:]))
		if comp < 10 || start+comp > len(b) {
			t.Fatalf("bad layout comp=%d start=%d", comp, start)
		}
		b[start+comp-5] ^= 0xff // inside the trailing 10-byte authentication code
		res := capPWExtract(b, "wrong", "secret")
		if len(res.CapHits) != 0 {
			t.Fatalf("CapHits=%v, want none", res.CapHits)
		}
		if res.DecryptedArchive || !res.EncryptedArchive {
			t.Fatalf("enc=%v dec=%v, want encrypted and not decrypted", res.EncryptedArchive, res.DecryptedArchive)
		}
		for _, s := range res.Streams {
			if len(s) > capMember {
				t.Fatalf("stream of %d bytes exceeds cap", len(s))
			}
		}
	})
}

// capBatchBlock builds a batch dropper with one multi-line echo block that
// redirects to a single file. Each element of texts becomes one "echo TEXT"
// line, so carveBatchFiles sees exactly those texts (the "echo " prefix is
// stripped, there are no carets, and only a trailing CR is trimmed). Text
// bytes are 'A', so no caret, CR or LF can alter the arithmetic.
func capBatchBlock(texts ...int) []byte {
	var sb strings.Builder
	sb.WriteString("@echo off\r\n")
	sb.WriteString(`>"C:\Temp\f.vbs" (` + "\r\n")
	for _, n := range texts {
		sb.WriteString("echo ")
		sb.Write(capFill(n))
		sb.WriteString("\r\n")
	}
	sb.WriteString(")\r\n")
	return []byte(sb.String())
}

// capEvenLines splits total text bytes over k lines (k > 0).
func capEvenLines(total, k int) []int {
	out := make([]int, k)
	for i := range out {
		out[i] = total / k
		if i < total%k {
			out[i]++
		}
	}
	return out
}

func capHasStreamLen(res extract.Result, n int) bool {
	for _, s := range res.Streams {
		if len(s) == n {
			return true
		}
	}
	return false
}

func capExactMemberSize(t *testing.T, res extract.Result) {
	t.Helper()
	if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
		t.Fatalf("CapHits=%v, want exactly [member-size]", res.CapHits)
	}
}

// A batch dropper whose carved file is clamped (CRLF join) or whose parsing is
// stopped (accumulation cap) must record exactly one member-size cap hit.
func TestCapStopBatchCarverMemberSize(t *testing.T) {
	const k = 1024 // lines; the join adds 2*(k-1) CRLF bytes the accum cap never sees

	// Text totals capMember+1-2(k-1) < capMember, so addLine never refuses and
	// only the join clamp (joined length capMember+1) can set the hit.
	t.Run("crlf-clamp-over-cap", func(t *testing.T) {
		total := capMember + 1 - 2*(k-1)
		res := capExtract(capBatchBlock(capEvenLines(total, k)...))
		capExactMemberSize(t, res)
		if !capHasStreamLen(res, capMember) {
			t.Fatalf("no carved stream of length %d (clamped)", capMember)
		}
	})

	// Joined length exactly capMember: no clamp, no hit, full stream carved.
	t.Run("crlf-join-exactly-cap-no-hit", func(t *testing.T) {
		total := capMember - 2*(k-1)
		res := capExtract(capBatchBlock(capEvenLines(total, k)...))
		if capHasHit(res, "member-size") {
			t.Fatalf("join of exactly capMember recorded member-size: %v", res.CapHits)
		}
		if !capHasStreamLen(res, capMember) {
			t.Fatalf("no carved stream of length %d", capMember)
		}
	})

	// A 4-byte first line plus a line that takes accumulated text to
	// capMember+1: the second line is refused and parsing stops, while the
	// joined length of what was kept (4 bytes) is nowhere near the clamp.
	t.Run("accum-cap-stops-parsing", func(t *testing.T) {
		res := capExtract(capBatchBlock(4, capMember-3))
		capExactMemberSize(t, res)
	})

	// Accum boundary: with more than one line the CRLF join would exceed the
	// cap at exactly capMember of text, so the boundary uses a single line.
	t.Run("single-line-exactly-cap-no-hit", func(t *testing.T) {
		res := capExtract(capBatchBlock(capMember))
		if capHasHit(res, "member-size") {
			t.Fatalf("single line of capMember bytes recorded member-size: %v", res.CapHits)
		}
		if !capHasStreamLen(res, capMember) {
			t.Fatalf("no carved stream of length %d", capMember)
		}
	})

	// A lone line of capMember+1 is refused before anything is kept; the
	// payload would vanish silently, so member-size must still be recorded.
	t.Run("single-line-over-cap-records-member-size", func(t *testing.T) {
		res := capExtract(capBatchBlock(capMember + 1))
		capExactMemberSize(t, res)
		for _, s := range res.Streams {
			if len(s) > capMember {
				t.Fatalf("stream of %d bytes exceeds capMember", len(s))
			}
		}
	})

	// Negative control: a dropper with small payload stays under cap and has no hit.
	t.Run("small-payload-no-hit", func(t *testing.T) {
		bat := []byte("@echo off\r\n" +
			`>>"C:\Temp\f.vbs" echo Dim http` + "\r\n" +
			`>>"C:\Temp\f.vbs" echo Set http = CreateObject("MSXML2.ServerXMLHTTP")` + "\r\n")
		res := capExtract(bat)
		if capHasHit(res, "member-size") {
			t.Fatalf("small batch dropper flagged member-size: %v", res.CapHits)
		}
	})

	// Negative control: a batch dropper with just "@echo off" (no actual carve).
	t.Run("prefilter-only-no-hit", func(t *testing.T) {
		bat := []byte("@echo off\r\nrem no drops here\r\nexit /b 0\r\n")
		res := capExtract(bat)
		if capHasHit(res, "member-size") {
			t.Fatalf("batch with no actual carve flagged member-size: %v", res.CapHits)
		}
	})
}

// capCabFill is the CAB tests' filler. 'A' is a base64/hex-looking byte, so a
// 16 MiB run of it sends every encoded-text decoder over the whole member under
// -race (about 12s per Extract); 0xFF is none of those and keeps the same size.
func capCabFill(n int) []byte {
	return bytes.Repeat([]byte{0xFF}, n)
}

type capCabFile struct {
	name string
	cb   uint32
}

// capCab builds a one-folder CAB (stored when mszip is false, else MSZIP with
// the 32K sliding-window dictionary carried across blocks). The folder holds
// data in CFDATA blocks of <= 32768 bytes; each file is declared at the running
// offset with its own cb, which may deliberately disagree with data.
func capCab(files []capCabFile, data []byte, mszip bool) []byte {
	blocks, sizes := [][]byte{}, []int{}
	if mszip {
		blocks, sizes = capMSZIPBlocks(data)
	} else {
		for off := 0; off < len(data); off += 32768 {
			end := min(off+32768, len(data))
			blocks = append(blocks, data[off:end])
			sizes = append(sizes, end-off)
		}
	}
	return capCabBlocks(files, blocks, sizes, mszip)
}

// capMSZIPBlocks frames data as CK-prefixed MSZIP CFDATA payloads of <= 32768
// bytes, each deflated against the previous 32K of output.
func capMSZIPBlocks(data []byte) ([][]byte, []int) {
	blocks, sizes := [][]byte{}, []int{}
	var dict []byte
	for off := 0; off < len(data); off += 32768 {
		end := min(off+32768, len(data))
		chunk := data[off:end]
		sizes = append(sizes, len(chunk))
		var cb bytes.Buffer
		cb.WriteString("CK")
		var fw *flate.Writer
		if len(dict) > 0 {
			fw, _ = flate.NewWriterDict(&cb, flate.BestSpeed, dict)
		} else {
			fw, _ = flate.NewWriter(&cb, flate.BestSpeed)
		}
		_, _ = fw.Write(chunk)
		_ = fw.Close()
		blocks = append(blocks, cb.Bytes())
		dict = append(append([]byte{}, dict...), chunk...)
		if len(dict) > 32768 {
			dict = dict[len(dict)-32768:]
		}
	}
	return blocks, sizes
}

// capCabBlocks assembles a one-folder CAB from explicit CFDATA payloads
// (already CK-framed when mszip), so a test can emit empty blocks. sizes holds
// each block's declared uncompressed length.
func capCabBlocks(files []capCabFile, blocks [][]byte, sizes []int, mszip bool) []byte {
	filesLen := 0
	for _, f := range files {
		filesLen += 16 + len(f.name) + 1
	}
	coffFiles := 36 + 8
	coffData := coffFiles + filesLen
	total := coffData
	for _, b := range blocks {
		total += 8 + len(b)
	}
	buf := make([]byte, total)
	copy(buf[0:4], "MSCF")
	binary.LittleEndian.PutUint32(buf[8:12], uint32(total))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(coffFiles))
	buf[24], buf[25] = 3, 1
	binary.LittleEndian.PutUint16(buf[26:28], 1)
	binary.LittleEndian.PutUint16(buf[28:30], uint16(len(files)&0xFFFF))
	binary.LittleEndian.PutUint32(buf[36:40], uint32(coffData))
	binary.LittleEndian.PutUint16(buf[40:42], uint16(len(blocks)&0xFFFF))
	if mszip {
		binary.LittleEndian.PutUint16(buf[42:44], 1)
	}
	pos := coffFiles
	var uoff uint32
	for _, f := range files {
		binary.LittleEndian.PutUint32(buf[pos:], f.cb)
		binary.LittleEndian.PutUint32(buf[pos+4:], uoff)
		uoff += f.cb
		copy(buf[pos+16:], f.name)
		pos += 16 + len(f.name) + 1
	}
	pos = coffData
	for i, b := range blocks {
		binary.LittleEndian.PutUint16(buf[pos+4:], uint16(len(b)&0xFFFF))
		binary.LittleEndian.PutUint16(buf[pos+6:], uint16(sizes[i]&0xFFFF))
		copy(buf[pos+8:], b)
		pos += 8 + len(b)
	}
	return buf
}

func TestCapStopCabMemberSize(t *testing.T) {
	wantOnly := func(t *testing.T, res extract.Result) {
		t.Helper()
		if len(res.CapHits) != 1 || res.CapHits[0] != "member-size" {
			t.Fatalf("CapHits=%v, want exactly [member-size]", res.CapHits)
		}
	}
	noHit := func(t *testing.T, res extract.Result) {
		t.Helper()
		if capHasHit(res, "member-size") {
			t.Fatalf("recorded member-size: %v", res.CapHits)
		}
	}
	t.Run("cab-member-over-cap", func(t *testing.T) {
		wantOnly(t, capExtract(capCab([]capCabFile{{"a.bin", capMember + 1}}, capCabFill(capMember+1), false)))
	})
	t.Run("cab-member-exactly-cap-no-hit", func(t *testing.T) {
		res := capExtract(capCab([]capCabFile{{"a.bin", capMember}}, capCabFill(capMember), false))
		noHit(t, res)
		if len(res.Streams) == 0 {
			t.Fatal("in-cap member not extracted")
		}
	})
	t.Run("cab-folder-cap-cuts-second-file", func(t *testing.T) {
		wantOnly(t, capExtract(capCab([]capCabFile{{"a.bin", capMember - 10}, {"b.bin", 20}}, capCabFill(capMember+10), false)))
	})
	t.Run("cab-folder-exactly-cap-no-hit", func(t *testing.T) {
		noHit(t, capExtract(capCab([]capCabFile{{"a.bin", capMember - 10}, {"b.bin", 10}}, capCabFill(capMember), false)))
	})
	t.Run("cab-short-folder-no-hit", func(t *testing.T) {
		// Declared size exceeds the CFDATA present, but far below the cap.
		noHit(t, capExtract(capCab([]capCabFile{{"a.bin", 100000}}, capCabFill(1000), false)))
	})
	t.Run("cab-mszip-folder-cap-cuts-second-file", func(t *testing.T) {
		wantOnly(t, capExtract(capCab([]capCabFile{{"a.bin", capMember - 10}, {"b.bin", 20}}, capCabFill(capMember+10), true)))
	})
	t.Run("cab-mszip-folder-exactly-cap-no-hit", func(t *testing.T) {
		noHit(t, capExtract(capCab([]capCabFile{{"a.bin", capMember - 10}, {"b.bin", 10}}, capCabFill(capMember), true)))
	})
	// Folder data ends exactly at the cap and nothing was discarded, but the
	// declared file range runs past it (incomplete/corrupt folder): not a cap hit.
	t.Run("cab-folder-exactly-cap-declared-past-no-hit", func(t *testing.T) {
		noHit(t, capExtract(capCab([]capCabFile{{"a.bin", capMember - 10}, {"b.bin", 20}}, capCabFill(capMember), false)))
	})
	t.Run("cab-mszip-folder-exactly-cap-declared-past-no-hit", func(t *testing.T) {
		noHit(t, capExtract(capCab([]capCabFile{{"a.bin", capMember - 10}, {"b.bin", 20}}, capCabFill(capMember), true)))
	})
	// Stored folder fills exactly the cap, then an empty CFDATA block, then a
	// block with real data: the empty block must not end the scan (AUD-04c8).
	storedBlocks := func(tail ...[]byte) ([][]byte, []int) {
		var blocks [][]byte
		var sizes []int
		data := capCabFill(capMember)
		for off := 0; off < len(data); off += 32768 {
			end := off + 32768
			if end > len(data) {
				end = len(data)
			}
			blocks = append(blocks, data[off:end])
			sizes = append(sizes, end-off)
		}
		for _, b := range tail {
			blocks = append(blocks, b)
			sizes = append(sizes, len(b))
		}
		return blocks, sizes
	}
	files := []capCabFile{{"a.bin", capMember - 10}, {"b.bin", 20}}
	t.Run("cab-stored-empty-block-after-cap-then-data", func(t *testing.T) {
		blocks, sizes := storedBlocks([]byte{}, []byte("tail"))
		wantOnly(t, capExtract(capCabBlocks(files, blocks, sizes, false)))
	})
	t.Run("cab-stored-empty-block-after-cap-only-no-hit", func(t *testing.T) {
		blocks, sizes := storedBlocks([]byte{})
		noHit(t, capExtract(capCabBlocks(files, blocks, sizes, false)))
	})
	// Same sequence in MSZIP: an empty deflate block (CK + final empty stored
	// block) after the cap decodes to zero bytes and must not end the scan.
	mszipBlocks := func(tail [][]byte, tailSizes []int) ([][]byte, []int) {
		blocks, sizes := capMSZIPBlocks(capCabFill(capMember))
		return append(blocks, tail...), append(sizes, tailSizes...)
	}
	emptyCK := []byte{'C', 'K', 0x01, 0x00, 0x00, 0xFF, 0xFF}
	var tailCK bytes.Buffer
	tailCK.WriteString("CK")
	tw, _ := flate.NewWriter(&tailCK, flate.BestSpeed)
	_, _ = tw.Write([]byte("tail"))
	_ = tw.Close()
	t.Run("cab-mszip-empty-block-after-cap-then-data", func(t *testing.T) {
		blocks, sizes := mszipBlocks([][]byte{emptyCK, tailCK.Bytes()}, []int{0, 4})
		wantOnly(t, capExtract(capCabBlocks(files, blocks, sizes, true)))
	})
	t.Run("cab-mszip-empty-block-after-cap-only-no-hit", func(t *testing.T) {
		blocks, sizes := mszipBlocks([][]byte{emptyCK}, []int{0})
		noHit(t, capExtract(capCabBlocks(files, blocks, sizes, true)))
	})
}
