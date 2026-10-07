package ci_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
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
)

// Cap values mirrored from internal/extract; a drift shows up as a failing
// boundary control rather than a silent pass.
const (
	capMember = 16 << 20
	capBin    = 8 << 20
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
	if res := capExtract(build(250)); capHasHit(res, "streams") {
		t.Fatalf("250 carved files (within cap) flagged: %v", res.CapHits)
	}
	res := capExtract(build(256))
	if !capHasHit(res, "streams") && !capHasHit(res, "archive-budget") {
		t.Fatalf("256 carved files past stream cap not recorded: %v (streams=%d)", res.CapHits, len(res.Streams))
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

// capRarUnknownBody returns n bytes of filler with the marker at index markAt.
func capRarUnknownBody(n, markAt int) []byte {
	b := capFill(n)
	copy(b[markAt:], "CAPMARK")
	return b
}

func TestCapStopRarUnknownSizeMember(t *testing.T) {
	t.Run("plain-over-cap-records-member-size", func(t *testing.T) {
		body := capRarUnknownBody(capMember+1, capMember-1) // marker straddles the cap edge
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
		body := capRarUnknownBody(capMember+1, capMember-1)
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
