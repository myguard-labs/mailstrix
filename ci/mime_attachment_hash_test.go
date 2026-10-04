package ci

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func mime02Root(headers string, body []byte) []byte {
	return append([]byte("From: sender@example.test\r\nMIME-Version: 1.0\r\n"+headers+"\r\n\r\n"), body...)
}
func mime02File(data []byte) []byte {
	return []byte("Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=x.bin\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data))
}
func mime02Multipart(parts ...[]byte) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		b.WriteString("--MIME02\r\n")
		b.Write(p)
		b.WriteString("\r\n")
	}
	b.WriteString("--MIME02--\r\n")
	return mime02Root("Content-Type: multipart/mixed; boundary=MIME02", b.Bytes())
}
func mime02Scanner(t *testing.T, listed [][]byte, effort int, enabled bool) *mailstrix.Scanner {
	t.Helper()
	return mime02ScannerHook(t, listed, effort, enabled, nil, func(string, ...any) {})
}
func mime02ScannerHook(t *testing.T, listed [][]byte, effort int, enabled bool, configure func(*mailstrix.Config), logf func(string, ...any)) *mailstrix.Scanner {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.yar"), []byte(`rule MIME02Recovered { strings: $a = "MIME02_YARA_RECOVERY" condition: $a }`), 0600); err != nil {
		t.Fatal(err)
	}
	csv := "# header\n"
	for _, data := range listed {
		csv += fmt.Sprintf("\"2024-01-01\",\"%x\",\"md5\",\"sha1\",\"anon\",\"x\"\n", sha256.Sum256(data))
	}
	if err := os.WriteFile(filepath.Join(dir, "malwarebazaar.bin"), []byte(csv), 0600); err != nil {
		t.Fatal(err)
	}
	key := ""
	if enabled {
		key = "local-fixture-only"
	}
	cfg := &mailstrix.Config{RulesDir: dir, CacheDir: dir, MBazaarKey: key, MBazaarRefresh: time.Hour, Effort: effort, EffortMax: 10}
	if configure != nil {
		configure(cfg)
	}
	if cfg.MBazaarFeed == "" {
		feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write([]byte(csv)); err != nil {
				t.Errorf("write local feed: %v", err)
			}
		}))
		t.Cleanup(feed.Close)
		cfg.MBazaarFeed = feed.URL
	}
	sc, err := mailstrix.NewScanner(cfg, logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	if enabled && sc.MBazaarMetrics().FeedHashes != int64(len(listed)) {
		t.Fatalf("feed not warmed: %+v", sc.MBazaarMetrics())
	}
	return sc
}
func mime02Check(t *testing.T, data []byte, listed [][]byte, want []string, lookups uint64) {
	t.Helper()
	sc := mime02Scanner(t, listed, 10, true)
	matches, err := sc.Scan(data, mailstrix.ScanMeta{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, m := range matches {
		if m.Rule == "MALWAREBAZAAR_MALWARE" {
			got[m.Meta["sha256"]] = true
			if !slices.Contains(m.Tags, "malwarebazaar") {
				t.Fatalf("missing malwarebazaar tag: %v", m.Tags)
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("attachment digest matches=%v, want=%v", got, want)
	}
	for _, digest := range want {
		if !got[digest] {
			t.Fatalf("missing attachment digest %s: %v", digest, got)
		}
	}
	if n := sc.MBazaarMetrics().Lookups; n != lookups {
		t.Fatalf("lookups=%d, want=%d", n, lookups)
	}
}
func mime02Digest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func TestMIMEAttachmentHashWholeMessage(t *testing.T) {
	p := []byte("MIME02 complete attachment\x00\xff\r\n")
	mime02Check(t, mime02Multipart(mime02File(p)), [][]byte{p}, []string{mime02Digest(p)}, 1)
}
func TestMIMEAttachmentHashMetadata(t *testing.T) {
	p := []byte("MIME02 exact file\r\nbytes\x00\xff")
	for _, tc := range []struct {
		name, headers, cte string
		want               bool
	}{
		{"attachment", "Content-Type: application/octet-stream\r\nContent-Disposition: attachment", "base64", true},
		{"inline", "Content-Type: application/octet-stream\r\nContent-Disposition: inline; filename=x", "binary", true},
		{"name", "Content-Type: application/octet-stream; name=x", "8bit", true},
		{"rfc2231", "Content-Type: application/octet-stream\r\nContent-Disposition: inline; filename*=utf-8''file%20x", "7bit", true},
		{"independentType", "Content-Type: application/octet-stream; name=x\r\nContent-Disposition: attachment; =broken", "", true},
		{"independentDisposition", "Content-Type: broken; =bad\r\nContent-Disposition: attachment", "", true},
		{"plain", "Content-Type: text/plain", "", false},
		{"html", "Content-Type: text/html", "", false},
		{"unnamedBinary", "Content-Type: application/octet-stream", "", false},
		{"unnamedInline", "Content-Type: text/plain\r\nContent-Disposition: inline", "", false},
		{"malformed", "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; =bad", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := p
			if tc.cte == "base64" {
				body = []byte(base64.StdEncoding.EncodeToString(p))
			}
			msg := mime02Root(tc.headers+"\r\nContent-Transfer-Encoding: "+tc.cte, body)
			var want []string
			var lookups uint64
			if tc.want {
				want = []string{mime02Digest(p)}
				lookups = 1
			}
			mime02Check(t, msg, [][]byte{p}, want, lookups)
		})
	}
	t.Run("raw", func(t *testing.T) { mime02Check(t, p, [][]byte{p}, []string{mime02Digest(p)}, 1) })
	t.Run("envelope", func(t *testing.T) { msg := mime02Multipart(mime02File(p)); mime02Check(t, msg, [][]byte{msg}, nil, 1) })
	t.Run("emptyEnvelope", func(t *testing.T) {
		msg := mime02Root("Content-Type: multipart/mixed; boundary=absent", nil)
		r := extract.Extract(msg, time.Time{})
		if r.IsMIME || r.TopType != extract.TopTypeMIME {
			t.Fatalf("bad empty fixture: %+v", r)
		}
		mime02Check(t, msg, [][]byte{msg}, nil, 0)
	})
	t.Run("quotedPrintable", func(t *testing.T) {
		p := []byte("MIME02 QP=\r\nline")
		msg := mime02Root("Content-Type: text/plain; name=x\r\nContent-Transfer-Encoding: quoted-printable", []byte("MIME02 QP=3D\r\nline"))
		mime02Check(t, msg, [][]byte{p}, []string{mime02Digest(p)}, 1)
	})
}
func TestMIMEAttachmentHashIdentity(t *testing.T) {
	p := []byte("MIME02 inner ZIP member YARA content")
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, err := z.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(p); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	container := b.Bytes()
	msg := mime02Multipart(mime02File(container))
	r := extract.Extract(msg, time.Time{})
	found := false
	for _, s := range r.Streams {
		if bytes.Equal(s, p) {
			found = true
		}
	}
	if !found {
		t.Fatal("ZIP member did not reach YARA streams")
	}
	t.Run("derivedExcluded", func(t *testing.T) { mime02Check(t, msg, [][]byte{p}, nil, 1) })
	t.Run("containerIncluded", func(t *testing.T) { mime02Check(t, msg, [][]byte{container}, []string{mime02Digest(container)}, 1) })
}
func TestMIMEAttachmentHashIncomplete(t *testing.T) {
	p := []byte("MIME02_YARA_RECOVERY complete prefix")
	encoded := base64.StdEncoding.EncodeToString(p)
	for _, tc := range []struct{ name, cte, body string }{
		{"tail", "base64", encoded + "A"},
		{"punctuation", "base64", "!" + encoded},
		{"unknown", "x-unknown", string(p)},
		{"qpError", "quoted-printable", string(p) + "\n=\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := mime02Root("Content-Type: application/octet-stream; name=x\r\nContent-Transfer-Encoding: "+tc.cte, []byte(tc.body))
			r := extract.Extract(msg, time.Time{})
			if len(r.MIMEAttachments) != 0 {
				t.Fatal("incomplete file admitted")
			}
			sc := mime02Scanner(t, [][]byte{p}, 10, true)
			matches, err := sc.Scan(msg, mailstrix.ScanMeta{})
			if err != nil {
				t.Fatal(err)
			}
			recovered := false
			for _, m := range matches {
				if m.Rule == "MALWAREBAZAAR_MALWARE" {
					t.Fatal("incomplete prefix reputation matched")
				}
				if m.Rule == "MIME02Recovered" {
					recovered = true
				}
			}
			if !recovered {
				t.Fatal("YARA prefix recovery lost")
			}
			if sc.MBazaarMetrics().Lookups != 0 {
				t.Fatal("incomplete prefix looked up")
			}
		})
	}
	t.Run("truncatedBoundary", func(t *testing.T) {
		msg := mime02Multipart(mime02File(p), mime02File([]byte("MIME02 distinct truncated sibling")))
		msg = bytes.TrimSuffix(msg, []byte("\r\n--MIME02--\r\n"))
		r := extract.Extract(msg, time.Time{})
		if len(r.MIMEAttachments) != 1 {
			t.Fatalf("complete earlier sibling count=%d", len(r.MIMEAttachments))
		}
		mime02Check(t, msg, [][]byte{p}, []string{mime02Digest(p)}, 1)
	})
	t.Run("whitespace", func(t *testing.T) {
		msg := mime02Root("Content-Type: text/plain; name=x\r\nContent-Transfer-Encoding: base64", []byte(" \t\r\n"+encoded+" \t\r\n"))
		mime02Check(t, msg, [][]byte{p}, []string{mime02Digest(p)}, 1)
	})
	t.Run("qpLiteral", func(t *testing.T) {
		p := []byte("MIME02 invalid escape =XZ retained")
		msg := mime02Root("Content-Type: text/plain; name=x\r\nContent-Transfer-Encoding: quoted-printable", p)
		mime02Check(t, msg, [][]byte{p}, []string{mime02Digest(p)}, 1)
	})
}
func TestMIMEAttachmentHashNested(t *testing.T) {
	p := []byte("MIME02 nested attachment")
	inner := mime02Multipart(mime02File(p))
	for _, attached := range []bool{false, true} {
		t.Run(fmt.Sprint(attached), func(t *testing.T) {
			h := "Content-Type: message/rfc822"
			listed := [][]byte{p}
			want := []string{mime02Digest(p)}
			if attached {
				h += "\r\nContent-Disposition: attachment; filename=x.eml"
				listed = append(listed, inner)
				want = append(want, mime02Digest(inner))
			}
			mime02Check(t, mime02Root(h, inner), listed, want, uint64(len(want)))
		})
	}
	t.Run("incompleteAncestor", func(t *testing.T) {
		msg := mime02Root("Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64", []byte("!"+base64.StdEncoding.EncodeToString(inner)))
		r := extract.Extract(msg, time.Time{})
		if len(r.Streams) == 0 {
			t.Fatal("inner YARA recovery lost")
		}
		mime02Check(t, msg, [][]byte{p}, nil, 0)
	})
	t.Run("innerBody", func(t *testing.T) {
		msg := mime02Root("Content-Type: message/rfc822", mime02Root("Content-Type: text/plain", p))
		mime02Check(t, msg, [][]byte{p}, nil, 0)
	})
	t.Run("dedup", func(t *testing.T) {
		q := []byte("MIME02 distinct attachment")
		mime02Check(t, mime02Multipart(mime02File(p), mime02File(p), mime02File(q)), [][]byte{p, q}, []string{mime02Digest(p), mime02Digest(q)}, 2)
	})
}
func TestMIMEAttachmentHashBudgets(t *testing.T) {
	for _, n := range []int{0, 3, 4, (16 << 20) - 1, 16 << 20, (16 << 20) + 1} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			p := bytes.Repeat([]byte{'~'}, n)
			msg := mime02Root("Content-Type: application/octet-stream; name=x", p)
			r := extract.Extract(msg, time.Time{})
			want := 0
			if n >= 4 && n <= 16<<20 {
				want = 1
			}
			if len(r.MIMEAttachments) != want {
				t.Fatalf("size %d: candidates=%d want=%d", n, len(r.MIMEAttachments), want)
			}
			if want == 1 && !bytes.Equal(r.MIMEAttachments[0], p) {
				t.Fatal("exact bytes lost")
			}
			if n < 4 && len(r.CapHits) != 0 {
				t.Fatalf("complete tiny file reported incomplete: %v", r.CapHits)
			}
		})
	}
	for _, count := range []int{255, 256, 257} {
		t.Run(fmt.Sprintf("parts%d", count), func(t *testing.T) {
			parts := make([][]byte, count)
			for i := range parts {
				parts[i] = mime02File([]byte("tiny"))
			}
			r := extract.Extract(mime02Multipart(parts...), time.Time{})
			if n := len(r.MIMEAttachments); n != min(count, 256) {
				t.Fatalf("candidate count=%d", n)
			}
		})
	}
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprintf("remaining%d", extra), func(t *testing.T) {
			// Seven 16 MiB leaves plus one nearly-full leaf leave four bytes.
			part := append([]byte("Content-Type: application/octet-stream; name=x\r\n\r\n"), bytes.Repeat([]byte{'~'}, 16<<20)...)
			parts := make([][]byte, 0, 9)
			for i := 0; i < 7; i++ {
				parts = append(parts, part)
			}
			parts = append(parts, part[:len(part)-4], mime02File(bytes.Repeat([]byte{'!'}, 4+extra)))
			msg := mime02Multipart(parts...)
			r := extract.Extract(msg, time.Time{})
			want := 9
			if extra == 1 {
				want = 8
			}
			if len(r.MIMEAttachments) != want {
				t.Fatalf("remaining candidates=%d want=%d", len(r.MIMEAttachments), want)
			}
			total := 0
			for _, p := range r.MIMEAttachments {
				total += len(p)
			}
			if total > 128<<20 {
				t.Fatal("shared budget exceeded")
			}
		})
	}
	for _, depth := range []int{6, 7} {
		t.Run(fmt.Sprintf("depth%d", depth), func(t *testing.T) {
			msg := mime02Root("Content-Type: text/plain; name=x", []byte("tiny"))
			for i := 0; i < depth; i++ {
				msg = mime02Root("Content-Type: message/rfc822", msg)
			}
			r := extract.Extract(msg, time.Time{})
			want := 1
			if depth == 7 {
				want = 0
			}
			if len(r.MIMEAttachments) != want {
				t.Fatalf("depth candidates=%d", len(r.MIMEAttachments))
			}
		})
	}
	t.Run("expired", func(t *testing.T) {
		r := extract.Extract(mime02Multipart(mime02File([]byte("tiny"))), time.Now().Add(-time.Second))
		if len(r.MIMEAttachments) != 0 {
			t.Fatal("expired extraction admitted file")
		}
	})
	if !strings.Contains(extract.Version, "+mimeidentity") {
		t.Fatal("cache extraction version not bumped")
	}
}
func TestMIMEAttachmentHashEffort(t *testing.T) {
	p := []byte("MIME02_YARA_RECOVERY")
	msg := mime02Multipart(mime02File(p))
	for _, tc := range []struct {
		name    string
		effort  int
		enabled bool
	}{{"disabled", 10, false}, {"low", 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			sc := mime02Scanner(t, [][]byte{p}, tc.effort, tc.enabled)
			matches, err := sc.Scan(msg, mailstrix.ScanMeta{Effort: tc.effort})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, m := range matches {
				if m.Rule == "MALWAREBAZAAR_MALWARE" {
					t.Fatal("disabled reputation hit")
				}
				if m.Rule == "MIME02Recovered" {
					found = true
				}
			}
			if !found {
				t.Fatal("YARA recovery lost")
			}
			if sc.MBazaarMetrics().Lookups != 0 {
				t.Fatal("disabled reputation lookup")
			}
		})
	}
}

func TestMIMEAttachmentHashMacroIdentity(t *testing.T) {
	document, err := os.ReadFile("../internal/mailstrix/testdata/xlswithmacro.xlsm")
	if err != nil {
		t.Fatal(err)
	}
	msg := mime02Multipart(mime02File(document))
	r := extract.Extract(msg, time.Time{})
	if len(r.VBAStreams) == 0 {
		t.Fatal("macro fixture has no VBA")
	}
	mime02Check(t, msg, [][]byte{r.VBAStreams[0]}, nil, 1)
	mime02Check(t, msg, [][]byte{document}, []string{mime02Digest(document)}, 1)
}

func TestMIMEAttachmentHashDeadlineCache(t *testing.T) {
	// Network pollers cannot become durably blocked in a synctest bubble.
	// Keep the feed server outside the fake-clock bubble.
	p := []byte("MIME02_YARA_RECOVERY")
	csv := fmt.Sprintf("\"2024-01-01\",\"%x\",\"md5\",\"sha1\",\"anon\",\"x\"\n", sha256.Sum256(p))
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		if _, err := w.Write([]byte(csv)); err != nil {
			t.Errorf("write local feed: %v", err)
		}
	}))
	defer feed.Close()

	for _, expire := range []bool{false, true} {
		t.Run(fmt.Sprint(expire), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := []byte("MIME02_YARA_RECOVERY")
				msg := mime02Multipart(mime02File(p))
				var cfg *mailstrix.Config
				advanced := 0
				sc := mime02ScannerHook(t, [][]byte{p}, 10, true, func(c *mailstrix.Config) {
					c.MBazaarFeed = feed.URL
					c.ScanTimeout = 3 * time.Second
					c.BigFileThreshold = 1
					c.BigFileRules = c.RulesDir
					c.CacheTTL = time.Hour
					c.CacheSize = 10
					c.MaxBody = 1 << 20
					c.Token = "mime02-test"
					cfg = c
				}, func(format string, _ ...any) {
					if strings.HasPrefix(format, "%d oversized extracted streams") {
						advanced++
						if expire {
							time.Sleep(4 * time.Second)
						}
					}
				})
				matches, err := sc.Scan(msg, mailstrix.ScanMeta{})
				if errors.Is(err, mailstrix.ErrScanIncomplete) != expire {
					t.Fatalf("deadline err=%v want incomplete=%v", err, expire)
				}
				found := map[string]bool{}
				for _, m := range matches {
					found[m.Rule] = true
				}
				if !found["MIME02Recovered"] || found["MAILSTRIX_SCAN_INCOMPLETE"] != expire || found["MALWAREBAZAAR_MALWARE"] == expire {
					t.Fatalf("deadline matches=%v", matches)
				}
				if advanced != 1 {
					t.Fatalf("reputation boundary hook count=%d", advanced)
				}
				want := uint64(1)
				if expire {
					want = 0
				}
				if sc.MBazaarMetrics().Lookups != want {
					t.Fatalf("deadline lookups=%d", sc.MBazaarMetrics().Lookups)
				}
				server := mailstrix.NewServer(cfg, sc)
				before := sc.RawChannelScans()
				for range 2 {
					req := httptest.NewRequest("POST", "/scan", bytes.NewReader(msg))
					req.Header.Set("X-MAILSTRIX-Token", "mime02-test")
					req.Header.Set("Content-Length", fmt.Sprint(len(msg)))
					response := httptest.NewRecorder()
					server.ServeHTTP(response, req)
					if response.Code != 200 || !strings.Contains(response.Body.String(), "MIME02Recovered") {
						t.Fatalf("HTTP response=%d %s", response.Code, response.Body.String())
					}
				}
				wantScans := uint64(1)
				if expire {
					wantScans = 2
				}
				if n := sc.RawChannelScans() - before; n != wantScans {
					t.Fatalf("HTTP cache native scans=%d want=%d", n, wantScans)
				}
			})
		})
	}
}

func TestMIMEAttachmentHashWrapperBudget(t *testing.T) {
	inner := mime02Root("Content-Type: text/plain; name=x", []byte("tiny"))
	wrapper := append([]byte("Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=x.eml\r\n\r\n"), inner...)
	filler := append([]byte("Content-Type: application/octet-stream; name=x\r\n\r\n"), bytes.Repeat([]byte{'~'}, 16<<20)...)
	for _, remaining := range []int{0, 1, 2, 3, 4} {
		t.Run(fmt.Sprint(remaining), func(t *testing.T) {
			parts := make([][]byte, 0, 9)
			for range 7 {
				parts = append(parts, filler)
			}
			parts = append(parts, filler[:len(filler)-len(inner)-remaining], wrapper)
			msg := mime02Multipart(parts...)
			r := extract.Extract(msg, time.Time{})
			want := 9
			if remaining == 4 {
				want = 10
			}
			if len(r.MIMEAttachments) != want {
				t.Fatalf("wrapper shared budget candidates=%d want=%d", len(r.MIMEAttachments), want)
			}
			if !bytes.Equal(r.MIMEAttachments[8], inner) {
				t.Fatal("wrapper bytes changed")
			}
			if remaining < 4 {
				if len(r.CapHits) != 1 || r.CapHits[0] != "archive-budget" {
					t.Fatalf("wrapper exhaustion omitted cap signal: %v", r.CapHits)
				}
				mime02WrapperCapScan(t, msg, inner)
			}
		})
	}
}

func TestMIMEAttachmentHashCompleteTinyRemaining(t *testing.T) {
	filler := append([]byte("Content-Type: application/octet-stream; name=x\r\n\r\n"), bytes.Repeat([]byte{'~'}, 16<<20)...)
	for _, n := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			inner := mime02Root("Content-Type: text/plain; name=x", bytes.Repeat([]byte{'!'}, n))
			wrapper := append([]byte("Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=x.eml\r\n\r\n"), inner...)
			parts := make([][]byte, 0, 9)
			for range 7 {
				parts = append(parts, filler)
			}
			parts = append(parts, filler[:len(filler)-len(inner)-n], wrapper)
			r := extract.Extract(mime02Multipart(parts...), time.Time{})
			if len(r.CapHits) != 0 {
				t.Fatalf("complete tiny child reported incomplete: %v", r.CapHits)
			}
			if len(r.MIMEAttachments) != 9 || !bytes.Equal(r.MIMEAttachments[8], inner) {
				t.Fatal("tiny child admission or wrapper identity changed")
			}
		})
	}
}

// mime02WrapperCapScan exercises the public scanner and its HTTP cache consumer
// with the real shared budget, retaining the already admitted wrapper match.
func mime02WrapperCapScan(t *testing.T, msg, wrapper []byte) {
	t.Helper()
	cfg := new(mailstrix.Config)
	sc := mime02ScannerHook(t, [][]byte{wrapper}, 10, true, func(c *mailstrix.Config) {
		c.ScanTimeout = time.Minute
		c.MaxBody = int64(len(msg)) + 1
		c.CacheTTL = time.Hour
		c.CacheSize = 10
		c.Token = "mime02-test"
		cfg = c
	}, func(string, ...any) {})
	matches, err := sc.Scan(msg, mailstrix.ScanMeta{})
	if !errors.Is(err, mailstrix.ErrScanIncomplete) {
		t.Fatalf("wrapper cap error=%v, want ErrScanIncomplete", err)
	}
	retained, incomplete := false, false
	for _, m := range matches {
		if m.Rule == "MALWAREBAZAAR_MALWARE" && m.Meta["sha256"] == mime02Digest(wrapper) {
			retained = true
		}
		if m.Rule == "MAILSTRIX_SCAN_INCOMPLETE" {
			incomplete = true
		}
	}
	if !retained || !incomplete {
		t.Fatalf("wrapper cap lost retained match/incomplete marker: %v", matches)
	}
	server := mailstrix.NewServer(cfg, sc)
	before := sc.RawChannelScans()
	for range 2 {
		req := httptest.NewRequest("POST", "/scan", bytes.NewReader(msg))
		req.Header.Set("X-MAILSTRIX-Token", "mime02-test")
		req.Header.Set("Content-Length", fmt.Sprint(len(msg)))
		response := httptest.NewRecorder()
		server.ServeHTTP(response, req)
		if response.Code != 200 || !strings.Contains(response.Body.String(), "MAILSTRIX_SCAN_INCOMPLETE") || !strings.Contains(response.Body.String(), mime02Digest(wrapper)) {
			t.Fatalf("wrapper cap HTTP response=%d %s", response.Code, response.Body.String())
		}
	}
	if n := sc.RawChannelScans() - before; n != 2 {
		t.Fatalf("incomplete wrapper result cached: native scans=%d want=2", n)
	}
}
