package extract_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/extract"
	"github.com/myguard-labs/mailstrix/internal/mailstrix"
)

func archiveDecoderServer(t *testing.T, buf []byte) (*mailstrix.Scanner, *mailstrix.Server) {
	t.Helper()
	res := extract.Extract(buf, time.Time{})
	if len(res.Streams) == 0 || len(res.Streams[0]) == len(buf) {
		t.Fatal("fixture lacks discriminating decompressed member")
	}
	dir := t.TempDir()
	rules := fmt.Sprintf(`rule DecoderChild { condition: filesize == %d }
rule RecoveredDecoderHit { strings: $hit = "RECOVERED_DECODER_HIT" condition: $hit }`, len(res.Streams[0]))
	if err := os.WriteFile(filepath.Join(dir, "fixture.yar"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &mailstrix.Config{RulesDir: dir, EffortMax: 5, Effort: 5, ScanTimeout: 5 * time.Second,
		CacheTTL: time.Hour, CacheSize: 4}
	cfg.Finalize()
	scanner, err := mailstrix.NewScanner(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scanner.Close)
	server := mailstrix.NewServer(cfg, scanner)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return scanner, server
}

func archiveDecoderHTTP(t *testing.T, server *mailstrix.Server, buf []byte) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/scan", bytes.NewReader(buf))
	r.Header.Set("Content-Length", strconv.Itoa(len(buf)))
	r.Header.Set("X-MAILSTRIX-Effort", "5")
	server.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("HTTP status %d: %s", w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response, w
}

func TestArchiveDecoderHTTPNoCleanCache(t *testing.T) {
	for _, name := range []string{"payload.7z", "payload.rar"} {
		t.Run(name, func(t *testing.T) {
			buf, err := os.ReadFile("testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			_, server := archiveDecoderServer(t, buf)
			restore := extract.ArchiveDecoderPoolForTest(t)
			var pressure map[string]any
			func() { defer restore(); pressure, _ = archiveDecoderHTTP(t, server, buf) }()
			if pressure["degraded"] != "incomplete" {
				t.Errorf("decoder-refused scan certified complete: %+v", pressure)
			}
			recovered, w := archiveDecoderHTTP(t, server, buf)
			if w.Header().Get("X-MAILSTRIX-Cache") == "hit" || recovered["degraded"] != nil || !bytes.Contains(w.Body.Bytes(), []byte("DecoderChild")) {
				t.Fatalf("recovered capacity served stale clean or lost detection: cache=%q body=%s", w.Header().Get("X-MAILSTRIX-Cache"), w.Body.String())
			}
			_, cached := archiveDecoderHTTP(t, server, buf)
			if cached.Header().Get("X-MAILSTRIX-Cache") != "hit" {
				t.Fatal("complete recovered result no longer caches")
			}
		})
	}
}

func TestArchiveDecoderHTTPRecoveredHit(t *testing.T) {
	buf := extract.ArchiveDecoderMixedZIPForTest(t)
	_, server := archiveDecoderServer(t, buf)
	restore := extract.ArchiveDecoderPoolForTest(t)
	defer restore()
	response, w := archiveDecoderHTTP(t, server, buf)
	if response["degraded"] != "incomplete" || !bytes.Contains(w.Body.Bytes(), []byte("RecoveredDecoderHit")) {
		t.Fatalf("partial result lost actionable detection or incomplete status: %s", w.Body.String())
	}
}

func TestArchiveDecoderCacheIdentity(t *testing.T) {
	const suffix = "+decoderstatus+retainedlimit+xxh3key"
	if !strings.HasSuffix(extract.Version, suffix) {
		t.Fatalf("decoder completeness cache identity must preserve terminal ordering %q: %q", suffix, extract.Version)
	}
	buf, err := os.ReadFile("testdata/payload.7z")
	if err != nil {
		t.Fatal(err)
	}
	scanner, _ := archiveDecoderServer(t, buf)
	if !strings.HasPrefix(scanner.Fingerprint(), extract.Version+":") {
		t.Fatal("scanner cache fingerprint lost the extractor completeness identity")
	}
}
