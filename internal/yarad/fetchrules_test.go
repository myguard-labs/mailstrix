package yarad

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// rulesServer serves a compiled.yac + manifest like the rolling release. yac is
// the bundle bytes; ver/libyara go into the manifest; the checksum is computed
// from yac (override with badSum to simulate corruption).
func rulesServer(t *testing.T, yac []byte, ver int, libyara, badSum string) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(yac)
	checksum := "sha256:" + hex.EncodeToString(sum[:])
	if badSum != "" {
		checksum = badSum
	}
	m := RulesManifest{
		Version: ver, Generated: "2026-06-18T00:00:00Z",
		Checksum: checksum, Libyara: libyara, Rules: 1, Size: int64(len(yac)),
	}
	mb, _ := json.Marshal(m)
	mux := http.NewServeMux()
	mux.HandleFunc("/"+manifestName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(mb) })
	mux.HandleFunc("/"+cachedRulesName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(yac) })
	return httptest.NewServer(mux)
}

func seedLocal(t *testing.T, cacheDir string, ver int, yac []byte) {
	t.Helper()
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, cachedRulesName), yac, 0o600); err != nil {
		t.Fatal(err)
	}
	m := RulesManifest{Version: ver, Checksum: "sha256:x", Libyara: "4.5.2", Size: int64(len(yac))}
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(cacheDir, manifestName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFetchRulesUpdates(t *testing.T) {
	cacheDir := t.TempDir()
	newYac := []byte("NEW-COMPILED-BUNDLE")
	srv := rulesServer(t, newYac, 5, "4.5.2", "")
	defer srv.Close()

	res, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated || res.NewVersion != 5 {
		t.Fatalf("res = %+v, want updated v5", res)
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != string(newYac) {
		t.Errorf("bundle not installed: %q", got)
	}
	// Local manifest records the new version.
	lm := readLocalManifest(filepath.Join(cacheDir, manifestName))
	if lm.Version != 5 {
		t.Errorf("local manifest version = %d, want 5", lm.Version)
	}
}

func TestFetchRulesSkipsWhenUpToDate(t *testing.T) {
	cacheDir := t.TempDir()
	cur := []byte("CURRENT")
	seedLocal(t, cacheDir, 7, cur)
	srv := rulesServer(t, []byte("WOULD-BE-NEW"), 7, "4.5.2", "") // same version
	defer srv.Close()

	res, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated {
		t.Fatalf("updated despite equal version: %+v", res)
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != "CURRENT" {
		t.Errorf("bundle changed on a no-op: %q", got)
	}
}

func TestFetchRulesRefusesLibyaraSkew(t *testing.T) {
	cacheDir := t.TempDir()
	seedLocal(t, cacheDir, 1, []byte("CUR"))
	srv := rulesServer(t, []byte("NEW"), 2, "4.6.0", "") // newer but different libyara
	defer srv.Close()

	_, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client())
	if err == nil {
		t.Fatal("expected refusal on libyara skew")
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != "CUR" {
		t.Errorf("bundle changed despite skew refusal: %q", got)
	}
}

func TestFetchRulesRejectsBadChecksum(t *testing.T) {
	cacheDir := t.TempDir()
	seedLocal(t, cacheDir, 1, []byte("CUR"))
	srv := rulesServer(t, []byte("NEW-CORRUPT"), 2, "4.5.2", "sha256:"+fmt.Sprintf("%064d", 0))
	defer srv.Close()

	_, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client())
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	got, _ := os.ReadFile(filepath.Join(cacheDir, cachedRulesName))
	if string(got) != "CUR" {
		t.Errorf("corrupt bundle was installed: %q", got)
	}
}

func TestFetchRulesKeepsBackup(t *testing.T) {
	cacheDir := t.TempDir()
	seedLocal(t, cacheDir, 1, []byte("OLD-BUNDLE"))
	srv := rulesServer(t, []byte("NEW-BUNDLE"), 2, "4.5.2", "")
	defer srv.Close()

	if _, err := FetchRules(context.Background(), srv.URL, cacheDir, "4.5.2", srv.Client()); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(filepath.Join(cacheDir, cachedRulesName+backupSuffix))
	if err != nil {
		t.Fatalf("backup not kept: %v", err)
	}
	if string(bak) != "OLD-BUNDLE" {
		t.Errorf("backup = %q, want the previous bundle", bak)
	}
}

// TestFetchRulesEmptyLibyaraSkipsSkewCheck: a dev build (ourLibyara="") accepts
// any remote libyara (skew check disabled).
func TestFetchRulesEmptyLibyaraSkipsSkewCheck(t *testing.T) {
	cacheDir := t.TempDir()
	srv := rulesServer(t, []byte("NEW"), 1, "9.9.9", "")
	defer srv.Close()

	res, err := FetchRules(context.Background(), srv.URL, cacheDir, "", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated {
		t.Fatalf("expected update with skew check disabled: %+v", res)
	}
}

// TestRulesManifestJSONRoundTrip verifies that RulesManifest with Sources
// serialises and deserialises without loss.
func TestRulesManifestJSONRoundTrip(t *testing.T) {
	orig := RulesManifest{
		Version:   3,
		Generated: "2026-06-20T00:00:00Z",
		Checksum:  "sha256:abc123",
		Libyara:   "4.5.2",
		Rules:     42,
		Size:      1234,
		Sources: []RuleSource{
			{Name: "yaraforge", Repo: "https://github.com/YARAHQ/yara-forge", License: "mixed (see repo)", Ref: "latest", Set: "core"},
			{Name: "signature-base", Repo: "https://github.com/Neo23x0/signature-base", License: "CC BY-NC 4.0", Ref: "master"},
			{Name: "local", Repo: "https://github.com/eilandert/rspamd-yarad", License: "MIT", Ref: "baked"},
		},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got RulesManifest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Version != orig.Version || len(got.Sources) != len(orig.Sources) {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
	for i, s := range got.Sources {
		os := orig.Sources[i]
		if s.Name != os.Name || s.Repo != os.Repo || s.License != os.License || s.Ref != os.Ref || s.Set != os.Set {
			t.Errorf("sources[%d] = %+v, want %+v", i, s, os)
		}
	}
}

// TestLoadSources verifies that LoadSources reads and parses sources.json from a dir.
func TestLoadSources(t *testing.T) {
	dir := t.TempDir()
	srcs := []RuleSource{
		{Name: "yaraforge", Repo: "https://github.com/YARAHQ/yara-forge", License: "mixed (see repo)", Ref: "latest", Set: "core"},
		{Name: "local", Repo: "https://github.com/eilandert/rspamd-yarad", License: "MIT", Ref: "baked"},
	}
	b, _ := json.Marshal(srcs)
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	got := LoadSources(dir)
	if len(got) != 2 {
		t.Fatalf("got %d sources, want 2", len(got))
	}
	if got[0].Name != "yaraforge" || got[0].Set != "core" {
		t.Errorf("sources[0] = %+v", got[0])
	}
	if got[1].Name != "local" || got[1].Ref != "baked" {
		t.Errorf("sources[1] = %+v", got[1])
	}
}

// TestLoadSourcesMissing returns nil for a missing file (no error).
func TestLoadSourcesMissing(t *testing.T) {
	if got := LoadSources(t.TempDir()); got != nil {
		t.Fatalf("expected nil for missing sources.json, got %v", got)
	}
}
