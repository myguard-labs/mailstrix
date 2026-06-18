package yarad

import (
	"os"
	"path/filepath"
	"testing"
)

func quietLog(string, ...any) {}

// TestEnsureCachedRulesDisabled: no CacheDir => no-op, RulesPath unchanged.
func TestEnsureCachedRulesDisabled(t *testing.T) {
	cfg := &Config{RulesPath: "/baked/compiled.yac"}
	if err := EnsureCachedRules(cfg, quietLog); err != nil {
		t.Fatal(err)
	}
	if cfg.RulesPath != "/baked/compiled.yac" {
		t.Errorf("RulesPath changed to %q with caching disabled", cfg.RulesPath)
	}
}

// TestEnsureCachedRulesSeeds: empty cache is seeded from SeedRules and RulesPath
// is repointed at the cache copy.
func TestEnsureCachedRulesSeeds(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yac")
	if err := os.WriteFile(seed, []byte("SEEDBYTES"), 0o640); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(dir, "cache")

	cfg := &Config{CacheDir: cacheDir, SeedRules: seed}
	if err := EnsureCachedRules(cfg, quietLog); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, cachedRulesName)
	if cfg.RulesPath != cachePath {
		t.Fatalf("RulesPath = %q, want %q", cfg.RulesPath, cachePath)
	}
	got, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SEEDBYTES" {
		t.Errorf("cache content = %q, want seed bytes", got)
	}
}

// TestEnsureCachedRulesKeepsExisting: a usable cache file is NOT overwritten by
// the seed (the cache may hold a fetched update newer than the baked seed).
func TestEnsureCachedRulesKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yac")
	if err := os.WriteFile(seed, []byte("SEED"), 0o640); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, cachedRulesName)
	if err := os.WriteFile(cachePath, []byte("FETCHED-UPDATE"), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{CacheDir: cacheDir, SeedRules: seed}
	if err := EnsureCachedRules(cfg, quietLog); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cachePath)
	if string(got) != "FETCHED-UPDATE" {
		t.Errorf("existing cache overwritten: got %q", got)
	}
}

// TestEnsureCachedRulesReseedsWiped: a wiped (missing) cache is restored from the
// seed on the next call — the self-heal contract.
func TestEnsureCachedRulesReseedsWiped(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yac")
	if err := os.WriteFile(seed, []byte("SEED"), 0o640); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(dir, "cache")
	cachePath := filepath.Join(cacheDir, cachedRulesName)

	cfg := &Config{CacheDir: cacheDir, SeedRules: seed}
	if err := EnsureCachedRules(cfg, quietLog); err != nil {
		t.Fatal(err)
	}
	// Wipe the cache, as an operator clearing the bindmount would.
	if err := os.Remove(cachePath); err != nil {
		t.Fatal(err)
	}
	if err := EnsureCachedRules(cfg, quietLog); err != nil {
		t.Fatal(err)
	}
	if !rulesFileUsable(cachePath) {
		t.Fatal("cache not restored after wipe")
	}
}

// TestEnsureCachedRulesEmptyCacheFileReseeds: a zero-byte cache file (a truncated
// or interrupted write) is treated as unusable and reseeded.
func TestEnsureCachedRulesEmptyCacheFileReseeds(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yac")
	if err := os.WriteFile(seed, []byte("SEED"), 0o640); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, cachedRulesName)
	if err := os.WriteFile(cachePath, nil, 0o640); err != nil { // zero bytes
		t.Fatal(err)
	}

	cfg := &Config{CacheDir: cacheDir, SeedRules: seed}
	if err := EnsureCachedRules(cfg, quietLog); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cachePath)
	if string(got) != "SEED" {
		t.Errorf("empty cache not reseeded: got %q", got)
	}
}

// TestEnsureCachedRulesNoSeedErrors: empty cache and no usable seed => error, so
// the caller can fall back rather than start with no rules.
func TestEnsureCachedRulesNoSeedErrors(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	cfg := &Config{CacheDir: cacheDir, SeedRules: "/nonexistent/seed.yac"}
	if err := EnsureCachedRules(cfg, quietLog); err == nil {
		t.Fatal("expected an error when cache empty and seed unusable")
	}
}
