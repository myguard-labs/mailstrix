package mailstrix

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	yara "github.com/hillu/go-yara/v4"
)

func quietLog(string, ...any) {}

// compiledYac writes a real compiled .yac bundle at path from rule, so cache/seed
// fixtures are LOADABLE — the trust path now load-validates with yara.LoadRules,
// and arbitrary bytes ("SEED") would (correctly) be rejected as unloadable.
func compiledYac(t *testing.T, path, rule string) {
	t.Helper()
	c, err := yara.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddString(rule, ""); err != nil {
		t.Fatal(err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
}

const cacheRuleA = "rule A { condition: true }"
const cacheRuleB = "rule B { condition: false }"

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
	compiledYac(t, seed, cacheRuleA)
	seedBytes, _ := os.ReadFile(seed)
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
	if !bytes.Equal(got, seedBytes) {
		t.Errorf("cache content does not match seed bundle")
	}
}

// TestEnsureCachedRulesKeepsExisting: a usable cache file is NOT overwritten by
// the seed (the cache may hold a fetched update newer than the baked seed).
func TestEnsureCachedRulesKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yac")
	compiledYac(t, seed, cacheRuleA)
	cacheDir := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, cachedRulesName)
	compiledYac(t, cachePath, cacheRuleB) // a fetched update, distinct from the seed
	cacheBytes, _ := os.ReadFile(cachePath)

	cfg := &Config{CacheDir: cacheDir, SeedRules: seed}
	if err := EnsureCachedRules(cfg, quietLog); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cachePath)
	if !bytes.Equal(got, cacheBytes) {
		t.Errorf("existing loadable cache was overwritten by the seed")
	}
}

func TestEnsureCachedRulesCleansRollbackOnlyAfterRecovery(t *testing.T) {
	cacheDir := t.TempDir()
	seedVerified(t, cacheDir, 2, cacheRuleA)
	stale := filepath.Join(cacheDir, ".rules-rollback-stale")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, cachedRulesName), []byte("recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureCachedRules(&Config{CacheDir: cacheDir}, quietLog); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale rollback directory remains after verified recovery: %v", err)
	}

	compiledYac(t, filepath.Join(cacheDir, cachedRulesName), cacheRuleB)
	if err := os.WriteFile(filepath.Join(cacheDir, manifestName), []byte(`{"version":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	recovery := filepath.Join(cacheDir, ".rules-rollback-recovery")
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := EnsureCachedRules(&Config{CacheDir: cacheDir}, quietLog); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(recovery); err != nil {
		t.Fatalf("recovery directory removed beside incoherent cache: %v", err)
	}
}

func TestCleanupRollbackDirsTreatsCachePathLiterally(t *testing.T) {
	parent := t.TempDir()
	cacheDir := filepath.Join(parent, "cache[ab]")
	stale := filepath.Join(cacheDir, ".rules-rollback-own")
	sibling := filepath.Join(parent, "cachea", ".rules-rollback-sibling")
	for _, dir := range []string{stale, sibling} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cleanupRollbackDirs(cacheDir, quietLog)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("literal cache rollback directory remains: %v", err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatalf("glob-like cache path removed sibling recovery data: %v", err)
	}
}

// TestEnsureCachedRulesReseedsWiped: a wiped (missing) cache is restored from the
// seed on the next call — the self-heal contract.
func TestEnsureCachedRulesReseedsWiped(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yac")
	compiledYac(t, seed, cacheRuleA)
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
	compiledYac(t, seed, cacheRuleA)
	seedBytes, _ := os.ReadFile(seed)
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
	if !bytes.Equal(got, seedBytes) {
		t.Errorf("empty cache not reseeded from the seed bundle")
	}
}

// TestEnsureCachedRulesUnloadableCacheReseeds: a non-empty cache that is NOT a
// loadable bundle (corrupt / wrong libyara) passes the shape check but must be
// reseeded from the known-good seed rather than trusted to the startup load.
func TestEnsureCachedRulesUnloadableCacheReseeds(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yac")
	compiledYac(t, seed, cacheRuleA)
	seedBytes, _ := os.ReadFile(seed)
	cacheDir := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, cachedRulesName)
	// Non-empty but not a valid .yac: rulesFileUsable is true, yara.LoadRules fails.
	if err := os.WriteFile(cachePath, []byte("NOT-A-REAL-YAC-BUNDLE-ZZZZ"), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{CacheDir: cacheDir, SeedRules: seed}
	if err := EnsureCachedRules(cfg, quietLog); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cachePath)
	if !bytes.Equal(got, seedBytes) {
		t.Errorf("unloadable cache was trusted instead of reseeded from the seed")
	}
	if err := rulesBundleLoadable(cachePath); err != nil {
		t.Errorf("reseeded cache should be loadable: %v", err)
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
