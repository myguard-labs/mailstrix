package mailstrix

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"golang.org/x/sys/unix"
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

func ageFetchTemp(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-staleFetchTempAge - time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestCleanupStaleFetchTemps(t *testing.T) {
	cacheDir := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mkdir := func(name string) string {
		p := filepath.Join(cacheDir, name)
		if err := os.MkdirAll(filepath.Join(p, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "sub", "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mkfile := func(name string) string {
		p := filepath.Join(cacheDir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldStage := mkdir(".marker-stage-old")
	oldDL := mkfile(".compiled-dl-old.tmp")
	freshStage := mkdir(".marker-stage-fresh")
	freshDL := mkfile(".compiled-dl-fresh.tmp")
	live := mkfile("compiled.yac")
	bareStage := mkdir(".marker-stage") // no dash suffix: not ours
	wrongSuffix := mkfile(".compiled-dl-old.dat")
	fileNamedStage := mkfile(".marker-stage-file") // wrong type for its name
	dirNamedDL := mkdir(".compiled-dl-dir.tmp")    // wrong type for its name
	link := filepath.Join(cacheDir, ".marker-stage-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	dlLink := filepath.Join(cacheDir, ".compiled-dl-link.tmp")
	if err := os.Symlink(victim, dlLink); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{oldStage, oldDL, live, bareStage, wrongSuffix, fileNamedStage, dirNamedDL} {
		ageFetchTemp(t, p)
	}
	// os.Chtimes follows links; age the links themselves.
	old := time.Now().Add(-staleFetchTempAge - time.Hour)
	for _, l := range []string{link, dlLink} {
		ts := []unix.Timespec{unix.NsecToTimespec(old.UnixNano()), unix.NsecToTimespec(old.UnixNano())}
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, l, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatal(err)
		}
	}

	cleanupRollbackDirs(cacheDir, quietLog)

	for _, gone := range []string{oldStage, oldDL, link, dlLink} {
		if exists(gone) {
			t.Errorf("stale %s remains", filepath.Base(gone))
		}
	}
	for _, kept := range []string{freshStage, freshDL, live, bareStage, wrongSuffix, fileNamedStage, dirNamedDL, victim, filepath.Join(outside)} {
		if !exists(kept) {
			t.Errorf("%s was removed", kept)
		}
	}
}

func TestCleanupStaleFetchTempsBoundary(t *testing.T) {
	cacheDir := t.TempDir()
	p := filepath.Join(cacheDir, ".compiled-dl-edge.tmp")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
	cleanupStaleFetchTempsAt(cacheDir, mt, quietLog) // mtime == cutoff: kept
	if !exists(p) {
		t.Fatal("entry at the cutoff was removed")
	}
	cleanupStaleFetchTempsAt(cacheDir, mt.Add(time.Second), quietLog)
	if exists(p) {
		t.Fatal("entry older than the cutoff remains")
	}
}

func TestCleanupStaleFetchTempsLogsAndContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	cacheDir := t.TempDir()
	stuck := filepath.Join(cacheDir, ".marker-stage-a-stuck")
	if err := os.MkdirAll(filepath.Join(stuck, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stuck, 0o500); err != nil { // cannot unlink children
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stuck, 0o700) })
	next := filepath.Join(cacheDir, ".marker-stage-z-next")
	if err := os.Mkdir(next, 0o700); err != nil {
		t.Fatal(err)
	}
	dl := filepath.Join(cacheDir, ".compiled-dl-z.tmp")
	if err := os.WriteFile(dl, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{stuck, next, dl} {
		ageFetchTemp(t, p)
	}
	var logs []string
	cleanupStaleFetchTemps(cacheDir, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	if len(logs) != 1 || !strings.Contains(logs[0], ".marker-stage-a-stuck") {
		t.Fatalf("logs = %q, want one warning naming the stuck entry", logs)
	}
	if exists(next) || exists(dl) {
		t.Fatal("cleanup stopped at the first failure")
	}
}

func TestCleanupStaleFetchTempsMissingDirLogs(t *testing.T) {
	var logs []string
	cleanupStaleFetchTemps(filepath.Join(t.TempDir(), "absent"), func(f string, a ...any) { logs = append(logs, f) })
	if len(logs) != 1 {
		t.Fatalf("logs = %q, want one warning", logs)
	}
}
