package ci

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ms "github.com/myguard-labs/mailstrix/internal/mailstrix"
	"golang.org/x/sys/unix"
)

type blockingRulesTransport struct {
	base    http.RoundTripper
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type failingBundleTransport struct{ base http.RoundTripper }

func (f failingBundleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if filepath.Base(r.URL.Path) == "compiled.yac" {
		return nil, errors.New("injected bundle transport failure")
	}
	return f.base.RoundTrip(r)
}

func (b *blockingRulesTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if filepath.Base(r.URL.Path) == "compiled.yac" {
		b.once.Do(func() { close(b.entered) })
		select {
		case <-b.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return b.base.RoundTrip(r)
}

func rulesFetchTemps(t *testing.T, dir, prefix string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, prefix))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func ageRulesFetchTemp(t *testing.T, path string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func ensureRulesCleanup(t *testing.T, cacheDir, seed string) {
	t.Helper()
	cfg := &ms.Config{CacheDir: cacheDir, SeedRules: seed}
	if err := ms.EnsureCachedRules(cfg, func(string, ...any) {}); err != nil {
		t.Fatalf("EnsureCachedRules: %v", err)
	}
}

func closeRulesFetchTestFile(t *testing.T, f *os.File) {
	t.Helper()
	if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Errorf("close test lease: %v", err)
	}
}

func TestStartupCleanupPreservesActiveFetch(t *testing.T) {
	pub := &runUpdatePublisher{}
	pub.publish(t, 1, "rule TempOwner { condition: true }")
	pub.mu.Lock()
	seedBytes := append([]byte(nil), pub.bundle...)
	pub.mu.Unlock()

	cacheDir, seedDir := t.TempDir(), t.TempDir()
	seed := filepath.Join(seedDir, "compiled.yac")
	if err := os.WriteFile(seed, seedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(runUpdateSigner[ed25519.SeedSize:])
	trusted, err := ms.ParseRulesSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	transport := &blockingRulesTransport{base: pub, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := ms.FetchRulesWithExtraKeys(context.Background(), runUpdateURL, cacheDir, "4.5.2", &http.Client{Transport: transport, Timeout: 10 * time.Second}, true, []ed25519.PublicKey{trusted})
		done <- err
	}()

	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("bundle download did not start")
	}
	downloads := rulesFetchTemps(t, cacheDir, ".compiled-dl-*.tmp")
	if len(downloads) != 1 {
		t.Fatalf("active downloads=%v, want one", downloads)
	}
	ageRulesFetchTemp(t, downloads[0], 7*time.Hour)
	started := time.Now()
	ensureRulesCleanup(t, cacheDir, seed)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("startup cleanup waited for active owner: %v", elapsed)
	}
	if _, err := os.Lstat(downloads[0]); err != nil {
		t.Fatalf("startup cleanup removed active download: %v", err)
	}
	close(transport.release)
	if err := <-done; err != nil {
		t.Fatalf("FetchRulesWithExtraKeys: %v", err)
	}
	if _, err := os.Lstat(downloads[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published download temporary still exists: %v", err)
	}
}

func TestFailedFetchRemovesLeasedDownload(t *testing.T) {
	pub := &runUpdatePublisher{}
	pub.publish(t, 1, "rule TempError { condition: true }")
	cacheDir := t.TempDir()
	key := base64.StdEncoding.EncodeToString(runUpdateSigner[ed25519.SeedSize:])
	trusted, err := ms.ParseRulesSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ms.FetchRulesWithExtraKeys(context.Background(), runUpdateURL, cacheDir, "4.5.2", &http.Client{Transport: failingBundleTransport{base: pub}, Timeout: 10 * time.Second}, true, []ed25519.PublicKey{trusted})
	if err == nil || !strings.Contains(err.Error(), "injected bundle transport failure") {
		t.Fatalf("FetchRulesWithExtraKeys error=%v, want transport failure", err)
	}
	if downloads := rulesFetchTemps(t, cacheDir, ".compiled-dl-*.tmp"); len(downloads) != 0 {
		t.Fatalf("failed fetch retained leased downloads: %v", downloads)
	}
}

func TestStartupCleanupFetchTempLeaseBoundaries(t *testing.T) {
	cacheDir, seedDir := t.TempDir(), t.TempDir()
	seed := filepath.Join(seedDir, "compiled.yac")
	if err := os.WriteFile(seed, runUpdateBundle(t, "rule TempBoundary { condition: true }"), 0o600); err != nil {
		t.Fatal(err)
	}
	activeStage := filepath.Join(cacheDir, ".marker-stage-active")
	if err := os.Mkdir(activeStage, 0o700); err != nil {
		t.Fatal(err)
	}
	stageLease, err := os.OpenFile(activeStage, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0) // #nosec G304 -- test-owned TempDir path.
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(stageLease.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = stageLease.Close()
		t.Fatal(err)
	}
	defer closeRulesFetchTestFile(t, stageLease)

	staleDownload := filepath.Join(cacheDir, ".compiled-dl-stale.tmp")
	freshDownload := filepath.Join(cacheDir, ".compiled-dl-fresh.tmp")
	wrongType := filepath.Join(cacheDir, ".compiled-dl-directory.tmp")
	outside := filepath.Join(t.TempDir(), "outside")
	link := filepath.Join(cacheDir, ".marker-stage-link")
	for _, path := range []string{staleDownload, freshDownload, outside} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(wrongType, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{activeStage, staleDownload, wrongType, link} {
		if path != link {
			ageRulesFetchTemp(t, path, 7*time.Hour)
		}
	}
	old := time.Now().Add(-7 * time.Hour)
	times := []unix.Timespec{unix.NsecToTimespec(old.UnixNano()), unix.NsecToTimespec(old.UnixNano())}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, link, times, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	ageRulesFetchTemp(t, freshDownload, 5*time.Hour+59*time.Minute)

	ensureRulesCleanup(t, cacheDir, seed)
	for _, path := range []string{activeStage, freshDownload, wrongType, outside} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("cleanup removed protected path %s: %v", filepath.Base(path), err)
		}
	}
	for _, path := range []string{staleDownload, link} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("cleanup retained stale unowned path %s: %v", filepath.Base(path), err)
		}
	}

	if err := stageLease.Close(); err != nil {
		t.Fatal(err)
	}
	ensureRulesCleanup(t, cacheDir, seed)
	if _, err := os.Lstat(activeStage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup retained stage after owner release: %v", err)
	}
}

func TestStartupCleanupReclaimsExitedAndReplacedOwners(t *testing.T) {
	const childEnv = "MAILSTRIX_TEST_FETCH_TEMP_LEASE"
	if path := os.Getenv(childEnv); path != "" {
		lease, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0) // #nosec G304,G703 -- parent passes a test-owned TempDir path.
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(os.Stdout, "leased"); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			t.Fatal(err)
		}
		if _, err := lease.Stat(); err != nil {
			t.Fatal(err)
		}
		return
	}

	cacheDir, seedDir := t.TempDir(), t.TempDir()
	seed := filepath.Join(seedDir, "compiled.yac")
	if err := os.WriteFile(seed, runUpdateBundle(t, "rule TempExit { condition: true }"), 0o600); err != nil {
		t.Fatal(err)
	}
	exited := filepath.Join(cacheDir, ".marker-stage-exited")
	replaced := filepath.Join(cacheDir, ".marker-stage-replaced")
	for _, path := range []string{exited, replaced} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		ageRulesFetchTemp(t, path, 7*time.Hour)
	}

	oldLease, err := os.OpenFile(replaced, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0) // #nosec G304 -- test-owned TempDir path.
	if err != nil {
		t.Fatal(err)
	}
	defer closeRulesFetchTestFile(t, oldLease)
	if err := unix.Flock(int(oldLease.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(replaced, 0o700); err != nil {
		t.Fatal(err)
	}
	ageRulesFetchTemp(t, replaced, 7*time.Hour)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if len(os.Args) == 0 {
		t.Fatal("test process has no executable argument")
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupCleanupReclaimsExitedAndReplacedOwners$", "-test.count=1") // #nosec G204,G702 -- fixed argv executes the current test binary.
	cmd.Env = append(os.Environ(), childEnv+"="+exited)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "leased\n" {
		t.Fatalf("child did not acquire fetch-temp lease: %q %v", line, err)
	}

	ensureRulesCleanup(t, cacheDir, seed)
	if _, err := os.Lstat(exited); err != nil {
		t.Fatalf("cleanup removed live subprocess owner: %v", err)
	}
	if _, err := os.Lstat(replaced); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup retained unowned replacement inode: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed fetch-temp owner unexpectedly exited successfully")
	}
	waited = true
	ensureRulesCleanup(t, cacheDir, seed)
	if _, err := os.Lstat(exited); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup retained temporary after owner exit: %v", err)
	}
}
