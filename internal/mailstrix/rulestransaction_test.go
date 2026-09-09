package mailstrix

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFetchRulesDelayedDownloadCannotReplaceNewerInstall(t *testing.T) {
	oldBytes := compiledYacBytes(t, "rule VersionTwo { condition: true }")
	sum := sha256.Sum256(oldBytes)
	m := RulesManifest{Version: 2, Generated: "2026-06-18T00:00:00Z", Checksum: fmt.Sprintf("sha256:%x", sum), Libyara: "4.5.2", Size: int64(len(oldBytes))}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	oldSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".json") {
			if err := json.NewEncoder(w).Encode(m); err != nil {
				return
			}
			return
		}
		once.Do(func() { close(entered) })
		select {
		case <-release:
			if _, err := w.Write(oldBytes); err != nil {
				return
			}
		case <-r.Context().Done():
		}
	}))
	defer oldSource.Close()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	newBytes := compiledYacBytes(t, "rule VersionThree { condition: true }")
	newSource := rulesServer(t, newBytes, 3, "4.5.2", "")
	defer newSource.Close()
	dir := t.TempDir()
	seedVerified(t, dir, 1, "rule VersionOne { condition: true }")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type outcome struct {
		result FetchResult
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		r, err := FetchRules(ctx, oldSource.URL, dir, "4.5.2", oldSource.Client())
		finished <- outcome{r, err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("v2 download never entered")
	}
	// An independent caller must install v3 while v2 is still downloading.
	if r, err := FetchRules(ctx, newSource.URL, dir, "4.5.2", newSource.Client()); err != nil || !r.Updated || r.NewVersion != 3 {
		t.Fatalf("v3 could not install during the older download: %+v %v", r, err)
	}
	unblock()
	select {
	case got := <-finished:
		if got.err != nil || got.result.Updated || got.result.NewVersion != 3 {
			t.Fatalf("stale downloader overwrote newer installation: %+v %v", got.result, got.err)
		}
	case <-ctx.Done():
		t.Fatal("stale downloader did not complete")
	}
	if m, ok := LoadManifest(dir); !ok || m.Version != 3 {
		t.Fatalf("cached version regressed: %+v", m)
	}
	if got := readRuleFile(t, filepath.Join(dir, cachedRulesName)); string(got) != string(newBytes) {
		t.Fatal("cached bytes regressed")
	}
}

// TestRulesLockSubprocessHelper is invoked only by the parent test. Its bounded
// acquisition must time out while another process owns the cache lock.
func TestRulesLockSubprocessHelper(t *testing.T) {
	if os.Getenv("MAILSTRIX_LOCK_TEST_HELPER") != "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	unlock, err := lockRules(ctx, os.Getenv("MAILSTRIX_LOCK_TEST_DIR"))
	if unlock != nil {
		unlock()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("child acquired cache lock held by parent: %v", err)
	}
	t.Log("cross-process lock deadline verified")
}

func TestRulesLockExcludesOtherProcessAndReleases(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockRules(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(unlock) }
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRulesLockSubprocessHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "MAILSTRIX_LOCK_TEST_HELPER=1", "MAILSTRIX_LOCK_TEST_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cross-process exclusion failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "cross-process lock deadline verified") {
		t.Fatalf("child did not verify lock deadline:\n%s", out)
	}
	release()
	unlockAgain, err := lockRules(ctx, dir)
	if err != nil {
		t.Fatalf("released lock remains unavailable: %v", err)
	}
	unlockAgain()
}

func TestRulesTelemetryLocksShareAndExcludePublisher(t *testing.T) {
	dir := t.TempDir()
	unlockFirst, err := tryLockRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockFirst()
	unlockSecond, err := tryLockRules(dir)
	if err != nil {
		t.Fatalf("second telemetry reader was excluded: %v", err)
	}
	defer unlockSecond()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if unlock, err := lockRules(ctx, dir); !errors.Is(err, context.DeadlineExceeded) {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("publisher entered while telemetry readers held the lock: %v", err)
	}
}
