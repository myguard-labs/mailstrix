package mailstrix

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func cleanupRetrySnapshots(t *testing.T, dir string) {
	t.Helper()
	unlock, err := lockRules(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	cleanupStaleFetchTemps(dir, quietLog)
}

func TestMarkerRetrySnapshotOwnerExit(t *testing.T) {
	const childEnv = "MAILSTRIX_TEST_RETRY_LEASE_DIR"
	if dir := os.Getenv(childEnv); dir != "" {
		unlock, err := lockRules(t.Context(), filepath.Dir(dir))
		if err != nil {
			t.Fatal(err)
		}
		lease, err := lockMarkerRetrySnapshot(dir)
		unlock()
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately leave this descriptor open: process exit, rather than a
		// cleanup defer, must release the lease on the abandoned snapshot.
		if _, err := fmt.Fprintln(os.Stdout, "leased"); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			t.Fatal(err)
		}
		// Keep the descriptor live until the subprocess actually exits.
		if _, err := lease.Stat(); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := t.TempDir()
	active, abandoned := filepath.Join(dir, ".marker-retry-active"), filepath.Join(dir, ".marker-retry-abandoned")
	for _, path := range []string{active, abandoned} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, cachedRulesName), []byte("snapshot"), 0o600); err != nil {
			t.Fatal(err)
		}
		ageFetchTemp(t, path)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMarkerRetrySnapshotOwnerExit$", "-test.count=1")
	cmd.Env = append(os.Environ(), childEnv+"="+active)
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
		t.Fatalf("child did not acquire snapshot lease: %q %v", line, err)
	}
	cleanupRetrySnapshots(t, dir)
	if !exists(active) {
		t.Fatal("cleanup removed an old active retry snapshot")
	}
	if exists(abandoned) {
		t.Fatal("cleanup retained an old abandoned retry snapshot")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err == nil {
		t.Fatal("killed snapshot owner unexpectedly exited successfully")
	}
	cleanupRetrySnapshots(t, dir)
	if exists(active) {
		t.Fatal("process exit did not release the abandoned snapshot lease")
	}
}

func TestMarkerRetrySnapshotCleanupTypes(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link, file, fresh := filepath.Join(dir, ".marker-retry-link"), filepath.Join(dir, ".marker-retry-file"), filepath.Join(dir, ".marker-retry-fresh")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	ageFetchTemp(t, file)
	// Age the link itself: os.Chtimes would follow and age its outside target.
	old := time.Now().Add(-staleFetchTempAge - time.Hour)
	ts := []unix.Timespec{unix.NsecToTimespec(old.UnixNano()), unix.NsecToTimespec(old.UnixNano())}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, link, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fresh, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockRules(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	var logs []string
	cleanupStaleFetchTemps(dir, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	if len(logs) != 0 {
		t.Fatalf("cleanup warned for a stale file, stale symlink or fresh directory: %q", logs)
	}
	for _, path := range []string{link, file, fresh, filepath.Join(outside, "keep")} {
		if !exists(path) {
			t.Fatalf("cleanup removed non-stale or malformed snapshot %s", path)
		}
	}
	for _, path := range []string{link, file, filepath.Join(dir, "missing")} {
		if err := cleanupMarkerRetrySnapshot(path); err == nil {
			t.Fatalf("snapshot lease accepted a symlink, file or missing path: %s", path)
		}
	}
	if !exists(filepath.Join(outside, "keep")) {
		t.Fatal("snapshot cleanup followed a symlink")
	}
}

func TestMarkerRetrySnapshotBundle(t *testing.T) {
	for _, mode := range []string{"hardlink", "link-error", "relative-symlink"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			src, dst := filepath.Join(dir, cachedRulesName), filepath.Join(dir, "snapshot", cachedRulesName)
			if err := os.Mkdir(filepath.Dir(dst), 0o700); err != nil {
				t.Fatal(err)
			}
			target := src
			if mode == "relative-symlink" {
				target = filepath.Join(dir, "target.yac")
				if err := os.Symlink("target.yac", src); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(target, []byte("old generation"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := os.Link
			switch mode {
			case "link-error":
				link = func(string, string) error { return os.ErrPermission }
			case "relative-symlink":
				link = func(string, string) error { t.Fatal("snapshot hardlinked a symlink"); return nil }
			}
			if err := snapshotMarkerRetryBundle(src, dst, link); err != nil {
				t.Fatal(err)
			}
			sourceInfo, err := os.Stat(src)
			if err != nil {
				t.Fatal(err)
			}
			snapshotInfo, err := os.Lstat(dst)
			if err != nil {
				t.Fatal(err)
			}
			if !snapshotInfo.Mode().IsRegular() || os.SameFile(sourceInfo, snapshotInfo) != (mode == "hardlink") {
				t.Fatal("snapshot did not use the regular-file hardlink fast path or safe copy fallback")
			}
			replacement := filepath.Join(dir, "replacement")
			if err := os.WriteFile(replacement, []byte("new generation"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, src); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(dst); err != nil || string(got) != "old generation" {
				t.Fatalf("atomic cache replacement changed snapshot: %q %v", got, err)
			}
		})
	}
}

func TestMarkerRetrySnapshotBundleErrors(t *testing.T) {
	dir := t.TempDir()
	if err := snapshotMarkerRetryBundle(filepath.Join(dir, "missing"), filepath.Join(dir, "out"), os.Link); err == nil {
		t.Fatal("missing snapshot source accepted")
	}
	src := filepath.Join(dir, cachedRulesName)
	if err := os.WriteFile(src, []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshotMarkerRetryBundle(src, filepath.Join(dir, "missing", "out"), os.Link); err == nil {
		t.Fatal("unwritable snapshot destination accepted")
	}
}
