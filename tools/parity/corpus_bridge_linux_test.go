package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestClamGroupAbsenceBeforeOwnershipTransfer(t *testing.T) {
	for _, reapChild := range []bool{true, false} {
		t.Run(map[bool]string{true: "eventual absence", false: "unreaped group uncertainty"}[reapChild], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			leader := exec.CommandContext(ctx, "sleep", "60")
			if err := configureBridgeGroup(leader); err != nil {
				t.Fatal(err)
			}
			if err := leader.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = leader.Process.Kill(); _ = leader.Wait() }()
			// Both are direct test children so we can choose when the killed
			// group member is reaped, without creating persistent orphan zombies.
			child := exec.CommandContext(ctx, "sleep", "60")
			child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: leader.Process.Pid}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = child.Process.Kill()
				if !reapChild {
					_ = child.Wait()
				}
			}()
			if err := leader.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			waited := make(chan struct{})
			if reapChild {
				go func() { _ = child.Wait(); close(waited) }()
			}
			absent, runErr, groupErr := finishBridgeGroup(ctx, leader)
			if runErr == nil || absent != reapChild || (groupErr == nil) != reapChild {
				t.Fatalf("group absence=%t run error=%v group error=%v, want absence=%t", absent, runErr, groupErr, reapChild)
			}
			if reapChild {
				<-waited
			}
		})
	}
}

func TestCorpusPolicyNonregularRejectedBeforeRead(t *testing.T) {
	m, _, root := generated(t)
	raw, err := encodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, nonregular := range []string{filepath.Join(t.TempDir(), "fifo"), "/dev/zero"} {
		if nonregular != "/dev/zero" {
			if err := syscall.Mkfifo(nonregular, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		start := time.Now()
		code := corpusCompareCLI([]string{"--manifest", path, "--corpus-root", root.Name(), "--engine-image", "inert", "--clamav-qualification", "inert", "--policy", nonregular}, discardWriter{}, discardWriter{})
		if code != 2 || time.Since(start) > time.Second {
			t.Fatalf("nonregular policy not promptly rejected: code=%d", code)
		}
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
