//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFetchRejectsSpecialInput(t *testing.T) {
	if name := os.Getenv("PARITY_TEST_FIFO_INPUT"); name != "" {
		if _, err := readFetchJSON(name); err == nil {
			t.Fatal("special input accepted")
		}
		// Exercise the nonblocking opener independently of the preflight Lstat:
		// it also protects the FIFO replacement window between Lstat and open.
		f, err := openFetchInput(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	name := filepath.Join(t.TempDir(), "input.fifo")
	if err := unix.Mkfifo(name, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestFetchRejectsSpecialInput$")
	cmd.Env = append(os.Environ(), "PARITY_TEST_FIFO_INPUT="+name)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nonblocking special-file rejection failed: %v %s", err, b)
	}
	if ctx.Err() != nil {
		t.Fatal("special input blocked until deadline")
	}
	link := filepath.Join(t.TempDir(), "input.link")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFetchJSON(link); err == nil {
		t.Fatal("symlink input accepted")
	}
	if _, err := readFetchJSON(t.TempDir()); err == nil {
		t.Fatal("directory input accepted")
	}
}
