//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFetchPublicationErrnoDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"missing syscall", unix.ENOSYS, "fetch publication unsupported by kernel or filesystem\n"},
		{"unsupported flags", unix.EINVAL, "fetch publication unsupported by kernel or filesystem\n"},
		{"unsupported operation", unix.EOPNOTSUPP, "fetch publication unsupported by kernel or filesystem\n"},
		{"permission", unix.EACCES, "fetch publication failed\n"},
		{"exists", unix.EEXIST, "fetch publication failed\n"},
		{"full", unix.ENOSPC, "fetch publication failed\n"},
		{"private error", errors.New("PRIVATE-path"), "fetch publication failed\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := inertFetchFixture(t)
			ops := f.ops(t)
			calls := 0
			ops.publish = func(parent *os.Root, staged, destination string) error {
				return publishFetchWith(parent, staged, destination, func(oldfd int, oldname string, newfd int, newname string, flags uint) error {
					calls++
					if oldfd != newfd || oldname == newname || filepath.Base(oldname) != oldname || filepath.Base(newname) != newname || flags != unix.RENAME_NOREPLACE {
						t.Fatal("publication classification preconditions changed")
					}
					return tc.err
				})
			}
			parent := t.TempDir()
			var log bytes.Buffer
			if code := fetchCLI(f.args(t, filepath.Join(parent, "out")), &log, ops); code != 2 || log.String() != tc.want || calls != 1 {
				t.Fatalf("publication diagnostic: exit=%d calls=%d output=%q", code, calls, log.String())
			}
			requireEmptyFetchParent(t, parent)
		})
	}
}

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
