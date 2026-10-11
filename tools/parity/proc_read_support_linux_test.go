package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestP10ProcStatReadDisappearance(t *testing.T) {
	// Select this live test process from real /proc enumeration. Never delete or
	// replace a proc entry and never rely on another process exiting at read time.
	for _, fault := range []error{nil, os.ErrNotExist, syscall.ESRCH, syscall.EIO} {
		t.Run(strconv.Itoa(intErr(fault)), func(t *testing.T) {
			target := filepath.Join("/proc", strconv.Itoa(os.Getpid()), "stat")
			calls := 0
			read := func(path string) ([]byte, error) {
				if path == target {
					calls++
					if fault != nil {
						return nil, &os.PathError{Op: "read", Path: path, Err: fault}
					}
				}
				return os.ReadFile(path)
			}
			// A negative PGID cannot match the kernel's positive process group IDs.
			absent, err := bridgeGroupQuiescentRead(-1, read)
			if calls != 1 {
				t.Fatalf("real proc fixture target reads=%d, want 1", calls)
			}
			if errors.Is(fault, syscall.EIO) {
				if absent || !errors.Is(err, syscall.EIO) {
					t.Fatalf("stat read error must propagate: absent=%v error=%v", absent, err)
				}
			} else if !absent || err != nil {
				t.Fatalf("gone stat read must continue: absent=%v error=%v fault=%v", absent, err, fault)
			}
		})
	}
}
func intErr(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, os.ErrNotExist) {
		return 2
	}
	if e, ok := err.(syscall.Errno); ok {
		return int(e)
	}
	return -1
}
