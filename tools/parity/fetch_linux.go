//go:build linux

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func fetchPlatformSupported() bool { return true }

// NONBLOCK prevents an input replaced with a FIFO from hanging before f.Stat.
// NOFOLLOW prevents a last-component symlink from changing the selected file.
func openFetchInput(name string) (*os.File, error) {
	// #nosec G304 -- explicit caller-selected local manifest/plan path; never derived from downloaded content. readFetchJSON checks regular-file type and bounds.
	return os.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
}

// Both names are direct children of a stable opened parent; RENAME_NOREPLACE
// also protects a destination created after the caller's initial check.
func publishFetch(parent *os.Root, staged, destination string) error {
	return publishFetchWith(parent, staged, destination, unix.Renameat2)
}

// The syscall seam is package-local and used only by diagnostic fault tests.
func publishFetchWith(parent *os.Root, staged, destination string, rename func(int, string, int, string, uint) error) error {
	f, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	err = rename(int(f.Fd()), staged, int(f.Fd()), destination, unix.RENAME_NOREPLACE)
	// With our fixed valid flag and two direct same-parent basenames, EINVAL's
	// invalid-flag and self-descendant cases are excluded; it denotes unsupported
	// flags here. This classification is not valid for arbitrary rename calls.
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		return errFetchPublicationUnsupported
	}
	return err
}
