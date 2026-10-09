package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadAllSized (PERF-67): reads a file fully, stops at the limit, works
// on a non-file reader and an empty file, and -1 means no limit.
func TestReadAllSized(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 5000)
	path := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	read := func(limit int64) []byte {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		b, err := readAllSized(f, limit)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if got := read(-1); !bytes.Equal(got, data) {
		t.Errorf("no limit: %d bytes", len(got))
	}
	if got := read(10001); len(got) != 5000 {
		t.Errorf("limit above size: %d bytes", len(got))
	}
	if got := read(4001); len(got) != 4001 {
		t.Errorf("limit below size (cap+1 overrun probe): %d bytes", len(got))
	}
	if got, err := readAllSized(strings.NewReader("abc"), 2); err != nil || string(got) != "ab" {
		t.Errorf("non-file reader: %q %v", got, err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(empty)
	defer func() { _ = f.Close() }()
	if got, err := readAllSized(f, 100); err != nil || len(got) != 0 {
		t.Errorf("empty file: %d bytes, %v", len(got), err)
	}
}

// TestReadAllSizedOneAlloc: a regular file is read into a pre-sized buffer.
func TestReadAllSizedOneAlloc(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte("y"), 4<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(5, func() {
		f, _ := os.Open(path)
		_, _ = readAllSized(f, -1)
		_ = f.Close()
	})
	if allocs > 8 {
		t.Errorf("allocs per read = %g, want a pre-sized buffer", allocs)
	}
}
