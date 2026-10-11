package main

import (
	"bytes"
	"errors"
	"io"
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
		f, err := os.Open(filepath.Clean(path))
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
	f, err := os.Open(filepath.Clean(empty))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if got, err := readAllSized(f, 100); err != nil || len(got) != 0 {
		t.Errorf("empty file: %d bytes, %v", len(got), err)
	}
}

// readerOnly hides the file size hint while preserving the same read implementation.
type readerOnly struct{ io.Reader }

// TestReadAllSizedOneAlloc compares the presized path against real buffer regrowth.
// Open/Close and fixture construction stay outside the measured callbacks.
func TestReadAllSizedOneAlloc(t *testing.T) {
	data := bytes.Repeat([]byte("y"), 4<<20)
	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	measure := func(r io.Reader) (float64, int) {
		capacity := 0
		allocs := testing.AllocsPerRun(5, func() {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			got, err := readAllSized(r, -1)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("read bytes: got length %d, want %d", len(got), len(data))
			}
			capacity = cap(got)
		})
		return allocs, capacity
	}
	presized, capacity := measure(f)
	streaming, grownCapacity := measure(readerOnly{f})
	// bytes.Buffer doubles when its EOF probe exhausts the unhinted buffer.
	// The size+1 hint must avoid that growth, independently of runtime overhead.
	if capacity >= 2*len(data) || capacity >= grownCapacity {
		t.Errorf("presize regrowth: capacity=%d streaming=%d size=%d", capacity, grownCapacity, len(data))
	}
	if presized >= streaming {
		t.Errorf("presize allocations=%g, streaming=%g", presized, streaming)
	}
}

type sizedErrorReader struct {
	err  error
	sent bool
}

func (r *sizedErrorReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, r.err
	}
	r.sent = true
	return copy(p, "partial"), r.err
}

func TestReadAllSizedBoundariesAndErrors(t *testing.T) {
	for _, limit := range []int64{0, 1, 3, 4, -1} {
		want := "abc"
		if limit >= 0 && limit < 3 {
			want = want[:limit]
		}
		got, err := readAllSized(strings.NewReader("abc"), limit)
		if err != nil || string(got) != want {
			t.Fatalf("limit %d: got %q err %v want %q", limit, got, err, want)
		}
	}
	sentinel := errors.New("read failed")
	got, err := readAllSized(&sizedErrorReader{err: sentinel}, -1)
	if !errors.Is(err, sentinel) || string(got) != "partial" {
		t.Fatalf("partial error: got %q err %v", got, err)
	}
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := readAllSized(f, -1); err == nil || len(got) != 0 {
		t.Fatalf("closed file: len=%d err=%v", len(got), err)
	}
}
