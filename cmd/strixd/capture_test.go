package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// capture redirects *stream (os.Stdout or os.Stderr) to a pipe for the duration
// of fn and returns what was written. The pipe is drained concurrently so a
// large write cannot block fn. Restoration and cleanup run in a defer, so a
// panic in fn cannot leak the redirect; the reader goroutine ends once the
// write end is closed.
func capture(t *testing.T, stream **os.File, fn func()) (out string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := *stream
	*stream = w
	done := make(chan string, 1)
	go func() {
		b, err := io.ReadAll(r)
		if err != nil {
			b = append(b, "read error: "+err.Error()...)
		}
		done <- string(b)
	}()
	defer func() {
		*stream = orig
		if err := w.Close(); err != nil {
			t.Errorf("closing capture pipe writer: %v", err)
		}
		out = <-done
		if err := r.Close(); err != nil {
			t.Errorf("closing capture pipe reader: %v", err)
		}
	}()
	fn()
	return ""
}

// captureStdout returns what fn wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	return capture(t, &os.Stdout, fn)
}

// captureStderr returns what fn wrote to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	return capture(t, &os.Stderr, fn)
}

// writeTo writes s to f and fails the test on a write error.
func writeTo(t *testing.T, f *os.File, s string) {
	t.Helper()
	if _, err := f.WriteString(s); err != nil {
		t.Errorf("write: %v", err)
	}
}

func TestCaptureReturnsWrittenText(t *testing.T) {
	if got := captureStdout(t, func() { writeTo(t, os.Stdout, "hello out") }); got != "hello out" {
		t.Errorf("stdout = %q", got)
	}
	if got := captureStderr(t, func() { writeTo(t, os.Stderr, "hello err") }); got != "hello err" {
		t.Errorf("stderr = %q", got)
	}
}

func TestCaptureEmptyWhenNothingWritten(t *testing.T) {
	if got := captureStdout(t, func() {}); got != "" {
		t.Errorf("stdout = %q, want empty", got)
	}
	if got := captureStderr(t, func() {}); got != "" {
		t.Errorf("stderr = %q, want empty", got)
	}
}

func TestCaptureLargeWriteDoesNotBlock(t *testing.T) {
	big := strings.Repeat("x", 1<<20)
	got := captureStdout(t, func() { writeTo(t, os.Stdout, big) })
	if len(got) != len(big) {
		t.Errorf("captured %d bytes, want %d", len(got), len(big))
	}
}

// expectPanic runs f and reports whether it panicked.
func expectPanic(f func()) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	f()
	return false
}

func TestCaptureRestoresStreamsWhenFnPanics(t *testing.T) {
	origOut, origErr := os.Stdout, os.Stderr
	t.Cleanup(func() { os.Stdout, os.Stderr = origOut, origErr })

	if !expectPanic(func() { captureStdout(t, func() { panic("boom") }) }) {
		t.Fatal("captureStdout swallowed the panic")
	}
	if os.Stdout != origOut {
		t.Error("os.Stdout not restored after panic in fn")
	}
	if !expectPanic(func() { captureStderr(t, func() { panic("boom") }) }) {
		t.Fatal("captureStderr swallowed the panic")
	}
	if os.Stderr != origErr {
		t.Error("os.Stderr not restored after panic in fn")
	}
}
