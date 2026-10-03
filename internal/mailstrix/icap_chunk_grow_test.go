package mailstrix

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func chunked(chunks ...[]byte) string {
	var b strings.Builder
	for _, c := range chunks {
		fmt.Fprintf(&b, "%x\r\n%s\r\n", len(c), c)
	}
	b.WriteString("0\r\n\r\n")
	return b.String()
}

func TestICAPChunkReadIncremental(t *testing.T) {
	big := bytes.Repeat([]byte("ab"), icapChunkReadStep+777) // spans several steps
	exact := bytes.Repeat([]byte("z"), icapChunkReadStep)    // exactly one step
	in := chunked(big, exact, []byte("tail"))
	got, _, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(in)), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(append([]byte{}, big...), exact...), "tail"...)
	if !bytes.Equal(got, want) {
		t.Fatalf("body mismatch: got %d bytes, want %d", len(got), len(want))
	}
	// Boundary: a limit equal to the body size passes, one less is rejected.
	if _, _, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(in)), int64(len(want))); err != nil {
		t.Fatalf("limit == size rejected: %v", err)
	}
	if _, _, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(in)), int64(len(want)-1)); !errors.Is(err, errICAPBodyTooLarge) {
		t.Fatalf("limit == size-1: got %v, want too large", err)
	}
}

func TestICAPChunkHeaderClaimDoesNotReserve(t *testing.T) {
	// A header claiming ~8 MiB followed by 10 bytes and EOF must fail without
	// first allocating the claimed size.
	in := "7FFFF0\r\n0123456789"
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(in)), 16<<20)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("truncated chunk accepted")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("claimed chunk size reserved up front: %d bytes allocated", grew)
	}
}

func TestICAPChunkedAppendCountsPrefix(t *testing.T) {
	prefix := []byte("0123456789")
	in := chunked([]byte("abcde"))
	got, _, err := readICAPChunkedAppend(bufio.NewReader(strings.NewReader(in)), prefix, 15)
	if err != nil || string(got) != "0123456789abcde" {
		t.Fatalf("append at limit: %q %v", got, err)
	}
	if _, _, err := readICAPChunkedAppend(bufio.NewReader(strings.NewReader(in)), []byte("0123456789"), 14); !errors.Is(err, errICAPBodyTooLarge) {
		t.Fatalf("prefix not counted toward limit: %v", err)
	}
	// Malformed: negative and non-hex sizes are still rejected.
	for _, bad := range []string{"-1\r\nx\r\n0\r\n\r\n", "zz\r\n"} {
		if _, _, err := readICAPChunkedAppend(bufio.NewReader(strings.NewReader(bad)), nil, 100); err == nil {
			t.Errorf("malformed %q accepted", bad)
		}
	}
}
