package mailstrix

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
	"testing"
)

type icapPayloadProbe struct {
	reads int
}

func (p *icapPayloadProbe) Read([]byte) (int, error) {
	p.reads++
	return 0, errors.New("unexpected ICAP payload read")
}

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
	probe := &icapPayloadProbe{}
	if _, _, err := readICAPChunkedAppend(bufio.NewReader(io.MultiReader(strings.NewReader("1\r\n"), probe)), prefix, 9); !errors.Is(err, errICAPBodyTooLarge) {
		t.Fatalf("prefix already over limit: %v", err)
	}
	if probe.reads != 0 {
		t.Fatalf("over-limit prefix consumed attacker payload: reads=%d", probe.reads)
	}
	// Malformed, negative, and overlong size lines are still rejected.
	for _, tc := range []struct {
		name, input string
		wantErr     error
	}{
		{name: "negative", input: "-1\r\nx\r\n0\r\n\r\n"},
		{name: "malformed", input: "zz\r\n"},
		{name: "overlong", input: strings.Repeat("f", maxICAPChunkHeaderLine+1) + "\r\n", wantErr: errICAPLineTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := readICAPChunkedAppend(bufio.NewReader(strings.NewReader(tc.input)), nil, 100)
			if err == nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want rejection matching %v", err, tc.wantErr)
			}
		})
	}
}

func TestICAPChunkedAppendLimitBoundaries(t *testing.T) {
	const maxBytes = int64(3)
	for _, tc := range []struct {
		name, body string
	}{
		{name: "max-1", body: "ab"},
		{name: "max", body: "abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := readICAPChunkedBody(bufio.NewReader(strings.NewReader(chunked([]byte(tc.body)))), maxBytes)
			if err != nil || string(got) != tc.body {
				t.Fatalf("got body %q, err %v; want %q", got, err, tc.body)
			}
		})
	}

	t.Run("max+1", func(t *testing.T) {
		probe := &icapPayloadProbe{}
		r := bufio.NewReader(io.MultiReader(strings.NewReader("4\r\n"), probe))
		if _, _, err := readICAPChunkedBody(r, maxBytes); !errors.Is(err, errICAPBodyTooLarge) {
			t.Fatalf("got %v, want %v", err, errICAPBodyTooLarge)
		}
		if probe.reads != 0 {
			t.Fatalf("oversize chunk consumed attacker payload: reads=%d", probe.reads)
		}
	})
}

// TestICAPChunkedAppendRejectsTotalOverflowBeforePayloadRead is the
// repair-removal control for REL-MEM-ICAP-CHUNK-OVERFLOW. A continuation can
// begin with an existing preview, so adding MaxInt64 to len(out) must not wrap
// past the total-body limit and reach payload allocation or reads.
func TestICAPChunkedAppendRejectsTotalOverflowBeforePayloadRead(t *testing.T) {
	probe := &icapPayloadProbe{}
	r := bufio.NewReader(io.MultiReader(strings.NewReader("7fffffffffffffff\r\n"), probe))
	_, _, err := readICAPChunkedAppend(r, []byte("preview"), math.MaxInt64)
	if !errors.Is(err, errICAPBodyTooLarge) {
		t.Fatalf("existing preview + MaxInt64 chunk: got %v, want %v", err, errICAPBodyTooLarge)
	}
	if probe.reads != 0 {
		t.Fatalf("overflowing chunk consumed attacker payload: reads=%d", probe.reads)
	}
}
