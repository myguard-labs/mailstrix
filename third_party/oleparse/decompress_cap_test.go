package oleparse

import (
	"encoding/binary"
	"testing"
)

// uncompressedChunk builds one MS-OVBA RawChunk in uncompressed form: a 2-byte
// header (signature 0b011, CompressedFlag 0, size field 0x0FFF -> chunk_size
// 4095) followed by 4093 data bytes. Each such chunk appends 4093 bytes to the
// decompressed output for only 4095 input bytes — enough to drive the output
// past MAX_DECOMPRESSED with a bounded-size input.
func uncompressedChunk() []byte {
	const header = uint16(0x3000 | 0x0FFC) // sig=0b011<<12, flag=0, size=0x0FFC (+3 => 4095)
	out := make([]byte, 2+4093)
	binary.LittleEndian.PutUint16(out[0:], header)
	for i := 2; i < len(out); i++ {
		out[i] = 0x41
	}
	return out
}

func TestDecompressStreamBombCapped(t *testing.T) {
	// Enough chunks that the *uncapped* output would exceed MAX_DECOMPRESSED.
	chunk := uncompressedChunk()
	nChunks := (MAX_DECOMPRESSED / 4093) + 16 // a bit past the cap
	in := make([]byte, 0, 1+nChunks*len(chunk))
	in = append(in, 0x01) // SignatureByte
	for i := 0; i < nChunks; i++ {
		in = append(in, chunk...)
	}

	got := DecompressStream(in)

	// Cap is checked at the top of the chunk loop, so overshoot is at most one
	// chunk (<=4093 bytes) past MAX_DECOMPRESSED.
	if len(got) < MAX_DECOMPRESSED {
		t.Fatalf("expected output to reach the cap, got %d bytes (cap %d)", len(got), MAX_DECOMPRESSED)
	}
	if len(got) > MAX_DECOMPRESSED+4096 {
		t.Fatalf("output not capped: got %d bytes, want <= %d", len(got), MAX_DECOMPRESSED+4096)
	}
}

func TestDecompressStreamSmallInputUnaffected(t *testing.T) {
	// A single uncompressed chunk decompresses fully (well under the cap).
	in := append([]byte{0x01}, uncompressedChunk()...)
	got := DecompressStream(in)
	if len(got) != 4093 {
		t.Fatalf("expected 4093 bytes from one chunk, got %d", len(got))
	}
}
