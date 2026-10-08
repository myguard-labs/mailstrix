package extract

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/bodgit/sevenzip"
	"github.com/ulikunitz/xz/lzma"
)

// AUD-17: bound the LZMA dictionary a 7z member may make us allocate.
//
// bodgit/sevenzip hands the coder's 5 property bytes (lc/lp/pb byte + a
// little-endian uint32 dictionary size, both attacker-authored) and the
// folder's unpack size to its LZMA reader, which calls ulikunitz/xz
// lzma.NewReader with the default DictCap of 2 GiB-1. ulikunitz allocates
// min(max(declared, MinDictCap), unpackSize) bytes eagerly (lzma/reader.go
// NewReader), so a header declaring a 1 GiB dictionary plus a large unpack size
// costs 1 GiB of heap for a few hundred bytes of input.
//
// lzmaDictCeiling is that bound. Legitimate 7z archives routinely DECLARE
// larger dictionaries (7-Zip's default is 16 MiB, -mx=9 is 64 MiB) while their
// data is far smaller, and a decoder whose dictionary is at least as large as
// the unpack size is exactly equivalent to one with the declared size (no match
// distance can exceed the bytes produced so far). So the rule is:
//
//	effective = min(declared, unpackSize)    // what ulikunitz would allocate
//	effective > lzmaDictCeiling  =>  refuse (errLZMADictCap, a "lzma-dict" cap hit)
//
// Anything else is decoded with the declared size clamped to the ceiling, which
// leaves the effective dictionary unchanged. A member that genuinely needs more
// than the ceiling is therefore reported as an incomplete scan, never as clean.
const lzmaDictCeiling = 8 << 20

// errLZMADictCap marks a refusal by the dictionary ceiling.
var errLZMADictCap = errors.New("lzma: dictionary exceeds extraction ceiling")

// lzmaMethodID is the 7z method ID of LZMA (sevenzip/register.go).
var lzmaMethodID = []byte{0x03, 0x01, 0x01}

func init() {
	// RegisterDecompressor is a sync.Map Store keyed by method ID, so this
	// replaces the library's own LZMA entry; the library's init has already run
	// because this package imports it.
	sevenzip.RegisterDecompressor(lzmaMethodID, sevenzip.Decompressor(newBoundedLZMAReader))
}

// boundedLZMADict returns the property bytes to decode with, or errLZMADictCap.
// props is not modified.
func boundedLZMADict(props []byte, unpack uint64) ([]byte, error) {
	if len(props) != 5 {
		return nil, fmt.Errorf("lzma: invalid properties length %d", len(props))
	}
	declared := uint64(binary.LittleEndian.Uint32(props[1:]))
	eff := declared
	if unpack < eff {
		eff = unpack
	}
	if eff < lzma.MinDictCap {
		eff = lzma.MinDictCap
	}
	if eff > lzmaDictCeiling {
		return nil, errLZMADictCap
	}
	out := bytes.Clone(props)
	if declared > lzmaDictCeiling {
		binary.LittleEndian.PutUint32(out[1:], lzmaDictCeiling)
	}
	return out, nil
}

type lzmaCloser struct {
	c io.Closer
	r io.Reader
}

func (l *lzmaCloser) Read(p []byte) (int, error) {
	if l.r == nil {
		return 0, errors.New("lzma: already closed")
	}
	return l.r.Read(p)
}

func (l *lzmaCloser) Close() error {
	if l.c == nil {
		return errors.New("lzma: already closed")
	}
	err := l.c.Close()
	l.c, l.r = nil, nil
	return err
}

// newBoundedLZMAReader is the sevenzip.Decompressor for LZMA with the AUD-17
// dictionary ceiling.
func newBoundedLZMAReader(p []byte, s uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errors.New("lzma: need exactly one reader")
	}
	props, err := boundedLZMADict(p, s)
	if err != nil {
		return nil, err
	}
	// Rebuild the 13-byte .lzma header sevenzip's own reader builds; an unpack
	// size with the top bit set is "unknown" to ulikunitz, so refuse it.
	if s > 1<<50 {
		return nil, errors.New("lzma: stream size out of range")
	}
	h := bytes.NewBuffer(props)
	_ = binary.Write(h, binary.LittleEndian, s)
	cfg := lzma.ReaderConfig{DictCap: lzmaDictCeiling}
	lr, err := cfg.NewReader(io.MultiReader(h, readers[0]))
	if err != nil {
		return nil, fmt.Errorf("lzma: error creating reader: %w", err)
	}
	return &lzmaCloser{c: readers[0], r: lr}, nil
}
