package extract

import (
	"errors"
	"fmt"
	"io"

	"github.com/bodgit/sevenzip"
	"github.com/ulikunitz/xz/lzma"
)

// lzma2DictCeiling is 64 MiB: 7-Zip's -mx9 maximum LZMA2 preset dictionary, so
// every stock preset (and the existing -mx9 solid fixtures) passes, while
// archives declaring and unpacking beyond it are refused as a "lzma-dict"
// incomplete scan. The LZMA ceiling (lzmaDictCeiling, 8 MiB) is separate.
const lzma2DictCeiling = 64 << 20

// AUD-17b: the LZMA2 twin of lzmacap.go. bodgit/sevenzip's LZMA2 reader takes
// the dictionary from the single property byte (up to 4 GiB) and ulikunitz
// allocates it eagerly. Same policy as LZMA: effective = min(declared,
// unpackSize), floored at lzma.MinDictCap; effective > lzma2DictCeiling is
// refused with errLZMADictCap, otherwise decode with the effective size.

// lzma2MethodID is the 7z method ID of LZMA2 (sevenzip/register.go).
var lzma2MethodID = []byte{0x21}

func init() {
	sevenzip.RegisterDecompressor(lzma2MethodID, sevenzip.Decompressor(newBoundedLZMA2Reader))
}

// lzma2DictSize decodes the LZMA2 property byte (Lzma2Dec.c); p > 40 is invalid.
func lzma2DictSize(p byte) (uint64, error) {
	if p > 40 {
		return 0, errors.New("lzma2: invalid properties")
	}
	if p == 40 {
		return 0xFFFFFFFF, nil
	}
	return uint64(2|(p&1)) << (p/2 + 11), nil
}

// boundedLZMA2Dict returns the DictCap to decode with, or errLZMADictCap.
func boundedLZMA2Dict(props []byte, unpack uint64) (int, error) {
	if len(props) != 1 {
		return 0, errors.New("lzma2: not enough properties")
	}
	declared, err := lzma2DictSize(props[0])
	if err != nil {
		return 0, err
	}
	eff := declared
	if unpack < eff {
		eff = unpack
	}
	if eff < lzma.MinDictCap {
		eff = lzma.MinDictCap
	}
	if eff > lzma2DictCeiling {
		return 0, errLZMADictCap
	}
	// Decode with the effective size: back-references never reach past the
	// bytes already decoded, so a tiny member that declares a huge dictionary
	// does not get a ceiling-sized allocation.
	return int(eff), nil
}

// newBoundedLZMA2Reader is the sevenzip.Decompressor for LZMA2 with the
// AUD-17b dictionary ceiling.
func newBoundedLZMA2Reader(p []byte, s uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errors.New("lzma2: need exactly one reader")
	}
	dict, err := boundedLZMA2Dict(p, s)
	if err != nil {
		return nil, err
	}
	cfg := lzma.Reader2Config{DictCap: dict}
	if err := cfg.Verify(); err != nil {
		return nil, fmt.Errorf("lzma2: error verifying config: %w", err)
	}
	lr, err := cfg.NewReader2(readers[0])
	if err != nil {
		return nil, fmt.Errorf("lzma2: error creating reader: %w", err)
	}
	return &lzmaCloser{c: readers[0], r: lr}, nil
}
