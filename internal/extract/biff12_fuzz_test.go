package extract

import (
	"encoding/binary"
	"testing"
)

// FuzzParseBIFF12Formula verifies the parseBIFF12Formula invariants for
// arbitrary byte inputs:
//  1. Never panics.
//  2. Always terminates (token + stack + output caps).
//  3. The returned string never exceeds maxBIFFPtgOutputLen bytes.
//
// The BIFF12 parser shares its operand-stack logic with the BIFF8 one, but its
// ptgStr front-end diverges (uint16 charcount + UTF-16LE, no fHighByte flag), so
// it needs its own fuzz coverage of that untrusted decode path. No content
// assertions — output is deliberately unspecified beyond the length bound.
func FuzzParseBIFF12Formula(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})

	// Single UTF-16LE ptgStr.
	f.Add(strPtg("evil.com"))

	// Two ptgStr concatenated.
	{
		s := append(strPtg("http"), strPtg("://x")...)
		s = append(s, ptgConcat)
		f.Add(s)
	}

	// ptgStr + ptgFuncVar EXEC(110).
	{
		s := strPtg("calc.exe")
		s = append(s, ptgFuncVar, 1)
		s = binary.LittleEndian.AppendUint16(s, 110)
		f.Add(s)
	}

	// Truncated ptgStr: charcount 10, no body.
	f.Add([]byte{ptgStr, 0x0A, 0x00})

	// charcount that would overflow a naive size calc: 0xFFFF, no body.
	f.Add([]byte{ptgStr, 0xFF, 0xFF})

	// Unknown opcode — parser must bail without desync.
	f.Add(append(strPtg("kept"), 0x7A, 0xFF, 0xFF))

	// ptgFuncVar USERDEFINED trailer + trailing token.
	{
		s := []byte{ptgFuncVar, 0x00}
		s = binary.LittleEndian.AppendUint16(s, funcUserDefined)
		s = append(s, make([]byte, 9)...)
		s = append(s, strPtg("after")...)
		f.Add(s)
	}

	// Pure garbage.
	f.Add([]byte{0xFF, 0xFE, 0x00, 0xAB, 0x17, 0x02, 0x00, 'h', 0x00, 'i', 0x00, 0x08})

	f.Fuzz(func(t *testing.T, data []byte) {
		result := parseBIFF12Formula(data)
		if len(result) > maxBIFFPtgOutputLen {
			t.Fatalf("output length %d exceeds maxBIFFPtgOutputLen %d", len(result), maxBIFFPtgOutputLen)
		}
	})
}
