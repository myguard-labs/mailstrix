package extract

// Differential regression armour for the BIFF ptg dispatch dedup refactor.
//
// The four parse entry points (BIFF8/BIFF12 x plain/WithRefs) used to be four
// verbatim copies of one dispatch loop. They are now thin wrappers over a single
// shared core, parameterised by a biffPtgDialect. That refactor is only safe if
// every one of the four still returns byte-identical output for EVERY input,
// including malformed and truncated ones, whose fail-open cut points are subtly
// non-uniform across the four.
//
// This test pins that: it runs each new function and its verbatim pre-refactor
// snapshot (biff_ptg_old_test.go) over a large corpus of structured ptg streams,
// pure fuzz, and every truncation prefix of both, and asserts equality.

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// biffPtgCorpus builds the differential input corpus: hand-built ptg streams
// exercising every dispatch arm, pseudo-random fuzz, and every truncation prefix
// of both families (truncation is where the four functions' bounds checks
// diverge, so prefixes matter more than length).
func biffPtgCorpus(t testing.TB) [][]byte {
	t.Helper()

	// Every opcode the dispatch handles, plus class variants and unknowns, so
	// random streams built from this alphabet hit real arms rather than dying on
	// the default case at byte 0.
	opcodes := []byte{
		ptgExp, ptgAdd, ptgSub, ptgMul, ptgDiv, ptgPower, ptgConcat,
		ptgLT, ptgLE, ptgEQ, ptgGE, ptgGT, ptgNE, ptgIsect, ptgUnion, ptgRange,
		ptgUplus, ptgUminus, ptgPercent, ptgParen, ptgMissArg,
		ptgStr, ptgAttr, ptgBool, ptgInt, ptgNum,
		ptgFunc, ptgFuncVar, ptgName, ptgRef, ptgArea, ptgMemArea,
		ptgRef3d, ptgArea3d, ptgNameX,
		0x41, 0x61, 0x42, 0x62, 0x44, 0x64, 0x45, 0x65, 0x5A, 0x5B, 0x43, 0x63, 0x59,
		0x00, 0x18, 0x1A, 0x27, 0x28, 0x29, 0x2C, 0x7F, 0xFF,
	}

	var seeds [][]byte
	add := func(b ...byte) { seeds = append(seeds, b) }

	// Structured singles: each operand token, well-formed.
	add(ptgStr, 3, 0, 'a', 'b', 'c')          // BIFF8 8-bit string
	add(ptgStr, 2, 1, 'h', 0, 'i', 0)         // BIFF8 UTF-16 string
	add(ptgStr, 3, 0, 'x', 0, 'y', 0, 'z', 0) // BIFF12 reading of the same bytes
	add(ptgInt, 0x68, 0x00)                   // 104
	add(ptgBool, 1)
	add(ptgBool, 0)
	add(ptgNum, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	add(ptgRef, 0, 0, 0, 0)          // A1 in BIFF8 payload terms
	add(ptgRef, 4, 0, 2, 0)          // C5
	add(ptgRef, 0, 0, 0, 0, 0, 0, 0) // full BIFF12 ptgRef payload
	add(ptgRef, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
	add(ptgRef3d, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	add(ptgArea, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	add(ptgArea3d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	add(ptgName, 1, 0, 0, 0)
	add(ptgNameX, 1, 0, 0, 0, 0, 0)
	add(ptgMemArea, 0, 0, 0, 0, 0, 0)
	add(ptgExp, 0, 0, 0, 0, 0, 0, 0)

	// Functions: CHAR fold, EXEC via funcVar, USERDEFINED trailer, arity table.
	add(ptgInt, 104, 0, ptgFunc, 111, 0)                                         // CHAR(104) -> "h"
	add(ptgInt, 5, 0, ptgFunc, 111, 0)                                           // CHAR of a control byte -> no fold
	add(ptgStr, 1, 0, 'x', ptgFuncVar, 1, 110, 0)                                // EXEC("x")
	add(ptgStr, 1, 0, 'x', ptgFuncVar, 1, 0x6D, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0) // USERDEFINED
	add(ptgInt, 1, 0, ptgInt, 2, 0, ptgInt, 3, 0, ptgFunc, 31, 0)                // MID/3-arity
	add(ptgFuncVar, 0xFF, 110, 0)                                                // argc clamp
	add(ptgFuncVar, 0, 0xFF, 0xFF)                                               // unknown id

	// ptgAttr, including the bitAttrChoose branch-table path.
	add(ptgAttr, 0x00, 0, 0)
	add(ptgAttr, 0x04, 2, 0, 0, 0, 0, 0, 0, 0)
	add(ptgAttr, 0x04, 0xFF, 0xFF) // huge branch count -> truncation
	add(ptgAttr, 0x10, 1, 0)

	// Concat chains and stack-arity stressors.
	add(ptgStr, 1, 0, 'a', ptgStr, 1, 0, 'b', ptgConcat)
	add(ptgConcat)                     // pop on empty stack
	add(ptgAdd, ptgUminus, ptgMissArg) // operators with no operands
	add(ptgStr, 1, 0, 'a', ptgPercent)

	// Deliberately over-long declared string lengths (fail-open cut points).
	add(ptgStr, 0xFF, 0, 'a')
	add(ptgStr, 0xFF, 1, 'a', 0)
	add(ptgStr, 0xFF, 0xFF)

	// Reference-family tokens truncated mid-payload, each preceded by a real
	// operand so the fold has non-empty stack state to lose. These pin the
	// reference-token PAYLOAD WIDTHS and the plain-vs-WithRefs ptgRef rendering:
	// mutation testing confirms a wrong width (ptgRef 5->6, sizeArea 9->13,
	// sizeRef3d 7->9) or a dropped [[REF:]] guard is caught here.
	//
	// It does NOT distinguish BIFF8's unchecked `pos += N` advance from BIFF12's
	// bounds-checked skip: on truncation those differ only by one extra "" push,
	// which joinStack concatenates away. That equivalence is a property of the
	// code, not a gap in this corpus — see the skipRef note in biffPtgDialect.
	for _, refTok := range []byte{ptgRef, ptgArea, ptgExp, ptgRef3d, ptgArea3d, ptgMemArea, ptgName, ptgNameX} {
		for payload := 0; payload <= 16; payload++ {
			// "abc" then the reference token with `payload` bytes following it.
			s := []byte{ptgStr, 3, 0, 'a', 'b', 'c', refTok}
			for i := 0; i < payload; i++ {
				s = append(s, byte(0x10+i))
			}
			seeds = append(seeds, s)
			// Same, but with a trailing concat so a lost operand changes the result.
			seeds = append(seeds, append(append([]byte{}, s...), ptgConcat))
		}
	}

	// Empty and single-byte inputs.
	seeds = append(seeds, []byte{})
	for _, op := range opcodes {
		seeds = append(seeds, []byte{op})
	}

	// Pseudo-random streams over the opcode alphabet mixed with arbitrary bytes,
	// plus pure fuzz. Fixed seed so failures reproduce.
	rng := rand.New(rand.NewSource(0x8b1ff))
	for i := 0; i < 3000; i++ {
		n := 1 + rng.Intn(40)
		b := make([]byte, n)
		for j := range b {
			if rng.Intn(3) == 0 {
				b[j] = byte(rng.Intn(256))
			} else {
				b[j] = opcodes[rng.Intn(len(opcodes))]
			}
		}
		seeds = append(seeds, b)
	}
	for i := 0; i < 1500; i++ {
		b := make([]byte, rng.Intn(64))
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		seeds = append(seeds, b)
	}

	// Every truncation prefix of every seed. This is the point of the corpus: the
	// four functions' `pos+N >= len(data)` bounds are not uniform, so the exact
	// byte at which each bails out is the thing most likely to drift.
	corpus := make([][]byte, 0, len(seeds)*8)
	for _, s := range seeds {
		corpus = append(corpus, s)
		for cut := 0; cut < len(s); cut++ {
			corpus = append(corpus, s[:cut:cut])
		}
	}

	// The seeds above top out at 63 bytes, so none of them reaches the three limit
	// arms in the shared loop: the maxBIFFPtgTokens break, the maxBIFFPtgStackDepth
	// drop in push, and the maxBIFFPtgOutputLen clamp. Those arms are shared by all
	// four dialects, so a drift there would be invisible above. Mutation testing
	// confirms the depth-cap and token-cap off-by-ones are caught only because of
	// the seeds below.
	//
	// Added AFTER the prefix expansion on purpose — these are long, and expanding
	// every prefix of a 64 KiB seed would add ~65k corpus entries and turn a 0.2s
	// test into a slow one. A handful of cuts per seed is enough, since the cap arms
	// trigger on accumulated state, not on a byte boundary.
	long := [][]byte{
		bytes.Repeat([]byte{ptgBool, 1}, maxBIFFPtgStackDepth+64),     // depth cap
		bytes.Repeat([]byte{ptgInt, 0x39, 0x30}, maxBIFFPtgTokens+64), // token cap
		bytes.Repeat([]byte{ptgConcat}, maxBIFFPtgTokens+64),          // pops on empty stack
	}

	// The TOKEN cap needs a stream that burns tokens WITHOUT pushing, or the depth
	// cap (4096) fires first and masks it: at 3 bytes per ptgInt, token 8192 lands
	// long after push stopped accepting. ptgParen advances pos and spends a token
	// while pushing nothing, so the token break is the only arm that can fire.
	// NOTE: this reaches the arm but cannot OBSERVE an off-by-one on it — a
	// ptgParen stream folds to "" either way, and the differential compares return
	// values. Interleave operands so the token at which the fold stops is visible
	// in the output, which is what makes a `>=` -> `>` flip detectable.
	// The break must also land ON a pushing token, or the off-by-one is invisible:
	// letting one extra ptgParen through pushes nothing. Keep the push count under
	// the depth cap so the token counter stays the binding constraint, and arrange
	// for the tokens at the boundary to be ptgBool (which pushes TRUE).
	for _, lead := range []int{4, 1, 0} {
		var s []byte
		pushes := 0
		for tok := 0; tok < maxBIFFPtgTokens+8; tok++ {
			if tok >= maxBIFFPtgTokens-lead && pushes < maxBIFFPtgStackDepth-8 {
				s = append(s, ptgBool, 1)
				pushes++
			} else {
				s = append(s, ptgParen)
			}
		}
		long = append(long, s)
	}

	// Operands at and over the output clamp. Note what these do NOT pin: flipping
	// either clamp's `len(s) > cap` to `>= cap` is INERT, because at exactly cap
	// the truncation s = s[:cap] is a no-op and returns the same string. Verified
	// against the old snapshot directly, not inferred. So these seeds exercise the
	// clamp arms and pin the truncation LENGTH; the comparison operator itself has
	// no observable behaviour to pin — same shape as the skipRef note above.
	{
		// Over the clamp: 0xffff 3-byte runes decode to 196605 bytes.
		s := []byte{ptgStr, 0xff, 0xff}
		for i := 0; i < 0xffff; i++ {
			s = append(s, 0x2c, 0x6f) // U+6F2C, 3 bytes in UTF-8
		}
		long = append(long, s)
		long = append(long, append(append([]byte{}, s...), ptgConcat))

		// EXACTLY on the clamp, which is the only length at which `len(s) > cap`
		// and `len(s) >= cap` disagree. 65536 is not divisible by 3, so 3-byte
		// runes can never land on it; 32768 2-byte runes (U+00E9) do.
		for _, n := range []int{32767, 32768, 32769} {
			e := []byte{ptgStr, byte(n & 0xff), byte(n >> 8)}
			for i := 0; i < n; i++ {
				e = append(e, 0xe9, 0x00) // U+00E9, 2 bytes in UTF-8
			}
			long = append(long, e)
			long = append(long, append(append([]byte{}, e...), ptgConcat))
		}
	}

	// Also cross the joinStack clamp from both sides via concatenation.
	for _, target := range []int{maxBIFFPtgOutputLen - 1, maxBIFFPtgOutputLen, maxBIFFPtgOutputLen + 1} {
		var s []byte
		emitted := 0
		for emitted+0xff <= target {
			s = append(s, ptgStr, 0xff, 0)
			s = append(s, bytes.Repeat([]byte("a"), 0xff)...)
			emitted += 0xff
			if emitted > 0xff {
				s = append(s, ptgConcat)
			}
		}
		if rem := target - emitted; rem > 0 {
			s = append(s, ptgStr, byte(rem), 0)
			s = append(s, bytes.Repeat([]byte("b"), rem)...)
			s = append(s, ptgConcat)
		}
		long = append(long, s)
	}

	for _, s := range long {
		corpus = append(corpus, s)
		// A few interior cuts, including odd offsets that land mid-payload.
		for _, cut := range []int{1, 2, 3, len(s) / 3, len(s) / 2, len(s) - 3, len(s) - 1} {
			if cut > 0 && cut < len(s) {
				corpus = append(corpus, s[:cut:cut])
			}
		}
	}
	return corpus
}

func TestBIFFPtgDifferentialOldVsNew(t *testing.T) {
	corpus := biffPtgCorpus(t)

	parsers := []struct {
		name string
		new  func([]byte) string
		old  func([]byte) string
	}{
		{"parseBIFF8Formula", parseBIFF8Formula, parseBIFF8FormulaOld},
		{"parseBIFF12Formula", parseBIFF12Formula, parseBIFF12FormulaOld},
		{"parseBIFF8FormulaWithRefs", parseBIFF8FormulaWithRefs, parseBIFF8FormulaWithRefsOld},
		{"parseBIFF12FormulaWithRefs", parseBIFF12FormulaWithRefs, parseBIFF12FormulaWithRefsOld},
	}

	cases := 0
	for _, p := range parsers {
		mismatches := 0
		for _, in := range corpus {
			got := p.new(in)
			want := p.old(in)
			cases++
			if got != want {
				mismatches++
				if mismatches <= 5 {
					t.Errorf("%s(%s): new=%q old=%q", p.name, fmt.Sprintf("% x", in), got, want)
				}
			}
		}
		if mismatches > 5 {
			t.Errorf("%s: %d further mismatches suppressed", p.name, mismatches-5)
		}
	}
	if !t.Failed() {
		t.Logf("differential: %d inputs x %d parsers = %d comparisons, all byte-identical",
			len(corpus), len(parsers), cases)
	}
}
