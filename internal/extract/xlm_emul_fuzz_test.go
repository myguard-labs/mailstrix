package extract

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

// encodeFuzzCell serialises a single xlmCell into the wire format used by
// decodeFuzzCells. Format per record:
//
//	coord_len   uint8   (0 = terminator)
//	coord       [coord_len]byte
//	formula_len uint16 LE
//	formula     [formula_len]byte
//	value_len   uint16 LE
//	value       [value_len]byte
func encodeFuzzCell(coord, formula, value string) []byte {
	if len(coord) > 255 {
		coord = coord[:255]
	}
	var buf []byte
	buf = append(buf, byte(len(coord)))
	buf = append(buf, []byte(coord)...)
	flen := [2]byte{}
	binary.LittleEndian.PutUint16(flen[:], uint16(len(formula)))
	buf = append(buf, flen[:]...)
	buf = append(buf, []byte(formula)...)
	vlen := [2]byte{}
	binary.LittleEndian.PutUint16(vlen[:], uint16(len(value)))
	buf = append(buf, vlen[:]...)
	buf = append(buf, []byte(value)...)
	return buf
}

// decodeFuzzCells parses the compact wire format produced by encodeFuzzCell.
// It is fail-open: any truncation or out-of-range field stops the loop and
// returns whatever cells were decoded so far. Maximum 128 cells are decoded
// to prevent OOM on large corpus entries.
func decodeFuzzCells(data []byte) []xlmCell {
	const maxCells = 128
	var cells []xlmCell
	i := 0
	for i < len(data) && len(cells) < maxCells {
		// coord_len (uint8); 0 = end-of-stream.
		coordLen := int(data[i])
		i++
		if coordLen == 0 {
			break
		}
		if i+coordLen > len(data) {
			break
		}
		coord := string(data[i : i+coordLen])
		i += coordLen

		// formula_len (uint16 LE).
		if i+2 > len(data) {
			break
		}
		formulaLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
		i += 2
		if i+formulaLen > len(data) {
			break
		}
		formula := string(data[i : i+formulaLen])
		i += formulaLen

		// value_len (uint16 LE).
		if i+2 > len(data) {
			break
		}
		valueLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
		i += 2
		if i+valueLen > len(data) {
			break
		}
		value := string(data[i : i+valueLen])
		i += valueLen

		cells = append(cells, xlmCell{coord: coord, formula: formula, value: value})
	}
	return cells
}

// FuzzEmulateXLM verifies three invariants of emulateXLMCells for arbitrary
// byte inputs:
//
//  1. Never panics (a panic propagates through f.Fuzz and fails the run).
//  2. Always terminates (enforced by the 5-second deadline passed to the fn).
//  3. totalOutput never exceeds maxXLMFoldOutputLen after the call returns.
func FuzzEmulateXLM(f *testing.F) {
	// Seed 1: empty / nil input.
	f.Add([]byte(nil))
	f.Add([]byte{})

	// Seed 2: GOTO chain — A1 jumps to A3; A3 halts.
	{
		s := encodeFuzzCell("A1", "=GOTO(A3)", "")
		s = append(s, encodeFuzzCell("A3", "=HALT()", "")...)
		s = append(s, 0x00) // terminator
		f.Add(s)
	}

	// Seed 3: IF with both branches — A2 and A3 are reachable.
	{
		s := encodeFuzzCell("A1", `=IF(TRUE,A2,A3)`, "")
		s = append(s, encodeFuzzCell("A2", `=EXEC("yes")`, "")...)
		s = append(s, encodeFuzzCell("A3", `=EXEC("no")`, "")...)
		s = append(s, 0x00)
		f.Add(s)
	}

	// Seed 4: WHILE+NEXT loop.
	{
		s := encodeFuzzCell("A1", "=WHILE(TRUE)", "")
		s = append(s, encodeFuzzCell("A2", "=NEXT()", "")...)
		s = append(s, 0x00)
		f.Add(s)
	}

	// Seed 5: SET.VALUE + CALL into kernel32.
	{
		s := encodeFuzzCell("A1", `=SET.VALUE(B1,"cmd")`, "")
		s = append(s, encodeFuzzCell("B1", `=CALL("kernel32","VirtualAlloc","JJJJJ",0,4096,4096,64)`, "")...)
		s = append(s, 0x00)
		f.Add(s)
	}

	// Seed 6: self-GOTO (tight loop, must be fuse-capped).
	{
		s := encodeFuzzCell("A1", "=GOTO(A1)", "")
		s = append(s, 0x00)
		f.Add(s)
	}

	// Seed 7: 64-nested-IF chain — A1→A2→…→A64→EXEC("deep").
	{
		var s []byte
		for n := 1; n <= 63; n++ {
			formula := fmt.Sprintf("=IF(TRUE,A%d,HALT())", n+1)
			s = append(s, encodeFuzzCell(fmt.Sprintf("A%d", n), formula, "")...)
		}
		s = append(s, encodeFuzzCell("A64", `=EXEC("deep")`, "")...)
		s = append(s, 0x00)
		f.Add(s)
	}

	// Seed 8: circular SET.VALUE — cell writes to itself.
	{
		s := encodeFuzzCell("A1", "=SET.VALUE(A1,CHAR(65))", "")
		s = append(s, 0x00)
		f.Add(s)
	}

	// Seed 9: pure random garbage.
	f.Add([]byte{0xFF, 0xFE, 0x00, 0xAB, 0xCD, 0xEF, 0x42, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		cells := decodeFuzzCells(data)

		out := make([][]byte, 0, 16)
		totalOutput := 0

		// Invariant 2: always terminates within the deadline. Use a SHORT 1s
		// budget. evalExpr now checks the deadline INSIDE the A1-resolve inner
		// loop (not just at pass boundaries), so a pathological single cell with
		// many cross-refs can overrun by at most the cost of ~64 ref resolves —
		// previously a whole inner pass (~1.5s seen on a crafted input) could leak
		// past a pass-boundary-only check. A short budget keeps per-exec wall-clock
		// bounded so 32 parallel fuzz workers don't OOM/timeout (exit status 2).
		deadline := time.Now().Add(1 * time.Second)
		start := time.Now()
		emulateXLMCells(cells, &out, &totalOutput, deadline)
		// Guard the overrun explicitly: terminate must be within a small multiple of
		// the budget. A gross overrun (>2×) is a real deadline-respect regression.
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("emulateXLMCells ran %v on a 1s deadline — deadline not respected", el)
		}

		// Invariant 3: output never exceeds the global cap.
		if totalOutput > maxXLMFoldOutputLen {
			t.Fatalf("totalOutput %d exceeds cap %d", totalOutput, maxXLMFoldOutputLen)
		}
	})
}
