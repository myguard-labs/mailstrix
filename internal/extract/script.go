package extract

import (
	"bytes"
	"time"
)

// MS Script Encoder ("screnc") support. screnc turns a VBScript/JScript source
// into an opaque blob wrapped in `#@~^......==<encoded>......==^#~@`, used by
// .vbe/.jse files and embedded inside .wsf/.hta/.html/.sct. The encoding is a
// fixed, reversible per-character substitution (NOT encryption): decoding it
// back to cleartext lets yarad's keyword rules match the real script. The
// algorithm is public and unchanged for ~20 years; the tables below are the
// canonical ones from Didier Stevens' decode-vbe.py and the original motobit
// decoder.
//
// Reference: https://github.com/DidierStevens/DidierStevensSuite/blob/master/decode-vbe.py

const (
	scriptStart = "#@~^"
	scriptEnd   = "^#~@"
	// maxEncodedScripts bounds how many blocks we decode from one buffer.
	maxEncodedScripts = 64
	// maxDecodedScript caps one decoded block (a guard, not a real-script limit).
	maxDecodedScript = 4 << 20
)

// decChar[encodedByte][pick] -> cleartext byte.
// Canonical screnc decode table, verbatim from Didier Stevens' decode-vbe.py
// dDecode dict (keys 9–127). Bytes 0–8 and 14–31 are control bytes that pass
// through unchanged (zero entry → pass-through in decodeScript). Bytes 60
// (<), 62 (>), and 64 (@) are also passed through (screnc never encodes them
// into the substitution range; @ introduces 2-char escape sequences instead).
var decChar = [128][3]byte{
	9:   {0x57, 0x6e, 0x7b},
	10:  {0x4a, 0x4c, 0x41},
	11:  {0x0b, 0x0b, 0x0b},
	12:  {0x0c, 0x0c, 0x0c},
	13:  {0x4a, 0x4c, 0x41},
	14:  {0x0e, 0x0e, 0x0e},
	15:  {0x0f, 0x0f, 0x0f},
	16:  {0x10, 0x10, 0x10},
	17:  {0x11, 0x11, 0x11},
	18:  {0x12, 0x12, 0x12},
	19:  {0x13, 0x13, 0x13},
	20:  {0x14, 0x14, 0x14},
	21:  {0x15, 0x15, 0x15},
	22:  {0x16, 0x16, 0x16},
	23:  {0x17, 0x17, 0x17},
	24:  {0x18, 0x18, 0x18},
	25:  {0x19, 0x19, 0x19},
	26:  {0x1a, 0x1a, 0x1a},
	27:  {0x1b, 0x1b, 0x1b},
	28:  {0x1c, 0x1c, 0x1c},
	29:  {0x1d, 0x1d, 0x1d},
	30:  {0x1e, 0x1e, 0x1e},
	31:  {0x1f, 0x1f, 0x1f},
	32:  {0x2e, 0x2d, 0x32},
	33:  {0x47, 0x75, 0x30},
	34:  {0x7a, 0x52, 0x21},
	35:  {0x56, 0x60, 0x29},
	36:  {0x42, 0x71, 0x5b},
	37:  {0x6a, 0x5e, 0x38},
	38:  {0x2f, 0x49, 0x33},
	39:  {0x26, 0x5c, 0x3d},
	40:  {0x49, 0x62, 0x58},
	41:  {0x41, 0x7d, 0x3a},
	42:  {0x34, 0x29, 0x35},
	43:  {0x32, 0x36, 0x65},
	44:  {0x5b, 0x20, 0x39},
	45:  {0x76, 0x7c, 0x5c},
	46:  {0x72, 0x7a, 0x56},
	47:  {0x43, 0x7f, 0x73},
	48:  {0x38, 0x6b, 0x66},
	49:  {0x39, 0x63, 0x4e},
	50:  {0x70, 0x33, 0x45},
	51:  {0x45, 0x2b, 0x6b},
	52:  {0x68, 0x68, 0x62},
	53:  {0x71, 0x51, 0x59},
	54:  {0x4f, 0x66, 0x78},
	55:  {0x09, 0x76, 0x5e},
	56:  {0x62, 0x31, 0x7d},
	57:  {0x44, 0x64, 0x4a},
	58:  {0x23, 0x54, 0x6d},
	59:  {0x75, 0x43, 0x71},
	60:  {0x4a, 0x4c, 0x41}, // '<' — but screnc treats 60 as pass-through (see decodeScript)
	61:  {0x7e, 0x3a, 0x60},
	62:  {0x4a, 0x4c, 0x41}, // '>' — screnc treats 62 as pass-through (see decodeScript)
	63:  {0x5e, 0x7e, 0x53},
	64:  {0x40, 0x4c, 0x40}, // '@' — never reaches the table (escape handler catches it first)
	65:  {0x77, 0x45, 0x42},
	66:  {0x4a, 0x2c, 0x27},
	67:  {0x61, 0x2a, 0x48},
	68:  {0x5d, 0x74, 0x72},
	69:  {0x22, 0x27, 0x75},
	70:  {0x4b, 0x37, 0x31},
	71:  {0x6f, 0x44, 0x37},
	72:  {0x4e, 0x79, 0x4d},
	73:  {0x3b, 0x59, 0x52},
	74:  {0x4c, 0x2f, 0x22},
	75:  {0x50, 0x6f, 0x54},
	76:  {0x67, 0x26, 0x6a},
	77:  {0x2a, 0x72, 0x47},
	78:  {0x7d, 0x6a, 0x64},
	79:  {0x74, 0x39, 0x2d},
	80:  {0x54, 0x7b, 0x20},
	81:  {0x2b, 0x3f, 0x7f},
	82:  {0x2d, 0x38, 0x2e},
	83:  {0x2c, 0x77, 0x4c},
	84:  {0x30, 0x67, 0x5d},
	85:  {0x6e, 0x53, 0x7e},
	86:  {0x6b, 0x47, 0x6c},
	87:  {0x66, 0x34, 0x6f},
	88:  {0x35, 0x78, 0x79},
	89:  {0x25, 0x5d, 0x74},
	90:  {0x21, 0x30, 0x43},
	91:  {0x64, 0x23, 0x26},
	92:  {0x4d, 0x5a, 0x76},
	93:  {0x52, 0x5b, 0x25},
	94:  {0x63, 0x6c, 0x24},
	95:  {0x3f, 0x48, 0x2b},
	96:  {0x7b, 0x55, 0x28},
	97:  {0x78, 0x70, 0x23},
	98:  {0x29, 0x69, 0x41},
	99:  {0x28, 0x2e, 0x34},
	100: {0x73, 0x4c, 0x09},
	101: {0x59, 0x21, 0x2a},
	102: {0x33, 0x24, 0x44},
	103: {0x7f, 0x4e, 0x3f},
	104: {0x6d, 0x50, 0x77},
	105: {0x55, 0x09, 0x3b},
	106: {0x53, 0x56, 0x55},
	107: {0x7c, 0x73, 0x69},
	108: {0x3a, 0x35, 0x61},
	109: {0x5f, 0x61, 0x63},
	110: {0x65, 0x4b, 0x50},
	111: {0x46, 0x58, 0x67},
	112: {0x58, 0x3b, 0x51},
	113: {0x31, 0x57, 0x49},
	114: {0x69, 0x22, 0x4f},
	115: {0x6c, 0x6d, 0x46},
	116: {0x5a, 0x4d, 0x68},
	117: {0x48, 0x25, 0x7c},
	118: {0x27, 0x28, 0x36},
	119: {0x5c, 0x46, 0x70},
	120: {0x3d, 0x4a, 0x6e},
	121: {0x24, 0x32, 0x7a},
	122: {0x79, 0x41, 0x2f},
	123: {0x37, 0x3d, 0x5f},
	124: {0x60, 0x5f, 0x4b},
	125: {0x51, 0x4f, 0x5a},
	126: {0x20, 0x42, 0x2c},
	127: {0x36, 0x65, 0x57},
}

// combination[i] selects which column (0, 1, or 2) of decChar to use for the
// i-th decoded character (index % 64). The index increments for every input
// byte < 128, including pass-through whitespace bytes that don't go through
// the table — matching the reference implementation exactly.
// Source: decode-vbe.py dCombination dict.
var combination = [64]byte{
	0, 1, 2, 0, 1, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 2,
	0, 2, 1, 2, 0, 0, 1, 2, 2, 1, 0, 2, 1, 2, 2, 1,
	0, 0, 2, 1, 2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 2, 1,
	0, 2, 1, 2, 0, 0, 1, 2, 2, 0, 0, 1, 2, 0, 2, 1,
}

// fromEncodedScript finds and decodes every screnc block in buf, appending each
// cleartext result to res.Streams. It sets EncodedScript when at least one block
// decoded. Best-effort: a malformed/truncated block is skipped, the rest stand.
func fromEncodedScript(buf []byte, res *Result, deadline time.Time) {
	if !bytes.Contains(buf, []byte(scriptStart)) {
		return
	}
	rest := buf
	var emitted int // THIS buffer's decoded-block count, not global len(res.Streams)
	for len(res.Streams) < maxStreams && emitted < maxEncodedScripts && !expired(deadline) {
		i := bytes.Index(rest, []byte(scriptStart))
		if i < 0 {
			break
		}
		// Skip the marker and the 6-char length + "==" prefix (8 bytes) screnc
		// writes before the encoded body. Be defensive about a truncated header.
		body := rest[i+len(scriptStart):]
		if len(body) < 8 {
			break
		}
		body = body[8:]
		end := bytes.Index(body, []byte(scriptEnd))
		if end < 0 {
			break // no terminator: truncated/hostile, stop
		}
		clear := decodeScript(body[:end])
		if len(clear) > 0 {
			res.Streams = append(res.Streams, clear)
			res.EncodedScript = true
			emitted++
		}
		rest = body[end+len(scriptEnd):]
	}
}

// decodeScript reverses the screnc substitution over one encoded body.
//
// Algorithm (faithful to decode-vbe.py):
//  1. Pre-process 2-char @-escape sequences: @& → \n, @# → \r, @* → >,
//     @! → <, @$ → @.
//  2. For each remaining byte: if it is < 128, increment the index counter.
//     If it is in the substitution range (byte == 9 OR 32 ≤ byte ≤ 127,
//     excluding 60, 62, 64), look it up in decChar[byte][combination[index%64]]
//     to get the cleartext byte. Otherwise emit it as-is.
func decodeScript(enc []byte) []byte {
	out := make([]byte, 0, len(enc))
	index := 0
	i := 0
	for i < len(enc) {
		c := enc[i]

		// Handle @-escape sequences (pre-processing step).
		if c == '@' && i+1 < len(enc) {
			i++
			switch enc[i] {
			case '&':
				out = append(out, '\n')
			case '#':
				out = append(out, '\r')
			case '*':
				out = append(out, '>')
			case '!':
				out = append(out, '<')
			case '$':
				out = append(out, '@')
			}
			// Unknown @-escape: drop both bytes (matches reference behaviour).
			// Do NOT increment index: the @ char consumed here was not a
			// substitutable byte, so it doesn't advance the combination counter.
			i++
			continue
		}

		// The index counter advances for every byte < 128 (including
		// pass-through bytes), mirroring the reference implementation.
		if c < 128 {
			pick := combination[index%64]
			index++
			// Substitution range: byte 9 (tab) or printable ASCII 32–127,
			// but NOT 60 ('<'), 62 ('>'), or 64 ('@') — those pass through.
			if (c == 9 || (c >= 32 && c <= 127)) && c != 60 && c != 62 && c != 64 {
				out = append(out, decChar[c][pick])
			} else {
				out = append(out, c)
			}
		} else {
			// High bytes (>= 128) pass through without touching the counter.
			out = append(out, c)
		}

		i++
		if len(out) >= maxDecodedScript {
			break
		}
	}
	return out
}
