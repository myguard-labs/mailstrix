package extract

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Light static constant-folding of VBA/VBScript string obfuscation. A second
// cheap, deterministic deobf layer on top of the base64/hex/reverse decoders in
// decode.go: instead of reversing an ENCODING, it evaluates a small set of
// constant EXPRESSIONS that malware authors use to keep a keyword/URL/IOC out of
// the raw bytes — split string concatenation (`"po" & Chr(119) & "ershell"`),
// literal `Replace("...","...","...")`, and a literal `Array(72,101,...)` byte
// list (optionally single-byte-XORed by a literal key). The folded result is
// emitted as an extra stream so the maldoc rules match the reassembled content.
//
// Deliberately NOT an interpreter (per the decode.go contract): no control flow,
// no loop execution, no variable dataflow, depth cap 1. Only fully-literal
// expressions are folded — every operand is a string/number literal lexically
// present in the source, so the result is exactly what the runtime would build,
// with no guessing. A folded blob is never re-folded (it is appended after the
// source snapshot, like every other transform). Everything is bounded and
// fail-open: an unparseable expression just yields no extra stream.
const (
	// maxFoldInput bounds the per-source cost of the regex scans below; a buffer
	// larger than this is almost never a hand-written macro carrier.
	maxFoldInput = 1 << 20
	// maxFoldMatches caps how many expressions of each kind we evaluate per
	// source, so a buffer packed with Chr()/Array() runs cannot spin the CPU
	// (the global emit caps already bound the OUTPUT; this bounds the WORK).
	maxFoldMatches = 256
	// maxArrayElems caps the element count of one Array() literal we decode.
	maxArrayElems = maxBytesPerDecodedBlob
	// maxXorKeys caps how many distinct literal XOR keys we apply to one Array()
	// (the trivial single-byte decoder: pattern-recognise the key, apply once).
	maxXorKeys = 4
)

var (
	// One concatenation token: a VBA string literal ("" is an escaped quote) or a
	// Chr/ChrW/ChrB/ChrW$ call on a decimal or &H-hex literal.
	reFoldToken = `(?:"(?:[^"]|"")*"|(?i:chr[wb]?\$?)\s*\(\s*(?:&[hH][0-9A-Fa-f]+|\d+)\s*\))`
	// A concatenation chain: two or more tokens joined by & or +. Requiring a join
	// avoids folding a lone bare literal (which the raw scan already sees).
	reFoldChain = regexp.MustCompile(reFoldToken + `(?:\s*[&+]\s*` + reFoldToken + `)+`)
	// Pull the individual tokens back out of a matched chain.
	reFoldTok = regexp.MustCompile(reFoldToken)
	// Replace("expr","find","with") with all three operands string literals.
	reFoldReplace = regexp.MustCompile(`(?i:replace)\s*\(\s*("(?:[^"]|"")*")\s*,\s*("(?:[^"]|"")*")\s*,\s*("(?:[^"]|"")*")\s*\)`)
	// Array(72, 101, ...) of integer literals (decimal or &H), the body captured.
	reFoldArray = regexp.MustCompile(`(?i:array)\s*\(\s*((?:&[hH][0-9A-Fa-f]+|\d+)\s*(?:,\s*(?:&[hH][0-9A-Fa-f]+|\d+)\s*)+)\)`)
	// A literal single-byte XOR key used by a trivial in-loop decoder. We do not
	// execute the loop; we just harvest the constant and apply it once.
	reFoldXorKey = regexp.MustCompile(`(?i:xor)\s+(&[hH][0-9A-Fa-f]+|\d+)\b`)
)

// foldVBAConst evaluates the constant string-building expressions in src and
// emits each folded result. Returns false on a global emit cap (stop everything).
func foldVBAConst(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	if len(src) == 0 || len(src) > maxFoldInput {
		return true
	}
	if !foldConcat(src, deadline, emit) {
		return false
	}
	if !foldReplace(src, emit) {
		return false
	}
	return foldArray(src, emit)
}

// foldConcat reassembles `"a" & Chr(98) & "c"`-style concatenation chains.
func foldConcat(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	chains := reFoldChain.FindAll(src, maxFoldMatches)
	for _, chain := range chains {
		if expired(deadline) {
			return true
		}
		var b strings.Builder
		for _, tok := range reFoldTok.FindAll(chain, -1) {
			if tok[0] == '"' {
				b.WriteString(unquoteVBA(tok))
				continue
			}
			if n, ok := parseChrArg(tok); ok {
				b.WriteByte(byte(n))
			}
		}
		if !emit([]byte(b.String())) {
			return false
		}
	}
	return true
}

// foldReplace evaluates Replace() over fully-literal operands.
func foldReplace(src []byte, emit func([]byte) bool) bool {
	for _, m := range reFoldReplace.FindAllSubmatch(src, maxFoldMatches) {
		hay := unquoteVBA(m[1])
		find := unquoteVBA(m[2])
		repl := unquoteVBA(m[3])
		if find == "" { // VBA Replace with an empty Find returns the source unchanged
			continue
		}
		if !emit([]byte(strings.ReplaceAll(hay, find, repl))) {
			return false
		}
	}
	return true
}

// foldArray decodes Array(n,n,...) byte lists, plus a single-byte-XORed variant
// for each literal XOR key present in the source (the trivial decoder pattern).
func foldArray(src []byte, emit func([]byte) bool) bool {
	keys := xorKeys(src)
	for _, m := range reFoldArray.FindAllSubmatch(src, maxFoldMatches) {
		raw, ok := parseByteArray(m[1])
		if !ok {
			continue
		}
		if !emit(raw) {
			return false
		}
		for _, k := range keys {
			out := make([]byte, len(raw))
			for i := range raw {
				out[i] = raw[i] ^ k
			}
			if !emit(out) {
				return false
			}
		}
	}
	return true
}

// xorKeys returns up to maxXorKeys distinct in-range literal XOR keys in src.
func xorKeys(src []byte) []byte {
	var keys []byte
	seen := make(map[byte]bool)
	for _, m := range reFoldXorKey.FindAllSubmatch(src, -1) {
		n, ok := parseIntLit(string(m[1]))
		if !ok || n < 1 || n > 255 || seen[byte(n)] {
			continue
		}
		seen[byte(n)] = true
		keys = append(keys, byte(n))
		if len(keys) >= maxXorKeys {
			break
		}
	}
	return keys
}

// parseByteArray turns an Array() body ("72, 101, &H6C") into bytes, requiring
// every element be an integer in 0..255 (so a non-byte array yields nothing).
func parseByteArray(body []byte) ([]byte, bool) {
	parts := strings.Split(string(body), ",")
	if len(parts) > maxArrayElems {
		parts = parts[:maxArrayElems]
	}
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		n, ok := parseIntLit(strings.TrimSpace(p))
		if !ok || n < 0 || n > 255 {
			return nil, false
		}
		out = append(out, byte(n))
	}
	return out, true
}

// parseChrArg extracts the integer argument of a Chr(...) token, mod 256.
func parseChrArg(tok []byte) (int, bool) {
	i := bytes.IndexByte(tok, '(')
	j := bytes.LastIndexByte(tok, ')')
	if i < 0 || j <= i {
		return 0, false
	}
	n, ok := parseIntLit(strings.TrimSpace(string(tok[i+1 : j])))
	if !ok {
		return 0, false
	}
	return n & 0xff, true
}

// parseIntLit parses a VBA integer literal: decimal or &H-prefixed hex.
func parseIntLit(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	if len(s) > 2 && (s[0] == '&') && (s[1] == 'h' || s[1] == 'H') {
		v, err := strconv.ParseInt(s[2:], 16, 32)
		if err != nil {
			return 0, false
		}
		return int(v), true
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}

// unquoteVBA strips the surrounding quotes of a VBA string literal and collapses
// the doubled-quote escape ("") to a single quote.
func unquoteVBA(tok []byte) string {
	s := string(tok)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, `""`, `"`)
}
