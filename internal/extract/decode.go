package extract

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Static multi-layer deobfuscation. Malware authors hide a payload (a URL, a
// PowerShell one-liner, a dropped EXE) inside an otherwise-cleartext script or
// macro by base64/hex-encoding it, writing keywords backwards (VBA StrReverse),
// or stacking several such layers. A raw keyword scan never sees the payload
// because the bytes on disk are the encoded form. fromEncoded reverses the cheap,
// deterministic transforms — base64, hex, a whole-buffer reverse, and the VBA
// string-building folds — over the raw buffer and every already-extracted
// cleartext stream, emitting each decoded result as an extra stream so the
// keyword/maldoc rules match the real content.
//
// This is the tractable slice of oletools' deobfuscation: static transforms, NOT
// emulation. Unlike the original single-pass version, it now CHAINS: a decoded
// blob that still looksEncoded is fed back through the decoders one layer deeper,
// up to maxDecodeDepth (MSD-1), so a Dridex-style nested payload is unwrapped. It
// still does not interpret VBA or evaluate XLM/Excel-4.0 macros; that emulation
// tail stays with olevba/ViperMonkey (rspamd-olefy).
//
// Everything is bounded and fail-open: a source that decodes to nothing, a cap
// hit, or a malformed run just yields fewer streams — never an error. The
// recursion is bounded by a per-source blob/byte budget (reset per source stream,
// shared across its depths), a depth cap, and a per-source iteration cap.

const (
	// minBase64Run / minHexRun are the shortest encoded runs we bother decoding.
	// Short runs are almost always coincidental (a word, a short id) and decoding
	// them just adds noise; a real hidden payload is long. 24 base64 chars decode
	// to 18 bytes; 32 hex chars to 16 bytes.
	minBase64Run = 24
	minHexRun    = 32
	// PERF-4: minPrefilterRun is the contiguous run-length threshold the cheap
	// scalar prefilter (mayBeEncoded) uses before the decode chain / looksEncoded
	// regex work. It MUST be <= the smallest minimum-run of every alphabet-class
	// decoder so the prefilter can never skip a buffer a decoder would have
	// accepted. The alphabet-class decoders' minimum encoded-run lengths are:
	// base64=24, hex=32, netbios=32, base32=32, and the Dridex fold's quoted
	// alnum literal =20 (reDridex `"[0-9A-Za-z]{20,}"`). 20 is the smallest, so
	// minPrefilterRun=20: any run a decoder would match is >= 20 contiguous
	// base64-alphabet bytes and thus passes the gate. Lower than every threshold
	// = strict pre-gate (false-positive only; never a false-negative skip).
	minPrefilterRun = 20
	// minPrefilterDecRun is the run-length gate for the decimal-sequence decoder
	// (reDecSeq = `\d{1,3}(?:[;,]\d{1,3}){11,}`). Its shortest match is 12 groups
	// of >=1 digit separated by 11 single-char separators: 12 + 11 = 23 contiguous
	// bytes from the class [0-9,;]. 23 is exact-minimum, so use it directly (a run
	// shorter than 23 of that class can never satisfy reDecSeq).
	minPrefilterDecRun = 23
	// minDecodedLen drops a decode result too short to carry a keyword/URL.
	minDecodedLen = 8
	// maxDecodedBlobs caps how many decoded streams one buffer can add (across all
	// transforms and all source streams), maxBytesPerDecodedBlob caps one blob,
	// and maxCumulativeDecoded caps their total — so a buffer packed with encoded
	// runs cannot blow up the scan budget.
	maxDecodedBlobs        = 32
	maxBytesPerDecodedBlob = 1 << 20
	maxCumulativeDecoded   = 4 << 20
	// maxDecodeDepth bounds the recursive multi-layer decode (MSD-1): each source
	// stream is depth 0, and every decoded blob that still looksEncoded is
	// re-decoded one layer deeper, up to this depth. olevba unpacks Dridex-style
	// payloads to roughly this many layers.
	maxDecodeDepth = 4
	// maxDecodeIterations is a hard cap on worklist dequeues PER SOURCE stream — a
	// safety floor against a decode cycle or fan-out that the depth and blob/byte
	// budgets somehow don't already stop (the blob budget normally bites first).
	maxDecodeIterations = 256
	// deepDecodeLayer is the decode-layer at/after which a successfully emitted blob
	// is treated as a strong maliciousness signal (RULE-MSD-MULTILAYER). The source
	// is layer 0; a blob decoded out of the source is layer 1; a blob decoded out of
	// THAT is layer 2; etc. A blob surfacing at layer >= this many stacked decodes
	// (base64-over-hex-over-… nesting) has no benign analogue — legitimate content is
	// never multiply re-encoded — so decodeSourceTree emits ONE "MSD-DEEPDECODE
	// depth=<n>" marker per source tree carrying the deepest layer reached, and a
	// YARA rule scores it. 3 == three stacked decode passes produced output.
	deepDecodeLayer = 3
	// maxB64Encoded / maxHexEncoded bound the ENCODED candidate length we hand to
	// a decoder, so one giant run can't allocate/copy far past maxBytesPerDecodedBlob
	// before the emit cap truncates (base64 expands ~4/3, hex 2x). Both stay
	// alignment-valid (mult of 4 / mult of 2) when we slice a prefix.
	maxB64Encoded = (maxBytesPerDecodedBlob/3 + 1) * 4
	maxHexEncoded = maxBytesPerDecodedBlob * 2

	// MSD-encodings: per-encoding run-length constants.
	// minXxx is the minimum number of encoded units in a run for us to bother;
	// maxXxxEncoded is the longest encoded candidate we hand to the decoder.
	minXEscRun     = 8 // min \xHH escapes (each 4 encoded bytes)
	maxXEscEncoded = maxBytesPerDecodedBlob * 4
	minAmpHRun     = 8 // min &HXX groups
	// &HXX with NO separator is the densest form (4 encoded chars per byte:
	// "&H" + 2 hex), so the worst-case decoded size is encoded/4. ×4 keeps the
	// pre-emit allocation at maxBytesPerDecodedBlob even on a separator-less run
	// (a ×5 cap would let a dense run alloc 1.25 MiB before emit truncates).
	maxAmpHEncoded    = maxBytesPerDecodedBlob * 4
	minUEscRun        = 8 // min \uXXXX / %uXXXX units
	maxUEscEncoded    = maxBytesPerDecodedBlob * 6
	minDecSeqRun      = 12 // min decimal-separated tokens (1 + at least 11 more)
	maxDecSeqEncoded  = maxBytesPerDecodedBlob * 4
	minNetbiosRun     = 32 // min NETBIOS-encoded chars (16 decoded bytes)
	maxNetbiosEncoded = maxBytesPerDecodedBlob * 2
	minBase32Run      = 32 // min base32 chars (20 decoded bytes)
	maxBase32Encoded  = (maxBytesPerDecodedBlob/5 + 1) * 8

	// maxReverseInput bounds the per-source cost of the whole-buffer reverse.
	maxReverseInput = 1 << 20
	// maxFoldInput bounds the source length scanned by the VBA fold regexes
	// (Chr/Replace/Xor concat). RE2 is linear, so this caps worst-case CPU/alloc
	// on a pathological multi-MiB script, not a backtracking blow-up.
	maxFoldInput = 1 << 20
	// textSample / textPrintablePct gate transforms to mostly-printable sources:
	// base64/hex/reverse over a binary container (an OLE2/PDF body) is pure noise,
	// so we only run them on script/text carriers and on the decompressed cleartext
	// streams the format extractors already surfaced.
	textSample       = 4096
	textPrintablePct = 90

	// UTF-16 BOM-less detection (transcodeUTF16). utf16MinSample is the minimum
	// byte count before the alternating-NUL heuristic is trusted (too-short
	// buffers give noisy parity stats). utf16NULHighPct is the minimum NUL fraction
	// required on the "high" parity (the byte that is 0x00 for ASCII-range wide
	// text); utf16NULLowPct is the maximum NUL fraction tolerated on the other
	// parity. The gap between them is what separates real wide text from a binary
	// blob whose NULs fall on both parities.
	utf16MinSample  = 16
	utf16NULHighPct = 60
	utf16NULLowPct  = 20
)

var (
	// A maximal run of base64-alphabet bytes with optional padding.
	reBase64 = regexp.MustCompile(fmt.Sprintf(`[A-Za-z0-9+/]{%d,}={0,2}`, minBase64Run))
	// A run of an even number of hex digits (grouped in pairs so the match is
	// always byte-aligned for hex.DecodeString).
	reHex = regexp.MustCompile(fmt.Sprintf(`(?:[0-9A-Fa-f]{2}){%d,}`, minHexRun/2))
	// VBA Chr(N)/ChrW(N) with optional surrounding concat operators and string literals.
	// VBA uses "" to escape a literal " inside a string, so we allow doubled-quote
	// escapes with (?:[^"]|"")* instead of [^"]*.
	reChrConcat = regexp.MustCompile(`(?i)(?:"(?:[^"]|"")*"|Chr[W]?\(\d{1,5}\))(?:\s*[&+]\s*(?:"(?:[^"]|"")*"|Chr[W]?\(\d{1,5}\)))+`)

	// VBA Replace("str","old","new") with all literal string arguments.
	reReplace = regexp.MustCompile(`(?i)Replace\(\s*"((?:[^"]|"")*)"\s*,\s*"((?:[^"]|"")*)"\s*,\s*"((?:[^"]|"")*)"\s*\)`)

	// VBA Array(N,N,...) Xor K — trivial single-byte XOR decoder.
	reArrayXor = regexp.MustCompile(`(?i)Array\(([\d,\s]+)\)\s*Xor\s+(\d{1,3})`)

	// VBA StrReverse("literal") — reverse a static string argument. olevba folds
	// this; we reassemble the cleartext so keyword rules see e.g. the un-reversed
	// "powershell". Only a single quoted literal argument (not an expression);
	// runtime-reversed expressions are still caught by the whole-buffer reverse
	// gated on reversedMarkers below.
	reStrReverse = regexp.MustCompile(`(?i)StrReverse\(\s*"((?:[^"]|"")*)"\s*\)`)

	// VBA Environ("NAME") / Environ$("NAME") — an environment-variable lookup.
	// olevba folds this to "%NAME%" (olevba.py:1088); we emit a prefixed
	// "VBA-ENVIRON %NAME%" marker (the prefix clears the minDecodedLen floor a
	// bare "%TEMP%" would miss and gives rules a fixed token), so a rule can flag
	// env-var probing (Environ("APPDATA"), Environ("TEMP"), …) a dropper uses to
	// build a path. Only a quoted-literal name is folded; the numeric-index form
	// Environ(1) returns a value we can't know statically.
	reEnviron = regexp.MustCompile(`(?i)Environ\$?\(\s*"((?:[^"]|"")*)"\s*\)`)

	// Tokens inside a Chr/ChrW concat chain: a string literal or a Chr(N) call.
	reChrTok = regexp.MustCompile(`(?i)"((?:[^"]|"")*)"|Chr[W]?\((\d{1,5})\)`)

	// Dridex-obfuscated string literal: a quoted run of >=20 alphanumerics
	// (olevba.py:899 re_dridex_string). dridexNotHex gates out plain hex strings
	// (a Dridex blob must contain a non-hex letter G-Z/g-z; olevba.py:901).
	reDridex     = regexp.MustCompile(`"[0-9A-Za-z]{20,}"`)
	dridexNotHex = regexp.MustCompile(`[G-Zg-z]`)

	// VBA simple string-variable assignment: identifier = "literal"
	// (case-insensitive; identifier must start with a letter).
	reVBAStrAssign = regexp.MustCompile(`(?im)^[ \t]*([A-Za-z]\w{0,63})\s*=\s*"((?:[^"]|"")*)"`)

	// VBA trivial alias: identifier = otherIdentifier (no quotes, no operators).
	reVBAAlias = regexp.MustCompile(`(?im)^[ \t]*([A-Za-z]\w{0,63})\s*=\s*([A-Za-z]\w{0,63})\s*$`)

	// Replace() call where each arg is EITHER a string literal OR an identifier.
	// Capture groups: 1=arg1, 2=arg1-is-lit, 3=arg1-id,
	//                 4=arg2, 5=arg2-is-lit, 6=arg2-id,
	//                 7=arg3, 8=arg3-is-lit, 9=arg3-id.
	// Simplified: three groups, each matching "lit" or ident.
	reVBAVarReplace = regexp.MustCompile(`(?i)Replace\(\s*` +
		`(?:"((?:[^"]|"")*)"|([A-Za-z]\w{0,63}))\s*,\s*` +
		`(?:"((?:[^"]|"")*)"|([A-Za-z]\w{0,63}))\s*,\s*` +
		`(?:"((?:[^"]|"")*)"|([A-Za-z]\w{0,63}))\s*\)`)

	// MSD-encodings: compiled regexes for the 6 new encoding patterns.

	// \xHH hex-escape sequences: literal \x followed by two hex digits, repeated min minXEscRun times.
	reXEsc = regexp.MustCompile(fmt.Sprintf(`(?:\\x[0-9A-Fa-f]{2}){%d,}`, minXEscRun))

	// &HXX VBA hex literals: &H or &h followed by two hex digits with optional comma/whitespace separators.
	reAmpH = regexp.MustCompile(fmt.Sprintf(`(?:&[Hh][0-9A-Fa-f]{2}[,\s]*){%d,}`, minAmpHRun))
	// Sub-regex to extract individual &HXX groups within a run.
	reAmpHTok = regexp.MustCompile(`&[Hh]([0-9A-Fa-f]{2})`)

	// \uXXXX / %uXXXX Unicode escape sequences: backslash-u or percent-u followed by four hex digits.
	reUEsc = regexp.MustCompile(fmt.Sprintf(`(?:[\\%%]u[0-9A-Fa-f]{4}){%d,}`, minUEscRun))

	// Decimal-separated byte sequences: a leading 1-3 digit number followed by at least (minDecSeqRun-1)
	// more comma- or semicolon-separated 1-3 digit groups.
	reDecSeq = regexp.MustCompile(fmt.Sprintf(`\d{1,3}(?:[;,]\d{1,3}){%d,}`, minDecSeqRun-1))

	// NETBIOS (RFC1001) encoded strings: runs of uppercase A-P chars, min minNetbiosRun (even length required).
	// Uppercase only — actual NETBIOS encoding always produces A-P; lowercase reduces FP but is non-standard.
	reNetbios = regexp.MustCompile(fmt.Sprintf(`[A-P]{%d,}`, minNetbiosRun))

	// Base32 encoded strings: standard alphabet [A-Z2-7] with optional padding, min minBase32Run chars.
	reBase32 = regexp.MustCompile(fmt.Sprintf(`[A-Z2-7]{%d,}={0,6}`, minBase32Run))

	// Lowercased reversed forms of high-signal tokens. The whole-buffer reverse
	// is skipped unless one is present, so a normal buffer never gets a reversed
	// twin scanned (StrReverse obfuscation is niche; reversing every body would
	// double scan work for nothing).
	reversedMarkers = [][]byte{
		[]byte("llehsrewop"),    // powershell
		[]byte("llehs.tpircsw"), // wscript.shell
		[]byte("tcejboetaerc"),  // createobject
		[]byte("exe.dmc"),       // cmd.exe
		[]byte("elifotevas"),    // savetofile
		[]byte("ptthnwod"),      // downhttp (URLDownload… fragments / hxxp reversed-ish)
	}
)

// foldVBAStrings scans src for VBA string-building patterns (Chr/ChrW concat,
// Replace, and single-byte Xor over Array literals) and emits each reassembled
// string. Returns false if a global cap was hit.
func foldVBAStrings(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	const maxMatches = 64

	// Clamp the input handed to the regex engine. Go's regexp is RE2 (linear, no
	// catastrophic backtracking), so this is not a ReDoS fix but a worst-case
	// CPU/alloc bound: a multi-MiB script body would otherwise have every fold
	// regex scan its full length. A real VBA fold target sits well within this;
	// the prefix keeps the common case identical. Mirrors maxReverseInput.
	if len(src) > maxFoldInput {
		src = src[:maxFoldInput]
	}

	// Chr/ChrW concat
	matches := reChrConcat.FindAll(src, maxMatches)
	for _, m := range matches {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		var buf []byte
		s := string(m)
		toks := reChrTok.FindAllStringSubmatch(s, -1)
		for _, tok := range toks {
			if tok[1] != "" {
				buf = append(buf, []byte(strings.ReplaceAll(tok[1], `""`, `"`))...)
			} else {
				n, _ := strconv.Atoi(tok[2])
				if n < 0 || n > 0x10FFFF {
					continue
				}
				buf = append(buf, []byte(string(rune(n)))...) // #nosec G115 -- clamped above
			}
		}
		if !emit(buf) {
			return false
		}
	}

	// Replace("str","old","new")
	replMatches := reReplace.FindAllSubmatch(src, maxMatches)
	for _, m := range replMatches {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		subject := strings.ReplaceAll(string(m[1]), `""`, `"`)
		old := strings.ReplaceAll(string(m[2]), `""`, `"`)
		new := strings.ReplaceAll(string(m[3]), `""`, `"`)
		result := strings.ReplaceAll(subject, old, new)
		if !emit([]byte(result)) {
			return false
		}
	}

	// Array(N,...) Xor K
	xorMatches := reArrayXor.FindAllSubmatch(src, maxMatches)
	for _, m := range xorMatches {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		key, _ := strconv.Atoi(strings.TrimSpace(string(m[2])))
		parts := strings.Split(string(m[1]), ",")
		var buf []byte
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				continue
			}
			buf = append(buf, byte(n^key)) // #nosec G115 -- n bounded 0..255 above
		}
		if !emit(buf) {
			return false
		}
	}

	// StrReverse("literal") — emit the reversed cleartext.
	revMatches := reStrReverse.FindAllSubmatch(src, maxMatches)
	for _, m := range revMatches {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		lit := strings.ReplaceAll(string(m[1]), `""`, `"`)
		if !emit([]byte(reverseString(lit))) {
			return false
		}
	}

	// Environ("NAME") — emit a VBA-ENVIRON %NAME% marker so a rule can flag
	// env-var probing.
	envMatches := reEnviron.FindAllSubmatch(src, maxMatches)
	for _, m := range envMatches {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		name := strings.ReplaceAll(string(m[1]), `""`, `"`)
		if name == "" {
			continue
		}
		// Prefix a stable marker: a bare "%TEMP%" is shorter than minDecodedLen
		// and would be dropped, and the marker gives rules a fixed token to key
		// on (env-var probing) regardless of the variable name.
		if !emit([]byte("VBA-ENVIRON %" + name + "%")) {
			return false
		}
	}

	// Replace(var/lit, var/lit, var/lit) with variable-resolved args — handles
	// the pattern where the payload is assembled as a variable then junk is
	// stripped with Replace(payloadVar, junkVar, ""). Collect assignments first,
	// resolve each arg, then evaluate. Pure all-literal calls are already
	// covered by reReplace above; this path fires when at least one arg is a
	// variable reference.
	if !foldVBAVarReplace(src, deadline, emit) {
		return false
	}

	// Dridex-obfuscated string literals (olevba pass 4). A quoted >=20-char
	// alphanumeric run that is NOT plain hex is run through dridexURLDecode.
	dridexMatches := reDridex.FindAll(src, maxMatches)
	for _, m := range dridexMatches {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		inner := m[1 : len(m)-1] // strip the surrounding quotes
		if !dridexNotHex.Match(inner) {
			continue // plain hex — the hex pass already covers it
		}
		if dec, ok := dridexURLDecode(string(inner)); ok {
			if !emit([]byte(dec)) {
				return false
			}
		}
	}

	return true
}

// reverseString returns s with its runes in reverse order (so a multi-byte
// rune is not split). VBA StrReverse is character-wise, matching this.
func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// foldVBAVarReplace collects simple string-variable assignments from src,
// resolves one level of alias, then matches Replace() calls whose args are
// either string literals or variables from that map. When all three args
// resolve, it emits strings.ReplaceAll(subject, old, new). Returns false on
// deadline/budget hit, true otherwise.
//
// FP-safety: only args that fully resolve to known literal values are folded.
// Any unresolved identifier (not in the collected map) causes the Replace call
// to be skipped entirely — no garbage emitted.
func foldVBAVarReplace(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	// Caps: bound memory and work in linear passes.
	const (
		maxVarEntries = 256  // max identifier→literal map entries
		maxLiteralLen = 4096 // max per-value length stored in the map
		maxVarMatches = 64   // max Replace() calls evaluated
		maxAliasDepth = 1    // single alias resolution level
	)

	// Phase 1 — collect identifier = "literal" assignments.
	varMap := make(map[string]string, 32)
	for _, m := range reVBAStrAssign.FindAllSubmatch(src, -1) {
		if len(varMap) >= maxVarEntries {
			break
		}
		name := string(m[1])
		val := strings.ReplaceAll(string(m[2]), `""`, `"`)
		if len(val) > maxLiteralLen {
			continue // skip oversized literals to bound memory
		}
		// Keep the FIRST (earliest) assignment for a given name — matches VBA
		// sequential execution order for simple scripts.
		if _, exists := varMap[name]; !exists {
			varMap[name] = val
		}
	}

	// Phase 2 — resolve one level of trivial alias: identifier = otherIdentifier.
	for _, m := range reVBAAlias.FindAllSubmatch(src, -1) {
		name := string(m[1])
		src2 := string(m[2])
		if _, exists := varMap[name]; exists {
			continue // already have a literal binding — don't overwrite
		}
		if val, ok := varMap[src2]; ok {
			varMap[name] = val
		}
	}

	// Phase 3 — find and evaluate Replace() calls with at least one var arg.
	// reVBAVarReplace capture layout per match (7 groups):
	//   m[1] lit-arg1, m[2] id-arg1
	//   m[3] lit-arg2, m[4] id-arg2
	//   m[5] lit-arg3, m[6] id-arg3
	resolve := func(lit, id []byte) (string, bool) {
		if len(lit) > 0 || (len(id) == 0 && len(lit) == 0) {
			// literal branch: m[N] is non-empty for a quoted arg (even empty
			// string "" matches as zero-length lit group).
			// But we must distinguish "present quoted literal" from "absent".
			// reVBAVarReplace uses alternation: if lit group matched, id is "".
			return strings.ReplaceAll(string(lit), `""`, `"`), true
		}
		// identifier branch
		name := string(id)
		val, ok := varMap[name]
		return val, ok
	}

	replMatches := reVBAVarReplace.FindAllSubmatch(src, maxVarMatches)
	for _, m := range replMatches {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return false
		}
		// Determine which branch fired for each arg position.
		// m[1]/m[2]: arg1 (lit / id); m[3]/m[4]: arg2; m[5]/m[6]: arg3.
		//
		// The regex alternation fires exactly one of lit/id per arg.
		// When the lit group matched, m[2*i-1] is present; id group m[2*i] is "".
		// When the id group matched, m[2*i-1] is ""; m[2*i] is the identifier.
		//
		// Special case: empty literal "" — lit group is present but zero-length,
		// and id group is also zero-length. Discriminate: if the full match
		// contains a quoted segment for that arg we landed in the lit branch.
		// The simplest discriminant is: if id bytes are empty after the alternation
		// consumed an identifier, then lit won (and vice versa). In RE2, exactly
		// one of the two alternation branches inside (?:...|...) captures — the
		// other sub-group is nil (zero-length in FindAllSubmatch). We rely on the
		// fact that a non-empty identifier always produces a non-empty m[2i] byte
		// slice; an empty literal produces a zero-length but non-nil m[2i-1] slice
		// while m[2i] is zero-length. We cannot distinguish nil vs zero-length via
		// []byte comparison alone; instead, check whether the id bytes are non-empty
		// to decide which branch.
		arg1lit, arg1id := m[1], m[2]
		arg2lit, arg2id := m[3], m[4]
		arg3lit, arg3id := m[5], m[6]

		// If ALL three args are pure literals this call was already handled by
		// the all-literal reReplace pass above — skip to avoid double-emit.
		if len(arg1id) == 0 && len(arg2id) == 0 && len(arg3id) == 0 {
			continue
		}

		subj, ok1 := resolve(arg1lit, arg1id)
		if !ok1 {
			continue // unresolved — skip, no emit
		}
		old, ok2 := resolve(arg2lit, arg2id)
		if !ok2 {
			continue
		}
		newVal, ok3 := resolve(arg3lit, arg3id)
		if !ok3 {
			continue
		}

		result := strings.ReplaceAll(subj, old, newVal)
		if !emit([]byte(result)) {
			return false
		}
	}

	return true
}

// stripDigits returns the integer formed by the digit characters of s (other
// characters dropped). zeros==true substitutes '0' for each non-digit instead
// of dropping it. Mirrors olevba's StripChars / StripCharsWithZero. Returns ok
// false when no digits remain or the result overflows an int.
func stripDigits(s string, zeros bool) (int, bool) {
	var b strings.Builder
	any := false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
			any = true
		} else if zeros {
			b.WriteByte('0')
		}
	}
	if !any {
		return 0, false
	}
	n, err := strconv.Atoi(b.String())
	if err != nil {
		return 0, false
	}
	return n, true
}

// dridexURLDecode reverses the Dridex string obfuscation found in olevba
// (DridexUrlDecode). The format embeds two key markers around the midpoint of
// the (prefix/suffix-stripped) text, then splits the remainder into fixed-width
// digit groups, each decoded as chr(group/keyEnc2). All division is integer
// (olevba ran on Python 2). Fail-open: any out-of-range index, zero divisor, or
// non-printable byte returns ok=false, so a false-positive candidate just
// yields no blob.
func dridexURLDecode(in string) (out string, ok bool) {
	defer func() {
		if recover() != nil { // never let a slice-bounds panic escape
			out, ok = "", false
		}
	}()
	if len(in) < 8 {
		return "", false
	}
	work := in[4 : len(in)-4]
	if len(work) < 4 {
		return "", false
	}
	half := len(work) / 2
	keyEnc, ok1 := stripDigits(work[half-2:half], true)
	keySize, ok2 := stripDigits(work[half:half+2], true)
	if !ok1 || !ok2 {
		return "", false
	}
	nCharSize := keySize - keyEnc
	// Real Dridex group widths are ~10; cap at 16 to bound hostile input while
	// allowing genuine samples.
	if nCharSize <= 0 || nCharSize > 16 {
		return "", false
	}
	work = work[:half-2] + work[half+2:]
	half = len(work) / 2
	if half-nCharSize/2 < 0 || half+nCharSize/2 > len(work) {
		return "", false
	}
	keyEnc2, ok3 := stripDigits(work[half-nCharSize/2:half+nCharSize/2], false)
	if !ok3 || keyEnc2 == 0 {
		return "", false // division by zero / no key digits
	}
	work = work[:half-nCharSize/2] + work[half+nCharSize/2:]
	if len(work) == 0 {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(work); i += nCharSize {
		end := i + nCharSize
		if end > len(work) {
			end = len(work) // final partial group, like olevba's range slice
		}
		g, gok := stripDigits(work[i:end], false)
		if !gok {
			return "", false
		}
		code := g / keyEnc2
		if code < 0x20 || code > 0x7E {
			return "", false // not printable ASCII — almost certainly not Dridex
		}
		b.WriteByte(byte(code))
	}
	if b.Len() == 0 {
		return "", false
	}
	return b.String(), true
}

// fromEncoded runs the static decoders over buf and a snapshot of the streams
// extracted so far, appending decoded blobs to res.Streams. Each source stream is
// decoded RECURSIVELY (MSD-1): a decoded blob that still looksEncoded is fed back
// through the decoders one layer deeper, up to maxDecodeDepth, so a Dridex-style
// base64-over-hex-over-reverse payload is fully unwrapped.
//
// Budget contract: the per-source caps (maxDecodedBlobs / maxCumulativeDecoded)
// are GLOBAL across a source stream's recursion depths but RESET for each new
// source stream — so one noisy stream can't starve the others' detection in a
// multi-stream document. The global res.Streams/maxStreams ceiling still bounds
// the absolute total across all streams.
func fromEncoded(buf []byte, res *Result, opts *Options) {
	deadline := opts.Deadline
	// Snapshot: the raw buffer plus the streams present right now. Appends below
	// grow res.Streams (possibly reallocating its backing array) but never touch
	// this slice's elements, so we iterate a stable, finite set.
	sources := make([][]byte, 0, len(res.Streams)+1)
	sources = append(sources, buf)
	sources = append(sources, res.Streams...)

	total := 0

	// UTF-16 recovery: a wide (UTF-16LE/BE) PowerShell/VBScript/JScript payload is
	// ~50% NUL bytes, so mostlyText rejects it as binary and neither the decoders
	// nor the keyword rules ever see the cleartext. Transcode each UTF-16 source to
	// UTF-8 up front, emit the UTF-8 form as a scannable stream (so wide-script
	// keyword rules fire directly on it) AND add it as an extra decode source (so a
	// wide-then-base64 nested payload is still unwrapped). Bounded by the same
	// per-blob/cumulative/stream caps as every other decoded blob. The snapshot is
	// taken before this loop, so the appended streams are not themselves re-scanned
	// for UTF-16 (no recursion).
	var u16Blobs, u16Cum int
	for _, src := range append([][]byte(nil), sources...) {
		if expired(deadline) || len(res.Streams) >= maxStreams {
			break
		}
		u8, ok := transcodeUTF16(src)
		if !ok || len(u8) < minDecodedLen {
			continue
		}
		if len(u8) > maxBytesPerDecodedBlob {
			u8 = u8[:maxBytesPerDecodedBlob]
		}
		if u16Blobs >= maxDecodedBlobs || u16Cum+len(u8) > maxCumulativeDecoded {
			break
		}
		res.Streams = append(res.Streams, u8)
		sources = append(sources, u8)
		u16Blobs++
		u16Cum += len(u8)
		total++
	}
	// MSD-4 budget: the ingest-time defang emits one extra stream per source
	// outside decodeSourceTree's own per-source budget, so it needs its own caps
	// — otherwise N defanged sources × up to 1 MiB each would bypass the
	// maxDecodedBlobs / maxCumulativeDecoded ceilings (a memory amplifier on
	// crafted multi-stream input). These run across the WHOLE fromEncoded pass.
	var defangBlobs, defangCum int

	// MSD-4: defang pass — run before the global BFS so un-defanged copies are
	// available as extra sources. Each source is processed independently here
	// (its decode tree is fed through decodeSourceTree as before) because the
	// defang-then-redecode path is already one extra source, not a BFS item.
	for _, src := range sources {
		if expired(deadline) || len(res.Streams) >= maxStreams {
			break
		}
		if mostlyText(src) {
			if ud, ok := undefang(src); ok && len(ud) >= minDecodedLen {
				if len(ud) > maxBytesPerDecodedBlob {
					ud = ud[:maxBytesPerDecodedBlob]
				}
				// Respect the same blob/byte/stream budgets decodeSourceTree uses,
				// so the defang path can't bypass maxDecodedBlobs/maxCumulativeDecoded.
				if defangBlobs < maxDecodedBlobs && defangCum+len(ud) <= maxCumulativeDecoded &&
					len(res.Streams) < maxStreams {
					res.Streams = append(res.Streams, ud)
					defangBlobs++
					defangCum += len(ud)
					total++
					// Only re-decode the un-defanged copy when it still looksEncoded
					// (a defanged-then-base64 payload); a plain cleartext URL is
					// emitted above but NOT re-fed, to avoid an un-gated amplifier.
					if looksEncoded(ud) {
						total += decodeSourceTree(ud, res, opts)
					}
				}
			}
		}
	}

	// EFFORT-4 global BFS: seed ALL sources at depth 0 before any depth-1 child
	// is enqueued, so the global FIFO processes all sources shallowly before any
	// source deeply. Under maxStreams saturation this means the cut happens by
	// source ORDER × depth — never by effort — making coverage monotone in effort:
	// raising DecodeDepth only ADDS deeper layers after all shallower layers of
	// all sources are emitted.
	//
	// Per-source state (blobs, cum, iters, seen, maxLayer) is carried in per-index
	// maps so the per-source budget/dedup/marker semantics (MSD-1, MSD-2,
	// RULE-MSD-MULTILAYER) are fully preserved.
	maxDepth := opts.DecodeDepth
	if maxDepth < 1 {
		maxDepth = 1
	}
	maxItersPerSource := opts.DecodeIterations
	if maxItersPerSource < 1 {
		maxItersPerSource = 1
	}

	type bfsItem struct {
		data   []byte
		depth  int
		srcIdx int // which source this item belongs to
	}

	// Per-source state maps.
	type srcState struct {
		blobs    int
		cum      int
		iters    int
		maxLayer int
		seen     map[uint64]struct{}
	}
	states := make([]srcState, len(sources))
	for i := range states {
		states[i].seen = make(map[uint64]struct{})
	}

	// Seed: all sources at depth 0, in source order.
	queue := make([]bfsItem, 0, len(sources))
	for i, src := range sources {
		queue = append(queue, bfsItem{src, 0, i})
	}

	// Global BFS: children re-enqueued at depth+1 land after ALL existing items
	// (including other sources' depth-d items), giving breadth-first-by-depth
	// globally across all sources.
	var curChildren [][]byte
	for len(queue) > 0 {
		if expired(deadline) || len(res.Streams) >= maxStreams {
			break
		}
		cur := queue[0]
		queue = queue[1:]
		st := &states[cur.srcIdx]

		// Per-source iteration cap (matches old per-source maxIters semantics).
		if st.iters >= maxItersPerSource ||
			st.blobs >= maxDecodedBlobs || st.cum >= maxCumulativeDecoded {
			continue
		}
		if !mostlyText(cur.data) {
			continue
		}
		// PERF-4: cheap scalar pre-gate. Prose passes mostlyText but has no long
		// encoding-alphabet run and no structural marker, so the 10-decoder regex
		// chain finds nothing — skip it. Strict pre-gate: anything a decoder would
		// accept has a run >= its minimum (>= minPrefilterRun) or a marker, so it
		// still passes. Only no-op work on plain text is skipped. Gated before
		// st.iters++ so a skip does not consume the per-source iteration budget
		// (strictly leaves more budget for real items — never less work).
		if !mayBeEncoded(cur.data) {
			continue
		}
		st.iters++

		curLayer := cur.depth + 1
		curChildren = curChildren[:0]

		emit := func(b []byte) bool {
			if len(b) < minDecodedLen {
				return true
			}
			if len(b) > maxBytesPerDecodedBlob {
				b = b[:maxBytesPerDecodedBlob]
			}
			// MSD-2: per-source-tree dedup (preserves old per-tree semantics).
			h := fnv64(b)
			if _, dup := st.seen[h]; dup {
				return true
			}
			if st.blobs >= maxDecodedBlobs || len(res.Streams) >= maxStreams || st.cum+len(b) > maxCumulativeDecoded {
				return false
			}
			res.Streams = append(res.Streams, b)
			curChildren = append(curChildren, b)
			st.seen[h] = struct{}{}
			st.blobs++
			st.cum += len(b)
			total++
			if curLayer > st.maxLayer {
				st.maxLayer = curLayer
			}
			return true
		}

		ok := decodeBase64Runs(cur.data, deadline, emit) &&
			decodeHexRuns(cur.data, deadline, emit) &&
			emitReversed(cur.data, emit) &&
			foldVBAStrings(cur.data, deadline, emit) &&
			decodeXEscRuns(cur.data, deadline, emit) &&
			decodeAmpHRuns(cur.data, deadline, emit) &&
			decodeUEscRuns(cur.data, deadline, emit) &&
			decodeDecSeqRuns(cur.data, deadline, emit) &&
			decodeNetbiosRuns(cur.data, deadline, emit) &&
			decodeBase32Runs(cur.data, deadline, emit)

		if cur.depth+1 < maxDepth {
			for _, c := range curChildren {
				if looksEncoded(c) {
					queue = append(queue, bfsItem{c, cur.depth + 1, cur.srcIdx})
				}
			}
		}
		_ = ok // fail-open: budget cap in emit already stops further work for this source
	}

	// RULE-MSD-MULTILAYER: emit one MSD-DEEPDECODE marker per source tree that
	// reached deepDecodeLayer, in source order. Markers are appended after the
	// global walk so they never consume budget that could have gone to a real blob.
	for i := range sources {
		if expired(deadline) || len(res.Streams) >= maxStreams {
			break
		}
		if states[i].maxLayer >= deepDecodeLayer {
			res.Streams = append(res.Streams, []byte("MSD-DEEPDECODE depth="+strconv.Itoa(states[i].maxLayer)))
			total++
		}
	}

	// Record how many blobs the pass appended (always the trailing res.Streams),
	// so the caller can keep the macro/extracted-stream metrics free of decode noise.
	res.DecodedStreams = total
}

// decodeSourceTree runs the recursive multi-layer decode for ONE source stream
// and returns the number of blobs it emitted. Used by the MSD-4 defang path
// (un-defanged copies that looksEncoded are fed here as standalone sources).
// The blob/byte budget is local to this call (the per-source reset of the
// MSD-1 contract); it is shared across all recursion depths of this source via
// the closure below. A FIFO worklist gives breadth-first unwrapping within this
// source so the budget is spent on shallow layers before deep ones.
//
// The main multi-source decode walk in fromEncoded uses its own global BFS
// rather than calling this per-source, giving monotone coverage in effort across
// all sources simultaneously.
func decodeSourceTree(src []byte, res *Result, opts *Options) int {
	deadline := opts.Deadline
	// EFFORT-4: per-request caps, floored to 1 so a zero-value Options never
	// produces a zero-depth (no-op) or unbounded walk. A lower effort level
	// unwraps fewer stacked layers and dequeues fewer worklist items.
	maxDepth := opts.DecodeDepth
	if maxDepth < 1 {
		maxDepth = 1
	}
	maxIters := opts.DecodeIterations
	if maxIters < 1 {
		maxIters = 1
	}
	type item struct {
		data  []byte
		depth int
	}
	queue := []item{{src, 0}}

	// MSD-2: fnv64 content-dedup of EMITTED blobs. A decode cycle (A→B→A) or a
	// fan-out where several layers converge on the same blob would otherwise emit +
	// re-decode identical bytes at every reappearance — wasting iters/CPU (the
	// duplicate STREAM is later dropped by the scanner's SHA256 dedup, but the
	// decode work is not). Recording a blob only AFTER it is accepted, and querying
	// before re-enqueue, makes the walk O(distinct emitted blobs) and breaks cycles
	// structurally. fnv64 is non-cryptographic; a collision merely skips one
	// re-decode (never drops a stream, since seen() gates enqueue, not emit), and is
	// astronomically unlikely on the bounded blob count.
	//
	// The set holds ONLY successfully-emitted blobs — NOT the source (a decoded blob
	// byte-identical to the source must still reach YARA) and NOT budget-rejected
	// blobs (whose clamped-prefix hash must not suppress a later, different blob).
	seen := make(map[uint64]struct{})
	alreadyEmitted := func(b []byte) bool {
		_, ok := seen[fnv64(b)]
		return ok
	}

	var blobs, cum, iters int
	// children collects the blobs emitted while decoding the CURRENT item, so we
	// can decide which to re-enqueue one layer deeper after the decoders run.
	var children [][]byte
	// RULE-MSD-MULTILAYER: curLayer is the decode-layer of the blob emit() produces
	// (the depth of the item currently being decoded, +1 — a blob decoded OUT of a
	// depth-d item is one layer deeper than it). maxLayer tracks the deepest layer at
	// which any blob was actually emitted, so a single MSD-DEEPDECODE marker can carry
	// it after the walk. Set per iteration before the decoders run.
	curLayer := 0
	maxLayer := 0
	emit := func(b []byte) bool {
		if len(b) < minDecodedLen {
			return true
		}
		if len(b) > maxBytesPerDecodedBlob {
			b = b[:maxBytesPerDecodedBlob]
		}
		// MSD-2: skip a blob already EMITTED in this source tree (two identical
		// encoded runs, or a fan-out convergence). Hash the CLAMPED bytes — that is
		// what is stored. A skip is not a budget failure (return true), so decoding
		// continues past the duplicate.
		if alreadyEmitted(b) {
			return true
		}
		if blobs >= maxDecodedBlobs || len(res.Streams) >= maxStreams || cum+len(b) > maxCumulativeDecoded {
			return false // budget hit — NOT recorded as seen, so a later distinct blob isn't masked
		}
		res.Streams = append(res.Streams, b)
		children = append(children, b)
		seen[fnv64(b)] = struct{}{} // record only accepted blobs
		blobs++
		cum += len(b)
		if curLayer > maxLayer {
			maxLayer = curLayer // deepest layer that actually yielded a distinct blob
		}
		return true
	}

	for len(queue) > 0 {
		if expired(deadline) || iters >= maxIters ||
			blobs >= maxDecodedBlobs || cum >= maxCumulativeDecoded ||
			len(res.Streams) >= maxStreams {
			break
		}
		iters++
		cur := queue[0]
		queue = queue[1:]
		// Only decode mostly-text data; binary container/blob bytes yield noise.
		if !mostlyText(cur.data) {
			continue
		}

		// A blob emitted while decoding this depth-cur.depth item is one decode
		// layer deeper than it (RULE-MSD-MULTILAYER layer accounting).
		curLayer = cur.depth + 1
		children = children[:0]
		ok := decodeBase64Runs(cur.data, deadline, emit) &&
			decodeHexRuns(cur.data, deadline, emit) &&
			emitReversed(cur.data, emit) &&
			foldVBAStrings(cur.data, deadline, emit) &&
			decodeXEscRuns(cur.data, deadline, emit) &&
			decodeAmpHRuns(cur.data, deadline, emit) &&
			decodeUEscRuns(cur.data, deadline, emit) &&
			decodeDecSeqRuns(cur.data, deadline, emit) &&
			decodeNetbiosRuns(cur.data, deadline, emit) &&
			decodeBase32Runs(cur.data, deadline, emit)

		// Re-enqueue this item's encoded children one layer deeper. Gate on
		// looksEncoded so a fully-decoded cleartext blob isn't re-scanned for
		// nothing (the main speed lever — keeps deep layers ~free on benign input).
		// `+1 < maxDecodeDepth` bounds a decode chain to exactly maxDecodeDepth
		// passes: the source decodes at depth 0 and each child one deeper, so the
		// deepest decoded item is at depth maxDecodeDepth-1.
		if cur.depth+1 < maxDepth {
			// `children` are exactly the blobs emit() ACCEPTED this pass, so each is
			// already distinct (emit's markSeen dropped duplicates). Re-enqueue the
			// still-encoded ones one layer deeper; the dedup at emit time means a
			// blob seen at a shallower depth never reappears here (cycle-break).
			for _, c := range children {
				if looksEncoded(c) {
					queue = append(queue, item{c, cur.depth + 1})
				}
			}
		}
		if !ok {
			break // a per-source budget cap was hit — stop this source's tree
		}
	}
	// RULE-MSD-MULTILAYER: a blob surfaced at >= deepDecodeLayer stacked decode
	// passes — base64-over-hex-over-… nesting with no benign analogue. Emit ONE
	// marker per source tree carrying the deepest layer reached so a YARA rule can
	// score it. Appended directly (the marker is not itself decode input, so it
	// bypasses dedup/re-enqueue) but still honours maxStreams, and is counted in
	// the returned blob total so the caller's DecodedStreams metric stays exact.
	if maxLayer >= deepDecodeLayer && len(res.Streams) < maxStreams {
		res.Streams = append(res.Streams, []byte("MSD-DEEPDECODE depth="+strconv.Itoa(maxLayer)))
		blobs++
	}
	return blobs
}

// fnv64 is the 64-bit FNV-1a hash of b, inlined (no hasher allocation) for the
// MSD-2 worklist dedup hot path. Used only to detect re-decode of identical
// bytes; a collision merely skips one decode, never produces a wrong stream.
func fnv64(b []byte) uint64 {
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	h := uint64(offset)
	for _, c := range b {
		h ^= uint64(c)
		h *= prime
	}
	return h
}

// prefilterMarkers are the cheap structural substrings the decode chain /
// looksEncoded key on that do NOT manifest as a long alphabet-class run, so the
// run-length gate alone would miss them. A buffer containing ANY of these must
// pass the prefilter (do the expensive work). Lowercased; matched against a
// lowercased copy of the (clamped) scan window. Each corresponds to a decoder
// or looksEncoded pattern:
//   - "\\x"        -> reXEsc  (\xHH escapes; the literal 2 bytes backslash-x)
//   - "\\u","%u"   -> reUEsc  (\uXXXX / %uXXXX)
//   - "&h"         -> reAmpH  (&HXX VBA hex literals; case-insensitive)
//   - "chr"        -> reChrConcat (Chr/ChrW concat)
//   - "replace("   -> reReplace
//   - "array("     -> reArrayXor
//   - "strreverse" -> reStrReverse
//   - "environ"    -> reEnviron
//
// The reversedMarkers (llehsrewop, …) are also short substrings with no long
// run, so they are appended here too. reDridex (>=20 alnum in quotes) and the
// base64/hex/netbios/base32 runs are covered by the run-length gate, not here.
var prefilterMarkers = [][]byte{
	[]byte(`\x`),
	[]byte(`\u`),
	[]byte(`%u`),
	[]byte(`&h`),
	[]byte("chr"),
	[]byte("replace("),
	[]byte("array("),
	[]byte("strreverse"),
	[]byte("environ"),
}

// mayBeEncoded is the PERF-4 cheap scalar pre-gate run BEFORE the regex decode
// chain and looksEncoded. It returns true ("do the expensive work") whenever the
// buffer could plausibly carry an encoded payload, and false ONLY for buffers
// that demonstrably cannot — plain prose with no long encoding-alphabet run and
// no structural marker. It is a STRICT pre-gate: every input the chain or
// looksEncoded would have decoded still passes, because the thresholds are <=
// every decoder's own minimum run (see minPrefilterRun / minPrefilterDecRun).
// When in doubt it passes (returns true); the win is purely from prose being
// skipped, never from skipping anything decodable.
//
// One linear pass tracks two independent run lengths:
//   - b64Run: contiguous base64-alphabet bytes [A-Za-z0-9+/] (covers base64,
//     hex, netbios A-P, base32 A-Z2-7, and Dridex alnum — all subsets). >=20 passes.
//   - decRun: contiguous [0-9,;] bytes (the reDecSeq class). >=23 passes.
//
// Prose breaks both classes every few chars with spaces/punctuation, so it
// never accumulates a qualifying run; a real payload has one long unbroken run.
func mayBeEncoded(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	scan := b
	if len(scan) > maxFoldInput {
		scan = scan[:maxFoldInput]
	}
	b64Run, decRun := 0, 0
	// reChrConcat can match a concat of pure string LITERALS (e.g. "a" & "b")
	// with no "chr" marker and no long run, so the marker scan below would miss
	// it. Detect the necessary ingredients cheaply: a double-quote AND a concat
	// operator ('&' or '+'). If both are present anywhere in the scan, pass (the
	// regex MIGHT match — strict pre-gate). Prose with quotes but no &/+ (or vice
	// versa) is still skipped. Tracked in the same pass.
	hasQuote, hasConcatOp := false, false
	for _, c := range scan {
		switch c {
		case '"':
			hasQuote = true
		case '&', '+':
			hasConcatOp = true
		}
		// base64-alphabet class.
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' {
			b64Run++
			if b64Run >= minPrefilterRun {
				return true
			}
		} else {
			b64Run = 0
		}
		// decimal-sequence class [0-9,;].
		if (c >= '0' && c <= '9') || c == ',' || c == ';' {
			decRun++
			if decRun >= minPrefilterDecRun {
				return true
			}
		} else {
			decRun = 0
		}
	}
	// reChrConcat string-literal-only form (quoted literals joined by &/+).
	if hasQuote && hasConcatOp {
		return true
	}
	// No long run — fall back to the cheap structural-marker scan. Lowercase once.
	low := bytes.ToLower(scan)
	for _, m := range prefilterMarkers {
		if bytes.Contains(low, m) {
			return true
		}
	}
	for _, m := range reversedMarkers {
		if bytes.Contains(low, m) {
			return true
		}
	}
	return false
}

// looksEncoded reports whether b plausibly carries another encoded layer worth
// re-decoding: a long base64/hex run, a reversed high-signal token, or a VBA
// string-building construct. Used to gate the MSD-1 recursion so cleartext output
// is not re-enqueued. The scan length is clamped (RE2 is linear, but a multi-MiB
// blob would still cost a full pass) — a real nested payload sits well within it.
func looksEncoded(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	// PERF-4: cheap scalar pre-gate. Every pattern below (a long base64/hex run,
	// a reversed marker, or a VBA construct) implies either a base64-alphabet run
	// >= minPrefilterRun or one of prefilterMarkers/reversedMarkers, all of which
	// mayBeEncoded reports true for. So if mayBeEncoded is false, none of the
	// regexes below can match — short-circuit and skip the 11-automata scan.
	if !mayBeEncoded(b) {
		return false
	}
	scan := b
	if len(scan) > maxFoldInput {
		scan = scan[:maxFoldInput]
	}
	if reBase64.Match(scan) || reHex.Match(scan) {
		return true
	}
	low := bytes.ToLower(scan)
	for _, m := range reversedMarkers {
		if bytes.Contains(low, m) {
			return true
		}
	}
	// Mirror EVERY pattern foldVBAStrings handles, so a child blob that decoded
	// into any VBA string-build construct is re-enqueued and folded one layer down.
	// Also mirror the MSD-encodings patterns so nested encoded payloads recurse.
	return reChrConcat.Match(scan) || reReplace.Match(scan) || reArrayXor.Match(scan) ||
		reStrReverse.Match(scan) || reEnviron.Match(scan) || reDridex.Match(scan) ||
		reXEsc.Match(scan) || reAmpH.Match(scan) || reUEsc.Match(scan) ||
		reDecSeq.Match(scan) || reBase32.Match(scan)
	// reNetbios is deliberately OMITTED here: [A-P]{32,} matches plain uppercase
	// text (acronyms, ALL-CAPS, base64's A-P slice), so re-enqueueing on it would
	// re-decode benign cleartext every layer. NETBIOS is still decoded at the
	// source layer by decodeNetbiosRuns (gated on mostlyText/magic); it just does
	// not drive recursion. A genuinely NETBIOS-over-base64 nest still recurses via
	// the base64/base32 patterns above.
}

// mostlyText reports whether a leading sample of b is at least textPrintablePct
// printable ASCII (incl. tab/CR/LF) — a cheap "is this a script/text carrier
// rather than a binary blob" gate.
func mostlyText(b []byte) bool {
	n := len(b)
	if n == 0 {
		return false
	}
	if n > textSample {
		n = textSample
	}
	printable := 0
	for i := 0; i < n; i++ {
		c := b[i]
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			printable++
		}
	}
	return printable*100 >= n*textPrintablePct
}

// utf16LEBOM / utf16BEBOM are the byte-order marks that open a UTF-16 text file.
var (
	utf16LEBOM = []byte{0xFF, 0xFE}
	utf16BEBOM = []byte{0xFE, 0xFF}
)

// transcodeUTF16 detects a UTF-16-encoded text source and returns its UTF-8
// transcoding plus true; otherwise (nil, false). A wide (UTF-16) PowerShell /
// VBScript / JScript payload is ~50% NUL bytes, so mostlyText rejects it as
// "binary" and the whole decode walk (and the keyword rules) never see the
// cleartext — a real miss class. We recover it in two cases:
//
//   - An explicit UTF-16 BOM (FF FE little-endian, FE FF big-endian).
//   - No BOM but a strong alternating-NUL signature: in ASCII-range UTF-16LE the
//     odd bytes are 0x00 (and in UTF-16BE the even bytes are), which a binary
//     blob does not exhibit. We require a high NUL fraction at the right parity
//     AND a low NUL fraction at the other parity, so a genuinely binary buffer
//     (NULs scattered across both parities) is NOT misread as text.
//
// Bounded: only a leading sample drives detection; the transcode itself is capped
// by the caller. Decoding is lossy-tolerant (unpaired surrogates → U+FFFD via
// utf16.Decode), which is fine — we only need the ASCII keywords to surface.
func transcodeUTF16(b []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(b, utf16LEBOM):
		return decodeUTF16(b[2:], false), true
	case bytes.HasPrefix(b, utf16BEBOM):
		return decodeUTF16(b[2:], true), true
	}
	// BOM-less heuristic over a leading sample (odd trailing byte ignored).
	n := len(b)
	if n > textSample {
		n = textSample
	}
	if n < utf16MinSample {
		return nil, false
	}
	var evenNUL, oddNUL, pairs int
	for i := 0; i+1 < n; i += 2 {
		pairs++
		if b[i] == 0x00 {
			evenNUL++
		}
		if b[i+1] == 0x00 {
			oddNUL++
		}
	}
	if pairs == 0 {
		return nil, false
	}
	// UTF-16LE ASCII text: high odd-byte NUL, low even-byte NUL (the visible char).
	if oddNUL*100 >= pairs*utf16NULHighPct && evenNUL*100 <= pairs*utf16NULLowPct {
		return decodeUTF16(b, false), true
	}
	// UTF-16BE ASCII text: high even-byte NUL, low odd-byte NUL.
	if evenNUL*100 >= pairs*utf16NULHighPct && oddNUL*100 <= pairs*utf16NULLowPct {
		return decodeUTF16(b, true), true
	}
	return nil, false
}

// decodeUTF16 transcodes raw UTF-16 bytes (no BOM) to UTF-8. bigEndian selects
// the byte order. An odd trailing byte is dropped. Capped at maxBytesPerDecodedBlob
// of input so a multi-MB wide buffer cannot blow the per-blob budget.
func decodeUTF16(b []byte, bigEndian bool) []byte {
	if len(b) > maxBytesPerDecodedBlob*2 {
		b = b[:maxBytesPerDecodedBlob*2]
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			units = append(units, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			units = append(units, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return []byte(string(utf16.Decode(units)))
}

// decodeBase64Runs decodes each long base64 run in src. Returns false if a global
// cap was hit (stop everything).
func decodeBase64Runs(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reBase64.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		// An all-hex run is handled by the hex pass; decoding it as base64 too
		// would emit a bogus blob and burn the blob cap, so skip it here.
		if !allHex(run) {
			if dec, ok := tryBase64(run); ok {
				if !emit(dec) {
					return false
				}
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

// tryBase64 decodes one run, tolerating both padded and unpadded standard base64.
// A run longer than maxB64Encoded is truncated to an alignment-valid prefix first
// so a giant run cannot allocate far past the decoded-blob cap.
func tryBase64(run []byte) ([]byte, bool) {
	if len(run) > maxB64Encoded {
		run = run[:maxB64Encoded] // mult of 4, all-alphabet prefix (any '=' is past the cut)
	}
	if dec, err := base64.StdEncoding.DecodeString(string(run)); err == nil {
		return dec, true
	}
	s := strings.TrimRight(string(run), "=")
	if len(s)%4 == 1 { // not a valid raw-base64 length
		return nil, false
	}
	if dec, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return dec, true
	}
	return nil, false
}

// allHex reports whether b is a non-empty run of hex digits (no padding/sign).
func allHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// decodeHexRuns decodes each long hex run in src. Returns false on a global cap.
func decodeHexRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reHex.FindIndex(rest)
		if loc == nil {
			return true
		}
		// The match is an even number of hex digits by construction; cap the
		// candidate to an even prefix so a giant run can't allocate past the cap.
		run := rest[loc[0]:loc[1]]
		if len(run) > maxHexEncoded {
			run = run[:maxHexEncoded]
		}
		if dec, err := hex.DecodeString(string(run)); err == nil {
			if !emit(dec) {
				return false
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

// decodeXEscRuns decodes runs of \xHH hex-escape sequences (e.g. \x68\x74\x74…).
// Common in JavaScript/PowerShell malware obfuscation. Returns false on cap hit.
func decodeXEscRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reXEsc.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		// Clamp to maxXEscEncoded; trim to nearest multiple of 4 (each \xHH is 4 bytes).
		if len(run) > maxXEscEncoded {
			run = run[:maxXEscEncoded-(maxXEscEncoded%4)]
		}
		// Decode: each group of 4 bytes is \xHH; parse the 2 hex chars at offset 2.
		dec := make([]byte, 0, len(run)/4)
		for i := 0; i+4 <= len(run); i += 4 {
			hi := run[i+2]
			lo := run[i+3]
			var b byte
			switch {
			case hi >= '0' && hi <= '9':
				b = (hi - '0') << 4
			case hi >= 'a' && hi <= 'f':
				b = (hi - 'a' + 10) << 4
			case hi >= 'A' && hi <= 'F':
				b = (hi - 'A' + 10) << 4
			}
			switch {
			case lo >= '0' && lo <= '9':
				b |= lo - '0'
			case lo >= 'a' && lo <= 'f':
				b |= lo - 'a' + 10
			case lo >= 'A' && lo <= 'F':
				b |= lo - 'A' + 10
			}
			dec = append(dec, b)
		}
		if !emit(dec) {
			return false
		}
		rest = rest[loc[1]:]
	}
	return true
}

// decodeAmpHRuns decodes runs of VBA &HXX hex literals (e.g. &H68,&H74,&H74…).
// Common in VBA macro malware. Returns false on cap hit.
func decodeAmpHRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reAmpH.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		if len(run) > maxAmpHEncoded {
			run = run[:maxAmpHEncoded]
		}
		// Extract each &HXX group via sub-regex; parse the captured hex pair.
		toks := reAmpHTok.FindAllSubmatch(run, -1)
		if len(toks) == 0 {
			rest = rest[loc[1]:]
			continue
		}
		dec := make([]byte, 0, len(toks))
		for _, tok := range toks {
			hi := tok[1][0]
			lo := tok[1][1]
			var b byte
			switch {
			case hi >= '0' && hi <= '9':
				b = (hi - '0') << 4
			case hi >= 'a' && hi <= 'f':
				b = (hi - 'a' + 10) << 4
			case hi >= 'A' && hi <= 'F':
				b = (hi - 'A' + 10) << 4
			}
			switch {
			case lo >= '0' && lo <= '9':
				b |= lo - '0'
			case lo >= 'a' && lo <= 'f':
				b |= lo - 'a' + 10
			case lo >= 'A' && lo <= 'F':
				b |= lo - 'A' + 10
			}
			dec = append(dec, b)
		}
		if !emit(dec) {
			return false
		}
		rest = rest[loc[1]:]
	}
	return true
}

// decodeUEscRuns decodes runs of \uXXXX or %uXXXX Unicode escape sequences.
// Assembles UTF-16 code units and decodes them to UTF-8 via unicode/utf16.
// Returns false on cap hit.
func decodeUEscRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reUEsc.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		if len(run) > maxUEscEncoded {
			// Each unit is 6 chars; trim to multiple of 6.
			run = run[:maxUEscEncoded-(maxUEscEncoded%6)]
		}
		// Collect UTF-16 code units. Each encoded unit is 6 chars: \uXXXX or %uXXXX.
		units := make([]uint16, 0, len(run)/6)
		for i := 0; i+6 <= len(run); i += 6 {
			// Chars at i='\' or '%', i+1='u', i+2..i+5 are 4 hex digits.
			h3 := run[i+2]
			h2 := run[i+3]
			h1 := run[i+4]
			h0 := run[i+5]
			hexByte := func(c byte) uint16 {
				switch {
				case c >= '0' && c <= '9':
					return uint16(c - '0')
				case c >= 'a' && c <= 'f':
					return uint16(c-'a') + 10
				default: // A-F
					return uint16(c-'A') + 10
				}
			}
			u := hexByte(h3)<<12 | hexByte(h2)<<8 | hexByte(h1)<<4 | hexByte(h0)
			units = append(units, u)
		}
		if len(units) == 0 {
			rest = rest[loc[1]:]
			continue
		}
		runes := utf16.Decode(units)
		dec := []byte(string(runes))
		if !emit(dec) {
			return false
		}
		rest = rest[loc[1]:]
	}
	return true
}

// decodeDecSeqRuns decodes decimal-separated byte sequences (e.g. "104,116,116,112…").
// Conservative: requires ALL tokens to be 0..255 and a consistent separator (all ',' or all ';').
// Returns false on cap hit.
func decodeDecSeqRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reDecSeq.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		if len(run) > maxDecSeqEncoded {
			run = run[:maxDecSeqEncoded]
			// Trim back to the last separator so the clamp never cuts a token in
			// half (e.g. "256" → "25", which Atoi would silently accept as a wrong
			// byte). Drop the trailing partial token entirely.
			if i := bytes.LastIndexAny(run, ",;"); i >= 0 {
				run = run[:i]
			}
		}
		// Determine the separator from the first separator character.
		sep := byte(',')
		for _, c := range run {
			if c == ',' || c == ';' {
				sep = c
				break
			}
		}
		// Split on the separator and validate all tokens.
		parts := bytes.Split(run, []byte{sep})
		dec := make([]byte, 0, len(parts))
		valid := true
		for _, p := range parts {
			p = bytes.TrimSpace(p)
			if len(p) == 0 {
				valid = false
				break
			}
			// Reject if any byte is the OTHER separator (mixed separators).
			otherSep := byte(';')
			if sep == ';' {
				otherSep = ','
			}
			if bytes.IndexByte(p, otherSep) >= 0 {
				valid = false
				break
			}
			n, err := strconv.Atoi(string(p))
			if err != nil || n < 0 || n > 255 {
				valid = false
				break
			}
			dec = append(dec, byte(n)) // #nosec G115 -- n bounded 0..255 above
		}
		if valid && len(dec) >= minDecSeqRun {
			if !emit(dec) {
				return false
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

// decodeNetbiosRuns decodes NETBIOS (RFC1001) encoded strings.
// Each byte is encoded as two uppercase letters in [A-P]: high nibble = (b>>4)+'A', low = (b&0xF)+'A'.
// Decoding: ((c1-'A')<<4) | (c2-'A'). Only emits if decoded result is mostly printable text
// or starts with a known container magic (ZIP/OLE/MZ/PDF), to gate FP from random uppercase text.
// Returns false on cap hit.
func decodeNetbiosRuns(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reNetbios.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		// Cap to maxNetbiosEncoded; further clamp to even length.
		if len(run) > maxNetbiosEncoded {
			run = run[:maxNetbiosEncoded]
		}
		if len(run)%2 != 0 {
			run = run[:len(run)-1]
		}
		dec := make([]byte, len(run)/2)
		for i := 0; i < len(run); i += 2 {
			hi := run[i] - 'A'
			lo := run[i+1] - 'A'
			// Both nibbles must be in range [0,15] (chars A-P map to 0-15).
			// The regex [A-P] already guarantees this, but clamp defensively.
			if hi > 15 || lo > 15 {
				dec = nil
				break
			}
			dec[i/2] = (hi << 4) | lo
		}
		if dec == nil {
			rest = rest[loc[1]:]
			continue
		}
		// Gate: only emit if decoded result is mostly printable text OR carries
		// a known container magic (PK zip, OLE, MZ exe, PDF). This prevents emitting
		// garbage from random uppercase text like variable names or acronyms.
		if mostlyText(dec) || hasContainerMagic(dec) {
			if !emit(dec) {
				return false
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

// hasContainerMagic reports whether b starts with a known binary container signature:
// PK (ZIP), OLE2 (D0CF), MZ (EXE/DLL), or PDF (%PDF).
func hasContainerMagic(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	switch {
	case b[0] == 0x50 && b[1] == 0x4B: // PK (ZIP)
		return true
	case b[0] == 0xD0 && b[1] == 0xCF: // OLE2
		return true
	case b[0] == 0x4D && b[1] == 0x5A: // MZ (EXE/DLL)
		return true
	case len(b) >= 4 && b[0] == 0x25 && b[1] == 0x50 && b[2] == 0x44 && b[3] == 0x46: // %PDF
		return true
	}
	return false
}

// decodeBase32Runs decodes standard base32 encoded strings ([A-Z2-7] alphabet).
// To reduce FP against base64/NETBIOS/plain-text runs of pure [A-Z], only decodes
// runs containing at least one digit from [2-7] — the base32-distinctive chars.
// Returns false on cap hit.
func decodeBase32Runs(src []byte, deadline time.Time, emit func([]byte) bool) bool {
	rest := src
	for len(rest) > 0 {
		if expired(deadline) {
			return true
		}
		loc := reBase32.FindIndex(rest)
		if loc == nil {
			return true
		}
		run := rest[loc[0]:loc[1]]
		if len(run) > maxBase32Encoded {
			// Trim to multiple of 8 (base32 groups).
			n := maxBase32Encoded - (maxBase32Encoded % 8)
			run = run[:n]
		}
		// Require at least one base32-distinctive digit (2-7). Pure [A-Z] runs are
		// ambiguous (could be base64, NETBIOS, or plain text); runs with 2-7 are
		// distinctively base32.
		hasDistinctive := false
		for _, c := range run {
			if c >= '2' && c <= '7' {
				hasDistinctive = true
				break
			}
		}
		if !hasDistinctive {
			rest = rest[loc[1]:]
			continue
		}
		dec, ok := tryBase32(run)
		if ok {
			if !emit(dec) {
				return false
			}
		}
		rest = rest[loc[1]:]
	}
	return true
}

// tryBase32 decodes one run with standard base32 encoding, tolerating missing
// padding (appends '=' to make length a multiple of 8 if needed).
func tryBase32(run []byte) ([]byte, bool) {
	s := string(run)
	if dec, err := base32.StdEncoding.DecodeString(s); err == nil {
		return dec, true
	}
	// Pad to multiple of 8 and retry.
	s = strings.TrimRight(s, "=")
	if rem := len(s) % 8; rem != 0 {
		s += strings.Repeat("=", 8-rem)
	}
	if dec, err := base32.StdEncoding.DecodeString(s); err == nil {
		return dec, true
	}
	return nil, false
}

// emitReversed emits a whole-buffer reverse of src, but only when src carries a
// reversed high-signal token — so StrReverse-obfuscated keywords surface without
// reversing (and re-scanning) every benign body. Returns false on a global cap.
func emitReversed(src []byte, emit func([]byte) bool) bool {
	if len(src) == 0 || len(src) > maxReverseInput {
		return true
	}
	low := bytes.ToLower(src)
	hit := false
	for _, m := range reversedMarkers {
		if bytes.Contains(low, m) {
			hit = true
			break
		}
	}
	if !hit {
		return true
	}
	rev := make([]byte, len(src))
	for i := range src {
		rev[len(src)-1-i] = src[i]
	}
	return emit(rev)
}
