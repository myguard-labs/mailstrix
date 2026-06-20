package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	// maxB64Encoded / maxHexEncoded bound the ENCODED candidate length we hand to
	// a decoder, so one giant run can't allocate/copy far past maxBytesPerDecodedBlob
	// before the emit cap truncates (base64 expands ~4/3, hex 2x). Both stay
	// alignment-valid (mult of 4 / mult of 2) when we slice a prefix.
	maxB64Encoded = (maxBytesPerDecodedBlob/3 + 1) * 4
	maxHexEncoded = maxBytesPerDecodedBlob * 2
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
func fromEncoded(buf []byte, res *Result, deadline time.Time) {
	// Snapshot: the raw buffer plus the streams present right now. Appends below
	// grow res.Streams (possibly reallocating its backing array) but never touch
	// this slice's elements, so we iterate a stable, finite set.
	sources := make([][]byte, 0, len(res.Streams)+1)
	sources = append(sources, buf)
	sources = append(sources, res.Streams...)

	total := 0
	for _, src := range sources {
		if expired(deadline) || len(res.Streams) >= maxStreams {
			break
		}
		total += decodeSourceTree(src, res, deadline)
	}
	// Record how many blobs the pass appended (always the trailing res.Streams),
	// so the caller can keep the macro/extracted-stream metrics free of decode noise.
	res.DecodedStreams = total
}

// decodeSourceTree runs the recursive multi-layer decode for ONE source stream
// and returns the number of blobs it emitted. The blob/byte budget is local to
// this call (the per-source reset of the MSD-1 contract); it is shared across all
// recursion depths of this source via the closure below. A FIFO worklist gives
// breadth-first unwrapping so the budget is spent on shallow layers (more likely
// to be the real payload) before deep ones.
func decodeSourceTree(src []byte, res *Result, deadline time.Time) int {
	type item struct {
		data  []byte
		depth int
	}
	queue := []item{{src, 0}}

	var blobs, cum, iters int
	// children collects the blobs emitted while decoding the CURRENT item, so we
	// can decide which to re-enqueue one layer deeper after the decoders run.
	var children [][]byte
	emit := func(b []byte) bool {
		if len(b) < minDecodedLen {
			return true
		}
		if len(b) > maxBytesPerDecodedBlob {
			b = b[:maxBytesPerDecodedBlob]
		}
		if blobs >= maxDecodedBlobs || len(res.Streams) >= maxStreams || cum+len(b) > maxCumulativeDecoded {
			return false
		}
		res.Streams = append(res.Streams, b)
		children = append(children, b)
		blobs++
		cum += len(b)
		return true
	}

	for len(queue) > 0 {
		if expired(deadline) || iters >= maxDecodeIterations ||
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

		children = children[:0]
		ok := decodeBase64Runs(cur.data, deadline, emit) &&
			decodeHexRuns(cur.data, deadline, emit) &&
			emitReversed(cur.data, emit) &&
			foldVBAStrings(cur.data, deadline, emit)

		// Re-enqueue this item's encoded children one layer deeper. Gate on
		// looksEncoded so a fully-decoded cleartext blob isn't re-scanned for
		// nothing (the main speed lever — keeps deep layers ~free on benign input).
		// `+1 < maxDecodeDepth` bounds a decode chain to exactly maxDecodeDepth
		// passes: the source decodes at depth 0 and each child one deeper, so the
		// deepest decoded item is at depth maxDecodeDepth-1.
		if cur.depth+1 < maxDecodeDepth {
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
	return blobs
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
	return reChrConcat.Match(scan) || reReplace.Match(scan) || reArrayXor.Match(scan) ||
		reStrReverse.Match(scan) || reEnviron.Match(scan) || reDridex.Match(scan)
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
