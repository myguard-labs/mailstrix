package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Static single-layer deobfuscation. Malware authors hide a payload (a URL, a
// PowerShell one-liner, a dropped EXE) inside an otherwise-cleartext script or
// macro by base64/hex-encoding it or writing keywords backwards (VBA
// StrReverse). A raw keyword scan never sees the payload because the bytes on
// disk are the encoded form. fromEncoded reverses the cheap, deterministic
// transforms — base64, hex, and a whole-buffer reverse — over the raw buffer and
// every already-extracted cleartext stream, emitting each decoded result as an
// extra stream so the keyword/maldoc rules match the real content.
//
// This is the tractable slice of oletools' deobfuscation: SINGLE-LAYER static
// transforms, NOT emulation. It deliberately does not chain (a decoded blob is
// never fed back through fromEncoded — depth cap 1) and does not interpret VBA
// or evaluate XLM/Excel-4.0 macros; that decode/emulation tail (Dridex-style
// multi-stage unpacking) stays with olevba/ViperMonkey (rspamd-olefy).
//
// Everything is bounded and fail-open: a source that decodes to nothing, a cap
// hit, or a malformed run just yields fewer streams — never an error.

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
	// maxB64Encoded / maxHexEncoded bound the ENCODED candidate length we hand to
	// a decoder, so one giant run can't allocate/copy far past maxBytesPerDecodedBlob
	// before the emit cap truncates (base64 expands ~4/3, hex 2x). Both stay
	// alignment-valid (mult of 4 / mult of 2) when we slice a prefix.
	maxB64Encoded = (maxBytesPerDecodedBlob/3 + 1) * 4
	maxHexEncoded = maxBytesPerDecodedBlob * 2
	// maxReverseInput bounds the per-source cost of the whole-buffer reverse.
	maxReverseInput = 1 << 20
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

// fromEncoded runs the single-layer static decoders over buf and a snapshot of
// the streams extracted so far, appending any decoded blobs to res.Streams and
// setting res.Decoded when at least one was emitted. It NEVER reprocesses its own
// output: the source list is snapshotted before the first append, so a decoded
// blob is scanned by libyara but not decoded again (depth cap 1).
func fromEncoded(buf []byte, res *Result, deadline time.Time) {
	// Snapshot: the raw buffer plus the streams present right now. Appends below
	// grow res.Streams (possibly reallocating its backing array) but never touch
	// this slice's elements, so we iterate a stable, finite set.
	sources := make([][]byte, 0, len(res.Streams)+1)
	sources = append(sources, buf)
	sources = append(sources, res.Streams...)

	var blobs, cum int
	// emit appends one decoded blob, enforcing the caps. It returns false when a
	// global cap is hit (the caller must stop), true otherwise (incl. a skipped
	// too-short blob).
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
		blobs++
		cum += len(b)
		return true
	}

	for _, src := range sources {
		if expired(deadline) || blobs >= maxDecodedBlobs || cum >= maxCumulativeDecoded {
			break
		}
		// Only decode mostly-text sources; binary container bytes yield noise.
		if !mostlyText(src) {
			continue
		}
		if !decodeBase64Runs(src, deadline, emit) {
			break
		}
		if !decodeHexRuns(src, deadline, emit) {
			break
		}
		if !emitReversed(src, emit) {
			break
		}
	}
	// Record how many blobs the pass appended (always the last res.Streams), so
	// the caller can keep the macro/extracted-stream metrics free of decode noise.
	res.DecodedStreams = blobs
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
