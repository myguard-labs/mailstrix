package extract

import (
	"bytes"
	"regexp"
)

// reHxxp matches a defanged HTTP/HTTPS scheme marker only when immediately
// followed by optional 's' and then ':' or '[' (a bracketed colon).  This
// prevents rewriting the word "hxxp" that appears in legitimate security
// reports as prose rather than as an embedded URL.
//
// Pattern captures:
//
//	group 1: optional 's' (present for https)
//	group 2: the trailing delimiter character ':' or '['
//
// Go's RE2 has no lookaheads, so we capture the delimiter and re-emit it.
var reHxxp = regexp.MustCompile(`(?i)hxxp(s?)(:|(?:\[))`)

// reFxp matches the FTP scheme defang "fxp://" or "fxp[:]" at a scheme
// position (immediately followed by "://" or "[:]").
var reFxp = regexp.MustCompile(`(?i)fxp(:|(?:\[))`)

// Literal gates for reHxxp and reFxp: neither can match without its needle.
var (
	defangHxxpNeedle = []byte("hxxp")
	defangFxpNeedle  = []byte("fxp")
)

// defangLiterals is an ordered list of (old, new) byte-literal replacements
// applied AFTER the regex scheme fixes. Each pair is unambiguous: these
// exact byte sequences appear exclusively in defanged IOCs, not in normal
// prose or binary data.
//
// Ordering matters: longer/more-specific patterns come before shorter ones
// that are substrings of them (e.g. "[//]" before "[/]").
var defangLiterals = [][2][]byte{
	// Bracketed colon/slash/at -- longer patterns before shorter substrings.
	{[]byte("[://]"), []byte("://")},
	{[]byte("[//]"), []byte("//")},
	{[]byte("[/]"), []byte("/")},
	{[]byte("[:]"), []byte(":")},
	// Bracketed / parenthesized dot -- the most common IOC defang.
	{[]byte("[.]"), []byte(".")},
	{[]byte("(.)"), []byte(".")},
	{[]byte("{.}"), []byte(".")},
	// Worded dot -- only bracketed/parenthesized forms; bare " dot " is too
	// aggressive (occurs in English prose).
	{[]byte("[dot]"), []byte(".")},
	{[]byte("[DOT]"), []byte(".")},
	{[]byte("(dot)"), []byte(".")},
	{[]byte("(DOT)"), []byte(".")},
	// Bracketed/parenthesized at-sign.
	{[]byte("[@]"), []byte("@")},
	{[]byte("(@)"), []byte("@")},
	{[]byte("[at]"), []byte("@")},
	{[]byte("[AT]"), []byte("@")},
	{[]byte("(at)"), []byte("@")},
	{[]byte("(AT)"), []byte("@")},
	// Bracketed letters inside h[tt]ps-style scheme fragments.
	// Only "[tt]" is targeted -- it appears exclusively in "h[tt]p" and has
	// no legitimate prose use.  A generic bracket-stripper would FP on many
	// unrelated patterns.
	{[]byte("[tt]"), []byte("tt")},
	{[]byte("[TT]"), []byte("TT")},
}

// undefang returns a normalized COPY of buf with common defang markers
// reversed, and ok=true iff at least one substitution was made.  If nothing
// changed, it returns (buf, false) without allocating.
//
// Conservative design: only well-known, unambiguous defang patterns are
// reversed (see defangLiterals above and the regex-based scheme fixes).
// The function is not called on binary blobs -- callers gate on mostlyText.
// Input longer than maxFoldInput is clamped to that prefix so a multi-MiB
// carrier cannot cause unbounded allocation.
func undefang(buf []byte) ([]byte, bool) {
	if len(buf) == 0 {
		return buf, false
	}
	// Clamp: defang patterns always sit in the first part of a real IOC
	// carrier; the byte budget stays predictable.
	src := buf
	if len(src) > maxFoldInput {
		src = src[:maxFoldInput]
	}

	// Fast path: every literal defang starts with '[', '(' or '{', and the
	// scheme regexes need the literal "hxxp" or "fxp" (PERF-51: a bare 'h' or
	// 'f' used to wake the whole pass on almost any prose).
	hasHxxp := containsASCIIFold(src, defangHxxpNeedle)
	hasFxp := containsASCIIFold(src, defangFxpNeedle)
	if !hasHxxp && !hasFxp && !bytes.ContainsAny(src, "[({") {
		return buf, false
	}

	// Apply regex-based scheme fixes first (hxxp → http, fxp → ftp).
	// reHxxp captures group 1 = optional 's', group 2 = trailing delimiter.
	// reHxxp and reFxp use ReplaceAllFunc with submatch expansion via
	// FindSubmatch so we can re-emit the captured delimiter character.
	out := src
	if hasHxxp {
		out = reHxxp.ReplaceAllFunc(out, func(m []byte) []byte {
			sub := reHxxp.FindSubmatch(m)
			// sub[1] = optional 's', sub[2] = ':' or '['
			s := ""
			if len(sub) > 1 && len(sub[1]) > 0 {
				s = "s"
			}
			delim := []byte(":")
			if len(sub) > 2 && len(sub[2]) > 0 {
				delim = sub[2]
			}
			return append([]byte("http"+s), delim...)
		})
	}
	if hasFxp {
		out = reFxp.ReplaceAllFunc(out, func(m []byte) []byte {
			sub := reFxp.FindSubmatch(m)
			delim := []byte(":")
			if len(sub) > 1 && len(sub[1]) > 0 {
				delim = sub[1]
			}
			return append([]byte("ftp"), delim...)
		})
	}

	// Apply ordered literal replacements.
	for _, pair := range defangLiterals {
		if bytes.Contains(out, pair[0]) {
			out = bytes.ReplaceAll(out, pair[0], pair[1])
		}
	}

	// No change?
	if bytes.Equal(out, src) {
		return buf, false
	}
	return out, true
}
