// Package urlcand provides shared URL candidate extraction for reputation-feed
// checkers (urlhaus, threatfox). A single Extract call replaces the
// per-checker redundant regex walk + defang copy that the old code performed
// on every buffer.
//
// The extraction logic is identical to what the old per-checker Check methods
// did inline: FindAll on the raw buffer (raw candidates), then — only when the
// cheap byte-gate fires — FindAll on the defanged copy (deobfuscated
// candidates). All raw candidates come first; deobfuscated ones follow. A
// shared budget caps the total across both passes.
package urlcand

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"
)

var (
	urlRe        = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>)\]}\x00-\x1f]+`)
	schemeSep    = []byte("://")
	defangTokens = [][]byte{
		[]byte("hxxp"),
		[]byte("hXXp"),
		[]byte("[.]"),
		[]byte("(.)"),
		[]byte("{.}"),
		[]byte("[dot]"),
		[]byte("(dot)"),
		[]byte("{dot}"),
		[]byte("[DOT]"),
		[]byte(" dot "),
		[]byte("[:]"),
		[]byte("[://]"),
	}
)

// Candidate is one URL string extracted from a buffer.
type Candidate struct {
	Raw   string // the raw URL string as found in the buffer
	Deobf bool   // true when found only in the defanged copy
	Norm  string // canonical http(s) URL form for feed lookup, "" when invalid
	Host  string // lowercase hostname from Norm, "" when invalid
	IP    string // Host when it is a dotted-decimal IPv4 address, else ""

	normalized bool
}

// Extract extracts URL candidates from data. If maxURLs <= 0 it defaults to 64.
// Raw candidates (Deobf=false) come first; defanged candidates (Deobf=true)
// follow using the remaining budget. The total number of candidates never
// exceeds maxURLs.
//
// The extraction mirrors the semantics of the old per-checker inline loop:
// budget is decremented once per regex match (not per normalized/valid URL),
// so the same first-N matches are produced regardless of which checker
// subsequently processes them.
func Extract(data []byte, maxURLs int) []Candidate {
	if maxURLs <= 0 {
		maxURLs = 64
	}
	// PERF-29: cheap pre-gate before the regexp and defang string materialisation.
	// On a clean buffer (no "://" and no defang token) neither the raw
	// regexp nor the defang path can produce any candidate — return early without
	// allocating anything.
	defangPossible := hasDefangToken(data)
	if !bytes.Contains(data, schemeSep) && !defangPossible {
		return nil
	}
	budget := maxURLs

	matches := urlRe.FindAll(data, budget)
	if len(matches) == 0 && !defangPossible {
		return nil
	}

	var out []Candidate
	for _, m := range matches {
		if budget <= 0 {
			break
		}
		budget--
		out = append(out, NewCandidate(string(m), false))
	}

	if budget > 0 && defangPossible {
		if defanged := defang(data); defanged != "" {
			for _, m := range urlRe.FindAll([]byte(defanged), budget) {
				if budget <= 0 {
					break
				}
				budget--
				out = append(out, NewCandidate(string(m), true))
			}
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// NewCandidate builds a candidate. Normalized lookup fields are filled lazily on
// first feed use so clean extraction avoids URL parsing until it is needed.
func NewCandidate(raw string, deobf bool) Candidate {
	return Candidate{Raw: raw, Deobf: deobf}
}

// Normalize lazily fills and returns the shared normalized lookup fields.
func (c *Candidate) Normalize() (norm, host, ip string) {
	if !c.normalized {
		c.Norm, c.Host, c.IP = NormalizeHTTPURL(c.Raw)
		c.normalized = true
	}
	return c.Norm, c.Host, c.IP
}

// NormalizeHTTPURL returns a canonical http(s) URL for feed set comparison,
// the bare lowercase hostname, and the raw IPv4 hostname when present. It
// lowercases scheme/host, strips default ports and fragments, removes a bare
// trailing "/", and trims common trailing punctuation from regex captures.
func NormalizeHTTPURL(raw string) (norm, host, ip string) {
	raw = strings.TrimRight(strings.TrimSpace(raw), ".,);]}'\"")
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", ""
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return "", "", ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "" {
		return "", "", ""
	}
	hostPort := h
	if p := u.Port(); p != "" && !defaultPort(scheme, p) {
		hostPort = h + ":" + p
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	norm = scheme + "://" + hostPort + path
	if u.RawQuery != "" {
		norm += "?" + u.RawQuery
	}
	if isIPv4(h) {
		ip = h
	}
	return norm, h, ip
}

func defaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

func isIPv4(s string) bool {
	if s == "" {
		return false
	}
	dots := 0
	for _, c := range s {
		if c == '.' {
			dots++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dots == 3
}

func hasDefangToken(data []byte) bool {
	for _, tok := range defangTokens {
		if bytes.Contains(data, tok) {
			return true
		}
	}
	return false
}

// defang rewrites common URL obfuscations malware uses in document code back
// to a scannable form. Returns "" when nothing changed (so the caller skips a
// redundant second pass). Cheap and bounded: plain string replacement only.
func defang(data []byte) string {
	// Check on the raw bytes BEFORE materialising a string: for the common
	// no-defang case this avoids a full-buffer copy on the hot path.
	if !hasDefangToken(data) {
		return ""
	}
	s := string(data)
	r := strings.NewReplacer(
		"hxxps", "https", "hXXps", "https", "hxxp", "http", "hXXp", "http",
		"[.]", ".", "(.)", ".", "{.}", ".",
		"[dot]", ".", "(dot)", ".", "{dot}", ".", "[DOT]", ".", " dot ", ".",
		"[:]", ":", "[://]", "://",
	)
	out := r.Replace(s)
	if out == s {
		return ""
	}
	return out
}
