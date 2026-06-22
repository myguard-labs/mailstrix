package yarad

// Effort tiers (EFFORT-1) — the operator/caller cost dial.
//
// A single scalar level (1..EffortMax) scales every bounded extraction/scan cap
// so one binary serves a latency-tight front (rspamd, pre-queue) and a deeper
// backend (LDA/sieve), and can shed work under load. Level 1 = raw bytes plus
// the shallowest structural extraction; EffortMax = every decoder/feed at full
// depth.
//
// This file defines the CONTRACT only (EFFORT-1):
//   - EffortProfile: the resolved per-request cap set;
//   - ResolveEffortLevel: header/env resolution with the DoS clamp;
//   - EffortProfileFor: level -> profile.
//
// The profile is threaded to the scanner and folded into the verdict-cache key,
// but the individual caps (MSD decode depth, XLM/PDF clamps, reputation-feed
// gating, scan timeout) still read their package constants today. EFFORT-4
// retrofits each cap to read its EffortProfile field. Until then every level
// resolves to the same effective behaviour (full depth) — the plumbing is
// present but inert, so each new feature wires its cap in from day one and the
// dial activates the moment EFFORT-4 lands.

// EffortProfile is the resolved set of caps for one scan's effort level. Fields
// are the dials EFFORT-4 will wire; today they are populated for observability /
// cache-key stability but not yet read by the extractors.
type EffortProfile struct {
	// Level is the resolved effort (1..EffortMax) this profile was built for. It
	// is what folds into the verdict-cache key, so two scans of the same bytes at
	// different effort can hold distinct verdicts.
	Level int

	// DecodeDepth caps the MSD multi-layer static-decode recursion (decode.go
	// maxDecodeDepth). PDFDeepen enables the PDF action/JS indicator pass
	// (pdf.go fromPDFIndicators). ReputationFeeds enables the URLhaus/MalwareBazaar
	// lookups. These are the first caps EFFORT-4 wires; more (XLM formula/sheet
	// caps, fold/carve clamps, maxStreams) follow.
	DecodeDepth     int
	PDFDeepen       bool
	ReputationFeeds bool
}

// EffortProfileFor maps an effort level to its profile. EFFORT-1 returns a
// full-depth profile at every level (the inert contract): the structure and the
// Level field are real, the cap VALUES are the current always-on behaviour so no
// scan changes until EFFORT-4 introduces per-level differentiation.
//
// level is assumed already resolved/clamped to [1, EffortMax] by
// ResolveEffortLevel; it is defensively floored at 1 here so a stray 0 can't
// produce a degenerate profile.
func EffortProfileFor(level int) EffortProfile {
	if level < 1 {
		level = 1
	}
	// Inert full-depth profile (EFFORT-1). EFFORT-4 replaces the constants below
	// with a level-indexed table.
	return EffortProfile{
		Level:           level,
		DecodeDepth:     4, // mirrors extract.maxDecodeDepth (current always-on value)
		PDFDeepen:       true,
		ReputationFeeds: true,
	}
}

// ResolveEffortLevel applies the request-time resolution order:
//
//	header (if a valid 1..N int was sent) ?? envDefault
//
// then clamps the result to [1, effortMax]. The clamp is the DoS guard: a caller
// (or an attacker who can set the X-YARAD-Effort header) can never drive effort
// above the operator's configured ceiling. A malformed/empty header falls back
// to the env default; a header below 1 or above effortMax is clamped, not
// rejected (fail-toward-configured, never error a scan over a header).
//
// headerSet reports whether the header carried a usable integer (so the caller
// can distinguish "no header" from "header == envDefault" for metrics if wanted).
func ResolveEffortLevel(headerVal int, headerSet bool, envDefault, effortMax int) int {
	level := envDefault
	if headerSet {
		level = headerVal
	}
	if effortMax < 1 {
		effortMax = 1
	}
	if level < 1 {
		level = 1
	}
	if level > effortMax {
		level = effortMax
	}
	return level
}
