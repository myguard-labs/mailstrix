package yarad

import (
	"time"

	"github.com/eilandert/rspamd-yarad/internal/extract"
)

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
// As of EFFORT-4 the dial is LIVE: EffortProfileFor maps a level to a real cap
// set (MSD decode depth/iterations, PDF indicator pass, reputation-feed gating),
// ExtractOptions threads the extract-side caps into extract.Extract, and the
// scanner gates the external feeds on the profile. A low level unwraps fewer
// decode layers, skips the PDF structural-indicator pass, and skips the
// URLhaus/MalwareBazaar lookups; the ceiling runs everything at full depth.
//
// Not (yet) effort-scaled: the XLM formula/sheet caps — deferred to a follow-up
// (see TODO EFFORT-4-XLMCAPS); they still read their package constants.
// The per-libyara-scan wall-clock (scanTimeout) is now effort-scaled (EFFORT-4-SCANTIMEOUT)
// via EffortProfile.ScanTimeout.

// EffortProfile is the resolved set of caps for one scan's effort level. As of
// EFFORT-4 the fields are LIVE: ExtractOptions maps DecodeDepth/DecodeIterations/
// PDFDeepen into the extract package's per-request caps, and the scanner gates the
// reputation-feed lookups on ReputationFeeds. The level still folds into the
// verdict-cache key so two scans of the same bytes at different effort can hold
// distinct verdicts.
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
	DecodeDepth      int
	DecodeIterations int
	PDFDeepen        bool
	ReputationFeeds  bool

	// ScanTimeout is the per-request libyara wall-clock budget scaled by effort
	// level. At level 1 it is 50% of the base; at the ceiling it equals the base.
	// A zero base (no limit) keeps ScanTimeout at 0 (no limit).
	ScanTimeout time.Duration
}

// Cap ceilings used by the effort table. fullDecodeDepth mirrors
// extract.maxDecodeDepth (the always-on MSD recursion bound); fullDecodeIters
// mirrors extract.maxDecodeIterations. The lowest level still does ONE decode
// layer (a single base64/hex unwrap is the common case and cheap), so a level-1
// scan is not blind to a one-layer dropper.
const (
	fullDecodeDepth = 4
	fullDecodeIters = 256
	minDecodeIters  = 64 // floor so even level 1 can finish a small worklist
)

// EffortProfileFor maps a resolved effort level to its cap profile (EFFORT-4).
// The dial is now LIVE: a low level unwraps fewer MSD decode layers, skips the
// PDF structural-indicator pass, and skips the reputation-feed lookups; a high
// level runs everything at full depth. The mapping is expressed against
// EffortMax (the operator's ceiling) so it scales whatever ceiling is configured,
// not a hard-coded 10.
//
//   - DecodeDepth ramps 1..fullDecodeDepth linearly across the level range.
//   - PDFDeepen turns on once past the lowest fifth of the range (the structural
//     indicator pass is cheap but FP-bearing; the cheapest tier skips it).
//   - ReputationFeeds turn on in the upper half (the external-feed lookups are
//     the most expensive per-scan cost; shed them first under low effort).
//
// level is assumed already resolved/clamped to [1, EffortMax] by
// ResolveEffortLevel; it is defensively floored at 1 here so a stray 0 can't
// produce a degenerate profile. effortMax is the configured ceiling (>=1).
// minScanTimeout is the floor for scaled ScanTimeout so a low effort level
// never accidentally sets a very-short timeout that aborts benign scans.
const minScanTimeout = 1 * time.Second

func EffortProfileFor(level, effortMax int, baseScanTimeout time.Duration) EffortProfile {
	if effortMax < 1 {
		effortMax = 1
	}
	if level < 1 {
		level = 1
	}
	if level > effortMax {
		level = effortMax
	}

	// frac in [0,1]: 0 at level 1, 1 at the ceiling. A 1-level ceiling is always
	// full depth (there is no room to shed).
	var frac float64 = 1
	if effortMax > 1 {
		frac = float64(level-1) / float64(effortMax-1)
	}

	// DecodeDepth: 1 at the floor, fullDecodeDepth at the ceiling, rounded.
	depth := 1 + int(frac*float64(fullDecodeDepth-1)+0.5)
	if depth < 1 {
		depth = 1
	}
	if depth > fullDecodeDepth {
		depth = fullDecodeDepth
	}
	// DecodeIterations scale with depth so a shallow walk isn't handed the full
	// 256-dequeue budget it can't use; floored so a small worklist still drains.
	iters := minDecodeIters + int(frac*float64(fullDecodeIters-minDecodeIters)+0.5)
	if iters > fullDecodeIters {
		iters = fullDecodeIters
	}

	// ScanTimeout: scale linearly from 50% of base at level 1 to 100% at the
	// ceiling. A zero base means no limit — keep it zero. Floor at minScanTimeout
	// so a stray low effort level can't set an unreasonably short timeout.
	var scanTimeout time.Duration
	if baseScanTimeout > 0 {
		scaled := time.Duration(float64(baseScanTimeout) * (0.5 + 0.5*frac))
		if scaled < minScanTimeout {
			scaled = minScanTimeout
		}
		scanTimeout = scaled
	}

	return EffortProfile{
		Level:            level,
		DecodeDepth:      depth,
		DecodeIterations: iters,
		PDFDeepen:        frac > 0.2,  // skip only the cheapest tier (lowest ~fifth)
		ReputationFeeds:  frac >= 0.5, // external feeds shed first: upper half only
		ScanTimeout:      scanTimeout,
	}
}

// resolveScanEffort picks the effort level a scan runs at. The HTTP path folds a
// resolved level (>=1) into ScanMeta; any caller that did NOT resolve effort (the
// `yarad scan` CLI, a direct Scan with a bare ScanMeta) leaves it at 0. An
// unresolved (<1) level means "run at the configured ceiling" — full depth — so
// an un-resolved scan never silently degrades to the cheapest tier.
func resolveScanEffort(metaEffort, effortMax int) int {
	if metaEffort < 1 {
		return effortMax
	}
	return metaEffort
}

// ExtractOptions builds the extract package's per-request Options from this
// resolved profile plus the scan deadline. It is the single mapping point
// between the yarad-side effort profile and the extract-side caps (EFFORT-4).
func (p EffortProfile) ExtractOptions(deadline time.Time) *extract.Options {
	return &extract.Options{
		Deadline:         deadline,
		DecodeDepth:      p.DecodeDepth,
		DecodeIterations: p.DecodeIterations,
		PDFDeepen:        p.PDFDeepen,
	}
}

// autoTargetLevel maps current admission-gate pressure to the effort level the
// auto resolver (EFFORT-2) wants to be at. It is the steady-state target; the
// stepper (autoStepLevel) approaches it one level per scan for hysteresis.
//
//	occupied  in-flight admission slots (including the caller's own held slot),
//	          so it is in [1, capacity].
//	capacity  the gate size (cfg.MaxInflight); a non-positive value means the gate
//	          is effectively unbounded, so there is no pressure -> idle level.
//	idleLevel the ceiling to use when the gate is empty (cfg.Effort, == EffortMax
//	          by default). The target never exceeds it.
//	effortMax the operator's hard ceiling; idleLevel is clamped into [1, effortMax].
//
// Mapping: empty gate -> idleLevel; full gate -> 1; linear in between. We measure
// pressure as the fraction of slots used BEYOND the caller's own (occupied-1 over
// capacity-1) so a single in-flight request (no contention) still maps to the
// idle ceiling, and a saturated gate maps to 1.
func autoTargetLevel(occupied, capacity, idleLevel, effortMax int) int {
	if effortMax < 1 {
		effortMax = 1
	}
	if idleLevel < 1 {
		idleLevel = 1
	}
	if idleLevel > effortMax {
		idleLevel = effortMax
	}
	// No bound (or a degenerate 1-slot gate) -> no measurable pressure.
	if capacity <= 1 {
		return idleLevel
	}
	if occupied < 1 {
		occupied = 1
	}
	if occupied > capacity {
		occupied = capacity
	}
	// Fraction of contention in [0,1]: 0 when we are the only request, 1 when the
	// gate is full. span = idleLevel-1 levels to give away under full pressure.
	span := idleLevel - 1
	if span <= 0 {
		return idleLevel
	}
	// drop = round(frac * span), frac = (occupied-1)/(capacity-1).
	num := (occupied - 1) * span
	den := capacity - 1
	drop := (num + den/2) / den // integer round-half-up
	level := idleLevel - drop
	if level < 1 {
		level = 1
	}
	return level
}

// autoStepLevel moves the smoothed auto level one step toward target. Stepping
// by at most one level per scan is the hysteresis: a brief pressure spike can't
// slam effort to 1 and back, it ramps. cur==0 (uninitialised) snaps straight to
// target so the first scan starts at the right level, not at 0+1.
func autoStepLevel(cur, target int) int {
	if cur < 1 {
		return target // first observation: adopt target directly
	}
	switch {
	case target > cur:
		return cur + 1
	case target < cur:
		return cur - 1
	default:
		return cur
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
