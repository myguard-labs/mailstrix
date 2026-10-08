package mailstrix

import (
	"time"

	yara "github.com/hillu/go-yara/v4"
	"github.com/myguard-labs/mailstrix/internal/extract"
)

// matchKey is the (namespace, rule) identity used to dedup matches across the
// raw scan and every extracted stream. A struct key instead of "namespace/rule"
// concatenation avoids one synthetic key string allocation per match.
type matchKey struct {
	namespace string
	rule      string
}

// extractScan carries the per-scan mutable state of scanGeneration's extracted
// stream/marker sweep (AUD-M4a3). scanGeneration copies out, incomplete and
// completionErr back after the sweep.
type extractScan struct {
	s          *Scanner
	seen       map[[16]byte]struct{}
	deadline   time.Time
	res        *extract.Result
	vbaKeys    map[[16]byte]struct{}
	rules      *yara.Rules
	generation scannerGeneration
	meta       ScanMeta
	matchSeen  map[matchKey]struct{}

	out           []Match
	incomplete    bool
	completionErr error

	streamsVisited, markersVisited, oversizedRerouted int
}

// scan runs one extracted entry (real content stream OR an out-of-band
// marker) through dedup, the shared scan budget, and merge. Returns true when
// the budget is exhausted so the caller stops the whole sweep. Markers and
// Streams share one `seen` set and one budget — a marker byte-identical to a
// real stream is scanned once, and markers can't overrun the deadline.
// PERF-68: per-scan counters so the budget log reports what is actually left
// and the oversized-stream reroute logs once per scan, not once per stream.
func (x *extractScan) scan(stream []byte, h [16]byte, markerChannel bool) (stop bool) {
	if markerChannel {
		x.markersVisited++
	} else {
		x.streamsVisited++
	}
	if _, dup := x.seen[h]; dup {
		x.s.exDeduped.Add(1)
		return false
	}
	x.seen[h] = struct{}{}
	budget := x.s.scanTimeout
	if !x.deadline.IsZero() {
		// Native scans need at least one whole second; scanOne would round
		// a smaller positive budget up past the shared deadline.
		if budget = time.Until(x.deadline); budget < time.Second {
			x.s.logf("scan budget exhausted; %d streams + %d markers left unscanned",
				len(x.res.Streams)-x.streamsVisited+1, max(len(x.res.Markers)-x.markersVisited+1, 0))
			x.incomplete = true
			return true
		}
	}
	// Set the VBA external ONLY when this stream is genuine VBA macro source
	// (vbaKeys membership), so the macro-keyword rules (Didier vba.yara: `VBA and
	// any of(...)`) fire on decompressed macros — inert on raw bytes — but NOT on
	// a PDF/archive/script/marker/decoded stream that merely happens to contain a
	// macro keyword. A marker-channel entry is never VBA. filename/extension carry
	// through so a name-keyed rule fires the same on the container's decompressed
	// macros as on its raw bytes.
	isVBA := false
	if !markerChannel && len(x.vbaKeys) > 0 {
		_, isVBA = x.vbaKeys[h]
	}
	// Oversized-stream cost gate (BIGFILE, extracted side): an extractor can emit
	// multi-MiB children (VBA 4 MiB, bin 8 MiB, archive member 16 MiB, PDF/RTF/
	// TNEF/package cumulative tens of MiB). Scanning such a child against the full
	// ~12k-rule set is the same unbounded cost the raw gate guards against, and it
	// drains the shared deadline budget for the remaining streams even when the raw
	// body was under threshold. Route oversized REAL-content streams through the
	// big-file ruleset too; marker-channel entries are tiny + synthetic so they
	// always keep the full set. Mirrors the raw gate (nil bigRules → full set).
	streamRules := x.rules
	if !markerChannel && x.s.bigFileThreshold > 0 && int64(len(stream)) > x.s.bigFileThreshold {
		if big := x.generation.bigRules; big != nil {
			streamRules = big
			x.s.bigFileStreamScans.Add(1)
			x.oversizedRerouted++
		} else if x.s.bigNilWarned.CompareAndSwap(false, true) {
			x.s.logf("WARNING: oversized extracted stream (%dB) but no big-file ruleset loaded; using full set (may time out)", len(stream))
		}
	}
	// PERF-18: for the out-of-band Markers channel, use the marker-only bundle
	// (full ruleset with non-marker rules disabled) so the scan runs against a
	// tiny subset instead of the full ~12k-rule set. Falls back to the full
	// ruleset when the bundle is not available. filterMarkerChannel remains as
	// belt-and-suspenders regardless of which ruleset is used.
	if markerChannel {
		if mb := x.generation.markerRules; mb != nil {
			streamRules = mb
		}
	}
	if markerChannel {
		x.s.markerChannelScans.Add(1)
	} else {
		x.s.streamChannelScans.Add(1)
	}
	// PERF-41: the out-of-band marker channel scans synthetic literal markers
	// against the marker-only bundle, whose rules carry their whole condition in
	// the marker bytes and do NOT reference the filename/extension/file_type/VBA
	// externals (the rename/type signal is encoded IN the marker string, not read
	// from a var). Passing the attachment externals would force the expensive
	// per-scan yara.Scanner (DefineVariable) path; with zero scanVars the marker
	// scan takes the cheap rules.ScanMem path with compile-time defaults. Real
	// content streams keep the externals (a name/type-keyed rule must still fire).
	vars := scanVars{vba: isVBA, filename: x.meta.Filename, extension: x.meta.Extension, fileType: x.meta.FileType}
	if markerChannel {
		vars = scanVars{}
	}
	m, serr := x.s.scanOne(streamRules, stream, vars, budget)
	if serr != nil {
		x.completionErr = serr
		// This stream went unscanned, so the verdict is partial whatever the
		// clock says: libyara takes whole seconds, so a native timeout can
		// fire while the shared deadline has not passed yet.
		x.incomplete = true
		x.s.logf("scan of extracted stream failed (raw verdict kept): %v", serr)
		return false
	}
	// Phase 2 marker-channel: real content streams reject marker-tagged hits;
	// the out-of-band Markers channel keeps ONLY marker-tagged hits.
	m = filterMarkerChannel(m, markerChannel)
	// Inline incremental dedup: matchSeen is built once before the stream
	// loop (seeded from raw matches) and updated here, so we never rebuild
	// the map from scratch on each stream — O(N) total vs O(N²) before.
	before := len(x.out)
	for _, mm := range m {
		k := matchKey{namespace: mm.Namespace, rule: mm.Rule}
		if _, dup := x.matchSeen[k]; dup {
			continue
		}
		x.matchSeen[k] = struct{}{}
		x.out = append(x.out, mm)
	}
	// Anything appended is a rule that fired on the extracted stream but NOT
	// on the raw bytes — count it as pre-extraction's payoff.
	if added := len(x.out) - before; added > 0 {
		x.s.exStreamMatches.Add(uint64(added))
	}
	return false
}
