package yarad

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	yara "github.com/hillu/go-yara/v4"

	"github.com/eilandert/rspamd-yarad/internal/extract"
	"github.com/eilandert/rspamd-yarad/internal/feodo"
	"github.com/eilandert/rspamd-yarad/internal/mbazaar"
	"github.com/eilandert/rspamd-yarad/internal/threatfox"
	"github.com/eilandert/rspamd-yarad/internal/urlhaus"
)

// streamDedupKey returns a 16-byte key for the per-stream dedup set inside
// Scanner.Scan. xxhash is non-cryptographic but collision odds across ≤256
// streams of practical size are negligible (~2⁻⁶⁴ per pair), and it is
// orders of magnitude faster than SHA-256 on multi-MB buffers.
// Two independent 64-bit passes (second pass domain-separated with 0x01) give
// a 128-bit key so the map can use a [16]byte array — allocation-free and
// faster than a string key.
func streamDedupKey(b []byte) [16]byte {
	lo := xxhash.Sum64(b)
	d := xxhash.New()
	_, _ = d.Write([]byte{0x01})
	_, _ = d.Write(b)
	hi := d.Sum64()
	var k [16]byte
	binary.LittleEndian.PutUint64(k[0:8], lo)
	binary.LittleEndian.PutUint64(k[8:16], hi)
	return k
}

// Match is one matched YARA rule, reported back to the rspamd plugin. Tags and
// the "meta" map come straight from the rule definition so the plugin can score
// or branch on them without yarad knowing anything rule-specific.
type Match struct {
	Rule string `json:"rule"`
	// Namespace is the libyara namespace the rule was compiled into. yarad
	// compiles each rule file into a namespace named after the file (see
	// compileDir / compile-rules.sh `ns:path`), so this is effectively the
	// source ruleset file (e.g. "sigbase-gen_url.yar") — surfaced so the rspamd
	// plugin can show WHICH ruleset fired, not just the (often generic) rule
	// name. Empty for synthetic matches (URLhaus) that aren't from a rule file.
	Namespace string            `json:"namespace,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// Scanner compiles a set of YARA rules once and scans message bytes against
// them. The compiled *yara.Rules is immutable once built, so reloads build a
// fresh set and swap the pointer atomically — in-flight scans keep using the
// old set until they finish, new scans pick up the new one. No scan ever holds
// a lock for its (potentially slow) duration.
type Scanner struct {
	rules       atomic.Pointer[yara.Rules]
	scanTimeout time.Duration
	logf        func(string, ...any)

	// bigRules is the small, high-signal "big-file" ruleset used by the
	// oversized-buffer cost gate (STAB/BIGFILE). A full-ruleset scan of a multi-MB
	// buffer is inherently unbounded and can time out (fail-open => malware MISSED),
	// so when len(buf) > bigFileThreshold the raw buffer is scanned against THIS set
	// instead of s.rules: it completes fast and the local heuristics still fire.
	// Kept in sync with s.rules on Reload (compiled/loaded the same way). nil when
	// no big-file ruleset is configured, in which case Scan falls back to s.rules
	// for oversized buffers (logged once) rather than disarming.
	bigRules           atomic.Pointer[yara.Rules]
	bigFileThreshold   int64         // >0 enables the gate; len(buf) over this uses bigRules
	bigSrcDir          string        // YARAD_BIGFILE_RULES when it is a directory of sources
	bigSrcFile         string        // YARAD_BIGFILE_RULES when it is a precompiled .yac
	bigNilWarned       atomic.Bool   // log the "bigRules nil, falling back" path once
	bigFileScans       atomic.Uint64 // oversized raw buffers scanned against bigRules
	bigFileStreamScans atomic.Uint64 // oversized extracted streams scanned against bigRules
	rawScanErrs        atomic.Uint64 // raw-scan failures that fell through to extraction instead of aborting
	// Per-channel scanOne counts (PERF-17): which channel each libyara scan ran on,
	// so /metrics shows where scan cost goes. Totals INCLUDE the big-file subset
	// (bigFileScans ⊆ rawChannelScans, bigFileStreamScans ⊆ streamChannelScans).
	rawChannelScans    atomic.Uint64 // raw-body scans (every Scan call that scans the raw buffer)
	streamChannelScans atomic.Uint64 // real-content extracted-stream scans
	markerChannelScans atomic.Uint64 // out-of-band marker-channel scans

	// scanners pools yara.Scanner objects so a scan that overrides external
	// variables (VBA/filename — every macro stream) doesn't allocate and
	// Destroy a fresh Scanner each time. Keyed to the active *yara.Rules: when
	// Reload swaps the rules, pooled scanners bound to the old rules are stale
	// and are Destroyed on return rather than reused. See scannerGen.
	scanners atomic.Pointer[scannerGen]

	mu      sync.Mutex // serializes Reload so two SIGHUPs can't compile at once
	srcDir  string
	srcFile string // precompiled bundle; wins over srcDir when set
	count   atomic.Int64
	fp      atomic.Pointer[string] // ruleset identity fingerprint (namespace+identifier), changes on reload
	// contentFP hashes the loaded ruleset SOURCE bytes (main + big-file set), so a
	// rule body edit that keeps the same namespace+identifier (condition/meta/string
	// change), or a big-file-set-only edit, still changes the verdict cache key. It
	// is deterministic across replicas that loaded the same bundle (unlike an mtime),
	// so the shared Redis L2 stays correctly partitioned without breaking cross-replica
	// cache sharing. Changes on every reload that alters the rule sources.
	contentFP atomic.Pointer[string]

	// Observability for the OLE/OOXML pre-extract path (see ExtractMetrics).
	// Without these the document-extraction code is invisible in /metrics.
	// Uint64 (monotonic counters) so /metrics needs no signed→unsigned cast.
	exDocs, exStreams, exMacroDocs, exFailed, exPanicked, exEncrypted atomic.Uint64
	exMSI                                                             atomic.Uint64 // OLE2 buffers recognised as MSI installers
	exMSG                                                             atomic.Uint64 // OLE2 buffers recognised as Outlook .msg (attachments extracted)
	exOneNote                                                         atomic.Uint64 // buffers recognised as OneNote .one (embedded files carved)
	exArchive                                                         atomic.Uint64 // buffers recognised as an archive (zip/gz/7z/rar/tar; members unpacked)
	exOLEPackage                                                      atomic.Uint64 // OLE2 docs with an embedded OLE Package object (Ole10Native carved)
	exLNK                                                             atomic.Uint64 // Windows shell links (.lnk) with StringData surfaced
	exPDF                                                             atomic.Uint64 // PDFs with FlateDecode object streams inflated
	exRTF                                                             atomic.Uint64 // RTF docs with \objdata embedded objects carved
	exSLK                                                             atomic.Uint64 // SYLK (.slk) spreadsheets with XLM/DDE formulas scanned
	exEncodedScript                                                   atomic.Uint64 // buffers with >=1 decoded MS-Script-Encoder block
	exDecoded                                                         atomic.Uint64 // buffers with >=1 base64/hex/reversed blob from the static decode pass
	exStreamMatches                                                   atomic.Uint64 // distinct rule hits that came ONLY from an extracted stream (not raw bytes)
	exDeduped                                                         atomic.Uint64 // extracted streams skipped as duplicates (content hash matched a prior stream or raw buf)
	exDocProps                                                        atomic.Uint64 // documents with doc-property strings extracted
	exXLMFold                                                         atomic.Uint64 // documents with XLM formula constant-folding applied
	exExtMismatch                                                     atomic.Uint64 // attachments whose real container type contradicts a benign-looking extension (renamed dropper)

	// Rule-reload observability (see ReloadMetrics).
	reloadAttempts, reloadOK, reloadFail atomic.Uint64
	reloadLastUnix, reloadLastMillis     atomic.Int64
	reloadPrevFP                         atomic.Pointer[string] // fingerprint before the last successful reload
	// rulesModUnix is the mtime (unix seconds) of the loaded ruleset on disk:
	// the .yac bundle, or the newest source file in the rules dir. A daily image
	// rebuild refreshes it; if the rebuild silently breaks (fetch failed, image
	// not redeployed), this stops advancing and the rules-age metric/staleness
	// check catches it. 0 if the mtime could not be stat'd.
	rulesModUnix atomic.Int64

	// Optional abuse.ch URLhaus malware-URL lookup (nil when no Auth-Key set).
	urlhaus    *urlhaus.Checker
	urlhausMax int

	// effortMax is the operator's effort ceiling (cfg.EffortMax), used to resolve
	// a scan's per-request cap profile from meta.Effort (EFFORT-4).
	effortMax int

	// Optional abuse.ch MalwareBazaar attachment-hash lookup (nil when no key).
	mbazaar *mbazaar.Checker

	// Optional abuse.ch ThreatFox IOC lookup (nil when no Auth-Key set).
	threatfox    *threatfox.Checker
	threatfoxMax int

	// Optional abuse.ch Feodo Tracker IP blocklist (nil when not enabled).
	feodo *feodo.Checker

	// canary, when true, tags every surviving match with yarad_canary=1 so the
	// rspamd plugin routes them all to weight-0 (shadow/observe-only mode).
	canary bool

	// denylist holds rule names (lowercase) whose matches are dropped from every
	// result — public-ruleset demo/noise rules (e.g. Didier's `http`) that are
	// pure false positives for mail. nil/empty means no filtering. Accessed via
	// atomic pointer so ReloadDenylist (SIGHUP) can swap it while scans run.
	denylist atomic.Pointer[map[string]struct{}]
	// baseDenylist is the immutable env-parsed denylist, preserved so file-based
	// additions (ReloadDenylist) can merge on top without losing env entries.
	baseDenylist map[string]struct{}
	// denylistFile is the path to a file of additional deny rules (one per line).
	// Empty means no file. Re-read on SIGHUP via ReloadDenylist.
	denylistFile string
	// allowlist holds rule names (lowercase) whose matches are KEPT but tagged
	// `yarad_allow=1` so the plugin scores them log-only (0 weight). Lets an
	// operator demote a known-FP rule without dropping its visibility or patching
	// the source. nil/empty means no tagging. Denylist wins if a name is in both.
	allowlist map[string]struct{}

	// topMatches counts rule hits since the last reload for /version observability.
	topMatches *matchCounter
}

// scannerGen is a bounded free-list of yara.Scanner objects bound to one
// *yara.Rules. A yara.Scanner holds C memory that MUST be Destroy()ed and is
// bound to the rules it was built from, so when Reload swaps the rules every
// idle scanner becomes stale. We use an explicit mutex-guarded free-list (NOT a
// sync.Pool) precisely so a generation can be DRAINED — sync.Pool drops its
// contents to the GC without any finalizer, which would leak the C-allocated
// scanners on every reload. getScanner installs a fresh generation when the
// rules change and destroys the retired generation's idle scanners; putScanner
// returns a scanner to its generation only if that generation is still live,
// else destroys it.
type scannerGen struct {
	rules *yara.Rules
	mu    sync.Mutex
	free  []*yara.Scanner
}

// maxPooledScanners caps idle scanners kept per generation. Concurrency is
// already bounded by the scan-CPU gate, so a handful covers steady state; extra
// returns are destroyed rather than hoarded.
const maxPooledScanners = 32

// get pops an idle scanner or returns nil if the free-list is empty.
func (g *scannerGen) get() *yara.Scanner {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n := len(g.free); n > 0 {
		sc := g.free[n-1]
		g.free[n-1] = nil
		g.free = g.free[:n-1]
		return sc
	}
	return nil
}

// put returns a scanner to the free-list, or reports false if the list is full
// (caller destroys it).
func (g *scannerGen) put(sc *yara.Scanner) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.free) >= maxPooledScanners {
		return false
	}
	g.free = append(g.free, sc)
	return true
}

// drain removes and returns all idle scanners so the caller can Destroy them
// when the generation is retired.
func (g *scannerGen) drain() []*yara.Scanner {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.free
	g.free = nil
	return out
}

// getScanner returns a yara.Scanner bound to rules, reusing a pooled one when
// possible. The caller MUST hand it back via putScanner. gen is returned so
// putScanner can verify the scanner still belongs to the live generation.
func (s *Scanner) getScanner(rules *yara.Rules) (*yara.Scanner, *scannerGen, error) {
	gen := s.scanners.Load()
	if gen == nil || gen.rules != rules {
		// First use, or rules changed under us (post-Reload): retire the old
		// generation (destroy its idle scanners so the C memory is freed, not
		// leaked) and install a fresh one for the current rules. A benign race
		// where two goroutines both install just means one extra empty gen.
		old := gen
		gen = &scannerGen{rules: rules}
		s.scanners.Store(gen)
		if old != nil {
			for _, sc := range old.drain() {
				sc.Destroy()
			}
		}
	}
	if sc := gen.get(); sc != nil {
		return sc, gen, nil
	}
	sc, err := yara.NewScanner(rules)
	if err != nil {
		return nil, nil, err
	}
	return sc, gen, nil
}

// putScanner returns sc to its generation's free-list, or Destroys it if the
// generation is no longer current (a Reload happened) or the list is full, so a
// scanner bound to stale rules is never reused and idle scanners stay bounded.
func (s *Scanner) putScanner(sc *yara.Scanner, gen *scannerGen) {
	if sc == nil || gen == nil {
		return
	}
	if s.scanners.Load() == gen && gen.put(sc) {
		return
	}
	sc.Destroy()
}

// ExtractMetrics is a snapshot of the document pre-extraction counters, surfaced
// on /metrics so the new code path is observable: how many attachments were
// OLE/OOXML, how many carried macros, how often the parser failed/panicked, and
// how many were encrypted (and thus not decryptable here).
type ExtractMetrics struct {
	Docs       uint64 // buffers recognised as an OLE2/OOXML container
	Streams    uint64 // decompressed macro blobs scanned (sum across docs)
	MacroDocs  uint64 // documents that yielded >=1 macro stream
	Failed     uint64 // container parse attempts that errored
	Panicked   uint64 // parser panics recovered (subset of Failed)
	Encrypted  uint64 // ECMA-376 encrypted OOXML (not decrypted)
	MSI        uint64 // OLE2 buffers recognised as MSI installers (streams dumped)
	MSG        uint64 // OLE2 buffers recognised as Outlook .msg (attachments extracted)
	OneNote    uint64 // buffers recognised as OneNote .one (embedded files carved)
	Archive    uint64 // buffers recognised as an archive (zip/gz/7z/rar/tar; members unpacked)
	OLEPackage uint64 // OLE2 docs with an embedded OLE Package object (Ole10Native carved)
	LNK        uint64 // Windows shell links (.lnk) with StringData surfaced
	PDF        uint64 // PDFs with FlateDecode object streams inflated
	RTF        uint64 // RTF docs with \objdata embedded objects carved
	SLK        uint64 // SYLK (.slk) spreadsheets with XLM/DDE formulas scanned
	EncScript  uint64 // buffers with >=1 decoded MS-Script-Encoder (VBE/JSE) block
	Decoded    uint64 // buffers with >=1 base64/hex/reversed blob from the static decode pass
	// StreamMatches counts rule hits attributable ONLY to an extracted stream
	// (macro/MSI/VBE), i.e. rules that did NOT already fire on the raw bytes —
	// the direct measure of what pre-extraction adds over a raw-only scan.
	StreamMatches uint64
	// Deduped counts extracted streams skipped before YARA scanning because their
	// SHA256 matched a previously scanned stream (or the raw input buffer itself).
	Deduped     uint64
	DocProps    uint64 // documents with doc-property strings extracted
	XLMFold     uint64 // documents with XLM formula constant-folding applied
	ExtMismatch uint64 // attachments whose real container type contradicts a benign-looking extension (renamed dropper)
}

// ExtractMetrics returns the current pre-extraction counters.
func (s *Scanner) ExtractMetrics() ExtractMetrics {
	return ExtractMetrics{
		Docs:          s.exDocs.Load(),
		Streams:       s.exStreams.Load(),
		MacroDocs:     s.exMacroDocs.Load(),
		Failed:        s.exFailed.Load(),
		Panicked:      s.exPanicked.Load(),
		Encrypted:     s.exEncrypted.Load(),
		MSI:           s.exMSI.Load(),
		MSG:           s.exMSG.Load(),
		OneNote:       s.exOneNote.Load(),
		Archive:       s.exArchive.Load(),
		OLEPackage:    s.exOLEPackage.Load(),
		LNK:           s.exLNK.Load(),
		PDF:           s.exPDF.Load(),
		RTF:           s.exRTF.Load(),
		SLK:           s.exSLK.Load(),
		EncScript:     s.exEncodedScript.Load(),
		Decoded:       s.exDecoded.Load(),
		StreamMatches: s.exStreamMatches.Load(),
		Deduped:       s.exDeduped.Load(),
		DocProps:      s.exDocProps.Load(),
		XLMFold:       s.exXLMFold.Load(),
		ExtMismatch:   s.exExtMismatch.Load(),
	}
}

// NewScanner builds a scanner and performs the initial compile/load. It returns
// an error only when no rules at all could be loaded — a service with zero
// rules is a misconfiguration the operator must see at startup, not a silent
// "everything is clean".
func NewScanner(cfg *Config, logf func(string, ...any)) (*Scanner, error) {
	s := &Scanner{
		scanTimeout:      cfg.ScanTimeout,
		bigFileThreshold: cfg.BigFileThreshold,
		logf:             logf,
		srcDir:           cfg.RulesDir,
		srcFile:          cfg.RulesPath,
		urlhaus:          urlhaus.New(cfg.URLhausKey, cfg.URLhausRefresh, cfg.CacheDir, logf), // nil if no key
		urlhausMax:       cfg.URLhausMaxURLs,
		effortMax:        cfg.EffortMax,
		mbazaar:          mbazaar.New(cfg.MBazaarKey, cfg.MBazaarRefresh, cfg.MBazaarFeed, cfg.CacheDir, logf), // nil if no key
		threatfox:        threatfox.New(cfg.ThreatFoxKey, cfg.ThreatFoxRefresh, cfg.CacheDir, logf),            // nil if no key
		threatfoxMax:     cfg.ThreatFoxMaxURLs,
		feodo:            feodo.New(cfg.FeodoEnabled, cfg.URLhausKey, cfg.FeodoRefresh, cfg.CacheDir, logf), // nil if not enabled
		canary:           cfg.Canary,
		baseDenylist:     cfg.RuleDenylist,
		denylistFile:     cfg.DenylistFile,
		allowlist:        cfg.RuleAllowlist,
		topMatches:       newMatchCounter(matchCounterCap),
	}
	// Resolve the big-file ruleset path into a precompiled .yac (load) or a source
	// dir (compile), so Reload can build it the same way it builds the main set.
	// A path that doesn't exist is treated as "unset" — the gate then falls back to
	// the full ruleset for oversized buffers rather than failing startup.
	if cfg.BigFileThreshold > 0 && cfg.BigFileRules != "" {
		if fi, err := os.Stat(cfg.BigFileRules); err == nil {
			if fi.IsDir() {
				s.bigSrcDir = cfg.BigFileRules
			} else {
				s.bigSrcFile = cfg.BigFileRules
			}
		} else {
			logf("WARNING: YARAD_BIGFILE_RULES=%s not found: %v (oversized-buffer gate will fall back to the full ruleset)", cfg.BigFileRules, err)
		}
	}
	s.denylist.Store(&cfg.RuleDenylist)
	if s.urlhaus != nil {
		logf("URLhaus malware-URL lookup enabled (refresh=%s, max_urls/msg=%d)", cfg.URLhausRefresh, cfg.URLhausMaxURLs)
	}
	if s.mbazaar != nil {
		logf("MalwareBazaar attachment-hash lookup enabled (refresh=%s)", cfg.MBazaarRefresh)
	}
	if s.threatfox != nil {
		logf("ThreatFox IOC lookup enabled (refresh=%s, max_urls/msg=%d)", cfg.ThreatFoxRefresh, cfg.ThreatFoxMaxURLs)
	}
	if s.feodo != nil {
		logf("Feodo Tracker IP blocklist enabled (refresh=%s)", cfg.FeodoRefresh)
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	s.ReloadDenylist()
	return s, nil
}

// RuleCount reports how many rules are in the active set (for /health and logs).
func (s *Scanner) RuleCount() int64 { return s.count.Load() }

// BigFileScans reports how many oversized buffers were scanned against the
// big-file (targeted) ruleset instead of the full set (BIGFILE gate). Surfaced on
// /metrics so the gate's firing rate is observable.
func (s *Scanner) BigFileScans() uint64 { return s.bigFileScans.Load() }

// BigFileStreamScans reports how many oversized EXTRACTED streams (archive/decode/
// PDF/RTF/TNEF/VBA children over the threshold) were scanned against the big-file
// ruleset instead of the full set. Without this, a small raw container that
// expands into multi-MiB children could still spend the full-rules path on every
// child and exhaust the shared budget even though the raw body was protected.
// Surfaced on /metrics so the extracted-stream gate's firing rate is observable.
func (s *Scanner) BigFileStreamScans() uint64 { return s.bigFileStreamScans.Load() }

// RawChannelScans, StreamChannelScans, and MarkerChannelScans report the number of
// libyara scans run on each channel (PERF-17): the raw body, real-content extracted
// streams, and the out-of-band marker channel. Surfaced on /metrics so an operator
// can see where scan cost goes — e.g. a container family that fans out into many
// streams shows a high stream:raw ratio. Totals include the big-file subset (a
// big-file-routed scan still counts on its channel), so bigfile_*_scans_total is a
// breakdown WITHIN these, not a separate bucket.
func (s *Scanner) RawChannelScans() uint64    { return s.rawChannelScans.Load() }
func (s *Scanner) StreamChannelScans() uint64 { return s.streamChannelScans.Load() }
func (s *Scanner) MarkerChannelScans() uint64 { return s.markerChannelScans.Load() }

// RawScanErrs reports how many raw scans failed (timeout/libyara error) and fell
// through to extraction instead of aborting the request. Surfaced on /metrics so
// the fail-open-recovery path is observable.
func (s *Scanner) RawScanErrs() uint64 { return s.rawScanErrs.Load() }

// ReloadMetrics is a snapshot of rule-reload activity, surfaced on /metrics so a
// SIGHUP that silently fails (e.g. a bad rule edit) is visible to alerting
// instead of only appearing in logs.
type ReloadMetrics struct {
	Attempts        uint64 // Reload() calls (includes the initial boot load)
	Successes       uint64
	Failures        uint64
	LastUnix        int64  // unix seconds of the last successful reload
	LastMillis      int64  // wall-clock duration of the last reload attempt
	Rules           int64  // rule count after the last successful reload
	ModUnix         int64  // mtime (unix seconds) of the loaded ruleset on disk; 0 if unknown
	PrevFingerprint string // fingerprint before the last reload ("" on first load)
}

// ReloadMetrics returns the current reload counters.
func (s *Scanner) ReloadMetrics() ReloadMetrics {
	prev := ""
	if p := s.reloadPrevFP.Load(); p != nil {
		prev = *p
	}
	return ReloadMetrics{
		Attempts:        s.reloadAttempts.Load(),
		Successes:       s.reloadOK.Load(),
		Failures:        s.reloadFail.Load(),
		LastUnix:        s.reloadLastUnix.Load(),
		LastMillis:      s.reloadLastMillis.Load(),
		Rules:           s.count.Load(),
		ModUnix:         s.rulesModUnix.Load(),
		PrevFingerprint: prev,
	}
}

// Reload (re)compiles the rule set and atomically swaps it in. A failure leaves
// the previous set active — a broken edit to the rules dir must never disarm a
// running scanner. Safe to call from a SIGHUP handler concurrently with scans.
func (s *Scanner) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reloadAttempts.Add(1)
	start := time.Now()
	defer func() { s.reloadLastMillis.Store(time.Since(start).Milliseconds()) }()

	var (
		rules *yara.Rules
		err   error
	)
	if s.srcFile != "" {
		rules, err = yara.LoadRules(s.srcFile)
	} else {
		rules, err = compileDir(s.srcDir, s.logf)
	}
	if err != nil {
		s.reloadFail.Add(1)
		s.logf("ERROR reload failed, keeping previous rules: %v", err)
		return err
	}

	list := rules.GetRules()
	s.rules.Swap(rules)
	s.count.Store(int64(len(list)))
	fp := fingerprint(list)
	if old := s.fp.Load(); old != nil {
		s.reloadPrevFP.Store(old)
	}
	s.fp.Store(&fp)
	s.reloadOK.Add(1)
	s.reloadLastUnix.Store(time.Now().Unix())
	// Record the on-disk mtime of what we just loaded so staleness (a silently
	// broken daily rebuild) is observable. Best-effort: 0 if it can't be stat'd.
	s.rulesModUnix.Store(rulesetModUnix(s.srcFile, s.srcDir))
	// The previous *yara.Rules is intentionally NOT Destroy()ed here: an in-flight
	// scan may still hold the pointer it loaded before the swap, and freeing the
	// native rules under it would crash. go-yara registers a runtime finalizer on
	// *Rules (via runtime.SetFinalizer in Compile/GetRules), so the old set is
	// freed by the GC once no goroutine references it. Reloads are infrequent, so
	// finalizer-driven cleanup is the safe choice over manual/refcounted retire.
	src := s.srcDir
	if s.srcFile != "" {
		src = s.srcFile
	}
	s.logf("loaded %d YARA rules from %s (fp=%s)", s.count.Load(), src, fp)

	// Big-file (oversized-buffer) ruleset: compiled/loaded the SAME way as the main
	// set and swapped in atomically so it stays in sync on every reload/SIGHUP. A
	// failure here must NOT fail the reload — the main set is the trust anchor; the
	// gate simply falls back to the full ruleset (logged) until the next good load.
	if s.bigSrcFile != "" || s.bigSrcDir != "" {
		var (
			big    *yara.Rules
			bigErr error
		)
		if s.bigSrcFile != "" {
			big, bigErr = yara.LoadRules(s.bigSrcFile)
		} else {
			big, bigErr = compileDir(s.bigSrcDir, s.logf)
		}
		if bigErr != nil {
			s.logf("WARNING: big-file ruleset reload failed, keeping previous (oversized-buffer gate may fall back to full set): %v", bigErr)
		} else {
			bigSrc := s.bigSrcDir
			if s.bigSrcFile != "" {
				bigSrc = s.bigSrcFile
			}
			s.bigRules.Swap(big)
			s.logf("loaded %d big-file YARA rules from %s (oversized-buffer gate, threshold=%dB)", len(big.GetRules()), bigSrc, s.bigFileThreshold)
		}
	}

	// Fold a content hash of the loaded ruleset SOURCE (main + big-file set) into the
	// fingerprint. Identity (namespace+identifier) alone cannot see a condition/meta/
	// string edit that reuses the same rule name, nor a big-file-set-only change, so
	// without this an edited-but-same-named rule would keep its old verdict-cache key
	// and serve stale verdicts (especially the shared Redis L2) until TTL. Computed
	// from source bytes so it is identical across replicas that loaded the same bundle.
	ch := rulesetContentHash(s.srcFile, s.srcDir, s.bigSrcFile, s.bigSrcDir)
	s.contentFP.Store(&ch)

	// Reset the top-matches counter so counts reflect the current rule set only,
	// not a mix of old and new rule names that may have been renamed/removed.
	s.topMatches.Reset()
	return nil
}

// Fingerprint returns a short hash identifying the active rule set, prefixed
// with the extractor version. It is part of the verdict cache key, so a reload
// that changes the rules changes the fingerprint and old cached verdicts
// (in-process L1 and shared Redis L2) are no longer hit — they orphan and
// TTL-expire instead of serving a stale "clean". The extract.Version prefix
// folds the pre-extraction logic into that same invalidation: a verdict is now
// a function of BOTH the rules and how macros were decompressed, so an extractor
// bump must invalidate the cache (especially the Redis L2 that survives an image
// rebuild) exactly like a rule change does.
func (s *Scanner) Fingerprint() string {
	fp := ""
	if p := s.fp.Load(); p != nil {
		fp = *p
	}
	ch := ""
	if p := s.contentFP.Load(); p != nil {
		ch = *p
	}
	return extract.Version + ":" + fp + ":" + ch
}

// fingerprint hashes the sorted rule identities (namespace + identifier) so the
// same compiled rule set always yields the same value across processes/replicas,
// and any add/remove/rename changes it.
func fingerprint(rules []yara.Rule) string {
	ids := make([]string, 0, len(rules))
	for i := range rules {
		ids = append(ids, rules[i].Namespace()+"/"+rules[i].Identifier())
	}
	sort.Strings(ids)
	h := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return hex.EncodeToString(h[:8]) // 16 hex chars is plenty to distinguish rule sets
}

// rulesetContentHash returns a deterministic hash of the loaded ruleset SOURCE
// bytes — the precompiled bundle file(s) when set, otherwise the *.yar/*.yara
// sources in the rules dir(s). Main set and big-file set are both folded in (in a
// fixed order) so a body edit reusing a rule name, OR a big-file-set-only edit,
// changes the value. It is a pure function of the source bytes, so two replicas
// that loaded the same bundle produce the same hash (an mtime would not) — keeping
// the shared verdict cache correctly partitioned without breaking cross-replica
// sharing. Best-effort: an unreadable source contributes nothing rather than
// failing the reload; identity fingerprint + extract.Version still guard the key.
func rulesetContentHash(srcFile, srcDir, bigSrcFile, bigSrcDir string) string {
	h := sha256.New()
	addSource(h, srcFile, srcDir)
	_, _ = h.Write([]byte("\x00big\x00"))
	addSource(h, bigSrcFile, bigSrcDir)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// addSource feeds one ruleset's source bytes into h: the bundle file when set,
// else every *.yar/*.yara file in dir read in sorted-name order (deterministic
// regardless of directory iteration order). Each chunk is length-prefixed so two
// different file boundaries can't hash to the same stream.
func addSource(h hash.Hash, file, dir string) {
	writeChunk := func(name string, b []byte) {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(name)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(name))
		binary.LittleEndian.PutUint64(n[:], uint64(len(b)))
		_, _ = h.Write(n[:])
		_, _ = h.Write(b)
	}
	if file != "" {
		if b, err := os.ReadFile(file); err == nil { // #nosec G304 -- operator-configured rules path, not attacker input
			writeChunk(filepath.Base(file), b)
		}
		return
	}
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".yar", ".yara", ".yac":
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil { // #nosec G304 -- operator-configured rules dir, not attacker input
			writeChunk(name, b)
		}
	}
}

// rulesetModUnix returns the mtime (unix seconds) of the loaded ruleset: the
// precompiled bundle file when one is set, otherwise the NEWEST *.yar/*.yara
// source file in the rules dir (the freshest rule is what matters for staleness;
// an unchanged old file alongside a fresh one shouldn't make the set look old).
// Best-effort — returns 0 if nothing can be stat'd, so callers treat 0 as
// "age unknown" and never falsely report a stale set.
func rulesetModUnix(srcFile, srcDir string) int64 {
	if srcFile != "" {
		if fi, err := os.Stat(srcFile); err == nil {
			return fi.ModTime().Unix()
		}
		return 0
	}
	var newest int64
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yar") && !strings.HasSuffix(name, ".yara") {
			continue
		}
		fi, err := os.Stat(filepath.Join(srcDir, e.Name()))
		if err != nil {
			continue
		}
		if m := fi.ModTime().Unix(); m > newest {
			newest = m
		}
	}
	return newest
}

// compileDir compiles every *.yar / *.yara file under dir into one rule set.
// Files are added by namespace = their base name so identically named rules in
// different files don't collide.
//
// Public rulesets (YARA-Forge, signature-base, ANY.RUN) inevitably contain a
// few files this build can't compile: a rule importing a module we didn't build
// in (cuckoo, magic), or a syntax the linked libyara version rejects. One such
// file must NOT disarm the whole scanner, so each file is validated in a
// throwaway compiler first and only added to the real set if it compiles
// clean; bad files are logged and skipped. It is an error only if NOTHING
// compiles (a misconfigured rules dir, not a single rotten rule).
func compileDir(dir string, logf func(string, ...any)) (*yara.Rules, error) {
	var files []string
	for _, ext := range []string{"*.yar", "*.yara"} {
		m, _ := filepath.Glob(filepath.Join(dir, ext))
		files = append(files, m...)
	}
	sort.Strings(files) // deterministic namespace ordering
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.yar/*.yara files in %s", dir)
	}

	c, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("new compiler: %w", err)
	}
	defineExternals(c)
	added, skipped := 0, 0
	for _, f := range files {
		if compileErr := fileCompiles(f); compileErr != nil {
			skipped++
			logf("skip unparseable rule file %s: %v", filepath.Base(f), compileErr)
			continue
		}
		fh, err := os.Open(f) // #nosec G304 -- operator rules dir, not attacker input
		if err != nil {
			logf("skip unreadable rule file %s: %v", filepath.Base(f), err)
			skipped++
			continue
		}
		err = c.AddFile(fh, filepath.Base(f))
		_ = fh.Close()
		if err != nil {
			// Should be rare: fileCompiles already validated it in isolation.
			logf("skip rule file %s (rejected by shared compiler): %v", filepath.Base(f), err)
			skipped++
			continue
		}
		added++
	}
	if added == 0 {
		return nil, fmt.Errorf("no compilable *.yar/*.yara files in %s (%d skipped)", dir, skipped)
	}
	rules, err := c.GetRules()
	if err != nil {
		return nil, fmt.Errorf("get rules: %w", err)
	}
	if skipped > 0 {
		logf("compiled %d rule files, skipped %d unparseable", added, skipped)
	}
	return rules, nil
}

// fileCompiles validates one rule file in an isolated compiler so a single bad
// file (unknown module, bad syntax) can be skipped without poisoning the shared
// compiler the rest of the set is built in.
func fileCompiles(path string) error {
	c, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	defer c.Destroy()
	defineExternals(c)
	fh, err := os.Open(path) // #nosec G304 -- operator rules dir, not attacker input
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := c.AddFile(fh, filepath.Base(path)); err != nil {
		return err
	}
	_, err = c.GetRules()
	return err
}

// defineExternals declares the external variables that common public rulesets
// reference, so files using them COMPILE instead of being skipped:
//   - filename/extension — THOR/Loki (signature-base); empty defaults here so the
//     files compile, but Scan now OVERRIDES them per request from the attachment
//     name (see ScanMeta/scanVars), so name-keyed rules actually fire instead of
//     always seeing "".
//   - filepath/filetype/owner — also THOR/Loki; kept as empty defaults (yarad has
//     no real path / magic-type / file owner for a mail attachment), so their
//     conditions stay inert.
//   - file_type — InQuest uses this name for coarse file-type context. It stays
//     empty except for extension-derived types where we have a tight mail use
//     case (currently `.msg`/`.oft` => "outlook").
//   - VBA — Didier's vba.yara (`VBA and any of (...)`); default false so the rule
//     is inert on raw bytes, and Scan flips it true ONLY for decompressed macro
//     streams (see scanOne). This must mirror compile-rules.sh's yarac `-d` flags
//     so the precompiled .yac and this in-process path behave identically.
func defineExternals(c *yara.Compiler) {
	_ = c.DefineVariable("VBA", false)
	for _, v := range []string{"filename", "filepath", "extension", "filetype", "file_type", "owner"} {
		_ = c.DefineVariable(v, "")
	}
}

// ScanMeta carries the per-message context the rspamd plugin knows but the raw
// bytes don't — the attachment filename — mapped onto YARA external variables
// (`filename`/`extension`, plus a narrow `file_type` hint for .msg/.oft) so
// name/type-keyed rules fire. The zero value leaves externals at their
// compile-time defaults, so a whole-rfc822 scan or unnamed part behaves as
// before.
type ScanMeta struct {
	Filename  string // sanitized basename, e.g. "invoice.exe" ("" if none)
	Extension string // lowercased extension WITH the leading dot, e.g. ".exe" (Loki/THOR convention); "" if none
	FileType  string // coarse optional type context for rules that use file_type, e.g. "outlook" for .msg/.oft
	// Effort is the resolved effort-tier level (1..EffortMax) for this scan
	// (EFFORT-1). It rides on ScanMeta so it is automatically part of the
	// verdict-cache key (see cacheKey) — the same bytes scanned at different
	// effort can yield different verdicts and must not share a cached one. Zero
	// means "unset" (legacy callers / internal scans); cacheKey treats 0 and the
	// resolved default identically only when both produce the same key string, so
	// resolution always fills a concrete level before Scan.
	Effort int
}

// cacheKey renders the metadata for the verdict cache key. The verdict depends on
// these externals, so two scans of the same bytes with different metadata must
// land on different keys. Extension derives from Filename but is included so the
// key is explicit. NUL separator can't occur in either (NewScanMeta strips it).
func (m ScanMeta) cacheKey() string {
	return m.Filename + "\x00" + m.Extension + "\x00" + m.FileType + "\x00" + strconv.Itoa(m.Effort)
}

// maxFilenameLen caps the attacker-controlled attachment name fed to libyara —
// a hostile multi-kilobyte name must not bloat the cache key or the per-scan
// variable. 255 is the usual filesystem basename limit.
const maxFilenameLen = 255

// NewScanMeta normalizes a raw (attacker-controlled) attachment name into the
// external-variable values: basename only (any path stripped), control bytes
// removed, length-capped, and the extension lowercased WITH its leading dot to
// match the Loki/THOR `extension == ".exe"` convention. A blank/garbage name
// yields the zero ScanMeta so the externals keep their empty defaults.
func NewScanMeta(name string) ScanMeta {
	// Basename: drop anything up to the last path separator (either slash —
	// names can arrive from a Windows or *nix sender).
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	// Strip control characters (incl. CR/LF/NUL) so the value can't carry HTTP/log
	// injection through into the variable, and trim surrounding space.
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if len(name) > maxFilenameLen {
		name = name[:maxFilenameLen]
	}
	if name == "" {
		return ScanMeta{}
	}
	// Extension = lowercased text from the last dot to end, dot included. A
	// leading-dot name (".bashrc") or a trailing dot ("foo.") has no extension.
	ext := ""
	if i := strings.LastIndexByte(name, '.'); i > 0 && i < len(name)-1 {
		ext = strings.ToLower(name[i:])
	}
	return ScanMeta{Filename: name, Extension: ext, FileType: fileTypeFromExtension(ext)}
}

func fileTypeFromExtension(ext string) string {
	switch ext {
	case ".msg", ".oft":
		return "outlook"
	default:
		return ""
	}
}

// scanVars is the set of external-variable overrides applied on top of the
// compile-time defaults for one scanOne call. filename/extension/file_type come
// from the attachment (ScanMeta); vba is flipped true only for a decompressed
// macro stream. When all fields are zero the cheap rules.ScanMem path is used.
type scanVars struct {
	vba       bool
	filename  string
	extension string
	fileType  string
}

// needsScanner reports whether any external variable must be overridden — i.e.
// whether the per-scan yara.Scanner (which can DefineVariable) is required
// instead of the cheaper rules.ScanMem that uses only compile-time defaults.
func (v scanVars) needsScanner() bool {
	return v.vba || v.filename != "" || v.extension != "" || v.fileType != ""
}

// define applies the overrides to a scanner. EVERY external is set on every
// call (string ones to "" when absent), never conditionally: a pooled scanner
// is reused across scans, so a value left undefined would leak the previous
// scan's value. Setting "" reproduces the compile-time empty default.
func (v scanVars) define(sc *yara.Scanner) error {
	if err := sc.DefineVariable("VBA", v.vba); err != nil {
		return err
	}
	if err := sc.DefineVariable("filename", v.filename); err != nil {
		return err
	}
	if err := sc.DefineVariable("extension", v.extension); err != nil {
		return err
	}
	if err := sc.DefineVariable("file_type", v.fileType); err != nil {
		return err
	}
	return nil
}

// Scan runs the active rule set over buf and returns the matched rules. It is
// safe for concurrent use. A scan failure (timeout, libyara error) returns the
// error; the server treats that as "no match" but logs it, so a scanner problem
// never blocks mail (fail-open, matching the gozer contract).
//
// meta carries the attachment filename (if the plugin sent one): it is mapped to
// the `filename`/`extension`/`file_type` external variables for BOTH the raw scan
// and every extracted macro-stream scan, so name/type-keyed rules fire
// consistently on a document and its decompressed macros.
//
// Beyond the raw bytes, Scan also matches against any plaintext hidden inside an
// OLE2/OOXML container — the decompressed VBA macro source — which the keyword
// rules cannot see in the compressed original. The raw bytes are scanned first
// (file-format/structural rules need them); each extracted macro stream is then
// scanned and its matches merged in. Extraction is best-effort and fail-open:
// for a non-document, or on any extract/sub-scan failure, the raw verdict stands
// and nothing is lost.
func (s *Scanner) Scan(buf []byte, digest [32]byte, meta ScanMeta) ([]Match, error) {
	rules := s.rules.Load()
	if rules == nil {
		return nil, fmt.Errorf("no rules loaded")
	}
	// One wall-clock budget for the WHOLE request (raw + every extracted stream),
	// not per-scan: a hostile document with up to maxStreams macro modules must
	// not be able to spend scanTimeout × N and monopolize a worker far past the
	// rspamd/backend timeout. A zero/negative scanTimeout means "no limit" (yara
	// convention), so the deadline is disabled then.
	// EFFORT-4: resolve the per-request cap profile from the effort level the
	// server folded into meta (header ?? auto ?? env, already clamped to the
	// ceiling). The HTTP path always sets meta.Effort >= 1 (ResolveEffortLevel);
	// any caller that did NOT resolve effort (the `yarad scan` CLI, a direct
	// internal Scan with a bare ScanMeta) leaves it at 0 — treat that as "run at
	// the configured ceiling", NOT as level 1, so an un-resolved scan keeps full
	// depth rather than silently degrading to the cheapest tier. The profile
	// drives the MSD decode depth and PDF indicator pass (via extract.Options
	// below), whether the external reputation feeds run (gated near the end), and
	// the per-request libyara wall-clock budget (EFFORT-4-SCANTIMEOUT: scaled
	// 50%→100% of the base across the effort range to shed CPU under load).
	profile := EffortProfileFor(resolveScanEffort(meta.Effort, s.effortMax), s.effortMax, s.scanTimeout)

	// One wall-clock budget for the WHOLE request (raw + every extracted stream),
	// not per-scan: a hostile document with up to maxStreams macro modules must
	// not be able to spend scanTimeout × N and monopolize a worker far past the
	// rspamd/backend timeout. A zero/negative scanTimeout means "no limit" (yara
	// convention), so the deadline is disabled then.
	var deadline time.Time
	if profile.ScanTimeout > 0 {
		deadline = time.Now().Add(profile.ScanTimeout)
	}

	// Oversized-buffer cost gate (BIGFILE): a full-ruleset scan of a multi-MB
	// buffer is inherently unbounded (size × ~12k rules) and can time out even at a
	// large ScanTimeout, after which the scanner fail-opens and a padded dropper is
	// MISSED. When the buffer is over the threshold, scan the RAW bytes against the
	// small high-signal big-file ruleset instead, so the scan completes fast and the
	// local heuristics still fire. The trade is deliberate: we give up public-feed
	// coverage on oversized inputs to GUARANTEE completion + local-rule coverage.
	// If no big-file ruleset is loaded (misconfig / absent local.yac) we fall back
	// to the full set rather than disarm — logged once so it's visible, never fatal.
	rawRules := rules
	if s.bigFileThreshold > 0 && int64(len(buf)) > s.bigFileThreshold {
		if big := s.bigRules.Load(); big != nil {
			rawRules = big
			s.bigFileScans.Add(1)
			s.logf("oversized buffer (%dB > %dB threshold): scanning against big-file ruleset instead of full set", len(buf), s.bigFileThreshold)
		} else if s.bigNilWarned.CompareAndSwap(false, true) {
			s.logf("WARNING: oversized buffer (%dB) but no big-file ruleset loaded; using full set (may time out)", len(buf))
		}
	}

	// Raw bytes first. A failure here is the scanner's verdict (propagated,
	// fail-open at the server) — unchanged behaviour for non-documents. Over the
	// big-file threshold, rawRules is the targeted set (see the gate above);
	// otherwise it is the full set.
	s.rawChannelScans.Add(1)
	out, rawErr := s.scanOne(rawRules, buf, scanVars{filename: meta.Filename, extension: meta.Extension, fileType: meta.FileType}, profile.ScanTimeout)
	// A raw-scan failure (timeout on a pathologically slow buffer, or a libyara
	// error) must NOT short-circuit extraction: a hostile outer container can be
	// engineered to blow the raw-scan budget while hiding a clear-signal dropper
	// in a macro/embedded stream, and returning here would fail open and miss it.
	// Instead drop the (absent) raw matches and continue to extraction + the
	// reputation feeds below; the extracted streams are small and fast and run
	// under whatever deadline remains (each scanExtracted short-circuits when the
	// shared budget is gone, so this can never spend more wall-clock). If nothing
	// is recovered downstream the original error is returned at the end, so the
	// non-document fail-open contract is unchanged.
	if rawErr != nil {
		s.rawScanErrs.Add(1)
		s.logf("raw scan failed (%v); continuing to extraction so hidden streams are not missed", rawErr)
		out = nil
	}
	// Phase 2 marker-channel: a PURE-marker rule must NOT fire on raw bytes (the
	// literal is yarad-synthetic; a match here means an attacker planted it).
	out = filterMarkerChannel(out, false)
	// Build the dedup identity set once from the raw matches so that the stream
	// loop below can update it incrementally instead of rebuilding it on every
	// stream (O(N) total rather than O(N²) — PERF: mergeMatches-seen).
	matchID := func(m Match) string { return m.Namespace + "/" + m.Rule }
	matchSeen := make(map[string]struct{}, len(out)+16)
	for i := range out {
		matchSeen[matchID(out[i])] = struct{}{}
	}
	// Pre-extract any OLE2/OOXML macro source and account for it. The flags feed
	// /metrics so this path is observable; the streams are scanned below. The
	// same overall deadline bounds extraction time, not just the libyara scans.
	res := extract.ExtractWithOptions(buf, profile.ExtractOptions(deadline))
	if res.IsDoc {
		s.exDocs.Add(1)
	}
	if res.Encrypted {
		s.exEncrypted.Add(1)
	}
	if res.Failed {
		s.exFailed.Add(1)
	}
	if res.Panicked {
		s.exPanicked.Add(1)
	}
	if res.IsMSI {
		s.exMSI.Add(1)
	}
	if res.IsMSG {
		s.exMSG.Add(1)
	}
	if res.IsOneNote {
		s.exOneNote.Add(1)
	}
	if res.IsArchive {
		s.exArchive.Add(1)
	}
	if res.IsOLEPackage {
		s.exOLEPackage.Add(1)
	}
	if res.IsLNK {
		s.exLNK.Add(1)
	}
	if res.IsPDF {
		s.exPDF.Add(1)
	}
	if res.IsRTF {
		s.exRTF.Add(1)
	}
	if res.IsSLK {
		s.exSLK.Add(1)
	}
	if res.EncodedScript {
		s.exEncodedScript.Add(1)
	}
	if res.HasDocProps {
		s.exDocProps.Add(1)
	}
	if res.HasXLMFold {
		s.exXLMFold.Add(1)
	}
	if res.DecodedStreams > 0 {
		s.exDecoded.Add(1)
	}
	// Macro/extracted-stream accounting excludes the static-decode blobs (the
	// trailing DecodedStreams entries) so a plain script body carrying a base64
	// run isn't miscounted as a macro document; decode is tracked by exDecoded.
	if n := len(res.Streams) - res.DecodedStreams; n > 0 {
		s.exMacroDocs.Add(1)
		s.exStreams.Add(uint64(n))
	}
	// Enrich with the decompressed macro source. A sub-scan error must NOT
	// discard the matches already found on the raw bytes, so it is logged and
	// skipped rather than failing the whole scan.
	// Deduplicate extracted streams by content hash before scanning: identical
	// embedded objects (e.g. the same macro module repeated across a complex doc)
	// would otherwise each spend a full libyara scan budget for no added signal.
	// The raw input buffer is seeded into seen first so a stream byte-identical to
	// the raw bytes is also skipped (it can't add new matches).
	seen := make(map[[16]byte]struct{})
	seen[streamDedupKey(buf)] = struct{}{} // xxhash the body once so a stream byte-identical to the raw body is skipped (PERF-3)
	// vbaKeys identifies the genuine VBA macro-source streams (the extractor's
	// codes() output) by content hash, so the VBA external is set ONLY for those.
	// Previously every extracted stream scanned with VBA=true, over-firing
	// VBA-gated rules (`VBA and any of(...)`) on PDF/archive/script/marker/decoded
	// content (false positives). Markers are never VBA.
	vbaKeys := make(map[[16]byte]struct{}, len(res.VBAStreams))
	for _, vs := range res.VBAStreams {
		vbaKeys[streamDedupKey(vs)] = struct{}{}
	}
	// scanExtracted runs one extracted entry (real content stream OR an out-of-band
	// marker) through dedup, the shared scan budget, and merge. Returns true when
	// the budget is exhausted so the caller stops the whole sweep. Markers and
	// Streams share one `seen` set and one budget — a marker byte-identical to a
	// real stream is scanned once, and markers can't overrun the deadline.
	scanExtracted := func(stream []byte, markerChannel bool) (stop bool) {
		h := streamDedupKey(stream)
		if _, dup := seen[h]; dup {
			s.exDeduped.Add(1)
			return false
		}
		seen[h] = struct{}{}
		budget := s.scanTimeout
		if !deadline.IsZero() {
			if budget = time.Until(deadline); budget <= 0 {
				s.logf("scan budget exhausted; %d streams + %d markers left unscanned", len(res.Streams), len(res.Markers))
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
		if !markerChannel {
			_, isVBA = vbaKeys[h]
		}
		// Oversized-stream cost gate (BIGFILE, extracted side): an extractor can emit
		// multi-MiB children (VBA 4 MiB, bin 8 MiB, archive member 16 MiB, PDF/RTF/
		// TNEF/package cumulative tens of MiB). Scanning such a child against the full
		// ~12k-rule set is the same unbounded cost the raw gate guards against, and it
		// drains the shared deadline budget for the remaining streams even when the raw
		// body was under threshold. Route oversized REAL-content streams through the
		// big-file ruleset too; marker-channel entries are tiny + synthetic so they
		// always keep the full set. Mirrors the raw gate (nil bigRules → full set).
		streamRules := rules
		if !markerChannel && s.bigFileThreshold > 0 && int64(len(stream)) > s.bigFileThreshold {
			if big := s.bigRules.Load(); big != nil {
				streamRules = big
				s.bigFileStreamScans.Add(1)
				s.logf("oversized extracted stream (%dB > %dB threshold): scanning against big-file ruleset instead of full set", len(stream), s.bigFileThreshold)
			} else if s.bigNilWarned.CompareAndSwap(false, true) {
				s.logf("WARNING: oversized extracted stream (%dB) but no big-file ruleset loaded; using full set (may time out)", len(stream))
			}
		}
		if markerChannel {
			s.markerChannelScans.Add(1)
		} else {
			s.streamChannelScans.Add(1)
		}
		m, serr := s.scanOne(streamRules, stream, scanVars{vba: isVBA, filename: meta.Filename, extension: meta.Extension, fileType: meta.FileType}, budget)
		if serr != nil {
			s.logf("scan of extracted stream failed (raw verdict kept): %v", serr)
			return false
		}
		// Phase 2 marker-channel: real content streams reject marker-tagged hits;
		// the out-of-band Markers channel keeps ONLY marker-tagged hits.
		m = filterMarkerChannel(m, markerChannel)
		// Inline incremental dedup: matchSeen is built once before the stream
		// loop (seeded from raw matches) and updated here, so we never rebuild
		// the map from scratch on each stream — O(N) total vs O(N²) before.
		before := len(out)
		for _, mm := range m {
			k := matchID(mm)
			if _, dup := matchSeen[k]; dup {
				continue
			}
			matchSeen[k] = struct{}{}
			out = append(out, mm)
		}
		// Anything appended is a rule that fired on the extracted stream but NOT
		// on the raw bytes — count it as pre-extraction's payoff.
		if added := len(out) - before; added > 0 {
			s.exStreamMatches.Add(uint64(added))
		}
		return false
	}
	for _, stream := range res.Streams {
		if scanExtracted(stream, false) {
			break
		}
	}
	// Renamed-container check (yarad analog of SpamAssassin OLEMACRO_RENAME /
	// MIME_BAD_EXTENSION): the extractor recovered the REAL type, so compare it to
	// the claimed extension. A high-signal container under a benign coat
	// (OLE/OOXML/RTF/archive/LNK/MSI/OneNote named .txt/.jpg/.pdf/…) is a classic
	// rename evasion. Emitted on the out-of-band marker channel so the rule fires
	// zero-FP on the synthetic literal only (never on attacker-controlled bytes).
	if d := extMismatch(res, meta.Extension); d != "" {
		s.exExtMismatch.Add(1)
		scanExtracted([]byte(extMismatchMarkerPrefix+" "+d), true)
	}
	// PLAN-marker-channel Phase 2: the out-of-band PURE markers are still scanned
	// against the full ruleset, but filterMarkerChannel now keeps ONLY
	// marker-tagged hits here and rejects them on raw/content above — so a
	// PURE-marker rule fires exclusively on this channel (zero-FP by
	// construction). COMBINED markers (untagged rules) remain in res.Streams and
	// are unaffected. Phase 3 will compile a markers.yac so marker rules execute
	// ONLY on this channel (the perf win), making the filter redundant.
	for _, marker := range res.Markers {
		if scanExtracted(marker, true) {
			break
		}
	}
	// Drop denylisted rule names (public-ruleset demo/noise rules) before the
	// synthetic feed matches are added, so MALWAREBAZAAR_*/URLHAUS_* are never
	// affected by the rule denylist.
	out = s.filterDenied(out)
	// Record rule names for the top-matches counter (observability via /version).
	if len(out) > 0 {
		names := make([]string, len(out))
		for i, m := range out {
			names[i] = m.Rule
		}
		s.topMatches.Add(names)
	}
	// MalwareBazaar: exact SHA256 match of the whole scanned buffer (the
	// attachment, as the plugin POSTed it) against known malware samples —
	// a direct known-bad verdict independent of the YARA rules. Only the raw
	// buffer is hashed (samples are whole files, not decompressed macros).
	// EFFORT-4: the external reputation feeds are the most expensive per-scan
	// cost, so a low effort level sheds them (profile.ReputationFeeds=false) and
	// the verdict rests on the local rules only. The resolved level is part of the
	// verdict-cache key, so a cheap-tier (feeds-off) verdict never masks a later
	// full-tier (feeds-on) one for the same bytes.
	if profile.ReputationFeeds && s.mbazaar != nil {
		for _, h := range s.mbazaar.CheckDigest(digest) {
			out = append(out, Match{Rule: h.Rule(), Tags: []string{"malwarebazaar"}, Meta: map[string]string{"sha256": h.SHA256}})
		}
	}
	// URLhaus: check the raw message and every decompressed macro/RTF stream for
	// known malware-distribution URLs (incl. defanged ones). Each distinct URL
	// becomes its own match (deduped across buffers) so the mail history shows
	// exactly which URLs hit.
	if profile.ReputationFeeds && s.urlhaus != nil {
		seenURL := make(map[string]struct{})
		addHits := func(b []byte) {
			for _, h := range s.urlhaus.Check(b, s.urlhausMax) {
				if _, dup := seenURL[h.URL]; dup {
					continue
				}
				seenURL[h.URL] = struct{}{}
				out = append(out, Match{Rule: h.Rule(), Tags: []string{"urlhaus"}, Meta: map[string]string{"url": h.URL}})
			}
		}
		addHits(buf)
		for _, stream := range res.Streams {
			addHits(stream)
		}
	}
	// ThreatFox: URL/domain IOC lookup — botnet C&C indicators complementing URLhaus.
	if profile.ReputationFeeds && s.threatfox != nil {
		seenTF := make(map[string]struct{})
		addTFHits := func(b []byte) {
			for _, h := range s.threatfox.Check(b, s.threatfoxMax) {
				if _, dup := seenTF[h.URL]; dup {
					continue
				}
				seenTF[h.URL] = struct{}{}
				out = append(out, Match{Rule: h.Rule(), Tags: []string{"threatfox"}, Meta: map[string]string{"url": h.URL}})
			}
		}
		addTFHits(buf)
		for _, stream := range res.Streams {
			addTFHits(stream)
		}
	}
	// Feodo Tracker: IP blocklist — URLs with raw C&C IP hosts.
	if profile.ReputationFeeds && s.feodo != nil {
		seenFD := make(map[string]struct{})
		addFDHits := func(b []byte) {
			for _, h := range s.feodo.Check(b, s.urlhausMax) {
				if _, dup := seenFD[h.URL]; dup {
					continue
				}
				seenFD[h.URL] = struct{}{}
				out = append(out, Match{Rule: h.Rule(), Tags: []string{"feodo"}, Meta: map[string]string{"url": h.URL, "ip": h.IP}})
			}
		}
		addFDHits(buf)
		for _, stream := range res.Streams {
			addFDHits(stream)
		}
	}
	// The raw scan failed but extraction/feeds recovered nothing: preserve the
	// original fail-open-with-error contract (the server logs it as "no match").
	// When something WAS recovered, the matches stand — that is the whole point of
	// not short-circuiting on the raw error above.
	if rawErr != nil && len(out) == 0 {
		return nil, rawErr
	}
	return out, nil
}

// filterDenied applies the rule deny/allow lists to a match set. Denylisted rule
// names (public-ruleset demo/noise that are pure FPs for mail) are dropped;
// allowlisted names are KEPT but tagged `yarad_allow=1` so the plugin can score
// them log-only without losing their visibility in the history. Order is
// preserved; a no-op when both lists are empty. Deny wins if a name is in both.
func (s *Scanner) filterDenied(in []Match) []Match {
	deny := s.denylist.Load()
	if (deny == nil || len(*deny) == 0) && len(s.allowlist) == 0 && !s.canary {
		return in
	}
	if len(in) == 0 {
		return in
	}
	out := in[:0]
	for _, m := range in {
		name := strings.ToLower(m.Rule)
		if deny != nil {
			if _, denied := (*deny)[name]; denied {
				continue
			}
		}
		if _, allow := s.allowlist[name]; allow {
			if m.Meta == nil {
				m.Meta = map[string]string{}
			}
			m.Meta["yarad_allow"] = "1"
		}
		out = append(out, m)
	}
	if s.canary {
		for i := range out {
			if out[i].Meta == nil {
				out[i].Meta = map[string]string{}
			}
			out[i].Meta["yarad_canary"] = "1"
		}
	}
	return out
}

// ReloadDenylist re-reads the denylist file (if configured) and merges its
// entries with the immutable env-based denylist. Safe to call from the SIGHUP
// handler. If the file doesn't exist or is unreadable, a warning is logged and
// the scanner continues with only the env-based entries (fail-open).
func (s *Scanner) ReloadDenylist() {
	if s.denylistFile == "" {
		return
	}
	merged := make(map[string]struct{}, len(s.baseDenylist))
	for k, v := range s.baseDenylist {
		merged[k] = v
	}
	f, err := os.Open(s.denylistFile) // #nosec G304 -- operator-provided path (env), not attacker input
	if err != nil {
		s.logf("WARNING: cannot read denylist file %s: %v (using env-only denylist)", s.denylistFile, err)
		return
	}
	defer f.Close()
	added := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.ToLower(line)
		if _, exists := merged[name]; !exists {
			merged[name] = struct{}{}
			added++
		}
	}
	if err := sc.Err(); err != nil {
		s.logf("WARNING: error reading denylist file %s: %v (partial load)", s.denylistFile, err)
	}
	s.denylist.Store(&merged)
	s.logf("denylist reloaded: %d from env + %d from file = %d total", len(s.baseDenylist), added, len(merged))
}

// Close releases the scanner's background resources: it stops the abuse.ch feed
// refresher goroutines (URLhaus + MalwareBazaar) so they don't outlive a
// graceful shutdown. Both Close calls are nil-safe (no-op when the feed is
// disabled) and idempotent. Call after the HTTP server has drained.
func (s *Scanner) Close() {
	s.urlhaus.Close()
	s.mbazaar.Close()
	s.threatfox.Close()
	s.feodo.Close()
}

// URLhausMetrics reports the URLhaus checker's state for /metrics, or a disabled
// snapshot when no Auth-Key is configured.
func (s *Scanner) URLhausMetrics() urlhaus.Metrics {
	if s.urlhaus == nil {
		return urlhaus.Metrics{}
	}
	return s.urlhaus.Metrics()
}

// ThreatFoxMetrics reports the ThreatFox checker's state for /metrics.
func (s *Scanner) ThreatFoxMetrics() threatfox.Metrics {
	if s.threatfox == nil {
		return threatfox.Metrics{}
	}
	return s.threatfox.Metrics()
}

// FeodoMetrics reports the Feodo Tracker checker's state for /metrics.
func (s *Scanner) FeodoMetrics() feodo.Metrics {
	if s.feodo == nil {
		return feodo.Metrics{}
	}
	return s.feodo.Metrics()
}

// TopMatches returns the top n most-triggered rule names since the last reload,
// sorted descending by hit count. Surfaced on /version for operator visibility
// into which rules fire most (weight tuning, FP triage, coverage confirmation).
func (s *Scanner) TopMatches(n int) []MatchCount { return s.topMatches.TopN(n) }

// MBazaarMetrics reports the MalwareBazaar checker's state for /metrics, or a
// disabled snapshot when no Auth-Key is configured.
func (s *Scanner) MBazaarMetrics() mbazaar.Metrics {
	if s.mbazaar == nil {
		return mbazaar.Metrics{}
	}
	return s.mbazaar.Metrics()
}

// scanOne runs the rule set over a single buffer and maps libyara's matches to
// our Match type. It is the format-blind primitive: it knows nothing about
// documents, so the scanner core stays generic and all container handling lives
// in Scan (and the extract package).
//
// vars carries the per-scan external-variable overrides (VBA for macro streams,
// filename/extension for name-keyed rules). Overriding an external variable
// requires a yara.Scanner (rules.ScanMem uses only the compile-time defaults),
// so a buffer with no overrides keeps the cheaper rules.ScanMem path and only a
// scan that actually sets a variable allocates a Scanner.
func (s *Scanner) scanOne(rules *yara.Rules, buf []byte, vars scanVars, timeout time.Duration) ([]Match, error) {
	var mr yara.MatchRules
	if vars.needsScanner() {
		sc, gen, err := s.getScanner(rules)
		if err != nil {
			return nil, err
		}
		defer s.putScanner(sc, gen)
		// Every external is (re)defined and the callback re-bound on each use, so
		// a pooled scanner carries no state from its previous scan.
		if err := vars.define(sc); err != nil {
			return nil, err
		}
		// FAST_MODE (PERF-15): stop scanning each string after its first match in
		// the buffer. yarad consumes only the rule-fired SET below (Rule/Namespace/
		// Tags/Meta) and never per-string offsets or counts, so the matched-rule set
		// is byte-identical — FAST_MODE only suppresses redundant duplicate-string
		// records. The win is on large buffers where a string matches many times
		// (e.g. a multi-MB script body), exactly where libyara dominates the scan.
		sc.SetTimeout(timeout).SetFlags(yara.ScanFlagsFastMode).SetCallback(&mr)
		if err := sc.ScanMem(buf); err != nil {
			return nil, err
		}
	} else {
		// FAST_MODE (PERF-15): same rationale as the scanner path above — detection
		// set unchanged, only redundant string-match records are dropped. All
		// externals keep their compile-time defaults.
		if err := rules.ScanMem(buf, yara.ScanFlagsFastMode, timeout, &mr); err != nil {
			return nil, err
		}
	}
	out := make([]Match, 0, len(mr))
	for _, m := range mr {
		meta := make(map[string]string, len(m.Metas))
		for _, kv := range m.Metas {
			meta[kv.Identifier] = fmt.Sprintf("%v", kv.Value)
		}
		if len(meta) == 0 {
			meta = nil
		}
		out = append(out, Match{Rule: m.Rule, Namespace: m.Namespace, Tags: m.Tags, Meta: meta})
	}
	return out, nil
}

// mergeMatches appends matches found in an extracted macro stream to the
// raw-scan matches, skipping any rule already reported so a rule that fires on
// both the container and its decompressed macro is listed once. Raw matches
// keep their position; new ones are appended in stream order.
//
// Identity is namespace+identifier, NOT the identifier alone: yarad compiles
// each rule file into its own namespace precisely because public rulesets reuse
// the same rule name across files (see Match.Namespace). Keying on the name
// alone would silently drop a genuinely different stream-only rule whose name
// collides with an unrelated raw match — and undercount exStreamMatches.
func mergeMatches(into, more []Match) []Match {
	if len(more) == 0 {
		return into
	}
	id := func(m Match) string { return m.Namespace + "/" + m.Rule }
	seen := make(map[string]struct{}, len(into)+len(more))
	for i := range into {
		seen[id(into[i])] = struct{}{}
	}
	for _, m := range more {
		if _, dup := seen[id(m)]; dup {
			continue
		}
		seen[id(m)] = struct{}{}
		into = append(into, m)
	}
	return into
}

// markerTag is the YARA tag carried by yarad's PURE-marker rules (PLAN
// marker-channel Phase 2). A rule wears it iff it keys ONLY on a yarad-emitted
// PURE marker literal that extract routes to Result.Markers (see
// internal/extract/markers.go pureMarkerLiterals). COMBINED markers (marker tag
// + attacker IOC in one string) are NOT tagged — their rules still scan content.
const markerTag = "marker"

// matchIsMarker reports whether m comes from a marker-tagged rule.
func matchIsMarker(m Match) bool {
	for _, t := range m.Tags {
		if t == markerTag {
			return true
		}
	}
	return false
}

// filterMarkerChannel enforces the Phase 2 marker-channel contract on one
// channel's matches:
//
//   - markerChannel=false (raw bytes + real content streams): DROP marker-tagged
//     matches. A PURE-marker rule keyed on a yarad literal must never fire on
//     attacker-controlled raw bytes or real extracted content — that is the
//     "zero-FP by construction" guarantee. An attacker who plants the literal
//     "OLEID-OBJECTPOOL" in a body can no longer trip the marker rule.
//   - markerChannel=true (out-of-band Result.Markers): KEEP ONLY marker-tagged
//     matches. The channel carries yarad literals; a content/IOC rule has no
//     business firing there, so its match is dropped.
//
// Returns in unchanged when nothing is filtered (common case, no alloc).
func filterMarkerChannel(in []Match, markerChannel bool) []Match {
	keep := 0
	for _, m := range in {
		if matchIsMarker(m) == markerChannel {
			keep++
		}
	}
	if keep == len(in) {
		return in
	}
	out := make([]Match, 0, keep)
	for _, m := range in {
		if matchIsMarker(m) == markerChannel {
			out = append(out, m)
		}
	}
	return out
}
