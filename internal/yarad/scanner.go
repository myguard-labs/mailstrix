package yarad

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	yara "github.com/hillu/go-yara/v4"

	"github.com/eilandert/rspamd-yarad/internal/extract"
)

// Match is one matched YARA rule, reported back to the rspamd plugin. Tags and
// the "meta" map come straight from the rule definition so the plugin can score
// or branch on them without yarad knowing anything rule-specific.
type Match struct {
	Rule string            `json:"rule"`
	Tags []string          `json:"tags,omitempty"`
	Meta map[string]string `json:"meta,omitempty"`
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

	mu      sync.Mutex // serializes Reload so two SIGHUPs can't compile at once
	srcDir  string
	srcFile string // precompiled bundle; wins over srcDir when set
	count   atomic.Int64
	fp      atomic.Pointer[string] // ruleset fingerprint, changes on reload

	// Observability for the OLE/OOXML pre-extract path (see ExtractMetrics).
	// Without these the document-extraction code is invisible in /metrics.
	// Uint64 (monotonic counters) so /metrics needs no signed→unsigned cast.
	exDocs, exStreams, exMacroDocs, exFailed, exPanicked, exEncrypted atomic.Uint64

	// Rule-reload observability (see ReloadMetrics).
	reloadAttempts, reloadOK, reloadFail atomic.Uint64
	reloadLastUnix, reloadLastMillis     atomic.Int64
}

// ExtractMetrics is a snapshot of the document pre-extraction counters, surfaced
// on /metrics so the new code path is observable: how many attachments were
// OLE/OOXML, how many carried macros, how often the parser failed/panicked, and
// how many were encrypted (and thus not decryptable here).
type ExtractMetrics struct {
	Docs      uint64 // buffers recognised as an OLE2/OOXML container
	Streams   uint64 // decompressed macro blobs scanned (sum across docs)
	MacroDocs uint64 // documents that yielded >=1 macro stream
	Failed    uint64 // container parse attempts that errored
	Panicked  uint64 // parser panics recovered (subset of Failed)
	Encrypted uint64 // ECMA-376 encrypted OOXML (not decrypted)
}

// ExtractMetrics returns the current pre-extraction counters.
func (s *Scanner) ExtractMetrics() ExtractMetrics {
	return ExtractMetrics{
		Docs:      s.exDocs.Load(),
		Streams:   s.exStreams.Load(),
		MacroDocs: s.exMacroDocs.Load(),
		Failed:    s.exFailed.Load(),
		Panicked:  s.exPanicked.Load(),
		Encrypted: s.exEncrypted.Load(),
	}
}

// NewScanner builds a scanner and performs the initial compile/load. It returns
// an error only when no rules at all could be loaded — a service with zero
// rules is a misconfiguration the operator must see at startup, not a silent
// "everything is clean".
func NewScanner(cfg *Config, logf func(string, ...any)) (*Scanner, error) {
	s := &Scanner{
		scanTimeout: cfg.ScanTimeout,
		logf:        logf,
		srcDir:      cfg.RulesDir,
		srcFile:     cfg.RulesPath,
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// RuleCount reports how many rules are in the active set (for /health and logs).
func (s *Scanner) RuleCount() int64 { return s.count.Load() }

// ReloadMetrics is a snapshot of rule-reload activity, surfaced on /metrics so a
// SIGHUP that silently fails (e.g. a bad rule edit) is visible to alerting
// instead of only appearing in logs.
type ReloadMetrics struct {
	Attempts   uint64 // Reload() calls (includes the initial boot load)
	Successes  uint64
	Failures   uint64
	LastUnix   int64 // unix seconds of the last successful reload
	LastMillis int64 // wall-clock duration of the last reload attempt
	Rules      int64 // rule count after the last successful reload
}

// ReloadMetrics returns the current reload counters.
func (s *Scanner) ReloadMetrics() ReloadMetrics {
	return ReloadMetrics{
		Attempts:   s.reloadAttempts.Load(),
		Successes:  s.reloadOK.Load(),
		Failures:   s.reloadFail.Load(),
		LastUnix:   s.reloadLastUnix.Load(),
		LastMillis: s.reloadLastMillis.Load(),
		Rules:      s.count.Load(),
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
	s.fp.Store(&fp)
	s.reloadOK.Add(1)
	s.reloadLastUnix.Store(time.Now().Unix())
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
	return extract.Version + ":" + fp
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
//   - filename/filepath/extension/filetype/owner — THOR/Loki (signature-base);
//     empty defaults, their path conditions simply never match raw mail bytes.
//   - VBA — Didier's vba.yara (`VBA and any of (...)`); default false so the rule
//     is inert on raw bytes, and Scan flips it true ONLY for decompressed macro
//     streams (see scanOne). This must mirror compile-rules.sh's yarac `-d` flags
//     so the precompiled .yac and this in-process path behave identically.
func defineExternals(c *yara.Compiler) {
	_ = c.DefineVariable("VBA", false)
	for _, v := range []string{"filename", "filepath", "extension", "filetype", "owner"} {
		_ = c.DefineVariable(v, "")
	}
}

// Scan runs the active rule set over buf and returns the matched rules. It is
// safe for concurrent use. A scan failure (timeout, libyara error) returns the
// error; the server treats that as "no match" but logs it, so a scanner problem
// never blocks mail (fail-open, matching the gozer contract).
//
// Beyond the raw bytes, Scan also matches against any plaintext hidden inside an
// OLE2/OOXML container — the decompressed VBA macro source — which the keyword
// rules cannot see in the compressed original. The raw bytes are scanned first
// (file-format/structural rules need them); each extracted macro stream is then
// scanned and its matches merged in. Extraction is best-effort and fail-open:
// for a non-document, or on any extract/sub-scan failure, the raw verdict stands
// and nothing is lost.
func (s *Scanner) Scan(buf []byte) ([]Match, error) {
	rules := s.rules.Load()
	if rules == nil {
		return nil, fmt.Errorf("no rules loaded")
	}
	// One wall-clock budget for the WHOLE request (raw + every extracted stream),
	// not per-scan: a hostile document with up to maxStreams macro modules must
	// not be able to spend scanTimeout × N and monopolize a worker far past the
	// rspamd/backend timeout. A zero/negative scanTimeout means "no limit" (yara
	// convention), so the deadline is disabled then.
	var deadline time.Time
	if s.scanTimeout > 0 {
		deadline = time.Now().Add(s.scanTimeout)
	}

	// Raw bytes first. A failure here is the scanner's verdict (propagated,
	// fail-open at the server) — unchanged behaviour for non-documents.
	out, err := s.scanOne(rules, buf, false, s.scanTimeout)
	if err != nil {
		return nil, err
	}
	// Pre-extract any OLE2/OOXML macro source and account for it. The flags feed
	// /metrics so this path is observable; the streams are scanned below. The
	// same overall deadline bounds extraction time, not just the libyara scans.
	res := extract.Extract(buf, deadline)
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
	if n := len(res.Streams); n > 0 {
		s.exMacroDocs.Add(1)
		s.exStreams.Add(uint64(n))
	}
	// Enrich with the decompressed macro source. A sub-scan error must NOT
	// discard the matches already found on the raw bytes, so it is logged and
	// skipped rather than failing the whole scan.
	for _, stream := range res.Streams {
		budget := s.scanTimeout
		if !deadline.IsZero() {
			if budget = time.Until(deadline); budget <= 0 {
				s.logf("scan budget exhausted; %d macro streams left unscanned", len(res.Streams))
				break
			}
		}
		// VBA=true so the macro-keyword rules (Didier vba.yara: `VBA and any of
		// (...)`) fire on this decompressed source — they are inert on raw bytes.
		m, serr := s.scanOne(rules, stream, true, budget)
		if serr != nil {
			s.logf("scan of extracted macro stream failed (raw verdict kept): %v", serr)
			continue
		}
		out = mergeMatches(out, m)
	}
	return out, nil
}

// scanOne runs the rule set over a single buffer and maps libyara's matches to
// our Match type. It is the format-blind primitive: it knows nothing about
// documents, so the scanner core stays generic and all container handling lives
// in Scan (and the extract package).
//
// vba selects the value of the external `VBA` variable for this scan: false for
// raw bytes, true for a decompressed macro stream. Overriding a per-scan
// external variable requires a yara.Scanner (rules.ScanMem uses only the
// compile-time default), so the raw path keeps the cheaper rules.ScanMem and
// only the macro-stream path allocates a Scanner.
func (s *Scanner) scanOne(rules *yara.Rules, buf []byte, vba bool, timeout time.Duration) ([]Match, error) {
	var mr yara.MatchRules
	if vba {
		sc, err := yara.NewScanner(rules)
		if err != nil {
			return nil, err
		}
		defer sc.Destroy()
		if err := sc.DefineVariable("VBA", true); err != nil {
			return nil, err
		}
		sc.SetTimeout(timeout).SetCallback(&mr)
		if err := sc.ScanMem(buf); err != nil {
			return nil, err
		}
	} else {
		// flags=0 = default scan; VBA keeps its compile-time default (false).
		if err := rules.ScanMem(buf, 0, timeout, &mr); err != nil {
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
		out = append(out, Match{Rule: m.Rule, Tags: m.Tags, Meta: meta})
	}
	return out, nil
}

// mergeMatches appends matches found in an extracted macro stream to the
// raw-scan matches, skipping any rule already reported so a rule that fires on
// both the container and its decompressed macro is listed once. Raw matches
// keep their position; new ones are appended in stream order.
func mergeMatches(into, more []Match) []Match {
	if len(more) == 0 {
		return into
	}
	seen := make(map[string]struct{}, len(into)+len(more))
	for i := range into {
		seen[into[i].Rule] = struct{}{}
	}
	for _, m := range more {
		if _, dup := seen[m.Rule]; dup {
			continue
		}
		seen[m.Rule] = struct{}{}
		into = append(into, m)
	}
	return into
}
