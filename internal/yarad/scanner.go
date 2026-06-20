package yarad

import (
	"bufio"
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
	"github.com/eilandert/rspamd-yarad/internal/mbazaar"
	"github.com/eilandert/rspamd-yarad/internal/urlhaus"
)

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

	mu      sync.Mutex // serializes Reload so two SIGHUPs can't compile at once
	srcDir  string
	srcFile string // precompiled bundle; wins over srcDir when set
	count   atomic.Int64
	fp      atomic.Pointer[string] // ruleset fingerprint, changes on reload

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
	exEncodedScript                                                   atomic.Uint64 // buffers with >=1 decoded MS-Script-Encoder block
	exDecoded                                                         atomic.Uint64 // buffers with >=1 base64/hex/reversed blob from the static decode pass
	exStreamMatches                                                   atomic.Uint64 // distinct rule hits that came ONLY from an extracted stream (not raw bytes)
	exDeduped                                                         atomic.Uint64 // extracted streams skipped as duplicates (content hash matched a prior stream or raw buf)
	exDocProps                                                        atomic.Uint64 // documents with doc-property strings extracted
	exXLMFold                                                         atomic.Uint64 // documents with XLM formula constant-folding applied

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

	// Optional abuse.ch MalwareBazaar attachment-hash lookup (nil when no key).
	mbazaar *mbazaar.Checker

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
	EncScript  uint64 // buffers with >=1 decoded MS-Script-Encoder (VBE/JSE) block
	Decoded    uint64 // buffers with >=1 base64/hex/reversed blob from the static decode pass
	// StreamMatches counts rule hits attributable ONLY to an extracted stream
	// (macro/MSI/VBE), i.e. rules that did NOT already fire on the raw bytes —
	// the direct measure of what pre-extraction adds over a raw-only scan.
	StreamMatches uint64
	// Deduped counts extracted streams skipped before YARA scanning because their
	// SHA256 matched a previously scanned stream (or the raw input buffer itself).
	Deduped  uint64
	DocProps uint64 // documents with doc-property strings extracted
	XLMFold  uint64 // documents with XLM formula constant-folding applied
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
		EncScript:     s.exEncodedScript.Load(),
		Decoded:       s.exDecoded.Load(),
		StreamMatches: s.exStreamMatches.Load(),
		Deduped:       s.exDeduped.Load(),
		DocProps:      s.exDocProps.Load(),
		XLMFold:       s.exXLMFold.Load(),
	}
}

// NewScanner builds a scanner and performs the initial compile/load. It returns
// an error only when no rules at all could be loaded — a service with zero
// rules is a misconfiguration the operator must see at startup, not a silent
// "everything is clean".
func NewScanner(cfg *Config, logf func(string, ...any)) (*Scanner, error) {
	s := &Scanner{
		scanTimeout:  cfg.ScanTimeout,
		logf:         logf,
		srcDir:       cfg.RulesDir,
		srcFile:      cfg.RulesPath,
		urlhaus:      urlhaus.New(cfg.URLhausKey, cfg.URLhausRefresh, cfg.CacheDir, logf), // nil if no key
		urlhausMax:   cfg.URLhausMaxURLs,
		mbazaar:      mbazaar.New(cfg.MBazaarKey, cfg.MBazaarRefresh, cfg.MBazaarFeed, cfg.CacheDir, logf), // nil if no key
		canary:       cfg.Canary,
		baseDenylist: cfg.RuleDenylist,
		denylistFile: cfg.DenylistFile,
		allowlist:    cfg.RuleAllowlist,
		topMatches:   newMatchCounter(matchCounterCap),
	}
	s.denylist.Store(&cfg.RuleDenylist)
	if s.urlhaus != nil {
		logf("URLhaus malware-URL lookup enabled (refresh=%s, max_urls/msg=%d)", cfg.URLhausRefresh, cfg.URLhausMaxURLs)
	}
	if s.mbazaar != nil {
		logf("MalwareBazaar attachment-hash lookup enabled (refresh=%s)", cfg.MBazaarRefresh)
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	s.ReloadDenylist()
	return s, nil
}

// RuleCount reports how many rules are in the active set (for /health and logs).
func (s *Scanner) RuleCount() int64 { return s.count.Load() }

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
}

// cacheKey renders the metadata for the verdict cache key. The verdict depends on
// these externals, so two scans of the same bytes with different metadata must
// land on different keys. Extension derives from Filename but is included so the
// key is explicit. NUL separator can't occur in either (NewScanMeta strips it).
func (m ScanMeta) cacheKey() string { return m.Filename + "\x00" + m.Extension + "\x00" + m.FileType }

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

// define applies the overrides to a scanner. VBA is always set (to the desired
// value, false by default); string externals are set only when non-empty so an
// absent name/type leaves the empty compile-time default.
func (v scanVars) define(sc *yara.Scanner) error {
	if err := sc.DefineVariable("VBA", v.vba); err != nil {
		return err
	}
	if v.filename != "" {
		if err := sc.DefineVariable("filename", v.filename); err != nil {
			return err
		}
	}
	if v.extension != "" {
		if err := sc.DefineVariable("extension", v.extension); err != nil {
			return err
		}
	}
	if v.fileType != "" {
		if err := sc.DefineVariable("file_type", v.fileType); err != nil {
			return err
		}
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
func (s *Scanner) Scan(buf []byte, meta ScanMeta) ([]Match, error) {
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
	out, err := s.scanOne(rules, buf, scanVars{filename: meta.Filename, extension: meta.Extension, fileType: meta.FileType}, s.scanTimeout)
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
	seen := make(map[[32]byte]struct{})
	seen[sha256.Sum256(buf)] = struct{}{}
	for _, stream := range res.Streams {
		h := sha256.Sum256(stream)
		if _, dup := seen[h]; dup {
			s.exDeduped.Add(1)
			continue
		}
		seen[h] = struct{}{}
		budget := s.scanTimeout
		if !deadline.IsZero() {
			if budget = time.Until(deadline); budget <= 0 {
				s.logf("scan budget exhausted; %d macro streams left unscanned", len(res.Streams))
				break
			}
		}
		// VBA=true so the macro-keyword rules (Didier vba.yara: `VBA and any of
		// (...)`) fire on this decompressed source — they are inert on raw bytes.
		// filename/extension carry through so a name-keyed rule fires the same on
		// the container's decompressed macros as on its raw bytes.
		m, serr := s.scanOne(rules, stream, scanVars{vba: true, filename: meta.Filename, extension: meta.Extension, fileType: meta.FileType}, budget)
		if serr != nil {
			s.logf("scan of extracted macro stream failed (raw verdict kept): %v", serr)
			continue
		}
		before := len(out)
		out = mergeMatches(out, m)
		// Anything mergeMatches appended is a rule that fired on the extracted
		// stream but NOT on the raw bytes — count it as pre-extraction's payoff.
		if added := len(out) - before; added > 0 {
			s.exStreamMatches.Add(uint64(added))
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
	if s.mbazaar != nil {
		for _, h := range s.mbazaar.Check(buf) {
			out = append(out, Match{Rule: h.Rule(), Tags: []string{"malwarebazaar"}, Meta: map[string]string{"sha256": h.SHA256}})
		}
	}
	// URLhaus: check the raw message and every decompressed macro/RTF stream for
	// known malware-distribution URLs (incl. defanged ones). Each distinct URL
	// becomes its own match (deduped across buffers) so the mail history shows
	// exactly which URLs hit.
	if s.urlhaus != nil {
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
}

// URLhausMetrics reports the URLhaus checker's state for /metrics, or a disabled
// snapshot when no Auth-Key is configured.
func (s *Scanner) URLhausMetrics() urlhaus.Metrics {
	if s.urlhaus == nil {
		return urlhaus.Metrics{}
	}
	return s.urlhaus.Metrics()
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
		sc, err := yara.NewScanner(rules)
		if err != nil {
			return nil, err
		}
		defer sc.Destroy()
		if err := vars.define(sc); err != nil {
			return nil, err
		}
		sc.SetTimeout(timeout).SetCallback(&mr)
		if err := sc.ScanMem(buf); err != nil {
			return nil, err
		}
	} else {
		// flags=0 = default scan; all externals keep their compile-time defaults.
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
