package mailstrix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// manifestName is the rules manifest filename (next to compiled.yac in the cache
// and as a published release asset).
const manifestName = "compiled.yac.manifest.json"

// backupSuffix is appended to keep exactly one rollback copy of the cache bundle.
const backupSuffix = ".bak"

// RuleSource records where one ruleset came from: its repo URL, license, and
// git ref, so `strixd info` and /version can show provenance at a glance.
type RuleSource struct {
	Name    string `json:"name"`
	Repo    string `json:"repo"`
	License string `json:"license"`
	Ref     string `json:"ref"`
	Set     string `json:"set,omitempty"` // only yaraforge (core/extended/full)
}

// RulesManifest is the small JSON file `fetch-rules` reads first to decide whether
// to update. It is published next to compiled.yac on the rolling release and is
// also stored alongside the cached bundle as the local record.
type RulesManifest struct {
	Version   int          `json:"version"`           // monotonic; an update exists iff remote > local
	Generated string       `json:"generated"`         // RFC3339 UTC, display/audit
	Checksum  string       `json:"checksum"`          // "sha256:<hex>" of compiled.yac
	Libyara   string       `json:"libyara"`           // libyara version that compiled it (skew guard)
	Rules     int          `json:"rules"`             // rule count (display)
	Size      int64        `json:"size"`              // compiled.yac bytes (sanity)
	Sources   []RuleSource `json:"sources,omitempty"` // per-ruleset provenance
}

// FetchResult reports what FetchRules did, for logging and the CLI exit code.
type FetchResult struct {
	Updated          bool // a new bundle was downloaded and swapped in
	LocalVersion     int  // version before the run
	NewVersion       int  // version after (== LocalVersion when not updated)
	Reason           string
	PublishedVersion int // latest validated remote manifest, even on later failure
}

// FetchRules implements the manifest-driven update: fetch the remote manifest,
// decide from it, and (only when warranted) download + verify + atomically swap
// the compiled bundle in the cache, keeping one backup.
//
//	baseURL    the directory URL holding compiled.yac + its manifest
//	cacheDir   where the live bundle lives (compiled.yac [+ .bak] + manifest)
//	ourLibyara the libyara version yarad links (empty disables the skew check)
//
// Order (each step keeps the current bundle on failure — fail to last-good):
//  1. GET manifest. Network error => no change.
//  2. remote.Version <= local.Version  => up to date, nothing downloaded.
//  3. remote.Libyara != ourLibyara     => refuse (skew), keep current.
//  4. GET compiled.yac, verify size + sha256 against the manifest. Mismatch =>
//     discard, keep current.
//  5. Back up the live bundle, replace both cache files under the cache lock,
//     and restore both on a reported install or daemon reload failure.
func FetchRules(ctx context.Context, baseURL, cacheDir, ourLibyara string, hc *http.Client) (FetchResult, error) {
	return fetchRules(ctx, baseURL, cacheDir, ourLibyara, hc, 0, nil)
}

// fetchRules stages without the cache lock, then rechecks the monotonic version
// under the lock. Install and optional reload are one serialized transaction.
// On a reported failure both files are restored; rollback errors are explicit.
// Individual renames are atomic, but this is not a two-file power-loss journal.
// reload must leave the active scanner unchanged on error and must not reacquire
// the cache lock. It runs only after both cache files have been installed.
func fetchRules(ctx context.Context, baseURL, cacheDir, ourLibyara string, hc *http.Client, minimumVersion int, reload func() error) (FetchResult, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	base := strings.TrimRight(baseURL, "/")
	res := FetchResult{}

	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return res, fmt.Errorf("cache dir: %w", err)
	}
	cachePath := filepath.Join(cacheDir, cachedRulesName)
	localManifestPath := filepath.Join(cacheDir, manifestName)

	unlock, err := lockRules(ctx, cacheDir)
	if err != nil {
		return res, err
	}
	local := trustedLocalManifest(cachePath, localManifestPath)
	unlock()
	res.LocalVersion = local.Version
	res.NewVersion = local.Version

	remote, err := fetchManifest(ctx, hc, base+"/"+manifestName)
	if err != nil {
		return res, fmt.Errorf("fetch manifest: %w", err)
	}
	res.PublishedVersion = remote.Version
	if remote.Version < minimumVersion {
		return res, fmt.Errorf("published version %d is older than loaded version %d", remote.Version, minimumVersion)
	}
	if remote.Version <= local.Version {
		res.Reason = fmt.Sprintf("up to date (local v%d, remote v%d)", local.Version, remote.Version)
		return res, nil
	}
	if ourLibyara != "" && remote.Libyara != ourLibyara {
		return res, fmt.Errorf("refusing update: remote bundle libyara %s != ours %s", remote.Libyara, ourLibyara)
	}

	// Download into a temp file in the cache dir and verify before swapping.
	tmp, err := downloadToTemp(ctx, hc, base+"/"+cachedRulesName, cacheDir, remote.Size)
	if err != nil {
		return res, fmt.Errorf("download bundle: %w", err)
	}
	// Every return before the install rename removes the staged download; after a
	// successful rename this harmlessly observes os.ErrNotExist.
	defer func() { _ = os.Remove(tmp) }()

	if err := verifyBundle(tmp, remote); err != nil {
		return res, fmt.Errorf("verify bundle: %w", err)
	}
	// Size+sha prove integrity of the bytes, not that they LOAD: a bundle compiled
	// against a different libyara (or subtly corrupt at the source) can match its
	// own checksum yet fail yara.LoadRules. Load-validate the temp bundle BEFORE the
	// swap so a bad download never replaces the working cache — the deferred
	// os.Remove(tmp) discards it and the old cache (+ .bak) stays live.
	if err := rulesBundleLoadable(tmp); err != nil {
		return res, fmt.Errorf("downloaded bundle does not load (keeping current cache): %w", err)
	}

	unlock, err = lockRules(ctx, cacheDir)
	if err != nil {
		return res, err
	}
	defer unlock()
	local = trustedLocalManifest(cachePath, localManifestPath)
	res.LocalVersion, res.NewVersion = local.Version, local.Version
	if remote.Version <= local.Version {
		res.Reason = "up to date after concurrent update"
		return res, nil
	}
	// Prepare both rollback copies before changing either public filename.
	rollbackDir, err := os.MkdirTemp(cacheDir, ".rules-rollback-")
	if err != nil {
		return res, err
	}
	keepRecovery := false
	defer func() {
		if !keepRecovery {
			_ = os.RemoveAll(rollbackDir)
		}
	}()
	paths := []string{cachePath, localManifestPath}
	existed := make([]bool, len(paths))
	for i, path := range paths {
		_, statErr := os.Stat(path)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return res, statErr
		}
		existed[i] = statErr == nil
		if existed[i] {
			if err := copyFileAtomic(path, filepath.Join(rollbackDir, filepath.Base(path))); err != nil {
				return res, err
			}
		}
	}
	rollback := func(cause error) error {
		var recovery error
		for i, path := range paths {
			var err error
			if existed[i] {
				err = os.Rename(filepath.Join(rollbackDir, filepath.Base(path)), path)
			} else {
				err = os.Remove(path)
				if errors.Is(err, os.ErrNotExist) {
					err = nil
				}
			}
			recovery = errors.Join(recovery, err)
		}
		if recovery != nil {
			keepRecovery = true
			return errors.Join(cause, fmt.Errorf("cache rollback failed; active rules retained but disk cache needs recovery: %w", recovery))
		}
		return cause
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	// Retain the public single-generation backup for operator recovery.
	if fileExists(cachePath) {
		if err := copyFileAtomic(cachePath, cachePath+backupSuffix); err != nil {
			return res, fmt.Errorf("backup current bundle: %w", err)
		}
	}
	if err := os.Rename(tmp, cachePath); err != nil {
		return res, fmt.Errorf("install bundle: %w", err)
	}
	if err := writeLocalManifest(localManifestPath, remote); err != nil {
		return res, rollback(fmt.Errorf("write local manifest: %w", err))
	}
	if reload != nil {
		if err := reload(); err != nil {
			return res, rollback(fmt.Errorf("reload downloaded rules: %w", err))
		}
	}

	res.Updated = true
	res.NewVersion = remote.Version
	res.Reason = fmt.Sprintf("updated v%d -> v%d", local.Version, remote.Version)
	return res, nil
}

// LoadManifest returns the rules manifest stored alongside the cached bundle in
// cacheDir, whether one was found, and any cache-lock error. Used by `strixd info`
// and the release verifier to report which rule version is loaded. A zero-value
// manifest, false, nil means none is present.
func LoadManifest(cacheDir string) (RulesManifest, bool, error) {
	if cacheDir == "" {
		return RulesManifest{}, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := lockRules(ctx, cacheDir)
	if err != nil {
		return RulesManifest{}, false, err
	}
	defer unlock()
	m := readLocalManifest(filepath.Join(cacheDir, manifestName))
	return m, m.Version > 0, nil
}

// LoadSources reads the baked sources.json from dir (typically /usr/share/mailstrix).
// Returns nil when none exists or it cannot be parsed — callers must treat nil as
// "provenance unknown" rather than an error (the scanner still works fine).
func LoadSources(dir string) []RuleSource {
	if dir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dir, "sources.json")) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil
	}
	var srcs []RuleSource
	if json.Unmarshal(b, &srcs) != nil {
		return nil
	}
	return srcs
}

// readLocalManifest returns the cached manifest, or a zero-version manifest when
// none exists / is unreadable (so a first run always sees an update available).
func readLocalManifest(path string) RulesManifest {
	var m RulesManifest
	b, err := os.ReadFile(path) // #nosec G304 -- cache path is operator-configured
	if err != nil {
		return RulesManifest{}
	}
	if json.Unmarshal(b, &m) != nil {
		return RulesManifest{}
	}
	return m
}

// A version only suppresses downloads when its record describes the actual
// cache bytes. Startup reseeding, manual replacement or interrupted publication
// can leave a syntactically valid but stale version record beside another bundle.
func trustedLocalManifest(bundle, path string) RulesManifest {
	m := readLocalManifest(path)
	if m.Version <= 0 || verifyBundle(bundle, m) != nil {
		return RulesManifest{}
	}
	return m
}

func writeLocalManifest(path string, m RulesManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// Unique temp (not a fixed path+".tmp") so two concurrent fetch-rules runs
	// can't clobber each other's in-progress write; rename is atomic same-fs.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// fetchManifest GETs and decodes the remote manifest (size-capped).
func fetchManifest(ctx context.Context, hc *http.Client, url string) (RulesManifest, error) {
	var m RulesManifest
	body, err := httpGet(ctx, hc, url, 64<<10)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("decode manifest: %w", err)
	}
	if m.Version <= 0 {
		return m, fmt.Errorf("manifest has no valid version")
	}
	if m.Size <= 0 || m.Size > 512<<20 {
		return m, fmt.Errorf("manifest size must be 1..536870912")
	}
	if m.Libyara == "" {
		return m, fmt.Errorf("manifest has no libyara version")
	}
	generated, err := time.Parse(time.RFC3339, m.Generated)
	if err != nil {
		return m, fmt.Errorf("manifest generated: %w", err)
	}
	if generated.Unix() <= 0 {
		return m, fmt.Errorf("manifest generated timestamp must be after the Unix epoch")
	}
	if generated.After(time.Now()) {
		return m, fmt.Errorf("manifest generated timestamp is in the future")
	}
	if !strings.HasPrefix(m.Checksum, "sha256:") {
		return m, fmt.Errorf("manifest checksum must use sha256")
	}
	sum, err := hex.DecodeString(strings.TrimPrefix(m.Checksum, "sha256:"))
	if err != nil || len(sum) != sha256.Size {
		return m, fmt.Errorf("manifest checksum must contain 32 bytes")
	}
	return m, nil
}

// downloadToTemp streams url into a new temp file in dir, returning its path.
func downloadToTemp(ctx context.Context, hc *http.Client, url, dir string, size int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	f, err := os.CreateTemp(dir, ".compiled-dl-*.tmp")
	if err != nil {
		return "", err
	}
	// The validated manifest bounds disk usage; read one extra byte so a
	// matching prefix cannot hide an oversized response.
	n, err := io.Copy(f, io.LimitReader(resp.Body, size+1))
	if err == nil && n != size {
		err = fmt.Errorf("downloaded size %d != manifest %d", n, size)
	}
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// verifyBundle checks the downloaded file's size and sha256 against the manifest.
func verifyBundle(path string, m RulesManifest) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if m.Size > 0 && fi.Size() != m.Size {
		return fmt.Errorf("size %d != manifest %d", fi.Size(), m.Size)
	}
	want := strings.TrimPrefix(m.Checksum, "sha256:")
	if want == "" {
		return fmt.Errorf("manifest has no checksum")
	}
	f, err := os.Open(path) // #nosec G304 -- our own temp file in the cache dir
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("sha256 %s != manifest %s", got, want)
	}
	return nil
}

func httpGet(ctx context.Context, hc *http.Client, url string, cap int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, cap))
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
