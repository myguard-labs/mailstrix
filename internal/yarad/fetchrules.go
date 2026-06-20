package yarad

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// git ref, so `yarad info` and /version can show provenance at a glance.
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
	Updated      bool // a new bundle was downloaded and swapped in
	LocalVersion int  // version before the run
	NewVersion   int  // version after (== LocalVersion when not updated)
	Reason       string
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
//  5. Back up the live bundle (one copy), atomically rename the new one in, write
//     the manifest. On a post-swap load failure the caller can restore .bak.
func FetchRules(ctx context.Context, baseURL, cacheDir, ourLibyara string, hc *http.Client) (FetchResult, error) {
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

	local := readLocalManifest(localManifestPath)
	res.LocalVersion = local.Version
	res.NewVersion = local.Version

	remote, err := fetchManifest(ctx, hc, base+"/"+manifestName)
	if err != nil {
		return res, fmt.Errorf("fetch manifest: %w", err)
	}

	if remote.Version <= local.Version {
		res.Reason = fmt.Sprintf("up to date (local v%d, remote v%d)", local.Version, remote.Version)
		return res, nil
	}
	if ourLibyara != "" && remote.Libyara != "" && remote.Libyara != ourLibyara {
		return res, fmt.Errorf("refusing update: remote bundle libyara %s != ours %s (a .yac only loads on a matching libyara)", remote.Libyara, ourLibyara)
	}

	// Download into a temp file in the cache dir and verify before swapping.
	tmp, err := downloadToTemp(ctx, hc, base+"/"+cachedRulesName, cacheDir)
	if err != nil {
		return res, fmt.Errorf("download bundle: %w", err)
	}
	defer os.Remove(tmp) // removed unless the rename below consumes it

	if err := verifyBundle(tmp, remote); err != nil {
		return res, fmt.Errorf("verify bundle: %w", err)
	}

	// Back up the current live bundle (one copy) so a bad load can roll back.
	if fileExists(cachePath) {
		if err := copyFileAtomic(cachePath, cachePath+backupSuffix); err != nil {
			return res, fmt.Errorf("backup current bundle: %w", err)
		}
	}
	if err := os.Rename(tmp, cachePath); err != nil {
		return res, fmt.Errorf("install bundle: %w", err)
	}
	if err := writeLocalManifest(localManifestPath, remote); err != nil {
		// The bundle is in place; a manifest-write failure only loses the version
		// record (next run re-evaluates). Surface it but don't undo the swap.
		return FetchResult{Updated: true, LocalVersion: local.Version, NewVersion: remote.Version,
			Reason: "updated but manifest record not written"}, fmt.Errorf("write local manifest: %w", err)
	}

	res.Updated = true
	res.NewVersion = remote.Version
	res.Reason = fmt.Sprintf("updated v%d -> v%d", local.Version, remote.Version)
	return res, nil
}

// LoadManifest returns the rules manifest stored alongside the cached bundle in
// cacheDir, and whether one was found. Used by `yarad info` / `/version` to report
// which rule version is loaded. A zero-value manifest + false means none present.
func LoadManifest(cacheDir string) (RulesManifest, bool) {
	if cacheDir == "" {
		return RulesManifest{}, false
	}
	m := readLocalManifest(filepath.Join(cacheDir, manifestName))
	return m, m.Version > 0
}

// LoadSources reads the baked sources.json from dir (typically /usr/share/yarad).
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
	return m, nil
}

// downloadToTemp streams url into a new temp file in dir, returning its path.
func downloadToTemp(ctx context.Context, hc *http.Client, url, dir string) (string, error) {
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
	// Cap the download to a sane ceiling (compiled bundles are tens of MB).
	if _, err := io.Copy(f, io.LimitReader(resp.Body, 512<<20)); err != nil {
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
