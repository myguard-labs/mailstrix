package mailstrix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Recovery state belongs to the local cache record, not the signed wire schema.
type localRulesRecord struct {
	RulesManifest
	MarkerRetry *markerRetryState `json:"marker_retry,omitempty"`
}

type markerRetryState struct {
	Marker   rulesMarker `json:"marker"`
	Attempts int         `json:"attempts"`
	After    time.Time   `json:"after"`
}

const markerRetryMaxAttempts = 7 // exponent saturation: delays stay at one hour

// A retry snapshot moves from absent to leased while .rules.lock is held.
// Its directory inode is the lease: no separate lease file can be missing,
// replaced or inherited from another generation. The owner holds the flock
// through staging, verification and removal, including after .rules.lock is
// released. Process exit releases it automatically. Startup cleanup holds
// .rules.lock, acquires the same lease nonblocking, and removes only stale,
// unleased directories. Age alone never authorizes deleting an active snapshot.
func lockMarkerRetrySnapshot(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- operator-cache MkdirTemp/ReadDir directory; O_DIRECTORY|O_NOFOLLOW rejects files/symlinks.
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// Cooperating writers replace the live bundle atomically under .rules.lock,
// so a hardlink pins its old inode without copying and syncing the full file.
// Copy symlinks instead: a relative link resolves differently inside snapshot.
// The caller holds .rules.lock until the snapshot and retry claim are ready.
func snapshotMarkerRetryBundle(src, dst string, link func(string, string) error) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if fi.Mode().IsRegular() && link(src, dst) == nil {
		return nil
	}
	return copyFileAtomic(src, dst)
}

func cleanupMarkerRetrySnapshot(path string) error {
	lease, err := lockMarkerRetrySnapshot(path)
	if err != nil {
		return err
	}
	defer func() { _ = lease.Close() }()
	opened, err := lease.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, current) {
		return fmt.Errorf("retry snapshot changed during cleanup: %s", path)
	}
	return os.RemoveAll(path)
}

type rulesHTTPStatusError int

func (e rulesHTTPStatusError) Error() string { return fmt.Sprintf("status %d", int(e)) }

type markerDownloadError struct{ err error }

func (e markerDownloadError) Error() string { return e.err.Error() }
func (e markerDownloadError) Unwrap() error { return e.err }

func markerRetryNow(opts fetchOptions) time.Time {
	if opts.now != nil {
		return opts.now()
	}
	return time.Now()
}

func newMarkerRetry(marker *rulesMarker, err error, attempts int, now time.Time) *markerRetryState {
	if marker == nil || err == nil || errors.Is(err, context.Canceled) {
		return nil
	}
	transient := errors.Is(err, context.DeadlineExceeded)
	var download markerDownloadError
	if errors.As(err, &download) {
		var status rulesHTTPStatusError
		var network net.Error
		var operation *net.OpError
		transient = errors.As(download.err, &status) && (status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500 && status <= 599) ||
			errors.As(download.err, &network) && network.Timeout() || errors.As(download.err, &operation) || errors.Is(download.err, io.ErrUnexpectedEOF) || errors.Is(download.err, io.EOF)
	}
	if !transient {
		return nil
	}
	attempts = min(max(attempts, 0), markerRetryMaxAttempts-1) + 1
	delay := min(time.Minute<<uint(attempts-1), time.Hour)
	return &markerRetryState{Marker: *marker, Attempts: attempts, After: now.Add(delay)}
}

func markerRetryMatches(local, remote RulesManifest, opts fetchOptions) bool {
	r := local.markerRetry
	return !opts.markersOff && remote.markerErr == nil && remote.marker != nil && markerABIMatches(remote.marker) &&
		local.Version == remote.Version && local.Checksum == remote.Checksum && local.Size == remote.Size && local.Libyara == remote.Libyara &&
		r != nil && r.Attempts >= 1 && r.Attempts <= markerRetryMaxAttempts && !r.After.IsZero() && r.Marker == *remote.marker
}

// retryRemoteMarker claims a bounded retry under the update lock, then stages
// against an immutable snapshot outside it. The final recheck prevents a slow
// retry from attaching its tree to a newer concurrent rules generation.
func retryRemoteMarker(ctx context.Context, hc *http.Client, base, cacheDir string, remote RulesManifest, opts fetchOptions, res FetchResult) (FetchResult, error) {
	res.Reason = fmt.Sprintf("up to date (local v%d, remote v%d)", res.LocalVersion, remote.Version)
	unlock, err := lockRules(ctx, cacheDir)
	if err != nil {
		return res, err
	}
	cachePath, manifestPath := filepath.Join(cacheDir, cachedRulesName), filepath.Join(cacheDir, manifestName)
	local := trustedLocalManifest(cachePath, manifestPath)
	res.LocalVersion, res.NewVersion = local.Version, local.Version
	now := markerRetryNow(opts)
	if !markerRetryMatches(local, remote, opts) || now.Before(local.markerRetry.After) {
		unlock()
		return res, nil
	}
	snapshot, err := os.MkdirTemp(cacheDir, ".marker-retry-")
	if err != nil {
		unlock()
		return res, err
	}
	lease, err := lockMarkerRetrySnapshot(snapshot)
	if err != nil {
		_ = os.RemoveAll(snapshot)
		unlock()
		return res, err
	}
	defer func() {
		_ = os.RemoveAll(snapshot)
		_ = lease.Close()
	}()
	bundle := filepath.Join(snapshot, cachedRulesName)
	if err := snapshotMarkerRetryBundle(cachePath, bundle, os.Link); err != nil {
		unlock()
		return res, err
	}
	claim := newMarkerRetry(remote.marker, context.DeadlineExceeded, local.markerRetry.Attempts, now)
	local.markerRetry = claim
	if err := writeLocalManifest(manifestPath, local); err != nil {
		unlock()
		return res, err
	}
	unlock()
	stage, status, stageErr := prepareRemoteMarkerTree(ctx, hc, base, cacheDir, bundle, remote, opts)
	if stage != "" {
		defer func() { _ = os.RemoveAll(stage) }()
	}
	unlock, err = lockRules(ctx, cacheDir)
	if err != nil {
		return res, err
	}
	defer unlock()
	local = trustedLocalManifest(cachePath, manifestPath)
	res.LocalVersion, res.NewVersion = local.Version, local.Version
	if !markerRetryMatches(local, remote, opts) || local.markerRetry.Attempts != claim.Attempts || !local.markerRetry.After.Equal(claim.After) {
		res.Reason = "up to date after concurrent update"
		return res, nil
	}
	if stage == "" {
		res.Marker = status
		// Permanently invalid responses are never polled again for this version.
		if newMarkerRetry(remote.marker, stageErr, claim.Attempts, now) == nil {
			local.markerRetry = nil
			if err := writeLocalManifest(manifestPath, local); err != nil {
				return res, err
			}
		}
		return res, nil
	}
	if err := installRetriedMarker(ctx, cacheDir, local, stage, opts); err != nil {
		return res, err
	}
	res.Marker = MarkerStatusInstalled
	res.Reason = fmt.Sprintf("marker tree recovered for v%d", local.Version)
	return res, nil
}

// Caller owns the update lock. Only the optional tree and its local retry
// receipt change; compiled.yac, its backup and its version remain untouched.
func installRetriedMarker(ctx context.Context, cacheDir string, local RulesManifest, stage string, opts fetchOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rollbackDir, err := os.MkdirTemp(cacheDir, ".rules-rollback-")
	if err != nil {
		return err
	}
	keepRecovery := false
	defer func() {
		if !keepRecovery {
			_ = os.RemoveAll(rollbackDir)
		}
	}()
	tree := newMarkerTreeSwap(cacheDir, rollbackDir)
	manifestPath := filepath.Join(cacheDir, manifestName)
	rollback := func(cause error) error {
		recovery := errors.Join(tree.restore(), writeLocalManifest(manifestPath, local))
		if recovery != nil {
			keepRecovery = true
			return errors.Join(cause, fmt.Errorf("marker retry rollback failed; disk cache needs recovery: %w", recovery))
		}
		return cause
	}
	if err := tree.retire(); err != nil {
		return rollback(fmt.Errorf("retire marker tree: %w", err))
	}
	if err := tree.install(stage); err != nil {
		return rollback(fmt.Errorf("install marker tree: %w", err))
	}
	complete := local
	complete.markerRetry = nil
	if err := writeLocalManifest(manifestPath, complete); err != nil {
		return rollback(err)
	}
	if opts.reload != nil {
		if err := opts.reload(); err != nil {
			return rollback(fmt.Errorf("reload recovered marker tree: %w", err))
		}
	}
	return nil
}
