package mailstrix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockRules serializes participating cache readers and writers across processes.
// The lock file is permanent: unlinking it would let a new opener lock a different
// inode. Acquisition is cancellable; callers release before making network calls.
func lockRules(ctx context.Context, dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	// #nosec G304 -- dir is the operator-selected cache; the basename is fixed.
	f, err := os.OpenFile(filepath.Join(dir, ".rules.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

// tryLockRules is the nonblocking telemetry path. A busy cache keeps its last
// observed identity; HTTP probes must not wait for a native rule load.
func tryLockRules(dir string) (func(), error) {
	// #nosec G304 -- dir is the operator-selected cache; the basename is fixed.
	f, err := os.OpenFile(filepath.Join(dir, ".rules.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
