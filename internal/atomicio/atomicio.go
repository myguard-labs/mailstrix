// Package atomicio writes a file atomically (temp + rename) and keeps a single
// rollback backup. It is the shared swap discipline used for the cached abuse.ch
// feed snapshots (and is the same temp+rename pattern the rules cache uses), so a
// concurrent reader never sees a half-written file and a bad write can roll back.
package atomicio

import (
	"io"
	"os"
	"path/filepath"
)

// BackupSuffix is appended to keep exactly one previous copy.
const BackupSuffix = ".bak"

// WriteWithBackup writes data to path atomically: it writes a temp file in the
// same directory, fsyncs it, backs up any existing file to path+".bak", then
// renames the temp file into place (same-filesystem rename is atomic). The
// parent directory is created if missing. On any error the original file is left
// untouched.
func WriteWithBackup(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".atomicio-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmpName, perm); err != nil {
		return err
	}

	// Keep one backup of the current file before replacing it — by COPYING, not
	// renaming. Renaming the live file to .bak first would leave `path` absent in
	// the window before the final rename, so a crash or a concurrent warm-start in
	// that gap would see no live feed and start empty even though a valid snapshot
	// existed. Copying leaves `path` present continuously; the single rename below
	// then atomically replaces it. A backup-copy failure is non-fatal (the verified
	// new file still installs) — we just lose the rollback copy.
	if cur, err := os.Open(path); err == nil { // #nosec G304 -- caller-owned path
		bakTmp, e := os.CreateTemp(dir, ".atomicio-bak-*.tmp")
		if e == nil {
			bakName := bakTmp.Name()
			if _, e = io.Copy(bakTmp, cur); e == nil {
				e = bakTmp.Close()
			} else {
				_ = bakTmp.Close()
			}
			if e == nil {
				_ = os.Chmod(bakName, perm)
				_ = os.Rename(bakName, path+BackupSuffix)
			} else {
				_ = os.Remove(bakName)
			}
		}
		_ = cur.Close()
	}
	return os.Rename(tmpName, path)
}

// ReadCached reads path, returning the bytes and true when a non-empty file
// exists, or (nil, false) otherwise — the warm-start read for a cached feed.
func ReadCached(path string) ([]byte, bool) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured cache path
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}
