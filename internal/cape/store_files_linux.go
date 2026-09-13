//go:build linux

package cape

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Walk each path component with O_NOFOLLOW. The final directory must already
// exist, belong to this service UID and be private; provisioning is external.
func openPrivateDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrStoreUnavailable
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	if err = checkPrivate(f, true); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func checkPrivate(f *os.File, directory bool) error {
	var st unix.Stat_t
	euid := os.Geteuid()
	if unix.Fstat(int(f.Fd()), &st) != nil || euid < 0 || uint64(st.Uid) != uint64(euid) || st.Mode&0o777 != map[bool]uint32{true: 0o700, false: 0o600}[directory] {
		return ErrStoreUnavailable
	}
	if directory {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrStoreUnavailable
		}
	} else if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return ErrStoreUnavailable
	}
	return nil
}

func openStoreFile(dir *os.File, name string, flags int) (*os.File, error) {
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return nil, ErrStoreUnavailable
	}
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if err = checkPrivate(f, false); err != nil {
		_ = f.Close()
		return nil, err
	}
	var a, b unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &a) != nil || unix.Fstat(fd, &b) != nil || a.Dev != b.Dev {
		_ = f.Close()
		return nil, ErrStoreUnavailable
	}
	return f, nil
}

func openSpool(dir *os.File) (*os.File, error) {
	err := unix.Mkdirat(int(dir.Fd()), "spool", 0o700)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(int(dir.Fd()), "spool", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "spool")
	if err = checkPrivate(f, true); err != nil {
		_ = f.Close()
		return nil, err
	}
	var a, b unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &a) != nil || unix.Fstat(fd, &b) != nil || a.Dev != b.Dev {
		_ = f.Close()
		return nil, ErrStoreUnavailable
	}
	if err = dir.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func lockStore(dir *os.File) (*os.File, error) {
	f, err := openStoreFile(dir, "owner.lock", os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil // Permanent inode; never unlink it while releasing ownership.
}

func databasePath(dir *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10) + "/store.db"
}

func validateDatabaseFiles(dir *os.File) error {
	for _, name := range []string{"store.db", "store.db-wal", "store.db-shm"} {
		flags := os.O_RDWR
		if name == "store.db" {
			flags |= os.O_CREATE
		}
		f, err := openStoreFile(dir, name, flags)
		if errors.Is(err, os.ErrNotExist) && name != "store.db" {
			continue
		}
		if err != nil {
			return err
		}
		_ = f.Close()
	}
	return nil
}

func removeStoreFile(dir *os.File, name string) (bool, error) {
	if strings.ContainsAny(name, "/\\") {
		return false, ErrStoreUnavailable
	}
	err := unix.Unlinkat(int(dir.Fd()), name, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func renameStoreFile(dir *os.File, oldName, newName string) error {
	return unix.Renameat2(int(dir.Fd()), oldName, int(dir.Fd()), newName, unix.RENAME_NOREPLACE)
}

// A dedicated existing ext4/XFS volume is the supported production subset. Its
// kernel-reported total allocation space is itself the hard cap. Available space
// alone never establishes enforcement. Reject bind subtrees and multiply mounted
// devices visible in the current mount namespace. Because /proc/self/mountinfo
// cannot prove host-global exclusivity across mount namespaces, production
// activation additionally requires trusted host evidence for that property.
func filesystemCapacity(dir *os.File, path string) (capacity, error) {
	var fs unix.Statfs_t
	var st unix.Statx_t
	if unix.Fstatfs(int(dir.Fd()), &fs) != nil || (fs.Type != unix.EXT4_SUPER_MAGIC && fs.Type != unix.XFS_SUPER_MAGIC) ||
		unix.Statx(int(dir.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID|unix.STATX_BASIC_STATS, &st) != nil || st.Mask&unix.STATX_MNT_ID == 0 {
		return capacity{}, ErrStoreUnavailable
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return capacity{}, ErrStoreUnavailable
	}
	defer f.Close()
	scan := bufio.NewScanner(io.LimitReader(f, 1<<20))
	scan.Buffer(make([]byte, 4096), 64<<10)
	device := strconv.FormatUint(uint64(st.Dev_major), 10) + ":" + strconv.FormatUint(uint64(st.Dev_minor), 10)
	count := 0
	found := false
	size := 0
	for scan.Scan() {
		size += len(scan.Bytes()) + 1
		fields := strings.Fields(scan.Text())
		if len(fields) < 10 {
			return capacity{}, ErrStoreUnavailable
		}
		if fields[2] != device {
			continue
		}
		count++
		id, e := strconv.ParseUint(fields[0], 10, 64)
		if e == nil && id == st.Mnt_id && fields[3] == "/" && unescapeMount(fields[4]) == path {
			found = true
		}
	}
	if scan.Err() != nil || size >= 1<<20 || count != 1 || !found || fs.Bsize <= 0 || fs.Bsize > 1<<20 || fs.Blocks > uint64(PhysicalLimit/fs.Bsize) || fs.Bavail > fs.Blocks {
		return capacity{}, ErrStoreUnavailable
	}
	// fs.Blocks is bounded by PhysicalLimit/fs.Bsize above, and fs.Bavail cannot
	// exceed fs.Blocks, so both conversions fit in int64.
	c := capacity{total: int64(fs.Blocks) * fs.Bsize, available: int64(fs.Bavail) * fs.Bsize, block: fs.Bsize} // #nosec G115 -- bounds checked immediately above
	if !validCapacity(c) {
		return capacity{}, ErrStoreUnavailable
	}
	return c, nil
}

func unescapeMount(s string) string {
	return strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\").Replace(s)
}
