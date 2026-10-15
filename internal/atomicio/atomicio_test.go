package atomicio

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteWithBackupCreatesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "feed.csv") // sub dir must be created

	if err := WriteWithBackup(p, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "v1" {
		t.Fatalf("first write = %q", b)
	}
	// No backup yet on the first write.
	if _, err := os.Stat(p + BackupSuffix); err == nil {
		t.Error("unexpected backup after first write")
	}

	// Second write backs up the first.
	if err := WriteWithBackup(p, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "v2" {
		t.Fatalf("second write = %q", b)
	}
	if b, _ := os.ReadFile(p + BackupSuffix); string(b) != "v1" {
		t.Fatalf("backup = %q, want v1", b)
	}
}

// TestWriteWithBackupKeepsLivePresent guards the Codex P2 fix: the live file must
// stay present throughout a replacement (the backup is a COPY, not a rename), so
// a crash/concurrent read in the swap window never sees a missing live file.
func TestWriteWithBackupKeepsLivePresent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "feed")
	if err := WriteWithBackup(p, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Before the second write the live file exists; after it, still exists (and is
	// v2) and the backup holds v1 — at no modeled point is `path` absent.
	if _, ok := ReadCached(p); !ok {
		t.Fatal("live file missing before replacement")
	}
	if err := WriteWithBackup(p, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, ok := ReadCached(p); !ok || string(b) != "v2" {
		t.Fatalf("live after replace = %q,%v", b, ok)
	}
	if b, _ := os.ReadFile(p + BackupSuffix); string(b) != "v1" {
		t.Fatalf("backup = %q, want v1 (copied, not moved)", b)
	}
}

func TestWriteWithBackupCleansTempWhenBackupRenameFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "feed")
	if err := os.WriteFile(p, []byte("old-live"), 0o600); err != nil {
		t.Fatal(err)
	}
	bakDir := p + BackupSuffix
	if err := os.Mkdir(bakDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(bakDir, "keep")
	if err := os.WriteFile(marker, []byte("old-backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteWithBackup(p, []byte("new-live"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "new-live" {
		t.Fatalf("live = %q, %v; want new-live", b, err)
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "old-backup" {
		t.Fatalf("backup marker = %q, %v; want retained directory", b, err)
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".atomicio-bak-*.tmp")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary backups = %v, %v; want none", matches, err)
	}
}

func TestWriteWithBackupPerm(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := WriteWithBackup(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 600", fi.Mode().Perm())
	}
}

func TestReadCached(t *testing.T) {
	dir := t.TempDir()
	if _, ok := ReadCached(filepath.Join(dir, "missing")); ok {
		t.Error("missing file should not be ok")
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	if _, ok := ReadCached(empty); ok {
		t.Error("empty file should not be ok")
	}
	full := filepath.Join(dir, "full")
	_ = os.WriteFile(full, []byte("data"), 0o600)
	if b, ok := ReadCached(full); !ok || string(b) != "data" {
		t.Errorf("ReadCached = %q,%v", b, ok)
	}
}

func BenchmarkWriteWithBackupLarge(b *testing.B) {
	p := filepath.Join(b.TempDir(), "feed.bin")
	data := make([]byte, 4<<20)
	if err := WriteWithBackup(p, data, 0o600); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := WriteWithBackup(p, data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
}

func TestInstallFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "feed.bin")
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "spool.tmp")
	if err := os.WriteFile(src, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InstallFile(src, dst, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "new" {
		t.Fatalf("dst=%q want new", b)
	}
	if b, _ := os.ReadFile(dst + BackupSuffix); string(b) != "old" {
		t.Fatalf("bak=%q want old", b)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("src not consumed")
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode check: fi=%v err=%v", fi, err)
	}
}

func TestInstallFileErrors(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	src := filepath.Join(other, "s.tmp")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallFile(src, filepath.Join(dir, "f"), 0o600); err == nil {
		t.Fatal("cross-directory src accepted")
	}
	missing := filepath.Join(dir, "gone.tmp")
	if err := InstallFile(missing, filepath.Join(dir, "f"), 0o600); err == nil {
		t.Fatal("missing src accepted")
	}
}

// TestInstallFileRelativeSrcSameDir: a relative src (cwd-relative) paired with an
// absolute destination in that same directory is a valid install.
func TestInstallFileRelativeSrcSameDir(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "feed.bin")
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := os.WriteFile("spool.tmp", []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallFile("spool.tmp", dst, 0o600); err != nil {
		t.Fatalf("relative src in same dir rejected: %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "new" {
		t.Fatalf("dst=%q want new", b)
	}
	if b, _ := os.ReadFile(dst + BackupSuffix); string(b) != "old" {
		t.Fatalf("bak=%q want old", b)
	}
	if _, err := os.Stat("spool.tmp"); !os.IsNotExist(err) {
		t.Fatal("relative src not consumed")
	}
}

// TestInstallFileDirSpellingBoundary: "./" components and redundant separators in
// either path still resolve to the same directory and install.
func TestInstallFileDirSpellingBoundary(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("./spool.tmp", []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	sep := string(os.PathSeparator)
	dst := dir + sep + "." + sep + sep + "feed.bin"
	if err := InstallFile("./spool.tmp", dst, 0o600); err != nil {
		t.Fatalf("spelling variant rejected: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "feed.bin")); string(b) != "new" {
		t.Fatalf("dst=%q want new", b)
	}
	if _, err := os.Stat("spool.tmp"); !os.IsNotExist(err) {
		t.Fatal("src not consumed")
	}
}

// TestInstallFileCrossDirRemovesSrc: a src in another directory is rejected and,
// per the doc contract, removed on the error path; the destination is untouched.
func TestInstallFileCrossDirRemovesSrc(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	dst := filepath.Join(dir, "feed.bin")
	if err := os.WriteFile(dst, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(other, "spool.tmp")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallFile(src, dst, 0o600); err == nil {
		t.Fatal("cross-directory src accepted")
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("rejected src not removed: %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "live" {
		t.Fatalf("dst changed on reject: %q", b)
	}
}

// TestInstallFileRelativeCrossDirRemovesSrc: a relative src in a different
// directory than an absolute destination is rejected and removed.
func TestInstallFileRelativeCrossDirRemovesSrc(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(t.TempDir())
	if err := os.WriteFile("spool.tmp", []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallFile("spool.tmp", filepath.Join(dir, "feed.bin"), 0o600); err == nil {
		t.Fatal("relative cross-directory src accepted")
	}
	if _, err := os.Stat("spool.tmp"); !os.IsNotExist(err) {
		t.Fatalf("rejected relative src not removed: %v", err)
	}
}

// TestInstallFileAbsFailureRemovesSrc: when the working directory has been
// removed, a relative path cannot be made absolute; InstallFile must return the
// error and still remove src on that path.
func TestInstallFileAbsFailureRemovesSrc(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("removing the working directory is not supported on windows")
	}
	parent := t.TempDir()
	gone := filepath.Join(parent, "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	// Platforms that keep resolving a removed working directory cannot reach the
	// Abs error branch; the Linux CI runner does.
	if wd, err := os.Getwd(); err == nil {
		t.Skipf("working directory still resolves after removal (%s)", wd)
	}

	// Relative src: the source directory cannot be resolved.
	if err := InstallFile("spool.tmp", filepath.Join(parent, "feed.bin"), 0o600); err == nil {
		t.Fatal("unresolvable relative src directory accepted")
	}

	// Absolute src in parent, relative destination: the destination directory
	// cannot be resolved; src is removed on that error path too.
	src := filepath.Join(parent, "spool.tmp")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallFile(src, "feed.bin", 0o600); err == nil {
		t.Fatal("unresolvable destination directory accepted")
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("src not removed on Abs error: %v", err)
	}
}
