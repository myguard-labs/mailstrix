package atomicio

import (
	"os"
	"path/filepath"
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
