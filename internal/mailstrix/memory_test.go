package mailstrix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemorySampler(t *testing.T) {
	if procRSSBytes() <= 0 {
		t.Fatal("live RSS must be positive")
	}
	m := goMemStats()
	if m.HeapAlloc == 0 || m.HeapInuse < m.HeapAlloc || m.Sys < m.HeapInuse || m.Sys < m.HeapReleased {
		t.Fatalf("implausible memory stats: %+v", m)
	}
	path := filepath.Join(t.TempDir(), "statm")
	if procRSSBytesFrom(path) != 0 {
		t.Fatal("unreadable RSS must be unknown")
	}
	for _, value := range []string{"", "1", "1 nope", "1 -1", "1 0", "1 9223372036854775807", "1 9223372036854775808"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if procRSSBytesFrom(path) != 0 {
			t.Fatalf("malformed RSS %q must be unknown", value)
		}
	}
	if err := os.WriteFile(path, []byte("99 2 3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := procRSSBytesFrom(path); got != 2*int64(os.Getpagesize()) {
		t.Fatalf("RSS=%d", got)
	}
	for _, value := range []string{"", "max", "invalid", "0", "-1", "4611686018427387904"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if cgroupMemLimitBytesFrom(path) != 0 {
			t.Fatalf("unknown cgroup %q must be zero", value)
		}
	}
	if cgroupMemLimitBytesFrom(path+"missing") != 0 {
		t.Fatal("missing cgroup must be zero")
	}
	if err := os.WriteFile(path, []byte("1048577"), 0600); err != nil {
		t.Fatal(err)
	}
	if cgroupMemLimitBytesFrom(path+"missing", path) != 1048577 || cgroupMemLimitMiBFrom(path) != 1 {
		t.Fatal("byte precision or MiB compatibility lost")
	}
}
