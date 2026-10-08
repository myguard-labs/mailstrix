package ci_test

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/cape"
)

func capeSeamConfig(t *testing.T) cape.StoreConfig {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return cape.StoreConfig{Directory: dir, Tenants: []string{"alpha"}, MaxAttachment: 32}
}

func openSeamStore(t *testing.T, cfg cape.StoreConfig) error {
	t.Helper()
	s, err := cape.OpenStore(context.Background(), cfg)
	if err == nil {
		if cerr := s.Close(); cerr != nil {
			t.Fatal(cerr)
		}
	}
	return err
}

// The capacity seam must default to production behaviour (a temp dir is not a
// dedicated ext4/XFS mount), open when set, and fully restore.
func TestCAPEStoreCapacitySeam(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cape store is linux-only")
	}
	cfg := capeSeamConfig(t)
	if err := openSeamStore(t, cfg); !errors.Is(err, cape.ErrStoreUnavailable) {
		t.Fatalf("default OpenStore on a plain directory: got %v, want ErrStoreUnavailable", err)
	}
	restore := cape.SetStoreCapacityForTest()
	t.Cleanup(restore) // idempotent; clears the global override if an assertion fails first
	if err := openSeamStore(t, cfg); err != nil {
		t.Fatalf("OpenStore with seam set: %v", err)
	}
	// Other OpenStore checks stay in force with the seam set.
	loose := capeSeamConfig(t)
	if err := os.Chmod(loose.Directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := openSeamStore(t, loose); err == nil {
		t.Fatal("seam bypassed the private-directory check")
	}
	missing := cfg
	missing.Directory = cfg.Directory + "/absent"
	if err := openSeamStore(t, missing); err == nil {
		t.Fatal("seam bypassed the directory-exists check")
	}
	restore()
	if err := openSeamStore(t, cfg); !errors.Is(err, cape.ErrStoreUnavailable) {
		t.Fatalf("OpenStore after restore: got %v, want ErrStoreUnavailable", err)
	}
}

// Nested use unwinds to the previous state, not to unset.
func TestCAPEStoreCapacitySeamNested(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cape store is linux-only")
	}
	cfg := capeSeamConfig(t)
	outer := cape.SetStoreCapacityForTest()
	t.Cleanup(outer) // runs last (LIFO), leaving the override unset on failure
	inner := cape.SetStoreCapacityForTest()
	t.Cleanup(inner)
	inner()
	if err := openSeamStore(t, cfg); err != nil {
		t.Fatalf("inner restore cleared the outer override: %v", err)
	}
	outer()
	if err := openSeamStore(t, cfg); !errors.Is(err, cape.ErrStoreUnavailable) {
		t.Fatalf("outer restore left the override set: %v", err)
	}
}
