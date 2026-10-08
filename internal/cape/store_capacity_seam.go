package cape

import (
	"os"
	"sync/atomic"
)

// storeCapacityOverride is a test-only switch. False (the production state)
// means OpenStore measures the dedicated ext4/XFS volume via filesystemCapacity.
var storeCapacityOverride atomic.Bool

// seamCapacity reports a fixed, valid physical capacity (PhysicalLimit total and
// available, 4096-byte blocks), the same value the in-package fixtures use.
func seamCapacity(*os.File, string) (capacity, error) {
	return capacity{PhysicalLimit, PhysicalLimit, 4096}, nil
}

// openStoreCapacity returns the capacity hook OpenStore uses.
func openStoreCapacity() func(*os.File, string) (capacity, error) {
	if storeCapacityOverride.Load() {
		return seamCapacity
	}
	return filesystemCapacity
}

// SetStoreCapacityForTest makes OpenStore skip the dedicated-volume probe and
// use a fixed valid capacity until the returned restore func runs. It exists so
// cross-package tests can open a real Store on a t.TempDir() without a
// privileged ext4/XFS mount. Every other OpenStore check (private 0700 root
// owned by the euid, lock, sqlite pragmas, StateReserve) stays in force.
// Production code never calls it. The switch is a single atomic flag; restore
// puts back the value seen at call time, so nested use unwinds correctly.
func SetStoreCapacityForTest() (restore func()) {
	prev := storeCapacityOverride.Swap(true)
	return func() { storeCapacityOverride.Store(prev) }
}
