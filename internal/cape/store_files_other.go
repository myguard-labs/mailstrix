//go:build !linux

package cape

import "os"

// Durable CAPE storage currently supports Linux local ext4/XFS volumes only.
// Other targets still build, and fail closed when opening the optional store.
func openPrivateDirectory(string) (*os.File, error)         { return nil, ErrStoreUnavailable }
func openStoreFile(*os.File, string, int) (*os.File, error) { return nil, ErrStoreUnavailable }
func openSpool(*os.File) (*os.File, error)                  { return nil, ErrStoreUnavailable }
func lockStore(*os.File) (*os.File, error)                  { return nil, ErrStoreUnavailable }
func databasePath(*os.File) string                          { return "" }
func validateDatabaseFiles(*os.File) error                  { return ErrStoreUnavailable }
func removeStoreFile(*os.File, string) error                { return ErrStoreUnavailable }
func renameStoreFile(*os.File, string, string) error        { return ErrStoreUnavailable }
func filesystemCapacity(*os.File, string) (capacity, error) { return capacity{}, ErrStoreUnavailable }
