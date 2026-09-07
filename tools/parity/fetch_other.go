//go:build !linux

package main

import (
	"errors"
	"os"
)

func fetchPlatformSupported() bool              { return false }
func openFetchInput(_ string) (*os.File, error) { return nil, errors.New("unsupported fetch platform") }
func publishFetch(_ *os.Root, _, _ string) error {
	return errors.New("unsupported publication platform")
}
