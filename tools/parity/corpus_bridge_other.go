//go:build !linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

func configureBridgeGroup(_ *exec.Cmd) error {
	return errors.New("ClamAV bridge requires Linux process groups")
}

func runBridgeGroup(_ context.Context, cmd *exec.Cmd) (bool, error, error) {
	return true, cmd.Run(), nil
}

func openCorpusConfig(_ string) (*os.File, error) {
	return nil, errors.New("corpus comparison requires Linux")
}
