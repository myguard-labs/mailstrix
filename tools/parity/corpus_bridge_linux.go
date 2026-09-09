package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var signalBridgeGroup = func(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}

func configureBridgeGroup(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	// finishBridgeGroup observes cancellation and exclusively owns group
	// signalling while the leader pins its PID/PGID. The removed custom
	// asynchronous raw-PGID callback could outlive reaping and signal a recycled
	// group.
	cmd.Cancel = nil
	return nil
}

func openCorpusConfig(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func waitBridgeExit(ctx context.Context, pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if err == nil && info.Signo != 0 {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func bridgeGroupQuiescent(pid int) (bool, error) {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return false, err
		}
		found := false
		for _, entry := range entries {
			member, err := strconv.Atoi(entry.Name())
			if err != nil || member == pid {
				continue
			}
			raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			if err != nil {
				return false, err
			}
			closing := bytes.LastIndexByte(raw, ')')
			if closing < 0 {
				return false, errors.New("malformed process status while checking bridge group")
			}
			fields := strings.Fields(string(raw[closing+1:]))
			if len(fields) < 3 {
				return false, errors.New("malformed process status while checking bridge group")
			}
			group, err := strconv.Atoi(fields[2])
			if err != nil {
				return false, err
			}
			if group == pid {
				found = true
				break
			}
		}
		if !found {
			return true, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false, errors.New("ClamAV bridge process group absence unconfirmed")
}

func runBridgeGroup(ctx context.Context, cmd *exec.Cmd) (bool, error, error) {
	if err := cmd.Start(); err != nil {
		return true, err, nil
	}
	return finishBridgeGroup(ctx, cmd)
}

func finishBridgeGroup(ctx context.Context, cmd *exec.Cmd) (bool, error, error) {
	pid := cmd.Process.Pid
	observeErr := waitBridgeExit(ctx, pid)
	// The unreaped leader still owns pid and pgid here, so this signal cannot
	// target a recycled process group even after an early bridge exit.
	signalErr := signalBridgeGroup(pid)
	if errors.Is(signalErr, syscall.ESRCH) {
		signalErr = nil
	}
	// Keep the zombie leader unreaped while /proc proves that no other process
	// retains this group. A killed descendant may remain a zombie until its own
	// parent reaps it, which is terminal uncertainty rather than ownership.
	quiescent, quiescenceErr := bridgeGroupQuiescent(pid)
	waitErr := cmd.Wait()
	// Quiescence established that the pinned leader was the sole group member;
	// reaping it removes the group. Never probe the numeric PGID after Wait,
	// when the kernel is free to reuse it for an unrelated process.
	return quiescent, errors.Join(observeErr, waitErr), errors.Join(signalErr, quiescenceErr)
}
