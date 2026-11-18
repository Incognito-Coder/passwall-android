//go:build linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

var notifySignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}

func setSocketMark(fd uintptr, mark int) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMarkOpt, mark)
}

func raiseFileLimits() {
	for _, limit := range []uint64{1048576, 262144, 65536} {
		var rLimit syscall.Rlimit
		rLimit.Max = limit
		rLimit.Cur = limit
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
			return
		}
	}
}

func configureProcessCredentials(cmd *exec.Cmd, gid uint32) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: gid,
		},
	}
}
