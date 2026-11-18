//go:build !linux

package main

import (
	"os"
	"os/exec"
)

var notifySignals = []os.Signal{os.Interrupt}

func setSocketMark(fd uintptr, mark int) error {
	return nil
}

func raiseFileLimits() {
}

func configureProcessCredentials(cmd *exec.Cmd, gid uint32) {
}
