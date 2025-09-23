//go:build !windows

// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// LockMemory attempts to lock the process's entire virtual address space into RAM.
// This prevents sensitive data from being swapped to disk.
func LockMemory() error {
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("failed to lock memory: %v", err)
	}

	return nil
}
