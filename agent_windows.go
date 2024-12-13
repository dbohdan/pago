//go:build windows

// pago - a command-line password manager.
//
// License: MIT.
// See the file `LICENSE`.

package main

import (
	"fmt"
)

var defaultSocket = ""

func (cmd *AgentCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	return fmt.Errorf("not implemented on Windows")
}

func startAgent(agentSocket, password string) error {
	return fmt.Errorf("not implemented on Windows")
}

func tryAgent(socketPath string, data []byte) (string, error) {
	return "", fmt.Errorf("not implemented on Windows")
}
