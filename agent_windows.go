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

func (cmd *RunCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	return fmt.Errorf("not implemented on Windows")
}

func (cmd *StartCmd) Run(config *Config) error {
	return fmt.Errorf("not implemented on Windows")
}

func (cmd *StopCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	return fmt.Errorf("not implemented on Windows")
}

func startAgentProcess(agentSocket, identitiesText string) error {
	return fmt.Errorf("not implemented on Windows")
}

func pingAgent(agentSocket string) error {
	return fmt.Errorf("not implemented on Windows")
}

func decryptWithAgent(agentSocket string, data []byte) (string, error) {
	return "", fmt.Errorf("not implemented on Windows")
}
