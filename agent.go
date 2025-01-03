//go:build !windows

// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
	"github.com/tidwall/redcon"
	"github.com/valkey-io/valkey-go"
)

var defaultSocket = filepath.Join(defaultCacheDir, agentSocketPath)

func (cmd *RestartCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	_, _ = messageAgent(config.Socket, "SHUTDOWN")

	identitiesText, err := decryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	return startAgentProcess(config.Socket, identitiesText)
}

func (cmd *RunCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	return runAgent(config.Socket)
}

func (cmd *StartCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	if err := pingAgent(config.Socket); err == nil {
		return fmt.Errorf("found agent responding on socket")
	}

	identitiesText, err := decryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	return startAgentProcess(config.Socket, identitiesText)
}

func (cmd *StatusCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	err := pingAgent(config.Socket)
	if err == nil {
		fmt.Println("Ping successful")
		os.Exit(0)
	} else {
		fmt.Println("Failed to ping agent")
		os.Exit(1)
	}

	return nil
}

func (cmd *StopCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	_, err := messageAgent(config.Socket, "SHUTDOWN")
	return err
}

func startAgentProcess(agentSocket, identitiesText string) error {
	// The agent is the same executable.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	cmd := exec.Command(exe, "agent", "run", "--socket", agentSocket)

	// Start the process in the background.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %v", err)
	}

	_ = os.Remove(agentSocket)
	// Don't wait for the process to finish.
	go func() {
		_ = cmd.Wait()
	}()

	if err := waitUntilAvailable(agentSocket, waitForSocket); err != nil {
		return fmt.Errorf("timed out waiting for agent socket")
	}

	_, err = messageAgent(agentSocket, "IDENTITIES", identitiesText)
	return err
}

func runAgent(agentSocket string) error {
	if err := pingAgent(agentSocket); err == nil {
		return fmt.Errorf("found agent responding on socket")
	}

	socketDir := filepath.Dir(agentSocket)
	if err := os.MkdirAll(socketDir, dirPerms); err != nil {
		return fmt.Errorf("failed to create socket directory: %v", err)
	}

	os.Remove(agentSocket)

	identities := []age.Identity{}
	srv := redcon.NewServerNetwork(
		"unix",
		agentSocket,
		func(conn redcon.Conn, cmd redcon.Command) {
			switch strings.ToUpper(string(cmd.Args[0])) {

			case "DECRYPT":
				if len(cmd.Args) != 2 {
					conn.WriteError(`ERR wrong number of arguments for "decrypt" command`)
					return
				}

				encryptedData := cmd.Args[1]

				// Decrypt the data.
				reader := bytes.NewReader(encryptedData)
				decryptedReader, err := wrapDecrypt(reader, identities...)
				if err != nil {
					conn.WriteError("ERR failed to decrypt: " + err.Error())
					return
				}

				// Read decrypted data.
				decryptedData, err := io.ReadAll(decryptedReader)
				if err != nil {
					conn.WriteError("ERR failed to read decrypted data: " + err.Error())
					return
				}

				conn.WriteBulk(decryptedData)

			case "IDENTITIES":
				if len(cmd.Args) != 2 {
					conn.WriteError(`ERR wrong number of arguments for "identities" command`)
					return
				}

				identitiesText := string(cmd.Args[1])

				newIdentities, err := age.ParseIdentities(strings.NewReader(identitiesText))
				if err != nil {
					conn.WriteError(`ERR failed to parse identities`)
					return
				}
				identities = newIdentities

				conn.WriteString("OK")

			case "PING":
				conn.WriteString("PONG")

			case "SHUTDOWN":
				conn.WriteString("OK")
				conn.Close()

				os.Exit(0)

			default:
				conn.WriteError(fmt.Sprintf("ERR unknown command %q", cmd.Args[0]))
			}
		},
		nil,
		nil,
	)

	errc := make(chan error)

	go func() {
		if err := <-errc; err != nil {
			return
		}

		if err := os.Chmod(agentSocket, filePerms); err != nil {
			exitWithError("failed to set permissions on agent socket: %v", err)
		}
	}()

	return srv.ListenServeAndSignal(errc)
}

func messageAgent(agentSocket string, args ...string) (string, error) {
	// Check socket security.
	if err := checkSocketSecurity(agentSocket); err != nil {
		return "", fmt.Errorf("socket security check failed: %v", err)
	}

	// Connect to the server.
	opts, err := valkey.ParseURL("unix://" + agentSocket)
	if err != nil {
		return "", fmt.Errorf("failed to parse socket URL: %v", err)
	}
	opts.DisableCache = true

	client, err := valkey.NewClient(opts)
	if err != nil {
		return "", fmt.Errorf("failed to create Valkey client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Try a PING to verify the connection.
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		return "", fmt.Errorf("failed to ping agent: %v", err)
	}
	if len(args) == 0 {
		return "", nil
	}

	// Send the command.
	cmd := client.Do(ctx, client.B().Arbitrary(args...).Build())
	if err := cmd.Error(); err != nil {
		return "", fmt.Errorf("command failed: %v", err)
	}

	result, err := cmd.ToString()
	if err != nil {
		return "", fmt.Errorf("failed to get result: %v", err)
	}

	return string(result), nil
}

func pingAgent(agentSocket string) error {
	_, err := messageAgent(agentSocket)
	return err
}

func decryptWithAgent(agentSocket string, data []byte) (string, error) {
	return messageAgent(agentSocket, "DECRYPT", valkey.BinaryString(data))
}

func checkSocketSecurity(agentSocket string) error {
	info, err := os.Stat(agentSocket)
	if err != nil {
		return fmt.Errorf("failed to stat socket: %v", err)
	}

	// Check socket permissions.
	if info.Mode().Perm() != filePerms {
		return fmt.Errorf("incorrect socket permissions: %v", info.Mode().Perm())
	}

	// Check socket ownership.
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get socket system info")
	}

	if stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("socket owned by wrong user: %d", stat.Uid)
	}

	return nil
}
