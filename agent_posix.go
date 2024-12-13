//go:build !windows

// pago - a command-line password manager.
//
// License: MIT.
// See the file `LICENSE`.

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

func (cmd *AgentCmd) Run(config *Config) error {
	agentPassword := os.Getenv(agentPasswordEnv)
	if agentPassword == "" {
		return fmt.Errorf("`%v` environment variable not set", agentPasswordEnv)
	}

	return runAgent(config.Socket, agentPassword)
}

func startAgent(agentSocket, password string) error {
	// The agent is the same executable.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	cmd := exec.Command(exe, "agent")
	cmd.Env = append(os.Environ(), agentPasswordEnv+"="+password, socketEnv+"="+agentSocket)

	// Start the process in the background.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %v", err)
	}

	_ = os.Remove(agentSocket)
	// Don't wait for the process to finish.
	go cmd.Wait()

	if err := waitUntilAvailable(agentSocket, waitForSocket); err != nil {
		return fmt.Errorf("timed out waiting for agent socket")
	}

	return nil
}

func runAgent(agentSocket string, password string) error {
	socketDir := filepath.Dir(agentSocket)
	if err := os.MkdirAll(socketDir, dirPerms); err != nil {
		return fmt.Errorf("failed to create socket directory: %v", err)
	}

	os.Remove(agentSocket)

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

				// Create an identity from the password.
				identity, err := age.NewScryptIdentity(password)
				if err != nil {
					conn.WriteError("ERR failed to create identity: " + err.Error())
					return
				}

				// Decrypt the data.
				reader := bytes.NewReader(encryptedData)
				decryptedReader, err := wrapDecrypt(reader, identity)
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

			case "PING":
				conn.WriteString("PONG")

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

func tryAgent(socketPath string, data []byte) (string, error) {
	// Check socket security.
	if err := checkSocketSecurity(socketPath); err != nil {
		return "", fmt.Errorf("socket security check failed: %v", err)
	}

	// Connect to the server.
	opts, err := valkey.ParseURL("unix://" + socketPath)
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

	// Send the decrypt command.
	cmd := client.Do(ctx, client.B().Arbitrary("DECRYPT", valkey.BinaryString(data)).Build())
	if err := cmd.Error(); err != nil {
		return "", fmt.Errorf("DECRYPT command failed: %v", err)
	}

	result, err := cmd.ToString()
	if err != nil {
		return "", fmt.Errorf("failed to get result: %v", err)
	}

	return string(result), nil
}

func checkSocketSecurity(socketPath string) error {
	info, err := os.Stat(socketPath)
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
