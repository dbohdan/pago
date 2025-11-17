// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dbohdan.com/pago"
	"dbohdan.com/pago/crypto"

	"filippo.io/age"
	"github.com/tidwall/redcon"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/sys/unix"
)

const umask = 0o177

// StartProcess launches the agent executable in the background.
// It waits for the agent to become available and then sends it the identities.
func StartProcess(executable string, expire time.Duration, memlock bool, socket, identitiesText string) error {
	memlockFlag := "--memlock"
	if !memlock {
		memlockFlag = "--no-memlock"
	}

	//nolint:gosec
	cmd := exec.Command(executable, "run", memlockFlag, "--socket", socket, "--expire", expire.String())

	// Start the process in the background.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	_ = os.Remove(socket)
	// Don't wait for the process to finish.
	go func() {
		_ = cmd.Wait()
	}()

	if err := pago.WaitUntilAvailable(socket, pago.WaitForSocket); err != nil {
		if cmd.ProcessState.Exited() {
			code := cmd.ProcessState.ExitCode()
			message := ""

			if code == pago.ExitMemlockError {
				message = ": failed to lock memory"
			}

			return fmt.Errorf("agent process exited with code %v%v", code, message)
		}

		return fmt.Errorf("timed out waiting for agent socket: %w", err)
	}

	_, err := Message(socket, "IDENTITIES", identitiesText)
	if err != nil {
		return fmt.Errorf("failed to send identities to agent: %w", err)
	}

	return nil
}

// Run starts the agent server, listening for commands on the specified Unix socket.
// It handles decryption requests and manages identities.
func Run(socket string, expire time.Duration) error {
	if err := Ping(socket); err == nil {
		return errors.New("found agent responding on socket")
	}

	socketDir := filepath.Dir(socket)
	if err := os.MkdirAll(socketDir, pago.DirPerms); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove any stale socket file before creating a new one.
	os.Remove(socket)

	// Set umask to ensure the socket is created with correct permissions (0o600).
	oldUmask := unix.Umask(umask)
	defer unix.Umask(oldUmask)

	var timer *time.Timer
	identities := []age.Identity{}
	srv := redcon.NewServerNetwork(
		"unix",
		socket,
		func(conn redcon.Conn, cmd redcon.Command) {
			cmdName := strings.ToUpper(string(cmd.Args[0]))

			if timer != nil && cmdName != "PING" && cmdName != "SHUTDOWN" {
				timer.Reset(expire)
			}

			switch cmdName {
			case "DECRYPT":
				//nolint:mnd
				if len(cmd.Args) != 2 {
					conn.WriteError(`ERR wrong number of arguments for "decrypt" command`)

					return
				}

				encryptedData := cmd.Args[1]

				// Decrypt the data.
				reader := bytes.NewReader(encryptedData)

				decryptedReader, err := crypto.WrapDecrypt(reader, identities...)
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
				//nolint:mnd
				if len(cmd.Args) != 2 {
					conn.WriteError(`ERR wrong number of arguments for "identities" command`)

					return
				}

				identitiesText := string(cmd.Args[1])

				newIdentities, err := crypto.ParseIdentities(identitiesText)
				if err != nil {
					conn.WriteError(`ERR failed to parse identities`)

					return
				}

				identities = newIdentities

				conn.WriteString("OK")

			case "PING":
				conn.WriteString("PONG")

			case "SHUTDOWN":
				if timer != nil {
					timer.Stop()
				}

				conn.WriteString("OK")
				conn.Close()

				os.Exit(pago.ExitOK)

			default:
				conn.WriteError(fmt.Sprintf("ERR unknown command %q", cmd.Args[0]))
			}
		},
		nil,
		nil,
	)

	if expire > 0 {
		timer = time.AfterFunc(expire, func() {
			srv.Close()
		})
	}

	err := srv.ListenServeAndSignal(nil)
	if err != nil && strings.Contains(err.Error(), "server closed") {
		return nil
	}

	return fmt.Errorf("agent server failed: %w", err)
}

func Message(socket string, args ...string) ([]byte, error) {
	socket, err := filepath.Abs(socket)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve socket path: %w", err)
	}

	// Check socket security.
	if err = checkSocketSecurity(socket); err != nil {
		return nil, fmt.Errorf("socket security check failed: %w", err)
	}

	// Connect to the server.
	opts, err := valkey.ParseURL("unix://" + socket)
	if err != nil {
		return nil, fmt.Errorf("failed to parse socket URL: %w", err)
	}

	opts.DisableCache = true

	client, err := valkey.NewClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Valkey client: %w", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Try a PING to verify the connection.
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		return nil, fmt.Errorf("failed to ping agent: %w", err)
	}

	if len(args) == 0 {
		return nil, nil
	}

	// Send the command.
	cmd := client.Do(ctx, client.B().Arbitrary(args...).Build())
	if err := cmd.Error(); err != nil {
		return nil, fmt.Errorf("command failed: %w", err)
	}

	result, err := cmd.ToString()
	if err != nil {
		return nil, fmt.Errorf("failed to get result: %w", err)
	}

	return []byte(result), nil
}

// Ping sends a PING command to the agent to check if it's running and responsive.
func Ping(socket string) error {
	_, err := Message(socket)

	return err
}

// Decrypt sends a DECRYPT command to the agent to decrypt the provided data.
func Decrypt(socket string, data []byte) ([]byte, error) {
	return Message(socket, "DECRYPT", valkey.BinaryString(data))
}

// checkSocketSecurity verifies that the Unix socket has the correct permissions and ownership.
func checkSocketSecurity(socket string) error {
	info, err := os.Stat(socket)
	if err != nil {
		return fmt.Errorf("failed to stat socket: %w", err)
	}

	// Check if it's actually a Unix domain socket.
	if (info.Mode() & os.ModeSocket) == 0 {
		return errors.New("path is not a Unix domain socket")
	}

	// Check socket permissions (must be 0o600).
	if info.Mode().Perm() != pago.FilePerms {
		return fmt.Errorf("incorrect socket permissions: %v", info.Mode().Perm())
	}

	// Check socket ownership (must be owned by the current user).
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("failed to get socket system info")
	}

	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("socket owned by wrong user: %d", stat.Uid)
	}

	return nil
}
