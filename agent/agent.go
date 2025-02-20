// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package agent

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

	"dbohdan.com/pago"
	"dbohdan.com/pago/crypto"

	"filippo.io/age"
	"github.com/tidwall/redcon"
	"github.com/valkey-io/valkey-go"
)

func StartProcess(executable string, mlock bool, socket, identitiesText string) error {
	mlockFlag := "--mlock"
	if !mlock {
		mlockFlag = "--no-mlock"
	}

	cmd := exec.Command(executable, "run", mlockFlag, "--socket", socket)

	// Start the process in the background.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %v", err)
	}

	_ = os.Remove(socket)
	// Don't wait for the process to finish.
	go func() {
		_ = cmd.Wait()
	}()

	if err := pago.WaitUntilAvailable(socket, pago.WaitForSocket); err != nil {
		return fmt.Errorf("timed out waiting for agent socket")
	}

	_, err := Message(socket, "IDENTITIES", identitiesText)
	return err
}

func Run(socket string) error {
	if err := Ping(socket); err == nil {
		return fmt.Errorf("found agent responding on socket")
	}

	socketDir := filepath.Dir(socket)
	if err := os.MkdirAll(socketDir, pago.DirPerms); err != nil {
		return fmt.Errorf("failed to create socket directory: %v", err)
	}

	os.Remove(socket)

	identities := []age.Identity{}
	srv := redcon.NewServerNetwork(
		"unix",
		socket,
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

		if err := os.Chmod(socket, pago.FilePerms); err != nil {
			pago.ExitWithError("failed to set permissions on agent socket: %v", err)
		}
	}()

	return srv.ListenServeAndSignal(errc)
}

func Message(socket string, args ...string) (string, error) {
	// Check socket security.
	if err := checkSocketSecurity(socket); err != nil {
		return "", fmt.Errorf("socket security check failed: %v", err)
	}

	// Connect to the server.
	opts, err := valkey.ParseURL("unix://" + socket)
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

func Ping(socket string) error {
	_, err := Message(socket)
	return err
}

func Decrypt(socket string, data []byte) (string, error) {
	return Message(socket, "DECRYPT", valkey.BinaryString(data))
}

func checkSocketSecurity(socket string) error {
	info, err := os.Stat(socket)
	if err != nil {
		return fmt.Errorf("failed to stat socket: %v", err)
	}

	// Check socket permissions.
	if info.Mode().Perm() != pago.FilePerms {
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
