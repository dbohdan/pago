// pago - a simple password manager.
//
// This program is a fork of pash translated to Go
// and switched from GPG to age public-key encryption.
// It requires a *nix operating system with age installed.
// See https://github.com/FiloSottile/age.
// Original repository: https://github.com/dylanaraps/pash (archived).
//
// ==============================================================================
//
// The MIT License (MIT)
//
// Copyright (c) 2016-2019 Dylan Araps
// Copyright (c) 2024 D. Bohdan
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// ==============================================================================

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/adrg/xdg"
	"github.com/alecthomas/kong"
	"github.com/tidwall/redcon"
	"github.com/valkey-io/valkey-go"
	"github.com/xlab/treeprint"
	"golang.design/x/clipboard"
)

type CLI struct {
	// Global options.
	Dir     string `env:"PAGO_DIR" default:"${defaultDataDir}" help:"Store location"`
	Length  int    `env:"PAGO_LENGTH" default:"20" help:"Password length"`
	Pattern string `env:"PAGO_PATTERN" default:"[A-Za-z0-9]" help:"Password pattern (regular expression)"`
	Socket  string `env:"PAGO_SOCK" default:"${defaultSocket}" help:"Agent socket path (blank to disable)"`
	Timeout int    `env:"PAGO_TIMEOUT" default:"30" help:"Clipboard timeout ('off' to disable)"`

	// Commands.
	Add      AddCmd      `cmd:"" aliases:"a" help:"Create new password entry"`
	Agent    AgentCmd    `cmd:"" hidden:"" help:"Run the agent process"`
	Copy     CopyCmd     `cmd:"" aliases:"c" help:"Copy entry to clipboard"`
	Delete   DeleteCmd   `cmd:"" aliases:"d,del" help:"Delete password entry"`
	Generate GenerateCmd `cmd:"" aliases:"g,gen" help:"Generate and print password"`
	List     ListCmd     `cmd:"" aliases:"l" help:"List all entries"`
	Show     ShowCmd     `cmd:"" aliases:"s" help:"Show password for entry"`
	Tree     TreeCmd     `cmd:"" aliases:"t" help:"List all entries as tree"`
	Version  VersionCmd  `cmd:"" aliases:"v,ver" help:"Print version number and exit"`
}

type Config struct {
	AgentSocket string
	DataDir     string
	Home        string
	Identities  string
	Length      int
	Pattern     regexp.Regexp
	Recipients  string
	Store       string
	Timeout     time.Duration
}

const (
	ageExt          = ".age"
	agentSocketPath = "socket"
	defaultLength   = "20"
	defaultPattern  = "[A-Za-z0-9]"
	defaultTimeout  = "30"
	dirPerms        = 0o700
	maxStepsPerChar = 500
	socketPerms     = 0o600
	storePath       = "store"
	version         = "0.5.0"
	waitForSocket   = 3 * time.Second
)

var (
	defaultCacheDir = filepath.Join(xdg.CacheHome, "pago")
	defaultDataDir  = filepath.Join(xdg.DataHome, "pago")
)

type AddCmd struct {
	Name string `arg:"" help:"Name of the password entry"`
}

func (cmd *AddCmd) Run(config *Config) error {
	if passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("password file already exists: %v", cmd.Name)
	}

	generate, err := askYesNo("Generate a password?")
	if err != nil {
		return err
	}

	password := ""
	if generate {
		password, err = generatePassword(config.Pattern, config.Length)
	} else {
		password, err = readNewPassword()
	}
	if err != nil {
		return err
	}

	if err := savePassword(config.Recipients, config.Store, cmd.Name, password); err != nil {
		return err
	}
	fmt.Println("Password saved.")
	return nil
}

type AgentCmd struct{}

func (cmd *AgentCmd) Run(config *Config) error {
	agentPassword := os.Getenv("PAGO_AGENT_PASSWORD")
	if agentPassword == "" {
		return fmt.Errorf("'PAGO_AGENT_PASSWORD' environment variable not set")
	}

	return runAgent(config.AgentSocket, agentPassword)
}

type CopyCmd struct {
	Name string `arg:"" help:"Name of the password entry"`
}

func (cmd *CopyCmd) Run(config *Config) error {
	if !passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("password file doesn't exist: %v", cmd.Name)
	}

	password, err := decryptPassword(config.AgentSocket, config.Identities, config.Store, cmd.Name)
	if err != nil {
		return err
	}

	if err := clipboard.Init(); err != nil {
		return fmt.Errorf("failed to initialize clipboard: %v", err)
	}

	clipboard.Write(clipboard.FmtText, []byte(password))
	fmt.Println("Password copied to clipboard.")

	if config.Timeout > 0 {
		time.Sleep(config.Timeout)
		clipboard.Write(clipboard.FmtText, []byte(""))
	}
	return nil
}

type DeleteCmd struct {
	Name string `arg:"" help:"Name of the password entry"`
}

func (cmd *DeleteCmd) Run(config *Config) error {
	if !passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("password file doesn't exist: %v", cmd.Name)
	}

	return deletePassword(config.Store, cmd.Name)
}

type GenerateCmd struct{}

func (cmd *GenerateCmd) Run(config *Config) error {
	password, err := generatePassword(config.Pattern, config.Length)
	if err != nil {
		return err
	}
	fmt.Println(password)
	return nil
}

type ListCmd struct{}

func (cmd *ListCmd) Run(config *Config) error {
	list, err := listFiles(config.Store, func(name string, info os.FileInfo) (bool, string) {
		if info.IsDir() || !strings.HasSuffix(info.Name(), ageExt) || strings.HasPrefix(info.Name(), ".") {
			return false, ""
		}

		displayName := name
		displayName = strings.TrimPrefix(displayName, config.Store)
		displayName = strings.TrimPrefix(displayName, "/")
		displayName = strings.TrimSuffix(displayName, ageExt)

		return true, displayName
	})
	if err != nil {
		return fmt.Errorf("failed to list password files: %v", err)
	}

	fmt.Println(strings.Join(list, "\n"))
	return nil
}

type ShowCmd struct {
	Name string `arg:"" help:"Name of the password entry"`
}

func (cmd *ShowCmd) Run(config *Config) error {
	if !passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("password file doesn't exist: %v", cmd.Name)
	}

	return showPassword(config.AgentSocket, config.Identities, config.Store, cmd.Name)
}

type TreeCmd struct{}

func (cmd *TreeCmd) Run(config *Config) error {
	tree, err := dirTree(config.Store, func(name string, info os.FileInfo) (bool, string) {
		if strings.HasPrefix(info.Name(), ".") {
			return false, ""
		}

		displayName := strings.TrimSuffix(info.Name(), ageExt)
		if info.IsDir() {
			displayName += "/"
		}

		return true, displayName
	})
	if err != nil {
		return fmt.Errorf("failed to build tree: %v", err)
	}

	fmt.Print(tree)
	return nil
}

type VersionCmd struct{}

func (cmd *VersionCmd) Run(config *Config) error {
	fmt.Println(version)
	return nil
}

// Initialize configuration using the CLI as the main input.
func initConfig(cli *CLI) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	pattern, err := regexp.Compile(cli.Pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %v", err)
	}

	store := filepath.Join(cli.Dir, storePath)

	config := Config{
		AgentSocket: cli.Socket,
		DataDir:     cli.Dir,
		Home:        home,
		Identities:  filepath.Join(cli.Dir, "identities"),
		Length:      cli.Length,
		Pattern:     *pattern,
		Recipients:  filepath.Join(store, ".age-recipients"),
		Store:       store,
		Timeout:     time.Duration(cli.Timeout) * time.Second,
	}

	return &config, nil
}


func printError(format string, value any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", value)
}

func exitWithError(format string, value any) {
	printError(format, value)
	os.Exit(1)
}

func exitWithWrongUsage(format string, value any) {
	printError(format, value)
	os.Exit(2)
}

// Read a password from the terminal without echo.
func secureRead(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}

	return string(password), nil
}

func askYesNo(prompt string) (bool, error) {
	fmt.Printf("%s [y/n]: ", prompt)

	// Save the terminal state to restore later.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false, fmt.Errorf("failed to make terminal raw: %v", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Read a single byte from the terminal.
	var input [1]byte
	_, err = os.Stdin.Read(input[:])
	if err != nil {
		return false, fmt.Errorf("failed to read input: %v", err)
	}

	term.Restore(int(os.Stdin.Fd()), oldState)
	fmt.Println()

	answer := strings.ToLower(string(input[0]))
	return answer == "y", nil
}

// Generate a random password where each character matches a regular expression.
func generatePassword(pattern regexp.Regexp, length int) (string, error) {
	var password strings.Builder

	steps := 0
	for password.Len() < length {
		b := make([]byte, 1)
		_, err := rand.Read(b)
		if err != nil {
			return "", err
		}

		char := string(b[0])
		if pattern.MatchString(char) {
			password.WriteString(char)
		}

		steps++
		if steps == length*maxStepsPerChar {
			return "", fmt.Errorf("failed to generate password after %d steps", steps)
		}
	}

	return password.String(), nil
}

// Ask the user to input a password twice.
func readNewPassword() (string, error) {
	pass, err := secureRead("Enter password: ")
	if err != nil {
		return "", err
	}

	if pass == "" {
		return "", fmt.Errorf("empty password")
	}

	pass2, err := secureRead("Enter password (again): ")
	if err != nil {
		return "", err
	}

	if pass != pass2 {
		return "", fmt.Errorf("passwords do not match")
	}

	return pass, nil
}

// Map a password's name to its file path.
func passwordFile(passwordStore, name string) string {
	return filepath.Join(passwordStore, name+ageExt)
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}

func passwordExists(passwordStore, name string) bool {
	return pathExists(passwordFile(passwordStore, name))
}

// Parse the entire text of an age recipients file.
func parseRecipients(contents string) ([]age.Recipient, error) {
	var recips []age.Recipient

	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		recipient, err := age.ParseX25519Recipient(line)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient: %v", err)
		}

		recips = append(recips, recipient)
	}

	return recips, nil
}

// Encrypt the password and save it to a file.
func savePassword(recipients, passwordStore, name, password string) error {
	recipientsData, err := os.ReadFile(recipients)
	if err != nil {
		return fmt.Errorf("failed to read recipients file: %v", err)
	}

	recips, err := parseRecipients(string(recipientsData))
	if err != nil {
		return err
	}

	dest := passwordFile(passwordStore, name)
	err = os.MkdirAll(filepath.Dir(dest), dirPerms)

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()

	w, err := age.Encrypt(f, recips...)
	if err != nil {
		return fmt.Errorf("failed to create encryption writer: %v", err)
	}

	if _, err := io.WriteString(w, password); err != nil {
		return fmt.Errorf("failed to encrypt: %v", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finish encryption: %v", err)
	}

	return nil
}

// Returns a reader that can handle both armored and binary age files.
func wrapDecrypt(r io.Reader, identities ...age.Identity) (io.Reader, error) {
	// Try to parse as armored first.
	armoredReader := armor.NewReader(r)
	decryptedReader, err := age.Decrypt(armoredReader, identities...)
	if err == nil {
		return decryptedReader, nil
	}

	// If armored parsing fails, try binary.
	// We need to reset the reader to the beginning.
	seeker, ok := r.(io.Seeker)
	if !ok {
		return nil, fmt.Errorf("unseekable reader: %v", err)
	}

	_, err = seeker.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek: %v", err)
	}

	return age.Decrypt(r, identities...)
}

func decryptIdentities(agentSocket, identitiesPath string) (string, error) {
	encryptedData, err := os.ReadFile(identitiesPath)
	if err != nil {
		return "", fmt.Errorf("failed to open identities file: %v", err)
	}

	// If an agent socket is configured, try to use the agent.
	if agentSocket != "" {
		decrypted, err := tryAgent(agentSocket, encryptedData)
		if err == nil {
			return decrypted, nil
		}

		// If we couldn't connect, get a password and start a new agent.
		password, err := secureRead("Enter password to unlock identities: ")
		if err != nil {
			return "", fmt.Errorf("failed to read password: %v", err)
		}

		if err := startAgent(agentSocket, password); err != nil {
			return "", fmt.Errorf("failed to start agent: %v", err)
		}

		// Try connecting to the new agent.
		decrypted, err = tryAgent(agentSocket, encryptedData)
		if err == nil {
			return decrypted, nil
		}

		return "", fmt.Errorf("failed to use agent: %v", err)
	}

	// When no agent socket is configured, decrypt directly.
	password, err := secureRead("Enter password to unlock identities: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}

	// Create a password-based identity and decrypt the private keys with it.
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return "", fmt.Errorf("failed to create password-based identity: %v", err)
	}

	r, err := wrapDecrypt(bytes.NewReader(encryptedData), identity)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt identities: %v", err)
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read decrypted content: %v", err)
	}

	return string(decrypted), nil
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
		return "", fmt.Errorf("decrypt command failed: %v", err)
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
	if info.Mode().Perm() != socketPerms {
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

func waitUntilAvailable(path string, maximum time.Duration) error {
	start := time.Now()

	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}

		elapsed := time.Now().Sub(start)
		if elapsed > maximum {
			return fmt.Errorf("reached %v timeout", maximum)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func startAgent(agentSocket, password string) error {
	// The agent is the same executable.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	cmd := exec.Command(exe, "agent")
	cmd.Env = append(os.Environ(), "PAGO_AGENT_PASSWORD="+password)

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

		if err := os.Chmod(agentSocket, socketPerms); err != nil {
			exitWithError("failed to set permissions on agent socket: %v", err)
		}
	}()

	return srv.ListenServeAndSignal(errc)
}

func decryptPassword(agentSocket, identities, passwordStore, name string) (string, error) {
	// Decrypt the password-protected identities file first.
	identityFile, err := decryptIdentities(agentSocket, identities)
	if err != nil {
		return "", err
	}

	ids, err := age.ParseIdentities(strings.NewReader(identityFile))
	if err != nil {
		return "", fmt.Errorf("failed to parse identities: %v", err)
	}

	f, err := os.Open(passwordFile(passwordStore, name))
	if err != nil {
		return "", fmt.Errorf("failed to open encrypted file: %v", err)
	}
	defer f.Close()

	r, err := wrapDecrypt(f, ids...)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	password, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read decrypted content: %v", err)
	}

	return string(password), nil
}

// Delete a password entry and its empty parent directories.
func deletePassword(passwordStore, name string) error {
	if choice, err := askYesNo(fmt.Sprintf("Delete pass file '%s'?", name)); !choice || err != nil {
		return err
	}

	file := passwordFile(passwordStore, name)
	if err := os.Remove(file); err != nil {
		return fmt.Errorf("failed to delete password file: %v", err)
	}

	// Try to remove empty parent directories.
	dir := filepath.Dir(file)
	for dir != passwordStore {
		err := os.Remove(dir)
		if err != nil {
			break // Directory not empty or other error.
		}
		dir = filepath.Dir(dir)
	}

	return nil
}

// Print the password.
func showPassword(agentSocket, identities, passwordStore, name string) error {
	password, err := decryptPassword(agentSocket, identities, passwordStore, name)
	if err != nil {
		return err
	}
	fmt.Println(password)
	return nil
}

// Check if the password name contains unacceptable path traversal.
func validatePath(passwordStore, name string) error {
	path := passwordFile(passwordStore, name)

	for path != "/" {
		path = filepath.Dir(path)
		if path == passwordStore {
			return nil
		}
	}

	return fmt.Errorf("password path is out of bounds")
}

func listFiles(root string, transform func(name string, info os.FileInfo) (bool, string)) ([]string, error) {
	list := []string{}

	err := filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name, err = filepath.Abs(name)
		if err != nil {
			return err
		}

		keep, displayName := transform(name, info)
		if !keep {
			return nil
		}

		list = append(list, displayName)

		return nil
	})
	if err != nil {
		return []string{}, err
	}

	return list, nil
}

func dirTree(root string, transform func(name string, info os.FileInfo) (bool, string)) (string, error) {
	tree := treeprint.NewWithRoot(filepath.Base(root))
	visited := make(map[string]treeprint.Tree)

	err := filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name, err = filepath.Abs(name)
		if err != nil {
			return err
		}

		keep, displayName := transform(name, info)
		if !keep {
			return nil
		}

		if len(visited) == 0 {
			visited[name] = tree
			return nil
		}

		parent := visited[filepath.Dir(name)]

		var newTree treeprint.Tree
		if info.IsDir() {
			newTree = parent.AddBranch(displayName)
		} else {
			newTree = parent.AddNode(displayName)
		}

		visited[name] = newTree

		return nil
	})
	if err != nil {
		return "", err
	}

	return tree.String(), nil
}

func main() {
	var cli CLI

	parser := kong.Must(&cli,
		kong.Name("pago"),
		kong.Description("A simple password manager."),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{
			"defaultDataDir": defaultDataDir,
			"defaultSocket":  filepath.Join(defaultCacheDir, agentSocketPath),
		},
	)

	// Set the default command according to whether the data directory exists.
	args := os.Args[1:]
	if len(args) == 0 {
		dataDir := os.Getenv("PAGO_DIR")
		if dataDir == "" {
			dataDir = defaultDataDir
		}
		storePath := filepath.Join(dataDir, storePath)

		if pathExists(storePath) {
			args = []string{"tree"}
		} else {
			args = []string{"--help"}
		}
	}

	ctx, err := parser.Parse(args)
	if err != nil {
		parser.FatalIfErrorf(err)
	}

	config, err := initConfig(&cli)
	if err != nil {
		exitWithError("%v", err)
	}

	err = os.MkdirAll(config.Store, dirPerms)
	if err != nil {
		exitWithError("failed to create password store directory: %v", err)
	}

	if err := ctx.Run(config); err != nil {
		exitWithError("%v", err)
	}
}
