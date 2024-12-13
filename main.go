// pago - a command-line password manager.
//
// This program is a heavily modified fork of pash.
// Original repository: https://github.com/dylanaraps/pash (archived).
//
// License: MIT.
// See the file `LICENSE`.

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
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
	"github.com/xlab/treeprint"
	"golang.design/x/clipboard"
)

type CLI struct {
	// Global options.
	Dir    string `short:"d" env:"${dataDirEnv}" default:"${defaultDataDir}" help:"Store location"`
	Socket string `short:"s" env:"${socketEnv}" default:"${defaultSocket}" help:"Agent socket path (blank to disable)"`

	// Commands.
	Add      AddCmd      `cmd:"" aliases:"a" help:"Create new password entry"`
	Agent    AgentCmd    `cmd:"" hidden:"" help:"Run the agent process"`
	Clip     ClipCmd     `cmd:"" aliases:"c" help:"Copy entry to clipboard"`
	Delete   DeleteCmd   `cmd:"" aliases:"d,del" help:"Delete password entry"`
	Find     FindCmd     `cmd:"" aliases:"f" help:"Find entry by name"`
	Generate GenerateCmd `cmd:"" aliases:"g,gen" help:"Generate and print password"`
	Init     InitCmd     `cmd:"" help:"Create a new passwore store"`
	Show     ShowCmd     `cmd:"" aliases:"s" help:"Show password for entry or list entries"`
	Version  VersionCmd  `cmd:"" aliases:"v,ver" help:"Print version number and exit"`
}

type Config struct {
	DataDir    string
	Home       string
	Identities string
	Recipients string
	Socket     string
	Store      string
}

const (
	ageExt          = ".age"
	agentSocketPath = "socket"
	defaultLength   = "20"
	defaultPattern  = "[A-Za-z0-9]"
	dirPerms        = 0o700
	filePerms       = 0o600
	maxStepsPerChar = 1000
	storePath       = "store"
	version         = "0.6.0"
	waitForSocket   = 3 * time.Second

	agentPasswordEnv = "PAGO_AGENT_PASSWORD"
	dataDirEnv       = "PAGO_DIR"
	socketEnv        = "PAGO_SOCK"
	lengthEnv        = "PAGO_LENGTH"
	patternEnv       = "PAGO_PATTERN"
	timeoutEnv       = "PAGO_TIMEOUT"
)

var (
	defaultCacheDir = filepath.Join(xdg.CacheHome, "pago")
	defaultDataDir  = filepath.Join(xdg.DataHome, "pago")
)

type AddCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Length  int    `short:"l" env:"${lengthEnv}" default:"${defaultLength}" help:"Password length"`
	Pattern string `short:"p" env:"${patternEnv}" default:"${defaultPattern}" help:"Password pattern (regular expression)"`

	Input  bool `short:"i" help:"Input the password manually" xor:"mode"`
	Random bool `short:"r" help:"Generate a random password" xor:"mode"`
}

func (cmd *AddCmd) Run(config *Config) error {
	if passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("entry already exists: %v", cmd.Name)
	}

	var generate bool
	var err error

	if cmd.Input || cmd.Random {
		generate = cmd.Random
	} else {
		generate, err = askYesNo("Generate a password?")
		if err != nil {
			return err
		}
	}

	password := ""
	if generate {
		password, err = generatePassword(cmd.Pattern, cmd.Length)
	} else {
		password, err = readNewPassword()
	}
	if err != nil {
		return err
	}

	if err := savePassword(config.Recipients, config.Store, cmd.Name, password); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Password saved.")
	return nil
}

type AgentCmd struct{}

type ClipCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Timeout int `short:"t" env:"${timeoutEnv}" default:"30" help:"Clipboard timeout (0 to disable)"`
}

func (cmd *ClipCmd) Run(config *Config) error {
	if !passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("entry doesn't exist: %v", cmd.Name)
	}

	password, err := decryptPassword(config.Socket, config.Identities, config.Store, cmd.Name)
	if err != nil {
		return err
	}

	if err := clipboard.Init(); err != nil {
		return fmt.Errorf("failed to initialize clipboard: %v", err)
	}

	clipboard.Write(clipboard.FmtText, []byte(password))

	timeout := time.Duration(cmd.Timeout) * time.Second
	if timeout > 0 {
		ending := "s"
		if cmd.Timeout%10 == 1 && cmd.Timeout%100 != 11 {
			ending = ""
		}
		fmt.Fprintf(os.Stderr, "Clearing clipboard in %v second%s\n", cmd.Timeout, ending)

		time.Sleep(timeout)
		clipboard.Write(clipboard.FmtText, []byte(""))
	}

	return nil
}

type DeleteCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Force bool `short:"f" help:"Do not ask to confirm"`
}

func (cmd *DeleteCmd) Run(config *Config) error {
	if !passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("entry doesn't exist: %v", cmd.Name)
	}

	var choice bool
	var err error

	if cmd.Force {
		choice = true
	} else {
		if choice, err = askYesNo(fmt.Sprintf("Delete entry '%s'?", cmd.Name)); !choice || err != nil {
			return err
		}
	}

	file := passwordFile(config.Store, cmd.Name)
	if err := os.Remove(file); err != nil {
		return fmt.Errorf("failed to delete entry: %v", err)
	}

	// Try to remove empty parent directories.
	dir := filepath.Dir(file)
	for dir != config.Store {
		err := os.Remove(dir)
		if err != nil {
			// The directory is not empty or there was another error.
			break
		}
		dir = filepath.Dir(dir)
	}

	return nil
}

type FindCmd struct {
	Pattern string `arg:"" default:"" help:"Pattern to search for (regular expression)"`
}

func (cmd *FindCmd) Run(config *Config) error {
	pattern, err := regexp.Compile(cmd.Pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regular expression: %v", err)
	}

	list, err := listFiles(config.Store, func(name string, info os.FileInfo) (bool, string) {
		if info.IsDir() || !strings.HasSuffix(name, ageExt) {
			return false, ""
		}

		displayName := name
		displayName = strings.TrimPrefix(displayName, config.Store)
		displayName = strings.TrimPrefix(displayName, "/")
		displayName = strings.TrimSuffix(displayName, ageExt)

		if !pattern.MatchString(displayName) {
			return false, ""
		}

		return true, displayName
	})
	if err != nil {
		return fmt.Errorf("failed to search entries: %v", err)
	}

	fmt.Println(strings.Join(list, "\n"))
	return nil
}

type GenerateCmd struct {
	Length  int    `short:"l" env:"${lengthEnv}" default:"${defaultLength}" help:"Password length"`
	Pattern string `short:"p" env:"${patternEnv}" default:"${defaultPattern}" help:"Password pattern (regular expression)"`
}

func (cmd *GenerateCmd) Run(config *Config) error {
	password, err := generatePassword(cmd.Pattern, cmd.Length)
	if err != nil {
		return err
	}
	fmt.Println(password)
	return nil
}

type InitCmd struct{}

func (cmd *InitCmd) Run(config *Config) error {
	if pathExists(config.Identities) {
		return fmt.Errorf("identities file already exists")
	}
	if pathExists(config.Recipients) {
		return fmt.Errorf("recipients file already exists")
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("failed to generate identity: %w", err)
	}

	// Create a buffer for an armored, encrypted identity.
	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)

	password, err := readNewPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	recip, err := age.NewScryptRecipient(password)
	if err != nil {
		return fmt.Errorf("failed to create scrypt recipient: %w", err)
	}

	w, err := age.Encrypt(armorWriter, recip)
	if err != nil {
		return fmt.Errorf("failed to create encrypted writer: %w", err)
	}

	_, err = w.Write([]byte(identity.String()))
	if err != nil {
		return fmt.Errorf("failed to write identity: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encrypted writer: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer: %w", err)
	}

	if err := os.MkdirAll(config.Store, dirPerms); err != nil {
		return fmt.Errorf("failed to create store directory: %v", err)
	}

	if err := os.WriteFile(config.Identities, buf.Bytes(), filePerms); err != nil {
		return fmt.Errorf("failed to write identities file: %w", err)
	}

	if err := os.WriteFile(config.Recipients, []byte(identity.Recipient().String()+"\n"), filePerms); err != nil {
		return fmt.Errorf("failed to write recipients file: %w", err)
	}

	return nil
}

type ShowCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`
}

func printStoreTree(store string) error {
	tree, err := dirTree(store, func(name string, info os.FileInfo) (bool, string) {
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

func (cmd *ShowCmd) Run(config *Config) error {
	if cmd.Name == "" {
		return printStoreTree(config.Store)
	}

	if !passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("entry doesn't exist: %v", cmd.Name)
	}

	password, err := decryptPassword(
		config.Socket,
		config.Identities,
		config.Store,
		cmd.Name,
	)
	if err != nil {
		return err
	}

	fmt.Println(password)

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

	store := filepath.Join(cli.Dir, storePath)

	config := Config{
		DataDir:    cli.Dir,
		Home:       home,
		Identities: filepath.Join(cli.Dir, "identities"),
		Recipients: filepath.Join(store, ".age-recipients"),
		Socket:     cli.Socket,
		Store:      store,
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
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	return string(password), nil
}

func askYesNo(prompt string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/n]: ", prompt)

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
	fmt.Fprintln(os.Stderr)

	answer := strings.ToLower(string(input[0]))
	return answer == "y", nil
}

// Generate a random password where each character matches a regular expression.
func generatePassword(pattern string, length int) (string, error) {
	regexpPattern, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to compile regular expression: %v", err)
	}

	var password strings.Builder

	steps := 0
	for password.Len() < length {
		b := make([]byte, 1)
		_, err := rand.Read(b)
		if err != nil {
			return "", err
		}

		char := string(b[0])
		if regexpPattern.MatchString(char) {
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
		kong.Description("A command-line password manager."),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{
			"defaultDataDir": defaultDataDir,
			"defaultLength":  defaultLength,
			"defaultPattern": defaultPattern,
			"defaultSocket":  defaultSocket,

			"dataDirEnv": dataDirEnv,
			"socketEnv":  socketEnv,
			"timeoutEnv": timeoutEnv,
			"lengthEnv":  lengthEnv,
			"patternEnv": patternEnv,
		},
	)

	// Set the default command according to whether the data directory exists.
	args := os.Args[1:]
	if len(args) == 0 {
		dataDir := os.Getenv(dataDirEnv)
		if dataDir == "" {
			dataDir = defaultDataDir
		}
		storePath := filepath.Join(dataDir, storePath)

		if pathExists(storePath) {
			args = []string{"show"}
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
