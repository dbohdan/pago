// pago - a command-line password manager.
//
// This program is a heavily modified fork of pash.
// Original repository: https://github.com/dylanaraps/pash (archived).
//
// License: MIT.
// See the file `LICENSE`.

package main

import (
	"bufio"
	"bytes"
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
	"github.com/alecthomas/repr"
	"github.com/anmitsu/go-shlex"
	"github.com/ktr0731/go-fuzzyfinder"

	gitConfig "github.com/go-git/go-git/v5/config"
)

type CLI struct {
	// Global options.
	Confirm  bool   `env:"${confirmEnv}" default:"true" negatable:"" help:"Enter passwords twice"`
	Dir      string `short:"d" env:"${dataDirEnv}" default:"${defaultDataDir}" help:"Store location (${env})"`
	Git      bool   `env:"${gitEnv}" default:"true" negatable:"" help:"Commit to Git (${env})"`
	GitEmail string `env:"${gitEmailEnv}" default:"${defaultGitEmail}" help:"Email for Git commits (${env})"`
	GitName  string `env:"${gitNameEnv}" default:"${defaultGitName}" help:"Name for Git commits (${env})"`
	Socket   string `short:"s" env:"${socketEnv}" default:"${defaultSocket}" help:"Agent socket path (blank to disable, ${env})"`
	Verbose  bool   `short:"v" hidden:"" help:"Print debugging information"`

	// Commands.
	Add      AddCmd      `cmd:"" aliases:"a" help:"Create new password entry"`
	Agent    AgentCmd    `cmd:"" hidden:"" help:"Control the agent process"`
	Clip     ClipCmd     `cmd:"" aliases:"c" help:"Copy entry to clipboard"`
	Delete   DeleteCmd   `cmd:"" aliases:"d,del,rm" help:"Delete password entry"`
	Find     FindCmd     `cmd:"" aliases:"f" help:"Find entry by name"`
	Generate GenerateCmd `cmd:"" aliases:"g,gen" help:"Generate and print password"`
	Init     InitCmd     `cmd:"" help:"Create a new passwore store"`
	Show     ShowCmd     `cmd:"" aliases:"s" help:"Show password for entry or list entries"`
	Version  VersionCmd  `cmd:"" aliases:"v,ver" help:"Print version number and exit"`
}

type Config struct {
	Confirm    bool
	DataDir    string
	Git        bool
	GitEmail   string
	GitName    string
	Home       string
	Identities string
	Recipients string
	Socket     string
	Store      string
	Verbose    bool
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
	version         = "0.7.0"
	waitForSocket   = 3 * time.Second

	clipEnv     = "PAGO_CLIP"
	confirmEnv  = "PAGO_CONFIRM"
	dataDirEnv  = "PAGO_DIR"
	gitEnv      = "PAGO_GIT"
	gitEmailEnv = "GIT_AUTHOR_EMAIL"
	gitNameEnv  = "GIT_AUTHOR_NAME"
	lengthEnv   = "PAGO_LENGTH"
	patternEnv  = "PAGO_PATTERN"
	socketEnv   = "PAGO_SOCK"
	timeoutEnv  = "PAGO_TIMEOUT"
)

var (
	defaultCacheDir = filepath.Join(xdg.CacheHome, "pago")
	defaultDataDir  = filepath.Join(xdg.DataHome, "pago")
	defaultGitEmail = "pago password manager"
	defaultGitName  = "pago@localhost"
)

type AddCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Length  int    `short:"l" env:"${lengthEnv}" default:"${defaultLength}" help:"Password length (${env})"`
	Pattern string `short:"p" env:"${patternEnv}" default:"${defaultPattern}" help:"Password pattern (regular expression, ${env})"`

	Input  bool `short:"i" help:"Input the password manually" xor:"mode"`
	Random bool `short:"r" help:"Generate a random password" xor:"mode"`
}

func printRepr(value any) {
	valueRepr := repr.String(value, repr.Indent("\t"), repr.OmitEmpty(false))
	fmt.Fprintf(os.Stderr, "%s\n\n", valueRepr)
}

func (cmd *AddCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

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
		password, err = readNewPassword(config.Confirm)
	}
	if err != nil {
		return err
	}

	if err := savePassword(config.Recipients, config.Store, cmd.Name, password); err != nil {
		return err
	}

	if config.Git {
		if err := commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("add %q", cmd.Name),
			[]string{passwordFile(config.Store, cmd.Name)},
		); err != nil {
			return err
		}
	}

	fmt.Fprintln(os.Stderr, "Password saved.")
	return nil
}

type AgentCmd struct {
	Restart RestartCmd `cmd:"" help:"Restart the agent process"`
	Run     RunCmd     `cmd:"" help:"Run the agent"`
	Start   StartCmd   `cmd:"" help:"Start the agent process"`
	Status  StatusCmd  `cmd:"" help:"Check if agent is running"`
	Stop    StopCmd    `cmd:"" help:"Stop the agent process"`
}

type RestartCmd struct{}

type RunCmd struct{}

type StartCmd struct{}

type StatusCmd struct{}

type StopCmd struct{}

type ClipCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Command string `short:"c" env:"${clipEnv}" default:"${defaultClip}" help:"Command for copying text from stdin to clipboard (${env})"`
	Timeout int    `short:"t" env:"${timeoutEnv}" default:"30" help:"Clipboard timeout (0 to disable, ${env})"`
}

func copyToClipboard(command string, text string) error {
	args, err := shlex.Split(command, true)
	if err != nil {
		return fmt.Errorf("failed to split clipboard command: %v", err)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(text)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to rub clipboard command: %v", err)
	}

	return nil
}

func (cmd *ClipCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	if !passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("entry doesn't exist: %v", cmd.Name)
	}

	password, err := decryptPassword(config.Socket, config.Identities, config.Store, cmd.Name)
	if err != nil {
		return err
	}

	if err := copyToClipboard(cmd.Command, password); err != nil {
		return fmt.Errorf("failed to copy password to clipboard: %v", err)
	}

	timeout := time.Duration(cmd.Timeout) * time.Second
	if timeout > 0 {
		ending := "s"
		if cmd.Timeout%10 == 1 && cmd.Timeout%100 != 11 {
			ending = ""
		}
		fmt.Fprintf(os.Stderr, "Clearing clipboard in %v second%s\n", cmd.Timeout, ending)

		time.Sleep(timeout)
		if err := copyToClipboard(cmd.Command, ""); err != nil {
			return fmt.Errorf("failed to clear clipboard: %v", err)
		}
	}

	return nil
}

type DeleteCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Force bool `short:"f" help:"Do not ask to confirm"`
}

func (cmd *DeleteCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

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

	if config.Git {
		if err := commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("remove %q", cmd.Name),
			[]string{file},
		); err != nil {
			return err
		}
	}

	return nil
}

type FindCmd struct {
	Pattern string `arg:"" default:"" help:"Pattern to search for (regular expression)"`
}

// Return a function that filters filenames entries.
func passwordFilter(root string, pattern *regexp.Regexp) func(name string, info os.FileInfo) (bool, string) {
	return func(name string, info os.FileInfo) (bool, string) {
		if info.IsDir() || !strings.HasSuffix(name, ageExt) {
			return false, ""
		}

		displayName := name
		displayName = strings.TrimPrefix(displayName, root)
		displayName = strings.TrimPrefix(displayName, "/")
		displayName = strings.TrimSuffix(displayName, ageExt)

		if pattern != nil && !pattern.MatchString(displayName) {
			return false, ""
		}

		return true, displayName
	}
}

func (cmd *FindCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	pattern, err := regexp.Compile(cmd.Pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regular expression: %v", err)
	}

	list, err := listFiles(config.Store, passwordFilter(config.Store, pattern))
	if err != nil {
		return fmt.Errorf("failed to search entries: %v", err)
	}

	fmt.Println(strings.Join(list, "\n"))
	return nil
}

type GenerateCmd struct {
	Length  int    `short:"l" env:"${lengthEnv}" default:"${defaultLength}" help:"Password length (${env})"`
	Pattern string `short:"p" env:"${patternEnv}" default:"${defaultPattern}" help:"Password pattern (regular expression, ${env})"`
}

func (cmd *GenerateCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	password, err := generatePassword(cmd.Pattern, cmd.Length)
	if err != nil {
		return err
	}
	fmt.Println(password)
	return nil
}

type InitCmd struct{}

func (cmd *InitCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

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

	password, err := readNewPassword(config.Confirm)
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

	if config.Git {
		if err := initGitRepo(config.Store); err != nil {
			return err
		}

		if err := commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			"Initial commit",
			[]string{config.Recipients},
		); err != nil {
			return err
		}
	}

	return nil
}

type ShowCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`
	Pick bool   `short:"p" help:"Pick entry using fuzzy finder"`
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
	if config.Verbose {
		printRepr(cmd)
	}

	if !cmd.Pick && cmd.Name == "" {
		return printStoreTree(config.Store)
	}

	name := cmd.Name
	if cmd.Pick {
		// Create a list of all passwords.
		list, err := listFiles(config.Store, passwordFilter(config.Store, nil))
		if err != nil {
			return fmt.Errorf("failed to list passwords: %v", err)
		}

		if len(list) == 0 {
			return fmt.Errorf("no password entries found")
		}

		// Show an interactive fuzzy finder.
		idx, err := fuzzyfinder.Find(
			list,
			func(i int) string {
				return list[i]
			},
			fuzzyfinder.WithQuery(name),
		)
		if err != nil {
			if errors.Is(fuzzyfinder.ErrAbort, err) {
				return nil
			} else {
				return fmt.Errorf("fuzzy finder failed: %v", err)
			}
		}

		name = list[idx]
	}

	if !passwordExists(config.Store, name) {
		return fmt.Errorf("entry doesn't exist: %v", cmd.Name)
	}

	password, err := decryptPassword(
		config.Socket,
		config.Identities,
		config.Store,
		name,
	)
	if err != nil {
		return err
	}

	fmt.Print(password)
	if !strings.HasSuffix(password, "\n") {
		fmt.Println()
	}

	return nil
}

type VersionCmd struct{}

func (cmd *VersionCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

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
		Confirm:    cli.Confirm,
		DataDir:    cli.Dir,
		Git:        cli.Git,
		GitEmail:   cli.GitEmail,
		GitName:    cli.GitName,
		Home:       home,
		Identities: filepath.Join(cli.Dir, "identities"),
		Recipients: filepath.Join(store, ".age-recipients"),
		Socket:     cli.Socket,
		Store:      store,
		Verbose:    cli.Verbose,
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

// Read a password without echo if standard input is a terminal.
func secureRead(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	if term.IsTerminal(int(syscall.Stdin)) {
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}

		return string(password), nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", scanner.Err()
	}

	return scanner.Text(), nil
}
func askYesNo(prompt string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/n]: ", prompt)

	// Save the terminal state to restore later.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false, fmt.Errorf("failed to make terminal raw: %v", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	answer := ""
	for answer != "n" && answer != "y" {
		// Read a single byte from the terminal.
		var input [1]byte
		_, err = os.Stdin.Read(input[:])
		if err != nil {
			return false, fmt.Errorf("failed to read input: %v", err)
		}

		answer = strings.ToLower(string(input[0]))
	}

	term.Restore(int(os.Stdin.Fd()), oldState)
	fmt.Fprintln(os.Stderr)

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

// Ask the user to input a password, twice if `confirm` is true.
func readNewPassword(confirm bool) (string, error) {
	pass, err := secureRead("Enter password: ")
	if err != nil {
		return "", err
	}

	if pass == "" {
		return "", fmt.Errorf("empty password")
	}

	if confirm {
		pass2, err := secureRead("Enter password (again): ")
		if err != nil {
			return "", err
		}

		if pass != pass2 {
			return "", fmt.Errorf("passwords do not match")
		}
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
	armorWriter := armor.NewWriter(f)

	w, err := age.Encrypt(armorWriter, recips...)
	if err != nil {
		return fmt.Errorf("failed to create encryption writer: %v", err)
	}

	if _, err := io.WriteString(w, password); err != nil {
		return fmt.Errorf("failed to encrypt: %v", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finish encryption: %v", err)
	}

	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer: %w", err)
	}

	return nil
}

// Returns a reader that can handle both armored and binary age files.
func wrapDecrypt(r io.Reader, identities ...age.Identity) (io.Reader, error) {
	// Check if the input starts with an armor header.
	seeker, ok := r.(io.Seeker)
	if !ok {
		return nil, fmt.Errorf("input must be seekable")
	}

	// Read enough bytes to check for the armor header.
	header := make([]byte, len(armor.Header))
	_, err := io.ReadFull(r, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	_, err = seeker.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek: %v", err)
	}

	isArmored := string(header) == armor.Header

	if isArmored {
		armoredReader := armor.NewReader(r)
		decryptedReader, err := age.Decrypt(armoredReader, identities...)
		if err != nil {
			return nil, fmt.Errorf("armored decryption failed: %v", err)
		}

		return decryptedReader, nil
	}

	// Try binary decryption.
	decryptedReader, err := age.Decrypt(r, identities...)
	if err != nil {
		return nil, fmt.Errorf("binary decryption failed: %v", err)
	}

	return decryptedReader, nil
}

func decryptIdentities(identitiesPath string) (string, error) {
	encryptedData, err := os.ReadFile(identitiesPath)
	if err != nil {
		return "", fmt.Errorf("failed to read identities file: %v", err)
	}

	password, err := secureRead("Enter password to unlock identities: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}

	// Create a passphrase-based identity and decrypt the private keys with it.
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
	encryptedData, err := os.ReadFile(passwordFile(passwordStore, name))
	if err != nil {
		return "", fmt.Errorf("failed to read password file: %v", err)
	}

	// If an agent socket is configured, try to use the agent.
	if agentSocket != "" {
		if err := pingAgent(agentSocket); err != nil {
			// Ping failed.
			// Attempt to start the agent.
			identitiesText, err := decryptIdentities(identities)
			if err != nil {
				return "", err
			}

			if err := startAgentProcess(agentSocket, identitiesText); err != nil {
				return "", fmt.Errorf("failed to start agent: %v", err)
			}
		}

		password, err := decryptWithAgent(agentSocket, encryptedData)
		if err != nil {
			return "", err
		}

		return password, nil
	}

	// When no agent socket is configured, decrypt directly.
	// Decrypt the password-protected identities file first.
	identitiesText, err := decryptIdentities(identities)
	if err != nil {
		return "", err
	}

	ids, err := age.ParseIdentities(strings.NewReader(identitiesText))
	if err != nil {
		return "", fmt.Errorf("failed to parse identities: %v", err)
	}

	r, err := wrapDecrypt(bytes.NewReader(encryptedData), ids...)
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

func main() {
	globalConfig, err := gitConfig.LoadConfig(gitConfig.GlobalScope)
	if err == nil {
		defaultGitEmail = globalConfig.User.Email
		defaultGitName = globalConfig.User.Name
	}

	var cli CLI

	parser := kong.Must(&cli,
		kong.Name("pago"),
		kong.Description("A command-line password manager."),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Exit(func(code int) {
			if code == 1 {
				code = 2
			}

			os.Exit(code)
		}),
		kong.Vars{
			"defaultClip":     defaultClip,
			"defaultDataDir":  defaultDataDir,
			"defaultGitEmail": defaultGitEmail,
			"defaultGitName":  defaultGitName,
			"defaultLength":   defaultLength,
			"defaultPattern":  defaultPattern,
			"defaultSocket":   defaultSocket,

			"clipEnv":     clipEnv,
			"confirmEnv":  confirmEnv,
			"dataDirEnv":  dataDirEnv,
			"gitEnv":      gitEnv,
			"gitEmailEnv": gitEmailEnv,
			"gitNameEnv":  gitNameEnv,
			"socketEnv":   socketEnv,
			"timeoutEnv":  timeoutEnv,
			"lengthEnv":   lengthEnv,
			"patternEnv":  patternEnv,
		},
	)

	// Set the default command according to whether the data directory exists.
	args := os.Args[1:]
	if len(args) == 0 {
		dataDir := os.Getenv(dataDirEnv)
		if dataDir == "" {
			dataDir = defaultDataDir
		}
		storeDir := filepath.Join(dataDir, storePath)

		if pathExists(storeDir) {
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
	if config.Verbose {
		printRepr(config)
	}

	err = os.MkdirAll(config.Store, dirPerms)
	if err != nil {
		exitWithError("failed to create password store directory: %v", err)
	}

	if err := ctx.Run(config); err != nil {
		exitWithError("%v", err)
	}
}
