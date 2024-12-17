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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/adrg/xdg"
	"github.com/alecthomas/kong"
	"github.com/alecthomas/repr"
	"github.com/anmitsu/go-shlex"
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
	Edit     EditCmd     `cmd:"" aliases:"e" help:"Edit password entry"`
	Find     FindCmd     `cmd:"" aliases:"f" help:"Find entry by name"`
	Generate GenerateCmd `cmd:"" aliases:"g,gen" help:"Generate and print password"`
	Info     InfoCmd     `cmd:"" hidden:"" help:"Show information"`
	Init     InitCmd     `cmd:"" help:"Create a new passwore store"`
	Rewrap   RewrapCmd   `cmd:"" help:"Change the password for the identities file"`
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
	version         = "0.8.0"
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

	Force     bool `short:"f" help:"Overwrite existing entry"`
	Input     bool `short:"i" help:"Input the password manually" xor:"mode"`
	Multiline bool `short:"m" help:"Read password from stdin until EOF" xor:"mode"`
	Random    bool `short:"r" help:"Generate a random password" xor:"mode"`
}

func printRepr(value any) {
	valueRepr := repr.String(value, repr.Indent("\t"), repr.OmitEmpty(false))
	fmt.Fprintf(os.Stderr, "%s\n\n", valueRepr)
}

func (cmd *AddCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	if !cmd.Force && passwordExists(config.Store, cmd.Name) {
		return fmt.Errorf("entry already exists: %v", cmd.Name)
	}

	var password string
	var err error

	if cmd.Multiline {
		fmt.Fprintln(os.Stderr, "Reading password from stdin until EOF:")

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, os.Stdin); err != nil {
			return fmt.Errorf("failed to read from stdin: %v", err)
		}

		password = buf.String()
	} else {
		// Either generate a password or use input with confirmation.
		var generate bool

		if cmd.Input || cmd.Random {
			generate = cmd.Random
		} else {
			generate, err = askYesNo("Generate a password?")
			if err != nil {
				return err
			}
		}

		if generate {
			password, err = generatePassword(cmd.Pattern, cmd.Length)
		} else {
			password, err = readNewPassword(config.Confirm)
		}
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

	fmt.Fprintln(os.Stderr, "Password saved")
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
	Name string `arg:"" optional:"" help:"Name of the password entry"`

	Command string `short:"c" env:"${clipEnv}" default:"${defaultClip}" help:"Command for copying text from stdin to clipboard (${env})"`
	Pick    bool   `short:"p" help:"Pick entry using fuzzy finder"`
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

	name := cmd.Name
	if cmd.Pick {
		picked, err := pickPassword(config.Store, name)
		if err != nil {
			return err
		}
		if picked == "" {
			return nil
		}
		name = picked
	}

	if !passwordExists(config.Store, name) {
		return fmt.Errorf("entry doesn't exist: %v", name)
	}

	password, err := decryptPassword(config.Socket, config.Identities, config.Store, name)
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
	Name string `arg:"" optional:"" help:"Name of the password entry"`

	Force bool `short:"f" help:"Do not ask to confirm"`
	Pick  bool `short:"p" help:"Pick entry using fuzzy finder"`
}

func (cmd *DeleteCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	name := cmd.Name
	if cmd.Pick {
		picked, err := pickPassword(config.Store, name)
		if err != nil {
			return err
		}
		if picked == "" {
			return nil
		}
		name = picked
	}

	if !passwordExists(config.Store, name) {
		return fmt.Errorf("entry doesn't exist: %v", name)
	}

	var choice bool
	var err error

	if cmd.Force {
		choice = true
	} else {
		if choice, err = askYesNo(fmt.Sprintf("Delete entry '%s'?", name)); !choice || err != nil {
			return err
		}
	}

	file := passwordFile(config.Store, name)

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
			fmt.Sprintf("remove %q", name),
			[]string{file},
		); err != nil {
			return err
		}
	}

	return nil
}

type EditCmd struct {
	Force bool   `short:"f" help:"Create the entry if it doesn't exist"`
	Name  string `arg:"" optional:"" help:"Name of the password entry"`
	Pick  bool   `short:"p" help:"Pick entry using fuzzy finder"`
}

func (cmd *EditCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	name := cmd.Name
	if cmd.Pick {
		picked, err := pickPassword(config.Store, name)
		if err != nil {
			return err
		}
		if picked == "" {
			return nil
		}
		name = picked
	}

	var password string
	var err error

	if passwordExists(config.Store, name) {
		// Decrypt the existing password.
		password, err = decryptPassword(config.Socket, config.Identities, config.Store, name)
		if err != nil {
			return err
		}
	} else if !cmd.Force {
		return fmt.Errorf("entry doesn't exist: %v", name)
	}

	text, err := Edit(password)
	if err != nil && !errors.Is(err, CancelError) {
		return fmt.Errorf("editor failed: %v", err)
	}

	fmt.Println()

	if text == password || errors.Is(err, CancelError) {
		fmt.Fprintln(os.Stderr, "No changes made")
		return nil
	}

	// Save the edited password.
	if err := savePassword(config.Recipients, config.Store, name, text); err != nil {
		return err
	}

	if config.Git {
		if err := commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("edit %q", name),
			[]string{passwordFile(config.Store, name)},
		); err != nil {
			return err
		}
	}

	fmt.Fprintln(os.Stderr, "Password updated")
	return nil
}

type FindCmd struct {
	Pattern string `arg:"" default:"" help:"Pattern to search for (regular expression)"`
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

type InfoCmd struct {
	Dir DirCmd `cmd:"" help:"Show data directory path"`
}

type DirCmd struct{}

func (cmd *DirCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	fmt.Println(config.DataDir)

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

type RewrapCmd struct{}

func (cmd *RewrapCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	identitiesText, err := decryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	newPassword, err := readNewPassword(config.Confirm)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)

	recip, err := age.NewScryptRecipient(newPassword)
	if err != nil {
		return fmt.Errorf("failed to create scrypt recipient: %w", err)
	}

	w, err := age.Encrypt(armorWriter, recip)
	if err != nil {
		return fmt.Errorf("failed to create encrypted writer: %w", err)
	}

	_, err = w.Write([]byte(identitiesText))
	if err != nil {
		return fmt.Errorf("failed to write identity: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encrypted writer: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer: %w", err)
	}

	if err := os.WriteFile(config.Identities, buf.Bytes(), filePerms); err != nil {
		return fmt.Errorf("failed to write identities file: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Identities file reencrypted")
	return nil
}

type ShowCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`
	Pick bool   `short:"p" help:"Pick entry using fuzzy finder"`
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
		picked, err := pickPassword(config.Store, name)
		if err != nil {
			return err
		}
		if picked == "" {
			return nil
		}
		name = picked
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
