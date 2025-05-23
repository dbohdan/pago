// pago - a command-line password manager.
//
// This program is a heavily modified fork of pash.
// Original repository: https://github.com/dylanaraps/pash (archived).
//
// License: MIT.
// See the file LICENSE.

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

	"dbohdan.com/pago"
	"dbohdan.com/pago/agent"
	"dbohdan.com/pago/crypto"
	"dbohdan.com/pago/editor"
	"dbohdan.com/pago/git"
	"dbohdan.com/pago/input"
	"dbohdan.com/pago/tree"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/alecthomas/kong"
	"github.com/alecthomas/repr"
	"github.com/anmitsu/go-shlex"
	gitConfig "github.com/go-git/go-git/v5/config"
)

type CLI struct {
	// Global options.
	AgentExecutable string `short:"a" name:"agent" env:"${AgentEnv}" default:"${DefaultAgent}" help:"Agent executable (${env})"`
	Confirm         bool   `env:"${ConfirmEnv}" default:"true" negatable:"" help:"Enter passwords twice (${env})"`
	Dir             string `short:"d" env:"${DataDirEnv}" default:"${DefaultDataDir}" help:"Store location (${env})"`
	Git             bool   `env:"${GitEnv}" default:"true" negatable:"" help:"Commit to Git (${env})"`
	GitEmail        string `env:"${GitEmailEnv}" default:"${GitEmail}" help:"Email for Git commits (${env})"`
	GitName         string `env:"${GitNameEnv}" default:"${GitName}" help:"Name for Git commits (${env})"`
	Memlock         bool   `env:"${MemlockEnv}" default:"true" negatable:"" help:"Lock agent memory with mlockall(2) (${env})"`
	Socket          string `short:"s" env:"${SocketEnv}" default:"${DefaultSocket}" help:"Agent socket path (blank to disable, ${env})"`
	Verbose         bool   `short:"v" hidden:"" help:"Print debugging information"`

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
	Pick     PickCmd     `cmd:"" aliases:"p" help:"Show password for an entry picked with a fuzzy finder. A shortcut for \"show --pick\"."`
	Rekey    RekeyCmd    `cmd:"" help:"Reencrypt all password entries with the recipients file"`
	Rewrap   RewrapCmd   `cmd:"" help:"Change the password for the identities file"`
	Show     ShowCmd     `cmd:"" aliases:"s" help:"Show password for entry or list entries"`
	Version  VersionCmd  `cmd:"" aliases:"v,ver" help:"Print version number and exit"`
}

type Config struct {
	AgentExecutable string
	Confirm         bool
	DataDir         string
	Git             bool
	GitEmail        string
	GitName         string
	Home            string
	Identities      string
	Memlock         bool
	Recipients      string
	Socket          string
	Store           string
	Verbose         bool
}

const (
	maxStepsPerChar = 1000
	storePath       = "store"
)

type AddCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Length  int    `short:"l" env:"${LengthEnv}" default:"${DefaultLength}" help:"Password length (${env})"`
	Pattern string `short:"p" env:"${PatternEnv}" default:"${DefaultPattern}" help:"Password pattern (regular expression, ${env})"`

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

	file, err := pago.EntryFile(config.Store, cmd.Name)
	if err != nil {
		return err
	}

	if !cmd.Force && entryExists(config.Store, cmd.Name) {
		return fmt.Errorf("entry already exists: %v", cmd.Name)
	}

	var password string

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
			generate, err = input.AskYesNo("Generate a password?")
			if err != nil {
				return err
			}
		}

		if generate {
			password, err = generatePassword(cmd.Pattern, cmd.Length)
		} else {
			password, err = input.ReadNewPassword(config.Confirm)
		}
	}
	if err != nil {
		return err
	}

	if err := crypto.SaveEntry(config.Recipients, config.Store, cmd.Name, password); err != nil {
		return err
	}

	if config.Git {
		if err := git.Commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("add %q", cmd.Name),
			[]string{file},
		); err != nil {
			return err
		}
	}

	fmt.Fprintln(os.Stderr, "Password saved")
	return nil
}

type AgentCmd struct {
	Restart RestartCmd `cmd:"" help:"Restart the agent process"`
	Start   StartCmd   `cmd:"" help:"Start the agent process"`
	Status  StatusCmd  `cmd:"" help:"Check if agent is running"`
	Stop    StopCmd    `cmd:"" help:"Stop the agent process"`
}

type RestartCmd struct{}

func (cmd *RestartCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	_, _ = agent.Message(config.Socket, "SHUTDOWN")

	identitiesText, err := crypto.DecryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	return agent.StartProcess(
		config.AgentExecutable,
		config.Memlock,
		config.Socket,
		identitiesText,
	)
}

type StartCmd struct{}

func (cmd *StartCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	if err := agent.Ping(config.Socket); err == nil {
		return fmt.Errorf("found agent responding on socket")
	}

	identitiesText, err := crypto.DecryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	return agent.StartProcess(
		config.AgentExecutable,
		config.Memlock,
		config.Socket,
		identitiesText,
	)
}

type StatusCmd struct{}

func (cmd *StatusCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	err := agent.Ping(config.Socket)
	if err == nil {
		fmt.Println("Ping successful")
		os.Exit(0)
	} else {
		fmt.Println("Failed to ping agent")
		os.Exit(1)
	}

	return nil
}

type StopCmd struct{}

func (cmd *StopCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	_, err := agent.Message(config.Socket, "SHUTDOWN")
	return err
}

type ClipCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`

	Command string `short:"c" env:"${ClipEnv}" default:"${DefaultClip}" help:"Command for copying text from stdin to clipboard (${env})"`
	Pick    bool   `short:"p" help:"Pick entry using fuzzy finder"`
	Timeout int    `short:"t" env:"${TimeoutEnv}" default:"30" help:"Clipboard timeout (0 to disable, ${env})"`
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

func englishPlural(singular, plural string, count int) string {
	if count%10 == 1 && count%100 != 11 {
		return singular
	}

	return plural
}

func decryptEntry(agentExecutable string, agentMemlock bool, agentSocket, identities, passwordStore, name string) (string, error) {
	if agentSocket == "" {
		return crypto.DecryptEntry(identities, passwordStore, name)
	}

	file, err := pago.EntryFile(passwordStore, name)
	if err != nil {
		return "", err
	}

	encryptedData, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read password file: %v", err)
	}

	if err := agent.Ping(agentSocket); err != nil {
		// Ping failed.
		// Attempt to start the agent.
		identitiesText, err := crypto.DecryptIdentities(identities)
		if err != nil {
			return "", err
		}

		if err := agent.StartProcess(agentExecutable, agentMemlock, agentSocket, identitiesText); err != nil {
			return "", fmt.Errorf("failed to start agent: %v", err)
		}
	}

	password, err := agent.Decrypt(agentSocket, encryptedData)
	if err != nil {
		return "", err
	}

	return password, nil
}

func (cmd *ClipCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	name := cmd.Name
	if cmd.Pick {
		picked, err := input.PickEntry(config.Store, name)
		if err != nil {
			return err
		}
		if picked == "" {
			return nil
		}
		name = picked
	}

	if !entryExists(config.Store, name) {
		return fmt.Errorf("entry doesn't exist: %v", name)
	}

	password, err := decryptEntry(
		config.AgentExecutable,
		config.Memlock,
		config.Socket,
		config.Identities,
		config.Store,
		name,
	)
	if err != nil {
		return err
	}

	if err := copyToClipboard(cmd.Command, password); err != nil {
		return fmt.Errorf("failed to copy password to clipboard: %v", err)
	}

	timeout := time.Duration(cmd.Timeout) * time.Second
	if timeout > 0 {
		fmt.Fprintf(
			os.Stderr,
			"Clearing clipboard in %v %s\n",
			cmd.Timeout,
			englishPlural("second", "seconds", cmd.Timeout),
		)

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
		picked, err := input.PickEntry(config.Store, name)
		if err != nil {
			return err
		}
		if picked == "" {
			return nil
		}
		name = picked
	}

	if !entryExists(config.Store, name) {
		return fmt.Errorf("entry doesn't exist: %v", name)
	}

	if !cmd.Force {
		if choice, err := input.AskYesNo(fmt.Sprintf("Delete entry '%s'?", name)); !choice || err != nil {
			return err
		}
	}

	file, err := pago.EntryFile(config.Store, name)
	if err != nil {
		return nil
	}

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
		if err := git.Commit(
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
	Save  bool   `default:"true" negatable:"" help:"Allow saving edited entry"`
	Pick  bool   `short:"p" help:"Pick entry using fuzzy finder"`
}

func (cmd *EditCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	name := cmd.Name
	if cmd.Pick {
		picked, err := input.PickEntry(config.Store, name)
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

	if entryExists(config.Store, name) {
		// Decrypt the existing password.
		password, err = decryptEntry(
			config.AgentExecutable,
			config.Memlock,
			config.Socket,
			config.Identities,
			config.Store,
			name,
		)
		if err != nil {
			return err
		}
	} else if !cmd.Force {
		return fmt.Errorf("entry doesn't exist: %v", name)
	}

	text, err := editor.Edit(password, cmd.Save)
	if err != nil && !errors.Is(err, editor.CancelError) {
		return fmt.Errorf("editor failed: %v", err)
	}

	fmt.Println()

	if text == password || errors.Is(err, editor.CancelError) {
		fmt.Fprintln(os.Stderr, "No changes made")
		return nil
	}

	// Save the edited password.
	if err := crypto.SaveEntry(config.Recipients, config.Store, name, text); err != nil {
		return err
	}

	file, err := pago.EntryFile(config.Store, cmd.Name)
	if err != nil {
		return nil
	}

	if config.Git {
		if err := git.Commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("edit %q", name),
			[]string{file},
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

	list, err := pago.ListFiles(config.Store, pago.EntryFilter(config.Store, pattern))
	if err != nil {
		return fmt.Errorf("failed to search entries: %v", err)
	}

	fmt.Println(strings.Join(list, "\n"))
	return nil
}

type GenerateCmd struct {
	Length  int    `short:"l" env:"${LengthEnv}" default:"${DefaultLength}" help:"Password length (${env})"`
	Pattern string `short:"p" env:"${PatternEnv}" default:"${DefaultPattern}" help:"Password pattern (regular expression, ${env})"`
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

	password, err := input.ReadNewPassword(config.Confirm)
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

	if err := os.MkdirAll(config.Store, pago.DirPerms); err != nil {
		return fmt.Errorf("failed to create store directory: %v", err)
	}

	if err := os.WriteFile(config.Identities, buf.Bytes(), pago.FilePerms); err != nil {
		return fmt.Errorf("failed to write identities file: %w", err)
	}

	if err := os.WriteFile(config.Recipients, []byte(identity.Recipient().String()+"\n"), pago.FilePerms); err != nil {
		return fmt.Errorf("failed to write recipients file: %w", err)
	}

	if config.Git {
		if err := git.InitRepo(config.Store); err != nil {
			return err
		}

		if err := git.Commit(
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

type PickCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`
}

func (cmd *PickCmd) Run(config *Config) error {
	showCmd := &ShowCmd{Name: cmd.Name, Pick: true}
	return showCmd.Run(config)
}

type RekeyCmd struct{}

func (cmd *RekeyCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	// Get a list of all password entries.
	entries, err := pago.ListFiles(config.Store, pago.EntryFilter(config.Store, nil))
	if err != nil {
		return fmt.Errorf("failed to list passwords: %v", err)
	}

	if len(entries) == 0 {
		return fmt.Errorf("no password entries found")
	}

	// Decrypt the identities once.
	// This is so we don't have to ask the user for a password repeatedly without using the agent.
	identitiesText, err := crypto.DecryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	ids, err := age.ParseIdentities(strings.NewReader(identitiesText))
	if err != nil {
		return fmt.Errorf("failed to parse identities: %v", err)
	}

	// Decrypt each entry using the loaded identities and reencrypt it with the recipients.
	count := 0
	for _, entry := range entries {
		file, err := crypto.EntryFile(config.Store, entry)
		if err != nil {
			return fmt.Errorf("failed to get path for %q: %v", entry, err)
		}

		encryptedData, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read password file %q: %v", entry, err)
		}

		r, err := crypto.WrapDecrypt(bytes.NewReader(encryptedData), ids...)
		if err != nil {
			return fmt.Errorf("failed to decrypt %q: %v", entry, err)
		}

		passwordBytes, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("failed to read decrypted content from %q: %v", entry, err)
		}

		if err := crypto.SaveEntry(config.Recipients, config.Store, entry, string(passwordBytes)); err != nil {
			return fmt.Errorf("failed to reencrypt %q: %v", entry, err)
		}

		count++
	}

	fmt.Fprintf(os.Stderr, "Reencrypted %d %s\n", count, englishPlural("entry", "entries", count))

	if config.Git {
		files := make([]string, len(entries))
		for i, entry := range entries {
			file, err := crypto.EntryFile(config.Store, entry)
			if err != nil {
				return fmt.Errorf("failed to get path for %q: %v", entry, err)
			}

			files[i] = file
		}

		if err := git.Commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("reencrypt %d %s", count, englishPlural("entry", "entries", count)),
			files,
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

	identitiesText, err := crypto.DecryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	newPassword, err := input.ReadNewPassword(config.Confirm)
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

	if err := os.WriteFile(config.Identities, buf.Bytes(), pago.FilePerms); err != nil {
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
		return tree.PrintStoreTree(config.Store)
	}

	name := cmd.Name
	if cmd.Pick {
		picked, err := input.PickEntry(config.Store, name)
		if err != nil {
			return err
		}
		if picked == "" {
			return nil
		}
		name = picked
	}

	if !entryExists(config.Store, name) {
		return fmt.Errorf("entry doesn't exist: %v", cmd.Name)
	}

	password, err := decryptEntry(
		config.AgentExecutable,
		config.Memlock,
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

	fmt.Println(pago.Version)
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
		AgentExecutable: cli.AgentExecutable,
		Confirm:         cli.Confirm,
		DataDir:         cli.Dir,
		Git:             cli.Git,
		GitEmail:        cli.GitEmail,
		GitName:         cli.GitName,
		Home:            home,
		Identities:      filepath.Join(cli.Dir, "identities"),
		Memlock:         cli.Memlock,
		Recipients:      filepath.Join(store, ".age-recipients"),
		Socket:          cli.Socket,
		Store:           store,
		Verbose:         cli.Verbose,
	}

	return &config, nil
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

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}

func entryExists(passwordStore, name string) bool {
	file, err := crypto.EntryFile(passwordStore, name)
	if err != nil {
		return false
	}

	return pathExists(file)
}

func main() {
	GitEmail := pago.DefaultGitEmail
	GitName := pago.DefaultGitName

	globalConfig, err := gitConfig.LoadConfig(gitConfig.GlobalScope)
	if err == nil {
		GitEmail = globalConfig.User.Email
		GitName = globalConfig.User.Name
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
			"DefaultAgent":   pago.DefaultAgent,
			"DefaultClip":    pago.DefaultClip,
			"DefaultDataDir": pago.DefaultDataDir,
			"DefaultLength":  pago.DefaultPasswordLength,
			"DefaultPattern": pago.DefaultPasswordPattern,
			"DefaultSocket":  pago.DefaultSocket,
			"GitEmail":       GitEmail,
			"GitName":        GitName,

			"AgentEnv":    pago.AgentEnv,
			"ClipEnv":     pago.ClipEnv,
			"ConfirmEnv":  pago.ConfirmEnv,
			"DataDirEnv":  pago.DataDirEnv,
			"GitEmailEnv": pago.GitEmailEnv,
			"GitEnv":      pago.GitEnv,
			"GitNameEnv":  pago.GitNameEnv,
			"MemlockEnv":  pago.MemlockEnv,
			"SocketEnv":   pago.SocketEnv,
			"TimeoutEnv":  pago.TimeoutEnv,
			"LengthEnv":   pago.LengthEnv,
			"PatternEnv":  pago.PatternEnv,
		},
	)

	// Set the default command according to whether the data directory exists.
	args := os.Args[1:]
	if len(args) == 0 {
		dataDir := os.Getenv(pago.DataDirEnv)
		if dataDir == "" {
			dataDir = pago.DefaultDataDir
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
		pago.ExitWithError("%v", err)
	}
	if config.Verbose {
		printRepr(config)
	}

	err = os.MkdirAll(config.Store, pago.DirPerms)
	if err != nil {
		pago.ExitWithError("failed to create password store directory: %v", err)
	}

	if err := ctx.Run(config); err != nil {
		pago.ExitWithError("%v", err)
	}
}
