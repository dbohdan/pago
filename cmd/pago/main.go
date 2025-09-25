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
	"reflect"
	"regexp"
	"sort"
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
	"github.com/BurntSushi/toml"
	"github.com/alecthomas/kong"
	"github.com/alecthomas/repr"
	"github.com/anmitsu/go-shlex"
	"github.com/atotto/clipboard"
	gitConfig "github.com/go-git/go-git/v5/config"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type CLI struct {
	// Global options.
	AgentExecutable string        `short:"a" name:"agent" env:"${AgentEnv}" default:"${DefaultAgent}" help:"Agent executable (${env})"`
	Confirm         bool          `env:"${ConfirmEnv}" default:"true" negatable:"" help:"Enter passwords twice (${env})"`
	Dir             string        `short:"d" env:"${DataDirEnv}" default:"${DefaultDataDir}" help:"Store location (${env})"`
	Expire          time.Duration `short:"e" env:"${ExpireEnv}" default:"0" help:"Agent expiration time (Go duration, 0 to disable, ${env})"`
	Git             bool          `env:"${GitEnv}" default:"true" negatable:"" help:"Commit to Git (${env})"`
	GitEmail        string        `env:"${GitEmailEnv}" default:"${GitEmail}" help:"Email for Git commits (${env})"`
	GitName         string        `env:"${GitNameEnv}" default:"${GitName}" help:"Name for Git commits (${env})"`
	Memlock         bool          `env:"${MemlockEnv}" default:"true" negatable:"" help:"Lock agent memory with mlockall(2) (${env})"`
	Socket          string        `short:"s" env:"${SocketEnv}" default:"${DefaultSocket}" help:"Agent socket path (blank to disable, ${env})"`
	Verbose         bool          `short:"v" hidden:"" help:"Print debugging information"`

	// Commands.
	Add      AddCmd      `cmd:"" aliases:"a" help:"Create new password entry"`
	Agent    AgentCmd    `cmd:"" hidden:"" help:"Control the agent process"`
	Clip     ClipCmd     `cmd:"" aliases:"c" help:"Copy entry to clipboard"`
	Delete   DeleteCmd   `cmd:"" aliases:"d,del,rm" help:"Delete password entry"`
	Edit     EditCmd     `cmd:"" aliases:"e" help:"Edit password entry"`
	Find     FindCmd     `cmd:"" aliases:"f" help:"Find entry by name"`
	Generate GenerateCmd `cmd:"" aliases:"g,gen" help:"Generate and print password"`
	Info     InfoCmd     `cmd:"" hidden:"" help:"Show information"`
	Init     InitCmd     `cmd:"" help:"Create a new password store"`
	Pick     PickCmd     `cmd:"" aliases:"p" help:"Show password entry picked with a fuzzy finder. A shortcut for \"show --pick\"."`
	Rekey    RekeyCmd    `cmd:"" help:"Reencrypt all password entries with the recipients file"`
	Rename   RenameCmd   `cmd:"" aliases:"mv,r" help:"Rename or move a password entry"`
	Rewrap   RewrapCmd   `cmd:"" help:"Change the password for the identities file"`
	Show     ShowCmd     `cmd:"" aliases:"s" help:"Show password entry or list entries"`
	Version  VersionCmd  `cmd:"" aliases:"v,ver" help:"Print version number and exit"`
}

// Config holds the resolved configuration for pago operations.
type Config struct {
	AgentExecutable string
	Confirm         bool
	DataDir         string
	Expire          time.Duration
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
	maxStepsPerChar = 1000 // Maximum attempts to find a random character matching the pattern.
	storePath       = "store"
)

type AddCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Force     bool   `short:"f" help:"Overwrite existing entry"`
	Input     bool   `short:"i" help:"Input the password manually" xor:"mode"`
	Length    int    `short:"l" env:"${LengthEnv}" default:"${DefaultLength}" help:"Password length (${env})"`
	Multiline bool   `short:"m" help:"Read from stdin until EOF" xor:"mode"`
	Pattern   string `short:"p" env:"${PatternEnv}" default:"${DefaultPattern}" help:"Password pattern (regular expression, ${env})"`
	Random    bool   `short:"r" help:"Generate a random password" xor:"mode"`
}

// printRepr prints a detailed representation of a Go value to stderr for debugging.
func printRepr(value any) {
	valueRepr := repr.String(
		value,
		repr.Indent("\t"),
		repr.OmitEmpty(false),
		repr.OmitZero(false),
	)
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
		fmt.Fprintln(os.Stderr, "Reading from stdin until EOF:")

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, os.Stdin); err != nil {
			return fmt.Errorf("failed to read from stdin: %v", err)
		}

		password = buf.String()
	} else {
		// Determine whether to generate a random password or prompt for manual input.
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
			var passwordBytes []byte
			passwordBytes, err = input.ReadNewPassword(config.Confirm)
			if err == nil {
				defer pago.Zero(passwordBytes)
				password = string(passwordBytes)
			}
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

	fmt.Fprintln(os.Stderr, "Entry saved")
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
		config.Expire,
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

	// Check if an agent is already running.
	if err := agent.Ping(config.Socket); err == nil {
		return fmt.Errorf("found agent responding on socket")
	}

	identitiesText, err := crypto.DecryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	return agent.StartProcess(
		config.AgentExecutable,
		config.Expire,
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

	return nil // This line is unreachable.
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

	Command string `short:"c" env:"${ClipEnv}" help:"Command for copying text from stdin to clipboard (${env})"`
	Key     string `short:"k" help:"Retrieve a key from a TOML entry"`
	Pick    bool   `short:"p" help:"Pick entry using fuzzy finder"`
	Timeout int    `short:"t" env:"${TimeoutEnv}" default:"30" help:"Clipboard timeout (0 to disable, ${env})"`
}

// copyToClipboard executes a command to copy text to the system clipboard.
func copyToClipboard(command string, text string) error {
	if command == "" {
		return clipboard.WriteAll(text)
	}

	args, err := shlex.Split(command, true)
	if err != nil {
		return fmt.Errorf("failed to split clipboard command: %v", err)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(text)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run clipboard command: %v", err)
	}

	return nil
}

// englishPlural returns the singular or plural form of a word based on count.
func englishPlural(singular, plural string, count int) string {
	if count%10 == 1 && count%100 != 11 {
		return singular
	}

	return plural
}

// decryptEntry decrypts a password entry, using the agent if available and configured.
func decryptEntry(agentExecutable string, agentExpire time.Duration, agentMemlock bool, agentSocket, identities, passwordStore, name string) ([]byte, error) {
	if agentSocket == "" {
		// Agent is disabled, decrypt directly.
		return crypto.DecryptEntry(identities, passwordStore, name)
	}

	file, err := pago.EntryFile(passwordStore, name)
	if err != nil {
		return nil, err
	}

	encryptedData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read password file: %v", err)
	}

	if err := agent.Ping(agentSocket); err != nil {
		// If ping fails, attempt to start the agent.
		identitiesText, err := crypto.DecryptIdentities(identities)
		if err != nil {
			return nil, err
		}

		if err := agent.StartProcess(agentExecutable, agentExpire, agentMemlock, agentSocket, identitiesText); err != nil {
			return nil, fmt.Errorf("failed to start agent: %v", err)
		}
	}

	content, err := agent.Decrypt(agentSocket, encryptedData)
	if err != nil {
		return nil, err
	}

	return content, nil
}

// isTOML returns whether content is a TOML entry.
func isTOML(content string) bool {
	return strings.HasPrefix(content, "# TOML")
}

// generateOTP generates a one-time password from an otpauth URI.
func generateOTP(otpURL string) (string, error) {
	otpKey, err := otp.NewKeyFromURL(otpURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse otpauth URL: %w", err)
	}

	opts := totp.ValidateOpts{
		Period:    uint(otpKey.Period()),
		Digits:    otpKey.Digits(),
		Algorithm: otpKey.Algorithm(),
	}

	code, err := totp.GenerateCodeCustom(otpKey.Secret(), time.Now(), opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	return code, nil
}

// getPassword decrypts an entry and returns its content, or a specific key's
// value if it's a TOML entry.
func getPassword(agentExecutable string, agentExpire time.Duration, agentMemlock bool, agentSocket, identities, passwordStore, name, key string) (string, error) {
	contentBytes, err := decryptEntry(agentExecutable, agentExpire, agentMemlock, agentSocket, identities, passwordStore, name)
	if err != nil {
		return "", err
	}
	defer pago.Zero(contentBytes)
	content := string(contentBytes)

	if !isTOML(content) {
		if key != "" {
			return "", fmt.Errorf("%q is not a TOML entry; cannot use key", name)
		}

		return content, nil
	}

	var data map[string]any
	if _, err := toml.Decode(content, &data); err != nil {
		return "", fmt.Errorf("failed to parse entry as TOML: %w", err)
	}

	if key == "" {
		key = "password"

		if defaultKey, ok := data["default"]; ok {
			if defaultKeyStr, ok := defaultKey.(string); ok {
				key = defaultKeyStr
			} else {
				return "", fmt.Errorf(`key "default" must have string value`)
			}
		}
	}

	value, ok := data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in entry %q", key, name)
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {

	case reflect.Map:
		return "", fmt.Errorf("key %q in entry %q is a table", key, name)

	case reflect.String:
		s := v.String()

		if key == "otp" {
			return generateOTP(s)
		}

		return s, nil
	}

	var buf bytes.Buffer
	err = toml.NewEncoder(&buf).Encode(value)
	if err != nil {
		return "", fmt.Errorf("failed to encode decoded value: %v", err)
	}

	return buf.String(), nil
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

	password, err := getPassword(
		config.AgentExecutable,
		config.Expire,
		config.Memlock,
		config.Socket,
		config.Identities,
		config.Store,
		name,
		cmd.Key,
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

// removeEmptyParentDirs recursively removes empty parent directories up to a specified root.
func removeEmptyParentDirs(top, dir string) {
	for dir != top {
		err := os.Remove(dir)
		if err != nil {
			// The directory is not empty or there was another error, stop.
			break
		}

		dir = filepath.Dir(dir)
	}
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

	removeEmptyParentDirs(config.Store, filepath.Dir(file))

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
	Name string `arg:"" optional:"" help:"Name of the password entry"`

	Force bool `short:"f" help:"Create the entry if it doesn't exist"`
	Mouse bool `env:"${MouseEnv}" default:"true" negatable:"" help:"Enable mouse support in the editor (${env})"`
	Pick  bool `short:"p" help:"Pick entry using fuzzy finder"`
	Save  bool `default:"true" negatable:"" help:"Allow saving edited entry"`
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

	var content string
	var err error

	if entryExists(config.Store, name) {
		// Decrypt the existing entry content.
		contentBytes, err := decryptEntry(
			config.AgentExecutable,
			config.Expire,
			config.Memlock,
			config.Socket,
			config.Identities,
			config.Store,
			name,
		)
		if err != nil {
			return err
		}

		content = string(contentBytes)
	} else if !cmd.Force {
		return fmt.Errorf("entry doesn't exist: %v", name)
	}

	newContent, err := editor.Edit(name, content, cmd.Save, cmd.Mouse)
	if err != nil && !errors.Is(err, editor.CancelError) {
		return fmt.Errorf("editor failed: %v", err)
	}

	fmt.Println()

	if newContent == content || errors.Is(err, editor.CancelError) {
		fmt.Fprintln(os.Stderr, "No changes made")
		return nil
	}

	// Save the edited entry.
	if err := crypto.SaveEntry(config.Recipients, config.Store, name, newContent); err != nil {
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

	fmt.Fprintln(os.Stderr, "Entry updated")
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

	passwordBytes, err := input.ReadNewPassword(config.Confirm)
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}
	defer pago.Zero(passwordBytes)

	recip, err := age.NewScryptRecipient(string(passwordBytes))
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

	Key string `short:"k" help:"Retrieve a key from a TOML entry"`
}

func (cmd *PickCmd) Run(config *Config) error {
	// This command is a shortcut for "show --pick".
	showCmd := &ShowCmd{Name: cmd.Name, Key: cmd.Key, Pick: true}
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

	// Decrypt the identities once to avoid repeated password prompts.
	identitiesText, err := crypto.DecryptIdentities(config.Identities)
	if err != nil {
		return err
	}

	ids, err := crypto.ParseIdentities(identitiesText)
	if err != nil {
		return fmt.Errorf("failed to parse identities: %v", err)
	}

	// Decrypt each entry using the loaded identities and re-encrypt it with the current recipients.
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

type RenameCmd struct {
	OldName string `arg:"" help:"Old name of the password entry"`
	NewName string `arg:"" help:"New name of the password entry"`
}

func (cmd *RenameCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	if !entryExists(config.Store, cmd.OldName) {
		return fmt.Errorf("entry doesn't exist: %v", cmd.OldName)
	}

	if entryExists(config.Store, cmd.NewName) {
		return fmt.Errorf("entry already exists: %v", cmd.NewName)
	}

	oldFile, err := pago.EntryFile(config.Store, cmd.OldName)
	if err != nil {
		return err
	}

	newFile, err := pago.EntryFile(config.Store, cmd.NewName)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(newFile), pago.DirPerms); err != nil {
		return fmt.Errorf("failed to create directory for new entry: %v", err)
	}

	if err := os.Rename(oldFile, newFile); err != nil {
		return fmt.Errorf("failed to rename entry: %v", err)
	}

	removeEmptyParentDirs(config.Store, filepath.Dir(oldFile))

	if config.Git {
		if err := git.Commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("rename %q to %q", cmd.OldName, cmd.NewName),
			[]string{oldFile, newFile},
		); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "Renamed %q to %q\n", cmd.OldName, cmd.NewName)
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

	newPasswordBytes, err := input.ReadNewPassword(config.Confirm)
	if err != nil {
		return err
	}
	defer pago.Zero(newPasswordBytes)

	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)

	recip, err := age.NewScryptRecipient(string(newPasswordBytes))
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

// getTOMLKeys decrypts a TOML entry and returns a sorted list of its keys.
func getTOMLKeys(agentExecutable string, agentExpire time.Duration, agentMemlock bool, agentSocket, identities, passwordStore, name string) ([]string, error) {
	contentBytes, err := decryptEntry(agentExecutable, agentExpire, agentMemlock, agentSocket, identities, passwordStore, name)
	if err != nil {
		return nil, err
	}
	defer pago.Zero(contentBytes)
	content := string(contentBytes)

	if !isTOML(content) {
		return nil, fmt.Errorf("%q is not a TOML entry; cannot list keys", name)
	}

	var data map[string]any
	if _, err := toml.Decode(content, &data); err != nil {
		return nil, fmt.Errorf("failed to parse entry as TOML: %w", err)
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys, nil
}

type ShowCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`

	Key  string `short:"k" help:"Retrieve a key from a TOML entry" xor:"toml"`
	Keys bool   `short:"K" help:"List keys in a TOML entry" xor:"toml"`
	Pick bool   `short:"p" help:"Pick entry using fuzzy finder"`
}

func (cmd *ShowCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	if cmd.Keys && cmd.Name == "" && !cmd.Pick {
		return fmt.Errorf("entry name required with --keys")
	}

	if !cmd.Pick && cmd.Name == "" {
		// If no name is provided and not picking, print the store tree.
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

	var output string
	if cmd.Keys {
		keys, err := getTOMLKeys(
			config.AgentExecutable,
			config.Expire,
			config.Memlock,
			config.Socket,
			config.Identities,
			config.Store,
			name,
		)
		if err != nil {
			return err
		}

		output = strings.Join(keys, "\n")
	} else {
		var err error
		output, err = getPassword(
			config.AgentExecutable,
			config.Expire,
			config.Memlock,
			config.Socket,
			config.Identities,
			config.Store,
			name,
			cmd.Key,
		)
		if err != nil {
			return err
		}
	}

	fmt.Print(output)
	if !strings.HasSuffix(output, "\n") {
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

// initConfig initializes the Config struct based on CLI arguments and environment variables.
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
		Expire:          cli.Expire,
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

// generatePassword generates a random password of a specified length,
// where each character matches a given regular expression pattern.
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

// pathExists checks if a file or directory exists at the given path.
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}

// entryExists checks if an entry with the given name exists in the store.
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

	// Attempt to load Git user configuration for default author details.
	globalConfig, err := gitConfig.LoadConfig(gitConfig.GlobalScope)
	if err == nil {
		GitEmail = globalConfig.User.Email
		GitName = globalConfig.User.Name
	}

	var cli CLI

	defaultSocket, err := pago.DefaultSocket()
	if err != nil {
		pago.ExitWithError("%v", err)
	}

	parser := kong.Must(&cli,
		kong.Name("pago"),
		kong.Description("A command-line password manager."),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Exit(func(code int) {
			if code != 0 {
				code = 2
			}

			os.Exit(code)
		}),
		kong.Vars{
			"DefaultAgent":   pago.DefaultAgent,
			"DefaultDataDir": pago.DefaultDataDir,
			"DefaultLength":  pago.DefaultPasswordLength,
			"DefaultPattern": pago.DefaultPasswordPattern,
			"DefaultSocket":  defaultSocket,
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
			"ExpireEnv":   pago.ExpireEnv,
			"MouseEnv":    pago.MouseEnv,
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
