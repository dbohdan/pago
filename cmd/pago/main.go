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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
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
	gogit "github.com/go-git/go-git/v5"
	gitConfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type CLI struct {
	// Global options.
	AgentExecutable string        `short:"a" name:"agent" env:"${AgentEnv}" default:"${DefaultAgent}" help:"Agent executable (${env})"`
	Confirm         bool          `env:"${ConfirmEnv}" default:"true" negatable:"" help:"Enter passwords twice (${env})"`
	Dir             string        `short:"d" env:"${DataDirEnv}" default:"${DefaultDataDir}" help:"Store location (${env})"`
	Expire          pago.Duration `short:"e" env:"${ExpireEnv}" default:"0" help:"Agent expiration time (Go duration or integer seconds, 0 to disable, ${env})"`
	Git             bool          `env:"${GitEnv}" default:"true" negatable:"" help:"Commit to Git (${env})"`
	GitEmail        string        `env:"${GitEmailEnv}" default:"${GitEmail}" help:"Email for Git commits (${env})"`
	GitName         string        `env:"${GitNameEnv}" default:"${GitName}" help:"Name for Git commits (${env})"`
	Memlock         bool          `env:"${MemlockEnv}" default:"true" negatable:"" help:"Lock agent memory with mlockall(2) (${env})"`
	PassphraseFD    int           `name:"passphrase-fd" env:"${PassphraseFDEnv}" default:"-1" help:"Read the master password from this file descriptor instead of prompting (${env})"`
	Socket          string        `short:"s" env:"${SocketEnv}" default:"${DefaultSocket}" help:"Agent socket path (blank to disable, ${env})"`
	Verbose         bool          `short:"v" hidden:"" help:"Print debugging information"`

	// Commands.
	Add        AddCmd      `cmd:"" aliases:"a" help:"Create new password entry"`
	Agent      AgentCmd    `cmd:"" hidden:"" help:"Control the agent process"`
	Clip       ClipCmd     `cmd:"" aliases:"c" help:"Copy entry to clipboard"`
	Copy       CopyCmd     `cmd:"" aliases:"cp,duplicate" help:"Duplicate a password entry"`
	Delete     DeleteCmd   `cmd:"" aliases:"d,del,rm" help:"Delete password entry"`
	Edit       EditCmd     `cmd:"" aliases:"e" help:"Edit password entry"`
	Find       FindCmd     `cmd:"" aliases:"f" help:"Find entry by name"`
	Generate   GenerateCmd `cmd:"" aliases:"g,gen" help:"Generate and print password"`
	GitCommand GitCmd      `cmd:"" name:"git" help:"Run Git inside the store directory"`
	Log        LogCmd      `cmd:"" help:"Show recent commits in the store's Git history"`
	Info       InfoCmd     `cmd:"" hidden:"" help:"Show information"`
	Init       InitCmd     `cmd:"" help:"Create a new password store"`
	Pick       PickCmd     `cmd:"" aliases:"p" help:"Show password entry picked with a fuzzy finder. A shortcut for \"show --pick\"."`
	Rekey      RekeyCmd    `cmd:"" help:"Reencrypt all password entries with the recipients file"`
	Rename     RenameCmd   `cmd:"" aliases:"mv,r" help:"Rename or move a password entry"`
	Rewrap     RewrapCmd   `cmd:"" help:"Change the password for the identities file"`
	Show       ShowCmd     `cmd:"" aliases:"s" help:"Show password entry or list entries"`
	Version    VersionCmd  `cmd:"" aliases:"v,ver" help:"Print version number and exit"`
}

// Config holds the resolved configuration for pago operations.
type Config struct {
	AgentExecutable string
	Confirm         bool
	DataDir         string
	Expire          pago.Duration
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

type AddCmd struct {
	Name string `arg:"" help:"Name of the password entry"`

	Force     bool   `short:"f" help:"Overwrite existing entry"`
	Input     bool   `short:"i" help:"Input the password manually" xor:"mode"`
	Length    int    `short:"l" env:"${LengthEnv}" default:"${DefaultLength}" help:"Password length (${env})"`
	Multiline bool   `short:"m" help:"Read from stdin until EOF" xor:"mode"`
	Pattern   string `short:"p" env:"${PatternEnv}" default:"${DefaultPattern}" help:"Password pattern (regular expression, ${env})"`
	Random    bool   `short:"r" help:"Generate a random password" xor:"mode"`
	Trim      bool   `short:"t" help:"Strip trailing newline characters from the password"`
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

func readMultiline() (string, error) {
	fmt.Fprintln(os.Stderr, "Reading from stdin until EOF:")

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, os.Stdin); err != nil {
		return "", fmt.Errorf("failed to read from stdin: %w", err)
	}

	return buf.String(), nil
}

func (cmd *AddCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	file, err := pago.EntryFile(config.Store, cmd.Name)
	if err != nil {
		return fmt.Errorf("failed to get entry file path: %w", err)
	}

	if !cmd.Force && entryExists(config.Store, cmd.Name) {
		return fmt.Errorf("entry already exists: %v", cmd.Name)
	}

	// Without an input-mode flag and without a terminal there is no way to
	// prompt the user. Default to reading the password from stdin verbatim.
	if !cmd.Multiline && !cmd.Input && !cmd.Random && !input.IsTerminal() {
		cmd.Multiline = true
	}

	var password string

	//nolint:nestif
	if cmd.Multiline {
		password, err = readMultiline()
	} else {
		// Determine whether to generate a random password or prompt for manual input.
		var generate bool

		if cmd.Input || cmd.Random {
			generate = cmd.Random
		} else {
			generate, err = input.AskYesNo("Generate a password?")
			if err != nil {
				return fmt.Errorf("failed to ask for password generation: %w", err)
			}
		}

		if generate {
			password, err = generatePassword(cmd.Pattern, cmd.Length)
		} else {
			password, err = input.ReadNewPassword(config.Confirm)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to get password: %w", err)
	}

	if cmd.Trim {
		password = strings.TrimRight(password, "\r\n")
	}

	if err := crypto.SaveEntry(config.Recipients, config.Store, cmd.Name, password); err != nil {
		return fmt.Errorf("failed to save entry: %w", err)
	}

	if config.Git {
		if err := git.Commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("add %q", cmd.Name),
			[]string{file},
		); err != nil {
			return fmt.Errorf("failed to commit to Git: %w", err)
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
		return fmt.Errorf("failed to decrypt identities: %w", err)
	}

	return agent.StartProcess(
		config.AgentExecutable,
		config.Expire.Duration(),
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
		return errors.New("found agent responding on socket")
	}

	identitiesText, err := crypto.DecryptIdentities(config.Identities)
	if err != nil {
		return fmt.Errorf("failed to decrypt identities: %w", err)
	}

	return agent.StartProcess(
		config.AgentExecutable,
		config.Expire.Duration(),
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
		os.Exit(pago.ExitOK)
	}

	fmt.Println("Failed to ping agent")
	os.Exit(pago.ExitError)

	return nil // Never reached.
}

type StopCmd struct{}

func (cmd *StopCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	_, err := agent.Message(config.Socket, "SHUTDOWN")
	if err != nil {
		return fmt.Errorf("failed to send shutdown message: %w", err)
	}

	return nil
}

type ClipCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`

	Command string        `short:"c" env:"${ClipEnv}" help:"Command for copying text from stdin to clipboard (${env})"`
	Key     []string      `short:"k" help:"Retrieve a key from a TOML entry (repeatable)"`
	Pick    bool          `short:"p" help:"Pick entry using fuzzy finder"`
	Timeout pago.Duration `short:"t" env:"${TimeoutEnv}" default:"30" help:"Clipboard timeout (Go duration or integer seconds, 0 to disable, ${env})"`
}

// copyToClipboard executes a command to copy text to the system clipboard.
func copyToClipboard(command string, text string) error {
	if command == "" {
		return fmt.Errorf("failed to write to clipboard: %w", clipboard.WriteAll(text))
	}

	args, err := shlex.Split(command, true)
	if err != nil {
		return fmt.Errorf("failed to split clipboard command: %w", err)
	}

	//nolint:gosec
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(text)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run clipboard command: %w", err)
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
func decryptEntry(agentExecutable string, agentExpire time.Duration, agentMemlock bool, agentSocket, identities, passwordStore, name string) (string, error) {
	if agentSocket == "" {
		// Agent is disabled, decrypt directly.
		return crypto.DecryptEntry(identities, passwordStore, name)
	}

	file, err := pago.EntryFile(passwordStore, name)
	if err != nil {
		return "", fmt.Errorf("failed to get entry file path: %w", err)
	}

	encryptedData, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read password file: %w", err)
	}

	if err := agent.Ping(agentSocket); err != nil {
		// If ping fails, attempt to start the agent.
		identitiesText, err := crypto.DecryptIdentities(identities)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt identities: %w", err)
		}

		if err := agent.StartProcess(agentExecutable, agentExpire, agentMemlock, agentSocket, identitiesText); err != nil {
			return "", fmt.Errorf("%w: %w", pago.ErrAgent, err)
		}
	}

	content, err := agent.Decrypt(agentSocket, encryptedData)
	if err != nil {
		return "", fmt.Errorf("%w: %w", pago.ErrDecryption, err)
	}

	return string(content), nil
}

// isTOML returns whether content is a TOML entry.
func isTOML(content string) bool {
	return strings.HasPrefix(content, "# TOML")
}

// validateEntryContent rejects content marked as TOML that does not parse.
// Non-TOML entries are accepted unchanged.
func validateEntryContent(content string) error {
	if !isTOML(content) {
		return nil
	}

	var data map[string]any
	if _, err := toml.Decode(content, &data); err != nil {
		return fmt.Errorf("invalid TOML: %w", err)
	}

	return nil
}

// generateOTP generates a one-time password from an otpauth URI.
func generateOTP(otpURL string) (string, error) {
	otpKey, err := otp.NewKeyFromURL(otpURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse otpauth URL: %w", err)
	}

	opts := totp.ValidateOpts{
		Period:    uint(otpKey.Period()),
		Skew:      0,
		Digits:    otpKey.Digits(),
		Algorithm: otpKey.Algorithm(),
		Encoder:   "",
	}

	code, err := totp.GenerateCodeCustom(otpKey.Secret(), time.Now(), opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	return code, nil
}

// marshalJSON returns v JSON-encoded as a string.
func marshalJSON(v any) (string, error) {
	buf, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(buf), nil
}

// quoteKeyPath formats a TOML key path for display in error messages.
// It does so by quoting each key with %q and joining them with periods.
// For example: []string{"a", "b"} becomes "a"."b".
func quoteKeyPath(keys []string) string {
	quoted := []string{}

	for _, key := range keys {
		quoted = append(quoted, fmt.Sprintf("%q", key))
	}

	return strings.Join(quoted, ".")
}

// getPassword decrypts an entry and returns its content, or a specific key's
// value if it's a TOML entry. When asJSON is true the value is JSON-encoded
// instead of being formatted for human display.
func getPassword(agentExecutable string, agentExpire time.Duration, agentMemlock bool, agentSocket, identities, passwordStore, name string, keys []string, asJSON bool) (string, error) {
	content, err := decryptEntry(agentExecutable, agentExpire, agentMemlock, agentSocket, identities, passwordStore, name)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt entry: %w", err)
	}

	if !isTOML(content) {
		if len(keys) > 0 {
			return "", fmt.Errorf("%q is not a TOML entry; cannot use keys", name)
		}

		if asJSON {
			return marshalJSON(content)
		}

		return content, nil
	}

	var data map[string]any
	if _, err := toml.Decode(content, &data); err != nil {
		return "", fmt.Errorf("failed to parse entry as TOML: %w", err)
	}

	effectiveKeys := keys
	if len(effectiveKeys) == 0 && !asJSON {
		key := pago.DefaultTOMLPasswordKey

		if defaultKey, ok := data[pago.TOMLDefaultKey]; ok {
			if defaultKeyStr, ok := defaultKey.(string); ok {
				key = defaultKeyStr
			} else {
				return "", fmt.Errorf("key %q must have string value", pago.TOMLDefaultKey)
			}
		}

		effectiveKeys = []string{key}
	}

	var value any = data
	for i, key := range effectiveKeys {
		currentMap, ok := value.(map[string]any)
		if !ok {
			return "", fmt.Errorf("value at key path %s is not a table", quoteKeyPath(effectiveKeys[:i]))
		}

		v, ok := currentMap[key]
		if !ok {
			return "", fmt.Errorf("key path %s not found in entry %q", quoteKeyPath(effectiveKeys[:i+1]), name)
		}

		value = v
	}

	if s, ok := value.(string); ok && strings.HasPrefix(s, "otpauth://") {
		code, err := generateOTP(s)
		if err != nil {
			return "", err
		}

		if asJSON {
			return marshalJSON(code)
		}

		return code, nil
	}

	if asJSON {
		return marshalJSON(value)
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Map:
		return "", fmt.Errorf("key path %s in entry %q is a table", quoteKeyPath(effectiveKeys), name)

	case reflect.String:
		return v.String(), nil

	default:
		// Do nothing.
	}

	var buf bytes.Buffer

	err = toml.NewEncoder(&buf).Encode(value)
	if err != nil {
		return "", fmt.Errorf("failed to encode decoded value: %w", err)
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
			return fmt.Errorf("failed to pick entry: %w", err)
		}

		if picked == "" {
			return nil
		}

		name = picked
	}

	if !entryExists(config.Store, name) {
		return fmt.Errorf("%w: %v", pago.ErrEntryNotFound, name)
	}

	password, err := getPassword(
		config.AgentExecutable,
		config.Expire.Duration(),
		config.Memlock,
		config.Socket,
		config.Identities,
		config.Store,
		name,
		cmd.Key,
		false,
	)
	if err != nil {
		return fmt.Errorf("failed to get password: %w", err)
	}

	if err := copyToClipboard(cmd.Command, password); err != nil {
		return fmt.Errorf("failed to copy password to clipboard: %w", err)
	}

	timeout := cmd.Timeout.Duration()
	if timeout > 0 {
		fmt.Fprintf(os.Stderr, "Clearing clipboard in %v\n", timeout)

		// Catch SIGINT and SIGTERM so a hasty Ctrl+C does not leave the
		// password sitting on the clipboard.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		defer signal.Stop(sigCh)

		select {
		case <-time.After(timeout):
		case <-sigCh:
		}

		if err := copyToClipboard(cmd.Command, ""); err != nil {
			return fmt.Errorf("failed to clear clipboard: %w", err)
		}
	}

	return nil
}

type CopyCmd struct {
	OldName string `arg:"" help:"Source entry name"`
	NewName string `arg:"" help:"Destination entry name"`

	Force bool `short:"f" help:"Overwrite existing destination entry"`
}

func (cmd *CopyCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	if !entryExists(config.Store, cmd.OldName) {
		return fmt.Errorf("%w: %v", pago.ErrEntryNotFound, cmd.OldName)
	}

	if !cmd.Force && entryExists(config.Store, cmd.NewName) {
		return fmt.Errorf("entry already exists: %v", cmd.NewName)
	}

	content, err := decryptEntry(
		config.AgentExecutable,
		config.Expire.Duration(),
		config.Memlock,
		config.Socket,
		config.Identities,
		config.Store,
		cmd.OldName,
	)
	if err != nil {
		return fmt.Errorf("failed to decrypt source entry: %w", err)
	}

	if err := crypto.SaveEntry(config.Recipients, config.Store, cmd.NewName, content); err != nil {
		return fmt.Errorf("failed to save destination entry: %w", err)
	}

	newFile, err := pago.EntryFile(config.Store, cmd.NewName)
	if err != nil {
		return fmt.Errorf("failed to get destination file path: %w", err)
	}

	if config.Git {
		if err := git.Commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("copy %q to %q", cmd.OldName, cmd.NewName),
			[]string{newFile},
		); err != nil {
			return fmt.Errorf("failed to commit to Git: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Copied %q to %q\n", cmd.OldName, cmd.NewName)

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
			return fmt.Errorf("failed to pick entry: %w", err)
		}

		if picked == "" {
			return nil
		}

		name = picked
	}

	if !entryExists(config.Store, name) {
		return fmt.Errorf("%w: %v", pago.ErrEntryNotFound, name)
	}

	if !cmd.Force {
		if !input.IsTerminal() {
			return errors.New("cannot prompt for confirmation: stdin is not a terminal; pass --force to delete without confirmation")
		}

		if choice, err := input.AskYesNo(fmt.Sprintf("Delete entry '%s'?", name)); !choice || err != nil {
			if err != nil {
				return fmt.Errorf("failed to confirm deletion: %w", err)
			}

			return nil
		}
	}

	file, err := pago.EntryFile(config.Store, name)
	if err != nil {
		return fmt.Errorf("failed to get entry file path: %w", err)
	}

	if err := os.Remove(file); err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
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
			return fmt.Errorf("failed to commit to Git: %w", err)
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

	if !input.IsTerminal() {
		return errors.New("cannot run editor: stdin is not a terminal")
	}

	name := cmd.Name
	if cmd.Pick {
		picked, err := input.PickEntry(config.Store, name)
		if err != nil {
			return fmt.Errorf("failed to pick entry: %w", err)
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
		content, err = decryptEntry(
			config.AgentExecutable,
			config.Expire.Duration(),
			config.Memlock,
			config.Socket,
			config.Identities,
			config.Store,
			name,
		)
		if err != nil {
			return fmt.Errorf("failed to decrypt entry: %w", err)
		}
	} else if !cmd.Force {
		return fmt.Errorf("%w: %v", pago.ErrEntryNotFound, name)
	}

	newContent, err := editor.Edit(name, content, cmd.Save, cmd.Mouse)
	if err != nil && !errors.Is(err, editor.ErrCancel) {
		return fmt.Errorf("editor failed: %w", err)
	}

	fmt.Println()

	if newContent == content || errors.Is(err, editor.ErrCancel) {
		fmt.Fprintln(os.Stderr, "No changes made")

		return nil
	}

	if err := validateEntryContent(newContent); err != nil {
		return fmt.Errorf("entry was not saved: %w", err)
	}

	// Save the edited entry.
	if err := crypto.SaveEntry(config.Recipients, config.Store, name, newContent); err != nil {
		return fmt.Errorf("failed to save entry: %w", err)
	}

	file, err := pago.EntryFile(config.Store, cmd.Name)
	if err != nil {
		return fmt.Errorf("failed to get entry file path: %w", err)
	}

	if config.Git {
		if err := git.Commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			fmt.Sprintf("edit %q", name),
			[]string{file},
		); err != nil {
			return fmt.Errorf("failed to commit to Git: %w", err)
		}
	}

	fmt.Fprintln(os.Stderr, "Entry updated")

	return nil
}

type FindCmd struct {
	Pattern string `arg:"" default:"" help:"Pattern to search for (regular expression)"`

	JSON bool `short:"j" name:"json" help:"Output as a JSON array"`
}

func (cmd *FindCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	pattern, err := regexp.Compile(cmd.Pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regular expression: %w", err)
	}

	list, err := pago.ListFiles(config.Store, pago.EntryFilter(config.Store, pattern))
	if err != nil {
		return fmt.Errorf("failed to search entries: %w", err)
	}

	if cmd.JSON {
		buf, err := json.Marshal(list)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		fmt.Println(string(buf))

		return nil
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
		return fmt.Errorf("failed to generate password: %w", err)
	}

	fmt.Println(password)

	return nil
}

type GitCmd struct {
	Command string   `name:"git-command" env:"${GitCommandEnv}" default:"git" help:"Git command to invoke (${env})"`
	Args    []string `arg:"" optional:"" passthrough:"" help:"Arguments to pass to Git"`
}

func (cmd *GitCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	parts, err := shlex.Split(cmd.Command, true)
	if err != nil {
		return fmt.Errorf("failed to split git command: %w", err)
	}

	if len(parts) == 0 {
		return errors.New("git command is empty")
	}

	args := make([]string, 0, len(parts)-1+2+len(cmd.Args))
	args = append(args, parts[1:]...)
	args = append(args, "-C", config.Store)
	args = append(args, cmd.Args...)

	//nolint:gosec
	runCmd := exec.Command(parts[0], args...)
	runCmd.Stdin = os.Stdin
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	if err := runCmd.Run(); err != nil {
		return fmt.Errorf("git command failed: %w", err)
	}

	return nil
}

type InfoCmd struct {
	Dir DirCmd `cmd:"" help:"Show data directory path"`
}

type DirCmd struct{}

//nolint:unparam
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
		return errors.New("identities file already exists")
	}

	if pathExists(config.Recipients) {
		return errors.New("recipients file already exists")
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
		return fmt.Errorf("failed to read password: %w", err)
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
		return fmt.Errorf("failed to create store directory: %w", err)
	}

	if err := pago.WriteFileAtomic(config.Identities, buf.Bytes(), pago.FilePerms); err != nil {
		return fmt.Errorf("failed to write identities file: %w", err)
	}

	if err := pago.WriteFileAtomic(config.Recipients, []byte(identity.Recipient().String()+"\n"), pago.FilePerms); err != nil {
		return fmt.Errorf("failed to write recipients file: %w", err)
	}

	if config.Git {
		if err := git.InitRepo(config.Store); err != nil {
			return fmt.Errorf("failed to initialize Git repository: %w", err)
		}

		if err := git.Commit(
			config.Store,
			config.GitName,
			config.GitEmail,
			"Initial commit",
			[]string{config.Recipients},
		); err != nil {
			return fmt.Errorf("failed to commit to Git: %w", err)
		}
	}

	return nil
}

type LogCmd struct {
	MaxCount int `short:"n" default:"10" help:"Maximum number of commits to show"`
}

func (cmd *LogCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	repo, err := gogit.PlainOpen(config.Store)
	if err != nil {
		if errors.Is(err, gogit.ErrRepositoryNotExists) {
			return errors.New("the store directory is not a Git repository")
		}

		return fmt.Errorf("failed to open Git repository: %w", err)
	}

	ref, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to resolve HEAD: %w", err)
	}

	iter, err := repo.Log(&gogit.LogOptions{From: ref.Hash()}) //nolint:exhaustruct
	if err != nil {
		return fmt.Errorf("failed to read log: %w", err)
	}
	defer iter.Close()

	type entry struct {
		date    string
		files   string
		subject string
	}

	entries := []entry{}
	maxFiles := 0

	err = iter.ForEach(func(commit *object.Commit) error {
		if len(entries) >= cmd.MaxCount {
			return storer.ErrStop
		}

		stats, err := commit.Stats()
		if err != nil {
			return fmt.Errorf("failed to read stats for %s: %w", commit.Hash, err)
		}

		quoted := make([]string, 0, len(stats))
		for _, s := range stats {
			quoted = append(quoted, fmt.Sprintf("%q", s.Name))
		}

		files := strings.Join(quoted, " ")
		if len(files) > maxFiles {
			maxFiles = len(files)
		}

		subject, _, _ := strings.Cut(commit.Message, "\n")

		entries = append(entries, entry{
			date:    commit.Author.When.Format("2006-01-02 15:04 -0700"),
			files:   files,
			subject: subject,
		})

		return nil
	})
	if err != nil && !errors.Is(err, storer.ErrStop) {
		return fmt.Errorf("log iteration failed: %w", err)
	}

	for _, e := range entries {
		fmt.Printf("%s %-*s %s\n", e.date, maxFiles, e.files, e.subject)
	}

	return nil
}

type PickCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`

	JSON bool     `short:"j" name:"json" help:"Output result as JSON"`
	Key  []string `short:"k" help:"Retrieve a key from a TOML entry (repeatable)"`
}

func (cmd *PickCmd) Run(config *Config) error {
	// This command is a shortcut for "show --pick".
	showCmd := &ShowCmd{Name: cmd.Name, JSON: cmd.JSON, Key: cmd.Key, Keys: false, Pick: true}

	return showCmd.Run(config)
}

// pushIdentitiesToAgent forwards fresh identities to a running agent so it
// does not go stale after a rekey or rewrap. It is a no-op if the agent
// socket is disabled or no agent is listening.
func pushIdentitiesToAgent(socket, identitiesText string) error {
	if socket == "" {
		return nil
	}

	if err := agent.Ping(socket); err != nil {
		return nil //nolint:nilerr // No agent running is not an error here.
	}

	if _, err := agent.Message(socket, "IDENTITIES", identitiesText); err != nil {
		return fmt.Errorf("failed to update agent identities: %w", err)
	}

	return nil
}

type RekeyCmd struct{}

func (cmd *RekeyCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	// Get a list of all password entries.
	entries, err := pago.ListFiles(config.Store, pago.EntryFilter(config.Store, nil))
	if err != nil {
		return fmt.Errorf("failed to list passwords: %w", err)
	}

	if len(entries) == 0 {
		return errors.New("no password entries found")
	}

	// Decrypt the identities once to avoid repeated password prompts.
	identitiesText, err := crypto.DecryptIdentities(config.Identities)
	if err != nil {
		return fmt.Errorf("failed to decrypt identities: %w", err)
	}

	ids, err := crypto.ParseIdentities(identitiesText)
	if err != nil {
		return fmt.Errorf("failed to parse identities: %w", err)
	}

	// Decrypt each entry using the loaded identities and re-encrypt it with the current recipients.
	count := 0

	for _, entry := range entries {
		file, err := pago.EntryFile(config.Store, entry)
		if err != nil {
			return fmt.Errorf("failed to get path for %q: %w", entry, err)
		}

		encryptedData, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read password file %q: %w", entry, err)
		}

		r, err := crypto.WrapDecrypt(bytes.NewReader(encryptedData), ids...)
		if err != nil {
			return fmt.Errorf("failed to decrypt %q: %w", entry, err)
		}

		passwordBytes, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("failed to read decrypted content from %q: %w", entry, err)
		}

		if err := crypto.SaveEntry(config.Recipients, config.Store, entry, string(passwordBytes)); err != nil {
			return fmt.Errorf("failed to reencrypt %q: %w", entry, err)
		}

		count++
	}

	fmt.Fprintf(os.Stderr, "Reencrypted %d %s\n", count, englishPlural("entry", "entries", count))

	if err := pushIdentitiesToAgent(config.Socket, identitiesText); err != nil {
		return err
	}

	if config.Git {
		files := make([]string, len(entries))
		for i, entry := range entries {
			file, err := pago.EntryFile(config.Store, entry)
			if err != nil {
				return fmt.Errorf("failed to get path for %q: %w", entry, err)
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
			return fmt.Errorf("failed to commit to Git: %w", err)
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
		return fmt.Errorf("%w: %v", pago.ErrEntryNotFound, cmd.OldName)
	}

	if entryExists(config.Store, cmd.NewName) {
		return fmt.Errorf("entry already exists: %v", cmd.NewName)
	}

	oldFile, err := pago.EntryFile(config.Store, cmd.OldName)
	if err != nil {
		return fmt.Errorf("failed to get old entry file path: %w", err)
	}

	newFile, err := pago.EntryFile(config.Store, cmd.NewName)
	if err != nil {
		return fmt.Errorf("failed to get new entry file path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(newFile), pago.DirPerms); err != nil {
		return fmt.Errorf("failed to create directory for new entry: %w", err)
	}

	if err := os.Rename(oldFile, newFile); err != nil {
		return fmt.Errorf("failed to rename entry: %w", err)
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
			return fmt.Errorf("failed to commit to Git: %w", err)
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
		return fmt.Errorf("failed to decrypt identities: %w", err)
	}

	newPassword, err := input.ReadNewPassword(config.Confirm)
	if err != nil {
		return fmt.Errorf("failed to read new password: %w", err)
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

	if err := pago.WriteFileAtomic(config.Identities, buf.Bytes(), pago.FilePerms); err != nil {
		return fmt.Errorf("failed to write identities file: %w", err)
	}

	if err := pushIdentitiesToAgent(config.Socket, identitiesText); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Identities file reencrypted")

	return nil
}

// getTOMLKeys decrypts a TOML entry and returns a sorted list of its keys.
func getTOMLKeys(agentExecutable string, agentExpire time.Duration, agentMemlock bool, agentSocket, identities, passwordStore, name string, keyPath []string) ([]string, error) {
	content, err := decryptEntry(agentExecutable, agentExpire, agentMemlock, agentSocket, identities, passwordStore, name)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt entry: %w", err)
	}

	if !isTOML(content) {
		return nil, fmt.Errorf("%q is not a TOML entry; cannot list keys", name)
	}

	var data map[string]any
	if _, err := toml.Decode(content, &data); err != nil {
		return nil, fmt.Errorf("failed to parse entry as TOML: %w", err)
	}

	var value any = data
	for i, key := range keyPath {
		currentMap, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("value at key path %s is not a table", quoteKeyPath(keyPath[:i]))
		}

		v, ok := currentMap[key]
		if !ok {
			return nil, fmt.Errorf("key path %s not found in entry %q", quoteKeyPath(keyPath[:i+1]), name)
		}

		value = v
	}

	currentMap, ok := value.(map[string]any)
	if !ok {
		if len(keyPath) > 0 {
			return nil, fmt.Errorf("value at key path %s is not a table", quoteKeyPath(keyPath))
		}

		return nil, fmt.Errorf("entry %q is not a TOML table", name)
	}

	keys := make([]string, 0, len(currentMap))
	for k := range currentMap {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys, nil
}

type ShowCmd struct {
	Name string `arg:"" optional:"" help:"Name of the password entry"`

	JSON bool     `short:"j" name:"json" help:"Output result as JSON"`
	Key  []string `short:"k" help:"Retrieve a key from a TOML entry (repeatable)"`
	Keys bool     `short:"K" help:"List keys in a TOML entry"`
	Pick bool     `short:"p" help:"Pick entry using fuzzy finder"`
}

func (cmd *ShowCmd) Run(config *Config) error {
	if config.Verbose {
		printRepr(cmd)
	}

	if cmd.Keys && cmd.Name == "" && !cmd.Pick {
		return errors.New("entry name required with --keys")
	}

	if !cmd.Pick && cmd.Name == "" {
		// If no name is provided and not picking, print the store tree.
		return tree.PrintStoreTree(config.Store)
	}

	name := cmd.Name
	if cmd.Pick {
		picked, err := input.PickEntry(config.Store, name)
		if err != nil {
			return fmt.Errorf("failed to pick entry: %w", err)
		}

		if picked == "" {
			return nil
		}

		name = picked
	}

	if !entryExists(config.Store, name) {
		return fmt.Errorf("%w: %v", pago.ErrEntryNotFound, cmd.Name)
	}

	output, err := cmd.fetchOutput(config, name)
	if err != nil {
		return err
	}

	fmt.Print(output)

	if !strings.HasSuffix(output, "\n") {
		fmt.Println()
	}

	return nil
}

// fetchOutput returns the formatted output for `show`, choosing between key
// listing and value retrieval and applying JSON formatting where requested.
func (cmd *ShowCmd) fetchOutput(config *Config, name string) (string, error) {
	if cmd.Keys {
		keys, err := getTOMLKeys(
			config.AgentExecutable,
			config.Expire.Duration(),
			config.Memlock,
			config.Socket,
			config.Identities,
			config.Store,
			name,
			cmd.Key,
		)
		if err != nil {
			return "", fmt.Errorf("failed to get TOML keys: %w", err)
		}

		if cmd.JSON {
			return marshalJSON(keys)
		}

		return strings.Join(keys, "\n"), nil
	}

	output, err := getPassword(
		config.AgentExecutable,
		config.Expire.Duration(),
		config.Memlock,
		config.Socket,
		config.Identities,
		config.Store,
		name,
		cmd.Key,
		cmd.JSON,
	)
	if err != nil {
		return "", fmt.Errorf("failed to get password: %w", err)
	}

	return output, nil
}

type VersionCmd struct{}

//nolint:unparam
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
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	store := filepath.Join(cli.Dir, pago.StorePath)

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
		return "", fmt.Errorf("failed to compile regular expression: %w", err)
	}

	var password strings.Builder
	steps := 0

	for password.Len() < length {
		b := make([]byte, 1)

		_, err := rand.Read(b)
		if err != nil {
			return "", fmt.Errorf("failed to generate random byte: %w", err)
		}

		char := string(b[0])
		if regexpPattern.MatchString(char) {
			password.WriteString(char)
		}

		steps++
		if steps == length*pago.MaxStepsPerChar {
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
	file, err := pago.EntryFile(passwordStore, name)
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

			"AgentEnv":        pago.AgentEnv,
			"ClipEnv":         pago.ClipEnv,
			"ConfirmEnv":      pago.ConfirmEnv,
			"DataDirEnv":      pago.DataDirEnv,
			"GitCommandEnv":   pago.GitCommandEnv,
			"GitEmailEnv":     pago.GitEmailEnv,
			"GitEnv":          pago.GitEnv,
			"GitNameEnv":      pago.GitNameEnv,
			"MemlockEnv":      pago.MemlockEnv,
			"ExpireEnv":       pago.ExpireEnv,
			"MouseEnv":        pago.MouseEnv,
			"PassphraseFDEnv": pago.PassphraseFDEnv,
			"SocketEnv":       pago.SocketEnv,
			"TimeoutEnv":      pago.TimeoutEnv,
			"LengthEnv":       pago.LengthEnv,
			"PatternEnv":      pago.PatternEnv,
		},
	)

	// Set the default command according to whether the data directory exists.
	args := os.Args[1:]
	if len(args) == 0 {
		dataDir := os.Getenv(pago.DataDirEnv)
		if dataDir == "" {
			dataDir = pago.DefaultDataDir
		}

		storeDir := filepath.Join(dataDir, pago.StorePath)

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

	if err := input.SetPassphraseFD(cli.PassphraseFD); err != nil {
		pago.ExitWithError("%v", err)
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
		pago.PrintError("%v", err)
		os.Exit(exitCodeFor(err))
	}
}

// exitCodeFor inspects an error chain and returns a matching exit code.
func exitCodeFor(err error) int {
	switch {
	case errors.Is(err, pago.ErrEntryNotFound):
		return pago.ExitNotFound
	case errors.Is(err, pago.ErrAgent):
		return pago.ExitAgent
	case errors.Is(err, pago.ErrDecryption):
		return pago.ExitDecryption
	default:
		return pago.ExitError
	}
}
