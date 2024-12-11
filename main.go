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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/adrg/xdg"
	"github.com/anmitsu/go-shlex"
	tsize "github.com/kopoli/go-terminal-size"
	"github.com/mitchellh/go-wordwrap"
	"github.com/xlab/treeprint"
)

type Config struct {
	CacheDir   string
	Clip       []string
	DataDir    string
	Home       string
	Identities string
	Length     int
	Pattern    regexp.Regexp
	Recipients string
	Store      string
	Timeout    time.Duration
}

const (
	ageExt         = ".age"
	dirPerms       = 0o700
	defaultClip    = "xclip -in -selection clipboard"
	defaultLength  = "20"
	defaultPattern = "[A-Za-z0-9]"
	defaultTimeout = "30"
	maxSteps       = 10000
	version        = "0.3.0"
)

// Initialize configuration with defaults and environment variables.
func initConfig() (*Config, error) {
	clip, err := shlex.Split(getEnv("PAGO_CLIP", defaultClip), true)
	if err != nil {
		return nil, fmt.Errorf("failed to split clipboard command: %v", err)
	}
	if len(clip) == 0 {
		return nil, fmt.Errorf("empty clipboard command")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	length, err := strconv.Atoi(getEnv("PAGO_LENGTH", defaultLength))
	if err != nil {
		return nil, fmt.Errorf("invalid password length: %v", err)
	}

	timeoutSeconds, err := strconv.Atoi(getEnv("PAGO_TIMEOUT", defaultTimeout))
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %v", err)
	}

	patternString := getEnv("PAGO_PATTERN", defaultPattern)
	pattern, err := regexp.Compile(patternString)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %v", err)
	}

	cacheDir := getEnv("PAGO_CACHE_DIR", filepath.Join(xdg.CacheHome, "pago"))
	dataDir := getEnv("PAGO_DIR", filepath.Join(xdg.DataHome, "pago"))
	store := filepath.Join(dataDir, "store")

	config := Config{
		CacheDir:   cacheDir,
		Clip:       clip,
		DataDir:    dataDir,
		Home:       home,
		Identities: filepath.Join(dataDir, "identities"),
		Length:     length,
		Pattern:    *pattern,
		Recipients: filepath.Join(store, ".age-recipients"),
		Store:      store,
		Timeout:    time.Duration(timeoutSeconds) * time.Second,
	}

	return &config, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func exitWithError(format string, value any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", value)
	os.Exit(1)
}

func exitWithWrongUsage(format string, value any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", value)
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
		if steps >= maxSteps {
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

func passwordExists(passwordStore, name string) bool {
	_, err := os.Stat(passwordFile(passwordStore, name))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}

	return true
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

func decryptIdentities(identitiesPath string) (string, error) {
	f, err := os.Open(identitiesPath)
	if err != nil {
		return "", fmt.Errorf("failed to open identities file: %v", err)
	}
	defer f.Close()

	password, err := secureRead("Enter password to unlock identities: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}

	// Create a password-based identity and decrypt the private keys with it.
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return "", fmt.Errorf("failed to create password-based identity: %v", err)
	}

	r, err := wrapDecrypt(f, identity)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt identities: %v", err)
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read decrypted content: %v", err)
	}

	return string(decrypted), nil
}

func decryptPassword(identities, passwordStore, name string) (string, error) {
	// Decrypt the password-protected identities file first.
	identityFile, err := decryptIdentities(identities)
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
func showPassword(identities, passwordStore, name string) error {
	password, err := decryptPassword(identities, passwordStore, name)
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

// Copy text to clipboard with a timeout.
func copyToClipboard(command []string, timeout time.Duration, text string) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = strings.NewReader(text)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error copying to clipboard: %s", err)
	}

	if timeout > 0 {
		time.Sleep(timeout)

		cmd := exec.Command(command[0], command[1:]...)
		cmd.Stdin = strings.NewReader("")

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error clearing clipboard: %s", err)
		}
	}

	return nil
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
	tree := treeprint.New()
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

func wrapForTerm(s string) string {
	size, err := tsize.GetSize()
	if err != nil {
		return s
	}

	return wordwrap.WrapString(s, uint(size.Width))
}

func usage(dataDir, home string) {
	dataDir = strings.ReplaceAll(dataDir, home, "~")

	message := fmt.Sprintf(`pago %s - simple password manager.

=> [a]dd  [name] - Create a new password entry.
=> [c]opy [name] - Copy entry to the clipboard.
=> [d]el  [name] - Delete a password entry.
=> [g]enerate    - Generate a password.
=> [l]ist        - List all entries.
=> [s]how [name] - Show password for an entry.
=> [t]ree        - List all entries in a tree.

Password length:   PAGO_LENGTH=%s
Password pattern:  PAGO_PATTERN='%s'
Store location:    PAGO_DIR=%s
Clipboard tool:    PAGO_CLIP='%s'
Clipboard timeout: PAGO_TIMEOUT=%s ('off' to disable)
`,
		version,
		defaultLength,
		defaultPattern,
		dataDir,
		defaultClip,
		defaultTimeout,
	)

	fmt.Print(wrapForTerm(message))
}

func requireArgs(command string, minimum, maximum int) {
	actual := len(os.Args) - 2

	if actual < minimum {
		exitWithWrongUsage("too few arguments for '%s'", command)
	}

	if actual > maximum {
		exitWithWrongUsage("too many arguments for '%s'", command)
	}
}

func main() {
	config, err := initConfig()
	if err != nil {
		exitWithError("%v", err)
	}

	err = os.MkdirAll(config.Store, dirPerms)
	if err != nil {
		exitWithError("failed to create password store directory: %v", err)
	}

	printHelp := false
	if len(os.Args) < 2 {
		printHelp = true
	} else {
		for _, arg := range os.Args[1:] {
			if arg == "-h" || arg == "--help" {
				printHelp = true
				break
			}
		}
	}
	if printHelp {
		usage(config.DataDir, config.Home)
		os.Exit(0)
	}

	command := os.Args[1]
	var name string
	if len(os.Args) > 2 {
		name = os.Args[2]
	}

	if err := validatePath(config.Store, name); err != nil {
		exitWithError("%v", err)
	}

	switch command {

	case "a", "add":
		requireArgs(command, 1, 1)

		if passwordExists(config.Store, name) {
			exitWithError("password file already exists: %v", name)
		}

		generate, err := askYesNo("Generate a password?")
		if err != nil {
			exitWithError("%v", err)
		}

		password := ""
		if generate {
			password, err = generatePassword(config.Pattern, config.Length)
		} else {
			password, err = readNewPassword()
		}
		if err != nil {
			exitWithError("%v", err)
		}

		if err := savePassword(config.Recipients, config.Store, name, password); err != nil {
			exitWithError("%v", err)
		}
		fmt.Println("Password saved.")

	case "c", "copy":
		requireArgs(command, 1, 1)

		if !passwordExists(config.Store, name) {
			exitWithError("password file doesn't exist: %v", name)
		}

		password, err := decryptPassword(config.Identities, config.Store, name)
		if err != nil {
			exitWithError("%v", err)
		}
		if err := copyToClipboard(config.Clip, config.Timeout, password); err != nil {
			exitWithError("%v", err)
		}
		fmt.Println("Password copied to clipboard.")

	case "d", "del", "delete":
		requireArgs(command, 1, 1)

		if !passwordExists(config.Store, name) {
			exitWithError("password file doesn't exist: %v", name)
		}

		if err := deletePassword(config.Store, name); err != nil {
			exitWithError("%v", err)
		}

	case "g", "gen", "generate":
		requireArgs(command, 0, 0)

		password, err := generatePassword(config.Pattern, config.Length)
		if err != nil {
			exitWithError("%v", err)
		}
		fmt.Println(password)

	case "h", "help":
		requireArgs(command, 0, 0)

		usage(config.DataDir, config.Home)
		os.Exit(0)

	case "l", "list":
		requireArgs(command, 0, 0)

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
			exitWithError("failed to list password files: %v", err)
		}

		fmt.Println(strings.Join(list, "\n"))

	case "s", "show":
		requireArgs(command, 1, 1)

		if !passwordExists(config.Store, name) {
			exitWithError("password file doesn't exist: %v", name)
		}

		if err := showPassword(config.Identities, config.Store, name); err != nil {
			exitWithError("%v", err)
		}

	case "t", "tree":
		requireArgs(command, 0, 0)

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
			exitWithError("failed to build tree: %v", err)
		}

		fmt.Print(tree)

	default:
		exitWithWrongUsage("unknown command: %v", command)
	}
}
