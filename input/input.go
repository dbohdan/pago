// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package input

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"dbohdan.com/pago"

	"github.com/ktr0731/go-fuzzyfinder"
	"golang.org/x/term"
)

// PickEntry interactively selects an entry using a fuzzy finder.
func PickEntry(store string, query string) (string, error) {
	// Create a list of all passwords.
	list, err := pago.ListFiles(store, pago.EntryFilter(store, nil))
	if err != nil {
		return "", fmt.Errorf("failed to list passwords: %w", err)
	}

	if len(list) == 0 {
		return "", errors.New("no password entries found")
	}

	// Show an interactive fuzzy finder.
	idx, err := fuzzyfinder.Find(
		list,
		func(i int) string {
			return list[i]
		},
		fuzzyfinder.WithQuery(query),
	)
	if err != nil {
		if errors.Is(err, fuzzyfinder.ErrAbort) {
			return "", nil
		}

		return "", fmt.Errorf("fuzzy finder failed: %w", err)
	}

	return list[idx], nil
}

// IsTerminal reports whether standard input is connected to a terminal.
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

var passphraseScanner *bufio.Scanner

// SetPassphraseFD configures SecureRead to consume passphrases from the given
// file descriptor (one line per call) instead of prompting on stdin or the
// terminal. A negative descriptor disables the override.
func SetPassphraseFD(descriptor int) error {
	if descriptor < 0 {
		passphraseScanner = nil

		return nil
	}

	f := os.NewFile(uintptr(descriptor), "passphrase")
	if f == nil {
		return fmt.Errorf("invalid passphrase file descriptor: %d", descriptor)
	}

	passphraseScanner = bufio.NewScanner(f)

	return nil
}

// SecureRead reads a password without echo if standard input is a terminal.
// If a passphrase file descriptor has been configured, the passphrase is read
// from the next line of that descriptor instead.
func SecureRead(prompt string) (string, error) {
	if passphraseScanner != nil {
		if !passphraseScanner.Scan() {
			if err := passphraseScanner.Err(); err != nil {
				return "", fmt.Errorf("failed to read passphrase from fd: %w", err)
			}

			return "", errors.New("passphrase file descriptor exhausted")
		}

		return passphraseScanner.Text(), nil
	}

	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)

		fmt.Fprintln(os.Stderr)

		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}

		return string(password), nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", fmt.Errorf("failed to read password: %w", scanner.Err())
	}

	return scanner.Text(), nil
}

// AskYesNo prompts the user with a yes/no question and returns their boolean answer.
func AskYesNo(prompt string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/n]: ", prompt)

	// Save the terminal state to restore later.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false, fmt.Errorf("failed to make terminal raw: %w", err)
	}

	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), oldState)
	}()

	answer := ""
	for answer != "n" && answer != "y" {
		// Read a single byte from the terminal.
		var input [1]byte

		_, err = os.Stdin.Read(input[:])
		if err != nil {
			return false, fmt.Errorf("failed to read input: %w", err)
		}

		answer = strings.ToLower(string(input[0]))
	}

	fmt.Fprintln(os.Stderr)

	return answer == "y", nil
}

// ReadNewPassword prompts the user to input a new password,
// optionally asking for confirmation by re-entering it.
func ReadNewPassword(confirm bool) (string, error) {
	pass, err := SecureRead("Enter password: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	if len(pass) == 0 {
		return "", errors.New("empty password")
	}

	if confirm {
		pass2, err := SecureRead("Enter password (again): ")
		if err != nil {
			return "", fmt.Errorf("failed to read password confirmation: %w", err)
		}

		if pass != pass2 {
			return "", errors.New("passwords do not match")
		}
	}

	return pass, nil
}
