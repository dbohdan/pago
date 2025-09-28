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
		return "", fmt.Errorf("failed to list passwords: %v", err)
	}

	if len(list) == 0 {
		return "", fmt.Errorf("no password entries found")
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
		return "", fmt.Errorf("fuzzy finder failed: %v", err)
	}

	return list[idx], nil
}

// Read a password without echo if standard input is a terminal.
func SecureRead(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)
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

// AskYesNo prompts the user with a yes/no question and returns their boolean answer.
func AskYesNo(prompt string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/n]: ", prompt)

	// Save the terminal state to restore later.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false, fmt.Errorf("failed to make terminal raw: %v", err)
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
			return false, fmt.Errorf("failed to read input: %v", err)
		}

		answer = strings.ToLower(string(input[0]))
	}

	_ = term.Restore(int(os.Stdin.Fd()), oldState)
	fmt.Fprintln(os.Stderr)

	return answer == "y", nil
}

// ReadNewPassword prompts the user to input a new password,
// optionally asking for confirmation by re-entering it.
func ReadNewPassword(confirm bool) (string, error) {
	pass, err := SecureRead("Enter password: ")
	if err != nil {
		return "", err
	}

	if len(pass) == 0 {
		return "", fmt.Errorf("empty password")
	}

	if confirm {
		pass2, err := SecureRead("Enter password (again): ")
		if err != nil {
			return "", err
		}

		if pass != pass2 {
			return "", fmt.Errorf("passwords do not match")
		}
	}

	return pass, nil
}
