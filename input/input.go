// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package input

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"dbohdan.com/pago"

	"github.com/ktr0731/go-fuzzyfinder"
	"golang.org/x/term"
)

// Pick an entry using a fuzzy finder.
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
func SecureRead(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	if term.IsTerminal(int(syscall.Stdin)) {
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}

		return password, nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, scanner.Err()
	}

	// scanner.Bytes() returns a slice that is valid only until the next Scan().
	// We need to copy it.
	pass := scanner.Bytes()
	passCopy := make([]byte, len(pass))
	copy(passCopy, pass)

	return passCopy, nil
}

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

// Ask the user to input a password, twice if confirm is true.
func ReadNewPassword(confirm bool) ([]byte, error) {
	pass, err := SecureRead("Enter password: ")
	if err != nil {
		return nil, err
	}

	if len(pass) == 0 {
		return nil, fmt.Errorf("empty password")
	}

	if confirm {
		pass2, err := SecureRead("Enter password (again): ")
		if err != nil {
			pago.Zero(pass)
			return nil, err
		}
		defer pago.Zero(pass2)

		if !bytes.Equal(pass, pass2) {
			pago.Zero(pass)
			return nil, fmt.Errorf("passwords do not match")
		}
	}

	return pass, nil
}
