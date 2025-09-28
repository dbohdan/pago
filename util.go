// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// EntryFile constructs the full file path for a given entry name in the store.
// It also validates the entry name for invalid characters and ensures the path is within the store.
func EntryFile(passwordStore, name string) (string, error) {
	re := regexp.MustCompile(NameInvalidChars)
	if re.MatchString(name) {
		return "", fmt.Errorf("entry name contains invalid characters matching %s", NameInvalidChars)
	}

	file := filepath.Join(passwordStore, name+AgeExt)

	// Ensure the entry path does not escape the password store directory.
	for path := file; path != "/"; path = filepath.Dir(path) {
		if path == passwordStore {
			return file, nil
		}
	}

	return "", fmt.Errorf("entry path is out of bounds")
}

// WaitUntilAvailable waits until a file or directory at the given path exists,
// or until a maximum duration has passed.
func WaitUntilAvailable(path string, maximum time.Duration) error {
	start := time.Now()

	for {
		if _, err := os.Stat(path); err == nil {
			return nil // Path exists.
		}

		elapsed := time.Since(start)
		if elapsed > maximum {
			return fmt.Errorf("reached %v timeout", maximum)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

// PrintError prints a formatted error message to stderr.
func PrintError(format string, value any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", value)
}

// ExitWithError prints a formatted error message to stderr and exits the program with status 1.
func ExitWithError(format string, value any) {
	PrintError(format, value)
	os.Exit(1)
}

// ListFiles walks a directory tree and returns a list of file names
// that satisfy a given transformation/filter function.
func ListFiles(root string, transform func(name string, info os.FileInfo) (bool, string)) ([]string, error) {
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

// Return a function that filters entries by a filename pattern.
func EntryFilter(root string, pattern *regexp.Regexp) func(name string, info os.FileInfo) (bool, string) {
	return func(name string, info os.FileInfo) (bool, string) {
		if info.IsDir() || !strings.HasSuffix(name, AgeExt) {
			return false, ""
		}

		displayName := name
		displayName = strings.TrimPrefix(displayName, root)
		displayName = strings.TrimPrefix(displayName, "/")
		displayName = strings.TrimSuffix(displayName, AgeExt)

		if pattern != nil && !pattern.MatchString(displayName) {
			return false, ""
		}

		return true, displayName
	}
}
