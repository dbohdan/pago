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

// Map an entry's name to its file path.
func EntryFile(passwordStore, name string) (string, error) {
	re := regexp.MustCompile(NameInvalidChars)
	if re.MatchString(name) {
		return "", fmt.Errorf("entry name contains invalid characters matching %s", NameInvalidChars)
	}

	file := filepath.Join(passwordStore, name+AgeExt)

	for path := file; path != "/"; path = filepath.Dir(path) {
		if path == passwordStore {
			return file, nil
		}
	}

	return "", fmt.Errorf("entry path is out of bounds")
}

func WaitUntilAvailable(path string, maximum time.Duration) error {
	start := time.Now()

	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}

		elapsed := time.Since(start)
		if elapsed > maximum {
			return fmt.Errorf("reached %v timeout", maximum)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func PrintError(format string, value any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", value)
}

func ExitWithError(format string, value any) {
	PrintError(format, value)
	os.Exit(1)
}

// Zero zeroes-out a byte slice.
// This is used for passwords.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

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
