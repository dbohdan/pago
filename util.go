// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const waitStep = 50 * time.Millisecond

// Sentinel errors signal categories of failure to the top-level error handler.
// Wrapping with %w keeps the original message; main inspects via errors.Is to
// pick a distinct exit code.
var (
	ErrEntryNotFound = errors.New("entry not found")
	ErrDecryption    = errors.New("decryption failed")
	ErrAgent         = errors.New("agent error")
)

// Duration is a time.Duration that accepts a bare non-negative integer as a
// number of seconds when parsed from text. Any other input is parsed by
// time.ParseDuration. This lets the user write "30" (= 30s) or "1m30s"
// interchangeably and keeps PAGO_TIMEOUT and PAGO_EXPIRE on the same syntax.
//
//nolint:recvcheck // Pointer receiver is required by encoding.TextUnmarshaler.
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler so kong and the env-var
// machinery accept the type directly.
func (d *Duration) UnmarshalText(text []byte) error {
	v, err := ParseDuration(string(text))
	if err != nil {
		return err
	}

	*d = Duration(v)

	return nil
}

func (d Duration) String() string {
	return time.Duration(d).String()
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// ParseDuration parses a Go duration string with the addition that a bare
// non-negative integer is interpreted as a number of seconds.
func ParseDuration(s string) (time.Duration, error) {
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}

	return d, nil
}

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

	return "", errors.New("entry path is out of bounds")
}

// WriteFileAtomic writes data to a file by first writing to a temporary file
// in the same directory and then renaming it to the target path.
// This prevents the target from being left truncated or partial if the program
// is interrupted mid-write.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pago-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	tmp := f.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()

	if err := f.Chmod(perm); err != nil {
		_ = f.Close()

		return fmt.Errorf("failed to set permissions on temp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()

		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()

		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	cleanup = false

	return nil
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

		time.Sleep(waitStep)
	}
}

// PrintError prints a formatted error message to stderr.
func PrintError(format string, value any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", value)
}

// ExitWithError prints a formatted error message to stderr and exits the program with status 1.
func ExitWithError(format string, value any) {
	PrintError(format, value)
	os.Exit(ExitError)
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
			return fmt.Errorf("failed to get absolute path: %w", err)
		}

		keep, displayName := transform(name, info)
		if !keep {
			return nil
		}

		list = append(list, displayName)

		return nil
	})
	if err != nil {
		return []string{}, fmt.Errorf("failed to walk directory: %w", err)
	}

	return list, nil
}

// EntryFilter returns a function that filters entries by a filename pattern.
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
