// pago - a command-line password manager.
//
// License: MIT.
// See the file `LICENSE`.

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	expect "github.com/Netflix/go-expect"
)

const (
	commandPago = "./pago"
	password    = "test"
)

func runCommandEnv(env []string, args ...string) (string, string, error) {
	cmd := exec.Command(commandPago, args...)
	cmd.Env = append(os.Environ(), env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

func runCommand(args ...string) (string, string, error) {
	return runCommandEnv([]string{}, args...)
}

func withPagoDir(test func(dataDir string) (string, error)) (string, error) {
	tempDir, err := os.MkdirTemp("", "pago-test-")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}

	c, err := expect.NewConsole()
	if err != nil {
		return "", fmt.Errorf("failed to create console: %w", err)
	}
	defer c.Close()

	cmd := exec.Command(commandPago, "--dir", tempDir, "init")
	cmd.Stdin = c.Tty()
	cmd.Stdout = c.Tty()
	cmd.Stderr = c.Tty()

	go func() {
		c.ExpectString("Enter password")
		c.SendLine(password)
		c.ExpectString("again")
		c.SendLine(password)
	}()

	err = cmd.Start()
	if err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("command failed: %w", err)
	}

	defer func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to remove temporary directory %q: %v\n", tempDir, removeErr)
		}
	}()

	return test(tempDir)
}

func createFakeEntry(dataDir, name string) error {
	file, err := os.OpenFile(filepath.Join(dataDir, "store", name+".age"), os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return err
	}

	return file.Close()
}

func TestUsage(t *testing.T) {
	stdout, _, _ := runCommand("--help")

	re := "Usage"
	if matched, _ := regexp.MatchString(re, stdout); !matched {
		t.Errorf("Expected %q in stdout", re)
	}
}

func TestVersion(t *testing.T) {
	stdout, _, _ := runCommand("version")

	if matched, _ := regexp.MatchString(`\d+\.\d+\.\d+`, stdout); !matched {
		t.Error("Expected version number in stdout")
	}
}

func TestBadUsage(t *testing.T) {
	_, _, err := runCommand("boo")

	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Errorf("Expected exit status 2, got %v", err)
	}
}

func TestInit(t *testing.T) {
	tree, err := withPagoDir(func(dataDir string) (string, error) {
		return dirTree(dataDir, func(name string, info os.FileInfo) (bool, string) {
			return true, name
		})
	})

	if err != nil {
		t.Errorf("Command `init` failed: %v", err)
	}

	for _, re := range []string{`/store\n`, `/\.age-recipients\n`} {
		if matched, _ := regexp.MatchString(re, tree); !matched {
			t.Errorf("Expected %q in directory tree", re)
		}
	}
}

func TestAdd(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--random",
		)
		return stdout + "\n" + stderr, err
	})
	if err != nil {
		t.Errorf("Command `add` failed: %v", err)
	}

	re := "Password saved"
	if matched, _ := regexp.MatchString(re, output); !matched {
		t.Errorf("Expected %q in stdout", re)
	}
}

func TestClip(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--length", "32", "--pattern", "[a]", "--random",
		)
		if err != nil {
			return stdout + "\n" + stderr, err
		}

		c, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer c.Close()

		cmd := exec.Command(commandPago, "clip", "-d", dataDir, "-s", "", "-c", "echo", "-t", "1", "foo")
		cmd.Stdin = c.Tty()
		cmd.Stdout = c.Tty()
		cmd.Stderr = c.Tty()

		go func() {
			c.ExpectString("Enter password")
			c.SendLine(password)
			c.ExpectString("Clearing clipboard in 1 second")
		}()

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("failed to start command: %w", err)
		}

		err = cmd.Wait()
		if err != nil {
			return "", fmt.Errorf("command failed: %w", err)
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `clip` failed: %v", err)
	}
}

func TestDelete(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		_, _, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--random",
		)
		if err != nil {
			return "", err
		}

		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"delete", "foo", "--force",
		)
		return stdout + "\n" + stderr, err
	})
	if err != nil {
		t.Errorf("Command `delete` failed: %v", err)
	}

	if matched, _ := regexp.MatchString("^$", strings.TrimSpace(output)); !matched {
		t.Error("Expected no output")
	}
}
func TestFind(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		for _, name := range []string{"foo", "bar", "baz"} {
			err := createFakeEntry(dataDir, name)
			if err != nil {
				return "", err
			}
		}

		stdout, _, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"find", "b",
		)
		return stdout, err
	})
	if err != nil {
		t.Errorf("Command `find` failed: %v", err)
	}

	re := `^bar\nbaz$`
	if matched, _ := regexp.MatchString(re, strings.TrimSpace(output)); !matched {
		t.Errorf("Expected %q in stdout", re)
	}
}

func TestGenerate(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		stdout, stderr, err := runCommand("generate", "--length", "15", "--pattern", "a")
		return stdout + "\n" + stderr, err
	})
	if err != nil {
		t.Errorf("Command `generate` failed: %v", err)
	}

	re := `^a{15}$`
	if matched, _ := regexp.MatchString(re, strings.TrimSpace(output)); !matched {
		t.Errorf("Expected %q in stdout", re)
	}
}

func TestShowName(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--length", "32", "--pattern", "[a]", "--random",
		)
		if err != nil {
			return stdout + "\n" + stderr, err
		}

		c, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer c.Close()

		var buf bytes.Buffer
		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "show", "foo")
		cmd.Stdin = c.Tty()
		cmd.Stdout = &buf
		cmd.Stderr = c.Tty()

		go func() {
			c.ExpectString("Enter password")
			c.SendLine(password)
		}()

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("failed to start command: %w", err)
		}

		err = cmd.Wait()
		if err != nil {
			return "", fmt.Errorf("command failed: %w", err)
		}

		return buf.String(), nil
	})
	if err != nil {
		t.Errorf("Command `show foo` failed: %v", err)
	}

	re := `^a{32}$`
	if matched, _ := regexp.MatchString(re, strings.TrimSpace(output)); !matched {
		t.Errorf("Expected %q in output", re)
	}
}

func TestShowTree(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		for _, name := range []string{"foo", "bar", "baz"} {
			err := createFakeEntry(dataDir, name)
			if err != nil {
				return "", err
			}
		}

		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"show",
		)
		return stdout + "\n" + stderr, err
	})
	if err != nil {
		t.Errorf("Command `show` failed: %v", err)
	}

	re := `^store\n├── bar\n├── baz\n└── foo$`
	if matched, _ := regexp.MatchString(re, strings.TrimSpace(output)); !matched {
		t.Errorf("Expected %q in output", re)
	}
}
