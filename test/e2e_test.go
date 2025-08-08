// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"dbohdan.com/pago/tree"

	"filippo.io/age"
	"filippo.io/age/armor"
	expect "github.com/Netflix/go-expect"
)

const (
	commandPago      = "../cmd/pago/pago"
	commandPagoAgent = "../cmd/pago-agent/pago-agent"
	password         = "test"
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

	err = cmd.Start()
	if err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	_, _ = c.ExpectString("Enter password")
	_, _ = c.SendLine(password)
	_, _ = c.ExpectString("again")
	_, _ = c.SendLine(password)

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
		return tree.DirTree(dataDir, func(name string, info os.FileInfo) (bool, string) {
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

func TestAddMultiline(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		cmd := exec.Command(commandPago, "--dir", dataDir, "add", "multiline-test", "--multiline")
		cmd.Stdin = strings.NewReader("line1\nline2\nline3")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()

		return stdout.String() + "\n" + stderr.String(), err
	})
	if err != nil {
		t.Errorf("Command `add --multiline` failed: %v", err)
	}

	re := "Reading password from stdin until EOF"
	if matched, _ := regexp.MatchString(re, output); !matched {
		t.Errorf("Expected %q in output", re)
	}
}

func TestAddNewline(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "ab\ncd", "--random",
		)
		return stdout + "\n" + stderr, err
	})
	if err == nil {
		t.Errorf("Command `add` should fail")
	}

	re := "entry name contains invalid characters"
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

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("failed to start command: %w", err)
		}

		_, _ = c.ExpectString("Enter password")
		_, _ = c.SendLine(password)
		_, _ = c.ExpectString("Clearing clipboard in 1 second")

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

func TestInfoDir(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"info", "dir",
		)
		return stdout + "\n" + stderr, err
	})
	if err != nil {
		t.Errorf("Command `info dir` failed: %v", err)
	}

	if matched, _ := regexp.MatchString(`^/`, output); !matched {
		t.Error("Expected absolute path in output")
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

func TestRekey(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		for _, name := range []string{"foo", "bar", "baz/qux"} {
			stdout, stderr, err := runCommandEnv(
				[]string{"PAGO_DIR=" + dataDir},
				"add", name, "--length", "32", "--pattern", "[a]", "--random",
			)
			if err != nil {
				return stdout + "\n" + stderr, err
			}
		}

		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return "", fmt.Errorf("failed to generate age identity: %w", err)
		}

		// Write the public key to .age-recipients.
		recipientsPath := filepath.Join(dataDir, "store/.age-recipients")
		err = os.WriteFile(recipientsPath, []byte(identity.Recipient().String()+"\n"), 0600)
		if err != nil {
			return "", fmt.Errorf("failed to write recipients file: %w", err)
		}

		c, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer c.Close()

		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "rekey")
		cmd.Stdin = c.Tty()
		cmd.Stdout = c.Tty()
		cmd.Stderr = c.Tty()

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("failed to start rekey command: %w", err)
		}

		_, err = c.ExpectString("Enter password")
		if err != nil {
			return "", fmt.Errorf("failed to get password prompt: %w", err)
		}
		_, _ = c.SendLine(password)

		err = cmd.Wait()
		if err != nil {
			return "", fmt.Errorf("rekey failed: %w", err)
		}

		// Verify we can decrypt the entries using our key.
		for _, name := range []string{"foo", "bar", "baz/qux"} {
			encryptedPath := filepath.Join(dataDir, "store", name+".age")
			encryptedBytes, err := os.ReadFile(encryptedPath)
			if err != nil {
				return "", fmt.Errorf("failed to read encrypted file %q: %w", name, err)
			}

			r, err := age.Decrypt(armor.NewReader(bytes.NewReader(encryptedBytes)), identity)
			if err != nil {
				return "", fmt.Errorf("failed to decrypt %q: %w", name, err)
			}

			decrypted, err := io.ReadAll(r)
			if err != nil {
				return "", fmt.Errorf("failed to read decrypted content of %q: %w", name, err)
			}

			if !regexp.MustCompile(`^a{32}$`).Match(decrypted) {
				return "", fmt.Errorf("unexpected decrypted content for %q: %q", name, decrypted)
			}
		}

		return "", nil
	})

	if err != nil {
		t.Errorf("Command `rekey` failed: %v", err)
	}
}

func TestRename(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		// Add an entry.
		_, _, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo/bar", "--random",
		)
		if err != nil {
			return "", err
		}

		// Rename the entry.
		_, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"rename", "foo/bar", "foo/baz",
		)
		if err != nil {
			return "", err
		}
		output1 := stderr

		// Check that the old entry is gone.
		if _, err := os.Stat(filepath.Join(dataDir, "store", "foo/bar.age")); !os.IsNotExist(err) {
			return "", fmt.Errorf("old entry foo/bar still exists")
		}

		// Check that the new entry exists.
		if _, err := os.Stat(filepath.Join(dataDir, "store", "foo/baz.age")); os.IsNotExist(err) {
			return "", fmt.Errorf("new entry foo/baz does not exist")
		}

		// Move to a new directory.
		_, stderr, err = runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"rename", "foo/baz", "qux/quux",
		)
		if err != nil {
			return "", err
		}
		output2 := stderr

		// Check that the old entry is gone.
		if _, err := os.Stat(filepath.Join(dataDir, "store", "foo/baz.age")); !os.IsNotExist(err) {
			return "", fmt.Errorf("old entry foo/baz still exists")
		}

		// Check that the new entry exists.
		if _, err := os.Stat(filepath.Join(dataDir, "store", "qux/quux.age")); os.IsNotExist(err) {
			return "", fmt.Errorf("new entry qux/quux does not exist")
		}

		// Check that the old directory is gone.
		if _, err := os.Stat(filepath.Join(dataDir, "store", "foo")); !os.IsNotExist(err) {
			return "", fmt.Errorf("old directory foo should have been removed")
		}

		return output1 + output2, nil
	})
	if err != nil {
		t.Errorf("Command `rename` failed: %v", err)
	}

	re := `^Renamed "foo/bar" to "foo/baz"\nRenamed "foo/baz" to "qux/quux"`
	if matched, _ := regexp.MatchString(re, strings.TrimSpace(output)); !matched {
		t.Errorf("Expected %q in output, got %q", re, strings.TrimSpace(output))
	}
}

func TestRewrap(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		c, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer c.Close()

		newPassword := "latest"
		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "rewrap")
		cmd.Stdin = c.Tty()
		cmd.Stdout = c.Tty()
		cmd.Stderr = c.Tty()

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("failed to start rewrap command: %w", err)
		}

		_, err = c.ExpectString("Enter password")
		if err != nil {
			return "", fmt.Errorf("failed to get first password prompt: %w", err)
		}
		_, _ = c.SendLine(password)

		_, err = c.ExpectString("Enter password")
		if err != nil {
			return "", fmt.Errorf("failed to get second password prompt: %w", err)
		}
		_, _ = c.SendLine(newPassword)

		_, err = c.ExpectString("again")
		if err != nil {
			return "", fmt.Errorf("failed to get confirmation prompt: %w", err)
		}
		_, _ = c.SendLine(newPassword)

		err = cmd.Wait()
		if err != nil {
			return "", fmt.Errorf("rewrap failed: %w", err)
		}

		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--length", "32", "--pattern", "[a]", "--random",
		)
		if err != nil {
			return stdout + "\n" + stderr, err
		}

		// Verify we can decrypt with the new password.
		cmd = exec.Command(commandPago, "--dir", dataDir, "--socket", "", "show", "foo")
		cmd.Stdin = c.Tty()
		cmd.Stdout = c.Tty()
		cmd.Stderr = c.Tty()

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("failed to run `show` command: %w", err)
		}

		_, err = c.ExpectString("Enter password")
		if err != nil {
			return "", fmt.Errorf("failed to get passworr prompt for `show`: %w", err)
		}
		_, _ = c.SendLine(newPassword)

		err = cmd.Wait()
		if err != nil {
			return "", fmt.Errorf("`show` failed: %w", err)
		}

		return "", nil
	})

	if err != nil {
		t.Errorf("Command `rewrap` failed: %v", err)
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

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("failed to start command: %w", err)
		}

		_, _ = c.ExpectString("Enter password")
		_, _ = c.SendLine(password)

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

func TestAgentStartPingStop(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		c, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer c.Close()

		socketPath := filepath.Join(dataDir, "agent.sock")

		cmd := exec.Command(
			commandPago,
			"--agent", commandPagoAgent,
			"--dir", dataDir,
			"--no-memlock",
			"--socket", socketPath,
			"agent", "start",
		)
		cmd.Stdin = c.Tty()
		cmd.Stdout = c.Tty()
		cmd.Stderr = c.Tty()

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("failed to start agent: %w", err)
		}

		_, err = c.ExpectString("Enter password")
		if err != nil {
			return "", fmt.Errorf("failed to get password prompt: %w", err)
		}
		_, _ = c.SendLine(password)

		err = cmd.Wait()
		if err != nil {
			return "", fmt.Errorf("agent start failed: %w", err)
		}

		env := []string{"PAGO_DIR=" + dataDir, "PAGO_SOCK=" + socketPath}
		stdout, stderr, err := runCommandEnv(
			env,
			"agent", "status",
		)
		if err != nil {
			return stdout + "\n" + stderr, fmt.Errorf("agent status check failed: %w", err)
		}

		stdout, stderr, err = runCommandEnv(
			env,
			"agent", "stop",
		)
		if err != nil {
			return stdout + "\n" + stderr, fmt.Errorf("agent stop failed: %w", err)
		}

		// Verify the agent is stopped by checking its status again.
		_, _, err = runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir, "PAGO_SOCK=" + socketPath},
			"agent", "status",
		)
		if err == nil {
			return "", fmt.Errorf("agent status check should have failed after stop")
		}

		return "", nil
	})

	if err != nil {
		t.Errorf("Agent test failed: %v", err)
	}
}
