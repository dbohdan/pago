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
	"syscall"
	"testing"
	"time"

	"dbohdan.com/pago"
	"dbohdan.com/pago/crypto"
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

// runCommandEnv executes the pago command with custom environment variables.
func runCommandEnv(env []string, args ...string) (string, string, error) {
	cmd := exec.Command(commandPago, args...)
	cmd.Env = append(os.Environ(), env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

// runCommand executes the pago command with default environment variables.
func runCommand(args ...string) (string, string, error) {
	return runCommandEnv([]string{}, args...)
}

// withPagoDir sets up a temporary pago directory, initializes it,
// runs the provided test function, and then cleans up the directory.
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

// createFakeEntry creates an empty .age file in the test store for testing purposes.
func createFakeEntry(dataDir, name string) error {
	file, err := os.OpenFile(filepath.Join(dataDir, "store", name+".age"), os.O_CREATE|os.O_RDONLY, pago.FilePerms)
	if err != nil {
		return fmt.Errorf("failed to create fake entry file: %w", err)
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

// requireExitCode runs the test and checks that the process exited with code.
func requireExitCode(t *testing.T, want int, err error) {
	t.Helper()

	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != want {
		t.Errorf("expected exit code %d, got %v", want, err)
	}
}

func TestPassphraseFD(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		// Add an entry with known content (no TTY needed).
		addCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "add", "foo", "--multiline", "--trim")
		addCmd.Stdin = strings.NewReader("hunter2\n")
		if out, err := addCmd.CombinedOutput(); err != nil {
			return string(out), fmt.Errorf("add failed: %w", err)
		}

		r, w, err := os.Pipe()
		if err != nil {
			return "", fmt.Errorf("failed to create pipe: %w", err)
		}
		defer r.Close()

		go func() {
			_, _ = w.Write([]byte(password + "\n"))
			_ = w.Close()
		}()

		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "--passphrase-fd", "3", "show", "foo")
		cmd.ExtraFiles = []*os.File{r}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			return stdout.String() + "\n" + stderr.String(), fmt.Errorf("show with --passphrase-fd failed: %w", err)
		}

		if got := stdout.String(); got != "hunter2\n" {
			return "", fmt.Errorf("expected %q, got %q", "hunter2\n", got)
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `--passphrase-fd` failed: %v", err)
	}
}

func TestExitCodeNotFound(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		_, _, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--random",
		)
		if err != nil {
			return "", err
		}

		_, _, runErr := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"delete", "nonexistent", "--force",
		)
		requireExitCode(t, 4, runErr)

		return "", nil
	})
	if err != nil {
		t.Errorf("setup failed: %v", err)
	}
}

func TestExitCodeDecryption(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		_, _, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--random",
		)
		if err != nil {
			return "", err
		}

		// Wrong master password fed via stdin (not a TTY).
		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "show", "foo")
		cmd.Stdin = strings.NewReader("wrong-password\n")
		runErr := cmd.Run()
		requireExitCode(t, 5, runErr)

		return "", nil
	})
	if err != nil {
		t.Errorf("setup failed: %v", err)
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

	re := "Entry saved"
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

	re := "Reading from stdin until EOF"
	if matched, _ := regexp.MatchString(re, output); !matched {
		t.Errorf("Expected %q in output", re)
	}
}

func TestAddTrim(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		// Add a multiline entry with --trim and a trailing newline.
		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "add", "trimmed", "--multiline", "--trim")
		cmd.Stdin = strings.NewReader("hunter2\n")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			return stdout.String() + "\n" + stderr.String(), fmt.Errorf("add --trim failed: %w", err)
		}

		// Show the entry and check that the trailing newline is gone.
		c, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer c.Close()

		var buf bytes.Buffer
		showCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "show", "trimmed")
		showCmd.Stdin = c.Tty()
		showCmd.Stdout = &buf
		showCmd.Stderr = c.Tty()

		if err := showCmd.Start(); err != nil {
			return "", fmt.Errorf("failed to start show: %w", err)
		}

		_, _ = c.ExpectString("Enter password")
		_, _ = c.SendLine(password)

		if err := showCmd.Wait(); err != nil {
			return "", fmt.Errorf("show failed: %w", err)
		}

		// `show` adds at most one trailing newline; the stored content must be exactly "hunter2".
		if got := buf.String(); got != "hunter2\n" {
			return "", fmt.Errorf("expected stored value %q, got %q", "hunter2", got)
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `add --trim` failed: %v", err)
	}
}

func TestAddNoTTY(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		// Pipe a password into `add` with no input-mode flag. Without a TTY,
		// pago should fall back to reading stdin verbatim instead of trying
		// to prompt and erroring out.
		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "add", "piped")
		cmd.Stdin = strings.NewReader("piped-secret")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		return stdout.String() + "\n" + stderr.String(), err
	})
	if err != nil {
		t.Errorf("Command `add` over pipe failed: %v\n%s", err, output)
	}

	re := "Entry saved"
	if matched, _ := regexp.MatchString(re, output); !matched {
		t.Errorf("Expected %q in output, got %q", re, output)
	}
}

func TestDeleteNoTTY(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		_, _, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--random",
		)
		if err != nil {
			return "", err
		}

		// Without a terminal and without --force, delete must abort cleanly.
		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "delete", "foo")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		return stdout.String() + "\n" + stderr.String(), err
	})

	if err == nil {
		t.Error("Command `delete` without TTY should fail")
	}

	re := "stdin is not a terminal"
	if matched, _ := regexp.MatchString(re, output); !matched {
		t.Errorf("Expected %q in stderr, got %q", re, output)
	}
}

func TestEditNoTTY(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		_, _, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--random",
		)
		if err != nil {
			return "", err
		}

		cmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "edit", "foo")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		return stdout.String() + "\n" + stderr.String(), err
	})

	if err == nil {
		t.Error("Command `edit` without TTY should fail")
	}

	re := "stdin is not a terminal"
	if matched, _ := regexp.MatchString(re, output); !matched {
		t.Errorf("Expected %q in stderr, got %q", re, output)
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
		_, _ = c.ExpectString("Clearing clipboard in 1s")

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

func TestClipSignalClears(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--length", "32", "--pattern", "[a]", "--random",
		)
		if err != nil {
			return stdout + "\n" + stderr, err
		}

		// A wrapper that records the most recent clipboard contents to a file.
		// pago invokes this twice: once to copy and once to clear.
		clipScript := filepath.Join(dataDir, "clip.sh")
		clipFile := filepath.Join(dataDir, "clipboard.txt")

		script := fmt.Sprintf("#!/bin/sh\ncat > %s\n", clipFile)
		if err := os.WriteFile(clipScript, []byte(script), 0o755); err != nil {
			return "", fmt.Errorf("failed to write clipboard script: %w", err)
		}

		c, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer c.Close()

		clip := exec.Command(commandPago, "clip", "-d", dataDir, "-s", "", "-c", clipScript, "-t", "30", "foo")
		clip.Stdin = c.Tty()
		clip.Stdout = c.Tty()
		clip.Stderr = c.Tty()

		if err := clip.Start(); err != nil {
			return "", fmt.Errorf("failed to start clip: %w", err)
		}

		_, _ = c.ExpectString("Enter password")
		_, _ = c.SendLine(password)
		_, _ = c.ExpectString("Clearing clipboard")

		// At this point the wrapper has been invoked once with the password.
		got, err := os.ReadFile(clipFile)
		if err != nil {
			return "", fmt.Errorf("failed to read clipboard file: %w", err)
		}

		if !regexp.MustCompile(`^a{32}$`).Match(got) {
			return "", fmt.Errorf("expected password in clipboard file, got %q", got)
		}

		// Interrupt during the timeout sleep. The signal handler must run the
		// clear step before the process exits.
		if err := clip.Process.Signal(syscall.SIGINT); err != nil {
			return "", fmt.Errorf("failed to signal: %w", err)
		}

		done := make(chan error, 1)
		go func() { done <- clip.Wait() }()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = clip.Process.Kill()
			return "", fmt.Errorf("clip did not exit after SIGINT")
		}

		got, err = os.ReadFile(clipFile)
		if err != nil {
			return "", fmt.Errorf("failed to read clipboard file after signal: %w", err)
		}

		if len(got) != 0 {
			return "", fmt.Errorf("expected clipboard cleared, file still contains %q", got)
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `clip` SIGINT clear failed: %v", err)
	}
}

func TestCopy(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		// Add a multiline entry with known content (no TTY needed).
		addCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "add", "foo", "--multiline", "--trim")
		addCmd.Stdin = strings.NewReader("hunter2\n")
		if out, err := addCmd.CombinedOutput(); err != nil {
			return string(out), fmt.Errorf("add failed: %w", err)
		}

		// Copy foo -> bar.
		c, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer c.Close()

		cpCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "cp", "foo", "bar")
		cpCmd.Stdin = c.Tty()
		cpCmd.Stdout = c.Tty()
		cpCmd.Stderr = c.Tty()
		if err := cpCmd.Start(); err != nil {
			return "", fmt.Errorf("failed to start cp: %w", err)
		}
		_, _ = c.ExpectString("Enter password")
		_, _ = c.SendLine(password)
		if err := cpCmd.Wait(); err != nil {
			return "", fmt.Errorf("cp failed: %w", err)
		}

		// Verify bar.age exists.
		if _, err := os.Stat(filepath.Join(dataDir, "store", "bar.age")); err != nil {
			return "", fmt.Errorf("destination entry missing: %w", err)
		}

		// Read bar back and verify the content matches.
		var buf bytes.Buffer
		showCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "show", "bar")
		showCmd.Stdin = c.Tty()
		showCmd.Stdout = &buf
		showCmd.Stderr = c.Tty()
		if err := showCmd.Start(); err != nil {
			return "", fmt.Errorf("failed to start show: %w", err)
		}
		_, _ = c.ExpectString("Enter password")
		_, _ = c.SendLine(password)
		if err := showCmd.Wait(); err != nil {
			return "", fmt.Errorf("show failed: %w", err)
		}

		if got := buf.String(); got != "hunter2\n" {
			return "", fmt.Errorf("expected %q, got %q", "hunter2\n", got)
		}

		// Copying onto an existing destination without --force must fail.
		dupCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "cp", "foo", "bar")
		dupCmd.Stdin = strings.NewReader("")
		out, err := dupCmd.CombinedOutput()
		if err == nil {
			return string(out), fmt.Errorf("cp without --force should have failed")
		}
		if !strings.Contains(string(out), "already exists") {
			return string(out), fmt.Errorf("expected 'already exists' error, got %q", out)
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `cp` failed: %v", err)
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

func TestGitPassthrough(t *testing.T) {
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
			"git", "log", "--oneline",
		)
		return stdout + "\n" + stderr, err
	})
	if err != nil {
		t.Errorf("Command `git log` failed: %v", err)
	}

	for _, re := range []string{`Initial commit`, `add "foo"`} {
		if matched, _ := regexp.MatchString(re, output); !matched {
			t.Errorf("Expected %q in git log output, got %q", re, output)
		}
	}
}

func TestGitPassthroughCustomCmd(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		// Verify PAGO_GIT_COMMAND is honored by replacing git with a wrapper
		// that records its arguments.
		marker := filepath.Join(dataDir, "git-wrapper.out")
		wrapper := filepath.Join(dataDir, "fake-git.sh")

		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\n", marker)
		if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
			return "", fmt.Errorf("failed to write wrapper: %w", err)
		}

		_, _, err := runCommandEnv(
			[]string{
				"PAGO_DIR=" + dataDir,
				"PAGO_GIT_COMMAND=" + wrapper,
			},
			"git", "status", "--porcelain",
		)
		if err != nil {
			return "", err
		}

		got, err := os.ReadFile(marker)
		if err != nil {
			return "", fmt.Errorf("wrapper did not run: %w", err)
		}

		want := "-C\n" + filepath.Join(dataDir, "store") + "\nstatus\n--porcelain\n"
		if string(got) != want {
			return "", fmt.Errorf("wrapper got %q, want %q", got, want)
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `git` with PAGO_GIT_COMMAND failed: %v", err)
	}
}

func TestLog(t *testing.T) {
	output, err := withPagoDir(func(dataDir string) (string, error) {
		for _, name := range []string{"foo", "bar", "baz/qux"} {
			_, _, err := runCommandEnv(
				[]string{"PAGO_DIR=" + dataDir},
				"add", name, "--random",
			)
			if err != nil {
				return "", err
			}
		}

		stdout, stderr, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"log", "-n", "3",
		)
		return stdout + "\n" + stderr, err
	})
	if err != nil {
		t.Errorf("Command `log` failed: %v", err)
	}

	dateRe := `\d{4}-\d{2}-\d{2} \d{2}:\d{2} [+-]\d{4}`

	// Files column is padded to the width of the longest entry ("baz/qux.age").
	for _, re := range []string{
		dateRe + ` "baz/qux\.age" add "baz/qux"`,
		dateRe + ` "bar\.age" {5}add "bar"`,
		dateRe + ` "foo\.age" {5}add "foo"`,
	} {
		if matched, _ := regexp.MatchString(re, output); !matched {
			t.Errorf("Expected line matching %q in log output, got %q", re, output)
		}
	}

	// -n 3 must not include the initial commit.
	if matched, _ := regexp.MatchString(`Initial commit`, output); matched {
		t.Errorf("Did not expect 'Initial commit' with -n 3, got %q", output)
	}
}

func TestLogNoRepo(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pago-test-log-no-git-")
	if err != nil {
		t.Fatalf("failed to create tempdir: %v", err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

	c, err := expect.NewConsole()
	if err != nil {
		t.Fatalf("failed to create console: %v", err)
	}
	defer c.Close()

	initCmd := exec.Command(commandPago, "--dir", tempDir, "--no-git", "init")
	initCmd.Stdin = c.Tty()
	initCmd.Stdout = c.Tty()
	initCmd.Stderr = c.Tty()
	if err := initCmd.Start(); err != nil {
		t.Fatalf("failed to start init: %v", err)
	}

	_, _ = c.ExpectString("Enter password")
	_, _ = c.SendLine(password)
	_, _ = c.ExpectString("again")
	_, _ = c.SendLine(password)

	if err := initCmd.Wait(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	stdout, stderr, err := runCommandEnv(
		[]string{"PAGO_DIR=" + tempDir},
		"log",
	)
	if err == nil {
		t.Error("Expected `log` to fail in a non-Git store")
	}

	output := stdout + "\n" + stderr
	if matched, _ := regexp.MatchString(`not a Git repository`, output); !matched {
		t.Errorf("Expected 'not a Git repository' in output, got %q", output)
	}
}

func TestFindJSON(t *testing.T) {
	for _, flag := range []string{"--json", "-j"} {
		output, err := withPagoDir(func(dataDir string) (string, error) {
			for _, name := range []string{"foo", "bar", "baz"} {
				err := createFakeEntry(dataDir, name)
				if err != nil {
					return "", err
				}
			}

			stdout, _, err := runCommandEnv(
				[]string{"PAGO_DIR=" + dataDir},
				"find", flag, "b",
			)
			return stdout, err
		})
		if err != nil {
			t.Errorf("Command `find %s` failed: %v", flag, err)
		}

		if got := strings.TrimSpace(output); got != `["bar","baz"]` {
			t.Errorf("Expected JSON array for %s, got %q", flag, got)
		}
	}
}

func TestShowJSON(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		// A non-TOML entry should be JSON-encoded as a string.
		addCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "add", "plain", "--multiline", "--trim")
		addCmd.Stdin = strings.NewReader("hunter2\n")
		if out, err := addCmd.CombinedOutput(); err != nil {
			return string(out), fmt.Errorf("add plain failed: %w", err)
		}

		// A TOML entry to traverse.
		tomlCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", "", "add", "toml", "--multiline")
		tomlCmd.Stdin = strings.NewReader(`# TOML
password = "hunter2"
n = 5
arr = [1, 2, 3]
[nested]
deep = "value"
`)
		if out, err := tomlCmd.CombinedOutput(); err != nil {
			return string(out), fmt.Errorf("add toml failed: %w", err)
		}

		cases := []struct {
			args []string
			want string
		}{
			{[]string{"--json", "plain"}, `"hunter2"`},
			{[]string{"--json", "-k", "password", "toml"}, `"hunter2"`},
			{[]string{"--json", "-k", "n", "toml"}, `5`},
			{[]string{"--json", "-k", "arr", "toml"}, `[1,2,3]`},
			{[]string{"--json", "-k", "nested", "toml"}, `{"deep":"value"}`},
			{[]string{"--json", "-K", "toml"}, `["arr","n","nested","password"]`},
		}

		for _, tc := range cases {
			c, err := expect.NewConsole()
			if err != nil {
				return "", fmt.Errorf("failed to create console: %w", err)
			}

			args := append([]string{"--dir", dataDir, "--socket", "", "show"}, tc.args...)
			cmd := exec.Command(commandPago, args...)

			var buf bytes.Buffer
			cmd.Stdin = c.Tty()
			cmd.Stdout = &buf
			cmd.Stderr = c.Tty()

			if err := cmd.Start(); err != nil {
				_ = c.Close()
				return "", fmt.Errorf("failed to start show %v: %w", tc.args, err)
			}

			_, _ = c.ExpectString("Enter password")
			_, _ = c.SendLine(password)

			if err := cmd.Wait(); err != nil {
				_ = c.Close()
				return buf.String(), fmt.Errorf("show %v failed: %w", tc.args, err)
			}

			_ = c.Close()

			if got := strings.TrimSpace(buf.String()); got != tc.want {
				return "", fmt.Errorf("show %v: expected %q, got %q", tc.args, tc.want, got)
			}
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `show --json` failed: %v", err)
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

// getSSHIdentity reads and parses a test SSH private key to return an age.Identity.
func getSSHIdentity(t *testing.T) age.Identity {
	t.Helper()

	privateKey, err := os.ReadFile("id_ed25519")
	if err != nil {
		t.Fatalf("Failed to read SSH private key: %v", err)
	}

	ids, err := crypto.ParseIdentities(string(privateKey))
	if err != nil {
		t.Fatalf("Failed to parse SSH identity: %v", err)
	}

	return ids[0]
}

func TestRekeyWithSSH(t *testing.T) {
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

		// Write the SSH public key to .age-recipients.
		publicKey, err := os.ReadFile("id_ed25519.pub")
		if err != nil {
			return "", fmt.Errorf("failed to read test SSH public key: %w", err)
		}

		recipientsPath := filepath.Join(dataDir, "store/.age-recipients")
		err = os.WriteFile(recipientsPath, publicKey, pago.FilePerms)
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

		// Verify we can decrypt the entries using the SSH key.
		sshIdentity := getSSHIdentity(t)

		for _, name := range []string{"foo", "bar", "baz/qux"} {
			encryptedPath := filepath.Join(dataDir, "store", name+".age")
			encryptedBytes, err := os.ReadFile(encryptedPath)
			if err != nil {
				return "", fmt.Errorf("failed to read encrypted file %q: %w", name, err)
			}

			r, err := age.Decrypt(armor.NewReader(bytes.NewReader(encryptedBytes)), sshIdentity)
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
		t.Errorf("SSH rekey test failed: %v", err)
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
		err = os.WriteFile(recipientsPath, []byte(identity.Recipient().String()+"\n"), pago.FilePerms)
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

// rewriteIdentities decrypts the existing identities file with the master
// password, appends the supplied identity, and re-encrypts it.
func rewriteIdentities(dataDir, masterPassword string, extra age.Identity) error {
	path := filepath.Join(dataDir, "identities")

	encrypted, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read identities file: %w", err)
	}

	scryptID, err := age.NewScryptIdentity(masterPassword)
	if err != nil {
		return fmt.Errorf("failed to create scrypt identity: %w", err)
	}

	r, err := crypto.WrapDecrypt(bytes.NewReader(encrypted), scryptID)
	if err != nil {
		return fmt.Errorf("failed to decrypt identities: %w", err)
	}

	existing, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read identities: %w", err)
	}

	x25519, ok := extra.(*age.X25519Identity)
	if !ok {
		return fmt.Errorf("expected *age.X25519Identity, got %T", extra)
	}

	combined := strings.TrimRight(string(existing), "\n") + "\n" + x25519.String() + "\n"

	recipient, err := age.NewScryptRecipient(masterPassword)
	if err != nil {
		return fmt.Errorf("failed to create scrypt recipient: %w", err)
	}

	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return fmt.Errorf("failed to create encrypted writer: %w", err)
	}
	if _, err := w.Write([]byte(combined)); err != nil {
		return fmt.Errorf("failed to write identities: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encrypted writer: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer: %w", err)
	}

	return os.WriteFile(path, buf.Bytes(), pago.FilePerms)
}

// encryptEntry writes an age-armored ciphertext for plaintext encrypted to the
// given recipient at store/<name>.age.
func encryptEntry(dataDir, name, plaintext string, recipient age.Recipient) error {
	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return fmt.Errorf("failed to create encrypted writer: %w", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		return fmt.Errorf("failed to write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encrypted writer: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return fmt.Errorf("failed to close armor writer: %w", err)
	}

	return os.WriteFile(filepath.Join(dataDir, "store", name+".age"), buf.Bytes(), pago.FilePerms)
}

func TestRekeyUpdatesAgent(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		// Add an entry encrypted under the original identity.
		_, _, err := runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "foo", "--length", "32", "--pattern", "[a]", "--random",
		)
		if err != nil {
			return "", err
		}

		socketPath := filepath.Join(dataDir, "agent.sock")

		// Start the agent. It caches only the original identity.
		startConsole, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer startConsole.Close()

		startCmd := exec.Command(
			commandPago,
			"--agent", commandPagoAgent,
			"--dir", dataDir,
			"--no-memlock",
			"--socket", socketPath,
			"agent", "start",
		)
		startCmd.Stdin = startConsole.Tty()
		startCmd.Stdout = startConsole.Tty()
		startCmd.Stderr = startConsole.Tty()

		if err := startCmd.Start(); err != nil {
			return "", fmt.Errorf("failed to start agent: %w", err)
		}

		_, _ = startConsole.ExpectString("Enter password")
		_, _ = startConsole.SendLine(password)

		if err := startCmd.Wait(); err != nil {
			return "", fmt.Errorf("agent start failed: %w", err)
		}

		// Add a second identity Y to the encrypted identities file and to the
		// recipients. From this point on the agent's cache is stale.
		newIdentity, err := age.GenerateX25519Identity()
		if err != nil {
			return "", fmt.Errorf("failed to generate identity: %w", err)
		}

		if err := rewriteIdentities(dataDir, password, newIdentity); err != nil {
			return "", err
		}

		recipientsPath := filepath.Join(dataDir, "store", ".age-recipients")
		existingRecipients, err := os.ReadFile(recipientsPath)
		if err != nil {
			return "", fmt.Errorf("failed to read recipients: %w", err)
		}

		bothRecipients := strings.TrimRight(string(existingRecipients), "\n") + "\n" + newIdentity.Recipient().String() + "\n"
		if err := os.WriteFile(recipientsPath, []byte(bothRecipients), pago.FilePerms); err != nil {
			return "", fmt.Errorf("failed to write recipients: %w", err)
		}

		// Run rekey. With the fix this also pushes the fresh identities to
		// the agent.
		rekeyConsole, err := expect.NewConsole()
		if err != nil {
			return "", fmt.Errorf("failed to create console: %w", err)
		}
		defer rekeyConsole.Close()

		rekeyCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", socketPath, "rekey")
		rekeyCmd.Stdin = rekeyConsole.Tty()
		rekeyCmd.Stdout = rekeyConsole.Tty()
		rekeyCmd.Stderr = rekeyConsole.Tty()

		if err := rekeyCmd.Start(); err != nil {
			return "", fmt.Errorf("failed to start rekey: %w", err)
		}

		_, _ = rekeyConsole.ExpectString("Enter password")
		_, _ = rekeyConsole.SendLine(password)

		if err := rekeyCmd.Wait(); err != nil {
			return "", fmt.Errorf("rekey failed: %w", err)
		}

		// Place a new entry encrypted to the new identity only. The agent must
		// have learned about the new identity via rekey, otherwise this entry
		// is undecryptable through the agent.
		if err := encryptEntry(dataDir, "bar", strings.Repeat("b", 16), newIdentity.Recipient()); err != nil {
			return "", err
		}

		showCmd := exec.Command(commandPago, "--dir", dataDir, "--socket", socketPath, "show", "bar")
		var showOut bytes.Buffer
		showCmd.Stdout = &showOut
		showCmd.Stderr = &showOut
		showCmd.Stdin = strings.NewReader("")

		if err := showCmd.Run(); err != nil {
			return showOut.String(), fmt.Errorf("show through agent failed: %w", err)
		}

		if got := strings.TrimSpace(showOut.String()); got != strings.Repeat("b", 16) {
			return showOut.String(), fmt.Errorf("expected %q, got %q", strings.Repeat("b", 16), got)
		}

		// Stop the agent.
		_, _, _ = runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir, "PAGO_SOCK=" + socketPath},
			"agent", "stop",
		)

		return "", nil
	})
	if err != nil {
		t.Errorf("Rekey agent reload test failed: %v", err)
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
			return "", fmt.Errorf("failed to get password prompt for `show`: %w", err)
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

func TestShowKey(t *testing.T) {
	var buf bytes.Buffer

	_, err := withPagoDir(func(dataDir string) (string, error) {
		// Add a TOML entry.
		cmd := exec.Command(commandPago, "--dir", dataDir, "add", "toml", "--multiline")
		cmd.Stdin = strings.NewReader(`# TOML
# Comment.
password = "hunter2"
foo = "string"
bar = 5

phi = 1.68
# Another comment.
baz = [1, 2, 3, true, false]

[qux]
key = "value"

[qux.nested]
deep = "secret"
`)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			return stdout.String() + "\n" + stderr.String(), err
		}

		// Add a TOML entry with a custom default key.
		cmd = exec.Command(commandPago, "--dir", dataDir, "add", "toml-default", "--multiline")
		cmd.Stdin = strings.NewReader(`# TOML
default = "foo"
foo = "secret"
`)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()
		if err != nil {
			return stdout.String() + "\n" + stderr.String(), err
		}

		// Add a non-TOML entry.
		_, _, err = runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "not-toml", "--random",
		)
		if err != nil {
			return "", err
		}

		testCases := []struct {
			entry    string
			keys     []string
			expected string
			wantErr  bool
		}{
			{"toml", nil, "hunter2", false},
			{"toml", []string{"foo"}, "string", false},
			{"toml", []string{"bar"}, "5", false},
			{"toml", []string{"phi"}, "1.68", false},
			{"toml", []string{"baz"}, "[1, 2, 3, true, false]", false},
			{"toml", []string{"qux"}, "", true}, // Tables cannot be retrieved.
			{"toml", []string{"qux", "key"}, "value", false},
			{"toml", []string{"qux", "nested", "deep"}, "secret", false},
			{"toml", []string{"qux", "nonexistent"}, "", true},
			{"toml", []string{"nonexistent"}, "", true},
			{"toml-default", nil, "secret", false},
			{"not-toml", []string{"foo"}, "", true}, // Cannot use "--key" on non-TOML entries.
		}

		for _, tc := range testCases {
			// Show a key from the entry.
			c, err := expect.NewConsole()
			if err != nil {
				return "", fmt.Errorf("failed to create console: %w", err)
			}
			defer c.Close()

			buf.Reset()

			args := []string{"--dir", dataDir, "--socket", "", "show"}
			for _, k := range tc.keys {
				args = append(args, "--key", k)
			}
			args = append(args, tc.entry)
			cmd := exec.Command(commandPago, args...)

			cmd.Stdin = c.Tty()
			cmd.Stdout = &buf
			cmd.Stderr = c.Tty()

			err = cmd.Start()
			if err != nil {
				return "", fmt.Errorf("failed to start command for entry %q keys %v: %w", tc.entry, tc.keys, err)
			}

			_, _ = c.ExpectString("Enter password")
			_, _ = c.SendLine(password)

			err = cmd.Wait()
			if (err != nil) != tc.wantErr {
				return "", fmt.Errorf("command failed for entry %q keys %v: %w", tc.entry, tc.keys, err)
			}

			output := strings.TrimSpace(buf.String())
			if !tc.wantErr && output != tc.expected {
				return "", fmt.Errorf("for entry %q keys %v, expected %q, got %q", tc.entry, tc.keys, tc.expected, output)
			}
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `show --key` failed: %v (%q)", err, buf)
	}
}

func TestShowKeys(t *testing.T) {
	var buf bytes.Buffer

	_, err := withPagoDir(func(dataDir string) (string, error) {
		// Add a TOML entry.
		cmd := exec.Command(commandPago, "--dir", dataDir, "add", "toml", "--multiline")
		cmd.Stdin = strings.NewReader(`# TOML
# Comment.
password = "hunter2"
foo = "string"
bar = 5

phi = 1.68
# Another comment.
baz = [1, 2, 3, true, false]
qux = {"key" = "value"}
`)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			return stdout.String() + "\n" + stderr.String(), err
		}

		// Add a non-TOML entry.
		_, _, err = runCommandEnv(
			[]string{"PAGO_DIR=" + dataDir},
			"add", "not-toml", "--random",
		)
		if err != nil {
			return "", err
		}

		testCases := []struct {
			entry    string
			args     []string
			expected string
			wantErr  bool
		}{
			{"toml", []string{"-K"}, "bar\nbaz\nfoo\npassword\nphi\nqux", false},
			{"toml", []string{"--keys"}, "bar\nbaz\nfoo\npassword\nphi\nqux", false},
			{"toml", []string{"-K", "-k", "qux"}, "key", false},
			{"toml", []string{"--keys", "--key", "qux"}, "key", false},
			{"not-toml", []string{"-K"}, "", true},
			{"nonexistent", []string{"--keys"}, "", true},
			{"", []string{"--keys"}, "", true},
		}

		for _, tc := range testCases {
			// List keys from the entry.
			c, err := expect.NewConsole()
			if err != nil {
				return "", fmt.Errorf("failed to create console: %w", err)
			}
			defer c.Close()

			buf.Reset()

			args := []string{"--dir", dataDir, "--socket", "", "show"}
			args = append(args, tc.args...)
			if tc.entry != "" {
				args = append(args, tc.entry)
			}
			cmd := exec.Command(commandPago, args...)

			cmd.Stdin = c.Tty()
			cmd.Stdout = &buf
			cmd.Stderr = c.Tty()

			err = cmd.Start()
			if err != nil {
				return "", fmt.Errorf("failed to start command for entry %q: %w", tc.entry, err)
			}

			// Only expect password prompt if we are not expecting an error from pago before decryption.
			if !tc.wantErr || tc.entry == "not-toml" {
				_, _ = c.ExpectString("Enter password")
				_, _ = c.SendLine(password)
			}

			err = cmd.Wait()
			if (err != nil) != tc.wantErr {
				return "", fmt.Errorf("command failed for entry %q: %w", tc.entry, err)
			}

			output := strings.TrimSpace(buf.String())
			if !tc.wantErr && output != tc.expected {
				return "", fmt.Errorf("for entry %q, expected %q, got %q", tc.entry, tc.expected, output)
			}
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `show --keys` failed: %v (%q)", err, buf)
	}
}

func TestShowOTP(t *testing.T) {
	_, err := withPagoDir(func(dataDir string) (string, error) {
		// Add a TOML entry with a 6-digit otpauth URI.
		cmd := exec.Command(commandPago, "--dir", dataDir, "add", "otp-test-6digit", "--multiline")
		// Example URI from https://github.com/google/google-authenticator/wiki/Key-Uri-Format
		cmd.Stdin = strings.NewReader(`# TOML
otp = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"`)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			return stdout.String() + "\n" + stderr.String(), err
		}

		// Add another TOML entry with an 8-digit otpauth URI.
		cmd = exec.Command(commandPago, "--dir", dataDir, "add", "otp-test-8digit", "--multiline")
		cmd.Stdin = strings.NewReader(`# TOML
otp = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8"`)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()
		if err != nil {
			return stdout.String() + "\n" + stderr.String(), err
		}

		// Add a TOML entry where the URI lives under a non-`otp` key and the
		// default points to it. Previously this returned the raw URI; now any
		// `otpauth://` value is recognized.
		cmd = exec.Command(commandPago, "--dir", dataDir, "add", "otp-test-renamed", "--multiline")
		cmd.Stdin = strings.NewReader(`# TOML
default = "secret"
secret = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"`)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()
		if err != nil {
			return stdout.String() + "\n" + stderr.String(), err
		}

		checkOTP := func(entryName, expectedPattern string, extraArgs ...string) error {
			var buf bytes.Buffer
			c, err := expect.NewConsole()
			if err != nil {
				return fmt.Errorf("failed to create console: %w", err)
			}
			defer c.Close()

			args := []string{"--dir", dataDir, "--socket", "", "show"}
			args = append(args, extraArgs...)
			args = append(args, entryName)
			cmd := exec.Command(commandPago, args...)
			cmd.Stdin = c.Tty()
			cmd.Stdout = &buf
			cmd.Stderr = c.Tty()

			err = cmd.Start()
			if err != nil {
				return fmt.Errorf("failed to start command: %w", err)
			}

			_, _ = c.ExpectString("Enter password")
			_, _ = c.SendLine(password)

			err = cmd.Wait()
			if err != nil {
				return fmt.Errorf("command failed: %w", err)
			}

			output := strings.TrimSpace(buf.String())
			if matched, _ := regexp.MatchString(expectedPattern, output); !matched {
				return fmt.Errorf("expected OTP matching %q, got %q", expectedPattern, output)
			}
			return nil
		}

		if err := checkOTP("otp-test-6digit", `^\d{6}$`, "--key", "otp"); err != nil {
			return "", err
		}

		if err := checkOTP("otp-test-8digit", `^\d{8}$`, "--key", "otp"); err != nil {
			return "", err
		}

		// `default = "secret"` should follow to the otpauth URI and generate a code.
		if err := checkOTP("otp-test-renamed", `^\d{6}$`); err != nil {
			return "", err
		}

		// Explicit `--key secret` on the same entry should also generate a code.
		if err := checkOTP("otp-test-renamed", `^\d{6}$`, "--key", "secret"); err != nil {
			return "", err
		}

		return "", nil
	})
	if err != nil {
		t.Errorf("Command `show --key otp` failed: %v", err)
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
