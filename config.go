// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/adrg/xdg"
)

const (
	AgeExt           = ".age"
	AgentSocketPath  = "socket"
	DirPerms         = 0o700
	ExitMemlockError = 3
	FilePerms        = 0o600
	NameInvalidChars = `[\n]`
	Version          = "0.21.0"
	WaitForSocket    = 3 * time.Second

	DefaultAgent           = "pago-agent"
	DefaultGitEmail        = "pago@localhost"
	DefaultGitName         = "pago password manager"
	DefaultPasswordLength  = "20"
	DefaultPasswordPattern = "[A-Za-z0-9]"

	AgentEnv    = "PAGO_AGENT"
	ClipEnv     = "PAGO_CLIP"
	ConfirmEnv  = "PAGO_CONFIRM"
	DataDirEnv  = "PAGO_DIR"
	ExpireEnv   = "PAGO_EXPIRE"
	GitEmailEnv = "GIT_AUTHOR_EMAIL"
	GitEnv      = "PAGO_GIT"
	GitNameEnv  = "GIT_AUTHOR_NAME"
	LengthEnv   = "PAGO_LENGTH"
	MouseEnv    = "PAGO_MOUSE"
	MemlockEnv  = "PAGO_MEMLOCK"
	PatternEnv  = "PAGO_PATTERN"
	SocketEnv   = "PAGO_SOCK"
	TimeoutEnv  = "PAGO_TIMEOUT"
)

var (
	DefaultDataDir = filepath.Join(xdg.DataHome, "pago")
)

func DefaultSocket() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	// Build candidate directories in priority order.
	candidates := []string{}
	subdir := "pago"

	if envDir := os.Getenv("XDG_RUNTIME_DIR"); envDir != "" {
		candidates = append(candidates, envDir)
	}

	if runtime.GOOS == "freebsd" {
		candidates = append(candidates, filepath.Join("/var/run/xdg", currentUser.Username))
	}

	candidates = append(
		candidates,
		filepath.Join("/run/user", currentUser.Uid),
		filepath.Join("/var/run/user", currentUser.Uid),
	)

	// Find the first candidate that exists.
	var runtimeDir string
	for _, candidateDir := range candidates {
		if _, err := os.Stat(candidateDir); err == nil {
			runtimeDir = candidateDir
			break
		}
	}

	// If no candidate exists, fall back to the temporary directory.
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
		subdir = "pago-" + currentUser.Username + "@" + hostname
	}

	return filepath.Join(runtimeDir, subdir, "socket"), nil
}
