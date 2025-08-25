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
	Version          = "0.15.0"
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
	GitEmailEnv = "GIT_AUTHOR_EMAIL"
	GitEnv      = "PAGO_GIT"
	GitNameEnv  = "GIT_AUTHOR_NAME"
	LengthEnv   = "PAGO_LENGTH"
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

	// We don't use xdg.RuntimeDir because of its value on BSD and macOS.
	// "/run/user/$UID/" is unlikely to be configured on a BSD.
	// On macOS, the user's temporary directory is closer to the semantics required by the spec than "~/Library/Application Support/".
	// (But still wrong?
	// The spec says the directory's existence must be tied to the user session.)
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	subdir := "pago"

	if _, err := os.Stat(runtimeDir); err != nil && runtime.GOOS == "freebsd" {
		runtimeDir = "/var/run/xdg/" + currentUser.Username
	}

	if _, err := os.Stat(runtimeDir); err != nil {
		runtimeDir = "/run/user/" + currentUser.Uid
	}

	if _, err := os.Stat(runtimeDir); err != nil {
		runtimeDir = "/var/run/user/" + currentUser.Uid
	}

	if _, err := os.Stat(runtimeDir); err != nil {
		runtimeDir = os.TempDir()
		subdir = "pago-" + currentUser.Username
	}

	return filepath.Join(runtimeDir, subdir, "socket"), nil
}
