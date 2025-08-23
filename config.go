// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

import (
	"os"
	"os/user"
	"path/filepath"
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
	Version          = "0.12.0"
	WaitForSocket    = 3 * time.Second

	DefaultAgent           = "pago-agent"
	DefaultGitEmail        = "pago password manager"
	DefaultGitName         = "pago@localhost"
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

// Workaround for xdg.RuntimeDir being "/run/user/{{Uid}}" on *BSD.
func DefaultSocket() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}

	runtimeDir := xdg.RuntimeDir
	subdir := "pago"

	if _, err := os.Stat(runtimeDir); err != nil {
		runtimeDir = "/var/run/user/" + currentUser.Uid
	}

	if _, err := os.Stat(runtimeDir); err != nil {
		runtimeDir = os.TempDir()
		subdir = "pago-" + currentUser.Username
	}

	return filepath.Join(runtimeDir, subdir, "socket"), nil
}
