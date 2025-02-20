// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

import (
	"path/filepath"
	"time"

	"github.com/adrg/xdg"
)

const (
	AgeExt           = ".age"
	AgentSocketPath  = "socket"
	DirPerms         = 0o700
	FilePerms        = 0o600
	NameInvalidChars = `[\n]`
	Version          = "0.10.0"
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
	MlockEnv    = "PAGO_MLOCK"
	PatternEnv  = "PAGO_PATTERN"
	SocketEnv   = "PAGO_SOCK"
	TimeoutEnv  = "PAGO_TIMEOUT"
)

var (
	DefaultCacheDir = filepath.Join(xdg.CacheHome, "pago")
	DefaultDataDir  = filepath.Join(xdg.DataHome, "pago")
	DefaultSocket   = filepath.Join(DefaultCacheDir, AgentSocketPath)
)
