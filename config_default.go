//go:build !(android || darwin || windows)

// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

const (
	DefaultClip = "xclip -in -selection clip"
)
