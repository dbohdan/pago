//go:build !darwin && !windows

// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package main

const (
	defaultClip = "xclip -in -selection clip"
)
