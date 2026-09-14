// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package main

import (
	"errors"
	"strings"
	"testing"
)

var errClipboardTest = errors.New("test clipboard error")

func TestValidateEntryContent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"non-TOML is accepted", "hunter2", false},
		{"non-TOML with TOML-looking body is accepted", "key = ?\n", false},
		{"empty TOML is accepted", "# TOML\n", false},
		{"valid TOML is accepted", "# TOML\nkey = \"value\"\n", false},
		{"invalid TOML is rejected", "# TOML\nkey = \n", true},
		{"trailing-equals on TOML is rejected", "# TOML\nkey =", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			err := validateEntryContent(c.content)
			if (err != nil) != c.wantErr {
				t.Errorf("validateEntryContent(%q): err = %v, wantErr = %v", c.content, err, c.wantErr)
			}

			if c.wantErr && err != nil && !strings.Contains(err.Error(), "invalid TOML") {
				t.Errorf("expected error mentioning %q, got %q", "invalid TOML", err.Error())
			}
		})
	}
}

func TestCopyToClipboard(t *testing.T) {
	t.Parallel()

	clipboardWriteAll = func(string) error { return nil }
	if err := copyToClipboard("", "hunter2"); err != nil {
		t.Errorf("successful WriteAll returned error: %v", err)
	}

	clipboardWriteAll = func(string) error { return errClipboardTest }
	if err := copyToClipboard("", "hunter2"); !errors.Is(err, errClipboardTest) {
		t.Errorf("failed WriteAll: err = %v, want wrapped errClipboardTest", err)
	}

	if err := copyToClipboard("cat", "hunter2"); err != nil {
		t.Errorf("clipboard command path returned error: %v", err)
	}
}
