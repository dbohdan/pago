// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package main

import (
	"strings"
	"testing"
)

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
