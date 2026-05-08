// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"0", 0, false},
		{"30", 30 * time.Second, false},
		{"1s", time.Second, false},
		{"1m30s", time.Minute + 30*time.Second, false},
		{"100ms", 100 * time.Millisecond, false},
		{"-1ms", -time.Millisecond, false},
		{"-1", 0, true},
		{"abc", 0, true},
		{"", 0, true},
	}

	for _, c := range cases {
		got, err := ParseDuration(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseDuration(%q): err = %v, wantErr = %v", c.in, err, c.wantErr)

			continue
		}

		if !c.wantErr && got != c.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
