// pago - a command-line password manager.
//
// License: MIT.
// See the file `LICENSE`.

package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	style "github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

type editor struct {
	err      error
	save     bool
	textarea textarea.Model
}

type cancelError struct{}

const (
	bannerNoSave    = "[ Ctrl+V: Paste ] [ Esc: Cancel ]"
	bannerSave      = "[ Ctrl+D: Save ] [ Ctrl+V: Paste ] [ Esc: Cancel ]"
	defaultHeight   = 15
	defaultWidth    = 80
	editorCharLimit = 1 << 16
)

var CancelError = &cancelError{}

func (e *cancelError) Error() string {
	return "editor canceled"
}

func (e editor) Init() tea.Cmd {
	return nil
}

func (e editor) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.Type {

		case tea.KeyEsc, tea.KeyCtrlC:
			e.err = CancelError
			return e, tea.Quit

		case tea.KeyCtrlD:
			if !e.save {
				return e, nil
			}

			return e, tea.Quit
		}
	}

	e.textarea, cmd = e.textarea.Update(msg)
	return e, cmd
}

func (e editor) View() string {
	banner := bannerNoSave
	if e.save {
		banner = bannerSave
	}

	return fmt.Sprintf("%s\n\n%s\n", banner, e.textarea.View())
}

// Edit presents an editor with the given initial content and returns the edited text.
func Edit(initial string, save bool) (string, error) {
	if len(initial) > editorCharLimit {
		return "", fmt.Errorf("initial text too long")
	}

	ta := textarea.New()
	ta.CharLimit = editorCharLimit
	ta.ShowLineNumbers = false
	ta.SetValue(initial)
	ta.Focus()

	// Remove cursor line highlighting.
	ta.FocusedStyle.CursorLine = style.Style{}
	// Remove base styling.
	ta.FocusedStyle.Base = style.Style{}
	// Match blurred and focused styles.
	ta.BlurredStyle = ta.FocusedStyle

	width, height, err := term.GetSize(0)
	if err == nil {
		height /= 2
	} else {
		width = defaultWidth
		height = defaultHeight
	}
	ta.SetWidth(width)
	ta.SetHeight(height)

	e := editor{
		save:     save,
		textarea: ta,
	}

	p := tea.NewProgram(e)
	m, err := p.Run()
	if err != nil {
		return "", fmt.Errorf("editor failed: %v", err)
	}

	ed := m.(editor)
	if ed.err != nil {
		return "", ed.err
	}

	return strings.TrimSpace(ed.textarea.Value()), nil
}
