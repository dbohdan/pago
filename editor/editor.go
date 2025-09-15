// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package editor

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	style "github.com/charmbracelet/lipgloss"
)

type editor struct {
	err      error
	save     bool
	textarea textarea.Model
	title    string
}

type cancelError struct{}

const (
	bannerNoSave    = "[ Ctrl+V: Paste ] [ Esc: Cancel ]"
	bannerSave      = "[ Ctrl+D: Save ] [ Ctrl+V: Paste ] [ Esc: Cancel ]"
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

	case tea.WindowSizeMsg:
		e.textarea.SetWidth(msg.Width)
		e.textarea.SetHeight(msg.Height - 2) // Negative height works.
	}

	e.textarea, cmd = e.textarea.Update(msg)
	return e, cmd
}

func (e editor) View() string {
	banner := bannerNoSave
	if e.save {
		banner = bannerSave
	}

	return fmt.Sprintf("%q %s\n\n%s", e.title, banner, e.textarea.View())
}

// Edit presents an editor with a given title and initial content and returns the edited text.
func Edit(title, initial string, save bool) (string, error) {
	if len(initial) > editorCharLimit {
		return "", fmt.Errorf("initial text too long")
	}

	ta := textarea.New()
	ta.CharLimit = editorCharLimit
	ta.Cursor.SetMode(cursor.CursorStatic)
	ta.ShowLineNumbers = false
	ta.SetValue(initial)
	ta.Focus()

	// Remove cursor line highlighting.
	ta.FocusedStyle.CursorLine = style.Style{}
	// Remove base styling.
	ta.FocusedStyle.Base = style.Style{}
	// Match blurred and focused styles.
	ta.BlurredStyle = ta.FocusedStyle

	e := editor{
		save:     save,
		title:    title,
		textarea: ta,
	}

	p := tea.NewProgram(e, tea.WithAltScreen())
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
