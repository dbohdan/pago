// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package editor

import (
	"fmt"

	"github.com/atotto/clipboard"
	"github.com/dustin/go-humanize"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type cancelError struct{}

const (
	bannerNoSave    = "%q [ Ctrl+V Paste ] [ Ctrl+C: Cancel ]"
	bannerSave      = "%q [ Ctrl+D: Save ] [ Ctrl+V Paste ] [ Ctrl+C: Cancel ]"
	editorCharLimit = 1 << 30
)

var CancelError = &cancelError{}

func (e *cancelError) Error() string {
	return "editor canceled"
}

// Edit presents an editor with a given initial content and returns the edited text.
func Edit(title, initial string, save bool) (string, error) {
	if len(initial) > editorCharLimit {
		return "", fmt.Errorf("initial text too large: over %s", humanize.IBytesN(editorCharLimit, 1))
	}

	theme := tview.Theme{}
	tview.Styles = theme
	// With a zero theme, selectedStyle must differ from tcell.StyleDefault, or selection will be invisible.
	selectedStyle := tcell.StyleDefault.Reverse(true)

	app := tview.NewApplication().
		EnableMouse(true).
		EnablePaste(true)

	textArea := tview.NewTextArea().
		SetSelectedStyle(selectedStyle).
		SetText(initial, false).
		SetWordWrap(false)

	textArea.SetClipboard(
		func(text string) {
			_ = clipboard.WriteAll(text)
		},

		func() string {
			text, _ := clipboard.ReadAll()
			return text
		},
	)

	var bannerText string
	if save {
		bannerText = bannerSave
	} else {
		bannerText = bannerNoSave
	}
	banner := tview.NewTextView().
		SetText(fmt.Sprintf(bannerText, title))

	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(banner, 1, 0, false).
		AddItem(tview.NewBox(), 1, 0, false). // Empty space.
		AddItem(textArea, 0, 1, true)

	var canceled bool
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {

		case tcell.KeyCtrlC:
			canceled = true
			app.Stop()

			return nil

		case tcell.KeyCtrlD:
			if save {
				app.Stop()
			}

			return nil

		case tcell.KeyHome:
			if event.Modifiers()&tcell.ModCtrl != 0 {
				// Go to the beginning of the buffer.
				// Not implemented until upstream implements it.
				return nil
			}

		case tcell.KeyEnd:
			if event.Modifiers()&tcell.ModCtrl != 0 {
				// Go to the end of the buffer.
				// Not implemented until upstream implements it.
				return nil
			}
		}

		return event
	})

	if err := app.SetRoot(layout, true).SetFocus(textArea).Run(); err != nil {
		return "", fmt.Errorf("editor failed: %v", err)
	}

	if canceled {
		return "", CancelError
	}

	return textArea.GetText(), nil
}
