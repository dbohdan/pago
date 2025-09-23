// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package git

import (
	"fmt"
	"path/filepath"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// InitRepo initializes a new Git repository at the specified directory.
func InitRepo(repoDir string) error {
	_, err := gogit.PlainInit(repoDir, false)
	if err != nil {
		return fmt.Errorf("failed to initialize Git repository: %v", err)
	}

	return nil
}

// Commit stages the specified files and creates a new commit in the Git repository.
func Commit(repoDir, authorName, authorEmail, message string, add []string) error {
	repo, err := gogit.PlainOpen(repoDir)
	if err != nil {
		return fmt.Errorf("failed to open Git repository: %v", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %v", err)
	}

	for _, name := range add {
		relPath, err := filepath.Rel(repoDir, name)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %v", err)
		}

		_, err = w.Add(relPath)
		if err != nil {
			return fmt.Errorf("failed to stage file: %v", err)
		}
	}

	_, err = w.Commit(message, &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  authorName,
			Email: authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to commit: %v", err)
	}

	return nil
}
