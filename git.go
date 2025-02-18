// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func InitGitRepo(repoDir string) error {
	_, err := git.PlainInit(repoDir, false)
	if err != nil {
		return fmt.Errorf("failed to initialize Git repository: %v", err)
	}

	return nil
}

func Commit(repoDir, authorName, authorEmail, message string, add []string) error {
	repo, err := git.PlainOpen(repoDir)
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

	_, err = w.Commit(message, &git.CommitOptions{
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
