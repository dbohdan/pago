// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package pago

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xlab/treeprint"
)

func DirTree(root string, transform func(name string, info os.FileInfo) (bool, string)) (string, error) {
	tree := treeprint.NewWithRoot(filepath.Base(root))
	visited := make(map[string]treeprint.Tree)

	err := filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name, err = filepath.Abs(name)
		if err != nil {
			return err
		}

		keep, displayName := transform(name, info)
		if !keep {
			return nil
		}

		if len(visited) == 0 {
			visited[name] = tree
			return nil
		}

		parent, ok := visited[filepath.Dir(name)]
		if !ok {
			return nil
		}

		var newTree treeprint.Tree
		if info.IsDir() {
			newTree = parent.AddBranch(displayName)
		} else {
			newTree = parent.AddNode(displayName)
		}

		visited[name] = newTree

		return nil
	})
	if err != nil {
		return "", err
	}

	return tree.String(), nil
}

func PrintStoreTree(store string) error {
	tree, err := DirTree(store, func(name string, info os.FileInfo) (bool, string) {
		if strings.HasPrefix(info.Name(), ".") {
			return false, ""
		}

		displayName := strings.TrimSuffix(info.Name(), AgeExt)
		if info.IsDir() {
			displayName += "/"
		}

		return true, displayName
	})
	if err != nil {
		return fmt.Errorf("failed to build tree: %v", err)
	}

	fmt.Print(tree)
	return nil
}

func ListFiles(root string, transform func(name string, info os.FileInfo) (bool, string)) ([]string, error) {
	list := []string{}

	err := filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name, err = filepath.Abs(name)
		if err != nil {
			return err
		}

		keep, displayName := transform(name, info)
		if !keep {
			return nil
		}

		list = append(list, displayName)

		return nil
	})
	if err != nil {
		return []string{}, err
	}

	return list, nil
}

// Return a function that filters entries by a filename pattern.
func EntryFilter(root string, pattern *regexp.Regexp) func(name string, info os.FileInfo) (bool, string) {
	return func(name string, info os.FileInfo) (bool, string) {
		if info.IsDir() || !strings.HasSuffix(name, AgeExt) {
			return false, ""
		}

		displayName := name
		displayName = strings.TrimPrefix(displayName, root)
		displayName = strings.TrimPrefix(displayName, "/")
		displayName = strings.TrimSuffix(displayName, AgeExt)

		if pattern != nil && !pattern.MatchString(displayName) {
			return false, ""
		}

		return true, displayName
	}
}
