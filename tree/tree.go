// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package tree

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"dbohdan.com/pago"

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

		displayName := strings.TrimSuffix(info.Name(), pago.AgeExt)
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
