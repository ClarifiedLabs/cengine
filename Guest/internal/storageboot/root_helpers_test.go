package storageboot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreshRootRejectsExistingAuthorityAndRecoveredData(t *testing.T) {
	for _, kind := range []string{"directory", "file", "dangling-link"} {
		t.Run(kind, func(t *testing.T) {
			root := openRoot(t)
			path := filepath.Join(root.Name(), authorityName)
			switch kind {
			case "directory":
				must(t, os.Mkdir(path, 0700))
			case "file":
				must(t, os.WriteFile(path, nil, 0600))
			case "dangling-link":
				must(t, os.Symlink("missing", path))
			}
			if freshRoot(root) == nil {
				t.Fatal("accepted authority marker")
			}
		})
	}
	root := openRoot(t)
	for _, name := range []string{"volumes", "lost+found"} {
		must(t, os.Mkdir(filepath.Join(root.Name(), name), 0700))
	}
	must(t, freshRoot(root))
	must(t, os.WriteFile(filepath.Join(root.Name(), "lost+found", "recovered"), nil, 0600))
	if freshRoot(root) == nil {
		t.Fatal("accepted recovered data")
	}
}
