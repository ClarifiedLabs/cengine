//go:build linux

package volume

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const Root = "/run/cengine/volumes"

func Ensure(name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("invalid volume name %q", name)
	}
	path := filepath.Join(Root, name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	return path, nil
}
