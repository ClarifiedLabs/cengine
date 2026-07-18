//go:build linux

package operations

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestContainerRootUsesRunningProcessRoot(t *testing.T) {
	pid := os.Getpid()
	got, err := containerRoot(pid)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("/proc/%d/root", pid)
	if got != want {
		t.Fatalf("containerRoot(%d) = %q, want %q", pid, got, want)
	}
}

func TestArchivePathResolvesRelativeEntries(t *testing.T) {
	root := "/container/tmp"

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "entry", path: "a.txt", want: filepath.Join(root, "a.txt")},
		{name: "dot entry", path: "./a.txt", want: filepath.Join(root, "a.txt")},
		{name: "archive root", path: ".", want: root},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := archivePath(root, test.path)
			if err != nil {
				t.Fatalf("archivePath(%q): %v", test.path, err)
			}
			if got != test.want {
				t.Fatalf("archivePath(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

func TestArchivePathRejectsPathsOutsideDestination(t *testing.T) {
	tests := []struct {
		path string
		want error
	}{
		{path: "", want: syscall.EINVAL},
		{path: "/etc/passwd", want: syscall.EINVAL},
		{path: "../etc/passwd", want: syscall.EPERM},
		{path: "directory/../../etc/passwd", want: syscall.EPERM},
	}

	for _, test := range tests {
		_, err := archivePath("/container/tmp", test.path)
		if !errors.Is(err, test.want) {
			t.Fatalf("archivePath(%q) error = %v, want %v", test.path, err, test.want)
		}
	}
}
