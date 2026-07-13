//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnableCgroupControllersDelegatesDockerResourceControllers(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpuset cpu io memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enableCgroupControllers(root); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "+cpu +memory +pids" {
		t.Fatalf("unexpected controller delegation %q", value)
	}
}
