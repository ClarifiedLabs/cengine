//go:build linux

package supervisor

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var namespacedKernelSysctls = map[string]struct{}{
	"kernel/msgmax":          {},
	"kernel/msgmnb":          {},
	"kernel/msgmni":          {},
	"kernel/sem":             {},
	"kernel/shmall":          {},
	"kernel/shmmax":          {},
	"kernel/shmmni":          {},
	"kernel/shm_rmid_forced": {},
	"kernel/domainname":      {},
}

func validateWorkloadSysctls(assignments map[string]string) error {
	for name, value := range assignments {
		if _, err := workloadSysctlPath("/proc/sys", name); err != nil {
			return err
		}
		if strings.ContainsAny(value, "\x00\n\r") {
			return fmt.Errorf("invalid sysctl value for %s", name)
		}
	}
	return nil
}

// workloadSysctlPath matches runc's writer: every dot becomes a /proc/sys path
// separator, while existing slashes remain separators.
func workloadSysctlPath(root, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\x00\n\r") {
		return "", fmt.Errorf("invalid sysctl name %q", name)
	}
	pathName := strings.ReplaceAll(name, ".", "/")
	parts := strings.Split(pathName, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid sysctl name %q", name)
	}
	for _, part := range parts {
		if !validWorkloadSysctlComponent(part, false) {
			return "", fmt.Errorf("invalid sysctl name %q", name)
		}
	}
	relative := strings.Join(parts, "/")
	if !strings.HasPrefix(relative, "net/") &&
		!strings.HasPrefix(relative, "fs/mqueue/") {
		if _, allowed := namespacedKernelSysctls[relative]; !allowed {
			return "", fmt.Errorf("sysctl %s is not namespaced", name)
		}
	}
	cleanRoot := filepath.Clean(root)
	path := filepath.Join(append([]string{cleanRoot}, parts...)...)
	rel, err := filepath.Rel(cleanRoot, path)
	if err != nil || rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("sysctl %s resolves outside /proc/sys", name)
	}
	return path, nil
}

func validWorkloadSysctlComponent(value string, dotsAllowed bool) bool {
	if value == "" || value == "." || value == ".." ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' && !(dotsAllowed && character == '.') {
			return false
		}
	}
	return true
}

func applyWorkloadSysctls(
	root string,
	assignments map[string]string,
	lstat func(string) (fs.FileInfo, error),
	writeFile func(string, []byte, os.FileMode) error,
) error {
	if err := validateWorkloadSysctls(assignments); err != nil {
		return err
	}
	names := make([]string, 0, len(assignments))
	for name := range assignments {
		names = append(names, name)
	}
	sort.Strings(names)
	paths := make(map[string]string, len(names))
	for _, name := range names {
		path, err := workloadSysctlPath(root, name)
		if err != nil {
			return err
		}
		info, err := lstat(path)
		if err != nil {
			return fmt.Errorf("inspect sysctl %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular sysctl file", path)
		}
		paths[name] = path
	}
	for _, name := range names {
		if err := writeFile(paths[name], []byte(assignments[name]), 0o644); err != nil {
			return fmt.Errorf("write sysctl %s: %w", name, err)
		}
	}
	return nil
}
