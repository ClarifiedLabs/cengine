package copycontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	MaxXattrListBytes  = 64 * 1024
	MaxXattrValueBytes = 64 * 1024
	MaxXattrBytes      = 1024 * 1024
	MaxXattrEntries    = 1024
)

// XattrSnapshot distinguishes a known-empty set from an unsupported filesystem.
// Nil snapshots are reserved for legacy journals and invalid for managed-v4.
type XattrSnapshot struct {
	State   string  `json:"state"`
	Entries []Xattr `json:"entries"`
}

type Xattr struct {
	Name  XattrName `json:"name"`
	Value []byte    `json:"value"`
}

// XattrName preserves arbitrary Linux name bytes through base64 JSON encoding.
type XattrName string

func (name XattrName) MarshalJSON() ([]byte, error) {
	return json.Marshal([]byte(name))
}

func (name *XattrName) UnmarshalJSON(data []byte) error {
	var raw []byte
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*name = XattrName(raw)
	return nil
}

// XattrOperations supplies inode-bound operations. Callers own descriptor
// lifetime and confinement; no syscall wrappers or mutable hooks live here.
// Supply each operation used by the selected algorithm (List/Get for snapshot,
// List/Set/Remove for restore). Unsupported restore does not call operations.
type XattrOperations struct {
	List   func(int, []byte) (int, error)
	Get    func(int, string, []byte) (int, error)
	Set    func(int, string, []byte, int) error
	Remove func(int, string) error
}

func validXattrName(name string) bool {
	namespace, suffix, ok := strings.Cut(name, ".")
	return ok && namespace != "" && suffix != "" && len(name) <= 255 &&
		!strings.ContainsRune(name, 0)
}

func ValidateXattrs(snapshot *XattrSnapshot) error {
	if snapshot == nil || (snapshot.State != "supported" && snapshot.State != "unsupported") ||
		snapshot.Entries == nil || len(snapshot.Entries) > MaxXattrEntries {
		return errors.New("invalid copy-up xattr snapshot")
	}
	if snapshot.State == "unsupported" && len(snapshot.Entries) != 0 {
		return errors.New("unsupported copy-up xattr snapshot contains values")
	}
	seen := make(map[string]bool, len(snapshot.Entries))
	total, names := 0, 0
	for _, entry := range snapshot.Entries {
		if !validXattrName(string(entry.Name)) || seen[string(entry.Name)] || entry.Value == nil || len(entry.Value) > MaxXattrValueBytes {
			return fmt.Errorf("invalid copy-up xattr %q", entry.Name)
		}
		seen[string(entry.Name)] = true
		names += len(entry.Name) + 1
		total += len(entry.Name) + 1 + len(entry.Value)
		if names > MaxXattrListBytes || total > MaxXattrBytes {
			return errors.New("copy-up xattr snapshot exceeds byte limit")
		}
	}
	return nil
}

// ListXattrs enumerates once with a fixed-size buffer, validates and sorts raw
// names. EOPNOTSUPP alone means unsupported; other failures are never retried.
func ListXattrs(fd int, operations XattrOperations) ([]string, bool, error) {
	buffer := make([]byte, MaxXattrListBytes)
	n, err := operations.List(fd, buffer)
	if errors.Is(err, unix.EOPNOTSUPP) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("list copy-up xattrs: %w", err)
	}
	if n < 0 || n > len(buffer) || (n > 0 && buffer[n-1] != 0) {
		return nil, false, errors.New("invalid copy-up xattr list")
	}
	if n == 0 {
		return []string{}, true, nil
	}
	names := strings.Split(string(buffer[:n-1]), "\x00")
	if len(names) > MaxXattrEntries {
		return nil, false, errors.New("copy-up xattr list exceeds entry limit")
	}
	sort.Strings(names)
	for index, name := range names {
		if !validXattrName(name) || (index > 0 && names[index-1] == name) {
			return nil, false, fmt.Errorf("invalid copy-up xattr name %q", name)
		}
	}
	return names, true, nil
}

// SnapshotXattrs copies each value with fixed per-value and aggregate bounds.
// After successful enumeration every Get error is fatal, including ENODATA and
// EOPNOTSUPP: neither can turn a partially observed set into an empty snapshot.
func SnapshotXattrs(fd int, operations XattrOperations) (*XattrSnapshot, error) {
	names, supported, err := ListXattrs(fd, operations)
	if err != nil {
		return nil, err
	}
	snapshot := &XattrSnapshot{State: "unsupported", Entries: []Xattr{}}
	if !supported {
		return snapshot, nil
	}
	snapshot.State = "supported"
	buffer := make([]byte, MaxXattrValueBytes)
	total := 0
	for _, name := range names {
		n, err := operations.Get(fd, name, buffer)
		if err != nil {
			return nil, fmt.Errorf("read copy-up xattr %q: %w", name, err)
		}
		if n < 0 || n > len(buffer) {
			return nil, fmt.Errorf("invalid copy-up xattr size for %q", name)
		}
		total += len(name) + 1 + n
		if total > MaxXattrBytes {
			return nil, errors.New("copy-up xattr snapshot exceeds byte limit")
		}
		value := make([]byte, n)
		copy(value, buffer[:n])
		snapshot.Entries = append(snapshot.Entries, Xattr{Name: XattrName(name), Value: value})
	}
	return snapshot, nil
}

// RestoreXattrs validates before any operation, removes unwanted names in sorted
// order, then upserts saved values in snapshot order. It stops at the first
// error, except a removal's ENODATA. Unsupported snapshots do not authorize
// deletion. Callers must apply ownership and mode first: chown can clear
// capabilities and chmod can rewrite ACL masks. This function never does either.
func RestoreXattrs(fd int, snapshot *XattrSnapshot, operations XattrOperations) error {
	if err := ValidateXattrs(snapshot); err != nil {
		return err
	}
	if snapshot.State == "unsupported" {
		return nil
	}
	names, supported, err := ListXattrs(fd, operations)
	if err != nil {
		return err
	}
	if !supported {
		if len(snapshot.Entries) != 0 {
			return fmt.Errorf("restore copy-up xattrs: %w", unix.EOPNOTSUPP)
		}
		return nil
	}
	wanted := make(map[string]bool, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		wanted[string(entry.Name)] = true
	}
	for _, name := range names {
		if !wanted[name] {
			if err := operations.Remove(fd, name); err != nil && !errors.Is(err, unix.ENODATA) {
				return fmt.Errorf("remove copy-up xattr %q: %w", name, err)
			}
		}
	}
	for _, entry := range snapshot.Entries {
		if err := operations.Set(fd, string(entry.Name), entry.Value, 0); err != nil {
			return fmt.Errorf("restore copy-up xattr %q: %w", entry.Name, err)
		}
	}
	return nil
}
