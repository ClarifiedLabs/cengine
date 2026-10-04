package copycontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func listForTest(t *testing.T, names ...string) func(int, []byte) (int, error) {
	t.Helper()
	return func(_ int, buffer []byte) (int, error) {
		if len(buffer) != MaxXattrListBytes {
			t.Fatal("unbounded list buffer")
		}
		if len(names) == 0 {
			return 0, nil
		}
		raw := strings.Join(names, "\x00") + "\x00"
		if len(raw) > len(buffer) {
			t.Fatal("test list exceeds buffer")
		}
		return copy(buffer, raw), nil
	}
}

func TestXattrValidationAndNulls(t *testing.T) {
	for name, snapshot := range map[string]*XattrSnapshot{
		"nil":                nil,
		"state":              {State: "unknown", Entries: []Xattr{}},
		"nil-entries":        {State: "supported"},
		"unsupported-values": {State: "unsupported", Entries: []Xattr{{Name: "user.a", Value: []byte{}}}},
		"nil-value":          {State: "supported", Entries: []Xattr{{Name: "user.a"}}},
		"duplicate":          {State: "supported", Entries: []Xattr{{Name: "user.a", Value: []byte{}}, {Name: "user.a", Value: []byte{}}}},
		"count":              {State: "supported", Entries: make([]Xattr, MaxXattrEntries+1)},
		"value-size":         {State: "supported", Entries: []Xattr{{Name: "user.a", Value: make([]byte, MaxXattrValueBytes+1)}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateXattrs(snapshot); err == nil {
				t.Fatal("accepted invalid snapshot")
			}
			// Validation must precede even enumeration or unsupported short-circuit.
			if err := RestoreXattrs(0, snapshot, XattrOperations{}); err == nil {
				t.Fatal("invalid restore accepted")
			}
		})
	}
	for _, name := range []string{"", ".a", "user.", "missing-namespace", "user.a\x00b", "user." + strings.Repeat("a", 251)} {
		if err := ValidateXattrs(&XattrSnapshot{State: "supported", Entries: []Xattr{{Name: XattrName(name), Value: []byte{}}}}); err == nil {
			t.Fatalf("accepted name %q", name)
		}
	}
	for _, raw := range []string{`null`, `{"state":"supported","entries":null}`, `{"state":"supported","entries":[{"name":null,"value":""}]}`, `{"state":"supported","entries":[{"name":"dXNlci5h","value":null}]}`} {
		var snapshot *XattrSnapshot
		if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
			t.Fatal(err)
		}
		if err := ValidateXattrs(snapshot); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, state := range []string{"supported", "unsupported"} {
		s := &XattrSnapshot{State: state, Entries: []Xattr{}}
		if err := ValidateXattrs(s); err != nil {
			t.Fatal(err)
		}
		if got := string(marshal(t, s)); got != `{"state":"`+state+`","entries":[]}` {
			t.Fatalf("empty encoding = %s", got)
		}
	}
}

func TestXattrExactLimits(t *testing.T) {
	if MaxXattrEntries != 1024 || MaxXattrListBytes != 64*1024 || MaxXattrValueBytes != 64*1024 || MaxXattrBytes != 1024*1024 {
		t.Fatal("xattr bounds changed")
	}
	entries := make([]Xattr, MaxXattrEntries)
	for i := range entries {
		entries[i] = Xattr{Name: XattrName(fmt.Sprintf("user.%d", i)), Value: []byte{}}
	}
	if err := ValidateXattrs(&XattrSnapshot{State: "supported", Entries: entries}); err != nil {
		t.Fatal(err)
	}
	entries = make([]Xattr, 256)
	for i := range entries {
		entries[i] = Xattr{Name: XattrName(fmt.Sprintf("user.%03d", i) + strings.Repeat("x", 247)), Value: []byte{}}
	}
	if err := ValidateXattrs(&XattrSnapshot{State: "supported", Entries: entries}); err != nil {
		t.Fatalf("exact list bound: %v", err)
	}
	entries = append(entries, Xattr{Name: "user.extra", Value: []byte{}})
	if err := ValidateXattrs(&XattrSnapshot{State: "supported", Entries: entries}); err == nil {
		t.Fatal("name bytes bound ignored")
	}
	entries = make([]Xattr, 16)
	namesBytes := 0
	for i := range entries {
		entries[i] = Xattr{Name: XattrName(fmt.Sprintf("user.%02d", i)), Value: make([]byte, MaxXattrValueBytes)}
		namesBytes += len(entries[i].Name) + 1
	}
	entries[15].Value = entries[15].Value[:MaxXattrValueBytes-namesBytes]
	if err := ValidateXattrs(&XattrSnapshot{State: "supported", Entries: entries}); err != nil {
		t.Fatalf("exact aggregate bound: %v", err)
	}
	entries[15].Value = append(entries[15].Value, 0)
	if err := ValidateXattrs(&XattrSnapshot{State: "supported", Entries: entries}); err == nil {
		t.Fatal("aggregate bound ignored")
	}
}

func TestSnapshotFaultsAndBounds(t *testing.T) {
	for _, fault := range []error{unix.EIO, unix.EPERM, unix.ENOSYS, unix.ERANGE} {
		calls := 0
		_, err := SnapshotXattrs(0, XattrOperations{List: func(int, []byte) (int, error) { calls++; return 0, fault }})
		if !errors.Is(err, fault) || calls != 1 {
			t.Fatalf("list: calls=%d error=%v", calls, err)
		}
	}
	for _, fault := range []error{unix.EIO, unix.EPERM, unix.ENODATA, unix.EOPNOTSUPP, unix.ERANGE} {
		calls := 0
		_, err := SnapshotXattrs(0, XattrOperations{List: listForTest(t, "user.a", "user.b"), Get: func(int, string, []byte) (int, error) { calls++; return 0, fault }})
		if !errors.Is(err, fault) || calls != 1 {
			t.Fatalf("get: calls=%d error=%v", calls, err)
		}
	}
	for name, list := range map[string]func(int, []byte) (int, error){
		"oversize":     func(int, []byte) (int, error) { return MaxXattrListBytes + 1, nil },
		"negative":     func(int, []byte) (int, error) { return -1, nil },
		"unterminated": func(_ int, b []byte) (int, error) { b[0] = 'x'; return 1, nil },
		"duplicate":    listForTest(t, "user.a", "user.a"),
		"invalid-name": listForTest(t, "missing-namespace"),
		"empty-name":   listForTest(t, ""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SnapshotXattrs(0, XattrOperations{List: list}); err == nil {
				t.Fatal("invalid list accepted")
			}
		})
	}
	for _, n := range []int{-1, MaxXattrValueBytes + 1} {
		if _, err := SnapshotXattrs(0, XattrOperations{List: listForTest(t, "user.a"), Get: func(int, string, []byte) (int, error) { return n, nil }}); err == nil {
			t.Fatal("invalid value size accepted")
		}
	}
	names := make([]string, MaxXattrEntries+1)
	for i := range names {
		names[i] = fmt.Sprintf("user.%d", i)
	}
	if _, err := SnapshotXattrs(0, XattrOperations{List: listForTest(t, names...)}); err == nil {
		t.Fatal("entry bound ignored")
	}
	if _, err := SnapshotXattrs(0, XattrOperations{List: listForTest(t, names[:17]...), Get: func(_ int, _ string, b []byte) (int, error) {
		if len(b) != MaxXattrValueBytes {
			t.Fatal("unbounded value buffer")
		}
		return len(b), nil
	}}); err == nil {
		t.Fatal("aggregate bound ignored")
	}
}

func TestSnapshotOrderingAndOwnedValues(t *testing.T) {
	var got []string
	s, err := SnapshotXattrs(42, XattrOperations{List: listForTest(t, "user.\xff", "user.a", "user.empty"), Get: func(fd int, name string, b []byte) (int, error) {
		if fd != 42 || len(b) != MaxXattrValueBytes {
			t.Fatal("operation contract changed")
		}
		got = append(got, name)
		if name == "user.empty" {
			return 0, nil
		}
		return copy(b, []byte(name)), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"user.a", "user.empty", "user.\xff"}) {
		t.Fatalf("get order: %q", got)
	}
	for _, e := range s.Entries {
		if e.Value == nil {
			t.Fatal("empty value became nil")
		}
		if e.Name != "user.empty" && string(e.Value) != string(e.Name) {
			t.Fatalf("aliased value: %+v", e)
		}
	}
	if err := ValidateXattrs(s); err != nil {
		t.Fatal(err)
	}
}

func TestUnsupportedVersusKnownEmpty(t *testing.T) {
	noSupport := XattrOperations{List: func(int, []byte) (int, error) { return 0, fmt.Errorf("wrapped: %w", unix.EOPNOTSUPP) }}
	for _, tc := range []struct {
		ops   XattrOperations
		state string
	}{{noSupport, "unsupported"}, {XattrOperations{List: listForTest(t)}, "supported"}} {
		s, err := SnapshotXattrs(0, tc.ops)
		if err != nil || s.State != tc.state || s.Entries == nil || len(s.Entries) != 0 {
			t.Fatalf("snapshot = %v, %v", s, err)
		}
	}
	if err := RestoreXattrs(0, &XattrSnapshot{State: "unsupported", Entries: []Xattr{}}, XattrOperations{}); err != nil {
		t.Fatal(err)
	}
	if err := RestoreXattrs(0, &XattrSnapshot{State: "supported", Entries: []Xattr{}}, noSupport); err != nil {
		t.Fatal(err)
	}
	if err := RestoreXattrs(0, &XattrSnapshot{State: "supported", Entries: []Xattr{{Name: "user.a", Value: []byte{}}}}, noSupport); !errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatalf("populated unsupported restore: %v", err)
	}
	removed := 0
	if err := RestoreXattrs(0, &XattrSnapshot{State: "supported", Entries: []Xattr{}}, XattrOperations{List: listForTest(t, "security.capability", "system.posix_acl_default"), Remove: func(int, string) error { removed++; return nil }}); err != nil || removed != 2 {
		t.Fatalf("known-empty restore: removed=%d, %v", removed, err)
	}
}

func TestRestoreACLAndCapabilityOrderingAndFaults(t *testing.T) {
	s := &XattrSnapshot{State: "supported", Entries: []Xattr{
		{Name: "system.posix_acl_access", Value: []byte{2, 0, 255}},
		{Name: "security.capability", Value: []byte{0, 255, 1}},
		{Name: "user.empty", Value: []byte{}},
	}}
	for _, failureAt := range []string{"", "list", "remove:system.posix_acl_default", "remove:user.added", "set:system.posix_acl_access", "set:security.capability", "set:user.empty"} {
		t.Run(failureAt, func(t *testing.T) {
			var actions []string
			act := func(name string) error {
				actions = append(actions, name)
				if name == failureAt {
					return unix.EIO
				}
				return nil
			}
			ops := XattrOperations{
				List: func(fd int, b []byte) (int, error) {
					if err := act("list"); err != nil {
						return 0, err
					}
					return listForTest(t, "user.added", "security.capability", "system.posix_acl_default")(fd, b)
				},
				Remove: func(_ int, name string) error { return act("remove:" + name) },
				Set: func(_ int, name string, value []byte, flags int) error {
					if flags != 0 {
						t.Fatal("not an upsert")
					}
					for _, entry := range s.Entries {
						if name == string(entry.Name) && !reflect.DeepEqual(value, entry.Value) {
							t.Fatal("changed ACL/capability bytes")
						}
					}
					return act("set:" + name)
				},
			}
			err := RestoreXattrs(0, s, ops)
			want := []string{"list", "remove:system.posix_acl_default", "remove:user.added", "set:system.posix_acl_access", "set:security.capability", "set:user.empty"}
			if failureAt == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if !errors.Is(err, unix.EIO) {
					t.Fatalf("fault = %v", err)
				}
				for i, action := range want {
					if action == failureAt {
						want = want[:i+1]
						break
					}
				}
			}
			if !reflect.DeepEqual(actions, want) {
				t.Fatalf("actions=%v, want=%v", actions, want)
			}
		})
	}
	for _, fault := range []error{unix.ENODATA, unix.EPERM, unix.ENOSPC, unix.EOPNOTSUPP} {
		sets := 0
		err := RestoreXattrs(0, s, XattrOperations{List: listForTest(t, "user.added"), Remove: func(int, string) error { return fmt.Errorf("wrapped: %w", fault) }, Set: func(int, string, []byte, int) error { sets++; return nil }})
		if fault == unix.ENODATA {
			if err != nil || sets != 3 {
				t.Fatalf("disappeared attr: %v, sets=%d", err, sets)
			}
		} else if !errors.Is(err, fault) || sets != 0 {
			t.Fatalf("remove fault: %v, sets=%d", err, sets)
		}
		// ENODATA is ignored only for removal, never for setting a saved value.
		err = RestoreXattrs(0, s, XattrOperations{List: listForTest(t), Set: func(int, string, []byte, int) error { return fault }})
		if !errors.Is(err, fault) {
			t.Fatalf("set fault: %v", err)
		}
	}
}
