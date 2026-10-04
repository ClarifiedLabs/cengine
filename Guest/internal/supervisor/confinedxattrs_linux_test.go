//go:build linux

package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func xattrListForTest(names ...string) func(int, []byte) (int, error) {
	return func(_ int, buffer []byte) (int, error) {
		if len(buffer) != maxConfinedXattrListBytes {
			return 0, errors.New("unbounded list buffer")
		}
		if len(names) == 0 {
			return 0, nil
		}
		return copy(buffer, strings.Join(names, "\x00")+"\x00"), nil
	}
}

func TestConfinedXattrSnapshotBoundsAndFaults(t *testing.T) {
	for _, fault := range []error{unix.EIO, unix.EPERM, unix.ENOSYS, unix.ERANGE} {
		t.Run("list-"+fault.Error(), func(t *testing.T) {
			_, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{list: func(int, []byte) (int, error) { return 0, fault }})
			if !errors.Is(err, fault) {
				t.Fatalf("list error = %v", err)
			}
		})
	}
	unsupported, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{list: func(int, []byte) (int, error) { return 0, unix.EOPNOTSUPP }})
	if err != nil || unsupported.State != "unsupported" {
		t.Fatalf("unsupported = %v, %v", unsupported, err)
	}
	empty, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{list: xattrListForTest()})
	if err != nil || empty.State != "supported" || empty.Entries == nil || len(empty.Entries) != 0 {
		t.Fatalf("known empty = %v, %v", empty, err)
	}
	for _, fault := range []error{unix.EIO, unix.EPERM, unix.ENODATA, unix.EOPNOTSUPP, unix.ERANGE} {
		t.Run("get-"+fault.Error(), func(t *testing.T) {
			_, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{list: xattrListForTest("user.a"), get: func(int, string, []byte) (int, error) { return 0, fault }})
			if !errors.Is(err, fault) {
				t.Fatalf("get error = %v", err)
			}
		})
	}
	for name, list := range map[string]func(int, []byte) (int, error){
		"oversize":     func(int, []byte) (int, error) { return maxConfinedXattrListBytes + 1, nil },
		"negative":     func(int, []byte) (int, error) { return -1, nil },
		"unterminated": func(_ int, b []byte) (int, error) { b[0] = 'x'; return 1, nil },
		"duplicate":    xattrListForTest("user.a", "user.a"),
		"invalid-name": xattrListForTest("missing-namespace"),
		"empty-name":   xattrListForTest(""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{list: list}); err == nil {
				t.Fatal("invalid list accepted")
			}
		})
	}
	for _, n := range []int{-1, maxConfinedXattrValueBytes + 1} {
		if _, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{list: xattrListForTest("user.a"), get: func(int, string, []byte) (int, error) { return n, nil }}); err == nil {
			t.Fatal("invalid value size accepted")
		}
	}
	names := make([]string, maxConfinedXattrEntries+1)
	for i := range names {
		names[i] = fmt.Sprintf("user.%d", i)
	}
	if _, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{list: xattrListForTest(names...)}); err == nil {
		t.Fatal("entry bound ignored")
	}
	if _, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{list: xattrListForTest(names[:17]...), get: func(_ int, _ string, b []byte) (int, error) {
		if len(b) != maxConfinedXattrValueBytes {
			t.Fatal("unbounded value buffer")
		}
		return len(b), nil
	}}); err == nil {
		t.Fatal("aggregate bound ignored")
	}
}

func TestConfinedXattrNonUTF8NameRoundTrip(t *testing.T) {
	snapshot, err := snapshotConfinedXattrsWith(0, confinedXattrOperations{
		list: xattrListForTest("user.\xff"),
		get:  func(_ int, _ string, buffer []byte) (int, error) { return copy(buffer, []byte{0, 255}), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var decoded confinedXattrSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateConfinedXattrs(&decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot, &decoded) {
		t.Fatalf("lossy name roundtrip: %s", data)
	}
}

func TestConfinedXattrExactRestoreAndFaults(t *testing.T) {
	snapshot := &confinedXattrSnapshot{State: "supported", Entries: []confinedXattr{{Name: "user.keep", Value: []byte("original")}, {Name: "user.empty", Value: []byte{}}}}
	var actions []string
	operations := confinedXattrOperations{
		list:   xattrListForTest("user.keep", "user.added", "system.posix_acl_default"),
		remove: func(_ int, name string) error { actions = append(actions, "remove:"+name); return nil },
		set: func(_ int, name string, value []byte, flags int) error {
			actions = append(actions, "set:"+name+":"+string(value))
			if flags != 0 {
				t.Fatal("not an upsert")
			}
			return nil
		},
	}
	if err := restoreConfinedXattrsWith(0, snapshot, operations); err != nil {
		t.Fatal(err)
	}
	want := []string{"remove:system.posix_acl_default", "remove:user.added", "set:user.keep:original", "set:user.empty:"}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("actions = %v", actions)
	}
	for _, fault := range []error{unix.EIO, unix.EPERM, unix.ENOSPC, unix.EOPNOTSUPP} {
		for _, removal := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/remove=%v", fault, removal), func(t *testing.T) {
				ops := operations
				if removal {
					ops.remove = func(int, string) error { return fault }
				} else {
					ops.set = func(int, string, []byte, int) error { return fault }
				}
				if err := restoreConfinedXattrsWith(0, snapshot, ops); !errors.Is(err, fault) {
					t.Fatalf("restore error = %v", err)
				}
			})
		}
	}
	unsupported := &confinedXattrSnapshot{State: "unsupported", Entries: []confinedXattr{}}
	if err := restoreConfinedXattrsWith(0, unsupported, confinedXattrOperations{}); err != nil {
		t.Fatal(err)
	}
	noSupport := confinedXattrOperations{list: func(int, []byte) (int, error) { return 0, unix.EOPNOTSUPP }}
	if err := restoreConfinedXattrsWith(0, snapshot, noSupport); !errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatalf("lost populated attrs: %v", err)
	}
	empty := &confinedXattrSnapshot{State: "supported", Entries: []confinedXattr{}}
	actions = nil
	if err := restoreConfinedXattrsWith(0, empty, operations); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 3 {
		t.Fatalf("empty snapshot did not remove every attr: %v", actions)
	}
	if err := restoreConfinedXattrsWith(0, empty, noSupport); err != nil {
		t.Fatal(err)
	}
}
