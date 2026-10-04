package storageclient

import (
	"errors"
	"math"
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	w "dev.cengine/guest/internal/storagewire"
)

func TestCredentialABI(t *testing.T) {
	if w.CredentialABI != 3 || unsafe.Sizeof(credentialHeader{}) != 64 || unsafe.Offsetof(credentialHeader{}.Semantics) != 40 || unsafe.Offsetof(credentialHeader{}.Effective) != 48 || unsafe.Offsetof(credentialHeader{}.Valid) != 56 {
		t.Fatal("ABI layout")
	}
}
func TestCredentialSnapshot(t *testing.T) {
	groups := make([]uint32, w.MaxGroups)
	for i := range groups {
		groups[i] = uint32(i)
	}
	calls := 0
	q := func(fd int, h *credentialHeader, out []uint32) error {
		if fd != 71 || h.Unique != 123456 || h.Version != 3 || h.Flags != 0 || h.Semantics != 0 {
			t.Fatal("wrong delivering fd/unique/ABI")
		}
		if calls == 0 && (out != nil || h.GroupCount != 0) {
			t.Fatal("not size query")
		}
		if calls == 1 && len(out) != len(groups) {
			t.Fatal("truncated groups")
		}
		h.GroupCount = uint32(len(groups))
		h.State = 1
		h.FSUID = 0
		h.FSGID = 100
		h.Effective = 0
		h.Valid = 0x1ffffffffff
		h.Semantics = uint64(w.MetadataMask)
		copy(out, groups)
		calls++
		return nil
	}
	s, err := capture(q, 71, 123456, 0x1ffffffffff)
	if err != nil || !s.present || calls != 2 || !reflect.DeepEqual(s.caller.Groups, groups) || s.caller.EffectiveCaps != 0 || s.semantics != w.MetadataMask {
		t.Fatalf("snapshot: %+v %v", s, err)
	}
	groups[0] = 999
	if s.caller.Groups[0] != 0 {
		t.Fatal("mutable identity")
	}
}
func TestCredentialFailuresAndNone(t *testing.T) {
	cases := []struct {
		name   string
		change func(*credentialHeader, int)
		fail   bool
	}{
		{"none", func(h *credentialHeader, _ int) {
			h.State = 0
			h.FSUID = math.MaxUint32
			h.FSGID = math.MaxUint32
			h.Valid = 0
		}, false},
		{"abi", func(h *credentialHeader, _ int) { h.Version = 1 }, true},
		{"unique", func(h *credentialHeader, _ int) { h.Unique++ }, true},
		{"flags", func(h *credentialHeader, _ int) { h.Flags = 1 }, true},
		{"unknown_semantics", func(h *credentialHeader, _ int) { h.Semantics = 1025 }, true},
		{"abi2", func(h *credentialHeader, _ int) { h.Version = 2 }, true},
		{"missing_valid", func(h *credentialHeader, _ int) { h.Semantics = 2 }, true},
		{"changed_semantics", func(h *credentialHeader, n int) { h.Semantics = uint64(1 | n<<1) }, true},
		{"none_semantics", func(h *credentialHeader, _ int) {
			h.State = 0
			h.FSUID = math.MaxUint32
			h.FSGID = math.MaxUint32
			h.Valid = 0
			h.Semantics = 1
		}, true},
		{"mask", func(h *credentialHeader, _ int) { h.Valid = 7 }, true},
		{"cap", func(h *credentialHeader, _ int) { h.Effective = 8 }, true},
		{"invaliduid", func(h *credentialHeader, _ int) { h.FSUID = math.MaxUint32 }, true},
		{"groups", func(h *credentialHeader, _ int) { h.GroupCount = w.MaxGroups + 1 }, true},
		{"changed", func(h *credentialHeader, n int) { h.FSGID = uint32(n) }, true},
		{"noneisnotroot", func(h *credentialHeader, _ int) { h.State = 0; h.Valid = 0 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, err := capture(func(_ int, h *credentialHeader, _ []uint32) error {
				h.State = 1
				h.Valid = 3
				tc.change(h, calls)
				calls++
				return nil
			}, 7, 4, 3)
			if (err != nil) != tc.fail {
				t.Fatalf("%+v %v", s, err)
			}
			if !tc.fail && (!s.valid || s.present) {
				t.Fatal("NONE state")
			}
		})
	}
	for _, at := range []int{0, 1} {
		calls := 0
		_, err := capture(func(_ int, h *credentialHeader, _ []uint32) error {
			defer func() { calls++ }()
			if calls == at {
				return ErrUnsupported
			}
			h.State = 1
			h.Valid = 3
			return nil
		}, 7, 4, 3)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	}
}
func TestNativeCredentialsFailClosed(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("real patched-device coverage is a separate Linux fixture")
	}
	_, err := capture(nativeCredentialQuery, 7, 1, 3)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
func TestAuthSelection(t *testing.T) {
	c, other := &Client{}, &Client{}
	present := Snapshot{owner: c, valid: true, present: true, caller: w.Caller{Groups: []uint32{}, FSUID: 0}}
	a, err := c.auth(present, 0)
	if err != nil || a.Caller.EffectiveCaps != 0 {
		t.Fatal(a, err)
	}
	if _, err = other.auth(present, 0); err == nil {
		t.Fatal("cross-session snapshot")
	}
	if _, err = c.auth(Snapshot{}, w.LifecycleAuth); err == nil {
		t.Fatal("zero is NONE")
	}
	none := Snapshot{owner: c, valid: true}
	if _, err = c.auth(none, w.CallerAuth); err == nil {
		t.Fatal("NONE elevated to caller")
	}
	for _, kind := range []w.AuthKind{w.OpenGrantAuth, w.NodeMetadataAuth, w.LifecycleAuth} {
		a, err = c.auth(none, kind)
		if err != nil || a.Caller != nil {
			t.Fatal(a, err)
		}
	}
}
