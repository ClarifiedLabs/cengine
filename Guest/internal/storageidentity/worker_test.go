package storageidentity

import (
	"errors"
	"reflect"
	"syscall"
	"testing"

	"dev.cengine/guest/internal/storagewire"
)

func TestSnapshotCopiesAndPreservesExactMultiset(t *testing.T) {
	caller := storagewire.Caller{FSUID: 0, FSGID: 123, Groups: []uint32{9, 2, 9}, EffectiveCaps: uint64(1)<<40 | 1}
	got, err := snapshot(caller, 027)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(caller.Groups, []uint32{9, 2, 9}) || !reflect.DeepEqual(got.Groups, []uint32{2, 9, 9}) {
		t.Fatalf("input mutated or groups deduplicated: input=%v copy=%v", caller.Groups, got.Groups)
	}
	caller.Groups[1] = 777
	if got.Groups[0] != 2 || got.FSUID != 0 || got.EffectiveCaps != uint64(1)<<40|1 {
		t.Fatalf("snapshot changed: %+v", got)
	}
}

func TestInputValidation(t *testing.T) {
	base := storagewire.Caller{Groups: []uint32{}}
	for name, change := range map[string]func(*storagewire.Caller){
		"missing groups":  func(c *storagewire.Caller) { c.Groups = nil },
		"too many groups": func(c *storagewire.Caller) { c.Groups = make([]uint32, storagewire.MaxGroups+1) },
		"sentinel uid":    func(c *storagewire.Caller) { c.FSUID = ^uint32(0) },
		"sentinel gid":    func(c *storagewire.Caller) { c.FSGID = ^uint32(0) },
		"sentinel group":  func(c *storagewire.Caller) { c.Groups = []uint32{^uint32(0)} },
	} {
		t.Run(name, func(t *testing.T) {
			caller := base
			change(&caller)
			var w Worker
			if err := w.Do(caller, 0, func() error { t.Error("invalid caller reached callback"); return nil }); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	var w Worker
	if err := w.Do(base, 01000, func() error { t.Error("invalid umask reached callback"); return nil }); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("umask error = %v", err)
	}
	if err := w.Do(base, 0, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil callback error = %v", err)
	}
	base.Groups = make([]uint32, storagewire.MaxGroups)
	if _, err := snapshot(base, 0777); err != nil {
		t.Fatalf("maximum group count rejected: %v", err)
	}
}
