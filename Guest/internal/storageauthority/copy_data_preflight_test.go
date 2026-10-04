//go:build linux || darwin

package storageauthority

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCopyDataPreflightAllReplaysAfterAllRoots(t *testing.T) {
	f := newFixture(t, nil)
	intents := map[ID]CopyIntent{}
	for n := 0; n < 2; n++ {
		v := f.volume(fmt.Sprintf("tail-%d", n))
		_, g := copyPrepare(t, f, v, ReadWrite)
		i, err := g.BeginCopy(copyRoot(f, v))
		must(t, err)
		must(t, g.FinishCopy(i.ID))
		o, err := g.BeginCopyDataOperation(1, CopyOperationDirectoryTail, i.ID)
		must(t, err)
		if f.a.s.CopyReplay == nil {
			f.a.s.CopyReplay = map[ID]copyOperationRecord{}
		}
		f.a.s.CopyReplay[v.ID] = o.token.record
		must(t, o.CompleteRequest(nil, false))
		intents[v.ID] = f.a.s.Copy.Intents[v.ID]
		g.Release()
	}
	must(t, f.a.commit(f.a.clone()))
	must(t, f.a.Close())
	before := copyDataCensus(t, f)
	seen := map[ID]bool{}
	f.c.CopyRecoveryPreflight = func(root *os.File, device, action string, i CopyIntent) error {
		if !reflect.DeepEqual(before, copyDataCensus(t, f)) {
			t.Fatal("mutation between preflights")
		}
		if root == nil || device != f.c.DeviceID || action != CopyOperationDirectoryTail || i != intents[i.Root.Volume] || seen[i.Root.Volume] {
			t.Fatal("wrong replay preflight")
		}
		seen[i.Root.Volume] = true
		return nil
	}
	// No callback may run until even unrelated retained roots validate.
	path := filepath.Join(f.path, "volumes", "tail-1")
	must(t, os.Rename(path, path+"-hidden"))
	_, err := f.openCurrent()
	if err == nil || len(seen) != 0 || !reflect.DeepEqual(before, copyDataCensus(t, f)) {
		t.Fatal("preflight or mutation preceded all-root validation")
	}
	must(t, os.Rename(path+"-hidden", path))
	f.a, err = f.openCurrent()
	must(t, err)
	if len(seen) != 2 {
		t.Fatal("startup omitted a replay preflight")
	}
}
