//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storagemanaged

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

// A selected authority Retire can wait for the namespace gate while unrelated
// work owns it. Empty target resources are not evidence that its Barrier owns
// the syncfs seam. Exercise both another real Registry.Barrier and the mutation
// syncfs seam; Authority itself serializes retirement barriers, but not DATA IO.
func TestNativeFaultFinalSyncTupleUnderGate(t *testing.T) {
	for _, kind := range []string{"other-volume", "other-attachment", "mutation"} {
		for _, fault := range []a.NativeFaultError{a.NativeEIO, a.NativeENOSPC} {
			t.Run(fmt.Sprintf("%s-error-%d", kind, fault), func(t *testing.T) {
				f := newFixture(t)
				f.expectFaults = true
				selected := a.Binding{Store: f.storeID, Volume: f.volumeID, Attachment: newID(t), Container: a.ContainerID(strings.Repeat("c", 64)), Launch: newID(t), Key: fingerprint(t, key(t)), Role: a.RuntimeRole, Mode: a.ReadWrite}
				plan := a.NativeFaultPlan{Stage: a.NativeRetireFinalSyncfs, Error: fault, Store: selected.Store, Epoch: f.authority.Epoch(), Volume: selected.Volume, Attachment: selected.Attachment, RetireOperation: newID(t)}
				witness, err := f.authority.NewNativeFaultWitness(plan)
				must(t, err)
				// Count delegated, real syscalls separately from injection observations.
				realCalls := 0
				f.registry.syncOps.syncfs = func(fd int) error {
					realCalls++
					return unix.Syncfs(fd)
				}
				_, err = f.registry.InstallNativeFault(witness)
				must(t, err)
				must(t, f.authority.RegisterAttachment(f.control, a.RegisterRequest{Operation: newID(t), Binding: selected}))
				// Deliberately no selected DATA session: this is the vulnerable empty
				// target-resource case, not a successful drain/resource-close stub.
				other := selected
				other.Volume, other.Attachment = newID(t), newID(t)
				other.Key = fingerprint(t, key(t))
				otherPath := filepath.Join(f.path, "volumes", "other")
				must(t, os.Mkdir(otherPath, 0700))
				otherRoot, err := os.Open(otherPath)
				must(t, err)
				defer otherRoot.Close()
				st, err := stat(int(otherRoot.Fd()))
				must(t, err)
				must(t, f.authority.AddVolume(f.control, a.VolumeRequest{Operation: newID(t), Volume: a.Volume{ID: other.Volume, Name: "other", Root: a.RootIdentity{Device: st.Dev, Inode: st.Ino}}}))
				barrierRoot := otherRoot
				if kind == "other-attachment" {
					other.Volume, barrierRoot = selected.Volume, f.volume
				}
				must(t, f.authority.RegisterAttachment(f.control, a.RegisterRequest{Operation: newID(t), Binding: other}))

				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				injectedSync := f.registry.syncOps.syncfs
				var offObservation a.NativeFaultObservation
				f.registry.syncOps.syncfs = func(fd int) error {
					b := f.registry.barrierBinding
					if b == nil || !plan.Matches(*b) {
						close(entered) // exactly one unrelated operation, already under gate
						<-release
						err := injectedSync(fd)
						offObservation = witness.Observation()
						return err
					}
					return injectedSync(fd)
				}
				offDone, targetDone := make(chan struct{}), make(chan struct{})
				var offErr, targetErr error
				var receipt a.Receipt
				wait := func(done <-chan struct{}) bool {
					select {
					case <-done:
						return true
					case <-time.After(5 * time.Second):
						t.Error("concurrent registry operation did not join")
						return false
					}
				}
				go func() {
					defer close(offDone)
					if kind == "mutation" {
						f.gate.Lock()
						defer f.gate.Unlock()
						offErr = f.registry.syncFilesystem(other.Volume, int(otherRoot.Fd()))
					} else {
						offErr = f.registry.Barrier(other, barrierRoot)
					}
				}()
				defer func() { unblock(); wait(offDone) }()
				if !wait(entered) {
					return
				}
				go func() {
					defer close(targetDone)
					receipt, targetErr = f.authority.Retire(context.Background(), f.control, a.RetireRequest{Operation: plan.RetireOperation, Store: plan.Store, Volume: plan.Volume, Attachment: plan.Attachment, Launch: selected.Launch})
				}()
				defer func() { unblock(); wait(targetDone) }()
				// BarrierCalls publishes authority selection, not gate acquisition.
				// The other volume remains stopped immediately before the fault seam.
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for witness.Observation().BarrierCalls == 0 {
					select {
					case <-tick.C:
					case <-deadline.C:
						t.Fatal("selected retirement never reached the locked registry gate")
					}
				}
				unblock()
				if !wait(offDone) || !wait(targetDone) {
					return
				}
				if offErr != nil || offObservation != (a.NativeFaultObservation{BarrierCalls: 1}) {
					t.Fatalf("off-tuple sync consumed injection/counters: err=%v observation=%+v", offErr, offObservation)
				}
				want := unix.EIO
				if fault == a.NativeENOSPC {
					want = unix.ENOSPC
				}
				if !errors.Is(targetErr, want) || receipt != (a.Receipt{}) {
					t.Fatalf("selected retirement: receipt=%+v err=%v, want %v", receipt, targetErr, want)
				}
				if got := witness.Observation(); got != (a.NativeFaultObservation{Fired: 1, BarrierCalls: 1, FinalSyncCalls: 1}) {
					t.Fatalf("selected final sync: %+v", got)
				}
				f.gate.Lock()
				defer f.gate.Unlock()
				if realCalls != 1 || f.registry.barrierBinding != nil {
					t.Fatalf("real off-tuple syscall count=%d or leaked barrier identity", realCalls)
				}
				if kind != "other-attachment" && f.registry.faults[other.Volume] != nil {
					t.Fatal("selected injection poisoned another volume")
				}
			})
		}
	}
}
