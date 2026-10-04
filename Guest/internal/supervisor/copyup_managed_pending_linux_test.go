//go:build linux

package supervisor

import (
	"errors"
	"reflect"
	"testing"

	"dev.cengine/guest/internal/protocol"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// Drive the actual initializer with real durable pending fences and wire-encoded
// private replies. Invalid fd deliberately makes any premature ordinary DATA
// fail: exact replay denials must be returned before root/transaction probes.
func TestManagedV4PendingInitializerRetainsRealFence(t *testing.T) {
	for _, action := range []w.PrepareAction{w.BindCopyTransaction, w.SealManifest, w.StartCleanup, w.FinishCopy} {
		for _, when := range []string{"before", "after"} {
			if action == w.FinishCopy && when == "after" {
				continue
			}
			t.Run(replayAction(action)+"-"+when, func(t *testing.T) {
				h := crashedReplayHost(t, replayAction(action)+"-"+when)
				h.deny = action
				b := h.binding
				copy := &managedCopy{
					root:  &confinedRoot{fd: -1},
					scope: managedCopyScope{Store: string(b.Store), Volume: string(b.Volume), Prepare: string(b.Prepare), Attachment: string(b.Attachment)},
					call:  func(_ int, r w.PrepareRequest) (w.PrepareReply, error) { return h.call(r) },
				}
				err := copy.initialize("/absent", protocol.Mount{Destination: "/seed"})
				if !errors.Is(err, a.ErrUnauthorized) {
					t.Fatal("initializer touched ordinary DATA before exact replay", err)
				}
				if !reflect.DeepEqual(h.calls, []w.PrepareAction{w.BeginCopy, action}) {
					t.Fatal("wrong recovery operation", h.calls)
				}
				if !errors.Is(h.guard.CheckCopyReplay(), a.ErrBlocked) {
					t.Fatal("failed recovery lost marker fence")
				}
			})
		}
	}
}
