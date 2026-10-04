package supervisor

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func dataReplayIntent(phase string) a.CopyIntent {
	id := a.ID("11111111-1111-4111-8111-111111111111")
	object := func(ino uint32, kind uint32) a.Ext4ObjectV1 {
		o := a.Ext4ObjectV1{Inode: uint64(ino), Generation: 7, FileType: kind, HandleType: 1, HandleSize: 8}
		binary.LittleEndian.PutUint32(o.Handle[:4], ino)
		binary.LittleEndian.PutUint32(o.Handle[4:], 7)
		return o
	}
	root := a.CopyRootV1{Store: id, Volume: id, BackingUUID: [16]byte{1}, Root: object(21, 0040000)}
	binding := a.Binding{Store: id, Volume: id, Attachment: id, Launch: id, Prepare: id, Container: a.ContainerID(strings.Repeat("a", 64)), Key: a.Fingerprint(strings.Repeat("b", 64)), Role: a.PrepareRole, Mode: a.ReadWrite}
	i := a.CopyIntent{ID: id, Epoch: id, Owner: binding, Root: root, Transaction: object(22, 0040000), Phase: phase, InitialCaptured: true, ManifestDigest: [32]byte{1}, ManifestSize: 1}
	if phase == a.CopyCleaning || phase == a.CopyCompleted {
		i.Cleanup.Manifest = object(23, 0100000)
	}
	return i
}

func TestManagedCopyDataReplayCorrelation(t *testing.T) {
	for _, action := range []w.PrepareAction{w.RollbackCopy, w.ResumeCopyDirectory} {
		phases := []string{a.CopySealed, a.CopyCleaning}
		if action == w.ResumeCopyDirectory {
			phases = append(phases, a.CopyCompleted)
		}
		for _, phase := range phases {
			for _, fault := range []string{"", "intent", "root", "owner", "epoch", "pending", "phase", "tail-metadata"} {
				if fault == "tail-metadata" && action != w.ResumeCopyDirectory {
					continue
				}
				t.Run(phase+"/"+string(rune('0'+action))+"/"+fault, func(t *testing.T) {
					before := dataReplayIntent(phase)
					var calls []w.PrepareAction
					call := func(request w.PrepareRequest) (w.PrepareReply, error) {
						calls = append(calls, request.Action)
						i := before
						if len(calls) == 1 {
							return w.PrepareReply{Intent: i, Root: i.Root, Pending: action}, nil
						}
						if len(calls) == 3 {
							if request.Action != w.BeginCopy {
								t.Fatal("no fresh Begin")
							}
							i.ID = "22222222-2222-4222-8222-222222222222"
							i.Phase, i.Transaction, i.ManifestDigest, i.ManifestSize, i.InitialCaptured, i.Initial, i.Cleanup = a.CopyBegun, a.Ext4ObjectV1{}, [32]byte{}, 0, false, a.CopyCleanupV1{}, a.CopyCleanupV1{}
							return w.PrepareReply{Intent: i, Root: i.Root}, nil
						}
						if request.Action != action || request.Intent != before.ID {
							t.Fatal("uncorrelated request", request)
						}
						if action == w.RollbackCopy {
							i.Phase, i.Cleanup = a.CopyCleaning, dataReplayIntent(a.CopyCleaning).Cleanup
						}
						v := w.PrepareReply{Intent: i, Root: i.Root}
						switch fault {
						case "intent":
							v.Intent.ID = "22222222-2222-4222-8222-222222222222"
						case "root":
							v.Intent.Root.BackingUUID[0]++
							v.Root = v.Intent.Root
						case "owner":
							v.Intent.Owner.Attachment = "22222222-2222-4222-8222-222222222222"
						case "epoch":
							v.Intent.Epoch = "22222222-2222-4222-8222-222222222222"
						case "pending":
							v.Pending = action
						case "phase":
							v.Intent.Phase = a.CopyBound
						case "tail-metadata":
							v.Intent.Initial.Mode ^= 1
						}
						return v, nil
					}
					got, err := beginManagedCopy(call, func(a.CopyIntent) error { return nil })
					if fault != "" {
						if err == nil || len(calls) != 2 {
							t.Fatal("accepted divergent recovery", got, err, calls)
						}
						return
					}
					want := []w.PrepareAction{w.BeginCopy, action}
					wantPhase := phase
					if action == w.RollbackCopy {
						wantPhase = a.CopyCleaning
					}
					if phase == a.CopyCompleted {
						want, wantPhase = append(want, w.BeginCopy), a.CopyBegun
					}
					if err != nil || got.Phase != wantPhase || !reflect.DeepEqual(calls, want) {
						t.Fatal(got, err, calls)
					}
				})
			}
		}
	}
}
