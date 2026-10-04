package diskbootstrap

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"dev.cengine/guest/internal/disk"
	a "dev.cengine/guest/internal/storageauthority"
)

type probeOperations struct{ fakeOperations }

func (f *probeOperations) probeReadOnly(t target, uuid string, size uint64) (identity, error) {
	err := f.call("probe:" + t.device)
	if f.badIdentity {
		size++
	}
	return identity{uuid, size}, err
}
func probeFixture() (Hello, Manifest) {
	h := helloFixture()
	h.Kind = "storage"
	h.Disks = h.Disks[:1]
	m := manifestFixture()
	m.Kind = "storage"
	m.Disks = m.Disks[:1]
	m.Disks[0].Role = "storage-root"
	m.Disks[0].Action = "probe-read-only"
	m.Disks[0].OperationUUID = nil
	return h, m
}
func TestProbeSessionNeverMountsInitializesOrSyncs(t *testing.T) {
	for _, phase := range []string{"", "probe:/dev/vda", "identity", "unsupported", "lost-commit"} {
		t.Run(phase, func(t *testing.T) {
			h, m := probeFixture()
			f := &probeOperations{fakeOperations{fail: phase, badIdentity: phase == "identity"}}
			var ops diskOperations = f
			if phase == "unsupported" {
				ops = &f.fakeOperations
			}
			input := rawFrame(m)
			if phase != "lost-commit" {
				input = append(input, rawFrame(commitFixture())...)
			}
			x := &exchange{Reader: bytes.NewReader(input)}
			ack, err := sessionEvidence(x, h, ops)
			if phase == "" {
				if err != nil || ack.Sync != "read-only-no-replay" || ack.Disks[0].OperationUUID != nil {
					t.Fatalf("ack %+v: %v", ack, err)
				}
			} else if err == nil || ack != nil {
				t.Fatalf("accepted %s", phase)
			}
			want := []string{"prepare", "probe:/dev/vda"}
			if phase == "unsupported" {
				want = want[:1]
			}
			if !reflect.DeepEqual(f.calls, want) {
				t.Fatalf("unexpected write-side operations: %v", f.calls)
			}
		})
	}
}
func TestProbeManifestClosedObservationContract(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"container":    func(m *Manifest) { m.Kind = "container"; m.Disks[0].Role = "container-root" },
		"missing-uuid": func(m *Manifest) { m.Disks[0].Ext4UUID = nil },
		"operation":    func(m *Manifest) { m.Disks[0].OperationUUID = ptr(testOperation) },
		"extra-disk":   func(m *Manifest) { m.Disks = append(m.Disks, m.Disks[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			h, m := probeFixture()
			mutate(&m)
			f := &probeOperations{}
			x := &exchange{Reader: bytes.NewReader(rawFrame(m))}
			if _, err := sessionEvidence(x, h, f); err == nil || len(f.calls) != 0 {
				t.Fatal("invalid probe performed operations", f.calls, err)
			}
		})
	}
	_, m := probeFixture()
	var b bytes.Buffer
	if err := WriteFrame(&b, &m); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(&b); err != nil {
		t.Fatal(err)
	}
	ack := Synced{Version: Version, Type: "synced", ShimLaunchUUID: testLaunch, GuestBootNonce: testNonce, Sync: "read-only-no-replay", Disks: []SyncedDisk{{0, testBytes, testUUID, nil}}}
	if err := WriteFrame(&b, &ack); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(&b); err != nil {
		t.Fatal(err)
	}
	ack.Disks[0].OperationUUID = ptr(testOperation)
	if validMessage(&ack) {
		t.Fatal("probe ack carried operation")
	}
	ack.Disks[0].OperationUUID = nil
	ack.Disks = append(ack.Disks, SyncedDisk{1, testBytes, testUUID, nil})
	if validMessage(&ack) {
		t.Fatal("probe ack carried multiple disks")
	}
}
func TestResumePromotionRequiresActualProbeAndConsumesFailure(t *testing.T) {
	for _, probe := range []bool{false, true} {
		root, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		r := VerifiedBootResult{state: &verifiedState{root: root, binding: StorageBinding{testLaunch, testNonce, testUUID, testBytes}}}
		if probe {
			root.Close()
			r.state.root = nil
			r.state.probe = &disk.Ext4ReadOnlyLease{}
		}
		copy := r
		signed := a.SignedLifecycleResumeOpen{} // mismatched signed launch: never reach unmount/mount
		if err := r.PromoteResume(nil, signed); err == nil {
			t.Fatal("promoted absent/invalid probe")
		}
		if probe && !copy.state.resumeAttempted {
			t.Fatal("copies did not share terminal failure")
		}
		if !probe && copy.state.resumeAttempted {
			t.Fatal("ordinary mount became resume capability")
		}
		if err := copy.PromoteResume(nil, signed); err == nil {
			t.Fatal("replayed failed promotion")
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := (VerifiedBootResult{}).PromoteResume(nil, a.SignedLifecycleResumeOpen{}); err == nil {
		t.Fatal("zero boot promoted")
	}
}

func TestProbeLifecycleRootDoesNotEscapeReadOnlyDescriptor(t *testing.T) {
	binding := StorageBinding{testLaunch, testNonce, testUUID, testBytes}
	r := VerifiedBootResult{state: &verifiedState{probe: &disk.Ext4ReadOnlyLease{}, binding: binding}}
	defer r.Close()
	root, got, probe, err := r.LifecycleRoot()
	if err != nil || root != nil || got != binding || !probe {
		t.Fatalf("probe must yield purpose/binding, not an RO root: %v %v %v", root, probe, err)
	}
	r.state.resumeAttempted = true // unsuccessful promotion cannot release a root
	if root, _, _, err := r.LifecycleRoot(); err == nil || root != nil {
		t.Fatal("failed promotion returned a root")
	}
}

func TestProbeCannotBecomeOrdinaryStorageOrFreshCapability(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := VerifiedBootResult{state: &verifiedState{root: root, probe: &disk.Ext4ReadOnlyLease{}, fresh: true}}
	defer r.Close()
	if _, _, err := r.StorageRoot(); err == nil {
		t.Fatal("probe became writable boot")
	}
	if err := r.FreshInitialization(); err == nil {
		t.Fatal("probe became initialization permission")
	}
	if _, err := r.ContainerBinding(); err == nil {
		t.Fatal("probe became container permission")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
