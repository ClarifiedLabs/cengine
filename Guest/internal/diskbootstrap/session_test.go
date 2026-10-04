package diskbootstrap

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

type fakeOperations struct {
	calls       []string
	fail        string
	badIdentity bool
}

func (f *fakeOperations) call(s string) error {
	f.calls = append(f.calls, s)
	if f.fail == s {
		return errors.New("private raw disk error must not escape")
	}
	return nil
}
func (f *fakeOperations) prepare([]target) error { return f.call("prepare") }
func (f *fakeOperations) initialize(t target, _ string, _ uint64) error {
	return f.call("initialize:" + t.device)
}
func (f *fakeOperations) mount(t target) error { return f.call("mount:" + t.device) }
func (f *fakeOperations) sync(t target) (identity, error) {
	err := f.call("sync:" + t.device)
	id := identity{testUUID, testBytes}
	if f.badIdentity {
		id.bytes++
	}
	return id, err
}

type exchange struct {
	io.Reader
	bytes.Buffer
}

func (x *exchange) Read(p []byte) (int, error) { return x.Reader.Read(p) }
func runFixture(t *testing.T, m Manifest, commit any, ops *fakeOperations) ([]any, error) {
	t.Helper()
	x := &exchange{Reader: bytes.NewReader(append(rawFrame(m), rawFrame(commit)...))}
	err := session(x, helloFixture(), ops)
	var messages []any
	for x.Buffer.Len() != 0 {
		m, decodeErr := ReadFrame(&x.Buffer)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		messages = append(messages, m)
	}
	return messages, err
}
func TestInvalidWholeManifestPerformsZeroOperations(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"nonce":             func(m *Manifest) { m.GuestBootNonce = testLaunch },
		"kind":              func(m *Manifest) { m.Kind = "storage" },
		"missing":           func(m *Manifest) { m.Disks = m.Disks[:1] },
		"extra":             func(m *Manifest) { m.Disks = append(m.Disks, m.Disks[1]) },
		"reordered":         func(m *Manifest) { m.Disks[0], m.Disks[1] = m.Disks[1], m.Disks[0] },
		"duplicate":         func(m *Manifest) { m.Disks[1].Ordinal = 0 },
		"later size":        func(m *Manifest) { m.Disks[1].ExpectedBytes += 4096 },
		"size overflow":     func(m *Manifest) { m.Disks[1].ExpectedBytes = 1 << 63 },
		"later role":        func(m *Manifest) { m.Disks[1].Role = "storage-root" },
		"later action":      func(m *Manifest) { m.Disks[1].Action = "format-if-empty" },
		"traversal":         func(m *Manifest) { m.Disks[1].VolumeName = ptr("../bad") },
		"absolute":          func(m *Manifest) { m.Disks[1].VolumeName = ptr("/bad") },
		"empty name":        func(m *Manifest) { m.Disks[1].VolumeName = ptr("") },
		"missing name":      func(m *Manifest) { m.Disks[1].VolumeName = nil },
		"root name":         func(m *Manifest) { m.Disks[0].VolumeName = ptr("bad") },
		"mount operation":   func(m *Manifest) { m.Disks[1].OperationUUID = ptr(testOperation) },
		"missing operation": func(m *Manifest) { m.Disks[0].OperationUUID = nil },
		"missing uuid":      func(m *Manifest) { m.Disks[0].Ext4UUID = nil },
		"zero uuid":         func(m *Manifest) { m.Disks[0].Ext4UUID = ptr("00000000-0000-0000-0000-000000000000") },
		"unaligned":         func(m *Manifest) { m.Disks[0].ExpectedBytes++ },
		"too small":         func(m *Manifest) { m.Disks[0].ExpectedBytes = 4096 },
		"duplicate name":    func(m *Manifest) { d := m.Disks[1]; d.Ordinal = 2; m.Disks = append(m.Disks, d) },
	} {
		t.Run(name, func(t *testing.T) {
			m := manifestFixture()
			mutate(&m)
			f := &fakeOperations{}
			messages, err := runFixture(t, m, commitFixture(), f)
			if err == nil || len(f.calls) != 0 {
				t.Fatalf("invalid manifest performed operations: %v %+v", err, f.calls)
			}
			if len(messages) != 2 {
				t.Fatalf("unexpected messages: %+v", messages)
			}
			if _, ok := messages[1].(*Failure); !ok {
				t.Fatal("invalid manifest acknowledged")
			}
		})
	}
}
func TestSessionSerialOperationsObservedIdentityAndCommit(t *testing.T) {
	f := &fakeOperations{}
	messages, err := runFixture(t, manifestFixture(), commitFixture(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"prepare", "initialize:/dev/vda", "sync:/dev/vda", "mount:/dev/vdb", "sync:/dev/vdb"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls %v", f.calls)
	}
	ack, ok := messages[1].(*Synced)
	if !ok || len(ack.Disks) != 2 || ack.Disks[0].OperationUUID == nil || ack.Disks[1].OperationUUID != nil || ack.Disks[1].Ext4UUID != testUUID {
		t.Fatalf("ack %+v", ack)
	}
	m := manifestFixture()
	if got := diskTarget("container", m.Disks[1]); got != (target{"/dev/vdb", "/run/cengine/volumes/example", "cengine-volume"}) {
		t.Fatal(got)
	}
	if got := diskTarget("storage", m.Disks[0]); got != (target{"/dev/vda", "/data", "cengine-volumes"}) {
		t.Fatal(got)
	}
}
func TestOperationOrSyncFailureNeverAcknowledges(t *testing.T) {
	for _, phase := range []string{"prepare", "initialize:/dev/vda", "sync:/dev/vda", "mount:/dev/vdb", "sync:/dev/vdb", "identity"} {
		f := &fakeOperations{fail: phase, badIdentity: phase == "identity"}
		messages, err := runFixture(t, manifestFixture(), commitFixture(), f)
		if err == nil {
			t.Fatal("accepted failure", phase)
		}
		for _, message := range messages {
			if _, ok := message.(*Synced); ok {
				t.Fatal("acknowledged", phase)
			}
		}
		if bytes.Contains(rawFrame(messages[len(messages)-1]), []byte("private raw")) {
			t.Fatal("leaked operation error")
		}
	}
}
func TestOnlyExactCommitUnlocksGateNoSecondManifest(t *testing.T) {
	bad := commitFixture()
	bad.GuestBootNonce = testUUID
	other := commitFixture()
	other.ShimLaunchUUID = testUUID
	for _, commit := range []any{bad, other, manifestFixture(), failure("commit", nil)} {
		f := &fakeOperations{}
		_, err := runFixture(t, manifestFixture(), commit, f)
		if err == nil || err.Error() != "commit" || len(f.calls) != 5 {
			t.Fatalf("gate accepted/replayed: %v %v", err, f.calls)
		}
	}
	f := &fakeOperations{}
	x := &exchange{Reader: bytes.NewReader(rawFrame(manifestFixture()))}
	if err := session(x, helloFixture(), f); err == nil || err.Error() != "commit" {
		t.Fatal("lost commit unlocked gate", err)
	}
}
