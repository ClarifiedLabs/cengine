package workloadstorage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
)

// Private mount/trace fixture: tests Session ownership and actual host file
// syscalls, NOT native FUSE or authority denial. Client trace has separate real
// TLS/FIFO tests. No mock syscall error is accepted as a negative here.
type writableSessionFactory struct {
	*originalFactoryFake
	open   func() (*os.File, error)
	owner  *retainedFDOwner
	aborts atomic.Int32
}

func (f *writableSessionFactory) newOriginalWritableFD(attachment Attachment) *retainedFDOwner {
	f.owner = newRetainedFDOwner(f.open, func() { f.aborts.Add(1) }, attachment.Done())
	return f.owner
}

type writableSessionAttachment struct {
	sessionAttachmentFake
	positive bool
}

func (m *writableSessionAttachment) BeginOriginalConsumerFile(_ a.DataHello, positive bool) error {
	m.positive = positive
	return nil
}
func (m *writableSessionAttachment) EndOriginalConsumerFile(a.DataHello) (c.OriginalConsumerFileTrace, error) {
	if !m.positive {
		return c.OriginalConsumerFileTrace{}, ErrInvalidFrame
	}
	return c.OriginalConsumerFileTrace{Write: &c.OriginalConsumerFileRequest{Node: 2, Handle: 3, RequestSequence: 4}, Sync: &c.OriginalConsumerFileRequest{Node: 2, Handle: 3, RequestSequence: 5}, WriteOK: true, SyncOK: true}, nil
}
func writableSession(t *testing.T) (*Session, OriginalConsumerArm, *writableSessionFactory, string) {
	t.Helper()
	s, arm, base := originalInstalledSession(t)
	arm.Version = 5
	arm.CaseName = "same-e-retained-fd"
	dir := t.TempDir()
	retainedTestFile(t, filepath.Join(dir, retainedFDName), []byte("original"))
	f := &writableSessionFactory{originalFactoryFake: base, open: func() (*os.File, error) { return os.Open(dir) }}
	s.factory = f
	s.entries[arm.TargetAttachment].attachment = &writableSessionAttachment{sessionAttachmentFake: sessionAttachmentFake{done: make(chan struct{})}}
	return s, arm, f, dir
}
func TestOriginalWritableSessionPositiveSameFDAndSuccessfulNegativeRefused(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("full profile")
	}
	s, arm, f, dir := writableSession(t)
	raw, _ := json.Marshal(arm)
	reply, err := s.originalConsumerControl("original-consumer-arm", raw)
	if err != nil {
		t.Fatal(err)
	}
	var positive OriginalConsumerEvidence
	if originalDecode(reply, &positive) != nil || positive.Writable == nil || !validPositiveFileTrace(*positive.Writable.Trace) || positive.FDOperation != "write-file-fsync" {
		t.Fatal("missing real file positive", string(reply))
	}
	data, err := os.ReadFile(filepath.Join(dir, retainedFDName))
	if err != nil || string(data) != "\xa5riginal" {
		t.Fatal("baseline must follow positive", data, err)
	}
	if _, err = s.originalConsumerControl("original-consumer-begin", raw); err != nil {
		t.Fatal(err)
	}
	// Actual writable operation succeeds on host backing; it MUST NOT become
	// denial even if a dishonest fixture supplies a trace/closed-mount story.
	_, _, _, _, peer := originalIdentities(t)
	f.observer.peer = peer
	q := OriginalConsumerProbe{Arm: arm, Scope: arm.Scope, Peer: peer}
	payload, _ := json.Marshal(q)
	if _, err = s.originalConsumerControl("original-consumer-probe", payload); err == nil {
		t.Fatal("successful mutation labeled denied")
	}
	data, err = os.ReadFile(filepath.Join(dir, retainedFDName))
	if err != nil || string(data) != "\x5ariginal" {
		t.Fatal("attempt did not use original FD", data, err)
	}
}
func TestOriginalWritableSessionReleaseRejectsUnjoinedAcquisition(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("full profile")
	}
	s, arm, f, dir := writableSession(t)
	entered, unblock := make(chan struct{}), make(chan struct{})
	f.open = func() (*os.File, error) { close(entered); <-unblock; return os.Open(dir) }
	raw, _ := json.Marshal(arm)
	reply := make(chan error, 1)
	go func() { _, err := s.originalConsumerControl("original-consumer-arm", raw); reply <- err }()
	<-entered
	released, err := s.originalConsumerControl("original-consumer-release", raw)
	if err == nil || released != nil || f.observer.writable == nil || f.observer.attachment == nil || f.aborts.Load() != 1 {
		t.Fatal("unjoined owner released", err, string(released))
	}
	close(unblock)
	select {
	case err = <-reply:
		if err == nil {
			t.Fatal("canceled arm accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("arm failed to return")
	}
	select {
	case <-f.owner.done:
	case <-time.After(time.Second):
		t.Fatal("owned syscall not joined")
	}
	if _, err = s.originalConsumerControl("original-consumer-release", raw); err == nil {
		t.Fatal("sticky failed join became released")
	}
}
func TestOriginalWritableReleaseBeforeBeginIsJoinedAndIdempotent(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("full profile")
	}
	s, arm, f, _ := writableSession(t)
	raw, _ := json.Marshal(arm)
	if _, err := s.originalConsumerControl("original-consumer-arm", raw); err != nil {
		t.Fatal(err)
	}
	if f.observer.cancel != nil {
		t.Fatal("dead Arm cancel retained")
	}
	for i := 0; i < 2; i++ {
		if _, err := s.originalConsumerControl("original-consumer-release", raw); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-f.owner.done:
	default:
		t.Fatal("clean release not joined")
	}
	if f.observer.writable != nil || f.observer.attachment != nil || len(f.observer.identity.Certificate().DER()) != 0 || f.aborts.Load() != 0 {
		t.Fatal("clean release retained resources or aborted mount")
	}
}

func TestOriginalWritableStopAndArmPublicationRace(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("full profile")
	}
	for i := 0; i < 20; i++ {
		s, arm, f, _ := writableSession(t)
		raw, _ := json.Marshal(arm)
		gate, armed, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() { <-gate; _, _ = s.originalConsumerControl("original-consumer-arm", raw); close(armed) }()
		go func() { <-gate; _ = f.observer.stop(); close(stopped) }()
		close(gate)
		<-armed
		<-stopped
		if f.owner != nil {
			select {
			case <-f.owner.done:
			case <-time.After(time.Second):
				t.Fatal("stop missed concurrently published writable owner")
			}
		}
		if !f.observer.stopped {
			t.Fatal("publication gate not sealed")
		}
	}
}

func TestOriginalWritableVersionAndTraceContinuity(t *testing.T) {
	arm := originalTestArm()
	arm.Version = 5
	for _, name := range []string{"same-e-retained-fd", "cross-e-retained-fd"} {
		arm.CaseName = name
		if !arm.valid() {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"same-e-existing-data", "cross-e-existing-data", "cross-mount-root-grant"} {
		arm.CaseName = name
		if arm.valid() {
			t.Fatal("version widened", name)
		}
	}
	positive := c.OriginalConsumerFileTrace{Write: &c.OriginalConsumerFileRequest{Node: 2, Handle: 3, RequestSequence: 4}, Sync: &c.OriginalConsumerFileRequest{Node: 2, Handle: 3, RequestSequence: 5}, WriteOK: true, SyncOK: true}
	negative := c.OriginalConsumerFileTrace{Write: &c.OriginalConsumerFileRequest{Node: 2, Handle: 3, RequestSequence: 6}}
	if !validNegativeFileTrace(negative, positive) {
		t.Fatal("matching negative trace")
	}
	for _, change := range []func(*c.OriginalConsumerFileTrace){func(v *c.OriginalConsumerFileTrace) { v.Write = nil }, func(v *c.OriginalConsumerFileTrace) { v.WriteOK = true }, func(v *c.OriginalConsumerFileTrace) { v.Write.Handle++ }, func(v *c.OriginalConsumerFileTrace) { v.Write.RequestSequence = 5 }} {
		copy := negative
		request := *negative.Write
		copy.Write = &request
		change(&copy)
		if validNegativeFileTrace(copy, positive) {
			t.Fatal("bad trace accepted")
		}
	}
}
