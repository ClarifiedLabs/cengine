package storagefuse

import (
	"sync"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type blockingPrepareClient struct {
	*fakeClient
	mu                              sync.Mutex
	entered, release, secondCapture chan struct{}
	gate                            *prepareProcessGate
	t                               *testing.T
}

func (b *blockingPrepareClient) Capture(fd int, unique uint64) (credential, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cred, err := b.fakeClient.Capture(fd, unique)
	if len(b.captured) == 2 {
		close(b.secondCapture)
	}
	return cred, err
}
func (b *blockingPrepareClient) Do(cred credential, auth w.AuthKind, body w.RequestBody) (c.Result, error) {
	if b.gate.owner == nil {
		b.t.Error("transport before process pin")
	}
	close(b.entered)
	<-b.release
	return b.fakeClient.Do(cred, auth, body)
}

func TestPrepareProcessConcurrentForeignMutationCapturedThenRejected(t *testing.T) {
	f, fc := fixture()
	owner := testProcess()
	f.prepare = testMountProcess(t, owner, false)
	b := &blockingPrepareClient{fakeClient: fc, entered: make(chan struct{}), release: make(chan struct{}), secondCapture: make(chan struct{}), gate: f.prepare, t: t}
	f.client = b
	first, second := make(chan fuse.Status, 1), make(chan fuse.Status, 1)
	go func() { first <- gateCall(f, 999, beginProcess()) }()
	<-b.entered
	go func() { second <- gateCall(f, 1001, w.UnlinkRequest{Parent: 101, Name: []byte("victim")}) }()
	<-b.secondCapture // second request captures even while Begin is in transport
	close(b.release)
	<-first
	if s := <-second; s != fuse.EACCES {
		t.Fatal(s)
	}
	if _, ok := fc.body.(w.PrepareRequest); !ok {
		t.Fatal("foreign mutation reached transport", fc.body)
	}
}

func TestPrepareProcessZeroIdentityAndReadOnlyCannotPin(t *testing.T) {
	for _, test := range []struct {
		tid  uint32
		ro   bool
		want fuse.Status
	}{{0, false, fuse.EACCES}, {999, true, fuse.EROFS}} {
		f, fc := fixture()
		f.prepare = testMountProcess(t, testProcess(), test.ro)
		if s := gateCall(f, test.tid, beginProcess()); s != test.want || fc.body != nil || len(fc.captured) != 1 {
			t.Fatal(test, s)
		}
	}
}

func TestPrepareProcessReadOnlyRejectsAllSevenActionsAfterBegin(t *testing.T) {
	for _, begun := range []bool{false, true} {
		for action := w.BeginCopy; action <= w.StartCleanup; action++ {
			f, fc := fixture()
			f.prepare = testMountProcess(t, testProcess(), true)
			f.prepare.begun = begun
			body := beginProcess()
			body.Action = action
			if s := gateCall(f, 999, body); s != fuse.EROFS || fc.body != nil || len(fc.captured) != 1 {
				t.Fatal(begun, action, s)
			}
		}
	}
}
