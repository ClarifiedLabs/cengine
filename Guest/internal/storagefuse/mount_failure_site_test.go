package storagefuse

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

func expectFailureDetails(t *testing.T, err error, site, op, category string) {
	t.Helper()
	stage, gotSite, gotOp, gotCategory := MountFailureDetails(err)
	if stage != "active" || gotSite != site || gotOp != op || gotCategory != category {
		t.Fatalf("diagnostic = %q/%q/%q/%q, want active/%s/%s/%s", stage, gotSite, gotOp, gotCategory, site, op, category)
	}
}

func TestMountFailureSitesRealCallbacks(t *testing.T) {
	for _, tc := range []struct {
		name, site, op, category string
		run                      func(*testing.T, *rawFS, *fakeClient)
	}{
		{"admission", "admission", "GETATTR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			f.slots <- struct{}{}
			f.slots <- struct{}{}
			if f.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Opcode: 3}}, &fuse.AttrOut{}) != fuse.EIO {
				t.Fatal("status changed")
			}
		}},
		{"capture", "capture", "OPENDIR", "EPERM", func(t *testing.T, f *rawFS, fc *fakeClient) {
			fc.captureErr = errors.Join(c.ErrCredentials, unix.EPERM)
			f.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Opcode: 27}}, &fuse.OpenOut{})
		}},
		{"none", "provenance-none-caller", "OPENDIR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			fc.state = none
			f.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Opcode: 27}}, &fuse.OpenOut{})
		}},
		{"present-lifecycle", "provenance-present-lifecycle", "RELEASEDIR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			f.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{Opcode: 29}})
		}},
		{"kind", "provenance-kind", "GETATTR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			fc.state = 255
			f.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Opcode: 3}}, &fuse.AttrOut{})
		}},
		{"grant", "client-grant", "OPENDIR", "grant", func(t *testing.T, f *rawFS, fc *fakeClient) {
			fc.errorDo = c.ErrGrant
			f.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Opcode: 27, NodeId: 1}}, &fuse.OpenOut{})
		}},
		{"reply-kind", "reply-attr-kind", "GETATTR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			fc.result = &c.Result{Reply: w.Reply{Body: w.OpenReply{}}}
			f.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Opcode: 3, NodeId: 1}}, &fuse.AttrOut{})
		}},
		{"reply-handle", "reply-handle", "OPENDIR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			fc.result = &c.Result{Reply: w.Reply{Body: w.OpenDirReply{}}}
			f.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Opcode: 27, NodeId: 1}}, &fuse.OpenOut{})
		}},
		{"directory-delivery", "directory-delivery", "OPENDIR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			fc.result = &c.Result{Handle: 8, Reply: w.Reply{Body: w.OpenDirReply{}}}
			life := &lifecycleFS{rawFS: f, life: &mountLifecycle{}}
			life.directories.limit = 16
			if life.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Opcode: 27, NodeId: 1, Unique: 9}}, &fuse.OpenOut{}) != fuse.OK {
				t.Fatal("open failed")
			}
			life.observeReply(fuse.ReplyDelivery{Opcode: 27, Unique: 9, Expected: 32, Bytes: 16})
		}},
		{"directory-admission", "directory-admission", "OPENDIR", "capacity", func(t *testing.T, f *rawFS, fc *fakeClient) {
			life := &lifecycleFS{rawFS: f, life: &mountLifecycle{}}
			life.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Opcode: 27, Unique: 9}}, &fuse.OpenOut{})
		}},
		{"interrupt", "interrupted", "INTERRUPT", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			f.observeReply(fuse.ReplyDelivery{Opcode: 36})
		}},
		{"short-write", "reply-delivery", "GETATTR", "short-write", func(t *testing.T, f *rawFS, fc *fakeClient) {
			f.observeReply(fuse.ReplyDelivery{Opcode: 3, Err: io.ErrShortWrite})
		}},
		{"eintr", "reply-delivery", "GETATTR", "EINTR", func(t *testing.T, f *rawFS, fc *fakeClient) {
			f.observeReply(fuse.ReplyDelivery{Opcode: 3, Err: unix.EINTR})
		}},
		{"destroy-short-write", "destroy", "DESTROY", "short-write", func(t *testing.T, f *rawFS, fc *fakeClient) {
			life := &lifecycleFS{rawFS: f, life: &mountLifecycle{}}
			life.observeReply(fuse.ReplyDelivery{Opcode: 38, Err: io.ErrShortWrite})
		}},
		{"directory-interrupted", "interrupted", "OPENDIR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			life := &lifecycleFS{rawFS: f, life: &mountLifecycle{}}
			life.observeReply(fuse.ReplyDelivery{Opcode: 27, Interrupted: true})
		}},
		{"directory-status-eintr", "interrupted", "OPENDIR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			life := &lifecycleFS{rawFS: f, life: &mountLifecycle{}}
			life.observeReply(fuse.ReplyDelivery{Opcode: 27, Status: fuse.EINTR})
		}},
		{"directory-suppressed", "suppressed", "OPENDIR", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			life := &lifecycleFS{rawFS: f, life: &mountLifecycle{}}
			life.observeReply(fuse.ReplyDelivery{Opcode: 27, Suppressed: true})
		}},
		{"serve-exit", "serve-exit", "other", "other", func(t *testing.T, f *rawFS, fc *fakeClient) { f.OnUnmount() }},
		{"panic", "panic", "READ", "translation", func(t *testing.T, f *rawFS, fc *fakeClient) {
			fc.result = &c.Result{Reply: w.Reply{Body: w.GetAttrReply{}}} // real Read type assertion panic
			func() {
				defer func() {
					if value := recover(); value != nil {
						if f.panicFailure(value) != fuse.EIO {
							t.Fatal("panic status changed")
						}
					}
				}()
				f.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Opcode: 15, NodeId: 1}, Fh: 8, Size: 1}, nil)
			}()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, fc := fixture()
			tracker := &mountFailureTracker{}
			tracker.enter(stageActive)
			var retired error
			calls := 0
			f.retire = func(err error) { retired = tracker.wrap(err); calls++ }
			tc.run(t, f, fc)
			if retired == nil || fc.aborted != 1 || calls != 1 {
				t.Fatal("callback did not fail closed exactly once")
			}
			expectFailureDetails(t, retired, tc.site, tc.op, tc.category)
			f.OnUnmount()
			if calls != 1 || fc.aborted != 1 {
				t.Fatal("cleanup repeated retirement")
			}
			expectFailureDetails(t, retired, tc.site, tc.op, tc.category)
		})
	}
}

func TestMountFailureDetailsClosedVocabularyAndNoRawFormatting(t *testing.T) {
	for site := siteOther; site <= siteDataTerminal; site++ {
		for _, opcode := range []uint32{0, 3, 27, 29, 36, 52, 0xffffffff} {
			cause := &os.PathError{Path: "/SECRET\nspoof", Op: "SECRET", Err: unprintableMountError{}}
			err := &mountFailure{stage: stageActive, cause: &callbackFailure{site: site, opcode: opcode, cause: cause}}
			expectFailureDetails(t, err, site.name(), failureOperation(opcode), "other")
			var original *os.PathError
			if !errors.As(err, &original) || original != cause {
				t.Fatal("lost original error identity")
			}
		}
	}
	err := &mountFailure{stage: stageActive, cause: &callbackFailure{site: 255, opcode: 0xffffffff, cause: unprintableMountError{}}}
	expectFailureDetails(t, err, "other", "other", "other")
	if (&callbackFailure{}).Error() != "storagefuse: callback failure" {
		t.Fatal("nonconstant wrapper error")
	}
}

func TestMountFailureDetailsConcurrentCleanupKeepsFirstSite(t *testing.T) {
	tracker := &mountFailureTracker{}
	tracker.enter(stageActive)
	first := &callbackFailure{site: siteClientGrant, opcode: 27, cause: c.ErrGrant}
	tracker.wrap(first)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := tracker.wrap(&callbackFailure{site: siteServeExit, cause: unix.EIO})
			expectFailureDetails(t, err, "client-grant", "OPENDIR", "grant")
			if !errors.Is(err, c.ErrGrant) || !errors.Is(err, unix.EIO) {
				t.Error("lost cause")
			}
		}()
	}
	workers.Wait()
	// A construction failure with no callback site must not borrow a cleanup site.
	tracker = &mountFailureTracker{}
	tracker.enter(stageActive)
	tracker.wrap(unix.EPERM)
	expectFailureDetails(t, tracker.wrap(first), "other", "other", "EPERM")
}

type delayedDiagnosticClient struct {
	*fakeClient
	entered, release chan struct{}
}

func (fc *delayedDiagnosticClient) Do(credential, w.AuthKind, w.RequestBody) (c.Result, error) {
	close(fc.entered)
	<-fc.release
	return c.Result{}, c.ErrGrant
}

func TestMountFailureTerminalWatcherWinsBeforeCallbackReturns(t *testing.T) {
	f, fc := fixture()
	delayed := &delayedDiagnosticClient{fakeClient: fc, entered: make(chan struct{}), release: make(chan struct{})}
	f.client = delayed
	tracker := &mountFailureTracker{}
	tracker.enter(stageActive)
	var retired error
	f.retire = func(err error) { retired = tracker.wrap(err) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Opcode: 15, NodeId: 1}, Fh: 8, Size: 1}, nil)
	}()
	<-delayed.entered
	f.terminalFailure(c.ErrClosed) // exact native watcher stop path; no callback header exists here
	close(delayed.release)
	<-done
	expectFailureDetails(t, retired, "data-terminal", "other", "closed")
	if !errors.Is(retired, c.ErrClosed) || fc.aborted != 1 {
		t.Fatal("first terminal reason changed")
	}
}

func TestMountFailureOperationAllowlist(t *testing.T) {
	for opcode, want := range map[uint32]string{0: "other", 3: "GETATTR", 15: "READ", 27: "OPENDIR", 29: "RELEASEDIR", 36: "INTERRUPT", 52: "STATX", 0xffffffff: "other"} {
		if got := failureOperation(opcode); got != want {
			t.Fatalf("operation = %q, want %q", got, want)
		}
	}
}

func TestMountFailurePanicPayloadNeverFormatted(t *testing.T) {
	f, _ := fixture()
	tracker := &mountFailureTracker{}
	tracker.enter(stageActive)
	var retired error
	f.retire = func(err error) { retired = tracker.wrap(err) }
	func() {
		defer func() {
			if value := recover(); value != nil {
				f.panicFailure(value)
			}
		}()
		defer markCallbackPanic(27)
		panic(unprintableMountError{})
	}()
	expectFailureDetails(t, retired, "panic", "OPENDIR", "translation")
}
