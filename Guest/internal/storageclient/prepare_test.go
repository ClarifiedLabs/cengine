package storageclient

import (
	"crypto/tls"
	"errors"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func TestPrepareUsesExistingDATAAndCallerPolicy(t *testing.T) {
	seen := make(chan w.Request, 1)
	c := fixture(t, func(cfg *Config) {
		cfg.Authority.Binding.Role = a.PrepareRole
		cfg.Authority.Binding.Prepare = testID('6')
	}, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply {
			switch req.Body.(type) {
			case w.OpenDirRequest:
				return w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 100}}}
			case w.PrepareRequest:
				seen <- req
				return w.Reply{Body: w.PrepareReply{}}
			default:
				return w.Reply{Errno: 5}
			}
		})
	})
	opened, err := c.Do(caller(c), 0, w.OpenDirRequest{Node: 99})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.Handle(opened.Handle)
	if err != nil {
		t.Fatal(err)
	}
	body := w.PrepareRequest{Node: 99, Handle: grant.Handle, Action: w.FinishCopy, Intent: testID('7')}
	if _, err = c.Do(none(c), w.OpenGrantAuth, body); err == nil {
		t.Fatal("NONE accepted")
	}
	if _, err = c.Do(caller(&Client{}), 0, body); !errors.Is(err, ErrCredentials) {
		t.Fatal("foreign snapshot", err)
	}
	if _, err = c.Do(caller(c), 0, body); err != nil {
		t.Fatal(err)
	}
	req := <-seen
	if req.Auth.Kind != w.CallerAuth || req.Auth.Caller.FSUID != 1000 || req.Body.(w.PrepareRequest).Handle != 100 {
		t.Fatal(req)
	}
}
func TestPrepareRootGrantAndScope(t *testing.T) {
	root := &nodeState{local: 1, entry: testEntry(99, true), pinned: true}
	other := &nodeState{local: 2, entry: testEntry(42, true), refs: 1}
	rootHandle := &handleState{local: 1, wire: 100, node: root, directory: true}
	otherHandle := &handleState{local: 2, wire: 200, node: other, directory: true}
	c := &Client{nodes: map[LocalNode]*nodeState{1: root, 2: other}, wireNodes: map[w.NodeID]*nodeState{99: root, 42: other}, wireHandles: map[w.HandleID]*handleState{100: rootHandle, 200: otherHandle}}
	req := w.Request{Sequence: 1, Body: w.PrepareRequest{Node: 99, Handle: 100, Action: w.BeginCopy}}
	if err := c.checkRequest(req); err != nil {
		t.Fatal(err)
	}
	for _, body := range []w.PrepareRequest{{Node: 42, Handle: 200, Action: w.BeginCopy}, {Node: 99, Handle: 200, Action: w.BeginCopy}, {Node: 99, Handle: 300, Action: w.BeginCopy}} {
		req.Body = body
		if !errors.Is(c.checkRequest(req), ErrGrant) {
			t.Fatal(body)
		}
	}
	req.Body = w.PrepareRequest{Node: 99, Handle: 100, Action: w.BeginCopy}
	rootHandle.directory = false
	if !errors.Is(c.checkRequest(req), ErrGrant) {
		t.Fatal("file grant")
	}
	rootHandle.directory = true
	rootHandle.releasing = true
	if !errors.Is(c.checkRequest(req), ErrGrant) {
		t.Fatal("released grant")
	}
	c.authority = a.DataHello{Epoch: testID('5'), Binding: a.Binding{Store: testID('1'), Volume: testID('2')}}
	if c.checkPrepareReply(w.PrepareReply{Root: a.CopyRootV1{Store: testID('3'), Volume: testID('2')}}) == nil {
		t.Fatal("foreign root")
	}
	intent := a.CopyIntent{ID: testID('6'), Owner: c.authority.Binding, Epoch: c.authority.Epoch, Root: a.CopyRootV1{Store: testID('1'), Volume: testID('2')}}
	if err := c.checkPrepareReply(w.PrepareReply{Intent: intent}); err != nil {
		t.Fatal(err)
	}
	intent.Epoch = testID('4')
	if c.checkPrepareReply(w.PrepareReply{Intent: intent}) == nil {
		t.Fatal("stale epoch")
	}
}
