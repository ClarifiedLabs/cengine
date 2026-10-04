package storagecontrol

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

func TestReplacePrepareAndDataKeyCannotControl(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	c := f.client()
	v := a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: id(t), Name: "replace"}
	call(t, c, Request{CreateVolume: &v})
	p := id(t)
	binding, k := f.binding(v.Volume, p)
	call(t, c, Request{ReservePrepare: &a.ReserveRequest{Operation: id(t), Prepare: p, Attachments: []a.Binding{binding}}})
	call(t, c, Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: binding}})
	cfg := f.config()
	cfg.CurrentController.Key = fp(t, k)
	if _, e := f.connect(cfg); e == nil {
		t.Fatal("data key became controller")
	}
	receipt := call(t, c, Request{Retire: &a.RetireRequest{Operation: id(t), Store: f.store, Volume: v.Volume, Attachment: binding.Attachment, Launch: binding.Launch}}).Receipt
	next := id(t)
	newBinding, _ := f.binding(v.Volume, next)
	replace := a.ReplaceRequest{Operation: id(t), Prepare: p, Receipts: []a.Receipt{*receipt}, Successor: a.ReserveRequest{Operation: id(t), Prepare: next, Attachments: []a.Binding{newBinding}}}
	call(t, c, Request{ReplacePrepare: &replace})
	call(t, c, Request{ReplacePrepare: &replace})
	snap := call(t, c, Request{Query: &Empty{}}).Snapshot
	if snap.Prepares[p].Phase != a.Replaced || snap.Prepares[next].Phase != a.Pending {
		t.Fatal("replacement not atomic")
	}
}
func TestLostCreateReplyExplicitRetryAndInvalidSemanticFields(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	c := f.client()
	q := a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: id(t), Name: "lost"}
	// Commit is observed independently, while the originating client deliberately
	// never reads its response. Closing that socket must not roll anything back.
	must(t, writeFrame(c.conn, Request{ID: 1, CreateVolume: &q}, f.l.RequestBytes, &budget{}))
	observer := f.client()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if call(t, observer, Request{Query: &Empty{}}).Snapshot.Volumes[q.Volume].ID == q.Volume {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("create not committed")
		}
		time.Sleep(time.Millisecond)
	}
	c.Close()
	r := call(t, observer, Request{CreateVolume: &q})
	if r.VolumeReceipt.Phase != a.VolumeReady {
		t.Fatal("lost-reply retry")
	}
	q.Name = "changed"
	_, e := observer.Call(context.Background(), Request{CreateVolume: &q})
	remote(t, e, Conflict)
	q.Operation = id(t)
	q.Volume = id(t)
	q.Name = "../escape"
	_, e = observer.Call(context.Background(), Request{CreateVolume: &q})
	remote(t, e, Invalid)
}

// A real TLS peer may still send malformed protocol messages: neither its pin nor
// its certificate is permission to accept a mismatched/fabricated result.
func TestClientRejectsWrongCorrelationAndReceipt(t *testing.T) {
	for _, kind := range []string{"id", "union", "receipt", "epoch"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureFor(t, Limits{}, nil)
			left, right := tcpPair(t)
			done := make(chan struct{})
			defer func() { right.Close(); <-done }()
			q := Request{Retire: &a.RetireRequest{Operation: id(t), Store: f.store, Volume: id(t), Attachment: id(t), Launch: id(t)}}
			if kind != "receipt" {
				q = Request{Query: &Empty{}}
			}
			go func() {
				defer close(done)
				defer left.Close()
				conn := tls.Server(left, f.server.config.TLS)
				if conn.Handshake() != nil {
					return
				}
				var hello Hello
				if readFrame(conn, &hello, 4096, &budget{}) != nil {
					return
				}
				if writeFrame(conn, HelloReply{Version: LifecycleWorkloadVersion, Store: f.store, ServiceEpoch: hello.ServiceEpoch, LifecycleIdentity: hello.LifecycleIdentity}, 4096, &budget{}) != nil {
					return
				}
				var request Request
				if readFrame(conn, &request, f.l.RequestBytes, &budget{}) != nil {
					return
				}
				r := Response{ID: request.ID, Error: Unknown}
				switch kind {
				case "id":
					r.ID++
				case "union":
					r.OK = &Empty{}
				case "receipt":
					r.Error = ""
					r.Receipt = &a.Receipt{Schema: a.SchemaVersion, Store: f.store, Volume: id(t), Attachment: request.Retire.Attachment, Launch: request.Retire.Launch, Revision: 1}
				case "epoch":
					r.Error = ""
					r.Snapshot = &a.Snapshot{Schema: a.SchemaVersion, Revision: 1, Store: a.Store{ID: f.store}, Epoch: id(t)}
				}
				_ = writeFrame(conn, r, f.l.ResponseBytes, &budget{})
			}()
			c, e := NewPKILifecycleWorkloadClient(context.Background(), right, f.config())
			must(t, e)
			_, e = c.Call(context.Background(), q)
			if !errors.Is(e, ErrProtocol) {
				t.Fatalf("accepted %s response: %v", kind, e)
			}
			if _, e = c.Call(context.Background(), q); !errors.Is(e, ErrClosed) {
				t.Fatal("protocol failure left client reusable")
			}
		})
	}
}

func TestPartialFrameHandshakeAndWriteDeadlines(t *testing.T) {
	l := DefaultLimits()
	l.HandshakeTimeout = 40 * time.Millisecond
	l.WriteTimeout = 40 * time.Millisecond
	l.ResponseBytes = 1024
	f := fixtureFor(t, l, nil)
	left, right := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(context.Background(), left) }()
	defer right.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("empty handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake deadline failed")
	}
	// TLS forwarding must preserve write deadlines; a peer not reading a reply
	// cannot retain a worker forever. net.Pipe reliably blocks the TLS write.
	left, right = net.Pipe()
	defer right.Close()
	go func() { done <- f.server.Serve(context.Background(), left) }()
	conn := f.rawController(right)
	must(t, conn.Handshake())
	must(t, writeFrame(conn, f.hello(), 4096, &budget{}))
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("blocked hello reply succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline failed")
	}
}

// Authentication and retry still use the actual authority. Only the synchronous
// file-IO boundary is blocked to prove that socket teardown cannot free a worker.
func TestBlockedMutationRetainsWorkerAfterTimeout(t *testing.T) {
	l := DefaultLimits()
	l.OperationTimeout = 60 * time.Millisecond
	l.ResponseBytes = 1 << 20
	f := fixtureFor(t, l, nil)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	realCreate := f.server.createVolume
	f.server.createVolume = func(p *a.ControllerPrincipal, q a.CreateVolumeRequest) (a.VolumeReceipt, error) {
		close(entered)
		<-release
		defer close(finished)
		return realCreate(p, q)
	}
	c := f.client()
	q := a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: id(t), Name: "blocked-worker"}
	done := make(chan error, 1)
	go func() { _, err := c.Call(context.Background(), Request{CreateVolume: &q}); done <- err }()
	<-entered
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked IO reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("transport did not time out")
	}
	observer := f.client()
	if len(f.server.slots) != 2 {
		t.Fatal("timed-out worker released capacity before core returned")
	}
	if _, err := f.connect(f.config()); err == nil {
		t.Fatal("replacement worker exceeded capacity")
	}
	close(release)
	<-finished
	deadline := time.Now().Add(time.Second)
	for len(f.server.slots) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("finished worker did not release")
		}
		time.Sleep(time.Millisecond)
	}
	// Avoid invoking the blocking seam twice: use the actual query to reconcile
	// accepted work, then the separately covered core retry contract.
	snapshot := call(t, observer, Request{Query: &Empty{}}).Snapshot
	if snapshot.Volumes[q.Volume].ID != q.Volume {
		t.Fatal("socket timeout rolled accepted mutation back")
	}
}

func TestQueryLeaseBoundsSnapshotAdmission(t *testing.T) {
	f := fixtureFor(t, Limits{}, nil)
	c := f.client()
	f.server.queries <- struct{}{}
	response, err := c.Call(context.Background(), Request{Query: &Empty{}})
	remote(t, err, Limit)
	if response.Snapshot != nil {
		t.Fatal("query bypassed snapshot lease")
	}
	<-f.server.queries
	call(t, c, Request{Query: &Empty{}})
}
