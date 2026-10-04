package storageclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

type readDirReplayStep struct {
	body   w.RequestBody
	auth   w.Auth
	reply  w.Reply
	fault  string
	seen   chan<- struct{}
	resume <-chan struct{}
}

type readDirReplayHarness struct {
	t      *testing.T
	c      *Client
	intent a.CopyIntent
	steps  chan readDirReplayStep
}

func newReadDirReplayHarness(t *testing.T, requests int, scope string) *readDirReplayHarness {
	t.Helper()
	h := &readDirReplayHarness{t: t, steps: make(chan readDirReplayStep, 1)}
	h.c = fixture(t, func(cfg *Config) {
		cfg.Authority.Binding.Role, cfg.Authority.Binding.Prepare = a.PrepareRole, testID('6')
		cfg.Limits.Requests = requests
		if scope == "runtime" {
			cfg.Authority.Binding.Role, cfg.Authority.Binding.Prepare = a.RuntimeRole, ""
		}
		if scope == "read-only" {
			cfg.Authority.Binding.Mode = a.ReadOnly
		}
		object := a.Ext4ObjectV1{Inode: 22, Generation: 7, FileType: 0040000, HandleType: 1, HandleSize: 8}
		binary.LittleEndian.PutUint32(object.Handle[:4], 22)
		binary.LittleEndian.PutUint32(object.Handle[4:], 7)
		root := a.CopyRootV1{Store: cfg.Authority.Binding.Store, Volume: cfg.Authority.Binding.Volume, BackingUUID: [16]byte{1}, Root: object}
		object.Inode = 23
		binary.LittleEndian.PutUint32(object.Handle[:4], 23)
		// Capture immutable authority before New/server startup, not via h.c in the goroutine.
		h.intent = a.CopyIntent{ID: testID('7'), Owner: cfg.Authority.Binding, Epoch: cfg.Authority.Epoch, Root: root, Transaction: object, Phase: a.CopyBound, InitialCaptured: true, Initial: a.CopyCleanupV1{UID: 1000, GID: 1001, Mode: 0755, ATimeSeconds: 3, MTimeSeconds: 4, ATimeNanos: 5, MTimeNanos: 6}}
	}, func(conn *tls.Conn) {
		for sequence := uint64(1); ; sequence++ {
			var req w.Request
			if w.ReadFrame(conn, &req) != nil {
				return
			}
			var step readDirReplayStep
			select {
			case step = <-h.steps:
			default:
				t.Error("unscripted request/automatic retry", req.Body)
				_ = conn.NetConn().Close()
				return
			}
			if req.Sequence != sequence || !reflect.DeepEqual(req.Body, step.body) || !reflect.DeepEqual(req.Auth, step.auth) {
				t.Errorf("DATA request mismatch: got %#v, want sequence=%d body=%#v auth=%#v", req, sequence, step.body, step.auth)
				_ = conn.NetConn().Close()
				return
			}
			reply := step.reply
			reply.Sequence, reply.Op = req.Sequence, step.body.Operation()
			switch step.fault {
			case "missing":
				_ = conn.NetConn().Close()
				return
			case "sequence":
				reply.Sequence++
			case "operation":
				reply.Op, reply.Body, reply.Errno = w.OpFlush, w.FlushReply{}, 0
			case "intent", "owner", "epoch":
				v := reply.Body.(w.PrepareReply)
				if step.fault == "intent" {
					v.Intent.ID = testID('8')
				}
				if step.fault == "owner" {
					v.Intent.Owner.Launch = testID('8')
				}
				if step.fault == "epoch" {
					v.Intent.Epoch = testID('8')
				}
				reply.Body = v
			case "unknown-pending":
				raw, err := w.Marshal(&reply)
				if err != nil {
					t.Error(err)
					return
				}
				raw = bytes.Replace(raw, []byte(`"pending":2`), []byte(`"pending":255`), 1)
				frame := make([]byte, 4+len(raw))
				binary.BigEndian.PutUint32(frame, uint32(len(raw)))
				copy(frame[4:], raw)
				if _, err = conn.Write(frame); err != nil {
					t.Error(err)
				}
				continue
			}
			if step.seen != nil {
				close(step.seen)
			}
			if step.resume != nil {
				<-step.resume
			}
			if err := w.WriteFrame(conn, &reply); err != nil {
				t.Error(err)
				return
			}
		}
	})
	h.call(w.OpenDirRequest{Node: 99}, w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 100}}})
	return h
}

func (h *readDirReplayHarness) exchange(s Snapshot, kind w.AuthKind, body w.RequestBody, reply w.Reply, fault string) {
	h.t.Helper()
	auth := w.Auth{Kind: kind}
	if s.present {
		value := s.caller
		auth = w.Auth{Kind: w.CallerAuth, Caller: &value}
	}
	h.steps <- readDirReplayStep{body: body, auth: auth, reply: reply, fault: fault}
	got, err := h.c.Do(s, kind, body)
	if fault != "" {
		if !errors.Is(err, ErrClosed) {
			h.t.Fatal("invalid reply/cleanup did not close client", fault, err)
		}
		return
	}
	if err != nil || got.Reply.Errno != reply.Errno || !reflect.DeepEqual(got.Reply.Body, reply.Body) {
		h.t.Fatalf("%v: reply/errno changed: got %#v, err=%v, want %#v", body.Operation(), got.Reply, err, reply)
	}
}

func (h *readDirReplayHarness) call(body w.RequestBody, reply w.Reply) {
	h.t.Helper()
	h.exchange(caller(h.c), 0, body, reply, "")
}

func (h *readDirReplayHarness) control(action w.PrepareAction, handle w.HandleID, reply w.PrepareReply) {
	h.t.Helper()
	body := w.PrepareRequest{Node: 99, Handle: handle, Action: action, Intent: reply.Intent.ID}
	if action == w.BeginCopy {
		body.Intent = ""
	}
	h.call(body, w.Reply{Body: reply})
}

func (h *readDirReplayHarness) evidence(pending w.PrepareAction) w.PrepareReply {
	return w.PrepareReply{Pending: pending, Intent: h.intent, Root: h.intent.Root}
}

func (h *readDirReplayHarness) bind() {
	v := h.evidence(0)
	v.Identity = v.Intent.Transaction
	h.control(w.BindCopyTransaction, 100, v)
}

func (h *readDirReplayHarness) release(node w.NodeID, handle w.HandleID) {
	h.t.Helper()
	h.exchange(none(h.c), w.LifecycleAuth, w.ReleaseDirRequest{Node: node, Handle: handle}, w.Reply{Body: w.ReleaseDirReply{}}, "")
}

func (h *readDirReplayHarness) close(clean, capacity bool) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := h.c.CloseGracefully(ctx)
	if clean && err != nil {
		h.t.Fatal("exact replay did not complete", err)
	}
	if !clean && !errors.Is(err, ErrClosed) {
		h.t.Fatal("incomplete replay was forgiven", err)
	}
	if capacity && (!errors.Is(err, ErrCapacity) || !errors.Is(err, ErrIncomplete)) {
		h.t.Fatal("overflow lost sticky capacity evidence", err)
	}
}

// A queued release seals future admissions, not an earlier accepted read reply.
// Synchronize on the actual receive and queue transitions; no sleeps or polling.
func TestPrepareReadDirReplayQueuedRelease(t *testing.T) {
	h := newReadDirReplayHarness(t, 2, "")
	query := w.ReadDirRequest{Node: 99, Handle: 100, Cookie: 7, MaxBytes: 4096}
	h.control(w.BeginCopy, 100, h.evidence(w.BindCopyTransaction))
	h.call(query, w.Reply{Errno: 16})
	h.bind()
	h.control(w.BeginCopy, 100, h.evidence(0))
	seen := make(chan struct{})
	resume, release := gate()
	t.Cleanup(release)
	snapshot := caller(h.c)
	h.steps <- readDirReplayStep{body: query, auth: w.Auth{Kind: w.CallerAuth, Caller: &snapshot.caller}, reply: w.Reply{Body: w.ReadDirReply{Entries: []w.DirEntry{}}}, seen: seen, resume: resume}
	readDone := make(chan error, 1)
	go func() { _, err := h.c.Do(snapshot, 0, query); readDone <- err }()
	select {
	case <-seen:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not reach DATA peer")
	}
	body := w.ReleaseDirRequest{Node: 99, Handle: 100}
	h.steps <- readDirReplayStep{body: body, auth: w.Auth{Kind: w.LifecycleAuth}, reply: w.Reply{Body: w.ReleaseDirReply{}}}
	releaseDone := make(chan error, 1)
	go func() { _, err := h.c.Do(none(h.c), w.LifecycleAuth, body); releaseDone <- err }()
	awaitClient(t, h.c, func() bool { return h.c.wireHandles[100].releasing && len(h.c.queue) == 1 })
	closed := gracefulStart(t, h.c, context.Background())
	stillClosing(t, closed)
	release()
	for _, done := range []<-chan error{readDone, releaseDone, closed} {
		if err := awaitError(t, done); err != nil {
			t.Fatal("queued release invalidated accepted retry", err)
		}
	}
}

func TestPrepareReadDirReplayGracefulDATA(t *testing.T) {
	cases := []string{"recovered", "repeat-busy", "repeat-pending", "repeat-pending-unresolved", "pending-after-bind", "pending-after-bind-rebound", "no-retry", "no-bind", "no-clear", "early-success", "prior-eio", "live-handle", "cleanup-eio", "before-begin", "no-pending", "runtime", "read-only", "nonroot", "other-handle", "pending-begin", "pending-seal", "pending-cleanup", "begun", "sealed", "initial-not-captured"}
	for _, errno := range []uint32{1, 2, 5, 13, 20, 34, 40, 61, 116} {
		cases = append(cases, fmt.Sprintf("errno-%d", errno))
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			h := newReadDirReplayHarness(t, 2, name)
			query := w.ReadDirRequest{Node: 99, Handle: 100, Cookie: 7, MaxBytes: 4096}
			ok := w.Reply{Body: w.ReadDirReply{Entries: []w.DirEntry{}}}
			if name == "nonroot" {
				h.call(w.LookupRequest{Parent: 99, Name: []byte("sub")}, w.Reply{Body: w.LookupReply{Entry: testEntry(42, true)}})
				h.call(w.OpenDirRequest{Node: 42}, w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 101}}})
				query.Node, query.Handle = 42, 101
			}
			if name == "other-handle" {
				h.call(w.OpenDirRequest{Node: 99}, w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 101}}})
				query.Handle = 101
			}
			if name == "prior-eio" {
				h.call(w.GetAttrRequest{Node: 99}, w.Reply{Errno: 5})
			}
			if name == "before-begin" {
				h.call(query, w.Reply{Errno: 16})
			}
			pending := h.evidence(w.BindCopyTransaction)
			switch name {
			case "no-pending":
				pending.Pending = 0
			case "pending-begin":
				pending.Pending = w.BeginCopy
			case "pending-seal":
				pending.Pending = w.SealManifest
			case "pending-cleanup":
				pending.Pending = w.StartCleanup
			case "begun":
				pending.Intent.Phase, pending.Intent.Transaction = a.CopyBegun, a.Ext4ObjectV1{}
			case "sealed":
				pending.Intent.Phase, pending.Intent.ManifestSize, pending.Intent.ManifestDigest = a.CopySealed, 1, [32]byte{1}
			case "initial-not-captured":
				pending.Intent.InitialCaptured, pending.Intent.Initial = false, a.CopyCleanupV1{}
			}
			prepare := name != "runtime" && name != "read-only"
			if prepare {
				h.control(w.BeginCopy, 100, pending)
			}
			errno := uint32(16)
			_, _ = fmt.Sscanf(name, "errno-%d", &errno)
			h.call(query, w.Reply{Errno: errno}) // EBUSY must be delivered unchanged, never auto-retried.
			if name == "repeat-busy" {
				for i := 0; i < 5; i++ {
					h.call(query, w.Reply{Errno: 16})
				}
			}
			if name == "repeat-pending" || name == "repeat-pending-unresolved" {
				h.control(w.BeginCopy, 100, pending)
			}
			if name == "early-success" {
				h.call(query, ok)
			}
			if prepare && name != "no-bind" {
				h.bind()
				if name == "pending-after-bind" || name == "pending-after-bind-rebound" {
					h.control(w.BeginCopy, 100, pending)
					if name == "pending-after-bind-rebound" {
						h.bind()
					}
				}
			}
			if prepare && name != "no-clear" {
				h.control(w.BeginCopy, 100, h.evidence(0))
			}
			if name != "no-retry" && name != "early-success" && name != "repeat-pending-unresolved" {
				h.call(query, ok)
			}
			if query.Handle == 101 {
				h.release(query.Node, 101)
			}
			if name == "cleanup-eio" {
				h.exchange(none(h.c), w.LifecycleAuth, w.ReleaseDirRequest{Node: 99, Handle: 100}, w.Reply{Errno: 5}, "cleanup")
			} else if name != "live-handle" {
				h.release(99, 100)
			}
			clean := name == "recovered" || name == "repeat-busy" || name == "repeat-pending" || name == "pending-after-bind-rebound"
			h.close(clean, false)
		})
	}
}

func TestPrepareReadDirReplayExactQueryAndAuth(t *testing.T) {
	for _, field := range []string{"node", "handle", "cookie", "max-bytes", "fsuid", "fsgid", "groups", "group-order", "caps", "auth-kind"} {
		for _, exactRetry := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/exact-retry-%t", field, exactRetry), func(t *testing.T) {
				h := newReadDirReplayHarness(t, 2, "")
				node := w.NodeID(99)
				if field == "node" {
					node = 42
					h.call(w.LookupRequest{Parent: 99, Name: []byte("sub")}, w.Reply{Body: w.LookupReply{Entry: testEntry(node, true)}})
				}
				h.call(w.OpenDirRequest{Node: node}, w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 101}}})
				query := w.ReadDirRequest{Node: 99, Handle: 100, Cookie: 7, MaxBytes: 4096}
				h.control(w.BeginCopy, 100, h.evidence(w.BindCopyTransaction))
				h.call(query, w.Reply{Errno: 16})
				h.bind()
				h.control(w.BeginCopy, 100, h.evidence(0))
				changed, snapshot, kind := query, caller(h.c), w.AuthKind(0)
				switch field {
				case "node":
					changed.Node, changed.Handle = node, 101
				case "handle":
					changed.Handle = 101
				case "cookie":
					changed.Cookie++
				case "max-bytes":
					changed.MaxBytes *= 2
				case "fsuid":
					snapshot.caller.FSUID++
				case "fsgid":
					snapshot.caller.FSGID++
				case "groups":
					snapshot.caller.Groups = []uint32{1000, 1002}
				case "group-order":
					snapshot.caller.Groups = []uint32{1001, 1000}
				case "caps":
					snapshot.caller.EffectiveCaps = 1
				case "auth-kind":
					snapshot, kind = none(h.c), w.OpenGrantAuth
				}
				ok := w.Reply{Body: w.ReadDirReply{Entries: []w.DirEntry{}}}
				h.exchange(snapshot, kind, changed, ok, "")
				if exactRetry {
					h.call(query, ok)
				}
				h.release(node, 101)
				h.release(99, 100)
				h.close(exactRetry, false)
			})
		}
	}
}

func TestPrepareReadDirReplayExactEvidence(t *testing.T) {
	for _, stage := range []string{"bind", "clear"} {
		for _, field := range []string{"fresh-intent", "root", "transaction", "initial-uid", "initial-gid", "initial-mode", "initial-atime", "initial-mtime", "initial-atime-nanos", "initial-mtime-nanos", "initial-captured", "phase-manifest", "cleanup", "handle", "missing-root", "identity", "missing-identity"} {
			if stage == "clear" && (field == "missing-root" || field == "identity" || field == "missing-identity") {
				continue
			}
			t.Run(stage+"/"+field, func(t *testing.T) {
				h := newReadDirReplayHarness(t, 2, "")
				h.call(w.OpenDirRequest{Node: 99}, w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 101}}})
				query := w.ReadDirRequest{Node: 99, Handle: 100, Cookie: 7, MaxBytes: 4096}
				h.control(w.BeginCopy, 100, h.evidence(w.BindCopyTransaction))
				h.call(query, w.Reply{Errno: 16})
				v, handle := h.evidence(0), w.HandleID(100)
				switch field {
				case "fresh-intent":
					v.Intent.ID = testID('8')
				case "root":
					v.Intent.Root.BackingUUID[0]++
					v.Root = v.Intent.Root
				case "transaction":
					v.Intent.Transaction.Generation++
					binary.LittleEndian.PutUint32(v.Intent.Transaction.Handle[4:], v.Intent.Transaction.Generation)
				case "initial-uid":
					v.Intent.Initial.UID++
				case "initial-gid":
					v.Intent.Initial.GID++
				case "initial-mode":
					v.Intent.Initial.Mode++
				case "initial-atime":
					v.Intent.Initial.ATimeSeconds++
				case "initial-mtime":
					v.Intent.Initial.MTimeSeconds++
				case "initial-atime-nanos":
					v.Intent.Initial.ATimeNanos++
				case "initial-mtime-nanos":
					v.Intent.Initial.MTimeNanos++
				case "initial-captured":
					v.Intent.InitialCaptured, v.Intent.Initial = false, a.CopyCleanupV1{}
				case "phase-manifest":
					v.Intent.Phase, v.Intent.ManifestSize, v.Intent.ManifestDigest = a.CopySealed, 1, [32]byte{1}
				case "cleanup":
					v.Intent.Phase, v.Intent.Cleanup.Mode = a.CopyCleaning, 0755
				case "handle":
					handle = 101
				case "missing-root":
					v.Root = a.CopyRootV1{}
				}
				if stage == "bind" {
					v.Identity = v.Intent.Transaction
					if field == "identity" {
						v.Identity = v.Intent.Root.Root
					}
					if field == "missing-identity" {
						v.Identity = a.Ext4ObjectV1{}
					}
					h.control(w.BindCopyTransaction, handle, v)
					h.control(w.BeginCopy, 100, h.evidence(0))
				} else {
					h.bind()
					h.control(w.BeginCopy, handle, v)
				}
				h.call(query, w.Reply{Body: w.ReadDirReply{Entries: []w.DirEntry{}}})
				h.release(99, 101)
				h.release(99, 100)
				h.close(false, false)
			})
		}
	}
}

func TestPrepareReadDirReplayCapacity(t *testing.T) {
	for _, count := range []int{2, 3} {
		t.Run(fmt.Sprintf("unique-%d", count), func(t *testing.T) {
			h := newReadDirReplayHarness(t, 2, "")
			h.control(w.BeginCopy, 100, h.evidence(w.BindCopyTransaction))
			for i := 0; i < count; i++ {
				query := w.ReadDirRequest{Node: 99, Handle: 100, Cookie: uint64(i), MaxBytes: 4096}
				for repeat := 0; repeat < 5; repeat++ {
					h.call(query, w.Reply{Errno: 16})
				}
				h.control(w.BeginCopy, 100, h.evidence(w.BindCopyTransaction))
			}
			h.bind()
			h.control(w.BeginCopy, 100, h.evidence(0))
			for i := count - 1; i >= 0; i-- {
				h.call(w.ReadDirRequest{Node: 99, Handle: 100, Cookie: uint64(i), MaxBytes: 4096}, w.Reply{Body: w.ReadDirReply{Entries: []w.DirEntry{}}})
			}
			h.release(99, 100)
			h.close(count == 2, count > 2)
		})
	}
}

func TestPrepareReadDirReplayObservationCannotOutliveReplay(t *testing.T) {
	for _, name := range []string{"cleared-without-probe", "successful-read-without-probe", "other-operation-failure"} {
		t.Run(name, func(t *testing.T) {
			h := newReadDirReplayHarness(t, 2, "")
			query := w.ReadDirRequest{Node: 99, Handle: 100, Cookie: 7, MaxBytes: 4096}
			ok := w.Reply{Body: w.ReadDirReply{Entries: []w.DirEntry{}}}
			h.control(w.BeginCopy, 100, h.evidence(w.BindCopyTransaction))
			switch name {
			case "cleared-without-probe":
				h.bind()
				h.control(w.BeginCopy, 100, h.evidence(0))
			case "successful-read-without-probe":
				h.call(query, ok)
			case "other-operation-failure":
				h.call(w.GetAttrRequest{Node: 99}, w.Reply{Errno: 16})
			}
			h.call(query, w.Reply{Errno: 16})
			h.bind()
			h.control(w.BeginCopy, 100, h.evidence(0))
			h.call(query, ok)
			h.release(99, 100)
			h.close(false, false)
		})
	}
}

func TestPrepareReadDirReplayRequiresValidatedReplies(t *testing.T) {
	for _, fault := range []string{"sequence", "operation", "missing", "unknown-pending", "intent", "owner", "epoch"} {
		for broken := 0; broken < 5; broken++ {
			if fault == "unknown-pending" && broken != 0 || (fault == "owner" || fault == "epoch") && broken != 0 && broken != 2 && broken != 3 || fault == "intent" && broken != 2 {
				continue
			}
			t.Run(fmt.Sprintf("%s/step-%d", fault, broken), func(t *testing.T) {
				h := newReadDirReplayHarness(t, 2, "")
				begin := w.PrepareRequest{Node: 99, Handle: 100, Action: w.BeginCopy}
				bind := w.PrepareRequest{Node: 99, Handle: 100, Action: w.BindCopyTransaction, Intent: h.intent.ID}
				query := w.ReadDirRequest{Node: 99, Handle: 100, Cookie: 7, MaxBytes: 4096}
				bound := h.evidence(0)
				bound.Identity = h.intent.Transaction
				bodies := []w.RequestBody{begin, query, bind, begin, query}
				replies := []w.Reply{{Body: h.evidence(w.BindCopyTransaction)}, {Errno: 16}, {Body: bound}, {Body: h.evidence(0)}, {Body: w.ReadDirReply{Entries: []w.DirEntry{}}}}
				for i := 0; i <= broken; i++ {
					f := ""
					if i == broken {
						f = fault
					}
					h.exchange(caller(h.c), 0, bodies[i], replies[i], f)
				}
				h.close(false, false)
			})
		}
	}
}
