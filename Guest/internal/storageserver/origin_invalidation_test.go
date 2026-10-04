package storageserver

import (
	"bytes"
	"crypto/tls"
	"errors"
	"math"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
)

func originWrite(cache bool) (w.Request, w.Reply) {
	r := w.Request{Sequence: 1, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.WriteRequest{Node: 2, Handle: 3, Data: []byte("data")}}
	if cache {
		r.Auth = w.Auth{Kind: w.OpenGrantAuth}
		v := r.Body.(w.WriteRequest)
		v.WriteFlags = w.WriteCache
		r.Body = v
	}
	return r, w.Reply{Sequence: r.Sequence, Op: w.OpWrite, Body: w.WriteReply{Written: 4}}
}

func originPeers(t *testing.T) (*Server, *peer, *peer, *peer) {
	t.Helper()
	s := &Server{config: Config{Limits: DefaultLimits()}, peers: make(map[*peer]struct{})}
	volume := id(t)
	newPeer := func(v a.ID) *peer {
		p := &peer{server: s, hello: a.DataHello{Binding: a.Binding{Volume: v, Attachment: id(t)}}}
		s.peers[p] = struct{}{}
		return p
	}
	return s, newPeer(volume), newPeer(volume), newPeer(id(t))
}

func originEvents(p *peer, first uint64) []w.Event {
	return []w.Event{
		{EventSequence: first, Volume: p.hello.Binding.Volume, Object: w.ObjectID{2}, Kind: w.InvalidateAttr, Name: []byte{}},
		{EventSequence: first + 1, Volume: p.hello.Binding.Volume, Object: w.ObjectID{2}, Kind: w.InvalidateEntry, Parent: w.ObjectID{1}, Name: []byte("file")},
		{EventSequence: first + 2, Volume: p.hello.Binding.Volume, Object: w.ObjectID{2}, Kind: w.InvalidateData, Name: []byte{}},
	}
}

func expectOriginFrames(t *testing.T, p *peer, reply *w.Reply, events []w.Event) {
	t.Helper()
	var want [][]byte
	if reply != nil {
		b, err := frame(reply)
		must(t, err)
		want = append(want, b)
	}
	for i := range events {
		b, err := frame(&events[i])
		must(t, err)
		want = append(want, b)
	}
	if len(p.queue) != len(want) {
		t.Fatalf("frames=%d want=%d", len(p.queue), len(want))
	}
	for i := range want {
		if !bytes.Equal(p.queue[i], want[i]) {
			t.Fatalf("frame %d: got %s want %s", i, p.queue[i], want[i])
		}
	}
	p.queue, p.bytes = nil, 0
}

func TestOriginDataPublication(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cache       bool
		change      func(*w.Request, *w.Reply)
		noReply     bool
		dispatchErr error
		omit        bool
	}{
		{name: "ordinary_full", omit: true},
		{name: "cache_full", cache: true, omit: true},
		{name: "ordinary_grant_full", omit: true, change: func(r *w.Request, _ *w.Reply) { r.Auth = w.Auth{Kind: w.OpenGrantAuth} }},
		{name: "ordinary_short", change: func(_ *w.Request, v *w.Reply) { v.Body = w.WriteReply{Written: 3} }},
		{name: "cache_short", cache: true, change: func(_ *w.Request, v *w.Reply) { v.Body = w.WriteReply{Written: 3} }},
		{name: "ordinary_error", change: func(_ *w.Request, v *w.Reply) { v.Errno, v.Body = 5, nil }},
		{name: "cache_error", cache: true, change: func(_ *w.Request, v *w.Reply) { v.Errno, v.Body = 5, nil }},
		{name: "dispatch_error", dispatchErr: m.ErrVolumeFault},
		{name: "cache_dispatch_error", cache: true, dispatchErr: m.ErrVolumeFault},
		{name: "no_reply", noReply: true},
		{name: "cache_no_reply", cache: true, noReply: true},
		{name: "sequence_mismatch", change: func(_ *w.Request, v *w.Reply) { v.Sequence++ }},
		{name: "operation_mismatch", change: func(_ *w.Request, v *w.Reply) { v.Op, v.Body = w.OpGetAttr, w.GetAttrReply{Attr: rootEntry().Attr} }},
		{name: "oversized_write", change: func(_ *w.Request, v *w.Reply) { v.Body = w.WriteReply{Written: 5} }},
		{name: "invalid_node", change: func(r *w.Request, _ *w.Reply) { v := r.Body.(w.WriteRequest); v.Node = 0; r.Body = v }},
		{name: "invalid_cache_auth", cache: true, change: func(r *w.Request, _ *w.Reply) {
			r.Auth = w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}
		}},
		{name: "invalid_reply_body", noReply: true, change: func(_ *w.Request, v *w.Reply) { v.Body = nil }},
		{name: "set_size", omit: true, change: originSetAttr(w.SetSize, false)},
		{name: "set_size_error", change: originSetAttr(w.SetSize, true)},
		{name: "set_size_dispatch_error", dispatchErr: m.ErrVolumeFault, change: originSetAttr(w.SetSize, false)},
		{name: "set_size_no_reply", noReply: true, change: originSetAttr(w.SetSize, false)},
		{name: "set_mode", change: originSetAttr(w.SetMode, false)},
		{name: "set_mtime", change: originSetAttr(w.SetMTime, false)},
		{name: "fallocate", change: func(r *w.Request, v *w.Reply) {
			r.Body = w.FallocateRequest{Node: 2, Handle: 3, Length: 4}
			v.Op, v.Body = w.OpFallocate, w.FallocateReply{}
		}},
		{name: "create", change: func(r *w.Request, v *w.Reply) {
			r.Body = w.CreateRequest{Parent: 1, Name: []byte("file"), Mode: 0600}
			e := rootEntry()
			e.Attr.Mode = 0100600
			v.Op, v.Body = w.OpCreate, w.CreateReply{Entry: e, Opened: w.Opened{Handle: 3}}
		}},
		{name: "getattr", change: func(r *w.Request, v *w.Reply) {
			*r = request(1)
			v.Op, v.Body = w.OpGetAttr, w.GetAttrReply{Attr: rootEntry().Attr}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, origin, remote, other := originPeers(t)
			r, reply := originWrite(tc.cache)
			if tc.change != nil {
				tc.change(&r, &reply)
			}
			events := originEvents(origin, 1)
			must(t, s.publish(origin, r, m.Result{Reply: reply, Events: events}, !tc.noReply, tc.dispatchErr))
			want := events
			if tc.omit {
				want = events[:2]
			}
			var originReply *w.Reply
			if !tc.noReply {
				originReply = &reply
			}
			expectOriginFrames(t, origin, originReply, want)
			expectOriginFrames(t, remote, nil, events)
			expectOriginFrames(t, other, nil, nil)
		})
	}
}

func originSetAttr(valid uint32, failed bool) func(*w.Request, *w.Reply) {
	return func(r *w.Request, v *w.Reply) {
		r.Body = w.SetAttrRequest{Node: 2, Valid: valid, Semantics: w.MetadataValid | w.MetadataCTime}
		attr := rootEntry().Attr
		attr.Mode = 0100600
		v.Op, v.Body = w.OpSetAttr, w.SetAttrReply{Attr: attr}
		if failed {
			v.Errno, v.Body = 5, nil
		}
	}
}

func TestOriginDataWriterReversal(t *testing.T) {
	s, first, second, other := originPeers(t)
	// Per-request origin, not a permanently exempt writer. The first writer must
	// receive all invalidations when the second attachment writes the same object.
	for i, origin := range []*peer{first, second} {
		remote := second
		if origin == second {
			remote = first
		}
		r, reply := originWrite(i == 1)
		events := originEvents(origin, uint64(1+3*i))
		must(t, s.publish(origin, r, m.Result{Reply: reply, Events: events}, true, nil))
		expectOriginFrames(t, origin, &reply, events[:2])
		expectOriginFrames(t, remote, nil, events)
		expectOriginFrames(t, other, nil, nil)
	}
}

func TestOriginDataServeRequestAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cache       bool
		dispatchErr error
	}{
		{"ordinary_full", false, nil},
		{"cache_full", true, nil},
		{"dispatch_error", false, m.ErrVolumeFault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Limits{}, false)
			f.s.factory = func(_ *a.Guard, _ *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
				return execFunc(func(_ *a.Guard, r w.Request) (m.Result, error) {
					if v, ok := r.Body.(w.WriteRequest); ok {
						events := originEvents(&peer{hello: a.DataHello{Binding: b}}, 1)
						return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpWrite, Body: w.WriteReply{Written: uint32(len(v.Data))}}, Events: events}, tc.dispatchErr
					}
					return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: rootEntry().Attr}}}, nil
				}), rootEntry(), nil
			}
			origin, originDone, _ := f.connected()
			remote, remoteDone, _ := f.connected()
			t.Cleanup(func() {
				defer origin.NetConn().Close()
				defer remote.NetConn().Close()
				// Let storage failure finish its own shutdown. Closing first can
				// race stopForStorage and make EOF win the terminal result.
				if tc.dispatchErr == nil {
					origin.NetConn().Close()
					remote.NetConn().Close()
				}
				for _, done := range []chan error{originDone, remoteDone} {
					if err := wait(t, done); tc.dispatchErr != nil && !errors.Is(err, tc.dispatchErr) {
						t.Errorf("lost dispatch failure: %v", err)
					}
				}
			})
			r, _ := originWrite(tc.cache)
			must(t, w.WriteFrame(origin, &r))
			reply, ok := readMessage(t, origin).(*w.Reply)
			if !ok {
				t.Fatal("missing write reply")
			}
			must(t, w.ValidateReplyFor(r, *reply))
			for _, conn := range []*tls.Conn{origin, remote} {
				count := 3
				if conn == origin && tc.dispatchErr == nil {
					count = 2
				}
				for i := 0; i < count; i++ {
					e, ok := readMessage(t, conn).(*w.Event)
					if !ok || e.EventSequence != uint64(i+1) {
						t.Fatalf("missing ordered event %d: %+v", i+1, e)
					}
				}
			}
			if tc.dispatchErr == nil {
				// A subsequent reply must be next, not an unconsumed origin DATA.
				next := request(2)
				must(t, w.WriteFrame(origin, &next))
				reply, ok := readMessage(t, origin).(*w.Reply)
				if !ok {
					t.Fatal("origin DATA echoed before next reply")
				}
				must(t, w.ValidateReplyFor(next, *reply))
			}
		})
	}
}

func TestOriginDataFilteredEventsStillValidated(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*w.Event)
		want   error
	}{
		{"duplicate_sequence", func(e *w.Event) { e.EventSequence = 2 }, w.ErrInvalid},
		{"zero_sequence", func(e *w.Event) { e.EventSequence = 0 }, w.ErrInvalid},
		{"invalid_object", func(e *w.Event) { e.Object = w.ObjectID{} }, w.ErrInvalid},
		{"invalid_range", func(e *w.Event) { e.Offset, e.Length = math.MaxInt64, 1 }, w.ErrInvalid},
		{"invalid_name", func(e *w.Event) { e.Name = []byte("bad") }, w.ErrInvalid},
		{"wrong_volume", func(e *w.Event) { e.Volume = id(t) }, ErrStorage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, origin, remote, other := originPeers(t)
			r, reply := originWrite(true)
			events := originEvents(origin, 1)
			tc.change(&events[2]) // Last event would have been filtered on origin.
			if err := s.publish(origin, r, m.Result{Reply: reply, Events: events}, true, nil); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			for _, p := range []*peer{origin, remote, other} {
				expectOriginFrames(t, p, nil, nil)
			}
		})
	}
}

func TestOriginDataFilteredSequenceRemainsGlobal(t *testing.T) {
	s, origin, remote, other := originPeers(t)
	r, reply := originWrite(false)
	events := originEvents(origin, 1)
	must(t, s.publish(origin, r, m.Result{Reply: reply, Events: events}, true, nil))
	expectOriginFrames(t, origin, &reply, events[:2])
	expectOriginFrames(t, remote, nil, events)
	// DATA sequence 3 was consumed despite origin filtering, even for a later
	// request from a different volume. Gaps on an individual peer remain legal.
	r.Sequence, reply.Sequence = 2, 2
	events[2].Volume = other.hello.Binding.Volume
	if err := s.publish(other, r, m.Result{Reply: reply, Events: events[2:]}, true, nil); !errors.Is(err, w.ErrInvalid) {
		t.Fatalf("filtered sequence reused: %v", err)
	}
	for _, p := range []*peer{origin, remote, other} {
		expectOriginFrames(t, p, nil, nil)
	}
}
