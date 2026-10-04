package storageserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
)

func TestHandshakeDeadlineIncludesUnreadRootReply(t *testing.T) {
	l := DefaultLimits()
	l.HandshakeTimeout = 100 * time.Millisecond
	l.WriteTimeout = 5 * time.Second
	f := newFixture(t, l, false)
	b, k := f.binding()
	c, done := f.start(b, k)
	defer c.NetConn().Close()
	// Do not consume RootReply. The handshake deadline, not the much longer
	// writer deadline, must terminate this authenticated attachment.
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("root handshake survived")
		}
	case <-time.After(time.Second):
		t.Fatal("root reply escaped handshake timeout")
	}
	if h := retired(t, f.retired); h.Binding != b {
		t.Fatal(h)
	}
}

func TestStickyFaultDeliversPartialMutationBeforeClosingVolume(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		return execFunc(func(g *a.Guard, r w.Request) (m.Result, error) {
			return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpGetAttr, Errno: 5}, Events: []w.Event{{EventSequence: 1, Volume: b.Volume, Object: w.ObjectID{9}, Kind: w.InvalidateAttr, Name: []byte{}}}}, m.ErrVolumeFault
		}), rootEntry(), nil
	}
	c1, d1, b1 := f.connected()
	c2, d2, b2 := f.connected()
	r := request(1)
	must(t, w.WriteFrame(c1, &r))
	if reply := readMessage(t, c1).(*w.Reply); reply.Errno != 5 {
		t.Fatal(reply)
	}
	for _, c := range []*tls.Conn{c1, c2} {
		if e := readMessage(t, c).(*w.Event); e.EventSequence != 1 {
			t.Fatal(e)
		}
	}
	if e := wait(t, d1); !errors.Is(e, m.ErrVolumeFault) {
		t.Fatal(e)
	}
	if e := wait(t, d2); !errors.Is(e, m.ErrVolumeFault) {
		t.Fatal(e)
	}
	got := map[a.Binding]bool{retired(t, f.retired).Binding: true, retired(t, f.retired).Binding: true}
	if !got[b1] || !got[b2] {
		t.Fatal(got)
	}
}

func TestEventOverloadRetiresOnlySlowAttachment(t *testing.T) {
	limits := DefaultLimits()
	// Reading the previous event does not join the server's TLS Write: that
	// frame can still be charged when the next reply and event are enqueued.
	// The fast peer therefore needs three slots, even without pipelining.
	limits.WriterMessages = 3
	f := newFixture(t, limits, false)
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
		return execFunc(func(g *a.Guard, r w.Request) (m.Result, error) {
			return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: rootEntry().Attr}}, Events: []w.Event{{EventSequence: r.Sequence, Volume: b.Volume, Object: w.ObjectID{9}, Kind: w.InvalidateAttr, Name: []byte{}}}}, nil
		}), rootEntry(), nil
	}
	fast, fastDone, fastBinding := f.connected()
	defer fast.NetConn().Close()
	slow, slowDone, slowBinding := f.connected()
	defer slow.NetConn().Close()
	exchange := func(sequence uint64) {
		t.Helper()
		r := request(sequence)
		must(t, w.WriteFrame(fast, &r))
		message := readMessage(t, fast)
		reply, ok := message.(*w.Reply)
		if !ok {
			t.Fatalf("request %d: expected reply before event, got %T", sequence, message)
		}
		must(t, w.ValidateReplyFor(r, *reply))
		message = readMessage(t, fast)
		event, ok := message.(*w.Event)
		if !ok || event.EventSequence != sequence || event.Volume != fastBinding.Volume {
			t.Fatalf("request %d: unexpected event: %+v", sequence, message)
		}
	}
	// Four unread events must exhaust the slow peer's three slots; the
	// in-flight write must remain charged, not escape the output bound.
	for i := uint64(1); i <= 4; i++ {
		exchange(i)
	}
	if e := wait(t, slowDone); !errors.Is(e, ErrOverload) {
		t.Fatal(e)
	}
	if h := retired(t, f.retired); h.Binding != slowBinding {
		t.Fatal(h)
	}
	// The healthy origin must remain usable after the slow peer has retired.
	exchange(5)
	select {
	case h := <-f.retired:
		t.Fatalf("unexpected retirement: %+v", h)
	default:
	}
	fast.NetConn().Close()
	wait(t, fastDone)
}

func TestConnectionCapacityAndCallbackRemainBounded(t *testing.T) {
	l := DefaultLimits()
	l.Connections = 1
	f := newFixture(t, l, false)
	blocked := make(chan struct{})
	original := f.s.config.RequestRetirement
	f.s.config.RequestRetirement = func(h a.DataHello, e error) { original(h, e); <-blocked }
	c, done, _ := f.connected()
	c.NetConn().Close()
	retired(t, f.retired)
	left, right := net.Pipe()
	defer right.Close()
	if e := f.s.Serve(context.Background(), f.a, left); !errors.Is(e, ErrOverload) {
		t.Fatal(e)
	}
	close(blocked)
	wait(t, done)
}

func TestWrongCertificateAndProfileNeverRetireClaimedBinding(t *testing.T) {
	for _, badProfile := range []bool{false, true} {
		t.Run(map[bool]string{false: "key", true: "profile"}[badProfile], func(t *testing.T) {
			f := newFixture(t, Limits{}, false)
			b, k := f.binding()
			if !badProfile {
				k = key(t)
			}
			server, client := f.pair(k)
			done := make(chan error, 1)
			go func() { done <- f.s.Serve(context.Background(), f.a, server) }()
			var hello w.ServerHello
			must(t, w.ReadFrame(client, &hello))
			ch := w.ClientHello{Authority: a.DataHello{Epoch: hello.Epoch, Binding: b}, Profile: w.RequiredProfile()}
			if badProfile {
				// Reject the previous ABI explicitly, even when the required ABI changes.
				ch.Profile.CredentialABI = w.CredentialABI - 1
				if err := ch.Validate(); !errors.Is(err, w.ErrInvalid) {
					t.Fatalf("mismatched ABI validated: %v", err)
				}
				// Bypass WriteFrame's local validation, retaining valid JSON and framing.
				payload, e := json.Marshal(&ch)
				must(t, e)
				packet := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
				_, e = client.Write(append(packet, payload...))
				must(t, e)
			} else {
				must(t, w.WriteFrame(client, &ch))
			}
			if e := wait(t, done); e == nil || (badProfile && !errors.Is(e, w.ErrInvalid)) {
				t.Fatalf("unexpected unauthenticated hello result: %v", e)
			}
			select {
			case <-f.retired:
				t.Fatal("retired untrusted binding")
			default:
			}
		})
	}
}

func TestPartialFrameTimeoutAndBudgetReleased(t *testing.T) {
	l := DefaultLimits()
	l.ReadTimeout = 30 * time.Millisecond
	l.ReceiveFrames = 1
	f := newFixture(t, l, false)
	c, done, b := f.connected()
	defer c.NetConn().Close()
	_, err := c.Write([]byte{0, 0, 0, 8, '{'})
	must(t, err)
	if e := wait(t, done); e == nil {
		t.Fatal("partial frame survived deadline")
	}
	if h := retired(t, f.retired); h.Binding != b {
		t.Fatal(h)
	}
	if len(f.s.receive) != 0 {
		t.Fatal("leaked receive reservation")
	}
}
