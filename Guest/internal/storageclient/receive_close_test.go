package storageclient

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	w "dev.cengine/guest/internal/storagewire"
)

// Buffer exactly one real encrypted TLS record, then gate its delivery to TLS.
// This owns no decoder/client seam: public New still runs the real TLS, strict
// DATA decoder and receive goroutine. Close interrupts the underlying socket but
// cannot discard bytes already read. The test releases those bytes after the
// graceful-stop commit, deterministically exercising validation at that boundary.
type gatedTLSRecordConn struct {
	net.Conn
	buffer                 []byte // only the TLS reader accesses this
	mu                     sync.Mutex
	armed                  bool
	ready                  chan struct{}
	proceed                chan struct{}
	closed                 chan struct{}
	releaseOnce, closeOnce sync.Once
	reads                  atomic.Int32
}

func newGatedTLSRecordConn() *gatedTLSRecordConn {
	return &gatedTLSRecordConn{ready: make(chan struct{}), proceed: make(chan struct{}), closed: make(chan struct{})}
}
func (g *gatedTLSRecordConn) arm()     { g.mu.Lock(); g.armed = true; g.mu.Unlock() }
func (g *gatedTLSRecordConn) release() { g.releaseOnce.Do(func() { close(g.proceed) }) }
func (g *gatedTLSRecordConn) Close() error {
	err := g.Conn.Close()
	g.closeOnce.Do(func() { close(g.closed) })
	return err
}
func (g *gatedTLSRecordConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(g.buffer) == 0 {
		g.reads.Add(1)
		var header [5]byte
		if _, err := io.ReadFull(g.Conn, header[:]); err != nil {
			return 0, err
		}
		// TLS's uint16 record length bounds this test-only buffer.
		g.buffer = make([]byte, 5+int(binary.BigEndian.Uint16(header[3:])))
		copy(g.buffer, header[:])
		if _, err := io.ReadFull(g.Conn, g.buffer[5:]); err != nil {
			return 0, err
		}
		g.mu.Lock()
		armed := g.armed
		g.armed = false
		g.mu.Unlock()
		if armed {
			close(g.ready)
			<-g.proceed
		}
	}
	n := copy(p, g.buffer)
	g.buffer = g.buffer[n:]
	return n, nil
}

func awaitReceiveGate(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("receive gate did not advance")
	}
}

func TestGracefulValidatesBufferedTLSFrameAfterStop(t *testing.T) {
	for _, tc := range []struct {
		name string
		want error
	}{
		{"unsolicited-reply", ErrProtocol},
		{"duplicate-reply", ErrProtocol},
		{"pending-probe-reply", ErrProtocol},
		{"canceled-reply", ErrProtocol},
		{"wrong-volume-event", ErrProtocol},
		{"duplicate-event", w.ErrInvalid},
		{"malformed-frame", w.ErrInvalid},
		{"valid-unadmitted-event", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := newGatedTLSRecordConn()
			defer transport.release()
			send, sendNow := gate()
			defer sendNow()
			sent := make(chan error, 1)
			notifications := make(chan struct{}, 2)
			event := w.Event{EventSequence: 1, Volume: testID('2'), Object: w.ObjectID{99}, Kind: w.InvalidateAttr, Name: []byte{}}
			reply := w.Reply{Sequence: 1, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: testEntry(99, true).Attr}}
			c := fixtureWithClientConn(t, func(raw net.Conn) net.Conn { transport.Conn = raw; return transport }, func(cfg *Config) {
				cfg.Invalidate = func(context.Context, Notification) error { notifications <- struct{}{}; return nil }
			}, func(conn *tls.Conn) {
				if tc.name == "duplicate-reply" {
					var req w.Request
					if err := w.ReadFrame(conn, &req); err != nil {
						return
					}
					reply.Sequence = req.Sequence
					if err := w.WriteFrame(conn, &reply); err != nil {
						return
					}
				}
				if tc.name == "pending-probe-reply" {
					var req w.Request
					if err := w.ReadFrame(conn, &req); err != nil {
						return
					}
					if err := w.WriteFrame(conn, &w.Reply{Sequence: req.Sequence, Op: w.OpGetXAttr, Errno: 34}); err != nil {
						return
					}
				}
				if tc.name == "duplicate-event" {
					if err := w.WriteFrame(conn, &event); err != nil {
						return
					}
				}
				<-send
				switch tc.name {
				case "unsolicited-reply", "duplicate-reply", "pending-probe-reply", "canceled-reply":
					sent <- w.WriteFrame(conn, &reply)
				case "malformed-frame":
					_, err := conn.Write([]byte{0, 0, 0, 2, '{', '}'})
					sent <- err
				default:
					if tc.name == "wrong-volume-event" {
						event.Volume = testID('6')
					}
					sent <- w.WriteFrame(conn, &event)
				}
			})
			if tc.name == "duplicate-reply" {
				if err := awaitError(t, asyncGetAttr(c)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "duplicate-event" {
				awaitReceiveGate(t, notifications)
			}
			var pendingKey xattrProbeKey
			if tc.name == "pending-probe-reply" {
				if _, err := c.Do(caller(c), 0, w.GetXAttrRequest{Node: 99, Name: []byte("user.x"), Size: 1}); err != nil {
					t.Fatal(err)
				}
				c.mu.Lock()
				for key := range c.pendingProbes {
					pendingKey = key
				}
				c.mu.Unlock()
			}
			awaitClient(t, c, func() bool { return !c.processing && !c.replyPending && c.outstanding == nil && c.pendingEvents == 0 })
			transport.arm()
			sendNow()
			awaitReceiveGate(t, transport.ready)
			if err := awaitError(t, sent); err != nil {
				t.Fatal(err)
			}
			reads := transport.reads.Load()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := gracefulStart(t, c, ctx)
			awaitReceiveGate(t, transport.closed)
			stillClosing(t, done) // the already-read record's receive worker must join
			if tc.name == "canceled-reply" {
				cancel()
				awaitClient(t, c, func() bool { return errors.Is(c.err, context.Canceled) })
				stillClosing(t, done)
			}
			transport.release()
			err := awaitError(t, done)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("close=%v, want %v", err, tc.want)
			}
			if tc.name == "canceled-reply" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation", err)
			}
			if tc.name == "pending-probe-reply" && !errors.Is(err, ErrIncomplete) {
				t.Fatal("lost incomplete probe", err)
			}
			select {
			case <-c.Terminal():
				if tc.want == nil {
					t.Fatal("valid unadmitted event caused retirement")
				}
			default:
				if tc.want != nil {
					t.Fatal("invalid frame did not signal retirement")
				}
			}
			if transport.reads.Load() != reads {
				t.Fatal("read another packet after stop")
			}
			select {
			case <-notifications:
				t.Fatal("admitted an event after stop")
			default:
			}
			c.mu.Lock()
			unchanged := c.pendingEvents == 0 && !c.replyPending && c.outstanding == nil && c.pins == 1 && len(c.handles) == 0
			if tc.name == "pending-probe-reply" {
				_, retained := c.pendingProbes[pendingKey]
				unchanged = unchanged && retained && len(c.pendingProbes) == 1
			}
			c.mu.Unlock()
			if !unchanged {
				t.Fatal("post-stop validation changed admission/grant counts")
			}
		})
	}
}

func TestGracefulIdleReceiverDoesNotWaitForFuturePacket(t *testing.T) {
	transport := newGatedTLSRecordConn()
	defer transport.release()
	c := fixtureWithClientConn(t, func(raw net.Conn) net.Conn { transport.Conn = raw; return transport }, nil, nil)
	transport.arm()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.CloseGracefully(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.ready:
		t.Fatal("unexpected future record")
	default:
	}
}
