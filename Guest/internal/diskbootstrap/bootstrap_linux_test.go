//go:build linux

package diskbootstrap

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"dev.cengine/guest/internal/vsock"
)

type stringPeer string

func (p stringPeer) Network() string { return "vsock" }
func (p stringPeer) String() string  { return string(p) }

type testConnection struct {
	exchange
	remote      net.Addr
	closed      bool
	beforeWrite func()
}

func (c *testConnection) Write(p []byte) (int, error) {
	if c.beforeWrite != nil {
		c.beforeWrite()
	}
	return c.Buffer.Write(p)
}
func (c *testConnection) Close() error                     { c.closed = true; return nil }
func (c *testConnection) LocalAddr() net.Addr              { return vsock.Addr{CID: 3, Port: Port} }
func (c *testConnection) RemoteAddr() net.Addr             { return c.remote }
func (c *testConnection) SetDeadline(time.Time) error      { return nil }
func (c *testConnection) SetReadDeadline(time.Time) error  { return nil }
func (c *testConnection) SetWriteDeadline(time.Time) error { return nil }

type testListener struct {
	connections []*testConnection
	accepted    int
	closed      bool
}

func (l *testListener) Accept() (net.Conn, error) {
	if l.closed || l.accepted >= len(l.connections) {
		return nil, errors.New("closed")
	}
	c := l.connections[l.accepted]
	l.accepted++
	return c, nil
}
func (l *testListener) Close() error   { l.closed = true; return nil }
func (l *testListener) Addr() net.Addr { return vsock.Addr{Port: Port} }
func TestPeerRequiresConcreteKernelVsockAddrCID2(t *testing.T) {
	for _, remote := range []net.Addr{vsock.Addr{CID: 2}, vsock.Addr{CID: 3}, &vsock.Addr{CID: 2}, stringPeer("2:4105"), &net.TCPAddr{}, nil} {
		c := &testConnection{remote: remote}
		_, concrete := remote.(vsock.Addr)
		want := concrete && remote.(vsock.Addr).CID == 2
		if got := authenticatedPeer(c); got != want {
			t.Fatalf("peer %T %v: %v", remote, remote, got)
		}
	}
}
func TestFirstAuthenticatedSessionClosesListenerBeforeHelloAndNeverReopens(t *testing.T) {
	for _, successful := range []bool{false, true} {
		input := rawFrame(manifestFixture())
		if successful {
			input = append(input, rawFrame(commitFixture())...)
		}
		bad := &testConnection{remote: stringPeer("2:4105")}
		good := &testConnection{remote: vsock.Addr{CID: 2}, exchange: exchange{Reader: bytes.NewReader(input)}}
		extra := &testConnection{remote: vsock.Addr{CID: 2}}
		listener := &testListener{connections: []*testConnection{bad, good, extra}}
		good.beforeWrite = func() {
			if !listener.closed {
				t.Fatal("sent hello before closing listener")
			}
		}
		ops := &fakeOperations{}
		err := acceptSession(listener, helloFixture(), ops)
		if (err == nil) != successful {
			t.Fatalf("success=%v err=%v", successful, err)
		}
		if !bad.closed || bad.Buffer.Len() != 0 || !good.closed || listener.accepted != 2 || !listener.closed || extra.closed {
			t.Fatal("session reopened or unauthenticated peer used")
		}
	}
}
