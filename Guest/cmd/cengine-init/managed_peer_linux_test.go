//go:build linux

package main

import (
	"errors"
	"net"
	"testing"

	"dev.cengine/guest/internal/vsock"
)

type peerProbe struct {
	net.Conn
	peer   net.Addr
	reads  int
	closed bool
}

func (p *peerProbe) RemoteAddr() net.Addr { return p.peer }
func (p *peerProbe) Read(data []byte) (int, error) {
	p.reads++
	return 0, errors.New("unexpected read")
}
func (p *peerProbe) Close() error { p.closed = true; return p.Conn.Close() }

type oncePeerListener struct{ conn net.Conn }

func (l *oncePeerListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, net.ErrClosed
	}
	c := l.conn
	l.conn = nil
	return c, nil
}
func (*oncePeerListener) Close() error   { return nil }
func (*oncePeerListener) Addr() net.Addr { return vsock.Addr{CID: 3, Port: 4102} }
func TestGenericControlAndRootFSRejectNonHostBeforeRead(t *testing.T) {
	for _, root := range []bool{false, true} {
		left, right := net.Pipe()
		defer right.Close()
		probe := &peerProbe{Conn: left, peer: vsock.Addr{CID: 3, Port: 1}}
		state := &controlServer{}
		if root {
			state.serveRootFS(&oncePeerListener{conn: probe})
		} else {
			state.serve(probe)
		}
		if probe.reads != 0 || !probe.closed {
			t.Fatal("non-host reached generic parser")
		}
	}
	for _, cid := range []uint32{0, 1, 2, 3} {
		left, right := net.Pipe()
		if hostPeer(&peerProbe{Conn: left, peer: vsock.Addr{CID: cid, Port: 1}}) != (cid == 2) {
			t.Fatal("CID mismatch")
		}
		left.Close()
		right.Close()
	}
}

func TestAuxiliaryPlanesRejectNonHostBeforeReading(t *testing.T) {
	for _, exec := range []bool{false, true} {
		left, right := net.Pipe()
		defer right.Close()
		probe := &peerProbe{Conn: left, peer: vsock.Addr{CID: 3, Port: 1}}
		state := &controlServer{}
		if exec {
			state.handleExecIO(probe)
		} else {
			state.handlePortProxy(probe)
		}
		if probe.reads != 0 || !probe.closed {
			t.Fatal("non-host reached auxiliary parser")
		}
	}
}
