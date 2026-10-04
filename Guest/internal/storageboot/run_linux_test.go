//go:build linux

package storageboot

import (
	"dev.cengine/guest/internal/vsock"
	"net"
	"testing"
)

type addressed struct {
	net.Conn
	remote net.Addr
}

func (c addressed) RemoteAddr() net.Addr { return c.remote }

type stringPeer string

func (s stringPeer) Network() string { return "vsock" }
func (s stringPeer) String() string  { return string(s) }
func TestConcreteKernelPeerOnly(t *testing.T) {
	for _, addr := range []net.Addr{vsock.Addr{CID: 2}, vsock.Addr{CID: 3}, &vsock.Addr{CID: 2}, stringPeer("2:4106"), &net.TCPAddr{}, nil} {
		_, concrete := addr.(vsock.Addr)
		want := concrete && addr.(vsock.Addr).CID == 2
		if authenticatedPeer(addressed{remote: addr}) != want {
			t.Fatal(addr)
		}
	}
}
