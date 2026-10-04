package storagebootstrap

import (
	"context"
	p "dev.cengine/guest/internal/storagepki"
	"net"
	"testing"
	"time"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func attachmentID(t *testing.T) string { t.Helper(); id, e := p.NewUUID(); check(t, e); return id }
func credentialStream(t *testing.T, serve func(context.Context, net.Conn) error) (net.Conn, func() error) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	check(t, e)
	raw, e := net.Dial("tcp", listener.Addr().String())
	check(t, e)
	peer, e := listener.Accept()
	check(t, e)
	listener.Close()
	done := make(chan error, 1)
	go func() { done <- serve(context.Background(), peer) }()
	return raw, func() error {
		select {
		case e := <-done:
			return e
		case <-time.After(3 * time.Second):
			t.Fatal("credential worker did not stop")
			return nil
		}
	}
}
