package storagecontrol

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

type pkiFixture struct {
	t                                      *testing.T
	authority                              *a.Authority
	bootstrap                              ed25519.PrivateKey
	issuer                                 p.Issuer
	controllerKey, serverKey, successorKey p.Key
	now                                    time.Time
}

func pkiPin(t *testing.T, k p.Key) p.Fingerprint {
	t.Helper()
	v, err := k.Fingerprint()
	must(t, err)
	return v
}
func (f *pkiFixture) issue(k p.Key, b p.Binding) p.Identity {
	f.t.Helper()
	csr, err := k.CSR(b)
	must(f.t, err)
	var c p.Certificate
	switch b.Role() {
	case p.ServerRole:
		c, err = f.issuer.IssueServer(csr, b, f.now, time.Hour)
	case p.ControllerRole:
		c, err = f.issuer.IssueController(csr, b, f.now, time.Hour)
	default:
		c, err = f.issuer.IssueAttachment(csr, b, f.now, time.Hour)
	}
	must(f.t, err)
	identity, err := c.WithKey(k)
	must(f.t, err)
	return identity
}
func servePKI(t *testing.T, s interface {
	Serve(context.Context, net.Conn) error
}) (net.Conn, *testWorker) {
	t.Helper()
	left, right := tcpPair(t)
	worker := &testWorker{done: make(chan struct{})}
	go func() { defer close(worker.done); worker.err = s.Serve(context.Background(), left) }()
	t.Cleanup(func() { right.Close(); worker.wait(t) })
	return right, worker
}
