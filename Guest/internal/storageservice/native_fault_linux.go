//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storageservice

import (
	"context"
	"net"
	"sync/atomic"

	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	"golang.org/x/sys/unix"
)

// InstallNativeFault is test-binary-only and construction-time-only. It exposes
// no private authority/resources, identity material, or custom callbacks.
func (s *commonService) InstallNativeFault(plan a.NativeFaultPlan) (*NativeFault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, a.ErrClosed
	}
	if s.controlActive != 0 || s.lifecycleActive != 0 || s.dataActive != 0 || !s.resources.Idle() {
		return nil, a.ErrBusy
	}
	witness, err := s.authority.NewNativeFaultWitness(plan)
	if err != nil {
		return nil, err
	}
	counter, err := s.data.InstallNativeFault(witness)
	if err != nil {
		return nil, err
	}
	return &NativeFault{service: s, witness: witness, counter: counter}, nil
}

// NativeFault exposes only fixed observation and the same real authenticated
// control endpoint. It cannot invoke an authority operation itself.
type NativeFault struct {
	service    *commonService
	witness    *a.NativeFaultWitness
	counter    *m.NativeFaultCounter
	lostActive atomic.Bool
}

func (f *NativeFault) Count() uint32                         { return f.counter.Count() }
func (f *NativeFault) Observation() a.NativeFaultObservation { return f.counter.Observation() }

func (f *NativeFault) ServeControl(ctx context.Context, raw net.Conn) error {
	if raw == nil {
		return ErrConfiguration
	}
	if f.witness.Plan().Stage != a.NativeRetireLostReply {
		return f.service.ServeControl(ctx, raw)
	}
	// One live control exchange owns the drop; another connection cannot steal
	// it with a concurrent handshake/query after durability but before reply.
	if !f.lostActive.CompareAndSwap(false, true) {
		_ = raw.Close()
		return a.ErrBusy
	}
	defer f.lostActive.Store(false)
	return f.service.ServeControl(ctx, &nativeLostReplyConn{raw, f.witness})
}

type nativeLostReplyConn struct {
	net.Conn
	witness *a.NativeFaultWitness
}

func (c *nativeLostReplyConn) Write(b []byte) (int, error) {
	// No encrypted bytes from the selected response are handed to the peer.
	// The preceding real durableRetire, barrier and TLS authentication are not
	// replaced. A new authenticated connection can reconcile and retry.
	if c.witness.DropReply() {
		_ = c.Conn.Close()
		return 0, unix.EIO
	}
	return c.Conn.Write(b)
}

func (s *LifecycleService) InstallNativeFault(plan a.NativeFaultPlan) (*NativeFault, error) {
	if !s.valid() {
		return nil, ErrConfiguration
	}
	return s.owner.InstallNativeFault(plan)
}
