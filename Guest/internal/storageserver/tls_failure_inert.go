//go:build !cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat

package storageserver

import (
	"context"
	"crypto/tls"
	a "dev.cengine/guest/internal/storageauthority"
	"net"
)

// WithTLSFailureObservation is inert outside the exclusive full-compat profile.
func WithTLSFailureObservation(ctx context.Context) context.Context { return ctx }

type tlsFailureReadObserver struct{}

func (*Server) observeTLSFailure(_ context.Context, raw net.Conn) (net.Conn, *tlsFailureReadObserver) {
	return raw, nil
}
func (*tlsFailureReadObserver) failure(err error) error { return err }
func (*tlsFailureReadObserver) stop()                   {}

func (*tlsFailureReadObserver) peerFailure(_ tls.ConnectionState, _ a.DataHello, err error) error {
	return err
}
