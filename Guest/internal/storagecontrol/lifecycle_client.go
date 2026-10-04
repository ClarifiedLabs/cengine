package storagecontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

// LifecycleClientConfig admits only immutable PKI credentials, exact server pin,
// and full expected incarnation. No caller TLS policy, signer or principal seam.
type LifecycleClientConfig struct {
	Identity   p.Identity
	ServerRoot p.Root
	ServerKey  p.Fingerprint
	Hello      LifecycleHello
	Limits     Limits
}

// LifecycleClient has one bounded ordered exchange and never reconnects or caches
// a receipt. Only an authenticated BUSY takeover is retried on the same session;
// connection failure leaves mutations uncertain.
type LifecycleClient struct {
	conn   *tls.Conn
	raw    net.Conn
	config LifecycleClientConfig
	server p.Binding
	memory budget
	gate   chan struct{}
	closed chan struct{}
	once   sync.Once
	id     uint64
}

// NewLifecycleClient owns raw even on failure. Neither constructor dials/listens.
func NewLifecycleClient(ctx context.Context, raw net.Conn, c LifecycleClientConfig) (_ *LifecycleClient, err error) {
	defer func() {
		if err != nil && raw != nil {
			raw.Close()
		}
	}()
	if ctx == nil || raw == nil || !lifecycleHelloValid(c.Hello) {
		return nil, ErrConfiguration
	}
	c.Limits, err = lifecycleLimits(c.Limits)
	if err != nil {
		return nil, err
	}
	controller, e := p.NewControllerBinding(p.StoreID(c.Hello.Identity.Store), p.ControllerEpoch(c.Hello.ControllerEpoch))
	if e != nil || c.Identity.Certificate().Binding() != controller {
		return nil, ErrConfiguration
	}
	server, e := p.NewServerBinding(p.StoreID(c.Hello.Identity.Store), p.ServiceEpoch(c.Hello.ServiceEpoch))
	if e != nil {
		return nil, ErrConfiguration
	}
	conn, e := p.NewControllerTLSClient(raw, c.Identity, c.ServerRoot, server, c.ServerKey)
	if e != nil {
		return nil, ErrConfiguration
	}
	client := &LifecycleClient{conn: conn, raw: raw, config: c, server: server, gate: make(chan struct{}, 1), closed: make(chan struct{})}
	hctx, cancel := context.WithTimeout(ctx, c.Limits.HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(hctx, func() { client.Close() })
	defer stop()
	if err = conn.SetDeadline(time.Now().Add(c.Limits.HandshakeTimeout)); err != nil {
		return nil, err
	}
	if err = conn.HandshakeContext(hctx); err != nil {
		return nil, err
	}
	if err = p.VerifyServer(conn.ConnectionState(), c.ServerRoot, server, c.ServerKey); err != nil {
		return nil, err
	}
	if err = writeFrame(conn, c.Hello, 4096, &client.memory); err != nil {
		return nil, err
	}
	var reply LifecycleHello
	if err = readFrame(conn, &reply, 4096, &client.memory); err != nil {
		return nil, err
	}
	if reply != c.Hello {
		return nil, ErrProtocol
	}
	// Explicitly win the cancellation handoff before publishing the client.
	// A deferred stop alone could lose after the final Err check and return a
	// transport that the already-started callback is asynchronously closing.
	if !stop() {
		return nil, hctx.Err()
	}
	if err = hctx.Err(); err != nil {
		return nil, err
	}
	return client, nil
}
func (c *LifecycleClient) Close() error {
	var err error
	c.once.Do(func() { close(c.closed); err = c.raw.Close() })
	return err
}
func (c *LifecycleClient) grantMatches(g a.LifecycleGrant) bool {
	leaf, err := x509.ParseCertificate(c.config.Identity.Certificate().DER())
	if err != nil {
		return false
	}
	pin, err := a.PublicKeyFingerprint(leaf.PublicKey)
	return err == nil && g.Validate() == nil && g.Identity == c.config.Hello.Identity && lifecycleEpoch(g) == c.config.Hello.ControllerEpoch && g.NewKey == pin
}

// Result performs fresh authenticated IO with the actual Authority, including on
// its still-live terminal seal. The nonce must be ROOT's fresh 32-byte challenge;
// the adapter correlates it, but is not a challenge issuer or replay database.
func (c *LifecycleClient) Result(ctx context.Context, grant a.LifecycleGrant, nonce []byte) (a.LifecycleReceipt, error) {
	if !c.grantMatches(grant) || len(nonce) != 32 {
		return a.LifecycleReceipt{}, ErrProtocol
	}
	r, err := c.call(ctx, lifecycleRequest{Result: &lifecycleResultRequest{grant, bytes.Clone(nonce)}})
	if err != nil {
		return a.LifecycleReceipt{}, err
	}
	return *r.Receipt, nil
}

// ServiceResult performs fresh authenticated IO for the current live open. ROOT
// supplies a fresh nonce; this client never substitutes a cached applied receipt.
func (c *LifecycleClient) ServiceResult(ctx context.Context, grant a.LifecycleGrant, nonce []byte) (a.LifecycleServiceResult, error) {
	if !c.grantMatches(grant) || grant.Operation == a.LifecycleRetire || len(nonce) != 32 {
		return a.LifecycleServiceResult{}, ErrProtocol
	}
	r, err := c.call(ctx, lifecycleRequest{ServiceResult: &lifecycleResultRequest{grant, bytes.Clone(nonce)}})
	if err != nil {
		return a.LifecycleServiceResult{}, err
	}
	return *r.ServiceResult, nil
}

func (c *LifecycleClient) Takeover(ctx context.Context, grant a.SignedLifecycleGrant) (a.Controller, error) {
	if !c.grantMatches(grant.Grant) || grant.Grant.Operation != a.LifecycleTakeover || len(grant.Signature) != 64 {
		return a.Controller{}, ErrProtocol
	}
	if ctx == nil {
		return a.Controller{}, ErrConfiguration
	}
	// One absolute budget includes every exchange, gate wait and retry delay.
	// call still owns the gate per exchange: DATA and other session requests
	// must remain able to progress while an IO obligation completes.
	opctx, cancel := context.WithTimeout(ctx, c.config.Limits.OperationTimeout)
	defer cancel()
	grant.Signature = bytes.Clone(grant.Signature)
	for {
		r, err := c.call(opctx, lifecycleRequest{Takeover: &grant})
		if err == nil {
			return *r.Controller, nil
		}
		if opctx.Err() != nil {
			return a.Controller{}, opctx.Err()
		}
		remote, ok := err.(*RemoteError)
		if !ok || remote.Code != Busy {
			return a.Controller{}, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-opctx.Done():
			timer.Stop()
			return a.Controller{}, opctx.Err()
		case <-c.closed:
			timer.Stop()
			return a.Controller{}, ErrClosed
		case <-timer.C:
		}
	}
}
func (c *LifecycleClient) Retire(ctx context.Context, grant a.SignedLifecycleGrant) error {
	if !c.grantMatches(grant.Grant) || grant.Grant.Operation != a.LifecycleRetire || len(grant.Signature) != 64 {
		return ErrProtocol
	}
	grant.Signature = bytes.Clone(grant.Signature)
	_, err := c.call(ctx, lifecycleRequest{Retire: &grant})
	return err
}
func (c *LifecycleClient) call(ctx context.Context, q lifecycleRequest) (r lifecycleResponse, err error) {
	if ctx == nil {
		return r, ErrConfiguration
	}
	// The configured timeout includes waiting for the single in-flight slot.
	opctx, cancel := context.WithTimeout(ctx, c.config.Limits.OperationTimeout)
	defer cancel()
	select {
	case c.gate <- struct{}{}:
	case <-opctx.Done():
		return r, opctx.Err()
	case <-c.closed:
		return r, ErrClosed
	}
	defer func() { <-c.gate }()
	select {
	case <-c.closed:
		return r, ErrClosed
	default:
	}
	if err = opctx.Err(); err != nil {
		return r, err
	}
	// Refuse only at counter exhaustion, before increment could wrap to zero.
	if c.id == ^uint64(0) {
		c.Close()
		return r, ErrLimit
	}
	stop := context.AfterFunc(opctx, func() { c.Close() })
	defer stop()
	defer func() {
		if err != nil {
			if _, ok := err.(*RemoteError); !ok {
				c.Close()
			}
		}
	}()
	if err = p.VerifyServer(c.conn.ConnectionState(), c.config.ServerRoot, c.server, c.config.ServerKey); err != nil {
		return r, err
	}
	c.id++
	q.ID = c.id
	if err = c.conn.SetWriteDeadline(time.Now().Add(c.config.Limits.WriteTimeout)); err != nil {
		return r, err
	}
	if err = writeFrame(c.conn, q, c.config.Limits.RequestBytes, &c.memory); err != nil {
		return r, err
	}
	if err = c.conn.SetReadDeadline(time.Now().Add(c.config.Limits.ReadTimeout)); err != nil {
		return r, err
	}
	if err = readFrame(c.conn, &r, c.config.Limits.ResponseBytes, &c.memory); err != nil {
		return r, err
	}
	if err = opctx.Err(); err != nil {
		return r, err
	}
	if r.ID != q.ID {
		return lifecycleResponse{}, ErrProtocol
	}
	n := 0
	if r.Receipt != nil {
		n++
	}
	if r.ServiceResult != nil {
		n++
	}
	if r.Controller != nil {
		n++
	}
	if r.OK != nil {
		n++
	}
	if r.Error != "" {
		if !validCode(r.Error) || n != 0 {
			return lifecycleResponse{}, ErrProtocol
		}
		return r, &RemoteError{r.Error}
	}
	if n != 1 {
		return lifecycleResponse{}, ErrProtocol
	}
	switch {
	case q.ServiceResult != nil:
		v := r.ServiceResult
		if v == nil || v.Validate() != nil || v.Grant != q.ServiceResult.Grant || v.Identity != c.config.Hello.Identity || !bytes.Equal(v.Nonce, q.ServiceResult.Nonce) || v.ServiceEpoch != c.config.Hello.ServiceEpoch || v.ControllerEpoch != c.config.Hello.ControllerEpoch || v.ControllerKey != q.ServiceResult.Grant.NewKey {
			return lifecycleResponse{}, ErrProtocol
		}
	case q.Result != nil:
		if r.Receipt == nil || r.Receipt.Validate() != nil || r.Receipt.Grant != q.Result.Grant || !bytes.Equal(r.Receipt.Nonce, q.Result.Nonce) || r.Receipt.ServiceEpoch != c.config.Hello.ServiceEpoch {
			return lifecycleResponse{}, ErrProtocol
		}
	case q.Takeover != nil:
		if r.Controller == nil || r.Controller.Epoch != lifecycleEpoch(q.Takeover.Grant) || r.Controller.Key != q.Takeover.Grant.NewKey {
			return lifecycleResponse{}, ErrProtocol
		}
	case q.Retire != nil:
		if r.OK == nil {
			return lifecycleResponse{}, ErrProtocol
		}
	default:
		return lifecycleResponse{}, ErrProtocol
	}
	return r, nil
}
