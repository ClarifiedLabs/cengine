package storagecontrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"sync"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

// Client has one ordered in-flight call, no reconnect and no replay. A failed
// exchange closes the connection. Only the caller can retry immutable operation
// IDs on a NEW authenticated connection after reconciling authority state.
type Client struct {
	conn   *tls.Conn
	raw    net.Conn
	limits Limits
	memory budget
	gate   chan struct{}
	once   sync.Once
	closed chan struct{}
	id     uint64
	role   Role
	hello  Hello
	policy workloadPolicy
}

// conn is constructed internally over raw; never accept a caller's TLS policy or
// preauthenticated connection through this private handshake path.
func newClientOwned(ctx context.Context, raw net.Conn, c workloadClientConfig, conn *tls.Conn, policy workloadPolicy) (_ *Client, err error) {
	if raw == nil {
		return nil, ErrConfiguration
	}
	defer func() {
		if err != nil {
			raw.Close()
		}
	}()
	if ctx == nil || conn == nil || !policy.validHello(c.Hello) {
		return nil, ErrConfiguration
	}
	if _, ok := raw.(*tls.Conn); ok {
		return nil, ErrConfiguration
	}
	key, e := hex.DecodeString(string(c.ServerKey))
	if e != nil || len(key) != 32 || hex.EncodeToString(key) != string(c.ServerKey) {
		return nil, ErrConfiguration
	}
	l, err := limits(c.Limits)
	if err != nil {
		return nil, err
	}
	client := &Client{conn: conn, raw: raw, limits: l, gate: make(chan struct{}, 1), closed: make(chan struct{}), role: c.Hello.Role, hello: c.Hello, policy: policy}
	hctx, cancel := context.WithTimeout(ctx, l.HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(hctx, func() { raw.Close() })
	defer stop()
	if err = conn.SetDeadline(time.Now().Add(l.HandshakeTimeout)); err != nil {
		return nil, err
	}
	if err = conn.HandshakeContext(hctx); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.DidResume || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return nil, a.ErrUnauthorized
	}
	fp, e := a.PublicKeyFingerprint(state.PeerCertificates[0].PublicKey)
	if e != nil || fp != c.ServerKey {
		return nil, a.ErrUnauthorized
	}
	if !validLeaf(state.PeerCertificates[0], x509.ExtKeyUsageServerAuth) {
		return nil, a.ErrUnauthorized
	}
	if err = writeFrame(conn, c.Hello, 4096, &client.memory); err != nil {
		return nil, err
	}
	var hello HelloReply
	if err = readFrame(conn, &hello, 4096, &client.memory); err != nil {
		return nil, err
	}
	if hello.Version != policy.version() || hello.Store != c.Hello.Store || hello.ServiceEpoch != c.Hello.ServiceEpoch || !policy.matchesIdentity(hello.LifecycleIdentity) {
		return nil, ErrProtocol
	}
	if hello.Error != "" {
		if !validCode(hello.Error) {
			return nil, ErrProtocol
		}
		return nil, &RemoteError{hello.Error}
	}
	if err = hctx.Err(); err != nil {
		return nil, err
	}
	return client, nil
}
func (c *Client) Close() error {
	var err error
	c.once.Do(func() { close(c.closed); err = c.raw.Close() })
	return err
}
func (c *Client) Call(ctx context.Context, q Request) (r Response, err error) {
	if ctx == nil || q.ID != 0 {
		return r, ErrProtocol
	}
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return r, ctx.Err()
	case <-c.closed:
		return r, ErrClosed
	}
	defer func() { <-c.gate }()
	select {
	case <-c.closed:
		return r, ErrClosed
	default:
	}
	if err = ctx.Err(); err != nil {
		return r, err
	}
	q.ID = c.id + 1
	if !q.valid() {
		return r, ErrProtocol
	}
	if c.role != Controller || q.Takeover != nil {
		return r, &RemoteError{Unauthorized}
	}
	callctx, cancel := context.WithTimeout(ctx, c.limits.OperationTimeout)
	defer cancel()
	stop := context.AfterFunc(callctx, func() { c.Close() })
	defer stop()
	defer func() {
		if err != nil {
			if _, ok := err.(*RemoteError); !ok {
				c.Close()
			}
		}
	}()
	c.id = q.ID
	if err = c.conn.SetWriteDeadline(time.Now().Add(c.limits.WriteTimeout)); err != nil {
		return r, err
	}
	if err = writeFrame(c.conn, q, c.limits.RequestBytes, &c.memory); err != nil {
		return r, err
	}
	if err = c.conn.SetReadDeadline(time.Now().Add(c.limits.ReadTimeout)); err != nil {
		return r, err
	}
	if err = readFrame(c.conn, &r, c.limits.ResponseBytes, &c.memory); err != nil {
		return Response{}, err
	}
	if !r.validForPolicy(q, c.policy) || (r.Snapshot != nil && (r.Snapshot.Store.ID != c.hello.Store || r.Snapshot.Epoch != c.hello.ServiceEpoch)) {
		return Response{}, ErrProtocol
	}
	if r.Error != "" {
		return r, &RemoteError{r.Error}
	}
	return r, nil
}
