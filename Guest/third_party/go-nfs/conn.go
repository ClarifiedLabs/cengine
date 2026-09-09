package nfs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	xdr2 "github.com/rasky/go-xdr/xdr2"
	"github.com/willscott/go-nfs-client/nfs/rpc"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

var (
	// ErrInputInvalid is returned when input cannot be parsed
	ErrInputInvalid = errors.New("invalid input")
	// ErrAlreadySent is returned when writing a header/status multiple times
	ErrAlreadySent = errors.New("response already started")
)

// ResponseCode is a combination of accept_stat and reject_stat.
type ResponseCode uint32

// ResponseCode Codes
const (
	ResponseCodeSuccess ResponseCode = iota
	ResponseCodeProgUnavailable
	ResponseCodeProcUnavailable
	ResponseCodeGarbageArgs
	ResponseCodeSystemErr
	ResponseCodeRPCMismatch
	ResponseCodeAuthError
)

type conn struct {
	*Server
	writeSerializer chan []byte
	net.Conn
}

func (c *conn) serve(ctx context.Context) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer c.Close()
	stopClose := context.AfterFunc(connCtx, func() { _ = c.Close() })
	defer stopClose()
	c.writeSerializer = make(chan []byte, 1)
	go func() {
		c.serializeWrites(connCtx)
		cancel() // release a queued response if the peer stops reading
	}()

	bio := bufio.NewReader(c.Conn)
	timeout := c.Server.ReadTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	for {
		if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return
		}
		w, err := c.readRequestHeader(connCtx, bio)
		if err != nil {
			if err == io.EOF {
				// Clean close.
				c.Close()
				return
			}
			return
		}
		Log.Tracef("request: %v", w.req)
		err = c.handle(connCtx, w)
		respErr := w.finish(connCtx)
		w.releaseRequestBody()
		if err != nil {
			Log.Errorf("error handling req: %v", err)
			// failure to handle at a level needing to close the connection.
			c.Close()
			return
		}
		if respErr != nil {
			Log.Errorf("error sending response: %v", respErr)
			c.Close()
			return
		}
	}
}

func (c *conn) serializeWrites(ctx context.Context) {
	// todo: maybe don't need the extra buffer
	writer := bufio.NewWriter(c.Conn)
	var fragmentBuf [4]byte
	var fragmentInt uint32
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-c.writeSerializer:
			if !ok {
				return
			}
			timeout := c.Server.ReadTimeout
			if timeout <= 0 {
				timeout = 30 * time.Second
			}
			if err := c.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
				return
			}
			// prepend the fragmentation header
			fragmentInt = uint32(len(msg))
			fragmentInt |= (1 << 31)
			binary.BigEndian.PutUint32(fragmentBuf[:], fragmentInt)
			n, err := writer.Write(fragmentBuf[:])
			if n < 4 || err != nil {
				return
			}
			n, err = writer.Write(msg)
			if err != nil {
				return
			}
			if n < len(msg) {
				panic("todo: ensure writes complete fully.")
			}
			if err = writer.Flush(); err != nil {
				return
			}
		}
	}
}

// Handle a request. errors from this method indicate a failure to read or
// write on the network stream, and trigger a disconnection of the connection.
func (c *conn) handle(ctx context.Context, w *response) error {
	handler := c.Server.handlerFor(w.req.Header.Prog, w.req.Header.Proc)
	if handler == nil {
		Log.Errorf("No handler for %d.%d", w.req.Header.Prog, w.req.Header.Proc)
		if err := w.drain(ctx); err != nil {
			return err
		}
		return c.err(ctx, w, &ResponseCodeProcUnavailableError{})
	}
	invoke := func() error { return handler(ctx, w, c.Server.Handler) }
	var appError error
	if scoped, ok := c.Server.Handler.(RequestIdentityHandler); ok && w.req.Header.Proc != 0 {
		identity, err := ParseAuthSys(w.req.Header.Cred)
		if err != nil || w.req.Header.Verf.Flavor != 0 || len(w.req.Header.Verf.Body) != 0 {
			if err := w.drain(ctx); err != nil {
				return err
			}
			// RFC 5531: MSG_DENIED, AUTH_ERROR, AUTH_BADCRED (not accept_stat).
			w.responded = true
			if err := w.writeXdrHeader(); err != nil {
				return err
			}
			return xdr.Write(w.writer, [3]uint32{1, 1, 1})
		}
		appError = scoped.WithIdentity(ctx, identity, invoke)
	} else {
		appError = invoke()
	}
	if drainErr := w.drain(ctx); drainErr != nil {
		return drainErr
	}
	if appError != nil && !w.responded {
		if err := c.err(ctx, w, appError); err != nil {
			return err
		}
	}
	if !w.responded {
		Log.Errorf("Handler did not indicate response status via writing or erroring")
		if err := c.err(ctx, w, &ResponseCodeSystemError{}); err != nil {
			return err
		}
	}
	return nil
}

func (c *conn) err(ctx context.Context, w *response, err error) error {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	if w.err == nil {
		w.err = err
	}

	if w.responded {
		return nil
	}

	rpcErr := w.errorFmt(err)
	if writeErr := w.writeHeader(rpcErr.Code()); writeErr != nil {
		return writeErr
	}

	body, _ := rpcErr.MarshalBinary()
	return w.Write(body)
}

type request struct {
	xid uint32
	rpc.Header
	Body io.Reader
}

func (r *request) String() string {
	if r.Header.Prog == nfsServiceID {
		return fmt.Sprintf("RPC #%d (nfs.%s)", r.xid, NFSProcedure(r.Header.Proc))
	} else if r.Header.Prog == mountServiceID {
		return fmt.Sprintf("RPC #%d (mount.%s)", r.xid, MountProcedure(r.Header.Proc))
	}
	return fmt.Sprintf("RPC #%d (%d.%d)", r.xid, r.Header.Prog, r.Header.Proc)
}

type response struct {
	*conn
	writer      *bytes.Buffer
	responded   bool
	err         error
	errorFmt    func(error) RPCError
	req         *request
	releaseBody func()
}

func (w *response) releaseRequestBody() {
	if w.releaseBody != nil {
		w.req.Body = nil
		w.releaseBody()
		w.releaseBody = nil
	}
}

func (w *response) writeXdrHeader() error {
	err := xdr.Write(w.writer, &w.req.xid)
	if err != nil {
		return err
	}
	respType := uint32(1)
	err = xdr.Write(w.writer, &respType)
	if err != nil {
		return err
	}
	return nil
}

func (w *response) writeHeader(code ResponseCode) error {
	if w.responded {
		return ErrAlreadySent
	}
	w.responded = true
	if err := w.writeXdrHeader(); err != nil {
		return err
	}

	status := rpc.MsgAccepted
	if code == ResponseCodeAuthError || code == ResponseCodeRPCMismatch {
		status = rpc.MsgDenied
	}

	err := xdr.Write(w.writer, &status)
	if err != nil {
		return err
	}

	if status == rpc.MsgAccepted {
		// Write opaque_auth header.
		err = xdr.Write(w.writer, &rpc.AuthNull)
		if err != nil {
			return err
		}
	}

	return xdr.Write(w.writer, &code)
}

// Write a response to an xdr message
func (w *response) Write(dat []byte) error {
	if !w.responded {
		if err := w.writeHeader(ResponseCodeSuccess); err != nil {
			return err
		}
	}

	acc := 0
	for acc < len(dat) {
		n, err := w.writer.Write(dat[acc:])
		if err != nil {
			return err
		}
		acc += n
	}
	return nil
}

// drain reads the rest of the request frame if not consumed by the handler.
func (w *response) drain(ctx context.Context) error {
	if reader, ok := w.req.Body.(*io.LimitedReader); ok {
		if reader.N == 0 {
			return nil
		}
		// todo: wrap body in a context reader.
		_, err := io.CopyN(io.Discard, w.req.Body, reader.N)
		if err == nil || err == io.EOF {
			return nil
		}
		return err
	}
	return io.ErrUnexpectedEOF
}

func (w *response) finish(ctx context.Context) error {
	select {
	case w.conn.writeSerializer <- w.writer.Bytes():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *conn) readRequestHeader(ctx context.Context, reader *bufio.Reader) (w *response, err error) {
	fragment, err := xdr.ReadUint32(reader)
	if err != nil {
		if xdrErr, ok := err.(*xdr2.UnmarshalError); ok {
			if xdrErr.Err == io.EOF {
				return nil, io.EOF
			}
		}
		return nil, err
	}
	if fragment&(1<<31) == 0 {
		Log.Warnf("Warning: haven't implemented fragment reconstruction.\n")
		return nil, ErrInputInvalid
	}
	reqLen := fragment - uint32(1<<31)
	// A maximum-size WRITE plus bounded RPC/XDR framing and credentials.
	if reqLen < 40 || reqLen > MaxRead+4096 {
		return nil, ErrInputInvalid
	}

	r := io.LimitedReader{R: reader, N: int64(reqLen)}

	xid, err := xdr.ReadUint32(&r)
	if err != nil {
		return nil, err
	}
	reqType, err := xdr.ReadUint32(&r)
	if err != nil {
		return nil, err
	}
	if reqType != 0 { // 0 = request, 1 = response
		return nil, ErrInputInvalid
	}

	req := request{
		xid,
		rpc.Header{},
		&r,
	}
	// Bound opaque_auth before allocation, not merely after decoding it.
	for _, field := range []*uint32{&req.Header.Rpcvers, &req.Header.Prog, &req.Header.Vers, &req.Header.Proc} {
		if err = binary.Read(&r, binary.BigEndian, field); err != nil {
			return nil, err
		}
	}
	for _, auth := range []*rpc.Auth{&req.Header.Cred, &req.Header.Verf} {
		var length uint32
		if err = binary.Read(&r, binary.BigEndian, &auth.Flavor); err != nil {
			return nil, err
		}
		if err = binary.Read(&r, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		if length > 400 {
			return nil, ErrInputInvalid
		}
		body := make([]byte, (length+3)&^3)
		if _, err = io.ReadFull(&r, body); err != nil {
			return nil, err
		}
		auth.Body = body[:length]
	}

	// Receive the entire bounded record before entering an identity scope.
	// Slow clients must never occupy the finite credential-worker slots while
	// withholding procedure arguments. Reserve against a server-wide memory
	// budget before allocating, so many incomplete records cannot exhaust RAM.
	release, err := c.Server.reserveRPCBytes(r.N)
	if err != nil {
		return nil, err
	}
	body := make([]byte, r.N)
	if _, err := io.ReadFull(&r, body); err != nil {
		release()
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	req.Body = &io.LimitedReader{R: bytes.NewReader(body), N: int64(len(body))}
	w = &response{
		conn:     c,
		req:      &req,
		errorFmt: basicErrorFormatter,
		// TODO: use a pool for these.
		writer:      bytes.NewBuffer([]byte{}),
		releaseBody: release,
	}
	return w, nil
}
