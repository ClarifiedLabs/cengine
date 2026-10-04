package storageclient

import (
	"bytes"
	w "dev.cengine/guest/internal/storagewire"
)

func (c *Client) writeRequest(req *w.Request) error {
	prepare, ok := req.Body.(w.PrepareRequest)
	if c.prepareCompatibility == nil || !ok || prepare.Operation() != w.OpPrepare || prepare.Action != w.BeginCopy {
		return w.WriteFrame(c.conn, req)
	}
	if req.ValidateBinding(c.authority.Binding) != nil || c.prepareCompatibility.ClaimPartialData(c.authority, c.localCertificateDER) != nil {
		return ErrProtocol
	}
	// Serialize this actual internally sequenced request with the real frame codec.
	var frame bytes.Buffer
	if err := w.WriteFrame(&frame, req); err != nil {
		return err
	}
	// One write only: a short/error write does not become evidence or a retry.
	n, err := c.conn.Write(frame.Bytes()[:5])
	if err != nil || n != 5 {
		return ErrProtocol
	}
	err = c.prepareCompatibility.PartialDataWritten(req.Sequence)
	// Direct underlying close is bounded; never wait for TLS close_notify.
	_ = c.conn.NetConn().Close()
	return err
}
