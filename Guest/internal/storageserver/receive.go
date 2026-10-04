package storageserver

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	w "dev.cengine/guest/internal/storagewire"
)

// setReadDeadline cannot undo a concurrent stopInputLocked deadline.
func (p *peer) setReadDeadline(deadline time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inputClosed {
		return context.Canceled
	}
	return p.conn.SetReadDeadline(deadline)
}

// readRequest owns no payload memory while idle. Once the first byte arrives,
// one absolute deadline covers header completion, capacity wait, and payload.
// Success transfers the receive reservation to the request executor; all errors
// release it here. The strict wire decoder still validates the complete payload.
func (p *peer) readRequest() (request w.Request, err error) {
	if err = p.setReadDeadline(time.Time{}); err != nil {
		return request, err
	}
	var header [4]byte
	if _, err = io.ReadFull(p.conn, header[:1]); err != nil {
		return request, err
	}
	deadline := time.Now().Add(p.server.config.Limits.ReadTimeout)
	if err = p.setReadDeadline(deadline); err != nil {
		return request, err
	}
	if _, err = io.ReadFull(p.conn, header[1:]); err != nil {
		return request, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > w.MaxFrame {
		return request, fmt.Errorf("%w: frame length", w.ErrInvalid)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case p.receivePool() <- struct{}{}:
	case <-p.inputStopped:
		return request, context.Canceled
	case <-timer.C:
		return request, context.DeadlineExceeded
	}
	defer func() {
		if err != nil {
			<-p.receivePool()
		}
	}()
	// A ready slot must not win a select and revive an expired frame deadline.
	if !time.Now().Before(deadline) {
		return request, context.DeadlineExceeded
	}
	payload := make([]byte, int(n))
	if _, err = io.ReadFull(p.conn, payload); err != nil {
		return request, err
	}
	err = w.Unmarshal(payload, &request)
	return request, err
}
