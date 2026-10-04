//go:build linux

package storageworker

import (
	"errors"
	"os"
	"time"
)

// Exchange keeps an in-flight final ACK authenticatable until Receive joins.
// Waitid still pins the zombie; the reaper cannot close the channel or recycle
// its numeric PID during this exchange. A transport failure is never death proof.
func (o *Owner) Exchange(payload []byte, deadline time.Time) ([]byte, error) {
	return o.ExchangeWithGate(payload, deadline, func(send func() error) error { return send() })
}

// ExchangeWithGate preserves the same reaping fence while PID1 serializes only
// the handoff send against session closure. The gate cannot manufacture a reply.
func (o *Owner) ExchangeWithGate(payload []byte, deadline time.Time, gate func(func() error) error) ([]byte, error) {
	o.commandMu.Lock()
	defer o.commandMu.Unlock()
	if o.awaitingReply {
		return nil, ErrProtocol // never send over an unresolved exchange
	}
	if err := o.SetDeadline(deadline); err != nil {
		return nil, err
	}
	sent := false
	if err := gate(func() error {
		if sent {
			return ErrProtocol
		}
		if err := o.Send(payload); err != nil {
			return err
		}
		sent = true
		return nil
	}); err != nil {
		return nil, err
	}
	if !sent {
		return nil, ErrProtocol
	}
	return o.receiveReplyLocked()
}

// ReceivePending never sends. commandMu fences the sole reaper throughout the
// native credential check, just as Exchange does. A reaped/closed channel fails
// closed; an expired deadline alone retains the outstanding receive.
func (o *Owner) ReceivePending(deadline time.Time) ([]byte, error) {
	o.commandMu.Lock()
	defer o.commandMu.Unlock()
	if !o.awaitingReply {
		return nil, ErrProtocol
	}
	if err := o.SetDeadline(deadline); err != nil {
		return nil, err
	}
	return o.receiveReplyLocked()
}

func (o *Owner) receiveReplyLocked() ([]byte, error) {
	raw, err := o.Receive()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			o.awaitingReply = true
			return nil, &ReplyPendingError{}
		}
		return nil, err
	}
	o.awaitingReply = false
	if err := o.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return raw, nil
}
