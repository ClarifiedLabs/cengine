package storageserver

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"sync"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

type peer struct {
	consumer       *consumerConnection
	consumerLeaf   [32]byte
	prepareReceive chan struct{} // one reserved progress frame, immutable after handshake
	rootWritten    chan struct{}
	server         *Server
	conn           *tls.Conn
	principal      *a.DataPrincipal
	hello          a.DataHello
	executor       executor
	mu             sync.Mutex
	err            error
	terminal       error
	finished       bool
	inputClosed    bool
	inputStopped   chan struct{}
	done           chan struct{}
	retirement     sync.Once
	retired        chan struct{}
	queue          [][]byte
	bytes          int
	wake           chan struct{}
}

func (p *peer) failure() error { p.mu.Lock(); defer p.mu.Unlock(); return p.err }
func (p *peer) fail(err error) {
	if err == nil {
		err = io.EOF
	}
	p.mu.Lock()
	first := p.err == nil
	if first {
		p.err = err
		p.stopInputLocked()
		close(p.done)
		p.queue = nil
		p.bytes = 0
	}
	p.mu.Unlock()
	if first {
		p.conn.NetConn().Close()
	}
	p.requestRetirement()
}
func (p *peer) requestRetirement() {
	p.mu.Lock()
	hello := p.hello
	err := p.err
	if p.terminal != nil {
		err = p.terminal
	}
	p.mu.Unlock()
	if hello.Binding.Attachment == "" || err == nil {
		return
	}
	p.retirement.Do(func() { go func() { defer close(p.retired); p.server.config.RequestRetirement(hello, err) }() })
}

// Stop admission immediately, but let the bounded writer deliver the terminal
// error reply and partial-mutation events. No filesystem guard waits for delivery.
func (p *peer) stopForStorage(err error) {
	p.mu.Lock()
	if p.terminal == nil {
		p.terminal = err
	}
	p.stopInputLocked()
	p.mu.Unlock()
	p.requestRetirement()
}
func (p *peer) stopInputLocked() {
	if !p.inputClosed {
		p.inputClosed = true
		close(p.inputStopped)
		p.conn.SetReadDeadline(time.Now())
	}
}
func (p *peer) finishWrites() {
	p.mu.Lock()
	p.finished = true
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (p *peer) joinRetirement() {
	p.mu.Lock()
	authenticated := p.principal != nil
	p.mu.Unlock()
	if authenticated {
		p.requestRetirement()
		<-p.retired
	}
}

func frame(message w.Message) ([]byte, error) {
	payload, err := w.Marshal(message)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}
func (p *peer) enqueueMessage(message w.Message) error {
	b, err := frame(message)
	if err != nil {
		return err
	}
	return p.enqueue(b)
}

// Immutable frames may be shared between recipients. Accounting conservatively
// charges the complete frame to each recipient, including the in-flight write.
func (p *peer) enqueue(b []byte) error {
	p.mu.Lock()
	if p.err != nil {
		err := p.err
		p.mu.Unlock()
		return err
	}
	if len(p.queue) >= p.server.config.Limits.WriterMessages || len(b) > p.server.config.Limits.WriterBytes-p.bytes {
		p.mu.Unlock()
		p.fail(ErrOverload)
		return ErrOverload
	}
	p.queue = append(p.queue, b)
	p.bytes += len(b)
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return nil
}
func (p *peer) writeLoop() {
	first := true
	for {
		p.mu.Lock()
		if p.err != nil {
			p.mu.Unlock()
			return
		}
		if len(p.queue) == 0 {
			if p.finished {
				err := p.terminal
				p.mu.Unlock()
				p.fail(err)
				return
			}
			p.mu.Unlock()
			select {
			case <-p.done:
				return
			case <-p.wake:
				continue
			}
		}
		b := p.queue[0]
		// Keep this entry accounted until the write is joined.
		p.mu.Unlock()
		if err := p.conn.SetWriteDeadline(time.Now().Add(p.server.config.Limits.WriteTimeout)); err != nil {
			p.fail(err)
			return
		}
		remaining := b
		for len(remaining) > 0 {
			n, err := p.conn.Write(remaining)
			if err != nil {
				p.fail(err)
				return
			}
			if n <= 0 || n > len(remaining) {
				p.fail(io.ErrShortWrite)
				return
			}
			remaining = remaining[n:]
		}
		p.mu.Lock()
		if p.err != nil {
			p.mu.Unlock()
			return
		}
		p.queue[0] = nil
		p.queue = p.queue[1:]
		p.bytes -= len(b)
		if first {
			first = false
			close(p.rootWritten)
		}
		p.mu.Unlock()
	}
}
