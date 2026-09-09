package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"
)

// Server is a handle to the listening NFS server.
type Server struct {
	Handler
	ID [8]byte
	// ReadTimeout bounds receipt of each RPC record, including idle connections.
	// Zero selects 30 seconds. Cancellation also closes active connections.
	ReadTimeout time.Duration
	context.Context
	receiveMu    sync.Mutex
	receiveBytes int64
}

const maxBufferedRPCBytes int64 = 64 << 20

func (s *Server) reserveRPCBytes(size int64) (func(), error) {
	s.receiveMu.Lock()
	if size < 0 || size > maxBufferedRPCBytes-s.receiveBytes {
		s.receiveMu.Unlock()
		// Close/retry rather than wait while retaining a client's partial frame.
		return nil, errors.New("NFS receive budget exhausted")
	}
	s.receiveBytes += size
	s.receiveMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.receiveMu.Lock()
			s.receiveBytes -= size
			s.receiveMu.Unlock()
		})
	}, nil
}

// RegisterMessageHandler registers a handler for a specific
// XDR procedure.
func RegisterMessageHandler(protocol uint32, proc uint32, handler HandleFunc) error {
	if registeredHandlers == nil {
		registeredHandlers = make(map[registeredHandlerID]HandleFunc)
	}
	for k := range registeredHandlers {
		if k.protocol == protocol && k.proc == proc {
			return errors.New("already registered")
		}
	}
	id := registeredHandlerID{protocol, proc}
	registeredHandlers[id] = handler
	return nil
}

// HandleFunc represents a handler for a specific protocol message.
type HandleFunc func(ctx context.Context, w *response, userHandler Handler) error

// TODO: store directly as a uint64 for more efficient lookups
type registeredHandlerID struct {
	protocol uint32
	proc     uint32
}

var registeredHandlers map[registeredHandlerID]HandleFunc

// Serve listens on the provided listener port for incoming client requests.
func (s *Server) Serve(l net.Listener) error {
	defer l.Close()
	baseCtx := context.Background()
	if s.Context != nil {
		baseCtx = s.Context
	}
	if bytes.Equal(s.ID[:], []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		if _, err := rand.Reader.Read(s.ID[:]); err != nil {
			return err
		}
	}

	var tempDelay time.Duration

	for {
		conn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0
		c := s.newConn(conn)
		go c.serve(baseCtx)
	}
}

func (s *Server) newConn(nc net.Conn) *conn {
	c := &conn{
		Server: s,
		Conn:   nc,
	}
	return c
}

// TODO: keep an immutable map for each server instance to have less
// chance of races.
func (s *Server) handlerFor(prog uint32, proc uint32) HandleFunc {
	for k, v := range registeredHandlers {
		if k.protocol == prog && k.proc == proc {
			return v
		}
	}
	return nil
}

// Serve is a singleton listener paralleling http.Serve
func Serve(l net.Listener, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.Serve(l)
}
