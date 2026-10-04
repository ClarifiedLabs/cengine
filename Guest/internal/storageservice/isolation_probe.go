package storageservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
)

// Fixed operations, no caller-selected address/path/key/payload. This is a
// private-worker observation, NOT a ROOT grant or deployed mounted-client proof.
type IsolationRequest struct {
	RequestID     string `json:"requestID"`
	OperationUUID string `json:"operationUUID"`
	ArmDigest     string `json:"armDigest"`
	Challenge     string `json:"challenge"`
}

type IsolationProof struct {
	Request        IsolationRequest `json:"request"`
	WorkerUUID     string           `json:"workerUUID"`
	CaseName       string           `json:"caseName"`
	Store          string           `json:"store"`
	ServiceEpoch   string           `json:"serviceEpoch"`
	Revision       uint64           `json:"revision"`
	RegistrySHA256 string           `json:"registrySHA256"`
	Result         string           `json:"result"`
}

// BindCompatibilityDataListener is called once with the actual bound DATA address,
// never a command-supplied destination. Normal profiles retain no probe endpoint.
func (s *commonService) BindCompatibilityDataListener(address net.Addr) error {
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		return nil
	}
	tcp, ok := address.(*net.TCPAddr)
	if !ok || tcp.IP.IsUnspecified() || tcp.Port == 0 {
		return a.ErrInvalid
	}
	s.isolationMu.Lock()
	defer s.isolationMu.Unlock()
	if s.isolationAddress != "" {
		return a.ErrConflict
	}
	s.isolationAddress = tcp.String()
	return nil
}

type legacyListenerProbe struct {
	peer string
	done chan error
}

// ServeDataConnection preserves the real handler and publishes only after its
// worker cleanup and this accepted descriptor's Close, not on client-side EOF.
func (s *commonService) ServeDataConnection(ctx context.Context, raw net.Conn) error {
	err := s.ServeData(ctx, raw)
	closeErr := raw.Close()
	s.isolationMu.Lock()
	if p := s.isolationPending; p != nil && raw.RemoteAddr().String() == p.peer && raw.LocalAddr().String() == s.isolationAddress {
		select {
		case p.done <- errors.Join(err, closeErr):
		default:
		}
	}
	s.isolationMu.Unlock()
	return err
}

func (s *commonService) rejectLegacyConnection() error {
	// Actual legacy CEngineFS v2 frame, not bootstrap JSON or a guessed error.
	// TLS rejects the framing before legacy token interpretation; no claim of a
	// formerly issued legacy token is made. There is no TLS downgrade fallback.
	// The frozen frame is used only to verify rejection.
	payload := []byte(`{"version":2,"type":"request","request":{"id":1,"op":"handshake","volume":"legacy-probe","token":"0000000000000000000000000000000000000000000000000000000000000000"}}`)
	wire := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(wire, uint32(len(payload)))
	copy(wire[4:], payload)
	deadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	s.isolationMu.Lock()
	address := s.isolationAddress
	if address == "" || s.isolationPending != nil {
		s.isolationMu.Unlock()
		return a.ErrBlocked
	}
	client, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		s.isolationMu.Unlock()
		return err
	}
	pending := &legacyListenerProbe{peer: client.LocalAddr().String(), done: make(chan error, 1)}
	s.isolationPending = pending
	s.isolationMu.Unlock()
	defer client.Close()
	defer func() { s.isolationMu.Lock(); s.isolationPending = nil; s.isolationMu.Unlock() }()
	if err = client.SetDeadline(deadline); err != nil {
		return err
	}
	n, writeErr := client.Write(wire)
	if writeErr != nil || n != len(wire) {
		return a.ErrConflict
	}
	// Only the exact accepted peer on the live endpoint can publish this result.
	// A timeout, EOF, refusal, or internally connected stream is not evidence.
	select {
	case serverErr := <-pending.done:
		var rejected tls.RecordHeaderError
		if !errors.As(serverErr, &rejected) || !bytes.Equal(rejected.RecordHeader[:], wire[:5]) || ctx.Err() != nil {
			return a.ErrConflict
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
