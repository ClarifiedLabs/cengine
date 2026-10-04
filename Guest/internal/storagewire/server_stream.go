package storagewire

import (
	"encoding/binary"
	"encoding/json"
	"io"
)

// ServerMessage is the closed post-handshake FIFO union. Handshake messages are
// read with ReadFrame using their expected concrete type, in handshake order.
type ServerMessage interface {
	Message
	serverMessage()
}

func (*Reply) serverMessage() {}
func (*Event) serverMessage() {}

// ReadServerFrame reads an interleaved reply or invalidation, so clients never
// need a permissive JSON decoder or their own envelope definitions. The distinct
// required event_sequence field discriminates events; mixed shapes fail strict
// validation. The caller still verifies stream sequences, correlation and volume.
func ReadServerFrame(r io.Reader) (ServerMessage, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrame {
		return nil, invalid("frame length")
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	if err := checkJSON(b); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, invalid("server frame object")
	}
	var m ServerMessage = &Reply{}
	if _, ok := fields["event_sequence"]; ok {
		m = &Event{}
	}
	// No field from staging is published without the complete strict decoder.
	if err := Unmarshal(b, m); err != nil {
		return nil, err
	}
	return m, nil
}
