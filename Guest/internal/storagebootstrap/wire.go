// Package storagebootstrap is a private host-controller channel, not activation.
// No key import, export, general signing, filesystem path or network address is a wire operation.
package storagebootstrap

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaximumPayload = 64 << 10 // ordinary private lifecycle frame

var ErrProtocol = errors.New("storagebootstrap: invalid private channel")

func canonical(data []byte, value any) error {
	if len(data) == 0 || len(data) > MaximumPayload {
		return ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return ErrProtocol
	}
	b, err := canonicalBytes(value)
	if err != nil || !bytes.Equal(data, b) {
		return ErrProtocol
	}
	return nil
}

// Normalize typed structs recursively, without ever converting uint64 via Double.
func canonicalBytes(value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var tree any
	if err = decoder.Decode(&tree); err != nil {
		return nil, err
	}
	return json.Marshal(tree)
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaximumPayload {
		return nil, ErrProtocol
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func WriteFrame(w io.Writer, value any) error {
	b, err := canonicalBytes(value)
	if err != nil {
		return err
	}
	if len(b) == 0 || len(b) > MaximumPayload {
		return ErrProtocol
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	for _, part := range [][]byte{h[:], b} {
		for len(part) > 0 {
			n, e := w.Write(part)
			if e != nil {
				return e
			}
			if n <= 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
