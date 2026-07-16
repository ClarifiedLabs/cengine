//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPortDatagramFrameRoundTrips(t *testing.T) {
	var frame bytes.Buffer
	payload := []byte("udp-response")
	if err := writePortDatagram(&frame, payload); err != nil {
		t.Fatal(err)
	}
	got, err := readPortDatagram(&frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("readPortDatagram() = %q, want %q", got, payload)
	}
}

func TestPortDatagramFrameRejectsOversizePayload(t *testing.T) {
	var frame bytes.Buffer
	if err := binary.Write(&frame, binary.BigEndian, uint32(65_536)); err != nil {
		t.Fatal(err)
	}
	if _, err := readPortDatagram(&frame); err == nil {
		t.Fatal("readPortDatagram() accepted oversized frame")
	}
}
