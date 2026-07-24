package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"dev.cengine/guest/internal/protocol"
)

func TestSetTimeControlOperationDispatchesValidatedPayload(t *testing.T) {
	var seconds, microseconds int64
	state := &controlServer{setTime: func(sec, usec int64) error {
		seconds, microseconds = sec, usec
		return nil
	}}
	payload := json.RawMessage(`{"seconds":1784920000,"microseconds":123456}`)
	response, err := state.handle(protocol.Envelope{Operation: "set-time", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if seconds != 1_784_920_000 || microseconds != 123_456 {
		t.Fatalf("set-time dispatched %d.%06d", seconds, microseconds)
	}
	if string(response) != `{"status":"synchronized"}` {
		t.Fatalf("set-time response = %s", response)
	}
}

func TestSetTimeControlOperationRejectsMissingFields(t *testing.T) {
	state := &controlServer{setTime: func(int64, int64) error {
		t.Fatal("set-time invoked syscall for malformed payload")
		return nil
	}}
	_, err := state.handle(protocol.Envelope{
		Operation: "set-time",
		Payload:   json.RawMessage(`{"seconds":1784920000}`),
	})
	if err == nil || !strings.Contains(err.Error(), "requires seconds and microseconds") {
		t.Fatalf("set-time error = %v", err)
	}
}

func TestSetTimeControlOperationPropagatesFailure(t *testing.T) {
	failure := errors.New("clock update failed")
	state := &controlServer{setTime: func(int64, int64) error { return failure }}
	_, err := state.handle(protocol.Envelope{
		Operation: "set-time",
		Payload:   json.RawMessage(`{"seconds":1,"microseconds":2}`),
	})
	if !errors.Is(err, failure) {
		t.Fatalf("set-time error = %v, want %v", err, failure)
	}
}
