package storagewire

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestInterleavedServerFrames(t *testing.T) {
	event := &Event{EventSequence: 1, Volume: testID, Object: ObjectID{1}, Kind: InvalidateAttr, Name: []byte{}}
	reply := &Reply{Sequence: 1, Op: OpFlush, Body: FlushReply{}}
	messages := []ServerMessage{reply, event, &Reply{Sequence: 2, Op: OpRelease, Errno: 5}}
	var stream bytes.Buffer
	for _, m := range messages {
		if err := WriteFrame(&stream, m); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range messages {
		got, err := ReadServerFrame(&stream)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("wrong message kind/body")
		}
	}
	for _, payload := range []string{
		`{"sequence":1,"event_sequence":1,"op":"flush","errno":0,"body":{}}`,
		`{"sequence":1,"sequence":2,"op":"flush","errno":0,"body":{}}`,
		`{"sequence":1,"auth":{"kind":4},"op":"forget","body":{"entries":[{"node":1,"count":1}]}}`,
		`null`, `[]`, `{} {}`, `{"a":` + string(bytes.Repeat([]byte("["), MaxDepth+1)) + `0` + string(bytes.Repeat([]byte("]"), MaxDepth+1)) + `}`,
	} {
		frame := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(frame, uint32(len(payload)))
		copy(frame[4:], payload)
		if got, err := ReadServerFrame(bytes.NewReader(frame)); err == nil || got != nil {
			t.Fatalf("accepted %s", payload)
		}
	}
	if _, err := ReadServerFrame(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})); err == nil {
		t.Fatal("oversize frame")
	}
}
