//go:build cengine_native_faulttest

package storageserver

import (
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"sync"
	"testing"
	"time"
)

// Host bookkeeping only: opaque tokens exercise the finite scheduling gate,
// never claim authenticated native admission, filesystem execution or drain.
func TestNativeSnapshot101QueueClosed(t *testing.T) {
	targets := [2]a.Binding{{Store: id(t), Volume: id(t), Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}, {Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	targets[1].Store = targets[0].Store
	targets[1].Volume = targets[0].Volume
	server := &Server{receive: make(chan struct{}, 3)}
	q, err := server.InstallNativeSnapshot101Queue(id(t), targets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.InstallNativeSnapshot101Queue(id(t), targets); err == nil {
		t.Fatal("duplicate installation")
	}
	if q.Release(-1) == nil || q.Release(2) == nil {
		t.Fatal("out of range release")
	}
	if err := q.Arm(); err != nil {
		t.Fatal(err)
	}
	if q.Arm() == nil {
		t.Fatal("rearm")
	}
	var guard [2]a.Guard
	q.admit(targets[0], &guard[0], w.Request{Sequence: 1, Body: w.GetAttrRequest{}})
	q.admit(targets[0], &guard[0], w.Request{Sequence: 2, Body: w.RenameRequest{OldName: []byte("other"), NewName: []byte("moved")}})
	if q.State().Held != [2]bool{} {
		t.Fatal("prerequisite or wrong name captured")
	}
	var group sync.WaitGroup
	bodies := [2]w.RequestBody{w.RenameRequest{OldName: []byte("p0"), NewName: []byte("moved")}, w.UnlinkRequest{Name: []byte("p1")}}
	for i := range bodies {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			q.admit(targets[i], &guard[i], w.Request{Sequence: uint64(i + 3), Body: bodies[i]})
		}(i)
	}
	for range 2 {
		select {
		case <-q.Admissions():
		case <-time.After(time.Second):
			t.Fatal("missing gate")
		}
	}
	state := q.State()
	if state.Held != [2]bool{true, true} || state.ReceiveCapacity != 3 || state.Sequences != [2]uint64{3, 4} {
		t.Fatal(state)
	}
	for i := range bodies {
		if err := q.Release(i); err != nil {
			t.Fatal(err)
		}
		if err := q.Release(i); err != nil {
			t.Fatal(err)
		}
	}
	group.Wait()
	for i := range guard {
		q.wait(&guard[i])
		q.wait(&guard[i])
	}
	for range 2 {
		select {
		case <-q.Waits():
		case <-time.After(time.Second):
			t.Fatal("missing exact waiter")
		}
	}
	select {
	case <-q.Waits():
		t.Fatal("duplicate waiter")
	default:
	}
	if q.State().Held != [2]bool{} || q.guards != [2]*a.Guard{} {
		t.Fatal("retained scheduling ownership")
	}
}
