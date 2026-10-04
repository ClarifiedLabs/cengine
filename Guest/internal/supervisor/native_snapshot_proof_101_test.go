//go:build cengine_native_faulttest

package supervisor

import (
	ss "dev.cengine/guest/internal/storageserver"
	w "dev.cengine/guest/internal/storagewire"
	"testing"
)

func snapshot101FenceOperation(mode string, want w.Operation, event ss.NativeSnapshot101Wait) bool {
	switch mode {
	case "fd":
		return want == w.OpWrite && (event.Operation == w.OpWrite || (event.Operation == w.OpGetXAttr && event.XattrName == "security.capability"))
	case "mmap":
		return want == w.OpWrite && event.Operation == w.OpWrite && event.WriteFlags&w.WriteCache != 0
	case "atime":
		return (want == w.OpRead || want == w.OpReadDir) && (event.Operation == want || (want == w.OpRead && event.Operation == w.OpGetAttr && event.Node != 0 && event.Handle != 0))
	default:
		return false
	}
}

func TestSnapshot101ClosedPrerequisite(t *testing.T) {
	for _, mode := range []string{"fd", "mmap", "atime", "namespace", ""} {
		for _, name := range []string{"security.capability", "other", "", "security.capability\x00", "user.private"} {
			event := ss.NativeSnapshot101Wait{Operation: w.OpGetXAttr, XattrName: name}
			if got := snapshot101FenceOperation(mode, w.OpWrite, event); got != (mode == "fd" && name == "security.capability") {
				t.Fatalf("mode=%q name=%q got=%v", mode, name, got)
			}
		}
	}
	for _, op := range []w.Operation{w.OpGetAttr, w.OpRead, w.OpReadDir, w.OpGetXAttr} {
		if snapshot101FenceOperation("fd", w.OpWrite, ss.NativeSnapshot101Wait{Operation: op}) {
			t.Fatal("arbitrary prerequisite", op)
		}
	}
	if snapshot101FenceOperation("mmap", w.OpWrite, ss.NativeSnapshot101Wait{Operation: w.OpWrite}) {
		t.Fatal("mmap lacks WriteCache")
	}
	for _, op := range []w.Operation{w.OpRead, w.OpReadDir} {
		if !snapshot101FenceOperation("atime", op, ss.NativeSnapshot101Wait{Operation: op}) {
			t.Fatal("lost actual atime operation")
		}
	}
	if !snapshot101FenceOperation("fd", w.OpWrite, ss.NativeSnapshot101Wait{Operation: w.OpWrite}) || !snapshot101FenceOperation("mmap", w.OpWrite, ss.NativeSnapshot101Wait{Operation: w.OpWrite, WriteFlags: w.WriteCache}) {
		t.Fatal("lost actual WRITE")
	}
}

// Wire nodes/handles are connection-local, not stat inode numbers. Require the
// same full binding and retained view observed by the original positive syscall.
func snapshot101ReadFence(want w.Operation, positive, event ss.NativeSnapshot101Wait) bool {
	return positive.Operation == want && positive.Sequence > 0 && positive.Node != 0 && positive.Handle != 0 &&
		event.Binding == positive.Binding && event.Node == positive.Node && event.Handle == positive.Handle &&
		event.Sequence > positive.Sequence && snapshot101FenceOperation("atime", want, event)
}

func TestSnapshot101ReadPrerequisiteClosed(t *testing.T) {
	positive := ss.NativeSnapshot101Wait{Sequence: 10, Operation: w.OpRead, Node: 7, Handle: 9}
	event := positive
	event.Sequence = 13
	event.Operation = w.OpGetAttr
	if !snapshot101ReadFence(w.OpRead, positive, event) {
		t.Fatal("lost retained-read prerequisite")
	}
	for _, mode := range []string{"fd", "mmap", "namespace", ""} {
		if snapshot101FenceOperation(mode, w.OpRead, event) {
			t.Fatal("prerequisite leaked to mode", mode)
		}
	}
	for _, mutate := range []func(*ss.NativeSnapshot101Wait){
		func(e *ss.NativeSnapshot101Wait) { e.Node = 0 },
		func(e *ss.NativeSnapshot101Wait) { e.Node++ },
		func(e *ss.NativeSnapshot101Wait) { e.Handle = 0 },
		func(e *ss.NativeSnapshot101Wait) { e.Handle++ },
		func(e *ss.NativeSnapshot101Wait) { e.Binding.Attachment = "foreign" },
		func(e *ss.NativeSnapshot101Wait) { e.Binding.Key = "foreign" },
		func(e *ss.NativeSnapshot101Wait) { e.Sequence = 10 },
		func(e *ss.NativeSnapshot101Wait) { e.Sequence = 0 },
		func(e *ss.NativeSnapshot101Wait) { e.Operation = w.OpGetXAttr },
		func(e *ss.NativeSnapshot101Wait) { e.Operation = w.OpReadDir },
	} {
		bad := event
		mutate(&bad)
		if snapshot101ReadFence(w.OpRead, positive, bad) {
			t.Fatalf("accepted wrong prerequisite: %+v", bad)
		}
	}
	positive.Operation = w.OpReadDir
	if snapshot101ReadFence(w.OpReadDir, positive, event) {
		t.Fatal("uncached Getdents must fence actual READDIR, not GETATTR")
	}
	event.Operation = w.OpReadDir
	if !snapshot101ReadFence(w.OpReadDir, positive, event) {
		t.Fatal("lost actual READDIR")
	}
}
