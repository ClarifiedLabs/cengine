//go:build cengine_native_faulttest

package storageserver

import (
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"sync"
	"testing"
)

// Host-only bookkeeping/negative checks. These do not replace native mount proof.
func TestNativeSnapshot101XattrDiagnostic(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"security.capability", "security.capability"},
		{"security.capability\x00private", "other"},
		{"user.private", "other"},
		{"security.selinux", "other"},
		{"", "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := [2]a.Binding{{Store: id(t), Volume: id(t), Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}, {Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}}
			targets[1].Store, targets[1].Volume = targets[0].Store, targets[0].Volume
			o, err := (&Server{}).InstallNativeSnapshot101(targets)
			if err != nil {
				t.Fatal(err)
			}
			if err := o.Arm([2]w.Operation{w.OpWrite, w.OpWrite}); err != nil {
				t.Fatal(err)
			}
			var guard a.Guard // bookkeeping token only, never admitted or released
			o.admitted(targets[0], &guard, w.Request{Sequence: 14, Body: w.GetXAttrRequest{Name: []byte(tc.name)}})
			o.waiting(&guard)
			event := <-o.Waits()
			if event.Operation != w.OpGetXAttr || event.Sequence != 14 || event.XattrName != tc.want || event.WriteFlags != 0 {
				t.Fatalf("wrong closed diagnostic: %+v", event)
			}
		})
	}
}

// Host-only bookkeeping/negative checks. These do not replace native mount proof.
func TestNativeSnapshot101ObserverClosed(t *testing.T) {
	targets := [2]a.Binding{{Store: id(t), Volume: id(t), Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}, {Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	targets[1].Store = targets[0].Store
	targets[1].Volume = targets[0].Volume
	server := &Server{}
	observer, err := server.InstallNativeSnapshot101(targets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.InstallNativeSnapshot101(targets); err == nil {
		t.Fatal("reinstallation")
	}
	if observer.Arm([2]w.Operation{w.OpRename, w.OpWrite}) == nil {
		t.Fatal("out-of-catalog operation")
	}
	if err = observer.Arm([2]w.Operation{w.OpWrite, w.OpReadDir}); err != nil {
		t.Fatal(err)
	}
	if observer.Arm([2]w.Operation{w.OpWrite, w.OpReadDir}) == nil {
		t.Fatal("rearm")
	}
	var stale a.Guard
	observer.admitted(targets[0], &stale, w.Request{Sequence: 6, Body: w.WriteRequest{}}) // unfenced completion must not occupy the only slot
	var guards [2]a.Guard                                                                 // opaque bookkeeping tokens only, never admitted/released
	observer.admitted(targets[0], &guards[0], w.Request{Sequence: 7, Body: w.WriteRequest{WriteFlags: w.WriteCache}})
	observer.admitted(targets[1], &guards[1], w.Request{Sequence: 8, Body: w.ReadDirRequest{}})
	var group sync.WaitGroup
	for range 8 {
		for i := range guards {
			group.Add(1)
			go func(i int) { defer group.Done(); observer.waiting(&guards[i]) }(i)
		}
	}
	group.Wait()
	seen := map[a.ID]bool{}
	for range 2 {
		event := <-observer.Waits()
		if seen[event.Binding.Attachment] {
			t.Fatal("duplicate")
		}
		seen[event.Binding.Attachment] = true
		if event.Operation == w.OpWrite && (event.Sequence != 7 || event.WriteFlags != w.WriteCache) {
			t.Fatal(event)
		}
	}
	select {
	case <-observer.Waits():
		t.Fatal("duplicate wait evidence")
	default:
	}
	if observer.guards[0] != ([4]*a.Guard{}) || observer.guards[1] != ([4]*a.Guard{}) {
		t.Fatal("retained guard pointers")
	}
	for _, bad := range [][2]a.Binding{{targets[0], targets[0]}, {{Role: a.PrepareRole}, targets[1]}, {{}, targets[1]}} {
		if _, err := (&Server{}).InstallNativeSnapshot101(bad); err == nil {
			t.Fatal("invalid targets")
		}
	}
}

func TestNativeSnapshot101SubsequentWriteClosed(t *testing.T) {
	targets := [2]a.Binding{{Store: id(t), Volume: id(t), Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}, {Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	targets[1].Store, targets[1].Volume = targets[0].Store, targets[0].Volume
	o, err := (&Server{}).InstallNativeSnapshot101(targets)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Arm([2]w.Operation{w.OpWrite, w.OpWrite}); err != nil {
		t.Fatal(err)
	}
	var guards [2]a.Guard
	o.admitted(targets[0], &guards[0], w.Request{Sequence: 10, Body: w.GetXAttrRequest{Name: []byte("security.capability")}})
	o.admitted(targets[1], &guards[1], w.Request{Sequence: 10, Body: w.GetXAttrRequest{Name: []byte("user.private")}})
	o.waiting(&guards[0])
	o.waiting(&guards[1])
	for _, b := range targets {
		o.admitted(b, &guards[0], w.Request{Sequence: 10, Body: w.WriteRequest{}})
	}
	foreign := targets[0]
	foreign.Attachment = id(t)
	o.admitted(foreign, &guards[0], w.Request{Sequence: 11, Body: w.WriteRequest{}})
	o.admitted(targets[1], &guards[1], w.Request{Sequence: 11, Body: w.WriteRequest{}})
	select {
	case e := <-o.Writes():
		t.Fatal("accepted wrong binding/sequence/prerequisite", e)
	default:
	}
	for range 3 {
		o.admitted(targets[0], &guards[0], w.Request{Sequence: 11, Body: w.WriteRequest{}})
	}
	select {
	case e := <-o.Writes():
		if e.Binding != targets[0] || e.Sequence != 11 || e.Operation != w.OpWrite {
			t.Fatal(e)
		}
	default:
		t.Fatal("lost actual subsequent write")
	}
	select {
	case e := <-o.Writes():
		t.Fatal("duplicate", e)
	default:
	}
}

func TestNativeSnapshot101SubsequentReadClosed(t *testing.T) {
	targets := [2]a.Binding{{Store: id(t), Volume: id(t), Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}, {Attachment: id(t), Role: a.RuntimeRole, Mode: a.ReadWrite}}
	targets[1].Store, targets[1].Volume = targets[0].Store, targets[0].Volume
	for _, invalid := range []string{"", "no-positive", "wrong-positive", "no-handle", "wrong-node", "wrong-handle", "getattr-readdir", "unfenced", "old-fence"} {
		t.Run(invalid, func(t *testing.T) {
			o, err := (&Server{}).InstallNativeSnapshot101(targets)
			if err != nil {
				t.Fatal(err)
			}
			var g [2]a.Guard // bookkeeping tokens only, not runtime admission proof
			if invalid != "no-positive" {
				var body w.RequestBody = w.ReadRequest{Node: 7, Handle: 9}
				if invalid == "wrong-positive" {
					body = w.ReadDirRequest{Node: 7, Handle: 9}
				}
				o.admitted(targets[0], &g[0], w.Request{Sequence: 10, Body: body})
			}
			o.admitted(targets[1], &g[1], w.Request{Sequence: 10, Body: w.ReadDirRequest{Node: 1, Handle: 2}})
			positive := o.PositiveReads()
			if positive[1].Operation != w.OpReadDir || positive[1].Node != 1 || positive[1].Handle != 2 {
				t.Fatal(positive)
			}
			ops := [2]w.Operation{w.OpRead, w.OpReadDir}
			if invalid == "getattr-readdir" {
				ops[0] = w.OpReadDir
			}
			if err := o.Arm(ops); err != nil {
				t.Fatal(err)
			}
			handle := w.HandleID(9)
			attr := w.GetAttrRequest{Node: 7, Handle: &handle}
			if invalid == "no-handle" {
				attr.Handle = nil
			}
			if invalid == "wrong-node" {
				attr.Node++
			}
			if invalid == "wrong-handle" {
				handle++
			}
			seq := uint64(13)
			if invalid == "old-fence" {
				seq = 10
			}
			o.admitted(targets[0], &g[0], w.Request{Sequence: seq, Body: attr})
			if invalid != "unfenced" {
				o.waiting(&g[0])
				e := <-o.Waits()
				if e.Operation != w.OpGetAttr || e.Node != attr.Node || e.Sequence != seq {
					t.Fatal(e)
				}
			}
			// Equal/older sequence, foreign binding, wrong op and different views fail.
			o.admitted(targets[0], &g[0], w.Request{Sequence: 13, Body: w.ReadRequest{Node: 7, Handle: 9}})
			foreign := targets[0]
			foreign.Key = "foreign"
			o.admitted(foreign, &g[0], w.Request{Sequence: 14, Body: w.ReadRequest{Node: 7, Handle: 9}})
			for _, body := range []w.RequestBody{w.ReadRequest{Node: 8, Handle: 9}, w.ReadRequest{Node: 7, Handle: 10}, w.ReadDirRequest{Node: 7, Handle: 9}, w.WriteRequest{Node: 7, Handle: 9}, attr} {
				o.admitted(targets[0], &g[0], w.Request{Sequence: 14, Body: body})
			}
			select {
			case e := <-o.Reads():
				t.Fatal("wrong subsequent evidence", e)
			default:
			}
			for range 3 {
				o.admitted(targets[0], &g[0], w.Request{Sequence: 15, Body: w.ReadRequest{Node: 7, Handle: 9}})
			}
			select {
			case e := <-o.Reads():
				if invalid != "" || e.Binding != targets[0] || e.Node != 7 || e.Handle != 9 || e.Operation != w.OpRead || e.Sequence != 15 {
					t.Fatal(invalid, e)
				}
			default:
				if invalid == "" {
					t.Fatal("missing actual subsequent READ")
				}
			}
			select {
			case e := <-o.Reads():
				t.Fatal("duplicate", e)
			default:
			}
			if o.PositiveReads() != positive {
				t.Fatal("positive view changed after Arm")
			}
		})
	}
}
