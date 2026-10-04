package storageclient

import (
	"errors"
	"math"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
)

func TestCoalesceEventExactCoverage(t *testing.T) {
	attr := w.Event{EventSequence: 1, Volume: testID('2'), Object: w.ObjectID{42}, Kind: w.InvalidateAttr, Name: []byte{}}
	data := attr
	data.Kind = w.InvalidateData
	data.Offset = 17
	data.Length = 23
	entry := attr
	entry.Kind = w.InvalidateEntry
	entry.Parent = w.ObjectID{99}
	entry.Name = []byte("name")
	for _, tc := range []struct {
		name          string
		before, after w.Event
		merge         bool
		kind          w.EventKind
	}{
		{"attr-attr", attr, attr, true, w.InvalidateAttr},
		{"attr-data", attr, data, true, w.InvalidateData},
		{"data-attr", data, attr, true, w.InvalidateData},
		{"data-data", data, data, true, w.InvalidateData},
		{"namespace-identical", entry, entry, false, ""},
		{"namespace-inode", entry, attr, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.after.EventSequence = 2
			got, ok := coalesceEvent(tc.before, tc.after)
			if ok != tc.merge {
				t.Fatal(got, ok)
			}
			if ok && (got.Kind != tc.kind || got.EventSequence != 2 || got.Validate() != nil) {
				t.Fatal(got)
			}
			if ok && got.Kind == w.InvalidateData && (got.Offset != 17 || got.Length != 23) {
				t.Fatal("changed data coverage", got)
			}
		})
	}
	for _, field := range []string{"volume", "object", "offset", "length"} {
		t.Run(field, func(t *testing.T) {
			later := data
			later.EventSequence++
			switch field {
			case "volume":
				later.Volume = testID('3')
			case "object":
				later.Object = w.ObjectID{43}
			case "offset":
				later.Offset++
			case "length":
				later.Length++
			}
			if _, ok := coalesceEvent(data, later); ok {
				t.Fatal("merged different identity/range")
			}
		})
	}
}

func TestEventQueueNeverMergesAcrossInterveningEvent(t *testing.T) {
	c := &Client{events: make(chan *eventWork, 2)}
	event := w.Event{EventSequence: 1, Volume: testID('2'), Object: w.ObjectID{42}, Kind: w.InvalidateAttr, Name: []byte{}}
	if err := c.enqueueEvent(event); err != nil {
		t.Fatal(err)
	}
	other := event
	other.Object = w.ObjectID{43}
	other.EventSequence++
	if err := c.enqueueEvent(other); err != nil {
		t.Fatal(err)
	}
	event.EventSequence = 3
	if err := c.enqueueEvent(event); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if c.pendingEvents != 2 || len(c.events) != 2 {
		t.Fatal("overflow changed ownership")
	}
	if first := <-c.events; first.event.EventSequence != 1 || first.count != 1 {
		t.Fatal("earlier event changed", first)
	}
}

func TestEventCountOverflowDoesNotWrapOrMutateTail(t *testing.T) {
	event := w.Event{EventSequence: 1, Volume: testID('2'), Object: w.ObjectID{42}, Kind: w.InvalidateAttr, Name: []byte{}}
	c := &Client{events: make(chan *eventWork, 1), pendingEvents: math.MaxInt - 1}
	if err := c.enqueueEvent(event); err != nil {
		t.Fatal(err)
	}
	event.EventSequence++
	if err := c.enqueueEvent(event); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if c.pendingEvents != math.MaxInt || c.eventTail.count != 1 || c.eventTail.event.EventSequence != 1 {
		t.Fatal("overflow mutated ownership")
	}
}
