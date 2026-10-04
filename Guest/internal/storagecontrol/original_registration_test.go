package storagecontrol

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

// These are real retained TLS control calls and durable registry transitions,
// not a remote-code fixture. They do not attest a deployed guest mount.
func TestOriginalRegistrationAfterRetirement(t *testing.T) {
	for _, name := range []string{"attachment-key-reuse", "delayed-registration"} {
		t.Run(name, func(t *testing.T) {
			f := fixtureFor(t, Limits{}, nil)
			c := f.client()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			invoke := func(q Request) Response {
				t.Helper()
				r, err := c.Call(ctx, q)
				must(t, err)
				return r
			}
			query := func() *a.Snapshot { return invoke(Request{Query: &Empty{}}).Snapshot }
			create := a.CreateVolumeRequest{Operation: id(t), Store: f.store, Volume: id(t), Name: "original-registration"}
			invoke(Request{CreateVolume: &create})
			b, k := f.binding(create.Volume, "")
			registration := a.RegisterRequest{Operation: id(t), Binding: b}
			invoke(Request{RegisterAttachment: &registration})
			principal := f.data(k, b)
			guard, err := f.authority.Admit(principal, b.Volume, false)
			must(t, err)
			guard.Release()
			before := query()
			invoke(Request{RegisterAttachment: &registration})
			if !reflect.DeepEqual(before, query()) {
				t.Fatal("exact active retry changed registry")
			}
			retire := a.RetireRequest{Operation: id(t), Store: f.store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch}
			receipt := invoke(Request{Retire: &retire}).Receipt
			atProbe := query()
			retired := atProbe.Attachments[b.Attachment]
			if receipt == nil || retired.Phase != a.Drained || retired.Retirement != retire.Operation || retired.Receipt == nil || *retired.Receipt != *receipt || receipt.Revision <= before.Revision || atProbe.Revision < receipt.Revision || retired.Binding != b {
				t.Fatal("retirement not independently reconciled")
			}
			// Query exposes a detached snapshot: compare everything except the
			// exact retirement and its advancing registry revision.
			expected := *before
			expected.Revision = atProbe.Revision
			expected.Attachments = make(map[a.ID]a.Attachment, len(before.Attachments))
			for id, item := range before.Attachments {
				expected.Attachments[id] = item
			}
			expected.Attachments[b.Attachment] = retired
			if !reflect.DeepEqual(&expected, atProbe) {
				t.Fatal("unrelated registry changed during retirement")
			}
			attempt := registration
			want := Blocked
			if name == "attachment-key-reuse" {
				attempt.Operation = id(t)
				attempt.Binding.Attachment = id(t)
				want = Conflict
			}
			_, err = c.Call(ctx, Request{RegisterAttachment: &attempt})
			remote(t, err, want)
			if !reflect.DeepEqual(atProbe, query()) {
				t.Fatal("denied registration changed registry")
			}
			if _, err = f.authority.Admit(principal, b.Volume, false); !errors.Is(err, a.ErrBlocked) {
				t.Fatalf("retired original admitted: %v", err)
			}
			// A fresh op cannot revive the exact retired binding either.
			attempt = registration
			attempt.Operation = id(t)
			_, err = c.Call(ctx, Request{RegisterAttachment: &attempt})
			remote(t, err, Blocked)
			if !reflect.DeepEqual(atProbe, query()) {
				t.Fatal("fresh-op replay changed registry")
			}
			// The transport and volume remain usable with a genuinely fresh A/K.
			fresh, freshKey := f.binding(create.Volume, "")
			invoke(Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: fresh}})
			freshPrincipal := f.data(freshKey, fresh)
			guard, err = f.authority.Admit(freshPrincipal, fresh.Volume, false)
			must(t, err)
			guard.Release()
			c.Close()
		})
	}
}
