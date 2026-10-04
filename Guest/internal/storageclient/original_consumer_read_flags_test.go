package storageclient

import (
	"context"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
)

func TestOriginalConsumerReadPreservesActualReadOnlyFlags(t *testing.T) {
	requireOriginalFileProfile(t)
	const flags = w.OpenLargeFile | w.OpenNoATime | w.OpenNonblock | w.OpenNoFollow
	capture := func(c *Client) *OriginalConsumerReadGrant {
		if err := c.BeginOriginalConsumerRead(c.Authority()); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Do(none(c), w.OpenGrantAuth, w.ReadRequest{Node: 100, Handle: 200, Size: 4096, IOFlags: flags}); err != nil {
			t.Fatal(err)
		}
		g, err := c.EndOriginalConsumerRead(c.Authority())
		if err != nil {
			t.Fatal(err)
		}
		v, err := g.Witness(c.Authority())
		if err != nil || v.IOFlags != flags || v.Size != 4096 || v.Node != 100 || v.Handle != 200 || v.RequestSequence != 3 {
			t.Fatal(v, err)
		}
		return g
	}
	source := originalReadClient(t, '6', nil)
	target := originalReadClient(t, '7', func(req w.Request) *w.Reply {
		if b, ok := req.Body.(w.ReadRequest); ok && b.IOFlags != flags {
			t.Error("flags substituted", b)
		}
		return nil
	})
	a, b := capture(source), capture(target)
	if _, err := target.ReplayOriginalConsumerRead(context.Background(), target.Authority(), a, b); err != nil {
		t.Fatal(err)
	}
}
func TestOriginalConsumerReadRejectsUnmatchedOrWritableFlags(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, flags := range []uint32{w.OpenReadWrite, w.OpenWriteOnly, w.OpenCreate, w.OpenTruncate, w.OpenDirect, w.OpenAppend, 1 << 31} {
		c := originalReadClient(t, '6', nil)
		if err := c.BeginOriginalConsumerRead(c.Authority()); err != nil {
			t.Fatal(err)
		}
		c.Do(none(c), w.OpenGrantAuth, w.ReadRequest{Node: 100, Handle: 200, Size: 4096, IOFlags: flags})
		if g, err := c.EndOriginalConsumerRead(c.Authority()); err == nil || g != nil {
			t.Fatal("writable flags accepted", flags)
		}
	}
	for _, field := range []string{"flags", "size"} {
		t.Run(field, func(t *testing.T) {
			source, target := originalReadClient(t, '6', nil), originalReadClient(t, '7', nil)
			a, b := captureOriginalRead(t, source), captureOriginalRead(t, target)
			if field == "flags" {
				a.ioFlags = w.OpenLargeFile
			} else {
				a.size = 32
			}
			if got, err := target.ReplayOriginalConsumerRead(context.Background(), target.Authority(), a, b); err == nil || got != (OriginalConsumerRootReplay{}) {
				t.Fatal("different operation accepted", got, err)
			}
		})
	}
}
