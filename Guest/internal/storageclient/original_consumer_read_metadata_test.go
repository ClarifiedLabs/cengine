package storageclient

import (
	w "dev.cengine/guest/internal/storagewire"
	"testing"
)

// Real TLS/FIFO requests, not a mounted Linux claim. The optional GETATTR is
// constrained to the one READ's object and immediately preceding wire sequence.
func TestOriginalReadMetadataPrelude(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, name := range []string{"node", "handle", "only-metadata", "duplicate", "after-read", "wrong-node", "wrong-handle", "wrong-inode", "directory", "size", "errno"} {
		t.Run(name, func(t *testing.T) {
			c := originalReadClient(t, '6', func(req w.Request) *w.Reply {
				if req.Body.Operation() != w.OpGetAttr {
					return nil
				}
				attr := testEntry(100, false).Attr
				attr.Size = 32
				switch name {
				case "wrong-inode":
					attr.Ino++
				case "directory":
					attr.Mode = 0040755
				case "size":
					attr.Size++
				case "errno":
					return &w.Reply{Errno: 5}
				default:
					return nil
				}
				return &w.Reply{Body: w.GetAttrReply{Attr: attr}}
			})
			if err := c.BeginOriginalConsumerRead(c.Authority()); err != nil {
				t.Fatal(err)
			}
			get := w.GetAttrRequest{Node: 100}
			auth := w.NodeMetadataAuth
			if name == "handle" || name == "wrong-handle" {
				handle := w.HandleID(200)
				if name == "wrong-handle" {
					handle++
				}
				get.Handle = &handle
				auth = w.OpenGrantAuth
			}
			if name == "wrong-node" {
				get.Node = 99
			}
			read := func() { c.Do(none(c), w.OpenGrantAuth, w.ReadRequest{Node: 100, Handle: 200, Size: 4096}) }
			if name == "after-read" {
				read()
			}
			c.Do(none(c), auth, get)
			if name == "duplicate" {
				c.Do(none(c), auth, get)
			}
			if name != "only-metadata" && name != "after-read" {
				read()
			}
			grant, err := c.EndOriginalConsumerRead(c.Authority())
			if name != "node" && name != "handle" {
				if err == nil || grant != nil {
					t.Fatal("invalid prelude accepted", grant, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			witness, err := grant.Witness(c.Authority())
			if err != nil || witness.Node != 100 || witness.Handle != 200 || witness.RequestSequence != 4 {
				t.Fatal("READ witness replaced by metadata", witness, err)
			}
		})
	}
}
