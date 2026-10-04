package storageclient

import (
	"context"
	"crypto/tls"
	w "dev.cengine/guest/internal/storagewire"
	"testing"
)

func TestOriginalConsumerCapabilityFIFO(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, fault := range []string{"exact", "empty", "legacy", "positive", "name", "write", "duplicate", "sync-node", "successful", "errno", "malformed", "canceled", "wrong-end", "joined-close", "causal-abort", "unrelated-abort", "preclosed"} {
		t.Run(fault, func(t *testing.T) {
			c := originalFileClient(t, func(conn *tls.Conn, req w.Request) w.Reply {
				if fault == "successful" {
					return w.Reply{Body: w.GetXAttrReply{Size: 0, Value: []byte{}}}
				}
				if fault == "errno" {
					return w.Reply{Errno: 13}
				}
				if fault == "malformed" {
					conn.Write([]byte{0, 0, 0, 1, '!'})
				}
				conn.NetConn().Close()
				return w.Reply{Errno: 5}
			})
			var err error
			if fault == "legacy" || fault == "positive" {
				err = c.BeginOriginalConsumerFile(c.Authority(), fault == "positive")
			} else {
				err = c.BeginOriginalConsumerCapabilityFile(c.Authority())
			}
			if err != nil {
				t.Fatal(err)
			}
			get := w.GetXAttrRequest{Node: 100, Name: []byte("security.capability"), Size: 20}
			if fault == "name" {
				get.Name = []byte("user.capability")
			}
			if fault == "write" {
				c.Do(none(c), w.OpenGrantAuth, originalFileWrite(false))
			}
			if fault == "preclosed" {
				c.Close()
			}
			if fault != "empty" {
				c.Do(caller(c), 0, get)
			}
			if fault == "duplicate" {
				c.Do(caller(c), 0, get)
			}
			if fault == "canceled" {
				c.Abort(context.Canceled)
			}
			if fault == "joined-close" {
				c.Close() // native mount cleanup after the actual completed wire denial
			}
			if fault == "causal-abort" {
				c.Abort(c.Err()) // exact client terminal cause, propagated by rawFS
				c.Close()
			}
			if fault == "unrelated-abort" {
				c.Abort(ErrClosed) // not the retained remote terminal cause
			}
			node := w.NodeID(100)
			if fault == "sync-node" {
				node++
			}
			c.Do(none(c), w.OpenGrantAuth, w.FsyncRequest{Node: node, Handle: 200})
			h := c.Authority()
			if fault == "wrong-end" {
				h.Epoch = testID('8')
			}
			got, err := c.EndOriginalConsumerFile(h)
			if fault != "exact" && fault != "joined-close" && fault != "causal-abort" {
				if err == nil {
					t.Fatal("false witness", fault, got)
				}
				return
			}
			if err != nil || got.Capability == nil || got.Capability.Node != 100 || got.Capability.RequestSequence != 3 || got.Write != nil || got.Sync != nil || got.WriteOK || got.SyncOK {
				t.Fatal(got, err)
			}
			if _, err = c.EndOriginalConsumerFile(h); err == nil {
				t.Fatal("reused witness")
			}
		})
	}
}

func TestOriginalConsumerCapabilityMustJoin(t *testing.T) {
	requireOriginalFileProfile(t)
	entered, release := make(chan struct{}), make(chan struct{})
	c := originalFileClient(t, func(conn *tls.Conn, req w.Request) w.Reply {
		close(entered)
		<-release
		conn.NetConn().Close()
		return w.Reply{Errno: 5}
	})
	if err := c.BeginOriginalConsumerCapabilityFile(c.Authority()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		c.Do(caller(c), 0, w.GetXAttrRequest{Node: 100, Name: []byte("security.capability"), Size: 20})
		close(done)
	}()
	<-entered
	if _, err := c.EndOriginalConsumerFile(c.Authority()); err == nil {
		t.Fatal("unjoined witness")
	}
	close(release)
	<-done
	if _, err := c.EndOriginalConsumerFile(c.Authority()); err != nil {
		t.Fatal(err)
	}
}
