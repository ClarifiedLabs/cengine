package storageclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"

	"dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func originalFileClient(t *testing.T, handler func(*tls.Conn, w.Request) w.Reply) *Client {
	t.Helper()
	c := fixture(t, nil, func(conn *tls.Conn) {
		rpcServer(conn, func(req w.Request) w.Reply {
			switch req.Body.(type) {
			case w.LookupRequest:
				return w.Reply{Body: w.LookupReply{Entry: testEntry(100, false)}}
			case w.OpenRequest:
				return w.Reply{Body: w.OpenReply{Opened: w.Opened{Handle: 200}}}
			}
			return handler(conn, req)
		})
	})
	if _, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("file")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(caller(c), 0, w.OpenRequest{Node: 100, Flags: w.OpenReadWrite}); err != nil {
		t.Fatal(err)
	}
	return c
}
func originalFileReply(_ *tls.Conn, req w.Request) w.Reply {
	switch req.Body.(type) {
	case w.WriteRequest:
		return w.Reply{Body: w.WriteReply{Written: 1}}
	case w.FsyncRequest:
		return w.Reply{Body: w.FsyncReply{}}
	case w.FallocateRequest:
		return w.Reply{Body: w.FallocateReply{}}
	default:
		return w.Reply{Errno: 22}
	}
}
func originalFileWrite(positive bool) w.WriteRequest {
	b := byte(0x5a)
	if positive {
		b = 0xa5
	}
	return w.WriteRequest{Node: 100, Handle: 200, Data: []byte{b}}
}
func requireOriginalFileProfile(t *testing.T) {
	t.Helper()
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		t.Skip("exclusive full profile")
	}
}

func TestOriginalConsumerFileNegativeImpostors(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, name := range []string{"malformed", "duplicate-local", "wrong-local-sync", "abort", "missing-live-sync"} {
		t.Run(name, func(t *testing.T) {
			c := originalFileClient(t, func(conn *tls.Conn, req w.Request) w.Reply {
				if name == "missing-live-sync" {
					return w.Reply{Errno: 13}
				}
				if name == "malformed" {
					_ = w.WriteFrame(conn, &w.Reply{Sequence: req.Sequence, Op: w.OpFsync, Body: w.FsyncReply{}})
				} else {
					_ = conn.NetConn().Close()
				}
				return w.Reply{Errno: 5}
			})
			if err := c.BeginOriginalConsumerFile(c.Authority(), false); err != nil {
				t.Fatal(err)
			}
			c.Do(none(c), w.OpenGrantAuth, originalFileWrite(false))
			switch name {
			case "duplicate-local":
				c.Do(none(c), w.OpenGrantAuth, originalFileWrite(false))
			case "wrong-local-sync":
				c.Do(none(c), w.OpenGrantAuth, w.FsyncRequest{Node: 100, Handle: 201})
			case "abort":
				c.Abort(ErrGrant)
			}
			if got, err := c.EndOriginalConsumerFile(c.Authority()); err == nil || got.Write != nil {
				t.Fatal("negative impostor", got, err)
			}
		})
	}
}

func TestOriginalConsumerFileGates(t *testing.T) {
	c := fixture(t, nil, nil)
	good := c.Authority()
	if preparecompat.CurrentProfile() != preparecompat.FullProfile {
		if c.BeginOriginalConsumerFile(good, true) == nil {
			t.Fatal("inert enabled")
		}
		return
	}
	for _, mutate := range []func(*a.DataHello){
		func(h *a.DataHello) { h.Epoch = testID('9') }, func(h *a.DataHello) { h.Binding.Store = testID('9') },
		func(h *a.DataHello) { h.Binding.Volume = testID('9') }, func(h *a.DataHello) { h.Binding.Attachment = testID('9') },
		func(h *a.DataHello) { h.Binding.Launch = testID('9') }, func(h *a.DataHello) { h.Binding.Container = "wrong" },
		func(h *a.DataHello) { h.Binding.Key = "wrong" }, func(h *a.DataHello) { h.Binding.Prepare = testID('9') },
		func(h *a.DataHello) { h.Binding.Role = a.PrepareRole }, func(h *a.DataHello) { h.Binding.Mode = a.ReadOnly },
	} {
		bad := good
		mutate(&bad)
		if c.BeginOriginalConsumerFile(bad, true) == nil {
			t.Fatal("wrong tuple")
		}
	}
	if err := c.BeginOriginalConsumerFile(good, true); err != nil {
		t.Fatal(err)
	}
	p := c.originalFile
	for i := 0; i < 100; i++ {
		if c.BeginOriginalConsumerFile(good, false) == nil || c.originalFile != p {
			t.Fatal("record replaced")
		}
	}
	if _, err := c.EndOriginalConsumerFile(good); err == nil {
		t.Fatal("empty positive")
	}
	c.Close()
	if c.BeginOriginalConsumerFile(good, false) == nil {
		t.Fatal("terminal begin")
	}
}
func TestOriginalConsumerFileActualFIFO(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, positive := range []bool{true, false} {
		t.Run(map[bool]string{true: "positive", false: "errno-attempt"}[positive], func(t *testing.T) {
			c := originalFileClient(t, func(conn *tls.Conn, req w.Request) w.Reply {
				if !positive {
					return w.Reply{Errno: 13}
				}
				return originalFileReply(conn, req)
			})
			if err := c.BeginOriginalConsumerFile(c.Authority(), positive); err != nil {
				t.Fatal(err)
			}
			c.Do(none(c), w.OpenGrantAuth, originalFileWrite(positive))
			c.Do(none(c), w.OpenGrantAuth, w.FsyncRequest{Node: 100, Handle: 200})
			got, err := c.EndOriginalConsumerFile(c.Authority())
			if err != nil || got.Write == nil || got.Sync == nil || got.Write.Node != 100 || got.Write.Handle != 200 || got.Write.RequestSequence != 3 || got.Sync.RequestSequence != 4 || got.WriteOK != positive || got.SyncOK != positive {
				t.Fatal(got, err)
			}
			encoded, _ := json.Marshal(got)
			expected := `{"write":{"node":100,"handle":200,"requestSequence":3},"sync":{"node":100,"handle":200,"requestSequence":4},"writeOK":true,"syncOK":true}`
			if positive && string(encoded) != expected {
				t.Fatal(string(encoded))
			}
			if _, err = c.EndOriginalConsumerFile(c.Authority()); err == nil {
				t.Fatal("reused trace")
			}
		})
	}
}
func TestOriginalConsumerFileRejectsImpostors(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, name := range []string{"byte", "offset", "length", "duplicate-write", "duplicate-sync", "sync-first", "sync-handle", "data-only", "mutation", "wrong-grant", "zero-write", "positive-errno", "canceled", "malformed", "wrong-end"} {
		t.Run(name, func(t *testing.T) {
			c := originalFileClient(t, func(conn *tls.Conn, req w.Request) w.Reply {
				if name == "positive-errno" {
					return w.Reply{Errno: 13}
				}
				if name == "zero-write" && req.Body.Operation() == w.OpWrite {
					return w.Reply{Body: w.WriteReply{}}
				}
				if name == "malformed" {
					conn.Write([]byte{0, 0, 0, 1, '!'})
					return w.Reply{Errno: 5}
				}
				return originalFileReply(conn, req)
			})
			if err := c.BeginOriginalConsumerFile(c.Authority(), true); err != nil {
				t.Fatal(err)
			}
			write := originalFileWrite(true)
			sync := w.FsyncRequest{Node: 100, Handle: 200}
			switch name {
			case "byte":
				write.Data[0] = 0x5a
			case "offset":
				write.Offset = 1
			case "length":
				write.Data = append(write.Data, 0xa5)
			case "sync-first":
				c.Do(none(c), w.OpenGrantAuth, sync)
			case "sync-handle":
				sync.Handle++
			case "data-only":
				sync.DataOnly = true
			case "wrong-grant":
				write.Handle++
			case "mutation":
				c.Do(none(c), w.OpenGrantAuth, w.FallocateRequest{Node: 100, Handle: 200, Length: 1})
			}
			c.Do(none(c), w.OpenGrantAuth, write)
			if name == "duplicate-write" {
				c.Do(none(c), w.OpenGrantAuth, write)
			}
			c.Do(none(c), w.OpenGrantAuth, sync)
			if name == "duplicate-sync" {
				c.Do(none(c), w.OpenGrantAuth, sync)
			}
			if name == "canceled" {
				c.Abort(context.Canceled)
			}
			expected := c.Authority()
			if name == "wrong-end" {
				expected.Epoch = testID('8')
			}
			if got, err := c.EndOriginalConsumerFile(expected); err == nil || got.Write != nil {
				t.Fatal("impostor accepted", got, err)
			}
		})
	}
}
func TestOriginalConsumerFileTerminalAttemptAndEarlyEnd(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{true: "canceled", false: "transport-loss"}[cancel], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			c := originalFileClient(t, func(conn *tls.Conn, req w.Request) w.Reply {
				close(entered)
				<-release
				conn.NetConn().Close()
				return w.Reply{Errno: 5}
			})
			if err := c.BeginOriginalConsumerFile(c.Authority(), false); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { c.Do(none(c), w.OpenGrantAuth, originalFileWrite(false)); close(done) }()
			<-entered
			if _, err := c.EndOriginalConsumerFile(c.Authority()); err == nil {
				t.Fatal("unreturned call accepted")
			}
			if cancel {
				c.Abort(context.Canceled)
			}
			close(release)
			<-done
			c.Do(none(c), w.OpenGrantAuth, w.FsyncRequest{Node: 100, Handle: 200})
			got, err := c.EndOriginalConsumerFile(c.Authority())
			if cancel {
				if err == nil {
					t.Fatal("canceled attempt accepted")
				}
				return
			}
			if err != nil || got.Write == nil || got.Write.RequestSequence != 3 || got.Sync != nil || got.WriteOK || got.SyncOK {
				t.Fatal(got, err)
			}
		})
	}
}
