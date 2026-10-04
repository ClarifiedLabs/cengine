package storageclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"dev.cengine/guest/internal/preparecompat"
	w "dev.cengine/guest/internal/storagewire"
)

// TLS/FIFO source fixture, NOT kernel mount, authority retirement or native proof.
func originalReadClient(t *testing.T, volume byte, change func(w.Request) *w.Reply) *Client {
	t.Helper()
	c := fixture(t, func(cfg *Config) {
		cfg.Authority.Binding.Volume = testID(volume)
		cfg.Authority.Binding.Attachment = testID(volume)
	}, func(conn *tls.Conn) {
		rpcServer(conn, func(req w.Request) w.Reply {
			if change != nil {
				if reply := change(req); reply != nil {
					return *reply
				}
			}
			switch req.Body.(type) {
			case w.LookupRequest:
				return w.Reply{Body: w.LookupReply{Entry: testEntry(100, false)}}
			case w.OpenRequest:
				return w.Reply{Body: w.OpenReply{Opened: w.Opened{Handle: 200}}}
			case w.GetAttrRequest:
				b := req.Body.(w.GetAttrRequest)
				attr := testEntry(b.Node, b.Node == 99).Attr
				if b.Node == 100 {
					attr.Size = 32
				}
				return w.Reply{Body: w.GetAttrReply{Attr: attr}}
			case w.ReadRequest:
				return w.Reply{Body: w.ReadReply{Data: bytes.Repeat([]byte{volume}, 32)}}
			case w.ReleaseRequest:
				return w.Reply{Body: w.ReleaseReply{}}
			}
			return w.Reply{Errno: 22}
		})
	})
	if _, err := c.Do(caller(c), 0, w.LookupRequest{Parent: 99, Name: []byte("exclusive-object")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(caller(c), 0, w.OpenRequest{Node: 100, Flags: w.OpenReadOnly}); err != nil {
		t.Fatal(err)
	}
	return c
}
func captureOriginalRead(t *testing.T, c *Client) *OriginalConsumerReadGrant {
	t.Helper()
	if err := c.BeginOriginalConsumerRead(c.Authority()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(none(c), w.OpenGrantAuth, w.ReadRequest{Node: 100, Handle: 200, Size: 4096}); err != nil {
		t.Fatal(err)
	}
	grant, err := c.EndOriginalConsumerRead(c.Authority())
	if err != nil {
		t.Fatal(err)
	}
	return grant
}
func TestOriginalConsumerReadCoincidentGrantsStayInB(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, closedSource := range []bool{false, true} {
		t.Run(map[bool]string{false: "live-source", true: "retained-terminal-source-not-retirement-proof"}[closedSource], func(t *testing.T) {
			source := originalReadClient(t, '6', nil)
			var wire []w.Request
			target := originalReadClient(t, '7', func(req w.Request) *w.Reply { wire = append(wire, req); return nil })
			a, b := captureOriginalRead(t, source), captureOriginalRead(t, target)
			if closedSource {
				source.Close()
			}
			result, err := target.ReplayOriginalConsumerRead(context.Background(), target.Authority(), a, b)
			digest := sha256.Sum256(bytes.Repeat([]byte{'7'}, 32))
			if err != nil || result.RootNode != 99 || result.Node != 100 || result.Handle != 200 || result.RootSequence != 4 || result.ReadSequence != 5 || result.ContentSHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal(result, err)
			}
			if len(wire) != 5 || wire[3].Auth.Kind != w.NodeMetadataAuth || wire[3].Auth.Caller != nil || wire[4].Auth.Kind != w.OpenGrantAuth || wire[4].Auth.Caller != nil {
				t.Fatal("not actual scoped grant RPCs", wire)
			}
			if _, err := target.ReplayOriginalConsumerRead(context.Background(), target.Authority(), a, b); err == nil {
				t.Fatal("reused one-shot reference")
			}
		})
	}
}
func TestOriginalConsumerReadCaptureRejectsSubstitutes(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, name := range []string{"cache-only", "two-reads", "offset", "oversize", "wrong-handle", "metadata", "short", "errno", "early-end", "mixed-writer", "wrong-end"} {
		t.Run(name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			c := originalReadClient(t, '6', func(req w.Request) *w.Reply {
				if req.Body.Operation() != w.OpRead {
					return nil
				}
				if name == "early-end" {
					close(entered)
					<-release
				}
				if name == "short" {
					return &w.Reply{Body: w.ReadReply{Data: []byte{1}}}
				}
				if name == "errno" {
					return &w.Reply{Errno: 13}
				}
				return nil
			})
			if err := c.BeginOriginalConsumerRead(c.Authority()); err != nil {
				t.Fatal(err)
			}
			if c.BeginOriginalConsumerRead(c.Authority()) == nil || c.BeginOriginalConsumerFile(c.Authority(), true) == nil {
				t.Fatal("overlapping recorder")
			}
			r := w.ReadRequest{Node: 100, Handle: 200, Size: 4096}
			switch name {
			case "offset":
				r.Offset = 1
			case "oversize":
				r.Size = 4097
			case "wrong-handle":
				r.Handle++
			}
			switch name {
			case "cache-only":
			case "metadata":
				c.Do(none(c), w.NodeMetadataAuth, w.GetAttrRequest{Node: 99})
			case "mixed-writer":
				c.Do(none(c), w.OpenGrantAuth, w.WriteRequest{Node: 100, Handle: 200, Data: []byte{1}})
			case "early-end":
				done := make(chan struct{})
				go func() { c.Do(none(c), w.OpenGrantAuth, r); close(done) }()
				<-entered
				if _, err := c.EndOriginalConsumerRead(c.Authority()); err == nil {
					t.Fatal("unjoined read accepted")
				}
				close(release)
				<-done
				if _, err := c.EndOriginalConsumerRead(c.Authority()); err != nil {
					t.Fatal(err)
				}
				return
			default:
				c.Do(none(c), w.OpenGrantAuth, r)
			}
			if name == "two-reads" {
				c.Do(none(c), w.OpenGrantAuth, r)
			}
			expected := c.Authority()
			if name == "wrong-end" {
				expected.Epoch = testID('9')
			}
			got, err := c.EndOriginalConsumerRead(expected)
			if err == nil || got != nil {
				t.Fatal("substitute", got, err)
			}
			if name == "cache-only" && err != OriginalReadCacheOnly {
				t.Fatal("missing cache-only diagnostic", err)
			}
			if name == "metadata" && err != OriginalReadGetAttr {
				t.Fatal("missing traffic diagnostic", err)
			}
			if name == "two-reads" && err != OriginalReadRepeated {
				t.Fatal("missing repeated READ diagnostic", err)
			}
			if (name == "offset" || name == "oversize") && err != OriginalReadShape {
				t.Fatal("missing request-shape diagnostic", err)
			}
		})
	}
}
func TestOriginalConsumerReadReplayRejectsLeakAndAliases(t *testing.T) {
	requireOriginalFileProfile(t)
	for _, name := range []string{"A-content", "root-file", "errno", "same-volume", "same-key", "wrong-E", "wrong-store", "wrong-container", "wrong-launch", "wrong-expected", "same-digest", "foreign-target", "zero-source", "closed-target", "released-handle", "reused-handle", "extra-traffic", "unknown-node", "unknown-handle", "canceled"} {
		t.Run(name, func(t *testing.T) {
			var reads int
			source := originalReadClient(t, '6', nil)
			target := originalReadClient(t, '7', func(req w.Request) *w.Reply {
				if req.Body.Operation() == w.OpRead {
					reads++
					if reads == 2 && name == "A-content" {
						return &w.Reply{Body: w.ReadReply{Data: bytes.Repeat([]byte{'6'}, 32)}}
					}
				}
				if req.Body.Operation() == w.OpGetAttr {
					if name == "root-file" {
						return &w.Reply{Body: w.GetAttrReply{Attr: testEntry(99, false).Attr}}
					}
					if name == "errno" {
						return &w.Reply{Errno: 13}
					}
				}
				return nil
			})
			a, b := captureOriginalRead(t, source), captureOriginalRead(t, target)
			expected := target.Authority()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "same-volume":
				a.authority.Binding.Volume = expected.Binding.Volume
			case "same-key":
				a.authority.Binding.Key = expected.Binding.Key
			case "wrong-E":
				a.authority.Epoch = testID('9')
			case "wrong-store":
				a.authority.Binding.Store = testID('9')
			case "wrong-container":
				a.authority.Binding.Container = "other"
			case "wrong-launch":
				a.authority.Binding.Launch = testID('9')
			case "wrong-expected":
				expected.Epoch = testID('9')
			case "same-digest":
				a.digest = b.digest
			case "foreign-target":
				b.owner = source
			case "zero-source":
				a = &OriginalConsumerReadGrant{}
			case "closed-target":
				target.Close()
			case "released-handle", "reused-handle":
				if _, err := target.Do(none(target), w.LifecycleAuth, w.ReleaseRequest{Node: 100, Handle: 200}); err != nil {
					t.Fatal(err)
				}
				if name == "reused-handle" {
					if _, err := target.Do(caller(target), 0, w.OpenRequest{Node: 100, Flags: w.OpenReadOnly}); err != nil {
						t.Fatal(err)
					}
					b.sequence = target.sequence
				}
			case "extra-traffic":
				target.OriginalConsumerPositiveRoot(ctx, expected)
			case "unknown-node":
				a.node++
			case "unknown-handle":
				a.handle++
			case "canceled":
				cancel()
			}
			got, err := target.ReplayOriginalConsumerRead(ctx, expected, a, b)
			if err == nil || got != (OriginalConsumerRootReplay{}) {
				t.Fatal("alias or leak accepted", got, err)
			}
		})
	}
}
func TestOriginalConsumerReadReplayCancellationJoins(t *testing.T) {
	requireOriginalFileProfile(t)
	source := originalReadClient(t, '6', nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	target := originalReadClient(t, '7', func(req w.Request) *w.Reply {
		if req.Body.Operation() == w.OpGetAttr {
			calls.Add(1)
			close(entered)
			<-release
		}
		return nil
	})
	a, b := captureOriginalRead(t, source), captureOriginalRead(t, target)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		got, err := target.ReplayOriginalConsumerRead(ctx, target.Authority(), a, b)
		if got != (OriginalConsumerRootReplay{}) {
			done <- ErrProtocol
			return
		}
		done <- err
	}()
	<-entered
	// A concurrent replay must fail immediately rather than queue on the mutex.
	if _, err := target.ReplayOriginalConsumerRead(ctx, target.Authority(), a, b); err == nil {
		t.Fatal("concurrent reuse")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("not bounded")
	}
	close(release)
	select {
	case <-target.joined:
	default:
		t.Fatal("unjoined workers")
	}
	if calls.Load() != 1 {
		t.Fatal("retried")
	}
}
func TestOriginalConsumerReadInertProfile(t *testing.T) {
	if preparecompat.CurrentProfile() == preparecompat.FullProfile {
		return
	}
	c := fixture(t, nil, nil)
	if c.BeginOriginalConsumerRead(c.Authority()) == nil {
		t.Fatal("normal profile enabled")
	}
}
