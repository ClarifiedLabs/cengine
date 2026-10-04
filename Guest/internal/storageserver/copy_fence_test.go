package storageserver

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// All RPC guards below come from authenticated DATA through Serve/readLoop.
// The executor seam supplies only the host-independent, no-op copy transaction;
// authority still owns the durable Begin/Finish and fence checks.
func TestCopyFenceWaitReleasesServiceDispatch(t *testing.T) {
	for _, slots := range []int{2, 3} {
		name := map[int]string{2: "full_runtime_pool", 3: "spare_slot_then_full_fifo"}[slots]
		t.Run(name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.ReceiveFrames = slots
			f := newFixture(t, limits, false)
			before, beforeKey := f.binding()
			after, afterKey := f.binding()
			ownerKey := key(t)
			owner := before
			owner.Attachment, owner.Prepare, owner.Key, owner.Role = id(t), id(t), fingerprint(t, ownerKey), a.PrepareRole
			must(t, f.a.ReservePrepare(f.control, a.ReserveRequest{Operation: id(t), Prepare: owner.Prepare, Attachments: []a.Binding{owner}}))
			must(t, f.a.RegisterAttachment(f.control, a.RegisterRequest{Operation: id(t), Binding: owner}))
			other, otherKey := copyFenceOtherVolume(t, f, before)

			allowBefore := make(chan struct{})
			var allowOnce sync.Once
			unblock := func() { allowOnce.Do(func() { close(allowBefore) }) }
			type connection struct {
				client *tls.Conn
				done   chan error
			}
			var connections []connection
			// Cleanup also covers failures while parked: real retirement wakes and
			// aborts nonowner guards, then drains them. Socket close alone cannot.
			// Do not retain an extra owner guard or manufacture a drain receipt.
			t.Cleanup(func() {
				unblock()
				for _, c := range connections {
					c.client.NetConn().Close()
				}
				for _, b := range []a.Binding{before, after, other, owner} {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_, err := f.a.Retire(ctx, f.control, a.RetireRequest{Operation: id(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch})
					cancel()
					if err != nil {
						t.Errorf("drain %s: %v", b.Attachment, err)
					}
				}
				for _, c := range connections {
					select {
					case <-c.done:
					case <-time.After(5 * time.Second):
						t.Error("Serve did not join after retirement")
					}
				}
				if len(f.s.receive) != 0 || len(f.s.connections) != 0 {
					t.Errorf("leaked reservations: receive=%d connections=%d", len(f.s.receive), len(f.s.connections))
				}
			})
			start := func(b a.Binding, k ed25519.PrivateKey) *tls.Conn {
				t.Helper()
				raw, client := f.pair(k)
				done := make(chan error, 1)
				connections = append(connections, connection{client, done})
				go func() { done <- f.s.Serve(context.Background(), f.a, raw) }()
				var hello w.ServerHello
				must(t, w.ReadFrame(client, &hello))
				must(t, w.WriteFrame(client, &w.ClientHello{Authority: a.DataHello{Epoch: hello.Epoch, Binding: b}, Profile: w.RequiredProfile()}))
				var root w.RootReply
				must(t, w.ReadFrame(client, &root))
				return client
			}

			type admission struct {
				binding a.Binding
				guard   *a.Guard
				seq     uint64
			}
			admitted := make(chan admission, 3)
			waiting := make(chan *a.Guard, 8)
			executed := make(chan admission, 3)
			f.s.copyHooks = &copyFenceHooks{
				admitted: func(b a.Binding, g *a.Guard, r w.Request) {
					if b.Attachment == before.Attachment || b.Attachment == after.Attachment {
						admitted <- admission{b, g, r.Sequence}
						if b.Attachment == before.Attachment && r.Sequence == 1 {
							<-allowBefore
						}
					}
				},
				waiting: func(g *a.Guard) { waiting <- g },
			}
			var st unix.Stat_t
			must(t, unix.Stat(filepath.Join(f.path, "volumes", "data"), &st))
			object := a.Ext4ObjectV1{Inode: st.Ino, Generation: 1, FileType: 0040000, HandleType: 1, HandleSize: 8}
			binary.LittleEndian.PutUint32(object.Handle[:4], uint32(st.Ino))
			binary.LittleEndian.PutUint32(object.Handle[4:], 1)
			// Only the serialized executor accesses intent; no shared test err variable.
			var intent a.CopyIntent
			f.s.factory = func(g *a.Guard, p *a.DataPrincipal, b a.Binding) (executor, w.Entry, error) {
				if err := g.ValidateFor(p); err != nil {
					return nil, w.Entry{}, err
				}
				return execFunc(func(g *a.Guard, r w.Request) (m.Result, error) {
					if err := g.ValidateFor(p); err != nil {
						return m.Result{}, err
					}
					var err error
					if b.Attachment == owner.Attachment {
						if r.Sequence == 1 {
							intent, err = g.BeginCopy(a.CopyRootV1{Store: b.Store, Volume: b.Volume, BackingUUID: [16]byte{1}, Root: object})
						} else {
							err = g.FinishCopy(intent.ID)
						}
					} else if b.Volume == before.Volume {
						executed <- admission{b, g, r.Sequence}
					}
					return m.Result{Reply: w.Reply{Sequence: r.Sequence, Op: w.OpGetAttr, Body: w.GetAttrReply{Attr: rootEntry().Attr}}}, err
				}), rootEntry(), nil
			}
			pre, post, prepare, unrelated := start(before, beforeKey), start(after, afterKey), start(owner, ownerKey), start(other, otherKey)
			send := func(c *tls.Conn, sequence uint64) {
				t.Helper()
				r := request(sequence)
				must(t, w.WriteFrame(c, &r))
			}
			reply := func(c *tls.Conn, sequence uint64) {
				t.Helper()
				message := readMessage(t, c)
				r, ok := message.(*w.Reply)
				if !ok {
					t.Fatalf("expected DATA reply, got %T", message)
				}
				must(t, w.ValidateReplyFor(request(sequence), *r))
				if r.Errno != 0 {
					t.Fatalf("DATA request %d failed: %+v", sequence, r)
				}
			}
			admit := func(b a.Binding, seq uint64) *a.Guard {
				t.Helper()
				select {
				case got := <-admitted:
					if got.binding != b || got.seq != seq {
						t.Fatalf("unexpected admission: %+v", got)
					}
					return got.guard
				case <-time.After(5 * time.Second):
					t.Fatal("DATA request not admitted")
					return nil
				}
			}
			park := func(g *a.Guard) {
				t.Helper()
				select {
				case got := <-waiting:
					if got != g {
						t.Fatal("wrong admitted guard entered fence wait")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("Serve did not enter copy-fence wait")
				}
			}

			send(pre, 1)
			preGuard := admit(before, 1) // Irrevocably admitted BEFORE Begin.
			send(prepare, 1)
			reply(prepare, 1) // Begin committed through actual owner DATA dispatch.
			unblock()
			park(preGuard)
			// A mutex probe is insufficient: exercise actual unrelated DATA admission,
			// dispatch and reply while this volume is fenced and capacity is available.
			send(unrelated, 1)
			reply(unrelated, 1)
			send(post, 1) // A second authenticated runtime admits AFTER Begin.
			postGuard := admit(after, 1)
			park(postGuard)
			guards := []*a.Guard{preGuard, postGuard}
			if slots == 3 {
				send(unrelated, 2)
				reply(unrelated, 2) // Both runtime waiters are now parked.
				send(pre, 2)
				guards = append(guards, admit(before, 2)) // Queued behind pre's waiter.
			}
			if len(f.s.receive) != cap(f.s.receive) {
				t.Fatalf("runtime DATA did not fill receive pool: %d/%d", len(f.s.receive), cap(f.s.receive))
			}
			select {
			case got := <-executed:
				t.Fatalf("runtime dispatched before owner Finish: %+v", got)
			default:
			}
			send(prepare, 2) // Only the owner's reserved frame can make progress now.
			reply(prepare, 2)
			reply(pre, 1)
			reply(post, 1)
			if slots == 3 {
				reply(pre, 2)
			}
			for _, g := range guards {
				if _, err := g.CopyFence(); !errors.Is(err, a.ErrClosed) {
					t.Errorf("replied DATA guard not released: %v", err)
				}
			}
			if len(executed) != slots || len(f.s.receive) != 0 {
				t.Fatalf("runtime work not completed exactly once: executed=%d receive=%d", len(executed), len(f.s.receive))
			}
		})
	}
}

func copyFenceOtherVolume(t *testing.T, f *fixture, template a.Binding) (a.Binding, ed25519.PrivateKey) {
	t.Helper()
	path := filepath.Join(f.path, "volumes", "other")
	must(t, os.Mkdir(path, 0777))
	var st unix.Stat_t
	must(t, unix.Stat(path, &st))
	volume := id(t)
	must(t, f.a.AddVolume(f.control, a.VolumeRequest{Operation: id(t), Volume: a.Volume{ID: volume, Name: "other", Root: a.RootIdentity{Device: uint64(st.Dev), Inode: st.Ino}}}))
	k := key(t)
	b := template
	b.Volume, b.Attachment, b.Key = volume, id(t), fingerprint(t, k)
	must(t, f.a.RegisterAttachment(f.control, a.RegisterRequest{Operation: id(t), Binding: b}))
	return b, k
}
