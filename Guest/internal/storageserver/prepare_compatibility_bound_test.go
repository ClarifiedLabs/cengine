//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageserver

import (
	"context"
	a "dev.cengine/guest/internal/storageauthority"
	m "dev.cengine/guest/internal/storagemanaged"
	w "dev.cengine/guest/internal/storagewire"
	"encoding/binary"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

// Only ext4 generation/handle acquisition is a host stand-in. The inode/type,
// private creation, authority bind, rename, parent fsyncs, obligation, TLS and
// reply-loss paths are real. No native/Linux execution is claimed.
func compatibilityHostObject(fd int) (a.Ext4ObjectV1, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return a.Ext4ObjectV1{}, err
	}
	o := a.Ext4ObjectV1{Inode: st.Ino, Generation: 29, FileType: uint32(st.Mode) & unix.S_IFMT, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(o.Handle[:4], uint32(st.Ino))
	binary.LittleEndian.PutUint32(o.Handle[4:], o.Generation)
	return o, nil
}
func TestStorageCompatibilityA6ActualTLSBoundReplyDrop(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	b, k, witness := fullPrepare(t, f, "transaction-published-bind-reply-lost")
	rootFile, err := os.Open(filepath.Join(f.path, "volumes", "data"))
	must(t, err)
	defer rootFile.Close()
	identity, err := compatibilityHostObject(int(rootFile.Fd()))
	must(t, err)
	root := a.CopyRootV1{Store: b.Store, Volume: b.Volume, BackingUUID: [16]byte{1, 2, 3}, Root: identity}
	f.s.factory = func(g *a.Guard, p *a.DataPrincipal, _ a.Binding) (executor, w.Entry, error) {
		must(t, g.ValidateFor(p))
		return execFunc(func(g *a.Guard, request w.Request) (m.Result, error) {
			if err := g.ValidateFor(p); err != nil {
				return m.Result{}, err
			}
			req := request.Body.(w.PrepareRequest)
			action := a.CopyOperationBegin
			if req.Action == w.BindCopyTransaction {
				action = a.CopyOperationProvision
			}
			op, err := g.BeginCopyOperation(request.Sequence, action, req.Intent)
			if err != nil {
				return m.Result{}, err
			}
			var intent a.CopyIntent
			if req.Action == w.BeginCopy {
				intent, err = g.BeginCopy(root)
			} else {
				intent, err = g.ProvisionCopyTransaction(req.Intent, compatibilityHostObject)
			}
			if err != nil {
				return m.Result{}, err
			}
			if err = op.CompleteRequest(nil, true); err != nil {
				return m.Result{}, err
			}
			reply := w.PrepareReply{Root: root, Intent: intent}
			if req.Action == w.BindCopyTransaction {
				reply.Identity = intent.Transaction
			}
			return m.Result{Reply: w.Reply{Sequence: request.Sequence, Op: w.OpPrepare, Body: reply}}, nil
		}), rootEntry(), nil
	}
	client, done := f.start(b, k)
	var mounted w.RootReply
	must(t, w.ReadFrame(client, &mounted))
	req := w.Request{Sequence: 11, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.PrepareRequest{Node: 1, Handle: 1, Action: w.BeginCopy}}
	must(t, w.WriteFrame(client, &req))
	var begun w.Reply
	must(t, w.ReadFrame(client, &begun))
	intent := begun.Body.(w.PrepareReply).Intent
	req.Sequence = 12
	req.Body = w.PrepareRequest{Node: 1, Handle: 1, Action: w.BindCopyTransaction, Intent: intent.ID}
	must(t, w.WriteFrame(client, &req))
	if _, err = w.ReadServerFrame(client); err == nil {
		t.Fatal("Bind reply not dropped")
	}
	wait(t, done)
	cut := witness.Snapshot()
	if cut.State != "observed" || cut.Sequence != 12 || cut.Bound == nil || cut.Bound.Phase != a.CopyBound || cut.Bound.Owner != b {
		t.Fatal("actual bound cut", cut)
	}
	if _, err = os.Stat(filepath.Join(f.path, "volumes", "data", ".cengine-copyup-transaction")); err != nil {
		t.Fatal(err)
	}
	_, err = f.a.Retire(context.Background(), f.control, a.RetireRequest{Operation: id(t), Store: b.Store, Volume: b.Volume, Attachment: b.Attachment, Launch: b.Launch})
	must(t, err)
	final := witness.Snapshot()
	if final.State != "finished" || !final.RetirementStarted || final.AcceptedInFlight != 0 || *final.Bound != *cut.Bound {
		t.Fatal("actual drain", final)
	}
}
