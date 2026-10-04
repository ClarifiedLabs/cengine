package storageauthority

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func copyObject(inode uint64) Ext4ObjectV1 {
	o := Ext4ObjectV1{Inode: inode, Generation: 29, FileType: 0040000, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(o.Handle[:4], uint32(inode))
	binary.LittleEndian.PutUint32(o.Handle[4:], o.Generation)
	return o
}

func copyRoot(f *fixture, v Volume) CopyRootV1 {
	return CopyRootV1{Store: f.a.s.Store.ID, Volume: v.ID, BackingUUID: [16]byte{1, 2, 3}, Root: copyObject(v.Root.Inode)}
}

func copyPrepare(t *testing.T, f *fixture, v Volume, mode Mode) (Binding, *Guard) {
	t.Helper()
	p := mustID(t)
	b, k := f.binding(v, PrepareRole, mode, p)
	must(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), p, []Binding{b}}))
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}))
	peer, err := f.a.AuthenticateData(context.Background(), f.conn(k, tls.VersionTLS13, true), DataHello{f.a.Epoch(), b})
	must(t, err)
	g, err := f.a.Admit(peer, v.ID, false)
	must(t, err)
	t.Cleanup(g.Release)
	return b, g
}

func copyWaiting(t *testing.T, g *Guard) <-chan struct{} {
	t.Helper()
	ch, err := g.CopyFence()
	must(t, err)
	if ch == nil {
		t.Fatal("missing copy fence")
	}
	select {
	case <-ch:
		t.Fatal("already closed copy fence")
	default:
	}
	return ch
}

func copyUnfenced(t *testing.T, g *Guard) {
	t.Helper()
	ch, err := g.CopyFence()
	must(t, err)
	if ch != nil {
		t.Fatal("unexpected copy fence")
	}
}

func TestCopyIntentAuthenticationDigestAndCompletion(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("copy")
	_, peer := f.runtime(v, ReadWrite) // reservation must not reject runtime RW
	other, err := f.a.Admit(peer, v.ID, false)
	must(t, err)
	defer other.Release()
	b, g := copyPrepare(t, f, v, ReadWrite)
	root := copyRoot(f, v)
	intent, err := g.BeginCopy(root)
	must(t, err)
	if intent.Owner != b || intent.Epoch != f.a.Epoch() || intent.Phase != CopyBegun {
		t.Fatal("wrong owner")
	}
	again, err := g.BeginCopy(root)
	must(t, err)
	if again != intent {
		t.Fatal("Begin changed unfinished intent")
	}
	copyUnfenced(t, g)
	waiting := copyWaiting(t, other)
	device, err := g.CopyDeviceID()
	must(t, err)
	if device != f.c.DeviceID {
		t.Fatal("device identity")
	}
	_, err = other.BeginCopy(root)
	wantErr(t, err, ErrUnauthorized)
	_, err = other.CopyDeviceID()
	wantErr(t, err, ErrUnauthorized)
	wantErr(t, other.FinishCopy(intent.ID), ErrUnauthorized)
	transaction := copyObject(root.Root.Inode + 1)
	manifest := []byte("exact journal bytes\n")
	wantErr(t, g.SealCopyManifest(intent.ID, transaction, manifest), ErrConflict)
	must(t, g.BindCopyTransaction(intent.ID, transaction))
	must(t, g.BindCopyTransaction(intent.ID, transaction))
	_, err = g.AuthenticateCopyManifest(intent.ID, transaction, nil)
	must(t, err)
	_, err = g.AuthenticateCopyManifest(intent.ID, transaction, []byte{})
	wantErr(t, err, ErrInvalid)
	wantErr(t, g.BindCopyTransaction(intent.ID, copyObject(transaction.Inode+1)), ErrConflict)
	must(t, g.SealCopyManifest(intent.ID, transaction, manifest))
	must(t, g.SealCopyManifest(intent.ID, transaction, manifest))
	_, err = g.AuthenticateCopyManifest(intent.ID, transaction, manifest)
	must(t, err)
	_, err = g.AuthenticateCopyManifest(intent.ID, transaction, nil)
	wantErr(t, err, ErrInvalid)
	_, err = g.AuthenticateCopyManifest(intent.ID, transaction, []byte("exact journal bytes!"))
	wantErr(t, err, ErrConflict)
	_, err = g.AuthenticateCopyManifest(mustID(t), transaction, manifest)
	wantErr(t, err, ErrUnauthorized)
	wantErr(t, g.SealCopyManifest(intent.ID, transaction, []byte("changed")), ErrConflict)
	wantErr(t, g.SealCopyManifest(intent.ID, transaction, make([]byte, MaxCopyManifestBytes+1)), ErrInvalid)
	snap, err := f.a.Query(f.control)
	must(t, err)
	data, err := json.Marshal(snap)
	must(t, err)
	var public map[string]any
	must(t, json.Unmarshal(data, &public))
	if public["copy"] != nil {
		t.Fatal("private ledger leaked")
	}
	must(t, g.FinishCopy(intent.ID))
	await(t, waiting)
	copyUnfenced(t, other)
	wantErr(t, g.FinishCopy(intent.ID), ErrUnauthorized)
	_, err = g.AuthenticateCopyManifest(intent.ID, transaction, manifest)
	wantErr(t, err, ErrUnauthorized)
	wantErr(t, g.BindCopyTransaction(intent.ID, transaction), ErrUnauthorized)
	fresh, err := g.BeginCopy(root)
	must(t, err)
	if fresh.ID == intent.ID {
		t.Fatal("reused completed identity")
	}
	wantErr(t, g.FinishCopy(intent.ID), ErrUnauthorized)
	must(t, g.FinishCopy(fresh.ID))
	must(t, f.a.validate())
}

func TestCopyPersistentFenceDrainedReplacement(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("persist")
	b, g := copyPrepare(t, f, v, ReadWrite)
	root := copyRoot(f, v)
	intent, err := g.BeginCopy(root)
	must(t, err)
	tx := copyObject(root.Root.Inode + 1)
	must(t, g.BindCopyTransaction(intent.ID, tx))
	manifest := []byte("persistent")
	must(t, g.SealCopyManifest(intent.ID, tx, manifest))
	intent = f.a.s.Copy.Intents[v.ID]
	oldChannel := f.a.copyFences[v.ID]
	g.Release()
	must(t, f.a.Close())
	await(t, oldChannel)
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	if f.a.s.Copy.Intents[v.ID] != intent || f.a.copyFences[v.ID] == oldChannel {
		t.Fatal("intent/fence did not survive reopen")
	}
	newChannel := f.a.copyFences[v.ID]
	select {
	case <-newChannel:
		t.Fatal("reopened fence closed")
	default:
	}
	nextP := mustID(t)
	nextB, key := f.binding(v, PrepareRole, ReadWrite, nextP)
	replace := ReplaceRequest{mustID(t), b.Prepare, nil, ReserveRequest{mustID(t), nextP, []Binding{nextB}}}
	wantErr(t, f.a.ReplacePrepare(f.control, replace), ErrBlocked)
	receipt := f.retire(b)
	if f.a.s.Copy.Intents[v.ID] != intent {
		t.Fatal("retirement released/changed intent")
	}
	wantErr(t, f.a.CompletePrepare(f.control, CompleteRequest{mustID(t), b.Prepare, []Receipt{receipt}, Attestation{b.Prepare, true, true}}), ErrBlocked)
	replace.Receipts = []Receipt{receipt}
	beforeTransfer := f.a.copyFences[v.ID]
	must(t, f.a.ReplacePrepare(f.control, replace))
	must(t, f.a.ReplacePrepare(f.control, replace))
	await(t, beforeTransfer)
	transferred := f.a.s.Copy.Intents[v.ID]
	want := intent
	want.Owner, want.Epoch = nextB, f.a.Epoch()
	if transferred != want {
		t.Fatal("replacement changed durable identity/digest")
	}
	must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), nextB}))
	peer, err := f.a.AuthenticateData(context.Background(), f.conn(key, tls.VersionTLS13, true), DataHello{f.a.Epoch(), nextB})
	must(t, err)
	nextG, err := f.a.Admit(peer, v.ID, true)
	must(t, err)
	defer nextG.Release()
	got, err := nextG.BeginCopy(root)
	must(t, err)
	if got != want {
		t.Fatal("successor did not resume")
	}
	_, err = nextG.AuthenticateCopyManifest(intent.ID, tx, manifest)
	must(t, err)
	must(t, nextG.FinishCopy(intent.ID))
	must(t, f.a.validate())
}

func TestCopyFenceRetirementWakeDoesNotUnlockOwner(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("retire")
	runtimeB, peer := f.runtime(v, ReadOnly)
	runtimeG, err := f.a.Admit(peer, v.ID, false)
	must(t, err)
	defer runtimeG.Release()
	ownerB, owner := copyPrepare(t, f, v, ReadWrite)
	intent, err := owner.BeginCopy(copyRoot(f, v))
	must(t, err)
	ch := copyWaiting(t, runtimeG)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := RetireRequest{mustID(t), runtimeB.Store, runtimeB.Volume, runtimeB.Attachment, runtimeB.Launch}
	_, err = f.a.Retire(ctx, f.control, req)
	wantErr(t, err, context.Canceled)
	await(t, ch)
	_, err = runtimeG.CopyFence()
	wantErr(t, err, ErrUnauthorized)
	runtimeG.Release()
	_, err = f.a.Retire(context.Background(), f.control, req)
	must(t, err)
	ownerReq := RetireRequest{mustID(t), ownerB.Store, ownerB.Volume, ownerB.Attachment, ownerB.Launch}
	_, err = f.a.Retire(ctx, f.control, ownerReq)
	wantErr(t, err, context.Canceled)
	copyUnfenced(t, owner) // accepted owner work may drain, but no controls
	wantErr(t, owner.FinishCopy(intent.ID), ErrUnauthorized)
	owner.Release()
	_, err = f.a.Retire(context.Background(), f.control, ownerReq)
	must(t, err)
	if f.a.s.Copy.Intents[v.ID].Phase != CopyBegun {
		t.Fatal("retirement completed copy")
	}
	select {
	case <-f.a.copyFences[v.ID]:
		t.Fatal("retirement dropped fence")
	default:
	}
}

func TestCopyGuardAuthAndPhysicalScope(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("scope")
	_, g := copyPrepare(t, f, v, ReadWrite)
	root := copyRoot(f, v)
	for _, change := range []func(*CopyRootV1){
		func(r *CopyRootV1) { r.Store = mustID(t) }, func(r *CopyRootV1) { r.Volume = mustID(t) },
		func(r *CopyRootV1) { r.BackingUUID = [16]byte{} }, func(r *CopyRootV1) { r.Root.Generation++ },
		func(r *CopyRootV1) { r.Root.HandleSize = 7 }, func(r *CopyRootV1) { r.Root.FileType = 0100000 },
		func(r *CopyRootV1) { r.Root = copyObject(r.Root.Inode + 1) },
	} {
		bad := root
		change(&bad)
		_, err := g.BeginCopy(bad)
		wantErr(t, err, ErrInvalid)
	}
	intent, err := g.BeginCopy(root)
	must(t, err)
	wrongUUID := root
	wrongUUID.BackingUUID[0]++
	_, err = g.BeginCopy(wrongUUID)
	wantErr(t, err, ErrConflict)
	otherV := f.volume("other")
	_, otherPeer := f.runtime(otherV, ReadWrite)
	otherG, err := f.a.Admit(otherPeer, otherV.ID, true)
	must(t, err)
	defer otherG.Release()
	copyUnfenced(t, otherG)
	wantErr(t, otherG.FinishCopy(intent.ID), ErrUnauthorized)
	_, ro := copyPrepare(t, f, f.volume("ro"), ReadOnly)
	_, err = ro.BeginCopy(copyRoot(f, f.a.s.Volumes[ro.token.binding.Volume]))
	wantErr(t, err, ErrUnauthorized)
	for _, invalid := range []*Guard{nil, {}, {token: &guardToken{}}} {
		_, err = invalid.CopyFence()
		wantErr(t, err, ErrUnauthorized)
		_, err = invalid.BeginCopy(root)
		wantErr(t, err, ErrUnauthorized)
	}
	must(t, g.FinishCopy(intent.ID))
	g.Release()
	_, err = g.CopyFence()
	wantErr(t, err, ErrClosed)
	_, err = g.BeginCopy(root)
	wantErr(t, err, ErrClosed)
}

func TestCopyStateCorruptionRejected(t *testing.T) {
	for name, corrupt := range map[string]func(*diskState, ID){
		"missing-schema": func(s *diskState, v ID) { s.Copy = nil },
		"future-schema":  func(s *diskState, v ID) { s.Copy.Version++ },
		"missing-table":  func(s *diskState, v ID) { s.Copy.Intents = nil },
		"phase":          func(s *diskState, v ID) { i := s.Copy.Intents[v]; i.Phase = "future"; s.Copy.Intents[v] = i },
		"owner": func(s *diskState, v ID) {
			i := s.Copy.Intents[v]
			i.Owner.Attachment = ID("00000000-0000-4000-8000-000000000000")
			s.Copy.Intents[v] = i
		},
		"handle":                  func(s *diskState, v ID) { i := s.Copy.Intents[v]; i.Root.Root.Handle[0] ^= 1; s.Copy.Intents[v] = i },
		"digest-without-manifest": func(s *diskState, v ID) { i := s.Copy.Intents[v]; i.ManifestDigest[0] = 1; s.Copy.Intents[v] = i },
		"unbound-sealed": func(s *diskState, v ID) {
			i := s.Copy.Intents[v]
			i.Phase = CopySealed
			i.ManifestSize = 2
			i.ManifestDigest[0] = 1
			s.Copy.Intents[v] = i
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("corrupt")
			_, g := copyPrepare(t, f, v, ReadWrite)
			_, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			g.Release()
			s := f.a.clone()
			corrupt(s, v.ID)
			must(t, f.a.j.persist(s))
			must(t, f.a.Close())
			_, err = f.openCurrent()
			wantErr(t, err, ErrInvalid)
		})
	}
}

func TestCopyCommitFaultQuarantinesAndWakes(t *testing.T) {
	for _, operation := range []string{"begin", "bind", "seal", "finish"} {
		t.Run(operation, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("fault")
			_, g := copyPrepare(t, f, v, ReadWrite)
			root := copyRoot(f, v)
			tx := copyObject(root.Root.Inode + 1)
			var intent CopyIntent
			var err error
			if operation != "begin" {
				intent, err = g.BeginCopy(root)
				must(t, err)
			}
			if operation == "seal" || operation == "finish" {
				must(t, g.BindCopyTransaction(intent.ID, tx))
			}
			if operation == "finish" {
				must(t, g.SealCopyManifest(intent.ID, tx, []byte("manifest")))
			}
			ch := f.a.copyFences[v.ID]
			f.a.j.fault = func(step string) error {
				if step == "state-sync" {
					return errors.New("injected IO")
				}
				return nil
			}
			switch operation {
			case "begin":
				_, err = g.BeginCopy(root)
			case "bind":
				err = g.BindCopyTransaction(intent.ID, tx)
			case "seal":
				err = g.SealCopyManifest(intent.ID, tx, []byte("manifest"))
			case "finish":
				err = g.FinishCopy(intent.ID)
			}
			wantErr(t, err, ErrBlocked)
			if ch != nil {
				await(t, ch)
			}
			_, err = g.CopyFence()
			wantErr(t, err, ErrBlocked)
			g.Release()
			must(t, f.a.Close())
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
		})
	}
}

func TestCopyEveryPhasePersistsAndCompletedReplayFailsAfterOpen(t *testing.T) {
	for _, phase := range []string{CopyBegun, CopyBound, CopySealed, CopyCompleted} {
		t.Run(phase, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("phase")
			_, g := copyPrepare(t, f, v, ReadWrite)
			intent, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			tx := copyObject(v.Root.Inode + 1)
			if phase != CopyBegun {
				must(t, g.BindCopyTransaction(intent.ID, tx))
			}
			if phase == CopySealed || phase == CopyCompleted {
				must(t, g.SealCopyManifest(intent.ID, tx, []byte("journal")))
			}
			if phase == CopyCompleted {
				must(t, g.FinishCopy(intent.ID))
			}
			want := f.a.s.Copy.Intents[v.ID]
			g.Release()
			must(t, f.a.Close())
			f.a, err = f.openCurrent()
			must(t, err)
			if f.a.s.Copy.Intents[v.ID] != want {
				t.Fatal("phase changed across reopen")
			}
			if (f.a.copyFences[v.ID] == nil) != (phase == CopyCompleted) {
				t.Fatal("wrong reopened fence")
			}
			wantErr(t, g.FinishCopy(intent.ID), ErrClosed)
			must(t, f.a.validate())
		})
	}
}

func TestCopyReadOnlySuccessorCannotTakeFence(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("successor-mode")
	b, g := copyPrepare(t, f, v, ReadWrite)
	intent, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	g.Release()
	r := f.retire(b)
	nextP := mustID(t)
	nextB, _ := f.binding(v, PrepareRole, ReadOnly, nextP)
	replace := ReplaceRequest{mustID(t), b.Prepare, []Receipt{r}, ReserveRequest{mustID(t), nextP, []Binding{nextB}}}
	revision := f.a.s.Revision
	ch := f.a.copyFences[v.ID]
	wantErr(t, f.a.ReplacePrepare(f.control, replace), ErrBlocked)
	if f.a.s.Revision != revision || f.a.s.Copy.Intents[v.ID] != intent || f.a.copyFences[v.ID] != ch {
		t.Fatal("rejected replacement changed authority")
	}
	must(t, f.a.validate())
}

func TestCopyCapacityFundsBoundSealAndFinish(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("budget")
	_, g := copyPrepare(t, f, v, ReadWrite)
	root := copyRoot(f, v)
	projected := f.a.clone()
	projected.Copy.Intents[v.ID] = CopyIntent{ID: mustID(t), Owner: g.token.binding, Epoch: g.token.epoch, Root: root, Phase: CopyBegun}
	projected.Revision++
	limits := exactCapacity(t, projected)
	// Deliberately exercise the private capacity boundary. Production limits
	// remain immutable; projected Begin has the exact same encoded ID width.
	f.a.limits = limits
	f.a.limits.JournalBytes--
	steps := 0
	f.a.j.fault = func(string) error { steps++; return nil }
	_, err := g.BeginCopy(root)
	wantErr(t, err, ErrLimit)
	if steps != 0 || len(f.a.s.Copy.Intents) != 0 || len(f.a.copyFences) != 0 {
		t.Fatal("unfunded begin escaped")
	}
	f.a.limits = limits
	intent, err := g.BeginCopy(root)
	must(t, err)
	tx := copyObject(uint64(^uint32(0)))
	tx.Generation = ^uint32(0)
	binary.LittleEndian.PutUint32(tx.Handle[4:], tx.Generation)
	must(t, g.BindCopyTransaction(intent.ID, tx))
	must(t, g.SealCopyManifest(intent.ID, tx, make([]byte, MaxCopyManifestBytes)))
	must(t, g.FinishCopy(intent.ID))
	if f.a.fault != nil {
		t.Fatal("reserved completion poisoned authority")
	}
	must(t, f.a.validate())
}

func TestCopyMissingNotificationFailsClosedAndRetiringUnfencedRequestDrains(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("notification")
	b, peer := f.runtime(v, ReadWrite)
	g, err := f.a.Admit(peer, v.ID, false)
	must(t, err)
	defer g.Release()
	_, owner := copyPrepare(t, f, v, ReadWrite)
	intent, err := owner.BeginCopy(copyRoot(f, v))
	must(t, err)
	ch := f.a.copyFences[v.ID]
	delete(f.a.copyFences, v.ID) // test a broken in-memory invariant, not disk repair
	_, err = g.CopyFence()
	wantErr(t, err, ErrBlocked)
	f.a.copyFences[v.ID] = ch
	must(t, owner.FinishCopy(intent.ID))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	_, err = f.a.Retire(ctx, f.control, req)
	wantErr(t, err, context.Canceled)
	copyUnfenced(t, g)
	g.Release()
	_, err = f.a.Retire(context.Background(), f.control, req)
	must(t, err)
}

func TestMissingCopyStateNeverUpgrades(t *testing.T) {
	for _, state := range []string{"empty", "active", "pending-drained", "completed"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t, nil)
			if state == "active" {
				f.runtime(f.volume("active"), ReadWrite)
			}
			if state == "pending-drained" || state == "completed" {
				b, g := copyPrepare(t, f, f.volume("prepare"), ReadWrite)
				g.Release()
				r := f.retire(b)
				if state == "completed" {
					must(t, f.a.CompletePrepare(f.control, CompleteRequest{mustID(t), b.Prepare, []Receipt{r}, Attestation{b.Prepare, true, true}}))
				}
			}
			legacy := f.a.clone()
			legacy.Copy = nil
			must(t, f.a.j.persist(legacy))
			must(t, f.a.Close())
			path := filepath.Join(f.path, registryName, stateName)
			before, err := os.ReadFile(path)
			must(t, err)
			_, err = f.openCurrent()
			wantErr(t, err, ErrInvalid)
			after, err := os.ReadFile(path)
			must(t, err)
			if string(after) != string(before) {
				t.Fatal("missing copy state was repaired or upgraded")
			}
		})
	}
}
