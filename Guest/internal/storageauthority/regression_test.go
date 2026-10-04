package storageauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestConcurrentControlFailureCannotBeClearedBySuccessfulBarrier(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newFixture(t, func(Binding, *os.File) error { close(entered); <-release; return nil })
	v := f.volume("data")
	b, _ := f.runtime(v, ReadWrite)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch}
	_, err := f.a.Retire(ctx, f.control, req)
	wantErr(t, err, context.Canceled)
	await(t, entered)
	other, _ := f.binding(v, RuntimeRole, ReadWrite, "")
	f.a.mu.Lock()
	f.a.j.fault = func(stage string) error {
		if stage == "state-rename" {
			return unix.EIO
		}
		return nil
	}
	f.a.mu.Unlock()
	wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), other}), ErrBlocked)
	f.a.mu.Lock()
	f.a.j.fault = nil
	done := f.a.runtime[b.Attachment].done
	f.a.mu.Unlock()
	close(release)
	await(t, done)
	if f.a.s.Attachments[b.Attachment].Phase != Retiring {
		t.Fatal("barrier cleared concurrent IO fault")
	}
	must(t, f.a.Close())
	_, err = f.openCurrent()
	wantErr(t, err, ErrRepairRequired)
}

func TestRetiringBeforeBarrierSurvivesRestartAndInterruptedBarrierBlocks(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("data")
	b, p := f.runtime(v, ReadWrite)
	g, err := f.a.Admit(p, v.ID, true)
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.a.Retire(ctx, f.control, RetireRequest{mustID(t), b.Store, b.Volume, b.Attachment, b.Launch})
	wantErr(t, err, context.Canceled)
	// Read the real durable intent before allowing the request to finish. It is
	// already RETIRING even though accepted resource cleanup has not completed.
	s, err := f.a.j.load()
	must(t, err)
	if s.Attachments[b.Attachment].Phase != Retiring {
		t.Fatal("intent not durable before wait")
	}
	g.Release()
	f.retire(b)
	must(t, f.a.j.markNamed(barrierName))
	must(t, f.a.Close())
	_, err = f.openCurrent()
	wantErr(t, err, ErrRepairRequired)
}

func TestControlGrantConflictsAndStaleGrantCannotRegainOwnership(t *testing.T) {
	f := newFixture(t, nil)
	take := func(key ed25519.PrivateKey, g LifecycleGrant) {
		t.Helper()
		msg, err := LifecycleGrantSigningBytes(g)
		must(t, err)
		p, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key, tls.VersionTLS13, true))
		must(t, err)
		_, err = f.a.TakeoverLifecycle(p, SignedLifecycleGrant{g, ed25519.Sign(f.bootstrap, msg)})
		must(t, err)
	}
	key2 := newKey(t)
	g := f.takeoverGrant(1, fp(t, key2))
	take(key2, g)
	key3 := newKey(t)
	conflicting := g
	conflicting.NewKey = fp(t, key3)
	msg, err := LifecycleGrantSigningBytes(conflicting)
	must(t, err)
	p3, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key3, tls.VersionTLS13, true))
	must(t, err)
	_, err = f.a.TakeoverLifecycle(p3, SignedLifecycleGrant{conflicting, ed25519.Sign(f.bootstrap, msg)})
	wantErr(t, err, ErrUnauthorized)
	take(key3, f.takeoverGrant(2, fp(t, key3)))
	p2, err := f.a.AuthenticateSuccessor(context.Background(), f.conn(key2, tls.VersionTLS13, true))
	must(t, err)
	msg, err = LifecycleGrantSigningBytes(g)
	must(t, err)
	_, err = f.a.TakeoverLifecycle(p2, SignedLifecycleGrant{g, ed25519.Sign(f.bootstrap, msg)})
	wantErr(t, err, ErrUnauthorized)
	must(t, f.a.validate())
}

func TestInvalidRegistrationAndExactReceiptSet(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("data")
	b, _ := f.binding(v, RuntimeRole, ReadWrite, "")
	req := RegisterRequest{mustID(t), b}
	must(t, f.a.RegisterAttachment(f.control, req))
	must(t, f.a.RegisterAttachment(f.control, req))
	changed := req
	changed.Binding.Mode = ReadOnly
	wantErr(t, f.a.RegisterAttachment(f.control, changed), ErrConflict)
	changed.Operation = mustID(t)
	wantErr(t, f.a.RegisterAttachment(f.control, changed), ErrConflict)
	f.retire(b)
	wantErr(t, f.a.RegisterAttachment(f.control, req), ErrBlocked)
	p := mustID(t)
	prep, _ := f.binding(v, PrepareRole, ReadWrite, p)
	reserve := ReserveRequest{mustID(t), p, []Binding{prep, prep}}
	wantErr(t, f.a.ReservePrepare(f.control, reserve), ErrInvalid)
	reserve.Attachments = []Binding{prep}
	must(t, f.a.ReservePrepare(f.control, reserve))
	receipt := f.retire(prep)
	bad := receipt
	bad.Revision++
	complete := CompleteRequest{mustID(t), p, []Receipt{bad}, Attestation{p, true, true}}
	wantErr(t, f.a.CompletePrepare(f.control, complete), ErrBlocked)
	complete.Receipts = []Receipt{receipt, receipt}
	wantErr(t, f.a.CompletePrepare(f.control, complete), ErrBlocked)
	complete.Receipts = []Receipt{receipt}
	must(t, f.a.CompletePrepare(f.control, complete))
	complete.Attestation.Succeeded = false
	wantErr(t, f.a.CompletePrepare(f.control, complete), ErrConflict)
}

func TestMissingRegistryAndExportSymlinkDoNotInitialize(t *testing.T) {
	f := newFixture(t, nil)
	must(t, f.a.Close())
	must(t, os.Rename(filepath.Join(f.path, registryName), filepath.Join(f.path, "saved-registry")))
	_, err := f.openCurrent()
	wantErr(t, err, ErrMissing)
	must(t, os.Rename(filepath.Join(f.path, "saved-registry"), filepath.Join(f.path, registryName)))
	must(t, os.Rename(filepath.Join(f.path, "volumes"), filepath.Join(f.path, "saved-volumes")))
	must(t, os.Symlink("saved-volumes", filepath.Join(f.path, "volumes")))
	_, err = f.openCurrent()
	if err == nil {
		t.Fatal("followed exports symlink")
	}
}
