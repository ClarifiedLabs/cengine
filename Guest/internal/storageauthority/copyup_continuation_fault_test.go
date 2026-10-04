//go:build linux || darwin

package storageauthority

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCopyContinuationIOFailureRetainsFence(t *testing.T) {
	for _, step := range []string{"state-sync", "copy-initial-durable", "copy-private-mkdir", "copy-private-sync", "copy-private-parent-sync", "copy-bound-durable", "copy-private-publish", "copy-public-parent-sync", "copy-source-parent-sync"} {
		t.Run(step, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("provision-fault")
			_, g := copyPrepare(t, f, v, ReadWrite)
			i, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			fired := false
			f.a.j.fault = func(name string) error {
				if name == step {
					fired = true
					return unix.EIO
				}
				return nil
			}
			_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
			wantErr(t, err, unix.EIO)
			wantErr(t, err, ErrBlocked)
			if !fired || f.a.s.Copy.Intents[v.ID].Phase == CopyCompleted {
				t.Fatal("failure released durable fence")
			}
			g.Release()
			must(t, f.a.Close())
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
		})
	}
	for _, step := range persistBoundaries {
		t.Run("cleanup/"+step, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("cleanup-fault")
			_, g := copyPrepare(t, f, v, ReadWrite)
			i, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
			must(t, err)
			f.a.j.fault = func(name string) error {
				if name == step {
					return unix.ENOSPC
				}
				return nil
			}
			_, err = g.StartCopyCleanup(i.ID, i.Transaction, i.Initial)
			wantErr(t, err, unix.ENOSPC)
			wantErr(t, err, ErrBlocked)
			if f.a.s.Copy.Intents[v.ID] != i {
				t.Fatal("uncertain cleanup published in memory")
			}
			if _, err = os.Stat(filepath.Join(f.path, "volumes", v.Name, copyTransactionName)); err != nil {
				t.Fatal("cleanup failure removed evidence", err)
			}
			g.Release()
			must(t, f.a.Close())
			_, err = f.openCurrent()
			wantErr(t, err, ErrRepairRequired)
		})
	}
}

func TestCopyContinuationCannotTurnInitialIntoPublicAdoption(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("private-provenance")
	_, g := copyPrepare(t, f, v, ReadWrite)
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	callbackErr := errors.New("identity temporarily unavailable")
	_, err = g.ProvisionCopyTransaction(i.ID, func(int) (Ext4ObjectV1, error) { return Ext4ObjectV1{}, callbackErr })
	wantErr(t, err, callbackErr)
	i = f.a.s.Copy.Intents[v.ID]
	if !i.InitialCaptured || i.Phase != CopyBegun {
		t.Fatal("missing durable initial capture")
	}
	wantErr(t, g.BindCopyTransaction(i.ID, copyObject(v.Root.Inode+1)), ErrConflict)
	wantErr(t, g.FinishCopy(i.ID), ErrConflict)
	private := filepath.Join(f.path, registryName, "copy-"+string(i.ID))
	must(t, os.Chmod(private, 0755))
	_, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	wantErr(t, err, ErrConflict)
	must(t, os.Chmod(private, 0700))
	got, err := g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	if got.Initial != i.Initial {
		t.Fatal("recaptured initial metadata")
	}
	wantErr(t, g.FinishCopy(i.ID), ErrConflict)
	must(t, g.SealCopyManifestDigest(i.ID, got.Transaction, [32]byte{1}, 1))
	wantErr(t, g.FinishCopy(i.ID), ErrConflict)
}

func TestCopyContinuationRevisionReservationThroughLastRevision(t *testing.T) {
	f := newFixture(t, nil)
	v := f.volume("revision")
	b, g := copyPrepare(t, f, v, ReadWrite)
	// Begin plus initial/bind/seal/clean/finish plus retirement intent/receipt
	// and terminal PREPARE, plus the two reserved lifecycle retirement revisions.
	f.a.s.Revision = ^uint64(0) - 11
	must(t, f.a.j.persist(f.a.s))
	i, err := g.BeginCopy(copyRoot(f, v))
	must(t, err)
	i, err = g.ProvisionCopyTransaction(i.ID, hostCopyObject)
	must(t, err)
	must(t, g.SealCopyManifestDigest(i.ID, i.Transaction, [32]byte{1}, MaxCopyManifestBytes))
	c := i.Initial
	c.Manifest = copyObject(i.Transaction.Inode + 1)
	if c.Manifest.Inode == v.Root.Inode {
		c.Manifest = copyObject(i.Transaction.Inode + 2)
	}
	c.Manifest.FileType = 0100000
	_, err = g.StartCopyCleanup(i.ID, i.Transaction, c)
	must(t, err)
	must(t, g.FinishCopy(i.ID))
	g.Release()
	r := f.retire(b)
	must(t, f.a.CompletePrepare(f.control, CompleteRequest{mustID(t), b.Prepare, []Receipt{r}, Attestation{b.Prepare, true, true}}))
	if f.a.s.Revision != ^uint64(0)-2 {
		t.Fatal("incorrect reserved revision count", f.a.s.Revision)
	}
	must(t, f.a.validate())
}

func TestCopyContinuationMalformedCleanupStateRejected(t *testing.T) {
	for _, corruption := range []string{"early-cleanup", "missing-initial-flag", "bad-initial-nanos", "initial-object", "unbound-cleaning", "sealed-cleaning-no-manifest"} {
		t.Run(corruption, func(t *testing.T) {
			f := newFixture(t, nil)
			v := f.volume("invalid")
			_, g := copyPrepare(t, f, v, ReadWrite)
			i, err := g.BeginCopy(copyRoot(f, v))
			must(t, err)
			switch corruption {
			case "early-cleanup":
				i.Cleanup.Mode = 0700
			case "missing-initial-flag":
				i.Initial.Mode = 0700
			case "bad-initial-nanos":
				i.InitialCaptured = true
				i.Initial.MTimeNanos = 1e9
			case "initial-object":
				i.InitialCaptured = true
				i.Initial.Staging = copyObject(v.Root.Inode + 1)
			case "unbound-cleaning":
				i.Phase = CopyCleaning
			case "sealed-cleaning-no-manifest":
				i.Phase = CopyCleaning
				i.Transaction = copyObject(v.Root.Inode + 1)
				i.ManifestSize = 1
				i.ManifestDigest = [32]byte{1}
			}
			f.a.s.Copy.Intents[v.ID] = i
			wantErr(t, f.a.validate(), ErrInvalid)
		})
	}
}
