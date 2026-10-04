package storageservice

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

func TestLifecycleConsumerZeroOwner(t *testing.T) {
	for _, service := range []*LifecycleService{nil, {}} {
		for _, command := range []func(cc.Arm) (cc.Status, error){service.ArmConsumerObservation, service.QueryConsumerObservation, service.FinalizeConsumerObservation} {
			if _, err := command(cc.Arm{}); !errors.Is(err, ErrConfiguration) {
				t.Fatal(err)
			}
		}
	}
}

// A real runtime attachment leaf from lifecycle E1 is rejected by lifecycle E2's
// DATA TLS endpoint. Arm/query/finalize must all reach that endpoint's recorder.
func TestLifecycleConsumerActualDATAFinalize(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	controller := lifecycleCredential(t, f)
	workload, join := lifecycleWorkload(t, f.s, controller)
	ready, err := f.s.Ready()
	must(t, err)
	meta, err := f.s.Scope()
	must(t, err)
	volume := id(t)
	call(t, workload, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: ready.Store.ID, Volume: volume, Name: "consumer"}})
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	must(t, err)
	b := a.Binding{Store: ready.Store.ID, Volume: volume, Attachment: id(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: id(t), Key: fingerprint(t, key), Role: a.RuntimeRole, Mode: a.ReadWrite}
	call(t, workload, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: b}})
	workload.Close()
	_ = join() // Closing an established CONTROL stream terminates it with EOF.
	hello := a.DataHello{Epoch: ready.ServiceEpoch, Binding: b}
	binding, err := d.AttachmentBinding(hello)
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	raw, wait := serve(t, f.s.ServeAttachmentCSR)
	cert, err := RequestLifecycleAttachmentCertificate(context.Background(), raw, controller, ready, meta.Identity, hello, csr)
	must(t, err)
	must(t, wait())
	identity, err := cert.WithKey(key)
	must(t, err)
	must(t, f.s.Close())
	f.s, err = ReopenLifecycle(f.cfg, meta.Identity, f.initial, a.ExpectedLifecycleStartup{ExpectedStartup: a.ExpectedStartup{Store: meta.Store.ID, Epoch: meta.Epoch, Controller: meta.Controller}, OpenRevision: meta.OpenRevision})
	must(t, err)
	ready, err = f.s.Ready()
	must(t, err)
	worker := string(id(t))
	sum := sha256.Sum256(cert.DER())
	q := cc.Arm{Version: cc.Version, Profile: cc.Profile, RequestID: string(id(t)), ArmDigest: strings.Repeat("b", 64), OperationUUID: string(id(t)), CaseName: cc.CrossE, OriginalBootBinding: cc.BootBinding{ShimLaunchUUID: string(b.Launch), GuestBootNonce: string(id(t))}, Original: cc.OriginalFor(hello), OriginalLeafSHA256: hex.EncodeToString(sum[:]), WorkerScope: cc.WorkerScope{StoreUUID: string(ready.Store.ID), ServiceEpoch: string(ready.ServiceEpoch), WorkerUUID: worker}}
	commands := []func(cc.Arm) (cc.Status, error){f.s.ArmConsumerObservation, f.s.QueryConsumerObservation, f.s.FinalizeConsumerObservation}
	if pc.CurrentProfile() != pc.FullProfile {
		if f.s.BindPrepareCompatibilityWorker(worker) == nil {
			t.Fatal("ordinary worker bound")
		}
		for _, command := range commands {
			if _, err := command(q); err == nil {
				t.Fatal("ordinary observation enabled")
			}
		}
		return
	}
	if _, err := f.s.ArmConsumerObservation(q); err == nil {
		t.Fatal("arm before admitted worker binding")
	}
	must(t, f.s.BindPrepareCompatibilityWorker(worker))
	if f.s.BindPrepareCompatibilityWorker(string(id(t))) == nil {
		t.Fatal("worker rebound")
	}
	for _, mutate := range []func(*cc.Arm){
		func(q *cc.Arm) { q.WorkerScope.WorkerUUID = string(id(t)) },
		func(q *cc.Arm) { q.WorkerScope.ServiceEpoch = string(id(t)) },
		func(q *cc.Arm) {
			q.WorkerScope.StoreUUID = string(id(t))
			q.Original.Binding.Store = q.WorkerScope.StoreUUID
		},
	} {
		bad := q
		mutate(&bad)
		for _, command := range commands {
			if _, err := command(bad); err == nil {
				t.Fatal("wrong current scope")
			}
		}
	}
	before, err := f.s.Scope()
	must(t, err)
	journal := lifecycleServiceJournal(t, f)
	status, err := f.s.ArmConsumerObservation(q)
	must(t, err)
	if status.State != "armed" {
		t.Fatal(status)
	}
	if _, err := f.s.FinalizeConsumerObservation(q); err == nil {
		t.Fatal("finalized without evidence")
	}
	root, err := p.ParseRootDER(ready.TLSRootDER)
	must(t, err)
	server, err := p.NewServerBinding(p.StoreID(ready.Store.ID), p.ServiceEpoch(ready.ServiceEpoch))
	must(t, err)
	cfg, err := p.ClientTLSConfig(identity, root, server, ready.ServerKey)
	must(t, err)
	reject := func() {
		t.Helper()
		raw, wait := serve(t, f.s.ServeData)
		client := tls.Client(raw, cfg)
		must(t, client.SetDeadline(time.Now().Add(4*time.Second)))
		must(t, client.Handshake())
		var buf [1]byte
		if _, err := client.Read(buf[:]); err == nil {
			t.Fatal("old leaf accepted")
		}
		if err := wait(); err == nil {
			t.Fatal("old leaf not rejected by DATA")
		}
		client.Close()
	}
	reject()
	status, err = f.s.QueryConsumerObservation(q)
	must(t, err)
	must(t, cc.ValidateStatus(status))
	if status.State != "observed" || status.SelectedCount != 1 {
		t.Fatal(status)
	}
	terminal, err := f.s.FinalizeConsumerObservation(q)
	must(t, err)
	status.State = "finalized"
	if !reflect.DeepEqual(status, terminal) {
		t.Fatal("finalize changed evidence")
	}
	reject()
	again, err := f.s.FinalizeConsumerObservation(q)
	must(t, err)
	if !reflect.DeepEqual(again, terminal) {
		t.Fatal("DATA changed sealed result")
	}
	after, err := f.s.Scope()
	must(t, err)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(journal, lifecycleServiceJournal(t, f)) {
		t.Fatal("observation changed authority")
	}
}
