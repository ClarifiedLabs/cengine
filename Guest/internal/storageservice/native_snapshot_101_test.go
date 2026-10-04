//go:build cengine_native_faulttest

package storageservice

import (
	"context"
	"errors"
	"net"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
)

// Real InitializeLifecycle/Ready, owned authority/resources and typed TLS configuration;
// no host executor, fabricated Server, mounted filesystem or native acceptance.
func snapshot101Targets(t *testing.T, f *snapshot101Fixture) [2]a.Binding {
	t.Helper()
	var targets [2]a.Binding
	volume := id(t)
	for i := range targets {
		key, err := p.NewAttachmentKey(p.RuntimeRole)
		must(t, err)
		targets[i] = a.Binding{Store: f.ready.Store.ID, Volume: volume, Attachment: id(t), Container: a.ContainerID(id(t)), Launch: id(t), Key: fingerprint(t, key), Role: a.RuntimeRole, Mode: a.ReadWrite}
	}
	return targets
}

func installSnapshot101(f *snapshot101Fixture, queue bool, epoch a.ID, targets [2]a.Binding) error {
	if queue {
		_, err := f.s.InstallNativeSnapshot101Queue(epoch, targets)
		return err
	}
	_, err := f.s.InstallNativeSnapshot101(targets)
	return err
}

func TestNativeSnapshot101InstallInitializedService(t *testing.T) {
	for _, queue := range []bool{false, true} {
		name := "observer"
		if queue {
			name = "queue"
		}
		t.Run(name, func(t *testing.T) {
			f := newSnapshot101Fixture(t)
			targets := snapshot101Targets(t, f)
			for _, bad := range []string{"store", "volume", "attachment", "role", "mode"} {
				invalid := targets
				switch bad {
				case "store":
					invalid[0].Store, invalid[1].Store = id(t), id(t)
					invalid[1].Store = invalid[0].Store
				case "volume":
					invalid[1].Volume = id(t)
				case "attachment":
					invalid[1].Attachment = invalid[0].Attachment
				case "role":
					invalid[1].Role = a.PrepareRole
				case "mode":
					invalid[1].Mode = a.ReadOnly
				}
				if err := installSnapshot101(f, queue, f.ready.ServiceEpoch, invalid); !errors.Is(err, d.ErrConfiguration) && !errors.Is(err, ErrConfiguration) {
					t.Fatalf("%s: %v", bad, err)
				}
			}
			if queue {
				if err := installSnapshot101(f, true, id(t), targets); !errors.Is(err, ErrConfiguration) {
					t.Fatalf("foreign epoch: %v", err)
				}
			}
			must(t, installSnapshot101(f, queue, f.ready.ServiceEpoch, targets))
			for _, other := range []bool{false, true} {
				if err := installSnapshot101(f, other, f.ready.ServiceEpoch, targets); !errors.Is(err, d.ErrConfiguration) {
					t.Fatalf("duplicate/cross install: %v", err)
				}
			}
		})
	}
}

func TestNativeSnapshot101InstallAfterTransportRejected(t *testing.T) {
	for _, transport := range []string{"control", "lifecycle", "data", "credentials", "direct-data"} {
		for _, queue := range []bool{false, true} {
			name := "observer"
			if queue {
				name = "queue"
			}
			t.Run(transport+"/"+name, func(t *testing.T) {
				f := newSnapshot101Fixture(t)
				targets := snapshot101Targets(t, f)
				worker := f.s.ServeControl
				switch transport {
				case "lifecycle":
					worker = f.s.ServeLifecycle
				case "data":
					worker = f.s.ServeData
				case "credentials":
					worker = f.s.ServeAttachmentCSR
				case "direct-data":
					worker = func(ctx context.Context, raw net.Conn) error {
						return f.s.owner.data.Serve(ctx, f.s.owner.authority, raw)
					}
				}
				raw, wait := serve(t, worker)
				must(t, raw.Close())
				if err := wait(); err == nil {
					t.Fatal("closed unauthenticated transport succeeded")
				}
				if f.s.owner.controlActive != 0 || f.s.owner.lifecycleActive != 0 || f.s.owner.dataActive != 0 {
					t.Fatal("transport not joined")
				}
				err := installSnapshot101(f, queue, f.ready.ServiceEpoch, targets)
				if !errors.Is(err, ErrConfiguration) && !errors.Is(err, d.ErrConfiguration) {
					t.Fatalf("late install: %v", err)
				}
			})
		}
	}
}

func TestNativeSnapshot101InstallActiveAndClosedServiceRejected(t *testing.T) {
	f := newSnapshot101Fixture(t)
	targets := snapshot101Targets(t, f)
	client, wait := lifecycleWorkload(t, f.s, lifecycleCredential(t, f.lifecycleFixture)) // actual authenticated control TLS
	for _, queue := range []bool{false, true} {
		if err := installSnapshot101(f, queue, f.ready.ServiceEpoch, targets); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("active install: %v", err)
		}
	}
	client.Close()
	wait()
	must(t, f.s.Close())
	for _, queue := range []bool{false, true} {
		if err := installSnapshot101(f, queue, f.ready.ServiceEpoch, targets); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("closed install: %v", err)
		}
	}
}

type snapshot101Fixture struct {
	*lifecycleFixture
	ready Ready
}

func newSnapshot101Fixture(t *testing.T) *snapshot101Fixture {
	t.Helper()
	f := newLifecycleServiceFixture(t)
	ready, err := f.s.Ready()
	must(t, err)
	return &snapshot101Fixture{f, ready}
}
func TestNativeLifecycleSnapshotInvalidOwner(t *testing.T) {
	for _, service := range []*LifecycleService{nil, {}} {
		if _, err := service.InstallNativeSnapshot101([2]a.Binding{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal(err)
		}
		if _, err := service.InstallNativeSnapshot101Queue("", [2]a.Binding{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal(err)
		}
	}
}
