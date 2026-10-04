//go:build linux

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dev.cengine/guest/internal/protocol"
)

func TestManagedSupervisorClosesGenericEntrypoints(t *testing.T) {
	s := New()
	if err := s.ConfigureManaged(); err != nil {
		t.Fatal(err)
	}
	if s.ConfigureManaged() == nil {
		t.Fatal("configuration replay accepted")
	}
	called := false
	if s.WithRootFSPreparation(func() error { called = true; return nil }) == nil || called {
		t.Fatal("rootfs mutation entered after configuration")
	}
	if s.Prepare(protocol.WorkloadSpec{}) == nil {
		t.Fatal("generic prepare entered")
	}
	if _, err := s.Start(); err == nil {
		t.Fatal("generic start entered")
	}
	if _, err := s.StartManaged(nil); err == nil {
		t.Fatal("managed start before prepare")
	}
	if err := s.StopManaged(context.Background()); err != nil {
		t.Fatal(err)
	}
	spec, plan := managedFixture()
	if s.PrepareManaged(spec, plan) == nil {
		t.Fatal("prepare after stop")
	}
}

func TestManagedRootFSAndConfigurationShareLifecycleLock(t *testing.T) {
	s := New()
	entered, release, configured := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { _ = s.WithRootFSPreparation(func() error { close(entered); <-release; return nil }) }()
	<-entered
	go func() { configured <- s.ConfigureManaged() }()
	select {
	case err := <-configured:
		t.Fatalf("configuration raced rootfs streaming: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-configured; err != nil {
		t.Fatal(err)
	}
}

func TestManagedStopHonorsDeadlineWaitingForLifecycle(t *testing.T) {
	s := New()
	if err := s.ConfigureManaged(); err != nil {
		t.Fatal(err)
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.StopManaged(ctx); err != context.DeadlineExceeded {
		t.Fatalf("stop deadline: %v", err)
	}
}

func TestManagedInjectionRejectedOnGenericLegacyPrepareAndStart(t *testing.T) {
	for _, kind := range []string{"volume", "bind", "tmpfs", "socket"} {
		s := New()
		spec := protocol.WorkloadSpec{Mounts: []protocol.Mount{{Kind: kind, ManagedAttachment: managedTestRuntime}}}
		if s.Prepare(spec) == nil {
			t.Fatalf("prepare accepted injection on %s", kind)
		}
		s.spec = &spec
		if _, err := s.Start(); err == nil {
			t.Fatalf("start accepted injection on %s", kind)
		}
	}
}

func TestManagedCopyUpReusesConfinedInitializationAndNoCopy(t *testing.T) {
	rootfs, base := t.TempDir(), t.TempDir()
	image := filepath.Join(rootfs, "data")
	volume := filepath.Join(base, managedTestPrepare, "root")
	if err := os.MkdirAll(image, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(volume, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(image, "seed"), []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	mount := protocol.Mount{Kind: "volume", Source: managedTestVolume, Destination: "/data", ManagedAttachment: managedTestPrepare, NoCopy: true, ReadOnly: true}
	if err := initializeManagedVolumeAt(rootfs, base, mount); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(volume, "seed")); !os.IsNotExist(err) {
		t.Fatalf("nocopy seeded volume: %v", err)
	}
	mount.NoCopy = false
	if err := initializeManagedVolumeAt(rootfs, base, mount); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(volume, "seed"))
	if err != nil || string(data) != "image" {
		t.Fatalf("copy-up: %q %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(volume, "seed"), []byte("authoritative"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initializeManagedVolumeAt(rootfs, base, mount); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(volume, "seed"))
	if err != nil || string(data) != "authoritative" {
		t.Fatalf("reuse overwrote data: %q %v", data, err)
	}
}

func TestManagedPrivateRootRejectsSymlinkedAttachmentAndRoot(t *testing.T) {
	for _, component := range []string{"attachment", "root"} {
		t.Run(component, func(t *testing.T) {
			base, outside := t.TempDir(), t.TempDir()
			attachment := filepath.Join(base, managedTestPrepare)
			link := attachment
			if component == "root" {
				if err := os.Mkdir(attachment, 0700); err != nil {
					t.Fatal(err)
				}
				link = filepath.Join(attachment, "root")
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			root, err := openManagedRoot(base, managedTestPrepare)
			if err == nil {
				root.close()
				t.Fatal("symlinked private root accepted")
			}
		})
	}
}
