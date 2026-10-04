//go:build linux

package supervisor

import (
	"dev.cengine/guest/internal/protocol"
	"testing"
)

func TestManagedBootRejectsGenericLaunchButAllowsInitialRootFS(t *testing.T) {
	s := New()
	if err := s.RequireManagedBoot(); err != nil {
		t.Fatal(err)
	}
	if s.RequireManagedBoot() == nil {
		t.Fatal("managed boot replay accepted")
	}
	called := false
	if err := s.WithRootFSPreparation(func() error { called = true; return nil }); err != nil || !called {
		t.Fatal("image rootfs blocked before configure")
	}
	if s.Prepare(protocol.WorkloadSpec{}) == nil {
		t.Fatal("generic prepare accepted")
	}
	if _, err := s.Start(); err == nil {
		t.Fatal("generic start accepted")
	}
	if err := s.ConfigureManaged(); err != nil {
		t.Fatal(err)
	}
	if s.WithRootFSPreparation(func() error { t.Fatal("rootfs callback after configure"); return nil }) == nil {
		t.Fatal("generic rootfs accepted")
	}
}
