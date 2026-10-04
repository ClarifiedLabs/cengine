//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storageservice

import (
	"errors"
	"net"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
)

func TestLifecycleNativeFaultRejectsActiveLifecycleSession(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	client, join := lifecycleConnect(t, f.s, lifecycleCredential(t, f), 1)
	if _, err := f.s.InstallNativeFault(a.NativeFaultPlan{}); !errors.Is(err, a.ErrBusy) {
		t.Fatal("active lifecycle connection admitted native fault installation", err)
	}
	must(t, client.Close())
	_ = join()
}

func TestLifecycleNativeFaultAndPendingRequireOwner(t *testing.T) {
	for _, service := range []*LifecycleService{nil, {}} {
		if _, err := service.InstallNativeFault(a.NativeFaultPlan{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid owner installed fault", err)
		}
		left, right := net.Pipe()
		if _, err := service.NativePendingProvision(t.Context(), right, a.DataHello{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid owner provisioned", err)
		}
		_ = left.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := left.Read(make([]byte, 1)); err == nil {
			t.Fatal("invalid owner leaked stream")
		}
		_ = left.Close()
	}
}
