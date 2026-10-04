package storagefuse

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestMountConfigurationAuthorityModeAndRole(t *testing.T) {
	cfg := Config{Client: c.Config{Conn: new(tls.Conn), Version: w.Version, Profile: w.RequiredProfile(), Timeout: time.Second}, Retire: func(error) {}}
	cfg.Client.Authority.Binding.Role = a.RuntimeRole
	for _, ro := range []bool{false, true} {
		cfg.ReadOnly = ro
		cfg.Client.Authority.Binding.Mode = a.ReadWrite
		if ro {
			cfg.Client.Authority.Binding.Mode = a.ReadOnly
		}
		if err := validateMountConfig(cfg); err != nil {
			t.Fatal(err)
		}
		cfg.ReadOnly = !ro
		if !errors.Is(validateMountConfig(cfg), ErrProfile) {
			t.Fatal("mode mismatch accepted")
		}
	}
	cfg.ReadOnly = true
	cfg.Client.Authority.Binding.Role = "unknown"
	if !errors.Is(validateMountConfig(cfg), ErrProfile) {
		t.Fatal("unknown role accepted")
	}
}

func TestOptionalDestroyRequiresExactSuccessfulDelivery(t *testing.T) {
	for _, kind := range []string{"clean", "no-intent", "interrupt-opcode", "suppressed", "short", "io", "errno", "unknown-unique", "prior-failure"} {
		t.Run(kind, func(t *testing.T) {
			raw, fc := fixture()
			life := new(mountLifecycle)
			life.closing.Store(kind != "no-intent")
			fs := &lifecycleFS{rawFS: raw, life: life}
			r := fuse.ReplyDelivery{Unique: 7, Opcode: 38, Bytes: 16, Expected: 16}
			switch kind {
			case "interrupt-opcode":
				r.Opcode = 36
			case "suppressed":
				r.Suppressed = true
			case "short":
				r.Bytes = 15
			case "io":
				r.Err = io.ErrUnexpectedEOF
			case "errno":
				r.Status = fuse.EIO
			case "unknown-unique":
				r.Unique = 0
			case "prior-failure":
				raw.stop(io.ErrUnexpectedEOF)
			}
			fs.observeReply(r)
			fs.OnUnmount()
			if (fc.aborted == 0) != (kind == "clean") {
				t.Fatalf("aborted=%d", fc.aborted)
			}
		})
	}
}

func TestGracefulOrderingRejectsBusyUnknownAndTimeout(t *testing.T) {
	for _, failure := range []int{-1, 0, 1, 2, 3} {
		var called []int
		steps := make([]func(context.Context) error, 4)
		for i := range steps {
			i := i
			steps[i] = func(context.Context) error {
				called = append(called, i)
				if i == failure {
					return syscall.EBUSY
				}
				return nil
			}
		}
		err := completeGraceful(context.Background(), steps[0], steps[1], steps[2], steps[3])
		end := 4
		if failure >= 0 {
			end = failure + 1
			if !errors.Is(err, syscall.EBUSY) {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(called, []int{0, 1, 2, 3}[:end]) {
			t.Fatal(called)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	never := func(context.Context) error { t.Fatal("called after cancellation"); return nil }
	if !errors.Is(completeGraceful(ctx, never, never, never, never), context.Canceled) {
		t.Fatal("cancellation reported clean")
	}
}

func TestTerminalReasonsRetainedConcurrently(t *testing.T) {
	life := new(mountLifecycle)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); life.fail(io.ErrUnexpectedEOF); _ = life.result() }()
	}
	wg.Wait()
	life.fail(nil)
	if !errors.Is(life.result(), io.ErrUnexpectedEOF) {
		t.Fatal("lost terminal failure")
	}
}

func TestGracefulDecisionJoinsWatcherWithoutFailureSignal(t *testing.T) {
	life := new(mountLifecycle)
	life.clean.Store(true)
	decision := make(chan struct{})
	close(decision)
	if err := life.waitTerminal(make(chan struct{}), decision, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	terminal := make(chan struct{})
	close(terminal)
	if err := life.waitTerminal(terminal, decision, func() error { return io.ErrUnexpectedEOF }); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("failure hidden by clean decision", err)
	}
}

func TestNativeMountModeProof(t *testing.T) {
	for _, ro := range []bool{false, true} {
		mode := "rw"
		if ro {
			mode = "ro"
		}
		info := "22 1 0:83 / /private/mnt " + mode + ",nosuid,nodev - fuse.managed-v3 managed-v3 rw\n"
		if !mountModeMatches(info, "/private/mnt", 22, ro) {
			t.Fatal(info)
		}
		if mountModeMatches(info, "/private/mnt", 23, ro) || mountModeMatches(info, "/substitution", 22, ro) || mountModeMatches(info, "/private/mnt", 22, !ro) {
			t.Fatal("wrong identity/mode accepted")
		}
	}
}

func TestOrdinaryFuseUnmountDoesNotInventDestroyProof(t *testing.T) {
	raw, fc := fixture()
	life := new(mountLifecycle)
	life.closing.Store(true)
	(&lifecycleFS{rawFS: raw, life: life}).OnUnmount()
	if fc.aborted != 0 || life.clean.Load() || life.unmounted.Load() || life.destroyed.Load() {
		t.Fatal("OnUnmount manufactured proof")
	}
}
