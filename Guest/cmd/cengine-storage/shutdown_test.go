package main

import (
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"dev.cengine/guest/internal/storageboot"
)

func TestShutdownStoragePoweroffOnlyAfterAllProofs(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("4105 initialization failed"), errors.New("configuration failed"), errors.New("Ready write failed")} {
		var calls []string
		err := shutdownStorage(func() error { calls = append(calls, "joined-worker"); return terminal },
			func() error { calls = append(calls, "closed-roots"); return nil },
			func() error { calls = append(calls, "synced-unmounted-block-flushed"); return nil },
			func() error { calls = append(calls, "poweroff"); return nil })
		if err != nil || !reflect.DeepEqual(calls, []string{"joined-worker", "closed-roots", "synced-unmounted-block-flushed", "poweroff"}) {
			t.Fatal(calls, err)
		}
	}
}

func TestShutdownStorageUncertaintyNeverPowersOff(t *testing.T) {
	for _, fail := range []string{"worker", "root", "sync", "unmount", "block"} {
		t.Run(fail, func(t *testing.T) {
			var calls []string
			err := shutdownStorage(func() error {
				calls = append(calls, "worker")
				if fail == "worker" {
					return errors.Join(io.EOF, storageboot.ErrShutdownUncertain)
				}
				return io.EOF
			}, func() error {
				calls = append(calls, "root")
				if fail == "root" {
					return syscall.EBUSY
				}
				return nil
			}, func() error { calls = append(calls, fail); return syscall.EIO },
				func() error { t.Fatal("poweroff on uncertainty"); return nil })
			if err == nil {
				t.Fatal("uncertainty reported success")
			}
			if fail == "worker" && !reflect.DeepEqual(calls, []string{"worker"}) {
				t.Fatal("released roots before reaping", calls)
			}
			if fail == "root" && !reflect.DeepEqual(calls, []string{"worker", "root"}) {
				t.Fatal("unmounted before root closure", calls)
			}
		})
	}
}

func TestShutdownStorageWaitsForDelayedReap(t *testing.T) {
	reaped := make(chan struct{})
	entered := make(chan struct{})
	done := make(chan error, 1)
	var mu sync.Mutex
	var calls []string
	record := func(name string) func() error {
		return func() error { mu.Lock(); defer mu.Unlock(); calls = append(calls, name); return nil }
	}
	go func() {
		done <- shutdownStorage(func() error { close(entered); <-reaped; return io.EOF }, record("root"), record("disk"), record("poweroff"))
	}()
	<-entered
	select {
	case <-done:
		t.Fatal("shutdown bypassed reap")
	case <-time.After(10 * time.Millisecond):
	}
	mu.Lock()
	count := len(calls)
	mu.Unlock()
	if count != 0 {
		t.Fatal("closed ownership before reap")
	}
	close(reaped)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(calls, []string{"root", "disk", "poweroff"}) {
		t.Fatal(calls)
	}
}

func TestPID1HasNoPostMountFatalExit(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "var verified diskbootstrap.VerifiedBootResult")
	if start < 0 || strings.Contains(source[start:], "log.Fatal") || strings.Contains(source[start:], "os.Exit") {
		t.Fatal("post-mount fatal exit bypasses cleanup")
	}
	if strings.Count(source, "unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)") != 1 || !strings.Contains(source, "diskbootstrap.CloseStorageShutdownLeases") || !strings.Contains(source, "runtime.KeepAlive(err)") {
		t.Fatal("missing sole poweroff gate or retained ownership")
	}
}
