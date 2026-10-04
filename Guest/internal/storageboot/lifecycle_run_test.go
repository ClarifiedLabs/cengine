package storageboot

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	s "dev.cengine/guest/internal/storageservice"
)

type lifecycleDeadlineSignal struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
}

func (c *lifecycleDeadlineSignal) SetDeadline(deadline time.Time) error {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.SetDeadline(deadline)
}

func TestLifecycleSessionStopBeforeCloseAndBusyIsReported(t *testing.T) {
	for _, fault := range []string{"joined", "worker-busy", "service-busy", "start-failure"} {
		t.Run(fault, func(t *testing.T) {
			root, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			cfg, _ := lifecycleTestConfig(t)
			host, guest := net.Pipe()
			defer host.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var owner *s.LifecycleService
			var raw net.Conn
			workerDone := make(chan error, 1)
			stopped := false
			startErr := errors.New("start-failure")
			start := func(service *s.LifecycleService) (func() error, error) {
				owner = service
				h, g := net.Pipe()
				raw = g
				t.Cleanup(func() { _ = h.Close() })
				signaled := &lifecycleDeadlineSignal{Conn: raw, entered: make(chan struct{})}
				go func() { workerDone <- service.ServeLifecycle(context.Background(), signaled) }()
				<-signaled.entered // real active transport, not a fake service
				stop := func() error {
					stopped = true
					if _, err := service.Scope(); err != nil {
						t.Error("service closed before stop", err)
					}
					if fault == "worker-busy" {
						return a.ErrBusy
					}
					if fault == "service-busy" {
						return nil
					}
					_ = raw.Close()
					<-workerDone
					return nil
				}
				if fault == "start-failure" {
					return stop, startErr
				}
				return stop, nil
			}
			done := make(chan error, 1)
			go func() {
				done <- lifecycleSessionInProcess(ctx, guest, root, lifecycleTestBinding(), func() error { return nil }, start, time.Second)
			}()
			if _, err = ReadLifecycleFrame(host); err != nil {
				t.Fatal(err)
			}
			config := lifecycleFrame("configure", lifecycleTestBinding())
			config.Configuration = &cfg
			if err = WriteLifecycleFrame(host, &config); err != nil {
				t.Fatal(err)
			}
			_, err = ReadLifecycleFrame(host)
			if fault != "start-failure" && err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case err = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("session failed to stop")
			}
			if !stopped {
				t.Fatal("stop not called")
			}
			if fault == "worker-busy" || fault == "service-busy" {
				if !errors.Is(err, a.ErrBusy) {
					t.Fatal("busy hidden", err)
				}
				_ = raw.Close()
				<-workerDone
			} else if fault == "start-failure" && !errors.Is(err, startErr) {
				t.Fatal("start failure hidden", err)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
