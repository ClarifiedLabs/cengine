//go:build linux

package storageboot

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	pc "dev.cengine/guest/internal/preparecompat"
)

func TestLifecycleIsolationPlatformDataAndCleanup(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full-profile listener observations")
	}
	for _, alreadyBound := range []bool{false, true} {
		t.Run(map[bool]string{false: "actual-data", true: "bind-failure-closes-all"}[alreadyBound], func(t *testing.T) {
			root, err := os.Open(t.TempDir())
			must(t, err)
			defer root.Close()
			cfg, _ := lifecycleTestConfig(t)
			service, err := lifecycleConstruct(root, lifecycleTestBinding(), cfg, func() error { return nil })
			must(t, err)
			defer func() { must(t, service.Close()) }()
			if alreadyBound {
				must(t, service.BindCompatibilityDataListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}))
			}
			var listeners []net.Listener
			listen := func() (net.Listener, error) {
				l := lifecycleSocket(t)
				listeners = append(listeners, l)
				return l, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop, err := startLifecycleServices(ctx, cancel, service, "127.0.0.1:0", func(uint32) (net.Listener, error) { return listen() }, func(string, string) (net.Listener, error) { return listen() }, time.Second)
			if alreadyBound {
				if err == nil || stop != nil {
					t.Fatal("probe binding failure admitted")
				}
			} else {
				must(t, err)
				defer func() { must(t, stop()) }()
				proof, err := service.ProbeIsolation("legacy-connection")
				must(t, err)
				if proof == nil || proof.Result != "legacy-tls-header-rejected" {
					t.Fatal("actual DATA wrapper not used")
				}
				must(t, stop())
			}
			if len(listeners) != 4 {
				t.Fatal("all listeners not acquired")
			}
			for _, l := range listeners {
				if conn, err := net.DialTimeout("tcp", l.Addr().String(), time.Second); err == nil {
					_ = conn.Close()
					t.Fatal("listener leaked")
				}
			}
		})
	}
}
