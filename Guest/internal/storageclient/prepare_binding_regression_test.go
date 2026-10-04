package storageclient

import (
	"crypto/tls"
	"sync/atomic"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func TestPrepareBindingRejectsRuntimeAndReadOnlyControlBeforeTransport(t *testing.T) {
	for _, role := range []a.Role{a.RuntimeRole, a.PrepareRole} {
		for _, mode := range []a.Mode{a.ReadOnly, a.ReadWrite} {
			if role == a.PrepareRole && mode == a.ReadWrite {
				continue
			}
			t.Run(string(role)+"-"+string(mode), func(t *testing.T) {
				var requests atomic.Int32
				client := fixture(t, func(cfg *Config) {
					cfg.Authority.Binding.Role = role
					cfg.Authority.Binding.Mode = mode
					if role == a.PrepareRole {
						cfg.Authority.Binding.Prepare = testID('6')
					}
				}, func(s *tls.Conn) {
					rpcServer(s, func(req w.Request) w.Reply { requests.Add(1); return w.Reply{Errno: 5} })
				})
				for action := w.BeginCopy; action <= w.StartCleanup; action++ {
					body := w.PrepareRequest{Node: 99, Handle: 100, Action: action}
					if action != w.BeginCopy {
						body.Intent = testID('7')
					}
					req := w.Request{Sequence: 1, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: body}
					if req.ValidateBinding(client.authority.Binding) == nil {
						t.Fatal("binding admitted control", action)
					}
					if _, err := client.Do(caller(client), 0, body); err == nil {
						t.Fatal("client admitted control", action)
					}
				}
				if requests.Load() != 0 {
					t.Fatal("control reached DATA")
				}
			})
		}
	}
}
