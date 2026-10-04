package storageclient

import (
	"crypto/tls"
	"errors"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// Real Client.Do, TLS framing and grant bookkeeping: allowing forced FLUSH in
// the adapter must not bypass the attachment's existing open-file authority.
func TestPrepareFlushUsesExactLiveFileGrant(t *testing.T) {
	seen := make(chan w.Request, 2)
	c := fixture(t, func(cfg *Config) {
		cfg.Authority.Binding.Role = a.PrepareRole
		cfg.Authority.Binding.Prepare = testID('6')
	}, func(s *tls.Conn) {
		rpcServer(s, func(req w.Request) w.Reply {
			switch req.Body.(type) {
			case w.CreateRequest:
				return w.Reply{Body: w.CreateReply{Entry: testEntry(100, false), Opened: w.Opened{Handle: 200}}}
			case w.FlushRequest:
				seen <- req
				return w.Reply{Body: w.FlushReply{}}
			case w.ReleaseRequest:
				return w.Reply{Body: w.ReleaseReply{}}
			default:
				return w.Reply{Errno: 5}
			}
		})
	})
	opened, err := c.Do(caller(c), 0, w.CreateRequest{Parent: 99, Name: []byte("a"), Flags: w.OpenCreate | w.OpenWriteOnly | w.OpenExclusive, Mode: 0600})
	if err != nil || opened.Reply.Errno != 0 {
		t.Fatal(opened, err)
	}
	grant, err := c.Handle(opened.Handle)
	if err != nil {
		t.Fatal(err)
	}
	body := w.FlushRequest{Node: grant.Node, Handle: grant.Handle}
	if _, err := c.Do(none(&Client{}), w.OpenGrantAuth, body); !errors.Is(err, ErrCredentials) {
		t.Fatal("foreign captured snapshot accepted", err)
	}
	for _, bad := range []w.FlushRequest{{Node: 99, Handle: grant.Handle}, {Node: grant.Node, Handle: 201}} {
		if _, err := c.Do(none(c), w.OpenGrantAuth, bad); !errors.Is(err, ErrGrant) {
			t.Fatal("foreign node/handle accepted", bad, err)
		}
	}
	if result, err := c.Do(none(c), w.OpenGrantAuth, body); err != nil || result.Reply.Errno != 0 {
		t.Fatal(result, err)
	}
	request := <-seen
	if request.Auth.Kind != w.OpenGrantAuth || request.Auth.Caller != nil || request.Body != body {
		t.Fatal("NONE promoted or handle changed", request)
	}
	if result, err := c.Do(none(c), w.LifecycleAuth, w.ReleaseRequest{Node: grant.Node, Handle: grant.Handle}); err != nil || result.Reply.Errno != 0 {
		t.Fatal(result, err)
	}
	if _, err := c.Do(none(c), w.OpenGrantAuth, body); !errors.Is(err, ErrGrant) {
		t.Fatal("released handle flushed", err)
	}
	select {
	case extra := <-seen:
		t.Fatal("invalid grant reached transport", extra)
	default:
	}
}
