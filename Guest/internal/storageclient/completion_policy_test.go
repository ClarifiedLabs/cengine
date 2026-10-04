package storageclient

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
)

func TestCompletedOutcomePolicyIsClosed(t *testing.T) {
	bodies := []w.RequestBody{
		w.LookupRequest{}, w.GetAttrRequest{}, w.SetAttrRequest{}, w.CreateRequest{},
		w.OpenRequest{}, w.ReadRequest{}, w.WriteRequest{}, w.FlushRequest{},
		w.FsyncRequest{}, w.FsyncDirRequest{}, w.ReleaseRequest{}, w.ReleaseDirRequest{},
		w.OpenDirRequest{}, w.ReadDirRequest{}, w.MkdirRequest{}, w.MknodRequest{},
		w.SymlinkRequest{}, w.ReadlinkRequest{}, w.LinkRequest{}, w.RenameRequest{},
		w.UnlinkRequest{}, w.RmdirRequest{}, w.AccessRequest{}, w.GetXAttrRequest{Size: 1},
		w.ListXAttrRequest{Size: 1}, w.SetXAttrRequest{}, w.RemoveXAttrRequest{},
		w.StatFSRequest{}, w.ForgetRequest{}, w.FallocateRequest{}, w.LseekRequest{},
	}
	for _, body := range bodies {
		t.Run(string(body.Operation()), func(t *testing.T) {
			for _, errno := range []uint32{0, 1, 2, 5, 13, 22, 28, 30, 34, 61, 95} {
				want := completedFailure
				if errno == 0 {
					want = completedSuccess
				}
				if body.Operation() == w.OpLookup && errno == 2 || body.Operation() == w.OpGetXAttr && errno == 61 {
					want = completedNegative
				}
				if (body.Operation() == w.OpGetXAttr || body.Operation() == w.OpListXAttr) && errno == 34 {
					want = completedProbeRetry
				}
				if got := classifyCompletedOutcome(body, errno); got != want {
					t.Fatalf("errno=%d: got %v want %v", errno, got, want)
				}
			}
		})
	}
	for _, body := range []w.RequestBody{w.GetXAttrRequest{}, w.ListXAttrRequest{}} {
		if classifyCompletedOutcome(body, 34) != completedFailure {
			t.Fatal("size-only ERANGE accepted")
		}
	}
}

func TestXattrProbeKeyRequiresExactQueryAndCaller(t *testing.T) {
	request := func() w.Request {
		return w.Request{Sequence: 1, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{FSUID: 1000, FSGID: 1000, Groups: []uint32{7}, EffectiveCaps: 1}}, Body: w.GetXAttrRequest{Node: 99, Name: []byte("user.x"), Size: 1}}
	}
	key, _, ok := xattrProbe(request())
	if !ok {
		t.Fatal("not a probe")
	}
	for _, field := range []string{"node", "name", "operation", "uid", "gid", "groups", "caps", "size-sequence"} {
		req := request()
		body := req.Body.(w.GetXAttrRequest)
		switch field {
		case "node":
			body.Node++
		case "name":
			body.Name = []byte("user.y")
		case "uid":
			req.Auth.Caller.FSUID++
		case "gid":
			req.Auth.Caller.FSGID++
		case "groups":
			req.Auth.Caller.Groups[0]++
		case "caps":
			req.Auth.Caller.EffectiveCaps++
		case "size-sequence":
			body.Size = 64
			req.Sequence++
		}
		req.Body = body
		if field == "operation" {
			req.Body = w.ListXAttrRequest{Node: body.Node, Size: body.Size}
		}
		got, _, ok := xattrProbe(req)
		if !ok || (got == key) != (field == "size-sequence") {
			t.Fatalf("probe key mismatch: %s", field)
		}
	}
}

func TestGracefulXattrProbeBounds(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		t.Run(map[bool]string{false: "capacity-reused-after-retry", true: "overflow-stays-incomplete"}[overflow], func(t *testing.T) {
			c := fixture(t, func(cfg *Config) { cfg.Limits.Requests = 1 }, func(conn *tls.Conn) {
				rpcServer(conn, func(req w.Request) w.Reply {
					if req.Body.(w.GetXAttrRequest).Size == 1 {
						return w.Reply{Errno: 34}
					}
					return w.Reply{Body: w.GetXAttrReply{Size: 4, Value: []byte("data")}}
				})
			})
			query := func(name string, size uint32) {
				t.Helper()
				result, err := c.Do(caller(c), 0, w.GetXAttrRequest{Node: 99, Name: []byte(name), Size: size})
				if err != nil || size == 1 && result.Reply.Errno != 34 || size != 1 && result.Reply.Errno != 0 {
					t.Fatal(result, err)
				}
				c.mu.Lock()
				bounded := len(c.pendingProbes) <= 1
				c.mu.Unlock()
				if !bounded {
					t.Fatal("unbounded probe evidence")
				}
			}
			query("user.a", 1)
			query("user.a", 1) // repeated same-key insufficiency does not consume another slot
			if !overflow {
				query("user.a", 4)
			}
			query("user.b", 1)
			query("user.a", 4)
			query("user.b", 4)
			err := c.CloseGracefully(context.Background())
			if !overflow && err != nil || overflow && (!errors.Is(err, ErrIncomplete) || !errors.Is(err, ErrCapacity)) {
				t.Fatal(err)
			}
		})
	}
}

func TestXattrUnresolvedProbeSurvivesAbortClose(t *testing.T) {
	for _, abort := range []bool{false, true} {
		c := fixture(t, nil, func(conn *tls.Conn) { rpcServer(conn, func(w.Request) w.Reply { return w.Reply{Errno: 34} }) })
		if _, err := c.Do(caller(c), 0, w.GetXAttrRequest{Node: 99, Name: []byte("user.x"), Size: 1}); err != nil {
			t.Fatal(err)
		}
		reason := errors.New("adapter delivery failure")
		if abort {
			c.Abort(reason)
		}
		err := c.Close()
		if !errors.Is(err, ErrIncomplete) || !errors.Is(err, ErrClosed) || abort && !errors.Is(err, reason) {
			t.Fatal("lost failure evidence", err)
		}
	}
}

func TestGracefulXattrProbeJoinsAcceptedRetry(t *testing.T) {
	proceed, release := gate()
	entered := make(chan struct{})
	c := fixture(t, nil, func(conn *tls.Conn) {
		rpcServer(conn, func(req w.Request) w.Reply {
			if req.Body.(w.GetXAttrRequest).Size == 1 {
				return w.Reply{Errno: 34}
			}
			close(entered)
			<-proceed
			return w.Reply{Body: w.GetXAttrReply{Size: 4, Value: []byte("data")}}
		})
	})
	t.Cleanup(release)
	if _, err := c.Do(caller(c), 0, w.GetXAttrRequest{Node: 99, Name: []byte("user.x"), Size: 1}); err != nil {
		t.Fatal(err)
	}
	retry := make(chan error, 1)
	go func() {
		_, err := c.Do(caller(c), 0, w.GetXAttrRequest{Node: 99, Name: []byte("user.x"), Size: 4})
		retry <- err
	}()
	<-entered
	done := gracefulStart(t, c, context.Background())
	stillClosing(t, done)
	release()
	if err := awaitError(t, retry); err != nil {
		t.Fatal(err)
	}
	if err := awaitError(t, done); err != nil {
		t.Fatal(err)
	}
}
