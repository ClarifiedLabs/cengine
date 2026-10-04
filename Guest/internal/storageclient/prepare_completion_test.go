package storageclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func TestPrepareIdentityAbsenceCompletionPolicyClosed(t *testing.T) {
	for _, action := range []w.PrepareAction{0, w.BeginCopy, w.BindCopyTransaction, w.IdentityAt, w.SealManifest, w.AuthenticateManifest, w.StartCleanup, w.FinishCopy, 255} {
		for _, path := range []string{"", ".", "z", ".cengine-copyup-transaction/staging/a"} {
			for errno := uint32(0); errno <= w.MaxLinuxErrno; errno++ {
				want := completedFailure
				if errno == 0 {
					want = completedSuccess
				} else if action == w.IdentityAt && path != "" && path != "." && errno == 2 {
					want = completedNegative
				}
				if got := classifyCompletedOutcome(w.PrepareRequest{Action: action, Path: []byte(path)}, errno); got != want {
					t.Fatalf("action=%d path=%q errno=%d outcome=%d want=%d", action, path, errno, got, want)
				}
			}
		}
	}
}

func prepareCompletionClient(t *testing.T, serve func(*tls.Conn)) *Client {
	t.Helper()
	return fixture(t, func(cfg *Config) {
		cfg.Authority.Binding.Role = a.PrepareRole
		cfg.Authority.Binding.Prepare = testID('6')
	}, serve)
}

func prepareCompletionOpen(t *testing.T, c *Client) w.HandleID {
	t.Helper()
	opened, err := c.Do(caller(c), 0, w.OpenDirRequest{Node: 99})
	if err != nil || opened.Reply.Errno != 0 {
		t.Fatal("root open failed", err)
	}
	grant, err := c.Handle(opened.Handle)
	if err != nil || !grant.Directory || grant.Node != 99 {
		t.Fatal("missing exact root directory grant", err)
	}
	return grant.Handle
}

// Actual TLS, DATA codecs, reply correlation/application and graceful workers.
// Native recovery must observe absent counterparts: published a has no staging/a,
// and staged z has no published z. The negative observation grants no identity.
func TestPrepareIdentityAbsenceGracefulDATA(t *testing.T) {
	type testCase struct {
		name       string
		action     w.PrepareAction
		path       string
		errno      uint32
		priorError bool
		keepHandle bool
		clean      bool
	}
	cases := []testCase{
		{name: "unpublished-entry", action: w.IdentityAt, path: "z", errno: 2, clean: true},
		{name: "published-entry-not-staged", action: w.IdentityAt, path: ".cengine-copyup-transaction/staging/a", errno: 2, clean: true},
		{name: "empty-root", action: w.IdentityAt, errno: 2},
		{name: "dot-root", action: w.IdentityAt, path: ".", errno: 2},
		{name: "prior-error-retained", action: w.IdentityAt, path: "z", errno: 2, priorError: true},
		{name: "unreleased-root-retained", action: w.IdentityAt, path: "z", errno: 2, keepHandle: true},
	}
	for _, errno := range []uint32{1, 5, 13, 20, 40, 116} {
		cases = append(cases, testCase{name: fmt.Sprintf("identity-errno-%d", errno), action: w.IdentityAt, path: "z", errno: errno})
	}
	for _, action := range []w.PrepareAction{w.BeginCopy, w.BindCopyTransaction, w.SealManifest, w.AuthenticateManifest, w.StartCleanup, w.FinishCopy} {
		cases = append(cases, testCase{name: fmt.Sprintf("control-%d-missing", action), action: action, errno: 2})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := prepareCompletionClient(t, func(conn *tls.Conn) {
				rpcServer(conn, func(req w.Request) w.Reply {
					switch req.Body.(type) {
					case w.OpenDirRequest:
						return w.Reply{Body: w.OpenDirReply{Opened: w.Opened{Handle: 100}}}
					case w.PrepareRequest:
						return w.Reply{Errno: tc.errno}
					case w.GetAttrRequest:
						return w.Reply{Errno: 5}
					case w.ReleaseDirRequest:
						return w.Reply{Body: w.ReleaseDirReply{}}
					default:
						t.Error("unexpected DATA request")
						return w.Reply{Errno: 5}
					}
				})
			})
			handle := prepareCompletionOpen(t, c)
			if tc.priorError {
				if r, err := c.Do(caller(c), 0, w.GetAttrRequest{Node: 99}); err != nil || r.Reply.Errno != 5 {
					t.Fatal("prior completed error not delivered", err)
				}
			}
			body := w.PrepareRequest{Node: 99, Handle: handle, Action: tc.action, Intent: testID('7'), Path: []byte(tc.path)}
			if body.Action == w.BeginCopy {
				body.Intent = ""
			}
			r, err := c.Do(caller(c), 0, body)
			if err != nil || r.Reply.Errno != tc.errno || r.Reply.Body != nil {
				t.Fatal("completed errno changed or fabricated identity", r.Reply.Errno, err)
			}
			if !tc.keepHandle {
				if r, err := c.Do(none(c), w.LifecycleAuth, w.ReleaseDirRequest{Node: 99, Handle: handle}); err != nil || r.Reply.Errno != 0 {
					t.Fatal("actual root release not acknowledged", err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = c.CloseGracefully(ctx)
			if tc.clean && err != nil {
				t.Fatal("completed identity absence poisoned graceful close", err)
			}
			if !tc.clean && (!errors.Is(err, ErrIncomplete) || !errors.Is(err, ErrClosed)) {
				t.Fatal("failure or unreleased handle was forgiven", err)
			}
			select {
			case <-c.joined:
			default:
				t.Fatal("close returned without worker join")
			}
			select {
			case <-c.Terminal():
				if tc.clean {
					t.Fatal("negative identity reply became terminal")
				}
			default:
				if !tc.clean {
					t.Fatal("completion failure did not publish terminal state")
				}
			}
		})
	}
}

func TestPrepareIdentityAbsenceRequiresValidatedReply(t *testing.T) {
	for _, fault := range []string{"sequence", "operation", "missing"} {
		t.Run(fault, func(t *testing.T) {
			c := prepareCompletionClient(t, func(conn *tls.Conn) {
				var open, query w.Request
				if w.ReadFrame(conn, &open) != nil || w.WriteFrame(conn, &w.Reply{Sequence: open.Sequence, Op: w.OpOpenDir, Body: w.OpenDirReply{Opened: w.Opened{Handle: 100}}}) != nil || w.ReadFrame(conn, &query) != nil {
					return
				}
				if fault == "missing" {
					_ = conn.Close()
					return
				}
				reply := w.Reply{Sequence: query.Sequence, Op: w.OpPrepare, Errno: 2}
				if fault == "sequence" {
					reply.Sequence++
				} else {
					reply.Op = w.OpLookup
				}
				if err := w.WriteFrame(conn, &reply); err != nil {
					t.Error(err)
				}
			})
			handle := prepareCompletionOpen(t, c)
			if _, err := c.Do(caller(c), 0, w.PrepareRequest{Node: 99, Handle: handle, Action: w.IdentityAt, Intent: testID('7'), Path: []byte("z")}); !errors.Is(err, ErrClosed) {
				t.Fatal("uncorrelated or missing negative reply accepted", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := c.CloseGracefully(ctx); !errors.Is(err, ErrClosed) {
				t.Fatal("invalid reply allowed graceful completion", err)
			}
		})
	}
}
