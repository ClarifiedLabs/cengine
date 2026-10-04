package storageclient

import (
	"context"
	"crypto/tls"
	"errors"
	"reflect"
	"testing"
	"time"

	w "dev.cengine/guest/internal/storagewire"
)

type probeRPC struct {
	body        w.RequestBody
	reply       w.Reply
	otherCaller bool
}

// Real mutually authenticated TLS and DATA codecs/workers, not direct apply
// calls. Credential capture itself is a separate native-Linux responsibility.
func TestXattrProbeCannotBeResolvedByInvalidReply(t *testing.T) {
	for _, invalid := range []string{"sequence", "operation", "result-size"} {
		t.Run(invalid, func(t *testing.T) {
			c := fixture(t, nil, func(conn *tls.Conn) {
				var first, retry w.Request
				if w.ReadFrame(conn, &first) != nil {
					return
				}
				if w.WriteFrame(conn, &w.Reply{Sequence: first.Sequence, Op: w.OpGetXAttr, Errno: 34}) != nil {
					return
				}
				if w.ReadFrame(conn, &retry) != nil {
					return
				}
				reply := w.Reply{Sequence: retry.Sequence, Op: w.OpGetXAttr, Body: w.GetXAttrReply{Size: 4, Value: []byte("data")}}
				switch invalid {
				case "sequence":
					reply.Sequence++
				case "operation":
					reply.Op, reply.Body = w.OpGetAttr, w.GetAttrReply{Attr: testEntry(99, true).Attr}
				case "result-size":
					reply.Body = w.GetXAttrReply{Size: 5, Value: []byte("large")}
				}
				if err := w.WriteFrame(conn, &reply); err != nil {
					t.Error(err)
				}
			})
			if _, err := c.Do(caller(c), 0, w.GetXAttrRequest{Node: 99, Name: []byte("user.x"), Size: 1}); err != nil {
				t.Fatal(err)
			}
			_, err := c.Do(caller(c), 0, w.GetXAttrRequest{Node: 99, Name: []byte("user.x"), Size: 4})
			if !errors.Is(err, ErrIncomplete) || !errors.Is(err, w.ErrInvalid) {
				t.Fatal("invalid reply cleared probe evidence", err)
			}
			if err := c.CloseGracefully(context.Background()); !errors.Is(err, ErrIncomplete) || !errors.Is(err, w.ErrInvalid) {
				t.Fatal(err)
			}
		})
	}
}

func TestGracefulXattrProbeOutcomes(t *testing.T) {
	get := func(name string, size uint32) w.RequestBody {
		return w.GetXAttrRequest{Node: 99, Name: []byte(name), Size: size}
	}
	list := func(size uint32) w.RequestBody { return w.ListXAttrRequest{Node: 99, Size: size} }
	getOK := w.Reply{Body: w.GetXAttrReply{Size: 4, Value: []byte("data")}}
	listOK := w.Reply{Body: w.ListXAttrReply{Size: 7, Names: []byte("user.x\x00")}}
	getRange := probeRPC{body: get("user.x", 1), reply: w.Reply{Errno: 34, Body: w.XAttrSizeError{Size: 4}}}
	listRange := probeRPC{body: list(1), reply: w.Reply{Errno: 34, Body: w.XAttrSizeError{Size: 7}}}
	for _, tc := range []struct {
		name  string
		steps []probeRPC
		clean bool
	}{
		{"absent-user-probe", []probeRPC{{body: get("user.absent", 0), reply: w.Reply{Errno: 61}}}, true},
		{"absent-acl-data", []probeRPC{{body: get("system.posix_acl_access", 128), reply: w.Reply{Errno: 61}}}, true},
		{"get-range-retry", []probeRPC{getRange, {body: get("user.x", 4), reply: getOK}}, true},
		{"list-range-retry", []probeRPC{listRange, {body: list(7), reply: listOK}}, true},
		{"get-range-no-size-body", []probeRPC{{body: get("user.x", 1), reply: w.Reply{Errno: 34}}, {body: get("user.x", 4), reply: getOK}}, true},
		{"range-abandoned", []probeRPC{getRange}, false},
		{"range-repeat-retry", []probeRPC{getRange, getRange, {body: get("user.x", 4), reply: getOK}}, true},
		{"range-size-only", []probeRPC{getRange, {body: get("user.x", 0), reply: w.Reply{Body: w.GetXAttrReply{Size: 4, Value: []byte{}}}}}, false},
		{"range-other-name", []probeRPC{getRange, {body: get("user.y", 4), reply: getOK}}, false},
		{"range-other-caller", []probeRPC{getRange, {body: get("user.x", 4), reply: getOK, otherCaller: true}}, false},
		{"range-other-operation", []probeRPC{getRange, {body: list(7), reply: listOK}}, false},
		{"range-then-absent", []probeRPC{getRange, {body: get("user.x", 4), reply: w.Reply{Errno: 61}}}, false},
		{"range-on-size-probe", []probeRPC{{body: get("user.x", 0), reply: w.Reply{Errno: 34}}, {body: get("user.x", 4), reply: getOK}}, false},
		{"read-eio-not-recovered", []probeRPC{{body: get("user.x", 4), reply: w.Reply{Errno: 5}}, {body: get("user.x", 4), reply: getOK}}, false},
		{"permission-not-recovered", []probeRPC{{body: get("user.x", 4), reply: w.Reply{Errno: 13}}, {body: get("user.x", 4), reply: getOK}}, false},
		{"unsupported-not-empty", []probeRPC{{body: list(7), reply: w.Reply{Errno: 95}}}, false},
		{"list-enodata-not-empty", []probeRPC{{body: list(7), reply: w.Reply{Errno: 61}}}, false},
		{"remove-enodata-not-probe", []probeRPC{{body: w.RemoveXAttrRequest{Node: 99, Name: []byte("user.x")}, reply: w.Reply{Errno: 61}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixture(t, nil, func(conn *tls.Conn) {
				index := 0
				rpcServer(conn, func(req w.Request) w.Reply {
					if index >= len(tc.steps) || !reflect.DeepEqual(req.Body, tc.steps[index].body) {
						t.Error("unexpected DATA request")
						return w.Reply{Errno: 5}
					}
					reply := tc.steps[index].reply
					index++
					return reply
				})
			})
			for _, step := range tc.steps {
				snapshot := caller(c)
				if step.otherCaller {
					snapshot.caller.FSUID++
				}
				result, err := c.Do(snapshot, 0, step.body)
				if err != nil || result.Reply.Errno != step.reply.Errno || !reflect.DeepEqual(result.Reply.Body, step.reply.Body) || c.Err() != nil {
					t.Fatalf("changed DATA errno/result: %+v, %v, terminal=%v", result, err, c.Err())
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := c.CloseGracefully(ctx)
			if tc.clean && err != nil || !tc.clean && !errors.Is(err, ErrIncomplete) {
				t.Fatalf("clean=%t, close=%v", tc.clean, err)
			}
			if tc.clean {
				select {
				case <-c.Terminal():
					t.Fatal("completed probe signaled retirement")
				default:
				}
				c.mu.Lock()
				unchanged := c.pins == 1 && len(c.nodes) == 1 && len(c.wireNodes) == 1 && len(c.handles) == 0
				c.mu.Unlock()
				if !unchanged {
					t.Fatal("probe policy changed grant ownership")
				}
			}
		})
	}
}
