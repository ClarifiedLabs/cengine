package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"reflect"
	"testing"

	"github.com/willscott/go-nfs-client/nfs/rpc"
)

func authForTest(uid, gid uint32, groups ...uint32) rpc.Auth {
	b := new(bytes.Buffer)
	for _, n := range []uint32{123, 4, 0x686f7374, uid, gid, uint32(len(groups))} {
		binary.Write(b, binary.BigEndian, n)
	}
	for _, n := range groups {
		binary.Write(b, binary.BigEndian, n)
	}
	return rpc.Auth{Flavor: 1, Body: b.Bytes()}
}
func TestParseAuthSys(t *testing.T) {
	good := authForTest(10001, 10002, 7, 8)
	id, err := ParseAuthSys(good)
	if err != nil || id.UID != 10001 || id.GID != 10002 || !reflect.DeepEqual(id.Groups, []uint32{7, 8}) {
		t.Fatalf("identity: %+v %v", id, err)
	}
	cases := []rpc.Auth{rpc.AuthNull, {Flavor: 2, Body: good.Body}, authForTest(^uint32(0), 1), authForTest(1, ^uint32(0)), authForTest(1, 1, ^uint32(0)), authForTest(1, 1, make([]uint32, 17)...), {Flavor: 1, Body: append(append([]byte{}, good.Body...), 0)}}
	for n := 0; n < len(good.Body); n++ {
		cases = append(cases, rpc.Auth{Flavor: 1, Body: good.Body[:n]})
	}
	for i, auth := range cases {
		if _, err := ParseAuthSys(auth); err == nil {
			t.Errorf("accepted malformed credential %d", i)
		}
	}
	huge := append([]byte{}, good.Body...)
	binary.BigEndian.PutUint32(huge[4:8], 256)
	if _, err := ParseAuthSys(rpc.Auth{Flavor: 1, Body: huge}); err == nil {
		t.Fatal("accepted oversized hostname")
	}
}

type identityTestHandler struct {
	Handler
	called bool
}

func (h *identityTestHandler) WithIdentity(_ context.Context, _ Identity, _ func() error) error {
	h.called = true
	return nil
}
func TestDispatchRejectsBadAuthBeforeFilesystem(t *testing.T) {
	for _, cred := range []rpc.Auth{rpc.AuthNull, authForTest(^uint32(0), 1), {Flavor: 1, Body: []byte{1}}} {
		h := &identityTestHandler{}
		c := &conn{Server: &Server{Handler: h}}
		w := &response{conn: c, writer: new(bytes.Buffer), errorFmt: basicErrorFormatter, req: &request{xid: 42, Header: rpc.Header{Prog: nfsServiceID, Proc: 1, Cred: cred}, Body: &io.LimitedReader{R: bytes.NewReader(nil)}}}
		if err := c.handle(context.Background(), w); err != nil {
			t.Fatal(err)
		}
		if h.called {
			t.Fatal("malformed credential reached filesystem scope")
		}
		var words [5]uint32
		if err := binary.Read(w.writer, binary.BigEndian, &words); err != nil {
			t.Fatal(err)
		}
		if words != [5]uint32{42, 1, 1, 1, 1} {
			t.Fatalf("RPC auth denial: %v", words)
		}
	}
}
