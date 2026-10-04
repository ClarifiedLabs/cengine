package storageclient

import (
	"crypto/tls"
	w "dev.cengine/guest/internal/storagewire"
	"errors"
	"reflect"
	"testing"
)

func TestDoStampsOnlyCapturedMetadata(t *testing.T) {
	want := w.MetadataValid | w.MetadataCTime | w.MetadataKillSUID | w.MetadataKillPriv
	c := fixture(t, nil, func(server *tls.Conn) {
		var req w.Request
		if err := w.ReadFrame(server, &req); err != nil {
			t.Error(err)
			return
		}
		b, ok := req.Body.(w.SetAttrRequest)
		if !ok || b.Semantics != want || b.Valid != 0 || req.Auth.Caller.FSUID != 11001 || req.Auth.Caller.EffectiveCaps != 0 || !reflect.DeepEqual(req.Auth.Caller.Groups, []uint32{7, 7, 8}) {
			t.Errorf("lost captured metadata/identity: %+v", req)
		}
		if err := w.WriteFrame(server, &w.Reply{Sequence: req.Sequence, Op: w.OpSetAttr, Errno: 1}); err != nil {
			t.Error(err)
		}
	})
	s, err := capture(func(_ int, h *credentialHeader, groups []uint32) error {
		if h.Version != 3 || h.Unique != 123 || h.Semantics != 0 {
			t.Fatal("nonzero input semantics or source mismatch")
		}
		h.State = 1
		h.Valid = c.supportedCaps
		h.FSUID = 11001
		h.FSGID = 11002
		h.GroupCount = 3
		h.Semantics = uint64(want)
		copy(groups, []uint32{7, 7, 8})
		return nil
	}, 77, 123, c.supportedCaps)
	if err != nil {
		t.Fatal(err)
	}
	s.owner = c
	for _, tc := range []struct {
		s    Snapshot
		kind w.AuthKind
		body w.RequestBody
	}{
		{caller(c), 0, w.SetAttrRequest{Node: 99}},
		{none(c), w.NodeMetadataAuth, w.SetAttrRequest{Node: 99}},
		{s, 0, w.GetAttrRequest{Node: 99}},
		{s, 0, w.SetAttrRequest{Node: 99, Semantics: want}},
		{s, 0, w.SetAttrRequest{Node: 99, Semantics: w.MetadataValid}},
		{Snapshot{owner: c, valid: true, semantics: want}, w.NodeMetadataAuth, w.GetAttrRequest{Node: 99}},
	} {
		if _, err := c.Do(tc.s, tc.kind, tc.body); !errors.Is(err, ErrCredentials) {
			t.Fatalf("accepted provenance override: %v", err)
		}
	}
	body := w.SetAttrRequest{Node: 99}
	if _, err := c.Do(s, 0, body); err != nil {
		t.Fatal(err)
	}
	if body.Semantics != 0 {
		t.Fatal("mutated caller builder")
	}
}
