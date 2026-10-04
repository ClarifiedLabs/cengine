package storagewire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func prepareFixture() PrepareReply {
	object := a.Ext4ObjectV1{Inode: 22, Generation: 7, FileType: 0040000, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(object.Handle[:4], 22)
	binary.LittleEndian.PutUint32(object.Handle[4:], 7)
	root := a.CopyRootV1{Store: testID, Volume: testID, BackingUUID: [16]byte{1}, Root: object}
	owner := a.Binding{Store: testID, Volume: testID, Attachment: testID, Prepare: testID, Container: a.ContainerID(strings.Repeat("a", 64)), Launch: testID, Key: a.Fingerprint(strings.Repeat("b", 64)), Role: a.PrepareRole, Mode: a.ReadWrite}
	transaction := object
	transaction.Inode = 23
	binary.LittleEndian.PutUint32(transaction.Handle[:4], 23)
	return PrepareReply{Root: root, Intent: a.CopyIntent{ID: testID, Owner: owner, Epoch: testID, Root: root, Transaction: transaction, Phase: a.CopyBound}, Identity: object}
}
func TestPrepareWireAndIoctlRoundTrips(t *testing.T) {
	for action := BeginCopy; action <= FinishCopy; action++ {
		r := PrepareRequest{Node: 99, Handle: 100, Action: action, Intent: testID}
		if action == BeginCopy {
			r.Intent = ""
		}
		if action == IdentityAt {
			r.Path = []byte("dir/raw\xff")
		}
		req := request(r)
		raw, err := Marshal(&req)
		if err != nil {
			t.Fatal(action, err)
		}
		var decoded Request
		if err = Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(decoded, req) {
			t.Fatal(decoded, err)
		}
		reply := Reply{Sequence: 1, Op: OpPrepare, Body: prepareFixture()}
		if err = ValidateReplyFor(req, reply); err != nil {
			t.Fatal(action, err)
		}
		raw, err = Marshal(&reply)
		if err != nil {
			t.Fatal(err)
		}
		var got Reply
		if err = Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(got, reply) {
			t.Fatal(got, err)
		}
		r.Node, r.Handle = 0, 0
		buf, err := EncodePrepareIoctl(r)
		if err != nil || len(buf) != PrepareIoctlSize {
			t.Fatal(err)
		}
		control, err := DecodePrepareIoctl(buf)
		if err != nil || !reflect.DeepEqual(control, r) {
			t.Fatal(control, err)
		}
		buf, err = EncodePrepareIoctlReply(reply.Body.(PrepareReply))
		if err != nil || len(buf) != PrepareIoctlSize {
			t.Fatal(err)
		}
		controlReply, err := DecodePrepareIoctlReply(buf)
		if err != nil || !reflect.DeepEqual(controlReply, reply.Body) {
			t.Fatal(controlReply, err)
		}
	}
	if PrepareIoctl != 0xe000ce41 || PrepareIoctlSize != 8192 || CredentialABI != 3 || Version != 4 || !RequiredProfile().PrepareIdentityV1 {
		t.Fatal("ABI drift")
	}
}
func TestPrepareStrictIoctlEnvelope(t *testing.T) {
	valid, err := EncodePrepareIoctl(PrepareRequest{Action: BeginCopy})
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func([]byte) []byte{
		"short":     func(b []byte) []byte { return b[:len(b)-1] },
		"long":      func(b []byte) []byte { return append(b, 0) },
		"version":   func(b []byte) []byte { b[0]++; return b },
		"op":        func(b []byte) []byte { b[4]++; return b },
		"zero size": func(b []byte) []byte { clear(b[8:12]); return b },
		"oversize":  func(b []byte) []byte { binary.LittleEndian.PutUint32(b[8:], PrepareIoctlSize); return b },
		"reserved":  func(b []byte) []byte { b[12] = 1; return b },
		"tail":      func(b []byte) []byte { b[len(b)-1] = 1; return b },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePrepareIoctl(mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, payload := range []string{
		`{"node":0,"handle":0,"action":1,"intent":"","unknown":0}`,
		`{"node":0,"node":0,"handle":0,"action":1,"intent":""}`,
		`{"Node":0,"handle":0,"action":1,"intent":""}`,
		`{"node":0,"handle":0,"action":1,"intent":"","path":null}`,
		`{"node":1,"handle":0,"action":1,"intent":""}`,
		`{"node":0,"handle":1,"action":1,"intent":""}`,
		`{"node":0,"handle":0,"action":1,"intent":""} {}`,
	} {
		buf := bytes.Clone(valid)
		clear(buf[16:])
		copy(buf[16:], payload)
		binary.LittleEndian.PutUint32(buf[8:], uint32(len(payload)))
		if _, err := DecodePrepareIoctl(buf); err == nil {
			t.Fatal(payload)
		}
	}
	if _, err := DecodePrepareIoctlReply(valid); err == nil {
		t.Fatal("request as reply")
	}
}
func TestPreparePolicyAndPathConfinement(t *testing.T) {
	owner := prepareFixture().Intent.Owner
	base := PrepareRequest{Node: 99, Handle: 100, Action: IdentityAt, Intent: testID, Path: []byte("a/b")}
	r := request(base)
	if err := r.ValidateBinding(owner); err != nil {
		t.Fatal(err)
	}
	owner.Role = a.RuntimeRole
	owner.Prepare = ""
	if !errors.Is(r.ValidateBinding(owner), a.ErrUnauthorized) {
		t.Fatal("runtime accepted")
	}
	owner = prepareFixture().Intent.Owner
	owner.Mode = a.ReadOnly
	if !errors.Is(r.ValidateBinding(owner), ErrReadOnly) {
		t.Fatal("RO accepted")
	}
	for _, kind := range []AuthKind{OpenGrantAuth, NodeMetadataAuth, LifecycleAuth} {
		r.Auth = Auth{Kind: kind}
		if r.Validate() == nil {
			t.Fatal(kind)
		}
	}
	for _, path := range []string{"/a", "../a", "a/..", "a/./b", "a//b", "a/", "a\x00b", strings.Repeat("a", MaxName+1), strings.Repeat("a/", MaxTarget)} {
		b := base
		b.Path = []byte(path)
		if request(b).Validate() == nil {
			t.Fatal("path accepted", path)
		}
	}
	for _, change := range []func(*PrepareRequest){
		func(b *PrepareRequest) { b.Node = 0 }, func(b *PrepareRequest) { b.Handle = 0 }, func(b *PrepareRequest) { b.Action = 0 }, func(b *PrepareRequest) { b.Action = 8 }, func(b *PrepareRequest) { b.Intent = "" }, func(b *PrepareRequest) { b.Action = SealManifest },
	} {
		b := base
		change(&b)
		if request(b).Validate() == nil {
			t.Fatal(b)
		}
	}
	profile := RequiredProfile()
	profile.PrepareIdentityV1 = false
	if (ServerHello{Epoch: testID, Version: Version, Profile: profile}).Validate() == nil || (ServerHello{Epoch: testID, Version: 3, Profile: RequiredProfile()}).Validate() == nil {
		t.Fatal("v3 fallback")
	}
}
func TestPrepareReplyOptionalValuesAndFixedArrays(t *testing.T) {
	for _, action := range []PrepareAction{SealManifest, AuthenticateManifest, FinishCopy} {
		if err := ValidatePrepareReplyFor(PrepareRequest{Action: action, Intent: testID}, PrepareReply{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []PrepareAction{BeginCopy, BindCopyTransaction, IdentityAt} {
		r := PrepareRequest{Action: action, Intent: testID}
		if action == BeginCopy {
			r.Intent = ""
		}
		if action == IdentityAt {
			r.Path = []byte(".")
		}
		if ValidatePrepareReplyFor(r, PrepareReply{}) == nil {
			t.Fatal(action)
		}
	}
	for _, change := range []func(*PrepareReply){
		func(r *PrepareReply) { r.Intent.Phase = "FUTURE" }, func(r *PrepareReply) { r.Intent.ManifestSize = a.MaxCopyManifestBytes + 1 },
		func(r *PrepareReply) { r.Identity.HandleSize = 7 }, func(r *PrepareReply) { r.Identity.HandleType = 2 }, func(r *PrepareReply) { r.Identity.Handle[4]++ }, func(r *PrepareReply) { r.Identity.Inode++ }, func(r *PrepareReply) { r.Root.BackingUUID = [16]byte{} }, func(r *PrepareReply) { r.Intent.Owner.Role = a.RuntimeRole }, func(r *PrepareReply) { r.Intent.Root.BackingUUID[0]++ },
	} {
		r := prepareFixture()
		change(&r)
		if _, err := EncodePrepareIoctlReply(r); err == nil {
			t.Fatal(r)
		}
	}
	raw, err := json.Marshal(prepareFixture())
	if err != nil {
		t.Fatal(err)
	}
	var dto map[string]any
	if err = json.Unmarshal(raw, &dto); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 7, 9} {
		identity := dto["identity"].(map[string]any)
		handle := make([]int, n)
		for index, value := range prepareFixture().Identity.Handle {
			if index < len(handle) {
				handle[index] = int(value)
			}
		}
		identity["handle"] = handle
		// Removing a final zero or appending one otherwise decodes to the SAME
		// valid handle: only strict array length enforcement can reject it.
		payload, _ := json.Marshal(dto)
		buf := make([]byte, PrepareIoctlSize)
		binary.LittleEndian.PutUint32(buf, PrepareIoctlVersion)
		binary.LittleEndian.PutUint32(buf[4:], prepareIoctlReply)
		binary.LittleEndian.PutUint32(buf[8:], uint32(len(payload)))
		copy(buf[16:], payload)
		if _, err := DecodePrepareIoctlReply(buf); err == nil {
			t.Fatal("bad fixed array", n)
		}
	}
}
