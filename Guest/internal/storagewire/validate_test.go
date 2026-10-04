package storagewire

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"dev.cengine/guest/internal/storageauthority"
)

type operationCase struct {
	req     RequestBody
	rep     ReplyBody
	mutates bool
}

func operationCases() []operationCase {
	entry := goodEntry()
	attr := goodAttr()
	opened := Opened{4}
	directory := entry
	directory.Attr.Mode = 0040755
	symlink := entry
	symlink.Attr.Mode = 0120777
	device := entry
	device.Attr.Mode = 0020600
	device.Attr.Rdev = 258
	return []operationCase{
		{LookupRequest{1, []byte{255}}, LookupReply{entry}, false},
		{GetAttrRequest{Node: 1}, GetAttrReply{attr}, false},
		{SetAttrRequest{Node: 1, Valid: SetSize, Semantics: MetadataValid | MetadataKillSUID | MetadataKillSGID}, SetAttrReply{attr}, true},
		{CreateRequest{1, []byte("x"), OpenCreate | OpenReadWrite, 0, 0644, 0022}, CreateReply{entry, opened}, true},
		{OpenRequest{1, OpenReadOnly, 0}, OpenReply{opened}, false},
		{ReadRequest{1, 4, 0, 3, 0}, ReadReply{[]byte{0, 255, 128}}, false},
		{WriteRequest{1, 4, 0, OpenWriteOnly, 0, []byte{0, 255, 128}}, WriteReply{3}, true},
		{FlushRequest{1, 4}, FlushReply{}, false},
		{FsyncRequest{1, 4, true}, FsyncReply{}, false},
		{FsyncDirRequest{1, 4, false}, FsyncDirReply{}, false},
		{ReleaseRequest{1, 4, ReleaseFlush}, ReleaseReply{}, false},
		{ReleaseDirRequest{1, 4, 0}, ReleaseDirReply{}, false},
		{OpenDirRequest{1, OpenDirectory}, OpenDirReply{opened}, false},
		{ReadDirRequest{1, 4, 0, MaxIO}, ReadDirReply{[]DirEntry{{[]byte{255}, 123, 0100644, 1}}}, false},
		{MkdirRequest{1, []byte("x"), 0040755, 0022}, MkdirReply{directory}, true},
		{MknodRequest{1, []byte("x"), 0020600, 0022, 258}, MknodReply{device}, true},
		{SymlinkRequest{1, []byte("x"), []byte{255, '/', 'y'}}, SymlinkReply{symlink}, true},
		{ReadlinkRequest{1}, ReadlinkReply{[]byte{255, '/', 'y'}}, false},
		{LinkRequest{1, 2, []byte("x")}, LinkReply{entry}, true},
		{RenameRequest{1, 2, []byte("x"), []byte("y"), RenameExchange}, RenameReply{}, true},
		{UnlinkRequest{1, []byte("x")}, UnlinkReply{}, true},
		{RmdirRequest{1, []byte("x")}, RmdirReply{}, true},
		{AccessRequest{1, 4}, AccessReply{}, false},
		{GetXAttrRequest{1, []byte("user.x"), 2}, GetXAttrReply{2, []byte{0, 255}}, false},
		{ListXAttrRequest{1, MaxXAttr}, ListXAttrReply{8, []byte{'u', 's', 'e', 'r', '.', 255, 'x', 0}}, false},
		{SetXAttrRequest{1, []byte{'u', 's', 'e', 'r', '.', 255}, []byte{}, XAttrCreate}, SetXAttrReply{}, true},
		{RemoveXAttrRequest{1, []byte("user.x")}, RemoveXAttrReply{}, true},
		{StatFSRequest{1}, StatFSReply{FSStat{10, 5, 4, 20, 10, 4096, 255, 4096}}, false},
		{ForgetRequest{[]ForgetEntry{{1, math.MaxUint64}, {2, 1}}}, ForgetReply{}, false},
		{FallocateRequest{1, 4, 0, 10, FallocateKeepSize | FallocatePunchHole}, FallocateReply{}, true},
		{LseekRequest{1, 4, 10, SeekHole}, LseekReply{20}, false},
	}
}
func TestEveryOperationRoundTripAndPolicy(t *testing.T) {
	cases := operationCases()
	if len(cases) != len(policies) {
		t.Fatal("operation coverage drift")
	}
	seen := map[Operation]bool{}
	for _, c := range cases {
		t.Run(string(c.req.Operation()), func(t *testing.T) {
			op := c.req.Operation()
			if seen[op] {
				t.Fatal("duplicate fixture")
			}
			seen[op] = true
			req := request(c.req)
			p, ok := PolicyFor(op)
			if !ok {
				t.Fatal("missing policy")
			}
			if p.AuthKinds.Allows(LifecycleAuth) {
				req.Auth = Auth{Kind: LifecycleAuth}
			}
			rep := Reply{Sequence: 1, Op: op, Body: c.rep}
			if err := ValidateReplyFor(req, rep); err != nil {
				t.Fatal(err)
			}
			for _, m := range []Message{&req, &rep} {
				b, err := Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				dst := reflect.New(reflect.TypeOf(m).Elem()).Interface().(Message)
				if err := Unmarshal(b, dst); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(m, dst) {
					t.Fatalf("roundtrip mismatch: %s", b)
				}
			}
			if req.Mutates() != c.mutates {
				t.Fatal("mutation table mismatch")
			}
			if err := req.ValidatePolicy(storageauthority.ReadWrite); err != nil {
				t.Fatal(err)
			}
			if err := req.ValidatePolicy(storageauthority.ReadOnly); (err == nil) == c.mutates {
				t.Fatalf("RO: %v", err)
			}
			// Every closed operation is checked against every auth kind, not merely
			// the representative auth used by its roundtrip fixture.
			for kind := AuthKind(0); kind <= LifecycleAuth+1; kind++ {
				alt := req
				alt.Auth = Auth{Kind: kind}
				if kind == CallerAuth {
					alt.Auth = callerAuth()
				}
				want := p.AuthKinds.Allows(kind)
				if op == OpGetAttr && kind == OpenGrantAuth {
					want = false
				}
				if err := alt.Validate(); (err == nil) != want {
					t.Errorf("auth %d: %v, want %v", kind, err, want)
				}
			}
			// Error paths still retain the exact request op and sequence.
			errorRep := Reply{Sequence: 1, Op: op, Errno: 5}
			if err := ValidateReplyFor(req, errorRep); err != nil {
				t.Fatal(err)
			}
			b, err := Marshal(&errorRep)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Reply
			if err := Unmarshal(b, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Body != nil {
				t.Fatal("error acquired body")
			}
			errorRep.Sequence = 2
			if err := ValidateReplyFor(req, errorRep); err == nil {
				t.Fatal("wrong sequence")
			}
		})
	}
}
func TestKillprivRequestShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  RequestBody
		valid bool
	}{
		{"setattr_noop", SetAttrRequest{Semantics: MetadataValid, Node: 1}, true},
		{"setattr_size", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetSize}, true},
		{"setattr_mode", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetMode, Mode: 0600}, true},
		{"setattr_now", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetATime | SetATimeNow}, true},
		{"setattr_kill_only", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetKillSUIDGID, KillSUIDGID: true}, false},
		{"setattr_mode_kill", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetMode | SetKillSUIDGID, Mode: 0600, KillSUIDGID: true}, false},
		{"setattr_now_kill", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetATimeNow | SetKillSUIDGID, KillSUIDGID: true}, false},
		{"setattr_size_kill", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetSize | SetKillSUIDGID, KillSUIDGID: true}, false},
		{"setattr_uid_kill", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetUID | SetKillSUIDGID, KillSUIDGID: true}, false},
		{"setattr_gid_kill", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetGID | SetKillSUIDGID, KillSUIDGID: true}, false},
		{"setattr_uid_gid_kill", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetUID | SetGID | SetKillSUIDGID, UID: 123, GID: 456, KillSUIDGID: true}, false},
		{"setattr_missing_kill_bit", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetSize, KillSUIDGID: true}, false},
		{"setattr_missing_kill_value", SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetSize | SetKillSUIDGID}, false},
		{"open_read_only", OpenRequest{1, OpenReadOnly, 0}, true},
		{"open_read_only_truncate", OpenRequest{1, OpenReadOnly | OpenTruncate, 0}, false},
		{"open_read_only_kill", OpenRequest{1, OpenReadOnly, FuseOpenKillSUIDGID}, false},
		{"open_write_only_kill", OpenRequest{1, OpenWriteOnly, FuseOpenKillSUIDGID}, false},
		{"open_read_write_kill", OpenRequest{1, OpenReadWrite, FuseOpenKillSUIDGID}, false},
		{"open_read_only_truncate_kill", OpenRequest{1, OpenReadOnly | OpenTruncate, FuseOpenKillSUIDGID}, false},
		{"open_write_only_truncate_kill", OpenRequest{1, OpenWriteOnly | OpenTruncate, FuseOpenKillSUIDGID}, false},
		{"open_read_write_truncate_kill", OpenRequest{1, OpenReadWrite | OpenTruncate, FuseOpenKillSUIDGID}, false},
		{"create_kill", CreateRequest{1, []byte("x"), OpenCreate | OpenReadWrite, FuseOpenKillSUIDGID, 0644, 0022}, false},
		{"create_exclusive_kill", CreateRequest{1, []byte("x"), OpenCreate | OpenExclusive | OpenReadWrite, FuseOpenKillSUIDGID, 0644, 0022}, false},
		{"create_exclusive_truncate_kill", CreateRequest{1, []byte("x"), OpenCreate | OpenExclusive | OpenReadWrite | OpenTruncate, FuseOpenKillSUIDGID, 0644, 0022}, false},
		{"create_exclusive_truncate", CreateRequest{1, []byte("x"), OpenCreate | OpenExclusive | OpenReadWrite | OpenTruncate, 0, 0644, 0022}, true},
		{"create_read_only_truncate", CreateRequest{1, []byte("x"), OpenCreate | OpenReadOnly | OpenTruncate, 0, 0644, 0022}, true},
		{"create_read_only_truncate_kill", CreateRequest{1, []byte("x"), OpenCreate | OpenReadOnly | OpenTruncate, FuseOpenKillSUIDGID, 0644, 0022}, false},
		{"create_write_only_truncate_kill", CreateRequest{1, []byte("x"), OpenCreate | OpenWriteOnly | OpenTruncate, FuseOpenKillSUIDGID, 0644, 0022}, false},
		{"create_read_write_truncate_kill", CreateRequest{1, []byte("x"), OpenCreate | OpenReadWrite | OpenTruncate, FuseOpenKillSUIDGID, 0644, 0022}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(tc.body)
			if err := req.Validate(); (err == nil) != tc.valid {
				t.Errorf("Validate: %v, want valid=%v", err, tc.valid)
			}
			if _, err := Marshal(&req); (err == nil) != tc.valid {
				t.Errorf("Marshal: %v, want valid=%v", err, tc.valid)
			}
			// Bypass the validating encoder to exercise inbound validation too.
			body, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(requestEnvelope{req.Sequence, req.Auth, tc.body.Operation(), body})
			if err != nil {
				t.Fatal(err)
			}
			var got Request
			if err := Unmarshal(raw, &got); (err == nil) != tc.valid {
				t.Errorf("Unmarshal: %v, want valid=%v", err, tc.valid)
			}
			if tc.valid && !reflect.DeepEqual(req, got) {
				t.Fatalf("roundtrip: got %#v, want %#v", got, req)
			}
		})
	}
}

func TestInvalidBodiesFlagsBounds(t *testing.T) {
	zero := HandleID(0)
	bad := []RequestBody{
		LookupRequest{0, []byte("x")}, LookupRequest{1, nil}, LookupRequest{1, []byte(".")}, LookupRequest{1, []byte("..")}, LookupRequest{1, []byte("a/b")}, LookupRequest{1, []byte{'a', 0}}, LookupRequest{1, bytes.Repeat([]byte("x"), MaxName+1)},
		GetAttrRequest{Node: 1, Handle: &zero},
		SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: 1 << 31}, SetAttrRequest{Semantics: MetadataValid, Node: 1, Mode: 1}, SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetMode, Mode: 0100644}, SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetSize, Size: math.MaxUint64}, SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetATimeNow}, SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetATime, ATime: Timestamp{0, 1000000000}}, SetAttrRequest{Semantics: MetadataValid, Node: 1, Valid: SetKillSUIDGID},
		CreateRequest{Parent: 1, Name: []byte("x"), Mode: 0040755}, CreateRequest{Parent: 1, Name: []byte("x"), Umask: 01000},
		OpenRequest{Node: 1, Flags: 3}, OpenRequest{Node: 1, Flags: 1 << 31}, OpenRequest{Node: 1, Flags: OpenCreate}, OpenRequest{Node: 1, FuseOpenFlags: 2},
		ReadRequest{Node: 1, Handle: 0}, ReadRequest{Node: 1, Handle: 1, Size: MaxIO + 1}, ReadRequest{Node: 1, Handle: 1, Offset: math.MaxInt64, Size: 1}, ReadRequest{Node: 1, Handle: 1, Offset: math.MaxUint64},
		WriteRequest{Node: 1, Handle: 1, Data: nil}, WriteRequest{Node: 1, Handle: 1, Data: make([]byte, MaxIO+1)}, WriteRequest{Node: 1, Handle: 1, Offset: math.MaxInt64, Data: []byte{1}}, WriteRequest{Node: 1, Handle: 1, WriteFlags: 2, Data: []byte{}}, WriteRequest{Node: 1, Handle: 1, WriteFlags: WriteCache, Data: []byte{}},
		OpenDirRequest{1, OpenWriteOnly}, ReadDirRequest{1, 1, 0, 0}, ReadDirRequest{1, 1, 0, MaxIO + 1}, ReadDirRequest{1, 1, math.MaxUint64, 1},
		MkdirRequest{1, []byte("x"), 0100644, 0}, MknodRequest{1, []byte("x"), 0120777, 0, 0}, MknodRequest{1, []byte("x"), 0100644, 0, 1},
		SymlinkRequest{1, []byte("x"), nil}, SymlinkRequest{1, []byte("x"), []byte{0}}, SymlinkRequest{1, []byte("x"), bytes.Repeat([]byte("x"), MaxTarget+1)},
		RenameRequest{1, 2, []byte("x"), []byte("y"), 3}, RenameRequest{1, 0, []byte("x"), []byte("y"), 0}, LinkRequest{0, 1, []byte("x")},
		AccessRequest{1, 8}, GetXAttrRequest{1, []byte("user.x"), MaxXAttr + 1}, GetXAttrRequest{1, []byte{0}, 0}, ListXAttrRequest{1, MaxXAttr + 1},
		SetXAttrRequest{1, []byte("user.x"), []byte{}, 3}, SetXAttrRequest{1, []byte("user.x"), make([]byte, MaxXAttr+1), 0},
		FallocateRequest{1, 1, 0, 0, 0}, FallocateRequest{1, 1, math.MaxInt64, 1, 0}, FallocateRequest{1, 1, 0, 1, FallocatePunchHole},
		LseekRequest{1, 1, 0, 0}, LseekRequest{1, 1, math.MaxUint64, SeekHole},
	}
	for i, b := range bad {
		r := request(b)
		if err := r.Validate(); err == nil {
			t.Errorf("accepted %d: %#v", i, b)
		}
	}
	for _, b := range []RequestBody{ReleaseRequest{1, 1, 2}, ReleaseDirRequest{1, 1, ReleaseFlush}, ForgetRequest{}, ForgetRequest{[]ForgetEntry{{1, 0}}}, ForgetRequest{[]ForgetEntry{{1, 1}, {1, 2}}}, ForgetRequest{make([]ForgetEntry, MaxForget+1)}} {
		r := Request{1, Auth{Kind: LifecycleAuth}, b}
		if err := r.Validate(); err == nil {
			t.Errorf("accepted lifecycle %#v", b)
		}
	}
	req := request(OpenRequest{1, OpenWriteOnly, 0})
	if !errors.Is(req.ValidatePolicy(storageauthority.ReadOnly), ErrReadOnly) {
		t.Fatal("write open on RO")
	}
	req.Body = SetAttrRequest{Node: 1, Valid: SetSize, Semantics: MetadataValid | MetadataOpen}
	if !errors.Is(req.ValidatePolicy(storageauthority.ReadOnly), ErrReadOnly) {
		t.Fatal("truncate on RO")
	}
	req.Body = AccessRequest{1, 2}
	if !errors.Is(req.ValidatePolicy(storageauthority.ReadOnly), ErrReadOnly) {
		t.Fatal("W_OK on RO")
	}
	if err := req.ValidatePolicy("root"); err == nil {
		t.Fatal("invalid mode")
	}
}

type embeddedRequest struct{ LookupRequest }
type embeddedReply struct{ FlushReply }

func TestUnionCannotBeExtendedOrNil(t *testing.T) {
	var ptr *LookupRequest
	for _, body := range []RequestBody{nil, ptr, &LookupRequest{1, []byte("x")}, embeddedRequest{LookupRequest{1, []byte("x")}}} {
		r := request(body)
		if err := r.Validate(); err == nil {
			t.Fatal("extended request")
		}
		if !r.Mutates() {
			t.Fatal("invalid body reported safe")
		}
	}
	for _, body := range []ReplyBody{nil, (*FlushReply)(nil), &FlushReply{}, embeddedReply{}, WriteReply{}} {
		r := Reply{Sequence: 1, Op: OpFlush, Body: body}
		if err := r.Validate(); err == nil {
			t.Fatal("extended/wrong reply")
		}
	}
}
func TestAuthHasNoRootFallback(t *testing.T) {
	for _, a := range []Auth{{}, {Kind: CallerAuth}, {Kind: CallerAuth, Caller: &Caller{}}, {Kind: OpenGrantAuth, Caller: &Caller{Groups: []uint32{}}}, {Kind: 99}} {
		if err := a.Validate(); err == nil {
			t.Fatal("accepted missing/incorrect auth")
		}
	}
	r := request(GetAttrRequest{Node: 1})
	r.Auth = Auth{Kind: NodeMetadataAuth}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	fh := HandleID(2)
	r.Body = GetAttrRequest{Node: 1, Handle: &fh}
	if err := r.Validate(); err == nil {
		t.Fatal("metadata with FH")
	}
	r.Auth = Auth{Kind: OpenGrantAuth}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Body = SetAttrRequest{Semantics: MetadataValid, Node: 1, Handle: &fh, Valid: SetMode, Mode: 0600}
	if err := r.Validate(); err == nil {
		t.Fatal("opener metadata authority")
	}
	r.Body = WriteRequest{Node: 1, Handle: 2, WriteFlags: WriteCache, Data: []byte{}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Auth = Auth{Kind: CallerAuth, Caller: &Caller{Groups: []uint32{}}}
	r.Body = LookupRequest{1, []byte("x")}
	b, err := Marshal(&r)
	if err != nil {
		t.Fatal(err)
	}
	var got Request
	if err := Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Auth.Caller.EffectiveCaps != 0 || len(got.Auth.Caller.Groups) != 0 {
		t.Fatal("normalized root")
	}
}
func TestReplyBoundsAndCorrelation(t *testing.T) {
	req := request(ReadRequest{1, 2, 0, 1, 0})
	rep := Reply{1, OpRead, 0, ReadReply{[]byte{1, 2}}}
	if err := ValidateReplyFor(req, rep); err == nil {
		t.Fatal("long read")
	}
	req.Body = WriteRequest{Node: 1, Handle: 2, Data: []byte{1}}
	rep = Reply{1, OpWrite, 0, WriteReply{2}}
	if err := ValidateReplyFor(req, rep); err == nil {
		t.Fatal("long write")
	}
	req.Body = ReadDirRequest{1, 2, 7, 31}
	rep = Reply{1, OpReadDir, 0, ReadDirReply{[]DirEntry{{[]byte("x"), 1, 0100644, 8}}}}
	if err := ValidateReplyFor(req, rep); err == nil {
		t.Fatal("directory buffer")
	}
	req.Body = ReadDirRequest{1, 2, 8, MaxIO}
	if err := ValidateReplyFor(req, rep); err == nil {
		t.Fatal("directory cookie")
	}
	for _, body := range []ReplyBody{ReadReply{make([]byte, MaxIO+1)}, WriteReply{MaxIO + 1}, ReadlinkReply{nil}, GetXAttrReply{MaxXAttr + 1, []byte{}}, ListXAttrReply{2, []byte{'a', 1}}, ListXAttrReply{3, []byte{'a', 0, 0}}, ListXAttrReply{4, []byte{'a', 0, 'a', 0}}, ReadDirReply{make([]DirEntry, MaxDirEntries+1)}, ReadDirReply{[]DirEntry{{[]byte("x"), 1, 0, 1}}}, LseekReply{math.MaxUint64}, StatFSReply{}} {
		rep := Reply{1, body.Operation(), 0, body}
		if err := rep.Validate(); err == nil {
			t.Errorf("accepted %#v", body)
		}
	}
	a := goodAttr()
	a.CTime.Nanoseconds = 1000000000
	if err := (Reply{1, OpGetAttr, 0, GetAttrReply{a}}).Validate(); err == nil {
		t.Fatal("bad timestamp")
	}
	entry := goodEntry()
	b, err := Marshal(&Reply{1, OpLookup, 0, LookupReply{entry}})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(string(b), `"ino":123`, `"ino":123,"unknown":0`, 1), strings.Replace(string(b), `"ino":123`, `"ino":123,"ino":124`, 1), strings.Replace(string(b), `"object":"01020300000000000000000000000000"`, `"object":"0102030000000000000000000000000A"`, 1)} {
		var rep Reply
		if err := Unmarshal([]byte(bad), &rep); err == nil {
			t.Fatal("nested attr/object accepted")
		}
	}
}
func TestHelloProfileRootAndEvents(t *testing.T) {
	binding := storageauthority.Binding{Store: testID, Volume: testID, Attachment: testID, Container: storageauthority.ContainerID(strings.Repeat("a", 64)), Launch: testID, Key: storageauthority.Fingerprint(strings.Repeat("b", 64)), Role: storageauthority.RuntimeRole, Mode: storageauthority.ReadWrite}
	hello := ClientHello{storageauthority.DataHello{Epoch: testID, Binding: binding}, RequiredProfile()}
	root := RootReply{goodEntry()}
	root.Root.Attr.Mode = 0040755
	event := Event{EventSequence: 1, Volume: testID, Object: ObjectID{1}, Parent: ObjectID{2}, Kind: InvalidateEntry, Name: []byte{255}}
	for _, m := range []Message{&ServerHello{testID, Version, RequiredProfile()}, &hello, &root, &event} {
		b, err := Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		dst := reflect.New(reflect.TypeOf(m).Elem()).Interface().(Message)
		if err := Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(m, dst) {
			t.Fatal("hello/event mismatch")
		}
	}
	p := RequiredProfile()
	pv := reflect.ValueOf(&p).Elem()
	for i := 0; i < pv.NumField(); i++ {
		bad := RequiredProfile()
		f := reflect.ValueOf(&bad).Elem().Field(i)
		if f.Kind() == reflect.Bool {
			f.SetBool(!f.Bool())
		} else {
			f.SetUint(f.Uint() + 1)
		}
		h := ServerHello{testID, Version, bad}
		if err := h.Validate(); err == nil {
			t.Fatal("negotiated profile weakening")
		}
	}
	h := ServerHello{testID, 2, RequiredProfile()}
	if err := h.Validate(); err == nil {
		t.Fatal("v2 fallback")
	}
	hello.Authority.Binding.Role = storageauthority.PrepareRole
	if err := hello.Validate(); err == nil {
		t.Fatal("missing prepare ID")
	}
	hello.Authority.Binding.Prepare = testID
	if err := hello.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(&hello)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(b, []byte(`"binding":{`), []byte(`"binding":{"unknown":1,`), 1)
	if err := Unmarshal(bad, &hello); err == nil {
		t.Fatal("unknown authority field")
	}
	root.Root.Attr.Mode = 0100644
	if err := root.Validate(); err == nil {
		t.Fatal("nondirectory root")
	}
	event.Kind = InvalidateAttr
	if err := event.Validate(); err == nil {
		t.Fatal("wrong event union")
	}
	event.Parent = ObjectID{}
	event.Name = []byte{}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	event.Kind = InvalidateData
	event.Offset = math.MaxInt64
	event.Length = 1
	if err := event.Validate(); err == nil {
		t.Fatal("event range overflow")
	}
	event.Offset = 0
	event.Length = 0
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	eb, err := Marshal(&event)
	if err != nil {
		t.Fatal(err)
	}
	eb = bytes.Replace(eb, []byte(`"volume":`), []byte(`"node":1,"volume":`), 1)
	if err := Unmarshal(eb, &event); err == nil {
		t.Fatal("event session node")
	}
}
func TestSequenceMonotonicAndOverflow(t *testing.T) {
	var s SequenceTracker
	for _, n := range []uint64{1, 3, math.MaxUint64} {
		if err := s.Accept(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []uint64{0, 1, math.MaxUint64} {
		if err := s.Accept(n); err == nil {
			t.Fatal("sequence accepted")
		}
	}
}
func FuzzDecodeRequest(f *testing.F) {
	r := request(LookupRequest{1, []byte{255}})
	b, _ := Marshal(&r)
	f.Add(b)
	f.Add([]byte(`{"sequence":1,"auth":{},"op":"lookup","body":{}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var r Request
		if err := Unmarshal(b, &r); err != nil {
			return
		}
		out, err := Marshal(&r)
		if err != nil {
			t.Fatal(err)
		}
		var r2 Request
		if err := Unmarshal(out, &r2); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(r, r2) {
			t.Fatal("non-idempotent codec")
		}
	})
}
func TestObjectIDStrict(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `"00"`, `"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"`, `"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"`} {
		var id ObjectID
		if err := json.Unmarshal([]byte(raw), &id); err == nil {
			t.Fatal("bad object ID", raw)
		}
	}
}
