package storagemanaged

import (
	"errors"
	"sync"
	"syscall"
	"testing"

	"dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageidentity"
	w "dev.cengine/guest/internal/storagewire"
)

func TestMissingAdmissionBeforeAnyQueue(t *testing.T) {
	gate := new(sync.Mutex)
	registry, err := NewRegistry(gate)
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{registry: registry}
	gate.Lock()
	defer gate.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Deliberately hold both queues. Missing authority must return without waiting
	// or dereferencing roots, maps, worker, malformed body, or the principal.
	for _, g := range []*storageauthority.Guard{nil, {}} {
		_, err := s.Dispatch(g, w.Request{})
		if !errors.Is(err, storageauthority.ErrUnauthorized) {
			t.Fatalf("Dispatch: %v", err)
		}
	}
	_, _, err = New(nil, nil, storageauthority.Binding{}, gate, &storageidentity.Worker{}, registry)
	if !errors.Is(err, storageauthority.ErrUnauthorized) {
		t.Fatalf("New: %v", err)
	}
}
func TestRegistryRequiresSharedGate(t *testing.T) {
	if _, err := NewRegistry(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatal(err)
	}
	if err := (*Registry)(nil).Barrier(storageauthority.Binding{}, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatal(err)
	}
}
func TestErrnoDoesNotExposeInternalErrors(t *testing.T) {
	if errno(errors.New("private worker detail")) != 5 {
		t.Fatal("not EIO")
	}
	if errno(errors.Join(errors.New("context"), syscall.EACCES)) != 13 {
		t.Fatal("lost errno")
	}
}

// These old fixture shapes cannot originate from the supported kernel profile.
// Keep them invalid at the shared wire boundary, not as managed syscall errors.
func legacyMetadataRequests() []struct {
	name    string
	request func(w.NodeID) w.RequestBody
} {
	return []struct {
		name    string
		request func(w.NodeID) w.RequestBody
	}{
		{"setattr-kill-only", func(n w.NodeID) w.RequestBody {
			return w.SetAttrRequest{Node: n, Semantics: w.MetadataValid, Valid: w.SetKillSUIDGID, KillSUIDGID: true}
		}},
		{"setattr-kill-mode-times", func(n w.NodeID) w.RequestBody {
			return w.SetAttrRequest{Node: n, Semantics: w.MetadataValid, Valid: w.SetKillSUIDGID | w.SetMode | w.SetATime | w.SetMTime, KillSUIDGID: true, Mode: 0700, ATime: w.Timestamp{Seconds: 1}, MTime: w.Timestamp{Seconds: 2}}
		}},
		{"setattr-kill-times-now", func(n w.NodeID) w.RequestBody {
			return w.SetAttrRequest{Node: n, Semantics: w.MetadataValid, Valid: w.SetKillSUIDGID | w.SetATime | w.SetMTime | w.SetATimeNow | w.SetMTimeNow, KillSUIDGID: true}
		}},
		{"open-truncate", func(n w.NodeID) w.RequestBody {
			return w.OpenRequest{Node: n, Flags: w.OpenReadWrite | w.OpenTruncate}
		}},
		{"create-legacy-kill", func(n w.NodeID) w.RequestBody {
			return w.CreateRequest{Parent: n, Name: []byte("legacy"), Flags: w.OpenReadWrite | w.OpenTruncate, FuseOpenFlags: w.FuseOpenKillSUIDGID, Mode: 0600}
		}},
		{"write-legacy-kill", func(n w.NodeID) w.RequestBody {
			return w.WriteRequest{Node: n, Handle: 1, WriteFlags: w.WriteKillSUIDGID, Data: []byte("invalid")}
		}},
		{"open-kill-without-truncate", func(n w.NodeID) w.RequestBody {
			return w.OpenRequest{Node: n, Flags: w.OpenReadWrite, FuseOpenFlags: w.FuseOpenKillSUIDGID}
		}},
	}
}

func TestLegacyMetadataSignalsAreInvalidBeforeExecution(t *testing.T) {
	for _, tc := range legacyMetadataRequests() {
		t.Run(tc.name, func(t *testing.T) {
			request := w.Request{Sequence: 1, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{FSUID: 1001, FSGID: 1001, Groups: []uint32{}}}, Body: tc.request(1)}
			if _, err := w.Marshal(&request); !errors.Is(err, w.ErrInvalid) {
				t.Fatal("standalone kill must be a protocol error", err)
			}
		})
	}
}

func TestWireBoundsUsedBeforeExecution(t *testing.T) {
	requests := []w.Request{
		{Sequence: 1, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.LookupRequest{Parent: 1, Name: []byte("../outside")}},
		{Sequence: 1, Auth: w.Auth{Kind: w.OpenGrantAuth}, Body: w.ReadRequest{Node: 1, Handle: 1, Offset: 1 << 63, Size: 1}},
		{Sequence: 1, Auth: w.Auth{Kind: w.OpenGrantAuth}, Body: w.WriteRequest{Node: 1, Handle: 1, Data: make([]byte, w.MaxIO+1)}},
		{Sequence: 1, Auth: w.Auth{Kind: w.CallerAuth}, Body: w.StatFSRequest{Node: 1}},
	}
	for _, r := range requests {
		if _, err := w.Marshal(&r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}
