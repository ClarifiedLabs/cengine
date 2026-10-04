package storagewire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func pendingFixture(action PrepareAction, phase string) PrepareReply {
	v := prepareFixture()
	v.Pending, v.Identity, v.Intent.Phase = action, a.Ext4ObjectV1{}, phase
	if phase == a.CopyBegun {
		v.Intent.Transaction = a.Ext4ObjectV1{}
	}
	if phase == a.CopySealed {
		v.Intent.ManifestDigest, v.Intent.ManifestSize = [32]byte{1}, 1
	}
	return v
}

func TestPreparePendingWireAndIoctl(t *testing.T) {
	for _, tc := range []struct {
		action PrepareAction
		phase  string
	}{
		{BeginCopy, a.CopyBegun}, {BeginCopy, a.CopyBound}, {BeginCopy, a.CopySealed}, {BeginCopy, a.CopyCleaning},
		{BindCopyTransaction, a.CopyBegun}, {BindCopyTransaction, a.CopyBound}, {BindCopyTransaction, a.CopySealed},
		{SealManifest, a.CopyBound}, {SealManifest, a.CopySealed},
		{StartCleanup, a.CopyBound}, {StartCleanup, a.CopySealed}, {StartCleanup, a.CopyCleaning},
		{FinishCopy, a.CopyBegun}, {FinishCopy, a.CopyCleaning},
		{RollbackCopy, a.CopySealed}, {RollbackCopy, a.CopyCleaning},
		{ResumeCopyDirectory, a.CopySealed}, {ResumeCopyDirectory, a.CopyCleaning}, {ResumeCopyDirectory, a.CopyCompleted},
	} {
		v := pendingFixture(tc.action, tc.phase)
		r := PrepareRequest{Action: BeginCopy}
		if err := ValidatePrepareReplyFor(r, v); err != nil {
			t.Fatal(tc, err)
		}
		buf, err := EncodePrepareIoctlReply(v)
		if err != nil || len(buf) != 8192 {
			t.Fatal(tc, err)
		}
		got, err := DecodePrepareIoctlReply(buf)
		if err != nil || got != v {
			t.Fatal(tc, got, err)
		}
		reply := Reply{Sequence: 1, Op: OpPrepare, Body: v}
		raw, err := Marshal(&reply)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Reply
		if err = Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(decoded, reply) {
			t.Fatal(err)
		}
		for action := BindCopyTransaction; action <= ResumeCopyDirectory; action++ {
			if ValidatePrepareReplyFor(PrepareRequest{Action: action, Intent: testID}, v) == nil {
				t.Fatal("uncorrelated pending", action)
			}
		}
	}
}

func TestPreparePendingRejectsImpossibleOrUnboundedActions(t *testing.T) {
	for _, v := range []PrepareReply{
		pendingFixture(IdentityAt, a.CopyBound), pendingFixture(AuthenticateManifest, a.CopyBound),
		pendingFixture(PrepareAction(10), a.CopyBound), pendingFixture(^PrepareAction(0), a.CopyBound),
		pendingFixture(SealManifest, a.CopyBegun), pendingFixture(StartCleanup, a.CopyBegun),
		pendingFixture(FinishCopy, a.CopyBound), pendingFixture(FinishCopy, a.CopyCompleted),
		pendingFixture(RollbackCopy, a.CopyBound), pendingFixture(RollbackCopy, a.CopyCompleted),
		pendingFixture(ResumeCopyDirectory, a.CopyBound), pendingFixture(ResumeCopyDirectory, a.CopyBegun),
		{Pending: BeginCopy},
	} {
		if _, err := EncodePrepareIoctlReply(v); err == nil {
			t.Fatal("accepted", v)
		}
	}
	v := pendingFixture(FinishCopy, a.CopyBegun)
	v.Intent.InitialCaptured = true
	if _, err := EncodePrepareIoctlReply(v); err == nil {
		t.Fatal("finish of partially provisioned begin")
	}
}

func TestPreparePendingStrictJSON(t *testing.T) {
	v := pendingFixture(SealManifest, a.CopyBound)
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var missing PrepareReply
	if err := json.Unmarshal(bytes.Replace(raw, []byte(`"pending":4,`), nil, 1), &missing); err == nil {
		t.Fatal("accepted missing explicit pending field")
	}
	for _, value := range []string{`null`, `"4"`, `-1`, `4294967296`, `4.0`, `4,"pending":4`, `4,"Pending":4`} {
		payload := bytes.Replace(raw, []byte(`"pending":4`), []byte(`"pending":`+value), 1)
		buf := make([]byte, PrepareIoctlSize)
		binary.LittleEndian.PutUint32(buf, PrepareIoctlVersion)
		binary.LittleEndian.PutUint32(buf[4:], prepareIoctlReply)
		binary.LittleEndian.PutUint32(buf[8:], uint32(len(payload)))
		copy(buf[16:], payload)
		if _, err := DecodePrepareIoctlReply(buf); err == nil {
			t.Fatal("accepted", value)
		}
	}
}
