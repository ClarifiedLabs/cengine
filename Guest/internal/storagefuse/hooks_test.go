package storagefuse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestControlledForkRejectsProfileBeforeInitReply(t *testing.T) {
	f, fc := fixture()
	opts, _ := mountOptions(2)
	opts.ValidateInit = f.validateInit
	opts.ObserveReply = f.observeReply
	ps := fuse.NewProtocolServer(f, &opts)
	// Both native Darwin and upstream-default Linux versions must be rejected:
	// setting a flag without opting into Linux protocol 7.33 is insufficient.
	in := fuse.InitIn{InHeader: fuse.InHeader{Opcode: 26, Unique: 81}, Major: 7, Minor: 38, Flags: ^uint32(0)}
	in.Length = uint32(binary.Size(in))
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, in)
	head, out := make([]byte, 16), make([]byte, 64)
	n, s := ps.HandleRequest([][]byte{buf.Bytes()}, [][]byte{head, out})
	if s != 0 || n != 16 || int32(binary.LittleEndian.Uint32(head[4:8])) != -int32(fuse.EINVAL) || f.negotiated.Load() {
		t.Fatal(n, s, head)
	}
	// Native sender observes the rejection and retires, unlike ProtocolServer.
	f.observeReply(fuse.ReplyDelivery{Unique: 81, Opcode: 26, Status: fuse.EINVAL, Bytes: 16, Expected: 16})
	if fc.aborted != 1 {
		t.Fatal("rejected INIT not terminal")
	}
}
func TestDeliveryHookRetiresFailuresAndNotNormalForget(t *testing.T) {
	for _, tc := range []fuse.ReplyDelivery{
		{Unique: 7, Opcode: 35, Err: io.ErrShortWrite, Bytes: 15, Expected: 16},
		{Unique: 8, Opcode: 14, Err: errors.New("discarded")},
		{Unique: 9, Opcode: 1, Interrupted: true},
		{Unique: 10, Opcode: 1, Suppressed: true},
	} {
		f, fc := fixture()
		f.observeReply(tc)
		if fc.aborted != 1 {
			t.Fatal(tc)
		}
	}
	for _, op := range []uint32{2, 42, 41} {
		f, fc := fixture()
		f.observeReply(fuse.ReplyDelivery{Unique: 12, Opcode: op, Suppressed: true})
		if fc.aborted != 0 {
			t.Fatal(op)
		}
	}
}
func TestBridgeCannotAuthorizePrivateStateWithoutSnapshot(t *testing.T) {
	bridge := clientBridge{new(c.Client)}
	_, err := bridge.Do(credential{state: present}, 0, w.LookupRequest{Parent: 1, Name: []byte("x")})
	if !errors.Is(err, c.ErrCredentials) {
		t.Fatal(err)
	}
}
func TestMountIdentityAndPropagationParsing(t *testing.T) {
	info := "21 1 0:1 / / rw - rootfs rootfs rw\n22 21 0:83 / /private/mnt rw - fuse.managed-v3 managed-v3 rw,request_cred\n"
	id, conn, err := ownedMount(info, "/private/mnt")
	if err != nil || id != 22 || conn != 83 {
		t.Fatal(id, conn, err)
	}
	for _, bad := range []string{info + "23 21 0:84 / /private/mnt rw - fuse.managed-v3 managed-v3 rw\n", "22 21 0:83 / /private/mnt rw - ext4 dev rw\n", "22 21 8:83 / /private/mnt rw - fuse.managed-v3 managed-v3 rw\n"} {
		if _, _, err := ownedMount(bad, "/private/mnt"); err == nil {
			t.Fatal("ambiguous identity")
		}
	}
	if err := privateParent(info, "/private"); err != nil {
		t.Fatal(err)
	}
	if err := privateParent("21 1 0:1 / / rw shared:7 - rootfs rootfs rw\n", "/private"); err == nil {
		t.Fatal("shared parent accepted")
	}
	if err := privateParent("21 1 0:1 / / rw master:7 - rootfs rootfs rw\n", "/private"); err == nil {
		t.Fatal("slave parent accepted")
	}
	escaped := "22 21 0:83 / /private/a\\040b rw - fuse.managed-v3 managed-v3 rw\n"
	if _, _, err := ownedMount(escaped, "/private/a b"); err != nil {
		t.Fatal(err)
	}
}
