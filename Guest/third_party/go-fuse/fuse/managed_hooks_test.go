package fuse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func managedInitRequest(t *testing.T, opts MountOptions) ([]byte, []byte) {
	t.Helper()
	ps := NewProtocolServer(NewDefaultRawFileSystem(), &opts)
	in := InitIn{InHeader: InHeader{Opcode: _OP_INIT, Unique: 73}, Major: 7, Minor: 38, Flags: ^uint32(0), Flags2: ^uint32(0)}
	in.Length = uint32(binary.Size(in))
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, in); err != nil {
		t.Fatal(err)
	}
	head, out := make([]byte, 16), make([]byte, 64)
	_, s := ps.HandleRequest([][]byte{buf.Bytes()}, [][]byte{head, out})
	if s != 0 {
		t.Fatal(s)
	}
	return head, out
}
func TestManagedInitRejectsBeforeSuccessAndUsesCopy(t *testing.T) {
	called := false
	head, _ := managedInitRequest(t, MountOptions{ValidateInit: func(out InitOut) error { called = true; return errors.New("reject") }})
	if !called || int32(binary.LittleEndian.Uint32(head[4:8])) != -int32(EINVAL) || binary.LittleEndian.Uint32(head[:4]) != 16 {
		t.Fatalf("%v %x", called, head)
	}
	head, out := managedInitRequest(t, MountOptions{ValidateInit: func(out InitOut) error { out.Major = 999; out.MaxWrite = 1; return nil }})
	if int32(binary.LittleEndian.Uint32(head[4:8])) != 0 || binary.LittleEndian.Uint32(out[:4]) != 7 || binary.LittleEndian.Uint32(out[20:24]) == 1 {
		t.Fatalf("mutation escaped %x", out)
	}
	head, _ = managedInitRequest(t, MountOptions{ValidateInit: func(InitOut) error { panic("reject") }})
	if int32(binary.LittleEndian.Uint32(head[4:8])) != -int32(EINVAL) {
		t.Fatal("validator panic accepted")
	}
}
func TestManagedProtocolOptInAndDefaults(t *testing.T) {
	_, base := managedInitRequest(t, MountOptions{})
	if binary.LittleEndian.Uint32(base[4:8]) != _OUR_MINOR_VERSION {
		t.Fatal("default changed")
	}
	seen := false
	opts := MountOptions{ManagedProtocol: true, ExtraCapabilities: 1 << 28, ValidateInit: func(out InitOut) error {
		seen = true
		if out.Minor != 33 || out.Flags&(1<<28) == 0 || out.Flags&(1<<30) != 0 || out.Flags2 != 0 {
			return errors.New("bad output")
		}
		return nil
	}, ObserveReply: func(ReplyDelivery) { t.Fatal("ProtocolServer cannot observe native delivery") }}
	head, _ := managedInitRequest(t, opts)
	if runtime.GOOS == "linux" {
		if !seen || int32(binary.LittleEndian.Uint32(head[4:8])) != 0 {
			t.Fatal("managed INIT failed")
		}
	} else if seen || int32(binary.LittleEndian.Uint32(head[4:8])) != -int32(EINVAL) {
		t.Fatal("non-Linux managed protocol accepted")
	}
	opts.ObserveReply = nil
	head, _ = managedInitRequest(t, opts)
	if int32(binary.LittleEndian.Uint32(head[4:8])) != -int32(EINVAL) {
		t.Fatal("missing hook accepted")
	}
}
func TestManagedDeliveryObservesExactSend(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		n                       int
		err                     error
		suppressed, interrupted bool
	}{
		{name: "success", n: 16}, {name: "short", n: 15}, {name: "errno", err: syscall.ENOENT}, {name: "partial-error", n: 3, err: syscall.EIO}, {name: "suppressed", suppressed: true}, {name: "interrupt", n: 16, interrupted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := InHeader{Opcode: _OP_CREATE, Unique: 0xfedcba9876543210}
			req := request{inputBuf: unsafe.Slice((*byte)(unsafe.Pointer(&h)), int(unsafe.Sizeof(h))), outHeaderBuf: make([]byte, 16), suppressReply: tc.suppressed}
			calls, sends := 0, 0
			got := deliverObserved(&req, tc.interrupted, func(iov [][]byte) (int, error) {
				sends++
				if iovLen(iov) != 16 {
					t.Fatal(iovLen(iov))
				}
				return tc.n, tc.err
			}, func(r ReplyDelivery) {
				calls++
				if r.Unique != h.Unique || r.Opcode != h.Opcode || r.Suppressed != tc.suppressed || r.Interrupted != tc.interrupted {
					t.Fatal(r)
				}
				if !tc.suppressed && r.Bytes != tc.n {
					t.Fatal(r)
				}
				if tc.name == "short" && !errors.Is(r.Err, io.ErrShortWrite) {
					t.Fatal(r)
				}
				if tc.err != nil && !errors.Is(r.Err, tc.err) {
					t.Fatal(r)
				}
			})
			if calls != 1 || sends != btoi(!tc.suppressed) {
				t.Fatal(calls, sends)
			}
			if (tc.err != nil || tc.name == "short") && got == OK {
				t.Fatal("false delivery success")
			}
		})
	}
}
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
func TestManagedObserverForcesCountedWriteAndCannotHideFailure(t *testing.T) {
	opts := MountOptions{ObserveReply: func(ReplyDelivery) {}}
	opts.setDefaults(NewDefaultRawFileSystem())
	if !opts.DisableSplice {
		t.Fatal("unobserved splice")
	}
	h := InHeader{Unique: 1}
	r := request{inputBuf: unsafe.Slice((*byte)(unsafe.Pointer(&h)), int(unsafe.Sizeof(h))), outHeaderBuf: make([]byte, 16)}
	if s := deliverObserved(&r, false, func([][]byte) (int, error) { return 16, nil }, func(ReplyDelivery) { panic("observer") }); s != EIO {
		t.Fatal(s)
	}
}
