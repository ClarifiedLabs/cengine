package fuse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"testing"
)

type managedInitCounter struct {
	RawFileSystem
	calls int
}

func (fs *managedInitCounter) Init(*Server) { fs.calls++ }

// Exercise the native Server INIT/read/handler/write path without a mount or FUSE device.
// The sink is an ordinary temporary file; byte/errno faults are tested separately.
func TestManagedNativeRejectedInitIsWrittenObservedAndReturned(t *testing.T) {
	for _, missing := range []string{"reject", "validator", "observer", "both"} {
		t.Run(missing, func(t *testing.T) { managedNativeRejectedInit(t, missing) })
	}
}

func managedNativeRejectedInit(t *testing.T, missing string) {
	sink, err := os.CreateTemp(t.TempDir(), "reply")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	dup, err := syscall.Dup(int(sink.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	opts := MountOptions{ValidateInit: func(InitOut) error { return errors.New("profile rejected") }, ObserveReply: func(r ReplyDelivery) {
		calls++
		if r.Unique != 101 || r.Opcode != _OP_INIT || r.Status != EINVAL || r.Err != nil || r.Bytes != 16 || r.Expected != 16 {
			t.Fatal(r)
		}
	}}
	if missing != "reject" {
		opts.ManagedProtocol = true
		if missing == "validator" || missing == "both" {
			opts.ValidateInit = nil
		}
		if missing == "observer" || missing == "both" {
			opts.ObserveReply = nil
		}
	}
	fs := &managedInitCounter{RawFileSystem: NewDefaultRawFileSystem()}
	opts.setDefaults(fs)
	server := &Server{opts: &opts, protocolServer: protocolServer{opts: &opts, fileSystem: fs}}
	server.fuseFD, err = server.newFuseFD(dup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.fuseFD.close()
	server.reqPool.New = func() any { return &requestAlloc{request: request{cancel: make(chan struct{})}} }
	server.readPool.New = func() any { return make([]byte, server.fuseFD.readBufBytes) }
	input := InitIn{InHeader: InHeader{Opcode: _OP_INIT, Unique: 101}, Major: 7, Minor: 38, Flags: ^uint32(0)}
	input.Length = uint32(binary.Size(input))
	var in bytes.Buffer
	_ = binary.Write(&in, binary.LittleEndian, input)
	if _, err := sink.Write(in.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if s := server.handleInit(); s != EINVAL || fs.calls != 0 {
		t.Fatal("constructor would infer success or invoke Init", s, fs.calls)
	}
	head := make([]byte, 16)
	if _, err := sink.ReadAt(head, int64(in.Len())); err != nil {
		t.Fatal(err)
	}
	wantCalls := 1
	if opts.ObserveReply == nil {
		wantCalls = 0
	}
	if calls != wantCalls || int32(binary.LittleEndian.Uint32(head[4:8])) != -int32(EINVAL) || binary.LittleEndian.Uint64(head[8:16]) != 101 {
		t.Fatal(calls, head)
	}
}
