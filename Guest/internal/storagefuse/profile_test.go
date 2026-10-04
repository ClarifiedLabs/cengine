package storagefuse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Exercise the PINNED implementation's INIT encoder, not a wishful MountOptions
// assertion. This is in-process protocol evidence, not a kernel profile proof.
func negotiated(t *testing.T, offered uint64) fuse.InitOut {
	t.Helper()
	opts, err := mountOptions(4)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		opts.ManagedProtocol = true
		opts.ValidateInit = func(fuse.InitOut) error { return nil }
		opts.ObserveReply = func(fuse.ReplyDelivery) {}
	}
	ps := fuse.NewProtocolServer(fuse.NewDefaultRawFileSystem(), &opts)
	in := fuse.InitIn{InHeader: fuse.InHeader{Opcode: 26, Unique: 1}, Major: 7, Minor: 38, Flags: uint32(offered), Flags2: uint32(offered >> 32)}
	in.Length = uint32(binary.Size(in))
	var input bytes.Buffer
	if err := binary.Write(&input, binary.LittleEndian, in); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 16)
	out := make([]byte, 64)
	n, status := ps.HandleRequest([][]byte{input.Bytes()}, [][]byte{head, out})
	expected := 80
	if runtime.GOOS == "darwin" {
		expected = 40
	} // macFUSE negotiates protocol 7.19
	if status != 0 || n != expected || binary.LittleEndian.Uint32(head[4:8]) != 0 {
		t.Fatalf("INIT result: %d %v %x", n, status, head)
	}
	return fuse.InitOut{Major: binary.LittleEndian.Uint32(out[0:4]), Minor: binary.LittleEndian.Uint32(out[4:8]), Flags: binary.LittleEndian.Uint32(out[12:16]), MaxWrite: binary.LittleEndian.Uint32(out[20:24]), Flags2: binary.LittleEndian.Uint32(out[32:36])}
}
func TestPinnedGoFuseNegotiatesRequiredBits(t *testing.T) {
	out := negotiated(t, ^uint64(0))
	if out.Flags64()&requiredCaps != requiredCaps || out.Flags64()&forbiddenCaps != 0 {
		t.Fatalf("negotiated flags %#x", out.Flags64())
	}
	if runtime.GOOS == "linux" {
		if err := checkNegotiated(out); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(checkNegotiated(out), ErrProfile) {
		t.Fatal("native non-Linux profile accepted")
	}
	if out.MaxWrite != w.MaxIO {
		t.Fatal(out.MaxWrite)
	}
	for _, bit := range []uint64{fuse.CAP_DONT_MASK, fuse.CAP_POSIX_ACL} {
		missing := negotiated(t, ^bit)
		if missing.Flags64()&bit != 0 || !errors.Is(checkNegotiated(missing), ErrProfile) {
			t.Fatalf("missing bit %#x accepted", bit)
		}
	}
}
func TestNativeRequestAdmissionMatchesAdapterBound(t *testing.T) {
	for _, count := range []int{1, 16, 1024} {
		opts, err := mountOptions(count)
		if err != nil || opts.MaxInflightRequests != count || opts.MaxBackground != count || opts.MaxInflightRequestBytes != count*(w.MaxIO+4096) {
			t.Fatalf("request count %d: %+v %v", count, opts, err)
		}
	}
	for _, count := range []int{-1, 0, 1025} {
		if _, err := mountOptions(count); err == nil {
			t.Fatalf("invalid request count %d accepted", count)
		}
	}
}

func TestConstructorRejectsMissingPrivateConfiguration(t *testing.T) {
	f, err := newMount(mountConfig{Mountpoint: "/must/not/be/touched", Retire: func(error) { t.Fatal("no attachment consumed") }})
	if f != nil || !errors.Is(err, ErrProfile) {
		t.Fatal(f, err)
	}
}
func TestLinuxFlagsNotHostFlags(t *testing.T) {
	for _, tc := range []struct {
		arch     string
		in, want uint32
	}{{"arm64", 0x10000, w.OpenDirect}, {"arm64", 0x4000, w.OpenDirectory}, {"arm64", 0x8000, w.OpenNoFollow}, {"arm64", 0x20000, w.OpenLargeFile}, {"amd64", 0x4000, w.OpenDirect}, {"amd64", 0x8000, w.OpenLargeFile}} {
		got, ok := openFlags(tc.in, tc.arch)
		if !ok || got != tc.want {
			t.Fatal(tc, got, ok)
		}
	}
	for _, v := range []uint32{3, 0x200000, 0x400000, 0x80000000} {
		if _, ok := openFlags(v, "arm64"); ok {
			t.Fatalf("accepted %#x", v)
		}
	}
	if _, ok := openFlags(0, "unknown"); ok {
		t.Fatal("unknown ABI")
	}
}
