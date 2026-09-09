//go:build linux

package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	nfs "github.com/willscott/go-nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
	"github.com/willscott/go-nfs-client/nfs/xdr"
	"golang.org/x/sys/unix"
)

// These tests deliberately enter through the RPC server, rather than calling
// WithIdentity or SetFileAttributes.Apply directly: creation applies attributes
// after the initial syscall, and must do so under the same caller credentials.
func newIdentityRPCServer(t *testing.T) (*volumeNFSHandler, string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root with SETUID/SETGID capabilities")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	h := newVolumeNFSHandler(root)
	if h.filesystem.rootErr != nil {
		t.Fatal(h.filesystem.rootErr)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&nfs.Server{Handler: h, Context: ctx}).Serve(listener) }()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-done
		h.filesystem.confined.Close()
		h.filesystem.rootFile.Close()
	})
	return h, root, listener.Addr().String()
}

func writeIdentityXDR(t *testing.T, b *bytes.Buffer, values ...interface{}) {
	t.Helper()
	for _, value := range values {
		if err := xdr.Write(b, value); err != nil {
			t.Fatal(err)
		}
	}
}

func identityRPCCall(t *testing.T, address string, id nfs.Identity, proc nfs.NFSProcedure, args []byte) (uint32, *bytes.Reader) {
	t.Helper()
	auth := new(bytes.Buffer)
	writeIdentityXDR(t, auth, uint32(1), "test", id.UID, id.GID, id.Groups)
	message := new(bytes.Buffer)
	writeIdentityXDR(t, message, uint32(42), uint32(0), rpc.Header{
		Rpcvers: 2, Prog: 100003, Vers: 3, Proc: uint32(proc),
		Cred: rpc.Auth{Flavor: 1, Body: auth.Bytes()}, Verf: rpc.AuthNull,
	})
	message.Write(args)
	c, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame := new(bytes.Buffer)
	writeIdentityXDR(t, frame, uint32(message.Len())|0x80000000)
	frame.Write(message.Bytes())
	if _, err := io.Copy(c, frame); err != nil {
		t.Fatal(err)
	}
	var length uint32
	if err := binary.Read(c, binary.BigEndian, &length); err != nil {
		t.Fatal(err)
	}
	if length&0x80000000 == 0 || length&0x7fffffff > 4096 {
		t.Fatalf("invalid response frame length: %#x", length)
	}
	body := make([]byte, length&0x7fffffff)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(body)
	var header [6]uint32
	if err := binary.Read(r, binary.BigEndian, &header); err != nil {
		t.Fatal(err)
	}
	if header != [6]uint32{42, 1, 0, 0, 0, 0} {
		t.Fatalf("RPC was not accepted: %v", header)
	}
	status, err := xdr.ReadUint32(r)
	if err != nil {
		t.Fatal(err)
	}
	return status, r
}

func identityCreateArgs(t *testing.T, handle []byte, name string, mode uint32) []byte {
	t.Helper()
	b := new(bytes.Buffer)
	writeIdentityXDR(t, b, handle, name, uint32(0), // UNCHECKED
		uint32(1), mode, uint32(0), uint32(0), // mode, no uid/gid
		uint32(1), uint64(0), uint32(0), uint32(0)) // size=0, no times
	return b.Bytes()
}

func identityCreatedAttrs(t *testing.T, r io.Reader) nfs.FileAttribute {
	t.Helper()
	present, err := xdr.ReadUint32(r)
	if err != nil || present != 1 {
		t.Fatalf("missing created handle: %d, %v", present, err)
	}
	if _, err := xdr.ReadOpaque(r); err != nil {
		t.Fatal(err)
	}
	present, err = xdr.ReadUint32(r)
	if err != nil || present != 1 {
		t.Fatalf("missing post-op attributes: %d, %v", present, err)
	}
	var attr nfs.FileAttribute
	if err := xdr.Read(r, &attr); err != nil {
		t.Fatal(err)
	}
	return attr
}

func TestNFSRPCCreateReadOnlyModeWithSizeZero(t *testing.T) {
	h, root, address := newIdentityRPCServer(t)
	id := nfs.Identity{UID: 10001, GID: 10001}
	handle := h.ToHandle(h.filesystem, []string{"."})
	for _, mode := range []uint32{0444, 0000} {
		t.Run(fmt.Sprintf("mode-%04o", mode), func(t *testing.T) {
			name := fmt.Sprintf("file-%04o", mode)
			status, reply := identityRPCCall(t, address, id, nfs.NFSProcedureCreate, identityCreateArgs(t, handle, name, mode))
			if status != uint32(nfs.NFSStatusOk) {
				t.Fatalf("CREATE mode %04o with size=0: status %d", mode, status)
			}
			attr := identityCreatedAttrs(t, reply)
			if attr.UID != id.UID || attr.GID != id.GID || attr.FileMode != mode || attr.Filesize != 0 {
				t.Fatalf("CREATE post-op attributes: %+v", attr)
			}
			info, err := os.Stat(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			disk := nfs.ToFileAttribute(info, name)
			if disk.UID != id.UID || disk.GID != id.GID || disk.FileMode != mode || disk.Filesize != 0 {
				t.Fatalf("CREATE persisted attributes: %+v", disk)
			}
		})
	}
}

func TestNFSRPCMkdirRetainsInheritedSetgid(t *testing.T) {
	h, root, address := newIdentityRPCServer(t)
	parent := filepath.Join(root, "group")
	if err := os.Mkdir(parent, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, 2000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSetgid|0770); err != nil {
		t.Fatal(err)
	}
	args := new(bytes.Buffer)
	writeIdentityXDR(t, args, h.ToHandle(h.filesystem, []string{"group"}), "child",
		uint32(1), uint32(0770), uint32(0), uint32(0), uint32(0), uint32(0), uint32(0))
	id := nfs.Identity{UID: 10001, GID: 10001, Groups: []uint32{2000}}
	status, reply := identityRPCCall(t, address, id, nfs.NFSProcedureMkDir, args.Bytes())
	if status != uint32(nfs.NFSStatusOk) {
		t.Fatalf("MKDIR: status %d", status)
	}
	attr := identityCreatedAttrs(t, reply)
	info, err := os.Stat(filepath.Join(parent, "child"))
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range []*nfs.FileAttribute{&attr, nfs.ToFileAttribute(info, "child")} {
		if got.Type != nfs.FileTypeDirectory || got.UID != id.UID || got.GID != 2000 || got.FileMode != 02770 {
			t.Fatalf("MKDIR must retain inherited group and setgid: %+v", got)
		}
	}
}

func TestNFSRPCUnauthorizedSetattr(t *testing.T) {
	h, root, address := newIdentityRPCServer(t)
	name := filepath.Join(root, "secret")
	if err := os.WriteFile(name, []byte("disposable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(name, 10001, 10001); err != nil {
		t.Fatal(err)
	}
	handle := h.ToHandle(h.filesystem, []string{"secret"})
	for _, tc := range []struct {
		name  string
		attrs []uint32
	}{
		{"mode", []uint32{1, 0644, 0, 0, 0, 0, 0}},
		{"unchanged-mode", []uint32{1, 0600, 0, 0, 0, 0, 0}},
		{"owner", []uint32{0, 1, 10002, 0, 0, 0, 0}},
		{"unchanged-owner", []uint32{0, 1, 10001, 0, 0, 0, 0}},
		{"size", []uint32{0, 0, 0, 1, 0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := new(bytes.Buffer)
			writeIdentityXDR(t, args, handle)
			for _, word := range tc.attrs {
				writeIdentityXDR(t, args, word)
			}
			writeIdentityXDR(t, args, uint32(0)) // no sattrguard
			status, _ := identityRPCCall(t, address, nfs.Identity{UID: 10002, GID: 10002}, nfs.NFSProcedureSetAttr, args.Bytes())
			if status != uint32(nfs.NFSStatusAccess) {
				t.Fatalf("unauthorized SETATTR: status %d, want ACCESS", status)
			}
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			attr := nfs.ToFileAttribute(info, name)
			content, err := os.ReadFile(name)
			if err != nil || string(content) != "disposable" || attr.UID != 10001 || attr.GID != 10001 || attr.FileMode != 0600 {
				t.Fatalf("denied SETATTR changed file: %+v, %q, %v", attr, content, err)
			}
		})
	}
}

func TestNFSRPCConcurrentCredentials(t *testing.T) {
	h, root, address := newIdentityRPCServer(t)
	uid, gid := os.Geteuid(), os.Getegid()
	groups, err := unix.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		after, err := unix.Getgroups()
		if err != nil || os.Geteuid() != uid || os.Getegid() != gid || !reflect.DeepEqual(groups, after) {
			t.Errorf("RPC dispatch changed service credentials: %d:%d %v, %v", os.Geteuid(), os.Getegid(), after, err)
		}
	})
	rootHandle := h.ToHandle(h.filesystem, []string{"."})
	for i := 0; i < 16; i++ {
		name := fmt.Sprintf("group-%d", i)
		group := uint32(13000 + i)
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0770); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, int(group)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, os.ModeSetgid|0770); err != nil {
			t.Fatal(err)
		}
		handle := h.ToHandle(h.filesystem, []string{name})
		id := nfs.Identity{UID: uint32(11000 + i), GID: uint32(12000 + i), Groups: []uint32{group}}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for attempt := 0; attempt < 4; attempt++ {
				file := fmt.Sprintf("file-%d", attempt)
				status, reply := identityRPCCall(t, address, id, nfs.NFSProcedureCreate, identityCreateArgs(t, handle, file, 0600))
				if status != uint32(nfs.NFSStatusOk) {
					t.Fatalf("concurrent CREATE: status %d", status)
				}
				attr := identityCreatedAttrs(t, reply)
				if attr.UID != id.UID || attr.GID != group || attr.FileMode != 0600 {
					t.Fatalf("request credentials crossed: got %+v, want uid=%d gid=%d", attr, id.UID, group)
				}
				// Without setgid inheritance, the caller's primary GID must win.
				status, reply = identityRPCCall(t, address, id, nfs.NFSProcedureCreate, identityCreateArgs(t, rootHandle, name+"-"+file, 0600))
				if status != uint32(nfs.NFSStatusOk) {
					t.Fatalf("concurrent primary-GID CREATE: status %d", status)
				}
				attr = identityCreatedAttrs(t, reply)
				if attr.UID != id.UID || attr.GID != id.GID {
					t.Fatalf("primary credentials crossed: got %+v, want %+v", attr, id)
				}
			}
		})
	}
}
