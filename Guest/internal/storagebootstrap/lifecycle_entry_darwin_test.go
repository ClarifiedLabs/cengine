//go:build darwin && cgo

package storagebootstrap

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// This unsigned native process exercises only hello and rejection before ROOT.
// It cannot qualify a signed launcher, enroll a controller or authenticate ROOT.
func TestLifecycleEntryNativeHello(t *testing.T) {
	if os.Getenv("CENGINE_LIFECYCLE_HELLO_TEST") == "1" {
		if RunLifecycleChild(context.Background()) == nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentFile := os.NewFile(uintptr(pair[0]), "parent")
	childFile := os.NewFile(uintptr(pair[1]), "child")
	defer childFile.Close()
	channel, err := net.FileConn(parentFile)
	parentFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	if err = channel.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleEntryNativeHello$")
	command.Env = []string{"CENGINE_LIFECYCLE_HELLO_TEST=1"}
	command.ExtraFiles = []*os.File{childFile}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			command.Process.Kill()
			command.Wait()
		}
	}()
	childFile.Close()
	var header [4]byte
	if _, err = io.ReadFull(channel, header[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > 4096 {
		t.Fatal("hello size", size)
	}
	raw := make([]byte, size)
	if _, err = io.ReadFull(channel, raw); err != nil {
		t.Fatal(err)
	}
	var hello struct {
		ChildAudit     []byte `json:"child_audit"`
		ChildUniqueID  uint64 `json:"child_unique_id"`
		DaemonAudit    []byte `json:"daemon_audit"`
		DaemonUniqueID uint64 `json:"daemon_unique_id"`
		Version        string `json:"version"`
	}
	if err = json.Unmarshal(raw, &hello); err != nil {
		t.Fatal(err)
	}
	if hello.Version != "storage-child-lifecycle.v2" || len(hello.ChildAudit) != 32 || len(hello.DaemonAudit) != 32 || hello.ChildUniqueID == 0 || hello.DaemonUniqueID == 0 || hello.ChildUniqueID == hello.DaemonUniqueID {
		t.Fatal("invalid native hello")
	}
	if binary.LittleEndian.Uint32(hello.ChildAudit[20:24]) != uint32(command.Process.Pid) || binary.LittleEndian.Uint32(hello.DaemonAudit[20:24]) != uint32(os.Getpid()) {
		t.Fatal("hello did not describe actual child/parent")
	}
	// The wrapper must leave original FD 3 alive for the bridge's next read.
	// Invalid parent initialization terminates without attempting ROOT XPC.
	if err = WriteFrame(channel, struct{}{}); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	joined = true
	if err != nil {
		t.Fatal(err)
	}
}
