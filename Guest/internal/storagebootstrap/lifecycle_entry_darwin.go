//go:build darwin && cgo

package storagebootstrap

/*
#include "lifecycle_xpc_darwin.h"
*/
import "C"

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"

	p "dev.cengine/guest/internal/storagepki"
)

// RunLifecycleChild is the sole native controller entry in every build.
// Native hello precedes parent initialization. The unchanged bridge then opens
// ROOT itself; no audit tuple, key, endpoint or receipt is accepted from argv/env.
func RunLifecycleChild(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrProtocol
	}
	var observed C.ce_lifecycle_processes
	if C.ce_lifecycle_parent(3, &observed) != 0 {
		return ErrProtocol
	}
	hello := struct {
		ChildAudit     []byte `json:"child_audit"`
		ChildUniqueID  uint64 `json:"child_unique_id"`
		DaemonAudit    []byte `json:"daemon_audit"`
		DaemonUniqueID uint64 `json:"daemon_unique_id"`
		Version        string `json:"version"`
	}{make([]byte, 32), uint64(observed.child_unique), make([]byte, 32), uint64(observed.daemon_unique), p.LifecycleChildVersion}
	for i := range hello.ChildAudit {
		hello.ChildAudit[i] = byte(observed.child_audit[i])
		hello.DaemonAudit[i] = byte(observed.daemon_audit[i])
	}
	// Close only a duplicate after hello: FD 3 must retain any queued parent
	// initialization for runLifecycleChild, which revalidates native parentage.
	fd, err := syscall.Dup(3)
	if err != nil {
		return err
	}
	syscall.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "lifecycle-hello")
	channel, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { channel.Close() })
	defer stop()
	if err = channel.SetWriteDeadline(time.Now().Add(lifecycleOperationTimeout)); err == nil {
		err = WriteFrame(channel, hello)
	}
	channel.Close()
	if err != nil {
		return err
	}
	return runLifecycleChild(ctx)
}
