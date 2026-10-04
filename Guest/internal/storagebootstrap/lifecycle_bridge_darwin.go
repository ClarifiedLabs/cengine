//go:build darwin && cgo

package storagebootstrap

/*
#cgo CFLAGS: -fblocks -Wall -Wextra -Werror
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include "lifecycle_xpc_darwin.h"
*/
import "C"

import (
	"context"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	p "dev.cengine/guest/internal/storagepki"
)

// runLifecycleChild is reached only by the explicitly build-tagged entry point.
// It requires inherited FD 3 from the private launcher, CLOEXEC_DEFAULT and an
// empty environment. No compatibility selector or process DTO is accepted.
// The parent must deliver credentials obtained from its private Guest boot path.
func runLifecycleChild(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrProtocol
	}
	var observed C.ce_lifecycle_processes
	if C.ce_lifecycle_parent(3, &observed) != 0 {
		return ErrProtocol
	}
	processes := lifecycleProcesses{daemonUniqueID: uint64(observed.daemon_unique), childUniqueID: uint64(observed.child_unique)}
	for i := range processes.daemonAudit {
		processes.daemonAudit[i] = byte(observed.daemon_audit[i])
		processes.childAudit[i] = byte(observed.child_audit[i])
	}
	file := os.NewFile(3, "private-storage-lifecycle")
	connection, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return err
	}
	defer connection.Close()
	channel, ok := connection.(*net.UnixConn)
	if !ok {
		return ErrProtocol
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRead := context.AfterFunc(ctx, func() { channel.Close() })
	defer stopRead()
	if err = channel.SetDeadline(time.Now().Add(lifecycleOperationTimeout)); err != nil {
		return err
	}
	raw, descriptor, err := readPrivateFrameLimit(channel, p.MaxLifecycleChildSize)
	if descriptor >= 0 {
		syscall.Close(descriptor)
		return ErrProtocol
	}
	if err != nil {
		return err
	}
	cfg, err := decodeLifecycleInitialization(raw, processes)
	if err != nil {
		return err
	}
	session, err := newLifecycleSession(cfg)
	if err != nil {
		return err
	}
	defer session.close()
	greeting := session.greeting.Canonical()
	root := C.ce_lifecycle_open(unsafe.Pointer(&greeting[0]), C.size_t(len(greeting)))
	if root == nil {
		return ErrProtocol
	}
	var wg sync.WaitGroup
	// Both cancellation paths are outside session.op. Join ALL Go C callers
	// before destroy, including the context callback, so no C pointer can escape.
	cancellationDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		C.ce_lifecycle_cancel(root)
		session.close()
		close(cancellationDone)
	})
	wg.Add(2)
	go func() {
		defer wg.Done()
		C.ce_lifecycle_wait_closed(root)
		session.close()
		cancel()
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		_ = serveLifecycleRoot(ctx, root, session)
	}()
	defer func() {
		cancel()
		if stopCancel() {
			C.ce_lifecycle_cancel(root)
			session.close()
		} else {
			<-cancellationDone
		}
		wg.Wait()
		C.ce_lifecycle_destroy(root)
	}()
	if err = WriteFrame(channel, session.greeting.Fields()); err != nil {
		return err
	}
	// An idle lifecycle owner must survive without parent keepalives. Waiting for
	// the next bounded frame is cancellable by channel.Close, not a 30s lease on
	// controller ownership. Every response and session operation stays bounded.
	if err = channel.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	for expected := uint64(1); expected != 0; expected++ {
		raw, descriptor, err = readPrivateFrameLimit(channel, lifecycleWorkloadRequestLimit)
		if err != nil {
			return err
		}
		var request lifecyclePrivateRequest
		if decodeLifecyclePrivateRequest(raw, &request) != nil || request.Version != p.LifecycleChildVersion || request.RequestID != expected {
			if descriptor >= 0 {
				syscall.Close(descriptor)
			}
			return ErrProtocol
		}
		if request.Operation == "close" && len(request.Body) == 0 && descriptor < 0 {
			return nil
		}
		if (descriptor >= 0) != lifecycleStreamOperation(request.Operation) {
			syscall.Close(descriptor)
			return ErrProtocol
		}
		var stream net.Conn
		if descriptor >= 0 {
			stream, err = consumeConnectedStream(descriptor)
			if err != nil {
				return err
			}
		}
		data, err := session.privateLifecycleRequest(ctx, request, stream)
		reply, err := lifecyclePrivateReply(request, data, err)
		if err != nil {
			// Best-effort bounded diagnostic, never permission to continue or replay.
			// Preserve the original failure even when the parent has already gone.
			if channel.SetWriteDeadline(time.Now().Add(lifecycleOperationTimeout)) == nil {
				_ = writeLifecyclePrivateReply(channel, reply, false)
			}
			return err
		}
		if err = channel.SetWriteDeadline(time.Now().Add(lifecycleOperationTimeout)); err != nil {
			return err
		}
		if err = writeLifecyclePrivateReply(channel, reply, request.Operation == "workload-command"); err != nil {
			return err
		}
	}
	return ErrProtocol
}

// Only ce_lifecycle_next can supply production challenges: it authenticates the
// actual Mach sender before copying bytes. Canonical decoding is NOT authority.
func serveLifecycleRoot(ctx context.Context, root *C.ce_lifecycle_root, session *lifecycleSession) error {
	buffer := make([]byte, p.MaxLifecycleChildSize)
	for ctx.Err() == nil {
		var length C.size_t
		result := C.ce_lifecycle_next(root, unsafe.Pointer(&buffer[0]), C.size_t(len(buffer)), &length)
		if result < 0 {
			return ErrProtocol
		}
		if result == 0 {
			continue
		}
		proofCtx, cancel := context.WithTimeout(ctx, lifecycleOperationTimeout)
		encoded, err := session.rootProof(proofCtx, buffer[:int(length)])
		cancel()
		if err != nil {
			return err
		}
		if C.ce_lifecycle_reply(root, unsafe.Pointer(&encoded[0]), C.size_t(len(encoded))) != 0 {
			return ErrProtocol
		}
	}
	return ctx.Err()
}
