//go:build linux

package storageboot

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"dev.cengine/guest/internal/diskbootstrap"
	a "dev.cengine/guest/internal/storageauthority"
	s "dev.cengine/guest/internal/storageservice"
	"dev.cengine/guest/internal/vsock"
)

var lifecycleAttempted atomic.Bool

// RunLifecycle is reached only from the cengine-storage PID1 entry after a real,
// successful disk verification, in every build. There is no kernel mode selector
// or legacy fallback. It consumes that capability even on failure.
// The only production socket source is the native Linux VSOCK listener; neither
// caller-provided net.Conn addresses nor a caller predicate establish host trust.
// Return/cancellation is NOT a retirement receipt or evidence of VM/process exit.
func RunLifecycle(ctx context.Context, verified diskbootstrap.VerifiedBootResult, managementAddress string) error {
	return runLifecycle(ctx, verified, managementAddress, &lifecycleAttempted, vsock.Listen, net.Listen)
}

// Socket/attempt seams are private, solely for component tests. No service,
// verified-root constructor, fresh capability or trust predicate is injectable.
func runLifecycle(ctx context.Context, verified diskbootstrap.VerifiedBootResult, address string, attempt *atomic.Bool, listenVSock func(uint32) (net.Listener, error), listenTCP func(string, string) (net.Listener, error)) (err error) {
	var root *os.File
	defer func() {
		if errors.Is(err, ErrShutdownUncertain) {
			err = retainLifecycleShutdown(err, root, verified)
			return
		}
		// All worker ownership has been positively joined before these root
		// closes. A failed close is containment, never permission to unmount.
		if root != nil {
			if closeErr := root.Close(); closeErr != nil {
				err = retainLifecycleShutdown(errors.Join(err, closeErr), root, verified)
				return
			}
		}
		if closeErr := verified.Close(); closeErr != nil {
			err = retainLifecycleShutdown(errors.Join(err, closeErr), verified)
		}
	}()
	if !attempt.CompareAndSwap(false, true) || ctx == nil {
		return s.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, binding, probe, err := verified.LifecycleRoot()
	if err != nil {
		return err
	}
	ip := net.ParseIP(address)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return s.ErrConfiguration
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener, err := listenVSock(Port)
	if err != nil {
		return err
	}
	conn, err := acceptLifecycleHost(ctx, listener)
	if err != nil {
		return err
	}
	_ = listenTCP // DATA is bound by the worker, never PID1
	start, err := processLifecycleStarterWithResume(root, binding, ip.String(), verified.FreshInitialization, &lifecycleResumeGate{
		probe: probe,
		promote: func(c LifecycleConfiguration) error {
			return verified.PromoteResume(c.RootPublicKey, *c.Resume)
		},
	}, func() (*os.File, error) {
		var nextBinding diskbootstrap.StorageBinding
		var nextProbe bool
		root, nextBinding, nextProbe, err = verified.LifecycleRoot()
		if err != nil {
			return nil, err
		}
		if root == nil || !nextProbe || nextBinding != binding {
			return nil, s.ErrConfiguration
		}
		return root, nil
	})
	if err != nil {
		_ = conn.Close()
		return err
	}
	return lifecycleSession(ctx, conn, binding, start, 30*time.Second)
}

// One accepted peer, no retries. Check the kernel's concrete CID before even the
// private hello. The native listener is created internally by RunLifecycle.
func acceptLifecycleHost(ctx context.Context, listener net.Listener) (net.Conn, error) {
	defer listener.Close()
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(joined); _ = listener.Close() })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	conn, err := listener.Accept()
	if err != nil {
		return nil, errors.Join(ctx.Err(), err)
	}
	if ctx.Err() != nil || !authenticatedPeer(conn) {
		_ = conn.Close()
		return nil, errors.Join(ctx.Err(), a.ErrUnauthorized)
	}
	return conn, nil
}

type lifecycleEndpoint struct {
	listener net.Listener
	hostOnly bool
	handle   func(context.Context, net.Conn) error
}

// All listeners are acquired before any handler starts; a bind failure cannot
// publish readiness or leave a partially active service. DATA uses the lifecycle
// wrapper around the real handler, including joined compatibility observations.
func startLifecycleServices(ctx context.Context, fail context.CancelFunc, service *s.LifecycleService, address string, listenVSock func(uint32) (net.Listener, error), listenTCP func(string, string) (net.Listener, error), budget time.Duration) (func() error, error) {
	var endpoints []lifecycleEndpoint
	cleanup := func() {
		for _, e := range endpoints {
			_ = e.listener.Close()
		}
	}
	for _, endpoint := range []struct {
		port   uint32
		handle func(context.Context, net.Conn) error
	}{{LifecyclePort, service.ServeLifecycle}, {ControlPort, service.ServeControl}, {CSRPort, service.ServeAttachmentCSR}} {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, err
		}
		listener, err := listenVSock(endpoint.port)
		if err != nil {
			cleanup()
			return nil, err
		}
		endpoints = append(endpoints, lifecycleEndpoint{listener, true, endpoint.handle})
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return nil, err
	}
	data, err := listenTCP("tcp", address)
	if err != nil {
		cleanup()
		return nil, err
	}
	endpoints = append(endpoints, lifecycleEndpoint{data, false, service.ServeDataConnection})
	if err := service.BindCompatibilityDataListener(data.Addr()); err != nil {
		cleanup()
		return nil, err
	}
	return serveLifecycleEndpoints(ctx, fail, endpoints, budget), nil
}

const lifecycleConnectionLimit = 32 // per endpoint, including idle/blocked workers

// Shutdown closes admission and every accepted raw connection, cancels handlers,
// and joins them within a fixed budget. Timeout keeps the authority owned and is
// reported as busy, never success or fabricated drain. Blocking filesystem work
// may outlive this return; callers must not infer process death or reopen safety.
func serveLifecycleEndpoints(parent context.Context, fail context.CancelFunc, endpoints []lifecycleEndpoint, budget time.Duration) func() error {
	ctx, cancel := context.WithCancel(parent)
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	stopping := false
	var acceptErr error
	var workers sync.WaitGroup
	shutdown := func() {
		mu.Lock()
		stopping = true
		for _, e := range endpoints {
			_ = e.listener.Close()
		}
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		cancel()
	}
	watchDone := make(chan struct{})
	stopWatch := context.AfterFunc(ctx, func() { defer close(watchDone); shutdown() })
	workers.Add(len(endpoints))
	for _, endpoint := range endpoints {
		go func(e lifecycleEndpoint) {
			defer workers.Done()
			slots := make(chan struct{}, lifecycleConnectionLimit)
			for {
				conn, err := e.listener.Accept()
				if err != nil {
					mu.Lock()
					unexpected := !stopping && ctx.Err() == nil
					if unexpected {
						acceptErr = errors.Join(acceptErr, err)
					}
					mu.Unlock()
					if unexpected {
						cancel()
						fail()
					}
					return
				}
				if e.hostOnly && !authenticatedPeer(conn) {
					_ = conn.Close()
					continue
				}
				mu.Lock()
				if stopping || ctx.Err() != nil {
					mu.Unlock()
					_ = conn.Close()
					return
				}
				select {
				case slots <- struct{}{}:
				default:
					mu.Unlock()
					_ = conn.Close()
					continue
				}
				connections[conn] = struct{}{}
				workers.Add(1)
				mu.Unlock()
				go func() {
					defer workers.Done()
					defer func() { _ = conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock(); <-slots }()
					_ = e.handle(ctx, conn)
				}()
			}
		}(endpoint)
	}
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			shutdown()
			if !stopWatch() {
				<-watchDone
			}
			joined := make(chan struct{})
			go func() { workers.Wait(); close(joined) }()
			timer := time.NewTimer(budget)
			defer timer.Stop()
			select {
			case <-joined:
			case <-timer.C:
				result = a.ErrBusy
			}
			mu.Lock()
			result = errors.Join(result, acceptErr)
			mu.Unlock()
		})
		return result
	}
}
