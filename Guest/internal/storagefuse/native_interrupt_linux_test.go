//go:build linux && (arm64 || amd64)

package storagefuse

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

func TestNativeMountedManagedV3InterruptGraceful(t *testing.T) {
	nativeMountedManagedV3(t, "interrupt")
}

// Hold a real encrypted DATA reply below TLS. No credentials, responses or
// executor results are synthesized. Close also releases the gate on failure.
type nativeInterruptGate struct {
	net.Conn
	armed            atomic.Bool
	entered, proceed chan struct{}
	once             sync.Once
}

func (g *nativeInterruptGate) release()     { g.once.Do(func() { close(g.proceed) }) }
func (g *nativeInterruptGate) Close() error { g.release(); return g.Conn.Close() }
func (g *nativeInterruptGate) Write(p []byte) (int, error) {
	if g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.proceed
	}
	return g.Conn.Write(p)
}

func nativeInterruptCompletion(t *testing.T, mount *Mounted, gate *nativeInterruptGate, replies <-chan fuse.ReplyDelivery) {
	t.Helper()
	defer gate.release()
	gate.armed.Store(true)
	tid := make(chan int, 1)
	opened := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid <- unix.Gettid()
		fd, err := unix.Open(mount.Mountpoint(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err == nil {
			err = unix.Close(fd)
		}
		opened <- err
	}()
	thread := <-tid
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("real DATA reply did not reach transport gate")
	}
	// A nonfatal signal while this exact thread is blocked in FUSE must queue
	// an advisory INTERRUPT. Go's SIGURG handler remains enabled, unmodified.
	nativeMust(t, unix.Tgkill(os.Getpid(), thread, unix.SIGURG))
	var interrupt fuse.ReplyDelivery
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for interrupt.Opcode == 0 {
		select {
		case r := <-replies:
			if r.Opcode == 36 {
				interrupt = r
			}
		case <-deadline.C:
			t.Fatal("no actual native INTERRUPT observation")
		}
	}
	if !completedInterrupt(interrupt) || !interrupt.Suppressed {
		t.Fatalf("expected matched advisory interrupt: %+v", interrupt)
	}
	if mount.fs.stopped.Load() || mount.client.Err() != nil || len(mount.fs.slots) == 0 {
		t.Fatalf("interrupt aborted or dropped admitted request: %v", mount.client.Err())
	}
	select {
	case err := <-opened:
		t.Fatalf("interrupted caller finished before its DATA response: %v", err)
	default:
	}
	gate.release()
	nativeMust(t, nativeWait(t, "interrupted syscall and close", opened))
	for {
		select {
		case r := <-replies:
			// Linux FUSE_INT_REQ_BIT is bit zero of the original Unique.
			if r.Opcode != 36 && r.Unique == interrupt.Unique&^1 {
				if !r.Interrupted || !deliveredDespiteInterrupt(r) {
					t.Fatalf("original response lacked delivery proof: %+v", r)
				}
				if mount.Err() != nil {
					t.Fatal(mount.Err())
				}
				return
			}
		case <-deadline.C:
			t.Fatal(fmt.Sprintf("no full original reply for interrupt %d", interrupt.Unique))
		}
	}
	// The enclosing real fixture closes gracefully, joins DATA, obtains the
	// controller's barrier receipt and verifies exact mount/FD cleanup.
}
