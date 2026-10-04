//go:build linux

package storageworker

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Child contains only transport and the inherited root descriptor. Accept does
// not open an authority or consume an application start gate. The integration
// layer MUST verify FD4's ext4/provenance and require an explicit authenticated
// application start packet before opening any authority or serving requests.
// Child owns Root; callers must not close/reuse FD3 or FD4 behind Accept's back.
type Child struct {
	*Channel
	Root *os.File
}

// Accept is called only in the fixed --managed-lifecycle-worker dispatch. It
// consumes FD3 and FD4 even on error. No environment/path/parent override exists.
func Accept() (*Child, error) { return accept(1) }

func accept(parent int) (*Child, error) {
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	channel := os.NewFile(3, "storageworker-inherited-channel")
	root := os.NewFile(4, "storageworker-inherited-root")
	fail := func(err error) (*Child, error) { _ = channel.Close(); _ = root.Close(); return nil, err }
	if os.Getppid() != parent || os.Getuid() != 0 || os.Getgid() != 0 || os.Geteuid() != 0 || os.Getegid() != 0 {
		return fail(errors.New("storageworker: root PID1 parent required"))
	}
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fail(err)
	}
	if os.Getppid() != parent {
		return fail(errors.New("storageworker: parent changed during accept"))
	}
	// Reject ambient inheritance that raced the parent's preflight. The
	// fixed worker dispatch must exit on Accept failure, before service work.
	if err := checkInheritedFDs(); err != nil {
		return fail(err)
	}
	st, err := root.Stat()
	if err != nil || !st.IsDir() {
		return fail(errors.New("storageworker: inherited root is not directory"))
	}
	ch, err := newChannel(channel, parent)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := ch.Send(readyPacket); err != nil {
		_ = ch.Close()
		_ = root.Close()
		return nil, err
	}
	return &Child{Channel: ch, Root: root}, nil
}

func (c *Child) Close() error { return errors.Join(c.Channel.Close(), c.Root.Close()) }
