package storagefuse

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Exactly the first two fsx seed-1 MAPWRITE ranges. No caller-controlled sizes.
var sparseOperations = [...]struct{ offset, length int }{{0x2ba358, 0xd6e}, {0x2ce205, 0x1589}}

func sparseModel(count int) ([]byte, error) {
	if count < 1 || count > len(sparseOperations) {
		return nil, errors.New("sparse operation count")
	}
	last := sparseOperations[count-1]
	model := make([]byte, last.offset+last.length)
	for i, op := range sparseOperations[:count] {
		for j := 0; j < op.length; j++ {
			model[op.offset+j] = byte(1 + (i*71+j)%251)
		}
	}
	return model, nil
}

func sparseSocket(file *os.File) (*net.UnixConn, error) {
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	u, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, errors.New("sparse socket type")
	}
	return u, nil
}

// Every received right is owned immediately, including malformed/truncated
// packets. Unexpected rights are closed, never retained or echoed to the sender.
func sparseReceive(conn *net.UnixConn, word string, wantsFD bool) (fd int, err error) {
	fd = -1
	data, control := make([]byte, 32), make([]byte, unix.CmsgSpace(2*4))
	n, oobn, flags, _, err := conn.ReadMsgUnix(data, control)
	if err != nil {
		return -1, err
	}
	var rights []int
	defer func() {
		for _, received := range rights {
			if received != fd || err != nil {
				unix.Close(received)
			}
		}
	}()
	messages, parseErr := unix.ParseSocketControlMessage(control[:oobn])
	for _, message := range messages {
		fds, e := unix.ParseUnixRights(&message)
		if e != nil {
			parseErr = e
		}
		for _, received := range fds {
			unix.CloseOnExec(received)
		}
		rights = append(rights, fds...)
	}
	want := 0
	if wantsFD {
		want = 1
	}
	if parseErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || string(data[:n]) != word || len(rights) != want {
		return -1, errors.New("sparse control packet")
	}
	if wantsFD {
		fd = rights[0]
	}
	return fd, nil
}

func sparseSend(conn *net.UnixConn, word string, fd int) error {
	var control []byte
	if fd >= 0 {
		control = unix.UnixRights(fd)
	}
	n, oobn, err := conn.WriteMsgUnix([]byte(word), control, nil)
	if err == nil && (n != len(word) || oobn != len(control)) {
		err = errors.New("short sparse control packet")
	}
	return err
}

type sparseBirth struct {
	pid, parent, group int
	start              uint64
}

func sparseParseBirth(raw []byte) (sparseBirth, error) {
	open, end := bytes.IndexByte(raw, '('), bytes.LastIndex(raw, []byte(") "))
	if len(raw) > 4096 || open < 2 || end < open {
		return sparseBirth{}, errors.New("sparse proc envelope")
	}
	pid, pe := strconv.Atoi(strings.TrimSpace(string(raw[:open])))
	fields := strings.Fields(string(raw[end+2:]))
	if pe != nil || len(fields) < 20 {
		return sparseBirth{}, errors.New("sparse proc fields")
	}
	parent, e1 := strconv.Atoi(fields[1])
	group, e2 := strconv.Atoi(fields[2])
	start, e3 := strconv.ParseUint(fields[19], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || pid <= 0 || parent <= 0 || group <= 0 || start == 0 {
		return sparseBirth{}, errors.New("sparse proc identity")
	}
	return sparseBirth{pid, parent, group, start}, nil
}

type sparseDiagnostic struct{ bytes.Buffer }

func (b *sparseDiagnostic) Write(p []byte) (int, error) {
	if len(p) > (16<<10)-b.Len() {
		return 0, errors.New("sparse diagnostic bound")
	}
	return b.Buffer.Write(p)
}

func TestNativeSparseContract(t *testing.T) {
	for _, count := range []int{-1, 0, 3, 1000} {
		if _, err := sparseModel(count); err == nil {
			t.Fatal("unbounded operation selection")
		}
	}
	first, _ := sparseModel(1)
	model, _ := sparseModel(2)
	if len(first) != 0x2bb0c6 || len(model) != 0x2cf78e || !bytes.Equal(first, model[:len(first)]) {
		t.Fatal("wrong exact sparse prefix")
	}
	for i, value := range model {
		payload := i >= 0x2ba358 && i < 0x2bb0c6 || i >= 0x2ce205 && i < 0x2cf78e
		if (value != 0) != payload {
			t.Fatal("hole/payload model", i)
		}
	}
	var out sparseDiagnostic
	if _, err := out.Write(make([]byte, 16<<10)); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Write([]byte{1}); err == nil || out.Len() != 16<<10 {
		t.Fatal("diagnostic overflow accepted")
	}
	raw := []byte("42 (odd ) name) S 7 42 " + strings.Repeat("0 ", 16) + "12345 0\n")
	got, err := sparseParseBirth(raw)
	if err != nil || got != (sparseBirth{42, 7, 42, 12345}) {
		t.Fatal(got, err)
	}
	for _, bad := range [][]byte{nil, []byte("42 (x) S"), bytes.Repeat([]byte("x"), 4097), bytes.Replace(raw, []byte("12345"), []byte("0"), 1)} {
		if _, err := sparseParseBirth(bad); err == nil {
			t.Fatal("invalid birth accepted")
		}
	}
}

func TestNativeSparseRightsContract(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3} {
		for _, word := range []string{"mount-v1", "wrong", strings.Repeat("x", 33)} {
			t.Run(fmt.Sprint(count, "-", len(word)), func(t *testing.T) {
				pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				left, right := os.NewFile(uintptr(pair[0]), "left"), os.NewFile(uintptr(pair[1]), "right")
				a, err := sparseSocket(left)
				left.Close()
				if err != nil {
					right.Close()
					t.Fatal(err)
				}
				defer a.Close()
				b, err := sparseSocket(right)
				right.Close()
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				a.SetDeadline(time.Now().Add(time.Second))
				b.SetDeadline(time.Now().Add(time.Second))
				file, err := os.CreateTemp(t.TempDir(), "right")
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				fds := make([]int, count)
				for i := range fds {
					fds[i] = int(file.Fd())
				}
				var control []byte
				if count != 0 {
					control = unix.UnixRights(fds...)
				}
				if _, _, err := a.WriteMsgUnix([]byte(word), control, nil); err != nil {
					t.Fatal(err)
				}
				fd, err := sparseReceive(b, "mount-v1", true)
				if count == 1 && word == "mount-v1" {
					if err != nil || fd < 0 {
						t.Fatal(fd, err)
					}
					unix.Close(fd)
				} else if err == nil || fd != -1 {
					t.Fatal("malformed rights accepted", fd, err)
				}
			})
		}
	}
}

// A process reap and joined FD exchange are independent ownership obligations.
func sparseRetirementSafe(reaped, exchanged bool) bool { return reaped && exchanged }

func TestNativeSparseRetirementOwnership(t *testing.T) {
	for _, reaped := range []bool{false, true} {
		for _, exchanged := range []bool{false, true} {
			if sparseRetirementSafe(reaped, exchanged) != (reaped && exchanged) {
				t.Fatal("unjoined retirement accepted")
			}
		}
	}
}

type sparseBlockedOutput struct {
	once             sync.Once
	entered, release chan struct{}
}

func (w *sparseBlockedOutput) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}
func TestNativeSparseDiagnosticBackpressure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	output := newNativeChildOutput(&sparseBlockedOutput{entered: entered, release: release})
	defer close(release)
	defer output.closeLive()
	output.Write([]byte("diagnostic"))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not enter sink")
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			output.Write([]byte("P cleanup-close 0 b 20000\n"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receipt backpressure blocked cleanup phases")
	}
}
