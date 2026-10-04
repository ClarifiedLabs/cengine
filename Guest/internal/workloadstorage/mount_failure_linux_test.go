//go:build linux

package workloadstorage

import (
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMountFailureSinkUsesExactDescriptorAndFixedLine(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	before, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &mountFailureReporter{emit: func(line string) { emitMountFailureTo(fd, line) }}
	r.report(&os.PathError{Op: "SECRET", Path: "/SECRET", Err: unix.EPERM}, true)
	want := "cengine managed-mount-failure stage=namespace site=other op=other category=EPERM\n"
	buffer := make([]byte, 256)
	if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := reader.Read(buffer)
	if err != nil || string(buffer[:n]) != want {
		t.Fatalf("stderr diagnostic = %q, error=%v", buffer[:n], err)
	}
	after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || before != after {
		t.Fatalf("inherited descriptor flags changed: %d -> %d, %v", before, after, err)
	}
}

func TestMountFailureSinkFullPipeDoesNotDelayRetirement(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd()) // original description is blocking, like inherited stderr
	fill, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fill)
	buffer := make([]byte, 4096)
	for {
		_, err := unix.Write(fill, buffer)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	r := &mountFailureReporter{emit: func(line string) { emitMountFailureTo(fd, line) }}
	done := make(chan struct{})
	go func() {
		session := &Session{prepareFailureSink: func(line string) { emitMountFailureTo(fd, line) }}
		session.reportPrepareFailure(prepareWorkload, unix.EIO)
		r.retirement(func(error) { close(done) })(unix.EINVAL)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		// Unblock and join even a regressed blocking writer before failing.
		_ = reader.Close()
		<-done
		t.Fatal("diagnostic sink blocked retirement")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK != 0 {
		t.Fatal("diagnostic changed inherited stderr flags")
	}
}

func TestMountFailureSinkFailureStillRetires(t *testing.T) {
	session := &Session{prepareFailureSink: func(line string) { emitMountFailureTo(-1, line) }}
	session.reportPrepareFailure(prepareWorkload, unix.EIO)
	retired := false
	r := &mountFailureReporter{emit: func(line string) { emitMountFailureTo(-1, line) }}
	r.retirement(func(error) { retired = true })(unix.EIO)
	if !retired {
		t.Fatal("failed diagnostic sink suppressed retirement")
	}
}
