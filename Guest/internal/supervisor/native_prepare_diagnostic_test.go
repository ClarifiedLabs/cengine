//go:build cengine_native_faulttest

package supervisor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

const prepareDiagnosticLimit = 16 << 10

type prepareDiagnosticBirth struct {
	pid, parent, group int
	start              uint64
}

func prepareDiagnosticParse(raw []byte) (prepareDiagnosticBirth, error) {
	open, end := bytes.IndexByte(raw, '('), bytes.LastIndex(raw, []byte(") "))
	if len(raw) > 4096 || open < 2 || end < open {
		return prepareDiagnosticBirth{}, errors.New("prepare proc envelope")
	}
	pid, pe := strconv.Atoi(strings.TrimSpace(string(raw[:open])))
	fields := strings.Fields(string(raw[end+2:]))
	if pe != nil || len(fields) < 20 {
		return prepareDiagnosticBirth{}, errors.New("prepare proc fields")
	}
	parent, e1 := strconv.Atoi(fields[1])
	group, e2 := strconv.Atoi(fields[2])
	start, e3 := strconv.ParseUint(fields[19], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || pid <= 0 || parent <= 0 || group <= 0 || start == 0 {
		return prepareDiagnosticBirth{}, errors.New("prepare proc identity")
	}
	return prepareDiagnosticBirth{pid, parent, group, start}, nil
}

func prepareDiagnosticNamespace(magic int64, self []byte, current int) bool {
	return magic == 0x9fa0 && current > 0 && string(self) == strconv.Itoa(current)
}

func prepareDiagnosticPID(raw []byte, expected int) bool {
	if len(raw) > 4096 || expected <= 0 {
		return false
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "Pid:" {
			if found || len(fields) != 2 || fields[1] != strconv.Itoa(expected) {
				return false
			}
			found = true
		}
	}
	return found
}

type prepareDiagnosticBuffer struct{ bytes.Buffer }

func (b *prepareDiagnosticBuffer) Write(p []byte) (int, error) {
	if len(p) > prepareDiagnosticLimit-b.Len() {
		return 0, errors.New("prepare diagnostic bound")
	}
	return b.Buffer.Write(p)
}

// Test-only proc interface. Native opens every task relative to the birth-pinned
// process directory; neither payload paths nor arbitrary process selectors exist.
type prepareDiagnosticProc interface {
	read(string, int64) ([]byte, error)
	tasks() ([]string, error)
	task(string) (prepareDiagnosticProc, error)
	close()
}

func prepareDiagnosticSnapshot(proc prepareDiagnosticProc, expected prepareDiagnosticBirth, expired func() bool) []byte {
	var out prepareDiagnosticBuffer
	fmt.Fprintf(&out, "D prepare-child pid=%d birth=%d\n", expected.pid, expected.start)
	bound := func() bool {
		if expired() {
			fmt.Fprintln(&out, "D prepare-observation-bound")
			return true
		}
		return false
	}
	matches := func(p prepareDiagnosticProc, want prepareDiagnosticBirth) bool {
		if bound() {
			return false
		}
		raw, err := p.read("stat", 4096)
		got, parseErr := prepareDiagnosticParse(raw)
		return err == nil && parseErr == nil && got == want
	}
	if !matches(proc, expected) {
		fmt.Fprintln(&out, "D prepare-process-unavailable")
		return out.Bytes()
	}
	if bound() {
		return out.Bytes()
	}
	names, err := proc.tasks()
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(&out, "D prepare-tasks-unavailable")
		return out.Bytes()
	}
	if len(names) > 32 {
		names = names[:32]
		fmt.Fprintln(&out, "D prepare-task-count-bound")
	}
	sort.Strings(names)
	for _, name := range names {
		if expired() || out.Len() > prepareDiagnosticLimit-4096 {
			fmt.Fprintln(&out, "D prepare-observation-bound")
			break
		}
		tid, err := strconv.Atoi(name)
		if err != nil || tid <= 0 || strconv.Itoa(tid) != name {
			continue
		}
		task, err := proc.task(name)
		if err != nil {
			continue
		}
		if bound() {
			task.close()
			break
		}
		raw, readErr := task.read("stat", 4096)
		birth, parseErr := prepareDiagnosticParse(raw)
		var row prepareDiagnosticBuffer
		if readErr == nil && parseErr == nil && birth.pid == tid && birth.parent == expected.parent && birth.group == expected.group {
			fmt.Fprintf(&row, "D prepare-tid=%d birth=%d\n", tid, birth.start)
			for _, field := range []string{"wchan", "syscall", "stack"} {
				if expired() {
					break
				}
				data, err := task.read(field, 1024)
				if err != nil || len(data) > 1024 {
					data = []byte("unavailable")
				}
				fmt.Fprintf(&row, "D %s %s\n", field, data)
			}
			// Do not publish a task row if its identity changed during observation.
			if matches(task, birth) && matches(proc, expected) {
				_, _ = out.Write(row.Bytes())
			}
		}
		task.close()
	}
	return out.Bytes()
}

// A proc read cannot delay the fixture's kill/join timers. The observer owns its
// descriptor until it actually returns, even if a kernel proc read stalls. It
// owns no mount, backing descriptor, signaling capability use, or retirement.
// Its private pidfd duplicate is never used to signal, only to validate identity.
func prepareDiagnosticObserver(trigger <-chan time.Time, stop <-chan struct{}, snapshot func() []byte, closePin func()) <-chan []byte {
	done := make(chan []byte, 1)
	go func() {
		defer closePin()
		select {
		case <-stop:
			return
		case <-trigger:
		}
		select {
		case <-stop:
			return
		default:
		}
		done <- snapshot()
	}()
	return done
}

type prepareDiagnosticPhase uint8

const (
	prepareInitializeBegin prepareDiagnosticPhase = iota
	prepareInitializeEnd
	prepareCloseBegin
	prepareCloseEnd
	prepareJoinBegin
	prepareJoinEnd
	prepareEvidenceBegin
	prepareEvidenceEnd
)

func prepareDiagnosticMark(out io.Writer, phase prepareDiagnosticPhase) {
	labels := [...]string{"initialize-begin", "initialize-end", "close-begin", "close-end", "join-begin", "join-end", "evidence-begin", "evidence-end"}
	if int(phase) < len(labels) {
		fmt.Fprintf(out, "D prepare-phase %s\n", labels[phase])
	}
}
