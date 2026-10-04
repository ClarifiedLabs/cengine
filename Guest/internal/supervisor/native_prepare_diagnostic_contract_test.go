//go:build cengine_native_faulttest

package supervisor

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type prepareDiagnosticFake struct {
	stat     func() []byte
	names    []string
	children map[string]*prepareDiagnosticFake
	fields   map[string][]byte
	opened   []string
	closed   int
	before   func(string)
}

func (p *prepareDiagnosticFake) read(name string, maximum int64) ([]byte, error) {
	if p.before != nil {
		p.before("read:" + name)
	}
	if name == "stat" {
		return p.stat(), nil
	}
	data, ok := p.fields[name]
	if !ok {
		return nil, errors.New("unavailable")
	}
	return data, nil
}
func (p *prepareDiagnosticFake) tasks() ([]string, error) {
	if p.before != nil {
		p.before("tasks")
	}
	return p.names, nil
}
func (p *prepareDiagnosticFake) task(name string) (prepareDiagnosticProc, error) {
	if p.before != nil {
		p.before("task:" + name)
	}
	p.opened = append(p.opened, name)
	if child := p.children[name]; child != nil {
		return child, nil
	}
	return nil, errors.New("unavailable")
}
func (p *prepareDiagnosticFake) close() { p.closed++ }
func prepareDiagnosticStat(pid, parent, group int, birth uint64) []byte {
	return []byte(fmt.Sprintf("%d (odd ) private-name) S %d %d %s%d 0\n", pid, parent, group, strings.Repeat("0 ", 16), birth))
}
func prepareDiagnosticFixture() (*prepareDiagnosticFake, *prepareDiagnosticFake, prepareDiagnosticBirth) {
	birth := prepareDiagnosticBirth{42, 7, 42, 12345}
	child := &prepareDiagnosticFake{stat: func() []byte { return prepareDiagnosticStat(43, 7, 42, 12346) }, fields: map[string][]byte{"wchan": []byte("wait"), "syscall": []byte("1 2 3"), "stack": []byte("kernel-frame")}}
	proc := &prepareDiagnosticFake{stat: func() []byte { return prepareDiagnosticStat(42, 7, 42, 12345) }, names: []string{"43", "../secret", "043", "-1"}, children: map[string]*prepareDiagnosticFake{"43": child}}
	return proc, child, birth
}

func TestPrepareDiagnosticBirthAndClosedPhases(t *testing.T) {
	raw := prepareDiagnosticStat(42, 7, 42, 12345)
	if got, err := prepareDiagnosticParse(raw); err != nil || got != (prepareDiagnosticBirth{42, 7, 42, 12345}) {
		t.Fatal(got, err)
	}
	for _, raw := range [][]byte{nil, []byte("42 (x) S"), bytes.Repeat([]byte("x"), 4097), prepareDiagnosticStat(0, 7, 42, 12345), prepareDiagnosticStat(42, 0, 42, 12345), prepareDiagnosticStat(42, 7, 0, 12345), prepareDiagnosticStat(42, 7, 42, 0)} {
		if _, err := prepareDiagnosticParse(raw); err == nil {
			t.Fatal("unproven identity accepted")
		}
	}
	var out bytes.Buffer
	for phase := prepareInitializeBegin; phase <= prepareEvidenceEnd; phase++ {
		prepareDiagnosticMark(&out, phase)
	}
	want := "D prepare-phase initialize-begin\nD prepare-phase initialize-end\nD prepare-phase close-begin\nD prepare-phase close-end\nD prepare-phase join-begin\nD prepare-phase join-end\nD prepare-phase evidence-begin\nD prepare-phase evidence-end\n"
	if out.String() != want {
		t.Fatal(out.String())
	}
	prepareDiagnosticMark(&out, 255)
	if out.String() != want {
		t.Fatal("open-ended phase")
	}
}

func TestPrepareDiagnosticExactChildAndBounds(t *testing.T) {
	proc, child, birth := prepareDiagnosticFixture()
	got := string(prepareDiagnosticSnapshot(proc, birth, func() bool { return false }))
	if !strings.Contains(got, "prepare-child pid=42 birth=12345") || !strings.Contains(got, "prepare-tid=43") || !strings.Contains(got, "kernel-frame") || strings.Contains(got, "private-name") || strings.Join(proc.opened, ",") != "43" || child.closed != 1 {
		t.Fatal(got, proc.opened, child.closed)
	}
	proc, child, birth = prepareDiagnosticFixture()
	child.fields["stack"] = bytes.Repeat([]byte("x"), 1025)
	got = string(prepareDiagnosticSnapshot(proc, birth, func() bool { return false }))
	if !strings.Contains(got, "D stack unavailable") || strings.Contains(got, "xxx") {
		t.Fatal(got)
	}
	proc, _, birth = prepareDiagnosticFixture()
	proc.names = nil
	for n := 0; n < 40; n++ {
		name := fmt.Sprint(43 + n)
		proc.names = append(proc.names, name)
		pid := 43 + n
		proc.children[name] = &prepareDiagnosticFake{stat: func() []byte { return prepareDiagnosticStat(pid, 7, 42, 12346) }, fields: map[string][]byte{"wchan": bytes.Repeat([]byte("w"), 1024), "syscall": bytes.Repeat([]byte("s"), 1024), "stack": bytes.Repeat([]byte("k"), 1024)}}
	}
	got = string(prepareDiagnosticSnapshot(proc, birth, func() bool { return false }))
	if len(got) > prepareDiagnosticLimit || !strings.Contains(got, "prepare-task-count-bound") || !strings.Contains(got, "prepare-observation-bound") || len(proc.opened) > 32 {
		t.Fatal(len(got), proc.opened)
	}
	var bounded prepareDiagnosticBuffer
	if _, err := bounded.Write(make([]byte, prepareDiagnosticLimit)); err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.Write([]byte{1}); err == nil || bounded.Len() != prepareDiagnosticLimit {
		t.Fatal("unbounded diagnostic")
	}
}

func TestPrepareDiagnosticPIDFDAndNamespace(t *testing.T) {
	if !prepareDiagnosticNamespace(0x9fa0, []byte("7"), 7) || !prepareDiagnosticPID([]byte("pos:\t0\nPid:\t42\nNSpid:\t42\n"), 42) {
		t.Fatal("valid binding rejected")
	}
	for _, raw := range []string{"", "Pid: -1\n", "Pid: 43\n", "Pid: 42\nPid: 42\n", "Pid: 42 extra\n", "Pid: 042\n", strings.Repeat("x", 4097)} {
		if prepareDiagnosticPID([]byte(raw), 42) {
			t.Fatal("foreign/unproven pidfd", raw)
		}
	}
	for _, self := range []string{"8", "07", "7\n", ""} {
		if prepareDiagnosticNamespace(0x9fa0, []byte(self), 7) {
			t.Fatal("foreign proc namespace")
		}
	}
	if prepareDiagnosticNamespace(0xef53, []byte("7"), 7) || prepareDiagnosticNamespace(0x9fa0, []byte("0"), 0) {
		t.Fatal("non-proc or invalid self")
	}
}

func TestPrepareDiagnosticExpiryStartsNoMoreReads(t *testing.T) {
	for _, boundary := range []string{"before-first", "process:read:stat", "process:tasks", "process:task:43", "thread:read:stat", "thread:read:wchan", "thread:read:stack"} {
		t.Run(boundary, func(t *testing.T) {
			proc, child, birth := prepareDiagnosticFixture()
			expired := boundary == "before-first"
			calls := 0
			hook := func(role string) func(string) {
				return func(op string) {
					if expired {
						t.Errorf("new proc operation after expiry: %s:%s", role, op)
					}
					calls++
					if role+":"+op == boundary {
						expired = true
					}
				}
			}
			proc.before = hook("process")
			child.before = hook("thread")
			got := string(prepareDiagnosticSnapshot(proc, birth, func() bool { return expired }))
			if !expired || strings.Contains(got, "D prepare-tid=") {
				t.Fatal("incomplete row published", got)
			}
			if boundary == "before-first" && calls != 0 {
				t.Fatal("initial read after expiry")
			}
		})
	}
}

func TestPrepareDiagnosticRejectsDeathReuseAndForeignTasks(t *testing.T) {
	for _, which := range []string{"process-reuse", "process-death", "foreign-thread", "thread-reuse", "process-changed-during-read", "expired"} {
		t.Run(which, func(t *testing.T) {
			proc, child, birth := prepareDiagnosticFixture()
			expired := false
			switch which {
			case "process-reuse":
				proc.stat = func() []byte { return prepareDiagnosticStat(42, 7, 42, 999) }
			case "process-death":
				proc.stat = func() []byte { return nil }
			case "foreign-thread":
				child.stat = func() []byte { return prepareDiagnosticStat(43, 99, 42, 12346) }
			case "thread-reuse":
				n := 0
				child.stat = func() []byte { n++; return prepareDiagnosticStat(43, 7, 42, uint64(12346+n)) }
			case "process-changed-during-read":
				n := 0
				proc.stat = func() []byte { n++; return prepareDiagnosticStat(42, 7, 42, uint64(12344+n)) }
			case "expired":
				expired = true
			}
			got := string(prepareDiagnosticSnapshot(proc, birth, func() bool { return expired }))
			if strings.Contains(got, "kernel-frame") || strings.Contains(got, "D prepare-tid=") {
				t.Fatal("unproven task published", got)
			}
		})
	}
}

// The callback includes INITIAL proc acquisition, not just later field reads.
func TestPrepareDiagnosticObserverAcquisitionCannotDelayOwner(t *testing.T) {
	trigger := make(chan time.Time, 1)
	stop := make(chan struct{})
	closed := make(chan struct{})
	started := make(chan struct{})
	release := make(chan struct{})
	done := prepareDiagnosticObserver(trigger, stop, func() []byte { close(started); <-release; return []byte("snapshot") }, func() { close(closed) })
	trigger <- time.Now()
	<-started
	close(stop)
	select {
	case <-closed:
		t.Fatal("closed proc while observation still owns it")
	default:
	}
	select {
	case <-done:
		t.Fatal("invented observation completion")
	default:
	}
	close(release)
	if got := <-done; string(got) != "snapshot" {
		t.Fatal(string(got))
	}
	<-closed
	stop = make(chan struct{})
	close(stop)
	closed = make(chan struct{})
	trigger = make(chan time.Time)
	prepareDiagnosticObserver(trigger, stop, func() []byte { t.Error("canceled observer ran"); return nil }, func() { close(closed) })
	<-closed
}
