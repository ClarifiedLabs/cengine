package workloadstorage

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"dev.cengine/guest/internal/storagefuse"
	"golang.org/x/sys/unix"
)

type unprintableAttachmentError struct{}

func (unprintableAttachmentError) Error() string { panic("raw attachment error was formatted") }

func TestMountFailureReporterEmitsBeforeRetirementAndOnlyOnce(t *testing.T) {
	_, cause := storagefuse.Mount(storagefuse.Config{}) // actual constructor diagnostic
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lines []string
	reporter := &mountFailureReporter{emit: func(line string) {
		if ctx.Err() != nil {
			t.Fatal("diagnostic emitted after private-channel cancellation")
		}
		lines = append(lines, line)
	}}
	retired := 0
	callback := reporter.retirement(func(err error) {
		if len(lines) != 1 || err != cause {
			t.Fatal("diagnostic ordering or retirement cause changed")
		}
		retired++
		cancel()
	})
	callback(cause)
	callback(cause) // diagnostics do not suppress or duplicate authority callbacks
	reporter.report(errors.Join(cause, unprintableAttachmentError{}), false)
	if retired != 2 || ctx.Err() == nil || len(lines) != 1 || lines[0] != "cengine managed-mount-failure stage=preflight site=other op=other category=profile" {
		t.Fatalf("unexpected diagnostic/callback result: %q, callbacks=%d", lines, retired)
	}
}

func TestMountFailureReporterRetiresEvenIfSinkPanics(t *testing.T) {
	cause := unprintableAttachmentError{}
	retired := false
	r := &mountFailureReporter{emit: func(string) { panic("sink failed") }}
	func() {
		defer func() { _ = recover() }()
		r.retirement(func(error) { retired = true })(cause)
	}()
	if !retired {
		t.Fatal("diagnostic sink suppressed retirement")
	}
}

func TestMountFailureReporterClosedOutput(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		namespace bool
		want      string
	}{
		{"namespace-errno", &os.PathError{Op: "SECRET", Path: "/SECRET\nspoof", Err: unix.ELOOP}, true, "cengine managed-mount-failure stage=namespace site=other op=other category=ELOOP"},
		{"namespace-unknown", unprintableAttachmentError{}, true, "cengine managed-mount-failure stage=namespace site=other op=other category=other"},
		{"unknown", unprintableAttachmentError{}, false, "cengine managed-mount-failure stage=other site=other op=other category=other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			r := &mountFailureReporter{emit: func(line string) { lines = append(lines, line) }}
			r.report(nil, tc.namespace)
			r.report(tc.err, tc.namespace)
			if len(lines) != 1 || lines[0] != tc.want {
				t.Fatalf("unexpected output: %q", lines)
			}
		})
	}
}

func TestMountFailureReporterConcurrentReturnAndRetirement(t *testing.T) {
	var lines []string
	r := &mountFailureReporter{emit: func(line string) { lines = append(lines, line) }}
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r.report(unprintableAttachmentError{}, false)
		}()
	}
	workers.Wait()
	if len(lines) != 1 || lines[0] != "cengine managed-mount-failure stage=other site=other op=other category=other" {
		t.Fatalf("unexpected output: %q", lines)
	}
}
