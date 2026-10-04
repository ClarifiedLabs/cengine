// Package storagediagnostics provides compile-time-only, self-runtime diagnostics.
// Only diagnostic-tagged PID 1 entry points call Start; normal builds do not
// import this package. There is no sampler-specific runtime configuration.
package storagediagnostics

import (
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	interval     = 5 * time.Second
	duration     = 60 * time.Second
	maxSnapshots = 12
	maxRecords   = 256
	maxFrames    = 32
	maxBytes     = 128 * 1024 // Total output across the entire session.

	snapshotLine = "[storage-diagnostics] snapshot\n"
	recordLine   = "[storage-diagnostics] goroutine\n"
	recordCap    = "[storage-diagnostics] capped: goroutine records\n"
	frameCap     = "[storage-diagnostics] capped: frames\n"
	byteCap      = "[storage-diagnostics] capped: output bytes\n"
)

var startOnce sync.Once

// Start launches one best-effort sampler on the existing private VM console.
// The caller must be the owned VM's PID 1. There is no environment, argument,
// kernel, filesystem, transport, or API configuration surface.
func Start() {
	startOnce.Do(func() {
		ticks := time.NewTicker(interval)
		deadline := time.NewTimer(duration)
		go func() {
			defer ticks.Stop()
			defer deadline.Stop()
			s := newSampler(os.Stderr)
			run(ticks.C, deadline.C, s.snapshot)
		}()
	})
}

// A baseline is followed by at most eleven ticks (nominally 0 through 55s).
// The independent deadline prevents slow samples from extending the schedule.
func run(ticks, deadline <-chan time.Time, snapshot func() bool) {
	for count := 0; count < maxSnapshots; count++ {
		if count > 0 {
			select {
			case _, open := <-ticks:
				if !open {
					return
				}
			case <-deadline:
				return
			}
		}
		// Prefer an expired deadline even when a tick is also ready.
		select {
		case <-deadline:
			return
		default:
		}
		if !snapshot() {
			return
		}
	}
}

type frameIterator interface {
	Next() (runtime.Frame, bool)
}

type sampler struct {
	writer    io.Writer
	profile   func([]runtime.StackRecord) (int, bool)
	frames    func([]uintptr) frameIterator
	records   [maxRecords]runtime.StackRecord
	buffer    []byte
	remaining int
	capped    bool
}

func newSampler(writer io.Writer) *sampler {
	return &sampler{
		writer:    writer,
		profile:   runtime.GoroutineProfile,
		frames:    func(pcs []uintptr) frameIterator { return runtime.CallersFrames(pcs) },
		buffer:    make([]byte, 0, maxBytes),
		remaining: maxBytes,
	}
}

func (s *sampler) snapshot() bool {
	s.buffer = s.buffer[:0]
	if s.line(snapshotLine) {
		n, ok := s.profile(s.records[:])
		if !ok || n < 0 || n > len(s.records) {
			// GoroutineProfile does not return a partial profile when the fixed
			// buffer is too small. Never resize it or emit stale records.
			s.line(recordCap)
		} else {
			for i := 0; i < n && !s.capped; i++ {
				s.record(s.records[i].Stack())
			}
		}
	}
	n, err := s.writer.Write(s.buffer)
	s.remaining -= len(s.buffer)
	// No retries, secondary logging, worker handoff, or unbounded queue. A
	// blocked console can block only this dedicated sampler goroutine.
	return !s.capped && err == nil && n == len(s.buffer)
}

func (s *sampler) record(pcs []uintptr) {
	if !s.line(recordLine) || len(pcs) == 0 {
		return
	}
	frames := s.frames(pcs)
	for count := 0; count < maxFrames; count++ {
		frame, more := frames.Next()
		// Function is the static, import-qualified Go symbol. Never serialize
		// Frame itself: its other fields contain PCs and source locations.
		symbol := frame.Function
		if symbol == "" || strings.ContainsAny(symbol, "\r\n\t") {
			symbol = "[symbol unavailable]"
		}
		if !s.line("\t", symbol, "\n") {
			return
		}
		if !more {
			// StackRecord itself holds only 32 PCs. Conservatively mark a full
			// record even if CallersFrames cannot tell whether it was truncated.
			if len(pcs) == maxFrames {
				s.line(frameCap)
			}
			return
		}
	}
	s.line(frameCap)
}

// line reserves space for the cap marker and appends only complete lines.
func (s *sampler) line(parts ...string) bool {
	if s.capped {
		return false
	}
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	if size > s.remaining-len(s.buffer)-len(byteCap) {
		s.buffer = append(s.buffer, byteCap...)
		s.capped = true
		return false
	}
	for _, part := range parts {
		s.buffer = append(s.buffer, part...)
	}
	return true
}
