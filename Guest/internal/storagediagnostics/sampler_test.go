package storagediagnostics

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeFrames struct {
	frame runtime.Frame
	left  int
	calls int
}

func (f *fakeFrames) Next() (runtime.Frame, bool) {
	f.calls++
	f.left--
	return f.frame, f.left > 0
}

func fakeSampler(w io.Writer, records, frames int, symbol string) *sampler {
	s := newSampler(w)
	s.profile = func(p []runtime.StackRecord) (int, bool) {
		if len(p) != maxRecords {
			panic("profile buffer was resized")
		}
		for i := 0; i < records && i < len(p); i++ {
			p[i].Stack0[0] = 1
		}
		return records, records <= len(p)
	}
	s.frames = func([]uintptr) frameIterator {
		return &fakeFrames{frame: runtime.Frame{Function: symbol}, left: frames}
	}
	return s
}

func TestOnlyStaticFunctionSymbolsAreEmitted(t *testing.T) {
	var out bytes.Buffer
	symbol := "dev.cengine/guest/internal/storageserver.(*Server).Serve"
	s := fakeSampler(&out, 1, 1, symbol)
	s.frames = func([]uintptr) frameIterator {
		return &fakeFrames{left: 1, frame: runtime.Frame{
			Function: symbol,
			PC:       0xdeadbeef,
			Entry:    0xcafebabe,
			File:     "/private/secret/args=credentials.go",
			Line:     12345,
		}}
	}
	if !s.snapshot() {
		t.Fatal("unexpected stop")
	}
	want := snapshotLine + recordLine + "\t" + symbol + "\n"
	if out.String() != want {
		t.Fatalf("non-symbol data in output: %q", out.String())
	}
}

func TestUnknownAndMultilineSymbolsCannotBreakFraming(t *testing.T) {
	for _, symbol := range []string{"", "pkg.fn\nforged", "pkg.fn\rforged", "pkg.fn\tforged"} {
		var out bytes.Buffer
		s := fakeSampler(&out, 1, 1, symbol)
		s.snapshot()
		if want := snapshotLine + recordLine + "\t[symbol unavailable]\n"; out.String() != want {
			t.Fatalf("unsafe framing: %q", out.String())
		}
	}
}

func TestRealSelfProfileHasSymbolsNotSourcePathsOrArguments(t *testing.T) {
	var out bytes.Buffer
	secret := "do-not-emit-runtime-argument-secret"
	s := newSampler(&out)
	if !s.snapshot() {
		t.Fatal("unexpected stop")
	}
	runtime.KeepAlive(secret)
	text := out.String()
	if !strings.Contains(text, ".TestRealSelfProfileHasSymbolsNotSourcePathsOrArguments\n") {
		t.Fatalf("missing symbolized self frame: %q", text)
	}
	for _, forbidden := range []string{secret, "sampler_test.go", "sampler.go:", "0x", "goroutine 1 [", "/Users/", "/private/"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("non-symbol data %q in output", forbidden)
		}
	}
}

func TestRecordCapNeverResizesOrUsesStaleRecords(t *testing.T) {
	var out bytes.Buffer
	s := fakeSampler(&out, maxRecords+1, 1, "must.not.appear")
	s.frames = func([]uintptr) frameIterator {
		t.Fatal("overflow profile must not be symbolized")
		return nil
	}
	if !s.snapshot() || out.String() != snapshotLine+recordCap {
		t.Fatalf("record cap output: %q", out.String())
	}
}

func TestRecordLimitIsUsable(t *testing.T) {
	var out bytes.Buffer
	s := fakeSampler(&out, maxRecords, 1, "pkg.blocked")
	if !s.snapshot() || strings.Count(out.String(), recordLine) != maxRecords {
		t.Fatal("exactly 256 records should fit")
	}
	if strings.Contains(out.String(), "capped:") {
		t.Fatal("unexpected cap at exact record limit")
	}
}

func TestExpandedFramesAreBounded(t *testing.T) {
	var out bytes.Buffer
	s := fakeSampler(&out, 1, 1, "unused")
	frames := &fakeFrames{frame: runtime.Frame{Function: "pkg.blocked"}, left: maxFrames + 10}
	s.frames = func([]uintptr) frameIterator { return frames }
	if !s.snapshot() || frames.calls != maxFrames || !strings.HasSuffix(out.String(), frameCap) {
		t.Fatalf("frame cap: calls=%d output=%q", frames.calls, out.String())
	}
}

func TestFullPCRecordIsConservativelyMarked(t *testing.T) {
	var out bytes.Buffer
	s := fakeSampler(&out, 1, 1, "pkg.blocked")
	s.profile = func(p []runtime.StackRecord) (int, bool) {
		for i := range p[0].Stack0 {
			p[0].Stack0[i] = 1
		}
		return 1, true
	}
	if !s.snapshot() || !strings.HasSuffix(out.String(), frameCap) {
		t.Fatalf("full PC record must be marked: %q", out.String())
	}
}

func TestByteCapIsSessionWideAndPreservesCompleteLines(t *testing.T) {
	var out bytes.Buffer
	symbol := "pkg." + strings.Repeat("f", 2000)
	s := fakeSampler(&out, 1, maxFrames, symbol)
	count := 0
	for count < maxSnapshots {
		count++
		if !s.snapshot() {
			break
		}
	}
	if count <= 1 || count == maxSnapshots || out.Len() > maxBytes || !strings.HasSuffix(out.String(), byteCap) {
		t.Fatalf("bad session cap: snapshots=%d bytes=%d", count, out.Len())
	}
	if cap(s.buffer) != maxBytes || s.remaining != maxBytes-out.Len() {
		t.Fatal("buffer or budget grew")
	}
	for _, line := range strings.SplitAfter(out.String(), "\n") {
		switch line {
		case "", snapshotLine, recordLine, frameCap, byteCap, "\t" + symbol + "\n":
		default:
			t.Fatalf("partial or unexpected line: %q", line)
		}
	}
	if strings.Count(out.String(), byteCap) != 1 {
		t.Fatal("missing or duplicate byte-cap marker")
	}
}

func TestOversizedSymbolIsOmittedNotTruncated(t *testing.T) {
	var out bytes.Buffer
	s := fakeSampler(&out, 1, 1, strings.Repeat("f", maxBytes+1))
	if s.snapshot() || out.String() != snapshotLine+recordLine+byteCap {
		t.Fatalf("oversized symbol was truncated: bytes=%d", out.Len())
	}
}

type failingWriter struct {
	short bool
	calls int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("private error must not be logged")
}

func TestWriteFailuresStopWithoutRetry(t *testing.T) {
	for _, short := range []bool{false, true} {
		w := &failingWriter{short: short}
		s := fakeSampler(w, 1, 1, "pkg.blocked")
		run(fakeTicks(maxSnapshots), make(chan time.Time), s.snapshot)
		if w.calls != 1 {
			t.Fatalf("writer retried %d times", w.calls)
		}
	}
}

func fakeTicks(count int) chan time.Time {
	ticks := make(chan time.Time, count)
	for i := 0; i < count; i++ {
		ticks <- time.Time{}
	}
	return ticks
}

func TestFakeTicksStopAtFinalSnapshot(t *testing.T) {
	ticks := fakeTicks(maxSnapshots + 3)
	count := 0
	run(ticks, make(chan time.Time), func() bool { count++; return true })
	if count != maxSnapshots || len(ticks) != 4 {
		t.Fatalf("baseline plus eleven ticks: count=%d remaining ticks=%d", count, len(ticks))
	}
	if interval != 5*time.Second || duration != 60*time.Second {
		t.Fatal("diagnostic schedule changed")
	}
}

func TestDeadlineWinsEvenWithReadyTicks(t *testing.T) {
	deadline := make(chan time.Time)
	count := 0
	run(fakeTicks(maxSnapshots), deadline, func() bool {
		count++
		close(deadline)
		return true
	})
	if count != 1 {
		t.Fatalf("sampling continued past deadline: %d", count)
	}
	count = 0
	run(fakeTicks(maxSnapshots), deadline, func() bool { count++; return true })
	if count != 0 {
		t.Fatal("expired deadline allowed initial sample")
	}
}

func TestClosedTicksStopAfterBaseline(t *testing.T) {
	ticks := make(chan time.Time)
	close(ticks)
	count := 0
	run(ticks, make(chan time.Time), func() bool { count++; return true })
	if count != 1 {
		t.Fatalf("closed tick channel did not stop: %d", count)
	}
}
