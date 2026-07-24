//go:build linux

package supervisor

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestPseudoTerminalUsesRequestedAndDefaultSizes(t *testing.T) {
	requested := &protocol.TerminalSize{Height: 37, Width: 119}
	master, slave, err := openPseudoTerminal(requested)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	size, err := unix.IoctlGetWinsize(int(master.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		t.Fatal(err)
	}
	if size.Row != requested.Height || size.Col != requested.Width {
		t.Fatalf("terminal size = %dx%d, want %dx%d", size.Row, size.Col, requested.Height, requested.Width)
	}

	zero := &protocol.TerminalSize{}
	if got := effectiveTerminalSize(zero); got.Height != 24 || got.Width != 80 {
		t.Fatalf("default terminal size = %dx%d, want 24x80", got.Height, got.Width)
	}
}

func TestSetTerminalSizeChangesLivePseudoTerminal(t *testing.T) {
	master, slave, err := openPseudoTerminal()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := setTerminalSize(master, protocol.TerminalSize{Height: 48, Width: 160}); err != nil {
		t.Fatal(err)
	}
	size, err := unix.IoctlGetWinsize(int(slave.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		t.Fatal(err)
	}
	if size.Row != 48 || size.Col != 160 {
		t.Fatalf("terminal size = %dx%d, want 48x160", size.Row, size.Col)
	}
}

func TestExecStartTerminalSizeOverridesExecCreateSize(t *testing.T) {
	configured := &protocol.TerminalSize{Height: 24, Width: 80}
	start := &protocol.TerminalSize{Height: 42, Width: 132}
	if got := selectedTerminalSize(start, configured); got != start {
		t.Fatalf("selected start terminal size = %#v, want %#v", got, start)
	}
	if got := selectedTerminalSize(&protocol.TerminalSize{}, configured); got != configured {
		t.Fatalf("selected zero start terminal size = %#v, want configured %#v", got, configured)
	}
}

func TestTerminalOutputSurvivesSlaveReopen(t *testing.T) {
	master, slave, err := openPseudoTerminal()
	if err != nil {
		t.Fatal(err)
	}
	slavePath := slave.Name()
	destination, err := os.CreateTemp(t.TempDir(), "terminal-output")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sleep", "10")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go pumpTerminalOutput(master, destination, command)

	if _, err := slave.WriteString("before\n"); err != nil {
		t.Fatal(err)
	}
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	reopened, err := os.OpenFile(slavePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.WriteString("after\n"); err != nil {
		t.Fatal(err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed command exited successfully")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		contents, err := os.ReadFile(destination.Name())
		if err != nil {
			t.Fatal(err)
		}
		output := string(contents)
		normalized := strings.ReplaceAll(output, "\r\n", "\n")
		if strings.Contains(normalized, "before\n") && strings.Contains(normalized, "after\n") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("terminal output = %q", output)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
