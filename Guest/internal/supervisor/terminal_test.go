//go:build linux

package supervisor

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

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
