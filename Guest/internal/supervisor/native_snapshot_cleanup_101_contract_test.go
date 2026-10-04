//go:build linux || darwin

package supervisor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Source regression for the Linux-only assertion/Goexit cleanup path. This is
// not evidence of a native child, mount, FinishCopy, or consumer joining.
func TestSnapshot101AssertionCleanupContract(t *testing.T) {
	path := "native_prepare_preflight_v4_linux_test.go"
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "prepareV4OwnInitializer" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			d, ok := n.(*ast.DeferStmt)
			if !ok {
				return true
			}
			calls := snapshot101Calls(d)
			if calls["snapshotProceed.Write"] == 0 {
				return true
			}
			if calls["snapshotProceed.Write"] != 1 || calls["time.After"] != 1 || calls["unix.PidfdSendSignal"] != 2 || calls["t.Fatal"] != 0 || calls["prepareV4Must"] != 0 {
				t.Fatalf("release/kill/join cleanup changed: %v", calls)
			}
			found = true
			return false
		})
	}
	if !found {
		t.Fatal("assertion Goexit must defer release before consumer cleanup")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(b)
	for _, want := range []string{
		"snapshotHeld = mode != \"snapshot-death\"\n\t\tsnapshotProgress[len(snapshotProgress)-1]()",
		"if snapshotHeld {",
		"if !released && pidfd >= 0 {",
		"case <-time.After(10 * time.Second):",
		"if released && pidfd >= 0 {",
		"if !joined {\n\t\t\t*safe = false",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("lost cleanup constraint %q", want)
		}
	}
}

// Host source checks guard the Linux-only proof ordering, not native acceptance.
func TestSnapshot101ReadPendingContract(t *testing.T) {
	b, err := os.ReadFile("native_snapshot_io_101_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(b)
	for _, want := range []string{
		"go func() { result <- readOperation() }()",
		"case err := <-result:\n\t\t\t\tt.Fatalf(\"read/readdir completed while fence held:",
		"consumer.receive(t, \"read-pending\")",
		"pending()\n\t\tprogress(\"while-V-fenced\")\n\t\tpending()",
		"!snapshot101ReadFence(ops[index], positiveReads[index], event)",
		"completed retained Pread lacks subsequent actual READ admission",
		"read.Sequence <= fenced[0].Sequence",
		"after.Stats[0].Atim == before.Stats[0].Atim || after.Stats[1].Atim == before.Stats[1].Atim",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("lost read proof constraint %q", want)
		}
	}
	waits := strings.Index(source, "for range consumers {")
	pending := strings.Index(source, "pending := func() {")
	release := strings.Index(source, "mount.assertGone(t)")
	finish := strings.Index(source, "consumer.send(t, 'f')")
	later := strings.Index(source, "case read := <-observe.Reads():")
	if waits < 0 || pending <= waits || release <= pending || finish <= release || later <= finish {
		t.Fatal("fence/pending/real release/completion/later READ order changed")
	}
}

// The pending acknowledgement must check the actual Pwrite result, not merely
// process liveness. The existing Goexit owner-release regression above protects
// failures before either pending acknowledgement or completion command.
func TestSnapshot101RetainedPendingContract(t *testing.T) {
	b, err := os.ReadFile("native_snapshot_io_101_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(b)
	for _, want := range []string{
		"n, err := unix.Pwrite(fd, aligned, 0); result <- writeResult{n, err}",
		"case r := <-result:\n\t\t\t\tt.Fatalf(\"Pwrite completed while fence held:",
		"pending()\n\t\tprogress(\"while-V-fenced\")\n\t\tpending()",
		"consumer.receive(t, \"pwrite-pending\")",
		"consumer.send(t, 'f')",
		"original retained FD bytes differ",
		"completed retained Pwrite lacks subsequent actual WRITE admission",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("lost retained proof constraint %q", want)
		}
	}
}
