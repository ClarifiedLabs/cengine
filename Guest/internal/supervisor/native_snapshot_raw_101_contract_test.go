//go:build linux || darwin

package supervisor

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshot101RawProgress(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "progress")
	var original os.FileInfo
	for _, value := range []string{"before", "while-V-fenced", "after"} {
		if err := snapshot101Progress(root, value); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != value {
			t.Fatalf("complete progress readback: %q, %v", data, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("progress mode: %v, %v", info, err)
		}
		if original != nil && !os.SameFile(original, info) {
			t.Fatal("progress inode replaced")
		}
		original = info
	}
	if err := snapshot101Progress(filepath.Join(root, "missing"), "before"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing mount: %v", err)
	}
	if err := snapshot101WriteProgress(root, "before"); err == nil {
		t.Fatal("directory accepted as progress file")
	}
}

func TestSnapshot101RawReadback(t *testing.T) {
	const want = "pinned-owner-data"
	for _, value := range []string{want, "", want[:len(want)-1], want + "x", "pinned-owner-datX"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "probe")
			if err := os.WriteFile(path, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			err := snapshot101Readback(path, want)
			if value == want && err != nil || value != want && !errors.Is(err, errSnapshot101Readback) {
				t.Fatalf("readback %q: %v", value, err)
			}
		})
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := snapshot101Readback(missing, want); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing probe: %v", err)
	}
	if err := snapshot101Readback(t.TempDir(), want); err == nil {
		t.Fatal("directory accepted as probe")
	}
	for _, want := range []string{"", strings.Repeat("x", 4097)} {
		if err := snapshot101Readback(missing, want); !errors.Is(err, errSnapshot101Readback) {
			t.Fatalf("unbounded model: %v", err)
		}
	}
}

// Host-executable source regression for the actual Linux-only setup, not just
// a helper test. Restoring any of the three os.OpenFile progress closures or
// either mounted prepareV4ExpectBytes (os.ReadFile) call must fail this test.
func TestSnapshot101RawSetupContract(t *testing.T) {
	for _, path := range []string{"native_snapshot_101_linux_test.go", "native_snapshot_io_101_linux_test.go", "native_snapshot_queue_101_linux_test.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		progress := 0
		ast.Inspect(file, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if !ok || name.Name != "progress" {
				return true
			}
			closure, ok := assignment.Rhs[0].(*ast.FuncLit)
			if !ok {
				t.Fatalf("%s: progress is not original closure", path)
			}
			calls := snapshot101Calls(closure)
			if calls["snapshot101Progress"] != 1 || calls["os.OpenFile"] != 0 || calls["os.Open"] != 0 || calls["os.NewFile"] != 0 || calls["os.ReadFile"] != 0 || calls["os.Getpid"] != 1 || calls["prepareV4ExpectBytes"] != 1 {
				t.Fatalf("%s: progress must retain PID/backing proof and use raw mounted I/O: %v", path, calls)
			}
			progress++
			return true
		})
		if progress != 1 {
			t.Fatalf("%s: missing progress closure", path)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Name.Name == "snapshot101ForeignOwner" {
				calls := snapshot101Calls(fn)
				if calls["snapshot101Readback"] != 2 || calls["prepareV4ExpectBytes"] != 0 {
					t.Fatalf("mounted owner readback exposed to Go netpoll: %v", calls)
				}
			}
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "native_snapshot_raw_101_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imported := range file.Imports {
		if imported.Path.Value == `"os"` {
			t.Fatal("raw mounted helper must not expose os.File")
		}
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		calls := snapshot101Calls(fn)
		if calls["unix.Open"] != 1 || calls["unix.Close"] != 1 {
			t.Fatalf("%s: explicit raw FD ownership missing: %v", fn.Name, calls)
		}
		closed := false
		ast.Inspect(fn, func(node ast.Node) bool {
			if deferred, ok := node.(*ast.DeferStmt); ok && snapshot101Calls(deferred)["unix.Close"] == 1 {
				closed = true
			}
			return true
		})
		if !closed {
			t.Fatalf("%s: close must also run on error", fn.Name)
		}
		switch fn.Name.Name {
		case "snapshot101Progress":
			if calls["snapshot101WriteProgress"] != 1 || calls["unix.Fsync"] != 1 {
				t.Fatal("progress lost file write/sync or directory sync")
			}
		case "snapshot101WriteProgress":
			if calls["unix.Write"] != 1 || calls["unix.Fsync"] != 1 {
				t.Fatal("progress lost actual write or file sync")
			}
		case "snapshot101Readback":
			if calls["unix.Pread"] != 1 {
				t.Fatal("readback lost actual read")
			}
		}
	}
}

func snapshot101Calls(node ast.Node) map[string]int {
	calls := map[string]int{}
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			calls[fn.Name]++
		case *ast.SelectorExpr:
			if pkg, ok := fn.X.(*ast.Ident); ok {
				calls[pkg.Name+"."+fn.Sel.Name]++
			}
		}
		return true
	})
	return calls
}
