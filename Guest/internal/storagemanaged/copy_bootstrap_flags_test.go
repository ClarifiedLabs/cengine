package storagemanaged

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
)

// Evaluate the actual Linux-only fixture operand on the host. Cross-compilation
// cannot catch native arm64 bits accidentally supplied to the generic wire ABI.
func TestCopyBootstrapFixtureWireFlags(t *testing.T) {
	source, err := os.ReadFile("copy_bootstrap_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	const fixed = "w.OpenDirectory | w.OpenNoFollow | w.OpenCloseOnExec"
	const original = "unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC"
	if strings.Count(string(source), fixed) != 1 {
		t.Fatal("expected exactly one explicit root bootstrap wire-flag operand")
	}
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			values := map[string]uint32{
				"w.OpenDirectory": w.OpenDirectory, "w.OpenNoFollow": w.OpenNoFollow,
				"w.OpenCloseOnExec": w.OpenCloseOnExec,
			}
			// Read the pinned dependency's foreign-architecture constants rather
			// than substituting the test host's syscall ABI or hardcoded numbers.
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "vendor", "golang.org", "x", "sys", "unix", "zerrors_linux_"+arch+".go"), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				v, ok := n.(*ast.ValueSpec)
				if !ok || len(v.Names) != 1 || len(v.Values) != 1 {
					return true
				}
				switch v.Names[0].Name {
				case "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC":
					literal, ok := v.Values[0].(*ast.BasicLit)
					if !ok {
						t.Fatal("native flag is not a literal")
					}
					value, err := strconv.ParseUint(literal.Value, 0, 32)
					if err != nil {
						t.Fatal(err)
					}
					values["unix."+v.Names[0].Name] = uint32(value)
				}
				return true
			})
			if len(values) != 6 {
				t.Fatal("missing native flag constants")
			}
			flags, err := copyBootstrapFixtureFlags(source, values)
			if err != nil || flags != w.OpenDirectory|w.OpenNoFollow|w.OpenCloseOnExec {
				t.Fatalf("bootstrap flags %#x: %v", flags, err)
			}
			request := w.Request{Sequence: 2, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}, Body: w.OpenDirRequest{Node: 1, Flags: flags}}
			data, err := w.Marshal(&request)
			if err != nil {
				t.Fatal(err)
			}
			var decoded w.Request
			if err := w.Unmarshal(data, &decoded); err != nil || decoded.Body.(w.OpenDirRequest) != request.Body.(w.OpenDirRequest) {
				t.Fatalf("bootstrap codec round trip: %v", err)
			}
			// Counterfactual: restore exactly the old source operand. The old
			// amd64 values happen to match; arm64 must still be rejected by the
			// unchanged codec, not silently stripped or granted extra semantics.
			oldSource := []byte(strings.Replace(string(source), fixed, original, 1))
			oldFlags, err := copyBootstrapFixtureFlags(oldSource, values)
			if err != nil {
				t.Fatal(err)
			}
			request.Body = w.OpenDirRequest{Node: 1, Flags: oldFlags}
			_, err = w.Marshal(&request)
			if arch == "arm64" {
				if oldFlags == flags || err == nil || !strings.Contains(err.Error(), "opendir flags") {
					t.Fatalf("old arm64 operand accepted: %#x, %v", oldFlags, err)
				}
			} else if oldFlags != flags || err != nil {
				t.Fatalf("amd64 counterfactual no longer matches generic ABI: %#x, %v", oldFlags, err)
			}
		})
	}
}

func copyBootstrapFixtureFlags(source []byte, values map[string]uint32) (uint32, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "copy_bootstrap_linux_test.go", source, 0)
	if err != nil {
		return 0, err
	}
	var operands []ast.Expr
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestCopyPendingReplayFreshSessionRootBootstrap" {
			continue
		}
		ast.Inspect(function.Body, func(n ast.Node) bool {
			literal, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || typ.Sel.Name != "OpenDirRequest" {
				return true
			}
			for _, element := range literal.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if ok {
					if key, ok := field.Key.(*ast.Ident); ok && key.Name == "Flags" {
						operands = append(operands, field.Value)
					}
				}
			}
			return true
		})
	}
	if len(operands) != 1 {
		return 0, fmt.Errorf("expected one root bootstrap flag expression, found %d", len(operands))
	}
	var evaluate func(ast.Expr) (uint32, error)
	evaluate = func(expression ast.Expr) (uint32, error) {
		switch v := expression.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := v.X.(*ast.Ident); ok {
				if value, ok := values[pkg.Name+"."+v.Sel.Name]; ok {
					return value, nil
				}
			}
		case *ast.BinaryExpr:
			if v.Op == token.OR {
				left, err := evaluate(v.X)
				if err != nil {
					return 0, err
				}
				right, err := evaluate(v.Y)
				return left | right, err
			}
		}
		return 0, fmt.Errorf("unsupported bootstrap flag expression %T", expression)
	}
	return evaluate(operands[0])
}
