//go:build cengine_native_faulttest

package supervisor

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	f "dev.cengine/guest/internal/storagefuse"
	"golang.org/x/sys/unix"
)

type prepareDiagnosticOpaqueError struct{}

func (*prepareDiagnosticOpaqueError) Error() string { panic("private error must not be formatted") }

type prepareDiagnosticFailWriter struct{}

func (prepareDiagnosticFailWriter) Write([]byte) (int, error) { return 0, unix.ENOSPC }

func TestPrepareResultDiagnosticClosedVocabularyAndErrorIdentity(t *testing.T) {
	_, mountErr := f.Mount(f.Config{}) // preflight rejection, no native construction
	if mountErr == nil {
		t.Fatal("invalid mount unexpectedly accepted")
	}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"success", nil, "status=ok"},
		{"errno", unix.EACCES, "status=error stage=other site=other operation=other category=EACCES"},
		{"opaque", &prepareDiagnosticOpaqueError{}, "status=error stage=other site=other operation=other category=other"},
		{"construction-before-cleanup", errors.Join(mountErr, unix.EACCES), "status=error stage=preflight site=other operation=other category=profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, phase := range []prepareDiagnosticPhase{prepareInitializeEnd, prepareCloseEnd} {
				label := "initialize"
				if phase == prepareCloseEnd {
					label = "close"
				}
				var out bytes.Buffer
				if got := prepareDiagnosticResult(&out, phase, tc.err); got != tc.err {
					t.Fatal("diagnostic replaced the actual result")
				}
				if want := "D prepare-result " + label + " " + tc.want + "\n"; out.String() != want || out.Len() > 256 {
					t.Fatalf("unexpected diagnostic %q", out.String())
				}
				if got := prepareDiagnosticResult(prepareDiagnosticFailWriter{}, phase, tc.err); got != tc.err {
					t.Fatal("output failure replaced the actual result")
				}
			}
		})
	}
	for phase := prepareDiagnosticPhase(0); ; phase++ {
		if phase != prepareInitializeEnd && phase != prepareCloseEnd {
			var out bytes.Buffer
			err := &prepareDiagnosticOpaqueError{}
			if prepareDiagnosticResult(&out, phase, err) != err || out.Len() != 0 {
				t.Fatal("unsupported phase emitted output or changed result")
			}
		}
		if phase == 255 {
			break
		}
	}
}

func TestPrepareResultDiagnosticActualFixtureWiring(t *testing.T) {
	data, err := os.ReadFile("native_prepare_preflight_v4_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, exact := range []string{
		"err = initializeManagedVolumeScopedAt(rootfs, base, mount, managedCopyScope{Store: string(hello.Binding.Store), Volume: string(hello.Binding.Volume), Prepare: string(hello.Binding.Prepare), Attachment: string(hello.Binding.Attachment)}, checkpoint)\n\tprepareDiagnosticMark(os.Stderr, prepareInitializeEnd)\n\t_ = prepareDiagnosticResult(os.Stderr, prepareInitializeEnd, err)",
		"prepareV4Must(t, prepareDiagnosticResult(os.Stderr, prepareCloseEnd, nativeMount.CloseGracefully(context.Background())))",
	} {
		if strings.Count(source, exact) != 1 {
			t.Fatal("actual initializer/close result is not reported before its unchanged assertion")
		}
	}
}
