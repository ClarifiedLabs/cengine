package storagefuse

import (
	"errors"
	"fmt"
	"testing"
)

type terminalCauseClient struct {
	*fakeClient
	cause error
}

func (c *terminalCauseClient) Abort(err error) { c.cause = err; c.fakeClient.Abort(err) }

func TestCallbackAnnotationPreservesClientTerminalIdentity(t *testing.T) {
	original := errors.New("remote terminal")
	for _, site := range []failureSite{siteClientDo, siteDataTerminal} {
		f, client := fixture()
		capture := &terminalCauseClient{fakeClient: client}
		f.client = capture
		var mounted, retired error
		f.abortMount = func(err error) { mounted = err }
		f.retire = func(err error) { retired = err }
		f.stopAt(site, 22, original)
		if capture.cause != original || client.aborted != 1 {
			t.Fatal("changed causal terminal error")
		}
		annotation, ok := mounted.(*callbackFailure)
		if !ok || annotation.cause != original || annotation.site != site || annotation.opcode != 22 || retired != mounted {
			t.Fatal("lost mount diagnostic annotation")
		}
		f.OnUnmount()
		if capture.cause != original || client.aborted != 1 {
			t.Fatal("cleanup replaced first cause")
		}
	}
}

func TestStopDoesNotUnwrapForeignOrJoinedCauses(t *testing.T) {
	original := errors.New("remote terminal")
	for _, err := range []error{fmt.Errorf("foreign: %w", original), errors.Join(original, errors.New("cleanup"))} {
		for _, annotated := range []bool{false, true} {
			f, client := fixture()
			capture := &terminalCauseClient{fakeClient: client}
			f.client = capture
			if annotated {
				f.stopAt(siteClientDo, 22, err)
			} else {
				f.stop(err)
			}
			if capture.cause != err {
				t.Fatal("foreign error was unwrapped")
			}
		}
	}
}
