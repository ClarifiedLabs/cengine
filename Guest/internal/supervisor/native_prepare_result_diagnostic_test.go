//go:build cengine_native_faulttest

package supervisor

import (
	"fmt"
	"io"

	f "dev.cengine/guest/internal/storagefuse"
)

// Report the actual return value without formatting an error's private payload.
// Callback errors intentionally have opaque Error strings; the existing closed
// vocabulary retains their site, operation and category. Return the SAME error
// to the existing assertion; diagnostics never change success, cleanup or joins.
func prepareDiagnosticResult(out io.Writer, phase prepareDiagnosticPhase, err error) error {
	var label string
	switch phase {
	case prepareInitializeEnd:
		label = "initialize"
	case prepareCloseEnd:
		label = "close"
	default:
		return err
	}
	if err == nil {
		fmt.Fprintf(out, "D prepare-result %s status=ok\n", label)
	} else {
		stage, site, operation, category := f.MountFailureDetails(err)
		fmt.Fprintf(out, "D prepare-result %s status=error stage=%s site=%s operation=%s category=%s\n", label, stage, site, operation, category)
	}
	return err
}
