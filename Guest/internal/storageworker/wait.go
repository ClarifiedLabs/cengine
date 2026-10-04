package storageworker

import "os"

// WaitResult is an observation, not a transport status. Reaped is true only
// after the sole cmd.Wait supplies a ProcessState and nil or *exec.ExitError.
// Other wait failures retain ownership, the birth pidfd, and the locked thread.
type WaitResult struct {
	Reaped bool
	State  *os.ProcessState
	Err    error
}
