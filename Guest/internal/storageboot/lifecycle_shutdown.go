package storageboot

import "errors"

// ErrShutdownUncertain means the caller must retain PID1 and all storage owners
// for host hard fallback. It is never permission to close roots or power off.
var ErrShutdownUncertain = errors.New("storage shutdown ownership uncertain")

// An error carries bounded ownership out to PID1's containment loop. In
// particular GC must not finalize a root or birth pidfd after an uncertain Wait.
type lifecycleShutdownUncertain struct {
	cause  error
	owners []any
}

func (e *lifecycleShutdownUncertain) Error() string { return e.cause.Error() }
func (e *lifecycleShutdownUncertain) Unwrap() error { return e.cause }
func retainLifecycleShutdown(cause error, owners ...any) error {
	return &lifecycleShutdownUncertain{cause: errors.Join(ErrShutdownUncertain, cause), owners: owners}
}
