//go:build linux && !cengine_native_faulttest

package supervisor

// No production activation, callback, or checkpoint state.
type confinedPublication struct{}

func (*confinedPublication) afterPublication(int) error { return nil }
