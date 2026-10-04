//go:build cengine_prepare_compat

package preparecompat

// Enabled retains the v1 build-tag meaning. Use CurrentProfile for negotiation.
func Enabled() bool { return true }
