//go:build !cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat

package storageauthority

func prepareCompatibilityEnabled() bool { return false }
