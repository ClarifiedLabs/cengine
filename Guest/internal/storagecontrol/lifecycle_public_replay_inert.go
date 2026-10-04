//go:build !cengine_prepare_full_compat

package storagecontrol

import (
	"context"
	a "dev.cengine/guest/internal/storageauthority"
)

func ReplaySignedLifecycleTakeover(context.Context, *LifecycleClient, a.SignedLifecycleGrant, a.SignedLifecycleGrant) error {
	return ErrProtocol
}
