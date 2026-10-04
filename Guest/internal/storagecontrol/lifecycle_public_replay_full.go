//go:build cengine_prepare_full_compat

package storagecontrol

import (
	"bytes"
	"context"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	"errors"
)

// ReplaySignedLifecycleTakeover deliberately bypasses only Takeover's local
// grantMatches guard, never its actual TLS exchange/correlation/closed response
// validation. ROOT signatures and checkpoint provenance belong to the child/host.
func ReplaySignedLifecycleTakeover(ctx context.Context, client *LifecycleClient, pending, old a.SignedLifecycleGrant) error {
	g, o := pending.Grant, old.Grant
	if pc.CurrentProfile() != pc.FullProfile || ctx == nil || client == nil || !client.grantMatches(g) ||
		g.Operation != a.LifecycleTakeover || o.Validate() != nil || o.Operation != a.LifecycleTakeover ||
		o.Identity != g.Identity || o.ExpectedEpoch+1 != g.ExpectedEpoch || o.ID == g.ID || o.Serial >= g.Serial || o.NewKey == g.NewKey || len(old.Signature) != 64 || len(pending.Signature) != 64 {
		return ErrProtocol
	}
	old.Signature = bytes.Clone(old.Signature)
	response, err := client.call(ctx, lifecycleRequest{Takeover: &old})
	var remote *RemoteError
	if ctx.Err() != nil || !errors.As(err, &remote) || remote.Code != Unauthorized || response.ID == 0 || response.Error != Unauthorized ||
		response.Receipt != nil || response.ServiceResult != nil || response.Controller != nil || response.OK != nil {
		return ErrProtocol
	}
	return nil
}
