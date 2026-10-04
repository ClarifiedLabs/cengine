package storageserver

import (
	"context"
	"encoding/hex"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	a "dev.cengine/guest/internal/storageauthority"
)

// authentication receives only the result of the real AuthenticateData call,
// after TLS and PKI verifyPeer succeeded. It cannot affect authority or root setup.
func (c *consumerConnection) authentication(ctx context.Context, h a.DataHello, leaf [32]byte, store, epoch a.ID, err error) {
	if c == nil || !c.reconnectSelected {
		return
	}
	o := c.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.status == nil || o.status.State == "failed" || o.status.State == "finalized" {
		return
	}
	if o.selected != c || o.status.State != "claimed" {
		o.fail("duplicate")
		return
	}
	q := o.status.Query
	if ctx.Err() != nil {
		o.fail("transport-or-unattributed")
		return
	}
	if time.Since(o.armedAt) >= 10*time.Second {
		o.fail("timeout")
		return
	}
	hash := hex.EncodeToString(leaf[:])
	if string(store) != q.WorkerScope.StoreUUID || string(epoch) != q.WorkerScope.ServiceEpoch || !cc.ExactOriginalHello(q.Original, h) || hash != q.OriginalLeafSHA256 {
		o.fail("mismatch")
		return
	}
	if err != a.ErrBlocked {
		o.fail("not-blocked")
		return
	}
	o.status.State = "observed"
	o.timer.Stop()
	o.status.Evidence = &cc.Evidence{Hello: &h, Stage: "authenticate-data", ErrorClass: "blocked", StoreUUID: string(store), ServiceEpoch: string(epoch), RejectedLeafSHA256: hash}
}
