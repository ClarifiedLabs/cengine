package storagefuse

import (
	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
)

// The only non-test bridge. State comes solely from the successful ABI-3 capture;
// no caller/group getter, caller constructor, error retry or authority bypass.
type clientBridge struct{ *c.Client }

func (b clientBridge) Capture(fd int, unique uint64) (credential, error) {
	snapshot, err := b.Client.Capture(fd, unique)
	if err != nil {
		return credential{}, err
	}
	value := credential{snapshot: snapshot}
	switch snapshot.Kind() {
	case c.SnapshotPresent:
		value.state = present
	case c.SnapshotNone:
		value.state = none
	default:
		return credential{}, c.ErrCredentials
	}
	return value, nil
}
func (b clientBridge) Do(value credential, auth w.AuthKind, body w.RequestBody) (c.Result, error) {
	return b.Client.Do(value.snapshot, auth, body)
}

var _ client = clientBridge{}
