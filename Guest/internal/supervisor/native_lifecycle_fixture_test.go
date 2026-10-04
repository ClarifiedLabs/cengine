//go:build cengine_native_faulttest

package supervisor

import (
	"crypto/ed25519"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

// Sign the fresh fixture incarnation with the same ROOT key trusted by Config.
// Reopen callers retain this exact signed grant; they never synthesize a new one.
func nativeLifecycleGrant(t *testing.T, store a.ID, root ed25519.PrivateKey, controller p.Key) a.SignedLifecycleGrant {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	bindingKey, err := p.NewControllerKey()
	must(err)
	binding, err := bindingKey.Fingerprint()
	must(err)
	key, err := controller.Fingerprint()
	must(err)
	id, err := a.NewID()
	must(err)
	grant := a.LifecycleGrant{
		Operation: a.LifecycleInitialize, ID: id,
		Identity: a.LifecycleIdentity{Store: store, Generation: 1, Binding: a.Fingerprint(binding.String())},
		Serial:   1, NewKey: a.Fingerprint(key.String()),
	}
	message, err := a.LifecycleGrantSigningBytes(grant)
	must(err)
	return a.SignedLifecycleGrant{Grant: grant, Signature: ed25519.Sign(root, message)}
}

func TestNativeLifecycleFixtureGrantSignature(t *testing.T) {
	root := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	controller, err := p.NewControllerKey()
	if err != nil {
		t.Fatal(err)
	}
	store, err := a.NewID()
	if err != nil {
		t.Fatal(err)
	}
	current := nativeLifecycleGrant(t, store, root, controller)
	message, err := a.LifecycleGrantSigningBytes(current.Grant)
	if err != nil || !ed25519.Verify(root.Public().(ed25519.PublicKey), message, current.Signature) {
		t.Fatal("fixture lacks genuine ROOT signature", err)
	}
	key, err := controller.Fingerprint()
	if err != nil || current.Grant.Identity.Store != store || current.Grant.NewKey != a.Fingerprint(key.String()) || current.Grant.ExpectedEpoch != 0 {
		t.Fatal("fixture grant does not bind initial controller/store", err)
	}
	current.Grant.Identity.Generation++
	message, err = a.LifecycleGrantSigningBytes(current.Grant)
	if err != nil || ed25519.Verify(root.Public().(ed25519.PublicKey), message, current.Signature) {
		t.Fatal("changed incarnation retained a valid signature", err)
	}
}
