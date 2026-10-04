package storageservice

import (
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func TestLifecycleConstructionInstallsAuthenticatedEndpoints(t *testing.T) {
	f := newLifecycleServiceFixture(t)
	must(t, f.s.Close())
	owner, err := constructAuthority(f.cfg, lifecycleController(f.initial.Grant), func(cfg a.Config) (*a.Authority, error) {
		return a.OpenLifecycleCurrent(cfg, f.initial)
	})
	must(t, err)
	t.Cleanup(func() { must(t, owner.Close()) })
	if owner.data == nil || owner.resources == nil || owner.credentialTLS == nil {
		t.Fatal("common construction lost shared DATA, barrier resources or PKI")
	}
	f.s, err = finishLifecycle(owner)
	must(t, err)
	if owner.control == nil || f.s.endpoint == nil {
		t.Fatal("lifecycle construction did not install both current endpoints")
	}
	identity := lifecycleCredential(t, f)
	client, join := lifecycleWorkload(t, f.s, identity)
	must(t, client.Close())
	_ = join()
}
