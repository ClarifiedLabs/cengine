//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package supervisor

import (
	"context"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	s "dev.cengine/guest/internal/storageservice"
	"testing"
	"time"
)

// Narrow copies of the production-CSR/control helpers in
// storagefuse/native_stale_credentials_linux_test.go; no synthetic principals.
func prepareMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func prepareID(t *testing.T) a.ID {
	t.Helper()
	id, err := a.NewID()
	prepareMust(t, err)
	return id
}

func prepareTrust(t *testing.T, ready s.Ready) (p.Root, p.Binding) {
	t.Helper()
	root, err := p.ParseRootDER(ready.TLSRootDER)
	prepareMust(t, err)
	server, err := p.NewServerBinding(p.StoreID(ready.Store.ID), p.ServiceEpoch(ready.ServiceEpoch))
	prepareMust(t, err)
	return root, server
}

func prepareControl(t *testing.T, service *s.LifecycleService, ready s.Ready, key p.Key) (p.Identity, *c.Client, func()) {
	t.Helper()
	binding, err := p.NewControllerBinding(p.StoreID(ready.Store.ID), p.ControllerEpoch(ready.Controller.Epoch))
	prepareMust(t, err)
	csr, err := key.CSR(binding)
	prepareMust(t, err)
	cert, err := service.IssueController(csr)
	prepareMust(t, err)
	identity, err := cert.WithKey(key)
	prepareMust(t, err)
	root, _ := prepareTrust(t, ready)
	scope, err := service.Scope()
	prepareMust(t, err)
	raw, join := prepareTCP(t, service.ServeControl)
	client, err := c.NewPKILifecycleWorkloadClient(context.Background(), raw, c.PKILifecycleWorkloadClientConfig{Identity: identity, ServerRoot: root, ServerKey: ready.ServerKey, LifecycleIdentity: scope.Identity, ServiceEpoch: ready.ServiceEpoch, CurrentController: ready.Controller})
	prepareMust(t, err)
	return identity, client, func() { prepareMust(t, client.Close()); join() }
}

func prepareCall(t *testing.T, client *c.Client, request c.Request) c.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.Call(ctx, request)
	prepareMust(t, err)
	return response
}
